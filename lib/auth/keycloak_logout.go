// Copyright (C) 2026 Cooplay contributors.
// SPDX-License-Identifier: AGPL-3.0-or-later
package auth

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"slices"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gravitational/trace"

	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/auth/authclient"
	"github.com/gravitational/teleport/lib/backend"
)

const keycloakLogoutEvent = "http://schemas.openid.net/event/backchannel-logout"

// KeycloakLogout applies either a verified IdP notification (Proxy only) or
// the caller's current login. No input can name another user's login marker.
func (a *ServerWithRoles) KeycloakLogout(ctx context.Context, req authclient.KeycloakLogoutRequest) error {
	s, ok := a.authServer.oidcAuthService.(*keycloakService)
	if !ok || s.lifecycle == nil {
		return trace.NotImplemented("managed Keycloak logout unavailable")
	}
	if req.LogoutToken != "" || req.ConnectorID != "" {
		if !a.hasBuiltinRole(types.RoleProxy) || req.LogoutToken == "" || req.ConnectorID == "" {
			return trace.AccessDenied("Keycloak logout notification requires a proxy")
		}
		return s.backchannelLogout(ctx, req.ConnectorID, req.LogoutToken)
	}
	identity := a.context.Identity.GetIdentity()
	if !IsKeycloakUser(a.context.User) || identity.Username != a.context.User.GetName() {
		return trace.AccessDenied("Keycloak login required")
	}
	var marker string
	for _, role := range identity.Groups {
		if strings.HasPrefix(role, keycloakLoginPrefix) {
			if marker != "" {
				return trace.AccessDenied("ambiguous Keycloak login")
			}
			marker = role
		}
	}
	if marker == "" {
		return trace.AccessDenied("Keycloak login marker missing")
	}
	item, err := s.a.bk.Get(ctx, keycloakLifecycleKey("logins", marker))
	if err != nil {
		return trace.AccessDenied("Keycloak login unavailable")
	}
	var login keycloakLogin
	if json.Unmarshal(item.Value, &login) != nil || login.Username != identity.Username || login.Marker != marker {
		return trace.AccessDenied("Keycloak login identity mismatch")
	}
	return s.persistRevocation(ctx, "roles", marker, types.LockTarget{Role: marker}, "current-login-logout", login.Expires.Add(24*time.Hour))
}

func (s *keycloakService) backchannelLogout(ctx context.Context, connector, raw string) error {
	if len(raw) == 0 || len(raw) > 64*1024 {
		return trace.AccessDenied("invalid Keycloak logout notification")
	}
	c, err := s.connector(ctx, connector)
	if err != nil {
		return trace.AccessDenied("invalid Keycloak logout connector")
	}
	httpCtx, cancel := s.httpContext(ctx)
	defer cancel()
	p, _, err := s.provider(httpCtx, c)
	if err != nil {
		return err
	}
	token, err := p.Verifier(&oidc.Config{ClientID: c.GetClientID(), SupportedSigningAlgs: []string{oidc.RS256}, SkipExpiryCheck: true, Now: s.a.clock.Now}).Verify(httpCtx, raw)
	if err != nil {
		return trace.AccessDenied("invalid Keycloak logout signature")
	}
	var claims struct {
		SID    string                     `json:"sid"`
		JTI    string                     `json:"jti"`
		Events map[string]json.RawMessage `json:"events"`
		Exp    int64                      `json:"exp"`
		NBF    int64                      `json:"nbf"`
		AZP    string                     `json:"azp"`
	}
	var all map[string]json.RawMessage
	if token.Claims(&claims) != nil || token.Claims(&all) != nil {
		return trace.AccessDenied("invalid Keycloak logout claims")
	}
	_, nonce := all["nonce"]
	var event map[string]any
	now := s.a.clock.Now()
	if token.Issuer != c.GetIssuerURL() || nonce || len(claims.Events) != 1 || json.Unmarshal(claims.Events[keycloakLogoutEvent], &event) != nil || event == nil || len(event) != 0 ||
		claims.JTI == "" || len(claims.JTI) > 512 || token.IssuedAt.IsZero() || token.IssuedAt.After(now.Add(30*time.Second)) || now.Sub(token.IssuedAt) > 5*time.Minute ||
		(claims.Exp != 0 && claims.Exp <= now.Unix()) || claims.NBF > now.Add(30*time.Second).Unix() ||
		(claims.AZP != "" && claims.AZP != c.GetClientID()) || (len(token.Audience) > 1 && claims.AZP == "") ||
		(token.Subject == "" && claims.SID == "") || len(token.Subject) > 512 || len(claims.SID) > 512 {
		return trace.AccessDenied("invalid Keycloak logout claims")
	}
	replayKey := keycloakLifecycleKey("logout-jti", keycloakDigest(c.GetIssuerURL()+"\x00"+claims.JTI))
	digest := keycloakDigest(raw)
	_, err = s.a.bk.Create(ctx, backend.Item{Key: replayKey, Value: []byte(digest), Expires: now.Add(10 * time.Minute)})
	if trace.IsAlreadyExists(err) {
		item, getErr := s.a.bk.Get(ctx, replayKey)
		if getErr != nil || subtle.ConstantTimeCompare(item.Value, []byte(digest)) != 1 {
			return trace.AccessDenied("Keycloak logout replay rejected")
		}
		// Identical retries repeat idempotent work, so a crash after accepting jti
		// but before creating locks can never turn a retry into a false success.
	} else if err != nil {
		return trace.AccessDenied("Keycloak logout replay storage unavailable")
	}
	if claims.SID != "" {
		key := keycloakLifecycleKey("revocations", "sid", keycloakDigest(c.GetIssuerURL()+"\x00"+claims.SID))
		if err := s.lifecyclePut(ctx, key, keycloakRevocation{Reason: "idp-session-logout", Time: now}, now.Add(24*time.Hour), true); err != nil && !trace.IsAlreadyExists(err) {
			return err
		}
	} else {
		key := keycloakLifecycleKey("subject-logout", keycloakDigest(c.GetIssuerURL()+"\x00"+token.Subject))
		// Monotonic compare-and-swap prevents delayed notifications from lowering
		// a newer cutoff. Include the full issued second for concurrent callbacks.
		cutoff := token.IssuedAt.Add(time.Second - time.Nanosecond)
		for {
			old, getErr := s.a.bk.Get(ctx, key)
			if trace.IsNotFound(getErr) {
				err = s.lifecyclePut(ctx, key, cutoff, now.Add(24*time.Hour), true)
				if trace.IsAlreadyExists(err) {
					continue
				}
				if err != nil {
					return err
				}
				break
			}
			if getErr != nil {
				return getErr
			}
			var previous time.Time
			if json.Unmarshal(old.Value, &previous) != nil {
				return trace.AccessDenied("invalid Keycloak logout state")
			}
			if !cutoff.After(previous) {
				break
			}
			data, _ := json.Marshal(cutoff)
			old.Value = data
			old.Expires = now.Add(24 * time.Hour)
			_, err = s.a.bk.ConditionalUpdate(ctx, *old)
			if trace.IsCompareFailed(err) {
				continue
			}
			if err != nil {
				return err
			}
			break
		}
	}
	return s.logins(ctx, func(login keycloakLogin) error {
		if login.Connector != connector || login.Issuer != c.GetIssuerURL() || (claims.SID != "" && login.SID != claims.SID) ||
			(token.Subject != "" && login.Subject != token.Subject) || (claims.SID == "" && login.Issued.Unix() > token.IssuedAt.Unix()) {
			return nil
		}
		return s.persistRevocation(ctx, "roles", login.Marker, types.LockTarget{Role: login.Marker}, "idp-logout", login.Expires.Add(24*time.Hour))
	})
}

// checkKeycloakRoles protects resource-specific reissue and web renewal while
// native lock watcher propagation is still in flight.
func (a *Server) checkKeycloakRoles(ctx context.Context, user string, roles []string) error {
	s, ok := a.oidcAuthService.(*keycloakService)
	if !ok || s.lifecycle == nil {
		return nil
	}
	if err := s.revoked(ctx, "users", user); err != nil {
		return err
	}
	var marker string
	for _, role := range roles {
		if strings.HasPrefix(role, keycloakLoginPrefix) {
			if marker != "" {
				return trace.AccessDenied("ambiguous Keycloak login")
			}
			marker = role
		}
	}
	if marker == "" {
		return trace.AccessDenied("Keycloak login marker missing")
	}
	item, err := s.a.bk.Get(ctx, keycloakLifecycleKey("logins", marker))
	if err != nil {
		return trace.AccessDenied("Keycloak login unavailable")
	}
	var login keycloakLogin
	if json.Unmarshal(item.Value, &login) != nil || login.Username != user || !slices.Contains(roles, keycloakGuard(login.Connector)) {
		return trace.AccessDenied("Keycloak login binding mismatch")
	}
	return s.checkLogin(ctx, &login)
}
