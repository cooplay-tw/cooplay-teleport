// Copyright (C) 2026 Cooplay contributors.
// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gravitational/trace"
	"golang.org/x/crypto/ssh"
	"golang.org/x/oauth2"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/api/constants"
	apidefaults "github.com/gravitational/teleport/api/defaults"
	"github.com/gravitational/teleport/api/types"
	apievents "github.com/gravitational/teleport/api/types/events"
	"github.com/gravitational/teleport/lib/auth/authclient"
	"github.com/gravitational/teleport/lib/authz"
	"github.com/gravitational/teleport/lib/backend"
	"github.com/gravitational/teleport/lib/client/sso"
	"github.com/gravitational/teleport/lib/events"
	"github.com/gravitational/teleport/lib/httplib"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/utils"
)

const (
	keycloakSessionTTL = 5 * time.Minute
	keycloakRequestTTL = 3 * time.Minute
	keycloakUserPrefix = "keycloak-"
	keycloakUserLabel  = "cooplay.dev/keycloak"
)

var keycloakNamespaceName = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

var keycloakRoleName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,127}$`)

// NewKeycloakService implements the deliberately limited, opt-in Keycloak
// connector. Registration is a deployment choice, not an Enterprise feature
// flag. Callers must retain ServerWithRoles authorization around this service.
func NewKeycloakService(a *Server) OIDCService {
	return &keycloakService{a: a}
}

type keycloakService struct {
	lifecycleMu sync.Mutex
	a           *Server
	lifecycle   *KeycloakLifecycleConfig
	httpClient  *http.Client
}

// IsKeycloakUser identifies identities owned by this connector implementation.
// The marker is administrator-controlled; IdP claims cannot set user metadata.
func IsKeycloakUser(user types.User) bool {
	if user == nil || !strings.HasPrefix(user.GetName(), keycloakUserPrefix) ||
		user.GetMetadata().Labels[keycloakUserLabel] != "v1" {
		return false
	}
	ref := user.GetCreatedBy().Connector
	return ref != nil && ref.Type == constants.OIDC && ref.ID != "" && len(user.GetOIDCIdentities()) == 1
}

// ValidateKeycloakConnector rejects settings this implementation cannot honor.
// In particular, mappings are exact comparisons, never upstream regex/template
// mappings. No identity claim can supply a role name or a Unix login.
func ValidateKeycloakConnector(c types.OIDCConnector) error {
	if c == nil || c.GetProvider() != "keycloak" {
		return trace.BadParameter("experimental connector requires provider keycloak")
	}
	concrete, ok := c.(*types.OIDCConnectorV3)
	if !ok {
		return trace.BadParameter("unsupported Keycloak connector resource")
	}
	if err := concrete.CheckAndSetDefaults(); err != nil {
		return trace.BadParameter("invalid Keycloak connector")
	}
	if err := c.Validate(); err != nil {
		return trace.BadParameter("invalid Keycloak connector")
	}
	if _, err := keycloakHTTPSURL(c.GetIssuerURL()); err != nil {
		return trace.BadParameter("Keycloak issuer must be an absolute HTTPS URL without query, fragment or credentials")
	}
	if len(c.GetRedirectURLs()) != 1 {
		return trace.BadParameter("Keycloak requires exactly one redirect_url")
	}
	u, err := keycloakHTTPSURL(c.GetRedirectURLs()[0])
	if err != nil || u.Path != "/v1/webapi/oidc/callback" {
		return trace.BadParameter("Keycloak redirect_url must be HTTPS and end with /v1/webapi/oidc/callback")
	}
	if c.GetUsernameClaim() != "" && c.GetUsernameClaim() != "sub" {
		return trace.BadParameter("Keycloak usernames are derived from issuer and sub")
	}
	if c.GetACR() != "" || c.GetMFASettings() != nil || c.GetClientRedirectSettings() != nil ||
		c.GetGoogleServiceAccountURI() != "" || c.GetGoogleServiceAccount() != "" ||
		c.GetGoogleAdminEmail() != "" || c.GetEntraIDGroupsProvider() != nil ||
		c.GetAllowUnverifiedEmail() || len(c.GetUserMatchers()) != 0 {
		return trace.BadParameter("unsupported Keycloak connector option")
	}
	if _, configured := c.GetMaxAge(); configured {
		return trace.BadParameter("max_age is unsupported; Keycloak always requests prompt=login")
	}
	if concrete.Spec.Prompt != "" && concrete.Spec.Prompt != "login" {
		return trace.BadParameter("Keycloak requires prompt=login")
	}
	if mode := c.GetPKCEMode(); mode != constants.OIDCPKCEModeUnknown && mode != constants.OIDCPKCEModeEnabled {
		return trace.BadParameter("Keycloak requires S256 PKCE")
	}
	if mode := c.GetRequestObjectMode(); mode != constants.OIDCRequestObjectModeUnknown && mode != constants.OIDCRequestObjectModeNone {
		return trace.BadParameter("Keycloak request objects are unsupported")
	}
	for _, scope := range c.GetScope() {
		if !slices.Contains([]string{"openid", "profile", "email", "groups"}, scope) {
			return trace.BadParameter("unsupported Keycloak scope")
		}
	}
	for _, m := range c.GetClaimsToRoles() {
		if m.Claim != "groups" || !strings.HasPrefix(m.Value, "/") || len(m.Value) > 512 ||
			strings.ContainsAny(m.Value, `*?[]{}()^$|\`) || strings.ContainsAny(m.Value, "\x00\r\n") {
			return trace.BadParameter("Keycloak mappings require exact full group paths in the groups claim")
		}
		for _, role := range m.Roles {
			if !keycloakRoleName.MatchString(role) || strings.HasPrefix(role, keycloakLoginPrefix) || strings.HasPrefix(role, keycloakGuardPrefix) {
				return trace.BadParameter("Keycloak mappings require literal role names")
			}
		}
	}
	return nil
}

func keycloakHTTPSURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil ||
		u.Opaque != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return nil, trace.BadParameter("invalid HTTPS URL")
	}
	return u, nil
}

type keycloakRequest struct {
	Request       types.OIDCAuthRequest `json:"request"`
	Nonce         string                `json:"nonce"`
	Verifier      string                `json:"verifier"`
	ConnectorHash string                `json:"connector_hash"`
	Expires       time.Time             `json:"expires"`
}

func keycloakFingerprint(c types.OIDCConnector) (string, error) {
	b, err := services.MarshalOIDCConnector(c)
	if err != nil {
		return "", trace.BadParameter("invalid Keycloak connector")
	}
	digest := sha256.Sum256(b)
	return hex.EncodeToString(digest[:]), nil
}

func keycloakStateKey(state string) backend.Key {
	return backend.NewKey("cooplay", "keycloak", "requests", state)
}

func (s *keycloakService) connector(ctx context.Context, id string) (types.OIDCConnector, error) {
	// Read current configuration, not the auth cache. Deleted or changed
	// connectors must not finish an in-flight authentication with stale policy.
	c, err := s.a.Services.GetOIDCConnector(ctx, id, true)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	if err := ValidateKeycloakConnector(c); err != nil {
		return nil, trace.Wrap(err)
	}
	if err := s.lifecycleConnector(ctx, c); err != nil {
		return nil, err
	}
	return c, nil
}

func (s *keycloakService) CreateOIDCAuthRequest(ctx context.Context, req types.OIDCAuthRequest) (*types.OIDCAuthRequest, error) {
	if !req.CheckUser || req.SSOTestFlow || req.ConnectorSpec != nil || req.Type != "" ||
		req.Scope != "" || req.SshAttestationStatement != nil || req.TlsAttestationStatement != nil ||
		req.StateToken != "" || req.PkceVerifier != "" || req.RedirectURL != "" {
		return nil, trace.AccessDenied("unsupported experimental Keycloak login flow")
	}
	if req.ClientRedirectURL == "" {
		return nil, trace.BadParameter("client redirect URL required")
	}
	if req.CreateWebSession {
		if len(req.SshPublicKey)+len(req.TlsPublicKey) != 0 || req.CSRFToken == "" {
			return nil, trace.BadParameter("invalid Keycloak web login request")
		}
		if _, err := httplib.OriginLocalRedirectURI(req.ClientRedirectURL); err != nil {
			return nil, trace.BadParameter("invalid web redirect URL")
		}
	} else {
		if len(req.SshPublicKey)+len(req.TlsPublicKey) == 0 {
			return nil, trace.BadParameter("public key required")
		}
		if err := sso.ValidateClientRedirect(req.ClientRedirectURL, sso.CeremonyTypeLogin, nil); err != nil {
			return nil, trace.BadParameter(InvalidClientRedirectErrorMessage)
		}
	}
	if req.CertTTL < 0 {
		return nil, trace.BadParameter("invalid certificate TTL")
	}
	if req.CertTTL == 0 || req.CertTTL > keycloakSessionTTL {
		req.CertTTL = keycloakSessionTTL
	}
	c, err := s.connector(ctx, req.ConnectorID)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	httpCtx, cancel := s.httpContext(ctx)
	defer cancel()
	_, config, err := s.provider(httpCtx, c)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	req.StateToken, err = utils.CryptoRandomHex(32)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	if err := req.Check(); err != nil {
		return nil, trace.BadParameter("invalid Keycloak login request")
	}
	nonce, err := utils.CryptoRandomHex(32)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	verifier := oauth2.GenerateVerifier()
	req.LoginHint = "" // Identity is never bound by an unverified email hint.
	req.RedirectURL = config.AuthCodeURL(req.StateToken, oidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier), oauth2.SetAuthURLParam("prompt", "login"))
	fingerprint, err := keycloakFingerprint(c)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	stored := keycloakRequest{Request: req, Nonce: nonce, Verifier: verifier, ConnectorHash: fingerprint, Expires: s.a.clock.Now().Add(keycloakRequestTTL)}
	data, err := json.Marshal(stored)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	// Native storage holds only the public request fields for proxy failure
	// redirects. Never expose the PKCE verifier via GetOIDCAuthRequest.
	if err := s.a.Services.CreateOIDCAuthRequest(ctx, req, keycloakRequestTTL); err != nil {
		return nil, trace.Wrap(err)
	}
	if _, err := s.a.bk.Create(ctx, backend.Item{Key: keycloakStateKey(req.StateToken), Value: data, Expires: stored.Expires}); err != nil {
		return nil, trace.Wrap(err)
	}
	return &req, nil
}

func (*keycloakService) CreateOIDCAuthRequestForMFA(context.Context, types.OIDCAuthRequest) (*types.OIDCAuthRequest, error) {
	return nil, trace.AccessDenied("experimental Keycloak connector does not implement SSO MFA")
}

// keycloakHTTPContext enforces timeouts and disallows redirects when fetching
// discovery, tokens or keys. A caller-supplied OAuth HTTP client may provide a
// private CA transport (also used by the TLS fixture); it cannot weaken these
// timeout/redirect rules through a connector resource or login request.
func keycloakHTTPContext(ctx context.Context) (context.Context, context.CancelFunc) {
	client := http.Client{Transport: http.DefaultTransport}
	if supplied, ok := ctx.Value(oauth2.HTTPClient).(*http.Client); ok {
		client.Transport = supplied.Transport
	}
	client.Timeout = 10 * time.Second
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	return oidc.ClientContext(ctx, &client), cancel
}

func (s *keycloakService) provider(ctx context.Context, c types.OIDCConnector) (*oidc.Provider, *oauth2.Config, error) {
	p, err := oidc.NewProvider(ctx, c.GetIssuerURL())
	if err != nil {
		return nil, nil, trace.AccessDenied("Keycloak discovery failed")
	}
	var metadata struct {
		JWKSURI string `json:"jwks_uri"`
	}
	if err := p.Claims(&metadata); err != nil {
		return nil, nil, trace.AccessDenied("invalid Keycloak discovery document")
	}
	issuer, _ := keycloakHTTPSURL(c.GetIssuerURL())
	for _, endpoint := range []string{p.Endpoint().AuthURL, p.Endpoint().TokenURL, metadata.JWKSURI} {
		u, err := keycloakHTTPSURL(endpoint)
		if err != nil || u.Host != issuer.Host {
			return nil, nil, trace.AccessDenied("Keycloak endpoints must use HTTPS on the issuer origin")
		}
	}
	endpoint := p.Endpoint()
	endpoint.AuthStyle = oauth2.AuthStyleInHeader
	scopes := []string{oidc.ScopeOpenID}
	for _, scope := range c.GetScope() {
		if !slices.Contains(scopes, scope) {
			scopes = append(scopes, scope)
		}
	}
	return p, &oauth2.Config{ClientID: c.GetClientID(), ClientSecret: c.GetClientSecret(), RedirectURL: c.GetRedirectURLs()[0], Endpoint: endpoint, Scopes: scopes}, nil
}

func (s *keycloakService) consume(ctx context.Context, state string) (*keycloakRequest, error) {
	if len(state) != 64 {
		return nil, trace.AccessDenied("invalid or expired Keycloak request")
	}
	if _, err := hex.DecodeString(state); err != nil {
		return nil, trace.AccessDenied("invalid or expired Keycloak request")
	}
	item, err := s.a.bk.Get(ctx, keycloakStateKey(state))
	if err != nil {
		return nil, trace.AccessDenied("invalid or expired Keycloak request")
	}
	// ConditionalDelete is atomic in the shared backend, so exactly one Auth
	// instance may exchange this request. Network failures fail closed.
	if err := s.a.bk.ConditionalDelete(ctx, item.Key, item.Revision); err != nil {
		return nil, trace.AccessDenied("invalid or consumed Keycloak request")
	}
	var req keycloakRequest
	if err := json.Unmarshal(item.Value, &req); err != nil || !s.a.clock.Now().Before(req.Expires) {
		return nil, trace.AccessDenied("invalid or expired Keycloak request")
	}
	return &req, nil
}

func (s *keycloakService) ValidateOIDCAuthCallback(ctx context.Context, q url.Values) (response *authclient.OIDCAuthResponse, resultErr error) {
	event := &apievents.UserLogin{Metadata: apievents.Metadata{Type: events.UserLoginEvent, Code: events.UserSSOLoginFailureCode}, Method: events.LoginMethodOIDC, ConnectionMetadata: authz.ConnectionMetadata(ctx)}
	defer func() {
		if resultErr == nil {
			event.Code = events.UserSSOLoginCode
			event.Success = true
		} else {
			// Provider errors can contain codes, tokens or claims. Audit only a
			// fixed error, never the OAuth query or the underlying response.
			event.Error = "Keycloak authentication rejected"
			event.UserMessage = event.Error
			resultErr = trace.AccessDenied("%s", event.Error)
		}
		if err := s.a.EmitAuditEvent(ctx, event); err != nil {
			if response != nil && response.Session != nil {
				_ = s.a.Services.WebSessions().Delete(context.WithoutCancel(ctx), types.DeleteWebSessionRequest{User: response.Username, SessionID: response.Session.GetName()})
			}
			response = nil
			resultErr = trace.AccessDenied("Keycloak audit recording failed")
		}
	}()
	if len(q["state"]) != 1 || len(q["code"]) > 1 || len(q["error"]) > 1 || len(q["iss"]) > 1 {
		return nil, trace.AccessDenied("invalid callback parameters")
	}
	stored, err := s.consume(ctx, q.Get("state"))
	if err != nil {
		return nil, err
	}
	event.ConnectorID = stored.Request.ConnectorID
	if q.Get("error") != "" || q.Get("code") == "" || len(q.Get("code")) > 4096 {
		return nil, trace.AccessDenied("Keycloak authorization rejected")
	}
	c, err := s.connector(ctx, stored.Request.ConnectorID)
	if err != nil {
		return nil, err
	}
	fingerprint, err := keycloakFingerprint(c)
	if err != nil || fingerprint != stored.ConnectorHash || (q.Get("iss") != "" && q.Get("iss") != c.GetIssuerURL()) {
		return nil, trace.AccessDenied("Keycloak connector changed during login")
	}
	httpCtx, cancel := s.httpContext(ctx)
	defer cancel()
	p, config, err := s.provider(httpCtx, c)
	if err != nil {
		return nil, err
	}
	token, err := config.Exchange(httpCtx, q.Get("code"), oauth2.VerifierOption(stored.Verifier))
	if err != nil {
		return nil, trace.AccessDenied("Keycloak code exchange failed")
	}
	raw, ok := token.Extra("id_token").(string)
	if !ok || len(raw) > 64*1024 {
		return nil, trace.AccessDenied("missing or oversized ID token")
	}
	id, err := p.Verifier(&oidc.Config{ClientID: c.GetClientID(), SupportedSigningAlgs: []string{oidc.RS256}, Now: s.a.clock.Now}).Verify(httpCtx, raw)
	if err != nil {
		return nil, trace.AccessDenied("invalid Keycloak ID token")
	}
	if id.Issuer != c.GetIssuerURL() || subtle.ConstantTimeCompare([]byte(id.Nonce), []byte(stored.Nonce)) != 1 || id.Subject == "" || len(id.Subject) > 512 || strings.ContainsRune(id.Subject, 0) || id.IssuedAt.IsZero() || id.IssuedAt.After(s.a.clock.Now().Add(30*time.Second)) {
		return nil, trace.AccessDenied("invalid Keycloak identity binding")
	}
	var claims struct {
		Groups          []string `json:"groups"`
		AuthorizedParty string   `json:"azp"`
		NotBefore       int64    `json:"nbf"`
		SID             string   `json:"sid"`
	}
	if err := id.Claims(&claims); err != nil || len(claims.Groups) > 256 ||
		claims.NotBefore > s.a.clock.Now().Add(30*time.Second).Unix() ||
		(claims.AuthorizedParty != "" && claims.AuthorizedParty != c.GetClientID()) ||
		(len(id.Audience) > 1 && claims.AuthorizedParty == "") {
		return nil, trace.AccessDenied("invalid Keycloak claims")
	}
	roles := make([]string, 0)
	for _, m := range c.GetClaimsToRoles() {
		if slices.Contains(claims.Groups, m.Value) {
			for _, role := range m.Roles {
				if !slices.Contains(roles, role) {
					roles = append(roles, role)
				}
			}
		}
	}
	if len(roles) == 0 {
		return nil, trace.AccessDenied("no Keycloak group maps to a role")
	}
	slices.Sort(roles)
	digest := sha256.Sum256([]byte(c.GetIssuerURL() + "\x00" + id.Subject))
	username := keycloakUserPrefix + hex.EncodeToString(digest[:])
	event.User = username
	event.UserRoles = roles
	// Keep an absolute deadline across slow backend/signing operations.
	now := s.a.clock.Now()
	ttl := min(keycloakSessionTTL, stored.Request.CertTTL, id.Expiry.Sub(now))
	for _, name := range roles {
		role, err := s.a.Services.GetRole(ctx, name)
		if err != nil {
			return nil, trace.AccessDenied("mapped Keycloak role unavailable")
		}
		if err := validateKeycloakRole(role); err != nil {
			return nil, err
		}
		ttl = min(ttl, role.GetOptions().MaxSessionTTL.Duration())
	}
	if ttl < apidefaults.MinCertDuration {
		return nil, trace.AccessDenied("Keycloak identity expires too soon")
	}
	// Never merge access-list or login-hook roles into this bounded connector.
	if _, err := s.a.Services.GetUserLoginState(ctx, username); !trace.IsNotFound(err) {
		return nil, trace.AccessDenied("Keycloak login-state augmentation is unsupported")
	}
	expires := now.Add(ttl)
	login, err := s.prepareLogin(ctx, c, id.Subject, claims.SID, username, claims.Groups, expires)
	if err != nil {
		return nil, err
	}
	user, err := s.saveUser(ctx, c.GetName(), id.Subject, username, roles, expires)
	if err != nil {
		return nil, err
	}
	if login != nil {
		user.SetRoles(append(slices.Clone(roles), login.Marker, keycloakGuard(c.GetName())))
	}
	response, err = s.issue(ctx, &stored.Request, user, expires)
	if err != nil {
		return nil, err
	}
	if err := s.checkLogin(ctx, login); err != nil {
		if response.Session != nil {
			_ = s.a.Services.WebSessions().Delete(context.WithoutCancel(ctx), types.DeleteWebSessionRequest{User: response.Username, SessionID: response.Session.GetName()})
		}
		return nil, err
	}
	return response, nil
}

func validateKeycloakRole(role types.Role) error {
	o := role.GetOptions()
	if o.MaxSessionTTL.Duration() <= 0 || o.MaxSessionTTL.Duration() > keycloakSessionTTL || !o.DisconnectExpiredCert || o.Lock != constants.LockingModeStrict {
		return trace.AccessDenied("Keycloak roles require max_session_ttl <= 5m, disconnect_expired_cert and strict locking")
	}
	concrete, ok := role.(*types.RoleV6)
	if !ok || role.GetVersion() != types.V8 {
		return trace.AccessDenied("Keycloak requires version v8 roles")
	}
	// Support only SSH allow conditions. v8 leaves other resource labels empty;
	// earlier role versions can grant wildcard resource access by default.
	// Inspect the protobuf remainder so both new fields and unknown fields fail
	// closed, instead of relying on an exhaustive list of non-SSH getters.

	allow := concrete.Spec.Allow
	kubeConfigured := len(allow.KubernetesLabels)+len(allow.KubeGroups)+len(allow.KubeUsers)+len(allow.KubernetesResources) != 0
	if kubeConfigured {
		if len(allow.KubernetesLabels) == 0 || len(allow.KubernetesResources) == 0 || len(allow.KubeGroups)+len(allow.KubeUsers) == 0 {
			return trace.AccessDenied("Keycloak Kubernetes roles require explicit cluster labels, identities and resources")
		}
		for _, identity := range append(slices.Clone(allow.KubeGroups), allow.KubeUsers...) {
			if !keycloakRoleName.MatchString(identity) || strings.HasPrefix(identity, "system") {
				return trace.AccessDenied("Keycloak Kubernetes identities must be literal unprivileged names")
			}
		}
		for _, resource := range allow.KubernetesResources {
			if resource.Kind != "pods" || resource.APIGroup != "" || !keycloakNamespaceName.MatchString(resource.Namespace) || resource.Name == "" || len(resource.Verbs) == 0 {
				return trace.AccessDenied("Keycloak Kubernetes roles require namespaced pod resources and explicit verbs")
			}
			for _, verb := range resource.Verbs {
				if !slices.Contains([]string{"get", "list", "watch"}, verb) && !(verb == "exec" && keycloakNamespaceName.MatchString(resource.Name)) {
					return trace.AccessDenied("unsupported Keycloak Kubernetes verb")
				}
			}
		}
	}
	remaining := concrete.Spec.Allow
	remaining.Logins = nil
	remaining.Namespaces = nil
	remaining.NodeLabels = nil
	remaining.NodeLabelsExpression = ""
	remaining.KubernetesLabels = nil
	remaining.KubeGroups = nil
	remaining.KubeUsers = nil
	remaining.KubernetesResources = nil
	// Custom label types encode empty fields, hence compare to the empty
	// message's encoded size rather than zero. Any other set field adds bytes.
	if remaining.Size() != (&types.RoleConditions{}).Size() {
		return trace.AccessDenied("Keycloak roles only support SSH and bounded Kubernetes pod access")
	}
	return nil
}

func (s *keycloakService) saveUser(ctx context.Context, connector, subject, username string, roles []string, expires time.Time) (types.User, error) {
	u := &types.UserV2{Kind: types.KindUser, Version: types.V2,
		Metadata: types.Metadata{Name: username, Namespace: apidefaults.Namespace, Expires: &expires, Labels: map[string]string{keycloakUserLabel: "v1"}},
		Spec: types.UserSpecV2{Roles: roles, Traits: map[string][]string{},
			OIDCIdentities: []types.ExternalIdentity{{ConnectorID: connector, Username: subject, UserID: subject}},
			CreatedBy:      types.CreatedBy{User: types.UserRef{Name: teleport.UserSystem}, Time: s.a.clock.Now().UTC(), Connector: &types.ConnectorRef{Type: constants.OIDC, ID: connector, Identity: subject}},
		},
	}
	existing, err := s.a.Services.GetUser(ctx, username, false)
	if err != nil && !trace.IsNotFound(err) {
		return nil, trace.Wrap(err)
	}
	if existing == nil {
		if _, err := s.a.CreateUser(ctx, u); err != nil {
			return nil, trace.Wrap(err)
		}
	} else {
		if !IsKeycloakUser(existing) || existing.GetCreatedBy().Connector.ID != connector || !existing.GetOIDCIdentities()[0].IsEqual(&u.Spec.OIDCIdentities[0]) {
			return nil, trace.AccessDenied("Keycloak identity collides with an existing user")
		}
		status := existing.GetStatus()
		if status.IsLocked && (status.LockExpires.IsZero() || status.LockExpires.After(s.a.clock.Now())) {
			return nil, trace.AccessDenied("Keycloak user is locked")
		}
		// Do not clear administrative account status while refreshing claims.
		u.Spec.Status = status
		u.SetRevision(existing.GetRevision())
		if _, err := s.a.UpdateUser(ctx, u); err != nil {
			return nil, trace.Wrap(err)
		}
	}
	return u, nil
}

func (s *keycloakService) issue(ctx context.Context, req *types.OIDCAuthRequest, user types.User, expires time.Time) (*authclient.OIDCAuthResponse, error) {
	// Native signing APIs accept durations. Reserve a second for signing, and
	// inspect the actual result below so a slow signer can never extend the
	// absolute identity deadline. An overrun fails closed and drops the session.
	ttl := expires.Sub(s.a.clock.Now()).Truncate(time.Second) - time.Second
	if ttl < apidefaults.MinCertDuration {
		return nil, trace.AccessDenied("Keycloak identity expires too soon")
	}
	r := &authclient.OIDCAuthResponse{Username: user.GetName(), Identity: user.GetOIDCIdentities()[0], Req: authclient.OIDCAuthRequest{
		ConnectorID: req.ConnectorID, CSRFToken: req.CSRFToken, SSHPubKey: req.SshPublicKey, TLSPubKey: req.TlsPublicKey, CreateWebSession: req.CreateWebSession, ClientRedirectURL: req.ClientRedirectURL,
	}}
	options, err := s.a.ClientOptionsForLogin(user)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	r.ClientOptions = options
	if req.CreateWebSession {
		sess, err := s.a.CreateWebSessionFromReq(ctx, NewWebSessionRequest{User: user.GetName(), Roles: user.GetRoles(), Traits: user.GetTraits(), SessionTTL: ttl, LoginTime: s.a.clock.Now().UTC(), LoginIP: req.ClientLoginIP, LoginUserAgent: req.ClientUserAgent, AttestWebSession: true})
		if err != nil {
			return nil, trace.Wrap(err)
		}
		r.Session = sess
		if keycloakSessionExpiry(sess, expires) != nil {
			_ = s.a.Services.WebSessions().Delete(context.WithoutCancel(ctx), types.DeleteWebSessionRequest{User: user.GetName(), SessionID: sess.GetName()})
			return nil, trace.AccessDenied("Keycloak session exceeded its absolute expiry")
		}
	} else {
		sshCert, tlsCert, err := s.a.CreateSessionCerts(ctx, &SessionCertsRequest{UserState: user, SessionTTL: ttl, SSHPubKey: req.SshPublicKey, TLSPubKey: req.TlsPublicKey, Compatibility: req.Compatibility, RouteToCluster: req.RouteToCluster, KubernetesCluster: req.KubernetesCluster, LoginIP: req.ClientLoginIP})
		if err != nil {
			return nil, trace.Wrap(err)
		}
		r.Cert, r.TLSCert = sshCert, tlsCert
		if err := keycloakCertificateExpiry(sshCert, tlsCert, expires); err != nil {
			return nil, trace.Wrap(err)
		}
		cluster, err := s.a.GetClusterName(ctx)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		ca, err := s.a.GetCertAuthority(ctx, types.CertAuthID{Type: types.HostCA, DomainName: cluster.GetClusterName()}, false)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		r.HostSigners = []types.CertAuthority{ca}
	}
	return r, nil
}

func keycloakSessionExpiry(sess types.WebSession, expires time.Time) error {
	if sess.GetExpiryTime().After(expires) {
		return trace.AccessDenied("Keycloak session exceeded its absolute expiry")
	}
	return keycloakCertificateExpiry(sess.GetPub(), sess.GetTLSCert(), expires)
}

func keycloakCertificateExpiry(sshCert, tlsCert []byte, expires time.Time) error {
	if len(sshCert) > 0 {
		pub, _, _, _, err := ssh.ParseAuthorizedKey(sshCert)
		if err != nil {
			return trace.AccessDenied("invalid Keycloak SSH certificate")
		}
		cert, ok := pub.(*ssh.Certificate)
		if !ok || cert.ValidBefore > uint64(expires.Unix()) {
			return trace.AccessDenied("Keycloak SSH certificate exceeded its absolute expiry")
		}
	}
	if len(tlsCert) > 0 {
		block, _ := pem.Decode(tlsCert)
		if block == nil {
			return trace.AccessDenied("invalid Keycloak TLS certificate")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil || cert.NotAfter.After(expires) {
			return trace.AccessDenied("Keycloak TLS certificate exceeded its absolute expiry")
		}
	}
	return nil
}
