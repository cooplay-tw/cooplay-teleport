// Copyright (C) 2026 Cooplay contributors.
// SPDX-License-Identifier: AGPL-3.0-or-later

package auth_test

import (
	"crypto/tls"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gravitational/trace"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"github.com/gravitational/teleport/api/client/proto"
	"github.com/gravitational/teleport/api/constants"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/api/utils/keys"
	"github.com/gravitational/teleport/lib/auth"
	"github.com/gravitational/teleport/lib/auth/authclient"
	"github.com/gravitational/teleport/lib/auth/authtest"
	"github.com/gravitational/teleport/lib/cryptosuites"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/tlsca"
)

// managedCoderFixture runs a managed daily-session connector whose mapped role
// carries the exact Coder application grant next to its SSH grant.
func managedCoderFixture(t *testing.T) (*keycloakFixture, *keycloakAdminFixture, auth.KeycloakLifecycleConfig, *authtest.TLSServer) {
	t.Helper()
	f, admin, cfg := managedKeycloakFixture(t, 86400)
	role := keycloakLabRole(t).(*types.RoleV6)
	role.Spec.Options.MaxSessionTTL = types.Duration(24 * time.Hour)
	role.Spec.Allow.AppLabels = types.Labels{"cooplay.dev/app": {"coder"}}
	_, err := f.a.AuthServer.UpsertRole(f.ctx, role)
	require.NoError(t, err)
	f.requestedTTL = 24 * time.Hour
	return f, admin, cfg, managedTLS(t, f)
}

type keycloakConsoleLogin struct {
	username string
	client   *authclient.Client
	identity tlsca.Identity
	marker   string
}

// managedConsoleLogin performs a tsh/Connect-style login and authenticates a
// native Auth client with the issued TLS certificate and its private key.
func managedConsoleLogin(t *testing.T, f *keycloakFixture, srv *authtest.TLSServer, sid string) keycloakConsoleLogin {
	t.Helper()
	key, err := cryptosuites.GenerateKeyWithAlgorithm(cryptosuites.ECDSAP256)
	require.NoError(t, err)
	sshPublic, err := ssh.NewPublicKey(key.Public())
	require.NoError(t, err)
	f.sshKey = ssh.MarshalAuthorizedKey(sshPublic)
	f.tlsKey, err = keys.MarshalPublicKey(key.Public())
	require.NoError(t, err)
	_, q := f.begin(t, false, func(c map[string]any) { c["sid"] = sid })
	response, err := f.svc.ValidateOIDCAuthCallback(f.ctx, q)
	require.NoError(t, err)
	privatePEM, err := keys.MarshalPrivateKey(key)
	require.NoError(t, err)
	certificate, err := tls.X509KeyPair(response.TLSCert, privatePEM)
	require.NoError(t, err)
	clt, err := srv.NewClientWithCert(certificate)
	require.NoError(t, err)
	t.Cleanup(func() { _ = clt.Close() })
	login := keycloakConsoleLogin{username: response.Username, client: clt, identity: parseKeycloakIdentity(t, response.TLSCert)}
	for _, role := range login.identity.Groups {
		if strings.HasPrefix(role, "keycloak-login-") {
			login.marker = role
		}
	}
	require.NotEmpty(t, login.marker)
	return login
}

func parseKeycloakIdentity(t *testing.T, certPEM []byte) tlsca.Identity {
	t.Helper()
	cert, err := tlsca.ParseCertificatePEM(certPEM)
	require.NoError(t, err)
	identity, err := tlsca.FromSubject(cert.Subject, cert.NotAfter)
	require.NoError(t, err)
	return *identity
}

// coderAppCert requests credentials the way VNet and `tsh proxy app` do: an
// in-memory (not written to disk) app certificate, which natively may use the
// full role TTL measured from now instead of the original login.
func coderAppCert(f *keycloakFixture, srv *authtest.TLSServer, login keycloakConsoleLogin) (*proto.Certs, error) {
	key, err := cryptosuites.GenerateKeyWithAlgorithm(cryptosuites.ECDSAP256)
	if err != nil {
		return nil, err
	}
	public, err := keys.MarshalPublicKey(key.Public())
	if err != nil {
		return nil, err
	}
	return login.client.GenerateUserCerts(f.ctx, proto.UserCertsRequest{
		Username:      login.username,
		TLSPublicKey:  public,
		Expires:       f.clock.Now().Add(48 * time.Hour),
		Usage:         proto.UserCertsRequest_App,
		RequesterName: proto.UserCertsRequest_TSH_APP_LOCAL_PROXY,
		RouteToApp: proto.RouteToApp{
			Name:        "coder",
			PublicAddr:  "coder.example.test",
			ClusterName: srv.ClusterName(),
		},
	})
}

// coderAppSession uses the web application launcher API.
func coderAppSession(f *keycloakFixture, srv *authtest.TLSServer, login keycloakConsoleLogin) (types.WebSession, error) {
	session, err := login.client.CreateAppSession(f.ctx, &proto.CreateAppSessionRequest{
		Username:    login.username,
		PublicAddr:  "coder.example.test",
		ClusterName: srv.ClusterName(),
		AppName:     "coder",
	})
	if err != nil {
		return nil, err
	}
	return f.a.AuthServer.GetAppSession(f.ctx, types.GetAppSessionRequest{SessionID: session.GetName()})
}

// keycloakAppCredentials returns the identities of an in-memory app certificate,
// its linked app session and a launcher app session, all from one login.
func keycloakAppCredentials(t *testing.T, f *keycloakFixture, srv *authtest.TLSServer, login keycloakConsoleLogin) []tlsca.Identity {
	t.Helper()
	certs, err := coderAppCert(f, srv, login)
	require.NoError(t, err)
	appIdentity := parseKeycloakIdentity(t, certs.TLS)
	require.Equal(t, "coder", appIdentity.RouteToApp.Name)
	linked, err := f.a.AuthServer.GetAppSession(f.ctx, types.GetAppSessionRequest{SessionID: appIdentity.RouteToApp.SessionID})
	require.NoError(t, err)
	launched, err := coderAppSession(f, srv, login)
	require.NoError(t, err)
	identities := []tlsca.Identity{appIdentity, parseKeycloakIdentity(t, linked.GetTLSCert()), parseKeycloakIdentity(t, launched.GetTLSCert())}
	for _, identity := range identities {
		// Every app credential carries the login marker and connector guard, so
		// native strict locks on either reach it exactly as they reach SSH.
		require.Subset(t, identity.Groups, login.identity.Groups)
		require.Equal(t, login.username, identity.Username)
	}
	return identities
}

func requireKeycloakLock(t *testing.T, f *keycloakFixture, identity tlsca.Identity, locked bool) {
	t.Helper()
	targets := slices.Collect(services.LockTargetsFromTLSIdentity(identity))
	require.Eventually(t, func() bool {
		err := f.a.LockWatcher.CheckLockInForce(constants.LockingModeStrict, targets...)
		return (err != nil) == locked
	}, 5*time.Second, 10*time.Millisecond, "app identity locked=%v expected", locked)
}

// TestKeycloakManagedAppCredentialsKeepLoginDeadline proves that every app
// certificate and app web session minted for a Keycloak login, through either
// resource-specific reissue (VNet, tsh proxy app, Connect) or the web launcher
// API, ends no later than the absolute login deadline and the stored user.
func TestKeycloakManagedAppCredentialsKeepLoginDeadline(t *testing.T) {
	f, _, _, srv := managedCoderFixture(t)
	login := managedConsoleLogin(t, f, srv, "sid-a")
	deadline := login.identity.Expires
	require.WithinDuration(t, f.clock.Now().Add(24*time.Hour), deadline, 5*time.Second)
	user, err := f.a.AuthServer.GetUser(f.ctx, login.username, false)
	require.NoError(t, err)
	require.False(t, deadline.After(user.Expiry()))

	// Natively, an in-memory app certificate requested now could last a full
	// role TTL from now, two hours past the original login deadline.
	f.clock.Advance(2 * time.Hour)
	require.NoError(t, auth.ReconcileKeycloak(f.ctx, f.svc))
	requireBounded := func(t *testing.T, limit time.Time) {
		t.Helper()
		certs, err := coderAppCert(f, srv, login)
		require.NoError(t, err)
		appIdentity := parseKeycloakIdentity(t, certs.TLS)
		require.True(t, appIdentity.Expires.After(f.clock.Now()), "app certificate must remain usable")
		require.False(t, appIdentity.Expires.After(limit), "app certificate %v exceeds %v", appIdentity.Expires, limit)
		linked, err := f.a.AuthServer.GetAppSession(f.ctx, types.GetAppSessionRequest{SessionID: appIdentity.RouteToApp.SessionID})
		require.NoError(t, err)
		require.False(t, linked.GetExpiryTime().After(limit), "linked app session exceeds the login deadline")
		require.False(t, parseKeycloakIdentity(t, linked.GetTLSCert()).Expires.After(limit))

		launched, err := coderAppSession(f, srv, login)
		require.NoError(t, err)
		require.True(t, launched.GetExpiryTime().After(f.clock.Now()), "launcher session must remain usable")
		require.False(t, launched.GetExpiryTime().After(limit), "launcher app session %v exceeds %v", launched.GetExpiryTime(), limit)
		launchedIdentity := parseKeycloakIdentity(t, launched.GetTLSCert())
		require.False(t, launchedIdentity.Expires.After(limit))
		require.Subset(t, launchedIdentity.Groups, login.identity.Groups)
	}
	t.Run("original login deadline", func(t *testing.T) { requireBounded(t, deadline) })

	// A newer, shorter login lowers the stored user's expiry (the user resource
	// is deleted then). Older credentials must not outlive it, including web
	// launcher sessions whose native TTL only follows the caller certificate.
	f.requestedTTL = time.Hour
	managedConsoleLogin(t, f, srv, "sid-b")
	user, err = f.a.AuthServer.GetUser(f.ctx, login.username, false)
	require.NoError(t, err)
	require.True(t, user.Expiry().Before(deadline))
	t.Run("stored user expiry", func(t *testing.T) { requireBounded(t, user.Expiry()) })
}

// TestKeycloakManagedAppCredentialRevocation proves that the native strict
// locks the connector already uses for SSH also cover every app certificate
// and app web session of the affected login(s), that Auth refuses to mint new
// ones synchronously from durable revocation state, and that re-enabling a
// disabled subject never resurrects them.
func TestKeycloakManagedAppCredentialRevocation(t *testing.T) {
	for _, reason := range []string{"current logout", "backchannel logout", "missed logout", "group removed", "disabled", "outage"} {
		t.Run(reason, func(t *testing.T) {
			f, admin, cfg, srv := managedCoderFixture(t)
			first := managedConsoleLogin(t, f, srv, "sid-a")
			other := managedConsoleLogin(t, f, srv, "sid-b")
			firstApps := keycloakAppCredentials(t, f, srv, first)
			otherApps := keycloakAppCredentials(t, f, srv, other)
			for _, identity := range append(slices.Clone(firstApps), otherApps...) {
				requireKeycloakLock(t, f, identity, false)
			}

			switch reason {
			case "current logout":
				require.NoError(t, first.client.KeycloakLogout(f.ctx, authclient.KeycloakLogoutRequest{}))
			case "backchannel logout":
				proxy, err := srv.NewClient(authtest.TestBuiltin(types.RoleProxy))
				require.NoError(t, err)
				defer proxy.Close()
				raw, err := signKeycloakToken(map[string]any{"iss": f.idp.URL + "/realms/lab", "aud": "teleport-lab", "iat": f.clock.Now().Unix(), "jti": "app-logout", "sid": "sid-a", "sub": "immutable-subject", "events": map[string]any{"http://schemas.openid.net/event/backchannel-logout": map[string]any{}}}, f.key)
				require.NoError(t, err)
				require.NoError(t, proxy.KeycloakLogout(f.ctx, authclient.KeycloakLogoutRequest{ConnectorID: "keycloak-lab", LogoutToken: raw}))
			case "missed logout":
				admin.ended.Store(true)
			case "group removed":
				admin.removed.Store(true)
			case "disabled":
				admin.disabled.Store(true)
			case "outage":
				admin.unavailable.Store(true)
				f.clock.Advance(3 * time.Second)
			}
			if reason == "outage" {
				require.Error(t, auth.ReconcileKeycloak(f.ctx, f.svc))
			} else {
				require.NoError(t, auth.ReconcileKeycloak(f.ctx, f.svc))
			}

			// Every login holding the removed group, the whole disabled account
			// or every login of a fenced connector is affected; logout variants
			// affect only the first login.
			otherRevoked := reason == "group removed" || reason == "disabled" || reason == "outage"
			for _, identity := range firstApps {
				requireKeycloakLock(t, f, identity, true)
			}
			for _, identity := range otherApps {
				requireKeycloakLock(t, f, identity, otherRevoked)
			}
			// Durable state denies new app credentials immediately, without
			// waiting for lock propagation to the Auth cache.
			_, err := coderAppCert(f, srv, first)
			require.True(t, trace.IsAccessDenied(err), "app certificate after %s: %v", reason, err)
			_, err = coderAppSession(f, srv, first)
			require.True(t, trace.IsAccessDenied(err), "launcher session after %s: %v", reason, err)
			if !otherRevoked {
				keycloakAppCredentials(t, f, srv, other)
				return
			}
			if reason == "outage" {
				// The connector guard is a fence, not a revocation: fresh
				// authoritative reconciliation restores existing credentials.
				admin.unavailable.Store(false)
				require.NoError(t, auth.ReconcileKeycloak(f.ctx, f.svc))
				for _, identity := range append(slices.Clone(firstApps), otherApps...) {
					requireKeycloakLock(t, f, identity, false)
				}
				keycloakAppCredentials(t, f, srv, first)
				return
			}

			// Restoring IdP state and restarting Auth never resurrects access.
			admin.disabled.Store(false)
			admin.removed.Store(false)
			f.svc, err = auth.NewManagedKeycloakService(f.a.AuthServer, cfg)
			require.NoError(t, err)
			f.a.AuthServer.SetOIDCService(f.svc)
			require.NoError(t, auth.ReconcileKeycloak(f.ctx, f.svc))
			for _, identity := range append(slices.Clone(firstApps), otherApps...) {
				requireKeycloakLock(t, f, identity, true)
			}
			_, err = coderAppCert(f, srv, first)
			require.True(t, trace.IsAccessDenied(err), "re-enabled IdP state reissued an app certificate: %v", err)
			_, err = coderAppSession(f, srv, other)
			require.True(t, trace.IsAccessDenied(err), "re-enabled IdP state created a launcher session: %v", err)
			_, q := f.begin(t, false, func(c map[string]any) { c["sid"] = "sid-new" })
			_, err = f.svc.ValidateOIDCAuthCallback(f.ctx, q)
			if reason == "disabled" {
				require.Error(t, err, "re-enabling the same subject must not permit a fresh login")
				return
			}
			// A restored group may authorize a fresh login; that new login's
			// credentials are separate from the permanently locked old markers.
			require.NoError(t, err)
		})
	}
}
