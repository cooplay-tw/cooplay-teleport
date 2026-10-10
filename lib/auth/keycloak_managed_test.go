// Copyright (C) 2026 Cooplay contributors.
// SPDX-License-Identifier: AGPL-3.0-or-later
package auth_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/auth"
	"github.com/gravitational/teleport/lib/auth/authclient"
	"github.com/gravitational/teleport/lib/auth/authtest"
	"github.com/gravitational/teleport/lib/backend"
	"github.com/gravitational/teleport/lib/cooplay/secrets"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/tlsca"
	"github.com/stretchr/testify/require"
)

type keycloakAdminFixture struct{ disabled, removed, unavailable, ended, brokenSessions atomic.Bool }

func managedKeycloakFixture(t *testing.T, sessionSeconds ...int) (*keycloakFixture, *keycloakAdminFixture, auth.KeycloakLifecycleConfig) {
	t.Helper()
	f := newKeycloakFixture(t)
	admin := &keycloakAdminFixture{}
	f.adminHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if admin.unavailable.Load() {
			w.WriteHeader(503)
			return
		}
		if r.URL.Path == "/realms/lab/protocol/openid-connect/token" {
			id, secret, ok := r.BasicAuth()
			if !ok || id != "sync-lab" || secret != keycloakTestSecret {
				w.WriteHeader(401)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "admin-fixture-only"})
			return
		}
		if r.Header.Get("Authorization") != "Bearer admin-fixture-only" || r.Method != http.MethodGet {
			w.WriteHeader(403)
			return
		}
		switch r.URL.Path {
		case "/admin/realms/lab/users/count":
			_, _ = w.Write([]byte(`1`))
		case "/admin/realms/lab/users/immutable-subject/sessions":
			if admin.brokenSessions.Load() {
				_, _ = w.Write([]byte(`null`))
				return
			}
			sessions := []map[string]any{}
			for _, sid := range []string{"sid-a", "sid-b", "sid-c", "sid-new"} {
				if admin.ended.Load() && sid == "sid-a" {
					continue
				}
				sessions = append(sessions, map[string]any{"id": sid, "userId": "immutable-subject", "clients": map[string]string{"uuid": "teleport-lab"}})
			}
			_ = json.NewEncoder(w).Encode(sessions)
		case "/admin/realms/lab/users/immutable-subject":
			_ = json.NewEncoder(w).Encode(map[string]any{"id": "immutable-subject", "enabled": !admin.disabled.Load()})
		case "/admin/realms/lab/users/immutable-subject/groups":
			if admin.removed.Load() {
				_, _ = w.Write([]byte(`[]`))
			} else {
				_, _ = w.Write([]byte(`[{"path":"/lab/operators"}]`))
			}
		default:
			w.WriteHeader(404)
		}
	})
	dir := t.TempDir()
	secret := filepath.Join(dir, "secret")
	ca := filepath.Join(dir, "ca.pem")
	require.NoError(t, os.WriteFile(secret, []byte(keycloakTestSecret), 0600))
	require.NoError(t, os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.idp.Certificate().Raw}), 0600))
	cfg := auth.KeycloakLifecycleConfig{CAFile: ca, RevocationJournalDir: filepath.Join(dir, "journal"), PollSeconds: 1, MaxStaleSeconds: 2, Connectors: map[string]auth.KeycloakLifecycleConnector{"keycloak-lab": {Issuer: f.idp.URL + "/realms/lab", ClientID: "teleport-lab", AdminURL: f.idp.URL + "/admin/realms/lab", ClientSecret: secrets.Reference{File: secret}, AdminClientID: "sync-lab", AdminClientSecret: secrets.Reference{File: secret}}}}
	if len(sessionSeconds) != 0 {
		cfg.MaxSessionSeconds = sessionSeconds[0]
		role := keycloakLabRole(t).(*types.RoleV6)
		role.Spec.Options.MaxSessionTTL = types.Duration(time.Duration(sessionSeconds[0]) * time.Second)
		_, err := f.a.AuthServer.UpsertRole(f.ctx, role)
		require.NoError(t, err)
	}
	var err error
	f.svc, err = auth.NewManagedKeycloakService(f.a.AuthServer, cfg)
	require.NoError(t, err)
	f.a.AuthServer.SetOIDCService(f.svc)
	require.NoError(t, auth.ReconcileKeycloak(f.ctx, f.svc))
	return f, admin, cfg
}

func managedLogin(t *testing.T, f *keycloakFixture, sid string) (*authclient.OIDCAuthResponse, []string) {
	t.Helper()
	_, q := f.begin(t, true, func(c map[string]any) { c["sid"] = sid })
	result, err := f.svc.ValidateOIDCAuthCallback(f.ctx, q)
	require.NoError(t, err)
	cert, err := tlsca.ParseCertificatePEM(result.Session.GetTLSCert())
	require.NoError(t, err)
	identity, err := tlsca.FromSubject(cert.Subject, cert.NotAfter)
	require.NoError(t, err)
	require.Len(t, identity.Groups, 3)
	var parsed []types.Role
	for _, name := range identity.Groups {
		role, err := f.a.AuthServer.GetRole(f.ctx, name)
		require.NoError(t, err)
		parsed = append(parsed, role)
	}
	roleSet := services.NewRoleSet(parsed...)
	require.False(t, roleSet.CanCopyFiles(), "marker cannot enable file transfer")
	require.False(t, roleSet.CanForwardAgents(), "marker cannot enable SSH agent forwarding")
	require.False(t, roleSet.CanPortForward(), "marker cannot enable port forwarding")
	return result, identity.Groups
}

func TestKeycloakManagedDisablePersistsAcrossServiceRestart(t *testing.T) {
	for _, reason := range []string{"disabled", "group removed"} {
		t.Run(reason, func(t *testing.T) {
			f, admin, cfg := managedKeycloakFixture(t)
			login, roles := managedLogin(t, f, "sid-a")
			if reason == "disabled" {
				admin.disabled.Store(true)
			} else {
				admin.removed.Store(true)
			}
			target := types.LockTarget{User: login.Username}
			kind, id := "users", login.Username
			if reason != "disabled" {
				for _, role := range roles {
					if strings.HasPrefix(role, "keycloak-login-") {
						target = types.LockTarget{Role: role}
						kind, id = "roles", role
					}
				}
			}
			require.NoError(t, auth.ReconcileKeycloak(f.ctx, f.svc))
			locks, err := f.a.AuthServer.GetLocks(f.ctx, false, target)
			require.NoError(t, err)
			require.Len(t, locks, 1)
			require.NoError(t, auth.ReconcileKeycloak(f.ctx, f.svc))
			second, err := f.a.AuthServer.GetLocks(f.ctx, false, target)
			require.NoError(t, err)
			require.Len(t, second, 1)
			// Simulate restoring a snapshot predating revocation. The separate
			// journal is retained and must restore the lost backend tombstone.
			require.NoError(t, f.a.Backend.Delete(f.ctx, backend.NewKey("cooplay", "keycloak", "lifecycle", "revocations", kind, id)))
			// Even an accidental native lock deletion cannot erase durable intent.
			require.NoError(t, f.a.AuthServer.DeleteLock(f.ctx, locks[0].GetName()))
			f.svc, err = auth.NewManagedKeycloakService(f.a.AuthServer, cfg)
			require.NoError(t, err)
			startupLocks, err := f.a.AuthServer.GetLocks(f.ctx, false, target)
			require.NoError(t, err)
			require.Len(t, startupLocks, 1, "startup must restore native locks before any background pass")
			f.a.AuthServer.SetOIDCService(f.svc)
			admin.disabled.Store(false)
			admin.removed.Store(false)
			require.NoError(t, auth.ReconcileKeycloak(f.ctx, f.svc))
			locks, err = f.a.AuthServer.GetLocks(f.ctx, false, target)
			require.NoError(t, err)
			require.Len(t, locks, 1)
			_, q := f.begin(t, true, func(c map[string]any) { c["sid"] = "sid-new" })
			_, err = f.svc.ValidateOIDCAuthCallback(f.ctx, q)
			if reason == "disabled" {
				require.Error(t, err)
			} else {
				require.NoError(t, err, "fresh membership validation may create new credentials; old marker stays locked")
			}
		})
	}
}

func TestKeycloakManagedOutageFailsClosedAndRecovers(t *testing.T) {
	f, admin, _ := managedKeycloakFixture(t)
	_, roles := managedLogin(t, f, "sid-a")
	require.NoError(t, auth.ReconcileKeycloak(f.ctx, f.svc))
	admin.unavailable.Store(true)
	f.clock.Advance(3 * time.Second)
	require.Error(t, auth.ReconcileKeycloak(f.ctx, f.svc))
	var guard string
	for _, r := range roles {
		if strings.HasPrefix(r, "keycloak-guard-") {
			guard = r
		}
	}
	locks, err := f.a.AuthServer.GetLocks(f.ctx, false, types.LockTarget{Role: guard})
	require.NoError(t, err)
	require.Len(t, locks, 1)
	_, q := f.begin(t, true, func(c map[string]any) { c["sid"] = "sid-b" })
	_, err = f.svc.ValidateOIDCAuthCallback(f.ctx, q)
	require.Error(t, err)
	admin.unavailable.Store(false)
	require.NoError(t, auth.ReconcileKeycloak(f.ctx, f.svc))
	locks, err = f.a.AuthServer.GetLocks(f.ctx, false, types.LockTarget{Role: guard})
	require.NoError(t, err)
	require.Empty(t, locks)
}

func managedTLS(t *testing.T, f *keycloakFixture) *authtest.TLSServer {
	t.Helper()
	t.Setenv("TELEPORT_UNSTABLE_KEYCLOAK", "yes")
	srv, err := f.a.NewTestTLSServer()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, srv.Close()) })
	return srv
}

func TestKeycloakManagedCurrentLogoutIsolation(t *testing.T) {
	f, _, _ := managedKeycloakFixture(t)
	first, firstRoles := managedLogin(t, f, "sid-a")
	second, secondRoles := managedLogin(t, f, "sid-b")
	srv := managedTLS(t, f)
	one, err := srv.NewClientFromWebSession(first.Session)
	require.NoError(t, err)
	defer one.Close()
	two, err := srv.NewClientFromWebSession(second.Session)
	require.NoError(t, err)
	defer two.Close()
	require.NoError(t, one.KeycloakLogout(f.ctx, authclient.KeycloakLogoutRequest{}))
	for _, role := range firstRoles {
		if strings.HasPrefix(role, "keycloak-login-") {
			locks, err := f.a.AuthServer.GetLocks(f.ctx, false, types.LockTarget{Role: role})
			require.NoError(t, err)
			require.Len(t, locks, 1)
		}
	}
	for _, role := range secondRoles {
		if strings.HasPrefix(role, "keycloak-login-") {
			locks, err := f.a.AuthServer.GetLocks(f.ctx, false, types.LockTarget{Role: role})
			require.NoError(t, err)
			require.Empty(t, locks)
		}
	}
	_, err = two.GetUser(f.ctx, second.Username, false)
	require.NoError(t, err)
	_, q := f.begin(t, true, func(c map[string]any) { c["sid"] = "sid-c" })
	_, err = f.svc.ValidateOIDCAuthCallback(f.ctx, q)
	require.NoError(t, err, "current logout must not disable account")
}

func TestKeycloakManagedBackchannelValidationAndReplay(t *testing.T) {
	f, _, _ := managedKeycloakFixture(t)
	first, _ := managedLogin(t, f, "sid-a")
	_, otherRoles := managedLogin(t, f, "sid-b")
	srv := managedTLS(t, f)
	proxy, err := srv.NewClient(authtest.TestBuiltin(types.RoleProxy))
	require.NoError(t, err)
	defer proxy.Close()
	claims := func() map[string]any {
		return map[string]any{"iss": f.idp.URL + "/realms/lab", "aud": "teleport-lab", "iat": f.clock.Now().Unix(), "jti": "logout-one", "sid": "sid-a", "sub": "immutable-subject", "events": map[string]any{"http://schemas.openid.net/event/backchannel-logout": map[string]any{}}}
	}
	for name, edit := range map[string]func(map[string]any){
		"nonce": func(c map[string]any) { c["nonce"] = "" }, "audience": func(c map[string]any) { c["aud"] = "other" }, "missing event": func(c map[string]any) { delete(c, "events") }, "expired": func(c map[string]any) { c["exp"] = f.clock.Now().Add(-time.Minute).Unix() }, "stale": func(c map[string]any) { c["iat"] = f.clock.Now().Add(-10 * time.Minute).Unix() }, "missing jti": func(c map[string]any) { delete(c, "jti") }, "no target": func(c map[string]any) { delete(c, "sid"); delete(c, "sub") },
	} {
		t.Run(name, func(t *testing.T) {
			c := claims()
			edit(c)
			raw, err := signKeycloakToken(c, f.key)
			require.NoError(t, err)
			require.Error(t, proxy.KeycloakLogout(f.ctx, authclient.KeycloakLogoutRequest{ConnectorID: "keycloak-lab", LogoutToken: raw}))
		})
	}
	raw, err := signKeycloakToken(claims(), f.key)
	require.NoError(t, err)
	req := authclient.KeycloakLogoutRequest{ConnectorID: "keycloak-lab", LogoutToken: raw}
	for _, role := range []types.SystemRole{types.RoleNode, types.RoleAdmin} {
		caller, err := srv.NewClient(authtest.TestBuiltin(role))
		require.NoError(t, err)
		require.Error(t, caller.KeycloakLogout(f.ctx, req), "only Proxy may submit a back-channel notification")
		require.NoError(t, caller.Close())
	}
	require.NoError(t, proxy.KeycloakLogout(f.ctx, req))
	require.NoError(t, proxy.KeycloakLogout(f.ctx, req), "identical retry resumes idempotently")
	changed := claims()
	changed["sid"] = "sid-b"
	req.LogoutToken, err = signKeycloakToken(changed, f.key)
	require.NoError(t, err)
	require.Error(t, proxy.KeycloakLogout(f.ctx, req), "jti reuse with another payload must fail")
	for _, role := range otherRoles {
		if strings.HasPrefix(role, "keycloak-login-") {
			locks, err := f.a.AuthServer.GetLocks(f.ctx, false, types.LockTarget{Role: role})
			require.NoError(t, err)
			require.Empty(t, locks)
		}
	}
	locks, err := f.a.AuthServer.GetLocks(f.ctx, false, types.LockTarget{User: first.Username})
	require.NoError(t, err)
	require.Empty(t, locks)
	_, q := f.begin(t, true, func(c map[string]any) { c["sid"] = "sid-a" })
	_, err = f.svc.ValidateOIDCAuthCallback(f.ctx, q)
	require.Error(t, err, "logout arriving before callback must prevent issuance")
}

// A previously healthy backend must not make a restarted Auth trust old health.
// A missed IdP notification is recovered using read-only client session state.
func TestKeycloakManagedStartupFenceAndMissedLogout(t *testing.T) {
	f, admin, cfg := managedKeycloakFixture(t)
	first, roles := managedLogin(t, f, "sid-a")
	_, independent := managedLogin(t, f, "sid-b")
	restarted, err := auth.NewManagedKeycloakService(f.a.AuthServer, cfg)
	require.NoError(t, err)
	f.svc = restarted
	f.a.AuthServer.SetOIDCService(restarted)
	var guard, marker string
	for _, r := range roles {
		if strings.HasPrefix(r, "keycloak-guard-") {
			guard = r
		}
		if strings.HasPrefix(r, "keycloak-login-") {
			marker = r
		}
	}
	locks, err := f.a.AuthServer.GetLocks(f.ctx, false, types.LockTarget{Role: guard})
	require.NoError(t, err)
	require.Len(t, locks, 1, "constructor must fence before background reconciliation")
	admin.unavailable.Store(true)
	require.Error(t, auth.ReconcileKeycloak(f.ctx, f.svc))
	_, q := f.begin(t, true, func(c map[string]any) { c["sid"] = "sid-new" })
	_, err = f.svc.ValidateOIDCAuthCallback(f.ctx, q)
	require.Error(t, err)
	admin.unavailable.Store(false)
	admin.ended.Store(true)
	require.NoError(t, auth.ReconcileKeycloak(f.ctx, f.svc))
	locks, err = f.a.AuthServer.GetLocks(f.ctx, false, types.LockTarget{Role: marker})
	require.NoError(t, err)
	require.Len(t, locks, 1)
	require.Contains(t, locks[0].Message(), "idp-session-ended")
	locks, err = f.a.AuthServer.GetLocks(f.ctx, false, types.LockTarget{Role: guard})
	require.NoError(t, err)
	require.Empty(t, locks)
	for _, role := range independent {
		locks, err = f.a.AuthServer.GetLocks(f.ctx, false, types.LockTarget{Role: role})
		require.NoError(t, err)
		require.Empty(t, locks, "independent active login survives")
	}
	locks, err = f.a.AuthServer.GetLocks(f.ctx, false, types.LockTarget{User: first.Username})
	require.NoError(t, err)
	require.Empty(t, locks, "session logout never suspends account")
	_, q = f.begin(t, true, func(c map[string]any) { c["sid"] = "sid-a" })
	_, err = f.svc.ValidateOIDCAuthCallback(f.ctx, q)
	require.Error(t, err, "ended session cannot finish callback")
	managedLogin(t, f, "sid-new")
}

func TestKeycloakManagedEmptyHealthAndMalformedSession(t *testing.T) {
	f, admin, _ := managedKeycloakFixture(t)
	admin.unavailable.Store(true)
	f.clock.Advance(3 * time.Second)
	require.Error(t, auth.ReconcileKeycloak(f.ctx, f.svc), "zero users must still probe private Admin API")
	admin.unavailable.Store(false)
	require.NoError(t, auth.ReconcileKeycloak(f.ctx, f.svc))
	_, roles := managedLogin(t, f, "sid-a")
	admin.brokenSessions.Store(true)
	require.Error(t, auth.ReconcileKeycloak(f.ctx, f.svc))
	for _, role := range roles {
		if strings.HasPrefix(role, "keycloak-login-") {
			locks, err := f.a.AuthServer.GetLocks(f.ctx, false, types.LockTarget{Role: role})
			require.NoError(t, err)
			require.Empty(t, locks, "null/partial API data cannot become durable logout")
		}
	}
}

func TestKeycloakManagedPrivateAdminOrigin(t *testing.T) {
	f, _, cfg := managedKeycloakFixture(t)
	original := f.adminHandler
	private := httptest.NewTLSServer(original)
	t.Cleanup(private.Close)
	f.adminHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/admin/") {
			w.WriteHeader(403)
			return
		}
		original.ServeHTTP(w, r)
	})
	ca, err := os.OpenFile(cfg.CAFile, os.O_APPEND|os.O_WRONLY, 0600)
	require.NoError(t, err)
	_, err = ca.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: private.Certificate().Raw}))
	require.NoError(t, err)
	require.NoError(t, ca.Close())
	connector := cfg.Connectors["keycloak-lab"]
	connector.AdminURL = private.URL + "/admin/realms/lab"
	cfg.Connectors["keycloak-lab"] = connector
	f.svc, err = auth.NewManagedKeycloakService(f.a.AuthServer, cfg)
	require.NoError(t, err)
	f.a.AuthServer.SetOIDCService(f.svc)
	require.NoError(t, auth.ReconcileKeycloak(f.ctx, f.svc))
	managedLogin(t, f, "sid-a")
	// The private origin is explicit, but its redirects must never forward the
	// service bearer to another endpoint (even if that endpoint has trusted TLS).
	var forwarded atomic.Int32
	sink := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { forwarded.Add(1) }))
	t.Cleanup(sink.Close)
	redirect := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, sink.URL+"/users/count", http.StatusTemporaryRedirect)
	}))
	t.Cleanup(redirect.Close)
	connector.AdminURL = redirect.URL + "/admin/realms/lab"
	cfg.Connectors["keycloak-lab"] = connector
	redirectService, err := auth.NewManagedKeycloakService(f.a.AuthServer, cfg)
	require.NoError(t, err)
	require.Error(t, auth.ReconcileKeycloak(f.ctx, redirectService))
	require.Zero(t, forwarded.Load(), "Admin redirect must not forward credentials")
	// This second service presents an untrusted CA. No insecure TLS fallback.
	untrusted := httptest.NewUnstartedServer(original)
	untrusted.TLS = &tls.Config{Certificates: []tls.Certificate{privateCertificate(t)}}
	untrusted.StartTLS()
	t.Cleanup(untrusted.Close)
	connector.AdminURL = untrusted.URL + "/admin/realms/lab"
	cfg.Connectors["keycloak-lab"] = connector
	denied, err := auth.NewManagedKeycloakService(f.a.AuthServer, cfg)
	require.NoError(t, err)
	require.Error(t, auth.ReconcileKeycloak(f.ctx, denied))
	for _, invalid := range []string{"http://localhost/admin/realms/lab", private.URL + "/admin/realms/other", private.URL + "/admin/realms/lab?x=1", private.URL + "/admin/realms/%6cab", private.URL + "/admin/realms/lab/../lab"} {
		connector.AdminURL = invalid
		cfg.Connectors["keycloak-lab"] = connector
		_, err = auth.NewManagedKeycloakService(f.a.AuthServer, cfg)
		require.Error(t, err)
	}
}

func privateCertificate(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "untrusted"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	raw, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	require.NoError(t, err)
	return tls.Certificate{Certificate: [][]byte{raw}, PrivateKey: key}
}

// A short-lived ID token is consumed at authentication. Explicit managed
// sessions remain bounded and revocable after that token has expired.
func TestKeycloakManagedDailySession(t *testing.T) {
	for _, reason := range []string{"missed logout", "disabled", "outage", "backchannel", "group removed"} {
		t.Run(reason, func(t *testing.T) {
			f, admin, cfg := managedKeycloakFixture(t, 86400)
			f.requestedTTL = 24 * time.Hour
			first, roles := managedLogin(t, f, "sid-a")
			expires := first.Session.GetExpiryTime()
			require.WithinDuration(t, f.clock.Now().Add(24*time.Hour), expires, 5*time.Second)
			var marker, guard string
			for _, name := range roles {
				role, err := f.a.AuthServer.GetRole(f.ctx, name)
				require.NoError(t, err)
				require.Equal(t, 24*time.Hour, role.GetOptions().MaxSessionTTL.Duration())
				if strings.HasPrefix(name, "keycloak-login-") {
					marker = name
				}
				if strings.HasPrefix(name, "keycloak-guard-") {
					guard = name
				}
			}
			f.clock.Advance(6 * time.Minute)
			require.NoError(t, auth.ReconcileKeycloak(f.ctx, f.svc))
			locks, err := f.a.AuthServer.GetLocks(f.ctx, false, types.LockTarget{Role: marker}, types.LockTarget{Role: guard})
			require.NoError(t, err)
			require.Empty(t, locks, "original token expiry is not IdP logout")
			target := types.LockTarget{Role: marker}
			switch reason {
			case "missed logout":
				admin.ended.Store(true)
			case "disabled":
				admin.disabled.Store(true)
				target = types.LockTarget{User: first.Username}
			case "group removed":
				admin.removed.Store(true)
			case "outage":
				admin.unavailable.Store(true)
				f.clock.Advance(3 * time.Second)
				target = types.LockTarget{Role: guard}
			case "backchannel":
				srv := managedTLS(t, f)
				proxy, err := srv.NewClient(authtest.TestBuiltin(types.RoleProxy))
				require.NoError(t, err)
				defer proxy.Close()
				raw, err := signKeycloakToken(map[string]any{"iss": f.idp.URL + "/realms/lab", "aud": "teleport-lab", "iat": f.clock.Now().Unix(), "jti": "daily-logout", "sid": "sid-a", "sub": "immutable-subject", "events": map[string]any{"http://schemas.openid.net/event/backchannel-logout": map[string]any{}}}, f.key)
				require.NoError(t, err)
				require.NoError(t, proxy.KeycloakLogout(f.ctx, authclient.KeycloakLogoutRequest{ConnectorID: "keycloak-lab", LogoutToken: raw}))
			}
			err = auth.ReconcileKeycloak(f.ctx, f.svc)
			if reason == "outage" {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			locks, err = f.a.AuthServer.GetLocks(f.ctx, false, target)
			require.NoError(t, err)
			require.Len(t, locks, 1)
			require.True(t, f.clock.Now().Before(expires), "lock must precede session expiry")
			// Restart replays durable intent; restoring IdP availability/status
			// must never resurrect an ended login or permanently disabled user.
			f.svc, err = auth.NewManagedKeycloakService(f.a.AuthServer, cfg)
			require.NoError(t, err)
			f.a.AuthServer.SetOIDCService(f.svc)
			admin.unavailable.Store(false)
			admin.disabled.Store(false)
			admin.removed.Store(false)
			require.NoError(t, auth.ReconcileKeycloak(f.ctx, f.svc))
			locks, err = f.a.AuthServer.GetLocks(f.ctx, false, target)
			require.NoError(t, err)
			if reason == "outage" {
				require.Empty(t, locks)
			} else {
				require.Len(t, locks, 1)
			}
		})
	}
}

func TestKeycloakManagedDailySessionRejectsStaleIdentity(t *testing.T) {
	f, _, _ := managedKeycloakFixture(t, 86400)
	for _, remaining := range []time.Duration{-time.Minute, 30 * time.Second} {
		_, q := f.begin(t, true, func(c map[string]any) { c["sid"] = "sid-a"; c["exp"] = f.clock.Now().Add(remaining).Unix() })
		_, err := f.svc.ValidateOIDCAuthCallback(f.ctx, q)
		require.Error(t, err)
	}
	for _, seconds := range []int{-1, 299, 86401} {
		_, err := auth.NewManagedKeycloakService(f.a.AuthServer, auth.KeycloakLifecycleConfig{MaxSessionSeconds: seconds})
		require.ErrorContains(t, err, "max_session_seconds")
	}
	for _, requested := range []time.Duration{0, 48 * time.Hour} {
		req := f.request(true)
		req.CertTTL = requested
		actual, err := f.svc.CreateOIDCAuthRequest(f.ctx, req)
		require.NoError(t, err)
		require.Equal(t, 24*time.Hour, actual.CertTTL)
	}
}

func TestKeycloakManagedDailySessionMigratesOnlyMarkerTTL(t *testing.T) {
	f, _, cfg := managedKeycloakFixture(t)
	_, oldRoles := managedLogin(t, f, "sid-a")
	cfg.MaxSessionSeconds = 86400
	role := keycloakLabRole(t).(*types.RoleV6)
	role.Spec.Options.MaxSessionTTL = types.Duration(24 * time.Hour)
	_, err := f.a.AuthServer.UpsertRole(f.ctx, role)
	require.NoError(t, err)
	f.svc, err = auth.NewManagedKeycloakService(f.a.AuthServer, cfg)
	require.NoError(t, err)
	f.a.AuthServer.SetOIDCService(f.svc)
	require.NoError(t, auth.ReconcileKeycloak(f.ctx, f.svc))
	login, _ := managedLogin(t, f, "sid-b")
	require.WithinDuration(t, f.clock.Now().Add(time.Hour), login.Session.GetExpiryTime(), 5*time.Second)
	for _, name := range oldRoles {
		if !strings.HasPrefix(name, "keycloak-login-") {
			continue
		}
		old, err := f.a.AuthServer.GetRole(f.ctx, name)
		require.NoError(t, err)
		require.Equal(t, 5*time.Minute, old.GetOptions().MaxSessionTTL.Duration(), "old login is not extended")
	}
}
