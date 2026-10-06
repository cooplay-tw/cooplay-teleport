// Copyright (C) 2026 Cooplay contributors.
// SPDX-License-Identifier: AGPL-3.0-or-later
package auth_test

import (
	"encoding/json"
	"encoding/pem"
	"net/http"
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

type keycloakAdminFixture struct{ disabled, removed, unavailable atomic.Bool }

func managedKeycloakFixture(t *testing.T) (*keycloakFixture, *keycloakAdminFixture, auth.KeycloakLifecycleConfig) {
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
	cfg := auth.KeycloakLifecycleConfig{CAFile: ca, RevocationJournalDir: filepath.Join(dir, "journal"), PollSeconds: 1, MaxStaleSeconds: 2, Connectors: map[string]auth.KeycloakLifecycleConnector{"keycloak-lab": {Issuer: f.idp.URL + "/realms/lab", ClientSecret: secrets.Reference{File: secret}, AdminClientID: "sync-lab", AdminClientSecret: secrets.Reference{File: secret}}}}
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
