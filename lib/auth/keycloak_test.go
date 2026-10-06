// Copyright (C) 2026 Cooplay contributors.
// SPDX-License-Identifier: AGPL-3.0-or-later

package auth_test

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gravitational/trace"
	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"sigs.k8s.io/yaml"

	"github.com/gravitational/teleport/api/constants"
	"github.com/gravitational/teleport/api/types"
	apievents "github.com/gravitational/teleport/api/types/events"
	"github.com/gravitational/teleport/api/utils/keys"
	"github.com/gravitational/teleport/lib/auth"
	"github.com/gravitational/teleport/lib/auth/authtest"
	"github.com/gravitational/teleport/lib/events"
	"github.com/gravitational/teleport/lib/events/eventstest"
	"github.com/gravitational/teleport/lib/services"
)

const keycloakTestSecret = "fixture-client-secret-not-a-real-credential"

type keycloakCode struct {
	claims    map[string]any
	challenge string
	key       *rsa.PrivateKey
}

type keycloakFixture struct {
	ctx          context.Context
	clock        *clockwork.FakeClock
	a            *authtest.AuthServer
	svc          auth.OIDCService
	idp          *httptest.Server
	key          *rsa.PrivateKey
	connector    types.OIDCConnector
	emitter      *eventstest.MockRecorderEmitter
	sshKey       []byte
	tlsKey       []byte
	mu           sync.Mutex
	codes        map[string]keycloakCode
	sequence     atomic.Int64
	exchanges    atomic.Int64
	adminHandler http.Handler
}

func newKeycloakFixture(t *testing.T) *keycloakFixture {
	t.Helper()
	f := &keycloakFixture{clock: clockwork.NewFakeClockAt(time.Now().UTC().Truncate(time.Second)), codes: make(map[string]keycloakCode)}
	var err error
	f.key, err = rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	f.idp = httptest.NewTLSServer(http.HandlerFunc(f.serveHTTP))
	t.Cleanup(f.idp.Close)
	f.ctx = oidc.ClientContext(t.Context(), f.idp.Client())
	f.a, err = authtest.NewAuthServer(authtest.AuthServerConfig{Dir: t.TempDir(), Clock: f.clock})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, f.a.Close()) })
	f.emitter = &eventstest.MockRecorderEmitter{}
	f.a.AuthServer.SetEmitter(f.emitter)
	f.svc = auth.NewKeycloakService(f.a.AuthServer)
	f.connector = newKeycloakConnector(t, f.idp.URL+"/realms/lab")
	_, err = f.a.AuthServer.Services.UpsertOIDCConnector(f.ctx, f.connector)
	require.NoError(t, err)
	_, err = f.a.AuthServer.UpsertRole(f.ctx, keycloakLabRole(t))
	require.NoError(t, err)
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	sshPub, err := ssh.NewPublicKey(pub)
	require.NoError(t, err)
	f.sshKey = ssh.MarshalAuthorizedKey(sshPub)
	f.tlsKey, err = keys.MarshalPublicKey(pub)
	require.NoError(t, err)
	require.Eventually(t, func() bool {
		return f.a.LockWatcher.CheckLockInForce(constants.LockingModeStrict, types.LockTarget{User: "keycloak-fixture"}) == nil
	}, 5*time.Second, 10*time.Millisecond)
	return f
}

func newKeycloakConnector(t *testing.T, issuer string) types.OIDCConnector {
	t.Helper()
	c, err := types.NewOIDCConnector("keycloak-lab", types.OIDCConnectorSpecV3{
		IssuerURL: issuer, ClientID: "teleport-lab", ClientSecret: keycloakTestSecret,
		Provider: "keycloak", RedirectURLs: []string{"https://proxy.example.test/v1/webapi/oidc/callback"},
		Scope: []string{"groups"}, ClaimsToRoles: []types.ClaimMapping{{Claim: "groups", Value: "/lab/operators", Roles: []string{"keycloak-lab-ssh"}}},
	})
	require.NoError(t, err)
	return c
}

func keycloakLabRole(t *testing.T) types.Role {
	t.Helper()
	data, err := os.ReadFile("../../examples/keycloak/role.yaml")
	require.NoError(t, err)
	data, err = yaml.YAMLToJSON(data)
	require.NoError(t, err)
	role, err := services.UnmarshalRole(data)
	require.NoError(t, err)
	require.Equal(t, []string{"lab-user"}, role.GetLogins(types.Allow))
	require.Equal(t, []string{"root"}, role.GetLogins(types.Deny))
	require.Empty(t, role.GetRules(types.Allow))
	return role
}

func (f *keycloakFixture) serveHTTP(w http.ResponseWriter, r *http.Request) {
	if f.adminHandler != nil && (strings.HasPrefix(r.URL.Path, "/admin/") || r.URL.Path == "/realms/lab/protocol/openid-connect/token") {
		f.adminHandler.ServeHTTP(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	switch r.URL.Path {
	case "/realms/lab/.well-known/openid-configuration":
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer": f.idp.URL + "/realms/lab", "authorization_endpoint": f.idp.URL + "/auth",
			"token_endpoint": f.idp.URL + "/token", "jwks_uri": f.idp.URL + "/jwks",
			"response_types_supported": []string{"code"}, "subject_types_supported": []string{"public"},
			"id_token_signing_alg_values_supported": []string{"RS256"}, "code_challenge_methods_supported": []string{"S256"},
		})
	case "/jwks":
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]any{{"kty": "RSA", "kid": "lab", "use": "sig", "alg": "RS256", "n": base64.RawURLEncoding.EncodeToString(f.key.N.Bytes()), "e": "AQAB"}}})
	case "/token":
		f.exchanges.Add(1)
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		client, secret, ok := r.BasicAuth()
		if !ok || client != "teleport-lab" || secret != keycloakTestSecret {
			http.Error(w, "bad client", http.StatusUnauthorized)
			return
		}
		f.mu.Lock()
		code, exists := f.codes[r.Form.Get("code")]
		delete(f.codes, r.Form.Get("code"))
		f.mu.Unlock()
		digest := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
		if !exists || r.Form.Get("grant_type") != "authorization_code" || r.Form.Get("redirect_uri") != "https://proxy.example.test/v1/webapi/oidc/callback" || base64.RawURLEncoding.EncodeToString(digest[:]) != code.challenge {
			http.Error(w, "invalid_grant", http.StatusBadRequest)
			return
		}
		raw, err := signKeycloakToken(code.claims, code.key)
		if err != nil {
			http.Error(w, "sign error", http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "unused-access-token", "token_type": "Bearer", "expires_in": 300, "id_token": raw, "refresh_token": "must-never-be-retained"})
	default:
		http.NotFound(w, r)
	}
}

func signKeycloakToken(claims map[string]any, key *rsa.PrivateKey) (string, error) {
	head := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","kid":"lab","typ":"JWT"}`))
	body, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	unsigned := head + "." + base64.RawURLEncoding.EncodeToString(body)
	digest := sha256.Sum256([]byte(unsigned))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

func (f *keycloakFixture) request(web bool) types.OIDCAuthRequest {
	req := types.OIDCAuthRequest{ConnectorID: f.connector.GetName(), CheckUser: true, CertTTL: time.Hour, ClientLoginIP: "127.0.0.1"}
	if web {
		req.CreateWebSession, req.CSRFToken, req.ClientRedirectURL = true, "fixture-csrf", "https://proxy.example.test/web"
	} else {
		req.SshPublicKey, req.TlsPublicKey = f.sshKey, f.tlsKey
		req.ClientRedirectURL = "http://127.0.0.1:34567/callback?secret_key=fixture-console-key"
	}
	return req
}

func (f *keycloakFixture) begin(t *testing.T, web bool, change func(map[string]any)) (*types.OIDCAuthRequest, url.Values) {
	t.Helper()
	req, err := f.svc.CreateOIDCAuthRequest(f.ctx, f.request(web))
	require.NoError(t, err)
	u, err := url.Parse(req.RedirectURL)
	require.NoError(t, err)
	q := u.Query()
	require.Equal(t, "S256", q.Get("code_challenge_method"))
	require.Equal(t, "login", q.Get("prompt"))
	require.Equal(t, "code", q.Get("response_type"))
	require.NotEmpty(t, q.Get("nonce"))
	require.NotEmpty(t, q.Get("code_challenge"))
	require.Empty(t, req.PkceVerifier)
	claims := map[string]any{"iss": f.idp.URL + "/realms/lab", "aud": "teleport-lab", "azp": "teleport-lab", "sub": "immutable-subject", "iat": f.clock.Now().Unix(), "exp": f.clock.Now().Add(5 * time.Minute).Unix(), "nonce": q.Get("nonce"), "groups": []string{"/lab/operators", "/unmapped"}, "email": "ignored@example.test"}
	if change != nil {
		change(claims)
	}
	code := fmt.Sprintf("fixture-authorization-code-%d", f.sequence.Add(1))
	f.mu.Lock()
	f.codes[code] = keycloakCode{claims: claims, challenge: q.Get("code_challenge"), key: f.key}
	f.mu.Unlock()
	return req, url.Values{"state": {req.StateToken}, "code": {code}, "iss": {f.idp.URL + "/realms/lab"}}
}

func TestKeycloakNativeLogin(t *testing.T) {
	f := newKeycloakFixture(t)
	var username string
	for _, web := range []bool{false, true} {
		t.Run(fmt.Sprintf("web=%v", web), func(t *testing.T) {
			req, callback := f.begin(t, web, func(c map[string]any) { c["email"] = fmt.Sprintf("mutable-%v@example.test", web) })
			stored, err := f.a.AuthServer.GetOIDCAuthRequest(f.ctx, req.StateToken)
			require.NoError(t, err)
			require.Empty(t, stored.PkceVerifier)
			response, err := f.svc.ValidateOIDCAuthCallback(f.ctx, callback)
			require.NoError(t, err)
			digest := sha256.Sum256([]byte(f.idp.URL + "/realms/lab\x00immutable-subject"))
			require.Equal(t, "keycloak-"+hex.EncodeToString(digest[:]), response.Username)
			if username != "" {
				require.Equal(t, username, response.Username)
			}
			username = response.Username
			user, err := f.a.AuthServer.GetUser(f.ctx, username, false)
			require.NoError(t, err)
			require.True(t, auth.IsKeycloakUser(user))
			require.Equal(t, []string{"keycloak-lab-ssh"}, user.GetRoles())
			require.Empty(t, user.GetTraits())
			require.False(t, user.Expiry().After(f.clock.Now().Add(5*time.Minute)))
			if web {
				require.NotNil(t, response.Session)
				require.False(t, response.Session.GetExpiryTime().After(user.Expiry()))
				_, err = f.a.AuthServer.GetWebSession(f.ctx, types.GetWebSessionRequest{User: username, SessionID: response.Session.GetName()})
				require.NoError(t, err)
			} else {
				cert, _, _, _, err := ssh.ParseAuthorizedKey(response.Cert)
				require.NoError(t, err)
				require.Contains(t, cert.(*ssh.Certificate).ValidPrincipals, "lab-user")
				require.NotContains(t, cert.(*ssh.Certificate).ValidPrincipals, "root")
				require.LessOrEqual(t, cert.(*ssh.Certificate).ValidBefore, uint64(user.Expiry().Unix()))
				block, _ := pem.Decode(response.TLSCert)
				require.NotNil(t, block)
				tlsCert, err := x509.ParseCertificate(block.Bytes)
				require.NoError(t, err)
				require.False(t, tlsCert.NotAfter.After(user.Expiry()))
			}
			event := f.emitter.LastEvent().(*apievents.UserLogin)
			require.True(t, event.Success)
			require.Equal(t, events.UserSSOLoginCode, event.Code)
			require.Equal(t, []string{"keycloak-lab-ssh"}, event.UserRoles)
			require.Equal(t, "keycloak-lab", event.ConnectorID)
			data, err := json.Marshal(f.emitter.Events())
			require.NoError(t, err)
			for _, secret := range []string{keycloakTestSecret, callback.Get("code"), req.StateToken, "must-never-be-retained", "unused-access-token", "ignored@example.test"} {
				require.NotContains(t, string(data), secret)
			}
			_, err = f.svc.ValidateOIDCAuthCallback(f.ctx, callback)
			require.True(t, trace.IsAccessDenied(err), "replayed callback must fail")
		})
	}
}

func TestKeycloakTokenRejections(t *testing.T) {
	f := newKeycloakFixture(t)
	tests := map[string]func(map[string]any){
		"issuer":           func(c map[string]any) { c["iss"] = "https://other.example.test" },
		"audience":         func(c map[string]any) { c["aud"] = "other-client" },
		"authorized party": func(c map[string]any) { c["azp"] = "other-client" },
		"missing authorized party with multiple audiences": func(c map[string]any) { delete(c, "azp"); c["aud"] = []string{"teleport-lab", "other"} },
		"nonce":                    func(c map[string]any) { c["nonce"] = "incorrect" },
		"expired":                  func(c map[string]any) { c["exp"] = f.clock.Now().Add(-time.Minute).Unix() },
		"too little lifetime":      func(c map[string]any) { c["exp"] = f.clock.Now().Add(30 * time.Second).Unix() },
		"future issued at":         func(c map[string]any) { c["iat"] = f.clock.Now().Add(time.Hour).Unix() },
		"future not before":        func(c map[string]any) { c["nbf"] = f.clock.Now().Add(time.Minute).Unix() },
		"missing subject":          func(c map[string]any) { delete(c, "sub") },
		"unmapped groups":          func(c map[string]any) { c["groups"] = []string{"/unmapped"} },
		"no prefix group matching": func(c map[string]any) { c["groups"] = []string{"/lab/operators/subgroup"} },
		"malformed groups":         func(c map[string]any) { c["groups"] = "/lab/operators" },
		"missing groups":           func(c map[string]any) { delete(c, "groups") },
	}
	for name, change := range tests {
		t.Run(name, func(t *testing.T) {
			_, callback := f.begin(t, false, change)
			response, err := f.svc.ValidateOIDCAuthCallback(f.ctx, callback)
			require.Nil(t, response)
			require.True(t, trace.IsAccessDenied(err), "%v", err)
			event := f.emitter.LastEvent().(*apievents.UserLogin)
			require.False(t, event.Success)
			require.Equal(t, "Keycloak authentication rejected", event.Error)
		})
	}
	t.Run("signature", func(t *testing.T) {
		_, callback := f.begin(t, false, nil)
		other, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		f.mu.Lock()
		code := f.codes[callback.Get("code")]
		code.key = other
		f.codes[callback.Get("code")] = code
		f.mu.Unlock()
		_, err = f.svc.ValidateOIDCAuthCallback(f.ctx, callback)
		require.True(t, trace.IsAccessDenied(err))
	})
	t.Run("PKCE", func(t *testing.T) {
		_, callback := f.begin(t, false, nil)
		f.mu.Lock()
		code := f.codes[callback.Get("code")]
		code.challenge = "must-not-match"
		f.codes[callback.Get("code")] = code
		f.mu.Unlock()
		_, err := f.svc.ValidateOIDCAuthCallback(f.ctx, callback)
		require.True(t, trace.IsAccessDenied(err))
	})
}

func TestKeycloakAtomicConsume(t *testing.T) {
	f := newKeycloakFixture(t)
	_, callback := f.begin(t, false, nil)
	secondService := auth.NewKeycloakService(f.a.AuthServer)
	var successes atomic.Int64
	var wg sync.WaitGroup
	for i := range 12 {
		wg.Go(func() {
			svc := f.svc
			if i%2 == 0 {
				svc = secondService
			}
			_, err := svc.ValidateOIDCAuthCallback(f.ctx, callback)
			if err == nil {
				successes.Add(1)
			}
		})
	}
	wg.Wait()
	require.EqualValues(t, 1, successes.Load())
	require.EqualValues(t, 1, f.exchanges.Load())
	_, callback = f.begin(t, false, nil)
	f.clock.Advance(3*time.Minute + time.Second)
	_, err := f.svc.ValidateOIDCAuthCallback(f.ctx, callback)
	require.True(t, trace.IsAccessDenied(err))
	require.EqualValues(t, 1, f.exchanges.Load(), "expired state must not reach the token endpoint")
}

func TestKeycloakIdentityAndPolicyChanges(t *testing.T) {
	f := newKeycloakFixture(t)
	t.Run("connector changes invalidate pending login", func(t *testing.T) {
		_, callback := f.begin(t, false, nil)
		f.connector.SetDisplay("changed policy")
		_, err := f.a.AuthServer.Services.UpsertOIDCConnector(f.ctx, f.connector)
		require.NoError(t, err)
		_, err = f.svc.ValidateOIDCAuthCallback(f.ctx, callback)
		require.True(t, trace.IsAccessDenied(err))
		require.Zero(t, f.exchanges.Load())
	})
	t.Run("local identity collision", func(t *testing.T) {
		digest := sha256.Sum256([]byte(f.idp.URL + "/realms/lab\x00local-collision"))
		user, err := types.NewUser("keycloak-" + hex.EncodeToString(digest[:]))
		require.NoError(t, err)
		user.SetRoles([]string{"keycloak-lab-ssh"})
		_, err = f.a.AuthServer.CreateUser(f.ctx, user)
		require.NoError(t, err)
		_, callback := f.begin(t, false, func(c map[string]any) { c["sub"] = "local-collision" })
		_, err = f.svc.ValidateOIDCAuthCallback(f.ctx, callback)
		require.True(t, trace.IsAccessDenied(err))
		reloaded, err := f.a.AuthServer.GetUser(f.ctx, user.GetName(), false)
		require.NoError(t, err)
		require.False(t, auth.IsKeycloakUser(reloaded))
	})
	t.Run("user status and persistent lock", func(t *testing.T) {
		_, callback := f.begin(t, false, nil)
		response, err := f.svc.ValidateOIDCAuthCallback(f.ctx, callback)
		require.NoError(t, err)
		user, err := f.a.AuthServer.GetUser(f.ctx, response.Username, false)
		require.NoError(t, err)
		user.SetLocked(f.clock.Now().Add(time.Hour), "fixture administrative hold")
		_, err = f.a.AuthServer.UpdateUser(f.ctx, user)
		require.NoError(t, err)
		_, callback = f.begin(t, false, nil)
		_, err = f.svc.ValidateOIDCAuthCallback(f.ctx, callback)
		require.True(t, trace.IsAccessDenied(err))
		lock, err := types.NewLock("fixture-user-lock", types.LockSpecV2{Target: types.LockTarget{User: user.GetName()}, Message: "fixture offboarding"})
		require.NoError(t, err)
		require.NoError(t, f.a.AuthServer.UpsertLock(f.ctx, lock))
		require.Eventually(t, func() bool {
			return f.a.LockWatcher.CheckLockInForce(constants.LockingModeStrict, lock.Target()) != nil
		}, 5*time.Second, 10*time.Millisecond)
		// Delete the expiring identity to model re-creation after its TTL; the
		// stable-name user lock still blocks native certificate issuance.
		require.NoError(t, f.a.AuthServer.DeleteUser(f.ctx, user.GetName()))
		_, callback = f.begin(t, false, nil)
		_, err = f.svc.ValidateOIDCAuthCallback(f.ctx, callback)
		require.True(t, trace.IsAccessDenied(err))
	})
}

func TestKeycloakConnectorRestrictions(t *testing.T) {
	tests := map[string]func(*types.OIDCConnectorV3){
		"HTTP issuer": func(c *types.OIDCConnectorV3) { c.Spec.IssuerURL = "http://idp.example.test" },
		"HTTP callback": func(c *types.OIDCConnectorV3) {
			c.Spec.RedirectURLs = []string{"http://proxy.example.test/v1/webapi/oidc/callback"}
		},
		"wrong callback": func(c *types.OIDCConnectorV3) { c.Spec.RedirectURLs = []string{"https://proxy.example.test/callback"} },
		"callback query": func(c *types.OIDCConnectorV3) {
			c.Spec.RedirectURLs = []string{"https://proxy.example.test/v1/webapi/oidc/callback?unsafe=1"}
		},
		"other provider":     func(c *types.OIDCConnectorV3) { c.Spec.Provider = "generic" },
		"offline scope":      func(c *types.OIDCConnectorV3) { c.Spec.Scope = []string{"offline_access"} },
		"disabled PKCE":      func(c *types.OIDCConnectorV3) { c.Spec.PKCEMode = "disabled" },
		"email identity":     func(c *types.OIDCConnectorV3) { c.Spec.UsernameClaim = "email" },
		"MFA":                func(c *types.OIDCConnectorV3) { c.Spec.MFASettings = &types.OIDCConnectorMFASettings{} },
		"regex groups":       func(c *types.OIDCConnectorV3) { c.Spec.ClaimsToRoles[0].Value = "/lab/.*" },
		"template roles":     func(c *types.OIDCConnectorV3) { c.Spec.ClaimsToRoles[0].Roles = []string{"{{external.groups}}"} },
		"non-group mapping":  func(c *types.OIDCConnectorV3) { c.Spec.ClaimsToRoles[0].Claim = "email" },
		"unsupported prompt": func(c *types.OIDCConnectorV3) { c.Spec.Prompt = "none" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			c := newKeycloakConnector(t, "https://idp.example.test/realms/lab").(*types.OIDCConnectorV3)
			require.NoError(t, auth.ValidateKeycloakConnector(c))
			mutate(c)
			require.Error(t, auth.ValidateKeycloakConnector(c))
		})
	}
}

func TestKeycloakUnsafeRolesAndFlows(t *testing.T) {
	f := newKeycloakFixture(t)
	for _, option := range []string{"long TTL", "no disconnect", "best effort", "admin API", "impersonation", "app", "database", "kubernetes"} {
		t.Run(option, func(t *testing.T) {
			role := keycloakLabRole(t)
			o := role.GetOptions()
			switch option {
			case "long TTL":
				o.MaxSessionTTL = types.Duration(time.Hour)
			case "no disconnect":
				o.DisconnectExpiredCert = false
			case "best effort":
				o.Lock = constants.LockingModeBestEffort
			case "admin API":
				role.SetRules(types.Allow, []types.Rule{{Resources: []string{"role"}, Verbs: []string{"create"}}})
			case "impersonation":
				role.SetImpersonateConditions(types.Allow, types.ImpersonateConditions{Users: []string{"*"}, Roles: []string{"*"}})
			case "app":
				role.SetAppLabels(types.Allow, types.Labels{"*": {"*"}})
			case "database":
				role.SetDatabaseLabels(types.Allow, types.Labels{"*": {"*"}})
				role.SetDatabaseUsers(types.Allow, []string{"lab-db-user"})
			case "kubernetes":
				role.SetKubernetesLabels(types.Allow, types.Labels{"*": {"*"}})
				role.SetKubeGroups(types.Allow, []string{"lab-users"})
			}
			role.SetOptions(o)
			_, err := f.a.AuthServer.UpsertRole(f.ctx, role)
			require.NoError(t, err)
			_, callback := f.begin(t, false, nil)
			_, err = f.svc.ValidateOIDCAuthCallback(f.ctx, callback)
			require.True(t, trace.IsAccessDenied(err))
		})
	}
	for _, mutate := range []func(*types.OIDCAuthRequest){
		func(r *types.OIDCAuthRequest) { r.SSOTestFlow = true },
		func(r *types.OIDCAuthRequest) { r.Scope = "/unsupported" },
		func(r *types.OIDCAuthRequest) { r.CheckUser = false },
		func(r *types.OIDCAuthRequest) { r.StateToken = "caller-controlled" },
		func(r *types.OIDCAuthRequest) { r.PkceVerifier = "caller-controlled" },
		func(r *types.OIDCAuthRequest) {
			r.ClientRedirectURL = "https://evil.example.test/callback?secret_key=x"
		},
		func(r *types.OIDCAuthRequest) { r.ClientRedirectURL = "/web/launchermfa" },
	} {
		req := f.request(false)
		mutate(&req)
		_, err := f.svc.CreateOIDCAuthRequest(f.ctx, req)
		require.Error(t, err)
	}
	_, err := f.svc.CreateOIDCAuthRequestForMFA(f.ctx, f.request(false))
	require.True(t, trace.IsAccessDenied(err))
}

type keycloakFailingAudit struct{}

func (keycloakFailingAudit) EmitAuditEvent(_ context.Context, event apievents.AuditEvent) error {
	if _, ok := event.(*apievents.UserLogin); ok {
		return trace.ConnectionProblem(nil, "fixture audit unavailable")
	}
	return nil
}

func TestKeycloakAuditFailureIsClosed(t *testing.T) {
	f := newKeycloakFixture(t)
	_, callback := f.begin(t, true, nil)
	f.a.AuthServer.SetEmitter(keycloakFailingAudit{})
	response, err := f.svc.ValidateOIDCAuthCallback(f.ctx, callback)
	require.Nil(t, response)
	require.ErrorContains(t, err, "audit recording failed")
	items, err := f.a.AuthServer.WebSessions().List(f.ctx)
	require.NoError(t, err)
	require.Empty(t, items)
}
