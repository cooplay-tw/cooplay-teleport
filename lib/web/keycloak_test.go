// Copyright 2026 Cooplay.
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gravitational/trace"
	"github.com/stretchr/testify/require"

	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/auth/authclient"
	"github.com/gravitational/teleport/lib/client"
	"github.com/gravitational/teleport/lib/httplib/csrf"
	"github.com/gravitational/teleport/lib/secret"
	websession "github.com/gravitational/teleport/lib/web/session"
)

type keycloakProxyTestClient struct {
	authclient.ClientI
	create   func(types.OIDCAuthRequest) (*types.OIDCAuthRequest, error)
	get      func(string) (*types.OIDCAuthRequest, error)
	validate func(url.Values) (*authclient.OIDCAuthResponse, error)
}

func (c *keycloakProxyTestClient) CreateOIDCAuthRequest(_ context.Context, r types.OIDCAuthRequest) (*types.OIDCAuthRequest, error) {
	return c.create(r)
}

func (c *keycloakProxyTestClient) ValidateOIDCAuthCallback(_ context.Context, q url.Values) (*authclient.OIDCAuthResponse, error) {
	return c.validate(q)
}

func (c *keycloakProxyTestClient) GetOIDCAuthRequest(_ context.Context, state string) (*types.OIDCAuthRequest, error) {
	if c.get != nil {
		return c.get(state)
	}
	return &types.OIDCAuthRequest{StateToken: state}, nil
}

func TestKeycloakWebLoginRequiresCSRF(t *testing.T) {
	t.Parallel()
	for _, cookie := range []bool{false, true} {
		t.Run(map[bool]string{false: "missing cookie", true: "valid cookie"}[cookie], func(t *testing.T) {
			called := false
			h := &Handler{cfg: Config{ProxyClient: &keycloakProxyTestClient{create: func(req types.OIDCAuthRequest) (*types.OIDCAuthRequest, error) {
				called = true
				require.True(t, req.CheckUser)
				require.True(t, req.CreateWebSession)
				require.Equal(t, strings.Repeat("a", 64), req.CSRFToken)
				require.Equal(t, "keycloak", req.ConnectorID)
				require.Equal(t, "192.0.2.1", req.ClientLoginIP)
				return &types.OIDCAuthRequest{RedirectURL: "https://idp.example/authorize"}, nil
			}}}}
			r := httptest.NewRequest(http.MethodGet, "/webapi/oidc/login/web?connector_id=keycloak&redirect_url=%2Fweb", nil)
			r.RemoteAddr = "192.0.2.1:1234"
			if cookie {
				r.AddCookie(&http.Cookie{Name: csrf.CookieName, Value: strings.Repeat("a", 64)})
			}
			redirect := h.keycloakLoginWeb(httptest.NewRecorder(), r, nil)
			require.Equal(t, cookie, called)
			if cookie {
				require.Equal(t, "https://idp.example/authorize", redirect)
			} else {
				require.Equal(t, client.LoginFailedRedirectURL, redirect)
			}
		})
	}
}

func TestKeycloakCallbackWebCookieProtection(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name       string
		cookie     string
		redirect   string
		wantCookie bool
	}{
		{name: "valid", cookie: strings.Repeat("a", 64), redirect: "https://proxy.example/web", wantCookie: true},
		{name: "different origin becomes local", cookie: strings.Repeat("a", 64), redirect: "https://attacker.example/web", wantCookie: true},
		{name: "missing csrf", redirect: "/web"},
		{name: "wrong csrf", cookie: strings.Repeat("b", 64), redirect: "/web"},
		{name: "malformed redirect", cookie: strings.Repeat("a", 64), redirect: "%"},
	} {
		t.Run(test.name, func(t *testing.T) {
			session, err := types.NewWebSession("session-id", types.KindWebSession, types.WebSessionSpecV2{User: "keycloak-user", Expires: time.Now().Add(time.Minute)})
			require.NoError(t, err)
			validated := false
			h := &Handler{cfg: Config{ProxyClient: &keycloakProxyTestClient{
				get: func(string) (*types.OIDCAuthRequest, error) {
					return &types.OIDCAuthRequest{CreateWebSession: true, CSRFToken: strings.Repeat("a", 64)}, nil
				},
				validate: func(url.Values) (*authclient.OIDCAuthResponse, error) {
					validated = true
					return &authclient.OIDCAuthResponse{
						Username: "keycloak-user", Session: session,
						Req: authclient.OIDCAuthRequest{CreateWebSession: true, CSRFToken: strings.Repeat("a", 64), ClientRedirectURL: test.redirect},
					}, nil
				},
			}}}
			r := httptest.NewRequest(http.MethodGet, "/webapi/oidc/callback?state=opaque&code=opaque", nil)
			if test.cookie != "" {
				r.AddCookie(&http.Cookie{Name: csrf.CookieName, Value: test.cookie})
			}
			w := httptest.NewRecorder()
			redirect := h.keycloakCallback(w, r, nil)
			if test.cookie != strings.Repeat("a", 64) {
				require.False(t, validated, "invalid browser binding must not exchange a code or issue credentials")
			}
			if !test.wantCookie {
				require.Empty(t, w.Result().Cookies())
				require.Equal(t, client.LoginFailedRedirectURL, redirect)
				return
			}
			require.Equal(t, "/web", redirect)
			cookies := w.Result().Cookies()
			require.Len(t, cookies, 1)
			require.Equal(t, websession.CookieName, cookies[0].Name)
			require.True(t, cookies[0].Secure)
			require.True(t, cookies[0].HttpOnly)
		})
	}
}

func TestKeycloakCallbackEncryptsConsoleCredentials(t *testing.T) {
	t.Parallel()
	key, err := secret.NewKey()
	require.NoError(t, err)
	callback := "http://127.0.0.1:12345/callback?" + url.Values{"secret_key": {key.String()}}.Encode()
	h := &Handler{cfg: Config{ProxyClient: &keycloakProxyTestClient{validate: func(url.Values) (*authclient.OIDCAuthResponse, error) {
		return &authclient.OIDCAuthResponse{
			Username: "keycloak-user", Cert: []byte("ssh certificate"), TLSCert: []byte("tls certificate"),
			Req: authclient.OIDCAuthRequest{SSHPubKey: []byte("key"), ClientRedirectURL: callback},
		}, nil
	}}}}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/webapi/oidc/callback?state=opaque&code=opaque", nil)
	redirect, err := url.Parse(h.keycloakCallback(w, r, nil))
	require.NoError(t, err)
	require.Equal(t, "127.0.0.1:12345", redirect.Host)
	require.Empty(t, redirect.Query().Get("secret_key"))
	require.NotContains(t, redirect.String(), "keycloak-user")
	plain, err := key.Open([]byte(redirect.Query().Get("response")))
	require.NoError(t, err)
	var response authclient.CLILoginResponse
	require.NoError(t, json.Unmarshal(plain, &response))
	require.Equal(t, "keycloak-user", response.Username)
	require.Equal(t, []byte("ssh certificate"), response.Cert)
	require.Equal(t, []byte("tls certificate"), response.TLSCert)
	require.Empty(t, w.Result().Cookies())
}

func TestKeycloakCallbackRejectsUnsafeConsoleRedirect(t *testing.T) {
	t.Parallel()
	key, err := secret.NewKey()
	require.NoError(t, err)
	for _, redirect := range []string{
		"/web/sso_confirm?channel_id=test",
		"https://attacker.example/callback?secret_key=" + key.String(),
		"http://127.0.0.1:12345/callback?secret_key=invalid",
		"http://127.0.0.1:12345/callback",
	} {
		t.Run(redirect, func(t *testing.T) {
			h := &Handler{cfg: Config{ProxyClient: &keycloakProxyTestClient{validate: func(url.Values) (*authclient.OIDCAuthResponse, error) {
				return &authclient.OIDCAuthResponse{
					Username: "keycloak-user", Cert: []byte("certificate"),
					Req: authclient.OIDCAuthRequest{SSHPubKey: []byte("key"), ClientRedirectURL: redirect},
				}, nil
			}}}}
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodGet, "/webapi/oidc/callback?state=opaque&code=opaque", nil)
			require.Equal(t, client.LoginFailedRedirectURL, h.keycloakCallback(w, r, nil))
			require.Empty(t, w.Result().Cookies())
		})
	}
}

func TestKeycloakConsoleLoginPreservesRequestAndDoesNotTrustPKCE(t *testing.T) {
	t.Parallel()
	h := &Handler{cfg: Config{ProxyClient: &keycloakProxyTestClient{create: func(req types.OIDCAuthRequest) (*types.OIDCAuthRequest, error) {
		require.True(t, req.CheckUser)
		require.False(t, req.CreateWebSession)
		require.Equal(t, "keycloak", req.ConnectorID)
		require.Equal(t, []byte("ssh key"), req.SshPublicKey)
		require.Equal(t, []byte("tls key"), req.TlsPublicKey)
		require.Equal(t, time.Minute, req.CertTTL)
		require.Equal(t, "192.0.2.1", req.ClientLoginIP)
		require.Empty(t, req.PkceVerifier)
		return &types.OIDCAuthRequest{RedirectURL: "https://idp.example/authorize"}, nil
	}}}}
	body, err := json.Marshal(client.SSOLoginConsoleReq{
		ConnectorID: "keycloak", RedirectURL: "http://127.0.0.1:12345/callback", CertTTL: time.Minute,
		UserPublicKeys: client.UserPublicKeys{SSHPubKey: []byte("ssh key"), TLSPubKey: []byte("tls key")},
		PKCEVerifier:   "untrusted-client-verifier",
	})
	require.NoError(t, err)
	r := httptest.NewRequest(http.MethodPost, "/webapi/oidc/login/console", strings.NewReader(string(body)))
	r.Header.Set("Content-Type", "application/json")
	r.RemoteAddr = "192.0.2.1:12345"
	response, err := h.keycloakLoginConsole(httptest.NewRecorder(), r, nil)
	require.NoError(t, err)
	require.Equal(t, &client.SSOLoginConsoleResponse{RedirectURL: "https://idp.example/authorize"}, response)
}

func TestKeycloakCallbackDoesNotExposeProviderError(t *testing.T) {
	t.Parallel()
	h := &Handler{cfg: Config{ProxyClient: &keycloakProxyTestClient{validate: func(url.Values) (*authclient.OIDCAuthResponse, error) {
		return nil, trace.AccessDenied("sensitive provider response")
	}}}}
	w := httptest.NewRecorder()
	redirect := h.keycloakCallback(w, httptest.NewRequest(http.MethodGet, "/webapi/oidc/callback?state=opaque&code=opaque", nil), nil)
	require.Equal(t, client.LoginFailedBadCallbackRedirectURL, redirect)
	require.Empty(t, w.Result().Cookies())
}
