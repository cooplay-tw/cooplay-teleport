// Copyright 2026 Cooplay.
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gravitational/trace"
	"github.com/julienschmidt/httprouter"
	"github.com/stretchr/testify/require"

	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/auth/authclient"
	"github.com/gravitational/teleport/lib/client"
	"github.com/gravitational/teleport/lib/httplib/csrf"
	"github.com/gravitational/teleport/lib/secret"
	"github.com/gravitational/teleport/lib/web/app"
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

func TestKeycloakWebLoginCSRF(t *testing.T) {
	t.Parallel()
	const (
		probePath = "/v1/webapi/oidc/login/web?connector_id=keycloak-company&redirect_url=%2Fweb"
		issuerURL = "https://sso.cooplay.tw/realms/company/protocol/openid-connect/auth"
	)
	validToken := strings.Repeat("a", 64)
	for _, test := range []struct {
		name          string
		cookie        *http.Cookie
		legacyProbe   bool
		wantNewCookie bool
	}{
		{name: "cookie-less probe on .7", wantNewCookie: true},
		{name: "cookie-less probe on .6", legacyProbe: true},
		{name: "empty cookie", cookie: &http.Cookie{Name: csrf.CookieName}, wantNewCookie: true},
		{name: "undecodable cookie", cookie: &http.Cookie{Name: csrf.CookieName, Value: "not-hex"}, wantNewCookie: true},
		{name: "short hex cookie", cookie: &http.Cookie{Name: csrf.CookieName, Value: "abcd"}, wantNewCookie: true},
		{name: "valid cookie", cookie: &http.Cookie{Name: csrf.CookieName, Value: validToken}},
	} {
		t.Run(test.name, func(t *testing.T) {
			var authToken string
			h := &Handler{cfg: Config{ProxyClient: &keycloakProxyTestClient{create: func(req types.OIDCAuthRequest) (*types.OIDCAuthRequest, error) {
				require.False(t, test.legacyProbe, "cookie-less .6 probe must fail before creating an auth request")
				require.True(t, req.CheckUser)
				require.True(t, req.CreateWebSession)
				require.Equal(t, "keycloak-company", req.ConnectorID)
				require.Equal(t, "/web", req.ClientRedirectURL)
				require.Equal(t, "192.0.2.1", req.ClientLoginIP)
				authToken = req.CSRFToken
				return &types.OIDCAuthRequest{RedirectURL: issuerURL}, nil
			}}}}
			if test.legacyProbe {
				// Exercise the .6 handler's parser and early failure for this probe.
				h.GET("/webapi/oidc/login/web", h.WithRedirect(func(_ http.ResponseWriter, r *http.Request, _ httprouter.Params) string {
					_, err := ParseSSORequestParams(r)
					require.ErrorIs(t, err, http.ErrNoCookie)
					return client.LoginFailedRedirectURL
				}))
			} else {
				h.RegisterKeycloakHandlers()
			}
			r := httptest.NewRequest(http.MethodGet, probePath, nil)
			r.RemoteAddr = "192.0.2.1:1234"
			if test.cookie != nil {
				r.AddCookie(test.cookie)
			}
			w := httptest.NewRecorder()
			http.StripPrefix("/v1", h).ServeHTTP(w, r)
			response := w.Result()
			require.Equal(t, http.StatusFound, response.StatusCode)
			if test.legacyProbe {
				require.Equal(t, client.LoginFailedRedirectURL, response.Header.Get("Location"))
				require.Zero(t, len(response.Cookies()))
				return
			}
			require.Equal(t, issuerURL, response.Header.Get("Location"))
			if !test.wantNewCookie {
				require.True(t, authToken == validToken, "auth request must reuse the existing token")
				require.Zero(t, len(response.Cookies()))
				return
			}
			cookies := response.Cookies()
			require.Equal(t, 1, len(cookies))
			cookie := cookies[0]
			require.Equal(t, csrf.CookieName, cookie.Name)
			require.True(t, cookie.HttpOnly)
			require.True(t, cookie.Secure)
			require.Equal(t, http.SameSiteNoneMode, cookie.SameSite)
			require.Equal(t, "/", cookie.Path)
			require.Empty(t, cookie.Domain)
			require.Zero(t, cookie.MaxAge)
			require.True(t, cookie.Expires.IsZero())
			if test.cookie != nil {
				require.True(t, test.cookie.Value != cookie.Value, "invalid cookie must be replaced")
			}
			callback := httptest.NewRequest(http.MethodGet, "/v1/webapi/oidc/callback", nil)
			callback.AddCookie(cookie)
			require.NoError(t, csrf.VerifyToken(authToken, callback))
			require.True(t, authToken == cookie.Value, "auth request must carry the exact cookie value")
		})
	}
}

func TestKeycloakWebLoginOverlappingStarts(t *testing.T) {
	t.Parallel()
	const (
		proxyOrigin = "https://proxy.example"
		user        = "keycloak-user"
	)
	starts := []struct{ state, redirectParam, wantRedirect string }{
		{
			state:         "first",
			redirectParam: url.QueryEscape("/web/launch/coder.example?path=%2Fcli-auth&query=state%3Da%2Bb"),
			wantRedirect:  "/web/launch/coder.example?path=%2Fcli-auth&query=state%3Da%2Bb",
		},
		{
			state:         "second",
			redirectParam: "/web?search=a%252Bb&sort=name",
			wantRedirect:  "/web?search=a%2Bb&sort=name",
		},
	}
	csrfToken := strings.Repeat("a", 64)
	requests := make(map[string]types.OIDCAuthRequest)
	h := &Handler{cfg: Config{ProxyClient: &keycloakProxyTestClient{
		create: func(req types.OIDCAuthRequest) (*types.OIDCAuthRequest, error) {
			start := starts[len(requests)]
			require.Equal(t, start.wantRedirect, req.ClientRedirectURL)
			require.True(t, req.CSRFToken == csrfToken, "both starts must use the existing cookie")
			req.StateToken = start.state
			req.RedirectURL = "https://sso.cooplay.tw/authorize?state=" + start.state
			requests[start.state] = req
			return &req, nil
		},
		get: func(state string) (*types.OIDCAuthRequest, error) {
			req, ok := requests[state]
			require.True(t, ok, "callback must look up its own auth request")
			return &req, nil
		},
		validate: func(query url.Values) (*authclient.OIDCAuthResponse, error) {
			state := query.Get("state")
			req := requests[state]
			delete(requests, state)
			session, err := types.NewWebSession("session-"+state, types.KindWebSession, types.WebSessionSpecV2{
				User: user, Expires: time.Now().Add(time.Minute),
			})
			require.NoError(t, err)
			return &authclient.OIDCAuthResponse{Username: user, Session: session, Req: authclient.OIDCAuthRequest{
				CreateWebSession: req.CreateWebSession, CSRFToken: req.CSRFToken, ClientRedirectURL: req.ClientRedirectURL,
			}}, nil
		},
	}}}
	h.RegisterKeycloakHandlers()
	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	proxyURL, err := url.Parse(proxyOrigin)
	require.NoError(t, err)
	old := httptest.NewRecorder()
	require.NoError(t, websession.SetCookie(old, user, "old-session", time.Time{}))
	jar.SetCookies(proxyURL, old.Result().Cookies())
	jar.SetCookies(proxyURL, []*http.Cookie{{Name: csrf.CookieName, Value: csrfToken, Path: "/", Secure: true}})

	newRequest := func(path string) *http.Request {
		r := httptest.NewRequest(http.MethodGet, proxyOrigin+path, nil)
		for _, cookie := range jar.Cookies(r.URL) {
			r.AddCookie(cookie)
		}
		return r
	}
	serve := func(r *http.Request) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		http.StripPrefix("/v1", h).ServeHTTP(w, r)
		jar.SetCookies(r.URL, w.Result().Cookies())
		return w
	}
	for _, start := range starts {
		w := serve(newRequest("/v1/webapi/oidc/login/web?connector_id=keycloak-company&redirect_url=" + start.redirectParam))
		require.Equal(t, http.StatusFound, w.Code)
		require.Equal(t, "https://sso.cooplay.tw/authorize?state="+start.state, w.Result().Header.Get("Location"))
		require.Zero(t, len(w.Result().Cookies()))
	}
	require.Equal(t, 2, len(requests))

	wantPreviousSession := "old-session"
	for i := len(starts) - 1; i >= 0; i-- {
		start := starts[i]
		callback := newRequest("/v1/webapi/oidc/callback?state=" + start.state + "&code=opaque")
		previousCookie, err := callback.Cookie(websession.CookieName)
		require.NoError(t, err)
		previousSession, err := websession.DecodeCookie(previousCookie.Value)
		require.NoError(t, err)
		require.Equal(t, wantPreviousSession, previousSession.SID)

		w := serve(callback)
		redirect, err := app.GetURLFromMetaRedirect(w.Body)
		require.NoError(t, err)
		require.Equal(t, start.wantRedirect, redirect)

		cookie, err := newRequest("/web").Cookie(websession.CookieName)
		require.NoError(t, err)
		session, err := websession.DecodeCookie(cookie.Value)
		require.NoError(t, err)
		require.Equal(t, user, session.User)
		wantPreviousSession = "session-" + start.state
		require.Equal(t, wantPreviousSession, session.SID)
	}
	require.Zero(t, len(requests))
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
		{name: "different browser's csrf", cookie: strings.Repeat("b", 64), redirect: "/web"},
		{name: "invalid csrf", cookie: "not-hex", redirect: "/web"},
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

// A named-connector ping builds OIDC settings directly, bypassing the common
// ping tail. Omitting the TTL makes tsh silently fall back to twelve hours.
func TestKeycloakNamedConnectorDefaultTTL(t *testing.T) {
	for _, ttl := range []time.Duration{time.Hour, 30 * 24 * time.Hour} {
		preference, err := types.NewAuthPreference(types.AuthPreferenceSpecV2{DefaultSessionTTL: types.Duration(ttl)})
		require.NoError(t, err)
		connector, err := types.NewOIDCConnector("keycloak", types.OIDCConnectorSpecV3{
			IssuerURL: "https://idp.example/realms/lab", ClientID: "lab", ClientSecret: "test",
			RedirectURLs:  []string{"https://proxy.example/v1/webapi/oidc/callback"},
			ClaimsToRoles: []types.ClaimMapping{{Claim: "groups", Value: "/lab", Roles: []string{"lab"}}},
		})
		require.NoError(t, err)
		settings := oidcSettings(connector, preference)
		require.Equal(t, ttl, settings.DefaultSessionTTL.Duration())
	}
}
