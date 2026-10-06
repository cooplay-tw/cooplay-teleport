// Copyright 2026 Cooplay.
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"net"
	"net/http"

	"github.com/gravitational/trace"
	"github.com/julienschmidt/httprouter"

	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/auth/authclient"
	"github.com/gravitational/teleport/lib/client"
	"github.com/gravitational/teleport/lib/client/sso"
	"github.com/gravitational/teleport/lib/httplib"
	"github.com/gravitational/teleport/lib/httplib/csrf"
)

// RegisterKeycloakHandlers registers the experimental Keycloak login flow at
// the native OIDC paths understood by tsh and the web UI. Call only when the
// explicit Keycloak opt-in is enabled; this does not enable Enterprise SSO.
func (h *Handler) RegisterKeycloakHandlers() {
	h.GET("/webapi/oidc/login/web", h.WithRedirect(h.keycloakLoginWeb))
	h.POST("/webapi/oidc/login/console", h.WithLimiter(h.keycloakLoginConsole))
	h.GET("/webapi/oidc/callback", h.WithMetaRedirect(h.keycloakCallback))
	h.POST("/webapi/oidc/logout/:connector", h.WithLimiter(h.keycloakBackchannelLogout))
}

func (h *Handler) keycloakLoginWeb(w http.ResponseWriter, r *http.Request, _ httprouter.Params) string {
	req, err := ParseSSORequestParams(r)
	if err != nil {
		return client.LoginFailedRedirectURL
	}
	remoteAddr, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return client.LoginFailedRedirectURL
	}
	response, err := h.cfg.ProxyClient.CreateOIDCAuthRequest(r.Context(), types.OIDCAuthRequest{
		CheckUser:         true,
		CSRFToken:         req.CSRFToken,
		ConnectorID:       req.ConnectorID,
		CreateWebSession:  true,
		ClientRedirectURL: req.ClientRedirectURL,
		ClientLoginIP:     remoteAddr,
		ClientUserAgent:   r.UserAgent(),
		LoginHint:         req.LoginHint,
		Scope:             req.Scope,
	})
	if err != nil || response == nil {
		return client.LoginFailedRedirectURL
	}
	return response.RedirectURL
}

func (h *Handler) keycloakLoginConsole(_ http.ResponseWriter, r *http.Request, _ httprouter.Params) (any, error) {
	var req client.SSOLoginConsoleReq
	if err := httplib.ReadResourceJSON(r, &req); err != nil {
		return nil, trace.AccessDenied("%s", SSOLoginFailureMessage)
	}
	if err := req.CheckAndSetDefaults(); err != nil {
		return nil, trace.AccessDenied("%s", SSOLoginFailureMessage)
	}
	remoteAddr, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return nil, trace.AccessDenied("%s", SSOLoginFailureMessage)
	}
	response, err := h.cfg.ProxyClient.CreateOIDCAuthRequest(r.Context(), types.OIDCAuthRequest{
		CheckUser:               true,
		ConnectorID:             req.ConnectorID,
		SshPublicKey:            req.SSHPubKey,
		TlsPublicKey:            req.TLSPubKey,
		SshAttestationStatement: req.SSHAttestationStatement.ToProto(),
		TlsAttestationStatement: req.TLSAttestationStatement.ToProto(),
		CertTTL:                 req.CertTTL,
		ClientRedirectURL:       req.RedirectURL,
		Compatibility:           req.Compatibility,
		RouteToCluster:          req.RouteToCluster,
		KubernetesCluster:       req.KubernetesCluster,
		ClientLoginIP:           remoteAddr,
		Scope:                   req.Scope,
		// The Auth service generates its own PKCE verifier; never trust a
		// verifier supplied by a client of this unauthenticated endpoint.
	})
	if err != nil || response == nil {
		return nil, trace.AccessDenied("%s", SSOLoginFailureMessage)
	}
	return &client.SSOLoginConsoleResponse{RedirectURL: response.RedirectURL}, nil
}

func (h *Handler) keycloakCallback(w http.ResponseWriter, r *http.Request, _ httprouter.Params) string {
	// Authentication failures deliberately have a single browser-visible error.
	// Never log the query, authorization code, state, token, or upstream error.
	query := r.URL.Query()
	if len(query["state"]) != 1 || query.Get("state") == "" {
		return client.LoginFailedBadCallbackRedirectURL
	}
	request, err := h.cfg.ProxyClient.GetOIDCAuthRequest(r.Context(), query.Get("state"))
	if err != nil || request == nil {
		return client.LoginFailedBadCallbackRedirectURL
	}
	// Check the browser binding before the Auth service exchanges the code or
	// issues a web session. Auth still validates and consumes the one-time
	// state, and the response is checked again before setting any cookie.
	if request.CreateWebSession {
		if err := csrf.VerifyToken(request.CSRFToken, r); err != nil {
			return client.LoginFailedRedirectURL
		}
	}
	response, err := h.cfg.ProxyClient.ValidateOIDCAuthCallback(r.Context(), query)
	if err != nil || response == nil || response.MFAToken != "" {
		return client.LoginFailedBadCallbackRedirectURL
	}
	if response.Req.CreateWebSession {
		if response.Session == nil || response.Session.GetDeviceWebToken() != nil {
			return client.LoginFailedRedirectURL
		}
		// Validate before setting a session cookie. Retain the upstream
		// origin-local redirect and login-CSRF protection.
		redirectURL, err := httplib.OriginLocalRedirectURI(response.Req.ClientRedirectURL)
		if err != nil {
			return client.LoginFailedRedirectURL
		}
		res := &SSOCallbackResponse{
			CSRFToken:         response.Req.CSRFToken,
			Username:          response.Username,
			SessionName:       response.Session.GetName(),
			SessionExpiry:     response.Session.Expiry(),
			ClientRedirectURL: redirectURL,
		}
		if err := SSOSetWebSessionAndRedirectURL(w, r, res, true); err != nil {
			return client.LoginFailedRedirectURL
		}
		return res.ClientRedirectURL
	}
	if len(response.Req.SSHPubKey)+len(response.Req.TLSPubKey) == 0 {
		return client.LoginFailedRedirectURL
	}
	// This MVP supports only loopback console login. In particular, never
	// enter ConstructSSHResponse's plaintext web-MFA response branch.
	if err := sso.ValidateClientRedirect(response.Req.ClientRedirectURL, sso.CeremonyTypeLogin, nil); err != nil {
		return client.LoginFailedRedirectURL
	}
	redirectURL, err := ConstructSSHResponse(AuthParams{
		ClientRedirectURL: response.Req.ClientRedirectURL,
		Username:          response.Username,
		Identity:          response.Identity,
		Cert:              response.Cert,
		TLSCert:           response.TLSCert,
		HostSigners:       response.HostSigners,
		FIPS:              h.cfg.FIPS,
		ClientOptions:     response.ClientOptions,
	})
	if err != nil {
		return client.LoginFailedRedirectURL
	}
	return redirectURL.String()
}

func (h *Handler) keycloakBackchannelLogout(w http.ResponseWriter, r *http.Request, p httprouter.Params) (any, error) {
	r.Body = http.MaxBytesReader(w, r.Body, 96*1024)
	if r.ParseForm() != nil || len(r.PostForm["logout_token"]) != 1 || len(r.URL.Query()) != 0 {
		return nil, trace.AccessDenied("invalid Keycloak logout")
	}
	if err := h.cfg.ProxyClient.KeycloakLogout(r.Context(), authclient.KeycloakLogoutRequest{ConnectorID: p.ByName("connector"), LogoutToken: r.PostForm.Get("logout_token")}); err != nil {
		return nil, trace.AccessDenied("Keycloak logout failed")
	}
	w.Header().Set("Cache-Control", "no-store")
	return OK(), nil
}
