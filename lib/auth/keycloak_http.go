// Copyright 2026 Cooplay.
// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

import (
	"encoding/json"
	"net/http"

	"github.com/gravitational/trace"
	"github.com/julienschmidt/httprouter"

	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/auth/authclient"
	"github.com/gravitational/teleport/lib/httplib"
	"github.com/gravitational/teleport/lib/services"
)

// RegisterKeycloakHandlers registers the experimental OIDC callback endpoint.
// The caller must enforce the Keycloak opt-in. Authentication still goes
// through the normal Auth service middleware and ServerWithRoles.
func (s *APIServer) RegisterKeycloakHandlers() {
	s.POST("/:version/oidc/requests/validate", s.WithAuth(s.validateKeycloakAuthCallback))
	s.POST("/:version/keycloak/logout", s.WithAuth(s.keycloakLogout))
}

func (s *APIServer) validateKeycloakAuthCallback(auth *ServerWithRoles, _ http.ResponseWriter, r *http.Request, _ httprouter.Params, version string) (any, error) {
	// Enforce the proxy identity before exchanging a code or minting credentials,
	// including console credentials (the generic OIDC wrapper only checks web
	// sessions after calling the OIDC service).
	if !auth.hasBuiltinRole(types.RoleProxy) {
		return nil, trace.AccessDenied("this request can only be executed by a proxy")
	}
	var req authclient.ValidateOIDCAuthCallbackReq
	if err := httplib.ReadJSON(r, &req); err != nil {
		return nil, trace.AccessDenied("invalid Keycloak callback")
	}
	response, err := auth.ValidateOIDCAuthCallback(r.Context(), req.Query)
	if err != nil {
		return nil, trace.AccessDenied("Keycloak authentication failed")
	}
	if response == nil || response.MFAToken != "" {
		return nil, trace.AccessDenied("Keycloak authentication failed")
	}
	raw := authclient.OIDCAuthRawResponse{
		Username:      response.Username,
		Identity:      response.Identity,
		Cert:          response.Cert,
		TLSCert:       response.TLSCert,
		Req:           response.Req,
		ClientOptions: response.ClientOptions,
	}
	if response.Session != nil {
		data, err := services.MarshalWebSession(response.Session, services.WithVersion(version), services.PreserveRevision())
		if err != nil {
			return nil, trace.Wrap(err)
		}
		raw.Session = data
	}
	raw.HostSigners = make([]json.RawMessage, len(response.HostSigners))
	for i, ca := range response.HostSigners {
		data, err := services.MarshalCertAuthority(ca, services.WithVersion(version), services.PreserveRevision())
		if err != nil {
			return nil, trace.Wrap(err)
		}
		raw.HostSigners[i] = data
	}
	return &raw, nil
}

func (s *APIServer) keycloakLogout(auth *ServerWithRoles, _ http.ResponseWriter, r *http.Request, _ httprouter.Params, _ string) (any, error) {
	r.Body = http.MaxBytesReader(nil, r.Body, 96*1024)
	var req authclient.KeycloakLogoutRequest
	if httplib.ReadJSON(r, &req) != nil {
		return nil, trace.AccessDenied("invalid Keycloak logout")
	}
	if err := auth.KeycloakLogout(r.Context(), req); err != nil {
		return nil, trace.AccessDenied("Keycloak logout failed")
	}
	return map[string]string{"message": "ok"}, nil
}
