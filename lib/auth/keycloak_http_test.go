// Copyright 2026 Cooplay.
// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gravitational/trace"
	"github.com/julienschmidt/httprouter"
	"github.com/stretchr/testify/require"

	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/auth/authclient"
	"github.com/gravitational/teleport/lib/authz"
)

type keycloakHTTPTestService struct {
	OIDCService
	calls int
	err   error
}

func (s *keycloakHTTPTestService) ValidateOIDCAuthCallback(_ context.Context, _ url.Values) (*authclient.OIDCAuthResponse, error) {
	s.calls++
	if s.err != nil {
		return nil, s.err
	}
	return &authclient.OIDCAuthResponse{Username: "keycloak-user", Cert: []byte("ssh certificate")}, nil
}

func TestKeycloakHTTPCallbackRequiresProxy(t *testing.T) {
	t.Parallel()
	for _, role := range []types.SystemRole{types.RoleProxy, types.RoleNode, types.RoleAdmin} {
		t.Run(string(role), func(t *testing.T) {
			ctx, err := authz.NewBuiltinRoleContext(role)
			require.NoError(t, err)
			svc := &keycloakHTTPTestService{}
			srv := &APIServer{
				Router: *httprouter.New(),
				APIConfig: APIConfig{
					AuthServer: &Server{oidcAuthService: svc},
					Authorizer: authz.AuthorizerFunc(func(context.Context) (*authz.Context, error) { return ctx, nil }),
				},
			}
			srv.RegisterKeycloakHandlers()
			r := httptest.NewRequest(http.MethodPost, "/v1/oidc/requests/validate", strings.NewReader(`{"query":{"state":["opaque"],"code":["opaque"]}}`))
			r.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			srv.ServeHTTP(w, r)
			if role != types.RoleProxy {
				require.Equal(t, http.StatusForbidden, w.Code)
				require.Zero(t, svc.calls, "unauthorized identity must not consume state or mint credentials")
				return
			}
			require.Equal(t, http.StatusOK, w.Code)
			require.Equal(t, 1, svc.calls)
			var response authclient.OIDCAuthRawResponse
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
			require.Equal(t, "keycloak-user", response.Username)
			require.Equal(t, []byte("ssh certificate"), response.Cert)
		})
	}
}

func TestKeycloakHTTPCallbackMiddlewareAndErrorRedaction(t *testing.T) {
	t.Parallel()
	for _, authDenied := range []bool{true, false} {
		t.Run(map[bool]string{true: "unauthenticated", false: "provider error"}[authDenied], func(t *testing.T) {
			ctx, err := authz.NewBuiltinRoleContext(types.RoleProxy)
			require.NoError(t, err)
			svc := &keycloakHTTPTestService{err: trace.AccessDenied("sensitive provider response")}
			srv := &APIServer{
				Router: *httprouter.New(),
				APIConfig: APIConfig{
					AuthServer: &Server{oidcAuthService: svc},
					Authorizer: authz.AuthorizerFunc(func(context.Context) (*authz.Context, error) {
						if authDenied {
							return nil, trace.AccessDenied("authentication required")
						}
						return ctx, nil
					}),
				},
			}
			srv.RegisterKeycloakHandlers()
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodPost, "/v1/oidc/requests/validate", strings.NewReader(`{"query":{}}`))
			r.Header.Set("Content-Type", "application/json")
			srv.ServeHTTP(w, r)
			require.Equal(t, http.StatusForbidden, w.Code)
			require.NotContains(t, w.Body.String(), "sensitive provider response")
			if authDenied {
				require.Zero(t, svc.calls)
			} else {
				require.Equal(t, 1, svc.calls)
			}
		})
	}
}
