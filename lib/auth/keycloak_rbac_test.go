// Copyright (C) 2026 Cooplay contributors.
// SPDX-License-Identifier: AGPL-3.0-or-later

package auth_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/gravitational/trace"
	"github.com/stretchr/testify/require"

	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/entitlements"
	"github.com/gravitational/teleport/lib/auth"
	"github.com/gravitational/teleport/lib/auth/authtest"
	"github.com/gravitational/teleport/lib/modules"
)

func TestKeycloakOptIn(t *testing.T) {
	for _, value := range []string{"", "true", "1", "YES", "yes"} {
		t.Run(value, func(t *testing.T) {
			t.Setenv("TELEPORT_UNSTABLE_KEYCLOAK", value)
			require.Equal(t, value == "yes", auth.KeycloakSSOEnabled())
			require.False(t, modules.GetModules().Features().GetEntitlement(entitlements.OIDC).Enabled)
			require.False(t, modules.GetModules().IsEnterpriseBuild())
		})
	}
}

func TestKeycloakConnectorRBAC(t *testing.T) {
	srv := newTestTLSServer(t)
	t.Setenv("TELEPORT_UNSTABLE_KEYCLOAK", "yes")
	srv.Auth().SetOIDCService(auth.NewKeycloakService(srv.Auth()))
	ctx := t.Context()
	connector, err := types.NewOIDCConnector("keycloak-lab", types.OIDCConnectorSpecV3{
		Provider:      "keycloak",
		IssuerURL:     "https://idp.example.invalid/realms/lab",
		ClientID:      "teleport-lab",
		ClientSecret:  "test-fixture-only",
		RedirectURLs:  []string{"https://proxy.example.invalid/v1/webapi/oidc/callback"},
		Scope:         []string{"openid", "groups"},
		ClaimsToRoles: []types.ClaimMapping{{Claim: "groups", Value: "/lab/readers", Roles: []string{"lab-reader"}}},
	})
	require.NoError(t, err)
	admin, err := srv.NewClient(authtest.TestBuiltin(types.RoleAdmin))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, admin.Close()) })
	_, err = admin.CreateOIDCConnector(ctx, connector)
	require.NoError(t, err)

	role, err := authtest.CreateRole(ctx, srv.Auth(), "keycloak-no-management", types.RoleSpecV6{})
	require.NoError(t, err)
	user, err := authtest.CreateUser(ctx, srv.Auth(), "keycloak-rbac-user", role)
	require.NoError(t, err)
	unprivileged, err := srv.NewClient(authtest.TestUser(user.GetName()))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, unprivileged.Close()) })
	_, err = unprivileged.UpsertOIDCConnector(ctx, connector)
	require.True(t, trace.IsAccessDenied(err), "unprivileged connector write: %v", err)
	_, err = unprivileged.GetOIDCConnector(ctx, connector.GetName(), true)
	require.True(t, trace.IsAccessDenied(err), "unprivileged secret read: %v", err)
	_, err = unprivileged.CreateOIDCAuthRequest(ctx, types.OIDCAuthRequest{ConnectorID: connector.GetName(), CreateWebSession: true})
	require.True(t, trace.IsAccessDenied(err), "unprivileged auth request: %v", err)

	connector.SetProvider("google")
	_, err = admin.UpsertOIDCConnector(ctx, connector)
	require.Error(t, err, "fork capability must not enable other OIDC providers")
	connector.SetProvider("keycloak")
	t.Setenv("TELEPORT_UNSTABLE_KEYCLOAK", "")
	_, err = admin.UpsertOIDCConnector(ctx, connector)
	require.True(t, trace.IsAccessDenied(err), "disabled opt-in: %v", err)
}

func TestKeycloakStartupRequiresManagedConfiguration(t *testing.T) {
	for _, input := range []string{"", "{invalid-json}", "{}", "{} {}"} {
		t.Run(input, func(t *testing.T) {
			t.Setenv("TELEPORT_UNSTABLE_KEYCLOAK", "yes")
			path := ""
			if input != "" {
				path = filepath.Join(t.TempDir(), "lifecycle.json")
				require.NoError(t, os.WriteFile(path, []byte(input), 0600))
			}
			t.Setenv("TELEPORT_KEYCLOAK_CONFIG", path)
			server, err := authtest.NewAuthServer(authtest.AuthServerConfig{Dir: t.TempDir()})
			if server != nil {
				require.NoError(t, server.Close())
			}
			require.Error(t, err, "opt-in must never start with the protocol-only fixture service")
		})
	}
}
