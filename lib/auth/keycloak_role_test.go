// Copyright (C) 2026 Cooplay contributors.
// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

import (
	"github.com/gravitational/teleport/lib/services"
	"os"
	"reflect"
	"sigs.k8s.io/yaml"
	"strings"
	"testing"
	"time"

	"github.com/gravitational/trace"
	"github.com/stretchr/testify/require"

	"github.com/gravitational/teleport/api/constants"
	"github.com/gravitational/teleport/api/types"
)

func keycloakSSHRoleForValidation() *types.RoleV6 {
	return &types.RoleV6{Version: types.V8, Spec: types.RoleSpecV6{
		Options: types.RoleOptions{
			MaxSessionTTL:         types.Duration(5 * time.Minute),
			DisconnectExpiredCert: true, Lock: constants.LockingModeStrict,
		},
		Allow: types.RoleConditions{
			Logins: []string{"lab-user"}, Namespaces: []string{"default"},
			NodeLabels:           types.Labels{"environment": {"lab"}},
			NodeLabelsExpression: `labels["environment"] == "lab"`,
		},
	}}
}

func TestKeycloakRoleConditionsWhitelist(t *testing.T) {
	require.NoError(t, validateKeycloakRole(keycloakSSHRoleForValidation()))
	fields := reflect.TypeOf(types.RoleConditions{})
	for i := 0; i < fields.NumField(); i++ {
		field := fields.Field(i)
		switch field.Name {
		case "Logins", "Namespaces", "NodeLabels", "NodeLabelsExpression":
			continue
		}
		if strings.HasPrefix(field.Name, "XXX_") {
			continue
		}
		t.Run(field.Name, func(t *testing.T) {
			role := keycloakSSHRoleForValidation()
			value := reflect.ValueOf(&role.Spec.Allow).Elem().Field(i)
			switch value.Kind() {
			case reflect.String:
				value.SetString("*")
			case reflect.Slice:
				value.Set(reflect.MakeSlice(value.Type(), 1, 1))
			case reflect.Map:
				value.Set(reflect.MakeMap(value.Type()))
				value.SetMapIndex(reflect.ValueOf("*"), reflect.MakeSlice(value.Type().Elem(), 1, 1))
			case reflect.Pointer:
				value.Set(reflect.New(value.Type().Elem()))
			default:
				t.Fatalf("new RoleConditions field %s needs a nonempty test value", field.Name)
			}
			err := validateKeycloakRole(role)
			require.True(t, trace.IsAccessDenied(err), "unexpectedly accepted %s: %v", field.Name, err)
		})
	}
	t.Run("unknown protobuf grant", func(t *testing.T) {
		role := keycloakSSHRoleForValidation()
		// Unknown field 1000, length-delimited, retained by protobuf decode.
		require.NoError(t, role.Spec.Allow.Unmarshal([]byte{0xc2, 0x3e, 0x01, 'x'}))
		require.True(t, trace.IsAccessDenied(validateKeycloakRole(role)))
	})
	t.Run("older role defaults", func(t *testing.T) {
		role := keycloakSSHRoleForValidation()
		role.Version = types.V3
		require.True(t, trace.IsAccessDenied(validateKeycloakRole(role)))
	})
}

func TestKeycloakKubernetesRole(t *testing.T) {
	data, err := os.ReadFile("../../examples/keycloak/kubernetes-role.yaml")
	require.NoError(t, err)
	data, err = yaml.YAMLToJSON(data)
	require.NoError(t, err)
	role, err := services.UnmarshalRole(data)
	require.NoError(t, err)
	require.NoError(t, validateKeycloakRole(role))
	for _, change := range []func(*types.RoleV6){
		func(r *types.RoleV6) { r.Spec.Allow.KubernetesResources[0].Namespace = "*" },
		func(r *types.RoleV6) { r.Spec.Allow.KubernetesResources[0].Verbs = []string{"*"} },
		func(r *types.RoleV6) { r.Spec.Allow.KubernetesResources[0].Kind = "secrets" },
		func(r *types.RoleV6) { r.Spec.Allow.KubeGroups = []string{"system:masters"} },
		func(r *types.RoleV6) { r.Spec.Allow.KubernetesResources = nil },
	} {
		fresh, err := services.UnmarshalRole(data)
		require.NoError(t, err)
		change(fresh.(*types.RoleV6))
		require.Error(t, validateKeycloakRole(fresh))
	}
}

func TestKeycloakDailyRoleCapPreservesRestrictions(t *testing.T) {
	role := keycloakSSHRoleForValidation()
	role.Spec.Options.MaxSessionTTL = types.Duration(24 * time.Hour)
	require.Error(t, validateKeycloakRole(role))
	require.NoError(t, validateKeycloakRoleWithTTL(role, 24*time.Hour))
	role.Spec.Options.DisconnectExpiredCert = false
	require.Error(t, validateKeycloakRoleWithTTL(role, 24*time.Hour))
	role.Spec.Options.DisconnectExpiredCert = true
	role.Spec.Options.Lock = "best_effort"
	require.Error(t, validateKeycloakRoleWithTTL(role, 24*time.Hour))
	role.Spec.Options.Lock = "strict"
	role.Spec.Options.MaxSessionTTL = types.Duration(24*time.Hour + time.Second)
	require.Error(t, validateKeycloakRoleWithTTL(role, 24*time.Hour))
}

func keycloakCoderRoleForValidation() *types.RoleV6 {
	role := keycloakSSHRoleForValidation()
	role.Spec.Allow = types.RoleConditions{
		AppLabels: types.Labels{"cooplay.dev/app": {"coder"}},
	}
	return role
}

func TestKeycloakCoderAppGrant(t *testing.T) {
	// Guard the literal contract consumed by deployment configuration.
	require.Equal(t, "cooplay.dev/app", keycloakCoderAppLabelKey)
	require.Equal(t, "coder", keycloakCoderAppLabelValue)

	kubernetes := func(t *testing.T) *types.RoleV6 {
		data, err := os.ReadFile("../../examples/keycloak/kubernetes-role.yaml")
		require.NoError(t, err)
		data, err = yaml.YAMLToJSON(data)
		require.NoError(t, err)
		role, err := services.UnmarshalRole(data)
		require.NoError(t, err)
		return role.(*types.RoleV6)
	}
	exact := types.Labels{"cooplay.dev/app": {"coder"}}

	for _, tc := range []struct {
		name    string
		role    func(*testing.T) *types.RoleV6
		allowed bool
	}{
		{name: "exact grant", allowed: true, role: func(*testing.T) *types.RoleV6 { return keycloakCoderRoleForValidation() }},
		{name: "exact grant with SSH", allowed: true, role: func(*testing.T) *types.RoleV6 {
			role := keycloakSSHRoleForValidation()
			role.Spec.Allow.AppLabels = exact
			return role
		}},
		{name: "exact grant with bounded Kubernetes", allowed: true, role: func(t *testing.T) *types.RoleV6 {
			role := kubernetes(t)
			role.Spec.Allow.AppLabels = exact
			return role
		}},
		{name: "exact grant with invalid Kubernetes", role: func(t *testing.T) *types.RoleV6 {
			role := kubernetes(t)
			role.Spec.Allow.AppLabels = exact
			role.Spec.Allow.KubernetesResources[0].Kind = "secrets"
			return role
		}},
		{name: "exact grant with incomplete Kubernetes", role: func(t *testing.T) *types.RoleV6 {
			role := keycloakCoderRoleForValidation()
			role.Spec.Allow.KubeGroups = []string{"lab-readers"}
			return role
		}},
		{name: "wildcard key and value", role: withAppLabels(types.Labels{"*": {"*"}})},
		{name: "wildcard key", role: withAppLabels(types.Labels{"*": {"coder"}})},
		{name: "wildcard value", role: withAppLabels(types.Labels{"cooplay.dev/app": {"*"}})},
		{name: "glob value", role: withAppLabels(types.Labels{"cooplay.dev/app": {"cod*"}})},
		{name: "regex value", role: withAppLabels(types.Labels{"cooplay.dev/app": {"^coder$"}})},
		{name: "open regex value", role: withAppLabels(types.Labels{"cooplay.dev/app": {"^.*$"}})},
		{name: "template value", role: withAppLabels(types.Labels{"cooplay.dev/app": {"{{internal.logins}}"}})},
		{name: "other value", role: withAppLabels(types.Labels{"cooplay.dev/app": {"grafana"}})},
		{name: "case variant value", role: withAppLabels(types.Labels{"cooplay.dev/app": {"Coder"}})},
		{name: "case variant key", role: withAppLabels(types.Labels{"Cooplay.dev/app": {"coder"}})},
		{name: "other key", role: withAppLabels(types.Labels{"app": {"coder"}})},
		{name: "extra label", role: withAppLabels(types.Labels{"cooplay.dev/app": {"coder"}, "environment": {"lab"}})},
		{name: "extra value", role: withAppLabels(types.Labels{"cooplay.dev/app": {"coder", "grafana"}})},
		{name: "duplicate value", role: withAppLabels(types.Labels{"cooplay.dev/app": {"coder", "coder"}})},
		{name: "empty value list", role: withAppLabels(types.Labels{"cooplay.dev/app": {}})},
		{name: "expression only", role: func(*testing.T) *types.RoleV6 {
			role := keycloakSSHRoleForValidation()
			role.Spec.Allow.AppLabelsExpression = `labels["cooplay.dev/app"] == "coder"`
			return role
		}},
		{name: "expression with exact grant", role: func(*testing.T) *types.RoleV6 {
			role := keycloakCoderRoleForValidation()
			role.Spec.Allow.AppLabelsExpression = `labels["cooplay.dev/app"] == "coder"`
			return role
		}},
		{name: "AWS role ARNs", role: withCoderGrant(func(c *types.RoleConditions) {
			c.AWSRoleARNs = []string{"arn:aws:iam::123456789012:role/lab"}
		})},
		{name: "Azure identities", role: withCoderGrant(func(c *types.RoleConditions) {
			c.AzureIdentities = []string{"/subscriptions/0/resourceGroups/lab/providers/Microsoft.ManagedIdentity/userAssignedIdentities/lab"}
		})},
		{name: "GCP service accounts", role: withCoderGrant(func(c *types.RoleConditions) {
			c.GCPServiceAccounts = []string{"lab@example.iam.gserviceaccount.com"}
		})},
		{name: "MCP tools", role: withCoderGrant(func(c *types.RoleConditions) { c.MCP = &types.MCPPermissions{Tools: []string{"*"}} })},
		{name: "empty MCP permissions", role: withCoderGrant(func(c *types.RoleConditions) { c.MCP = &types.MCPPermissions{} })},
		{name: "database labels", role: withCoderGrant(func(c *types.RoleConditions) { c.DatabaseLabels = types.Labels{"cooplay.dev/app": {"coder"}} })},
		{name: "desktop labels", role: withCoderGrant(func(c *types.RoleConditions) {
			c.WindowsDesktopLabels = types.Labels{"cooplay.dev/app": {"coder"}}
		})},
		{name: "admin rules", role: withCoderGrant(func(c *types.RoleConditions) {
			c.Rules = []types.Rule{{Resources: []string{types.KindApp}, Verbs: []string{types.VerbList}}}
		})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateKeycloakRole(tc.role(t))
			if tc.allowed {
				require.NoError(t, err)
				return
			}
			require.True(t, trace.IsAccessDenied(err), "unexpectedly accepted: %v", err)
		})
	}

	t.Run("unknown protobuf field with exact grant", func(t *testing.T) {
		role := keycloakCoderRoleForValidation()
		require.NoError(t, role.Spec.Allow.Unmarshal([]byte{0xc2, 0x3e, 0x01, 'x'}))
		require.Equal(t, exact, role.Spec.Allow.AppLabels, "unknown field decode must keep the exact grant")
		require.True(t, trace.IsAccessDenied(validateKeycloakRole(role)))
	})
	t.Run("session requirements still apply", func(t *testing.T) {
		for _, mutate := range []func(*types.RoleV6){
			func(r *types.RoleV6) { r.Spec.Options.MaxSessionTTL = types.Duration(time.Hour) },
			func(r *types.RoleV6) { r.Spec.Options.MaxSessionTTL = 0 },
			func(r *types.RoleV6) { r.Spec.Options.DisconnectExpiredCert = false },
			func(r *types.RoleV6) { r.Spec.Options.Lock = constants.LockingModeBestEffort },
			func(r *types.RoleV6) { r.Version = types.V7 },
		} {
			role := keycloakCoderRoleForValidation()
			mutate(role)
			require.True(t, trace.IsAccessDenied(validateKeycloakRole(role)))
		}
		role := keycloakCoderRoleForValidation()
		role.Spec.Options.MaxSessionTTL = types.Duration(30 * 24 * time.Hour)
		require.NoError(t, validateKeycloakRoleWithTTL(role, 30*24*time.Hour))
		require.Error(t, validateKeycloakRoleWithTTL(role, 24*time.Hour))
	})
	t.Run("published example", func(t *testing.T) {
		data, err := os.ReadFile("../../examples/keycloak/coder-app-role.yaml")
		require.NoError(t, err)
		data, err = yaml.YAMLToJSON(data)
		require.NoError(t, err)
		role, err := services.UnmarshalRole(data)
		require.NoError(t, err)
		require.Equal(t, exact, role.GetAppLabels(types.Allow))
		require.Empty(t, role.GetLogins(types.Allow))
		require.Empty(t, role.GetKubernetesLabels(types.Allow))
		require.NoError(t, validateKeycloakRole(role))
	})
}

func withAppLabels(labels types.Labels) func(*testing.T) *types.RoleV6 {
	return func(*testing.T) *types.RoleV6 {
		role := keycloakSSHRoleForValidation()
		role.Spec.Allow.AppLabels = labels
		return role
	}
}

func withCoderGrant(mutate func(*types.RoleConditions)) func(*testing.T) *types.RoleV6 {
	return func(*testing.T) *types.RoleV6 {
		role := keycloakCoderRoleForValidation()
		mutate(&role.Spec.Allow)
		return role
	}
}
