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
