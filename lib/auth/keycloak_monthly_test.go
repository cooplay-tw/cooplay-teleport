// Copyright (C) 2026 Cooplay contributors.
// SPDX-License-Identifier: AGPL-3.0-or-later
package auth_test

import (
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/auth"
	"github.com/gravitational/teleport/lib/tlsca"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"strings"
	"testing"
	"time"
)

func TestKeycloakManagedMonthlyCertificateBounds(t *testing.T) {
	const cap = 30 * 24 * time.Hour
	for _, requested := range []time.Duration{time.Hour, cap, cap + time.Hour} {
		t.Run(requested.String(), func(t *testing.T) {
			f, _, _ := managedKeycloakFixture(t, int(cap/time.Second))
			f.requestedTTL = requested
			_, q := f.begin(t, false, func(c map[string]any) { c["sid"] = "sid-a" })
			response, err := f.svc.ValidateOIDCAuthCallback(f.ctx, q)
			require.NoError(t, err)
			key, _, _, _, err := ssh.ParseAuthorizedKey(response.Cert)
			require.NoError(t, err)
			expected := f.clock.Now().Add(min(requested, cap))
			require.WithinDuration(t, expected, time.Unix(int64(key.(*ssh.Certificate).ValidBefore), 0), 5*time.Second)
			cert, err := tlsca.ParseCertificatePEM(response.TLSCert)
			require.NoError(t, err)
			require.WithinDuration(t, expected, cert.NotAfter, 5*time.Second)
		})
	}
}

func TestKeycloakManagedMonthlyMigrationPreservesOldDeadline(t *testing.T) {
	f, _, cfg := managedKeycloakFixture(t, 86400)
	f.requestedTTL = 24 * time.Hour
	old, oldRoles := managedLogin(t, f, "sid-a")
	expiry := old.Session.GetExpiryTime()
	cfg.MaxSessionSeconds = 2592000
	role := keycloakLabRole(t).(*types.RoleV6)
	role.Spec.Options.MaxSessionTTL = types.Duration(30 * 24 * time.Hour)
	_, err := f.a.AuthServer.UpsertRole(f.ctx, role)
	require.NoError(t, err)
	f.svc, err = auth.NewManagedKeycloakService(f.a.AuthServer, cfg)
	require.NoError(t, err)
	f.a.AuthServer.SetOIDCService(f.svc)
	require.NoError(t, auth.ReconcileKeycloak(f.ctx, f.svc))
	f.requestedTTL = 30 * 24 * time.Hour
	newer, _ := managedLogin(t, f, "sid-b")
	require.WithinDuration(t, f.clock.Now().Add(30*24*time.Hour), newer.Session.GetExpiryTime(), 5*time.Second)
	for _, name := range oldRoles {
		if !strings.HasPrefix(name, "keycloak-login-") {
			continue
		}
		marker, err := f.a.AuthServer.GetRole(f.ctx, name)
		require.NoError(t, err)
		require.Equal(t, 24*time.Hour, marker.GetOptions().MaxSessionTTL.Duration())
	}
	require.Equal(t, expiry, old.Session.GetExpiryTime())
}
