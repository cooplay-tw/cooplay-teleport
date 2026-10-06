// Copyright (C) 2026 Cooplay contributors.
// SPDX-License-Identifier: AGPL-3.0-or-later
package client

import (
	"context"
	"strings"
	"time"

	"github.com/gravitational/trace"

	"github.com/gravitational/teleport/lib/auth/authclient"
)

// RevokeKeycloakLogin revokes only the current profile's login. Call before
// deleting local keys; local cleanup must still run if the network is down.
func (tc *TeleportClient) RevokeKeycloakLogin(ctx context.Context) error {
	profile, err := tc.ProfileStatus()
	if profile == nil || !strings.HasPrefix(profile.Username, "keycloak-") {
		return nil
	}
	if err != nil && !trace.IsCompareFailed(err) {
		return trace.ConnectionProblem(nil, "Keycloak credential revocation was not confirmed")
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	cluster, err := tc.ConnectToCluster(ctx)
	if err != nil {
		return trace.ConnectionProblem(nil, "Keycloak credential revocation was not confirmed")
	}
	defer cluster.Close()
	root, err := cluster.ConnectToRootCluster(ctx)
	if err != nil {
		return trace.ConnectionProblem(nil, "Keycloak credential revocation was not confirmed")
	}
	defer root.Close()
	if err := root.KeycloakLogout(ctx, authclient.KeycloakLogoutRequest{}); err != nil {
		return trace.ConnectionProblem(nil, "Keycloak credential revocation was not confirmed")
	}
	return nil
}
