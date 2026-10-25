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

// keycloakUsernamePrefix marks usernames derived by the fork's Keycloak
// connector from the issuer and immutable subject.
const keycloakUsernamePrefix = "keycloak-"

// ErrKeycloakRevocationNotConfirmed reports a logout whose local credentials
// were removed although the server did not confirm revocation of the current
// Keycloak login. Callers should treat it as non-fatal but visible.
var ErrKeycloakRevocationNotConfirmed = &trace.ConnectionProblemError{
	Message: "Local credentials cleared; Keycloak credential revocation was not confirmed",
}

// IsKeycloakUsername reports whether username belongs to a login issued by the
// fork's Keycloak connector.
func IsKeycloakUsername(username string) bool {
	return strings.HasPrefix(username, keycloakUsernamePrefix)
}

// IsKeycloakRevocationNotConfirmed reports whether err is exactly
// ErrKeycloakRevocationNotConfirmed, i.e. local cleanup itself succeeded.
func IsKeycloakRevocationNotConfirmed(err error) bool {
	return err != nil && trace.Unwrap(err) == ErrKeycloakRevocationNotConfirmed
}

// RevokeKeycloakLogin revokes only the current profile's login. Call before
// deleting local keys; local cleanup must still run if the network is down.
func (tc *TeleportClient) RevokeKeycloakLogin(ctx context.Context) error {
	profile, err := tc.ProfileStatus()
	if profile == nil || !IsKeycloakUsername(profile.Username) {
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
