// Copyright (C) 2026 Cooplay contributors.
// SPDX-License-Identifier: AGPL-3.0-or-later

package clusters

import (
	"context"

	"github.com/gravitational/trace"

	"github.com/gravitational/teleport/lib/client"
)

// revokeKeycloakLogin revokes the current Keycloak login of tc's profile.
// Tests replace it to observe ordering without a Teleport cluster.
var revokeKeycloakLogin = func(ctx context.Context, tc *client.TeleportClient) error {
	return trace.Wrap(tc.RevokeKeycloakLogin(ctx))
}

// revokeKeycloakLoginBeforeLogout revokes the profile's current Keycloak login
// server-side while its local credentials still exist to authenticate the
// request. The profile status is only populated when a key ring is present,
// so an already logged-out profile is not revoked again. Any failure is
// reported as [client.ErrKeycloakRevocationNotConfirmed]; the caller must
// still delete local credentials.
func (c *Cluster) revokeKeycloakLoginBeforeLogout(ctx context.Context) error {
	if !client.IsKeycloakUsername(c.status.Username) {
		return nil
	}
	if err := revokeKeycloakLogin(ctx, c.clusterClient); err != nil {
		c.Logger.WarnContext(ctx, "Keycloak credential revocation was not confirmed, clearing local credentials anyway", "error", err)
		return trace.Wrap(client.ErrKeycloakRevocationNotConfirmed)
	}
	return nil
}
