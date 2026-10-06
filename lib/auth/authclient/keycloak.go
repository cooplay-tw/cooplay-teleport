// Copyright (C) 2026 Cooplay contributors.
// SPDX-License-Identifier: AGPL-3.0-or-later
package authclient

import (
	"context"
	"github.com/gravitational/trace"
)

// KeycloakLogoutRequest has no user-selected revocation target. Empty means
// the caller's login; token mode is restricted to a native Proxy identity.
type KeycloakLogoutRequest struct {
	ConnectorID string `json:"connector_id,omitempty"`
	LogoutToken string `json:"logout_token,omitempty"`
}

func (c *HTTPClient) KeycloakLogout(ctx context.Context, req KeycloakLogoutRequest) error {
	_, err := c.PostJSON(ctx, c.Endpoint("keycloak", "logout"), req)
	return trace.Wrap(err)
}
