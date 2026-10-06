// Copyright (C) 2026 Cooplay contributors.
// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

import (
	"os"

	"github.com/gravitational/trace"

	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/entitlements"
	"github.com/gravitational/teleport/lib/modules"
)

// KeycloakSSOEnabled is an explicit, experimental opt-in for this fork's
// independently implemented connector. It does not grant Enterprise features.
// Configure it identically on every Auth and Proxy process before startup.
func KeycloakSSOEnabled() bool {
	return os.Getenv("TELEPORT_UNSTABLE_KEYCLOAK") == "yes"
}

func (a *Server) checkOIDCConnectorCapability(connector types.OIDCConnector) error {
	if modules.GetModules().Features().GetEntitlement(entitlements.OIDC).Enabled {
		return nil
	}
	_, keycloak := a.oidcAuthService.(*keycloakService)
	if !KeycloakSSOEnabled() || !keycloak {
		return trace.AccessDenied("OIDC is only available in Teleport Enterprise or the explicitly enabled experimental Keycloak connector")
	}
	return ValidateKeycloakConnector(connector)
}

func (a *Server) hasOIDCLoginCapability() bool {
	_, keycloak := a.oidcAuthService.(*keycloakService)
	return modules.GetModules().Features().GetEntitlement(entitlements.OIDC).Enabled ||
		(KeycloakSSOEnabled() && keycloak)
}
