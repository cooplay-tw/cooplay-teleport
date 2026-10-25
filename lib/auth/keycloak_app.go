// Copyright (C) 2026 Cooplay contributors.
// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

import (
	"context"
	"time"

	"github.com/gravitational/trace"

	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/tlsca"
)

// keycloakAppSessionDeadline bounds application web sessions created through
// CreateAppSession (the web application launcher and direct API callers) by
// the same absolute Keycloak login deadline as resource-specific certificate
// reissue. Native CreateAppSession derives its TTL from the caller's identity
// expiry only; it neither consults the stored user expiry nor the durable
// Keycloak revocation state while native lock propagation is in flight.
//
// For a Keycloak user it rechecks durable revocation state, reserves signing
// time in the identity's expiry, and returns the absolute deadline that the
// caller must verify against the issued session. It returns the zero time for
// every other user, whose behavior is unchanged.
func (a *ServerWithRoles) keycloakAppSessionDeadline(ctx context.Context, identity *tlsca.Identity) (time.Time, error) {
	if !IsKeycloakUser(a.context.User) {
		return time.Time{}, nil
	}
	user := a.context.User
	if identity.Username != user.GetName() {
		return time.Time{}, trace.AccessDenied("Keycloak identity mismatch")
	}
	if err := a.authServer.checkKeycloakRoles(ctx, user.GetName(), identity.Groups); err != nil {
		return time.Time{}, err
	}
	if identity.Expires.IsZero() || user.Expiry().IsZero() {
		return time.Time{}, trace.AccessDenied("Keycloak identity has no expiry")
	}
	deadline := identity.Expires
	if user.Expiry().Before(deadline) {
		deadline = user.Expiry()
	}
	// Native APIs use durations; reserve signing time and verify the actual
	// result against the unchanged absolute deadline after issuance.
	identity.Expires = deadline.Add(-time.Second)
	if !identity.Expires.After(a.authServer.GetClock().Now()) {
		return time.Time{}, trace.AccessDenied("Keycloak identity expires too soon")
	}
	return deadline, nil
}

// keycloakCheckAppSession enforces the absolute deadline on an issued
// application session. An overlong session is deleted and never returned.
func (a *ServerWithRoles) keycloakCheckAppSession(ctx context.Context, session types.WebSession, deadline time.Time) error {
	if deadline.IsZero() {
		return nil
	}
	if err := keycloakSessionExpiry(session, deadline); err != nil {
		_ = a.authServer.DeleteAppSession(context.WithoutCancel(ctx), types.DeleteAppSessionRequest{SessionID: session.GetName()})
		return trace.Wrap(err)
	}
	return nil
}
