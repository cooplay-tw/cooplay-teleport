// Copyright (C) 2026 Cooplay contributors.
// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

import (
	"context"
	"slices"
	"strings"
	"time"

	"github.com/gravitational/trace"

	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/services"
)

func (s *keycloakService) purgeRevokedAppSessions(ctx context.Context, user string, target types.LockTarget) {
	if user == "" {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	s.cleanupAppSessions(ctx, "Keycloak revocation app session cleanup", user, target.User == user, map[string]struct{}{target.Role: {}})
}

func (s *keycloakService) sweepLockedAppSessions(ctx context.Context) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	const message = "Keycloak startup app session sweep"
	lockedRoles := make(map[string]struct{})
	for lock, err := range s.a.Services.RangeLocks(ctx, "", "", &types.LockFilter{InForceOnly: true}) {
		if err != nil {
			s.a.logger.WarnContext(ctx, message, "scanned", 0, "deleted", 0, "failed", 1)
			return
		}
		target := lock.Target()
		if strings.HasPrefix(target.Role, keycloakLoginPrefix) && target == (types.LockTarget{Role: target.Role}) {
			lockedRoles[target.Role] = struct{}{}
		}
	}
	s.cleanupAppSessions(ctx, message, "", false, lockedRoles)
}

func (s *keycloakService) cleanupAppSessions(ctx context.Context, message, user string, allForUser bool, lockedRoles map[string]struct{}) {
	var scanned, deleted, failed int
	defer func() {
		level := s.a.logger.InfoContext
		if failed > 0 {
			level = s.a.logger.WarnContext
		}
		level(ctx, message, "scanned", scanned, "deleted", deleted, "failed", failed)
	}()
	if len(lockedRoles) == 0 && !allForUser {
		return
	}
	var cursor string
	for {
		sessions, next, err := s.a.Services.ListAppSessions(ctx, 200, cursor, user)
		if err != nil {
			failed++
			return
		}
		for _, session := range sessions {
			scanned++
			if !allForUser {
				identity, err := services.WebSessionTLSIdentity(session)
				if err != nil || identity.Username != session.GetUser() {
					failed++
					continue
				}
				if !slices.ContainsFunc(identity.Groups, func(role string) bool {
					_, locked := lockedRoles[role]
					return locked
				}) {
					continue
				}
			}
			switch err := s.a.Services.DeleteAppSession(ctx, types.DeleteAppSessionRequest{SessionID: session.GetName()}); {
			case err == nil:
				deleted++
			case !trace.IsNotFound(err):
				failed++
			}
		}
		if next == "" {
			return
		}
		cursor = next
	}
}
