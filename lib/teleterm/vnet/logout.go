// Copyright (C) 2026 Cooplay contributors.
// SPDX-License-Identifier: AGPL-3.0-or-later

package vnet

import "context"

// forgetProfileCredentials runs after the daemon logged out of profileName.
// It makes a running VNet stop reusing app certificates that were issued
// before the logout: the next connection to each app of the profile reissues
// a certificate with current credentials, which prompts for login while the
// profile is logged out. It does not close established connections; for
// Keycloak logins those are terminated by the server-side strict locks.
//
// It deliberately does not take s.mu, which Start and diagnostics may hold
// for a long time; a process that is still starting has no cached
// certificates yet.
func (s *Service) forgetProfileCredentials(profileName string) {
	if process := s.credentialsProcess.Load(); process != nil {
		process.ForgetProfileCredentials(profileName)
		log.InfoContext(context.Background(), "Dropped VNet app credentials after logout", "profile", profileName)
	}
}
