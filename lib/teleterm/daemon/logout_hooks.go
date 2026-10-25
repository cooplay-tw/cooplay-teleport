// Copyright (C) 2026 Cooplay contributors.
// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"slices"
	"sync"
)

// logoutHooks are functions notified whenever ClusterLogout finishes.
type logoutHooks struct {
	mu    sync.Mutex
	hooks []func(profileName string)
}

// AddLogoutHook registers fn to run after every ClusterLogout of a root
// cluster profile, including logouts whose remote revocation or local cleanup
// failed and logouts of profiles that no longer exist. It runs after local
// credentials were deleted and cached clients were cleared. VNet uses it to
// stop reusing app certificates issued before the logout. fn must not block
// and must not call ClusterLogout.
func (s *Service) AddLogoutHook(fn func(profileName string)) {
	s.logoutHooks.mu.Lock()
	defer s.logoutHooks.mu.Unlock()
	s.logoutHooks.hooks = append(s.logoutHooks.hooks, fn)
}

func (h *logoutHooks) run(profileName string) {
	h.mu.Lock()
	hooks := slices.Clone(h.hooks)
	h.mu.Unlock()
	for _, fn := range hooks {
		fn(profileName)
	}
}
