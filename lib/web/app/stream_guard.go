// Copyright (C) 2026 Cooplay contributors.
// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"context"
	"time"
)

// App logout deletes the app web session; connection locks alone cannot
// observe that deletion. Keep checking it while HTTP, upgraded WebSocket or
// tunneled TCP requests are active, including silent streams. An unavailable
// access point fails closed. Checks never issue or refresh credentials.
const appStreamCheckInterval = 2 * time.Second
const appStreamCheckTimeout = 3 * time.Second

func monitorAppStream(parent context.Context, interval time.Duration, check func(context.Context) error) (context.Context, func()) {
	ctx, cancel := context.WithCancelCause(parent)
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				probe, stop := context.WithTimeout(ctx, appStreamCheckTimeout)
				err := check(probe)
				stop()
				if err != nil {
					cancel(err)
					return
				}
			}
		}
	}()
	return ctx, func() { cancel(nil); <-done }
}
