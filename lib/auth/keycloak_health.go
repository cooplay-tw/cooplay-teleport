// Copyright (C) 2026 Cooplay contributors.
// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

import (
	"context"
	"encoding/json"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/gravitational/trace"

	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/backend"
	"github.com/gravitational/teleport/lib/services/local"
)

const keycloakHealthLockPrefix = "keycloak-health-"

func keycloakHealthLockName(connector string) string {
	return keycloakHealthLockPrefix + keycloakDigest(connector)
}

// IsKeycloakHealthLock distinguishes the temporary reconciliation fence from
// a lock revoking a specific login or account.
func IsKeycloakHealthLock(lock types.Lock) bool {
	role := lock.Target().Role
	digest, ok := strings.CutPrefix(role, keycloakGuardPrefix)
	return ok && lock.Target() == (types.LockTarget{Role: role}) &&
		lock.GetName() == keycloakHealthLockPrefix+digest
}

func (s *keycloakService) lastKeycloakHealth(ctx context.Context, connector string) time.Time {
	item, err := s.a.bk.Get(ctx, keycloakLifecycleKey("health", connector))
	var last time.Time
	if err == nil && json.Unmarshal(item.Value, &last) == nil {
		return last
	}
	return time.Time{}
}

func (s *keycloakService) keycloakHealthStale(last time.Time) bool {
	return last.IsZero() || s.a.clock.Now().Sub(last) > time.Duration(s.lifecycle.MaxStaleSeconds)*time.Second
}

func (s *keycloakService) readHealthLockEvents(ctx context.Context, connector string) (uint64, backend.Condition, error) {
	item, err := s.a.bk.Get(ctx, keycloakLifecycleKey("health-lock-events", connector))
	if trace.IsNotFound(err) {
		return 0, backend.NotExists(), nil
	}
	if err != nil {
		return 0, backend.Condition{}, err
	}
	value, err := strconv.ParseUint(string(item.Value), 10, 64)
	return value, backend.Revision(item.Revision), err
}

func (s *keycloakService) exportHealthLockEvents(ctx context.Context, connector string) {
	count, _, err := s.readHealthLockEvents(ctx, connector)
	if err != nil {
		s.a.logger.ErrorContext(ctx, "Keycloak health lock event count unavailable", "connector", connector)
		return
	}
	keycloakHealthLockEvents.WithLabelValues(connector).Set(float64(count))
}

func (s *keycloakService) lockUnhealthyConnector(ctx context.Context, connector string) error {
	name, target := keycloakHealthLockName(connector), types.LockTarget{Role: keycloakGuard(connector)}
	const reason = "synchronization-unavailable"
	// Reserve time for native fencing if accounting fails. The health lock
	// must still be applied if the telemetry record cannot be read or written.
	accounting, cancel := context.WithTimeout(ctx, time.Second)
	err := s.createCountedHealthLock(accounting, connector, name, target, reason)
	cancel()
	if err != nil {
		s.a.logger.ErrorContext(ctx, "Keycloak could not account for health lock creation", "connector", connector)
		if err := s.ensureLock(ctx, name, target, reason); err != nil {
			return err
		}
	}
	keycloakHealthLockActive.WithLabelValues(connector).Set(1)
	return nil
}

func (s *keycloakService) createCountedHealthLock(ctx context.Context, connector, name string, target types.LockTarget, reason string) error {
	for range 2 {
		existing, err := s.a.Services.GetLock(ctx, name)
		if err != nil && !trace.IsNotFound(err) {
			return err
		}
		if existing != nil && existing.Target() == target && existing.LockExpiry() == nil {
			return nil
		}
		lock, err := types.NewLock(name, types.LockSpecV2{Target: target, Message: "Keycloak: " + reason})
		if err != nil {
			return err
		}
		lockItem, err := local.LockItem(lock)
		if err != nil {
			return err
		}
		actions := []backend.ConditionalAction{
			{Key: lockItem.Key, Condition: backend.NotExists(), Action: backend.Put(*lockItem)},
		}
		var nextCount uint64
		if existing == nil {
			count, condition, err := s.readHealthLockEvents(ctx, connector)
			if err != nil {
				return err
			}
			if count == math.MaxUint64 {
				return trace.LimitExceeded("Keycloak health lock event count exhausted")
			}
			nextCount = count + 1
			counter := backend.Item{
				Key:   keycloakLifecycleKey("health-lock-events", connector),
				Value: strconv.AppendUint(nil, nextCount, 10),
			}
			actions = append(actions, backend.ConditionalAction{Key: counter.Key, Condition: condition, Action: backend.Put(counter)})
		} else {
			// A concurrent deletion must not turn a repair into an uncounted
			// creation.
			actions[0].Condition = backend.Revision(existing.GetRevision())
		}
		_, err = s.a.bk.AtomicWrite(ctx, actions)
		if trace.IsCompareFailed(err) {
			continue
		}
		if err != nil {
			return err
		}
		if existing == nil {
			keycloakHealthLockEvents.WithLabelValues(connector).Set(float64(nextCount))
		}
		s.a.emitLockCreated(ctx, lock)
		return nil
	}
	return backend.ErrConditionFailed
}
