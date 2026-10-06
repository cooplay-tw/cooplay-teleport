// Copyright (C) 2026 Cooplay contributors.
// SPDX-License-Identifier: AGPL-3.0-or-later
package auth

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gravitational/trace"
)

type keycloakJournalEntry struct {
	Kind       string             `json:"kind"`
	ID         string             `json:"id"`
	Revocation keycloakRevocation `json:"revocation"`
	Expires    time.Time          `json:"expires,omitempty"`
}

// Each immutable entry is fsynced before an atomic link publishes its name.
// This directory belongs on a separate persistent encrypted volume and must be
// preserved when restoring an older Teleport snapshot. It contains no tokens.
func (s *keycloakService) appendJournal(entry keycloakJournalEntry) error {
	dir := s.lifecycle.RevocationJournalDir
	name := keycloakDigest(entry.Kind+"\x00"+entry.ID) + ".json"
	final := filepath.Join(dir, name)
	existing, err := os.ReadFile(final)
	if err == nil {
		var old keycloakJournalEntry
		if json.Unmarshal(existing, &old) != nil || old.Kind != entry.Kind || old.ID != entry.ID || old.Revocation.Target != entry.Revocation.Target {
			return trace.BadParameter("Keycloak revocation journal conflict")
		}
		return nil
	}
	if !os.IsNotExist(err) {
		return trace.ConnectionProblem(nil, "Keycloak revocation journal unavailable")
	}
	data, err := json.Marshal(entry)
	if err != nil {
		return trace.BadParameter("invalid Keycloak revocation record")
	}
	f, err := os.CreateTemp(dir, ".pending-")
	if err != nil {
		return trace.ConnectionProblem(nil, "Keycloak revocation journal unavailable")
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if _, err = f.Write(data); err != nil {
		return trace.ConnectionProblem(nil, "Keycloak revocation journal write failed")
	}
	if err = f.Sync(); err != nil {
		return trace.ConnectionProblem(nil, "Keycloak revocation journal sync failed")
	}
	if err = os.Link(f.Name(), final); err != nil && !os.IsExist(err) {
		return trace.ConnectionProblem(nil, "Keycloak revocation journal publish failed")
	}
	d, err := os.Open(dir)
	if err != nil {
		return trace.ConnectionProblem(nil, "Keycloak revocation journal directory unavailable")
	}
	defer d.Close()
	if err = d.Sync(); err != nil {
		return trace.ConnectionProblem(nil, "Keycloak revocation journal directory sync failed")
	}
	return nil
}

func (s *keycloakService) replayJournal(ctx context.Context) error {
	dir, err := os.Open(s.lifecycle.RevocationJournalDir)
	if err != nil {
		return trace.ConnectionProblem(nil, "Keycloak revocation journal unavailable")
	}
	defer dir.Close()
	for {
		entries, err := dir.ReadDir(128)
		if err != nil && err != io.EOF {
			return trace.ConnectionProblem(nil, "Keycloak revocation journal read failed")
		}
		for _, entry := range entries {
			if strings.HasPrefix(entry.Name(), ".pending-") {
				continue
			}
			info, err := entry.Info()
			if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 8192 {
				return trace.BadParameter("invalid Keycloak revocation journal file")
			}
			data, err := os.ReadFile(filepath.Join(s.lifecycle.RevocationJournalDir, entry.Name()))
			if err != nil {
				return trace.ConnectionProblem(nil, "Keycloak revocation journal read failed")
			}
			var value keycloakJournalEntry
			if json.Unmarshal(data, &value) != nil || !strings.HasSuffix(entry.Name(), ".json") || entry.Name() != keycloakDigest(value.Kind+"\x00"+value.ID)+".json" ||
				(value.Kind != "users" && value.Kind != "roles") || (value.Kind == "users" && (!strings.HasPrefix(value.ID, keycloakUserPrefix) || value.Revocation.Target.User != value.ID || value.Revocation.Target.Role != "")) ||
				(value.Kind == "roles" && (!strings.HasPrefix(value.ID, keycloakLoginPrefix) || value.Revocation.Target.Role != value.ID || value.Revocation.Target.User != "")) {
				return trace.BadParameter("invalid Keycloak revocation journal record")
			}
			if !value.Expires.IsZero() && !s.a.clock.Now().Before(value.Expires) {
				if value.Kind == "roles" {
					if err := os.Remove(filepath.Join(s.lifecycle.RevocationJournalDir, entry.Name())); err != nil && !os.IsNotExist(err) {
						return trace.ConnectionProblem(nil, "expired Keycloak journal cleanup failed")
					}
				}
				continue
			}
			if err := s.lifecyclePut(ctx, keycloakLifecycleKey("revocations", value.Kind, value.ID), value.Revocation, value.Expires, true); err != nil && !trace.IsAlreadyExists(err) {
				return err
			}
			// Startup must apply native locks synchronously before a restored
			// Auth can serve an old certificate. Waiting for the first background
			// reconciliation pass would create an avoidable recovery race.
			if err := s.ensureLock(ctx, "keycloak-revoke-"+keycloakDigest(value.Kind+"\x00"+value.ID), value.Revocation.Target, value.Revocation.Reason, value.Expires); err != nil {
				return err
			}
		}
		if err == io.EOF {
			return nil
		}
	}
}
