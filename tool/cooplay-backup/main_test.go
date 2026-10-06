// Copyright (C) 2026 Cooplay contributors.
// SPDX-License-Identifier: AGPL-3.0-or-later
package main

import (
	"bytes"
	"filippo.io/age"
	"github.com/stretchr/testify/require"
	"os"
	"path/filepath"
	"testing"
)

func TestAuthenticatedBackup(t *testing.T) {
	dir := t.TempDir()
	key, err := age.GenerateX25519Identity()
	require.NoError(t, err)
	identity := filepath.Join(dir, "identity")
	require.NoError(t, os.WriteFile(identity, []byte(key.String()), 0600))
	input := filepath.Join(dir, "input")
	content := bytes.Repeat([]byte("private fixture"), 10000)
	require.NoError(t, os.WriteFile(input, content, 0600))
	encrypted := filepath.Join(dir, "backup.age")
	require.NoError(t, transform("encrypt", input, encrypted, key.Recipient().String(), ""))
	output := filepath.Join(dir, "restored")
	require.NoError(t, transform("decrypt", encrypted, output, "", identity))
	actual, err := os.ReadFile(output)
	require.NoError(t, err)
	require.Equal(t, content, actual)
	raw, err := os.ReadFile(encrypted)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(encrypted, raw[:len(raw)-1], 0600))
	broken := filepath.Join(dir, "broken")
	require.Error(t, transform("decrypt", encrypted, broken, "", identity))
	_, err = os.Stat(broken)
	require.True(t, os.IsNotExist(err), "unauthenticated plaintext must not be published")
}
