// Copyright (C) 2026 Cooplay contributors.
// SPDX-License-Identifier: AGPL-3.0-or-later
package main

import (
	"encoding/json"
	"github.com/gravitational/teleport/lib/cooplay/secrets"
	"github.com/stretchr/testify/require"
	"os"
	"path/filepath"
	"testing"
)

func TestMaterializeGeneration(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.Chmod(dir, 0700))
	source := filepath.Join(dir, "source")
	require.NoError(t, os.WriteFile(source, []byte("temporary-fixture"), 0600))
	manifest := filepath.Join(dir, "refs.json")
	data, err := json.Marshal(map[string]secrets.Reference{"password": {File: source}})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(manifest, data, 0600))
	target := filepath.Join(dir, "generation")
	require.NoError(t, materialize(t.Context(), manifest, target, secrets.Reader{}))
	value, err := os.ReadFile(filepath.Join(target, "password"))
	require.NoError(t, err)
	require.Equal(t, "temporary-fixture", string(value))
	info, err := os.Stat(filepath.Join(target, "password"))
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0600), info.Mode().Perm())
	require.Error(t, materialize(t.Context(), manifest, target, secrets.Reader{}))
	require.NoError(t, os.Remove(source))
	next := filepath.Join(dir, "next")
	require.Error(t, materialize(t.Context(), manifest, next, secrets.Reader{}))
	_, err = os.Stat(next)
	require.True(t, os.IsNotExist(err))
}
