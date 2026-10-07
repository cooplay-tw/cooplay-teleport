// Copyright (C) 2026 Cooplay contributors.
// SPDX-License-Identifier: AGPL-3.0-or-later
package secrets

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFileRotationAndPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret")
	ref := Reference{File: path, JSONKey: "password"}
	r := Reader{}
	require.NoError(t, os.WriteFile(path, []byte(`{"password":"first"}`), 0600))
	v, err := r.Read(t.Context(), ref)
	require.NoError(t, err)
	require.Equal(t, "first", v)
	require.NoError(t, os.WriteFile(path, []byte(`{"password":"second"}`), 0600))
	v, err = r.Read(t.Context(), ref)
	require.NoError(t, err)
	require.Equal(t, "second", v)
	require.NoError(t, os.Chmod(path, 0644))
	_, err = r.Read(t.Context(), ref)
	require.Error(t, err)
	require.NoError(t, os.Remove(path))
	require.NoError(t, os.Symlink("/etc/passwd", path))
	_, err = r.Read(t.Context(), ref)
	require.Error(t, err)
}
func TestMultilineSecretRequiresExplicitReference(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tls-material")
	value := "-----BEGIN CERTIFICATE-----\nfixture\n-----END CERTIFICATE-----\n"
	require.NoError(t, os.WriteFile(path, []byte(value), 0600))
	_, err := (Reader{}).Read(t.Context(), Reference{File: path})
	require.Error(t, err)
	got, err := (Reader{}).Read(t.Context(), Reference{File: path, Multiline: true})
	require.NoError(t, err)
	require.Equal(t, value, got)
}
