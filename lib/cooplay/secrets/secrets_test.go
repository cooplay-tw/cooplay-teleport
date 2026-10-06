// Copyright (C) 2026 Cooplay contributors.
// SPDX-License-Identifier: AGPL-3.0-or-later
package secrets

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/stretchr/testify/require"
)

type fakeAPI struct {
	value string
	err   error
	calls int
}

func (f *fakeAPI) GetSecretValue(_ context.Context, in *secretsmanager.GetSecretValueInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
	if aws.ToString(in.VersionStage) != "AWSCURRENT" {
		panic("incorrect rotation stage")
	}
	f.calls++
	return &secretsmanager.GetSecretValueOutput{SecretString: &f.value}, f.err
}
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
func TestAWSRotationAndRedaction(t *testing.T) {
	api := &fakeAPI{value: "first"}
	r := Reader{API: api}
	ref := Reference{ARN: "arn:aws:secretsmanager:us-east-1:123456789012:secret:test", Region: "us-east-1"}
	v, err := r.Read(t.Context(), ref)
	require.NoError(t, err)
	require.Equal(t, "first", v)
	api.value = "second"
	v, err = r.Read(t.Context(), ref)
	require.NoError(t, err)
	require.Equal(t, "second", v)
	require.Equal(t, 2, api.calls)
	api.err = errors.New("contains-sensitive-token")
	_, err = r.Read(t.Context(), ref)
	require.Error(t, err)
	require.NotContains(t, err.Error(), "sensitive-token")
	api.err = nil
	api.value = `{"password":`
	ref.JSONKey = "password"
	_, err = r.Read(t.Context(), ref)
	require.EqualError(t, err, "invalid secret document")
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
