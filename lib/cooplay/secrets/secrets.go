// Copyright (C) 2026 Cooplay contributors.
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package secrets loads deployment secrets without logging their contents or
// caching stale values across rotations. References, never values, are config.
package secrets

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const maxSize = 64 * 1024

type Reference struct {
	File      string `json:"file,omitempty"`
	JSONKey   string `json:"json_key,omitempty"`
	Multiline bool   `json:"multiline,omitempty"`
}

type Reader struct{}

func (r Reference) Validate() error {
	if !filepath.IsAbs(r.File) || filepath.Clean(r.File) != r.File {
		return fmt.Errorf("secret requires a clean absolute file path")
	}
	return nil
}

// Read reopens a private file each time. Provisioning and rotation belong to
// the deployment, with no cloud credentials or secret-provider dependency.
func (r Reader) Read(ctx context.Context, ref Reference) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", fmt.Errorf("secret read cancelled")
	}
	if err := ref.Validate(); err != nil {
		return "", err
	}
	var value []byte
	{
		info, err := os.Lstat(ref.File)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
			return "", fmt.Errorf("secret file must be a private regular file")
		}
		f, err := os.Open(ref.File)
		if err != nil {
			return "", fmt.Errorf("secret file unavailable")
		}
		defer f.Close()
		actual, err := f.Stat()
		if err != nil || !os.SameFile(info, actual) {
			return "", fmt.Errorf("secret file changed during read")
		}
		value, err = io.ReadAll(io.LimitReader(f, maxSize+1))
		if err != nil {
			return "", fmt.Errorf("secret read failed")
		}
	}
	if len(value) == 0 || len(value) > maxSize {
		return "", fmt.Errorf("invalid secret size")
	}
	if ref.JSONKey != "" {
		var fields map[string]json.RawMessage
		if json.Unmarshal(value, &fields) != nil {
			return "", fmt.Errorf("invalid secret document")
		}
		var field string
		if json.Unmarshal(fields[ref.JSONKey], &field) != nil || field == "" {
			return "", fmt.Errorf("secret field unavailable")
		}
		value = []byte(field)
	}
	if ref.Multiline {
		if strings.ContainsRune(string(value), '\x00') {
			return "", fmt.Errorf("invalid secret value")
		}
		return string(value), nil
	}
	secret := strings.TrimSuffix(strings.TrimSuffix(string(value), "\n"), "\r")
	if secret == "" || strings.ContainsAny(secret, "\x00\r\n") {
		return "", fmt.Errorf("invalid secret value")
	}
	return secret, nil
}
