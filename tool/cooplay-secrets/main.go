// Copyright (C) 2026 Cooplay contributors.
// SPDX-License-Identifier: AGPL-3.0-or-later
// cooplay-secrets materializes a secret generation for services requiring files.
// Auth reads its own file/Secrets Manager references directly on every use.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/gravitational/teleport/lib/cooplay/secrets"
)

func materialize(ctx context.Context, manifest, destination string, reader secrets.Reader) error {
	if !filepath.IsAbs(destination) {
		return fmt.Errorf("destination must be absolute")
	}
	if _, err := os.Lstat(destination); !os.IsNotExist(err) {
		return fmt.Errorf("destination must not exist; create a new generation")
	}
	data, err := os.ReadFile(manifest)
	if err != nil || len(data) > 64*1024 {
		return fmt.Errorf("secret manifest unavailable")
	}
	var refs map[string]secrets.Reference
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&refs) != nil || decoder.Decode(new(any)) != io.EOF || len(refs) == 0 || len(refs) > 64 {
		return fmt.Errorf("invalid secret manifest")
	}
	// Fetch all values before publishing any generation. No partial rotation.
	values := map[string]string{}
	for name, ref := range refs {
		if !regexp.MustCompile(`^[a-z][a-z0-9_-]{0,63}$`).MatchString(name) {
			return fmt.Errorf("invalid secret filename")
		}
		value, err := reader.Read(ctx, ref)
		if err != nil {
			return fmt.Errorf("secret retrieval failed")
		}
		values[name] = value
	}
	parent := filepath.Dir(destination)
	info, err := os.Lstat(parent)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("secret parent must be a private directory")
	}
	staging, err := os.MkdirTemp(parent, ".secrets-")
	if err != nil {
		return fmt.Errorf("secret staging unavailable")
	}
	defer os.RemoveAll(staging)
	for name, value := range values {
		f, err := os.OpenFile(filepath.Join(staging, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return fmt.Errorf("secret file creation failed")
		}
		_, writeErr := f.WriteString(value)
		syncErr := f.Sync()
		closeErr := f.Close()
		if writeErr != nil || syncErr != nil || closeErr != nil {
			return fmt.Errorf("secret file write failed")
		}
	}
	if err := os.Rename(staging, destination); err != nil {
		return fmt.Errorf("secret generation publish failed")
	}
	dir, err := os.Open(parent)
	if err != nil {
		return fmt.Errorf("secret parent unavailable")
	}
	defer dir.Close()
	if dir.Sync() != nil {
		return fmt.Errorf("secret generation sync failed")
	}
	return nil
}

func main() {
	manifest := flag.String("manifest", "", "JSON file containing secret references")
	destination := flag.String("destination", "", "new absolute generation directory (parent mode 0700)")
	flag.Parse()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := materialize(ctx, *manifest, *destination, secrets.Reader{}); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println("Secret generation created; no secret values written to output.")
}
