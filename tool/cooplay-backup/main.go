// Copyright (C) 2026 Cooplay contributors.
// SPDX-License-Identifier: AGPL-3.0-or-later
// cooplay-backup provides streaming authenticated age encryption. Snapshot
// consistency, retention, and restoring the latest revocation journal belong
// to the private deployment's orchestration scripts.
package main

import (
	"filippo.io/age"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func privateRead(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 8192 {
		return nil, fmt.Errorf("private identity file required")
	}
	return os.ReadFile(path)
}
func transform(mode, input, output, recipient, identityFile string) error {
	if _, err := os.Lstat(output); !os.IsNotExist(err) {
		return fmt.Errorf("output must not exist")
	}
	in, err := os.Open(input)
	if err != nil {
		return fmt.Errorf("input unavailable")
	}
	defer in.Close()
	out, err := os.CreateTemp(filepath.Dir(output), ".age-")
	if err != nil {
		return fmt.Errorf("output staging unavailable")
	}
	defer os.Remove(out.Name())
	defer out.Close()
	switch mode {
	case "encrypt":
		key, err := age.ParseX25519Recipient(recipient)
		if err != nil {
			return fmt.Errorf("invalid age recipient")
		}
		encrypted, err := age.Encrypt(out, key)
		if err != nil {
			return fmt.Errorf("encryption initialization failed")
		}
		if _, err = io.Copy(encrypted, in); err != nil {
			return fmt.Errorf("encryption failed")
		}
		if encrypted.Close() != nil {
			return fmt.Errorf("encryption finalization failed")
		}
	case "decrypt":
		data, err := privateRead(identityFile)
		if err != nil {
			return err
		}
		keys, err := age.ParseIdentities(strings.NewReader(string(data)))
		if err != nil {
			return fmt.Errorf("invalid age identity")
		}
		decrypted, err := age.Decrypt(in, keys...)
		if err != nil {
			return fmt.Errorf("backup authentication failed")
		}
		if _, err = io.Copy(out, decrypted); err != nil {
			return fmt.Errorf("backup authentication failed")
		}
	default:
		return fmt.Errorf("mode must be encrypt or decrypt")
	}
	if out.Sync() != nil || out.Close() != nil {
		return fmt.Errorf("output sync failed")
	}
	// Atomic publication without overwriting an existing backup or restore.
	if err := os.Link(out.Name(), output); err != nil {
		return fmt.Errorf("output publication failed")
	}
	dir, err := os.Open(filepath.Dir(output))
	if err != nil {
		return fmt.Errorf("output directory unavailable")
	}
	defer dir.Close()
	if dir.Sync() != nil {
		return fmt.Errorf("output directory sync failed")
	}
	return nil
}
func main() {
	mode := flag.String("mode", "", "keygen, encrypt or decrypt")
	input := flag.String("input", "", "input path")
	output := flag.String("output", "", "new output path")
	recipient := flag.String("recipient", "", "public age X25519 recipient")
	identity := flag.String("identity", "", "private age identity file")
	flag.Parse()
	var err error
	if *mode == "keygen" {
		var key *age.X25519Identity
		key, err = age.GenerateX25519Identity()
		if err == nil {
			var f *os.File
			f, err = os.OpenFile(*output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
			if err == nil {
				_, err = f.WriteString(key.String() + "\n")
				if err == nil {
					err = f.Sync()
				}
				_ = f.Close()
			}
		}
		if err == nil {
			fmt.Println(key.Recipient().String())
		}
	} else {
		err = transform(*mode, *input, *output, *recipient, *identity)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "Backup operation failed; output was not accepted.")
		os.Exit(1)
	}
}
