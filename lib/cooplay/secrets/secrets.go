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
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

const maxSize = 64 * 1024

type Reference struct {
	File      string `json:"file,omitempty"`
	ARN       string `json:"arn,omitempty"`
	Region    string `json:"region,omitempty"`
	JSONKey   string `json:"json_key,omitempty"`
	Multiline bool   `json:"multiline,omitempty"`
}

type API interface {
	GetSecretValue(context.Context, *secretsmanager.GetSecretValueInput, ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error)
}

type Reader struct{ API API }

func (r Reference) Validate() error {
	if (r.File == "") == (r.ARN == "") {
		return fmt.Errorf("exactly one secret source is required")
	}
	if r.File != "" && (!filepath.IsAbs(r.File) || r.Region != "") {
		return fmt.Errorf("file secret requires an absolute path and no region")
	}
	if r.ARN != "" && (!strings.HasPrefix(r.ARN, "arn:") || !strings.Contains(r.ARN, ":secretsmanager:") || r.Region == "") {
		return fmt.Errorf("AWS secret requires a full ARN and region")
	}
	return nil
}

// Read reopens files / requests AWSCURRENT each time. IAM/transport/JSON errors
// are deliberately replaced: SDK errors and JSON excerpts can include secrets.
func (r Reader) Read(ctx context.Context, ref Reference) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := ref.Validate(); err != nil {
		return "", err
	}
	var value []byte
	if ref.File != "" {
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
	} else {
		api := r.API
		if api == nil {
			cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(ref.Region))
			if err != nil {
				return "", fmt.Errorf("AWS secret identity unavailable")
			}
			api = secretsmanager.NewFromConfig(cfg)
		}
		result, err := api.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{SecretId: aws.String(ref.ARN), VersionStage: aws.String("AWSCURRENT")})
		if err != nil || result == nil || result.SecretString == nil {
			return "", fmt.Errorf("AWS secret read failed")
		}
		value = []byte(*result.SecretString)
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
