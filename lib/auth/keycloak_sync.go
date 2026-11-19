// Copyright (C) 2026 Cooplay contributors.
// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

const keycloakHTTPRequestTimeout = 10 * time.Second

// keycloakSyncFailure holds only bounded diagnostic fields. Underlying errors
// may include sensitive paths, token responses or identity data.
type keycloakSyncFailure struct {
	step, kind string
	httpStatus int
	elapsed    time.Duration
}

func (*keycloakSyncFailure) Error() string { return "Keycloak reconciliation failed" }

func keycloakSyncBackendFailure(step string, err error) error {
	if err == nil {
		return nil
	}
	return &keycloakSyncFailure{step: step, kind: "backend"}
}

func (s *keycloakService) reportKeycloakSyncFailure(ctx context.Context, connector string, failure *keycloakSyncFailure, passElapsed time.Duration, lastSuccess time.Time) {
	keycloakSyncStepFailures.WithLabelValues(connector, failure.step, failure.kind).Inc()
	var sinceLastSuccess int64 = -1
	if !lastSuccess.IsZero() {
		sinceLastSuccess = max(0, int64(s.a.clock.Now().Sub(lastSuccess)/time.Second))
	}
	s.a.logger.ErrorContext(ctx, "Keycloak reconciliation failed; persistent revocations retained",
		"connector", connector, "step", failure.step, "kind", failure.kind, "http_status", failure.httpStatus,
		"request_ms", failure.elapsed.Milliseconds(), "pass_ms", passElapsed.Milliseconds(),
		"since_last_success_s", sinceLastSuccess)
}

func keycloakRequestErrorKind(err error) string {
	var netErr net.Error
	if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &netErr) && netErr.Timeout()) {
		return "timeout"
	}
	var verifyErr *tls.CertificateVerificationError
	var recordErr tls.RecordHeaderError
	var alertErr tls.AlertError
	var unknownCA x509.UnknownAuthorityError
	var invalidCert x509.CertificateInvalidError
	var hostnameErr x509.HostnameError
	var rootsErr x509.SystemRootsError
	if errors.As(err, &verifyErr) || errors.As(err, &recordErr) || errors.As(err, &alertErr) ||
		errors.As(err, &unknownCA) || errors.As(err, &invalidCert) || errors.As(err, &hostnameErr) || errors.As(err, &rootsErr) {
		return "tls"
	}
	// TLS uses unexported errors for some handshake failures. Inspect only
	// known library prefixes and never retain the error text.
	for cause := err; cause != nil; cause = errors.Unwrap(cause) {
		if strings.HasPrefix(cause.Error(), "tls: ") || strings.HasPrefix(cause.Error(), "remote error: tls: ") {
			return "tls"
		}
	}
	var opErr *net.OpError
	var dnsErr *net.DNSError
	if errors.As(err, &opErr) || errors.As(err, &dnsErr) || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return "connect"
	}
	return "other"
}

type keycloakAdminResponse struct {
	status  int
	elapsed time.Duration
}

func (r keycloakAdminResponse) failure(step, kind string) *keycloakSyncFailure {
	return &keycloakSyncFailure{step: step, kind: kind, httpStatus: r.status, elapsed: r.elapsed}
}

func keycloakAdminJSON(client *http.Client, req *http.Request, step string, out any) (result keycloakAdminResponse, failure *keycloakSyncFailure) {
	start := time.Now()
	defer func() {
		result.elapsed = time.Since(start)
		if failure != nil {
			failure.elapsed = result.elapsed
		}
	}()
	response, err := client.Do(req)
	if err != nil {
		return result, result.failure(step, keycloakRequestErrorKind(err))
	}
	defer response.Body.Close()
	result.status = response.StatusCode
	if result.status != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64*1024))
		if step == "account_user" && result.status == http.StatusNotFound {
			return result, nil
		}
		return result, result.failure(step, "http_status")
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, 1024*1024+1))
	if err != nil {
		return result, result.failure(step, keycloakRequestErrorKind(err))
	}
	if len(data) > 1024*1024 || json.Unmarshal(data, out) != nil {
		return result, result.failure(step, "decode")
	}
	return result, nil
}

// Called only for Admin GETs and the client-credentials grant. A zero pass
// deadline disables retries. Both attempts share the original HTTP context.
func keycloakReconcileAdminJSON(client *http.Client, req *http.Request, connector, step string, out any, passDeadline time.Time) (keycloakAdminResponse, *keycloakSyncFailure) {
	result, failure := keycloakAdminJSON(client, req, step, out)
	if failure == nil || (failure.kind != "timeout" && failure.kind != "connect" && failure.kind != "tls") {
		return result, failure
	}
	if req.Context().Err() != nil || time.Until(passDeadline) <= keycloakHTTPRequestTimeout {
		return result, failure
	}
	next := req.Clone(req.Context())
	if req.GetBody != nil {
		body, err := req.GetBody()
		if err != nil {
			return result, failure
		}
		next.Body = body
	}
	keycloakSyncStepFailures.WithLabelValues(connector, failure.step, failure.kind).Inc()
	return keycloakAdminJSON(client, next, step, out)
}
