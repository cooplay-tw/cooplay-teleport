// Copyright (C) 2026 Cooplay contributors.
// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gravitational/trace"
	"github.com/jonboulle/clockwork"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"

	"github.com/gravitational/teleport/lib/backend"
	"github.com/gravitational/teleport/lib/backend/memory"
	"github.com/gravitational/teleport/lib/cooplay/secrets"
	"github.com/gravitational/teleport/lib/events"
	"github.com/gravitational/teleport/lib/services/local"
)

type keycloakSyncTestTransport func(*http.Request) (*http.Response, error)

func (f keycloakSyncTestTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func keycloakSyncTestResponse(status int, body string) (*http.Response, error) {
	return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body))}, nil
}

func newKeycloakSyncTestService(t *testing.T, name string) (*keycloakService, *clockwork.FakeClock, *bytes.Buffer) {
	t.Helper()
	ctx := t.Context()
	clock := clockwork.NewFakeClock()
	bk, err := memory.New(memory.Config{Context: ctx, Clock: clock})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, bk.Close()) })
	log := new(bytes.Buffer)
	a := &Server{
		bk:       bk,
		clock:    clock,
		closeCtx: ctx,
		logger:   slog.New(slog.NewJSONHandler(log, nil)),
		emitter:  &events.DiscardEmitter{},
		Services: &Services{AccessInternal: local.NewAccessService(bk), Status: local.NewStatusService(bk)},
	}
	dir := t.TempDir()
	secret := filepath.Join(dir, "keycloak-client")
	require.NoError(t, os.WriteFile(secret, []byte("fixture-only"), 0600))
	cfg := KeycloakLifecycleConfig{
		RevocationJournalDir: filepath.Join(dir, "journal"),
		PollSeconds:          5,
		MaxStaleSeconds:      30,
		Connectors: map[string]KeycloakLifecycleConnector{name: {
			Issuer: "https://issuer.example.test/realms/lab", AdminURL: "https://admin.example.test/admin/realms/lab",
			ClientID: "teleport", ClientSecret: secrets.Reference{File: secret},
			AdminClientID: "sync", AdminClientSecret: secrets.Reference{File: secret},
		}},
	}
	svc, err := NewManagedKeycloakService(a, cfg)
	require.NoError(t, err)
	return svc.(*keycloakService), clock, log
}

func successfulKeycloakSync(r *http.Request) (*http.Response, error) {
	if r.Method == http.MethodPost {
		return keycloakSyncTestResponse(http.StatusOK, `{"access_token":"fixture-service-token"}`)
	}
	return keycloakSyncTestResponse(http.StatusOK, "1")
}

func TestKeycloakReconcileHealthLockMetrics(t *testing.T) {
	const name = "sync-lock-metrics"
	s, clock, _ := newKeycloakSyncTestService(t, name)
	ctx := t.Context()
	gauge := keycloakHealthLockActive.WithLabelValues(name)
	events := keycloakHealthLockEvents.WithLabelValues(name)
	assertLock := func(locked bool) {
		t.Helper()
		_, err := s.a.Services.GetLock(ctx, keycloakHealthLockName(name))
		if locked {
			require.NoError(t, err)
			require.EqualValues(t, 1, testutil.ToFloat64(gauge))
		} else {
			require.True(t, trace.IsNotFound(err), "lock lookup: %v", err)
			require.EqualValues(t, 0, testutil.ToFloat64(gauge))
		}
	}
	assertLock(true)
	require.Zero(t, testutil.ToFloat64(events), "startup fence does not count")
	s.httpClient.Transport = keycloakSyncTestTransport(successfulKeycloakSync)
	require.NoError(t, s.reconcile(ctx))
	assertLock(false)

	s.httpClient.Transport = keycloakSyncTestTransport(func(r *http.Request) (*http.Response, error) {
		clock.Advance(10 * time.Second)
		return nil, context.DeadlineExceeded
	})
	slowPass := func() {
		t.Helper()
		// The synthetic timeout consumes ten seconds of the fake clock. Give
		// the request less than ten seconds of real context budget after it.
		pass, cancel := context.WithTimeout(ctx, 9*time.Second)
		defer cancel()
		require.Error(t, s.reconcile(pass))
	}
	clock.Advance(6 * time.Second)
	slowPass()
	assertLock(false)
	require.Zero(t, testutil.ToFloat64(events))
	clock.Advance(5 * time.Second)
	slowPass()
	assertLock(true)
	require.EqualValues(t, 1, testutil.ToFloat64(events))
	item, err := s.a.bk.Get(ctx, keycloakLifecycleKey("health-lock-events", name))
	require.NoError(t, err)
	require.Equal(t, "1", string(item.Value))
	slowPass()
	require.EqualValues(t, 1, testutil.ToFloat64(events), "existing outage lock does not count again")

	s.httpClient.Transport = keycloakSyncTestTransport(successfulKeycloakSync)
	require.NoError(t, s.reconcile(ctx))
	assertLock(false)
	events.Set(0) // Simulate a fresh metric collector after restarting Auth.
	restarted, err := NewManagedKeycloakService(s.a, *s.lifecycle)
	require.NoError(t, err)
	s = restarted.(*keycloakService)
	assertLock(true)
	require.EqualValues(t, 1, testutil.ToFloat64(events))
}

func TestKeycloakReconcileRetriesTransientTokenFailure(t *testing.T) {
	const name = "sync-retry"
	s, _, _ := newKeycloakSyncTestService(t, name)
	s.httpClient.Transport = keycloakSyncTestTransport(successfulKeycloakSync)
	require.NoError(t, s.reconcile(t.Context()))
	var attempts int
	s.httpClient.Transport = keycloakSyncTestTransport(func(r *http.Request) (*http.Response, error) {
		if r.Method == http.MethodPost {
			body, err := io.ReadAll(r.Body)
			require.NoError(t, err)
			require.Equal(t, "grant_type=client_credentials", string(body))
			require.NoError(t, r.Body.Close())
			attempts++
			if attempts == 1 {
				return nil, &net.OpError{Op: "dial", Err: errors.New("fixture connection failure")}
			}
		}
		return successfulKeycloakSync(r)
	})
	failures := keycloakSyncStepFailures.WithLabelValues(name, "token", "connect")
	before := testutil.ToFloat64(failures)
	require.NoError(t, s.reconcile(t.Context()))
	require.Equal(t, 2, attempts)
	require.Equal(t, before+1, testutil.ToFloat64(failures))
	require.Zero(t, testutil.ToFloat64(keycloakHealthLockActive.WithLabelValues(name)))
	require.Zero(t, testutil.ToFloat64(keycloakHealthLockEvents.WithLabelValues(name)))
}

func TestKeycloakReconcileCountsConcurrentHealthLockCreationOnce(t *testing.T) {
	const name = "sync-concurrent"
	s, _, _ := newKeycloakSyncTestService(t, name)
	ctx := t.Context()
	require.NoError(t, s.a.DeleteLock(ctx, keycloakHealthLockName(name)))
	// Independent Auth services can race on the same backend. Both attempt
	// to fence access, and only the successful creation increments the count.
	peer := &keycloakService{a: s.a, lifecycle: s.lifecycle}
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for _, svc := range []*keycloakService{s, peer} {
		wg.Go(func() { results <- svc.lockUnhealthyConnector(ctx, name) })
	}
	wg.Wait()
	close(results)
	for err := range results {
		require.NoError(t, err)
	}
	count, _, err := s.readHealthLockEvents(ctx, name)
	require.NoError(t, err)
	require.EqualValues(t, 1, count)
}

func TestKeycloakReconcileFencesWhenHealthLockAccountingFails(t *testing.T) {
	const name = "sync-accounting-failed"
	s, _, logs := newKeycloakSyncTestService(t, name)
	ctx := t.Context()
	require.NoError(t, s.a.DeleteLock(ctx, keycloakHealthLockName(name)))
	_, err := s.a.bk.Put(ctx, backend.Item{
		Key: keycloakLifecycleKey("health-lock-events", name), Value: []byte("invalid"),
	})
	require.NoError(t, err)
	require.NoError(t, s.lockUnhealthyConnector(ctx, name))
	_, err = s.a.Services.GetLock(ctx, keycloakHealthLockName(name))
	require.NoError(t, err)
	require.EqualValues(t, 1, testutil.ToFloat64(keycloakHealthLockActive.WithLabelValues(name)))
	require.Contains(t, logs.String(), "Keycloak could not account for health lock creation")
}

func TestKeycloakReconcileRedactsAccountFailures(t *testing.T) {
	const name = "sync-redaction"
	s, clock, logs := newKeycloakSyncTestService(t, name)
	const subject, sid, username = "fixture-subject", "fixture-sid", "fixture-username"
	login := keycloakLogin{Connector: name, Subject: subject, SID: sid, Username: username, Expires: clock.Now().Add(time.Hour)}
	require.NoError(t, s.lifecyclePut(t.Context(), keycloakLifecycleKey("logins", "fixture-marker"), login, login.Expires, true))
	var sessionCalls int
	s.httpClient.Transport = keycloakSyncTestTransport(func(r *http.Request) (*http.Response, error) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/"+subject):
			return keycloakSyncTestResponse(http.StatusOK, `{"id":"fixture-subject","enabled":true}`)
		case strings.HasSuffix(r.URL.Path, "/sessions"):
			sessionCalls++
			return keycloakSyncTestResponse(http.StatusBadGateway, subject+" "+sid+" "+username+" "+r.URL.String()+" "+r.Header.Get("Authorization"))
		default:
			return successfulKeycloakSync(r)
		}
	})
	require.Error(t, s.reconcile(t.Context()))
	require.Equal(t, 1, sessionCalls, "HTTP failures are never retried")
	log := logs.String()
	for _, value := range []string{subject, sid, username, "admin.example.test", "fixture-service-token"} {
		require.NotContains(t, log, value)
	}
	var fields map[string]any
	require.NoError(t, json.Unmarshal([]byte(log), &fields))
	require.Subset(t, fields, map[string]any{
		"level": "ERROR", "connector": name, "step": "account_sessions", "kind": "http_status",
		"http_status": float64(http.StatusBadGateway), "since_last_success_s": float64(-1),
	})
	require.Contains(t, fields, "request_ms")
	require.Contains(t, fields, "pass_ms")
}

func TestKeycloakSyncRequestErrorKinds(t *testing.T) {
	for _, tc := range []struct {
		err  error
		kind string
	}{
		{err: context.DeadlineExceeded, kind: "timeout"},
		{err: &net.OpError{Op: "dial", Err: errors.New("fixture failure")}, kind: "connect"},
		{err: &tls.CertificateVerificationError{Err: x509.UnknownAuthorityError{}}, kind: "tls"},
		{err: context.Canceled, kind: "other"},
	} {
		require.Equal(t, tc.kind, keycloakRequestErrorKind(tc.err))
	}
}

func TestKeycloakSyncRequestRetryBudget(t *testing.T) {
	for _, tc := range []struct {
		name      string
		budget    time.Duration
		first     func() (*http.Response, error)
		wantCalls int
		wantKind  string
	}{
		{
			name: "transient failure", budget: 30 * time.Second, wantCalls: 2,
			first: func() (*http.Response, error) { return nil, context.DeadlineExceeded },
		},
		{
			name: "insufficient pass budget", budget: 10 * time.Second, wantCalls: 1, wantKind: "timeout",
			first: func() (*http.Response, error) { return nil, context.DeadlineExceeded },
		},
		{
			name: "invalid response", budget: 30 * time.Second, wantCalls: 1, wantKind: "decode",
			first: func() (*http.Response, error) { return keycloakSyncTestResponse(http.StatusOK, "{") },
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://idp.example.test/users/count", nil)
			require.NoError(t, err)
			var calls int
			client := &http.Client{Transport: keycloakSyncTestTransport(func(r *http.Request) (*http.Response, error) {
				calls++
				require.Same(t, ctx, r.Context(), "the retry shares the HTTP deadline")
				if calls == 1 {
					return tc.first()
				}
				return keycloakSyncTestResponse(http.StatusOK, "1")
			})}
			var count int
			_, failure := keycloakReconcileAdminJSON(client, req, "sync-budget", "probe", &count, time.Now().Add(tc.budget))
			require.Equal(t, tc.wantCalls, calls)
			if tc.wantKind == "" {
				require.Nil(t, failure)
				require.Equal(t, 1, count)
			} else {
				require.NotNil(t, failure)
				require.Equal(t, tc.wantKind, failure.kind)
			}
		})
	}
}
