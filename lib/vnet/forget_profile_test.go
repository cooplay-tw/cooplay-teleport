// Copyright (C) 2026 Cooplay contributors.
// SPDX-License-Identifier: AGPL-3.0-or-later

package vnet

import (
	"context"
	"testing"
	"time"

	"github.com/gravitational/trace"
	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/require"

	"github.com/gravitational/teleport/api/types"
)

// TestForgetProfileCredentials covers what a client application relies on
// after logging out of a profile: VNet no longer proxies new connections with
// app certificates issued before the logout (they would otherwise be reused
// until they expire), it reissues as soon as credentials are available again,
// and other profiles are unaffected.
func TestForgetProfileCredentials(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	clock := clockwork.NewFakeClockAt(time.Now())

	const (
		app       = "echo1.root1.example.com"
		multiPort = "multi-port.root1.example.com"
		otherApp  = "echo1.root2.example.com"
	)
	clientApp := newFakeClientApp(ctx, t, &fakeClientAppConfig{
		clusters: map[string]testClusterSpec{
			"root1.example.com": {
				apps: []appSpec{
					{publicAddr: app},
					{publicAddr: multiPort, tcpPorts: []*types.PortRange{{Port: 1337}, {Port: 4242}}},
				},
				cidrRange:    "192.168.2.0/24",
				leafClusters: map[string]testClusterSpec{},
			},
			"root2.example.com": {
				apps:         []appSpec{{publicAddr: otherApp}},
				leafClusters: map[string]testClusterSpec{},
			},
		},
		clock:                   clock,
		signatureAlgorithmSuite: types.SignatureAlgorithmSuite_SIGNATURE_ALGORITHM_SUITE_BALANCED_V1,
	})
	p := newTestPack(t, ctx, testPackConfig{
		clock:         clock,
		fakeClientApp: clientApp,
	})

	dial := func(t *testing.T, host string, port int) error {
		t.Helper()
		conn, err := p.dialHost(ctx, host, port)
		if err != nil {
			return err
		}
		defer conn.Close()
		testEchoConnection(t, conn)
		return nil
	}
	issued := func(host string) int {
		return len(clientApp.RequestedRouteToApps(host))
	}
	type target struct {
		host string
		port int
	}
	profileTargets := []target{{app, 80}, {multiPort, 1337}, {multiPort, 4242}}

	for _, target := range append(profileTargets, target{otherApp, 80}) {
		require.NoError(t, dial(t, target.host, target.port))
		require.NoError(t, dial(t, target.host, target.port), "cached certificate is reused")
	}
	require.Equal(t, 1, issued(app))
	require.Equal(t, 2, issued(multiPort))
	require.Equal(t, 1, issued(otherApp))

	// Log out of root1. The client application drops its keys and can no
	// longer issue certificates until the user logs in again.
	loggedOut := error(trace.AccessDenied("not logged in"))
	clientApp.reissueAppCertErr.Store(&loggedOut)
	p.clientApplicationService.forgetProfile("root1.example.com")
	for _, target := range profileTargets {
		require.Error(t, dial(t, target.host, target.port), "certificate issued before logout was reused for %v", target)
	}
	require.Equal(t, 1, issued(app))
	require.Equal(t, 2, issued(multiPort))
	// Another profile keeps its cached certificate.
	require.NoError(t, dial(t, otherApp, 80))
	require.Equal(t, 1, issued(otherApp))

	// After logging in again, the next connection reissues immediately rather
	// than waiting for the old certificate to expire.
	clientApp.reissueAppCertErr.Store(nil)
	for _, target := range profileTargets {
		require.NoError(t, dial(t, target.host, target.port))
		require.NoError(t, dial(t, target.host, target.port))
	}
	require.Equal(t, 2, issued(app))
	require.Equal(t, 4, issued(multiPort))
	require.Equal(t, 1, issued(otherApp))
}

// TestForgetProfileCredentialsBeforeLogin covers forgetting a profile whose
// certificates the admin process cached while its keys are already gone: the
// first new connection reissues without failing.
func TestForgetProfileCredentialsBeforeLogin(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	clock := clockwork.NewFakeClockAt(time.Now())
	const app = "echo1.root1.example.com"
	clientApp := newFakeClientApp(ctx, t, &fakeClientAppConfig{
		clusters: map[string]testClusterSpec{
			"root1.example.com": {apps: []appSpec{{publicAddr: app}}, leafClusters: map[string]testClusterSpec{}},
		},
		clock:                   clock,
		signatureAlgorithmSuite: types.SignatureAlgorithmSuite_SIGNATURE_ALGORITHM_SUITE_BALANCED_V1,
	})
	p := newTestPack(t, ctx, testPackConfig{clock: clock, fakeClientApp: clientApp})

	conn, err := p.dialHost(ctx, app, 80)
	require.NoError(t, err)
	testEchoConnection(t, conn)
	require.NoError(t, conn.Close())

	// Logout and a new login both happened before the next connection.
	p.clientApplicationService.forgetProfile("root1.example.com")
	conn, err = p.dialHost(ctx, app, 80)
	require.NoError(t, err, "a single connection attempt must succeed by reissuing")
	testEchoConnection(t, conn)
	require.NoError(t, conn.Close())
	require.Len(t, clientApp.RequestedRouteToApps(app), 2)
}
