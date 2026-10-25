// Copyright (C) 2026 Cooplay contributors.
// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gravitational/trace"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	"github.com/gravitational/teleport/api/trail"
	"github.com/gravitational/teleport/lib/client"
	"github.com/gravitational/teleport/lib/teleterm/api/uri"
	"github.com/gravitational/teleport/lib/teleterm/clusters"
	"github.com/gravitational/teleport/lib/teleterm/profiletest"
)

// TestClusterLogoutKeycloakRevocationNotConfirmed exercises the unmodified
// revocation client against an unreachable proxy: the daemon must finish every
// local cleanup step, notify logout hooks (VNet) and then report the
// unconfirmed revocation as a visible, non-fatal error.
func TestClusterLogoutKeycloakRevocationNotConfirmed(t *testing.T) {
	t.Setenv("KUBECONFIG", filepath.Join(t.TempDir(), "kubeconfig"))
	for _, tc := range []struct {
		name          string
		username      string
		removeProfile bool
		expectWarning bool
	}{
		{name: "Keycloak keep profile", username: "keycloak-" + strings.Repeat("b", 64), expectWarning: true},
		{name: "Keycloak remove profile", username: "keycloak-" + strings.Repeat("c", 64), removeProfile: true, expectWarning: true},
		{name: "non-Keycloak", username: "alice"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := client.NewFSClientStore(t.TempDir())
			index := profiletest.AddLoggedInProfile(t, store, profiletest.ClosedAddr(t), tc.username)
			storage, err := clusters.NewStorage(clusters.Config{ClientStore: store, InsecureSkipVerify: true, AddKeysToAgent: client.AddKeysToAgentNo})
			require.NoError(t, err)
			daemon, err := New(Config{
				Storage: storage,
				TshdEventsClient: NewTshdEventsClient(func() (grpc.DialOption, error) {
					return grpc.WithTransportCredentials(insecure.NewCredentials()), nil
				}),
				KubeconfigsDir: t.TempDir(),
				AgentsDir:      t.TempDir(),
			})
			require.NoError(t, err)
			t.Cleanup(daemon.Stop)

			var hookCalls []string
			daemon.AddLogoutHook(func(profileName string) {
				// Hooks run after local credentials are gone.
				_, err := store.GetKeyRing(index)
				require.True(t, trace.IsNotFound(err), "hook ran before local key deletion: %v", err)
				hookCalls = append(hookCalls, profileName)
			})

			start := time.Now()
			err = daemon.ClusterLogout(t.Context(), uri.NewClusterURI(index.ProxyHost), tc.removeProfile)
			require.Less(t, time.Since(start), 20*time.Second)
			if tc.expectWarning {
				require.True(t, client.IsKeycloakRevocationNotConfirmed(err), "unexpected error: %v", err)
				// This is what the Electron app receives.
				grpcStatus, ok := status.FromError(trail.ToGRPC(err))
				require.True(t, ok)
				require.Equal(t, codes.Unavailable, grpcStatus.Code())
				require.Equal(t, "Local credentials cleared; Keycloak credential revocation was not confirmed", grpcStatus.Message())
			} else {
				require.NoError(t, err)
			}
			require.Equal(t, []string{index.ProxyHost}, hookCalls)
			_, err = store.GetKeyRing(index)
			require.True(t, trace.IsNotFound(err), "local credentials must always be deleted: %v", err)
			profiles, err := store.ListProfiles()
			require.NoError(t, err)
			if tc.removeProfile {
				require.NotContains(t, profiles, index.ProxyHost)
			} else {
				require.Contains(t, profiles, index.ProxyHost)
			}

			// The profile watcher repeats logout after the keys disappear; that
			// must succeed without a second, impossible revocation attempt.
			require.NoError(t, daemon.ClusterLogout(t.Context(), uri.NewClusterURI(index.ProxyHost), tc.removeProfile))
			require.Len(t, hookCalls, 2)
		})
	}
}
