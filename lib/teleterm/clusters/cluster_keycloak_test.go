// Copyright (C) 2026 Cooplay contributors.
// SPDX-License-Identifier: AGPL-3.0-or-later

package clusters

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gravitational/trace"
	"github.com/stretchr/testify/require"

	"github.com/gravitational/teleport/lib/client"
	"github.com/gravitational/teleport/lib/teleterm/api/uri"
	"github.com/gravitational/teleport/lib/teleterm/profiletest"
)

// TestLogoutRevokesKeycloakLoginBeforeDeletingKeys uses a real on-disk
// profile and key ring with a fake revocation call, so the observed ordering
// and cleanup are those of Connect's actual logout code.
func TestLogoutRevokesKeycloakLoginBeforeDeletingKeys(t *testing.T) {
	// Logout edits the default kubeconfig; never touch the developer's file.
	t.Setenv("KUBECONFIG", filepath.Join(t.TempDir(), "kubeconfig"))
	keycloakUser := "keycloak-" + strings.Repeat("a", 64)

	for _, tc := range []struct {
		name          string
		username      string
		revokeErr     error
		expectRevoke  bool
		expectWarning bool
	}{
		{name: "Keycloak login revoked", username: keycloakUser, expectRevoke: true},
		{name: "Keycloak revocation not confirmed", username: keycloakUser, revokeErr: trace.ConnectionProblem(nil, "proxy unreachable"), expectRevoke: true, expectWarning: true},
		{name: "non-Keycloak login unaffected", username: "alice", revokeErr: trace.ConnectionProblem(nil, "must not be called")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := client.NewFSClientStore(t.TempDir())
			index := profiletest.AddLoggedInProfile(t, store, profiletest.ClosedAddr(t), tc.username)
			storage, err := NewStorage(Config{ClientStore: store, InsecureSkipVerify: true, AddKeysToAgent: client.AddKeysToAgentNo})
			require.NoError(t, err)
			clusterURI := uri.NewClusterURI(index.ProxyHost)
			cluster, _, err := storage.GetByURI(clusterURI)
			require.NoError(t, err)
			require.Equal(t, tc.username, cluster.status.Username)

			var revocations int
			original := revokeKeycloakLogin
			t.Cleanup(func() { revokeKeycloakLogin = original })
			revokeKeycloakLogin = func(_ context.Context, teleportClient *client.TeleportClient) error {
				revocations++
				require.Same(t, cluster.clusterClient, teleportClient)
				// The revocation request authenticates with the current login.
				_, err := store.GetKeyRing(index)
				require.NoError(t, err, "revocation must run before local keys are deleted")
				return tc.revokeErr
			}

			err = cluster.Logout(t.Context())
			if tc.expectWarning {
				require.True(t, client.IsKeycloakRevocationNotConfirmed(err), "unexpected error: %v", err)
				require.True(t, trace.IsConnectionProblem(err))
				require.Equal(t, "Local credentials cleared; Keycloak credential revocation was not confirmed", err.Error())
			} else {
				require.NoError(t, err)
			}
			require.Equal(t, tc.expectRevoke, revocations == 1, "revocations: %d", revocations)
			_, err = store.GetKeyRing(index)
			require.True(t, trace.IsNotFound(err), "local credentials must always be deleted: %v", err)

			// Logging out again finds no credentials and attempts nothing.
			again, _, err := storage.GetByURI(clusterURI)
			require.NoError(t, err)
			require.NoError(t, again.Logout(t.Context()))
			require.LessOrEqual(t, revocations, 1)
		})
	}
}

func TestIsKeycloakRevocationNotConfirmed(t *testing.T) {
	require.True(t, client.IsKeycloakRevocationNotConfirmed(client.ErrKeycloakRevocationNotConfirmed))
	require.True(t, client.IsKeycloakRevocationNotConfirmed(trace.Wrap(trace.Wrap(client.ErrKeycloakRevocationNotConfirmed))))
	require.False(t, client.IsKeycloakRevocationNotConfirmed(nil))
	require.False(t, client.IsKeycloakRevocationNotConfirmed(trace.ConnectionProblem(nil, "Local credentials cleared; Keycloak credential revocation was not confirmed")))
	// A local cleanup failure stays fatal even when revocation also failed.
	require.False(t, client.IsKeycloakRevocationNotConfirmed(trace.NewAggregate(trace.AccessDenied("cannot delete keys"), client.ErrKeycloakRevocationNotConfirmed)))
}
