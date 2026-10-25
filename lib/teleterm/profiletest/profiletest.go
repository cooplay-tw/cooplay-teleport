// Copyright (C) 2026 Cooplay contributors.
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package profiletest writes tsh profiles with locally signed credentials for
// Teleport Connect tests that need a logged-in profile but no cluster.
package profiletest

import (
	"crypto/x509/pkix"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	apiprofile "github.com/gravitational/teleport/api/profile"
	"github.com/gravitational/teleport/api/utils/keys"
	"github.com/gravitational/teleport/lib/auth/testauthority"
	"github.com/gravitational/teleport/lib/client"
	"github.com/gravitational/teleport/lib/fixtures"
	"github.com/gravitational/teleport/lib/sshca"
	"github.com/gravitational/teleport/lib/tlsca"
)

// RootClusterName is the root cluster name encoded in the credentials.
const RootClusterName = "root"

// AddLoggedInProfile saves a profile for webProxyAddr and a key ring for
// username, signed by throwaway CAs, and returns the key ring index. Nothing
// listens on webProxyAddr unless the caller starts a server there.
func AddLoggedInProfile(t *testing.T, store *client.Store, webProxyAddr, username string) client.KeyRingIndex {
	t.Helper()
	privateKey, err := keys.ParsePrivateKey(fixtures.PEMBytes["rsa"])
	require.NoError(t, err)

	caCert, err := tlsca.GenerateSelfSignedCAWithSigner(privateKey, pkix.Name{
		CommonName:   RootClusterName,
		Organization: []string{RootClusterName},
	}, nil, time.Hour)
	require.NoError(t, err)
	ca, err := tlsca.FromCertAndSigner(caCert, privateKey)
	require.NoError(t, err)
	subject, err := (&tlsca.Identity{Username: username, Groups: []string{"access"}}).Subject()
	require.NoError(t, err)
	tlsCert, err := ca.GenerateCertificate(tlsca.CertificateRequest{
		PublicKey: privateKey.Public(),
		Subject:   subject,
		NotAfter:  time.Now().Add(time.Hour),
	})
	require.NoError(t, err)

	sshCAKey, err := keys.ParsePrivateKey([]byte(fixtures.SSHCAPrivateKey))
	require.NoError(t, err)
	sshCA, err := ssh.NewSignerFromKey(sshCAKey)
	require.NoError(t, err)
	sshCert, err := testauthority.GenerateUserCert(sshca.UserCertificateRequest{
		CASigner:      sshCA,
		PublicUserKey: ssh.MarshalAuthorizedKey(privateKey.SSHPublicKey()),
		TTL:           time.Hour,
		Identity:      sshca.Identity{Username: username, Principals: []string{username}},
	})
	require.NoError(t, err)

	host, _, err := net.SplitHostPort(webProxyAddr)
	require.NoError(t, err)
	keyRing := client.NewKeyRing(privateKey, privateKey)
	keyRing.KeyRingIndex = client.KeyRingIndex{ProxyHost: host, Username: username, ClusterName: RootClusterName}
	keyRing.Cert = sshCert
	keyRing.TLSCert = tlsCert
	require.NoError(t, store.SaveProfile(&apiprofile.Profile{
		WebProxyAddr: webProxyAddr,
		Username:     username,
		SiteName:     RootClusterName,
	}, true))
	require.NoError(t, store.AddKeyRing(keyRing))
	return keyRing.KeyRingIndex
}

// ClosedAddr returns a loopback address on which nothing is listening.
func ClosedAddr(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := listener.Addr().String()
	require.NoError(t, listener.Close())
	return addr
}
