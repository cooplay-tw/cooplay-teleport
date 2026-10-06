// Copyright (C) 2026 Cooplay contributors.
// SPDX-License-Identifier: AGPL-3.0-or-later

package auth_test

import (
	"crypto/tls"
	"crypto/x509"
	"strings"
	"testing"
	"time"

	"github.com/gravitational/trace"
	"github.com/stretchr/testify/require"

	"github.com/gravitational/teleport/api/client/proto"
	"github.com/gravitational/teleport/api/constants"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/api/utils/sshutils"
	"github.com/gravitational/teleport/lib/auth"
	"github.com/gravitational/teleport/lib/auth/authclient"
	"github.com/gravitational/teleport/lib/auth/authtest"
	"github.com/gravitational/teleport/lib/sshca"
	"github.com/gravitational/teleport/lib/tlsca"
)

// TestKeycloakCertificateReissueBound exercises the resource-specific renewal
// path which normally permits a new full role TTL for in-memory credentials.
func TestKeycloakCertificateReissueBound(t *testing.T) {
	for _, tc := range []struct {
		name        string
		identityTTL time.Duration
		userTTL     time.Duration
	}{
		{name: "original identity expiry", identityTTL: 90 * time.Second, userTTL: 5 * time.Minute},
		{name: "stored user expiry", identityTTL: 3 * time.Minute, userTTL: 90 * time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := newTestTLSServer(t)
			user, _ := newKeycloakLifecycleUser(t, srv, tc.userTTL)
			identity := authtest.TestUser(user.GetName())
			identity.TTL = tc.identityTTL
			clt, err := srv.NewClient(identity)
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, clt.Close()) })
			// Native client credentials expose the selected certificate through
			// this callback, not the cleared tls.Config.Certificates slice.
			clientCertificate, err := clt.Config().GetClientCertificate(&tls.CertificateRequestInfo{})
			require.NoError(t, err)
			require.NotEmpty(t, clientCertificate.Certificate)
			original, err := x509.ParseCertificate(clientCertificate.Certificate[0])
			require.NoError(t, err)

			_, sshPublic, _, tlsPublic := newSSHAndTLSKeyPairs(t)
			certs, err := clt.GenerateUserCerts(t.Context(), proto.UserCertsRequest{
				Username:      user.GetName(),
				SSHPublicKey:  sshPublic,
				TLSPublicKey:  tlsPublic,
				Expires:       srv.Clock().Now().Add(time.Hour),
				Usage:         proto.UserCertsRequest_Database,
				RequesterName: proto.UserCertsRequest_TSH_DB_LOCAL_PROXY_TUNNEL,
				RouteToDatabase: proto.RouteToDatabase{
					ServiceName: "lab-db",
					Protocol:    "postgres",
				},
			})
			require.NoError(t, err)
			// Certificate issuance does not grant database access: the fixture's
			// role has no database users, names or labels. This tests renewal only.
			renewedTLS, err := tlsca.ParseCertificatePEM(certs.TLS)
			require.NoError(t, err)
			renewedSSH, err := sshutils.ParseCertificate(certs.SSH)
			require.NoError(t, err)
			for _, expires := range []time.Time{renewedTLS.NotAfter, time.Unix(int64(renewedSSH.ValidBefore), 0)} {
				require.True(t, expires.After(srv.Clock().Now()), "renewal should remain usable")
				require.False(t, expires.After(original.NotAfter), "renewal exceeded original identity expiry")
				require.False(t, expires.After(user.Expiry()), "renewal exceeded stored IdP login expiry")
			}
		})
	}
}

// A later policy edit must not let an existing Keycloak login adopt new roles,
// impersonate a local user, or escape its externally bounded session.
func TestKeycloakCertificateReissueRejectsRoleChanges(t *testing.T) {
	srv := newTestTLSServer(t)
	ctx := t.Context()
	user, role := newKeycloakLifecycleUser(t, srv, 5*time.Minute)
	clt, err := srv.NewClient(authtest.TestUser(user.GetName()))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, clt.Close()) })
	local, err := authtest.CreateUser(ctx, srv.Auth(), "local-control", role)
	require.NoError(t, err)
	localClient, err := srv.NewClient(authtest.TestUser(local.GetName()))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, localClient.Close()) })
	targetRole, err := authtest.CreateRole(ctx, srv.Auth(), "local-target-role", types.RoleSpecV6{
		Allow: types.RoleConditions{Logins: []string{"lab-target"}},
	})
	require.NoError(t, err)
	target, err := authtest.CreateUser(ctx, srv.Auth(), "local-target", targetRole)
	require.NoError(t, err)

	// Change policy after the clients have authenticated. A local control user
	// proves impersonation really is allowed by the updated native RBAC policy.
	role.SetImpersonateConditions(types.Allow, types.ImpersonateConditions{
		Users: []string{target.GetName()},
		Roles: []string{targetRole.GetName()},
	})
	_, err = srv.Auth().UpsertRole(ctx, role)
	require.NoError(t, err)
	user.AddRole(targetRole.GetName())
	_, err = srv.Auth().UpsertUser(ctx, user)
	require.NoError(t, err)
	_, sshPublic, _, tlsPublic := newSSHAndTLSKeyPairs(t)
	request := proto.UserCertsRequest{
		Username:     target.GetName(),
		SSHPublicKey: sshPublic,
		TLSPublicKey: tlsPublic,
		Expires:      srv.Clock().Now().Add(5 * time.Minute),
	}
	_, err = localClient.GenerateUserCerts(ctx, request)
	require.NoError(t, err, "local control must demonstrate the permissive policy")

	t.Run("impersonate local user", func(t *testing.T) {
		_, err := clt.GenerateUserCerts(ctx, request)
		require.True(t, trace.IsAccessDenied(err), "got %v", err)
		require.ErrorContains(t, err, "Keycloak role changes require a fresh login")
	})
	t.Run("drop requests reloads stored roles", func(t *testing.T) {
		req := request
		req.Username = user.GetName()
		req.DropAccessRequests = []string{"*"}
		_, err := clt.GenerateUserCerts(ctx, req)
		require.True(t, trace.IsAccessDenied(err), "got %v", err)
		require.ErrorContains(t, err, "Keycloak role changes require a fresh login")
	})
	t.Run("role impersonation", func(t *testing.T) {
		req := request
		req.Username = user.GetName()
		req.UseRoleRequests = true
		req.RoleRequests = []string{targetRole.GetName()}
		_, err := clt.GenerateUserCerts(ctx, req)
		require.True(t, trace.IsAccessDenied(err), "got %v", err)
		require.ErrorContains(t, err, "Keycloak role changes require a fresh login")
	})
}

func TestKeycloakWebSessionRenewal(t *testing.T) {
	srv := newTestTLSServer(t)
	ctx := t.Context()
	user, role := newKeycloakLifecycleUser(t, srv, 5*time.Minute)
	session, err := srv.Auth().CreateWebSessionFromReq(ctx, auth.NewWebSessionRequest{
		User:             user.GetName(),
		Roles:            user.GetRoles(),
		SessionTTL:       90 * time.Second,
		LoginTime:        srv.Clock().Now(),
		LoginIP:          "192.0.2.1",
		AttestWebSession: true,
	})
	require.NoError(t, err)
	clt, err := srv.NewClientFromWebSession(session)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, clt.Close()) })

	// A stored user edit must not silently reach the existing web identity.
	addedRole, err := authtest.CreateRole(ctx, srv.Auth(), "later-role", types.RoleSpecV6{})
	require.NoError(t, err)
	user.AddRole(addedRole.GetName())
	_, err = srv.Auth().UpsertUser(ctx, user)
	require.NoError(t, err)
	req := authclient.WebSessionReq{User: user.GetName(), PrevSessionID: session.GetName()}
	renewed, err := clt.ExtendWebSession(ctx, req)
	require.NoError(t, err, "ordinary renewal must still work")
	require.False(t, renewed.GetExpiryTime().After(session.GetExpiryTime()))
	cert, err := tlsca.ParseCertificatePEM(renewed.GetTLSCert())
	require.NoError(t, err)
	identity, err := tlsca.FromSubject(cert.Subject, cert.NotAfter)
	require.NoError(t, err)
	require.Equal(t, []string{role.GetName()}, identity.Groups)
	require.False(t, cert.NotAfter.After(session.GetExpiryTime()))

	for _, tc := range []struct {
		name   string
		mutate func(*authclient.WebSessionReq)
	}{
		{name: "switchback", mutate: func(r *authclient.WebSessionReq) { r.Switchback = true }},
		{name: "reload user", mutate: func(r *authclient.WebSessionReq) { r.ReloadUser = true }},
		{name: "access request", mutate: func(r *authclient.WebSessionReq) { r.AccessRequestID = "7d0d7d33-f8bd-4495-8516-20678d3e70ef" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			modified := req
			tc.mutate(&modified)
			_, err := clt.ExtendWebSession(ctx, modified)
			require.True(t, trace.IsAccessDenied(err), "got %v", err)
			require.ErrorContains(t, err, "Keycloak role changes require a fresh login")
		})
	}
}

// These lifecycle tests start after the IdP login. Mark the persisted fixture
// exactly as connector-owned users are marked, then use native TLS/Auth APIs.
func newKeycloakLifecycleUser(t *testing.T, srv *authtest.TLSServer, ttl time.Duration) (types.User, types.Role) {
	t.Helper()
	role, err := authtest.CreateRole(t.Context(), srv.Auth(), "keycloak-lab", types.RoleSpecV6{
		Options: types.RoleOptions{
			MaxSessionTTL:         types.Duration(5 * time.Minute),
			DisconnectExpiredCert: true,
			Lock:                  constants.LockingModeStrict,
		},
		Allow: types.RoleConditions{
			Logins:     []string{"lab-user"},
			NodeLabels: types.Labels{"environment": []string{"lab"}},
		},
	})
	require.NoError(t, err)
	user, err := types.NewUser("keycloak-" + strings.Repeat("a", 64))
	require.NoError(t, err)
	metadata := user.GetMetadata()
	metadata.Labels = map[string]string{"cooplay.dev/keycloak": "v1"}
	user.SetMetadata(metadata)
	user.SetExpiry(srv.Clock().Now().Add(ttl))
	user.SetRoles([]string{role.GetName()})
	user.SetCreatedBy(types.CreatedBy{Connector: &types.ConnectorRef{
		Type: constants.OIDC, ID: "keycloak-lab", Identity: "fixture-subject",
	}})
	user.(*types.UserV2).Spec.OIDCIdentities = []types.ExternalIdentity{{
		ConnectorID: "keycloak-lab", Username: "fixture-subject", UserID: "fixture-subject",
	}}
	created, err := srv.Auth().UpsertUser(t.Context(), user)
	require.NoError(t, err)
	return created, role
}

// Delays the native SSH signer itself, after the duration was calculated.
// The unchanged upstream signer then generates the real overlong certificate.
// This exercises the post-issuance bound rather than relaxing test deadlines.
type keycloakSlowSigner struct {
	sshca.Authority
	advance func(time.Duration)
	issued  chan []byte
}

func (s *keycloakSlowSigner) GenerateUserCert(req sshca.UserCertificateRequest) ([]byte, error) {
	s.advance(2 * time.Second)
	cert, err := s.Authority.GenerateUserCert(req)
	if err == nil {
		s.issued <- cert
	}
	return cert, err
}

func installKeycloakSlowSigner(t *testing.T, srv *authtest.TLSServer) <-chan []byte {
	t.Helper()
	original := srv.Auth().Authority
	signer := &keycloakSlowSigner{
		Authority: original,
		advance:   srv.Clock().(interface{ Advance(time.Duration) }).Advance,
		issued:    make(chan []byte, 4),
	}
	srv.Auth().Authority = signer
	t.Cleanup(func() { srv.Auth().Authority = original })
	return signer.issued
}

func TestKeycloakRenewalRejectsSlowSignerOverrun(t *testing.T) {
	t.Run("certificate reissue", func(t *testing.T) {
		srv := newTestTLSServer(t)
		user, _ := newKeycloakLifecycleUser(t, srv, 90*time.Second)
		clt, err := srv.NewClient(authtest.TestUser(user.GetName()))
		require.NoError(t, err)
		t.Cleanup(func() { require.NoError(t, clt.Close()) })
		_, sshPublic, _, tlsPublic := newSSHAndTLSKeyPairs(t)
		issued := installKeycloakSlowSigner(t, srv)
		certs, err := clt.GenerateUserCerts(t.Context(), proto.UserCertsRequest{
			Username: user.GetName(), SSHPublicKey: sshPublic, TLSPublicKey: tlsPublic,
			Expires:         srv.Clock().Now().Add(time.Hour),
			Usage:           proto.UserCertsRequest_Database,
			RequesterName:   proto.UserCertsRequest_TSH_DB_LOCAL_PROXY_TUNNEL,
			RouteToDatabase: proto.RouteToDatabase{ServiceName: "lab-db", Protocol: "postgres"},
		})
		require.Nil(t, certs, "no credentials may escape the absolute deadline")
		require.True(t, trace.IsAccessDenied(err), "got %v", err)
		require.ErrorContains(t, err, "exceeded its absolute expiry")
		actual, err := sshutils.ParseCertificate(<-issued)
		require.NoError(t, err)
		require.True(t, time.Unix(int64(actual.ValidBefore), 0).After(user.Expiry()), "fixture must really overrun")
	})
	t.Run("web renewal", func(t *testing.T) {
		srv := newTestTLSServer(t)
		user, _ := newKeycloakLifecycleUser(t, srv, 5*time.Minute)
		session, err := srv.Auth().CreateWebSessionFromReq(t.Context(), auth.NewWebSessionRequest{
			User: user.GetName(), Roles: user.GetRoles(), SessionTTL: 90 * time.Second,
			LoginTime: srv.Clock().Now(), LoginIP: "192.0.2.1", AttestWebSession: true,
		})
		require.NoError(t, err)
		clt, err := srv.NewClientFromWebSession(session)
		require.NoError(t, err)
		t.Cleanup(func() { require.NoError(t, clt.Close()) })
		issued := installKeycloakSlowSigner(t, srv)
		renewed, err := clt.ExtendWebSession(t.Context(), authclient.WebSessionReq{User: user.GetName(), PrevSessionID: session.GetName()})
		require.Nil(t, renewed, "no session may escape the absolute deadline")
		require.True(t, trace.IsAccessDenied(err), "got %v", err)
		require.ErrorContains(t, err, "exceeded its absolute expiry")
		actual, err := sshutils.ParseCertificate(<-issued)
		require.NoError(t, err)
		require.True(t, time.Unix(int64(actual.ValidBefore), 0).After(session.GetExpiryTime()), "fixture must really overrun")
		sessions, err := srv.Auth().WebSessions().List(t.Context())
		require.NoError(t, err)
		require.Len(t, sessions, 1, "overlong renewal must not be persisted")
		require.Equal(t, session.GetName(), sessions[0].GetName(), "the original bounded session remains")
	})
}
