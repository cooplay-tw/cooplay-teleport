// Teleport
// Copyright (C) 2024 Gravitational, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package vnet

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"

	"github.com/gravitational/trace"
	"github.com/jonboulle/clockwork"
	"golang.org/x/sync/singleflight"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/api/client/proto"
	"github.com/gravitational/teleport/api/types"
	vnetv1 "github.com/gravitational/teleport/gen/proto/go/teleport/lib/vnet/v1"
	"github.com/gravitational/teleport/lib/client"
	"github.com/gravitational/teleport/lib/srv/alpnproxy"
	alpncommon "github.com/gravitational/teleport/lib/srv/alpnproxy/common"
)

type appHandler struct {
	cfg *appHandlerConfig
	log *slog.Logger

	// mu guards access to portToLocalProxy and portToCertIssuer.
	mu               sync.Mutex
	portToLocalProxy map[uint16]*alpnproxy.LocalProxy
	// portToCertIssuer holds the certificate issuer of each local proxy.
	portToCertIssuer map[uint16]*appCertIssuer
}

type appHandlerConfig struct {
	appInfo  *vnetv1.AppInfo
	protocol alpncommon.Protocol

	appProvider *appProvider
	clock       clockwork.Clock
	// alwaysTrustRootClusterCA can be set in tests so that TLS dials to the
	// proxy always trust the root cluster CA rather than the system cert pool,
	// even when ALPN conn upgrades are not required.
	alwaysTrustRootClusterCA bool
}

func newAppHandler(cfg *appHandlerConfig) *appHandler {
	return &appHandler{
		cfg: cfg,
		log: log.With(
			teleport.ComponentKey, teleport.Component("vnet", "app-handler"),
			"profile", cfg.appInfo.GetAppKey().GetProfile(),
			"leaf_cluster", cfg.appInfo.GetAppKey().GetLeafCluster(),
			"fqdn", cfg.appInfo.GetApp().GetPublicAddr()),
		portToLocalProxy: make(map[uint16]*alpnproxy.LocalProxy),
		portToCertIssuer: make(map[uint16]*appCertIssuer),
	}
}

// getOrInitializeLocalProxy returns a separate local proxy for each port for multi-port apps. For
// single-port apps, it returns the same local proxy no matter the port.
func (h *appHandler) getOrInitializeLocalProxy(ctx context.Context, localPort uint16) (*alpnproxy.LocalProxy, *appCertIssuer, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	// Connections to single-port apps need to go through a local proxy that has a cert with TargetPort
	// set to 0. This ensures that the old behavior is kept for such apps, where the client can dial
	// the public address of an app on any port and be routed to the port from the URI.
	//
	// https://github.com/gravitational/teleport/blob/master/rfd/0182-multi-port-tcp-app-access.md#vnet-with-single-port-apps
	if len(h.cfg.appInfo.GetApp().GetTCPPorts()) == 0 {
		localPort = 0
	}
	lp, ok := h.portToLocalProxy[localPort]
	if ok {
		return lp, h.portToCertIssuer[localPort], nil
	}
	appCertIssuer := &appCertIssuer{
		appProvider: h.cfg.appProvider,
		appInfo:     h.cfg.appInfo,
		targetPort:  localPort,
	}
	certChecker := client.NewCertChecker(appCertIssuer, h.cfg.clock)
	middleware := &localProxyMiddleware{
		certChecker: certChecker,
		onNewConnection: func(ctx context.Context) error {
			return h.cfg.appProvider.OnNewAppConnection(ctx, h.cfg.appInfo.GetAppKey())
		},
	}
	h.log.DebugContext(ctx, "Creating local proxy", "target_port", localPort, "protocol", h.cfg.protocol)
	newLP, err := newLocalProxy(localProxyConfig{
		dialOptions:              h.cfg.appInfo.GetDialOptions(),
		protocols:                []alpncommon.Protocol{h.cfg.protocol},
		parentContext:            ctx,
		middleware:               middleware,
		clock:                    h.cfg.clock,
		alwaysTrustRootClusterCA: h.cfg.alwaysTrustRootClusterCA,
	})
	if err != nil {
		return nil, nil, trace.Wrap(err)
	}
	h.portToLocalProxy[localPort] = newLP
	h.portToCertIssuer[localPort] = appCertIssuer
	return newLP, appCertIssuer, nil
}

// handleTCPConnector handles an incoming TCP connection from VNet by passing it to the local alpn proxy,
// which is set up with middleware to automatically handle certificate renewal and re-logins.
func (h *appHandler) handleTCPConnector(ctx context.Context, localPort uint16, connector func() (net.Conn, error)) error {
	app := h.cfg.appInfo.GetApp()
	if len(app.GetTCPPorts()) > 0 {
		if !app.GetTCPPorts().Contains(int(localPort)) {
			h.cfg.appProvider.OnInvalidLocalPort(ctx, h.cfg.appInfo, localPort)
			return trace.BadParameter("local port %d is not in TCP ports of app %q", localPort, app.GetName())
		}
	}

	lp, certIssuer, err := h.getOrInitializeLocalProxy(ctx, localPort)
	if err != nil {
		return trace.Wrap(err)
	}
	// The client application drops the keys of a profile's app certificates
	// when the user logs out (see [UserProcess.ForgetProfileCredentials]). The
	// cached certificate then fails its TLS handshake before the downstream
	// connection is accepted. Retry once: the cert checker now rejects the
	// cached certificate and reissues with the profile's current credentials,
	// prompting for login if there are none, instead of reusing a certificate
	// issued before the logout until it expires.
	connectorCalled := false
	trackedConnector := func() (net.Conn, error) {
		connectorCalled = true
		return connector()
	}
	err = lp.HandleTCPConnector(ctx, trackedConnector)
	if err != nil && !connectorCalled && certIssuer.signerLost() {
		h.log.DebugContext(ctx, "App certificate key was cleared by the client application, reissuing", "error", err)
		err = lp.HandleTCPConnector(ctx, trackedConnector)
	}
	return trace.Wrap(err, "handling TCP connector")
}

// appCertIssuer implements [client.CertIssuer].
type appCertIssuer struct {
	appProvider *appProvider
	appInfo     *vnetv1.AppInfo
	targetPort  uint16
	group       singleflight.Group
	// signer tracks the key of the most recently issued certificate.
	signer atomic.Pointer[trackedAppSigner]
}

func (i *appCertIssuer) CheckCert(cert *x509.Certificate) error {
	if i.signerLost() {
		return trace.CompareFailed("app certificate key is no longer held by the client application")
	}
	return nil
}

func (i *appCertIssuer) IssueCert(ctx context.Context) (tls.Certificate, error) {
	cert, err, _ := i.group.Do("", func() (any, error) {
		return i.appProvider.ReissueAppCert(ctx, i.appInfo, i.targetPort)
	})
	if err != nil {
		return tls.Certificate{}, trace.Wrap(err)
	}
	tlsCert := cert.(tls.Certificate)
	if signer, ok := tlsCert.PrivateKey.(crypto.Signer); ok {
		tracked := &trackedAppSigner{Signer: signer}
		tlsCert.PrivateKey = tracked
		i.signer.Store(tracked)
	}
	return tlsCert, nil
}

// signerLost reports whether the client application no longer holds the key
// of the most recently issued certificate.
func (i *appCertIssuer) signerLost() bool {
	signer := i.signer.Load()
	return signer != nil && signer.lost.Load()
}

// trackedAppSigner records when the client application reports that it no
// longer holds the key of an app certificate.
type trackedAppSigner struct {
	crypto.Signer
	lost atomic.Bool
}

// Sign implements [crypto.Signer].
func (s *trackedAppSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	signature, err := s.Signer.Sign(rand, digest, opts)
	if trace.IsNotFound(err) {
		s.lost.Store(true)
	}
	return signature, err
}

// IsHTTPSTunnelApp returns true if the app should be proxied through the
// HTTPS-in-mTLS tunnel. Currently this includes HTTP and LLM apps.
func IsHTTPSTunnelApp(app types.Application) bool {
	return app.IsLLM() || app.GetProtocol() == types.ApplicationProtocolHTTP
}

// RouteToApp returns a *proto.RouteToApp populated from appInfo and targetPort.
func RouteToApp(appInfo *vnetv1.AppInfo, targetPort uint16) *proto.RouteToApp {
	app := appInfo.GetApp()
	return &proto.RouteToApp{
		Name:        app.GetName(),
		PublicAddr:  app.GetPublicAddr(),
		ClusterName: appInfo.GetCluster(),
		URI:         app.GetURI(),
		TargetPort:  uint32(targetPort),
		Scope:       app.GetScope(),
	}
}
