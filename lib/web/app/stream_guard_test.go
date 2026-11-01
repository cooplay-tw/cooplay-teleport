// Copyright (C) 2026 Cooplay contributors.
// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/auth/authclient"
	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/require"
)

type revokedAppAccessPoint struct {
	authclient.ProxyAccessPoint
	revoked atomic.Bool
}

func (p *revokedAppAccessPoint) GetAppSession(ctx context.Context, req types.GetAppSessionRequest) (types.WebSession, error) {
	if p.revoked.Load() {
		return nil, errors.New("app session deleted")
	}
	return p.ProxyAccessPoint.GetAppSession(ctx, req)
}

func TestWithAuthCancelsActiveRequestOnAppLogout(t *testing.T) {
	clk := clockwork.NewFakeClock()
	h, base, addr := newExpiryTestHandler(t, t.Context(), clk)
	base.appServers[0].GetApp().SetName("testapp")
	p := &revokedAppAccessPoint{ProxyAccessPoint: base}
	h.c.AccessPoint = p
	started, ended := make(chan struct{}), make(chan struct{})
	r := newClientCertRequest(t, addr, "testuser", clk.Now().Add(time.Minute))
	go func() {
		defer close(ended)
		h.withAuth(func(w http.ResponseWriter, r *http.Request, _ *session) error {
			close(started)
			<-r.Context().Done()
			return nil
		})(httptest.NewRecorder(), r)
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("request did not start")
	}
	p.revoked.Store(true)
	select {
	case <-ended:
	case <-time.After(6 * time.Second):
		t.Fatal("logout left active request running")
	}
}

func TestAppStreamCancelsUpgradedWebSocket(t *testing.T) {
	upstreamClosed := make(chan struct{})
	u := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer c.Close()
		defer close(upstreamClosed)
		_, _, _ = c.ReadMessage()
	}))
	defer u.Close()
	target, err := url.Parse(u.URL)
	require.NoError(t, err)
	proxy := httputil.NewSingleHostReverseProxy(target)
	var revoked atomic.Bool
	p := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, stop := monitorAppStream(r.Context(), 10*time.Millisecond, func(context.Context) error {
			if revoked.Load() {
				return errors.New("revoked")
			}
			return nil
		})
		defer stop()
		proxy.ServeHTTP(w, r.WithContext(ctx))
	}))
	defer p.Close()
	c, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(p.URL, "http"), nil)
	require.NoError(t, err)
	defer c.Close()
	revoked.Store(true)
	require.NoError(t, c.SetReadDeadline(time.Now().Add(time.Second)))
	_, _, err = c.ReadMessage()
	require.Error(t, err)
	select {
	case <-upstreamClosed:
	case <-time.After(time.Second):
		t.Fatal("upgraded backend survived revocation")
	}
}

func TestAppStreamFailsClosedAndStopsChecks(t *testing.T) {
	var calls atomic.Int64
	ctx, stop := monitorAppStream(t.Context(), time.Millisecond, func(ctx context.Context) error {
		calls.Add(1)
		return errors.New("access point unavailable")
	})
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("authorization failure did not close stream")
	}
	stop()
	require.Equal(t, int64(1), calls.Load())
	require.ErrorContains(t, context.Cause(ctx), "unavailable")
}
