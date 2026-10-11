package ui

import (
	"context"
	"errors"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/exposure"
	"github.com/blechschmidt/cloop/pkg/oidcauth"
)

// TestRunRefusesAnOpenHubBeyondLoopback is the backstop half of Task 20393:
// a Server with no OIDC and no Token, asked to listen on every interface
// without the acknowledgement, returns the refusal from Run and binds
// nothing — whoever constructed it, `cloop ui` or not.
func TestRunRefusesAnOpenHubBeyondLoopback(t *testing.T) {
	t.Parallel()
	port := pickFreePort(t)
	srv := New(t.TempDir(), port, "")
	srv.ListenHost = "0.0.0.0"

	errCh := make(chan error, 1)
	go func() { errCh <- srv.Run(context.Background()) }()
	select {
	case err := <-errCh:
		if !errors.Is(err, exposure.ErrOpenToNetwork) {
			t.Fatalf("Run = %v, want the refusal", err)
		}
	case <-time.After(10 * time.Second):
		_ = srv.Shutdown(context.Background())
		t.Fatal("Run is serving an open hub on every interface instead of refusing")
	}
	if a := srv.BoundAddr(); a != nil {
		t.Fatalf("a refused start bound %v", a)
	}
	if c, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(port), time.Second); err == nil {
		_ = c.Close()
		t.Fatalf("something answers on :%d after the refusal", port)
	}
}

// TestRunBindsLoopbackWithoutSignIn: with no address named, an open Server
// binds 127.0.0.1 — not the wildcard every hub bound before Task 20393.
func TestRunBindsLoopbackWithoutSignIn(t *testing.T) {
	t.Parallel()
	addr := runAndReadBoundAddr(t, New(t.TempDir(), pickFreePort(t), ""))
	if !addr.IP.Equal(net.IPv4(127, 0, 0, 1)) {
		t.Fatalf("an open hub bound %v, want 127.0.0.1", addr)
	}
}

// TestRunBindsEveryInterfaceWithSignIn: a credential keeps the old default,
// so an authenticated deployment that never named an address is unchanged.
func TestRunBindsEveryInterfaceWithSignIn(t *testing.T) {
	t.Parallel()
	addr := runAndReadBoundAddr(t, New(t.TempDir(), pickFreePort(t), "s3cret-token"))
	if !addr.IP.IsUnspecified() {
		t.Fatalf("a token-protected hub bound %v, want every interface", addr)
	}
}

// runAndReadBoundAddr starts srv, waits until it answers on loopback, and
// returns the address its listener holds. The server is shut down on cleanup.
func runAndReadBoundAddr(t *testing.T, srv *Server) *net.TCPAddr {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Error("Run did not return after cancel")
		}
	})
	waitForServerReady(t, srv.Port, 10*time.Second)
	a, ok := srv.BoundAddr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("BoundAddr = %v after the server answered", srv.BoundAddr())
	}
	return a
}

// TestListenPlanReadsWhatTheServerHolds: the decision Run makes comes from
// the Server's own fields — OIDC, Token, ListenHost and the acknowledgement —
// so it cannot disagree with how the server will actually authenticate. The
// acknowledged open case is checked here rather than by binding, so no test
// ever serves an open hub beyond loopback.
func TestListenPlanReadsWhatTheServerHolds(t *testing.T) {
	sso, err := oidcauth.New(oidcauth.Config{
		Enabled:     true,
		Issuer:      "https://idp.example.com",
		ClientID:    "cid",
		RedirectURL: "https://cloop.example.com/auth/callback",
	})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name    string
		srv     *Server
		want    string
		refused bool
		ack     bool
	}{
		{name: "open", srv: &Server{Port: 8080}, want: "127.0.0.1:8080"},
		{name: "open, every interface", srv: &Server{Port: 8080, ListenHost: "0.0.0.0"}, refused: true},
		{name: "open, every interface, acknowledged",
			srv:  &Server{Port: 8080, ListenHost: "0.0.0.0", AllowUnauthenticatedNetwork: true},
			want: "*:8080", ack: true},
		{name: "token", srv: &Server{Port: 8080, staticToken: "t"}, want: "*:8080"},
		{name: "SSO", srv: &Server{Port: 8080, OIDC: sso}, want: "*:8080"},
		{name: "SSO, loopback", srv: &Server{Port: 8080, OIDC: sso, ListenHost: "127.0.0.1"}, want: "127.0.0.1:8080"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			plan, err := tc.srv.listenPlan()
			if tc.refused {
				if !errors.Is(err, exposure.ErrOpenToNetwork) {
					t.Fatalf("listenPlan = %v, %v; want the refusal", plan, err)
				}
				return
			}
			if err != nil || plan.String() != tc.want || plan.Acknowledged != tc.ack {
				t.Fatalf("listenPlan = %v (acknowledged=%v), %v; want %s (acknowledged=%v)",
					plan, plan.Acknowledged, err, tc.want, tc.ack)
			}
		})
	}
}
