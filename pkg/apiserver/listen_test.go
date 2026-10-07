package apiserver

import (
	"context"
	"errors"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/exposure"
)

// TestServeBindsLoopbackWithoutAToken: without a token, POST /run/start
// starts a run for anyone who reaches the server, so with no address named it
// listens on 127.0.0.1 — and with a token, on every interface as before
// (Task 20393).
func TestServeBindsLoopbackWithoutAToken(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, token string
		loopback    bool
	}{
		{name: "no token", loopback: true},
		{name: "token", token: "s3cret"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			port := pickFreePort(t)
			srv := New(t.TempDir(), port, tc.token)
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			go func() { done <- srv.Run(ctx) }()
			defer func() {
				cancel()
				select {
				case <-done:
				case <-time.After(10 * time.Second):
					t.Error("Run did not return after cancel")
				}
			}()
			waitForServerReady(t, port, 10*time.Second)
			a, ok := srv.BoundAddr().(*net.TCPAddr)
			if !ok {
				t.Fatalf("BoundAddr = %v", srv.BoundAddr())
			}
			if tc.loopback && !a.IP.IsLoopback() {
				t.Errorf("without a token the server listens on %v, want 127.0.0.1", a)
			}
			if !tc.loopback && !a.IP.IsUnspecified() {
				t.Errorf("with a token the server listens on %v, want every interface", a)
			}
		})
	}
}

// TestServeRefusesTheNetworkWithoutAToken: --listen 0.0.0.0 without a token
// and without the acknowledgement returns the refusal, naming the server's
// own credential, and binds nothing.
func TestServeRefusesTheNetworkWithoutAToken(t *testing.T) {
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
		for _, want := range []string{"refusing to listen on *:" + strconv.Itoa(port), "CLOOP_API_TOKEN",
			exposure.AckKey} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("the refusal does not say %q: %v", want, err)
			}
		}
	case <-time.After(10 * time.Second):
		_ = srv.Shutdown(context.Background())
		t.Fatal("Run is serving the network without a token instead of refusing")
	}
	if srv.BoundAddr() != nil {
		t.Errorf("a refused start bound %v", srv.BoundAddr())
	}
}

// TestServeListenPlanHonoursTheAcknowledgement checks the acknowledged case by
// its plan, so no test serves an unauthenticated API beyond loopback.
func TestServeListenPlanHonoursTheAcknowledgement(t *testing.T) {
	srv := &Server{Port: 8081, ListenHost: "0.0.0.0", AllowUnauthenticatedNetwork: true}
	plan, err := srv.listenPlan()
	if err != nil || !plan.Acknowledged || plan.String() != "*:8081" {
		t.Fatalf("listenPlan = %v (acknowledged=%v), %v", plan, plan.Acknowledged, err)
	}
	if text, warning := listenNotice(plan); !warning || !strings.Contains(text, "WARNING") {
		t.Errorf("an acknowledged open API server must warn: %q", text)
	}
	open, _ := (&Server{Port: 8081}).listenPlan()
	if text, warning := listenNotice(open); warning || !strings.Contains(text, "127.0.0.1:8081 only") {
		t.Errorf("the open default's notice = %q (warning=%v)", text, warning)
	}
}
