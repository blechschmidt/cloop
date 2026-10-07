package security

// Guarantee: a hub without sign-in is never reachable from the network
// unless an operator acknowledged it (Task 20393).
//
// A hub with neither OIDC nor a static token answers every request from
// anyone who reaches it — it lists the projects, queues tasks and starts agent
// runs on its host. Until Task 20393 it listened on every interface whatever
// its authentication, and the hub that motivated the fix was answering
// /api/projects to the Internet. The guarantee is about the socket, so this
// drives ui.Server.Run — the same lifecycle `cloop ui` ends in, and the
// backstop for every other way a Server gets constructed — and reads the
// address its listener actually holds.

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/exposure"
	"github.com/blechschmidt/cloop/pkg/ui"
)

// TestAnOpenHubNeverListensBeyondLoopback starts an open Server with every
// kind of address an operator could give it, without the acknowledgement,
// and requires each to end on loopback or in the refusal. Each address beyond
// loopback is one a working machine would accept a bind on, so a regression
// shows up as a hub serving, not as a bind error.
func TestAnOpenHubNeverListensBeyondLoopback(t *testing.T) {
	listens := []string{"", "127.0.0.1", "localhost", "0.0.0.0", "::", "[::]"}
	if ip := ownNetworkAddr(); ip != nil {
		listens = append(listens, ip.String())
	}
	for _, listen := range listens {
		t.Run("listen="+listen, func(t *testing.T) {
			srv := ui.New(t.TempDir(), freeLoopbackPort(t), "")
			srv.ListenHost = listen

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

			deadline := time.Now().Add(10 * time.Second)
			for {
				select {
				case err := <-done:
					done <- err // for the deferred drain
					if !errors.Is(err, exposure.ErrOpenToNetwork) {
						t.Fatalf("Run(%q) = %v, want a bind on loopback or the refusal", listen, err)
					}
					if a := srv.BoundAddr(); a != nil {
						t.Fatalf("a refused start holds %v", a)
					}
					return
				default:
				}
				if a, ok := srv.BoundAddr().(*net.TCPAddr); ok {
					if !a.IP.IsLoopback() {
						t.Fatalf("an open hub given %q is listening on %v", listen, a)
					}
					return
				}
				if time.Now().After(deadline) {
					t.Fatalf("Run(%q) neither bound nor refused within 10s", listen)
				}
				time.Sleep(5 * time.Millisecond)
			}
		})
	}
}

// TestOnlyTheAcknowledgementLetsAnOpenHubOut: the refusal is lifted by
// ui.allow_unauthenticated_network and by nothing else — not by naming the
// address twice, not by an API token, not by TLS.
func TestOnlyTheAcknowledgementLetsAnOpenHubOut(t *testing.T) {
	refused := []exposure.Request{
		{Listen: "0.0.0.0", Port: 8080},
		{Listen: "0.0.0.0", Port: 8080, TLS: true, ExternalURL: "https://hub.example.com"},
		{Listen: "hub.localhost", Port: 8080},
	}
	for _, r := range refused {
		if _, err := exposure.Decide(r); !errors.Is(err, exposure.ErrOpenToNetwork) {
			t.Errorf("Decide(%+v) = %v, want the refusal", r, err)
		}
	}
	r := refused[0]
	r.AllowUnauthenticatedNetwork = true
	plan, err := exposure.Decide(r)
	if err != nil || !plan.Acknowledged {
		t.Fatalf("with the acknowledgement: %v, %v", plan, err)
	}
	text, warning := plan.Notice()
	if !warning || !strings.Contains(text, exposure.AckKey) {
		t.Errorf("an acknowledged open hub must warn at start, naming the setting: %q", text)
	}
}

// ownNetworkAddr is an address of this machine that is not loopback, or nil.
func ownNetworkAddr() net.IP {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok && ipn.IP.IsGlobalUnicast() && ipn.IP.To4() != nil {
			return ipn.IP
		}
	}
	return nil
}

// freeLoopbackPort is a port nothing listens on right now.
func freeLoopbackPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}
