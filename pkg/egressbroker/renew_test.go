package egressbroker

// Tests for what a hub that hosts the proxy needs from the broker (Task 20378):
// sessions renewed for as long as a run lives and no longer than its grant,
// revocations made elsewhere noticed by a re-read, a per-run proxy address,
// the configured default quotas, and a proxy that leaves nothing running once
// it is closed.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/secretbroker"
)

func TestExtendSessionRenewsUpToTheGrantAndNoFurther(t *testing.T) {
	now := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	b, audit := newBroker(t, &now, WithMaxSessionTTL(10*time.Minute))
	g := mustGrant(t, b, GrantRequest{Subject: mustSubject(t, "project:/srv/app"), TTL: 25 * time.Minute})

	red, err := b.Redeem(context.Background(), RedeemRequest{
		Requester: secretbroker.Requester{ExecutorID: "edge-1", ProjectID: "/srv/app"},
		RunID:     "run-1",
		TaskID:    "run-1",
		Actor:     "alice",
	})
	if err != nil {
		t.Fatalf("redeem: %v", err)
	}
	if want := now.Add(10 * time.Minute); !red.Session.ExpiresAt().Equal(want) {
		t.Fatalf("issued until %s, want %s", red.Session.ExpiresAt(), want)
	}

	// Eight minutes in: the session moves to now+10m.
	now = now.Add(8 * time.Minute)
	got, err := b.ExtendSession(context.Background(), red.Session.ID)
	if err != nil {
		t.Fatalf("extend: %v", err)
	}
	if want := now.Add(10 * time.Minute); !got.Equal(want) || !red.Session.ExpiresAt().Equal(want) {
		t.Fatalf("renewed to %s (session says %s), want %s", got, red.Session.ExpiresAt(), want)
	}
	ev, ok := findEvent(audit.all(), secretbroker.ActionEgressRenew, secretbroker.DecisionAllow)
	if !ok {
		t.Fatalf("a renewal must be audited:\n%s", renderEvents(audit.all()))
	}
	if ev.LeaseID != red.Session.ID || ev.GrantID != g.ID || ev.RunID != "run-1" || ev.Actor != "alice" ||
		!ev.ExpiresAt.Equal(got) {
		t.Errorf("renew row = %s", ev.Fields())
	}

	// Seventeen minutes in: the grant ends at 25 minutes, so that is the ceiling.
	now = now.Add(9 * time.Minute)
	got, err = b.ExtendSession(context.Background(), red.Session.ID)
	if err != nil {
		t.Fatalf("second extend: %v", err)
	}
	if !got.Equal(g.ExpiresAt) {
		t.Fatalf("renewed to %s, past the grant's own expiry %s", got, g.ExpiresAt)
	}

	// Nothing more can be gained: same deadline back, no second row for it.
	renewals := countEvents(audit.all(), secretbroker.ActionEgressRenew)
	if again, err := b.ExtendSession(context.Background(), red.Session.ID); err != nil || !again.Equal(got) {
		t.Fatalf("a renewal that cannot move the deadline = %s, %v; want %s", again, err, got)
	}
	if n := countEvents(audit.all(), secretbroker.ActionEgressRenew); n != renewals {
		t.Errorf("a renewal that changed nothing wrote a row (%d → %d)", renewals, n)
	}
}

func TestExtendSessionNeverShortens(t *testing.T) {
	now := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	b, _ := newBroker(t, &now, WithMaxSessionTTL(10*time.Minute))
	mustGrant(t, b, GrantRequest{Subject: mustSubject(t, "project:/srv/app"), TTL: time.Hour})
	red, err := b.Redeem(context.Background(), RedeemRequest{
		Requester: secretbroker.Requester{ProjectID: "/srv/app"},
	})
	if err != nil {
		t.Fatal(err)
	}
	issued := red.Session.ExpiresAt()
	// A clock that went backwards must not pull the deadline in with it.
	now = now.Add(-5 * time.Minute)
	if got, err := b.ExtendSession(context.Background(), red.Session.ID); err != nil || !got.Equal(issued) {
		t.Fatalf("extend after the clock stepped back = %s, %v; want the issued %s", got, err, issued)
	}
}

// TestRevocationElsewhereReachesALiveSession: `cloop egress revoke` in another
// process, or a revoke on another hub member, stamps the shared store and
// nothing else. The hub that holds the session learns of it by re-reading.
func TestRevocationElsewhereReachesALiveSession(t *testing.T) {
	now := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	audit := &recordingAuditor{}
	store := NewMemStore()
	hub, err := New(store, WithAuditor(audit), WithEndpoint("127.0.0.1:8899"),
		WithClock(func() time.Time { return now }))
	if err != nil {
		t.Fatal(err)
	}
	g := mustGrant(t, hub, GrantRequest{Subject: mustSubject(t, "project:/srv/app"), TTL: time.Hour})
	red, err := hub.Redeem(context.Background(), RedeemRequest{
		Requester: secretbroker.Requester{ProjectID: "/srv/app"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := hub.RecheckSession(red.Session.ID); err != nil {
		t.Fatalf("a live session under an active grant must recheck clean: %v", err)
	}

	// Another broker over the same store: the CLI.
	cli, err := New(store, WithClock(func() time.Time { return now }))
	if err != nil {
		t.Fatal(err)
	}
	if err := cli.Revoke(context.Background(), g.ID, "op"); err != nil {
		t.Fatal(err)
	}
	if red.Session.Closed() {
		t.Fatal("precondition: the CLI's broker holds none of the hub's sessions")
	}
	if err := hub.RecheckSession(red.Session.ID); !errors.Is(err, ErrGrantRevoked) {
		t.Fatalf("recheck after a revoke elsewhere = %v, want ErrGrantRevoked", err)
	}
	if _, err := hub.ExtendSession(context.Background(), red.Session.ID); !errors.Is(err, ErrGrantRevoked) {
		t.Fatalf("renewal after a revoke elsewhere = %v, want ErrGrantRevoked", err)
	}
	if _, ok := findEvent(audit.all(), secretbroker.ActionEgressRenew, secretbroker.DecisionDeny); !ok {
		t.Errorf("a refused renewal must be audited:\n%s", renderEvents(audit.all()))
	}
}

func TestExtendSessionRefusesAClosedOrLapsedSession(t *testing.T) {
	now := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	b, _ := newBroker(t, &now, WithMaxSessionTTL(time.Minute))
	mustGrant(t, b, GrantRequest{Subject: mustSubject(t, "project:/srv/app"), TTL: time.Hour})
	redeem := func() *Redemption {
		red, err := b.Redeem(context.Background(), RedeemRequest{Requester: secretbroker.Requester{ProjectID: "/srv/app"}})
		if err != nil {
			t.Fatal(err)
		}
		return red
	}

	closed := redeem()
	b.CloseSession(closed.Session.ID, "run ended")
	if _, err := b.ExtendSession(context.Background(), closed.Session.ID); !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("renewing a closed session = %v, want ErrSessionExpired", err)
	}

	lapsed := redeem()
	now = now.Add(2 * time.Minute)
	if _, err := b.ExtendSession(context.Background(), lapsed.Session.ID); !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("renewing a lapsed session = %v, want ErrSessionExpired", err)
	}
	if _, err := b.ExtendSession(context.Background(), "sess_unknown"); !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("renewing an unknown session = %v, want ErrSessionExpired", err)
	}
}

// TestALabelGrantStillMatchesOnRenewal: a session redeemed under a label grant
// must renew, which needs the requester's labels kept with it.
func TestALabelGrantStillMatchesOnRenewal(t *testing.T) {
	now := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	b, _ := newBroker(t, &now, WithMaxSessionTTL(10*time.Minute))
	mustGrant(t, b, GrantRequest{Subject: mustSubject(t, "label:region=eu"), TTL: time.Hour})
	labels := map[string]string{"region": "eu"}
	red, err := b.Redeem(context.Background(), RedeemRequest{
		Requester: secretbroker.Requester{ExecutorID: "edge-1", ProjectID: "/srv/app", Labels: labels},
	})
	if err != nil {
		t.Fatal(err)
	}
	labels["region"] = "us" // the caller's map is not the session's record
	now = now.Add(5 * time.Minute)
	if _, err := b.ExtendSession(context.Background(), red.Session.ID); err != nil {
		t.Fatalf("a label grant must renew for the executor it was issued to: %v", err)
	}
}

func TestDefaultQuotasBoundOnlyAGrantThatNamesNone(t *testing.T) {
	now := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	b, audit := newBroker(t, &now, WithDefaultQuotas(1000, 2000))
	unbounded := mustGrant(t, b, GrantRequest{Subject: mustSubject(t, "project:/srv/a"), TTL: time.Hour})
	own := mustGrant(t, b, GrantRequest{Subject: mustSubject(t, "project:/srv/b"), TTL: time.Hour,
		MaxBytesUp: 5, MaxBytesDown: 6})

	red, err := b.Redeem(context.Background(), RedeemRequest{Requester: secretbroker.Requester{ProjectID: "/srv/a"}})
	if err != nil {
		t.Fatal(err)
	}
	if red.Session.Grant.MaxBytesUp != 1000 || red.Session.Grant.MaxBytesDown != 2000 {
		t.Errorf("a grant naming no quota is redeemed under up=%d down=%d, want the defaults 1000/2000",
			red.Session.Grant.MaxBytesUp, red.Session.Grant.MaxBytesDown)
	}
	if stored, _ := b.store.GetGrant(unbounded.ID); stored.MaxBytesUp != 0 {
		t.Error("the default must bound the session, not rewrite the stored grant")
	}
	ev, _ := findEvent(audit.all(), secretbroker.ActionEgressRedeem, secretbroker.DecisionAllow)
	if !strings.Contains(ev.Constraints, "up<=") {
		t.Errorf("the redeem row must show the quota the session is held to, got %q", ev.Constraints)
	}

	red, err = b.Redeem(context.Background(), RedeemRequest{Requester: secretbroker.Requester{ProjectID: "/srv/b"}})
	if err != nil {
		t.Fatal(err)
	}
	if red.Session.GrantID != own.ID || red.Session.Grant.MaxBytesUp != 5 || red.Session.Grant.MaxBytesDown != 6 {
		t.Errorf("a grant's own quota must win over the default, got up=%d down=%d",
			red.Session.Grant.MaxBytesUp, red.Session.Grant.MaxBytesDown)
	}
}

func TestRedeemEndpointAndNoProxyArePerRedemption(t *testing.T) {
	now := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	b, _ := newBroker(t, &now)
	mustGrant(t, b, GrantRequest{Subject: mustSubject(t, "project:/srv/app"), TTL: time.Hour})

	red, err := b.Redeem(context.Background(), RedeemRequest{
		Requester: secretbroker.Requester{ProjectID: "/srv/app"},
		Endpoint:  "host.containers.internal:41001",
		NoProxy:   []string{"hub.internal", "HUB.internal", "", "bad,host", "10.0.0.7"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(red.ProxyURL, "http://"+red.Session.ID+":") ||
		!strings.HasSuffix(red.ProxyURL, "@host.containers.internal:41001") {
		t.Errorf("proxy URL = %q, want the per-redemption endpoint", redactToken(red.ProxyURL, red.Token))
	}
	env := red.Env()
	if want := "localhost,127.0.0.1,::1,hub.internal,10.0.0.7"; env["NO_PROXY"] != want || env["no_proxy"] != want {
		t.Errorf("NO_PROXY = %q / %q, want %q", env["NO_PROXY"], env["no_proxy"], want)
	}

	// No override: the broker's own endpoint.
	plain, err := b.Redeem(context.Background(), RedeemRequest{Requester: secretbroker.Requester{ProjectID: "/srv/app"}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(plain.ProxyURL, "@127.0.0.1:8899") {
		t.Errorf("proxy URL = %q, want the broker's endpoint", redactToken(plain.ProxyURL, plain.Token))
	}
	for _, k := range ProxyEnvKeys {
		if env[k] != red.ProxyURL {
			t.Errorf("%s does not carry the proxy URL", k)
		}
	}
}

func TestSessionJSONCarriesNoCredential(t *testing.T) {
	now := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	b, _ := newBroker(t, &now)
	mustGrant(t, b, GrantRequest{Subject: mustSubject(t, "project:/srv/app"), TTL: time.Hour})
	red, err := b.Redeem(context.Background(), RedeemRequest{
		Requester: secretbroker.Requester{ProjectID: "/srv/app"}, RunID: "run-9",
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(red.Session)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), red.Token) {
		t.Fatalf("a marshalled session carries its token: %s", raw)
	}
	var back map[string]any
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	if back["run_id"] != "run-9" || back["expires_at"] == nil {
		t.Errorf("marshalled session = %s", raw)
	}
}

// TestRenewalKeepsAnOpenTunnelAlive: a run renewed under an open tunnel keeps
// the tunnel past the deadline it was opened with, and loses it at the one it
// was renewed to.
func TestRenewalKeepsAnOpenTunnelAlive(t *testing.T) {
	_, port := echoListener(t)

	g := loopbackGrant(port)
	g.SessionTTL = 900 * time.Millisecond
	f := newFixture(t, g, Options{})
	conn, br := openTunnel(t, f, port)

	echo := func(what string) error {
		if _, err := conn.Write([]byte(what)); err != nil {
			return err
		}
		buf := make([]byte, len(what))
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, err := io.ReadFull(br, buf); err != nil {
			return err
		}
		if string(buf) != what {
			return fmt.Errorf("echo = %q", buf)
		}
		return nil
	}
	if err := echo("one"); err != nil {
		t.Fatalf("tunnel before renewal: %v", err)
	}

	issued := f.red.Session.ExpiresAt()
	time.Sleep(400 * time.Millisecond)
	renewed, err := f.broker.ExtendSession(context.Background(), f.red.Session.ID)
	if err != nil {
		t.Fatalf("extend: %v", err)
	}
	if !renewed.After(issued) {
		t.Fatalf("renewal did not move the deadline: %s → %s", issued, renewed)
	}

	// Past the deadline the tunnel was opened under, it still carries bytes.
	time.Sleep(time.Until(issued) + 150*time.Millisecond)
	if err := echo("two"); err != nil {
		t.Fatalf("the tunnel died at its original deadline despite the renewal: %v", err)
	}

	// And it dies at the renewed one, idle.
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := br.ReadByte(); err == nil {
		t.Fatal("the tunnel outlived its renewed session")
	}
	if time.Now().Before(renewed) {
		t.Errorf("the tunnel was cut at %s, before its renewed deadline %s", time.Now().UTC(), renewed)
	}
}

// TestProxyCloseLeavesNoGoroutines: everything a proxy starts — the server,
// the reaper, a tunnel's two copy loops, a plain request's deadline watcher —
// is gone once Close returns and the serve call has come back.
func TestProxyCloseLeavesNoGoroutines(t *testing.T) {
	_, port := echoListener(t)

	before := proxyGoroutines()

	b, err := New(NewMemStore())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Grant(context.Background(), GrantRequest{
		Subject: mustSubject(t, "project:/srv/app"), Hosts: []string{"127.0.0.1"},
		CIDRs: []string{"127.0.0.0/8"}, Ports: []int{port}, TTL: time.Hour,
	}); err != nil {
		t.Fatal(err)
	}
	p, err := NewProxy(b, Options{})
	if err != nil {
		t.Fatal(err)
	}
	pln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	served := make(chan error, 1)
	go func() { served <- p.Serve(pln) }()
	waitBound(t, p)
	red, err := b.Redeem(context.Background(), RedeemRequest{Requester: secretbroker.Requester{ProjectID: "/srv/app"}})
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{broker: b, proxy: p, red: red}
	conn, _ := openTunnel(t, f, port)

	if n := b.CloseAllSessions("test over"); n != 1 {
		t.Errorf("CloseAllSessions closed %d sessions, want 1", n)
	}
	if err := p.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	select {
	case err := <-served:
		if err != nil {
			t.Fatalf("serve: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Serve did not return after Close")
	}
	_ = conn.Close()

	deadline := time.Now().Add(5 * time.Second)
	for {
		now := proxyGoroutines()
		if len(now) <= len(before) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d proxy goroutines before, %d after Close:\n%s", len(before), len(now),
				strings.Join(now, "\n\n"))
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// proxyGoroutines returns the stacks of goroutines running the proxy's own
// code — the server and its handlers, the reaper, a tunnel's copy loops, a
// request's deadline watcher — so the leak check is about the proxy and not
// about whatever an earlier test's servers are still winding down.
func proxyGoroutines() []string {
	buf := make([]byte, 4<<20)
	var out []string
	for _, g := range strings.Split(string(buf[:runtime.Stack(buf, true)]), "\n\n") {
		for _, fn := range []string{"(*Proxy).", "(*Session).BindContext", "copyMetered"} {
			if strings.Contains(g, "egressbroker."+fn) {
				out = append(out, g)
				break
			}
		}
	}
	return out
}

func waitBound(t *testing.T, p *Proxy) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for p.Addr() == "" {
		if time.Now().After(deadline) {
			t.Fatal("proxy never bound")
		}
		time.Sleep(time.Millisecond)
	}
}

func countEvents(evs []secretbroker.Event, action secretbroker.Action) int {
	n := 0
	for _, ev := range evs {
		if ev.Action == action {
			n++
		}
	}
	return n
}

// redactToken keeps a failing assertion from printing a live credential.
func redactToken(s, token string) string {
	if token == "" {
		return s
	}
	return strings.ReplaceAll(s, token, "<token>")
}
