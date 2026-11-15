package egressbroker

// A run's egress session carries its own project's grant and nothing else
// (Task 20499): alpha's run, holding a session minted from alpha's grant,
// reaches for the host bravo's grant opens, and asks for a session on
// bravo's grant outright. Both are refused, nothing is dialled, and each
// refusal is a row naming alpha's project.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/secretbroker"
)

func TestARunsEgressSessionCarriesOnlyItsOwnProjectsGrant(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "bravo's host reached")
	}))
	defer origin.Close()
	port := portOf(t, origin.URL)

	audit := &recordingAuditor{}
	b, err := New(NewMemStore(), WithAuditor(audit))
	if err != nil {
		t.Fatal(err)
	}
	grant := func(subject string, g Grant) Grant {
		t.Helper()
		sub, err := secretbroker.ParseSubject(subject)
		if err != nil {
			t.Fatal(err)
		}
		out, err := b.Grant(context.Background(), GrantRequest{Subject: sub, Hosts: g.Hosts, CIDRs: g.CIDRs,
			Ports: g.Ports, TTL: time.Hour, Actor: "test"})
		if err != nil {
			t.Fatalf("grant %s: %v", subject, err)
		}
		return out
	}
	// The same port as bravo's, so it is the host that refuses.
	grant("project:/srv/alpha", Grant{Hosts: []string{"alpha.test"}, Ports: []int{443, port}})
	bravo := grant("project:/srv/bravo", loopbackGrant(port))

	rec := &dialRecorder{}
	p, err := NewProxy(b, Options{ListenAddr: "127.0.0.1:0", Dial: rec.dial})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = p.ListenAndServe() }()
	t.Cleanup(func() { _ = p.Close() })
	for deadline := time.Now().Add(2 * time.Second); p.Addr() == "" && time.Now().Before(deadline); {
		time.Sleep(time.Millisecond)
	}

	alpha := secretbroker.Requester{ExecutorID: "exec-1", ProjectID: "/srv/alpha"}
	// Asking for bravo's grant by its id: it is aimed at bravo, so it is not
	// alpha's to redeem.
	if _, err := b.Redeem(context.Background(), RedeemRequest{Requester: alpha, GrantID: bravo.ID, RunID: "run-alpha"}); !errors.Is(err, ErrNoGrant) {
		t.Fatalf("alpha's run redeeming bravo's grant: %v, want ErrNoGrant", err)
	}
	if ev, ok := findEvent(audit.all(), secretbroker.ActionEgressRedeem, secretbroker.DecisionDeny); !ok ||
		ev.ProjectID != "/srv/alpha" {
		t.Fatalf("the refused redemption's row is %+v (found %v), want it on alpha's project", ev, ok)
	}

	red, err := b.Redeem(context.Background(), RedeemRequest{Requester: alpha, RunID: "run-alpha"})
	if err != nil {
		t.Fatalf("alpha's own session: %v", err)
	}
	f := &fixture{broker: b, proxy: p, audit: audit, red: red, dialLog: rec}
	resp, err := f.client(t, nil).Get(origin.URL)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden || resp.Header.Get("X-Cloop-Egress-Verdict") != "host_not_allowed" {
		t.Fatalf("alpha's session reaching bravo's host: %d %q, want 403 host_not_allowed", resp.StatusCode,
			resp.Header.Get("X-Cloop-Egress-Verdict"))
	}
	if got := rec.seen(); len(got) != 0 {
		t.Fatalf("a refused request dialled %v", got)
	}
	evs := audit.waitFor(t, 2*time.Second, func(evs []secretbroker.Event) bool {
		_, ok := findEvent(evs, secretbroker.ActionEgressRequest, secretbroker.DecisionDeny)
		return ok
	})
	if ev, _ := findEvent(evs, secretbroker.ActionEgressRequest, secretbroker.DecisionDeny); ev.ProjectID != "/srv/alpha" ||
		ev.Reason == "" {
		t.Fatalf("the refused request's row is %+v, want it on alpha's project with a reason", ev)
	}
}
