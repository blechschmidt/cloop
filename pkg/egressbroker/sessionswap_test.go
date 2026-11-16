package egressbroker

// Two runs of different projects hold egress sessions on one proxy at once
// (Task 20502), each redeemed from its own project's grant. A request is
// served as the run whose whole credential it presents and as no other: one
// session's id with the other's token is refused, both ways, and so is no
// credential at all — and none of them dials anything. A whole credential
// reaches what its own grant opens, and not what the other run's opens.

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/secretbroker"
)

func TestASessionCredentialServesItsOwnRunAndNoOther(t *testing.T) {
	origin := func(name string) *httptest.Server {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, name+"'s origin")
		}))
		t.Cleanup(srv.Close)
		return srv
	}
	alphaOrigin, bravoOrigin := origin("alpha"), origin("bravo")

	b, err := New(NewMemStore(), WithAuditor(&recordingAuditor{}))
	if err != nil {
		t.Fatal(err)
	}
	grant := func(project string, port int) {
		t.Helper()
		sub, err := secretbroker.ParseSubject("project:" + project)
		if err != nil {
			t.Fatal(err)
		}
		g := loopbackGrant(port)
		if _, err := b.Grant(context.Background(), GrantRequest{Subject: sub, Hosts: g.Hosts, CIDRs: g.CIDRs,
			Ports: g.Ports, TTL: time.Hour, Actor: "test"}); err != nil {
			t.Fatalf("grant %s: %v", project, err)
		}
	}
	grant("/srv/alpha", portOf(t, alphaOrigin.URL))
	grant("/srv/bravo", portOf(t, bravoOrigin.URL))

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

	redeem := func(project, run string) *Redemption {
		t.Helper()
		red, err := b.Redeem(context.Background(), RedeemRequest{
			Requester: secretbroker.Requester{ExecutorID: "exec-1", ProjectID: project}, RunID: run})
		if err != nil {
			t.Fatalf("redeem for %s: %v", run, err)
		}
		return red
	}
	alpha := redeem("/srv/alpha", "run-alpha")
	bravo := redeem("/srv/bravo", "run-bravo")

	proxyURL, err := url.Parse("http://" + p.Addr())
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Timeout: 10 * time.Second,
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL), DisableKeepAlives: true}}
	get := func(target, authorization string) int {
		t.Helper()
		req, err := http.NewRequest(http.MethodGet, target, nil)
		if err != nil {
			t.Fatal(err)
		}
		if authorization != "" {
			req.Header.Set("Proxy-Authorization", authorization)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("GET %s: %v", target, err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}

	for name, c := range map[string]struct{ target, authorization string }{
		"alpha's id with bravo's token":                  {alphaOrigin.URL, FormatProxyCredential(alpha.Session.ID, bravo.Token)},
		"bravo's id with alpha's token":                  {bravoOrigin.URL, FormatProxyCredential(bravo.Session.ID, alpha.Token)},
		"bravo's id with alpha's token, on alpha's host": {alphaOrigin.URL, FormatProxyCredential(bravo.Session.ID, alpha.Token)},
		"no credential":                                  {alphaOrigin.URL, ""},
		"alpha's token as its id":                        {alphaOrigin.URL, FormatProxyCredential(alpha.Token, alpha.Token)},
	} {
		if got := get(c.target, c.authorization); got != http.StatusProxyAuthRequired {
			t.Errorf("%s: status %d, want 407", name, got)
		}
	}
	if got := rec.seen(); len(got) != 0 {
		t.Fatalf("a refused credential dialled %v", got)
	}

	// Alpha's whole credential on what only bravo's grant opens: alpha's
	// session, so refused, and nothing dialled.
	if got := get(bravoOrigin.URL, FormatProxyCredential(alpha.Session.ID, alpha.Token)); got != http.StatusForbidden {
		t.Errorf("alpha's credential to bravo's origin: status %d, want 403", got)
	}
	if got := rec.seen(); len(got) != 0 {
		t.Fatalf("alpha's credential dialled bravo's origin: %v", got)
	}

	// Each whole credential is its own run, and reaches its own grant's host.
	if got := get(alphaOrigin.URL, FormatProxyCredential(alpha.Session.ID, alpha.Token)); got != http.StatusOK {
		t.Fatalf("alpha's own credential to alpha's origin: status %d", got)
	}
	if got := get(bravoOrigin.URL, FormatProxyCredential(bravo.Session.ID, bravo.Token)); got != http.StatusOK {
		t.Fatalf("bravo's own credential to bravo's origin: status %d", got)
	}
	if got := rec.seen(); len(got) != 2 {
		t.Errorf("dialled %v, want alpha's origin then bravo's", got)
	}

	// Closing one run's session leaves the other's working.
	b.CloseSession(alpha.Session.ID, "run ended")
	if got := get(alphaOrigin.URL, FormatProxyCredential(alpha.Session.ID, alpha.Token)); got != http.StatusProxyAuthRequired {
		t.Errorf("alpha's closed session: status %d, want 407", got)
	}
	if got := get(bravoOrigin.URL, FormatProxyCredential(bravo.Session.ID, bravo.Token)); got != http.StatusOK {
		t.Errorf("bravo's session after alpha's closed: status %d", got)
	}
}

// TestRefuseClosesWhatAGrantCovers (Task 20502): the hub's proxy dials from
// its own host, past every sandbox ruleset, so it refuses the addresses of its
// sandbox networks through Options.Refuse — and a grant whose CIDRs cover them
// does not open them. Nothing is dialled; the same grant still reaches what
// Refuse leaves alone.
func TestRefuseClosesWhatAGrantCovers(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "a sandbox's listener")
	}))
	t.Cleanup(origin.Close)
	port := portOf(t, origin.URL)

	for _, refuse := range []bool{true, false} {
		rec := &dialRecorder{}
		opts := Options{Dial: rec.dial}
		if refuse {
			opts.Refuse = func(a netip.Addr) string {
				if a.IsLoopback() {
					return "an address on a sandbox network of this host"
				}
				return ""
			}
		}
		f := newFixture(t, loopbackGrant(port), opts)
		resp, err := f.client(t, nil).Get(origin.URL)
		if err != nil {
			t.Fatalf("refuse=%t: request: %v", refuse, err)
		}
		_ = resp.Body.Close()
		switch {
		case refuse && (resp.StatusCode != http.StatusForbidden || len(rec.seen()) != 0):
			t.Errorf("a refused address: status %d, dialled %v; want 403 and nothing dialled", resp.StatusCode, rec.seen())
		case !refuse && resp.StatusCode != http.StatusOK:
			t.Errorf("without the refusal the grant's address: status %d, want 200", resp.StatusCode)
		}
	}
}
