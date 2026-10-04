package egressbroker

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/hubmetrics"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
)

// scrapeValue reads one series from the process's hub registry, 0 when it has
// no sample yet. labels are name/value pairs in the family's label order.
func scrapeValue(t *testing.T, family string, labels ...string) float64 {
	t.Helper()
	series := family
	if len(labels) > 0 {
		var parts []string
		for i := 0; i+1 < len(labels); i += 2 {
			parts = append(parts, labels[i]+`="`+labels[i+1]+`"`)
		}
		series += "{" + strings.Join(parts, ",") + "}"
	}
	for _, line := range strings.Split(hubmetrics.Default.Gather(), "\n") {
		if rest, ok := strings.CutPrefix(line, series+" "); ok {
			v, err := strconv.ParseFloat(strings.TrimSpace(rest), 64)
			if err != nil {
				t.Fatalf("parse %q: %v", line, err)
			}
			return v
		}
	}
	return 0
}

// settled polls read until it has moved by want from base, or five seconds
// pass, and returns the last movement. The proxy records a request's verdict
// after it has written the response — the body is on the wire before the
// audit row and its metric — so a client that has read the body can be ahead
// of both; the package's audit assertions wait on the row for the same reason.
func settled(read func() float64, base, want float64) float64 {
	deadline := time.Now().Add(5 * time.Second)
	for {
		d := read() - base
		if d == want || time.Now().After(deadline) {
			return d
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestDenialReasonCoversEverySentinel: each refusal maps to the reason the
// catalog documents, and each error that is not a policy decision maps to none
// — so a failed DNS lookup can never move the denial rate.
func TestDenialReasonCoversEverySentinel(t *testing.T) {
	cases := map[error]string{
		ErrNoGrant:            hubmetrics.EgressNoGrant,
		ErrGrantRevoked:       hubmetrics.EgressRevoked,
		ErrGrantExpired:       hubmetrics.EgressExpired,
		ErrSessionExpired:     hubmetrics.EgressExpired,
		ErrHostNotAllowed:     hubmetrics.EgressHostNotAllowed,
		ErrPortNotAllowed:     hubmetrics.EgressPortNotAllowed,
		ErrMethodNotAllowed:   hubmetrics.EgressMethodNotAllowed,
		ErrDestinationBlocked: hubmetrics.EgressDestinationBlocked,
		ErrQuotaExceeded:      hubmetrics.EgressQuotaExhausted,

		ErrUnauthenticated: "",
		ErrGrantNotFound:   "",
		ErrInvalidGrant:    "",
		ErrInvalidRequest:  "",
		ErrResolveFailed:   "",
		ErrDialFailed:      "",
		io.EOF:             "",
	}
	for err, want := range cases {
		wrapped := fmt.Errorf("%w: with detail", err)
		if got := denialReason(wrapped); got != want {
			t.Errorf("denialReason(%v) = %q, want %q", err, got, want)
		}
	}
	if got := denialReason(nil); got != "" {
		t.Errorf("denialReason(nil) = %q", got)
	}
}

// TestHubMetricsFollowTheProxy drives real requests through a proxy and reads
// the outcome back from the hub registry: an allowed request and its bytes, a
// refusal and its reason, a spent session, and the live-session gauge.
//
// Deltas, because hubmetrics.Default is process-wide and other tests in this
// package record into it too; none of them runs alongside this one.
func TestHubMetricsFollowTheProxy(t *testing.T) {
	const body = "hello, egress"
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Read the whole request before answering. An origin that answers
		// first races net/http's own write of the body: the transport can
		// return the response before it notices the body failed — on the
		// quota — and the proxy would rightly record an upload it forwarded.
		_, _ = io.Copy(io.Discard, r.Body)
		fmt.Fprint(w, body)
	}))
	defer origin.Close()
	port := portOf(t, origin.URL)

	allowed := func() float64 { return scrapeValue(t, "cloop_egress_requests_total", "result", "allowed") }
	denied := func() float64 { return scrapeValue(t, "cloop_egress_requests_total", "result", "denied") }
	reason := func(r string) float64 { return scrapeValue(t, "cloop_egress_denials_total", "reason", r) }
	down := func() float64 { return scrapeValue(t, "cloop_egress_bytes_total", "direction", "down") }
	up := func() float64 { return scrapeValue(t, "cloop_egress_bytes_total", "direction", "up") }
	live := func() float64 { return scrapeValue(t, "cloop_egress_sessions_live") }

	live0 := live()
	g := loopbackGrant(port)
	g.Methods = []string{"GET", "POST"}
	g.MaxBytesUp = 8
	f := newFixture(t, g, Options{})
	if got := live() - live0; got != 1 {
		t.Fatalf("cloop_egress_sessions_live rose by %v on a redemption, want 1", got)
	}

	// Allowed, with its response bytes counted downstream.
	allowed0, down0 := allowed(), down()
	resp, err := f.client(t, nil).Get(origin.URL + "/x")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	got, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(got) != body {
		t.Fatalf("GET = %d %q", resp.StatusCode, got)
	}
	if d := settled(allowed, allowed0, 1); d != 1 {
		t.Errorf("an allowed request moved requests{allowed} by %v, want 1", d)
	}
	if d := settled(down, down0, float64(len(body))); d != float64(len(body)) {
		t.Errorf("bytes{down} rose by %v, want the %d body bytes", d, len(body))
	}

	// Refused by policy: a port the grant does not name. No dial, one denial.
	denied0, port0 := denied(), reason(hubmetrics.EgressPortNotAllowed)
	resp, err = f.client(t, nil).Get(fmt.Sprintf("http://127.0.0.1:%d/", port+1))
	if err != nil {
		t.Fatalf("GET other port: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("other port = %d, want 403", resp.StatusCode)
	}
	if d := settled(denied, denied0, 1); d != 1 {
		t.Errorf("a refusal moved requests{denied} by %v, want 1", d)
	}
	if d := settled(func() float64 { return reason(hubmetrics.EgressPortNotAllowed) }, port0, 1); d != 1 {
		t.Errorf("denials{port_not_allowed} rose by %v, want 1", d)
	}

	// The upload budget: a body over it is cut, charged, and refused.
	up0, quota0 := up(), reason(hubmetrics.EgressQuotaExhausted)
	resp, err = f.client(t, nil).Post(origin.URL+"/up", "text/plain", strings.NewReader("0123456789abcdef"))
	if err == nil {
		resp.Body.Close()
	}
	// The client may give up on the upload before the proxy has recorded why,
	// so the refusal is waited for before anything is read from it.
	quota := func() float64 { return reason(hubmetrics.EgressQuotaExhausted) }
	if d := settled(quota, quota0, 1); d != 1 {
		t.Errorf("denials{quota_exhausted} rose by %v for an over-budget upload, want 1", d)
	}
	if d := up() - up0; d <= 0 {
		t.Errorf("bytes{up} did not move for an upload (%v)", d)
	}

	// And now the session is spent: the next request is refused on the
	// session itself, before any policy check, and counted as such.
	denied0, quota0 = denied(), reason(hubmetrics.EgressQuotaExhausted)
	resp, err = f.client(t, nil).Get(origin.URL + "/after")
	if err != nil {
		t.Fatalf("GET after the budget: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("GET on a spent session = %d, want 407", resp.StatusCode)
	}
	if d := settled(denied, denied0, 1); d != 1 {
		t.Errorf("a spent session's request moved requests{denied} by %v, want 1", d)
	}
	if d := settled(quota, quota0, 1); d != 1 {
		t.Errorf("denials{quota_exhausted} rose by %v for a spent session, want 1", d)
	}

	// A credential that does not authenticate is not a verdict.
	allowed0, denied0 = allowed(), denied()
	stranger, err := url.Parse("http://sess_nope:nope@" + f.proxy.Addr())
	if err != nil {
		t.Fatal(err)
	}
	raw := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(stranger), DisableKeepAlives: true},
		Timeout: 5 * time.Second}
	if resp, err := raw.Get(origin.URL); err != nil {
		t.Fatalf("GET with a stranger's credential: %v", err)
	} else {
		resp.Body.Close()
		if resp.StatusCode != http.StatusProxyAuthRequired {
			t.Fatalf("a stranger's credential = %d, want 407", resp.StatusCode)
		}
	}
	if allowed() != allowed0 || denied() != denied0 {
		t.Errorf("an unauthenticated request moved the request counters (allowed %v→%v, denied %v→%v)",
			allowed0, allowed(), denied0, denied())
	}

	// Closing the session takes it off the gauge, once.
	live1 := live()
	f.broker.CloseSession(f.red.Session.ID, "test finished")
	f.broker.CloseSession(f.red.Session.ID, "test finished")
	if d := live1 - live(); d != 1 {
		t.Errorf("closing the session twice moved cloop_egress_sessions_live by %v, want 1", d)
	}
}

// TestHubMetricsCountRefusedRedemptions: a session the broker will not issue
// is a refusal, counted by the reason the grant was unusable rather than by
// the ErrNoGrant every refused redemption ends in.
func TestHubMetricsCountRefusedRedemptions(t *testing.T) {
	now := time.Now().UTC()
	clock := func() time.Time { return now }
	b, err := New(NewMemStore(), WithClock(clock))
	if err != nil {
		t.Fatal(err)
	}
	sub, err := secretbroker.ParseSubject("project:/srv/redeem")
	if err != nil {
		t.Fatal(err)
	}
	req := RedeemRequest{Requester: secretbroker.Requester{ProjectID: "/srv/redeem"}, Actor: "test"}
	redeem := func() error {
		_, err := b.Redeem(context.Background(), req)
		return err
	}
	reason := func(r string) float64 { return scrapeValue(t, "cloop_egress_denials_total", "reason", r) }

	noGrant := reason(hubmetrics.EgressNoGrant)
	if err := redeem(); !errors.Is(err, ErrNoGrant) {
		t.Fatalf("redeem with no grant = %v", err)
	}
	if d := reason(hubmetrics.EgressNoGrant) - noGrant; d != 1 {
		t.Errorf("denials{no_grant} rose by %v, want 1", d)
	}

	g, err := b.Grant(context.Background(), GrantRequest{
		Subject: sub, Hosts: []string{"example.com"}, Ports: []int{443}, TTL: time.Hour, Actor: "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Revoke(context.Background(), g.ID, "test"); err != nil {
		t.Fatal(err)
	}
	revoked := reason(hubmetrics.EgressRevoked)
	if err := redeem(); !errors.Is(err, ErrNoGrant) {
		t.Fatalf("redeem against a revoked grant = %v", err)
	}
	if d := reason(hubmetrics.EgressRevoked) - revoked; d != 1 {
		t.Errorf("denials{revoked} rose by %v, want 1", d)
	}

	b2, err := New(NewMemStore(), WithClock(clock))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b2.Grant(context.Background(), GrantRequest{
		Subject: sub, Hosts: []string{"example.com"}, Ports: []int{443}, TTL: time.Minute, Actor: "test",
	}); err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Minute)
	expired := reason(hubmetrics.EgressExpired)
	if _, err := b2.Redeem(context.Background(), req); !errors.Is(err, ErrNoGrant) {
		t.Fatalf("redeem against an expired grant = %v", err)
	}
	if d := reason(hubmetrics.EgressExpired) - expired; d != 1 {
		t.Errorf("denials{expired} rose by %v for an expired grant, want 1", d)
	}
}
