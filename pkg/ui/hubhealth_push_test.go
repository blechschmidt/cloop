package ui

// What a Hub health report costs and who hears it (Task 20446): each member
// makes its report on its own cadence and pushes the summary, so open
// dashboards cost the member nothing more; only a stream whose identity may
// read the report is sent the count, and one that stops being allowed to is
// told so; the identity provider is read from the hub's own sign-in client,
// and asked over the network at most once per interval for an issuer that
// client is not using.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/blechschmidt/cloop/pkg/authz"
	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/hubdoctor"
	"github.com/blechschmidt/cloop/pkg/oidcauth"
)

// healthSocket is one dashboard socket, recording every hub_health message it
// is sent and every frame's raw text.
type healthSocket struct {
	conn *websocket.Conn
	mu   sync.Mutex
	msgs []json.RawMessage
	raw  []string
}

// dialHealthSocket opens /api/ws as c (nil for an open hub) and reads it until
// the test ends.
func dialHealthSocket(t *testing.T, base string, c *http.Client) *healthSocket {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	opts := &websocket.DialOptions{}
	if c != nil {
		opts.HTTPClient = c
	}
	conn, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(base, "http")+"/api/ws", opts)
	if err != nil {
		cancel()
		t.Fatalf("dial /api/ws: %v", err)
	}
	conn.SetReadLimit(1 << 24)
	s := &healthSocket{conn: conn}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			_, data, err := conn.Read(ctx)
			if err != nil {
				return
			}
			var m wsMessage
			if json.Unmarshal(data, &m) != nil {
				continue
			}
			s.mu.Lock()
			s.raw = append(s.raw, string(data))
			if m.Type == "hub_health" {
				s.msgs = append(s.msgs, m.Data)
			}
			s.mu.Unlock()
		}
	}()
	t.Cleanup(func() {
		cancel()
		_ = conn.CloseNow()
		<-done
	})
	return s
}

// pushes returns the hub_health messages received so far, decoded.
func (s *healthSocket) pushes() []map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]map[string]any, 0, len(s.msgs))
	for _, m := range s.msgs {
		var v map[string]any
		_ = json.Unmarshal(m, &v)
		out = append(out, v)
	}
	return out
}

// frames returns every frame received so far.
func (s *healthSocket) frames() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.raw...)
}

// waitPushes waits up to 30 s for the socket to hold at least n pushes.
func (s *healthSocket) waitPushes(t *testing.T, n int, what string) []map[string]any {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		p := s.pushes()
		if len(p) >= n {
			return p
		}
		if time.Now().After(deadline) {
			t.Fatalf("waiting for %s: the socket holds %d hub_health message(s) %v", what, len(p), p)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// forceHubHealthRun makes a report now, as the schedule would.
func forceHubHealthRun(srv *Server, trigger string) *hubHealthReport {
	return srv.hubHealthRun(trigger, srv.hubConfigFingerprint(), false, func(time.Time) bool { return false })
}

// TestHubHealth_OpenSocketsCostOneReportPerCadence: six dashboards on one
// member — each asking once when its socket opens, as a page does — cost the
// member its first report and one per cadence, not one per dashboard; and
// every dashboard hears each report as it is made, with no request.
func TestHubHealth_OpenSocketsCostOneReportPerCadence(t *testing.T) {
	const cadence = time.Second
	var runs atomic.Int32
	srv, ts := hubHealthServer(t, func(s *Server) {
		s.hubHealth.interval = cadence
		s.hubHealth.extra = []hubdoctor.Check{{ID: "test.count", Title: "Counts the reports",
			Run: func(_ context.Context, add func(hubdoctor.Finding)) {
				runs.Add(1)
				add(hubdoctor.Finding{Check: "test.count", Title: "Counts the reports", Severity: hubdoctor.SeverityFail,
					Message: "always fails, so the summary has a count to carry", Remediation: "none"})
			}}}
	})
	ctx, cancel := context.WithCancel(context.Background())
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		srv.watchHubHealth(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		<-stopped
	})
	scheduleBefore := counterValue(t, srv.gatherMetrics(), "cloop_hub_health_reports_total", `trigger="schedule"`)

	const dashboards = 6
	sockets := make([]*healthSocket, dashboards)
	var reads []hubHealthReport
	start := time.Now()
	for i := range sockets {
		sockets[i] = dialHealthSocket(t, ts.URL, nil)
		code, rep, body := getHubHealth(t, nil, ts.URL, "?summary=1")
		if code != http.StatusOK {
			t.Fatalf("dashboard %d's read = %d: %s", i, code, body)
		}
		reads = append(reads, rep)
	}
	for _, r := range reads[1:] {
		if r.Generation < reads[0].Generation {
			t.Errorf("a later dashboard was answered with generation %d, after %d", r.Generation, reads[0].Generation)
		}
	}
	// Three more cadences.
	for _, s := range sockets {
		s.waitPushes(t, 3, "three reports' pushes")
	}
	elapsed := time.Since(start)
	n := int(runs.Load())
	if limit := 1 + int(elapsed/cadence) + 1; n > limit {
		t.Errorf("%d dashboards over %s cost %d reports, want at most %d: the first and one per %s cadence",
			dashboards, elapsed.Round(time.Millisecond), n, limit, cadence)
	}
	for i, s := range sockets {
		var last float64
		for _, p := range s.pushes() {
			g, ok := p["generation"].(float64)
			if !ok || g <= last {
				t.Errorf("dashboard %d heard generation %v after %v: %v", i, p["generation"], last, s.pushes())
			}
			last = g
			if f, ok := p["failing"].(float64); !ok || f < 1 {
				t.Errorf("dashboard %d heard a push without the failing count: %v", i, p)
			}
			for _, key := range []string{"checked_at", "served_at", "expires_at"} {
				if _, ok := p[key].(string); !ok {
					t.Errorf("dashboard %d's push has no %s: %v", i, key, p)
				}
			}
		}
	}
	if after := counterValue(t, srv.gatherMetrics(), "cloop_hub_health_reports_total", `trigger="schedule"`); after-scheduleBefore < 2 {
		t.Errorf("cloop_hub_health_reports_total{trigger=\"schedule\"} grew by %v over %d scheduled reports",
			after-scheduleBefore, n-1)
	}
}

// TestHubHealth_OnlyReadersHearTheCount: under an enforced role policy the
// administrator's socket is sent each report's count; a viewer's and an
// operator's are never sent one, nor anything else about the report. Once a
// runtime deny takes the administrator's config.write away, their socket is
// told so — carrying no count — and hears no further report; given back, it
// is sent the current summary again.
func TestHubHealth_OnlyReadersHearTheCount(t *testing.T) {
	idp := newUIFakeIdP(t)
	srv, ts := newOIDCTestServer(t, idp, "", nil)
	srv.Authz = runtimeDenyResolver(t, rbacPolicy())
	loginAs := func(groups []string) *http.Client {
		idp.groups = groups
		c := jarClient(t)
		login(t, c, ts)
		return c
	}
	viewerC, operatorC, adminC := loginAs([]string{"readers"}), loginAs([]string{"engineers"}), loginAs([]string{"owners"})
	viewer, operator, admin := dialHealthSocket(t, ts.URL, viewerC), dialHealthSocket(t, ts.URL, operatorC),
		dialHealthSocket(t, ts.URL, adminC)

	code, rep, body := getHubHealth(t, adminC, ts.URL, "?fresh=1")
	if code != http.StatusOK {
		t.Fatalf("admin GET /api/hub/health?fresh=1 = %d: %s", code, body)
	}
	p := admin.waitPushes(t, 1, "the administrator's push")
	if g, _ := p[0]["generation"].(float64); int(g) != int(rep.Generation) || p[0]["failing"] != float64(rep.Failing) {
		t.Errorf("the administrator heard %v, want generation %d with %d failing", p[0], rep.Generation, rep.Failing)
	}
	// The two other sockets were decided in the same pass; give a slow
	// runner time to deliver anything that was queued for them.
	time.Sleep(300 * time.Millisecond)
	for name, s := range map[string]*healthSocket{"viewer": viewer, "operator": operator} {
		if got := s.pushes(); len(got) != 0 {
			t.Errorf("the %s's socket heard %v", name, got)
		}
		for _, f := range s.frames() {
			if strings.Contains(f, `"hub_health"`) {
				t.Errorf("the %s's socket carries the report: %s", name, f)
			}
		}
	}

	// The administrator loses config.write. The member asks again — as its
	// half-minute look would, or a session change would at once.
	srv.Authz = runtimeDenyResolver(t, rbacPolicy(), authz.Binding{Claim: authz.ClaimGroup, Value: "owners", Deny: true})
	srv.recheckHubHealthAudience(nil)
	p = admin.waitPushes(t, 2, "the administrator's withdrawal")
	if len(p[1]) != 1 || p[1]["withdrawn"] != true {
		t.Errorf("the demoted administrator was sent %v, want only the withdrawal", p[1])
	}
	forceHubHealthRun(srv, hubHealthTriggerSchedule)
	srv.recheckHubHealthAudience(nil)
	time.Sleep(300 * time.Millisecond)
	if got := admin.pushes(); len(got) != 2 {
		t.Errorf("after the withdrawal the administrator's socket heard %v", got[2:])
	}
	for name, s := range map[string]*healthSocket{"viewer": viewer, "operator": operator} {
		if got := s.pushes(); len(got) != 0 {
			t.Errorf("the %s's socket heard %v", name, got)
		}
	}

	// Given back, the socket is sent where the report stands now.
	srv.Authz = runtimeDenyResolver(t, rbacPolicy())
	srv.recheckHubHealthAudience(nil)
	p = admin.waitPushes(t, 3, "the summary once config.write is back")
	srv.hubHealth.mu.Lock()
	latest := srv.hubHealth.report.Generation
	srv.hubHealth.mu.Unlock()
	if g, _ := p[2]["generation"].(float64); uint64(g) != latest || p[2]["failing"] == nil {
		t.Errorf("the administrator was sent %v once readmitted, want generation %d's summary", p[2], latest)
	}
}

// writeOIDCHubConfig gives the hub's configuration a ui.oidc block for issuer.
func writeOIDCHubConfig(t *testing.T, srv *Server, issuer, redirect string) {
	t.Helper()
	writeHubConfig(t, config.ConfigPath(srv.WorkDir), fmt.Sprintf(
		"ui:\n  oidc:\n    enabled: true\n    issuer: %s\n    client_id: cloop-dashboard\n    redirect_url: %s\n",
		issuer, redirect))
}

// idpRequests is how many times idp served each metadata document.
func idpRequests(idp *uiFakeIdP) (discovery, jwks int) {
	idp.mu.Lock()
	defer idp.mu.Unlock()
	return idp.discoveryRequests, idp.jwksRequests
}

// TestHubHealth_IssuerReadFromTheSignInClient: for the issuer the hub signs in
// with, a report reads what the sign-in client holds — the document it
// resolved and the keys it fetched — and asks the identity provider nothing,
// however many reports are made.
func TestHubHealth_IssuerReadFromTheSignInClient(t *testing.T) {
	idp := newUIFakeIdP(t)
	srv, ts := newOIDCTestServer(t, idp, "", nil)
	writeOIDCHubConfig(t, srv, idp.server.URL, ts.URL+"/auth/callback")
	login(t, jarClient(t), ts)
	disc0, jwks0 := idpRequests(idp)
	if disc0 == 0 || jwks0 == 0 {
		t.Fatalf("precondition: signing in fetched %d discovery and %d key-set document(s)", disc0, jwks0)
	}

	var rep *hubHealthReport
	for i := 0; i < 4; i++ {
		rep = forceHubHealthRun(srv, hubHealthTriggerSchedule)
	}
	if disc, jwks := idpRequests(idp); disc != disc0 || jwks != jwks0 {
		t.Errorf("four reports asked the identity provider %d more discovery and %d more key-set fetch(es)",
			disc-disc0, jwks-jwks0)
	}
	got := findingsByCheck(*rep)
	if d := got["oidc.discovery"]; len(d) != 1 || d[0].Severity != "pass" || !strings.Contains(d[0].Message, "sign-in client") {
		t.Errorf("oidc.discovery = %+v, want a pass read from the sign-in client", d)
	}
	if k := got["oidc.jwks"]; len(k) != 1 || k[0].Severity != "pass" || !strings.Contains(k[0].Message, "1 usable signing key(s)") {
		t.Errorf("oidc.jwks = %+v, want the one key the client holds", k)
	}
	if len(got["oidc.running"]) != 0 {
		t.Errorf("oidc.running = %+v for the issuer the hub signs in with", got["oidc.running"])
	}
}

// TestHubHealth_PreflightAtMostOncePerInterval: for an issuer the running
// sign-in client is not using — the configuration changed since the hub
// started — a report resolves it over the network, and the reports after it
// reuse that resolution for the interval rather than asking again; a change
// of the configuration asks once more.
func TestHubHealth_PreflightAtMostOncePerInterval(t *testing.T) {
	running, configured := newUIFakeIdP(t), newUIFakeIdP(t)
	srv, ts := newOIDCTestServer(t, running, "", nil)
	writeOIDCHubConfig(t, srv, configured.server.URL, ts.URL+"/auth/callback")
	fetchesBefore := counterValue(t, srv.gatherMetrics(), "cloop_oidc_idp_fetches_total",
		`document="discovery",client="preflight",outcome="ok"`)

	var reps []*hubHealthReport
	for i := 0; i < 4; i++ {
		reps = append(reps, forceHubHealthRun(srv, hubHealthTriggerSchedule))
	}
	if disc, jwks := idpRequests(configured); disc != 1 || jwks != 1 {
		t.Errorf("four reports fetched the configured issuer's documents %d and %d time(s), want once each", disc, jwks)
	}
	if disc, jwks := idpRequests(running); disc != 0 || jwks != 0 {
		t.Errorf("the reports asked the running client's issuer for %d and %d document(s)", disc, jwks)
	}
	outcomes := func(rep *hubHealthReport) hubdoctor.StepOutcome {
		for _, s := range rep.Steps {
			if s.ID == "oidc.preflight" {
				return s.Outcome
			}
		}
		return ""
	}
	if o := outcomes(reps[0]); o != hubdoctor.StepFinished {
		t.Errorf("the first report's oidc.preflight ended %q", o)
	}
	for i, rep := range reps[1:] {
		if o := outcomes(rep); o != hubdoctor.StepReused {
			t.Errorf("report %d's oidc.preflight ended %q, want reused", i+2, o)
		}
		got := findingsByCheck(*rep)
		if d := got["oidc.discovery"]; len(d) != 1 || d[0].Severity != "pass" || d[0].AsOf.IsZero() {
			t.Errorf("report %d's oidc.discovery = %+v, want the reused resolution with its time", i+2, d)
		}
		if r := got["oidc.running"]; len(r) != 1 || r[0].Severity != "warn" ||
			!strings.Contains(r[0].Message, configured.server.URL) {
			t.Errorf("report %d's oidc.running = %+v, want a warning naming the configured issuer", i+2, r)
		}
	}
	if after := counterValue(t, srv.gatherMetrics(), "cloop_oidc_idp_fetches_total",
		`document="discovery",client="preflight",outcome="ok"`); after-fetchesBefore < 1 {
		t.Errorf("cloop_oidc_idp_fetches_total for the preflight grew by %v", after-fetchesBefore)
	}

	// A new configuration is a new interval.
	time.Sleep(10 * time.Millisecond)
	writeOIDCHubConfig(t, srv, configured.server.URL+"/", ts.URL+"/auth/callback")
	forceHubHealthRun(srv, hubHealthTriggerConfig)
	forceHubHealthRun(srv, hubHealthTriggerSchedule)
	if disc, jwks := idpRequests(configured); disc != 2 || jwks != 2 {
		t.Errorf("after a configuration change the documents were fetched %d and %d time(s) in all, want twice each",
			disc, jwks)
	}
}

// TestHubHealth_EventsMakeOneReportSoon: a burst of executor events is one
// report, made after the burst settles and no sooner than the spacing after
// the last report allows; with nothing else pending the next is the cadence's.
func TestHubHealth_EventsMakeOneReportSoon(t *testing.T) {
	srv, ts := hubHealthServer(t, nil)
	_, first, _ := getHubHealth(t, nil, ts.URL, "")
	started := time.Now().Add(-hubHealthFirstRun)
	srv.hubHealthLook()
	srv.hubHealthLook()

	for i := 0; i < 20; i++ {
		srv.broadcastExecutorUpdate("status:online", fmt.Sprintf("burst-%d", i))
	}
	srv.hubHealth.mu.Lock()
	eventAt := srv.hubHealth.eventAt
	srv.hubHealth.mu.Unlock()
	if eventAt.IsZero() {
		t.Fatal("an executor update did not reach the schedule")
	}
	next := srv.hubHealthTick(started)
	want := first.CheckedAt.Add(hubHealthEventSpacing)
	if w := eventAt.Add(hubHealthEventDelay); w.After(want) {
		want = w
	}
	if !next.Equal(want) {
		t.Errorf("after the burst the next report is due at %s, want %s: the later of the event's delay and the spacing",
			next, want)
	}
	srv.hubHealth.mu.Lock()
	gen := srv.hubHealth.generation
	srv.hubHealth.mu.Unlock()
	if gen != first.Generation {
		t.Errorf("the burst made %d report(s) at once", gen-first.Generation)
	}

	// Once the spacing has passed, the tick makes one report for the burst.
	srv.hubHealth.mu.Lock()
	srv.hubHealth.madeAt = srv.hubHealth.madeAt.Add(-2 * hubHealthEventSpacing)
	srv.hubHealth.eventAt = srv.hubHealth.eventAt.Add(-2 * hubHealthEventDelay)
	srv.hubHealth.mu.Unlock()
	next = srv.hubHealthTick(started)
	srv.hubHealth.mu.Lock()
	gen, pending, rep := srv.hubHealth.generation, srv.hubHealth.eventAt, srv.hubHealth.report
	srv.hubHealth.mu.Unlock()
	if gen != first.Generation+1 || !pending.IsZero() {
		t.Errorf("past the spacing the tick made %d report(s), the event still pending: %v", gen-first.Generation, !pending.IsZero())
	}
	if !next.Equal(rep.ExpiresAt) {
		t.Errorf("with the burst reported the next report is due at %s, want the cadence's %s", next, rep.ExpiresAt)
	}
}

// TestHubHealth_ReadAfterAChangeIsNotReportedTwice: a read that arrives after
// a configuration change, before the member's looks have settled on it, makes
// the report of the files as they are; the schedule then has nothing to do,
// rather than reporting the change a second time under the configuration its
// looks last agreed on.
func TestHubHealth_ReadAfterAChangeIsNotReportedTwice(t *testing.T) {
	srv, ts := hubHealthServer(t, nil)
	started := time.Now().Add(-hubHealthFirstRun)
	_, first, _ := getHubHealth(t, nil, ts.URL, "?summary=1")
	srv.hubHealthLook()
	srv.hubHealthLook()

	time.Sleep(10 * time.Millisecond)
	writeHubConfig(t, config.ConfigPath(srv.WorkDir), "executors:\n  allow_host_process: false\n")
	_, changed, _ := getHubHealth(t, nil, ts.URL, "?summary=1")
	if changed.Generation != first.Generation+1 || !changed.StrictMode {
		t.Fatalf("the read after the change was answered with generation %d (strict %v), want a new report of it",
			changed.Generation, changed.StrictMode)
	}
	for i := 0; i < 3; i++ {
		srv.hubHealthLook()
		if next := srv.hubHealthTick(started); !next.Equal(changed.ExpiresAt) {
			t.Errorf("look %d: the next report is due at %s, want the cadence's %s", i+1, next, changed.ExpiresAt)
		}
	}
	srv.hubHealth.mu.Lock()
	gen, print := srv.hubHealth.generation, srv.hubHealth.print
	srv.hubHealth.mu.Unlock()
	if gen != changed.Generation || print != srv.hubConfigFingerprint() {
		t.Errorf("the schedule made %d more report(s), the last labelled %q for files now %q",
			gen-changed.Generation, print, srv.hubConfigFingerprint())
	}
}

// TestHubHealth_SSEStreamsHearIt: a page that fell back to the event stream
// is pushed the summary as a named hub_health event, as a socket would be,
// and only once per report.
func TestHubHealth_SSEStreamsHearIt(t *testing.T) {
	srv, _ := hubHealthServer(t, nil)
	c := &sseClient{ch: make(chan sseEvent, 8), resync: make(chan struct{}, 1), workDir: srv.WorkDir,
		kick: make(chan streamEnd, 1)}
	srv.mu.Lock()
	srv.clients[c] = struct{}{}
	srv.mu.Unlock()
	t.Cleanup(func() {
		srv.mu.Lock()
		delete(srv.clients, c)
		srv.mu.Unlock()
	})

	rep := forceHubHealthRun(srv, hubHealthTriggerSchedule)
	srv.recheckHubHealthAudience(nil)
	srv.deliverHubHealth(true, nil) // a late push of the same report
	var got []sseEvent
	for len(got) < 2 {
		select {
		case ev := <-c.ch:
			got = append(got, ev)
			continue
		default:
		}
		break
	}
	if len(got) != 1 || got[0].Event != "hub_health" {
		t.Fatalf("the event stream was sent %+v, want one hub_health event", got)
	}
	var p hubHealthPush
	if err := json.Unmarshal([]byte(got[0].Data), &p); err != nil || p.Generation != rep.Generation ||
		p.Failing != rep.Failing || p.Member.ID != rep.Member.ID || p.Member.ID == "" {
		t.Errorf("the event carries %s, want member %q's generation %d with %d failing", got[0].Data, rep.Member.ID,
			rep.Generation, rep.Failing)
	}
}

// TestHubHealth_EventDuringARunStaysPending: an event that arrives while a
// report is being made may not be in it — the executor check may already have
// read the fleet — so it still makes the next report soon, rather than waiting
// out the cadence; one that arrived before the run began is in it.
func TestHubHealth_EventDuringARunStaysPending(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	var hold atomic.Bool
	srv, _ := hubHealthServer(t, func(s *Server) {
		s.hubHealth.extra = []hubdoctor.Check{{ID: "test.hold", Title: "Holds the run open",
			Run: func(context.Context, func(hubdoctor.Finding)) {
				if hold.Load() {
					close(started)
					<-release
				}
			}}}
	})
	forceHubHealthRun(srv, hubHealthTriggerRequest)

	// Before a run: in it.
	srv.hubHealthEvent()
	forceHubHealthRun(srv, hubHealthTriggerEvent)
	srv.hubHealth.mu.Lock()
	pending := !srv.hubHealth.eventAt.IsZero()
	srv.hubHealth.mu.Unlock()
	if pending {
		t.Fatal("an event that arrived before the run began is still pending after it")
	}

	// During a run: still pending after it, and due soon.
	hold.Store(true)
	done := make(chan struct{})
	go func() {
		defer close(done)
		forceHubHealthRun(srv, hubHealthTriggerSchedule)
	}()
	<-started
	srv.hubHealthEvent()
	close(release)
	<-done
	srv.hubHealth.mu.Lock()
	eventAt, madeAt, dueAt := srv.hubHealth.eventAt, srv.hubHealth.madeAt, srv.hubHealth.dueAt
	due, why := srv.hubHealth.dueLocked(srv.hubHealth.print, time.Now())
	srv.hubHealth.mu.Unlock()
	if eventAt.IsZero() || !eventAt.After(madeAt) {
		t.Fatalf("an event that arrived during the run is not pending after it (event %s, run began %s)", eventAt, madeAt)
	}
	if why != hubHealthTriggerEvent || !due.Before(dueAt) {
		t.Errorf("the next report is due at %s for %q, want the event's report before the cadence's %s", due, why, dueAt)
	}
}

// TestHubHealth_DemotedBeforeTheFirstPushIsWithdrawn: a socket whose identity
// may read the report is counted as told from the moment it opens — its page
// reads the summary itself then — so a demotion before any report is pushed
// still withdraws the count that read put in its header.
func TestHubHealth_DemotedBeforeTheFirstPushIsWithdrawn(t *testing.T) {
	idp := newUIFakeIdP(t)
	srv, ts := newOIDCTestServer(t, idp, "", nil)
	srv.Authz = runtimeDenyResolver(t, rbacPolicy())
	idp.groups = []string{"owners"}
	adminC := jarClient(t)
	login(t, adminC, ts)
	idp.groups = []string{"readers"}
	viewerC := jarClient(t)
	login(t, viewerC, ts)
	// The report exists before the page opens, so the page's read is answered
	// from it and nothing is pushed.
	first := forceHubHealthRun(srv, hubHealthTriggerSchedule)
	admin, viewer := dialHealthSocket(t, ts.URL, adminC), dialHealthSocket(t, ts.URL, viewerC)
	code, read, body := getHubHealth(t, adminC, ts.URL, "?summary=1")
	if code != http.StatusOK || read.Generation != first.Generation {
		t.Fatalf("the administrator's read = %d (generation %d, want %d): %s", code, read.Generation, first.Generation, body)
	}
	time.Sleep(200 * time.Millisecond)
	if got := admin.pushes(); len(got) != 0 {
		t.Fatalf("a read answered from the last report pushed %v", got)
	}

	srv.Authz = runtimeDenyResolver(t, rbacPolicy(), authz.Binding{Claim: authz.ClaimGroup, Value: "owners", Deny: true})
	srv.recheckHubHealthAudience(nil)
	p := admin.waitPushes(t, 1, "the withdrawal")
	if p[0]["withdrawn"] != true || p[0]["failing"] != nil {
		t.Errorf("the demoted administrator was sent %v, want the withdrawal", p[0])
	}
	time.Sleep(200 * time.Millisecond)
	if got := viewer.pushes(); len(got) != 0 {
		t.Errorf("the viewer, never told, was sent %v", got)
	}
}

// TestHubHealth_UnresolvedIssuerIsRetriedBoundedly: while the hub's sign-in
// client holds no resolution of the issuer the report reads from it, a report
// asks the client to resolve it again — at most every 15 minutes on the
// schedule, every minute on Run the checks again — and never once it holds
// one.
func TestHubHealth_UnresolvedIssuerIsRetriedBoundedly(t *testing.T) {
	idp := newUIFakeIdP(t)
	srv, ts := newOIDCTestServer(t, idp, "", nil)
	writeOIDCHubConfig(t, srv, idp.server.URL, ts.URL+"/auth/callback")
	// Nobody has signed in: the client has resolved nothing.
	rep := forceHubHealthRun(srv, hubHealthTriggerSchedule)
	if disc, jwks := idpRequests(idp); disc != 1 || jwks != 1 {
		t.Fatalf("the first report asked the unresolved client to resolve %d/%d time(s), want once", disc, jwks)
	}
	if d := findingsByCheck(*rep)["oidc.discovery"]; len(d) != 1 || d[0].Severity != "pass" {
		t.Errorf("after the retry oidc.discovery = %+v, want the resolution it made", d)
	}
	for i := 0; i < 3; i++ {
		forceHubHealthRun(srv, hubHealthTriggerSchedule)
		srv.hubHealthRun(hubHealthTriggerRerun, srv.hubConfigFingerprint(), true, func(time.Time) bool { return false })
	}
	if disc, jwks := idpRequests(idp); disc != 1 || jwks != 1 {
		t.Errorf("reports of a resolved client asked the issuer %d/%d time(s) in all, want the one retry", disc, jwks)
	}
}

// TestHubHealth_FailingIssuerIsRetriedAtMostEveryInterval: a sign-in client
// whose issuer does not answer is asked again by a report at most every 15
// minutes, and by Run the checks again at most every minute.
func TestHubHealth_FailingIssuerIsRetriedAtMostEveryInterval(t *testing.T) {
	var asked atomic.Int32
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		asked.Add(1)
		http.Error(w, "down", http.StatusServiceUnavailable)
	}))
	t.Cleanup(down.Close)
	srv, ts := hubHealthServer(t, nil)
	auth, err := oidcauth.New(oidcauth.Config{Enabled: true, Issuer: down.URL, ClientID: "cloop-dashboard",
		ClientSecret: "s", RedirectURL: ts.URL + "/auth/callback"})
	if err != nil {
		t.Fatal(err)
	}
	srv.OIDC = auth
	writeOIDCHubConfig(t, srv, down.URL, ts.URL+"/auth/callback")
	rerun := func() *hubHealthReport {
		return srv.hubHealthRun(hubHealthTriggerRerun, srv.hubConfigFingerprint(), true, func(time.Time) bool { return false })
	}

	rep := forceHubHealthRun(srv, hubHealthTriggerSchedule)
	if n := asked.Load(); n != 1 {
		t.Fatalf("the first report asked the issuer %d time(s), want once", n)
	}
	if d := findingsByCheck(*rep)["oidc.discovery"]; len(d) != 1 || d[0].Severity != "fail" ||
		!strings.Contains(d[0].Message, "returned HTTP 503") {
		t.Errorf("oidc.discovery = %+v, want the failure the retry met", d)
	}
	forceHubHealthRun(srv, hubHealthTriggerSchedule)
	rerun()
	if n := asked.Load(); n != 1 {
		t.Errorf("a report and a rerun right after asked the issuer %d time(s) in all, want once", n)
	}
	// A minute on, a rerun asks again; a scheduled report still does not.
	srv.hubHealth.mu.Lock()
	srv.hubHealth.idpTriedAt = time.Now().Add(-2 * time.Minute)
	srv.hubHealth.mu.Unlock()
	forceHubHealthRun(srv, hubHealthTriggerSchedule)
	if n := asked.Load(); n != 1 {
		t.Errorf("a scheduled report two minutes after the last attempt asked again (%d)", n)
	}
	rerun()
	if n := asked.Load(); n != 2 {
		t.Errorf("a rerun two minutes after the last attempt asked the issuer %d time(s) in all, want twice", n)
	}
	// Fifteen minutes on, the schedule asks too.
	srv.hubHealth.mu.Lock()
	srv.hubHealth.idpTriedAt = time.Now().Add(-16 * time.Minute)
	srv.hubHealth.mu.Unlock()
	forceHubHealthRun(srv, hubHealthTriggerSchedule)
	if n := asked.Load(); n != 3 {
		t.Errorf("a scheduled report sixteen minutes after the last attempt left the count at %d, want 3", n)
	}
}
