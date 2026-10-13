package approvalnotify

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/internal/statedbtest"
	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// engineRig is one engine over a real control-plane database, posting to a
// loopback receiver, on a clock the test moves.
type engineRig struct {
	t        *testing.T
	eng      *Engine
	dbPath   string
	mu       sync.Mutex
	now      time.Time
	snap     Snapshot
	hooks    []config.NotificationWebhook
	received []map[string]any
	status   atomic.Int32
	refuse   atomic.Value // an event the receiver answers 400
	outcomes map[string]int
}

func newEngineRig(t *testing.T) *engineRig {
	t.Helper()
	r := &engineRig{t: t, dbPath: statedbtest.Path(t), now: time.Date(2026, 10, 13, 9, 0, 0, 0, time.UTC),
		outcomes: map[string]int{}}
	r.status.Store(http.StatusOK)
	srv, ca := tlsReceiver(t, func(w http.ResponseWriter, req *http.Request) {
		code := int(r.status.Load())
		body, _ := io.ReadAll(req.Body)
		var m map[string]any
		_ = json.Unmarshal(body, &m)
		if refuse, _ := r.refuse.Load().(string); refuse != "" && m["event"] == refuse {
			code = http.StatusBadRequest
		}
		if code == http.StatusOK {
			r.mu.Lock()
			r.received = append(r.received, m)
			r.mu.Unlock()
		}
		w.WriteHeader(code)
	})
	r.hooks = []config.NotificationWebhook{{Name: "ops", Type: config.NotifyJSON, URL: srv.URL + "/hook",
		AllowAddresses: []string{"127.0.0.1"}, CAFile: ca}}
	r.snap = Snapshot{RequestsKnown: true, TokensKnown: true}
	r.eng = New(Options{
		OpenDB: func() (*statedb.DB, error) { return statedb.Open(r.dbPath) },
		Settings: func() (Settings, error) {
			r.mu.Lock()
			defer r.mu.Unlock()
			return Settings{Webhooks: append([]config.NotificationWebhook(nil), r.hooks...), Link: "https://hub.example.com/?approvals=1"}, nil
		},
		Snapshot: func(context.Context) (Snapshot, error) {
			r.mu.Lock()
			defer r.mu.Unlock()
			return r.snap, nil
		},
		Now: func() time.Time {
			r.mu.Lock()
			defer r.mu.Unlock()
			return r.now
		},
		Record: func(sink, event, outcome string) {
			r.mu.Lock()
			r.outcomes[event+"/"+outcome]++
			r.mu.Unlock()
		},
		Logf: t.Logf,
	})
	return r
}

func (r *engineRig) pass() {
	r.t.Helper()
	if err := r.eng.Pass(context.Background()); err != nil {
		r.t.Fatalf("pass: %v", err)
	}
}

func (r *engineRig) advance(d time.Duration) {
	r.mu.Lock()
	r.now = r.now.Add(d)
	r.mu.Unlock()
}

func (r *engineRig) setRequests(reqs ...secretbroker.AccessRequest) {
	r.mu.Lock()
	r.snap.Requests = reqs
	r.mu.Unlock()
}

// events returns the events received so far, in order.
func (r *engineRig) events() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []string
	for _, m := range r.received {
		ev, _ := m["event"].(string)
		out = append(out, ev)
	}
	return out
}

func eq(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestEngineTellsEachMomentOnce: filing, the reminder and the decision each
// reach the webhook exactly once however many passes run, in order.
func TestEngineTellsEachMomentOnce(t *testing.T) {
	r := newEngineRig(t)
	filed := request("req_1", secretbroker.RequestPending, r.now.Add(-time.Minute), r.now.Add(72*time.Hour), time.Time{})
	r.setRequests(filed)
	r.pass()
	r.pass()
	if got := r.events(); !eq(got, []string{"request.filed"}) {
		t.Fatalf("after two passes the webhook got %v, want one filing", got)
	}

	r.advance(61 * time.Hour) // eleven hours left
	r.pass()
	r.pass()
	if got := r.events(); !eq(got, []string{"request.filed", "request.reminder"}) {
		t.Fatalf("after the reminder time the webhook got %v", got)
	}

	approved := filed
	approved.State, approved.DecidedAt, approved.DecidedBy = secretbroker.RequestApproved, r.now, "lead@example.com"
	r.advance(time.Minute)
	r.setRequests(approved)
	r.pass()
	r.pass()
	if got := r.events(); !eq(got, []string{"request.filed", "request.reminder", "request.approved"}) {
		t.Fatalf("after the decision the webhook got %v", got)
	}
	r.mu.Lock()
	last := r.received[len(r.received)-1]
	r.mu.Unlock()
	req, _ := last["request"].(map[string]any)
	if req["decided_by"] != "lead@example.com" || last["link"] != "https://hub.example.com/?approvals=1" {
		t.Fatalf("the approval message = %v", last)
	}
}

// TestEngineRetriesThenDrops: a receiver that fails is retried after a
// backoff, holding the notices behind the failed one; one that refuses for
// good is dropped and counted, and the webhook moves on.
func TestEngineRetriesThenDrops(t *testing.T) {
	r := newEngineRig(t)
	r.status.Store(http.StatusServiceUnavailable)
	r.setRequests(request("req_1", secretbroker.RequestPending, r.now, r.now.Add(72*time.Hour), time.Time{}))
	r.pass()
	if got := r.events(); len(got) != 0 {
		t.Fatalf("a failing receiver recorded %v", got)
	}
	db, err := statedb.Open(r.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	cur, _, _ := db.ApprovalNotifyCursorFor("ops")
	_ = db.Close()
	if cur.Failures != 1 || cur.NextAttemptAt.IsZero() || cur.LastError == "" {
		t.Fatalf("the failure was not noted: %+v", cur)
	}

	// Before the backoff: no attempt, even with the receiver back.
	r.status.Store(http.StatusOK)
	r.pass()
	if got := r.events(); len(got) != 0 {
		t.Fatalf("a send was attempted inside the backoff: %v", got)
	}
	r.advance(time.Minute)
	r.pass()
	if got := r.events(); !eq(got, []string{"request.filed"}) {
		t.Fatalf("after the backoff the webhook got %v", got)
	}

	// A permanent refusal drops the notice, and the next one goes through.
	r.refuse.Store("request.denied")
	denied := request("req_1", secretbroker.RequestDenied, r.now.Add(-time.Hour), r.now.Add(70*time.Hour), r.now)
	r.setRequests(denied, request("req_2", secretbroker.RequestPending, r.now, r.now.Add(72*time.Hour), time.Time{}))
	r.pass()
	got := r.events()
	if len(got) != 2 || got[1] != "request.filed" {
		t.Fatalf("after a refused notice the webhook got %v, want the next filing", got)
	}
	r.mu.Lock()
	dropped := r.outcomes["request.denied/"+OutcomeDropped]
	r.mu.Unlock()
	if dropped != 1 {
		t.Fatalf("the refused notice was not counted as dropped: %v", r.outcomes)
	}
}

// TestEngineSkipsWhatWasSettledAndStartsNewWebhooksAtTheHead: a filing decided
// before it could be sent is not sent; a webhook added later hears what happens
// from then on, not the backlog.
func TestEngineSkipsWhatWasSettledAndStartsNewWebhooksAtTheHead(t *testing.T) {
	r := newEngineRig(t)
	r.status.Store(http.StatusServiceUnavailable)
	r.setRequests(request("req_1", secretbroker.RequestPending, r.now, r.now.Add(72*time.Hour), time.Time{}))
	r.pass() // recorded, not delivered
	r.status.Store(http.StatusOK)
	r.advance(time.Hour)
	r.setRequests(request("req_1", secretbroker.RequestWithdrawn, r.now.Add(-time.Hour), r.now.Add(71*time.Hour), r.now))
	r.pass()
	if got := r.events(); !eq(got, []string{"request.withdrawn"}) {
		t.Fatalf("the webhook got %v, want only the withdrawal — the filing was settled before it went out", got)
	}

	// A second webhook, added now: nothing old is replayed into it.
	r.mu.Lock()
	second := r.hooks[0]
	second.Name = "late"
	r.hooks = append(r.hooks, second)
	r.mu.Unlock()
	r.pass()
	if got := r.events(); len(got) != 1 {
		t.Fatalf("adding a webhook replayed the outbox: %v", got)
	}
	r.advance(time.Minute)
	r.setRequests(request("req_2", secretbroker.RequestPending, r.now, r.now.Add(72*time.Hour), time.Time{}))
	r.pass()
	if got := r.events(); !eq(got, []string{"request.withdrawn", "request.filed", "request.filed"}) {
		t.Fatalf("a new filing reached %v, want both webhooks", got)
	}
}

// TestEngineFirstPassDoesNotReplayHistory: decisions made before the notifier
// ever ran are not announced.
func TestEngineFirstPassDoesNotReplayHistory(t *testing.T) {
	r := newEngineRig(t)
	r.setRequests(request("req_old", secretbroker.RequestApproved, r.now.Add(-48*time.Hour), r.now.Add(24*time.Hour), r.now.Add(-time.Hour)))
	r.pass()
	if got := r.events(); len(got) != 0 {
		t.Fatalf("a decision older than the notifier was announced: %v", got)
	}
}

// TestEngineReportsNewNoticesOncePerPass: what a pass records for the first
// time is handed to OnRecorded in one call — the hub runs one expiry sweep for
// any number of lapses — and nothing already recorded is handed over again,
// by a later pass or by the engine of a new leader on the same database.
func TestEngineReportsNewNoticesOncePerPass(t *testing.T) {
	r := newEngineRig(t)
	var batches [][]string
	r.eng.opts.OnRecorded = func(ns []Notice) { batches = append(batches, keys(ns)) }
	// Lapsed within the scan's skew of the first pass, so it notices them.
	r.setRequests(
		request("req_lapsed_1", secretbroker.RequestPending, r.now.Add(-73*time.Hour), r.now.Add(-time.Minute), time.Time{}),
		request("req_lapsed_2", secretbroker.RequestExpired, r.now.Add(-73*time.Hour), r.now.Add(-time.Second), time.Time{}),
		request("req_open", secretbroker.RequestPending, r.now, r.now.Add(72*time.Hour), time.Time{}),
	)
	r.pass()
	r.pass()
	want := []string{"request.filed:req_open", "request.lapsed:req_lapsed_1", "request.lapsed:req_lapsed_2"}
	if len(batches) != 1 || !eq(batches[0], want) {
		t.Fatalf("OnRecorded got %v, want one call with %v", batches, want)
	}

	// A new leader's engine, with an empty cache, on the same outbox.
	next := New(r.eng.opts)
	if err := next.Pass(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(batches) != 1 {
		t.Fatalf("a new engine re-reported what was already recorded: %v", batches[1:])
	}
}

// TestEngineKeepsWhatStillWaitsAndForgetsWebhooksLate: the notice of a token
// still waiting outlives the outbox's retention, so no later leader announces
// it again; and a webhook the leading member does not configure keeps its
// cursor for a day — members under different overlays trade the lead without
// skipping what was recorded in between — and is forgotten after.
func TestEngineKeepsWhatStillWaitsAndForgetsWebhooksLate(t *testing.T) {
	r := newEngineRig(t)
	r.mu.Lock()
	r.snap.Waiting = []TokenInfo{{ID: "0123456789abcdef", Name: "old-ci", Roles: []string{"operator"}, CreatedBy: "ops@example.com"}}
	r.mu.Unlock()
	r.pass()
	if got := r.events(); !eq(got, []string{"token.waiting"}) {
		t.Fatalf("the webhook got %v, want the waiting token", got)
	}

	// Long past retention, each new leader prunes on its first pass, and
	// must neither drop the row nor announce the token again.
	r.advance(60 * 24 * time.Hour)
	var announced []Notice
	opts := r.eng.opts
	opts.OnRecorded = func(ns []Notice) { announced = append(announced, ns...) }
	// The leader after it finds the row the first one's prune kept.
	for i := 0; i < 2; i++ {
		if err := New(opts).Pass(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if len(announced) != 0 || len(r.events()) != 1 {
		t.Fatalf("a token still waiting was announced again after the prune: %v, webhook %v", announced, r.events())
	}

	cursor := func() bool {
		db, err := statedb.Open(r.dbPath)
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()
		_, ok, err := db.ApprovalNotifyCursorFor("ops")
		if err != nil {
			t.Fatal(err)
		}
		return ok
	}
	// A leader without the webhook: its cursor survives the first hours…
	r.mu.Lock()
	hooks := r.hooks
	r.hooks = nil
	r.mu.Unlock()
	r.advance(2 * time.Hour)
	if err := New(opts).Pass(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !cursor() {
		t.Fatal("the cursor of a webhook another member configures was forgotten at once")
	}
	// …and is gone a day on.
	r.advance(25 * time.Hour)
	if err := New(opts).Pass(context.Background()); err != nil {
		t.Fatal(err)
	}
	if cursor() {
		t.Fatal("the cursor of a webhook nobody configures any more was kept")
	}
	r.mu.Lock()
	r.hooks = hooks
	r.mu.Unlock()
}

// TestEngineReadsAWebhookURLFromTheEnvironment: url_env is read at every send
// from the hub's own environment — never from anything a hub role can write —
// and a variable that is not set fails the send, to be retried, without
// saying anything about a URL.
func TestEngineReadsAWebhookURLFromTheEnvironment(t *testing.T) {
	r := newEngineRig(t)
	env := map[string]string{}
	r.mu.Lock()
	url := r.hooks[0].URL
	r.hooks[0].URL, r.hooks[0].URLEnv = "", "CLOOP_NOTIFY_OPS"
	r.mu.Unlock()
	r.eng.opts.LookupEnv = func(name string) (string, bool) {
		r.mu.Lock()
		defer r.mu.Unlock()
		v, ok := env[name]
		return v, ok
	}
	r.setRequests(request("req_1", secretbroker.RequestPending, r.now, r.now.Add(72*time.Hour), time.Time{}))
	r.pass()
	if got := r.events(); len(got) != 0 {
		t.Fatalf("a webhook whose variable is unset was sent %v", got)
	}
	db, err := statedb.Open(r.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	cur, _, _ := db.ApprovalNotifyCursorFor("ops")
	_ = db.Close()
	if cur.Failures != 1 || !strings.Contains(cur.LastError, "CLOOP_NOTIFY_OPS is not set") {
		t.Fatalf("the unset variable was not noted as a failure to retry: %+v", cur)
	}

	r.mu.Lock()
	env["CLOOP_NOTIFY_OPS"] = url
	r.mu.Unlock()
	r.advance(time.Minute)
	r.pass()
	if got := r.events(); !eq(got, []string{"request.filed"}) {
		t.Fatalf("once the variable is set the webhook got %v", got)
	}
}
