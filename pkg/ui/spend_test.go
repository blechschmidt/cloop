package ui

// The hub's half of Task 20264: booking spend against the identity that
// incurred it, and refusing the next task once a daily budget is gone.
//
// Before this, quota.Enforcer.CheckSpend gated every run start against a
// counter nothing ever incremented. The tests here are written to fail if that
// regresses — each one would pass trivially against the old code only if the
// budget were never enforced, so they assert the refusal, not merely the API
// shape.

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/authz"
	"github.com/blechschmidt/cloop/pkg/cost"
	"github.com/blechschmidt/cloop/pkg/quota"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// spendFixture is a hub with quotas installed, a control plane, and one
// project whose ledger the test writes into as a run would.
type spendFixture struct {
	srv      *Server
	enforcer *quota.Enforcer
	project  string
}

// newSpendFixture wires the pieces the drain needs: a control-plane database
// for the cursor, a project database for the ledger, and an enforcer with the
// supplied daily limits.
func newSpendFixture(t *testing.T, limits quota.Limits) *spendFixture {
	t.Helper()

	control := t.TempDir()
	seedMigratedDB(t, control)
	useControlPlaneDir(t, control)
	if _, err := state.Init(control, "control plane", 1); err != nil {
		t.Fatalf("init control plane: %v", err)
	}

	project := t.TempDir()
	seedMigratedDB(t, project)
	if _, err := state.Init(project, "billed project", 1); err != nil {
		t.Fatalf("init project: %v", err)
	}

	srv := &Server{WorkDir: control}
	e := installQuotas(t, srv, quota.Config{Defaults: limits})

	return &spendFixture{srv: srv, enforcer: e, project: project}
}

// finishTask appends one cost row, exactly as the orchestrator does when a
// task completes. identity is what the *run* claims — which the hub must not
// trust for billing.
func (f *spendFixture) finishTask(t *testing.T, identity string, tokens int, usd float64) {
	t.Helper()
	db, err := statedb.Open(filepath.Join(f.project, ".cloop", "state.db"))
	if err != nil {
		t.Fatalf("open project db: %v", err)
	}
	defer func() { _ = db.Close() }()
	if err := db.AppendCost(statedb.CostEntry{
		Timestamp: time.Now().UTC(), TaskID: 1, TaskTitle: "work",
		Provider: "anthropic", Model: "claude",
		InputTokens: tokens, EstimatedUSD: usd, Identity: identity,
	}); err != nil {
		t.Fatalf("append cost: %v", err)
	}
}

func subjectFor(identity string) *authz.Subject { return quota.SubjectForIdentity(identity) }

// ── the gap the task names ──────────────────────────────────────────────────

// TestSecondTaskIsRefusedOnceTheDailyBudgetIsExhausted is the test the whole
// task exists for.
//
// The premise it guards: with nothing calling Spend, CheckSpend consulted a
// permanently-zero counter and a daily budget could never be exceeded. Here the
// first task's real cost is booked through the drain, and the second is
// refused because of it.
func TestSecondTaskIsRefusedOnceTheDailyBudgetIsExhausted(t *testing.T) {
	f := newSpendFixture(t, quota.Limits{quota.ResDailyTokens: 1000})
	const alice = "alice@example.com"

	// The run starts with headroom.
	if err := f.enforcer.CheckSpend(subjectFor(alice)); err != nil {
		t.Fatalf("a fresh identity was refused before spending anything: %v", err)
	}
	f.srv.openSpendCursor(f.project, alice)

	// Task one burns the whole budget.
	f.finishTask(t, alice, 1000, 2.50)

	identity, denial := f.srv.drainSpend(f.project)
	if identity != alice {
		t.Fatalf("drain billed %q, want %q", identity, alice)
	}
	if denial == nil {
		t.Fatal("the budget was fully spent and the drain reported headroom — " +
			"this is the bug the task describes: spend is never booked")
	}

	// And the refusal is what the run-start gate would now see.
	if err := f.enforcer.CheckSpend(subjectFor(alice)); err == nil {
		t.Fatal("CheckSpend still admits after the daily token budget was spent")
	}
	d, ok := denial.(*quota.Denial)
	if !ok {
		t.Fatalf("denial is %T, want *quota.Denial so the HTTP layer can render it", denial)
	}
	if d.Resource != quota.ResDailyTokens {
		t.Errorf("denial names %q, want %q", d.Resource, quota.ResDailyTokens)
	}
	if !d.Transient() {
		t.Error("a daily budget denial clears at UTC midnight, so it must carry a Retry-After")
	}
}

// TestSpendAccumulatesPerIdentity: two tenants' spend must not pool. A shared
// counter would refuse whichever of them ran second.
func TestSpendAccumulatesPerIdentity(t *testing.T) {
	f := newSpendFixture(t, quota.Limits{quota.ResDailyTokens: 1000})
	const alice, bob = "alice@example.com", "bob@example.com"

	// Alice runs first and spends her whole budget.
	f.srv.openSpendCursor(f.project, alice)
	f.finishTask(t, alice, 1000, 1.00)
	if _, denial := f.srv.drainSpend(f.project); denial == nil {
		t.Fatal("alice spent her whole budget and was not refused")
	}

	// Bob then runs in the same project. A new dispatch re-stamps the cursor,
	// so his tasks bill him.
	f.srv.openSpendCursor(f.project, bob)
	f.finishTask(t, bob, 100, 0.10)
	identity, denial := f.srv.drainSpend(f.project)
	if identity != bob {
		t.Fatalf("after bob's dispatch the drain billed %q", identity)
	}
	if denial != nil {
		t.Fatalf("bob was refused on his first task: %v — alice's spend pooled into his counter", denial)
	}

	if got := f.enforcer.Usage(alice)[quota.ResDailyTokens]; got != 1000 {
		t.Errorf("alice's counter = %v, want 1000", got)
	}
	if got := f.enforcer.Usage(bob)[quota.ResDailyTokens]; got != 100 {
		t.Errorf("bob's counter = %v, want 100", got)
	}
}

// ── the trust split ─────────────────────────────────────────────────────────

// TestBillingIgnoresTheIdentityWrittenInsideTheSandbox is the cross-tenant
// property.
//
// The cost row's identity column is written by the orchestrator, which runs
// inside the sandbox, into a database in the sandbox's own workspace. If the
// hub billed the name it finds there, any workload could exhaust a colleague's
// daily budget by writing their address into its own ledger — a denial of
// service needing nothing but a text editor. Billing follows the cursor the hub
// wrote at dispatch instead.
func TestBillingIgnoresTheIdentityWrittenInsideTheSandbox(t *testing.T) {
	f := newSpendFixture(t, quota.Limits{quota.ResDailyTokens: 1000})
	const attacker, victim = "mallory@example.com", "victim@example.com"

	// The hub dispatched this run for mallory.
	f.srv.openSpendCursor(f.project, attacker)

	// The workload writes its cost row claiming to be the victim.
	f.finishTask(t, victim, 900, 5.00)

	identity, _ := f.srv.drainSpend(f.project)
	if identity != attacker {
		t.Fatalf("the drain billed %q — a workload named its own payer", identity)
	}
	if got := f.enforcer.Usage(victim)[quota.ResDailyTokens]; got != 0 {
		t.Errorf("the victim's counter moved to %v; a workload drained a "+
			"colleague's budget by writing their address into its ledger", got)
	}
	if got := f.enforcer.Usage(attacker)[quota.ResDailyTokens]; got != 900 {
		t.Errorf("the dispatching identity's counter = %v, want 900", got)
	}
}

// ── durability ──────────────────────────────────────────────────────────────

// TestBillingSurvivesAHubRestart: the cursor is what makes a restart mid-run
// cost nothing. A fresh Server, with a fresh enforcer, must resume billing the
// same identity from the same position — charging neither twice nor not at all.
func TestBillingSurvivesAHubRestart(t *testing.T) {
	f := newSpendFixture(t, quota.Limits{quota.ResDailyTokens: 10000})
	const alice = "alice@example.com"

	f.srv.openSpendCursor(f.project, alice)
	f.finishTask(t, alice, 100, 1.00)
	if _, denial := f.srv.drainSpend(f.project); denial != nil {
		t.Fatalf("unexpected denial: %v", denial)
	}
	if got := f.enforcer.Usage(alice)[quota.ResDailyTokens]; got != 100 {
		t.Fatalf("pre-restart counter = %v, want 100", got)
	}

	// The hub restarts: new Server, new enforcer, same databases. The daily
	// counter would be reloaded from the quota store in production; here the
	// point is the *cursor*, so the fresh enforcer starts empty and must be
	// charged only for what arrived after the restart.
	restarted := &Server{WorkDir: f.srv.WorkDir}
	e2 := installQuotas(t, restarted, quota.Config{
		Defaults: quota.Limits{quota.ResDailyTokens: 10000},
	})

	// Nothing new has happened, so a drain must book nothing at all.
	identity, _ := restarted.drainSpend(f.project)
	if identity != alice {
		t.Fatalf("after restart the drain billed %q, want %q — the cursor lost its payer",
			identity, alice)
	}
	if got := e2.Usage(alice)[quota.ResDailyTokens]; got != 0 {
		t.Fatalf("a restart re-charged %v already-booked tokens", got)
	}

	// The next task bills normally.
	f.finishTask(t, alice, 250, 2.00)
	if _, denial := restarted.drainSpend(f.project); denial != nil {
		t.Fatalf("unexpected denial: %v", denial)
	}
	if got := e2.Usage(alice)[quota.ResDailyTokens]; got != 250 {
		t.Errorf("post-restart counter = %v, want exactly the 250 that arrived after it", got)
	}
}

// TestDrainWithoutACursorBillsNobody: a project this hub never dispatched for
// has no payer, and guessing one would charge somebody for work they did not
// ask for.
func TestDrainWithoutACursorBillsNobody(t *testing.T) {
	f := newSpendFixture(t, quota.Limits{quota.ResDailyTokens: 10})

	f.finishTask(t, "someone@example.com", 5000, 50.00)

	identity, denial := f.srv.drainSpend(f.project)
	if identity != "" || denial != nil {
		t.Fatalf("drain on a project with no cursor billed %q (denial %v)", identity, denial)
	}
	if got := f.enforcer.Usage("someone@example.com")[quota.ResDailyTokens]; got != 0 {
		t.Errorf("counter moved to %v without a dispatch to justify it", got)
	}
}

// ── identity resolution ─────────────────────────────────────────────────────

// TestRunIdentityFallsBackThroughOwnerToLocal covers the chain the task
// specifies. The property that matters is the last line: it never yields "",
// because an unattributable run is spend that vanishes from every report.
func TestRunIdentityFallsBackThroughOwnerToLocal(t *testing.T) {
	t.Parallel()

	srv := &Server{WorkDir: t.TempDir()}
	req := httptest.NewRequest(http.MethodPost, "/api/run", nil)

	// No OIDC, no registry entry: nobody authenticated and nobody owns it.
	if got := srv.runIdentity(req, srv.WorkDir); got != cost.IdentityLocal {
		t.Errorf("unauthenticated run on an unowned project = %q, want %q",
			got, cost.IdentityLocal)
	}
	if got := srv.runIdentity(req, ""); got == "" {
		t.Error("runIdentity returned the empty string; such a run's spend " +
			"would be attributable to nobody and absent from every report")
	}

	// A nil request must resolve, not panic: this runs on the dispatch path
	// and a crashed hub is far worse than a fallback attribution.
	if got := srv.runIdentity(nil, srv.WorkDir); got != cost.IdentityLocal {
		t.Errorf("runIdentity(nil) = %q, want %q", got, cost.IdentityLocal)
	}
}

// TestReseedingTheCursorSettlesTheOutgoingBillFirst is a regression test for a
// silent, unbounded billing escape.
//
// openSpendCursor jumps the cursor to the ledger's current end, so anything the
// previous run left unbooked was skipped forever. Three ordinary sequences
// reach that — a dispatch racing the previous run's final drain, a run whose
// output could not be streamed and so was never drained, and a hub restart with
// a container run still going — and each discards exactly the tail of a plan,
// which is where an overrun lands. Repeat it and a tenant spends without limit:
// one task per run, start the next one, never pay for either.
func TestReseedingTheCursorSettlesTheOutgoingBillFirst(t *testing.T) {
	f := newSpendFixture(t, quota.Limits{quota.ResDailyTokens: 100000})
	const alice, bob = "alice@example.com", "bob@example.com"

	// Alice's run finishes a task. Nothing drains it — this stands in for the
	// final drain that never ran, or ran too late.
	f.srv.openSpendCursor(f.project, alice)
	f.finishTask(t, alice, 900, 9.00)

	// Bob's dispatch reseeds the cursor. Alice's task must be settled first.
	f.srv.openSpendCursor(f.project, bob)

	if got := f.enforcer.Usage(alice)[quota.ResDailyTokens]; got != 900 {
		t.Fatalf("alice's counter = %v, want 900 — reseeding the cursor for the "+
			"next run discarded her unbooked spend", got)
	}

	// And bob is not charged for it.
	if got := f.enforcer.Usage(bob)[quota.ResDailyTokens]; got != 0 {
		t.Errorf("bob's counter = %v, want 0 — alice's spend was reattributed to him", got)
	}

	// Bob's own task bills bob, and alice is not charged twice.
	f.finishTask(t, bob, 50, 0.50)
	if _, denial := f.srv.drainSpend(f.project); denial != nil {
		t.Fatalf("unexpected denial: %v", denial)
	}
	if got := f.enforcer.Usage(bob)[quota.ResDailyTokens]; got != 50 {
		t.Errorf("bob's counter = %v, want 50", got)
	}
	if got := f.enforcer.Usage(alice)[quota.ResDailyTokens]; got != 900 {
		t.Errorf("alice's counter = %v, want 900 — she was billed twice", got)
	}
}

// TestDrainIsIdempotent: a second drain with nothing new must book nothing.
// The cursor is the only thing standing between the 30-second ticker and
// charging a tenant for the same task over and over.
func TestDrainIsIdempotent(t *testing.T) {
	f := newSpendFixture(t, quota.Limits{quota.ResDailyTokens: 100000})
	const alice = "alice@example.com"

	f.srv.openSpendCursor(f.project, alice)
	f.finishTask(t, alice, 300, 3.00)

	for i := 0; i < 5; i++ {
		if _, denial := f.srv.drainSpend(f.project); denial != nil {
			t.Fatalf("drain %d: unexpected denial: %v", i, denial)
		}
	}
	if got := f.enforcer.Usage(alice)[quota.ResDailyTokens]; got != 300 {
		t.Errorf("after five drains alice's counter = %v, want 300 — "+
			"the ticker re-charges every task it has already booked", got)
	}
}

// TestNegativeAmountsCannotCancelABatch: the numbers in a cost row are written
// inside the sandbox. Under-reporting is accepted by the threat model; a single
// negative row cancelling every honest row beside it is not, because it turns
// the budget off rather than merely loosening it.
func TestNegativeAmountsCannotCancelABatch(t *testing.T) {
	f := newSpendFixture(t, quota.Limits{quota.ResDailyTokens: 100000})
	const alice = "alice@example.com"

	f.srv.openSpendCursor(f.project, alice)
	f.finishTask(t, alice, 1000, 10.00)
	f.finishTask(t, alice, -1000000, -100000)

	if _, denial := f.srv.drainSpend(f.project); denial != nil {
		t.Fatalf("unexpected denial: %v", denial)
	}
	if got := f.enforcer.Usage(alice)[quota.ResDailyTokens]; got != 1000 {
		t.Errorf("alice's counter = %v, want the 1000 honestly reported — "+
			"a negative row cancelled the batch", got)
	}
	if got := f.enforcer.Usage(alice)[quota.ResDailyCostUSD]; got != 10 {
		t.Errorf("alice's usd counter = %v, want 10", got)
	}
}
