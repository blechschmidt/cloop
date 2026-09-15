package ui

// Attributing AI spend to the identity that spent it, and making per-identity
// daily budgets actually bite (Task 20264).
//
// # The gap this closes
//
// quota.Enforcer has had Spend() and CheckSpend() since Task 20182, and
// RecordQuotaSpend has sat here as their only caller-shaped entry point. But
// nothing ever called it. CheckSpend therefore gated every run start against a
// counter that was permanently zero, which is to say it gated nothing: a daily
// token or dollar budget could be configured, displayed in the Quotas panel,
// and never once exceeded.
//
// # Why the hub has to be the accountant
//
// The numbers are produced by the orchestrator, which is not this process. The
// hub dispatches a whole `cloop run` to an executor — a host process, a
// container, an edge agent across the network — and that process writes one
// cost row per finished task into the *project's* state.db. The enforcer, and
// every quota counter, live here.
//
// So the hub reads what the run wrote and books it: drainSpend walks the cost
// rows it has not seen, charges them, and advances a durable cursor. The cursor
// is what makes this survive a restart mid-run — see migration 0036.
//
// # The trust split, which is the part worth getting right
//
// A cost row carries an identity, and enforcement deliberately ignores it.
//
// That column is written by the orchestrator, inside the sandbox, into a
// database in the sandbox's own workspace. If the hub charged the identity
// named in the row, a workload could empty a colleague's daily budget by
// writing their address into its own ledger — a cross-tenant denial of service
// requiring nothing but a text editor. So the row's identity is for reporting
// and forensics, and enforcement charges project_spend_cursor.identity, which
// only the hub writes and which it resolved from the authenticated request that
// asked for the run.
//
// What remains self-reported is the *amount*. A hostile workload can under-
// report its own tokens, and no accounting here can stop it — the provider
// call happens inside the sandbox. That is the correct division of labour:
// budgets are a cost control against honest overruns, and containment is the
// isolation model's job, not the ledger's. Both directions are stated plainly
// rather than left for a reader to assume the stronger one.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/cost"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/logger"
	"github.com/blechschmidt/cloop/pkg/multiui"
	"github.com/blechschmidt/cloop/pkg/quota"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// AuditSpendRefused is the audit event type for a run stopped because its
// paying identity exhausted a daily budget. Named rather than inlined so the
// Audit panel's filter and any SIEM rule key off one constant.
const AuditSpendRefused = auditaction.ActionQuotaSpendRefused

// spendDrainBatch bounds one drain. A hub that was down while a long plan ran
// comes back to a backlog; this keeps the catch-up read off the heap in one
// piece, and the caller loops until the ledger is exhausted.
const spendDrainBatch = 500

// ── who pays ────────────────────────────────────────────────────────────────

// runIdentity resolves who to bill for a run started by this request.
//
// The chain is ordered by how much the hub actually knows:
//
//  1. the authenticated caller, via the same quota subject admission already
//     used, so a run bills exactly the identity whose budget gated it. Using a
//     different derivation here would let the two disagree, and a gate that
//     checks one account and charges another is worse than no gate.
//  2. the project's registered owner, for a caller the hub cannot name — a
//     deployment-credential or static-token request against an owned project.
//     Somebody owns the tokens; the owner is the best-founded answer available.
//  3. cost.IdentityLocal, for a single-user install with no OIDC and no owner.
//     A positive "nobody was authenticated", not a guess.
//
// It never returns "": an unattributable run is one whose spend silently
// vanishes from every report, which is the failure this whole task exists to
// remove.
// A nil request is tolerated and resolves down the chain rather than
// panicking. This is a billing path reached from goroutines that outlive the
// request that started them, and crashing the hub is a strictly worse outcome
// than attributing one run to the project's owner.
func (s *Server) runIdentity(r *http.Request, workDir string) string {
	if r != nil {
		if subj := s.quotaSubject(r); subj != nil {
			if label := subj.Label(); label != "" && label != "anonymous" {
				return label
			}
		}
	}
	if workDir != "" {
		for _, e := range s.allProjectEntries() {
			if e.Path == workDir && strings.TrimSpace(e.Owner) != "" {
				return e.Owner
			}
		}
	}
	return cost.IdentityLocal
}

// ── the cursor ──────────────────────────────────────────────────────────────

// spendMu serialises drains. One drain per project at a time is what keeps the
// read-then-advance pair from interleaving with itself: two concurrent drains
// could both read the same unbooked rows before either advanced the cursor, and
// charge a tenant twice for one task.
//
// A single mutex rather than one per project because a drain is a handful of
// indexed reads and the contention is between a 30-second ticker and a run
// ending — not a hot path worth a map of locks.
var spendMu sync.Mutex

// openSpendCursor records who is paying for the run about to start, and seeds
// the booking position at the project ledger's current end.
//
// Seeding at MAX(id) rather than 0 is what stops a hub that has just adopted an
// existing project from charging today's tenant for its entire history. Called
// on the dispatch path; failures are logged and never block a run, because a
// run that cannot start is a worse outcome than spend that goes uncharged for
// one run.
func (s *Server) openSpendCursor(workDir, identity string) {
	if workDir == "" || identity == "" || s.quotas() == nil {
		return
	}

	// Settle the outgoing run's bill before moving the cursor to the new payer.
	//
	// This is load-bearing, not tidiness. Reseeding jumps last_cost_row_id to
	// the ledger's current end, so any row the previous run left unbooked is
	// skipped forever. Three ordinary sequences reach that: a dispatch racing
	// the previous run's final drain (the re-entrancy guard has already
	// reopened by the time the stream closes), a run whose output could not be
	// streamed and so never had a drain at all, and a hub restart, after which
	// nothing re-attaches a drain to a container or remote run that kept going
	// without it. In each case the previous tenant's tail spend — which is
	// exactly where an overrun lands — would vanish.
	//
	// Draining here does not make that spend timely, only certain: it is booked
	// at the next dispatch rather than when it happened. The refusal is
	// discarded because the run that incurred it is over; the counter it raised
	// is what admitSpend refuses the next start on.
	_, _ = s.drainSpend(workDir)

	spendMu.Lock()
	defer spendMu.Unlock()

	var startAt int64
	if pdb, err := statedb.Open(state.DBPath(workDir)); err == nil {
		startAt, _ = pdb.MaxCostRowID()
		_ = pdb.Close()
	}
	cdb, err := statedb.Open(state.DBPath(controlPlaneDir()))
	if err != nil {
		s.log().Warn(logger.EventAuthz, 0, "spend: open control plane",
			map[string]interface{}{"error": err.Error(), "project": workDir})
		return
	}
	defer func() { _ = cdb.Close() }()

	if err := cdb.OpenSpendCursor(workDir, identity, startAt); err != nil {
		s.log().Warn(logger.EventAuthz, 0, "spend: open cursor",
			map[string]interface{}{"error": err.Error(), "project": workDir})
	}
}

// drainSpend books every cost row this hub has not yet charged, and reports
// whether the paying identity has now exhausted a daily budget.
//
// Returns the identity charged and its refusal, if any. A nil error means
// either that there was headroom left or that there was nothing to check —
// callers must not read "no error" as "spend happened".
func (s *Server) drainSpend(workDir string) (identity string, denial error) {
	e := s.quotas()
	if e == nil || workDir == "" {
		return "", nil
	}

	spendMu.Lock()
	defer spendMu.Unlock()

	cdb, err := statedb.Open(state.DBPath(controlPlaneDir()))
	if err != nil {
		return "", nil
	}
	defer func() { _ = cdb.Close() }()

	cursor, ok, err := cdb.LoadSpendCursor(workDir)
	if err != nil || !ok || cursor.Identity == "" {
		// No dispatch has ever opened a cursor here, so this hub has nobody to
		// bill. Charging a guess would be worse than charging nothing.
		return "", nil
	}

	pdb, err := statedb.Open(state.DBPath(workDir))
	if err != nil {
		return cursor.Identity, nil
	}
	defer func() { _ = pdb.Close() }()

	at := cursor.LastCostRowID
	for {
		rows, err := pdb.ReadCostsAfterID(at, spendDrainBatch)
		if err != nil {
			// Logged rather than swallowed: a drain that silently stops
			// reading is indistinguishable, from every dashboard, from a
			// tenant who is simply not spending anything.
			s.log().Warn(logger.EventAuthz, 0, "spend: read ledger",
				map[string]interface{}{"error": err.Error(), "project": workDir})
			break
		}
		if len(rows) == 0 {
			break
		}
		var tokens, usd float64
		next := at
		for _, row := range rows {
			// Clamped per row, not per batch. These numbers are written inside
			// the sandbox, and a single row with a large negative value would
			// otherwise cancel out every honest row beside it — turning
			// under-reporting, which the threat model accepts, into a way to
			// zero the bill outright.
			tokens += nonNegative(float64(row.InputTokens)) +
				nonNegative(float64(row.OutputTokens)) +
				nonNegative(float64(row.ThinkingTokens))
			usd += nonNegative(row.EstimatedUSD)
			if row.RowID > next {
				next = row.RowID
			}
		}
		// Claim the batch first, book it second, and book only if the claim
		// won. See AdvanceSpendCursor: this is what stops the other hub sharing
		// this control plane from charging the same rows, and what bounds the
		// damage when the control plane is briefly unwritable.
		won, err := cdb.AdvanceSpendCursor(workDir, at, next)
		if err != nil {
			s.log().Warn(logger.EventAuthz, 0, "spend: advance cursor",
				map[string]interface{}{"error": err.Error(), "project": workDir})
			break
		}
		if !won {
			// Somebody else claimed these rows and is booking them. Stop
			// rather than re-read: their cursor is ahead of ours, and
			// continuing from a stale position would re-present rows they
			// have already charged.
			break
		}
		e.Spend(cursor.Identity, tokens, usd)
		at = next
		if len(rows) < spendDrainBatch {
			break
		}
	}

	return cursor.Identity, e.CheckSpendIdentity(cursor.Identity)
}

// nonNegative clamps a self-reported amount at zero.
func nonNegative(v float64) float64 {
	if v < 0 {
		return 0
	}
	return v
}

// ── enforcement ─────────────────────────────────────────────────────────────

// spendDrainInterval is how often a live run's spend is booked.
//
// It is a compromise between two costs. Draining more often charges a budget
// sooner, but every tick opens two SQLite handles; draining less often widens
// the window in which a tenant spends past a cap nobody has noticed. Tasks take
// minutes, so a task boundary is never missed by more than this, and thirty
// seconds keeps the overshoot to at most one task's worth of tokens.
const spendDrainInterval = 30 * time.Second

// startSpendDrain books a live run's spend on a ticker until the returned
// function is called. The returned stop is idempotent and safe to defer.
//
// A ticker rather than a hook on each log line: the interesting moment is a
// task *finishing*, which produces a cost row but not necessarily any output,
// and a run wedged inside one long provider call produces no lines at all.
func (s *Server) startSpendDrain(workDir string) (stop func()) {
	if s.quotas() == nil || workDir == "" {
		return func() {}
	}
	done := make(chan struct{})
	var once sync.Once

	go func() {
		defer recoverGoroutine("spend drain " + workDir)
		ticker := time.NewTicker(spendDrainInterval)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				s.enforceSpendBudget(workDir)
			}
		}
	}()

	return func() { once.Do(func() { close(done) }) }
}

// enforceSpendBudget drains a project's spend and stops the run if the paying
// identity has exhausted its daily budget.
//
// This is the half the task's premise was missing: CheckSpend gated run starts
// against a counter nothing incremented, so a tenant could start one run and
// spend without limit inside it forever. Draining between tasks turns a
// per-start gate into a real ceiling — the run is stopped at the first task
// boundary after the budget goes.
//
// The refusal is audited rather than swallowed. A run that just stops, with a
// budget as the only explanation and nothing in the trail, is indistinguishable
// from a crash to the person whose work it was.
func (s *Server) enforceSpendBudget(workDir string) {
	identity, denial := s.drainSpend(workDir)
	if denial == nil {
		return
	}
	d, ok := denial.(*quota.Denial)
	if !ok {
		return
	}

	// Refuse to act on a ceiling the hub cannot be sure of.
	//
	// The drain resolves limits from an identity string, and group- and
	// role-derived bindings need the claims that came with the request. The
	// enforcer remembers those per process, so after a restart — with a
	// container or remote run still going, which is exactly when a drain
	// matters — the resolved limit for a tenant who has not made a request
	// since is the *default*, not the binding they were admitted under.
	//
	// Killing a run on that is the worst thing this code can do: it stops work
	// for exceeding a limit that does not apply, and the audit event records a
	// breach that never happened. Booking the spend is still correct and still
	// happens; only the enforcement is withheld, and the next run start gates
	// against the real subject anyway.
	if !s.quotas().KnowsSubject(identity) && s.quotas().HasClaimBindings() {
		s.log().Warn(logger.EventAuthz, 0,
			"spend: over the default budget but this identity's claims are unknown, not stopping the run",
			map[string]interface{}{
				"identity": identity, "project": workDir,
				"resource": string(d.Resource), "limit": d.Limit, "used": d.Used,
			})
		return
	}

	s.auditSpendRefusal(workDir, identity, d)
	s.log().Warn(logger.EventAuthz, 0, "spend: daily budget exhausted, stopping run",
		map[string]interface{}{
			"identity": identity,
			"project":  workDir,
			"resource": string(d.Resource),
			"limit":    d.Limit,
			"used":     d.Used,
		})

	// Say so in the project's own live log before stopping it. The dashboard
	// shows that log, so this is where the person watching actually finds out
	// why their run ended; an audit row they cannot read is not an explanation.
	s.broadcastLog(workDir, fmt.Sprintf(
		"cloop: daily %s budget exhausted for %s (used %.2f of %.2f) — stopping run\n",
		d.Resource, identity, d.Used, d.Limit))

	s.stopRunForBudget(workDir)
}

// stopRunForBudget ends a run that has spent its budget.
//
// It asks the executor first and falls back to signalling host PIDs. The order
// matters: for a container or an edge agent there are no local PIDs to signal,
// and the host-only path this project used before executors existed would have
// left exactly the isolated runs — the ones a hosted deployment cares most
// about — running past their budget.
func (s *Server) stopRunForBudget(workDir string) {
	if run, ok := s.trackedRun(workDir); ok && run.ex != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		// Interrupt rather than kill: the orchestrator handles SIGINT by
		// finishing its in-flight step and persisting state. A budget overrun
		// is not a reason to corrupt the plan of the tenant who hit it.
		if err := run.ex.Signal(ctx, run.handleID, executor.SignalInterrupt); err == nil {
			s.observeRunExit(workDir)
			return
		}
	}
	if pids := multiui.CloopRunPIDsInDir(workDir); len(pids) > 0 {
		signalPIDs(pids, syscall.SIGINT)
		s.observeRunExit(workDir)
	}
}

// auditSpendRefusal records the refusal in the compliance trail.
//
// Best-effort, in the same shape as every other audit emission here: a wedged
// journal must never be the reason a budget is *not* enforced. The stop happens
// whether or not this lands.
func (s *Server) auditSpendRefusal(workDir, identity string, d *quota.Denial) {
	db, err := statedb.Open(state.DBPath(controlPlaneDir()))
	if err != nil {
		return
	}
	defer func() { _ = db.Close() }()
	// A spend refusal is a quota decision about an identity, not about a plan,
	// so it belongs to the hub's chain — `project` in the payload is the thing
	// that was stopped, not the place this is filed.
	db.AsControlPlane()

	payload, err := json.Marshal(map[string]any{
		"identity": identity,
		"resource": string(d.Resource),
		"limit":    d.Limit,
		"used":     d.Used,
		"source":   d.Source,
		"project":  workDir,
		"outcome":  "run_stopped",
	})
	if err != nil {
		return
	}

	_ = db.AppendAuditEvent(&statedb.AuditEvent{
		Actor:      identity,
		EventType:  string(AuditSpendRefused),
		EntityType: "project",
		EntityID:   workDir,
		Payload:    string(payload),
	})
}
