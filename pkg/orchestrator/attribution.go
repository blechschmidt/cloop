package orchestrator

import (
	"strings"
	"sync"
	"time"

	"github.com/blechschmidt/cloop/pkg/artifact"
	"github.com/blechschmidt/cloop/pkg/cost"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// processStart is when this binary started, captured at package init.
//
// It is the discriminator between a placement record written for *this* run
// and one left behind by a previous one — see staleRecord.
var processStart = time.Now()

// attributionGrace is how much older than this process a placement record may
// be and still be believed.
//
// The gap it has to absorb is only spawn-to-init: the hub writes the record
// immediately after the workload starts, and this variable is initialised as
// the workload's first act. Everything slow about a run — config load, plan
// decomposition, the first provider call — happens *after* it, so the window
// does not need to cover any of that. Ten minutes is therefore enormously more
// than the real gap, chosen to absorb a container that is slow to exec rather
// than to accommodate a long startup.
//
// Being generous here is the safe direction only up to a point: too large a
// window is what lets a genuinely stale record through, so it is deliberately
// minutes rather than the hours a "surely that's enough" instinct would pick.
const attributionGrace = 10 * time.Minute

// Executor attribution for task records (Task 20244).
//
// The orchestrator does not choose an executor. Placement happens a layer up:
// the hub resolves the project's binding, starts a whole `cloop run` on the
// chosen executor, and only then does this process exist. By the time a task
// starts there is no placement decision left to read — the decision is the
// reason this process is running at all.
//
// What the hub does leave behind is .cloop/sandbox-run.json, written by
// recordSandboxProvenance immediately after the workload starts and visible
// from inside the sandbox. That record is the attribution channel, and it is
// written for *every* driver including the host one, so the case this whole
// feature exists to make visible is the case that is always recorded.

// resolveTaskAttribution reports where the current run is executing, for
// stamping onto a task at start.
//
// The fallback deserves its reasoning spelled out, because it is the one place
// this can be wrong. When no placement record exists, the run was not started
// by a hub — it is a bare `cloop run`, whose harness spawns as a child of this
// process on this machine. That is host execution, and it is reported as such.
//
// The residual risk is the reverse: an isolated executor whose workspace was
// materialised without the record would be reported as host. That direction is
// deliberate. Under-reporting isolation raises a false alarm on a screen an
// operator can check; over-reporting it would let a genuine host execution
// read as sandboxed, which is the single failure this attribution exists to
// prevent. When the evidence is missing, the loud reading is the safe one.
// Re-read per task rather than cached once: if the hub fails a workload over to
// another executor mid-plan it rewrites the record, and the tasks that run
// afterwards should be attributed to where they actually ran. The file is a few
// hundred bytes and a task takes minutes, so the read is free.
func resolveTaskAttribution(workDir string) (id, kind, isolation string) {
	rec, ok := artifact.LoadSandboxRun(workDir)
	if !ok || strings.TrimSpace(rec.ExecutorKind) == "" || staleRecord(rec) {
		return "", executor.KindLocalProcess, string(executor.IsolationNone)
	}
	return rec.ExecutorID, rec.ExecutorKind, isolationOf(rec)
}

// runID is the identifier for this orchestrator process's execution, resolved
// once (Task 20282).
//
// Resolved lazily rather than at init because it reads the project directory,
// which the config names and which package init cannot see.
var (
	runIDOnce  sync.Once
	runIDValue string
)

// resolveRunID reports the execution id to stamp on this run's tasks.
//
// The hub minted one before it acquired anything and left it in the placement
// record, and using *that* value is the entire point: it is what the broker
// already wrote on the secret.lease rows, so reusing it is what makes the two
// halves of the trail join.
//
// A bare `cloop run` has no record and mints its own. That is not a fallback of
// last resort but the correct answer — the execution is real and its tasks
// deserve a correlatable trace, even though no leases were issued to it.
// Minting one here rather than leaving it empty also avoids the failure mode
// that would matter: an empty run id on every unmanaged run makes them all
// join to each other.
//
// A stale record is treated as no record, for the reason staleRecord exists —
// otherwise a developer's own run in a directory the hub once used would file
// its tasks under an execution that ended yesterday, and inherit that run's
// leases in any query that joins on the id.
func resolveRunID(workDir string) string {
	runIDOnce.Do(func() {
		if rec, ok := artifact.LoadSandboxRun(workDir); ok && !staleRecord(rec) {
			if id := strings.TrimSpace(rec.RunID); id != "" {
				runIDValue = id
				return
			}
		}
		runIDValue = artifact.NewRunID()
	})
	return runIDValue
}

// dispatchFacts is the placement record joined to the task about to run.
//
// It exists so the dispatch row carries what the hub knew — the image that was
// actually pinned, the spec that asked for it, the leases handed over — rather
// than only what the task row can hold. Those facts are on the opposite side of
// the sandbox boundary from the hub that chose them, and the placement record
// is the one channel that crosses it.
type dispatchFacts struct {
	RunID          string
	ExecutorID     string
	ExecutorKind   string
	Isolation      string
	RequestedImage string
	PinnedImage    string
	SpecHash       string
	SetupHash      string
	LeaseIDs       []string
	Identity       string
}

// resolveDispatchFacts reads the placement record for the dispatch row.
//
// Re-read per task rather than cached for the reason resolveTaskAttribution
// gives: a hub that fails a workload over to another executor mid-plan rewrites
// the record, and the tasks that run afterwards belong to the new placement.
// The run id is the exception and is resolved once — a failover does not end
// the execution the leases were issued to.
func resolveDispatchFacts(workDir string) dispatchFacts {
	f := dispatchFacts{RunID: resolveRunID(workDir)}
	f.ExecutorID, f.ExecutorKind, f.Isolation = resolveTaskAttribution(workDir)

	rec, ok := artifact.LoadSandboxRun(workDir)
	if !ok || staleRecord(rec) {
		return f
	}
	f.RequestedImage = rec.RequestedImage
	f.PinnedImage = rec.PinnedImage
	f.SpecHash = rec.SpecHash
	f.SetupHash = rec.SetupHash
	f.LeaseIDs = rec.LeaseIDs
	f.Identity = strings.TrimSpace(rec.Identity)
	return f
}

// beginTaskExecution stamps placement onto a task and records the dispatch.
//
// Both orchestrator loops call this at the moment a task enters in_progress, so
// the sequential and parallel paths cannot disagree about what a dispatch is —
// the same class of divergence Task 20269 removed from the gating decision.
//
// The audit row is emitted here, before the save, and the state store emits its
// own thinner one when the status is persisted. They are not duplicates of each
// other in any case that matters: this one is the full record and fires only
// when the orchestrator dispatches, while the store's fires for *any* writer
// that moves a task into in_progress — including tools that are not this
// orchestrator, which is exactly the case an auditor must not have hidden from
// them. `observed_by` on the payload tells them apart.
func (o *Orchestrator) beginTaskExecution(task *pm.Task) dispatchFacts {
	f := resolveDispatchFacts(o.config.WorkDir)
	stampAttribution(task, f.ExecutorID, f.ExecutorKind, f.Isolation)
	task.RunID = f.RunID

	statedb.AuditTaskDispatch(o.statedb, statedb.TaskDispatchInput{
		TaskID:         task.ID,
		TaskTitle:      task.Title,
		ProjectPath:    o.config.WorkDir,
		RunID:          f.RunID,
		ExecutorID:     f.ExecutorID,
		ExecutorKind:   f.ExecutorKind,
		Isolation:      f.Isolation,
		RequestedImage: f.RequestedImage,
		PinnedImage:    f.PinnedImage,
		SpecHash:       f.SpecHash,
		SetupHash:      f.SetupHash,
		LeaseIDs:       f.LeaseIDs,
		Actor:          f.Identity,
	})
	return f
}

// staleRecord reports whether a placement record describes an earlier run.
//
// The record lives in the project directory and is overwritten only when a hub
// dispatches a workload. Nothing removes it, so a project the hub once ran in a
// container keeps that record forever — and a developer later running `cloop
// run` by hand in the same directory would find it and attribute their host
// execution to the container that ran yesterday.
//
// That is the one failure this whole feature exists to prevent: a host run
// reading as sandboxed. Every other ambiguity here resolves towards "host",
// which at worst raises a false alarm; this one resolves towards "safe", which
// is a silent false negative on the hub's central claim.
//
// A record with no timestamp is not treated as stale. StartedAt has been
// written since the record existed, so an empty one means a hand-edited or
// truncated file — and refusing to believe it would reclassify it as host
// execution, which is a different guess, not a better-founded one. The kind
// check in the caller is what guards that case.
func staleRecord(rec artifact.SandboxRecord) bool {
	if rec.StartedAt.IsZero() {
		return false
	}
	return rec.StartedAt.Before(processStart.Add(-attributionGrace))
}

// isolationOf returns the isolation a record describes, inferring it from the
// driver kind when the record predates the Isolation field.
//
// The inference is conservative in the same direction as the fallback above:
// an unrecognised kind yields "none", because a boundary nobody can name is
// not a boundary anyone should be shown as protected by.
func isolationOf(rec artifact.SandboxRecord) string {
	if iso := strings.TrimSpace(rec.Isolation); iso != "" {
		return iso
	}
	switch rec.ExecutorKind {
	case executor.KindContainer:
		return string(executor.IsolationContainer)
	case executor.KindRemoteAgent, executor.KindKubernetes:
		return string(executor.IsolationRemote)
	default:
		return string(executor.IsolationNone)
	}
}

// resolveRunIdentity reports who this run's spend is attributable to, for
// stamping onto each cost ledger row (Task 20264).
//
// Same channel and same fallback shape as resolveTaskAttribution above: the
// hub wrote the initiating identity into .cloop/sandbox-run.json at dispatch,
// and no record means no hub — a bare `cloop run`, which is cost.IdentityLocal
// by definition.
//
// The staleness check is the part that matters. A record left by yesterday's
// hub-dispatched run stays in the project directory forever, so without it a
// developer's own `cloop run` in the same directory would bill its tokens to
// whoever last started a run there. Falling back to "local" when the evidence
// is old is both the honest answer and the one that cannot put spend on
// somebody else's name.
func resolveRunIdentity(workDir string) string {
	rec, ok := artifact.LoadSandboxRun(workDir)
	if !ok || staleRecord(rec) {
		return cost.IdentityLocal
	}
	if id := strings.TrimSpace(rec.Identity); id != "" {
		return id
	}
	return cost.IdentityLocal
}

// stampAttribution records where a task is running, on the task itself.
//
// Called at start rather than at completion so a task still in flight is
// attributable — "what is running on that edge device right now" is the
// question asked during an incident, and it has to be answerable before the
// task ends.
func stampAttribution(t *pm.Task, id, kind, isolation string) {
	if t == nil {
		return
	}
	t.ExecutorID, t.ExecutorKind, t.Isolation = id, kind, isolation
}

// attributionLabel renders an executor id for a human-readable line.
//
// A bare `cloop run` has no executor id to name — there was no registry
// involved — so it reads as "(unregistered)" rather than as an empty gap the
// reader has to interpret.
func attributionLabel(id string) string {
	if strings.TrimSpace(id) == "" {
		return "(unregistered)"
	}
	return id
}

// RanOnHost reports whether a task's recorded attribution says the harness ran
// as a process on the hub's own machine, with its filesystem and network.
//
// Either signal alone is enough. They are written together and should always
// agree, but this is the predicate the UI colours a warning with, and a
// disagreement between two fields that claim the same thing is exactly when a
// warning should fire rather than resolve to "fine".
//
// An unattributed task — both fields empty, written before Task 20244 — is
// not host execution. It is unknown, and saying otherwise would retroactively
// accuse every historical task of touching the host.
func RanOnHost(t *pm.Task) bool {
	if t == nil {
		return false
	}
	return t.ExecutorKind == executor.KindLocalProcess ||
		(t.Isolation == string(executor.IsolationNone) && t.ExecutorKind != "")
}
