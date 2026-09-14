package orchestrator

import (
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/artifact"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/pm"
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
