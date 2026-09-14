package orchestrator

import (
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/artifact"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/pm"
)

// TestResolveTaskAttribution_ContainerExecutor is the case the feature exists
// to make provable: a task placed on a container executor reports that it was,
// rather than reporting nothing.
func TestResolveTaskAttribution_ContainerExecutor(t *testing.T) {
	dir := t.TempDir()
	if _, err := artifact.WriteSandboxRun(dir, artifact.SandboxRecord{
		ExecutorID:   "docker-1",
		ExecutorKind: executor.KindContainer,
		Isolation:    string(executor.IsolationContainer),
		PinnedImage:  "ghcr.io/blechschmidt/cloop-harness@sha256:" + "ab" + "cd",
	}); err != nil {
		t.Fatalf("WriteSandboxRun: %v", err)
	}

	id, kind, iso := resolveTaskAttribution(dir)
	if id != "docker-1" {
		t.Errorf("ExecutorID = %q, want %q", id, "docker-1")
	}
	if kind != executor.KindContainer {
		t.Errorf("ExecutorKind = %q, want %q", kind, executor.KindContainer)
	}
	if iso != string(executor.IsolationContainer) {
		t.Errorf("Isolation = %q, want %q", iso, executor.IsolationContainer)
	}

	task := &pm.Task{ID: 1}
	stampAttribution(task, id, kind, iso)
	if RanOnHost(task) {
		t.Error("RanOnHost = true for a container-placed task — a sandboxed run " +
			"reported as host execution is a false alarm on the one screen an " +
			"operator relies on to spot real ones")
	}
}

// TestResolveTaskAttribution_NoRecordReadsAsHost pins the fallback, which is
// the one judgement call in this path.
//
// No placement record means no hub started this run: it is a bare `cloop run`,
// whose harness spawns as a child of this process on this machine. Reporting
// that as host execution is both accurate for that case and the safe direction
// for the ambiguous one — a missing record must never let a genuine host run
// read as sandboxed.
func TestResolveTaskAttribution_NoRecordReadsAsHost(t *testing.T) {
	id, kind, iso := resolveTaskAttribution(t.TempDir())
	if id != "" {
		t.Errorf("ExecutorID = %q, want empty: there was no registry to name", id)
	}
	if kind != executor.KindLocalProcess {
		t.Errorf("ExecutorKind = %q, want %q", kind, executor.KindLocalProcess)
	}
	if iso != string(executor.IsolationNone) {
		t.Errorf("Isolation = %q, want %q", iso, executor.IsolationNone)
	}

	task := &pm.Task{ID: 1}
	stampAttribution(task, id, kind, iso)
	if !RanOnHost(task) {
		t.Error("RanOnHost = false for an unplaced run — this is exactly the " +
			"case the no-host-execution audit has to catch")
	}
}

// TestResolveTaskAttribution_StaleRecordReadsAsHost covers the one ambiguity
// here that resolves towards "safe" rather than towards "loud", and so is the
// only one that can produce a silent false negative.
//
// Nothing deletes .cloop/sandbox-run.json, so a project the hub once ran in a
// container keeps that record indefinitely. A developer later running `cloop
// run` by hand in the same directory must not have their host execution
// attributed to yesterday's container.
func TestResolveTaskAttribution_StaleRecordReadsAsHost(t *testing.T) {
	dir := t.TempDir()
	if _, err := artifact.WriteSandboxRun(dir, artifact.SandboxRecord{
		ExecutorID:   "docker-1",
		ExecutorKind: executor.KindContainer,
		Isolation:    string(executor.IsolationContainer),
		StartedAt:    processStart.Add(-24 * time.Hour),
	}); err != nil {
		t.Fatalf("WriteSandboxRun: %v", err)
	}

	id, kind, iso := resolveTaskAttribution(dir)
	if kind != executor.KindLocalProcess || iso != string(executor.IsolationNone) {
		t.Errorf("a day-old placement record was believed: got kind=%q iso=%q, "+
			"want the host fallback — this is a host run reporting as sandboxed",
			kind, iso)
	}
	if id != "" {
		t.Errorf("stale executor id %q leaked into the attribution", id)
	}

	// A record written for *this* run is believed, so the guard above cannot
	// pass merely by disbelieving everything.
	fresh := t.TempDir()
	if _, err := artifact.WriteSandboxRun(fresh, artifact.SandboxRecord{
		ExecutorID:   "docker-1",
		ExecutorKind: executor.KindContainer,
		Isolation:    string(executor.IsolationContainer),
		StartedAt:    processStart.Add(-time.Second),
	}); err != nil {
		t.Fatalf("WriteSandboxRun: %v", err)
	}
	if _, kind, _ := resolveTaskAttribution(fresh); kind != executor.KindContainer {
		t.Errorf("a record from this run was rejected as stale: kind=%q", kind)
	}

	// A record with no timestamp is believed: StartedAt has always been
	// written, so an empty one is a truncated file rather than an old run, and
	// guessing "host" from it would be a different guess, not a better one.
	noTS := t.TempDir()
	if _, err := artifact.WriteSandboxRun(noTS, artifact.SandboxRecord{
		ExecutorID:   "docker-1",
		ExecutorKind: executor.KindContainer,
		Isolation:    string(executor.IsolationContainer),
	}); err != nil {
		t.Fatalf("WriteSandboxRun: %v", err)
	}
	// WriteSandboxRun stamps a zero StartedAt with the current time, so this
	// also confirms the writer's own default lands inside the window.
	if _, kind, _ := resolveTaskAttribution(noTS); kind != executor.KindContainer {
		t.Errorf("a freshly written record was rejected: kind=%q", kind)
	}
}

// TestIsolationOf_InfersFromKind covers records written before the Isolation
// field existed. They carry a kind and no isolation, and reading the absence as
// "none" would report every historical containerised run as host execution.
func TestIsolationOf_InfersFromKind(t *testing.T) {
	cases := []struct {
		kind string
		want executor.Isolation
	}{
		{executor.KindContainer, executor.IsolationContainer},
		{executor.KindRemoteAgent, executor.IsolationRemote},
		{executor.KindKubernetes, executor.IsolationRemote},
		{executor.KindLocalProcess, executor.IsolationNone},
		// An unrecognised driver yields "none" on purpose: a boundary nobody
		// can name is not one anyone should be shown as protected by.
		{"someFutureDriver", executor.IsolationNone},
	}
	for _, tc := range cases {
		got := isolationOf(artifact.SandboxRecord{ExecutorKind: tc.kind})
		if got != string(tc.want) {
			t.Errorf("isolationOf(kind=%q) = %q, want %q", tc.kind, got, tc.want)
		}
	}

	// An explicit isolation always wins over the inference.
	got := isolationOf(artifact.SandboxRecord{
		ExecutorKind: executor.KindContainer,
		Isolation:    string(executor.IsolationVM),
	})
	if got != string(executor.IsolationVM) {
		t.Errorf("recorded isolation ignored: got %q, want %q", got, executor.IsolationVM)
	}
}

// TestRanOnHost_UnattributedIsNotHost guards the direction that would make the
// warning useless: every task recorded before Task 20244 has empty attribution,
// and flagging all of them would bury the real findings in noise.
func TestRanOnHost_UnattributedIsNotHost(t *testing.T) {
	if RanOnHost(&pm.Task{ID: 1}) {
		t.Error("RanOnHost = true for a task with no attribution — unknown is " +
			"not the same claim as host")
	}
	if RanOnHost(nil) {
		t.Error("RanOnHost(nil) = true")
	}
	// Isolation "none" with a kind is a positive claim and must flag.
	if !RanOnHost(&pm.Task{ExecutorKind: executor.KindContainer, Isolation: "none"}) {
		t.Error("a task whose executor advertised no isolation must flag, even " +
			"when its kind says container — a disagreement between the two is " +
			"when the warning should fire, not resolve to fine")
	}
}
