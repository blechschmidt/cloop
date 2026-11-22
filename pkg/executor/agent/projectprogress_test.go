package agent

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor/projectseed"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
)

// plannedProject returns a seed for a project with a goal and no tasks — the
// shape that motivated Task 50, a run started in pm mode — and a directory
// holding the database a run that has *planned* but not finished leaves: three
// tasks, the first done, the second under way.
func plannedProject(t *testing.T) (seed []byte, planned string) {
	t.Helper()
	seed, err := projectseed.Build(&state.ProjectState{
		Goal:   "Build an attested enclave and a client for it",
		Status: "initialized",
		Plan:   &pm.Plan{Goal: "Build an attested enclave and a client for it"},
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	dir := t.TempDir()
	if err := projectseed.Write(dir, seed); err != nil {
		t.Fatalf("Write: %v", err)
	}
	st, err := state.Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	now := time.Now().UTC()
	st.Plan.Tasks = append(st.Plan.Tasks,
		&pm.Task{ID: 1, Title: "Pin down the enclave protocol", Priority: 1, Status: pm.TaskDone,
			Result: "documented", CompletedAt: &now},
		&pm.Task{ID: 2, Title: "Set up the Cargo workspace", Priority: 2, Status: pm.TaskInProgress, StartedAt: &now},
		&pm.Task{ID: 3, Title: "Implement the attested key exchange", Priority: 3, Status: pm.TaskPending},
	)
	st.Status = "running"
	if err := st.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}
	return seed, filepath.Join(dir, ".cloop")
}

// planThenLinger plays a `cloop run` that has planned its work and is still
// going: it installs the database the run would have written so far, then
// stays alive long enough for the agent's progress ticker to read it.
func planThenLinger(src string) []string {
	return []string{"/bin/sh", "-c",
		"cp '" + src + "/state.db' .cloop/state.db && " +
			"if [ -f '" + src + "/state.db-wal' ]; then cp '" + src + "/state.db-wal' .cloop/; fi && " +
			"sleep 1"}
}

// interimReports returns the progress reports among frames, in order.
func interimReports(t *testing.T, frames []remote.Frame) []projectseed.Result {
	t.Helper()
	var out []projectseed.Result
	for _, f := range frames {
		if f.Type != remote.TypeProjectResult {
			continue
		}
		p, err := remote.DecodeProjectResult(f)
		if err != nil {
			t.Fatalf("DecodeProjectResult: %v", err)
		}
		if !p.Interim {
			continue
		}
		doc, err := projectseed.DecodeResult(p.Data)
		if err != nil {
			t.Fatalf("DecodeResult: %v", err)
		}
		if !doc.Interim {
			t.Error("a frame marked interim carries a document that does not say so")
		}
		out = append(out, *doc)
	}
	return out
}

// TestAgentReportsThePlanWhileTheRunIsStillGoing is the device half of Task
// 50. A seeded run plans its own tasks — the hub sent a goal and no plan —
// and works through them for as long as it takes. Until the agent reported the
// plan as it went, the hub learned of those tasks only when the run ended, so
// the dashboard showed an empty project for the whole run, and a run whose
// executor stopped answering took its plan with it.
func TestAgentReportsThePlanWhileTheRunIsStillGoing(t *testing.T) {
	old := interimProjectReportEvery
	interimProjectReportEvery = 50 * time.Millisecond
	t.Cleanup(func() { interimProjectReportEvery = old })

	dir := t.TempDir()
	root := filepath.Join(dir, "work")
	a, conns := newScriptedAgent(t, filepath.Join(dir, "agent.json"), root)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = a.Run(ctx) }()

	cp := <-conns
	cp.handshakeAt(t, "FL6HRGvUlqxf96aO", remote.ProtocolVersion)

	seed, planned := plannedProject(t)
	frames := startSeeded(t, cp, remote.ProtocolVersion, seed, planThenLinger(planned))

	reports := interimReports(t, frames)
	if len(reports) == 0 {
		t.Fatalf("the agent sent no progress report while the run ran; frames: %v", frames)
	}
	last := reports[len(reports)-1]
	if len(last.Tasks) != 3 {
		t.Fatalf("the last progress report carries %d tasks, want the 3 the run planned: %+v",
			len(last.Tasks), last.Tasks)
	}
	for _, tc := range last.Tasks {
		if tc.Before != nil {
			t.Errorf("task #%d is reported as changed; the hub sent no tasks, so every one is new",
				tc.After.ID)
		}
	}
	// A report is the plan and nothing else: it is made from a database the
	// harness is still writing, every few seconds, and superseded by the next.
	switch {
	case last.Status != "":
		t.Errorf("a progress report claims the project status %q; the run has not ended", last.Status)
	case len(last.Steps) != 0 || len(last.Events) != 0 || len(last.Costs) != 0:
		t.Errorf("a progress report carries %d steps, %d events, %d cost rows; it should carry none",
			len(last.Steps), len(last.Events), len(last.Costs))
	}

	// Every report precedes the run's outcome, which precedes the terminal
	// status: the hub settles the run the moment the status closes its stream.
	lastInterim, outcome, status := -1, -1, -1
	for i, f := range frames {
		switch f.Type {
		case remote.TypeProjectResult:
			if p, _ := remote.DecodeProjectResult(f); p.Interim {
				lastInterim = i
			} else {
				outcome = i
			}
		case remote.TypeStatus:
			if st, err := remote.DecodeStatus(f); err == nil && st.Status.State.Terminal() {
				status = i
			}
		}
	}
	if outcome < 0 || status < 0 {
		t.Fatalf("the run ended without an outcome (%d) or a terminal status (%d)", outcome, status)
	}
	if !(lastInterim < outcome && outcome < status) {
		t.Errorf("frames out of order: last report %d, outcome %d, status %d", lastInterim, outcome, status)
	}
	// The outcome is the full account, and it is not marked interim.
	if p, _ := remote.DecodeProjectResult(frames[outcome]); p.Interim {
		t.Error("the run's outcome is marked interim; the hub would record the run as lost")
	}
}

// TestAgentSendsNoProgressReportToAnOlderHub: a hub below v32 refuses any
// project result for a handle it has not seen finish, and answers with a
// protocol error. The agent must send none on such a session — and the run
// must still end with its outcome reported, exactly as before.
func TestAgentSendsNoProgressReportToAnOlderHub(t *testing.T) {
	old := interimProjectReportEvery
	interimProjectReportEvery = 50 * time.Millisecond
	t.Cleanup(func() { interimProjectReportEvery = old })

	const older = remote.MinInterimProjectResultVersion - 1
	dir := t.TempDir()
	a, conns := newScriptedAgent(t, filepath.Join(dir, "agent.json"), filepath.Join(dir, "work"))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = a.Run(ctx) }()

	cp := <-conns
	cp.handshakeAt(t, "FL6HRGvUlqxf96aO", older)

	seed, planned := plannedProject(t)
	frames := startSeeded(t, cp, older, seed, planThenLinger(planned))

	if reports := interimReports(t, frames); len(reports) != 0 {
		t.Errorf("the agent sent %d progress reports to a v%d hub, which has no case for them",
			len(reports), older)
	}
	var sawOutcome bool
	for _, f := range frames {
		if f.Type == remote.TypeProjectResult {
			sawOutcome = true
		}
	}
	if !sawOutcome {
		t.Error("the run's outcome did not reach a hub that does accept one")
	}
}

// TestUnchangedPlanIsNotReportedTwice: a run spends minutes on one task, and
// the ticker fires every few seconds. Re-sending the same document would make
// the hub hold and decode it for nothing.
func TestUnchangedPlanIsNotReportedTwice(t *testing.T) {
	wl := &workload{}
	first := [32]byte{1, 2, 3}
	if !wl.sentProgress(first) {
		t.Fatal("the first report must be sent")
	}
	if wl.sentProgress(first) {
		t.Error("an unchanged plan was reported again")
	}
	if !wl.sentProgress([32]byte{9}) {
		t.Error("a changed plan must be reported")
	}
}

// TestFinishedWorkloadReportsNoProgress: once the harness has exited, the
// outcome is what travels. A progress report from after that could only stale
// what the hub is about to merge — and the hub refuses one on a closed handle.
func TestFinishedWorkloadReportsNoProgress(t *testing.T) {
	wl := &workload{workDir: "/tmp/project", seed: []byte{0x1f, 0x8b}}
	if _, _, ok := wl.projectProgress(); !ok {
		t.Fatal("a seeded, running workload has a plan to report")
	}
	wl.mu.Lock()
	wl.finished = true
	wl.mu.Unlock()
	if _, _, ok := wl.projectProgress(); ok {
		t.Error("a finished workload still offers progress reports")
	}

	// And a workload that was never sent a project has nothing to read.
	unseeded := &workload{workDir: "/tmp/project"}
	if _, _, ok := unseeded.projectProgress(); ok {
		t.Error("an unseeded workload offers a plan it was never given")
	}
}

// TestProgressReportingIsNotStartedWithoutASeed guards the ticker itself: it
// must cost an unseeded run nothing, and its stop must be safe to call.
func TestProgressReportingIsNotStartedWithoutASeed(t *testing.T) {
	a := &Agent{}
	stop := a.followProjectProgress(&workload{workDir: "/tmp/project"})
	if stop == nil {
		t.Fatal("followProjectProgress must always return a stop")
	}
	stop()
}
