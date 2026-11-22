package remote_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
)

// sendProgress sends one project_result frame on handle, marked interim or not.
func sendProgress(t *testing.T, p *peer, handle string, doc []byte, interim bool) {
	t.Helper()
	f, err := remote.NewFrame(remote.TypeProjectResult, "", handle,
		remote.ProjectResultPayload{Data: doc, Interim: interim})
	if err != nil {
		t.Fatalf("build project result: %v", err)
	}
	p.write(f)
}

// seededSpec is a dispatch that carried the project, so the hub accepts a
// report about it. The device here is hand-written and never opens the seed.
func seededSpec() executor.Spec {
	s := noWriteBackSpec()
	s.ProjectSeed = []byte{0x1f, 0x8b, 0x08, 0x00}
	return s
}

// TestRunningRunsPlanIsReadableWhileItRuns is the transport half of Task
// 50: a seeded run reports its plan while it is still going, and the hub
// can read the newest report — over and over, because the dashboard renders
// the project on every request — without consuming it.
//
// Before this, a report was only ever sent after the harness had exited, so
// the dashboard showed an empty project for the whole run.
func TestRunningRunsPlanIsReadableWhileItRuns(t *testing.T) {
	budget := remote.NewResultBudget(16<<10, 64<<10)
	ex := pinnedExecutor(t, "agent-1", budget, nil, nil)
	p, _ := connect(t, ex, remote.AgentRecord{AgentID: "agent-1"}, defaultHello(), nil)
	handle := startedHandle(t, ex, p, seededSpec())

	first, _ := fakeBundle(300)
	sendProgress(t, p, handle, first, true)
	if refused := barrier(t, p, handle); len(refused) != 0 {
		t.Fatalf("a progress report on a running handle was refused: %+v", refused)
	}

	got, err := ex.InterimProjectResult(handle)
	if err != nil {
		t.Fatalf("InterimProjectResult: %v — the run's plan never reached the hub", err)
	}
	if !got.Interim {
		t.Error("a progress report must be marked interim, or the hub would render it as an outcome")
	}
	if len(got.Data) != len(first) {
		t.Fatalf("read %d bytes, want the %d the device sent", len(got.Data), len(first))
	}
	if got.Redact == nil {
		t.Fatal("a report must come with the handle's redactor")
	}
	// Read again: the dashboard renders the project many times per run, and
	// the run has not ended.
	if again, err := ex.InterimProjectResult(handle); err != nil || len(again.Data) != len(first) {
		t.Fatalf("second read = %d bytes, %v; a peek must not consume the report", len(again.Data), err)
	}

	// The next report supersedes it, and is not counted twice.
	second, _ := fakeBundle(500)
	sendProgress(t, p, handle, second, true)
	if refused := barrier(t, p, handle); len(refused) != 0 {
		t.Fatalf("the next progress report was refused: %+v", refused)
	}
	wantPinned(t, ex, budget, 500, 500)
	if got, err := ex.InterimProjectResult(handle); err != nil || len(got.Data) != len(second) {
		t.Fatalf("after the second report the hub holds %d bytes, %v; want %d", len(got.Data), err, len(second))
	}

	// The run's own outcome replaces it for good: a later report — a ticker
	// that raced the final read-back — must not stale what the hub is about
	// to merge.
	outcome, _ := fakeBundle(700)
	sendProgress(t, p, handle, outcome, false)
	stale, _ := fakeBundle(200)
	sendProgress(t, p, handle, stale, true)
	if refused := barrier(t, p, handle); len(refused) != 0 {
		t.Fatalf("the run's outcome, or the report after it, was refused: %+v", refused)
	}
	peek, err := ex.InterimProjectResult(handle)
	if err != nil || len(peek.Data) != len(outcome) {
		t.Fatalf("the hub holds %d bytes, %v; want the run's outcome (%d)", len(peek.Data), err, len(outcome))
	}
	if peek.Interim {
		t.Error("the run's outcome is held as interim; a merge would then say the run was lost")
	}

	finish(t, p, handle, 0)
	barrier(t, p)
	collected, err := ex.ProjectResult(handle)
	if err != nil || len(collected.Data) != len(outcome) {
		t.Fatalf("collected %d bytes, %v; want the outcome (%d)", len(collected.Data), err, len(outcome))
	}
	if collected.Interim {
		t.Error("the collected outcome is marked interim")
	}
	wantPinned(t, ex, budget, 0, 0)
}

// TestLostRunsLastReportIsWhatIsLeft is the other half of why reports are
// held: a run whose executor stops answering never sends an outcome, and
// before this the plan it had made went with it. What the hub collects then is
// the last report, marked so the merge can say so and leave the project's
// status to whoever settles the run.
func TestLostRunsLastReportIsWhatIsLeft(t *testing.T) {
	budget := remote.NewResultBudget(16<<10, 64<<10)
	ex := pinnedExecutor(t, "agent-1", budget, nil, nil)
	p, _ := connect(t, ex, remote.AgentRecord{AgentID: "agent-1"}, defaultHello(), nil)
	handle := startedHandle(t, ex, p, seededSpec())

	doc, _ := fakeBundle(400)
	sendProgress(t, p, handle, doc, true)
	barrier(t, p, handle)

	got, err := ex.ProjectResult(handle)
	if err != nil || len(got.Data) != len(doc) {
		t.Fatalf("collected %d bytes, %v; want the last report (%d)", len(got.Data), err, len(doc))
	}
	if !got.Interim {
		t.Error("the last report must be marked interim, or the hub would record it as the run's outcome")
	}
	// Released once, like an outcome: merging the same report twice would add
	// its tasks twice.
	if _, err := ex.ProjectResult(handle); !errors.Is(err, executor.ErrProjectResultUnavailable) {
		t.Errorf("second collection = %v, want ErrProjectResultUnavailable", err)
	}
	wantPinned(t, ex, budget, 0, 0)
}

// TestProgressReportNeedsADocument: an interim frame exists to carry the plan.
// A device that sends one with only a reason in it is refused — the reason
// belongs in the final report, where the project's journal has somewhere to
// put it.
func TestProgressReportNeedsADocument(t *testing.T) {
	_, err := remote.DecodeProjectResult(mustFrame(t, remote.TypeProjectResult, "h",
		remote.ProjectResultPayload{Err: "could not read the project", Interim: true}))
	if err == nil || !strings.Contains(err.Error(), "no document") {
		t.Errorf("an interim frame with no document = %v, want a protocol refusal", err)
	}
	// The same payload as a final report is the pre-existing, supported case.
	if _, err := remote.DecodeProjectResult(mustFrame(t, remote.TypeProjectResult, "h",
		remote.ProjectResultPayload{Err: "could not read the project"})); err != nil {
		t.Errorf("a final report carrying only a reason = %v, want it accepted", err)
	}
}

// TestInterimProjectResultVersionGate pins the floor: the marked frame is new
// in v32, and an agent speaking to an older hub — which refuses any report for
// a handle it has not seen finish — must send none.
func TestInterimProjectResultVersionGate(t *testing.T) {
	if remote.SupportsInterimProjectResult(remote.MinInterimProjectResultVersion - 1) {
		t.Errorf("v%d must not be treated as accepting a running run's plan",
			remote.MinInterimProjectResultVersion-1)
	}
	if !remote.SupportsInterimProjectResult(remote.ProtocolVersion) {
		t.Error("this build's own version must accept a running run's plan")
	}
	if remote.MinInterimProjectResultVersion <= remote.MinProjectResultVersion {
		t.Error("a hub that accepts a running run's plan must also accept the run's outcome")
	}
}

func mustFrame(t *testing.T, typ remote.FrameType, handle string, payload any) remote.Frame {
	t.Helper()
	f, err := remote.NewFrame(typ, "", handle, payload)
	if err != nil {
		t.Fatalf("build %s frame: %v", typ, err)
	}
	return f
}
