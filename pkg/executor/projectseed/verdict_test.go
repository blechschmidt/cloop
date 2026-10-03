package projectseed

// A run on a device that dies after its orchestrator has decided a task — the
// review gate failed it, say — but before the decision reached the device's
// database must report that decision, not "still in progress" (Task 20365).
// The hub cannot read the device's live artifact, so without the verdict its
// own recovery could only re-queue the task and the rejected work would run
// again as if nothing had been decided.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/artifact"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/taskrecover"
)

// deadRunOnDevice plays a seeded run that started every task in ids and died
// with them in progress, the agent having printed TASK_DONE for each.
func deadRunOnDevice(t *testing.T, seed []byte, started time.Time, ids ...int) string {
	t.Helper()
	return onDevice(t, seed, func(dir string, st *state.ProjectState) {
		for _, id := range ids {
			task := st.Plan.TaskByID(id)
			task.Status = pm.TaskInProgress
			task.StartedAt = ptrTime(started)
			live := artifact.LiveArtifactPath(dir, id)
			if err := os.MkdirAll(filepath.Dir(live), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(live, []byte("Committed it.\nTASK_DONE\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		st.Status = "running"
		if err := st.Save(); err != nil {
			t.Fatalf("device save: %v", err)
		}
	})
}

func gatedHubProject(t *testing.T) string {
	t.Helper()
	return hubProject(t, &state.ProjectState{
		Goal:       "divide",
		Provider:   "claudecode",
		Status:     "initialized",
		ReviewGate: &pm.ReviewGate{Enabled: true, Mode: pm.ReviewModeBlock},
		Plan: &pm.Plan{Goal: "divide", Tasks: []*pm.Task{
			{ID: 1, Title: "Add division", Priority: 1, Status: pm.TaskPending},
			{ID: 2, Title: "Add multiplication", Priority: 1, Status: pm.TaskPending},
			{ID: 3, Title: "Add subtraction", Priority: 1, Status: pm.TaskPending},
		}},
	})
}

func TestHarvestReportsTheVerdictOfARunThatDied(t *testing.T) {
	isolateHome(t)
	hub := gatedHubProject(t)
	seed := seedFromHub(t, hub)
	started := time.Now().Add(-10 * time.Minute)
	dev := deadRunOnDevice(t, seed, started, 1, 2, 3)

	// Task 1: the gate rejected it. Task 2: the gate approved it, and the
	// write that would have stored the review never landed. Task 3: the run
	// died while the review was still going.
	for _, v := range []taskrecover.Verdict{
		{TaskID: 1, Status: pm.TaskFailed, Source: taskrecover.SourceReviewGate, Reason: "review_blocked",
			Detail:    "Review gate: changes requested by strict-model (1 finding(s)) — not published.",
			Diagnosis: "- [major] calc.txt:1: division by zero",
			Review:    &pm.TaskReview{Verdict: pm.ReviewChangesRequested, Blocked: true, Rounds: 1}},
		{TaskID: 2, Status: pm.TaskDone, Source: taskrecover.SourceReviewGate, Reason: "review_approved",
			Summary: "Added multiplication.", Review: &pm.TaskReview{Verdict: pm.ReviewApproved, Rounds: 1}},
		{TaskID: 3, Status: pm.TaskInProgress, Source: taskrecover.SourceReviewGate, Reason: taskrecover.ReasonReviewPending},
	} {
		v.StartedAt, v.WrittenAt = ptrTime(started), started.Add(time.Minute)
		if err := taskrecover.WriteVerdict(dev, v); err != nil {
			t.Fatal(err)
		}
	}

	data, err := Harvest(dev, seed, nil)
	if err != nil {
		t.Fatalf("Harvest: %v", err)
	}
	res, err := DecodeResult(data)
	if err != nil {
		t.Fatalf("DecodeResult: %v", err)
	}
	statuses := map[int]pm.TaskStatus{}
	for _, tc := range res.Tasks {
		statuses[tc.After.ID] = tc.After.Status
	}
	if statuses[1] != pm.TaskFailed || statuses[2] != pm.TaskDone || statuses[3] != pm.TaskInProgress {
		t.Fatalf("the device reported %v; want the gate's decisions, and task 3 still undecided", statuses)
	}

	rep, err := Apply(hub, res, Provenance{ExecutorID: "dev", ExecutorKind: "remote", Isolation: "remote"}, nil)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	got, err := state.Load(hub)
	if err != nil {
		t.Fatal(err)
	}
	t1, t2 := got.Plan.TaskByID(1), got.Plan.TaskByID(2)
	if t1.Status != pm.TaskFailed || !strings.Contains(t1.FailureDiagnosis, "division by zero") ||
		t1.Review == nil || !t1.Review.Blocked {
		t.Fatalf("task 1 on the hub = %s %q %+v; want the gate's rejection", t1.Status, t1.FailureDiagnosis, t1.Review)
	}
	var noted bool
	for _, a := range t1.Annotations {
		noted = noted || strings.Contains(a.Text, "cloop had already decided")
	}
	if !noted {
		t.Errorf("task 1 does not say its outcome came from a recovery: %+v", t1.Annotations)
	}
	// The verdict brought the review record, so the hub does not mistake an
	// approved task for one a pre-gate device ran unreviewed.
	if t2.Status != pm.TaskDone || t2.Review == nil || len(rep.Unreviewed) != 0 {
		t.Errorf("task 2 = %s, review %+v, flagged unreviewed %v", t2.Status, t2.Review, rep.Unreviewed)
	}

	// The recovery is on the hub's journal, as one made on the hub would be.
	events, _, err := state.ListEvents(hub, 0, 50)
	if err != nil {
		t.Fatal(err)
	}
	var recovered bool
	for _, e := range events {
		if e.Type == state.EventTaskFailed && e.TaskID == 1 && strings.Contains(e.Details, `"verdict_source":"review_gate"`) {
			recovered = true
		}
	}
	if !recovered {
		t.Errorf("no recovery event for task 1 on the hub's journal: %+v", events)
	}

	// What the device had not decided, the hub's own recovery settles — and
	// without the device's transcript it runs the task again rather than
	// believing the TASK_DONE nobody reviewed.
	outcomes := taskrecover.Reconcile(hub, got.Plan)
	if len(outcomes) != 1 || outcomes[0].TaskID != 3 || got.Plan.TaskByID(3).Status != pm.TaskPending {
		t.Fatalf("hub recovery = %+v; want only task 3, re-queued", outcomes)
	}
}

// A verdict from an earlier attempt on the device must not decide this one.
func TestHarvestIgnoresAStaleVerdict(t *testing.T) {
	isolateHome(t)
	hub := gatedHubProject(t)
	seed := seedFromHub(t, hub)
	started := time.Now().Add(-10 * time.Minute)
	dev := deadRunOnDevice(t, seed, started, 1)
	if err := taskrecover.WriteVerdict(dev, taskrecover.Verdict{TaskID: 1, Status: pm.TaskDone,
		Source: taskrecover.SourceAgent, WrittenAt: started.Add(-time.Hour)}); err != nil {
		t.Fatal(err)
	}
	res := harvestAndDecode(t, dev, seed)
	if st := statusIn(res, 1); st != pm.TaskInProgress {
		t.Fatalf("task 1 reported %q from an earlier attempt's verdict", st)
	}
}

// The agent reads the workspace with privileges the workload may not have: a
// link the workload planted is not followed to find a verdict.
func TestHarvestDoesNotFollowALinkedArtifactsDirectory(t *testing.T) {
	isolateHome(t)
	hub := gatedHubProject(t)
	seed := seedFromHub(t, hub)
	started := time.Now().Add(-10 * time.Minute)
	dev := deadRunOnDevice(t, seed, started, 1)

	elsewhere := t.TempDir()
	if err := taskrecover.WriteVerdict(elsewhere, taskrecover.Verdict{TaskID: 1, Status: pm.TaskDone,
		StartedAt: ptrTime(started), WrittenAt: started.Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	live := artifact.LiveArtifactDir(dev)
	if err := os.RemoveAll(live); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(artifact.LiveArtifactDir(elsewhere), live); err != nil {
		t.Fatal(err)
	}

	res := harvestAndDecode(t, dev, seed)
	if st := statusIn(res, 1); st != pm.TaskInProgress {
		t.Fatalf("task 1 reported %q from a verdict reached through a link", st)
	}
}

func harvestAndDecode(t *testing.T, dev string, seed []byte) *Result {
	t.Helper()
	data, err := Harvest(dev, seed, nil)
	if err != nil {
		t.Fatalf("Harvest: %v", err)
	}
	res, err := DecodeResult(data)
	if err != nil {
		t.Fatalf("DecodeResult: %v", err)
	}
	return res
}

func statusIn(r *Result, id int) pm.TaskStatus {
	for _, tc := range r.Tasks {
		if tc.After != nil && tc.After.ID == id {
			return tc.After.Status
		}
	}
	return ""
}
