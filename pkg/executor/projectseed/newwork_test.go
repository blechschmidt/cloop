package projectseed

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/pausereason"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
)

// Work the hub's plan gains while a seeded run is out is carried on with when
// the run comes back at the end of the plan it was sent (Task 20516): the
// project is paused work_added, for the hub to start a run of the plan as it
// stands now at once. Only work the run could not have started counts, so a
// task the run declines is never sent to it again and again.
func TestARunThatFinishedItsPlanIsCarriedOnWithWorkAddedWhileItWasOut(t *testing.T) {
	now := time.Now().UTC()
	finished := func(id int, title string) TaskChange {
		return TaskChange{
			Before: &pm.Task{ID: id, Title: title, Status: pm.TaskPending},
			After: &pm.Task{ID: id, Title: title, Status: pm.TaskDone, Result: "did " + title,
				StartedAt: ptrTime(now.Add(-time.Minute)), CompletedAt: ptrTime(now)},
		}
	}
	// sentWith is the record of a seed whose plan held these tasks
	// startable, by ID and title.
	sentWith := func(tasks ...*pm.Task) *SeedWork {
		return &SeedWork{Startable: StartableWork(&pm.Plan{Tasks: tasks})}
	}
	pending := func(id int, title string) *pm.Task {
		return &pm.Task{ID: id, Title: title, Priority: id, Status: pm.TaskPending}
	}

	t.Run("a task added on the hub while the run was out", func(t *testing.T) {
		// The sgx-rust-attestation case: #18 was sent, #19 was added while
		// the device worked on it.
		st := &state.ProjectState{Status: "paused", Plan: &pm.Plan{Tasks: []*pm.Task{
			{ID: 17, Title: "earlier", Status: pm.TaskDone},
			pending(18, "verify from non-SGX hosts"),
			pending(19, "fix the README status"),
		}}}
		st.PauseReason = &pausereason.Reason{Code: pausereason.CodeIdle, Detail: "every runnable task is finished"}
		sent := sentWith(pending(18, "verify from non-SGX hosts"))
		rep, _ := Merge(st, &Result{Format: 1, Status: "complete", Tasks: []TaskChange{finished(18, "verify from non-SGX hosts")}},
			Provenance{Sent: sent}, nil, now)

		if st.Status != "paused" || st.PauseReason == nil || st.PauseReason.Code != pausereason.CodeWorkAdded {
			t.Fatalf("status %q (%+v), want paused work_added", st.Status, st.PauseReason)
		}
		if !st.PauseReason.AutoResumable(now) || !st.PauseReason.ResumedAtOnce() || !rep.ResumesAtOnce {
			t.Errorf("pause %+v (report says %v) is not one the hub restarts at once", st.PauseReason, rep.ResumesAtOnce)
		}
		if want := "task #19 was added or reset here while the run was out"; st.PauseReason.Detail != want {
			t.Errorf("detail = %q, want %q", st.PauseReason.Detail, want)
		}
		if len(rep.NewWork) != 1 || rep.NewWork[0] != 19 {
			t.Errorf("new work = %v, want [19]", rep.NewWork)
		}
		// Paused before and paused after, for another reason: still a
		// change, or the merge would not save it.
		if !rep.Changed() || !rep.PauseChanged {
			t.Errorf("the report does not count the new pause as a change: %+v", rep)
		}
		sum := rep.Summary()
		if !strings.Contains(sum, "1 task was added or reset here while the run was out (#19), so the hub starts another run for it") {
			t.Errorf("the journal row does not say what the hub does about #19: %s", sum)
		}
		if strings.Contains(sum, "project paused") {
			t.Errorf("the journal row names the pause twice: %s", sum)
		}
	})

	t.Run("a task the hub reset while the run was out", func(t *testing.T) {
		// Failed when the seed was made, so not startable then; reset to
		// pending on the hub since.
		st := &state.ProjectState{Status: "complete", Plan: &pm.Plan{Tasks: []*pm.Task{
			pending(1, "a"),
			pending(2, "flaky one"),
		}}}
		sent := sentWith(pending(1, "a"), &pm.Task{ID: 2, Title: "flaky one", Status: pm.TaskFailed})
		rep, _ := Merge(st, &Result{Format: 1, Status: "complete", Tasks: []TaskChange{finished(1, "a")}},
			Provenance{Sent: sent}, nil, now)
		if st.PauseReason == nil || st.PauseReason.Code != pausereason.CodeWorkAdded || len(rep.NewWork) != 1 || rep.NewWork[0] != 2 {
			t.Fatalf("pause %+v, new work %v; want work_added for #2", st.PauseReason, rep.NewWork)
		}
		if rep.StatusFrom != "complete" || rep.StatusTo != "paused" {
			t.Errorf("status change %q → %q", rep.StatusFrom, rep.StatusTo)
		}
	})

	t.Run("a task whose ID now names another task", func(t *testing.T) {
		// The hub reuses an ID once its task is deleted: same ID, another
		// title, is another task, which the run never had.
		st := &state.ProjectState{Plan: &pm.Plan{Tasks: []*pm.Task{
			{ID: 1, Title: "a", Status: pm.TaskDone},
			pending(2, "a new task under an old number"),
		}}}
		sent := sentWith(pending(2, "the task that was deleted"))
		rep, _ := Merge(st, &Result{Format: 1, Status: "complete"}, Provenance{Sent: sent}, nil, now)
		if len(rep.NewWork) != 1 || rep.NewWork[0] != 2 {
			t.Fatalf("new work = %v (pause %+v), want [2]", rep.NewWork, st.PauseReason)
		}
	})

	t.Run("several tasks, named in full in the journal and in short on the badge", func(t *testing.T) {
		st := &state.ProjectState{Plan: &pm.Plan{Tasks: []*pm.Task{{ID: 1, Title: "a", Status: pm.TaskDone}}}}
		for id := 2; id <= 8; id++ {
			st.Plan.Tasks = append(st.Plan.Tasks, pending(id, "t"+string(rune('a'+id))))
		}
		rep, _ := Merge(st, &Result{Format: 1, Status: "complete"}, Provenance{Sent: sentWith()}, nil, now)
		if want := "7 tasks (#2, #3, #4, #5, #6, …) were added or reset here while the run was out"; st.PauseReason.Detail != want {
			t.Errorf("detail = %q, want %q", st.PauseReason.Detail, want)
		}
		if !strings.Contains(rep.Summary(), "(#2, #3, #4, #5, #6, #7, #8)") {
			t.Errorf("the journal row does not name every task: %s", rep.Summary())
		}
	})

	t.Run("a task the run was sent and did not start is left for a person", func(t *testing.T) {
		// Startable when it was sent, and the run came back without it: a
		// run started for it would decline it again, and the next one, and
		// the one after that.
		st := &state.ProjectState{Plan: &pm.Plan{Tasks: []*pm.Task{
			pending(1, "a"),
			pending(2, "declined on the device"),
		}}}
		sent := sentWith(pending(1, "a"), pending(2, "declined on the device"))
		rep, _ := Merge(st, &Result{Format: 1, Status: "complete", Tasks: []TaskChange{finished(1, "a")}},
			Provenance{Sent: sent}, nil, now)
		if len(rep.NewWork) != 0 || st.PauseReason == nil || st.PauseReason.Code != pausereason.CodeIdle {
			t.Fatalf("new work %v, pause %+v; want paused idle, nothing carried on", rep.NewWork, st.PauseReason)
		}
		if st.PauseReason.AutoResumable(now) {
			t.Error("a pause nobody may lift by a timer resumes by itself")
		}
		if want := "the run finished the plan it was sent; 1 task here is still pending (#2)"; st.PauseReason.Detail != want {
			t.Errorf("detail = %q, want %q", st.PauseReason.Detail, want)
		}
		if !strings.Contains(rep.Summary(), "(the run finished the plan it was sent; 1 task here is still pending (#2))") {
			t.Errorf("the journal row does not say why the project is paused: %s", rep.Summary())
		}
		if rep.ResumesAtOnce {
			t.Error("the hub would follow the run with another for work the run declined")
		}
	})

	t.Run("a task the run created itself is left for a person", func(t *testing.T) {
		st := &state.ProjectState{Plan: &pm.Plan{Tasks: []*pm.Task{pending(1, "a")}}}
		r := &Result{Format: 1, Status: "complete", Tasks: []TaskChange{
			finished(1, "a"),
			{After: &pm.Task{ID: 2, Title: "follow-up the agent filed", Status: pm.TaskPending}},
		}}
		rep, _ := Merge(st, r, Provenance{Sent: sentWith(pending(1, "a"))}, nil, now)
		if len(rep.Added) != 1 || len(rep.NewWork) != 0 || st.PauseReason == nil || st.PauseReason.Code != pausereason.CodeIdle {
			t.Fatalf("added %v, new work %v, pause %+v; want the created task added and left", rep.Added, rep.NewWork, st.PauseReason)
		}
	})

	t.Run("nothing a run could start: complete", func(t *testing.T) {
		// Pending, but blocked for good behind a failed task: a run here
		// calls that plan complete, and so does the hub.
		blocked := pending(3, "needs b")
		blocked.DependsOn = []int{2}
		st := &state.ProjectState{Status: "paused", Plan: &pm.Plan{Tasks: []*pm.Task{
			pending(1, "a"),
			{ID: 2, Title: "b", Status: pm.TaskFailed},
			blocked,
		}}}
		st.PauseReason = &pausereason.Reason{Code: pausereason.CodeIdle}
		rep, _ := Merge(st, &Result{Format: 1, Status: "complete", Tasks: []TaskChange{finished(1, "a")}},
			Provenance{Sent: sentWith(pending(1, "a"))}, nil, now)
		if st.Status != "complete" || st.PauseReason != nil || len(rep.NewWork) != 0 {
			t.Fatalf("status %q (%+v), new work %v; want complete", st.Status, st.PauseReason, rep.NewWork)
		}
	})

	t.Run("a closed review gate holds the rest", func(t *testing.T) {
		gate := pm.NewHumanGate("Review the attestation", "")
		gate.ID, gate.Priority = 2, 2
		st := &state.ProjectState{Plan: &pm.Plan{Tasks: []*pm.Task{pending(1, "a"), gate, pending(3, "after the gate")}}}
		rep, _ := Merge(st, &Result{Format: 1, Status: "complete", Tasks: []TaskChange{finished(1, "a")}},
			Provenance{Sent: sentWith(pending(1, "a"))}, nil, now)
		if st.PauseReason == nil || st.PauseReason.Code != pausereason.CodeApproval || st.PauseReason.TaskID != 2 {
			t.Fatalf("pause %+v, want waiting for approval at gate #2", st.PauseReason)
		}
		if len(rep.NewWork) != 0 {
			t.Errorf("new work %v behind a closed gate", rep.NewWork)
		}
	})

	t.Run("an idle device comes back to new work", func(t *testing.T) {
		// The device's other ordinary end: nothing it could start, with
		// work left that cannot start.
		st := &state.ProjectState{Plan: &pm.Plan{Tasks: []*pm.Task{pending(1, "a"), pending(2, "added")}}}
		idle := pausereason.New(pausereason.CodeIdle, "every runnable task is finished")
		rep, _ := Merge(st, &Result{Format: 1, Status: "paused", PauseReason: &idle, Tasks: []TaskChange{finished(1, "a")}},
			Provenance{Sent: sentWith(pending(1, "a"))}, nil, now)
		if st.PauseReason == nil || st.PauseReason.Code != pausereason.CodeWorkAdded || len(rep.NewWork) != 1 {
			t.Fatalf("pause %+v, new work %v; want work_added", st.PauseReason, rep.NewWork)
		}
	})

	t.Run("an idle device with nothing new settles as the hub's plan stands", func(t *testing.T) {
		// A task nothing will start — quarantined — keeps the project idle,
		// naming it; with nothing left at all it is complete.
		held := pending(2, "quarantined")
		held.Quarantine = &pm.TaskQuarantine{Kind: pm.QuarantineNodeKiller}
		st := &state.ProjectState{Plan: &pm.Plan{Tasks: []*pm.Task{pending(1, "a"), held}}}
		idle := pausereason.New(pausereason.CodeIdle, "every runnable task is finished")
		rep, _ := Merge(st, &Result{Format: 1, Status: "paused", PauseReason: &idle, Tasks: []TaskChange{finished(1, "a")}},
			Provenance{Sent: sentWith(pending(1, "a"))}, nil, now)
		if st.PauseReason == nil || st.PauseReason.Code != pausereason.CodeIdle ||
			!strings.Contains(st.PauseReason.Detail, "1 task here is still pending (#2)") || rep.ResumesAtOnce {
			t.Fatalf("pause %+v, want idle naming #2", st.PauseReason)
		}

		st = &state.ProjectState{Plan: &pm.Plan{Tasks: []*pm.Task{pending(1, "a")}}}
		Merge(st, &Result{Format: 1, Status: "paused", PauseReason: &idle, Tasks: []TaskChange{finished(1, "a")}},
			Provenance{Sent: sentWith(pending(1, "a"))}, nil, now)
		if st.Status != "complete" {
			t.Fatalf("status %q (%+v), want complete", st.Status, st.PauseReason)
		}
	})

	t.Run("any other pause stands", func(t *testing.T) {
		// A run that stopped for a reason stopped for that reason: a cap
		// lifts on its own schedule, and the run it resumes is given the
		// plan as it stands then.
		at := now.Add(time.Hour)
		for _, pr := range []pausereason.Reason{
			pausereason.NewUntil(pausereason.CodeUsageCap, "5-hour cap", at),
			pausereason.New(pausereason.CodeCancelled, "run interrupted"),
			pausereason.New(pausereason.CodeOperator, "run stopped"),
		} {
			pr := pr
			st := &state.ProjectState{Plan: &pm.Plan{Tasks: []*pm.Task{pending(1, "a"), pending(2, "added")}}}
			rep, _ := Merge(st, &Result{Format: 1, Status: "paused", PauseReason: &pr}, Provenance{Sent: sentWith(pending(1, "a"))}, nil, now)
			if st.PauseReason == nil || st.PauseReason.Code != pr.Code || len(rep.NewWork) != 0 {
				t.Errorf("%s: pause %+v, new work %v; want the run's own pause", pr.Code, st.PauseReason, rep.NewWork)
			}
		}
		for _, status := range []string{"failed", "running"} {
			st := &state.ProjectState{Plan: &pm.Plan{Tasks: []*pm.Task{pending(1, "a"), pending(2, "added")}}}
			rep, _ := Merge(st, &Result{Format: 1, Status: status}, Provenance{Sent: sentWith(pending(1, "a"))}, nil, now)
			if st.Status != status || len(rep.NewWork) != 0 {
				t.Errorf("%s: status %q, new work %v", status, st.Status, rep.NewWork)
			}
		}
	})

	t.Run("a progress report decides nothing", func(t *testing.T) {
		st := &state.ProjectState{Status: "paused", Plan: &pm.Plan{Tasks: []*pm.Task{pending(1, "a"), pending(2, "added")}}}
		st.PauseReason = &pausereason.Reason{Code: pausereason.CodeIdle}
		rep, _ := Merge(st, &Result{Format: 1, Status: "complete", Interim: true}, Provenance{Sent: sentWith(pending(1, "a"))}, nil, now)
		if st.PauseReason.Code != pausereason.CodeIdle || len(rep.NewWork) != 0 {
			t.Fatalf("an interim report changed the pause: %+v, new work %v", st.PauseReason, rep.NewWork)
		}
	})

	t.Run("a task the run reported on is never new work", func(t *testing.T) {
		// One the run set back to pending — a device that wants the hub to
		// keep starting runs on its say — and one it finished under a title
		// the hub has changed since, whose outcome the merge did not apply.
		reverted := TaskChange{
			Before: &pm.Task{ID: 2, Title: "done once", Status: pm.TaskDone},
			After:  &pm.Task{ID: 2, Title: "done once", Status: pm.TaskPending},
		}
		renamed := finished(3, "old title")
		st := &state.ProjectState{Plan: &pm.Plan{Tasks: []*pm.Task{
			{ID: 1, Title: "a", Status: pm.TaskDone},
			{ID: 2, Title: "done once", Status: pm.TaskDone},
			pending(3, "new title"),
		}}}
		sent := sentWith(pending(3, "old title"))
		rep, _ := Merge(st, &Result{Format: 1, Status: "complete", Tasks: []TaskChange{reverted, renamed}},
			Provenance{Sent: sent}, nil, now)
		if len(rep.NewWork) != 0 || rep.ResumesAtOnce {
			t.Fatalf("new work %v (pause %+v): the hub would start runs for tasks the run reported on",
				rep.NewWork, st.PauseReason)
		}
		if st.PauseReason == nil || st.PauseReason.Code != pausereason.CodeIdle {
			t.Errorf("pause %+v, want idle naming what is left", st.PauseReason)
		}
	})

	t.Run("work_added is the hub's to decide, never a device's", func(t *testing.T) {
		st := &state.ProjectState{Plan: &pm.Plan{Tasks: []*pm.Task{pending(1, "a")}}}
		forged := pausereason.NewUntil(pausereason.CodeWorkAdded, "task #1 was added", now)
		rep, _ := Merge(st, &Result{Format: 1, Status: "paused", PauseReason: &forged},
			Provenance{Sent: sentWith(pending(1, "a"))}, nil, now)
		if st.PauseReason == nil || st.PauseReason.Code == pausereason.CodeWorkAdded || rep.ResumesAtOnce {
			t.Fatalf("pause %+v, resumes at once %v: a device's work_added was taken", st.PauseReason, rep.ResumesAtOnce)
		}
	})

	t.Run("a run the hub was asked to stop is not followed by another", func(t *testing.T) {
		st := &state.ProjectState{Plan: &pm.Plan{Tasks: []*pm.Task{pending(1, "a"), pending(2, "added")}}}
		rep, _ := merge(st, &Result{Format: 1, Status: "complete", Tasks: []TaskChange{finished(1, "a")}},
			Provenance{Sent: sentWith(pending(1, "a"))}, nil, now, mergeOptions{stopRequested: true})
		if st.PauseReason == nil || st.PauseReason.Code != pausereason.CodeOperator || rep.ResumesAtOnce ||
			rep.HeldBy != HeldByStop {
			t.Fatalf("pause %+v, held by %q, resumes at once %v; want stopped", st.PauseReason, rep.HeldBy, rep.ResumesAtOnce)
		}
		if !strings.Contains(st.PauseReason.Detail, "task #2 was added or reset here while the run was out") ||
			!strings.Contains(rep.Summary(), "the run was asked to stop, so the hub does not start another for it") {
			t.Errorf("detail %q, journal %q", st.PauseReason.Detail, rep.Summary())
		}
	})

	t.Run("a project on an executor pool waits for a person to queue its run", func(t *testing.T) {
		st := &state.ProjectState{Plan: &pm.Plan{Tasks: []*pm.Task{pending(1, "a"), pending(2, "added")}}}
		rep, _ := Merge(st, &Result{Format: 1, Status: "complete", Tasks: []TaskChange{finished(1, "a")}},
			Provenance{Sent: sentWith(pending(1, "a")), Pooled: true}, nil, now)
		if st.PauseReason == nil || st.PauseReason.Code != pausereason.CodeIdle || rep.ResumesAtOnce || rep.HeldBy != HeldByPool {
			t.Fatalf("pause %+v, held by %q; want idle, waiting for Run", st.PauseReason, rep.HeldBy)
		}
		if !strings.Contains(st.PauseReason.Detail, "press Run to queue a run") ||
			!strings.Contains(rep.Summary(), "press Run to queue a run for it") {
			t.Errorf("detail %q, journal %q", st.PauseReason.Detail, rep.Summary())
		}
	})

	t.Run("a gate approved on the hub while the run waited at it", func(t *testing.T) {
		gate := pm.NewHumanGate("Review", "")
		gate.ID, gate.Priority = 2, 2
		approved := *gate
		approved.Approved = true
		behind := pending(3, "after the gate")
		st := &state.ProjectState{Plan: &pm.Plan{Tasks: []*pm.Task{{ID: 1, Title: "a", Status: pm.TaskDone}, &approved, behind}}}
		atGate := pausereason.NewForTask(pausereason.CodeApproval, "waiting for human review at gate #2: Review", 2)
		rep, _ := Merge(st, &Result{Format: 1, Status: "paused", PauseReason: &atGate},
			Provenance{Sent: sentWith(&pm.Task{ID: 1, Title: "a", Status: pm.TaskDone}, gate, pending(3, "after the gate"))}, nil, now)
		if st.PauseReason == nil || st.PauseReason.Code != pausereason.CodeWorkAdded || len(rep.NewWork) != 1 || rep.NewWork[0] != 3 {
			t.Fatalf("pause %+v, new work %v; want the run carried on past the approved gate", st.PauseReason, rep.NewWork)
		}

		// Still closed on the hub: the run's own account of where it waits.
		st = &state.ProjectState{Plan: &pm.Plan{Tasks: []*pm.Task{{ID: 1, Title: "a", Status: pm.TaskDone}, gate, pending(3, "after the gate")}}}
		rep, _ = Merge(st, &Result{Format: 1, Status: "paused", PauseReason: &atGate},
			Provenance{Sent: sentWith(&pm.Task{ID: 1, Title: "a", Status: pm.TaskDone}, gate, pending(3, "after the gate"))}, nil, now)
		if st.PauseReason == nil || st.PauseReason.Code != pausereason.CodeApproval || st.PauseReason.TaskID != 2 || len(rep.NewWork) != 0 {
			t.Fatalf("pause %+v, new work %v; want waiting at gate #2", st.PauseReason, rep.NewWork)
		}
	})

	t.Run("a declined approval is a person's, and stands", func(t *testing.T) {
		st := &state.ProjectState{Plan: &pm.Plan{Tasks: []*pm.Task{pending(1, "needs approval"), pending(2, "added")}}}
		declined := pausereason.NewForTask(pausereason.CodeApproval, "approval declined for task #1", 1)
		rep, _ := Merge(st, &Result{Format: 1, Status: "paused", PauseReason: &declined},
			Provenance{Sent: sentWith(pending(1, "needs approval"))}, nil, now)
		if st.PauseReason == nil || st.PauseReason.Code != pausereason.CodeApproval || len(rep.NewWork) != 0 {
			t.Fatalf("pause %+v, new work %v; want the declined approval", st.PauseReason, rep.NewWork)
		}
	})

	t.Run("a readers change the device stopped for is followed at once", func(t *testing.T) {
		st := &state.ProjectState{Plan: &pm.Plan{Tasks: []*pm.Task{pending(1, "a")}}}
		rc := pausereason.NewUntil(pausereason.CodeReadersChanged, "bravo no longer lists it", now)
		rep, _ := Merge(st, &Result{Format: 1, Status: "paused", PauseReason: &rc}, Provenance{Sent: sentWith(pending(1, "a"))}, nil, now)
		if !rep.ResumesAtOnce {
			t.Fatalf("pause %+v not followed at once", st.PauseReason)
		}
	})

	t.Run("a dispatch recorded before the seed's work was", func(t *testing.T) {
		// Nothing says what the seed held: every startable task the run did
		// not create counts, once — the run started for it is recorded.
		st := &state.ProjectState{Plan: &pm.Plan{Tasks: []*pm.Task{pending(1, "a"), pending(2, "added")}}}
		rep, _ := Merge(st, &Result{Format: 1, Status: "complete", Tasks: []TaskChange{finished(1, "a")}}, Provenance{}, nil, now)
		if len(rep.NewWork) != 1 || rep.NewWork[0] != 2 {
			t.Fatalf("new work %v (pause %+v), want [2]", rep.NewWork, st.PauseReason)
		}
	})
}

// The record of a seed survives the run's owner row, which carries the
// provenance to a hub member that adopts the run: a seed that held nothing to
// start must still read as recorded, not as a dispatch older than the record.
func TestTheSeedsWorkSurvivesTheOwnerRow(t *testing.T) {
	for _, sent := range []*SeedWork{
		{Startable: map[int]string{}},
		{Startable: map[int]string{4: TitleDigest("four")}},
	} {
		raw, err := jsonRoundTrip(Provenance{RunID: "r1", Sent: sent})
		if err != nil {
			t.Fatal(err)
		}
		if raw.Sent == nil {
			t.Fatalf("%+v came back as no record at all", sent)
		}
		if len(raw.Sent.Startable) != len(sent.Startable) || raw.Sent.Startable[4] != sent.Startable[4] {
			t.Errorf("startable = %v, want %v", raw.Sent.Startable, sent.Startable)
		}
	}
	raw, err := jsonRoundTrip(Provenance{RunID: "r1"})
	if err != nil || raw.Sent != nil {
		t.Errorf("a dispatch with no record gained one: %+v, %v", raw.Sent, err)
	}
}

// jsonRoundTrip writes p as the run's owner row carries it and reads it back.
func jsonRoundTrip(p Provenance) (Provenance, error) {
	raw, err := json.Marshal(p)
	if err != nil {
		return Provenance{}, err
	}
	var out Provenance
	err = json.Unmarshal(raw, &out)
	return out, err
}
