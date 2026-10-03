package orchestrator

// Recovery must not resurrect a task the orchestrator rejected (Task 20365).
//
// Each test drives a real run to the point where the orchestrator has
// overridden its agent — the agent printed TASK_DONE, or asked questions, or
// left work running — and fails the outcome write that would have stored the
// override, so the run stops with the task still in progress in the database:
// exactly what a run that dies there leaves behind. A second orchestrator's
// stale-task recovery then reads the project, and the task must come back as
// the first one decided, not as the agent's transcript says.

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/taskrecover"
)

// failWritesOnceArmed fails every merging state write after armed is set, and
// performs every write before it. A test arms it at the moment the override is
// decided, which makes the outcome write — the next critical one — fail.
func failWritesOnceArmed(t *testing.T) *atomic.Bool {
	t.Helper()
	armed := new(atomic.Bool)
	withFailingSave(t, func(_ *state.ProjectState, mode saveMode) bool {
		return armed.Load() && mode == mergeExternal
	})
	return armed
}

// scriptedAgent answers the task prompt with output (and background), and the
// orchestrator's own checks as configured. It arms the failing store when the
// call it is told to arm on arrives.
type scriptedAgent struct {
	armed      *atomic.Bool
	output     string
	background *provider.BackgroundActivity
	// verify and script answer --verify and --script-verify.
	verify string
	script string
	// armOn names the call that decides the override: "task", "verify" or
	// "script".
	armOn string

	mu    sync.Mutex
	tasks int
}

func (a *scriptedAgent) Complete(_ context.Context, prompt string, _ provider.Options) (*provider.Result, error) {
	kind := "task"
	switch {
	case strings.Contains(prompt, "VERIFY_PASS — the task is genuinely complete"):
		kind = "verify"
	case strings.Contains(prompt, "shell verification script"):
		kind = "script"
	}
	if kind == a.armOn && a.armed != nil {
		a.armed.Store(true)
	}
	switch kind {
	case "verify":
		return &provider.Result{Output: a.verify, Provider: "scripted"}, nil
	case "script":
		return &provider.Result{Output: a.script, Provider: "scripted"}, nil
	}
	a.mu.Lock()
	a.tasks++
	a.mu.Unlock()
	return &provider.Result{Output: a.output, Background: a.background, Provider: "scripted", Model: "m"}, nil
}
func (a *scriptedAgent) Name() string         { return "scripted" }
func (a *scriptedAgent) DefaultModel() string { return "m" }

func (a *scriptedAgent) taskCalls() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.tasks
}

// singleTaskProject is a project with one pending task, task #1.
func singleTaskProject(t *testing.T, parallel bool) string {
	t.Helper()
	dir := tempDir(t)
	s := initState(t, dir, "verdicts", 0)
	s.PMMode, s.Parallel = true, parallel
	if parallel {
		s.MaxParallel = 2
	}
	s.Plan = &pm.Plan{Goal: s.Goal, Tasks: []*pm.Task{
		{ID: 1, Title: "write the report", Description: "do it", Priority: 1, Status: pm.TaskPending},
	}}
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
	return dir
}

func withMode(cfg Config, dir string, parallel bool) Config {
	cfg.WorkDir, cfg.PMMode = dir, true
	if parallel {
		cfg.Parallel, cfg.MaxParallel = true, 2
	}
	return cfg
}

// stopBeforeOutcome runs o and checks it stopped on the failed outcome write
// with task #1 still in progress on disk — the state a dying run leaves. Then
// it lets writes through again, as an operator who freed the disk would,
// before the next run's recovery.
func stopBeforeOutcome(t *testing.T, o *Orchestrator, dir string, armed *atomic.Bool) {
	t.Helper()
	err := runBounded(t, o)
	armed.Store(false)
	if !errors.Is(err, ErrStateNotPersisted) {
		t.Fatalf("Run = %v, want it to stop on the failed outcome write", err)
	}
	if got := reload(t, dir).Plan.TaskByID(1); got.Status != pm.TaskInProgress {
		t.Fatalf("stored status = %q after the failed write; the test needs the run to have left it in progress", got.Status)
	}
}

// recoverWith runs a fresh orchestrator's stale-task recovery over dir, as the
// next `cloop run` does before it schedules anything, and returns task #1 as
// stored afterwards.
func recoverWith(t *testing.T, dir string) (*pm.Task, *scriptedAgent) {
	t.Helper()
	agent := &scriptedAgent{output: "Did it again.\nTASK_DONE"}
	o := newOrchestrator(t, dir, Config{WorkDir: dir, PMMode: true}, agent)
	t.Cleanup(func() { _ = o.Close() })
	if err := o.recoverStaleTasks(o.state); err != nil {
		t.Fatalf("recoverStaleTasks: %v", err)
	}
	return reload(t, dir).Plan.TaskByID(1), agent
}

// assertRecoveredAs checks that the recovered task carries the orchestrator's
// decision and says so.
func assertRecoveredAs(t *testing.T, task *pm.Task, want pm.TaskStatus, source string) {
	t.Helper()
	if task.Status != want {
		t.Fatalf("recovered as %q, want %q — recovery followed the agent, not the orchestrator", task.Status, want)
	}
	if !taskHasAnnotation(task, "cloop", source) {
		var notes []string
		for _, a := range task.Annotations {
			notes = append(notes, a.Author+": "+a.Text)
		}
		t.Errorf("no recovery note naming %q:\n  %s", source, strings.Join(notes, "\n  "))
	}
}

func TestRecovery_ReviewGateRejection(t *testing.T) {
	eachPath(t, func(t *testing.T, parallel bool) {
		repo := gateProject(t, &pm.ReviewGate{Enabled: true, Mode: pm.ReviewModeBlock}, "Add division")
		if parallel {
			s := reload(t, repo)
			s.Parallel, s.MaxParallel = true, 2
			if err := s.Save(); err != nil {
				t.Fatal(err)
			}
		}
		armed := failWritesOnceArmed(t)
		worker := &gateWorker{do: func(dir, _ string, _ int) string {
			commitFile(dir, "calc.txt", "a / b\n")
			return "Committed the division.\nTASK_DONE"
		}}
		reviewer := &gateReviewer{decide: func(string, int) string {
			armed.Store(true)
			return requestChanges
		}}
		o := newOrchestrator(t, repo, withMode(Config{ReviewProvider: reviewer}, repo, parallel), worker)
		stopBeforeOutcome(t, o, repo, armed)

		got, agent := recoverWith(t, repo)
		assertRecoveredAs(t, got, pm.TaskFailed, "review gate")
		if !strings.Contains(got.FailureDiagnosis, "division by zero") {
			t.Errorf("diagnosis = %q, want the reviewer's finding", got.FailureDiagnosis)
		}
		if got.Review == nil || !got.Review.Blocked {
			t.Errorf("review record = %+v", got.Review)
		}
		if agent.taskCalls() != 0 {
			t.Error("recovery ran the task again")
		}
		rows := journalRows(t, repo, state.EventTaskFailed, 1)
		if len(rows) == 0 || !strings.Contains(rows[len(rows)-1].Details, `"verdict_source":"review_gate"`) {
			t.Errorf("the journal does not record the recovery as the gate's decision: %+v", rows)
		}
	})
}

func TestRecovery_FailedVerification(t *testing.T) {
	for _, tc := range []struct {
		name string
		// retries is the task's VerifyRetries before the run: at the budget,
		// a failure is final; below it, the task goes back to pending.
		retries int
		want    pm.TaskStatus
	}{
		{"requeued", 0, pm.TaskPending},
		{"exhausted", 2, pm.TaskFailed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := singleTaskProject(t, false)
			s := reload(t, dir)
			s.Plan.TaskByID(1).VerifyRetries = tc.retries
			if err := s.Save(); err != nil {
				t.Fatal(err)
			}
			armed := failWritesOnceArmed(t)
			agent := &scriptedAgent{armed: armed, armOn: "verify", output: "Wrote it.\nTASK_DONE",
				verify: "The file is missing.\nVERIFY_FAIL"}
			o := newOrchestrator(t, dir, withMode(Config{Verify: true}, dir, false), agent)
			stopBeforeOutcome(t, o, dir, armed)

			got, _ := recoverWith(t, dir)
			assertRecoveredAs(t, got, tc.want, "verif")
		})
	}
}

func TestRecovery_FailedShellVerification(t *testing.T) {
	dir := singleTaskProject(t, false)
	armed := failWritesOnceArmed(t)
	agent := &scriptedAgent{armed: armed, armOn: "script", output: "Wrote it.\nTASK_DONE",
		script: "```bash\nexit 1\n```"}
	o := newOrchestrator(t, dir, withMode(Config{ScriptVerify: true}, dir, false), agent)
	stopBeforeOutcome(t, o, dir, armed)

	got, _ := recoverWith(t, dir)
	assertRecoveredAs(t, got, pm.TaskFailed, "script verify")
}

func TestRecovery_AbandonedBackgroundWork(t *testing.T) {
	eachPath(t, func(t *testing.T, parallel bool) {
		dir := singleTaskProject(t, parallel)
		armed := failWritesOnceArmed(t)
		agent := &scriptedAgent{armed: armed, armOn: "task",
			output: "Started training in the background; the model will be ready soon.\nTASK_DONE",
			background: &provider.BackgroundActivity{Detected: 1, Commands: []string{"python train.py"},
				Waited: 3 * time.Second, Terminated: 1}}
		o := newOrchestrator(t, dir, withMode(Config{}, dir, parallel), agent)
		stopBeforeOutcome(t, o, dir, armed)

		got, _ := recoverWith(t, dir)
		assertRecoveredAs(t, got, pm.TaskFailed, "background")
		if got.Background == nil || got.Background.State != pm.BackgroundAbandoned {
			t.Errorf("background record = %+v", got.Background)
		}
		if !strings.Contains(got.FailureDiagnosis, "background process") {
			t.Errorf("diagnosis = %q", got.FailureDiagnosis)
		}
	})
}

func TestRecovery_UnansweredClarification(t *testing.T) {
	eachPath(t, func(t *testing.T, parallel bool) {
		dir := singleTaskProject(t, parallel)
		armed := failWritesOnceArmed(t)
		agent := &scriptedAgent{armed: armed, armOn: "task",
			output: "Before I proceed: should I write it as Markdown or HTML? Could you clarify?"}
		o := newOrchestrator(t, dir, withMode(Config{}, dir, parallel), agent)
		stopBeforeOutcome(t, o, dir, armed)

		// Without the verdict this would come back pending: the transcript
		// has no signal. The orchestrator failed it.
		got, _ := recoverWith(t, dir)
		assertRecoveredAs(t, got, pm.TaskFailed, "clarification")
	})
}

func TestRecovery_UnfinishedTurn(t *testing.T) {
	eachPath(t, func(t *testing.T, parallel bool) {
		dir := singleTaskProject(t, parallel)
		armed := failWritesOnceArmed(t)
		agent := &scriptedAgent{armed: armed, armOn: "task",
			output: "Implemented the report. The test suite is still running; I'll commit once it finishes."}
		o := newOrchestrator(t, dir, withMode(Config{}, dir, parallel), agent)
		stopBeforeOutcome(t, o, dir, armed)

		got, _ := recoverWith(t, dir)
		if got.Status != pm.TaskPending {
			t.Fatalf("recovered as %q, want pending", got.Status)
		}
		if !taskHasAnnotation(got, "cloop", "unfinished_turn") {
			t.Errorf("the requeue does not carry the orchestrator's reason: %+v", got.Annotations)
		}
	})
}

// The control: with no override, the verdict is the agent's own outcome and
// recovery adopts it as it always did.
func TestRecovery_AcceptedOutcomeIsAdopted(t *testing.T) {
	eachPath(t, func(t *testing.T, parallel bool) {
		dir := singleTaskProject(t, parallel)
		armed := failWritesOnceArmed(t)
		agent := &scriptedAgent{armed: armed, armOn: "task", output: "Wrote the report.\nTASK_DONE"}
		o := newOrchestrator(t, dir, withMode(Config{}, dir, parallel), agent)
		stopBeforeOutcome(t, o, dir, armed)

		got, again := recoverWith(t, dir)
		assertRecoveredAs(t, got, pm.TaskDone, "agent")
		if again.taskCalls() != 0 {
			t.Error("recovery ran a finished task again")
		}
	})
}

// A new attempt must not be judged by the last one's verdict: the sidecar is
// gone before the agent starts.
func TestVerdict_ClearedWhenAnAttemptStarts(t *testing.T) {
	eachPath(t, func(t *testing.T, parallel bool) {
		dir := singleTaskProject(t, parallel)
		future := time.Now().Add(24 * time.Hour)
		if err := taskrecover.WriteVerdict(dir, taskrecover.Verdict{TaskID: 1, Status: pm.TaskFailed,
			Source: taskrecover.SourceReviewGate, WrittenAt: future}); err != nil {
			t.Fatal(err)
		}
		var during error
		agent := &probeAgent{probe: func() { _, during = taskrecover.ReadVerdict(dir, 1) }}
		o := newOrchestrator(t, dir, withMode(Config{}, dir, parallel), agent)
		if err := runBounded(t, o); err != nil {
			t.Fatalf("Run: %v", err)
		}
		if during != taskrecover.ErrNoVerdict {
			t.Fatalf("while the agent ran, the previous verdict was still there (err = %v)", during)
		}
		v, err := taskrecover.ReadVerdict(dir, 1)
		if err != nil || v.Status != pm.TaskDone || v.Source != taskrecover.SourceAgent {
			t.Fatalf("after the run the verdict is %+v (%v), want this attempt's", v, err)
		}
	})
}

// While the review gate has the task, its verdict says so: a run that dies
// mid-review must not have the agent's unreviewed TASK_DONE adopted.
func TestVerdict_AwaitsTheReviewGate(t *testing.T) {
	repo := gateProject(t, &pm.ReviewGate{Enabled: true, Mode: pm.ReviewModeBlock}, "Add division")
	worker := &gateWorker{do: func(dir, _ string, _ int) string {
		commitFile(dir, "calc.txt", "a / b\n")
		return "done\nTASK_DONE"
	}}
	var during *taskrecover.Verdict
	reviewer := &gateReviewer{decide: func(string, int) string {
		during, _ = taskrecover.ReadVerdict(repo, 1)
		return approve
	}}
	o := newOrchestrator(t, repo, Config{WorkDir: repo, PMMode: true, ReviewProvider: reviewer}, worker)
	if err := o.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !during.AwaitingReview() {
		t.Fatalf("during the review the verdict was %+v, want one awaiting the gate", during)
	}
	if v, err := taskrecover.ReadVerdict(repo, 1); err != nil || v.Status != pm.TaskDone ||
		v.Source != taskrecover.SourceReviewGate || v.Reason != "review_approved" {
		t.Fatalf("after approval the verdict is %+v (%v)", v, err)
	}
}

// probeAgent finishes the task, calling probe first.
type probeAgent struct{ probe func() }

func (p *probeAgent) Complete(_ context.Context, _ string, _ provider.Options) (*provider.Result, error) {
	if p.probe != nil {
		p.probe()
	}
	return &provider.Result{Output: "Wrote the report.\nTASK_DONE", Provider: "probe"}, nil
}
func (p *probeAgent) Name() string         { return "probe" }
func (p *probeAgent) DefaultModel() string { return "m" }

// The run's other way of leaving a task: stopping under it. The verdict says
// pending, so a recovery that runs before the stop is recorded agrees.
func TestVerdict_StopRecordsTheReturnToPending(t *testing.T) {
	dir := singleTaskProject(t, false)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	agent := &blockingAgent{started: make(chan struct{})}
	o := newOrchestrator(t, dir, Config{WorkDir: dir, PMMode: true}, agent)
	done := make(chan error, 1)
	go func() { done <- o.Run(ctx) }()
	<-agent.started
	cancel()
	<-done
	v, err := taskrecover.ReadVerdict(dir, 1)
	if err != nil || v.Status != pm.TaskPending || v.Source != taskrecover.SourceInterrupted {
		t.Fatalf("verdict after a stop = %+v (%v)", v, err)
	}
}

// blockingAgent blocks until its context ends.
type blockingAgent struct {
	started chan struct{}
	once    sync.Once
}

func (b *blockingAgent) Complete(ctx context.Context, _ string, _ provider.Options) (*provider.Result, error) {
	b.once.Do(func() { close(b.started) })
	<-ctx.Done()
	return nil, ctx.Err()
}
func (b *blockingAgent) Name() string         { return "blocking" }
func (b *blockingAgent) DefaultModel() string { return "m" }

// The verdict is written before the outcome write, and a verdict that cannot
// be written does not stop the run: the outcome write is the record.
func TestVerdict_UnwritableSidecarDoesNotStopTheRun(t *testing.T) {
	dir := singleTaskProject(t, false)
	// A directory where the sidecar belongs makes every write of it fail.
	if err := os.MkdirAll(taskrecover.VerdictPath(dir, 1), 0o755); err != nil {
		t.Fatal(err)
	}
	o := newOrchestrator(t, dir, Config{WorkDir: dir, PMMode: true}, &probeAgent{})
	if err := runBounded(t, o); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := reload(t, dir).Plan.TaskByID(1); got.Status != pm.TaskDone {
		t.Fatalf("status = %q", got.Status)
	}
}

// The decisions written ahead of the consumer must be the ones it makes, in
// the order it makes them; otherwise a run that dies in between is recovered
// as something the orchestrator would never have decided.
func TestVerdictHelpersMirrorTheOutcomeRules(t *testing.T) {
	running := &provider.BackgroundActivity{Detected: 1, Drained: false}
	drained := &provider.BackgroundActivity{Detected: 1, Drained: true}
	question := "Before I proceed: should I use Markdown or HTML? Could you clarify?"
	blocked := &gateOutcome{fail: true, review: &pm.TaskReview{Verdict: pm.ReviewChangesRequested, Blocked: true}, note: "blocked"}
	approved := &gateOutcome{review: &pm.TaskReview{Verdict: pm.ReviewApproved}, note: "approved"}

	early := []struct {
		name           string
		output         string
		bg             *provider.BackgroundActivity
		clarifyRetries bool
		want           pm.TaskStatus
		source         string
	}{
		{"clean completion decides nothing yet", "done\nTASK_DONE", nil, false, "", ""},
		{"drained work is fine", "done\nTASK_DONE", drained, false, "", ""},
		{"running work fails a completion", "done\nTASK_DONE", running, false, pm.TaskFailed, taskrecover.SourceBackground},
		{"running work does not override a failure", "no\nTASK_FAILED", running, false, "", ""},
		{"a question fails the task without a retry loop", question, nil, false, pm.TaskFailed, taskrecover.SourceClarification},
		{"a question waits for the retry loop", question, running, true, "", ""},
	}
	for _, tc := range early {
		status, why, _, ok := earlyVerdict(tc.output, tc.bg, tc.clarifyRetries)
		if ok != (tc.want != "") || status != tc.want || why.source != tc.source {
			t.Errorf("earlyVerdict(%s) = %q %q %v, want %q %q", tc.name, status, why.source, ok, tc.want, tc.source)
		}
	}

	gated := []struct {
		name   string
		out    *gateOutcome
		output string
		bg     *provider.BackgroundActivity
		want   pm.TaskStatus
		reason string
	}{
		{"a block fails the task", blocked, "done\nTASK_DONE", nil, pm.TaskFailed, "review_blocked"},
		{"a block leaves a skip alone", blocked, "n/a\nTASK_SKIPPED", nil, pm.TaskSkipped, "agent_skipped"},
		{"a fix turn that asks questions fails", approved, question, running, pm.TaskFailed, "clarification_unanswered"},
		{"a fix turn that left work running fails", approved, "done\nTASK_DONE", running, pm.TaskFailed, "background_abandoned"},
		{"an approval completes", approved, "done\nTASK_DONE", nil, pm.TaskDone, "review_approved"},
		{"an approved unsignalled turn is left to the default arm", approved, "I made the change.", nil, "", ""},
	}
	for _, tc := range gated {
		status, why, _, ok := gateVerdict(tc.out, tc.output, tc.bg)
		if ok != (tc.want != "") || status != tc.want || why.reason != tc.reason {
			t.Errorf("gateVerdict(%s) = %q %q %v, want %q %q", tc.name, status, why.reason, ok, tc.want, tc.reason)
		}
	}
}
