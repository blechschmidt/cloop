package orchestrator

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
)

// TestLooksLikeUnfinishedTurn: the positives are final messages this project's
// ledger recorded as implicitly completed, verbatim or nearly; the negatives
// are finished turns that use the same words.
func TestLooksLikeUnfinishedTurn(t *testing.T) {
	unfinished := []string{
		"The full test suite is still running; I'll continue with commit and push once it reports.",
		"`gofmt` and `go vet` are clean for `pkg/ui`. The race suite has about 10 minutes left. When it finishes I'll check the result, run the full `go build` + `go vet ./...`, then commit and push.",
		"The full `pkg/ui` suite is still running in the background. I'll pick up when it finishes: per-commit build checks, then push.",
		"Waiting on CI. The implementation is complete, pushed as `f6b88f5`, and validated locally.",
		"The implementation is complete and pushed. Waiting on CI for the final commit.",
		"My monitors are armed and will notify me — foreground sleeps are blocked, so I'll wait for them rather than poll.",
		"Both waiters are armed (CI jobs, and the deploy picking up my commit). Holding for those two signals — I won't call this done until they report.",
		"CI runs for the final commit aren't registered yet. Waiting for the monitor.",
		"**Status while `pkg/ui` runs.** Here's where things stand.",
		"Verification is in progress. Status while the full `pkg/ui` suite runs in an isolated worktree:",
		"Nothing further to do until the suite lands. The monitor is armed and will report the result; I\u2019ll then clear the build cache, push, and confirm the deploy.",
		// Task 20368, recorded done with 24 changed paths uncommitted
		// (Task 20370): nothing in the original sixteen patterns matched it.
		task20368FinalMessage,
		"Monitor armed for the full run conclusion. The eval-stack job itself is already verified green on the runner.",
	}
	for _, out := range unfinished {
		if !looksLikeUnfinishedTurn(out) {
			t.Errorf("not recognised as an unfinished turn:\n%s", out)
		}
	}

	finished := []string{
		"Task complete. Everything is committed, pushed, and verified.",
		"That was the final monitor draining its stream — no new information, and nothing left running. Task 20300 is complete.",
		"Everything is clean — nothing of mine is still running, and the working tree is exactly as I found it.",
		"The deploy timer is armed, the hub answers 200, and my commit changes zero production files.",
		"The CI run for my push was still in progress when I finished and will likely stay red on these; they need their own fix.",
		"Committed and pushed as `d32919a`. The agent now waits on the hub's reply before it retries.",
		"Nothing still running — every test run has finished, and the work is committed and pushed as a5a45c5.",
		"No review agent is still running, and the commit is pushed.",
		"I committed the fix, then pushed it to main, and CI passed.",
		"The timer that deploys main is armed for 04:30; everything is committed and pushed.",
		"",
	}
	for _, out := range finished {
		if looksLikeUnfinishedTurn(out) {
			ev, _ := unfinishedTurnEvidence(out)
			t.Errorf("a finished turn read as unfinished (matched %q):\n%s", ev, out)
		}
	}

	// A long summary: the words in its middle describe the work, not the turn.
	long := "Task complete; committed as abc1234.\n\n" +
		strings.Repeat("Details of the change and why it was made. ", 40) +
		"The orchestrator now says the suite is still running when a harness waits on it, " +
		"and it will notify me that way in the log. " +
		strings.Repeat("More detail about the fix and its tests. ", 40) +
		"\n\nEverything is pushed and verified."
	if looksLikeUnfinishedTurn(long) {
		t.Error("a finished summary was read as unfinished from words in its middle")
	}
}

// task20368FinalMessage is how Task 20368's turn ended, verbatim.
const task20368FinalMessage = "The commit message is drafted. The only thing still running is the adversarial " +
	"review agent. I'll address what it finds, re-run `-race` on the touched packages, then commit and push."

// TestTask20368EndingIsCaughtTwice: the message that stranded Task 20368 is
// matched by two patterns independently — the "still running" after a noun,
// and the promise to commit and push afterwards — so loosening either one
// alone does not let it through again.
func TestTask20368EndingIsCaughtTwice(t *testing.T) {
	hits := 0
	for _, rx := range unfinishedTurnPatterns {
		if rx.MatchString(task20368FinalMessage) {
			hits++
		}
	}
	if hits < 2 {
		t.Errorf("Task 20368's ending matches %d pattern(s), want at least 2", hits)
	}
}

// TestUnfinishedTurnLedger re-checks the patterns against a project's ledger
// of final messages: the task artifacts in <project>/.cloop/tasks, one per
// task, the frontmatter followed by the agent's final message. No message that
// ended with a TASK_* signal may match — those are never handed back, and a
// pattern that matches finished work is a pattern that will hand back a
// finished turn without one. It runs only when CLOOP_LEDGER_DIR names such a
// directory, since a ledger is a project's history and not the repository's.
func TestUnfinishedTurnLedger(t *testing.T) {
	dir := os.Getenv("CLOOP_LEDGER_DIR")
	if dir == "" {
		t.Skip("set CLOOP_LEDGER_DIR to a project's .cloop/tasks to re-check the patterns against its ledger")
	}
	files, err := filepath.Glob(filepath.Join(dir, "*.md"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no task artifacts in %s (%v)", dir, err)
	}
	var signalled, unsignalled, caught int
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		body := string(b)
		if strings.HasPrefix(body, "---\n") {
			if i := strings.Index(body[4:], "\n---\n"); i >= 0 {
				body = body[4+i+5:]
			}
		}
		ev, hit := unfinishedTurnEvidence(body)
		if pm.CheckTaskSignal(body) != pm.TaskInProgress {
			signalled++
			if hit {
				t.Errorf("%s ended with a signal, but reads as unfinished (matched %q)", filepath.Base(f), ev)
			}
			continue
		}
		unsignalled++
		if hit {
			caught++
		}
	}
	t.Logf("%d signalled, none matched; %d of %d unsignalled read as unfinished", signalled, caught, unsignalled)
}

// turnProvider plays a scripted conversation and records what each call asked.
type turnProvider struct {
	mu      sync.Mutex
	results []*provider.Result
	prompts []string
	resumes []string
}

func (p *turnProvider) Complete(ctx context.Context, prompt string, opts provider.Options) (*provider.Result, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	i := len(p.prompts)
	p.prompts = append(p.prompts, prompt)
	p.resumes = append(p.resumes, opts.ResumeSession)
	if i < len(p.results) {
		r := *p.results[i]
		return &r, nil
	}
	return &provider.Result{Output: "done\nTASK_DONE"}, nil
}

func (p *turnProvider) Name() string         { return "turns" }
func (p *turnProvider) DefaultModel() string { return "turns-model" }

const waitingTurn = "The full test suite is still running; I'll commit and push once it reports."

func TestCompleteTaskResumesAnUnfinishedTurn(t *testing.T) {
	prov := &turnProvider{results: []*provider.Result{
		{Output: waitingTurn, SessionID: "0b1f0a9e-9a2f-4f3c-8d0e-6f4a3b2c1d0e", InputTokens: 100, OutputTokens: 10},
		{Output: "Suite green, committed and pushed.\nTASK_DONE", SessionID: "0b1f0a9e-9a2f-4f3c-8d0e-6f4a3b2c1d0e", InputTokens: 7, OutputTokens: 3},
	}}
	res, turns, err := completeTask(context.Background(), prov, "do the task", provider.Options{}, nil)
	if err != nil {
		t.Fatalf("completeTask: %v", err)
	}
	if turns.unfinished != 1 || turns.total() != 1 {
		t.Fatalf("turns = %+v, want one unfinished hand-back", turns)
	}
	if pm.CheckTaskSignal(res.Output) != pm.TaskDone {
		t.Fatalf("the continued turn's answer was not returned: %q", res.Output)
	}
	if prov.resumes[1] != "0b1f0a9e-9a2f-4f3c-8d0e-6f4a3b2c1d0e" {
		t.Errorf("the turn was handed back in conversation %q, want the one it ran in", prov.resumes[1])
	}
	if prov.prompts[1] != continueTurnInstruction {
		t.Errorf("a resumed conversation was sent the whole task again:\n%s", prov.prompts[1])
	}
	if res.InputTokens != 107 || res.OutputTokens != 13 {
		t.Errorf("tokens = %d in / %d out, want every turn counted (107 / 13)", res.InputTokens, res.OutputTokens)
	}
}

func TestCompleteTaskRepromptsWithoutASession(t *testing.T) {
	prov := &turnProvider{results: []*provider.Result{
		{Output: waitingTurn},
		{Output: "All done.\nTASK_DONE"},
	}}
	_, turns, err := completeTask(context.Background(), prov, "do the task", provider.Options{}, nil)
	if err != nil || turns.unfinished != 1 {
		t.Fatalf("completeTask: turns=%+v err=%v", turns, err)
	}
	if prov.resumes[1] != "" {
		t.Errorf("asked to resume %q from a provider that reported no conversation", prov.resumes[1])
	}
	for _, want := range []string{"do the task", waitingTurn, continueTurnInstruction} {
		if !strings.Contains(prov.prompts[1], want) {
			t.Errorf("the re-prompt lacks %q:\n%s", want, prov.prompts[1])
		}
	}
}

func TestCompleteTaskLeavesFinishedAndSignalledTurnsAlone(t *testing.T) {
	for _, out := range []string{
		"Everything is committed and pushed.\nTASK_DONE",
		// Signalled, even while saying it is waiting: the agent's own verdict wins.
		waitingTurn + "\nTASK_FAILED",
		"Committed and pushed as d32919a.",
	} {
		prov := &turnProvider{results: []*provider.Result{{Output: out}}}
		_, turns, err := completeTask(context.Background(), prov, "p", provider.Options{}, nil)
		if err != nil || turns.total() != 0 || len(prov.prompts) != 1 {
			t.Errorf("output %q: turns=%+v calls=%d err=%v, want one call", out, turns, len(prov.prompts), err)
		}
	}
}

func TestCompleteTaskHandsTheTurnBackAtMostTwice(t *testing.T) {
	prov := &turnProvider{results: []*provider.Result{
		{Output: waitingTurn}, {Output: waitingTurn}, {Output: waitingTurn}, {Output: waitingTurn},
	}}
	res, turns, err := completeTask(context.Background(), prov, "p", provider.Options{}, nil)
	if err != nil {
		t.Fatalf("completeTask: %v", err)
	}
	if turns.unfinished != maxTurnContinuations || len(prov.prompts) != maxTurnContinuations+1 {
		t.Fatalf("turns=%+v after %d calls, want %d continuations", turns, len(prov.prompts), maxTurnContinuations)
	}
	// Still unfinished, so the task is not accepted as done even with a diff.
	ab, aborted := decideUnsignalled(t.TempDir(), "", res.Output, true)
	if !aborted || ab.Class != AbortUnfinishedTurn {
		t.Fatalf("decideUnsignalled = %+v, %v; want an unfinished_turn abort", ab, aborted)
	}
	if !ab.Class.Retryable() {
		t.Error("an unfinished turn should be retryable: the next attempt starts from its tree")
	}
}

func TestCompleteTaskReturnsTheStopDuringAContinuation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	prov := &cancellingTurnProvider{cancel: cancel}
	res, _, err := completeTask(ctx, prov, "p", provider.Options{}, nil)
	if err == nil || res != nil {
		t.Fatalf("got result=%v err=%v; a stop during the continuation must surface as the error", res, err)
	}
}

// cancellingTurnProvider answers with an unfinished turn and cancels the run
// before the continuation, the way the Stop button would.
type cancellingTurnProvider struct {
	cancel context.CancelFunc
	calls  int
}

func (p *cancellingTurnProvider) Complete(ctx context.Context, _ string, _ provider.Options) (*provider.Result, error) {
	p.calls++
	if p.calls == 1 {
		p.cancel()
		return &provider.Result{Output: waitingTurn}, nil
	}
	return nil, ctx.Err()
}

func (p *cancellingTurnProvider) Name() string         { return "cancelling" }
func (p *cancellingTurnProvider) DefaultModel() string { return "m" }

// TestRunPM_UnfinishedTurnIsNotDone runs the real loop. Before the fix, a task
// whose agent said "still running; I'll commit once it reports" and nothing
// else was recorded done — with its work uncommitted.
func TestRunPM_UnfinishedTurnIsNotDone(t *testing.T) {
	dir := tempDir(t)
	s := initState(t, dir, "goal", 0)
	s.PMMode = true
	s.Plan = &pm.Plan{Goal: "goal", Tasks: []*pm.Task{
		{ID: 1, Title: "Task A", Priority: 1, Status: pm.TaskPending},
		{ID: 2, Title: "Task B", Priority: 2, Status: pm.TaskPending},
	}}
	s.Save()

	prov := &mockProvider{name: "mock", results: []*provider.Result{
		// Task A: waits, is handed the turn back, finishes.
		{Output: waitingTurn, Provider: "mock"},
		{Output: "Suite green; committed and pushed.\nTASK_DONE", Provider: "mock"},
		// Task B: never stops waiting.
		{Output: waitingTurn, Provider: "mock"},
		{Output: waitingTurn, Provider: "mock"},
		{Output: waitingTurn, Provider: "mock"},
	}}
	o := newOrchestrator(t, dir, Config{WorkDir: dir, PMMode: true, MaxFailures: 1, NoHeal: true}, prov)
	_ = o.runPM(context.Background())

	a, b := o.state.Plan.Tasks[0], o.state.Plan.Tasks[1]
	if a.Status != pm.TaskDone {
		t.Errorf("task A = %q, want done after its turn was handed back", a.Status)
	}
	if !hasAnnotation(a, "handed back once") {
		t.Errorf("task A carries no note that its turn was handed back: %+v", a.Annotations)
	}
	if b.Status == pm.TaskDone {
		t.Fatal("task B was recorded done although its agent never stopped waiting")
	}
	if !hasAnnotation(b, string(AbortUnfinishedTurn)) {
		t.Errorf("task B carries no unfinished_turn abort note: %+v", b.Annotations)
	}
}
