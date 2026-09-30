package orchestrator

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/state"
)

// These tests drive the review gate (Task 20357) through real runs of the
// orchestrator against a real git repository, with the worker and the reviewer
// both scripted. Pushes are not held here — that needs the cloop binary as the
// git helper and is covered end to end in tests/e2e — so what is under test is
// the gate's decision and everything it controls: the task's outcome, the fix
// rounds, and the merges the orchestrator performs itself.

type gateCall struct {
	prompt string
	opts   provider.Options
}

// gateWorker is the agent: each call runs do in the task's directory.
type gateWorker struct {
	mu      sync.Mutex
	calls   []gateCall
	session string
	do      func(dir, prompt string, call int) string
}

func (w *gateWorker) Complete(_ context.Context, prompt string, opts provider.Options) (*provider.Result, error) {
	w.mu.Lock()
	n := len(w.calls)
	w.calls = append(w.calls, gateCall{prompt, opts})
	w.mu.Unlock()
	out := "did it\nTASK_DONE"
	if w.do != nil {
		out = w.do(opts.WorkDir, prompt, n)
	}
	return &provider.Result{Output: out, Provider: "worker", Model: "worker-model", SessionID: w.session,
		InputTokens: 10, OutputTokens: 5}, nil
}
func (w *gateWorker) Name() string         { return "worker" }
func (w *gateWorker) DefaultModel() string { return "worker-model" }

func (w *gateWorker) snapshot() []gateCall {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]gateCall(nil), w.calls...)
}

// gateReviewer answers reviews through decide.
type gateReviewer struct {
	mu      sync.Mutex
	prompts []string
	opts    []provider.Options
	decide  func(prompt string, call int) string
}

func (r *gateReviewer) Complete(_ context.Context, prompt string, opts provider.Options) (*provider.Result, error) {
	r.mu.Lock()
	n := len(r.prompts)
	r.prompts = append(r.prompts, prompt)
	r.opts = append(r.opts, opts)
	r.mu.Unlock()
	return &provider.Result{Output: r.decide(prompt, n), Provider: "reviewer", Model: "review-model",
		InputTokens: 100, OutputTokens: 20}, nil
}
func (r *gateReviewer) Name() string         { return "reviewer" }
func (r *gateReviewer) DefaultModel() string { return "review-model" }

func (r *gateReviewer) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.prompts)
}

const (
	approve        = `{"verdict":"approve","summary":"Looks right."}`
	requestChanges = `{"verdict":"request_changes","summary":"The handler divides by zero.","findings":[{"severity":"major","file":"calc.txt","line":1,"title":"division by zero","detail":"guard the divisor"}]}`
)

// commitFile writes a file in dir and commits it, as an agent would.
func commitFile(dir, name, body string) {
	_ = os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644)
	for _, args := range [][]string{{"add", "-A"}, {"commit", "-q", "-m", "agent: " + name}} {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		_ = cmd.Run()
	}
}

// gateProject is a git repository holding a cloop project with the given gate
// and one pending task per title.
func gateProject(t *testing.T, gate *pm.ReviewGate, titles ...string) string {
	t.Helper()
	if !gitAvailable() {
		t.Skip("git not available")
	}
	repo := initTestRepo(t)
	// Keep cloop's own files out of the repository, as a real project does.
	if err := os.WriteFile(filepath.Join(repo, ".gitignore"), []byte(".cloop/\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	commitFile(repo, ".gitignore", ".cloop/\n")
	s := initState(t, repo, "calculator", 0)
	s.PMMode = true
	s.ReviewGate = gate
	s.Plan = &pm.Plan{Goal: "calculator"}
	for i, title := range titles {
		s.Plan.Tasks = append(s.Plan.Tasks, &pm.Task{ID: i + 1, Title: title, Priority: 1, Status: pm.TaskPending})
	}
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
	return repo
}

func loadTask(t *testing.T, dir string, id int) *pm.Task {
	t.Helper()
	s, err := state.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	task := s.Plan.TaskByID(id)
	if task == nil {
		t.Fatalf("task %d missing", id)
	}
	return task
}

func gitOut(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func TestReviewGate_FixRoundResumesTheAgentThenApproves(t *testing.T) {
	repo := gateProject(t, &pm.ReviewGate{Enabled: true, Mode: pm.ReviewModeFix}, "Add division")
	worker := &gateWorker{session: "sess-1", do: func(dir, prompt string, call int) string {
		if call == 0 {
			commitFile(dir, "calc.txt", "a / b\n")
		} else {
			commitFile(dir, "calc.txt", "b == 0 ? err : a / b\n")
		}
		return "done\nTASK_DONE"
	}}
	reviewer := &gateReviewer{decide: func(prompt string, call int) string {
		if call == 0 {
			return requestChanges
		}
		return approve
	}}
	o := newOrchestrator(t, repo, Config{WorkDir: repo, PMMode: true, ReviewProvider: reviewer}, worker)
	if err := o.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}

	calls := worker.snapshot()
	if len(calls) != 2 {
		t.Fatalf("the agent ran %d times, want the task and one fix round", len(calls))
	}
	task := calls[0].prompt
	if i, j := strings.Index(task, "## REVIEW GATE"), strings.Index(task, "## INSTRUCTIONS"); i < 0 || j < i {
		t.Errorf("the task prompt does not carry the gate section ahead of its instructions")
	}
	fix := calls[1]
	if fix.opts.ResumeSession != "sess-1" {
		t.Errorf("the fix round did not resume the agent's conversation: %q", fix.opts.ResumeSession)
	}
	if !strings.Contains(fix.prompt, "division by zero") || strings.Contains(fix.prompt, "## PROJECT GOAL") {
		t.Errorf("fix prompt:\n%s", fix.prompt)
	}
	if reviewer.count() != 2 {
		t.Fatalf("reviews = %d, want 2", reviewer.count())
	}
	if !strings.Contains(reviewer.prompts[1], "YOUR PREVIOUS REVIEW") || !strings.Contains(reviewer.prompts[1], "b == 0") {
		t.Error("the second review did not see the previous findings and the fix")
	}
	if !reviewer.opts[0].ReadOnly {
		t.Error("the reviewer was not called read-only")
	}

	got := loadTask(t, repo, 1)
	if got.Status != pm.TaskDone {
		t.Fatalf("status = %s (diagnosis %q)", got.Status, got.FailureDiagnosis)
	}
	r := got.Review
	if r == nil || r.Verdict != pm.ReviewApproved || r.Rounds != 2 || r.FixRounds != 1 || r.Blocked {
		t.Fatalf("review = %+v", r)
	}
	if len(r.Repos) != 1 || r.Repos[0].Path != "." || r.Repos[0].Commits != 2 {
		t.Errorf("reviewed repos = %+v", r.Repos)
	}
	if !taskHasAnnotation(got, "reviewer", "approved") {
		t.Errorf("no reviewer annotation: %+v", got.Annotations)
	}
	if !journalHas(t, repo, "task_review") {
		t.Error("no task_review event in the journal")
	}
}

func TestReviewGate_BlockModeFailsTheTaskWithTheFindings(t *testing.T) {
	repo := gateProject(t, &pm.ReviewGate{Enabled: true, Mode: pm.ReviewModeBlock, Model: "strict-model"}, "Add division")
	worker := &gateWorker{do: func(dir, _ string, _ int) string {
		commitFile(dir, "calc.txt", "a / b\n")
		return "done\nTASK_DONE"
	}}
	reviewer := &gateReviewer{decide: func(string, int) string { return requestChanges }}
	o := newOrchestrator(t, repo, Config{WorkDir: repo, PMMode: true, ReviewProvider: reviewer}, worker)
	_ = o.Run(context.Background())

	if n := len(worker.snapshot()); n != 1 {
		t.Errorf("block mode sent the agent back: %d calls", n)
	}
	got := loadTask(t, repo, 1)
	if got.Status != pm.TaskFailed {
		t.Fatalf("status = %s, want failed", got.Status)
	}
	if got.Review == nil || !got.Review.Blocked || got.Review.Model != "strict-model" {
		t.Fatalf("review = %+v", got.Review)
	}
	if !strings.Contains(got.FailureDiagnosis, "division by zero") {
		t.Errorf("diagnosis lacks the finding: %q", got.FailureDiagnosis)
	}
	if taskHasAnnotation(got, "ai", "per AI TASK_FAILED signal") {
		t.Error("a review failure was misattributed to the agent's own signal")
	}
}

func TestReviewGate_AdvisoryRecordsAndLetsTheTaskThrough(t *testing.T) {
	repo := gateProject(t, &pm.ReviewGate{Enabled: true, Mode: pm.ReviewModeAdvisory}, "Add division")
	worker := &gateWorker{do: func(dir, _ string, _ int) string {
		commitFile(dir, "calc.txt", "a / b\n")
		return "done\nTASK_DONE"
	}}
	reviewer := &gateReviewer{decide: func(string, int) string { return requestChanges }}
	o := newOrchestrator(t, repo, Config{WorkDir: repo, PMMode: true, ReviewProvider: reviewer}, worker)
	if err := o.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	got := loadTask(t, repo, 1)
	if got.Status != pm.TaskDone || got.Review == nil || got.Review.Verdict != pm.ReviewChangesRequested || got.Review.Blocked {
		t.Fatalf("status %s, review %+v", got.Status, got.Review)
	}
}

func TestReviewGate_FailsClosedWithoutAVerdict(t *testing.T) {
	repo := gateProject(t, &pm.ReviewGate{Enabled: true}, "Add division")
	worker := &gateWorker{do: func(dir, _ string, _ int) string {
		commitFile(dir, "calc.txt", "a / b\n")
		return "done\nTASK_DONE"
	}}
	reviewer := &gateReviewer{decide: func(string, int) string { return "I think it is fine, mostly." }}
	o := newOrchestrator(t, repo, Config{WorkDir: repo, PMMode: true, ReviewProvider: reviewer}, worker)
	_ = o.Run(context.Background())
	got := loadTask(t, repo, 1)
	if got.Status != pm.TaskFailed || got.Review == nil || got.Review.Verdict != pm.ReviewUnavailable || !got.Review.Blocked {
		t.Fatalf("status %s, review %+v", got.Status, got.Review)
	}
	if reviewer.count() != 2 {
		t.Errorf("reviews = %d, want the answer and one retry for the format", reviewer.count())
	}
	if n := len(worker.snapshot()); n != 1 {
		t.Errorf("no verdict is not a request for changes, yet the agent was sent back (%d calls)", n)
	}
}

func TestReviewGate_NothingToReviewSkipsTheReviewer(t *testing.T) {
	repo := gateProject(t, &pm.ReviewGate{Enabled: true}, "Check the docs")
	worker := &gateWorker{} // changes nothing
	reviewer := &gateReviewer{decide: func(string, int) string { return requestChanges }}
	o := newOrchestrator(t, repo, Config{WorkDir: repo, PMMode: true, ReviewProvider: reviewer}, worker)
	if err := o.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	got := loadTask(t, repo, 1)
	if got.Status != pm.TaskDone || got.Review == nil || got.Review.Verdict != pm.ReviewNothing {
		t.Fatalf("status %s, review %+v", got.Status, got.Review)
	}
	if reviewer.count() != 0 {
		t.Errorf("the reviewer was asked about nothing")
	}
}

func TestReviewGate_OffChangesNothing(t *testing.T) {
	repo := gateProject(t, &pm.ReviewGate{Enabled: false, Model: "kept"}, "Add division")
	worker := &gateWorker{do: func(dir, _ string, _ int) string {
		commitFile(dir, "calc.txt", "a / b\n")
		return "done\nTASK_DONE"
	}}
	reviewer := &gateReviewer{decide: func(string, int) string { return requestChanges }}
	o := newOrchestrator(t, repo, Config{WorkDir: repo, PMMode: true, ReviewProvider: reviewer}, worker)
	if err := o.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	got := loadTask(t, repo, 1)
	if got.Status != pm.TaskDone || got.Review != nil || reviewer.count() != 0 {
		t.Fatalf("a disabled gate acted: status %s, review %+v, reviews %d", got.Status, got.Review, reviewer.count())
	}
	if strings.Contains(worker.snapshot()[0].prompt, "REVIEW GATE") {
		t.Error("a disabled gate still told the agent about itself")
	}
}

// Git mode merges each task branch back itself; the gate stands in front of
// that merge.
func TestReviewGate_GitModeMergesOnlyApprovedWork(t *testing.T) {
	for _, tc := range []struct {
		name    string
		verdict string
		merged  bool
	}{
		{"approved", approve, true},
		{"rejected", requestChanges, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repo := gateProject(t, &pm.ReviewGate{Enabled: true, Mode: pm.ReviewModeBlock}, "Add division")
			worker := &gateWorker{do: func(dir, _ string, _ int) string {
				// Left uncommitted: git mode commits the task's work itself,
				// and must commit exactly the tree that was reviewed.
				_ = os.WriteFile(filepath.Join(dir, "calc.txt"), []byte("a / b\n"), 0o644)
				return "done\nTASK_DONE"
			}}
			reviewer := &gateReviewer{decide: func(string, int) string { return tc.verdict }}
			o := newOrchestrator(t, repo, Config{WorkDir: repo, PMMode: true, GitMode: true, ReviewProvider: reviewer}, worker)
			_ = o.Run(context.Background())

			if branch := gitOut(t, repo, "rev-parse", "--abbrev-ref", "HEAD"); branch != "main" {
				t.Errorf("left on branch %q", branch)
			}
			onMain := gitOut(t, repo, "ls-tree", "--name-only", "main")
			if got := strings.Contains(onMain, "calc.txt"); got != tc.merged {
				t.Fatalf("calc.txt on main = %v, want %v\n%s", got, tc.merged, onMain)
			}
			if !tc.merged {
				branches := gitOut(t, repo, "branch", "--list", "cloop/task-*")
				if !strings.Contains(branches, "cloop/task-1") {
					t.Errorf("the rejected work's branch is gone: %q", branches)
				}
			}
		})
	}
}

// In worktree-parallel mode each task is reviewed in its own worktree, and the
// merge queue lands only what was approved.
func TestReviewGate_WorktreeParallelMergesOnlyApprovedWork(t *testing.T) {
	repo := gateProject(t, &pm.ReviewGate{Enabled: true, Mode: pm.ReviewModeBlock}, "good task", "bad task")
	worker := &gateWorker{do: func(dir, prompt string, _ int) string {
		name := "good.txt"
		if strings.Contains(prompt, "bad task") {
			name = "bad.txt"
		}
		_ = os.WriteFile(filepath.Join(dir, name), []byte(name+"\n"), 0o644)
		return "done\nTASK_DONE"
	}}
	reviewer := &gateReviewer{decide: func(prompt string, _ int) string {
		if strings.Contains(prompt, "bad.txt") {
			return requestChanges
		}
		return approve
	}}
	o := newOrchestrator(t, repo, Config{WorkDir: repo, PMMode: true, Parallel: true, MaxParallel: 2,
		WorktreeParallel: true, ReviewProvider: reviewer}, worker)
	_ = o.Run(context.Background())

	if _, err := os.Stat(filepath.Join(repo, "good.txt")); err != nil {
		t.Errorf("approved work did not merge: %v", err)
	}
	if _, err := os.Stat(filepath.Join(repo, "bad.txt")); err == nil {
		t.Error("rejected work was merged")
	}
	if got := loadTask(t, repo, 1); got.Status != pm.TaskDone || got.Review == nil || got.Review.Verdict != pm.ReviewApproved {
		t.Errorf("good task: %s %+v", got.Status, got.Review)
	}
	if got := loadTask(t, repo, 2); got.Status != pm.TaskFailed || got.Review == nil || !got.Review.Blocked {
		t.Errorf("bad task: %s %+v", got.Status, got.Review)
	}
}

func taskHasAnnotation(t *pm.Task, author, text string) bool {
	for _, a := range t.Annotations {
		if a.Author == author && strings.Contains(a.Text, text) {
			return true
		}
	}
	return false
}

func journalHas(t *testing.T, dir, eventType string) bool {
	t.Helper()
	rows, _, err := state.ListEvents(dir, 0, 200)
	if err != nil {
		t.Fatalf("events: %v", err)
	}
	for _, r := range rows {
		if string(r.Type) == eventType {
			return true
		}
	}
	return false
}
