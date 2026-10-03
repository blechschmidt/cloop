package orchestrator

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/pausereason"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/reviewgate"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/taskrecover"
)

// These tests drive "done means committed" (Task 20370) through real runs of
// the orchestrator against real git repositories, with the agent scripted:
// what it leaves in the tree, and what it does when its turn is handed back.

// committedProject is a git repository holding a cloop project with the given
// commit policy and review gate, and one pending task per title. .cloop/ is
// ignored, as in a real project, unless ignoreCloop is false.
func committedProject(t *testing.T, policy *pm.CommitPolicy, gate *pm.ReviewGate, ignoreCloop bool, titles ...string) string {
	t.Helper()
	if !gitAvailable() {
		t.Skip("git not available")
	}
	repo := initTestRepo(t)
	if ignoreCloop {
		commitFile(repo, ".gitignore", ".cloop/\n")
	}
	s := initState(t, repo, "ship it", 0)
	s.PMMode = true
	s.CommitPolicy = policy
	s.ReviewGate = gate
	s.Plan = &pm.Plan{Goal: "ship it"}
	for i, title := range titles {
		s.Plan.Tasks = append(s.Plan.Tasks, &pm.Task{ID: i + 1, Title: title, Priority: 1, Status: pm.TaskPending})
	}
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
	return repo
}

// commitOnly commits one file and nothing else, as an agent careful not to
// sweep up someone else's edits would.
func commitOnly(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
		t.Error(err)
		return
	}
	for _, args := range [][]string{{"add", "--", name}, {"commit", "-q", "-m", "agent: " + name, "--", name}} {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Errorf("git %v: %v\n%s", args, err, out)
		}
	}
}

// statusOutsideCloop is the repository's short status, without cloop's own
// directory.
func statusOutsideCloop(t *testing.T, dir string) string {
	t.Helper()
	return gitOut(t, dir, "status", "--porcelain", "--untracked-files=all", "--", ".", ":(exclude).cloop")
}

// withRemote gives repo a bare upstream for main and returns its path.
func withRemote(t *testing.T, repo string) string {
	t.Helper()
	bare := filepath.Join(t.TempDir(), "remote.git")
	gitOut(t, filepath.Dir(bare), "init", "-q", "--bare", "-b", "main", bare)
	gitOut(t, repo, "remote", "add", "origin", bare)
	gitOut(t, repo, "push", "-q", "-u", "origin", "main")
	return bare
}

func carryFile(repo string, id int) string {
	return filepath.Join(repo, ".cloop", "artifacts", strconv.Itoa(id)+"_uncommitted.json")
}

func eventsOf(t *testing.T, dir string, typ state.EventType) []state.EventRow {
	t.Helper()
	rows, _, err := state.ListEvents(dir, 0, 500)
	if err != nil {
		t.Fatal(err)
	}
	var out []state.EventRow
	for _, r := range rows {
		if r.Type == typ {
			out = append(out, r)
		}
	}
	return out
}

// The task the issue describes: the agent says TASK_DONE with its work still
// uncommitted, gets its turn back in the same conversation naming the paths,
// commits, and only then is the task done.
func TestCommitted_HandsTheTurnBackThenAccepts(t *testing.T) {
	repo := committedProject(t, &pm.CommitPolicy{Enabled: true}, nil, true, "Write the feature")
	worker := &gateWorker{session: "sess-c", do: func(dir, prompt string, call int) string {
		if call == 0 {
			_ = os.WriteFile(filepath.Join(dir, "feature.go"), []byte("package feature\n"), 0o644)
			return "Implemented the feature; the commit message is drafted.\nTASK_DONE"
		}
		commitOnly(t, dir, "feature.go", "package feature\n")
		return "Committed it.\nTASK_DONE"
	}}
	o := newOrchestrator(t, repo, Config{WorkDir: repo, PMMode: true}, worker)
	if err := o.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}

	calls := worker.snapshot()
	if len(calls) != 2 {
		t.Fatalf("the agent ran %d times, want the task and one hand-back", len(calls))
	}
	back := calls[1]
	if back.opts.ResumeSession != "sess-c" {
		t.Errorf("the turn was handed back in conversation %q, want the one it ran in", back.opts.ResumeSession)
	}
	for _, want := range []string{"?? feature.go", "only once its work is committed", "TASK_DONE"} {
		if !strings.Contains(back.prompt, want) {
			t.Errorf("the hand-back does not say %q:\n%s", want, back.prompt)
		}
	}
	if strings.Contains(back.prompt, "## PROJECT GOAL") {
		t.Error("a resumed conversation was sent the whole task again")
	}

	got := loadTask(t, repo, 1)
	if got.Status != pm.TaskDone {
		t.Fatalf("status = %s, want done once committed", got.Status)
	}
	if !hasAnnotation(got, "handed back once") || !hasAnnotation(got, "Done means committed") {
		t.Errorf("no note that the turn was handed back for uncommitted work: %+v", got.Annotations)
	}
	if st := statusOutsideCloop(t, repo); st != "" {
		t.Errorf("the tree is not clean after the task: %q", st)
	}
	if _, err := os.Stat(carryFile(repo, 1)); !os.IsNotExist(err) {
		t.Errorf("a finished task left its carry behind: %v", err)
	}
}

// An agent that never commits is not recorded done. Its work stays exactly
// where it left it, the retry is held to that work — even though it is
// already in the tree when the retry starts — and the run stops at the
// consecutive-abort ceiling with the matching pause reason.
func TestCommitted_NeverCommittedIsAbortedWithItsWorkInTheTree(t *testing.T) {
	repo := committedProject(t, &pm.CommitPolicy{Enabled: true}, nil, true, "Write the feature")
	var mu sync.Mutex
	sawLeftover := false
	worker := &gateWorker{session: "sess-n", do: func(dir, prompt string, call int) string {
		if call > maxTurnContinuations {
			// The retry finds the first attempt's work and leaves it as it
			// is — already in the tree when the retry started, so only the
			// carry keeps it the task's.
			if _, err := os.Stat(filepath.Join(dir, "feature.go")); err == nil {
				mu.Lock()
				sawLeftover = true
				mu.Unlock()
			}
			return "Nothing left to do.\nTASK_DONE"
		}
		_ = os.WriteFile(filepath.Join(dir, "feature.go"), []byte("package feature // call "+strconv.Itoa(call)+"\n"), 0o644)
		return "All done; I'll commit it later.\nTASK_DONE"
	}}
	o := newOrchestrator(t, repo, Config{WorkDir: repo, PMMode: true, MaxFailures: 2}, worker)
	o.testAbortBackoff = time.Millisecond
	if err := o.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}

	perAttempt := 1 + maxTurnContinuations
	if n := len(worker.snapshot()); n != 2*perAttempt {
		t.Fatalf("the agent ran %d times, want %d: two attempts of %d turns", n, 2*perAttempt, perAttempt)
	}
	mu.Lock()
	leftover := sawLeftover
	mu.Unlock()
	if !leftover {
		t.Error("the retry did not start from the work the first attempt left")
	}

	got := loadTask(t, repo, 1)
	if got.Status != pm.TaskPending {
		t.Fatalf("status = %s, want pending: the work was never committed", got.Status)
	}
	if !hasAnnotation(got, string(AbortUncommittedWork)) || !hasAnnotation(got, "handed back 2 times") {
		t.Errorf("annotations do not tell the story: %+v", got.Annotations)
	}
	// Never reverted or stashed.
	if b, err := os.ReadFile(filepath.Join(repo, "feature.go")); err != nil || !strings.Contains(string(b), "call 2") {
		t.Errorf("the agent's work is not where it left it: %q, %v", b, err)
	}
	if st := statusOutsideCloop(t, repo); st != "?? feature.go" {
		t.Errorf("status = %q, want the work still uncommitted", st)
	}

	s, err := state.Load(repo)
	if err != nil {
		t.Fatal(err)
	}
	if !s.PausedFor(pausereason.CodeUncommittedWork) {
		t.Errorf("run status %q, reason %+v; want paused for uncommitted work", s.Status, s.PauseReason)
	}

	aborted := eventsOf(t, repo, state.EventTaskAborted)
	if len(aborted) != 2 {
		t.Fatalf("task_aborted rows = %d, want one per attempt", len(aborted))
	}
	var details map[string]any
	if err := json.Unmarshal([]byte(aborted[0].Details), &details); err != nil {
		t.Fatal(err)
	}
	if details["abort_class"] != string(AbortUncommittedWork) || !strings.Contains(aborted[0].Details, "feature.go") {
		t.Errorf("journal row details = %s", aborted[0].Details)
	}
	if paused := eventsOf(t, repo, state.EventSessionPaused); len(paused) != 1 || !strings.Contains(paused[0].Details, "uncommitted_work") {
		t.Errorf("session_paused rows = %+v", paused)
	}

	v, err := taskrecover.ReadVerdict(repo, 1)
	if err != nil || v.Status != pm.TaskPending || v.Reason != string(AbortUncommittedWork) {
		t.Errorf("verdict = %+v, %v; want pending/uncommitted_work", v, err)
	}
	if b, err := os.ReadFile(carryFile(repo, 1)); err != nil || !strings.Contains(string(b), "feature.go") {
		t.Errorf("the carry for the next attempt = %q, %v", b, err)
	}
}

// What was already dirty when the task started — an operator's own edits —
// is not the task's: neither handed back for nor swept into its commit.
func TestCommitted_BaselineDirtIsNotBlamedOnTheTask(t *testing.T) {
	repo := committedProject(t, &pm.CommitPolicy{Enabled: true}, nil, true, "Write the feature")
	if err := os.WriteFile(filepath.Join(repo, "notes.txt"), []byte("operator's notes\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, "README.md"), []byte("# edited by the operator\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	worker := &gateWorker{do: func(dir, prompt string, call int) string {
		commitOnly(t, dir, "feature.go", "package feature\n")
		return "Committed.\nTASK_DONE"
	}}
	o := newOrchestrator(t, repo, Config{WorkDir: repo, PMMode: true}, worker)
	if err := o.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if n := len(worker.snapshot()); n != 1 {
		t.Fatalf("the agent ran %d times; the operator's edits were blamed on the task", n)
	}
	if got := loadTask(t, repo, 1); got.Status != pm.TaskDone {
		t.Fatalf("status = %s", got.Status)
	}
	// gitOut trims, so the first line's leading space is gone.
	if st := statusOutsideCloop(t, repo); st != "M README.md\n?? notes.txt" {
		t.Errorf("the operator's edits were touched: %q", st)
	}
}

// cloop's own directory is never the task's to commit — here it is not even
// ignored by the repository, and the agent writes into it too.
func TestCommitted_CloopDirectoryIsIgnored(t *testing.T) {
	repo := committedProject(t, &pm.CommitPolicy{Enabled: true}, nil, false, "Write the feature")
	worker := &gateWorker{do: func(dir, prompt string, call int) string {
		_ = os.MkdirAll(filepath.Join(dir, ".cloop", "notes"), 0o755)
		_ = os.WriteFile(filepath.Join(dir, ".cloop", "notes", "scratch.md"), []byte("x"), 0o644)
		commitOnly(t, dir, "feature.go", "package feature\n")
		return "Committed.\nTASK_DONE"
	}}
	o := newOrchestrator(t, repo, Config{WorkDir: repo, PMMode: true}, worker)
	if err := o.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if n := len(worker.snapshot()); n != 1 {
		t.Fatalf("the agent ran %d times: .cloop/ was blamed on the task", n)
	}
	if got := loadTask(t, repo, 1); got.Status != pm.TaskDone {
		t.Fatalf("status = %s", got.Status)
	}
	if !strings.Contains(gitOut(t, repo, "status", "--porcelain"), ".cloop/") {
		t.Fatal("test premise: .cloop/ should be visible to git status here")
	}
}

// With "pushed", a commit HEAD's upstream lacks is outstanding too: the turn
// goes back naming it, and the task is done once it is pushed.
func TestCommitted_UnpushedCommitIsHandedBack(t *testing.T) {
	repo := committedProject(t, &pm.CommitPolicy{Enabled: true, Pushed: true}, nil, true, "Ship the feature")
	bare := withRemote(t, repo)
	worker := &gateWorker{session: "sess-p", do: func(dir, prompt string, call int) string {
		if call == 0 {
			commitOnly(t, dir, "feature.go", "package feature\n")
			return "Committed.\nTASK_DONE"
		}
		cmd := exec.Command("git", "push", "-q")
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Errorf("push: %v\n%s", err, out)
		}
		return "Pushed.\nTASK_DONE"
	}}
	o := newOrchestrator(t, repo, Config{WorkDir: repo, PMMode: true}, worker)
	if err := o.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	calls := worker.snapshot()
	if len(calls) != 2 {
		t.Fatalf("the agent ran %d times, want the task and one hand-back", len(calls))
	}
	for _, want := range []string{"not on its upstream origin/main", "agent: feature.go", "committed and pushed"} {
		if !strings.Contains(calls[1].prompt, want) {
			t.Errorf("the hand-back does not say %q:\n%s", want, calls[1].prompt)
		}
	}
	if got := loadTask(t, repo, 1); got.Status != pm.TaskDone {
		t.Fatalf("status = %s", got.Status)
	}
	if remote, local := gitOut(t, bare, "rev-parse", "refs/heads/main"), gitOut(t, repo, "rev-parse", "HEAD"); remote != local {
		t.Errorf("remote at %s, HEAD at %s", remote, local)
	}
}

// A branch with no upstream has nowhere to push to: the push is noted as not
// checked rather than failed.
func TestCommitted_NoUpstreamIsNotedNotFailed(t *testing.T) {
	repo := committedProject(t, &pm.CommitPolicy{Enabled: true, Pushed: true}, nil, true, "Ship the feature")
	worker := &gateWorker{do: func(dir, prompt string, call int) string {
		commitOnly(t, dir, "feature.go", "package feature\n")
		return "Committed.\nTASK_DONE"
	}}
	o := newOrchestrator(t, repo, Config{WorkDir: repo, PMMode: true}, worker)
	if err := o.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if n := len(worker.snapshot()); n != 1 {
		t.Fatalf("the agent ran %d times for a branch with no upstream", n)
	}
	got := loadTask(t, repo, 1)
	if got.Status != pm.TaskDone {
		t.Fatalf("status = %s", got.Status)
	}
	if !hasAnnotation(got, "branch main has no upstream: the push was not checked") {
		t.Errorf("the skipped push is not noted: %+v", got.Annotations)
	}
}

// A push the review gate holds is pending, not missing: the gate publishes it
// once the reviewer approves, so the turn is not handed back for it.
func TestCommitted_HeldReviewGatePushIsPending(t *testing.T) {
	repo := committedProject(t, &pm.CommitPolicy{Enabled: true, Pushed: true},
		&pm.ReviewGate{Enabled: true, Mode: pm.ReviewModeFix}, true, "Ship the feature")
	bare := withRemote(t, repo)
	before := gitOut(t, bare, "rev-parse", "refs/heads/main")
	var worker *gateWorker
	worker = &gateWorker{do: func(dir, prompt string, call int) string {
		commitOnly(t, dir, "feature.go", "package feature\n")
		// Stand in for the gate's push helper, which the real binary runs.
		holdFile := ""
		for _, kv := range worker.snapshot()[call].opts.Env {
			if v, ok := strings.CutPrefix(kv, reviewgate.HoldFileEnv+"="); ok {
				holdFile = v
			}
		}
		if holdFile == "" {
			t.Error("the agent's environment has no hold file: the gate is not holding pushes")
			return "TASK_FAILED"
		}
		head := gitOut(t, dir, "rev-parse", "HEAD")
		rec, _ := json.Marshal(reviewgate.HeldPush{Repo: dir, Remote: "origin", URL: bare, Src: "HEAD",
			SrcRef: "refs/heads/main", SrcSHA: head, Dst: "refs/heads/main", Expect: before, At: time.Now()})
		f, err := os.OpenFile(holdFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			t.Error(err)
			return "TASK_FAILED"
		}
		_, _ = f.Write(append(rec, '\n'))
		_ = f.Close()
		return "Committed and pushed (held by the review gate).\nTASK_DONE"
	}}
	reviewer := &gateReviewer{decide: func(string, int) string { return approve }}
	o := newOrchestrator(t, repo, Config{WorkDir: repo, PMMode: true, ReviewProvider: reviewer,
		ReviewGateHelper: []string{"/bin/false"}}, worker)
	if err := o.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if n := len(worker.snapshot()); n != 1 {
		t.Fatalf("the agent ran %d times: a held push was treated as missing", n)
	}
	got := loadTask(t, repo, 1)
	if got.Status != pm.TaskDone || got.Review == nil || !got.Review.Approved() {
		t.Fatalf("status = %s, review %+v", got.Status, got.Review)
	}
	if remote, local := gitOut(t, bare, "rev-parse", "refs/heads/main"), gitOut(t, repo, "rev-parse", "HEAD"); remote != local {
		t.Errorf("the gate did not publish the held push: remote at %s, HEAD at %s", remote, local)
	}
}

// In worktree mode an attempt that left its work uncommitted keeps its
// worktree, and the retry reopens it: removing the worktree would have
// discarded the work, since the branch holds only what was committed.
func TestCommitted_ParallelWorktreeKeepsAnAbortedAttemptsWork(t *testing.T) {
	repo := committedProject(t, &pm.CommitPolicy{Enabled: true}, nil, true, "Write half a feature")
	var mu sync.Mutex
	var dirs []string
	reopenedWithWork := false
	worker := &gateWorker{do: func(dir, prompt string, call int) string {
		mu.Lock()
		dirs = append(dirs, dir)
		mu.Unlock()
		if call <= maxTurnContinuations {
			_ = os.WriteFile(filepath.Join(dir, "half.go"), []byte("package half\n"), 0o644)
			return "Half done.\nTASK_DONE"
		}
		if b, err := os.ReadFile(filepath.Join(dir, "half.go")); err == nil && string(b) == "package half\n" {
			mu.Lock()
			reopenedWithWork = true
			mu.Unlock()
		}
		commitOnly(t, dir, "half.go", "package half\n")
		return "Committed.\nTASK_DONE"
	}}
	o := newOrchestrator(t, repo, Config{WorkDir: repo, PMMode: true, Parallel: true, MaxParallel: 2,
		WorktreeParallel: true, MaxFailures: 3}, worker)
	o.testAbortBackoff = time.Millisecond
	if err := o.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	mu.Lock()
	ok, seen := reopenedWithWork, append([]string(nil), dirs...)
	mu.Unlock()
	if len(seen) != maxTurnContinuations+2 {
		t.Fatalf("the agent ran %d times, want an aborted attempt of %d turns and a retry", len(seen), maxTurnContinuations+1)
	}
	if !ok {
		t.Error("the retry did not reopen the worktree with the first attempt's work in it")
	}
	if seen[0] == repo || seen[len(seen)-1] != seen[0] {
		t.Errorf("worktrees used: %v; want the same task worktree both times", seen)
	}
	if got := loadTask(t, repo, 1); got.Status != pm.TaskDone {
		t.Fatalf("status = %s", got.Status)
	}
	if _, err := os.Stat(filepath.Join(repo, "half.go")); err != nil {
		t.Errorf("the reopened attempt's commit was not merged into main: %v", err)
	}
	if list := gitOut(t, repo, "worktree", "list", "--porcelain"); strings.Contains(list, "locked") {
		t.Errorf("a worktree is still locked after the task finished:\n%s", list)
	}
}

// Tasks that share one working tree cannot have their changes told apart, so
// the check is not made — and the task says so.
func TestCommitted_SharedParallelTreeIsNotChecked(t *testing.T) {
	repo := committedProject(t, &pm.CommitPolicy{Enabled: true}, nil, true, "Task A", "Task B")
	worker := &gateWorker{do: func(dir, prompt string, call int) string {
		_ = os.WriteFile(filepath.Join(dir, "f"+strconv.Itoa(call)+".go"), []byte("package f\n"), 0o644)
		return "Done.\nTASK_DONE"
	}}
	o := newOrchestrator(t, repo, Config{WorkDir: repo, PMMode: true, Parallel: true, MaxParallel: 2}, worker)
	if err := o.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if n := len(worker.snapshot()); n != 2 {
		t.Fatalf("the agent ran %d times, want each task once", n)
	}
	for _, id := range []int{1, 2} {
		got := loadTask(t, repo, id)
		if got.Status != pm.TaskDone || !hasAnnotation(got, "shared one working tree") {
			t.Errorf("task %d: %s, %+v", id, got.Status, got.Annotations)
		}
	}
}

// The setting is read from the project at each task, so turning it on from
// the dashboard reaches a run that is already going.
func TestCommitted_OffMeansTheAgentsWordStands(t *testing.T) {
	repo := committedProject(t, nil, nil, true, "Write the feature")
	worker := &gateWorker{do: func(dir, prompt string, call int) string {
		_ = os.WriteFile(filepath.Join(dir, "feature.go"), []byte("package feature\n"), 0o644)
		return "Done.\nTASK_DONE"
	}}
	o := newOrchestrator(t, repo, Config{WorkDir: repo, PMMode: true}, worker)
	if err := o.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if n := len(worker.snapshot()); n != 1 {
		t.Fatalf("with the setting off the agent ran %d times", n)
	}
	if got := loadTask(t, repo, 1); got.Status != pm.TaskDone {
		t.Fatalf("status = %s", got.Status)
	}
}
