package orchestrator

import (
	"context"
	"fmt"
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

func gitAvailable() bool {
	_, err := exec.LookPath("git")
	return err == nil
}

// initTestRepo creates a minimal git repo with one initial commit so the
// orchestrator's worktree path is valid. Returns the repo dir.
func initTestRepo(t *testing.T) string {
	t.Helper()
	dir := tempDir(t)
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
		}
	}
	run("init", "-b", "main")
	run("config", "user.email", "cloop-test@example.com")
	run("config", "user.name", "cloop test")
	run("config", "commit.gpgsign", "false")
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("# test\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	run("add", "README.md")
	run("commit", "-m", "initial")
	return dir
}

// workDirRecordingProvider writes a per-task file inside the cwd given by
// opts.WorkDir and remembers every distinct WorkDir it saw. Lets a test verify
// that the orchestrator's worktree-parallel mode actually routed each task into
// a different on-disk path.
type workDirRecordingProvider struct {
	mu      sync.Mutex
	dirs    []string
	files   map[string]string // file path -> contents
	taskSeq int
}

func (p *workDirRecordingProvider) Complete(_ context.Context, _ string, opts provider.Options) (*provider.Result, error) {
	p.mu.Lock()
	p.taskSeq++
	seq := p.taskSeq
	if opts.WorkDir != "" {
		p.dirs = append(p.dirs, opts.WorkDir)
	}
	p.mu.Unlock()

	fname := fmt.Sprintf("task-%d.txt", seq)
	body := fmt.Sprintf("hello from task %d\n", seq)
	fpath := filepath.Join(opts.WorkDir, fname)
	if err := os.WriteFile(fpath, []byte(body), 0o644); err != nil {
		return nil, err
	}
	p.mu.Lock()
	if p.files == nil {
		p.files = map[string]string{}
	}
	p.files[fpath] = body
	p.mu.Unlock()

	return &provider.Result{
		Output:   "wrote file\nTASK_DONE",
		Provider: "workdir-mock",
	}, nil
}

func (p *workDirRecordingProvider) Name() string         { return "workdir-mock" }
func (p *workDirRecordingProvider) DefaultModel() string { return "mock-model" }

// TestRunPMParallel_WorktreeParallel_IsolatesAndMerges proves the integration:
// when WorktreeParallel is enabled, each parallel task receives a distinct
// worktree path as its cwd, the tasks' file edits land in their respective
// worktrees, and after the run the main repo's working tree contains the
// merged result of both branches.
func TestRunPMParallel_WorktreeParallel_IsolatesAndMerges(t *testing.T) {
	if !gitAvailable() {
		t.Skip("git not available")
	}
	repo := initTestRepo(t)
	s := initState(t, repo, "goal", 0)
	s.PMMode = true
	s.Plan = &pm.Plan{
		Goal: "goal",
		Tasks: []*pm.Task{
			{ID: 1, Title: "Write file A", Priority: 1, Status: pm.TaskPending},
			{ID: 2, Title: "Write file B", Priority: 1, Status: pm.TaskPending},
		},
	}
	if err := s.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}

	prov := &workDirRecordingProvider{}
	o := newOrchestrator(t, repo, Config{
		WorkDir:          repo,
		PMMode:           true,
		Parallel:         true,
		MaxParallel:      2,
		WorktreeParallel: true,
	}, prov)

	if err := o.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}

	// Provider must have been given two distinct worktree paths, neither of
	// which equals the main repo root (that's the whole point of isolation).
	prov.mu.Lock()
	dirs := append([]string(nil), prov.dirs...)
	prov.mu.Unlock()
	if len(dirs) != 2 {
		t.Fatalf("expected 2 WorkDir captures, got %d: %v", len(dirs), dirs)
	}
	seen := map[string]bool{}
	for _, d := range dirs {
		if d == repo {
			t.Errorf("task ran in main repo (%q) instead of an isolated worktree", repo)
		}
		seen[d] = true
	}
	if len(seen) != 2 {
		t.Errorf("expected 2 distinct worktree paths, got: %v", dirs)
	}

	// All tasks should be marked done.
	final, _ := state.Load(repo)
	for _, task := range final.Plan.Tasks {
		if task.Status != pm.TaskDone {
			t.Errorf("task %d: expected done, got %s", task.ID, task.Status)
		}
	}

	// Both task files should now exist on the main branch (merged in via the
	// queue). Their existence in the main repo's working tree proves both
	// merges landed.
	if _, err := os.Stat(filepath.Join(repo, "task-1.txt")); err != nil {
		t.Errorf("task-1.txt missing in main repo after merge: %v", err)
	}
	if _, err := os.Stat(filepath.Join(repo, "task-2.txt")); err != nil {
		t.Errorf("task-2.txt missing in main repo after merge: %v", err)
	}

	// Worktree directories should have been removed (branches are kept).
	worktreeRoot := filepath.Join(repo, ".cloop", "worktrees")
	if entries, err := os.ReadDir(worktreeRoot); err == nil {
		for _, e := range entries {
			t.Errorf("worktree leftover after run: %s", e.Name())
		}
	}
}

// TestRunPMParallel_WorktreeParallel_NotAGitRepo confirms that when
// WorktreeParallel is requested but the workdir isn't a git repo, the
// orchestrator falls back to the shared workdir without erroring.
func TestRunPMParallel_WorktreeParallel_NotAGitRepo(t *testing.T) {
	if !gitAvailable() {
		t.Skip("git not available")
	}
	dir := tempDir(t) // not a git repo
	s := initState(t, dir, "goal", 0)
	s.PMMode = true
	s.Plan = &pm.Plan{
		Goal: "goal",
		Tasks: []*pm.Task{
			{ID: 1, Title: "task one", Priority: 1, Status: pm.TaskPending},
		},
	}
	if err := s.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}

	prov := &workDirRecordingProvider{}
	o := newOrchestrator(t, dir, Config{
		WorkDir:          dir,
		PMMode:           true,
		Parallel:         true,
		MaxParallel:      1,
		WorktreeParallel: true,
	}, prov)

	if err := o.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}

	prov.mu.Lock()
	dirs := append([]string(nil), prov.dirs...)
	prov.mu.Unlock()
	if len(dirs) != 1 {
		t.Fatalf("expected 1 WorkDir capture, got %d", len(dirs))
	}
	if dirs[0] != dir {
		t.Errorf("non-git fallback should use main WorkDir, got %q (want %q)", dirs[0], dir)
	}
}
