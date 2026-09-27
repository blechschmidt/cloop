package multiui

// A feature worktree (.cloop/features/<slug>, Task 20341) lives inside its
// parent project's directory but is a project of its own. Every "is a run
// executing in this project?" question used to count the whole subtree, so a
// feature's run would have shown its parent as running, refused to let the
// parent start, and been killed by the parent's Stop button. These tests pin
// the new boundary from both sides: a feature's run is not its parent's, and a
// parent's own parallel-task worktree still is.

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/feature"
	"github.com/blechschmidt/cloop/pkg/state"
)

func TestDirScopeMatchExcludesFeatureWorktrees(t *testing.T) {
	const p = "/work/proj"
	cases := []struct {
		dir, cwd string
		want     bool
	}{
		{p, p + "/.cloop/features/dark-mode", false},
		{p, p + "/.cloop/features/dark-mode/.cloop/worktrees/task-1", false},
		{p, p + "/.cloop/features/dark-mode/src", false},
		// The parent's own parallel tasks are still the parent's.
		{p, p + "/.cloop/worktrees/task-3", true},
		// Not a valid slug, so not a feature: stays with the parent.
		{p, p + "/.cloop/features/Not_A_Feature", true},
		{p, p + "/.cloop/features", true},
		// The feature, asked about itself, owns its whole subtree.
		{p + "/.cloop/features/dark-mode", p + "/.cloop/features/dark-mode", true},
		{p + "/.cloop/features/dark-mode", p + "/.cloop/features/dark-mode/.cloop/worktrees/task-9", true},
		{p + "/.cloop/features/dark-mode", p + "/.cloop/features/login", false},
		{p + "/.cloop/features/dark-mode", p, false},
	}
	for _, c := range cases {
		if got := dirScopeMatch(c.dir)(c.cwd); got != c.want {
			t.Errorf("dirScopeMatch(%q)(%q) = %v, want %v", c.dir, c.cwd, got, c.want)
		}
	}
}

func TestRunningDirsStopsAtFeatureRoot(t *testing.T) {
	var ix RunningDirs
	const p = "/work/proj"
	ix.add(p + "/.cloop/features/dark-mode/.cloop/worktrees/task-1")

	if !ix.Contains(p + "/.cloop/features/dark-mode") {
		t.Error("a run in a feature's task worktree must count for the feature")
	}
	if ix.Contains(p) {
		t.Error("a feature's run must not count for its parent")
	}
	if ix.Contains("/work") {
		t.Error("a feature's run must not count for anything above the feature")
	}

	// The parent's own run, added afterwards, still reaches the parent — the
	// early exit on an already-recorded directory must not swallow it.
	ix.add(p + "/.cloop/worktrees/task-2")
	if !ix.Contains(p) {
		t.Error("the parent's own parallel task must count for the parent")
	}
	if ix.Contains(p + "/.cloop/features/login") {
		t.Error("an unrelated feature must not be reported running")
	}
}

// TestFeatureRunIsNotTheParentsRun drives the real /proc path with a process
// that looks like `cloop run`, to prove the helpers the dashboard calls agree
// with each other and with the rule.
func TestFeatureRunIsNotTheParentsRun(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("liveness is read from /proc")
	}
	root := t.TempDir()
	parent := filepath.Join(root, "proj")
	featureDir := feature.Path(parent, "dark-mode")
	if err := os.MkdirAll(featureDir, 0o755); err != nil {
		t.Fatal(err)
	}
	startFakeRun(t, root, featureDir)

	if IsCloopRunningInDir(parent) {
		t.Error("IsCloopRunningInDir(parent) = true while only a feature runs — the parent's Run button would refuse to start")
	}
	if pids := CloopRunPIDsInDir(parent); len(pids) != 0 {
		t.Errorf("CloopRunPIDsInDir(parent) = %v — the parent's Stop button would kill the feature", pids)
	}
	if !IsCloopRunningInDir(featureDir) {
		t.Error("IsCloopRunningInDir(feature) = false while the feature runs")
	}
	if !IsCloopRunningUnder(parent) {
		t.Error("IsCloopRunningUnder(parent) = false — deleting the parent's tree would pull the feature's run out from under it")
	}
	ix := ScanRunningDirs()
	if ix.Contains(parent) || !ix.Contains(featureDir) {
		t.Errorf("ScanRunningDirs: parent=%v feature=%v, want false/true", ix.Contains(parent), ix.Contains(featureDir))
	}
}

func TestGetStatusUsingFeatureEntry(t *testing.T) {
	parent := t.TempDir()
	dir := feature.Path(parent, "login")
	if err := os.MkdirAll(filepath.Join(dir, ".cloop"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := state.Init(dir, "Add a login form", 0); err != nil {
		t.Fatal(err)
	}
	created := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	m := &feature.Meta{Slug: "login", Title: "Login", Branch: "cloop/feature/login", Base: "main",
		Parent: parent, CreatedAt: created, AutoPR: true,
		PR: &feature.PR{Number: 5, URL: "https://github.com/o/r/pull/5", State: "open"}}
	if err := feature.SaveMeta(dir, m); err != nil {
		t.Fatal(err)
	}

	ps := GetStatusUsing(ProjectEntry{Name: "proj/login", Path: dir, Parent: parent, Feature: "login"}, false)
	if ps.Parent != parent || ps.Feature == nil {
		t.Fatalf("status lacks feature fields: %+v", ps)
	}
	f := ps.Feature
	if f.Slug != "login" || f.Title != "Login" || f.Base != "main" || !f.AutoPR ||
		f.PR == nil || f.PR.Number != 5 || !f.CreatedAt.Equal(created) {
		t.Errorf("feature status = %+v", f)
	}
	if ps.Goal != "Add a login form" || !ps.HasProject {
		t.Errorf("project half of the status wrong: %+v", ps)
	}

	// A plain project carries neither field.
	plain := GetStatusUsing(ProjectEntry{Name: "proj", Path: parent}, false)
	if plain.Parent != "" || plain.Feature != nil {
		t.Errorf("plain project has feature fields: %+v", plain)
	}
}
