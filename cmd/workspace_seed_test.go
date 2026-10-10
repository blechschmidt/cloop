package cmd

// Tests for the two commands a Kubernetes Pod runs around a seeded run (Task
// 20402): `cloop workspace provision --seed`, which places the hub's project
// into the checkout, and `cloop workspace writeback --project-result-frame`,
// which prints what the run changed as the last block of the Pod's log.
//
// As with the provisioner's own tests, the flags are a wire format between
// pkg/executor/kubernetes/pod.go and this package, which never call each
// other, so the argv the driver renders is parsed here verbatim.

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/projectseed"
	"github.com/blechschmidt/cloop/pkg/executor/resultframe"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
)

const seedTestTag = "k-0a1b2c3d4e5f"

func resetSeedFlags(t *testing.T) {
	t.Helper()
	resetWorkspaceProvisionFlags(t)
	t.Cleanup(func() {
		workspaceProvisionSeed = ""
		workspaceProvisionSeedCopy = ""
		workspaceWriteBackDir = ""
		workspaceWriteBackRepo = ""
		workspaceWriteBackBranch = ""
		workspaceWriteBackBase = ""
		workspaceWriteBackMessage = ""
		workspaceWriteBackPush = false
		workspaceWriteBackBundle = ""
		workspaceWriteBackMaxB = 0
		workspaceWriteBackSeed = ""
		workspaceWriteBackResult = ""
		workspaceWriteBackFrame = ""
		workspaceWriteBackPlace = false
	})
}

// buildSeed is the hub's side: one pending task.
func buildSeed(t *testing.T) []byte {
	t.Helper()
	seed, err := projectseed.Build(&state.ProjectState{
		Goal:   "Task 20402: a project whose repository has no .cloop",
		Status: "initialized",
		Plan: &pm.Plan{Goal: "g", Tasks: []*pm.Task{
			{ID: 1, Title: "write hello", Status: pm.TaskPending},
		}},
	})
	if err != nil {
		t.Fatalf("projectseed.Build: %v", err)
	}
	return seed
}

func gitIn(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.invalid",
		"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.invalid")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return string(out)
}

// TestWorkspaceProvisionParsesTheSeededInitContainerArgv is the drift gate for
// the seed flags buildWorkspaceInitContainer appends.
func TestWorkspaceProvisionParsesTheSeededInitContainerArgv(t *testing.T) {
	resetSeedFlags(t)
	if err := workspaceProvisionCmd.ParseFlags([]string{
		"--dir", "/workspace",
		"--repo", "https://github.com/acme/app.git",
		"--ref", "main",
		"--seed", "/run/cloop/seed/seed.gz",
		"--seed-copy", "/run/cloop/dispatch/seed.gz",
	}); err != nil {
		t.Fatalf("the driver's argv must parse: %v", err)
	}
	o := workspaceProvisionOptions{
		Dir: workspaceProvisionDir, Repo: workspaceProvisionRepo, Ref: workspaceProvisionRef,
		Seed: workspaceProvisionSeed, SeedCopy: workspaceProvisionSeedCopy,
	}
	if o.Seed != "/run/cloop/seed/seed.gz" || o.SeedCopy != "/run/cloop/dispatch/seed.gz" {
		t.Fatalf("parsed %+v", o)
	}
	if _, err := o.workspace(); err != nil {
		t.Fatalf("the driver's argv must validate: %v", err)
	}
}

func TestWorkspaceProvisionSeedFlagsAreChecked(t *testing.T) {
	base := workspaceProvisionOptions{Dir: "/workspace", Repo: "https://github.com/acme/app.git"}
	for name, o := range map[string]workspaceProvisionOptions{
		"copy without seed": func() workspaceProvisionOptions { o := base; o.SeedCopy = "/c"; return o }(),
		"relative seed":     func() workspaceProvisionOptions { o := base; o.Seed = "seed.gz"; return o }(),
		"relative copy": func() workspaceProvisionOptions {
			o := base
			o.Seed, o.SeedCopy = "/s", "copy.gz"
			return o
		}(),
	} {
		if _, err := o.workspace(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// TestPlaceProvisionedSeedSupersedesAndHidesTheControlDir: the seed lands as
// .cloop/state.json, a database the repository commits stops counting, and
// nothing under .cloop/ is ever staged — the trap a push write-back's
// `git add --all` would otherwise walk into.
func TestPlaceProvisionedSeedSupersedesAndHidesTheControlDir(t *testing.T) {
	dir := t.TempDir()
	gitIn(t, dir, "init", "-q", "-b", "main", ".")
	if err := os.MkdirAll(filepath.Join(dir, ".cloop"), 0o755); err != nil {
		t.Fatal(err)
	}
	// The workaround people used before seeds: .cloop/ committed to the repo.
	if err := os.WriteFile(filepath.Join(dir, ".cloop", "state.db"), []byte("the repository's stale copy"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitIn(t, dir, "add", "-A")
	gitIn(t, dir, "commit", "-qm", "init")

	seed := buildSeed(t)
	seedPath := filepath.Join(t.TempDir(), "seed.gz")
	if err := os.WriteFile(seedPath, seed, 0o400); err != nil {
		t.Fatal(err)
	}
	copyPath := filepath.Join(t.TempDir(), "dispatch-seed.gz")

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	n, err := placeProvisionedSeed(ctx, dir, seedPath, copyPath)
	if err != nil {
		t.Fatalf("placeProvisionedSeed: %v", err)
	}
	if n != len(seed) {
		t.Errorf("reported %d bytes, want %d", n, len(seed))
	}

	if _, err := os.Stat(filepath.Join(dir, ".cloop", "state.json")); err != nil {
		t.Fatalf("the seed was not placed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, ".cloop", "state.db")); !os.IsNotExist(err) {
		t.Errorf("the repository's committed state.db survived the seed (stat: %v); the run would read it", err)
	}
	st, err := state.Load(dir)
	if err != nil {
		t.Fatalf("the placed seed does not load as a project: %v", err)
	}
	if st.Goal != "Task 20402: a project whose repository has no .cloop" {
		t.Errorf("the run would see goal %q", st.Goal)
	}

	got, err := os.ReadFile(copyPath)
	if err != nil || !bytes.Equal(got, seed) {
		t.Fatalf("the copy for the write-back holds %d bytes (%v), want the seed", len(got), err)
	}
	if info, err := os.Stat(copyPath); err != nil || info.Mode().Perm() != 0o400 {
		t.Errorf("the copy's mode = %v (%v), want 0400", info.Mode().Perm(), err)
	}

	// What the run then does: changes code, rewrites its database.
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main\n\nfunc main() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if status := gitIn(t, dir, "status", "--porcelain"); strings.Contains(status, ".cloop") {
		t.Errorf("git sees the project's control state as a change:\n%s", status)
	}
	gitIn(t, dir, "add", "--all", "--", ".")
	staged := gitIn(t, dir, "diff", "--cached", "--name-only")
	if strings.TrimSpace(staged) != "main.go" {
		t.Errorf("`git add --all` staged %q, want only main.go", strings.TrimSpace(staged))
	}
}

// TestWorkspaceWriteBackParsesTheSeededKubernetesWrapperArgv is the drift gate
// for the wrapper buildWriteBackArgv renders around a seeded harness — with no
// write-back, and with a push.
func TestWorkspaceWriteBackParsesTheSeededKubernetesWrapperArgv(t *testing.T) {
	for name, argv := range map[string][]string{
		"no write-back": {"--dir", "/workspace", "--seed", "/run/cloop/dispatch/seed.gz",
			"--project-result-frame", seedTestTag, "--", "cloop", "run"},
		"push": {"--dir", "/workspace", "--repo", "https://github.com/acme/app.git",
			"--branch", "cloop/task-1-x", "--base", strings.Repeat("1", 40), "--push",
			"--seed", "/run/cloop/dispatch/seed.gz", "--project-result-frame", seedTestTag, "--", "cloop", "run"},
	} {
		t.Run(name, func(t *testing.T) {
			resetSeedFlags(t)
			if err := workspaceWriteBackCmd.ParseFlags(argv); err != nil {
				t.Fatalf("the driver's argv must parse: %v", err)
			}
			o := workspaceWriteBackOptions{
				Dir: workspaceWriteBackDir, Repo: workspaceWriteBackRepo, Branch: workspaceWriteBackBranch,
				Base: workspaceWriteBackBase, Push: workspaceWriteBackPush, Seed: workspaceWriteBackSeed,
				Frame: workspaceWriteBackFrame,
			}
			if o.Frame != seedTestTag || o.Seed != "/run/cloop/dispatch/seed.gz" {
				t.Fatalf("parsed %+v", o)
			}
			ws, wb, err := o.plan()
			if err != nil {
				t.Fatalf("plan: %v", err)
			}
			if wb.Enabled() != o.Push || (o.Push && ws.Repo == "") {
				t.Errorf("write-back %+v for push=%v", wb, o.Push)
			}
		})
	}
}

func TestWorkspaceWriteBackPlanRefusesWhatItWouldIgnore(t *testing.T) {
	base := workspaceWriteBackOptions{Dir: "/w", Seed: "/s", Frame: seedTestTag}
	cases := map[string]func(o *workspaceWriteBackOptions){
		"both sinks":       func(o *workspaceWriteBackOptions) { o.Result = "/r" },
		"no sink":          func(o *workspaceWriteBackOptions) { o.Frame = "" },
		"bad tag":          func(o *workspaceWriteBackOptions) { o.Frame = "two words" },
		"branch, no push":  func(o *workspaceWriteBackOptions) { o.Branch = "cloop/x" },
		"base, no push":    func(o *workspaceWriteBackOptions) { o.Base = strings.Repeat("1", 40) },
		"message, no push": func(o *workspaceWriteBackOptions) { o.Message = "m" },
		"no seed, no push": func(o *workspaceWriteBackOptions) { o.Seed, o.Frame = "", "" },
	}
	for name, mutate := range cases {
		o := base
		mutate(&o)
		if _, _, err := o.plan(); err == nil {
			t.Errorf("%s: plan accepted %+v", name, o)
		}
	}
	if _, wb, err := base.plan(); err != nil || wb.Enabled() {
		t.Errorf("a seeded run with no write-back: %+v, %v", wb, err)
	}
}

// seededRun lays out what a seeded run leaves behind: the seed placed, then the
// run's own database with task 1 finished. It returns the dir and the path of
// the seed the run was started with.
func seededRun(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	seed := buildSeed(t)
	if err := projectseed.Write(dir, seed); err != nil {
		t.Fatal(err)
	}
	st, err := state.Load(dir)
	if err != nil {
		t.Fatalf("load the placed seed: %v", err)
	}
	st.Plan.Tasks[0].Status = pm.TaskDone
	st.Plan.Tasks[0].Result = "hello written"
	st.Status = "complete"
	if err := st.SaveDirect(); err != nil {
		t.Fatalf("save the run's outcome: %v", err)
	}
	seedPath := filepath.Join(t.TempDir(), "seed.gz")
	if err := os.WriteFile(seedPath, seed, 0o400); err != nil {
		t.Fatal(err)
	}
	return dir, seedPath
}

// TestWorkspaceWriteBackPrintsTheProjectResultLast: the harness runs, its
// output passes through, and the run's changes follow as one frame — the last
// thing on stdout — that decodes to the task the run finished.
func TestWorkspaceWriteBackPrintsTheProjectResultLast(t *testing.T) {
	dir, seedPath := seededRun(t)
	var stdout, stderr bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	err := runWorkspaceWriteBack(ctx, workspaceWriteBackOptions{
		Dir: dir, Seed: seedPath, Frame: seedTestTag,
		Argv: []string{"sh", "-c", "echo the harness ran"},
	}, executor.GitCredential{}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("runWorkspaceWriteBack: %v\n%s", err, stderr.String())
	}

	out := stdout.String()
	if !strings.HasSuffix(out, resultframe.Marker+" "+seedTestTag+" end\n") {
		t.Fatalf("the frame is not the last thing on stdout:\n%s", tailOf(out, 300))
	}
	s, err := resultframe.NewScanner(seedTestTag)
	if err != nil {
		t.Fatal(err)
	}
	transcript := s.Feed(out) + s.Close()
	if !strings.Contains(transcript, "the harness ran\n") {
		t.Errorf("the harness's output did not pass through: %q", transcript)
	}
	f, err := s.Take()
	if err != nil {
		t.Fatalf("the frame did not scan: %v", err)
	}
	if f.Kind != resultframe.KindResult {
		t.Fatalf("frame kind %s: %s", f.Kind, f.Payload)
	}
	res, err := projectseed.DecodeResult(f.Payload)
	if err != nil {
		t.Fatalf("DecodeResult: %v", err)
	}
	if len(res.Tasks) != 1 || res.Tasks[0].After.Status != pm.TaskDone || res.Status != "complete" {
		t.Fatalf("the result says %+v (status %q), want task 1 done", res.Tasks, res.Status)
	}
}

// TestWorkspaceWriteBackFramesTheReasonWhenNothingCanBeRead: a run whose state
// cannot be read back still ends with a frame — carrying why — so the hub can
// say so instead of reporting a run that sent nothing.
func TestWorkspaceWriteBackFramesTheReasonWhenNothingCanBeRead(t *testing.T) {
	dir := t.TempDir()
	var stdout bytes.Buffer
	err := runWorkspaceWriteBack(context.Background(), workspaceWriteBackOptions{
		Dir: dir, Seed: filepath.Join(dir, "no-such-seed"), Frame: seedTestTag,
	}, executor.GitCredential{}, &stdout, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("runWorkspaceWriteBack: %v", err)
	}
	s, _ := resultframe.NewScanner(seedTestTag)
	s.Feed(stdout.String())
	s.Close()
	f, err := s.Take()
	if err != nil {
		t.Fatalf("no frame: %v\n%s", err, stdout.String())
	}
	if f.Kind != resultframe.KindError || !strings.Contains(string(f.Payload), "unreadable") {
		t.Fatalf("got a %s frame: %q", f.Kind, f.Payload)
	}
}

func tailOf(s string, n int) string {
	if len(s) > n {
		return "…" + s[len(s)-n:]
	}
	return s
}
