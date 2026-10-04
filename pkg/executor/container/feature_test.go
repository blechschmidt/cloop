package container

// The container driver's feature mode (Task 20367), the parts that need no
// container runtime: staging the standalone tree, wrapping the harness, and
// reading what the sandbox left in its output directory as bytes only.

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/internal/logbus"
	"github.com/blechschmidt/cloop/pkg/redact"
)

const ftBranch = "cloop/feature/widget"

func ftGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.com", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.com")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

// featureSpec is a feature workload's spec with a real bundle behind it.
func featureSpec(t *testing.T) executor.Spec {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	repo := filepath.Join(t.TempDir(), "repo")
	ftGit(t, filepath.Dir(repo), "init", "-q", "-b", ftBranch, repo)
	if err := os.WriteFile(filepath.Join(repo, "f.txt"), []byte("f\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	ftGit(t, repo, "add", "-A")
	ftGit(t, repo, "commit", "-qm", "f")
	head := ftGit(t, repo, "rev-parse", "HEAD")
	file := filepath.Join(t.TempDir(), "b.bundle")
	ftGit(t, repo, "bundle", "create", "--quiet", file, "refs/heads/"+ftBranch)
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	var seed bytes.Buffer
	zw := gzip.NewWriter(&seed)
	_, _ = zw.Write([]byte(`{"goal":"g"}`))
	_ = zw.Close()
	return executor.Spec{
		WorkDir: repo,
		Argv:    []string{"cloop", "run", "--pm"},
		Labels:  map[string]string{executor.LabelRunID: "run_1"},
		Workspace: executor.Workspace{Kind: executor.WorkspaceBundle, Branch: &executor.BranchBundle{
			Branch: ftBranch, Head: head, Bytes: int64(len(data)), SHA256: hex.EncodeToString(sum[:])}},
		BranchBundleFile: file,
		ProjectSeed:      seed.Bytes(),
		WriteBack:        executor.WriteBack{Mode: executor.WriteBackBundle, Branch: ftBranch, MaxBundleBytes: 1 << 20},
	}
}

func TestStageFeatureBuildsAStandaloneTree(t *testing.T) {
	ex := &Executor{id: "sbx", handles: map[string]*record{}}
	spec := featureSpec(t)
	f, err := ex.stageFeature(context.Background(), spec, "", func(string) {})
	if err != nil {
		t.Fatalf("stageFeature: %v", err)
	}
	defer f.remove()
	if info, err := os.Lstat(filepath.Join(f.stage, ".git")); err != nil || !info.IsDir() {
		t.Fatalf("the staged tree is not a repository of its own: %v", err)
	}
	if got := ftGit(t, f.stage, "symbolic-ref", "HEAD"); got != "refs/heads/"+ftBranch {
		t.Errorf("staged tree on %s", got)
	}
	if b, _ := os.ReadFile(filepath.Join(f.out, featureSeedName)); !bytes.Equal(b, spec.ProjectSeed) {
		t.Error("the seed was not staged for the sandbox to place")
	}
	if b, err := os.ReadFile(filepath.Join(f.stage, ".cloop", "sandbox-run.json")); err != nil ||
		!strings.Contains(string(b), `"executor_id": "sbx"`) {
		t.Errorf("the run is not told where it runs: %s %v", b, err)
	}
	if info, _ := os.Stat(f.root); info.Mode().Perm() != 0o700 {
		t.Errorf("staging root mode %v", info.Mode().Perm())
	}

	f.remove()
	if _, err := os.Stat(f.root); !errors.Is(err, os.ErrNotExist) {
		t.Error("remove left the staging directory behind")
	}
	f.remove() // idempotent
}

func TestStageFeatureRefusesWhatItDoesNotServe(t *testing.T) {
	ex := &Executor{id: "sbx", handles: map[string]*record{}}
	base := featureSpec(t)
	cases := map[string]func(*executor.Spec){
		"an overlay on a fetched repository": func(s *executor.Spec) {
			s.Workspace = executor.Workspace{Kind: executor.WorkspaceGit, Repo: "https://github.com/a/b",
				Ref: s.Workspace.Branch.Head, Branch: &executor.BranchBundle{Branch: ftBranch, Head: s.Workspace.Branch.Head}}
		},
		"no project state": func(s *executor.Spec) { s.ProjectSeed = nil },
		"a push write-back": func(s *executor.Spec) {
			s.WriteBack = executor.WriteBack{Mode: executor.WriteBackPush, Branch: ftBranch}
		},
	}
	for name, mut := range cases {
		spec := base
		mut(&spec)
		if f, err := ex.stageFeature(context.Background(), spec, "", func(string) {}); err == nil {
			f.remove()
			t.Errorf("%s: staged", name)
		}
	}
}

func TestFeatureWrapRunsTheHarnessInsideTheWriteBack(t *testing.T) {
	f := &featureRun{branch: ftBranch, bundleCap: 1 << 20}
	spec := featureSpec(t)
	argv := f.wrap(spec)
	joined := strings.Join(argv, " ")
	for _, want := range []string{
		"cloop workspace writeback --dir /workspace --branch " + ftBranch,
		"--base " + spec.Workspace.Branch.Head,
		"--bundle /cloop-out/writeback.bundle --max-bundle-bytes 1048576",
		"--seed /cloop-out/seed --place-seed --project-result /cloop-out/project-result",
		"-- cloop run --pm",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("wrapped argv lacks %q:\n%s", want, joined)
		}
	}
	if argv[len(argv)-3] != "cloop" {
		t.Errorf("the harness's argv is not intact after --: %v", argv)
	}
}

func TestFeatureOutputIsReadAsBytesOnly(t *testing.T) {
	f := &featureRun{root: t.TempDir(), branch: ftBranch, bundleCap: 64}
	f.out = filepath.Join(f.root, "out")
	if err := os.Mkdir(f.out, 0o700); err != nil {
		t.Fatal(err)
	}
	// A regular file under the cap is read.
	if err := os.WriteFile(filepath.Join(f.out, featureBundleName), []byte("bundle"), 0o600); err != nil {
		t.Fatal(err)
	}
	if b, err := f.bundle(); err != nil || string(b) != "bundle" {
		t.Fatalf("bundle = %q, %v", b, err)
	}
	// Over the cap: refused.
	if err := os.WriteFile(filepath.Join(f.out, featureBundleName), bytes.Repeat([]byte("x"), 65), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := f.bundle(); err == nil || !strings.Contains(err.Error(), "limit") {
		t.Errorf("an oversized bundle = %v", err)
	}
	// A link to a file the sandbox could not read itself: refused, not followed.
	secret := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(secret, []byte("host secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	_ = os.Remove(filepath.Join(f.out, featureBundleName))
	if err := os.Symlink(secret, filepath.Join(f.out, featureBundleName)); err != nil {
		t.Fatal(err)
	}
	if b, err := f.bundle(); err == nil || strings.Contains(string(b), "host secret") {
		t.Errorf("a link in the output was followed: %q, %v", b, err)
	}
	// A FIFO would block a reader forever; it is refused at once.
	_ = os.Remove(filepath.Join(f.out, featureBundleName))
	if err := syscall.Mkfifo(filepath.Join(f.out, featureBundleName), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := f.bundle(); err == nil {
		t.Error("a FIFO in the output was read")
	}

	// The project result, or the reason there is none.
	if _, err := f.projectResult(); !errors.Is(err, executor.ErrProjectResultUnavailable) {
		t.Errorf("no result at all = %v", err)
	}
	if err := os.WriteFile(filepath.Join(f.out, featureResultName+".err"), []byte("the database was gone\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if res, err := f.projectResult(); err != nil || res.Err != "the database was gone" || res.Redact == nil {
		t.Errorf("a reported failure = %+v, %v", res, err)
	}

	// With no report at all, the write-back says why rather than nothing.
	if wb := f.writeBack(); wb.Err == "" || wb.Delivered() {
		t.Errorf("a missing report = %+v", wb)
	}
}

// TestFeatureResultScrubsARefreshedToken: the project state is read back after
// the run, so it is scrubbed of a token refreshed during it too.
func TestFeatureResultScrubsARefreshedToken(t *testing.T) {
	f := &featureRun{root: t.TempDir(), redact: redact.New("ghs_first_token_value").String}
	f.out = filepath.Join(f.root, "out")
	if err := os.Mkdir(f.out, 0o700); err != nil {
		t.Fatal(err)
	}
	bus := logbus.New("h", executor.StreamCombined, logbus.Options{Redact: redact.New("ghs_first_token_value")})
	f.followRedaction(bus)
	bus.AddRedactions("ghs_refreshed_token_value")
	if err := os.WriteFile(filepath.Join(f.out, featureResultName+".err"),
		[]byte("push with ghs_first_token_value then ghs_refreshed_token_value failed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := f.projectResult()
	if err != nil {
		t.Fatal(err)
	}
	if got := res.Redact(res.Err); strings.Contains(got, "ghs_") {
		t.Errorf("project result scrubbed to %q; both tokens should be gone", got)
	}
}

func TestFeatureRunSurvivesARestart(t *testing.T) {
	f := &featureRun{root: "/tmp/cloop-feature-x", branch: ftBranch, bundleCap: 4096}
	meta := handleMeta("docker", f)
	if meta[metaRuntime] != "docker" {
		t.Errorf("runtime lost: %v", meta)
	}
	back := restoreFeature(meta)
	if back == nil || back.root != f.root || back.branch != ftBranch || back.bundleCap != 4096 ||
		back.out != filepath.Join(f.root, "out") {
		t.Errorf("restored %+v", back)
	}
	if restoreFeature(map[string]string{metaRuntime: "docker"}) != nil {
		t.Error("a handle that was not a feature's restored as one")
	}
	if restoreFeature(map[string]string{metaFeatureRoot: "relative"}) != nil {
		t.Error("a relative staging root was trusted")
	}
}
