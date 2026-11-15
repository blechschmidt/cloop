package remote_test

// A capture over the real protocol (Task 20495): the agent in this process,
// the hub's endpoint behind a real WebSocket, and a working copy under the
// agent's root like one a run left.

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/agent"
	"github.com/blechschmidt/cloop/pkg/executor/movecapture"
	"github.com/blechschmidt/cloop/pkg/executor/movegit"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
)

func loopGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-c", "init.defaultBranch=main"}, args...)...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_AUTHOR_NAME=T", "GIT_AUTHOR_EMAIL=t@example.com", "GIT_COMMITTER_NAME=T", "GIT_COMMITTER_EMAIL=t@example.com")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

// seedWorkingCopy leaves a working copy under the agent's root as a run on
// the device would: a commit, uncommitted work and a run's output.
func seedWorkingCopy(t *testing.T, root, project string) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	dir := filepath.Join(root, executor.DeviceWorkDir(project))
	if err := os.MkdirAll(filepath.Join(dir, ".cloop", "artifacts"), 0o755); err != nil {
		t.Fatal(err)
	}
	loopGit(t, dir, "init", "-q")
	if err := os.WriteFile(filepath.Join(dir, "app.go"), []byte("package app\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	loopGit(t, dir, "add", "app.go")
	loopGit(t, dir, "commit", "-qm", "the device's commit")
	for name, content := range map[string]string{
		"app.go":                     "package app // edited on the device\n",
		"draft.md":                   "not yet committed\n",
		".cloop/artifacts/1_out.txt": "a run's output\n",
		".cloop/config.yaml":         "stays: on the device\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestLoopbackCaptureCarriesAWorkingCopy(t *testing.T) {
	lb := newLoopback(t)
	ex := lb.executor(t)
	project := "/srv/hub/projects/demo"
	seedWorkingCopy(t, lb.root, project)
	ctx := context.Background()

	// The preflight's question first: what does the working copy hold?
	ins, err := ex.CaptureProject(ctx, remote.CaptureRequest{Mode: remote.CaptureInspect,
		WorkDir: executor.DeviceWorkDir(project), Limits: remote.CaptureLimits{Document: 1 << 20}})
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	var raw bytes.Buffer
	if _, err := ins.WriteTo(remote.CapturePartDocument, &raw); err != nil {
		t.Fatal(err)
	}
	ins.Release()
	doc, err := movecapture.DecodeDocument(raw.Bytes(), movecapture.ModeInspect, "")
	if err != nil {
		t.Fatalf("the inspection: %v", err)
	}
	if !doc.Present || len(doc.Inspection.Git.Worktrees) == 0 || !doc.Inspection.Git.Worktrees[0].Dirty() {
		t.Fatalf("the inspection does not see the uncommitted work: %+v", doc.Inspection)
	}

	// Then the capture.
	moveID := "fedcba9876543210"
	got, err := ex.CaptureProject(ctx, remote.CaptureRequest{Mode: remote.CaptureFull, MoveID: moveID,
		WorkDir: executor.DeviceWorkDir(project),
		Limits:  remote.CaptureLimits{Document: 1 << 20, Bundle: 8 << 20, Files: 8 << 20}})
	if err != nil {
		t.Fatalf("capture: %v", err)
	}
	defer got.Release()
	raw.Reset()
	if _, err := got.WriteTo(remote.CapturePartDocument, &raw); err != nil {
		t.Fatal(err)
	}
	cap, err := movecapture.DecodeDocument(raw.Bytes(), movecapture.ModeCapture, moveID)
	if err != nil {
		t.Fatalf("the capture's document: %v", err)
	}
	if len(cap.Files) != 1 || cap.Files[0].Path != "artifacts/1_out.txt" {
		t.Errorf("files = %+v, want the run's output alone", cap.Files)
	}
	store := t.TempDir()
	bundle := filepath.Join(store, "repo.bundle")
	f, err := os.Create(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := got.WriteTo(remote.CapturePartBundle, f); err != nil {
		t.Fatal(err)
	}
	f.Close()
	dst := filepath.Join(store, "rebuilt")
	if err := movegit.Restore(ctx, movegit.RestoreOptions{Dir: dst, BundlePath: bundle, Manifest: *cap.Manifest}); err != nil {
		t.Fatalf("rebuild from the device's bundle: %v", err)
	}
	if b, err := os.ReadFile(filepath.Join(dst, "app.go")); err != nil || !strings.Contains(string(b), "edited on the device") {
		t.Errorf("the uncommitted edit did not travel: %q %v", b, err)
	}
	if _, err := os.Stat(filepath.Join(dst, "draft.md")); err != nil {
		t.Errorf("the untracked file did not travel: %v", err)
	}

	// Revoking the device lets go of an answer still held.
	if ex.PinnedCaptureBytes() == 0 {
		t.Fatal("the held answer is not counted")
	}
	if err := lb.hub.Revoke(ex.ID()); err != nil {
		t.Fatal(err)
	}
	if n := ex.PinnedCaptureBytes(); n != 0 {
		t.Errorf("revoking the device left %d bytes of its capture held", n)
	}
	if _, err := got.WriteTo(remote.CapturePartFiles, &raw); err == nil {
		t.Error("a revoked device's answer can still be written")
	}
}

// TestLoopbackCaptureStaysInsideTheTreesRoot: a request naming anything but
// one directory under the agent's root is refused by the hub before it is
// sent, and a working copy that leads outside the root is refused by the
// agent.
func TestLoopbackCaptureStaysInsideTheTreesRoot(t *testing.T) {
	lb := newLoopback(t)
	ex := lb.executor(t)
	ctx := context.Background()
	for _, name := range []string{"../escape", "a/b", "..", ""} {
		_, err := ex.CaptureProject(ctx, remote.CaptureRequest{Mode: remote.CaptureInspect, WorkDir: name})
		if err == nil {
			t.Errorf("a capture of %q was sent", name)
		}
	}
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(lb.root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(lb.root, "linked-0a1b2c3d")); err != nil {
		t.Fatal(err)
	}
	_, err := ex.CaptureProject(ctx, remote.CaptureRequest{Mode: remote.CaptureFull, MoveID: "fedcba9876543210",
		WorkDir: "linked-0a1b2c3d", Limits: remote.CaptureLimits{Document: 1 << 20, Bundle: 1 << 20, Files: 1 << 20}})
	if !errors.Is(err, remote.ErrCaptureRefused) {
		t.Fatalf("err = %v, want the agent's refusal", err)
	}
}

// TestLoopbackRunnerCapturesOnlyItsTenant: an executor pool's runner whose
// volume holds one project's data answers a capture of that project only — a
// capture naming another tenant, or none, is refused by the runner itself.
func TestLoopbackRunnerCapturesOnlyItsTenant(t *testing.T) {
	r := newRunnerRig(t, true)
	token, _ := r.mint(true)
	tenant := "prj-" + strings.Repeat("ab", 16)
	volume := t.TempDir()
	project := "/srv/hub/projects/demo"
	seedWorkingCopy(t, volume, project)
	a, err := agent.New(agent.Config{
		Server: "ws" + strings.TrimPrefix(r.server.URL, "http"), Token: token,
		CredentialPath: filepath.Join(t.TempDir(), "agent.json"),
		WorkDirRoot:    t.TempDir(), WorkspaceRoot: volume, HomeRoot: t.TempDir(),
		Ephemeral: true, Holds: tenant, Logf: detachableLogf(t),
	})
	if err != nil {
		t.Fatalf("agent.New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		_ = a.Run(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		<-stopped
	})
	var ex *remote.Executor
	waitFor(t, 15*time.Second, func() bool {
		for _, e := range r.hub.Executors() {
			if e.Connected() {
				ex = e
				return true
			}
		}
		return false
	}, "the runner to connect")

	req := remote.CaptureRequest{Mode: remote.CaptureInspect, WorkDir: executor.DeviceWorkDir(project),
		Limits: remote.CaptureLimits{Document: 1 << 20}}
	for _, other := range []string{"", "prj-" + strings.Repeat("cd", 16)} {
		req.Tenant = other
		if _, err := ex.CaptureProject(context.Background(), req); !errors.Is(err, remote.ErrCaptureRefused) {
			t.Errorf("tenant %q: err = %v, want the runner's refusal", other, err)
		}
	}
	req.Tenant = tenant
	got, err := ex.CaptureProject(context.Background(), req)
	if err != nil {
		t.Fatalf("the runner's own tenant: %v", err)
	}
	got.Release()
}
