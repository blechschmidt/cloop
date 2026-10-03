package remote_test

// Loopback coverage for shipping a branch to a device (protocol v16, Task
// 20367): the bundle travels in branch_chunk frames ahead of the start frame,
// the agent builds the tree from it, the harness commits on the branch, and the
// write-back comes home — over a real WebSocket, through a real agent.

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
)

const shippedBranch = "cloop/feature/widget"

// shipFixture is a repository with a feature branch, bundled whole.
type shipFixture struct {
	repo   string
	head   string
	bundle string
	bytes  int64
	digest string
}

func gitT(t *testing.T, dir string, args ...string) string {
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

// newShipFixture builds the repository; payloadBytes of incompressible data on
// the branch make the bundle span several chunks.
func newShipFixture(t *testing.T, payloadBytes int) *shipFixture {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	f := &shipFixture{repo: filepath.Join(t.TempDir(), "repo")}
	gitT(t, filepath.Dir(f.repo), "init", "-q", "-b", "main", f.repo)
	if err := os.WriteFile(filepath.Join(f.repo, "README.md"), []byte("base\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitT(t, f.repo, "add", "-A")
	gitT(t, f.repo, "commit", "-qm", "base")
	gitT(t, f.repo, "checkout", "-q", "-b", shippedBranch)
	if err := os.WriteFile(filepath.Join(f.repo, "feature.txt"), []byte("the feature's own work\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if payloadBytes > 0 {
		blob := make([]byte, payloadBytes)
		if _, err := rand.Read(blob); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(f.repo, "payload.bin"), blob, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	gitT(t, f.repo, "add", "-A")
	gitT(t, f.repo, "commit", "-qm", "feature work")
	f.head = gitT(t, f.repo, "rev-parse", "HEAD")
	f.bundle = filepath.Join(t.TempDir(), "branch.bundle")
	gitT(t, f.repo, "bundle", "create", "--quiet", f.bundle, "refs/heads/"+shippedBranch)
	data, err := os.ReadFile(f.bundle)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	f.bytes, f.digest = int64(len(data)), hex.EncodeToString(sum[:])
	return f
}

func (f *shipFixture) spec(argv string) executor.Spec {
	return executor.Spec{
		WorkDir: "widget",
		Argv:    []string{"/bin/sh", "-c", argv},
		Workspace: executor.Workspace{
			Kind:   executor.WorkspaceBundle,
			Branch: &executor.BranchBundle{Branch: shippedBranch, Head: f.head, Bytes: f.bytes, SHA256: f.digest},
		},
		BranchBundleFile: f.bundle,
	}
}

// TestLoopbackShipsABranchAcrossSeveralChunks: a bundle larger than one
// branch_chunk reaches the device whole, and the workload starts on the
// branch, attached, at the shipped head.
func TestLoopbackShipsABranchAcrossSeveralChunks(t *testing.T) {
	f := newShipFixture(t, 3*remote.MaxBranchChunkBytes/2)
	if f.bytes <= remote.MaxBranchChunkBytes {
		t.Fatalf("the fixture bundle is %d bytes, too small to need several chunks", f.bytes)
	}
	lb := newLoopback(t)
	ex := lb.executor(t)
	if !ex.Capabilities().SupportsBranchBundle {
		t.Fatal("a current agent does not advertise SupportsBranchBundle")
	}

	res, err := executor.Run(context.Background(), ex,
		f.spec(`git symbolic-ref HEAD; git rev-parse HEAD; cat feature.txt; [ -d .git ] && echo standalone`))
	if err != nil {
		t.Fatalf("Run: %v\n%s", err, res.Output)
	}
	out := string(res.Output)
	for _, want := range []string{"refs/heads/" + shippedBranch, f.head, "the feature's own work", "standalone"} {
		if !strings.Contains(out, want) {
			t.Errorf("the workload did not see %q; output:\n%s", want, out)
		}
	}
	// The transfer is gone from the device once the tree is built.
	if entries, _ := filepath.Glob(filepath.Join(lb.root, ".cloop-branch-incoming", "*")); len(entries) != 0 {
		t.Errorf("the device kept the shipped bundle: %v", entries)
	}
}

// TestLoopbackReturnsAFeatureRunsCommits: the harness commits on the shipped
// branch and the write-back carries the commit home. Until a feature needed it
// no real agent had run a write-back: the agent handed its inner driver a spec
// that still asked for one on a bind workspace, which Spec.Validate refuses.
func TestLoopbackReturnsAFeatureRunsCommits(t *testing.T) {
	f := newShipFixture(t, 0)
	lb := newLoopback(t)
	ex := lb.executor(t)

	spec := f.spec(`echo more > more.txt && git add -A && git -c user.name=h -c user.email=h@x commit -qm "harness work" && echo committed`)
	spec.WriteBack = executor.WriteBack{Mode: executor.WriteBackBundle, Branch: shippedBranch}
	res, err := executor.Run(context.Background(), ex, spec)
	if err != nil {
		t.Fatalf("Run: %v\n%s", err, res.Output)
	}
	wb := res.WriteBack
	if wb == nil || !wb.Delivered() {
		t.Fatalf("no write-back came home: %+v\n%s", wb, res.Output)
	}
	if wb.Branch != shippedBranch || wb.BaseSHA != f.head || wb.Commits != 1 {
		t.Errorf("write-back = %+v, want one commit on %s from %s", wb, shippedBranch, f.head)
	}
	if int64(len(res.Bundle)) != wb.BundleBytes || len(res.Bundle) == 0 {
		t.Fatalf("the bundle is %d bytes, the report says %d", len(res.Bundle), wb.BundleBytes)
	}
	// The bundle applies onto the hub's repository and names the harness's
	// commit.
	path := filepath.Join(t.TempDir(), "returned.bundle")
	if err := os.WriteFile(path, res.Bundle, 0o600); err != nil {
		t.Fatal(err)
	}
	gitT(t, f.repo, "fetch", "-q", path, "refs/heads/"+shippedBranch+":refs/heads/returned")
	if got := gitT(t, f.repo, "log", "-1", "--format=%s", "refs/heads/returned"); got != "harness work" {
		t.Errorf("the returned tip is %q", got)
	}
}

// TestLoopbackRefusesABundleThatDoesNotMatch: the hub checks the file it is
// about to send against the metadata the start frame will carry, so a
// substituted bundle is refused naming it rather than shipped.
func TestLoopbackRefusesABundleThatDoesNotMatch(t *testing.T) {
	f := newShipFixture(t, 0)
	lb := newLoopback(t)
	ex := lb.executor(t)
	spec := f.spec("true")
	spec.Workspace.Branch.SHA256 = strings.Repeat("0", 64)
	_, err := executor.Run(context.Background(), ex, spec)
	if err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("Run with a mismatched bundle = %v, want a refusal naming the digest", err)
	}
}

// TestBranchBundleVersionGate pins the protocol floor for shipped branches.
func TestBranchBundleVersionGate(t *testing.T) {
	if remote.SupportsBranchBundle(remote.MinBranchBundleVersion - 1) {
		t.Errorf("v%d must not be treated as able to receive a branch", remote.MinBranchBundleVersion-1)
	}
	if !remote.SupportsBranchBundle(remote.ProtocolVersion) {
		t.Error("this build must be able to ship a branch to itself")
	}
	const introducedIn = 16
	if remote.MinBranchBundleVersion != introducedIn {
		t.Errorf("MinBranchBundleVersion = %d, want %d", remote.MinBranchBundleVersion, introducedIn)
	}
}

// TestDecodeBranchChunkRefusesMalformedFrames: every bound is checked before a
// byte is written to the device's disk.
func TestDecodeBranchChunkRefusesMalformedFrames(t *testing.T) {
	ok := remote.BranchChunkPayload{Offset: 0, Data: []byte("x"), Total: 10}
	for name, tc := range map[string]struct {
		handle string
		p      remote.BranchChunkPayload
	}{
		"no handle":       {"", ok},
		"negative offset": {"h", remote.BranchChunkPayload{Offset: -1, Data: []byte("x"), Total: 10}},
		"empty":           {"h", remote.BranchChunkPayload{Offset: 0, Total: 10}},
		"oversized chunk": {"h", remote.BranchChunkPayload{Data: make([]byte, remote.MaxBranchChunkBytes+1), Total: executor.MaxBranchBundleBytes}},
		"no total":        {"h", remote.BranchChunkPayload{Data: []byte("x")}},
		"over ceiling":    {"h", remote.BranchChunkPayload{Data: []byte("x"), Total: executor.MaxBranchBundleBytes + 1}},
		"past the end":    {"h", remote.BranchChunkPayload{Offset: 9, Data: []byte("xx"), Total: 10}},
	} {
		frame, err := remote.NewFrame(remote.TypeBranchChunk, "", tc.handle, tc.p)
		if err != nil {
			t.Fatalf("%s: NewFrame: %v", name, err)
		}
		if _, err := remote.DecodeBranchChunk(frame); err == nil {
			t.Errorf("%s: a malformed branch chunk was accepted", name)
		}
	}
	frame, err := remote.NewFrame(remote.TypeBranchChunk, "", "h", ok)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := remote.DecodeBranchChunk(frame); err != nil {
		t.Errorf("a well-formed branch chunk was refused: %v", err)
	}
}
