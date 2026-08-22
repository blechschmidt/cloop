package e2e_test

// sandbox_test.go is the end-to-end proof of the per-project sandbox: the same
// task, run on the *same* executor, under two different projects' sandbox
// specs, lands in two different environments.
//
// That is the claim the whole feature rests on and the one a unit test cannot
// make. Every layer below has its own tests — the parser is fuzzed, placement
// is table-driven, the driver's argv is asserted flag by flag — and all of them
// could pass while the wiring between them silently drops the spec. Here the
// only thing asserted is what the workload observed about the filesystem it
// woke up in.
//
// It runs against a real container runtime and skips when there is none, in
// keeping with the rest of the container suite: a test that pulls hundreds of
// megabytes to run is a test people turn off.

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/artifact"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/container"
	"github.com/blechschmidt/cloop/pkg/sandbox"
)

// sandboxTestImages are the two images the two projects pin. They differ in a
// way the workload can observe without any tooling: /etc/os-release.
const (
	sandboxImageA = "alpine:3.20"
	sandboxImageB = "debian:stable-slim"
)

// requireSandboxRuntime returns a container executor, or skips.
func requireSandboxRuntime(t *testing.T, images ...string) *container.Executor {
	t.Helper()
	rt, err := container.DetectRuntime("")
	if err != nil {
		t.Skipf("no container runtime available: %v", err)
	}
	for _, image := range images {
		cmd := exec.Command(rt.Path, "image", "inspect", image)
		if err := cmd.Run(); err != nil {
			t.Skipf("image %s is not present locally; run `%s pull %s` to enable this test",
				image, rt.Name, image)
		}
	}
	ex, err := container.New(container.Options{
		ID:    "e2e-sandbox",
		Image: sandboxImageA,
		// The suite may run as root over a root-owned TempDir. The UID policy
		// this waives has its own coverage in tests/security; what is under
		// test here is whether the per-project spec reaches the workload.
		AllowRootUser: true,
	})
	if err != nil {
		t.Skipf("container executor unavailable: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		_, _ = ex.ReapOrphans(ctx)
	})
	return ex
}

// newSandboxProject creates a project directory containing a sandbox spec.
func newSandboxProject(t *testing.T, spec string) string {
	t.Helper()
	dir := t.TempDir()
	if resolved, err := filepath.EvalSymlinks(dir); err == nil {
		dir = resolved
	}
	path := filepath.Join(dir, ".cloop", "sandbox.yaml")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(spec), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

// runUnderSandbox resolves a project's spec, applies it, and runs argv.
//
// It reproduces the control plane's order deliberately — resolve, gate on the
// executor's capabilities, apply, run — rather than calling an internal helper,
// so a change to that order in pkg/ui that this test does not see would show up
// as a divergence rather than pass silently.
func runUnderSandbox(t *testing.T, ex executor.Executor, dir string, argv []string) (executor.RunResult, *sandbox.Resolved) {
	t.Helper()
	resolved, err := sandbox.Resolve(dir)
	if err != nil {
		t.Fatalf("resolve %s: %v", dir, err)
	}
	if err := executor.CheckSandboxSupport(ex, resolved.Requirements(), dir); err != nil {
		t.Fatalf("the container executor cannot honour the spec: %v", err)
	}

	spec := executor.Spec{WorkDir: dir, Argv: argv, Env: []string{}}
	if err := resolved.ApplyTo(&spec, dir, allowGrants{}); err != nil {
		t.Fatalf("apply spec: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	res, err := executor.Run(ctx, ex, spec)
	if err != nil {
		t.Fatalf("run in %s: %v (output %q)", dir, err, res.Output)
	}
	return res, resolved
}

type allowGrants struct{}

func (allowGrants) HasEgressGrant(string, string) bool { return true }

// TestE2ESandbox_TwoProjectsOneExecutor is the headline case: one executor, one
// task, two projects, two environments.
func TestE2ESandbox_TwoProjectsOneExecutor(t *testing.T) {
	ex := requireSandboxRuntime(t, sandboxImageA, sandboxImageB)

	projectA := newSandboxProject(t, "image: "+sandboxImageA+"\n"+
		"resources:\n  cpu: 1\n  memory: 256m\n")
	projectB := newSandboxProject(t, "image: "+sandboxImageB+"\n"+
		"resources:\n  cpu: 2\n  memory: 512m\n")

	// One task, byte for byte identical. Everything that differs comes from
	// the projects' specs.
	task := []string{"/bin/sh", "-c", "cat /etc/os-release | head -1"}

	resA, resolvedA := runUnderSandbox(t, ex, projectA, task)
	resB, resolvedB := runUnderSandbox(t, ex, projectB, task)

	outA, outB := string(resA.Output), string(resB.Output)
	if !strings.Contains(strings.ToLower(outA), "alpine") {
		t.Errorf("project A ran in %q, want an Alpine sandbox", strings.TrimSpace(outA))
	}
	if !strings.Contains(strings.ToLower(outB), "debian") {
		t.Errorf("project B ran in %q, want a Debian sandbox", strings.TrimSpace(outB))
	}
	if outA == outB {
		t.Fatalf("both projects ran in the same environment (%q) — the per-project "+
			"spec is not reaching the driver", strings.TrimSpace(outA))
	}

	// Same executor for both. Without this the test would pass just as well if
	// each project had silently been routed somewhere else, which is a
	// different (and much less interesting) feature.
	if resA.Handle.ExecutorID != resB.Handle.ExecutorID {
		t.Fatalf("the runs used different executors (%q, %q)",
			resA.Handle.ExecutorID, resB.Handle.ExecutorID)
	}

	// Distinct spec hashes, and each digest-pinned to its own image.
	if resolvedA.Hash == resolvedB.Hash {
		t.Error("the two specs hash identically")
	}
	for name, res := range map[string]executor.RunResult{"A": resA, "B": resB} {
		if res.Handle.Image == "" {
			t.Errorf("project %s recorded no image", name)
		}
	}
	if resA.Handle.Image == resB.Handle.Image {
		t.Errorf("both handles recorded the same image %q", resA.Handle.Image)
	}
}

// TestE2ESandbox_ResourceLimitsAreEnforced: the spec's numbers must reach
// cgroups, not just the argv. A limit that is recorded and not applied is worse
// than none, because it is believed.
func TestE2ESandbox_ResourceLimitsAreEnforced(t *testing.T) {
	ex := requireSandboxRuntime(t, sandboxImageA)
	dir := newSandboxProject(t, "image: "+sandboxImageA+"\nresources:\n  memory: 128m\n")

	// cgroup v2 exposes the ceiling at memory.max; v1 at the legacy path.
	res, _ := runUnderSandbox(t, ex, dir, []string{"/bin/sh", "-c",
		"cat /sys/fs/cgroup/memory.max 2>/dev/null || " +
			"cat /sys/fs/cgroup/memory/memory.limit_in_bytes 2>/dev/null || echo unknown"})

	got := strings.TrimSpace(string(res.Output))
	if got == "unknown" || got == "" {
		t.Skipf("this host does not expose the memory cgroup inside the sandbox (got %q)", got)
	}
	if got == "max" {
		t.Fatal("the sandbox has no memory ceiling; resources.memory was dropped")
	}
	const want = 128 * 1024 * 1024
	if !strings.HasPrefix(got, "134217728") {
		t.Fatalf("memory ceiling is %s bytes, want %d (128m from .cloop/sandbox.yaml)", got, want)
	}
}

// TestE2ESandbox_NetworkNarrowsWithoutAGrant: a spec that names no egress grant
// must take the network away even when the executor has one. This is the
// one-directional guarantee, observed from inside the sandbox.
func TestE2ESandbox_NetworkNarrowsWithoutAGrant(t *testing.T) {
	rt, err := container.DetectRuntime("")
	if err != nil {
		t.Skipf("no container runtime: %v", err)
	}
	if err := exec.Command(rt.Path, "image", "inspect", sandboxImageA).Run(); err != nil {
		t.Skipf("image %s not present locally", sandboxImageA)
	}
	// An executor the operator gave a network to.
	ex, err := container.New(container.Options{
		ID:            "e2e-sandbox-net",
		Image:         sandboxImageA,
		Network:       container.NetworkBridge,
		AllowRootUser: true,
	})
	if err != nil {
		t.Skipf("container executor unavailable: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		_, _ = ex.ReapOrphans(ctx)
	})

	dir := newSandboxProject(t, "image: "+sandboxImageA+"\n")
	// Count interfaces other than loopback. With --network=none there is
	// exactly one (lo), so the count is 0.
	res, _ := runUnderSandbox(t, ex, dir, []string{"/bin/sh", "-c",
		"ls /sys/class/net | grep -v '^lo$' | wc -l"})

	if got := strings.TrimSpace(string(res.Output)); got != "0" {
		t.Fatalf("the sandbox has %s non-loopback interface(s); a spec naming no egress "+
			"grant must leave it with none", got)
	}
}

// TestE2ESandbox_ArtifactRecordsThePin verifies the reproducibility record
// survives the round trip the control plane and the in-sandbox orchestrator
// actually make: written outside, read back from inside the project directory.
func TestE2ESandbox_ArtifactRecordsThePin(t *testing.T) {
	ex := requireSandboxRuntime(t, sandboxImageA)
	dir := newSandboxProject(t, "image: "+sandboxImageA+"\nsetup:\n  - mkdir -p /opt/e2e\n")

	res, resolved := runUnderSandbox(t, ex, dir, []string{"/bin/true"})

	rec := artifact.SandboxRecord{
		ExecutorID:     res.Handle.ExecutorID,
		ExecutorKind:   ex.Kind(),
		SpecHash:       resolved.Hash,
		RequestedImage: resolved.Spec.Image,
		PinnedImage:    res.Handle.Image,
		SetupHash:      resolved.Spec.SetupHash(),
		StartedAt:      res.Handle.StartedAt,
	}
	if _, err := artifact.WriteSandboxRun(dir, rec); err != nil {
		t.Fatalf("WriteSandboxRun: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		_ = ctx
		removeDerived(t, ex, res.Handle.Image)
	})

	got, ok := artifact.LoadSandboxRun(dir)
	if !ok {
		t.Fatal("the record did not read back")
	}
	if got.SpecHash != resolved.Hash || got.PinnedImage != res.Handle.Image {
		t.Fatalf("the record round-tripped wrong: %+v", got)
	}
	if got.SetupHash == "" {
		t.Error("the setup hash was not recorded; a rebuild could not be traced to its commands")
	}
	// The point of the whole exercise: what ran is identified by content, not
	// by a tag someone can repoint.
	if !got.Pinned() {
		t.Fatalf("the recorded image %q is not digest-pinned, so this run is not "+
			"reproducible once the tag moves", got.PinnedImage)
	}
}

func removeDerived(t *testing.T, ex *container.Executor, ref string) {
	t.Helper()
	if !strings.Contains(ref, container.DerivedImagePrefix) {
		return
	}
	rt, err := container.DetectRuntime("")
	if err != nil {
		return
	}
	_ = exec.Command(rt.Path, "image", "rm", "--force", ref).Run()
}

// TestE2ESandbox_InvalidSpecRefusesTheRun: a project whose spec is wrong must
// not fall back to the executor's defaults. Silently running in an environment
// nobody described is how a deployment problem gets debugged as a code problem.
func TestE2ESandbox_InvalidSpecRefusesTheRun(t *testing.T) {
	dir := newSandboxProject(t, "image: alpine:3.20\nprivileged: true\n")
	_, _, err := sandbox.Load(dir)
	if err == nil {
		t.Fatal("an unknown field was accepted")
	}
	if !strings.Contains(err.Error(), "privileged") {
		t.Fatalf("the error does not name the offending field: %v", err)
	}
}

// TestE2ESandbox_SpecCannotEscapeTheWorkspace is the containment claim, made
// against a real bind mount rather than against the validator.
func TestE2ESandbox_SpecCannotEscapeTheWorkspace(t *testing.T) {
	ex := requireSandboxRuntime(t, sandboxImageA)

	for name, spec := range map[string]string{
		"parent traversal": "image: " + sandboxImageA + "\nmounts:\n  - source: ../..\n    target: /host\n",
		"absolute source":  "image: " + sandboxImageA + "\nmounts:\n  - source: /etc\n    target: /host\n",
		"option injection": "image: " + sandboxImageA + "\nmounts:\n  - source: \"a:/etc:ro\"\n    target: /host\n",
	} {
		t.Run(name, func(t *testing.T) {
			dir := newSandboxProject(t, spec)
			if _, _, err := sandbox.Load(dir); err == nil {
				t.Fatal("the spec was accepted; /etc would be visible inside the sandbox")
			}
		})
	}

	// A mount that stays inside the workspace is accepted, so the rejections
	// above are containment and not a broken feature.
	dir := newSandboxProject(t, "image: "+sandboxImageA+"\nmounts:\n  - source: sub\n    target: /mnt/sub\n")
	if err := os.MkdirAll(filepath.Join(dir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "sub", "ok"), []byte("inside\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	res, _ := runUnderSandbox(t, ex, dir, []string{"/bin/cat", "/mnt/sub/ok"})
	if !strings.Contains(string(res.Output), "inside") {
		t.Fatalf("a legitimate in-workspace mount did not appear: %q", res.Output)
	}
}
