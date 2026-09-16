package ui

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/sandbox"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// withFleetCeiling installs a fleet ceiling for one test and takes it back
// afterwards.
//
// The switch is process state and the installer is a ratchet, so a test cannot
// undo itself by installing something looser — that is the property being
// tested. ResetResourceCeiling exists for exactly this, and the cleanup matters
// more than usual here: a leaked ceiling would silently clamp an unrelated test
// in the same package, and it would do it by making a number smaller rather
// than by failing, which is the hardest kind of leak to trace back.
func withFleetCeiling(t *testing.T, c executor.ResourceCeiling) {
	t.Helper()
	executor.ResetResourceCeiling()
	executor.ApplyResourceCeiling(c)
	t.Cleanup(executor.ResetResourceCeiling)
}

// withControlPlaneDir points the dispatch path's control-plane lookup at dir
// and restores the previous value.
func withControlPlaneDir(t *testing.T, dir string) {
	t.Helper()
	controlPlaneDirMu.Lock()
	prev := controlPlaneDirValue
	controlPlaneDirValue = dir
	controlPlaneDirMu.Unlock()
	t.Cleanup(func() {
		controlPlaneDirMu.Lock()
		controlPlaneDirValue = prev
		controlPlaneDirMu.Unlock()
	})
}

// writeSandboxYAML puts a .cloop/sandbox.yaml in a fresh project directory.
func writeSandboxYAML(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".cloop"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".cloop", "sandbox.yaml"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

// resolveSandboxLimits runs the real .cloop/sandbox.yaml path — parse, clamp,
// apply — so the test starts from the spec a dispatch would actually build
// rather than from one hand-written to be convenient.
func resolveSandboxLimits(t *testing.T, workDir string) executor.Spec {
	t.Helper()
	resolved, err := sandbox.Resolve(workDir)
	if err != nil {
		t.Fatalf("sandbox.Resolve: %v", err)
	}
	if !resolved.Present() {
		t.Fatal("expected the sandbox spec to be found")
	}
	var spec executor.Spec
	if err := resolved.ApplyTo(&spec, workDir, egressGrantChecker{}); err != nil {
		t.Fatalf("ApplyTo: %v", err)
	}
	return spec
}

// TestSandboxYAMLCannotExceedTheFleetCeiling is the defect this task closed.
//
// .cloop/sandbox.yaml is committed to the repository, so it is authored by
// whoever can push to the project. Before the ceiling existed its resource
// request *overrode* the operator's executor config — the container driver says
// so in as many words — and the only thing above it was a 1 TiB constant meant
// to catch typos. A project could therefore help itself to the machine.
func TestSandboxYAMLCannotExceedTheFleetCeiling(t *testing.T) {
	withFleetCeiling(t, executor.ResourceCeiling{MemoryMB: 2048, CPUMillis: 2000})
	withControlPlaneDir(t, "")

	// What a project could ask for and, until this change, receive.
	workDir := writeSandboxYAML(t, "image: alpine\nresources:\n  memory: 900g\n  cpu: 64\n")
	spec := resolveSandboxLimits(t, workDir)

	if spec.ResourceLimits.MemoryMB < 900*1024 {
		t.Fatalf("precondition: the sandbox file should have requested 900g, got %d MB — "+
			"if this fails the test is no longer exercising the path it was written for",
			spec.ResourceLimits.MemoryMB)
	}

	got, clamps := applyResourceCeiling(spec, workDir)

	if got.ResourceLimits.MemoryMB != 2048 {
		t.Errorf("memory: got %d MB, want it clamped to the fleet ceiling of 2048",
			got.ResourceLimits.MemoryMB)
	}
	if got.ResourceLimits.CPUMillis != 2000 {
		t.Errorf("cpu: got %d millis, want it clamped to the fleet ceiling of 2000",
			got.ResourceLimits.CPUMillis)
	}
	if len(clamps) != 2 {
		t.Fatalf("want both reductions recorded so they can be explained, got %+v", clamps)
	}
	for _, c := range clamps {
		if c.Source != executor.CeilingSourceFleet {
			t.Errorf("%s: want the fleet named as the binding ceiling, got %q", c.Resource, c.Source)
		}
	}
}

// TestAbsentSandboxYAMLIsStillBounded covers the evasion a ceiling would have
// if it only constrained projects that opted in to being constrained.
//
// applySandbox returns early for a project with no .cloop/sandbox.yaml, leaving
// ResourceLimits zero — and zero means *no limit*, not "the default". That is
// the state of every project that has never heard of sandbox specs, and of any
// project that deletes the file.
//
// The bound is not written onto the Spec (see
// TestCeilingNeverRaisesAnUnstatedRequestOnTheSpec — doing so would let it beat
// a tighter executor default). It reaches the workload through CeilingFor,
// which is what the container and Kubernetes drivers consult, so that is what
// this asserts.
func TestAbsentSandboxYAMLIsStillBounded(t *testing.T) {
	withFleetCeiling(t, executor.ResourceCeiling{MemoryMB: 2048, PIDs: 512})
	withControlPlaneDir(t, "")

	// No sandbox.yaml, and therefore no stated limits at all.
	spec := executor.Spec{WorkDir: t.TempDir()}
	if !spec.ResourceLimits.IsZero() {
		t.Fatal("precondition: an unconfigured project should request nothing")
	}

	got, _ := applyResourceCeiling(spec, spec.WorkDir)
	if !got.ResourceLimits.IsZero() {
		t.Fatalf("the spec was given limits it never requested: %+v", got.ResourceLimits)
	}

	// What the driver will resolve for a container with no configured default.
	ceiling := executor.CeilingFor(spec.WorkDir)
	if mem := executor.BoundLimit(0, ceiling.MemoryMB); mem != 2048 {
		t.Errorf("memory: an unconfigured project would get %d MB, want it bound to 2048", mem)
	}
	if pids := executor.BoundLimit(0, ceiling.PIDs); pids != 512 {
		t.Errorf("pids: an unconfigured project would get %d, want it bound to 512", pids)
	}
}

// TestProjectCeilingTightensBelowTheFleet drives the per-project half through
// the real control-plane database, which is the only way to show the dispatch
// path reads it.
func TestProjectCeilingTightensBelowTheFleet(t *testing.T) {
	withFleetCeiling(t, executor.ResourceCeiling{MemoryMB: 8192})

	hub := t.TempDir()
	if err := os.MkdirAll(filepath.Join(hub, ".cloop"), 0o755); err != nil {
		t.Fatal(err)
	}
	db, err := statedb.Open(state.DBPath(hub))
	if err != nil {
		t.Fatalf("open control plane: %v", err)
	}
	project := t.TempDir()
	if err := db.SetProjectResourceLimit(project,
		executor.ResourceCeiling{MemoryMB: 1024}, "operator@example.com"); err != nil {
		t.Fatalf("SetProjectResourceLimit: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	withControlPlaneDir(t, hub)

	spec := executor.Spec{WorkDir: project, ResourceLimits: executor.ResourceLimits{MemoryMB: 65536}}
	got, clamps := applyResourceCeiling(spec, project)

	if got.ResourceLimits.MemoryMB != 1024 {
		t.Fatalf("memory: got %d MB, want the tighter per-project ceiling of 1024",
			got.ResourceLimits.MemoryMB)
	}
	// Both ceilings spoke: the fleet lowered 64 GB to 8 GB, the project lowered
	// that to 1 GB. The second clamp is the one that must name the project, or
	// an operator cannot tell which of their two policies is binding.
	var sawProject bool
	for _, c := range clamps {
		if c.Source == executor.CeilingSourceProject {
			sawProject = true
		}
	}
	if !sawProject {
		t.Errorf("want the project ceiling named in the clamps, got %+v", clamps)
	}
}

// TestUnreadableControlPlaneFallsBackToTheFleetCeiling pins the failure posture
// documented on lookupProjectResourceCeiling: fail-open for that lookup alone,
// and bounded rather than unbounded, because the fleet ceiling is process state
// that has already been applied.
func TestUnreadableControlPlaneFallsBackToTheFleetCeiling(t *testing.T) {
	withFleetCeiling(t, executor.ResourceCeiling{MemoryMB: 2048})
	withControlPlaneDir(t, filepath.Join(t.TempDir(), "does-not-exist"))

	spec := executor.Spec{ResourceLimits: executor.ResourceLimits{MemoryMB: 65536}}
	got, _ := applyResourceCeiling(spec, t.TempDir())

	if got.ResourceLimits.MemoryMB != 2048 {
		t.Fatalf("a missing control plane left the workload at %d MB; the fleet ceiling "+
			"must still bound it", got.ResourceLimits.MemoryMB)
	}
}

// TestDiskCeilingAlsoBoundsTheWorkspaceFetch covers the dual enforcement disk
// needs and nothing else does.
//
// DiskMB bounds the writable layer, which the runtime enforces by killing the
// workload. Workspace.SizeLimitMB bounds the tree the provisioner fetches,
// checked before the harness starts. Lowering only the first would leave a
// project able to clone a repository larger than its own cap and fail mid-run
// on a message about the repository rather than about the limit.
func TestDiskCeilingAlsoBoundsTheWorkspaceFetch(t *testing.T) {
	withFleetCeiling(t, executor.ResourceCeiling{DiskMB: 1024})
	withControlPlaneDir(t, "")

	spec := executor.Spec{
		ResourceLimits: executor.ResourceLimits{DiskMB: 65536},
		Workspace:      executor.Workspace{Kind: executor.WorkspaceGit, SizeLimitMB: 65536},
	}
	got, _ := applyResourceCeiling(spec, t.TempDir())

	if got.ResourceLimits.DiskMB != 1024 {
		t.Errorf("disk: got %d MB, want 1024", got.ResourceLimits.DiskMB)
	}
	if got.Workspace.SizeLimitMB != 1024 {
		t.Errorf("workspace fetch limit: got %d MB, want it lowered to the disk ceiling of 1024",
			got.Workspace.SizeLimitMB)
	}
}

// TestWorkspaceFetchLimitIsNotRaised guards the direction. A project that asked
// for a 256 MB tree under a 1 GB ceiling keeps its own tighter number.
func TestWorkspaceFetchLimitIsNotRaised(t *testing.T) {
	withFleetCeiling(t, executor.ResourceCeiling{DiskMB: 1024})
	withControlPlaneDir(t, "")

	spec := executor.Spec{
		ResourceLimits: executor.ResourceLimits{DiskMB: 512},
		Workspace:      executor.Workspace{Kind: executor.WorkspaceGit, SizeLimitMB: 256},
	}
	got, _ := applyResourceCeiling(spec, t.TempDir())

	if got.Workspace.SizeLimitMB != 256 {
		t.Fatalf("workspace fetch limit: got %d MB, want the project's tighter 256 kept",
			got.Workspace.SizeLimitMB)
	}
}

// TestNoCeilingChangesNothing keeps the upgrade a no-op for every deployment
// that has not configured one.
func TestNoCeilingChangesNothing(t *testing.T) {
	executor.ResetResourceCeiling()
	t.Cleanup(executor.ResetResourceCeiling)
	withControlPlaneDir(t, "")

	spec := executor.Spec{ResourceLimits: executor.ResourceLimits{MemoryMB: 65536, CPUMillis: 32000}}
	got, clamps := applyResourceCeiling(spec, t.TempDir())

	if got.ResourceLimits != spec.ResourceLimits {
		t.Errorf("an unconfigured hub changed the limits:\n got %+v\nwant %+v",
			got.ResourceLimits, spec.ResourceLimits)
	}
	if len(clamps) != 0 {
		t.Errorf("want no clamps reported, got %+v", clamps)
	}
}
