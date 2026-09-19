package container

import (
	"testing"

	"github.com/blechschmidt/cloop/pkg/executor"
)

// withCeiling installs a fleet ceiling for one test and takes it back after.
//
// The switch is process state and its installer is a ratchet, so a leaked
// ceiling would silently shrink an unrelated test's limits rather than failing
// it — the hardest kind of leak to trace.
func withCeiling(t *testing.T, c executor.ResourceCeiling) {
	t.Helper()
	executor.ResetResourceCeiling()
	executor.ApplyResourceCeiling(c)
	t.Cleanup(executor.ResetResourceCeiling)
}

// TestBuildRequest_CeilingCapsTheSpec is the guarantee the whole feature exists
// for, measured where it becomes real: the values that turn into --memory,
// --cpus and --pids-limit on a container runtime's command line.
//
// The spec here is what a repository could commit to .cloop/sandbox.yaml.
// Before Task 20301 it won outright, bounded only by a 1 TiB constant.
func TestBuildRequest_CeilingCapsTheSpec(t *testing.T) {
	withCeiling(t, executor.ResourceCeiling{CPUMillis: 2000, MemoryMB: 2048, PIDs: 256})

	ex := fakeExecutor(t, Options{CPUs: 1, MemoryMB: 256, PIDsLimit: 64})
	req, err := ex.buildRequest(executor.Spec{
		WorkDir: "/srv/proj",
		Argv:    []string{"cloop", "run"},
		ResourceLimits: executor.ResourceLimits{
			CPUMillis: 64000,  // 64 cores
			MemoryMB:  921600, // 900g
			PIDs:      60000,
		},
	}, "/srv/proj", nil)
	if err != nil {
		t.Fatalf("buildRequest: %v", err)
	}

	if req.CPUs != 2 {
		t.Errorf("CPUs = %v, want 2 (the ceiling)", req.CPUs)
	}
	if req.MemoryMB != 2048 {
		t.Errorf("MemoryMB = %d, want 2048 (the ceiling)", req.MemoryMB)
	}
	if req.PIDsLimit != 256 {
		t.Errorf("PIDsLimit = %d, want 256 (the ceiling)", req.PIDsLimit)
	}
}

// TestBuildRequest_CeilingNeverRaisesTheExecutorDefault is the regression this
// design was corrected for, and it is the reason the ceiling is applied here
// rather than written onto the Spec before dispatch.
//
// A ceiling materialised onto the Spec would arrive as a *stated* request, and
// a stated request beats the executor's configured default. A hub configured
// `memory: 256` under a 2 GB fleet ceiling would then hand a project that asked
// for nothing 2 GB — the ceiling would have raised its allowance eightfold.
func TestBuildRequest_CeilingNeverRaisesTheExecutorDefault(t *testing.T) {
	withCeiling(t, executor.ResourceCeiling{CPUMillis: 8000, MemoryMB: 2048, PIDs: 4096})

	ex := fakeExecutor(t, Options{CPUs: 1, MemoryMB: 256, PIDsLimit: 64})
	req, err := ex.buildRequest(executor.Spec{
		WorkDir: "/srv/proj",
		Argv:    []string{"cloop", "run"},
	}, "/srv/proj", nil)
	if err != nil {
		t.Fatalf("buildRequest: %v", err)
	}

	if req.CPUs != 1 || req.MemoryMB != 256 || req.PIDsLimit != 64 {
		t.Fatalf("a ceiling looser than the executor's defaults changed them: "+
			"cpus=%v mem=%d pids=%d, want the configured 1/256/64",
			req.CPUs, req.MemoryMB, req.PIDsLimit)
	}
}

// TestBuildRequest_CeilingBoundsAnOtherwiseUnlimitedContainer closes the case a
// fleet ceiling is really for: an executor configured with no limits running a
// project that requested none.
//
// Without the ceiling this container gets no --memory and no --cpus at all, and
// one runaway task takes the machine down with it.
func TestBuildRequest_CeilingBoundsAnOtherwiseUnlimitedContainer(t *testing.T) {
	withCeiling(t, executor.ResourceCeiling{CPUMillis: 1500, MemoryMB: 512})

	// PIDsLimit -1 is the runtimes' explicit "unlimited", which an operator can
	// set and a ceiling must still override.
	ex := fakeExecutor(t, Options{PIDsLimit: -1})
	req, err := ex.buildRequest(executor.Spec{
		WorkDir: "/srv/proj",
		Argv:    []string{"cloop", "run"},
	}, "/srv/proj", nil)
	if err != nil {
		t.Fatalf("buildRequest: %v", err)
	}

	if req.CPUs != 1.5 {
		t.Errorf("CPUs = %v, want 1.5 from the ceiling", req.CPUs)
	}
	if req.MemoryMB != 512 {
		t.Errorf("MemoryMB = %d, want 512 from the ceiling", req.MemoryMB)
	}
	// The ceiling named no process cap, so the operator's explicit unlimited
	// stands: a ceiling bounds the resources it names and no others.
	if req.PIDsLimit != -1 {
		t.Errorf("PIDsLimit = %d, want the configured -1 left alone", req.PIDsLimit)
	}
}

// TestBuildRequest_ProjectCeilingTightensBelowTheFleet covers the second
// ceiling reaching the driver through the same accessor.
func TestBuildRequest_ProjectCeilingTightensBelowTheFleet(t *testing.T) {
	withCeiling(t, executor.ResourceCeiling{MemoryMB: 8192})
	executor.SetProjectCeilingLookup(func(path string) (executor.ResourceCeiling, bool) {
		if path == "/srv/noisy" {
			return executor.ResourceCeiling{MemoryMB: 512}, true
		}
		return executor.ResourceCeiling{}, false
	})

	ex := fakeExecutor(t, Options{})

	noisy, err := ex.buildRequest(executor.Spec{
		WorkDir: "/srv/noisy", Argv: []string{"x"},
	}, "/srv/noisy", nil)
	if err != nil {
		t.Fatalf("buildRequest: %v", err)
	}
	if noisy.MemoryMB != 512 {
		t.Errorf("capped project: MemoryMB = %d, want its own 512", noisy.MemoryMB)
	}

	quiet, err := ex.buildRequest(executor.Spec{
		WorkDir: "/srv/quiet", Argv: []string{"x"},
	}, "/srv/quiet", nil)
	if err != nil {
		t.Fatalf("buildRequest: %v", err)
	}
	if quiet.MemoryMB != 8192 {
		t.Errorf("uncapped project: MemoryMB = %d, want the fleet's 8192", quiet.MemoryMB)
	}
}

// TestBuildRequest_NoCeilingIsUnchanged keeps the upgrade a no-op for every
// deployment that has not configured one.
func TestBuildRequest_NoCeilingIsUnchanged(t *testing.T) {
	executor.ResetResourceCeiling()
	t.Cleanup(executor.ResetResourceCeiling)

	ex := fakeExecutor(t, Options{CPUs: 1, MemoryMB: 256, PIDsLimit: 64})
	req, err := ex.buildRequest(executor.Spec{
		WorkDir:        "/srv/proj",
		Argv:           []string{"x"},
		ResourceLimits: executor.ResourceLimits{MemoryMB: 65536},
	}, "/srv/proj", nil)
	if err != nil {
		t.Fatalf("buildRequest: %v", err)
	}
	if req.MemoryMB != 65536 {
		t.Fatalf("MemoryMB = %d, want the spec's 65536 untouched on an uncapped hub", req.MemoryMB)
	}
}

// withExecutorCeiling installs a per-executor ceiling for one test (Task 20310).
//
// Separate from withCeiling above because the two switches are independent and
// a test needs to be able to install either without the other: the whole point
// of the executor source is that it binds a machine the fleet ceiling says
// nothing about.
func withExecutorCeiling(t *testing.T, want map[string]executor.ResourceCeiling) {
	t.Helper()
	executor.ResetResourceCeiling()
	executor.SetExecutorCeilingLookup(func(id string) (executor.ResourceCeiling, bool) {
		c, ok := want[id]
		return c, ok
	})
	t.Cleanup(executor.ResetResourceCeiling)
}

// TestBuildRequest_ExecutorCeilingCapsTheSpec is the per-executor half of the
// guarantee above, measured in the same place: the numbers that become
// --memory, --cpus and --pids-limit on the runtime's command line.
//
// The admin here has capped one machine and nothing else — no fleet ceiling, no
// project ceiling — which is the case the executor source exists for and the
// one neither of the others can express.
func TestBuildRequest_ExecutorCeilingCapsTheSpec(t *testing.T) {
	ex := fakeExecutor(t, Options{CPUs: 1, MemoryMB: 256, PIDsLimit: 64})
	withExecutorCeiling(t, map[string]executor.ResourceCeiling{
		ex.id: {CPUMillis: 2000, MemoryMB: 2048, PIDs: 256},
	})

	req, err := ex.buildRequest(executor.Spec{
		WorkDir: "/srv/proj",
		Argv:    []string{"cloop", "run"},
		// What a repository could commit to .cloop/sandbox.yaml.
		ResourceLimits: executor.ResourceLimits{
			CPUMillis: 64000,
			MemoryMB:  921600,
			PIDs:      60000,
		},
	}, "/srv/proj", nil)
	if err != nil {
		t.Fatalf("buildRequest: %v", err)
	}

	if req.CPUs != 2 {
		t.Errorf("CPUs = %v, want 2 (this executor's ceiling)", req.CPUs)
	}
	if req.MemoryMB != 2048 {
		t.Errorf("MemoryMB = %d, want 2048 (this executor's ceiling)", req.MemoryMB)
	}
	if req.PIDsLimit != 256 {
		t.Errorf("PIDsLimit = %d, want 256 (this executor's ceiling)", req.PIDsLimit)
	}
}

// TestBuildRequest_AnotherExecutorsCeilingDoesNotApply is the scoping
// assertion, and the one that would make this feature actively harmful if it
// failed: a cap entered against one machine must not bind a workload on
// another.
func TestBuildRequest_AnotherExecutorsCeilingDoesNotApply(t *testing.T) {
	ex := fakeExecutor(t, Options{CPUs: 4, MemoryMB: 8192, PIDsLimit: 1024})
	withExecutorCeiling(t, map[string]executor.ResourceCeiling{
		"some-other-box": {MemoryMB: 128},
	})

	req, err := ex.buildRequest(executor.Spec{
		WorkDir: "/srv/proj",
		Argv:    []string{"cloop", "run"},
	}, "/srv/proj", nil)
	if err != nil {
		t.Fatalf("buildRequest: %v", err)
	}
	if req.MemoryMB != 8192 {
		t.Errorf("MemoryMB = %d, want this executor's own default of 8192 — "+
			"another executor's ceiling bound a workload it says nothing about", req.MemoryMB)
	}
}

// TestBuildRequest_FleetAndExecutorCeilingsBothBind proves the two compose by
// getting tighter rather than one replacing the other, at the driver's own call
// site. Each ceiling names one resource the other does not, so a bug that kept
// only the last one consulted would show up as an unbounded field.
func TestBuildRequest_FleetAndExecutorCeilingsBothBind(t *testing.T) {
	ex := fakeExecutor(t, Options{CPUs: 16, MemoryMB: 65536, PIDsLimit: 60000})
	withExecutorCeiling(t, map[string]executor.ResourceCeiling{
		ex.id: {MemoryMB: 1024},
	})
	// Installed after the lookup: ResetResourceCeiling in withExecutorCeiling's
	// setup would otherwise clear it.
	executor.ApplyResourceCeiling(executor.ResourceCeiling{CPUMillis: 2000})

	req, err := ex.buildRequest(executor.Spec{
		WorkDir: "/srv/proj",
		Argv:    []string{"cloop", "run"},
	}, "/srv/proj", nil)
	if err != nil {
		t.Fatalf("buildRequest: %v", err)
	}
	if req.CPUs != 2 {
		t.Errorf("CPUs = %v, want the fleet ceiling's 2", req.CPUs)
	}
	if req.MemoryMB != 1024 {
		t.Errorf("MemoryMB = %d, want this executor's 1024", req.MemoryMB)
	}
}
