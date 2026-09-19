package executor

// executorceiling_test.go covers the third ceiling source (Task 20310): the cap
// an admin sets on one executor, which sits between the hub-wide one and the
// project's.
//
// The cases worth writing are the ones where the three interact, because that
// is where a composition bug would let a ceiling *raise* an allowance — the one
// thing pkg/executor/ceiling.go says a ceiling may never do.

import "testing"

// TestExecutorCeilingTightensBetweenFleetAndProject is the composition case:
// three ceilings speaking about the same resource, and the tightest winning
// regardless of which one it is.
func TestExecutorCeilingTightensBetweenFleetAndProject(t *testing.T) {
	ResetResourceCeiling()
	t.Cleanup(ResetResourceCeiling)

	ApplyResourceCeiling(ResourceCeiling{MemoryMB: 16384, CPUMillis: 8000, PIDs: 4096})
	SetExecutorCeilingLookup(func(id string) (ResourceCeiling, bool) {
		if id == "edge-1" {
			// A small device: less memory than the fleet allows, and it is the
			// only one of the three with an opinion about PIDs.
			return ResourceCeiling{MemoryMB: 2048, PIDs: 512}, true
		}
		return ResourceCeiling{}, false
	})
	SetProjectCeilingLookup(func(path string) (ResourceCeiling, bool) {
		if path == "/srv/noisy" {
			return ResourceCeiling{CPUMillis: 1000}, true
		}
		return ResourceCeiling{}, false
	})

	spec := Spec{ResourceLimits: ResourceLimits{MemoryMB: 65536, CPUMillis: 32000, PIDs: 99999}}
	clamps := BoundSpec(&spec, "/srv/noisy", "edge-1")

	if spec.ResourceLimits.MemoryMB != 2048 {
		t.Errorf("memory: got %d MB, want the executor's 2048 — the tightest of the three",
			spec.ResourceLimits.MemoryMB)
	}
	if spec.ResourceLimits.CPUMillis != 1000 {
		t.Errorf("cpu: got %d, want the project's 1000", spec.ResourceLimits.CPUMillis)
	}
	if spec.ResourceLimits.PIDs != 512 {
		t.Errorf("pids: got %d, want the executor's 512 — the only ceiling that named it",
			spec.ResourceLimits.PIDs)
	}

	// Attribution matters as much as the number: a developer told their run was
	// capped needs to know which admin to ask, and "the executor" and "your
	// project" are different people.
	bySource := map[string]string{}
	for _, c := range clamps {
		bySource[c.Resource] = c.Source
	}
	if bySource["memory"] != CeilingSourceExecutor {
		t.Errorf("memory clamp attributed to %q, want %q", bySource["memory"], CeilingSourceExecutor)
	}
	if bySource["cpu"] != CeilingSourceProject {
		t.Errorf("cpu clamp attributed to %q, want %q", bySource["cpu"], CeilingSourceProject)
	}
	if bySource["pids"] != CeilingSourceExecutor {
		t.Errorf("pids clamp attributed to %q, want %q", bySource["pids"], CeilingSourceExecutor)
	}
}

// TestExecutorCeilingCannotRaiseAnAllowance is the invariant. An executor
// ceiling looser than the fleet's must change nothing: a ceiling only ever
// lowers, and an admin who types 64g on a device under an 8g fleet cap has not
// been granted 64g.
func TestExecutorCeilingCannotRaiseAnAllowance(t *testing.T) {
	ResetResourceCeiling()
	t.Cleanup(ResetResourceCeiling)

	ApplyResourceCeiling(ResourceCeiling{MemoryMB: 8192})
	SetExecutorCeilingLookup(func(string) (ResourceCeiling, bool) {
		return ResourceCeiling{MemoryMB: 65536}, true
	})

	spec := Spec{ResourceLimits: ResourceLimits{MemoryMB: 131072}}
	BoundSpec(&spec, "/srv/proj", "big-box")
	if spec.ResourceLimits.MemoryMB != 8192 {
		t.Errorf("memory: got %d MB, want the fleet's 8192 — a looser executor ceiling must not raise it",
			spec.ResourceLimits.MemoryMB)
	}

	if got := CeilingFor("/srv/proj", "big-box"); got.MemoryMB != 8192 {
		t.Errorf("CeilingFor: got %d MB, want 8192", got.MemoryMB)
	}
}

// TestExecutorCeilingIsScopedToItsOwnExecutor guards the mistake that would
// make this feature actively dangerous: one device's cap leaking onto another.
func TestExecutorCeilingIsScopedToItsOwnExecutor(t *testing.T) {
	ResetResourceCeiling()
	t.Cleanup(ResetResourceCeiling)

	SetExecutorCeilingLookup(func(id string) (ResourceCeiling, bool) {
		if id == "small" {
			return ResourceCeiling{MemoryMB: 512}, true
		}
		return ResourceCeiling{}, false
	})

	small := Spec{ResourceLimits: ResourceLimits{MemoryMB: 4096}}
	BoundSpec(&small, "/srv/proj", "small")
	if small.ResourceLimits.MemoryMB != 512 {
		t.Errorf("small executor: got %d MB, want 512", small.ResourceLimits.MemoryMB)
	}

	big := Spec{ResourceLimits: ResourceLimits{MemoryMB: 4096}}
	BoundSpec(&big, "/srv/proj", "big")
	if big.ResourceLimits.MemoryMB != 4096 {
		t.Errorf("big executor: got %d MB, want its request of 4096 untouched",
			big.ResourceLimits.MemoryMB)
	}
}

// TestExecutorCeilingIgnoredWithoutAnExecutorID covers the honest-answer case.
// A caller that has not placed the workload yet passes "", and must get the
// fleet and project ceilings rather than an arbitrary executor's.
func TestExecutorCeilingIgnoredWithoutAnExecutorID(t *testing.T) {
	ResetResourceCeiling()
	t.Cleanup(ResetResourceCeiling)

	called := false
	SetExecutorCeilingLookup(func(string) (ResourceCeiling, bool) {
		called = true
		return ResourceCeiling{MemoryMB: 1}, true
	})

	spec := Spec{ResourceLimits: ResourceLimits{MemoryMB: 4096}}
	BoundSpec(&spec, "/srv/proj", "")
	if called {
		t.Error("the executor ceiling lookup ran for an empty executor id")
	}
	if spec.ResourceLimits.MemoryMB != 4096 {
		t.Errorf("got %d MB, want the request untouched", spec.ResourceLimits.MemoryMB)
	}
}

// TestResetResourceCeilingClearsTheExecutorLookup keeps the process-state leak
// closed. The lookup is a package-level pointer, so a test that installed one
// and did not clear it would silently cap every later test in the package.
func TestResetResourceCeilingClearsTheExecutorLookup(t *testing.T) {
	SetExecutorCeilingLookup(func(string) (ResourceCeiling, bool) {
		return ResourceCeiling{MemoryMB: 1}, true
	})
	ResetResourceCeiling()
	if c, ok := ExecutorResourceCeiling("anything"); ok || !c.IsZero() {
		t.Errorf("after reset: got %+v ok=%v, want the zero ceiling and false", c, ok)
	}
}
