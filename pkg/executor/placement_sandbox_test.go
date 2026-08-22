package executor

// placement_sandbox_test.go covers the capability matching that keeps a
// per-project sandbox spec honest: a spec asking for something the executor
// cannot do must be refused with the constraint named, never silently dropped.

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// capExecutor is a stub whose capabilities the test dictates.
type capExecutor struct {
	id   string
	caps Capabilities
}

func (e *capExecutor) ID() string   { return e.id }
func (e *capExecutor) Kind() string { return "stub" }
func (e *capExecutor) Capabilities() Capabilities {
	return e.caps
}
func (e *capExecutor) Start(context.Context, Spec) (Handle, error)  { return Handle{}, nil }
func (e *capExecutor) Signal(context.Context, string, Signal) error { return nil }
func (e *capExecutor) Status(context.Context, string) (Status, error) {
	return Status{}, nil
}
func (e *capExecutor) Stream(context.Context, string) (<-chan LogLine, error) { return nil, nil }
func (e *capExecutor) HealthCheck(context.Context) error                      { return nil }

// sandboxCapable mirrors what the container driver advertises.
func sandboxCapable(id string) *capExecutor {
	return &capExecutor{id: id, caps: Capabilities{
		Isolation:              IsolationContainer,
		SupportsStream:         true,
		SupportsSignal:         true,
		SupportsResourceLimits: true,
		SupportsImageOverride:  true,
		SupportsSandboxBuild:   true,
		SupportsSandboxMounts:  true,
		NetworkEgress:          true,
	}}
}

// hostLike mirrors the localprocess driver: no isolation, no sandbox features.
func hostLike(id string) *capExecutor {
	return &capExecutor{id: id, caps: Capabilities{
		Isolation:      IsolationNone,
		SupportsStream: true,
		SupportsSignal: true,
		NetworkEgress:  true,
	}}
}

func TestSpecSandboxRequirements(t *testing.T) {
	cases := map[string]struct {
		spec   Spec
		verify func(*testing.T, Requirements)
	}{
		"image": {
			Spec{Image: "x:1"},
			func(t *testing.T, r Requirements) {
				if !r.RequireImageOverride {
					t.Error("RequireImageOverride not set")
				}
			},
		},
		"setup": {
			Spec{SetupCommands: []string{"echo hi"}},
			func(t *testing.T, r Requirements) {
				if !r.RequireSandboxBuild {
					t.Error("RequireSandboxBuild not set")
				}
			},
		},
		"mounts": {
			Spec{Mounts: []SpecMount{{Source: "a", Target: "/a"}}},
			func(t *testing.T, r Requirements) {
				if !r.RequireSandboxMounts {
					t.Error("RequireSandboxMounts not set — a driver that ignores Mounts would " +
						"produce a sandbox missing the path the project told it to expect")
				}
			},
		},
		"limits": {
			Spec{ResourceLimits: ResourceLimits{MemoryMB: 512}},
			func(t *testing.T, r Requirements) {
				if !r.RequireResourceLimits {
					t.Error("RequireResourceLimits not set")
				}
			},
		},
		"nothing": {
			Spec{Argv: []string{"x"}},
			func(t *testing.T, r Requirements) {
				if r.RequireImageOverride || r.RequireSandboxBuild ||
					r.RequireSandboxMounts || r.RequireResourceLimits {
					t.Errorf("a plain spec produced sandbox requirements: %+v", r)
				}
			},
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) { tc.verify(t, tc.spec.SandboxRequirements()) })
	}
}

func TestSelect_SandboxConstraints(t *testing.T) {
	cases := map[string]struct {
		caps Capabilities
		req  Requirements
		want Constraint
	}{
		"no image override": {
			Capabilities{Isolation: IsolationContainer},
			Requirements{RequireImageOverride: true},
			ConstraintImageOverride,
		},
		"no builder": {
			Capabilities{Isolation: IsolationRemote, SupportsImageOverride: true},
			Requirements{RequireSandboxBuild: true},
			ConstraintSandboxBuild,
		},
		"no mounts": {
			Capabilities{Isolation: IsolationContainer},
			Requirements{RequireSandboxMounts: true},
			ConstraintSandboxMounts,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Select([]Candidate{{Executor: &capExecutor{id: "e", caps: tc.caps}}}, tc.req)
			var pe *PlacementError
			if !errors.As(err, &pe) {
				t.Fatalf("Select = %v, want a *PlacementError", err)
			}
			if pe.Constraint != tc.want {
				t.Fatalf("Constraint = %q, want %q", pe.Constraint, tc.want)
			}
			if !errors.Is(err, ErrNoPlacement) {
				t.Fatal("error does not match ErrNoPlacement")
			}
		})
	}
}

func TestSelect_SandboxCapableNodeIsChosen(t *testing.T) {
	got, err := Select([]Candidate{
		{Executor: hostLike("host")},
		{Executor: sandboxCapable("sandbox")},
	}, Requirements{RequireImageOverride: true, RequireSandboxMounts: true})
	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	if got.ID() != "sandbox" {
		t.Fatalf("chose %q, want the sandbox-capable node", got.ID())
	}
}

// --- CheckSandboxSupport ------------------------------------------------

func TestCheckSandboxSupport_Allows(t *testing.T) {
	req := Requirements{
		RequireImageOverride:  true,
		RequireSandboxBuild:   true,
		RequireSandboxMounts:  true,
		RequireResourceLimits: true,
		RequireNetworkEgress:  true,
	}
	if err := CheckSandboxSupport(sandboxCapable("c"), req, "/p"); err != nil {
		t.Fatalf("a fully-capable executor was refused: %v", err)
	}
}

func TestCheckSandboxSupport_NoRequirementsAlwaysPasses(t *testing.T) {
	if err := CheckSandboxSupport(hostLike("host"), Requirements{}, "/p"); err != nil {
		t.Fatalf("a project with no sandbox spec was refused: %v", err)
	}
}

// TestCheckSandboxSupport_UnisolatedGetsTheHostRemediation: on a host-like
// executor every one of these gaps has the same fix — bind the project to a
// sandbox — and that is what the person reading the 409 needs, not a taxonomy
// of which capability was missing.
func TestCheckSandboxSupport_UnisolatedGetsTheHostRemediation(t *testing.T) {
	reqs := map[string]Requirements{
		"image":     {RequireImageOverride: true},
		"setup":     {RequireSandboxBuild: true},
		"mounts":    {RequireSandboxMounts: true},
		"resources": {RequireResourceLimits: true},
	}
	for name, req := range reqs {
		t.Run(name, func(t *testing.T) {
			err := CheckSandboxSupport(hostLike("host"), req, "/srv/app")
			var denied *HostExecutionDeniedError
			if !errors.As(err, &denied) {
				t.Fatalf("CheckSandboxSupport = %v, want *HostExecutionDeniedError", err)
			}
			if !errors.Is(err, ErrHostExecutionDenied) {
				t.Fatal("error does not match ErrHostExecutionDenied")
			}
			if denied.ProjectPath != "/srv/app" || denied.ExecutorID != "host" {
				t.Fatalf("error lost its context: %+v", denied)
			}
			if denied.Remediation() == "" {
				t.Fatal("no remediation — the 409 would be a dead end")
			}
		})
	}
}

// TestCheckSandboxSupport_IsolatedGetsTheConstraint: an executor that already
// isolates and merely lacks a feature must be told which feature, since "use a
// sandbox" is advice it has already taken.
func TestCheckSandboxSupport_IsolatedGetsTheConstraint(t *testing.T) {
	// Kubernetes-shaped: isolates, overrides images, cannot build one.
	k8sLike := &capExecutor{id: "k8s", caps: Capabilities{
		Isolation:             IsolationRemote,
		SupportsImageOverride: true,
		SupportsSandboxMounts: true,
		NetworkEgress:         true,
	}}
	err := CheckSandboxSupport(k8sLike, Requirements{RequireSandboxBuild: true}, "/p")

	var denied *HostExecutionDeniedError
	if errors.As(err, &denied) {
		t.Fatal("an isolated executor was told to use isolation")
	}
	var pe *PlacementError
	if !errors.As(err, &pe) {
		t.Fatalf("CheckSandboxSupport = %v, want *PlacementError", err)
	}
	if pe.Constraint != ConstraintSandboxBuild {
		t.Fatalf("Constraint = %q, want %q", pe.Constraint, ConstraintSandboxBuild)
	}
	// The message must name the alternative, not just the gap.
	if !strings.Contains(pe.Error(), "pre-build") {
		t.Fatalf("error does not say what to do instead: %s", pe.Error())
	}
}

// TestCheckSandboxSupport_HonoursHostPolicy: the process-wide no-host-execution
// switch is a second gate here, so a project with a sandbox spec cannot reach
// the host driver by a path that skips Registry.Resolve.
func TestCheckSandboxSupport_HonoursHostPolicy(t *testing.T) {
	restore := SetAllowHostExecution(false)
	defer SetAllowHostExecution(restore)

	err := CheckSandboxSupport(hostLike("host"), Requirements{}, "/p")
	var denied *HostExecutionDeniedError
	if !errors.As(err, &denied) {
		t.Fatalf("CheckSandboxSupport = %v, want *HostExecutionDeniedError under strict mode", err)
	}
}

// TestCheckSandboxSupport_IgnoresCapacity: a busy executor is still the one the
// project is bound to. Reporting load as a sandbox incompatibility would send
// the reader to edit their sandbox.yaml over a transient spike.
func TestCheckSandboxSupport_IgnoresCapacity(t *testing.T) {
	busy := sandboxCapable("busy")
	busy.caps.MaxConcurrent = 1
	if err := CheckSandboxSupport(busy, Requirements{RequireImageOverride: true}, "/p"); err != nil {
		t.Fatalf("a busy executor was reported as sandbox-incompatible: %v", err)
	}
}

func TestCheckSandboxSupport_NilExecutor(t *testing.T) {
	if err := CheckSandboxSupport(nil, Requirements{}, "/p"); !errors.Is(err, ErrExecutorNotFound) {
		t.Fatalf("CheckSandboxSupport(nil) = %v, want ErrExecutorNotFound", err)
	}
}
