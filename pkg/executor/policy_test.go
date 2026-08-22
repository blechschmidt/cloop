package executor

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// fakeExec is a minimal Executor whose only interesting property is its
// isolation level — which is the only thing the policy looks at.
type fakeExec struct {
	id        string
	kind      string
	isolation Isolation
}

func (f fakeExec) ID() string   { return f.id }
func (f fakeExec) Kind() string { return f.kind }
func (f fakeExec) Capabilities() Capabilities {
	return Capabilities{Isolation: f.isolation}
}
func (f fakeExec) Start(context.Context, Spec) (Handle, error)    { return Handle{}, nil }
func (f fakeExec) Signal(context.Context, string, Signal) error   { return nil }
func (f fakeExec) Status(context.Context, string) (Status, error) { return Status{}, nil }
func (f fakeExec) Stream(context.Context, string) (<-chan LogLine, error) {
	ch := make(chan LogLine)
	close(ch)
	return ch, nil
}
func (f fakeExec) HealthCheck(context.Context) error { return nil }

// restorePolicy resets the process-wide switch after a test mutates it. These
// tests therefore cannot be parallel with each other.
func restorePolicy(t *testing.T) {
	t.Helper()
	prev := HostExecutionAllowed()
	t.Cleanup(func() { allowHostExecution.Store(prev) })
}

func TestHostExecutionAllowed_DefaultsTrue(t *testing.T) {
	if !HostExecutionAllowed() {
		t.Fatal("the default policy must be permissive — a binary that never touches " +
			"the setting has to behave exactly as it did before it existed")
	}
}

// TestApplyHostExecutionPolicy_OnlyTightens is the ratchet. A control plane
// manages many projects, each with its own config.yaml; if applying a
// permissive one could re-open host execution, a tenant would be able to lift
// the operator's policy by editing a file they control.
func TestApplyHostExecutionPolicy_OnlyTightens(t *testing.T) {
	restorePolicy(t)

	SetAllowHostExecution(true)
	ApplyHostExecutionPolicy(false)
	if HostExecutionAllowed() {
		t.Fatal("a restrictive config did not tighten the policy")
	}

	ApplyHostExecutionPolicy(true)
	if HostExecutionAllowed() {
		t.Fatal("a permissive config loosened an already-hardened policy — one project's " +
			"config.yaml must not be able to re-enable host execution process-wide")
	}
}

func TestResolve_DeniesUnisolatedExecutorUnderStrictMode(t *testing.T) {
	restorePolicy(t)
	reg := NewRegistry()
	if err := reg.Register(fakeExec{id: "host", kind: KindLocalProcess, isolation: IsolationNone}); err != nil {
		t.Fatalf("register: %v", err)
	}

	SetAllowHostExecution(true)
	if _, err := reg.Resolve("/srv/proj"); err != nil {
		t.Fatalf("Resolve with host execution permitted: %v", err)
	}

	SetAllowHostExecution(false)
	_, err := reg.Resolve("/srv/proj")
	if err == nil {
		t.Fatal("Resolve handed out an un-isolated executor while host execution was denied")
	}
	if !errors.Is(err, ErrHostExecutionDenied) {
		t.Fatalf("Resolve error = %v, want it to wrap ErrHostExecutionDenied", err)
	}
	var denied *HostExecutionDeniedError
	if !errors.As(err, &denied) {
		t.Fatalf("Resolve error = %v, want a *HostExecutionDeniedError carrying alternatives", err)
	}
	if denied.ProjectPath != "/srv/proj" {
		t.Errorf("denial names project %q, want /srv/proj", denied.ProjectPath)
	}
	if !strings.Contains(denied.Error(), "allow_host_process") {
		t.Errorf("denial %q does not name the setting responsible", denied.Error())
	}
	// With nothing isolated registered, the message must say so rather than
	// pointing at an empty list of alternatives.
	if !strings.Contains(denied.Error(), "No isolated executor is configured") {
		t.Errorf("denial %q does not explain that there is nothing to move to", denied.Error())
	}
}

func TestResolve_AllowsIsolatedExecutorUnderStrictMode(t *testing.T) {
	restorePolicy(t)
	reg := NewRegistry()
	if err := reg.Register(fakeExec{id: "sandbox", kind: KindContainer, isolation: IsolationContainer}); err != nil {
		t.Fatalf("register: %v", err)
	}
	SetAllowHostExecution(false)

	ex, err := reg.Resolve("/srv/proj")
	if err != nil {
		t.Fatalf("strict mode blocked an isolated executor: %v", err)
	}
	if ex.ID() != "sandbox" {
		t.Fatalf("resolved %q, want sandbox", ex.ID())
	}
}

// TestResolve_DenialNamesAlternatives is what turns the 409 into something an
// operator can act on without reading documentation.
func TestResolve_DenialNamesAlternatives(t *testing.T) {
	restorePolicy(t)
	reg := NewRegistry()
	_ = reg.Register(fakeExec{id: "host", kind: KindLocalProcess, isolation: IsolationNone})
	_ = reg.Register(fakeExec{id: "sandbox", kind: KindContainer, isolation: IsolationContainer})
	_ = reg.Register(fakeExec{id: "edge-1", kind: KindRemoteAgent, isolation: IsolationRemote})
	if err := reg.SetDefault("host"); err != nil {
		t.Fatalf("SetDefault: %v", err)
	}
	SetAllowHostExecution(false)

	_, err := reg.Resolve("/srv/proj")
	var denied *HostExecutionDeniedError
	if !errors.As(err, &denied) {
		t.Fatalf("Resolve error = %v, want *HostExecutionDeniedError", err)
	}
	want := []string{"sandbox", "edge-1"}
	if len(denied.Alternatives) != len(want) {
		t.Fatalf("alternatives = %v, want %v", denied.Alternatives, want)
	}
	for _, id := range want {
		if !strings.Contains(denied.Error(), id) {
			t.Errorf("denial %q does not mention the available executor %q", denied.Error(), id)
		}
	}
	if strings.Contains(denied.Remediation(), "host") {
		t.Errorf("remediation %q offers the host executor as a way out of a host-execution ban",
			denied.Remediation())
	}
}

// TestResolveBinding_IgnoresPolicy: the Executors panel must be able to say
// "this project points at the host executor, which is currently forbidden".
// Collapsing that into "denied" would lose the target the operator needs to
// see in order to change it.
func TestResolveBinding_IgnoresPolicy(t *testing.T) {
	restorePolicy(t)
	reg := NewRegistry()
	_ = reg.Register(fakeExec{id: "host", kind: KindLocalProcess, isolation: IsolationNone})
	SetAllowHostExecution(false)

	ex, err := reg.resolveBinding("/srv/proj")
	if err != nil {
		t.Fatalf("resolveBinding under strict mode: %v", err)
	}
	if ex.ID() != "host" {
		t.Fatalf("resolveBinding returned %q, want host", ex.ID())
	}
}

func TestIsolatedIDs(t *testing.T) {
	reg := NewRegistry()
	_ = reg.Register(fakeExec{id: "host", kind: KindLocalProcess, isolation: IsolationNone})
	_ = reg.Register(fakeExec{id: "vm", kind: "microvm", isolation: IsolationVM})
	got := reg.IsolatedIDs()
	if len(got) != 1 || got[0] != "vm" {
		t.Fatalf("IsolatedIDs = %v, want [vm] — the host driver advertises no isolation", got)
	}
}
