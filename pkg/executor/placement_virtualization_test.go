package executor

import (
	"errors"
	"strings"
	"testing"
)

// TestSelectRequireVirtualization covers the constraint that makes
// Capabilities.Virtualized actionable rather than decorative.
//
// The two rows that justify the field existing at all are the last two: a
// local Kata container (IsolationVM) and a Kata Pod on a remote cluster
// (IsolationRemote) must both satisfy the same requirement, even though they
// report different isolation values — while a *non*-Kata remote executor,
// which is indistinguishable from the second by isolation alone, must not.
func TestSelectRequireVirtualization(t *testing.T) {
	cases := []struct {
		name string
		caps Capabilities
		want bool
	}{
		{"host process", Capabilities{Isolation: IsolationNone}, false},
		{"runc container", Capabilities{Isolation: IsolationContainer}, false},
		{"remote agent", Capabilities{Isolation: IsolationRemote}, false},
		{"local kata", Capabilities{Isolation: IsolationVM, Virtualized: true}, true},
		{"kata pod on a remote cluster", Capabilities{Isolation: IsolationRemote, Virtualized: true}, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cands := []Candidate{{
				Executor: newCapExec("e", tc.caps),
				Health:   Health{State: NodeReady},
			}}
			got, err := Select(cands, Requirements{RequireVirtualization: true})
			if tc.want {
				if err != nil {
					t.Fatalf("Select rejected a virtualized executor: %v", err)
				}
				if got.Executor.ID() != "e" {
					t.Fatalf("Select chose %q, want %q", got.Executor.ID(), "e")
				}
				return
			}
			if err == nil {
				t.Fatalf("Select placed a workload requiring a hypervisor onto %q", tc.name)
			}
			var pe *PlacementError
			if !errors.As(err, &pe) {
				t.Fatalf("Select error is %T, want *PlacementError", err)
			}
			if pe.Constraint != ConstraintVirtualization {
				t.Errorf("constraint = %q, want %q", pe.Constraint, ConstraintVirtualization)
			}
		})
	}
}

// TestSelectVirtualizationNotRequiredByDefault is the compatibility guarantee.
// Requirements is built by several callers, and a zero value must keep placing
// onto ordinary container and remote executors — the field is opt-in.
func TestSelectVirtualizationNotRequiredByDefault(t *testing.T) {
	cands := []Candidate{{
		Executor: newCapExec("plain", Capabilities{Isolation: IsolationContainer}),
		Health:   Health{State: NodeReady},
	}}
	if _, err := Select(cands, Requirements{}); err != nil {
		t.Fatalf("a zero Requirements refused a plain container executor: %v", err)
	}
}

// TestSelectVirtualizationPrefersOverUnvirtualized checks that when a
// hypervisor is required and only some candidates provide one, the refusal
// names the right executors rather than the first one considered.
func TestSelectVirtualizationPrefersOverUnvirtualized(t *testing.T) {
	cands := []Candidate{
		{Executor: newCapExec("runc", Capabilities{Isolation: IsolationContainer}), Health: Health{State: NodeReady}},
		{Executor: newCapExec("kata", Capabilities{Isolation: IsolationVM, Virtualized: true}), Health: Health{State: NodeReady}},
	}
	got, err := Select(cands, Requirements{RequireVirtualization: true})
	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	if got.Executor.ID() != "kata" {
		t.Errorf("Select chose %q, want the virtualized candidate", got.Executor.ID())
	}
}

// TestVirtualizationRefusalIsActionable checks the sentence an operator reads.
// A placement constraint is often the only word they can search for, so the
// message must name the config keys that fix it rather than restate the
// requirement.
func TestVirtualizationRefusalIsActionable(t *testing.T) {
	cands := []Candidate{{
		Executor: newCapExec("runc", Capabilities{Isolation: IsolationContainer}),
		Health:   Health{State: NodeReady},
	}}
	_, err := Select(cands, Requirements{RequireVirtualization: true})
	if err == nil {
		t.Fatal("Select: want a refusal")
	}
	msg := err.Error()
	for _, want := range []string{"oci_runtime", "runtime_class"} {
		if !strings.Contains(msg, want) {
			t.Errorf("refusal does not mention %q, so it does not say how to fix it:\n%s", want, msg)
		}
	}
}
