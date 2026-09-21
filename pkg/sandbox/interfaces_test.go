package sandbox

// Tests for capabilities.interfaces (Task 20329): the repo-committed selector
// over host_interface grants.
//
// The invariant under test is the one the whole sandbox pipeline rests on: a
// file that arrives with a pull request may narrow what a project was granted
// and can never widen it. For interfaces that matters more than for anything
// else here, because widening would not merely expose something — it would take
// an interface away from the executor.

import (
	"errors"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/executor"
)

func TestParseInterfaceSelectors(t *testing.T) {
	spec, _, err := Parse([]byte("capabilities:\n  interfaces: [dut, can0, dut]\n"))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	// Deduplicated, because naming an interface twice is a typo rather than a
	// request for two of them — and there cannot be two of them.
	if got := spec.Capabilities.Interfaces; len(got) != 2 || got[0] != "dut" || got[1] != "can0" {
		t.Fatalf("interfaces = %v, want [dut can0]", got)
	}
}

func TestParseInterfaceSelectors_Refuses(t *testing.T) {
	if _, _, err := Parse([]byte("capabilities:\n  interfaces: [\"has space\"]\n")); err == nil {
		t.Error("a selector with a space was accepted; it can match no grant handle")
	}
	var b strings.Builder
	b.WriteString("capabilities:\n  interfaces: [")
	for i := 0; i <= MaxInterfaceSelectors; i++ {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString("if")
		b.WriteByte(byte('a' + i))
	}
	b.WriteString("]\n")
	if _, _, err := Parse([]byte(b.String())); err == nil ||
		!strings.Contains(err.Error(), "at most") {
		t.Errorf("%d selectors = %v, want a refusal", MaxInterfaceSelectors+1, err)
	}
}

// TestInterfaceSelectorOnlyNarrows is the security property. The spec picks from
// what the grants delivered; a name it was not granted is a refusal, not an
// addition.
func TestInterfaceSelectorOnlyNarrows(t *testing.T) {
	granted := []executor.HostInterface{
		{Name: "dut", Source: "cloop-lab0", Target: "eth1"},
		{Name: "can0", Source: "cloop-lab1", Target: "eth2"},
	}

	t.Run("narrows", func(t *testing.T) {
		spec, _, err := Parse([]byte("capabilities:\n  network: bench\n  interfaces: [dut]\n"))
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}
		out := executor.Spec{Interfaces: granted}
		r := &Resolved{Spec: spec}
		if aerr := r.ApplyTo(&out, "/srv/fw", allowAll{}); aerr != nil {
			t.Fatalf("ApplyTo: %v", aerr)
		}
		if len(out.Interfaces) != 1 || out.Interfaces[0].Name != "dut" {
			t.Fatalf("Interfaces = %+v, want only dut", out.Interfaces)
		}
	})

	t.Run("cannot add", func(t *testing.T) {
		spec, _, err := Parse([]byte("capabilities:\n  network: bench\n  interfaces: [uplink]\n"))
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}
		out := executor.Spec{Interfaces: granted}
		r := &Resolved{Spec: spec}
		aerr := r.ApplyTo(&out, "/srv/fw", allowAll{})
		var notGranted *InterfaceNotGrantedError
		if aerr == nil {
			t.Fatalf("a spec naming an ungranted interface was accepted; Interfaces = %+v",
				out.Interfaces)
		}
		if !errors.As(aerr, &notGranted) {
			t.Fatalf("error is %T (%v), want *InterfaceNotGrantedError so the UI can map it "+
				"to a 409 and name the operator remedy", aerr, aerr)
		}
		if !strings.Contains(notGranted.Remediation(), "--interfaces uplink") {
			t.Errorf("remediation %q does not name the flag that fixes it",
				notGranted.Remediation())
		}
	})
}

// TestInterfaceSelectorDemandsTheCapability keeps a bench spec from being placed
// on an executor that would silently drop it.
func TestInterfaceSelectorDemandsTheCapability(t *testing.T) {
	spec, _, err := Parse([]byte("capabilities:\n  interfaces: [dut]\n"))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !(&Resolved{Spec: spec}).Requirements().RequireInterfaces {
		t.Fatal("a spec naming an interface does not demand RequireInterfaces")
	}
}

// TestInterfacesAffectTheSandboxHash keeps two specs that differ only in which
// segment they claim from sharing a derived image and a cache entry.
func TestInterfacesAffectTheSandboxHash(t *testing.T) {
	a, _, _ := Parse([]byte("capabilities:\n  interfaces: [dut]\n"))
	b, _, _ := Parse([]byte("capabilities:\n  interfaces: [can0]\n"))
	if a.Hash() == b.Hash() {
		t.Fatal("two specs claiming different interfaces hash the same")
	}
}

// TestInterfacesAreNotZero keeps IsZero honest: a spec whose only content is an
// interface selector is not an empty spec, and treating it as one would drop the
// selector before it reached ApplyTo.
func TestInterfacesAreNotZero(t *testing.T) {
	spec, _, err := Parse([]byte("capabilities:\n  interfaces: [dut]\n"))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if spec.IsZero() {
		t.Fatal("a spec with an interface selector reports IsZero, so it would be discarded")
	}
}
