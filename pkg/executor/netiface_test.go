package executor

import (
	"errors"
	"strings"
	"testing"
)

// The interface validator is the layer that stands between an operator's typo
// and a host that has given away the netdev it is reachable on, so these tests
// lean on the refusals rather than on the happy path.

func TestValidateHostInterface_Accepts(t *testing.T) {
	cases := []struct {
		name string
		in   HostInterface
	}{
		{"bare", HostInterface{Name: "dut", Source: "enp3s0"}},
		{"renamed", HostInterface{Name: "dut", Source: "cloop-lab0", Target: "eth1"}},
		{"addressed", HostInterface{Name: "dut", Source: "cloop-lab0", Target: "eth1",
			Address: "172.31.99.200/24"}},
		{"routed", HostInterface{Name: "dut", Source: "cloop-lab0", Target: "eth1",
			Address: "172.31.99.200/24", Gateway: "172.31.99.1"}},
		{"v6", HostInterface{Name: "dut", Source: "cloop-lab0",
			Address: "fd00::10/64", Gateway: "fd00::1"}},
		{"jumbo", HostInterface{Name: "cap", Source: "enp4s0f1", MTU: 9000}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := ValidateHostInterface(tc.in); err != nil {
				t.Fatalf("ValidateHostInterface(%+v) = %v, want nil", tc.in, err)
			}
		})
	}
}

func TestValidateHostInterface_Refuses(t *testing.T) {
	cases := []struct {
		name string
		in   HostInterface
		// want is a fragment the message must carry, so a refusal that fires
		// for the wrong reason does not pass as the right one.
		want string
	}{
		{"no name", HostInterface{Source: "eth1"}, "name is empty"},
		{"no source", HostInterface{Name: "dut"}, "empty source name"},
		{"loopback", HostInterface{Name: "dut", Source: "lo"}, "loopback"},
		{"docker bridge", HostInterface{Name: "dut", Source: "docker0"}, "Docker's own bridge"},
		{"podman bridge", HostInterface{Name: "dut", Source: "podman0"}, "Podman's own bridge"},
		{"libvirt bridge", HostInterface{Name: "dut", Source: "virbr0"}, "libvirt"},
		{"per-network bridge", HostInterface{Name: "dut", Source: "br-328fcf8d72a7"},
			"veth end attached to it"},
		// IFNAMSIZ. The kernel would refuse it; saying so here names the grant.
		{"too long", HostInterface{Name: "dut", Source: "this-name-is-way-too-long"},
			"kernel allows"},
		{"slash", HostInterface{Name: "dut", Source: "eth/1"}, "slash"},
		{"colon", HostInterface{Name: "dut", Source: "eth0:1"}, "alias separator"},
		{"comma", HostInterface{Name: "dut", Source: "eth0,x"}, "field separators"},
		{"flag-shaped", HostInterface{Name: "dut", Source: "-rf"}, "command-line flag"},
		{"target lo", HostInterface{Name: "dut", Source: "eth1", Target: "lo"}, "loopback"},
		{"bare address", HostInterface{Name: "dut", Source: "eth1", Address: "172.31.99.200"},
			"prefix length"},
		{"junk address", HostInterface{Name: "dut", Source: "eth1", Address: "nonsense"},
			"prefix length"},
		{"gateway without address", HostInterface{Name: "dut", Source: "eth1", Gateway: "10.0.0.1"},
			"no address"},
		{"gateway family mismatch", HostInterface{Name: "dut", Source: "eth1",
			Address: "172.31.99.200/24", Gateway: "fd00::1"}, "different"},
		{"mtu too small", HostInterface{Name: "dut", Source: "eth1", MTU: 10}, "outside"},
		{"mtu too large", HostInterface{Name: "dut", Source: "eth1", MTU: 1 << 20}, "outside"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateHostInterface(tc.in)
			if err == nil {
				t.Fatalf("ValidateHostInterface(%+v) = nil, want a refusal", tc.in)
			}
			if !errors.Is(err, ErrInvalidSpec) {
				t.Errorf("error does not wrap ErrInvalidSpec: %v", err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

// TestValidateInterfaces_RefusesTwoGrantsOnOneNetdev is the collision devices
// do not have. A device node can be opened twice; an interface lives in exactly
// one namespace, so the second move would fail and which grant won would be
// decided by ordering.
func TestValidateInterfaces_RefusesTwoGrantsOnOneNetdev(t *testing.T) {
	err := ValidateInterfaces([]HostInterface{
		{Name: "a", Source: "cloop-lab0", Target: "eth1"},
		{Name: "b", Source: "cloop-lab0", Target: "eth2"},
	})
	if err == nil || !strings.Contains(err.Error(), "claimed by two grants") {
		t.Fatalf("two grants on one host interface = %v, want a refusal naming the collision", err)
	}
}

func TestValidateInterfaces_RefusesCollisionsAndOverflow(t *testing.T) {
	if err := ValidateInterfaces([]HostInterface{
		{Name: "a", Source: "veth-a", Target: "eth1"},
		{Name: "a", Source: "veth-b", Target: "eth2"},
	}); err == nil || !strings.Contains(err.Error(), "listed twice") {
		t.Errorf("duplicate handle = %v, want a refusal", err)
	}
	if err := ValidateInterfaces([]HostInterface{
		{Name: "a", Source: "veth-a", Target: "eth1"},
		{Name: "b", Source: "veth-b", Target: "eth1"},
	}); err == nil || !strings.Contains(err.Error(), "both appear as") {
		t.Errorf("duplicate target = %v, want a refusal", err)
	}
	over := make([]HostInterface, MaxInterfaces+1)
	for i := range over {
		over[i] = HostInterface{Name: string(rune('a' + i)), Source: "veth" + string(rune('a'+i))}
	}
	if err := ValidateInterfaces(over); err == nil || !strings.Contains(err.Error(), "at most") {
		t.Errorf("%d interfaces = %v, want a refusal", len(over), err)
	}
}

func TestHostInterface_EffectiveTarget(t *testing.T) {
	if got := (HostInterface{Source: "cloop-lab0"}).EffectiveTarget(); got != "cloop-lab0" {
		t.Errorf("empty Target = %q, want the source name", got)
	}
	if got := (HostInterface{Source: "cloop-lab0", Target: "eth1"}).EffectiveTarget(); got != "eth1" {
		t.Errorf("Target = %q, want eth1", got)
	}
}

// TestSpecRefusesInterfacesWithDisableNetwork pins the contradiction. Silently
// resolving it either way produces a lie: a sandbox told it has no network that
// has one, or a host that gave away an interface the workload cannot see.
func TestSpecRefusesInterfacesWithDisableNetwork(t *testing.T) {
	s := Spec{
		WorkDir:        t.TempDir(),
		Argv:           []string{"true"},
		DisableNetwork: true,
		Interfaces:     []HostInterface{{Name: "dut", Source: "cloop-lab0", Target: "eth1"}},
	}
	err := s.Validate()
	if err == nil || !strings.Contains(err.Error(), "disables networking") {
		t.Fatalf("Validate with both = %v, want a refusal naming the contradiction", err)
	}
	if !strings.Contains(err.Error(), "dut") {
		t.Errorf("refusal %q does not name the grant that conflicts", err)
	}
}

// TestSpecRequiresInterfaceCapability keeps placement honest: a spec carrying
// interfaces must demand an executor that honours them, or it would be placed
// on one that silently drops the field.
func TestSpecRequiresInterfaceCapability(t *testing.T) {
	s := Spec{Interfaces: []HostInterface{{Name: "dut", Source: "cloop-lab0"}}}
	if !s.SandboxRequirements().RequireInterfaces {
		t.Fatal("a spec with interfaces does not set RequireInterfaces, so it could be " +
			"placed on an executor that cannot move one")
	}
	if (Spec{}).SandboxRequirements().RequireInterfaces {
		t.Error("a spec without interfaces demands the capability, which would refuse " +
			"ordinary executors")
	}
}
