package secretbroker

import (
	"errors"
	"strings"
	"testing"
)

func TestParseInterfaceInventory(t *testing.T) {
	got, err := ParseInterfaceInventory([]byte(`
# the bench
dut=cloop-lab0,target=eth1,address=172.31.99.200/24,gateway=172.31.99.1
can0=enp3s0,target=eth1x
capture=enp4s0f1,mtu=9000
v6=cloop-lab2,address=fd00::10/64
`))
	if err != nil {
		t.Fatalf("ParseInterfaceInventory: %v", err)
	}
	if len(got) != 4 {
		t.Fatalf("parsed %d entries, want 4: %+v", len(got), got)
	}
	if got[0] != (GrantedInterface{Name: "dut", Source: "cloop-lab0", Target: "eth1",
		Address: "172.31.99.200/24", Gateway: "172.31.99.1"}) {
		t.Errorf("first entry = %+v", got[0])
	}
	// An entry with no target takes the source's name, so a workload looking
	// for well-known hardware finds it where it expects.
	if got[2].Target != "enp4s0f1" || got[2].MTU != 9000 {
		t.Errorf("third entry = %+v, want target=enp4s0f1 mtu=9000", got[2])
	}
	// A v6 address survives the parse, which the colon-delimited device format
	// could not have carried at all — the reason this kind has its own grammar.
	if got[3].Address != "fd00::10/64" {
		t.Errorf("v6 address = %q, want fd00::10/64", got[3].Address)
	}
}

func TestParseInterfaceInventory_Refuses(t *testing.T) {
	cases := []struct {
		name, payload, want string
	}{
		{"empty", "", "empty"},
		{"no equals", "dut cloop-lab0", "name=ifname form"},
		{"unknown attribute", "dut=eth1,addres=10.0.0.1/8", "unknown attribute"},
		{"bare attribute", "dut=eth1,writable", "key=value form"},
		{"non-numeric mtu", "dut=eth1,mtu=big", "not a number"},
		{"loopback", "lo0=lo", "loopback"},
		{"docker bridge", "d=docker0", "Docker's own bridge"},
		{"per-network bridge", "d=br-328fcf8d72a7", "veth end attached to it"},
		{"duplicate handle", "a=veth0\na=veth1", "already defined"},
		{"two handles one netdev", "a=veth0\nb=veth0", "already claimed"},
		{"two entries one target", "a=veth0,target=eth1\nb=veth1,target=eth1", "already appears"},
		{"bare address", "a=veth0,address=10.0.0.1", "prefix length"},
		{"gateway alone", "a=veth0,gateway=10.0.0.1", "no address"},
		{"ifname too long", "a=this-name-is-way-too-long", "at most 15"},
		{"comment only", "# nothing here", "defines no interfaces"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseInterfaceInventory([]byte(tc.payload))
			if err == nil {
				t.Fatalf("ParseInterfaceInventory(%q) = nil, want a refusal", tc.payload)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

// TestHostInterfaceIsARegisteredKind is the check that keeps a new kind from
// being invisible: a stored grant whose kind fails Valid() is refused at lease
// time, long after an operator was allowed to create it.
func TestHostInterfaceIsARegisteredKind(t *testing.T) {
	if !KindHostInterface.Valid() {
		t.Error("KindHostInterface is not Valid(), so a stored grant would fail at lease time")
	}
	got, err := ParseKind("host_interface")
	if err != nil || got != KindHostInterface {
		t.Errorf("ParseKind(\"host_interface\") = %q, %v", got, err)
	}
	var listed bool
	for _, k := range Kinds() {
		if k == KindHostInterface {
			listed = true
		}
	}
	if !listed {
		t.Error("KindHostInterface is missing from Kinds(), so it is invisible in CLI help " +
			"and in the dashboard's kind picker, which is populated from it")
	}
}

func TestInterfaceConstraintsAreFenced(t *testing.T) {
	// An allowlist is mandatory, for the reason host_device's is: a grant that
	// matched everything in the inventory would open every segment the host
	// has, which is never what an operator meant to type.
	if err := (Constraints{}).ValidateFor(KindHostInterface); err == nil ||
		!strings.Contains(err.Error(), "interface allowlist") {
		t.Errorf("empty constraints on host_interface = %v, want a refusal", err)
	}
	if err := (Constraints{Interfaces: []string{"dut"}}).ValidateFor(KindHostInterface); err != nil {
		t.Errorf("a named interface = %v, want nil", err)
	}
	// And it applies to nothing else: an interface allowlist on a PAT grant is
	// a constraint that gates nothing, which reads as a boundary and is not one.
	err := (Constraints{Repos: []string{"x"}, Interfaces: []string{"dut"}}).ValidateFor(KindGitHubPAT)
	if err == nil || !strings.Contains(err.Error(), "applies to host_interface grants") {
		t.Errorf("interfaces on a github_pat grant = %v, want a refusal", err)
	}
	if !errors.Is(err, ErrInvalidConstraint) {
		t.Errorf("refusal does not wrap ErrInvalidConstraint: %v", err)
	}
}

func TestInterfaceConstraintsInSummary(t *testing.T) {
	s := Constraints{Interfaces: []string{"dut", "can0"}}.Summary()
	if !strings.Contains(s, "interfaces=can0|dut") {
		t.Errorf("Summary() = %q, want the interface allowlist in it — an audit row that "+
			"omits it would not say which segments the grant opened", s)
	}
}
