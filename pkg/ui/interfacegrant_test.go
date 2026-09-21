package ui

// Tests for applyInterfaceGrants (Task 20329): the seam where a broker
// host_interface grant becomes a Spec field.
//
// devicegrant_test.go's sibling, and it exists for the same reason: this
// package is where secretbroker.GrantedInterface and executor.HostInterface
// meet, so it is the only place that can check the two duplicated definitions
// still agree. They are duplicated on purpose — pkg/secretbroker does not
// import pkg/executor — and duplication that nothing checks is duplication that
// drifts.

import (
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
)

func ifaceSandboxExecutor() *deviceCapsExecutor {
	return &deviceCapsExecutor{
		id: "sbx", kind: executor.KindContainer,
		caps: executor.Capabilities{
			Isolation:          executor.IsolationContainer,
			SupportsInterfaces: true,
		},
	}
}

// TestApplyInterfaceGrantsCarriesEveryField is the happy path, field by field.
// A conversion that dropped Address would produce a link that is up and
// unaddressed, which on a bench looks like a cabling fault rather than a bug
// here.
func TestApplyInterfaceGrantsCarriesEveryField(t *testing.T) {
	granted := []secretbroker.GrantedInterface{
		{Name: "dut", Source: "cloop-lab0", Target: "eth1",
			Address: "172.31.99.200/24", Gateway: "172.31.99.1", MTU: 9000},
		{Name: "capture", Source: "enp4s0f1", Target: "enp4s0f1"},
	}
	spec, err := applyInterfaceGrantsList(executor.Spec{Env: []string{}},
		ifaceSandboxExecutor(), granted)
	if err != nil {
		t.Fatalf("applyInterfaceGrants: %v", err)
	}
	want := []executor.HostInterface{
		{Name: "dut", Source: "cloop-lab0", Target: "eth1",
			Address: "172.31.99.200/24", Gateway: "172.31.99.1", MTU: 9000},
		{Name: "capture", Source: "enp4s0f1", Target: "enp4s0f1"},
	}
	if len(spec.Interfaces) != len(want) {
		t.Fatalf("Interfaces = %+v, want %d", spec.Interfaces, len(want))
	}
	for i := range want {
		if spec.Interfaces[i] != want[i] {
			t.Errorf("interface %d = %+v, want %+v", i, spec.Interfaces[i], want[i])
		}
	}

	// Handles, never host interface names: the host's name for a netdev is a
	// fact about one bench, and what the workload needs is the sandbox-side
	// name, which it can enumerate.
	var names string
	for _, kv := range spec.Env {
		if strings.HasPrefix(kv, "CLOOP_HOST_INTERFACES=") {
			names = strings.TrimPrefix(kv, "CLOOP_HOST_INTERFACES=")
		}
	}
	if names != "dut,capture" {
		t.Errorf("CLOOP_HOST_INTERFACES = %q, want \"dut,capture\"", names)
	}
	if strings.Contains(strings.Join(spec.Env, " "), "cloop-lab0") {
		t.Error("the environment leaks the host's own interface name, which describes the " +
			"bench's wiring rather than what the project was granted")
	}
}

// TestApplyInterfaceGrantsRefusesAnExecutorThatCannotMoveOne is the difference
// from the device path that the whole function exists to encode.
//
// A device grant on the host driver is satisfied in the weakest possible sense
// — the workload could already open every node the hub user can — so that case
// is a warning there. Nothing is ever "already visible" for an interface, so
// every executor without the capability is an error here, including that one.
func TestApplyInterfaceGrantsRefusesAnExecutorThatCannotMoveOne(t *testing.T) {
	granted := []secretbroker.GrantedInterface{{Name: "dut", Source: "cloop-lab0", Target: "eth1"}}

	for _, tc := range []struct {
		name string
		ex   *deviceCapsExecutor
	}{
		{"kubernetes", &deviceCapsExecutor{id: "k8s", kind: executor.KindKubernetes,
			caps: executor.Capabilities{Isolation: executor.IsolationContainer}}},
		// The host driver, which the device path lets through with a warning.
		{"host process", &deviceCapsExecutor{id: "host", kind: executor.KindLocalProcess,
			caps: executor.Capabilities{
				Isolation:            executor.IsolationNone,
				SharesHostFilesystem: true,
			}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spec, err := applyInterfaceGrantsList(executor.Spec{}, tc.ex, granted)
			if err == nil {
				t.Fatalf("an executor that cannot move an interface accepted the grant; "+
					"spec.Interfaces = %+v", spec.Interfaces)
			}
			if !strings.Contains(err.Error(), "dut") {
				t.Errorf("refusal %q does not name the grant that cannot be honoured", err)
			}
			if !strings.Contains(err.Error(), "Kata or gVisor") {
				t.Errorf("refusal %q does not warn that a kernel-isolated runtime cannot "+
					"honour this either, which is the next thing an operator tries", err)
			}
		})
	}
}

// TestApplyInterfaceGrantsRefusesTwoGrantsOnOneNetdev covers the collision only
// the assembled list can reveal: two grants, each valid alone, both claiming an
// interface that can live in exactly one namespace.
func TestApplyInterfaceGrantsRefusesTwoGrantsOnOneNetdev(t *testing.T) {
	_, err := applyInterfaceGrantsList(executor.Spec{}, ifaceSandboxExecutor(),
		[]secretbroker.GrantedInterface{
			{Name: "a", Source: "cloop-lab0", Target: "eth1"},
			{Name: "b", Source: "cloop-lab0", Target: "eth2"},
		})
	if err == nil || !strings.Contains(err.Error(), "claimed by two grants") {
		t.Fatalf("two grants on one netdev = %v, want a refusal", err)
	}
}

// TestApplyInterfaceGrantsIsANoOpWithoutGrants keeps the common case free of
// side effects: nearly every project has no interface grant, and a spec that
// grew an empty env entry for one would change the sandbox hash for nothing.
func TestApplyInterfaceGrantsIsANoOpWithoutGrants(t *testing.T) {
	in := executor.Spec{Env: []string{"A=1"}}
	out, err := applyInterfaceGrantsList(in, ifaceSandboxExecutor(), nil)
	if err != nil {
		t.Fatalf("applyInterfaceGrants with no grants: %v", err)
	}
	if len(out.Interfaces) != 0 || len(out.Env) != 1 {
		t.Errorf("spec changed without a grant: %+v", out)
	}
}
