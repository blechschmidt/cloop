package remote_test

// Tests for the hub side of the device virtualization probe (Task 20312).
//
// The defect these lock down was found by trying to do the thing they describe:
// running an Ubuntu image under a Kata runtime on a real remote executor whose
// host has no nested virtualization. The hub advertised that executor as
// hypervisor-isolated — because an admin had typed "kata" and nothing on the
// wire could disagree — placement accepted work that required a VM, and the
// dispatch died ~50s later inside the sandbox with "timed out waiting for QMP
// ready: Connection refused". There is no degraded mode to land in: Kata passes
// accel=kvm unconditionally and its bundled QEMU is built --disable-tcg, so the
// only honest outcomes are a VM or a refusal.
//
// Three properties, and the third matters as much as the first two: a device
// that was never asked must not be demoted, or shipping this build would strand
// every Kata executor already in the field.

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
)

// kataSandbox is the configuration an admin sets to ask for a VM.
func kataSandbox() executor.SandboxSettings {
	return executor.SandboxSettings{
		Mode: executor.SandboxModeContainer, Engine: "docker",
		Runtime: "kata", Image: "ubuntu:24.04",
	}
}

// helloReporting builds a hello at the given protocol version whose device
// either can or cannot start a VM.
func helloReporting(version int, virtualization bool) remote.HelloPayload {
	h := helloAt(version)
	h.Capabilities = remote.AgentCapabilities{
		OS: "linux", Arch: "amd64", Virtualization: virtualization,
	}
	return h
}

// TestDeviceWithoutKVMIsNotAdvertisedAsVirtualized is the false capability
// itself. Placement reads Capabilities.Virtualized to satisfy a project that
// required a hypervisor; claiming it for a device with no /dev/kvm routes
// exactly the work whose guarantee cannot be met onto the machine that cannot
// meet it.
func TestDeviceWithoutKVMIsNotAdvertisedAsVirtualized(t *testing.T) {
	ex := sandboxExecutor(t, kataSandbox(), nil)
	_, sess := connect(t, ex, remote.AgentRecord{AgentID: "agent-1", Name: "edge-1"},
		helloReporting(remote.MinVirtualizationProbeVersion, false), nil)
	defer sess.Close()

	if got := ex.Capabilities(); got.Virtualized {
		t.Error("executor advertises Virtualized for a device that reports no usable /dev/kvm")
	}
}

// TestKataLosesKernelIsolationWithoutKVM: for Kata the kernel isolation *is*
// the VM — the syscalls are served by a guest kernel — so a hypervisor the
// device cannot start takes that property with it. Reporting it would offer a
// boundary to a sandbox that never boots.
func TestKataLosesKernelIsolationWithoutKVM(t *testing.T) {
	ex := sandboxExecutor(t, kataSandbox(), nil)
	_, sess := connect(t, ex, remote.AgentRecord{AgentID: "agent-1", Name: "edge-1"},
		helloReporting(remote.MinVirtualizationProbeVersion, false), nil)
	defer sess.Close()

	if ex.Capabilities().KernelIsolated {
		t.Error("kata's kernel isolation is the guest kernel; without a VM it does not exist")
	}
}

// TestDeviceWithKVMIsAdvertisedAsVirtualized is the other direction, and guards
// against a fix that simply turns the capability off. A device that *can*
// virtualize under a runtime that does must still qualify, or a correct Kata
// deployment loses the placements it exists for.
func TestDeviceWithKVMIsAdvertisedAsVirtualized(t *testing.T) {
	ex := sandboxExecutor(t, kataSandbox(), nil)
	_, sess := connect(t, ex, remote.AgentRecord{AgentID: "agent-1", Name: "edge-1"},
		helloReporting(remote.MinVirtualizationProbeVersion, true), nil)
	defer sess.Close()

	if got := ex.Capabilities(); !got.Virtualized {
		t.Error("executor should advertise Virtualized for a kata runtime on a device with /dev/kvm")
	}
}

// TestPreProbeAgentKeepsItsConfiguredVirtualization is the no-stranding rule.
//
// A pre-v9 agent omits the field, and the zero value of a bool is false — so
// reading it unconditionally would demote every deployed Kata device the moment
// this build ships, refusing placements that work today. Absence is "unknown",
// not "no".
func TestPreProbeAgentKeepsItsConfiguredVirtualization(t *testing.T) {
	ex := sandboxExecutor(t, kataSandbox(), nil)
	_, sess := connect(t, ex, remote.AgentRecord{AgentID: "agent-1", Name: "edge-1"},
		helloReporting(remote.MinVirtualizationProbeVersion-1, false), nil)
	defer sess.Close()

	if got := ex.Capabilities(); !got.Virtualized {
		t.Error("a pre-probe agent was demoted on a field it never reported; " +
			"that strands every Kata device in the field")
	}
}

// TestGVisorSandboxSurvivesADeviceWithoutKVM keeps the narrowing pointed at the
// right property. gVisor's Sentry is a userspace kernel and never opens
// /dev/kvm, so a device with no virtualization still serves a kernel-isolated
// sandbox; clearing KernelIsolated alongside Virtualized would refuse
// placements this machine can honour.
func TestGVisorSandboxSurvivesADeviceWithoutKVM(t *testing.T) {
	s := kataSandbox()
	s.Runtime = "runsc"
	ex := sandboxExecutor(t, s, nil)
	_, sess := connect(t, ex, remote.AgentRecord{AgentID: "agent-1", Name: "edge-1"},
		helloReporting(remote.MinVirtualizationProbeVersion, false), nil)
	defer sess.Close()

	caps := ex.Capabilities()
	if !caps.KernelIsolated {
		t.Error("gVisor needs no hypervisor; KernelIsolated must survive a device without /dev/kvm")
	}
	if caps.Virtualized {
		t.Error("gVisor is not a hypervisor and must never report Virtualized")
	}
}

// TestDispatchIsRefusedWhenTheDeviceCannotVirtualize is the refusal that
// replaces the QMP timeout. Failing here costs nothing and names the cause;
// failing on the device costs ~50s and names neither KVM nor the executor.
func TestDispatchIsRefusedWhenTheDeviceCannotVirtualize(t *testing.T) {
	ex := sandboxExecutor(t, kataSandbox(), nil)
	_, sess := connect(t, ex, remote.AgentRecord{AgentID: "agent-1", Name: "edge-1"},
		helloReporting(remote.MinVirtualizationProbeVersion, false), nil)
	defer sess.Close()

	_, err := ex.Start(context.Background(), plainSpec(t.TempDir()))
	if !errors.Is(err, remote.ErrVirtualizationUnavailable) {
		t.Fatalf("Start error = %v, want ErrVirtualizationUnavailable", err)
	}
	// The diagnostic is the whole point: it must name the device, the device
	// file that is missing, and a boundary the machine can actually provide.
	for _, want := range []string{"edge-1", "/dev/kvm", "kata", "runsc"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("diagnostic should mention %q; got %q", want, err)
		}
	}
}

// TestDispatchIsNotRefusedForANonVMSandbox bounds the refusal. A plain
// container or a gVisor sandbox needs no hypervisor, so a device without one
// must still receive that work.
func TestDispatchIsNotRefusedForANonVMSandbox(t *testing.T) {
	for _, runtime := range []string{"", "runc", "runsc"} {
		s := kataSandbox()
		s.Runtime = runtime
		ex := sandboxExecutor(t, s, nil)
		_, sess := connect(t, ex, remote.AgentRecord{AgentID: "agent-1", Name: "edge-1"},
			helloReporting(remote.MinVirtualizationProbeVersion, false), nil)

		_, err := ex.Start(briefly(t), plainSpec(t.TempDir()))
		if errors.Is(err, remote.ErrVirtualizationUnavailable) {
			t.Errorf("runtime %q needs no hypervisor but was refused for lacking one", runtime)
		}
		sess.Close()
	}
}

// TestPreProbeAgentIsNotRefusedAVMDispatch is the no-stranding rule applied to
// dispatch rather than advertisement. Refusing work a fleet is running today,
// on the strength of a field its agents never sent, would be an outage caused
// by an upgrade to the hub alone.
func TestPreProbeAgentIsNotRefusedAVMDispatch(t *testing.T) {
	ex := sandboxExecutor(t, kataSandbox(), nil)
	_, sess := connect(t, ex, remote.AgentRecord{AgentID: "agent-1", Name: "edge-1"},
		helloReporting(remote.MinVirtualizationProbeVersion-1, false), nil)
	defer sess.Close()

	_, err := ex.Start(briefly(t), plainSpec(t.TempDir()))
	if errors.Is(err, remote.ErrVirtualizationUnavailable) {
		t.Error("a pre-probe agent was refused on a field it never reported")
	}
}

// --- preflight -----------------------------------------------------------

// findingFor returns the named finding, or a zero Finding.
func findingFor(r remote.PreflightReport, name string) remote.Finding {
	for _, f := range r.Findings {
		if f.Name == name {
			return f
		}
	}
	return remote.Finding{}
}

// TestPreflightFailsOnADeviceThatCannotVirtualize is the operator-facing half.
// Before this, `cloop executor test <id>` on a remote executor printed "this
// executor has no preflight" and went straight to a smoke test — so the one
// executor kind whose hardware the hub cannot inspect directly was also the one
// kind that reported nothing about it.
func TestPreflightFailsOnADeviceThatCannotVirtualize(t *testing.T) {
	ex := sandboxExecutor(t, kataSandbox(), nil)
	_, sess := connect(t, ex, remote.AgentRecord{AgentID: "agent-1", Name: "edge-1"},
		helloReporting(remote.MinVirtualizationProbeVersion, false), nil)
	defer sess.Close()

	report := ex.Preflight()
	if report.OK() {
		t.Fatal("preflight passed for a kata runtime on a device with no /dev/kvm")
	}
	f := findingFor(report, "virtualization")
	if f.Level != remote.LevelFail {
		t.Fatalf("virtualization finding = %+v, want a fail", f)
	}
	if !strings.Contains(f.Message, "/dev/kvm") {
		t.Errorf("finding should name the missing device; got %q", f.Message)
	}
	// A fatal finding with no way out is a dead end, not a diagnosis.
	for _, want := range []string{"nested virtualization", "runsc"} {
		if !strings.Contains(f.Fix, want) {
			t.Errorf("remedy should mention %q; got %q", want, f.Fix)
		}
	}
}

// TestPreflightPassesOnADeviceThatCanVirtualize keeps the check from being a
// blanket refusal of every Kata executor.
func TestPreflightPassesOnADeviceThatCanVirtualize(t *testing.T) {
	ex := sandboxExecutor(t, kataSandbox(), nil)
	_, sess := connect(t, ex, remote.AgentRecord{AgentID: "agent-1", Name: "edge-1"},
		helloReporting(remote.MinVirtualizationProbeVersion, true), nil)
	defer sess.Close()

	report := ex.Preflight()
	if !report.OK() {
		t.Fatalf("preflight failed on a capable device: %v", report.Err())
	}
	if got := findingFor(report, "virtualization").Level; got != remote.LevelOK {
		t.Errorf("virtualization finding level = %q, want ok", got)
	}
}

// TestPreflightWarnsRatherThanFailsOnAPreProbeAgent: "cloop did not ask" and
// "the device said no" are different facts and must read differently. Failing
// here would make the preflight refuse working deployments; staying silent
// would let an operator read a clean checklist as proof of a hypervisor.
func TestPreflightWarnsRatherThanFailsOnAPreProbeAgent(t *testing.T) {
	ex := sandboxExecutor(t, kataSandbox(), nil)
	_, sess := connect(t, ex, remote.AgentRecord{AgentID: "agent-1", Name: "edge-1"},
		helloReporting(remote.MinVirtualizationProbeVersion-1, false), nil)
	defer sess.Close()

	report := ex.Preflight()
	if !report.OK() {
		t.Errorf("a pre-probe agent must not fail preflight: %v", report.Err())
	}
	f := findingFor(report, "virtualization")
	if f.Level != remote.LevelWarn {
		t.Fatalf("virtualization finding = %+v, want a warn", f)
	}
	if !strings.Contains(f.Fix, "--upgrade") {
		t.Errorf("remedy should point at the agent upgrade; got %q", f.Fix)
	}
}

// TestPreflightFailsWhenNoAgentIsConnected: an executor with nothing on the
// other end cannot run anything, and that is the first thing to say.
func TestPreflightFailsWhenNoAgentIsConnected(t *testing.T) {
	ex := sandboxExecutor(t, kataSandbox(), nil)

	report := ex.Preflight()
	if report.OK() {
		t.Fatal("preflight passed with no agent connected")
	}
	if got := findingFor(report, "agent").Level; got != remote.LevelFail {
		t.Errorf("agent finding level = %q, want fail", got)
	}
}
