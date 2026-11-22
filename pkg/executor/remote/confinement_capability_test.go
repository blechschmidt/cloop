package remote_test

// A device that speaks a protocol new enough to confine a payload and reports
// that it cannot build the sandbox (Task 49). The hub asked sgx to keep a
// project's run to its own directory, sgx could not — its unit denied the
// agent the Landlock calls — and the dispatch went out anyway, so the Start
// button failed once per click with a Landlock errno from the far side of the
// link, naming neither the device nor a remedy.

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
)

// helloWithHostSandbox is a hello from a current agent that does, or does not,
// say it can build the host sandbox.
func helloWithHostSandbox(version int, can bool) remote.HelloPayload {
	h := helloAt(version)
	h.Capabilities.HostSandbox = can
	return h
}

// TestConfinementRefusedWhenTheDeviceCannotSandbox: the refusal happens at the
// hub, before a lease is issued or a workspace staged, and it names the device
// and both ways out.
func TestConfinementRefusedWhenTheDeviceCannotSandbox(t *testing.T) {
	spec := plainSpec(t.TempDir())
	spec.ConfineToProject = true

	host := sandboxExecutor(t, executor.SandboxSettings{Mode: executor.SandboxModeHost}, nil)
	_, sess := connect(t, host, remote.AgentRecord{AgentID: "agent-1", Name: "edge-1"},
		helloWithHostSandbox(remote.ProtocolVersion, false), nil)
	_, err := host.Start(context.Background(), spec)
	sess.Close()
	if !errors.Is(err, remote.ErrProjectConfinementUnsupported) {
		t.Fatalf("Start = %v, want ErrProjectConfinementUnsupported", err)
	}
	for _, want := range []string{
		"edge-1",                         // which device
		"install --upgrade",              // the fix for the unit cloop itself rendered
		"Landlock",                       // what it is missing
		"executors.host_sandbox.opt_out", // the way out for a project that may share
		"containers",                     // and the one for a kernel without Landlock
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal should mention %q: %v", want, err)
		}
	}
}

// TestConfinementProceedsWhenTheDeviceCanSandbox: the capability is a reason to
// refuse, not a second switch for the feature — a device that says it can
// confine is dispatched to as before.
func TestConfinementProceedsWhenTheDeviceCanSandbox(t *testing.T) {
	spec := plainSpec(t.TempDir())
	spec.ConfineToProject = true

	host := sandboxExecutor(t, executor.SandboxSettings{Mode: executor.SandboxModeHost}, nil)
	_, sess := connect(t, host, remote.AgentRecord{AgentID: "agent-1", Name: "edge-1"},
		helloWithHostSandbox(remote.ProtocolVersion, true), nil)
	defer sess.Close()
	if _, err := host.Start(briefly(t), spec); errors.Is(err, remote.ErrProjectConfinementUnsupported) {
		t.Errorf("a device that can confine was refused: %v", err)
	}
}

// TestConfinementNotRefusedOnAnAgentThatNeverReports: below
// MinHostSandboxReportVersion the flag is silence rather than a denial — the
// field arrived with protocol v31 — so such an agent must be dispatched to as
// it was before this check existed, and refused by its own protocol check or
// by the device.
func TestConfinementNotRefusedOnAnAgentThatNeverReports(t *testing.T) {
	spec := plainSpec(t.TempDir())
	spec.ConfineToProject = true

	v := remote.MinHostSandboxReportVersion - 1
	if !remote.SupportsProjectConfinement(v) {
		t.Skipf("protocol v%d cannot confine at all, so this case cannot arise", v)
	}
	host := sandboxExecutor(t, executor.SandboxSettings{Mode: executor.SandboxModeHost}, nil)
	_, sess := connect(t, host, remote.AgentRecord{AgentID: "agent-1", Name: "edge-1"},
		helloWithHostSandbox(v, false), nil)
	defer sess.Close()
	if _, err := host.Start(briefly(t), spec); errors.Is(err, remote.ErrProjectConfinementUnsupported) {
		t.Errorf("an agent that never reports the capability was refused on it: %v", err)
	}
}

// TestConfinementCapabilityIgnoredInContainerMode: a container payload is kept
// to its bind mount by the engine, so the agent's Landlock has nothing to do
// with it and the dispatch must not be refused.
func TestConfinementCapabilityIgnoredInContainerMode(t *testing.T) {
	spec := plainSpec(t.TempDir())
	spec.ConfineToProject = true

	box := sandboxExecutor(t, executor.SandboxSettings{Mode: executor.SandboxModeContainer}, nil)
	_, sess := connect(t, box, remote.AgentRecord{AgentID: "agent-1", Name: "edge-1"},
		helloWithHostSandbox(remote.ProtocolVersion, false), nil)
	defer sess.Close()
	if _, err := box.Start(briefly(t), spec); errors.Is(err, remote.ErrProjectConfinementUnsupported) {
		t.Errorf("a container-mode dispatch was refused for confinement: %v", err)
	}
}

// TestReportsHostSandboxTracksTheProtocolItArrivedWith keeps the version gate
// honest: the capability and Spec.ReadOnly shipped in one release, and a build
// that moved one without the other would silently refuse working devices.
func TestReportsHostSandboxTracksTheProtocolItArrivedWith(t *testing.T) {
	if remote.MinHostSandboxReportVersion != remote.MinReadOnlyProjectsVersion {
		t.Errorf("MinHostSandboxReportVersion = %d, want MinReadOnlyProjectsVersion (%d): the capability "+
			"arrived with Spec.ReadOnly", remote.MinHostSandboxReportVersion, remote.MinReadOnlyProjectsVersion)
	}
	if remote.ReportsHostSandbox(remote.MinHostSandboxReportVersion-1) ||
		!remote.ReportsHostSandbox(remote.ProtocolVersion) {
		t.Error("ReportsHostSandbox disagrees with MinHostSandboxReportVersion")
	}
}
