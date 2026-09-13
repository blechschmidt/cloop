package remote_test

import (
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/executor/remote"
	"github.com/blechschmidt/cloop/pkg/version"
)

// TestHelloAgentVersionReachesTheControlPlane is the regression test for the
// first defect: HelloPayload.AgentVersion was declared with a comment about
// "diagnosing version-skew problems from the control plane", and nothing on the
// control plane ever read it. The value was decoded at the handshake and dropped,
// so no amount of fixing the agent side would have made a device's build visible.
func TestHelloAgentVersionReachesTheControlPlane(t *testing.T) {
	ex := newTestExecutor(t, nil)
	hello := defaultHello()
	hello.AgentVersion = "v0.4.2"

	_, sess := connect(t, ex, remote.AgentRecord{AgentID: "agent-1", Name: "edge-1"}, hello, nil)
	defer sess.Close()

	if got := sess.AgentVersion(); got != "v0.4.2" {
		t.Errorf("Session.AgentVersion() = %q, want %q", got, "v0.4.2")
	}
	// And reachable through the Executor, which is what the hub and the panel
	// actually hold — a value readable only from the Session would still be
	// invisible to everything that matters.
	if got := ex.AgentVersion(); got != "v0.4.2" {
		t.Errorf("Executor.AgentVersion() = %q, want %q", got, "v0.4.2")
	}
}

// TestAgentReportingSkewedBuildIsClassified is the scenario the task names: a
// device connects reporting a build well behind the hub, and the control plane
// must be able to say so from what the device sent.
func TestAgentReportingSkewedBuildIsClassified(t *testing.T) {
	ex := newTestExecutor(t, nil)
	hello := defaultHello()
	hello.AgentVersion = "v0.1.0"

	_, sess := connect(t, ex, remote.AgentRecord{AgentID: "agent-1", Name: "edge-1"}, hello, nil)
	defer sess.Close()

	skew, note := version.Classify("v0.4.0", ex.AgentVersion())
	if skew != version.SkewBehind {
		t.Fatalf("skew = %q, want %q", skew, version.SkewBehind)
	}
	if !skew.Material() {
		t.Error("a three-minor-release gap was not material")
	}
	for _, want := range []string{"v0.1.0", "v0.4.0"} {
		if !strings.Contains(note, want) {
			t.Errorf("note does not name %q: %q", want, note)
		}
	}
}

// TestLegacyAgentVersionIsNotMistakenForNewer covers the fleet as it exists
// today: every already-deployed agent reports the hardcoded "1". Parsed as a
// version that is major 1, which sorts *above* the hub's v0.x — so the devices
// most in need of upgrading would have been reported as ahead of their control
// plane, the exact opposite of the truth.
func TestLegacyAgentVersionIsNotMistakenForNewer(t *testing.T) {
	ex := newTestExecutor(t, nil)
	hello := defaultHello()
	hello.AgentVersion = version.LegacyAgentVersion

	_, sess := connect(t, ex, remote.AgentRecord{AgentID: "agent-1", Name: "edge-1"}, hello, nil)
	defer sess.Close()

	skew, _ := version.Classify("v0.4.0", ex.AgentVersion())
	if skew == version.SkewAhead {
		t.Fatal("an agent reporting the legacy placeholder was classified as NEWER than the hub")
	}
	if skew != version.SkewLegacy {
		t.Errorf("skew = %q, want %q", skew, version.SkewLegacy)
	}
}

// TestAgentVersionAbsentIsEmptyNotGarbage: an agent that reports no version at
// all must read back as empty, so the hub can distinguish "did not say" from
// any real value.
func TestAgentVersionAbsentIsEmptyNotGarbage(t *testing.T) {
	ex := newTestExecutor(t, nil)
	hello := defaultHello() // AgentVersion deliberately unset

	_, sess := connect(t, ex, remote.AgentRecord{AgentID: "agent-1", Name: "edge-1"}, hello, nil)
	defer sess.Close()

	if got := sess.AgentVersion(); got != "" {
		t.Errorf("Session.AgentVersion() = %q, want empty", got)
	}
	skew, note := version.Classify("v0.4.0", "")
	if skew != version.SkewUnknown {
		t.Errorf("skew = %q, want %q", skew, version.SkewUnknown)
	}
	if note == "" {
		t.Error("an unreported build carried no operator-facing note")
	}
}

// TestAgentVersionIsTrimmed guards against whitespace from a hand-edited unit
// or a shell-substituted build tag turning into a version nothing can compare.
func TestAgentVersionIsTrimmed(t *testing.T) {
	ex := newTestExecutor(t, nil)
	hello := defaultHello()
	hello.AgentVersion = "  v0.4.2\n"

	_, sess := connect(t, ex, remote.AgentRecord{AgentID: "agent-1", Name: "edge-1"}, hello, nil)
	defer sess.Close()

	if got := sess.AgentVersion(); got != "v0.4.2" {
		t.Errorf("Session.AgentVersion() = %q, want %q (untrimmed)", got, "v0.4.2")
	}
}

// TestAgentInventoryReportsWhetherAnyoneAnswered pins the bool on
// AgentInventory. The zero AgentCapabilities is indistinguishable from a device
// that genuinely advertised nothing, so an offline executor must be reported as
// "no session" rather than as a device with no CPUs and no harnesses.
func TestAgentInventoryReportsWhetherAnyoneAnswered(t *testing.T) {
	ex := newTestExecutor(t, nil)

	if _, ok := ex.AgentInventory(); ok {
		t.Error("AgentInventory reported a live advertisement with no session attached")
	}
	if got := ex.AgentVersion(); got != "" {
		t.Errorf("AgentVersion() = %q with no session, want empty", got)
	}

	hello := defaultHello()
	hello.AgentVersion = "v0.4.2"
	_, sess := connect(t, ex, remote.AgentRecord{AgentID: "agent-1", Name: "edge-1"}, hello, nil)
	defer sess.Close()

	caps, ok := ex.AgentInventory()
	if !ok {
		t.Fatal("AgentInventory reported no session while connected")
	}
	if caps.CPUs != 4 || caps.OS != "linux" || strings.Join(caps.Harnesses, ",") != "claude" {
		t.Errorf("advertisement not surfaced: %+v", caps)
	}
}
