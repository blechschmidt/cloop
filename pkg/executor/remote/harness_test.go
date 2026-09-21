package remote_test

// Tests for the harness placement refusal (Task 20332).
//
// The bug these pin down is not that a check was wrong — it is that a check
// everything was written for never ran. AgentCapabilities.Harnesses carried the
// device's inventory, executor.Requirements carried a Harnesses field, and
// pkg/executor/placement carried a ConstraintHarness refusal; nothing joined
// them, so a device advertising only `cloop` was sent claudecode work forever
// and failed on the far side with "executable file not found in $PATH".
//
// So the cases worth holding are the four the join has to get right: refuse
// when the device really cannot run it, and stay silent in each of the three
// situations that look like absence but are not.

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
)

// helloWithHarnesses is helloAt with a stated agent-CLI inventory.
func helloWithHarnesses(version int, harnesses ...string) remote.HelloPayload {
	h := helloAt(version)
	h.Capabilities.Harnesses = harnesses
	return h
}

// claudeSpec is a workload that will drive the claude CLI once it is running.
func claudeSpec(workDir string) executor.Spec {
	s := plainSpec(workDir)
	s.Harness = "claude"
	return s
}

// TestHostModeRefusesMissingHarness is the reported failure, in one assertion.
//
// The device advertises `cloop` and nothing else — which is exactly what the
// sgx agent reported — and the project drives `claude`. Before this refusal the
// dispatch went out, a GitHub credential was leased and shipped, a workspace was
// provisioned, and the run died half a second later on the device.
func TestHostModeRefusesMissingHarness(t *testing.T) {
	ex := sandboxExecutor(t, executor.SandboxSettings{Mode: executor.SandboxModeHost}, nil)
	_, sess := connect(t, ex, remote.AgentRecord{AgentID: "agent-1", Name: "edge-1"},
		helloWithHarnesses(remote.MinSandboxModeVersion, "cloop"), nil)
	defer sess.Close()

	_, err := ex.Start(context.Background(), claudeSpec(t.TempDir()))
	if !errors.Is(err, remote.ErrHarnessUnavailable) {
		t.Fatalf("Start error = %v, want ErrHarnessUnavailable", err)
	}
	// An operator reads this instead of the $PATH error, so it has to carry
	// everything that one did not: which device, which binary, what the device
	// does have, and the two ways out.
	for _, want := range []string{"edge-1", "claude", "cloop", "container sandbox", remote.HarnessImageHint} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("diagnostic should mention %q; got %q", want, err)
		}
	}
}

// TestContainerModeIgnoresDeviceHarnesses guards the remedy against the fix.
//
// Switching the executor to a container sandbox whose image carries `claude` is
// what the refusal above tells an operator to do. The device's own PATH is
// unchanged by that and still advertises only `cloop`, so a check that did not
// gate on the mode would refuse the operator's compliance with its own advice.
func TestContainerModeIgnoresDeviceHarnesses(t *testing.T) {
	ex := sandboxExecutor(t, executor.SandboxSettings{
		Mode: executor.SandboxModeContainer, Engine: "docker", Image: remote.HarnessImageHint,
	}, nil)
	_, sess := connect(t, ex, remote.AgentRecord{AgentID: "agent-1", Name: "edge-1"},
		helloWithHarnesses(remote.MinSandboxModeVersion, "cloop"), nil)
	defer sess.Close()

	_, err := ex.Start(briefly(t), claudeSpec(t.TempDir()))
	if errors.Is(err, remote.ErrHarnessUnavailable) {
		t.Fatalf("container mode must not be refused on the device's own inventory; got %v", err)
	}
}

// TestSpecWithoutHarnessIsNotRefused keeps the "no opinion" reading of an unset
// field. `cloop executor test` and the hub's smoke run dispatch workloads that
// drive no agent CLI at all; forcing them to name one would make every such
// probe fail on a device that happens to lack `claude`.
func TestSpecWithoutHarnessIsNotRefused(t *testing.T) {
	ex := sandboxExecutor(t, executor.SandboxSettings{Mode: executor.SandboxModeHost}, nil)
	_, sess := connect(t, ex, remote.AgentRecord{AgentID: "agent-1", Name: "edge-1"},
		helloWithHarnesses(remote.MinSandboxModeVersion, "cloop"), nil)
	defer sess.Close()

	_, err := ex.Start(briefly(t), plainSpec(t.TempDir()))
	if errors.Is(err, remote.ErrHarnessUnavailable) {
		t.Fatalf("a spec naming no harness must not be refused; got %v", err)
	}
}

// TestSilentInventoryIsNotADenial matches hasHarness in pkg/executor/placement:
// a device that advertised nothing has not said it lacks anything.
//
// This is the compatibility case. An older agent, or one whose probe found
// nothing to report, sends an empty list — and refusing on that would strand a
// fleet mid-upgrade on a check introduced after it shipped.
func TestSilentInventoryIsNotADenial(t *testing.T) {
	ex := sandboxExecutor(t, executor.SandboxSettings{Mode: executor.SandboxModeHost}, nil)
	_, sess := connect(t, ex, remote.AgentRecord{AgentID: "agent-1", Name: "edge-1"},
		helloAt(remote.MinSandboxModeVersion), nil)
	defer sess.Close()

	_, err := ex.Start(briefly(t), claudeSpec(t.TempDir()))
	if errors.Is(err, remote.ErrHarnessUnavailable) {
		t.Fatalf("an empty inventory must not be read as a denial; got %v", err)
	}
}

// TestHarnessMatchIsCaseInsensitive: the inventory is whatever the device's
// probe found on PATH, and the requirement is derived from a provider name.
// Neither side normalises the other, so the comparison has to.
func TestHarnessMatchIsCaseInsensitive(t *testing.T) {
	ex := sandboxExecutor(t, executor.SandboxSettings{Mode: executor.SandboxModeHost}, nil)
	_, sess := connect(t, ex, remote.AgentRecord{AgentID: "agent-1", Name: "edge-1"},
		helloWithHarnesses(remote.MinSandboxModeVersion, "Claude"), nil)
	defer sess.Close()

	_, err := ex.Start(briefly(t), claudeSpec(t.TempDir()))
	if errors.Is(err, remote.ErrHarnessUnavailable) {
		t.Fatalf("Claude should satisfy a claude requirement; got %v", err)
	}
}

// TestUnsetSandboxModeChecksTheDevice is the configuration the report came from.
//
// The sgx executor had no sandbox row at all, and unset means the host process —
// the same placement as an explicit host mode, for a different reason. A check
// that only fired on the explicit value would have missed the actual bug.
func TestUnsetSandboxModeChecksTheDevice(t *testing.T) {
	ex := sandboxExecutor(t, executor.SandboxSettings{}, nil)
	_, sess := connect(t, ex, remote.AgentRecord{AgentID: "agent-1", Name: "edge-1"},
		helloWithHarnesses(remote.MinSandboxModeVersion, "cloop"), nil)
	defer sess.Close()

	_, err := ex.Start(context.Background(), claudeSpec(t.TempDir()))
	if !errors.Is(err, remote.ErrHarnessUnavailable) {
		t.Fatalf("Start error = %v, want ErrHarnessUnavailable", err)
	}
}

// TestSandboxRequirementsCarryTheHarness ties the Spec field to the placement
// constraint, which is the half of the join that failover uses: Start refuses a
// pinned project, and placement has to reach the same verdict when it is
// assembling candidates, or the scheduler will hand work to an executor that
// then refuses it.
func TestSandboxRequirementsCarryTheHarness(t *testing.T) {
	if got := (executor.Spec{Harness: "claude"}).SandboxRequirements().Harnesses; len(got) != 1 || got[0] != "claude" {
		t.Errorf("Harnesses = %v, want [claude]", got)
	}
	// Empty must stay nil rather than [""], which no executor could satisfy.
	if got := (executor.Spec{Harness: "  "}).SandboxRequirements().Harnesses; got != nil {
		t.Errorf("a blank harness must yield no requirement; got %v", got)
	}
}
