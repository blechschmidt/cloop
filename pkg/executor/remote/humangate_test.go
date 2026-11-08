package remote_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
)

// TestOldAgentIsRefusedAPlanHoldingAReviewGate is the placement rule for human
// review gates (Task 20477). A device whose cloop predates them reads the
// seed, ignores the kind it does not know and runs the gate as a task —
// reporting it done, and carrying on past the point a person asked the run to
// stop at. So a seed flagged as holding a pending gate is refused there, with
// the device, the version and the way out named; the same seed without a gate
// is not refused for it.
func TestOldAgentIsRefusedAPlanHoldingAReviewGate(t *testing.T) {
	ex := newTestExecutor(t, nil)
	_, sess := connect(t, ex, remote.AgentRecord{AgentID: "agent-1", Name: "edge-1"},
		helloAt(remote.MinHumanGateVersion-1), nil)
	defer sess.Close()

	spec := executor.Spec{
		WorkDir:     "gated-project",
		Argv:        []string{"/bin/sh", "-c", "true"},
		ProjectSeed: seedFor(t, "a gated goal"),
		HumanGates:  true,
	}
	_, err := ex.Start(context.Background(), spec)
	if !errors.Is(err, remote.ErrProjectSeedUnsupported) {
		t.Fatalf("Start error = %v, want ErrProjectSeedUnsupported", err)
	}
	for _, want := range []string{"edge-1", "v26", "review gate", "approve or remove"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("diagnostic should mention %q; got %q", want, err)
		}
	}
}

func TestHumanGateVersionFloor(t *testing.T) {
	if remote.MinHumanGateVersion > remote.ProtocolVersion {
		t.Fatalf("MinHumanGateVersion (%d) is above ProtocolVersion (%d): no device could ever run a gated plan",
			remote.MinHumanGateVersion, remote.ProtocolVersion)
	}
	// Pinned to the version that introduced gates: a floor that crept up with
	// later bumps would refuse devices that honour gates perfectly well.
	if remote.MinHumanGateVersion != 27 {
		t.Errorf("MinHumanGateVersion = %d, want 27", remote.MinHumanGateVersion)
	}
	for v := remote.MinProtocolVersion; v <= remote.ProtocolVersion; v++ {
		if remote.SupportsHumanGates(v) != (v >= remote.MinHumanGateVersion) {
			t.Errorf("SupportsHumanGates(%d) disagrees with MinHumanGateVersion", v)
		}
	}
}
