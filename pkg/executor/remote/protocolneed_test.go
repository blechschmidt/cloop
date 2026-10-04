package remote_test

// Placement's half of Task 20371: a feature refused at placement on an
// enrolled device hears why from the device's driver — the protocol it speaks
// and the one shipping a branch needs, or the git it lacks — rather than a
// remedy written into pkg/executor, which cannot see either.

import (
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
)

func branchCandidate(t *testing.T, protocol int, git bool) executor.Candidate {
	t.Helper()
	ex := newTestExecutor(t, nil)
	h := helloAt(protocol)
	h.Capabilities.BranchBundles = git
	_, sess := connect(t, ex, remote.AgentRecord{AgentID: "agent-1", Name: "edge-1"}, h, nil)
	t.Cleanup(func() { _ = sess.Close() })
	return executor.Candidate{Executor: ex, Health: executor.Health{State: executor.NodeReady}}
}

func TestPlacementExplainsWhyADeviceCannotReceiveABranch(t *testing.T) {
	withHubBuild(t, "dev+g8b418e2")

	old := remote.MinBranchBundleVersion - 1
	_, err := executor.Select([]executor.Candidate{branchCandidate(t, old, true)},
		executor.Requirements{RequireBranchBundle: true})
	if err == nil {
		t.Fatal("placed a feature on an agent too old to receive its branch")
	}
	want := strings.TrimSuffix(executor.NeedsProtocol("its agent", old, remote.MinBranchBundleVersion,
		"to ship a feature's branch to it", "Or run the feature on a container executor."), ".")
	if !strings.Contains(err.Error(), want) {
		t.Errorf("placement refusal = %v\nwant it to carry %q", err, want)
	}

	// New enough, but no git on the device: a different fix, said as such.
	_, err = executor.Select([]executor.Candidate{branchCandidate(t, remote.MinBranchBundleVersion, false)},
		executor.Requirements{RequireBranchBundle: true})
	if err == nil || !strings.Contains(err.Error(), "reported no git") {
		t.Errorf("placement refusal for a device without git = %v", err)
	}
	if err != nil && strings.Contains(err.Error(), "speaks protocol") {
		t.Errorf("a device new enough was told its protocol is the problem: %v", err)
	}
}
