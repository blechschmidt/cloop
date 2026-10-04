package autoupdate

// edge_test.go: what "match the hub" means for the edge channel (Task 20376).
// A device on the edge channel converges on the hub's own build once CI has
// published it, never one that would lower its protocol; a device on the
// stable channel is never sent a build of main.

import (
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/executor"
)

const edgeHubCommit = "a0f387020b4df29e9f39ebe0369ec0de0ca8c674"

func edgeHub(published bool, protocol int) Hub {
	e := &executor.EdgeBuild{Short: "a0f3870", Target: "edge:" + edgeHubCommit, Published: published,
		Protocol: protocol}
	if !published {
		e.WhyNot = "CI has not published commit a0f3870 yet: CI is still running on it."
	}
	return Hub{Version: "dev+ga0f3870", Protocol: 17, Edge: e}
}

func edgeReady(id, channel string, protocol int) Device {
	return Device{ID: id, Name: id, Version: "dev+g06e06ed", ProtocolVersion: protocol, AgentProtocol: protocol,
		Online: true, Channel: channel}
}

func TestPlanMovesAnEdgeDeviceToTheHubsBuild(t *testing.T) {
	withHubBuild(t, "dev+ga0f3870")
	vs := Plan(enabled(), edgeHub(true, 17), []Device{edgeReady("sgx", executor.ChannelEdge, 16)})
	if !vs[0].Upgrade || vs[0].Target != "edge:"+edgeHubCommit {
		t.Fatalf("verdict = %+v, want an upgrade to the hub's edge build", vs[0])
	}
	if !strings.Contains(vs[0].Reason, "this hub's build (a0f3870)") {
		t.Errorf("the reason does not name the build: %s", vs[0].Reason)
	}
}

func TestPlanLeavesAnEdgeDeviceAloneUntilCIHasPublished(t *testing.T) {
	withHubBuild(t, "dev+ga0f3870")
	v := Plan(enabled(), edgeHub(false, 0), []Device{edgeReady("sgx", executor.ChannelEdge, 16)})[0]
	if v.Upgrade || !strings.Contains(v.Reason, "is not offered yet") || !strings.Contains(v.Reason, "still running") {
		t.Fatalf("verdict = %+v", v)
	}
}

func TestPlanNeverLowersAnEdgeDevicesProtocol(t *testing.T) {
	withHubBuild(t, "dev+ga0f3870")
	v := Plan(enabled(), edgeHub(true, 16), []Device{edgeReady("sgx", executor.ChannelEdge, 17)})[0]
	if v.Upgrade || !strings.Contains(v.Reason, "speaks v16") {
		t.Fatalf("verdict = %+v", v)
	}
}

func TestPlanCountsTheHubsCommitAsCurrent(t *testing.T) {
	withHubBuild(t, "dev+ga0f3870")
	d := edgeReady("sgx", executor.ChannelEdge, 17)
	d.Version = "dev+ga0f3870"
	v := Plan(enabled(), edgeHub(true, 17), []Device{d})[0]
	if v.Upgrade || !strings.Contains(v.Reason, "already on the hub's build") {
		t.Fatalf("verdict = %+v", v)
	}
}

// TestPlanNeverSendsMainToAStableDevice, whether the policy follows the hub or
// names the edge build outright.
func TestPlanNeverSendsMainToAStableDevice(t *testing.T) {
	withHubBuild(t, "dev+ga0f3870")
	for _, target := range []string{"", "edge:" + edgeHubCommit} {
		p := enabled()
		p.TargetVersion = target
		v := Plan(p, edgeHub(true, 17), []Device{edgeReady("pi", executor.ChannelStable, 16)})[0]
		if v.Upgrade {
			t.Fatalf("target %q: a stable device was selected: %+v", target, v)
		}
		if !strings.Contains(v.Reason, executor.EdgeOptIn) {
			t.Errorf("target %q: the reason does not name the device-side switch: %s", target, v.Reason)
		}
	}
}

// TestPlanFollowsOnlyTheHubsOwnEdgeBuild: an arbitrary commit cannot be
// judged, so the policy may not pin one.
func TestPlanFollowsOnlyTheHubsOwnEdgeBuild(t *testing.T) {
	withHubBuild(t, "dev+ga0f3870")
	p := enabled()
	p.TargetVersion = "edge:f25fd69"
	v := Plan(p, edgeHub(true, 17), []Device{edgeReady("sgx", executor.ChannelEdge, 16)})[0]
	if v.Upgrade || !strings.Contains(v.Reason, "not this hub's own build") {
		t.Fatalf("verdict = %+v", v)
	}
}

// TestPlanStillOffersReleasesToEdgeDevices: a pinned release reaches a device
// on either channel.
func TestPlanStillOffersReleasesToEdgeDevices(t *testing.T) {
	d := ready("sgx")
	d.Channel = executor.ChannelEdge
	v := only(t, enabled(), d)
	if !v.Upgrade || v.Target != hub {
		t.Fatalf("verdict = %+v, want the release", v)
	}
}
