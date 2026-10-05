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

// TestPlanNeverAsksAnEdgeDeviceToRollBack (Task 20380): the hub's build is
// the target only when it is not earlier on main than the device's — or from
// before sequences, when the device's build carries one — because the
// device's installer refuses anything earlier whoever asks.
func TestPlanNeverAsksAnEdgeDeviceToRollBack(t *testing.T) {
	withHubBuild(t, "dev+ga0f3870")
	at := func(hubSeq, deviceSeq int) Verdict {
		h := edgeHub(true, 18)
		h.Edge.Sequence = hubSeq
		d := edgeReady("sgx", executor.ChannelEdge, 18)
		d.Sequence = deviceSeq
		return Plan(enabled(), h, []Device{d})[0]
	}
	if v := at(4150, 4100); !v.Upgrade || v.Target != "edge:"+edgeHubCommit {
		t.Errorf("a later hub build was not the target: %+v", v)
	}
	if v := at(4150, 0); !v.Upgrade {
		t.Errorf("a device without a sequence was not moved to the hub's build: %+v", v)
	}
	for _, c := range []struct{ hubSeq, deviceSeq int }{{4100, 4150}, {0, 4150}} {
		v := at(c.hubSeq, c.deviceSeq)
		if v.Upgrade || !strings.Contains(v.Reason, "The device refuses a build earlier on main than its own") {
			t.Errorf("hub at %d, device at %d: %+v", c.hubSeq, c.deviceSeq, v)
		}
	}
}

// TestPlanNeverPinsAnEarlierRelease: a pinned release the hub knows to carry
// no sequence is refused for a device whose build carries one.
func TestPlanNeverPinsAnEarlierRelease(t *testing.T) {
	withHubBuild(t, "dev+ga0f3870")
	d := edgeReady("sgx", executor.ChannelEdge, 13)
	d.Version, d.Sequence = "dev+g06e06ed", 4150
	p := enabled()
	p.TargetVersion = "v0.0.4"
	v := Plan(p, edgeHub(true, 18), []Device{d})[0]
	if v.Upgrade || !strings.Contains(v.Reason, "carries no sequence") {
		t.Fatalf("verdict = %+v", v)
	}
}
