package remote_test

// Hub-side refusals for edge targets (Task 20376): what the hub checks before
// it asks a device for a build of main, and what it sends when it does.

import (
	"errors"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
)

const edgeCommit = "a0f387020b4df29e9f39ebe0369ec0de0ca8c674"

// connectWithCaps connects a device advertising protocol and caps.
func connectWithCaps(t *testing.T, protocol int, caps remote.AgentCapabilities) (*remote.Executor, *upgradePeer) {
	t.Helper()
	ex := newTestExecutor(t, nil)
	hello := helloAt(protocol)
	caps.OS, caps.Arch = "linux", "amd64"
	hello.Capabilities = caps
	p, sess := connect(t, ex, remote.AgentRecord{AgentID: "agent-1", Name: "edge-1"}, hello, nil)
	t.Cleanup(func() { _ = sess.Close() })
	up := &upgradePeer{}
	up.serve(p)
	return ex, up
}

func TestRequestUpgradeSendsAnEdgeBuildToAnEdgeDevice(t *testing.T) {
	withHubBuild(t, "dev+ga0f3870")
	ex, up := connectWithCaps(t, 16, remote.AgentCapabilities{UpdateChannel: "edge", RemoteUpgrade: true})
	if got := ex.UpdateChannel(); got != "edge" {
		t.Fatalf("UpdateChannel = %q", got)
	}
	out, err := ex.RequestUpgrade(upgradeCtx(t), remote.UpgradeRequest{
		TargetVersion: "EDGE:" + strings.ToUpper(edgeCommit), TargetProtocol: 17,
	})
	if err != nil || !out.Accepted {
		t.Fatalf("RequestUpgrade = %+v, %v", out, err)
	}
	if got := up.asked(); len(got) != 1 || got[0] != "edge:"+edgeCommit {
		t.Errorf("the device was asked for %v, want the normalised edge target", got)
	}
}

// TestRequestUpgradeLeavesTheChannelToTheDevice: a device on the stable
// channel is never sent a build of main, and the refusal says the hub cannot
// change that — only the operator on the device can.
func TestRequestUpgradeLeavesTheChannelToTheDevice(t *testing.T) {
	withHubBuild(t, "dev+ga0f3870")
	for name, caps := range map[string]remote.AgentCapabilities{
		"stable":           {UpdateChannel: "stable", RemoteUpgrade: true},
		"older than edges": {},
	} {
		t.Run(name, func(t *testing.T) {
			ex, up := connectWithCaps(t, 16, caps)
			for _, force := range []bool{false, true} {
				_, err := ex.RequestUpgrade(upgradeCtx(t), remote.UpgradeRequest{
					TargetVersion: "edge:" + edgeCommit, TargetProtocol: 17, Force: force,
				})
				if !errors.Is(err, remote.ErrUpgradeChannel) {
					t.Fatalf("force=%t: err = %v, want ErrUpgradeChannel", force, err)
				}
				if !strings.Contains(err.Error(), executor.EdgeOptIn) || !strings.Contains(err.Error(), "the hub cannot") {
					t.Errorf("the refusal does not say who can change the channel: %v", err)
				}
			}
			if got := up.asked(); len(got) != 0 {
				t.Errorf("the device was sent %v", got)
			}
		})
	}
}

// TestRequestUpgradeNeverLowersProtocolWithAnEdgeBuild: the manifest's
// protocol is judged as a release's is, and an unknown one is not waved
// through.
func TestRequestUpgradeNeverLowersProtocolWithAnEdgeBuild(t *testing.T) {
	withHubBuild(t, "dev+ga0f3870")
	ex, up := connectWithCaps(t, 17, remote.AgentCapabilities{UpdateChannel: "edge", RemoteUpgrade: true})

	_, err := ex.RequestUpgrade(upgradeCtx(t), remote.UpgradeRequest{TargetVersion: "edge:" + edgeCommit, TargetProtocol: 16})
	if !errors.Is(err, remote.ErrUpgradeLowersProtocol) || !strings.Contains(err.Error(), "speaks v16") {
		t.Fatalf("a v16 build for a v17 device: %v", err)
	}
	_, err = ex.RequestUpgrade(upgradeCtx(t), remote.UpgradeRequest{TargetVersion: "edge:" + edgeCommit,
		TargetProtocolIssue: "CI has not published it"})
	if !errors.Is(err, remote.ErrUpgradeLowersProtocol) || !strings.Contains(err.Error(), "could not read") {
		t.Fatalf("an unknown protocol: %v", err)
	}
	if got := up.asked(); len(got) != 0 {
		t.Fatalf("sent %v despite the refusals", got)
	}

	if _, err := ex.RequestUpgrade(upgradeCtx(t), remote.UpgradeRequest{
		TargetVersion: "edge:" + edgeCommit, TargetProtocol: 16, Force: true,
	}); err != nil {
		t.Fatalf("force did not override the protocol check: %v", err)
	}
	if got := up.asked(); len(got) != 1 {
		t.Errorf("asked = %v", got)
	}
}

func TestRequestUpgradeRefusesAMalformedEdgeTarget(t *testing.T) {
	ex, up := connectWithCaps(t, 16, remote.AgentCapabilities{UpdateChannel: "edge", RemoteUpgrade: true})
	_, err := ex.RequestUpgrade(upgradeCtx(t), remote.UpgradeRequest{TargetVersion: "edge:zzzzzzz", TargetProtocol: 17})
	if !errors.Is(err, remote.ErrUpgradeTarget) {
		t.Fatalf("err = %v, want ErrUpgradeTarget", err)
	}
	if len(up.asked()) != 0 {
		t.Error("a malformed target was sent")
	}
}

// TestRequestUpgradeRefusesADeviceThatCannotCarryItOut: a device that says it
// has no way to replace its binary is not asked — for a release either — and
// the refusal carries what it said.
func TestRequestUpgradeRefusesADeviceThatCannotCarryItOut(t *testing.T) {
	withHubBuild(t, "v0.2.0")
	const issue = "this agent runs unprivileged and the device has no remote-upgrade helper"
	ex, up := connectWithCaps(t, 16, remote.AgentCapabilities{UpdateChannel: "edge", RemoteUpgradeIssue: issue})
	for _, target := range []string{"v0.2.0", "edge:" + edgeCommit} {
		_, err := ex.RequestUpgrade(upgradeCtx(t), remote.UpgradeRequest{TargetVersion: target, TargetProtocol: 17, Force: true})
		if !errors.Is(err, remote.ErrUpgradeUnavailable) || !strings.Contains(err.Error(), issue) {
			t.Errorf("%s: err = %v, want ErrUpgradeUnavailable carrying the device's reason", target, err)
		}
	}
	if len(up.asked()) != 0 {
		t.Error("the device was asked anyway")
	}
}
