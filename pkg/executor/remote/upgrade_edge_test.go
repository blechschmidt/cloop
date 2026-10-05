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

// TestRequestUpgradeAsksADeviceThatSaidItCouldNot: what a device said about
// itself at hello is as old as the session, so the hub asks anyway and the
// device answers from a preflight it runs now. An operator who installed cosign
// after the agent connected is not refused until it reconnects.
func TestRequestUpgradeAsksADeviceThatSaidItCouldNot(t *testing.T) {
	withHubBuild(t, "v0.2.0")
	const issue = "cosign is not installed on this device"
	ex, up := connectWithCaps(t, 16, remote.AgentCapabilities{UpdateChannel: "edge", RemoteUpgradeIssue: issue})
	out, err := ex.RequestUpgrade(upgradeCtx(t), remote.UpgradeRequest{TargetVersion: "v0.2.0"})
	if err != nil || !out.Accepted {
		t.Fatalf("RequestUpgrade = %+v, %v; want the device asked", out, err)
	}
	if got := up.asked(); len(got) != 1 || got[0] != "v0.2.0" {
		t.Errorf("asked = %v", got)
	}
}

// TestRequestUpgradeNeverAsksForARollback is the hub's half of Task 20380: an
// edge build earlier on main than the device's — or one from before builds
// carried a sequence — is refused before a frame is sent, and force does not
// change that, because the device's installer would refuse it whoever asked.
func TestRequestUpgradeNeverAsksForARollback(t *testing.T) {
	withHubBuild(t, "dev+ga0f3870")
	ex, up := connectWithCaps(t, 18, remote.AgentCapabilities{UpdateChannel: "edge", RemoteUpgrade: true,
		BuildSequence: 4150})
	if got := ex.BuildSequence(); got != 4150 {
		t.Fatalf("BuildSequence = %d", got)
	}
	for _, seq := range []int{4100, 0} {
		for _, force := range []bool{false, true} {
			_, err := ex.RequestUpgrade(upgradeCtx(t), remote.UpgradeRequest{TargetVersion: "edge:" + edgeCommit,
				TargetProtocol: 18, TargetSequence: seq, TargetSequenceKnown: true, Force: force})
			if !errors.Is(err, remote.ErrUpgradeRollback) {
				t.Fatalf("sequence %d, force=%t: err = %v, want ErrUpgradeRollback", seq, force, err)
			}
			if !strings.Contains(err.Error(), executor.RollbackOptIn) {
				t.Errorf("the refusal does not name the one way that remains: %v", err)
			}
		}
	}
	if got := up.asked(); len(got) != 0 {
		t.Fatalf("sent %v despite the refusals", got)
	}

	// A later build is sent; an unknown sequence (the manifest was not read)
	// is the protocol rule's to judge, as before.
	if _, err := ex.RequestUpgrade(upgradeCtx(t), remote.UpgradeRequest{TargetVersion: "edge:" + edgeCommit,
		TargetProtocol: 18, TargetSequence: 4160, TargetSequenceKnown: true}); err != nil {
		t.Fatalf("a later build was refused: %v", err)
	}
	if got := up.asked(); len(got) != 1 {
		t.Errorf("asked = %v", got)
	}
}

// TestRequestUpgradeNeverAsksForAnEarlierRelease: a release the hub knows to
// carry no sequence — every release before Task 20380 — is refused for a
// device whose build carries one, force or not; for a device whose build
// carries none, the protocol rule decides as it always did.
func TestRequestUpgradeNeverAsksForAnEarlierRelease(t *testing.T) {
	withHubBuild(t, "dev+ga0f3870")
	ex, up := connectWithCaps(t, 13, remote.AgentCapabilities{UpdateChannel: "edge", RemoteUpgrade: true,
		BuildSequence: 4150})
	_, err := ex.RequestUpgrade(upgradeCtx(t), remote.UpgradeRequest{TargetVersion: "v0.0.4", Force: true})
	if !errors.Is(err, remote.ErrUpgradeRollback) || !strings.Contains(err.Error(), "carries no sequence") {
		t.Fatalf("err = %v, want ErrUpgradeRollback", err)
	}
	if got := up.asked(); len(got) != 0 {
		t.Fatalf("sent %v", got)
	}

	plain, up2 := connectWithCaps(t, 13, remote.AgentCapabilities{UpdateChannel: "edge", RemoteUpgrade: true})
	if _, err := plain.RequestUpgrade(upgradeCtx(t), remote.UpgradeRequest{TargetVersion: "v0.0.4"}); err != nil {
		t.Fatalf("a device without a sequence was refused v0.0.4: %v", err)
	}
	if got := up2.asked(); len(got) != 1 {
		t.Errorf("asked = %v", got)
	}
}

func TestStoredBuildSequence(t *testing.T) {
	for raw, want := range map[string]int{
		`{"update_channel":"edge","build_sequence":925}`: 925,
		`{"update_channel":"edge"}`:                      0,
		`{"build_sequence":-4}`:                          0,
		`{"build_sequence":2147483647}`:                  0,
		`not json`:                                       0,
		``:                                               0,
	} {
		if got := remote.StoredBuildSequence([]byte(raw)); got != want {
			t.Errorf("StoredBuildSequence(%q) = %d, want %d", raw, got, want)
		}
	}
}
