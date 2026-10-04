package remote_test

// Hub-side upgrade refusals (Task 20371).
//
// The Upgrade button and the auto-update policy make a device install a
// published release, and on a hub running an unreleased build that moved the
// reference deployment's device backwards: its agent spoke v14, "latest" was
// v0.0.4 speaking v13, and the device's own check could not order its dev build
// against the release, so it would have installed it. These tests hold the hub
// to refusing that before a frame is sent, and to sending what it should.

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
	"github.com/blechschmidt/cloop/pkg/version"
)

// withHubBuild pins the build the remedies are written for.
func withHubBuild(t *testing.T, v string) {
	t.Helper()
	prev := executor.HubBuild
	executor.HubBuild = func() string { return v }
	t.Cleanup(func() { executor.HubBuild = prev })
}

// upgradePeer answers upgrade frames on the agent's behalf and records the
// targets it was asked for.
type upgradePeer struct {
	mu      sync.Mutex
	targets []string
	forced  []bool
}

func (up *upgradePeer) serve(p *peer) {
	go func() {
		for {
			f, err := p.conn.ReadFrame(context.Background())
			if err != nil {
				return
			}
			if f.Type != remote.TypeUpgrade {
				continue
			}
			payload, err := remote.DecodeUpgrade(f)
			if err != nil {
				return
			}
			up.mu.Lock()
			up.targets = append(up.targets, payload.TargetVersion)
			up.forced = append(up.forced, payload.Force)
			up.mu.Unlock()
			reply, err := remote.NewFrame(remote.TypeUpgrading, f.ID, "", remote.UpgradingPayload{
				Accepted:      true,
				FromVersion:   "dev+g47e68a9",
				TargetVersion: payload.TargetVersion,
			})
			if err != nil {
				return
			}
			_ = p.conn.WriteFrame(context.Background(), reply)
		}
	}()
}

func (up *upgradePeer) asked() []string {
	up.mu.Lock()
	defer up.mu.Unlock()
	return append([]string(nil), up.targets...)
}

func upgradeCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// connectUpgradable connects a device whose agent advertises protocol
// advertised and whose session is in a state to be asked to upgrade.
func connectUpgradable(t *testing.T, advertised int) (*remote.Executor, *upgradePeer) {
	t.Helper()
	ex := newTestExecutor(t, nil)
	p, sess := connect(t, ex, remote.AgentRecord{AgentID: "agent-1", Name: "edge-1"}, helloAt(advertised), nil)
	t.Cleanup(func() { _ = sess.Close() })
	up := &upgradePeer{}
	up.serve(p)
	return ex, up
}

// TestRequestUpgradeRefusesALowerProtocol is the reference deployment's case:
// a v14 device, an unreleased hub, and v0.0.4 — the newest published release,
// speaking v13 — as the target. Refused, with the reason, and nothing sent.
func TestRequestUpgradeRefusesALowerProtocol(t *testing.T) {
	withHubBuild(t, "dev+g8b418e2")
	ex, up := connectUpgradable(t, 14)

	_, err := ex.RequestUpgrade(upgradeCtx(t), remote.UpgradeRequest{TargetVersion: "v0.0.4"})
	if !errors.Is(err, remote.ErrUpgradeLowersProtocol) {
		t.Fatalf("err = %v, want ErrUpgradeLowersProtocol", err)
	}
	want := executor.ProtocolDrop("agent agent-1 (edge-1)", 14, "v0.0.4", 13)
	if !strings.Contains(err.Error(), want) {
		t.Errorf("the refusal does not carry the helper's explanation.\n got: %s\nwant: …%s…", err, want)
	}
	if !strings.Contains(err.Error(), "force") {
		t.Errorf("the refusal does not say how to proceed anyway: %s", err)
	}
	if got := up.asked(); len(got) != 0 {
		t.Errorf("the device was sent an upgrade to %v despite the refusal", got)
	}
}

// TestRequestUpgradeJudgesUnresolvedLatest: a caller that could not look up
// which release is latest sends "latest", and the hub judges it as the newest
// release it knows of — saying that is what it did.
func TestRequestUpgradeJudgesUnresolvedLatest(t *testing.T) {
	withHubBuild(t, "dev+g8b418e2")
	ex, up := connectUpgradable(t, 14)
	newest, ok := version.NewestPublishedRelease()
	if !ok {
		t.Skip("no published release is listed")
	}
	if newest.Protocol >= 14 {
		// A later table may list a release at or above the device; then
		// nothing is lowered and this case has nothing to show.
		t.Skipf("the newest published release %s speaks v%d", newest.Tag, newest.Protocol)
	}

	for _, target := range []string{"", "latest", "LATEST"} {
		_, err := ex.RequestUpgrade(upgradeCtx(t), remote.UpgradeRequest{TargetVersion: target})
		if !errors.Is(err, remote.ErrUpgradeLowersProtocol) {
			t.Fatalf("target %q: err = %v, want ErrUpgradeLowersProtocol", target, err)
		}
		for _, want := range []string{"judged as " + newest.Tag, "newest published release this hub knows of",
			executor.ProtocolDrop("agent agent-1 (edge-1)", 14, newest.Tag, newest.Protocol)} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("target %q: refusal lacks %q: %s", target, want, err)
			}
		}
	}
	if got := up.asked(); len(got) != 0 {
		t.Errorf("the device was sent %v", got)
	}
}

// TestRequestUpgradeRefusesANonReleaseTarget: the old dialog prefilled the
// hub's own version, which on an unreleased hub is "dev+g8b418e2" — a name with
// no published release behind it.
func TestRequestUpgradeRefusesANonReleaseTarget(t *testing.T) {
	withHubBuild(t, "dev+g8b418e2")
	ex, up := connectUpgradable(t, 14)

	for _, target := range []string{"dev+g8b418e2", "dev", "nightly", "0.0.4", "v1.2.3+g4f7b5bc"} {
		// Force does not get a non-release through: there is nothing to force.
		_, err := ex.RequestUpgrade(upgradeCtx(t), remote.UpgradeRequest{TargetVersion: target, Force: true})
		if !errors.Is(err, remote.ErrUpgradeTarget) {
			t.Fatalf("target %q: err = %v, want ErrUpgradeTarget", target, err)
		}
		want := executor.UnpublishedTarget("agent agent-1 (edge-1)", target, 14)
		if !strings.Contains(err.Error(), want) {
			t.Errorf("target %q: refusal lacks the helper's explanation.\n got: %s\nwant: …%s…", target, err, want)
		}
	}
	if got := up.asked(); len(got) != 0 {
		t.Errorf("the device was sent %v", got)
	}
}

// TestRequestUpgradeSendsWhatDoesNotLowerTheProtocol: the refusal must not
// cost the cases that work — a release at or above the device's protocol, one
// newer than this hub knows of, and a forced rollback.
func TestRequestUpgradeSendsWhatDoesNotLowerTheProtocol(t *testing.T) {
	withHubBuild(t, "dev+g8b418e2")

	cases := []struct {
		name       string
		advertised int
		req        remote.UpgradeRequest
	}{
		{"a release above the device", 12, remote.UpgradeRequest{TargetVersion: "v0.0.4"}},
		{"a release this hub has never heard of", 14, remote.UpgradeRequest{TargetVersion: "v9.0.0"}},
		{"a forced rollback", 14, remote.UpgradeRequest{TargetVersion: "v0.0.4", Force: true}},
		{"latest on a device below the newest release", 12, remote.UpgradeRequest{TargetVersion: "latest"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ex, up := connectUpgradable(t, tc.advertised)
			out, err := ex.RequestUpgrade(upgradeCtx(t), tc.req)
			if err != nil {
				t.Fatalf("refused: %v", err)
			}
			if !out.Accepted {
				t.Fatalf("outcome = %+v, want accepted", out)
			}
			if got := up.asked(); len(got) != 1 || got[0] != tc.req.TargetVersion {
				t.Errorf("device was asked for %v, want [%s]", got, tc.req.TargetVersion)
			}
		})
	}
}

// TestRequestUpgradeJudgesTheAdvertisedProtocol: an agent newer than the hub
// negotiates down to the hub's protocol, but its binary still speaks its own —
// and that is what an upgrade would take away.
func TestRequestUpgradeJudgesTheAdvertisedProtocol(t *testing.T) {
	withHubBuild(t, "dev+g8b418e2")
	ahead := remote.ProtocolVersion + 1
	ex, up := connectUpgradable(t, ahead)

	if got := ex.ProtocolVersion(); got != remote.ProtocolVersion {
		t.Fatalf("negotiated %d, want the hub's %d", got, remote.ProtocolVersion)
	}
	if got := ex.AgentProtocol(); got != ahead {
		t.Fatalf("AgentProtocol() = %d, want the advertised %d", got, ahead)
	}
	if got := ex.DeviceProtocol(); got != ahead {
		t.Fatalf("DeviceProtocol() = %d, want %d", got, ahead)
	}
	_, err := ex.RequestUpgrade(upgradeCtx(t), remote.UpgradeRequest{TargetVersion: "v0.0.4"})
	if !errors.Is(err, remote.ErrUpgradeLowersProtocol) {
		t.Fatalf("err = %v, want ErrUpgradeLowersProtocol", err)
	}
	if !strings.Contains(err.Error(), executor.ProtocolDrop("agent agent-1 (edge-1)", ahead, "v0.0.4", 13)) {
		t.Errorf("the refusal is not judged against the advertised v%d: %s", ahead, err)
	}
	if got := up.asked(); len(got) != 0 {
		t.Errorf("the device was sent %v", got)
	}
}

// TestRequestUpgradeRefusesAPreUpgradeAgent keeps the oldest gate, now worded
// by the helper: both numbers, and the manual remedy.
func TestRequestUpgradeRefusesAPreUpgradeAgent(t *testing.T) {
	withHubBuild(t, "v0.2.0")
	ex, up := connectUpgradable(t, remote.MinUpgradeVersion-1)

	_, err := ex.RequestUpgrade(upgradeCtx(t), remote.UpgradeRequest{TargetVersion: "v0.2.0"})
	if !errors.Is(err, remote.ErrUpgradeUnsupported) {
		t.Fatalf("err = %v, want ErrUpgradeUnsupported", err)
	}
	want := executor.NeedsProtocol("agent agent-1 (edge-1)", remote.MinUpgradeVersion-1, remote.MinUpgradeVersion,
		"to upgrade it from here", "")
	if !strings.Contains(err.Error(), want) {
		t.Errorf("refusal = %s\nwant it to carry: %s", err, want)
	}
	if !strings.Contains(err.Error(), "by hand") {
		t.Errorf("the refusal does not name the manual remedy: %s", err)
	}
	if got := up.asked(); len(got) != 0 {
		t.Errorf("the device was sent %v", got)
	}
}

// TestMinRemoteUpgradeVersionMatchesTheWire keeps pkg/executor's copy of the
// floor — which decides whether the helper offers the Upgrade button or the
// manual path — equal to the wire's.
func TestMinRemoteUpgradeVersionMatchesTheWire(t *testing.T) {
	if executor.MinRemoteUpgradeVersion != remote.MinUpgradeVersion {
		t.Fatalf("executor.MinRemoteUpgradeVersion = %d, remote.MinUpgradeVersion = %d; the advice "+
			"would offer the Upgrade button to devices that cannot be sent the frame, or withhold it "+
			"from ones that can", executor.MinRemoteUpgradeVersion, remote.MinUpgradeVersion)
	}
}

// TestNewestPublishedReleaseIsNotAheadOfThisBuild: a release speaks the
// protocol of the tree it was tagged from, and every later tree speaks at least
// that. A table claiming otherwise has a typo that would refuse sound upgrades.
func TestNewestPublishedReleaseIsNotAheadOfThisBuild(t *testing.T) {
	newest, ok := version.NewestPublishedRelease()
	if !ok {
		t.Fatal("no published release is listed")
	}
	if newest.Protocol > remote.ProtocolVersion {
		t.Fatalf("%s is listed as speaking v%d, newer than this build's v%d", newest.Tag,
			newest.Protocol, remote.ProtocolVersion)
	}
}
