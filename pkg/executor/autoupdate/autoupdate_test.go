package autoupdate

import (
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
	"github.com/blechschmidt/cloop/pkg/version"
)

const hub = "v1.2.0"

// hubInfo is a hub that is the release hub, speaking this tree's protocol.
var hubInfo = Hub{Version: hub, Protocol: remote.ProtocolVersion}

// ready is a device that Plan should want to upgrade, so each test below can
// change exactly one thing and attribute the result to it.
func ready(id string) Device {
	return Device{
		ID:              id,
		Name:            id,
		Version:         "v1.0.0",
		ProtocolVersion: remote.MinUpgradeVersion,
		Online:          true,
	}
}

func enabled() Policy { return Policy{Enabled: true} }

// only returns the single verdict for a one-device plan.
func only(t *testing.T, p Policy, d Device) Verdict {
	t.Helper()
	vs := Plan(p, hubInfo, []Device{d})
	if len(vs) != 1 {
		t.Fatalf("expected 1 verdict, got %d", len(vs))
	}
	return vs[0]
}

func TestPlanUpgradesAStaleIdleDevice(t *testing.T) {
	v := only(t, enabled(), ready("edge-1"))
	if !v.Upgrade {
		t.Fatalf("a stale, idle, online device was not selected: %s", v.Reason)
	}
	if !strings.Contains(v.Reason, hub) {
		t.Fatalf("reason does not name the target: %s", v.Reason)
	}
}

// Rule 1: the one that protects work in progress. An upgrade restarts the
// agent, so upgrading a busy device destroys whatever it was running.
func TestPlanNeverInterruptsRunningWork(t *testing.T) {
	d := ready("edge-1")
	d.Busy = true
	v := only(t, enabled(), d)
	if v.Upgrade {
		t.Fatal("a device running work was selected for upgrade; the restart would kill the task")
	}
	if !strings.Contains(v.Reason, "running work") {
		t.Fatalf("reason does not explain the deferral: %s", v.Reason)
	}
}

// Rule 2: the one that stops a rollout becoming an outage.
func TestPlanBoundsConcurrentUpgrades(t *testing.T) {
	devices := []Device{ready("edge-1"), ready("edge-2"), ready("edge-3"), ready("edge-4")}

	got := countUpgrades(Plan(enabled(), hubInfo, devices))
	if got != DefaultMaxInFlight {
		t.Fatalf("default policy selected %d devices, want %d", got, DefaultMaxInFlight)
	}

	got = countUpgrades(Plan(Policy{Enabled: true, MaxInFlight: 2}, hubInfo, devices))
	if got != 2 {
		t.Fatalf("MaxInFlight=2 selected %d devices", got)
	}
}

// The budget has to span sweeps, not reset each tick. There is no completion
// signal — a successful upgrade kills the session that would carry it — so a
// device already mid-upgrade holds its slot, and without that "one at a time"
// silently means "one more every five minutes", which is the whole fleet.
func TestPlanCountsInFlightUpgradesAgainstTheBudget(t *testing.T) {
	busy := ready("edge-1")
	busy.Upgrading = true

	vs := Plan(Policy{Enabled: true, MaxInFlight: 1}, hubInfo, []Device{busy, ready("edge-2")})
	if n := countUpgrades(vs); n != 0 {
		t.Fatalf("selected %d devices while one was already upgrading; the slot was not held", n)
	}
	var waiting string
	for _, v := range vs {
		if v.Device.ID == "edge-2" {
			waiting = v.Reason
		}
	}
	if !strings.Contains(waiting, "waiting for a slot") {
		t.Fatalf("an eligible device that was made to wait does not say so: %s", waiting)
	}
}

// Rule 3: a cordon means a human is dealing with this machine.
func TestPlanLeavesHeldDevicesAlone(t *testing.T) {
	d := ready("edge-1")
	d.AdminHeld = true
	v := only(t, enabled(), d)
	if v.Upgrade {
		t.Fatal("a cordoned device was selected; an operator is holding it")
	}
}

func TestPlanSkipsOfflineDevices(t *testing.T) {
	d := ready("edge-1")
	d.Online = false
	if only(t, enabled(), d).Upgrade {
		t.Fatal("an offline device was selected; there is no session to ask on")
	}
}

// Rule 4, in its four shapes. Each is a case where forcing would turn one bad
// assumption into a fleet-wide problem.
func TestPlanRefusesWhatIsNotAnUpgrade(t *testing.T) {
	for _, tc := range []struct {
		name    string
		version string
		want    string
	}{
		{"already current", hub, "already on"},
		{"newer than target", "v2.0.0", "newer than the target"},
		{"unreported build", "", "does not report a build"},
		{"legacy placeholder", "1", "does not report a build"},
		{"unorderable", "not-a-version", "cannot order"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := ready("edge-1")
			d.Version = tc.version
			v := only(t, enabled(), d)
			if v.Upgrade {
				t.Fatalf("selected a device running %q against target %s", tc.version, hub)
			}
			if !strings.Contains(v.Reason, tc.want) {
				t.Fatalf("reason %q does not contain %q", v.Reason, tc.want)
			}
		})
	}
}

// A device too old to understand the frame must be refused before it is sent
// one: it would answer with a protocol error, keep its build, and look to the
// operator like an upgrade that silently did nothing.
func TestPlanRefusesAgentsThatPredateTheUpgradeFrame(t *testing.T) {
	for _, build := range []string{hub, "dev+g8b418e2"} {
		withHubBuild(t, build)
		d := ready("edge-1")
		d.ProtocolVersion = remote.MinUpgradeVersion - 1
		v := only(t, enabled(), d)
		if v.Upgrade {
			t.Fatal("selected a device whose agent cannot understand the upgrade frame")
		}
		// Both numbers, and the manual remedy: the install command, run on
		// the device.
		want := executor.NeedsProtocol("this device's agent", remote.MinUpgradeVersion-1,
			remote.MinUpgradeVersion, "to upgrade it remotely", "")
		if v.Reason != want {
			t.Errorf("hub %s: reason = %q\nwant %q", build, v.Reason, want)
		}
		if !strings.Contains(v.Reason, "sudo ./"+executor.AgentUpgradeProcedure) {
			t.Errorf("hub %s: reason does not name the manual remedy: %s", build, v.Reason)
		}
	}
}

// withHubBuild pins the build the helper writes its remedies for, so a reason
// can be compared with the helper's sentence for the same hub.
func withHubBuild(t *testing.T, v string) {
	t.Helper()
	prev := executor.HubBuild
	executor.HubBuild = func() string { return v }
	t.Cleanup(func() { executor.HubBuild = prev })
}

// TestPlanRefusesATargetThatIsNotARelease is the default policy on a hub
// running an unreleased build: the target is the hub's own "dev+g…" version,
// which no device can download. Every eligible device is refused with the
// reason and the path that works, rather than sent a request that cannot.
func TestPlanRefusesATargetThatIsNotARelease(t *testing.T) {
	withHubBuild(t, "dev+g8b418e2")
	devHub := Hub{Version: "dev+g8b418e2", Protocol: remote.ProtocolVersion}
	d := ready("edge-1")
	d.Version, d.AgentProtocol = "dev+g47e68a9", 14
	d.ProtocolVersion = 14

	vs := Plan(enabled(), devHub, []Device{d})
	if vs[0].Upgrade {
		t.Fatal("planned an upgrade to the hub's unreleased build, which no device can download")
	}
	want := executor.UnpublishedTarget("this device", "dev+g8b418e2", 14)
	if !strings.Contains(vs[0].Reason, want) {
		t.Fatalf("reason = %q\nwant it to carry %q", vs[0].Reason, want)
	}
	if !strings.Contains(vs[0].Reason, "pin a published release") {
		t.Errorf("the reason does not say what the policy can do instead: %s", vs[0].Reason)
	}
}

// TestPlanRefusesATargetThatLowersTheProtocol is the reference deployment with
// a pinned target: a device on a dev build speaking v14, and v0.0.4 speaking
// v13. The protocol is the reason, not "cannot order" — which is also true, and
// is what a device on a dev build always gets from the version comparison.
func TestPlanRefusesATargetThatLowersTheProtocol(t *testing.T) {
	withHubBuild(t, "dev+g8b418e2")
	devHub := Hub{Version: "dev+g8b418e2", Protocol: remote.ProtocolVersion}
	d := ready("sgx")
	d.Version, d.ProtocolVersion, d.AgentProtocol = "dev+g47e68a9", 14, 14

	for _, target := range []string{"v0.0.4", "v0.0.3"} {
		vs := Plan(Policy{Enabled: true, TargetVersion: target}, devHub, []Device{d})
		if vs[0].Upgrade {
			t.Fatalf("planned %s for a v14 device", target)
		}
		_, hi := version.ReleaseProtocol(target)
		want := executor.ProtocolDrop("this device's agent", 14, target, hi)
		if vs[0].Reason != want {
			t.Errorf("target %s: reason = %q\nwant %q", target, vs[0].Reason, want)
		}
		if strings.Contains(vs[0].Reason, "cannot order") {
			t.Errorf("target %s: a protocol drop was reported as an ordering problem", target)
		}
	}

	// "latest" is judged as the newest release this hub knows of.
	newest, _ := version.NewestPublishedRelease()
	vs := Plan(Policy{Enabled: true, TargetVersion: "latest"}, devHub, []Device{d})
	if vs[0].Upgrade || !strings.Contains(vs[0].Reason, "judged as "+newest.Tag) ||
		!strings.Contains(vs[0].Reason, executor.ProtocolDrop("this device's agent", 14, newest.Tag, newest.Protocol)) {
		t.Errorf("latest: %+v", vs[0])
	}
}

// TestPlanJudgesTheAdvertisedProtocol: a device newer than the hub negotiates
// down to it, but its binary speaks more — and the hub's own release, the
// default target, would take that away.
func TestPlanJudgesTheAdvertisedProtocol(t *testing.T) {
	withHubBuild(t, hub)
	d := ready("edge-1")
	d.Version = "v1.3.0"
	d.ProtocolVersion, d.AgentProtocol = remote.ProtocolVersion, remote.ProtocolVersion+1

	vs := Plan(enabled(), hubInfo, []Device{d})
	if vs[0].Upgrade {
		t.Fatal("planned a downgrade of the device's protocol")
	}
	want := executor.ProtocolDrop("this device's agent", remote.ProtocolVersion+1, hub, remote.ProtocolVersion)
	if vs[0].Reason != want {
		t.Errorf("reason = %q\nwant %q", vs[0].Reason, want)
	}
}

// TestPlanStillUpgradesWhatTheProtocolAllows: the new refusals must not cost
// the upgrades that are sound — a release at or above the device's protocol.
func TestPlanStillUpgradesWhatTheProtocolAllows(t *testing.T) {
	withHubBuild(t, "dev+g8b418e2")
	devHub := Hub{Version: "dev+g8b418e2", Protocol: remote.ProtocolVersion}
	d := ready("edge-1")
	d.Version, d.ProtocolVersion, d.AgentProtocol = "v0.0.1", 12, 12

	vs := Plan(Policy{Enabled: true, TargetVersion: "v0.0.4"}, devHub, []Device{d})
	if !vs[0].Upgrade {
		t.Fatalf("a v12 device was not planned for v0.0.4 (v13): %s", vs[0].Reason)
	}
}

func TestPlanDoesNothingWhenDisabled(t *testing.T) {
	if only(t, Policy{}, ready("edge-1")).Upgrade {
		t.Fatal("a disabled policy selected a device")
	}
}

// Off by default, because a hub that reboots edge hardware on the strength of
// an installation default is one nobody trusts with hardware.
func TestZeroPolicyIsDisabled(t *testing.T) {
	if (Policy{}).Resolve(hub).Enabled {
		t.Fatal("the zero policy is enabled")
	}
}

func TestResolveFillsDefaults(t *testing.T) {
	got := Policy{Enabled: true}.Resolve(hub)
	if got.TargetVersion != hub {
		t.Fatalf("empty target resolved to %q, want the hub's build %q", got.TargetVersion, hub)
	}
	if got.MaxInFlight != DefaultMaxInFlight {
		t.Fatalf("MaxInFlight resolved to %d", got.MaxInFlight)
	}

	// A pinned target is honoured even when it is older than the hub: staged
	// rollouts and rollbacks both need the fleet to sit off the hub's build.
	pinned := Policy{Enabled: true, TargetVersion: "v0.9.0"}.Resolve(hub)
	if pinned.TargetVersion != "v0.9.0" {
		t.Fatalf("a pinned target was overridden: %q", pinned.TargetVersion)
	}
}

// Plan returns a verdict for every device, not just the chosen ones: "why is
// that machine still on the old build" is the question this feature generates.
func TestPlanExplainsEveryDevice(t *testing.T) {
	vs := Plan(enabled(), hubInfo, []Device{ready("a"), ready("b"), ready("c")})
	if len(vs) != 3 {
		t.Fatalf("got %d verdicts for 3 devices", len(vs))
	}
	for _, v := range vs {
		if strings.TrimSpace(v.Reason) == "" {
			t.Fatalf("device %s has no reason", v.Device.ID)
		}
	}
}

// With a budget of one, an unstable order would hand the slot to a different
// device each sweep and the fleet would converge slowly for reasons invisible
// to the operator.
func TestPlanIsDeterministic(t *testing.T) {
	devices := []Device{ready("c"), ready("a"), ready("b")}
	first := Plan(enabled(), hubInfo, devices)
	for i := 0; i < 5; i++ {
		if got := Plan(enabled(), hubInfo, devices); got[0].Device.ID != first[0].Device.ID {
			t.Fatalf("selection is not stable: %s then %s", first[0].Device.ID, got[0].Device.ID)
		}
	}
	if first[0].Device.ID != "a" {
		t.Fatalf("verdicts are not ordered by id: first is %s", first[0].Device.ID)
	}
}

// The planner keeps its own copy of the protocol floor so it can be tested
// without the transport stack. This is what stops the copy drifting.
func TestMinRemoteUpgradeProtocolMatchesTheWireConstant(t *testing.T) {
	if minRemoteUpgradeProtocol != remote.MinUpgradeVersion {
		t.Fatalf("planner floor is %d but the wire says %d; a device would be planned for an "+
			"upgrade it cannot be sent, or refused one it could accept",
			minRemoteUpgradeProtocol, remote.MinUpgradeVersion)
	}
}

func countUpgrades(vs []Verdict) int {
	n := 0
	for _, v := range vs {
		if v.Upgrade {
			n++
		}
	}
	return n
}
