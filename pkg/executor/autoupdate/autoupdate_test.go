package autoupdate

import (
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/executor/remote"
)

const hub = "v1.2.0"

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
	vs := Plan(p, hub, []Device{d})
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

	got := countUpgrades(Plan(enabled(), hub, devices))
	if got != DefaultMaxInFlight {
		t.Fatalf("default policy selected %d devices, want %d", got, DefaultMaxInFlight)
	}

	got = countUpgrades(Plan(Policy{Enabled: true, MaxInFlight: 2}, hub, devices))
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

	vs := Plan(Policy{Enabled: true, MaxInFlight: 1}, hub, []Device{busy, ready("edge-2")})
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
	d := ready("edge-1")
	d.ProtocolVersion = remote.MinUpgradeVersion - 1
	v := only(t, enabled(), d)
	if v.Upgrade {
		t.Fatal("selected a device whose agent cannot understand the upgrade frame")
	}
	if !strings.Contains(v.Reason, "on the device") {
		t.Fatalf("reason does not name the manual remedy: %s", v.Reason)
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
	vs := Plan(enabled(), hub, []Device{ready("a"), ready("b"), ready("c")})
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
	first := Plan(enabled(), hub, devices)
	for i := 0; i < 5; i++ {
		if got := Plan(enabled(), hub, devices); got[0].Device.ID != first[0].Device.ID {
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
