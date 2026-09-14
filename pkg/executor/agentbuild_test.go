package executor

// agentbuild_test.go holds the build floor to the property it exists for: a
// device whose build predates a fix the operator has deployed must be refused at
// *placement*, with a sentence that names the remedy, rather than selected and
// left to fail at run time in whatever way the missing fix fails.
//
// The distinction the tests keep insisting on is between a device that is
// demonstrably too old and one that will not say — because the two have
// different fixes, and a floor that collapsed them would send half the operators
// who hit it to the wrong place.

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// buildAgent is a remote-agent-shaped executor that reports a build version, so
// it satisfies BuildReporter the way remote.Executor does.
type buildAgent struct {
	id    string
	build string
}

func (a *buildAgent) ID() string   { return a.id }
func (a *buildAgent) Kind() string { return KindRemoteAgent }
func (a *buildAgent) Capabilities() Capabilities {
	return Capabilities{Isolation: IsolationRemote, SupportsStream: true}
}
func (a *buildAgent) Start(context.Context, Spec) (Handle, error) {
	return Handle{ID: "h", ExecutorID: a.id, StartedAt: time.Now()}, nil
}
func (a *buildAgent) Signal(context.Context, string, Signal) error { return nil }
func (a *buildAgent) Status(context.Context, string) (Status, error) {
	return Status{State: StateExited}, nil
}
func (a *buildAgent) Stream(context.Context, string) (<-chan LogLine, error) {
	ch := make(chan LogLine)
	close(ch)
	return ch, nil
}
func (a *buildAgent) HealthCheck(context.Context) error { return nil }
func (a *buildAgent) AgentVersion() string              { return a.build }

// isolatedBox stands in for a container or Kubernetes executor: isolated, and
// running the control plane's own binary rather than a build of its own.
type isolatedBox struct{ *fakeExecutor }

func (isolatedBox) Capabilities() Capabilities {
	return Capabilities{Isolation: IsolationContainer, SupportsStream: true}
}

func withFloor(t *testing.T, floor string) {
	t.Helper()
	prev := SetMinAgentBuild(floor)
	t.Cleanup(func() { SetMinAgentBuild(prev) })
}

func candidate(ex Executor) Candidate {
	return Candidate{Executor: ex, Health: Health{State: NodeReady}}
}

// TestPlacementRefusesADeviceBelowTheFloor is the headline: the gap this closes
// is that the reported build was decorative, so an outdated device was selected
// and failed later.
func TestPlacementRefusesADeviceBelowTheFloor(t *testing.T) {
	withFloor(t, "v1.2.0")
	old := &buildAgent{id: "edge-old", build: "v1.1.9"}

	_, err := Select([]Candidate{candidate(old)}, Requirements{})
	if err == nil {
		t.Fatal("placed a workload on a device below the fleet's minimum build")
	}
	var pe *PlacementError
	if !errors.As(err, &pe) {
		t.Fatalf("error is not a *PlacementError: %v", err)
	}
	if pe.Constraint != ConstraintAgentBuild {
		t.Errorf("constraint = %q, want %q", pe.Constraint, ConstraintAgentBuild)
	}
	detail := err.Error()
	// Both versions, so the operator does not have to go and look either up.
	for _, want := range []string{"v1.1.9", "v1.2.0", AgentUpgradeProcedure} {
		if !strings.Contains(detail, want) {
			t.Errorf("rejection does not mention %q: %s", want, detail)
		}
	}
}

// TestPlacementAcceptsADeviceAtOrAboveTheFloor: the floor is a minimum, not an
// equality check. A fleet mid-rollout must keep placing on the devices that are
// already current.
func TestPlacementAcceptsADeviceAtOrAboveTheFloor(t *testing.T) {
	withFloor(t, "v1.2.0")
	for _, build := range []string{"v1.2.0", "v1.2.1", "v2.0.0"} {
		if _, err := Select([]Candidate{candidate(&buildAgent{id: "edge", build: build})},
			Requirements{}); err != nil {
			t.Errorf("build %s was refused under floor v1.2.0: %v", build, err)
		}
	}
}

// TestPlacementRefusesADeviceThatCannotProveItsBuild covers the three ways a
// device declines to answer. All are refusals — an operator who set a floor
// asked for devices that can substantiate their build — but each gets its own
// sentence, because "it predates version reporting" and "it is running an
// unreleased build" are fixed differently.
func TestPlacementRefusesADeviceThatCannotProveItsBuild(t *testing.T) {
	withFloor(t, "v1.2.0")
	cases := []struct {
		name   string
		build  string
		expect string
	}{
		{"unreported", "", "does not report a build version"},
		{"legacy placeholder", "1", "placeholder"},
		{"unreleased", "dev+g4f7b5bc", "cannot be ordered"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Select([]Candidate{candidate(&buildAgent{id: "edge", build: tc.build})},
				Requirements{})
			if err == nil {
				t.Fatalf("placed on a device reporting %q under a floor", tc.build)
			}
			if !strings.Contains(err.Error(), tc.expect) {
				t.Errorf("rejection for %q does not explain itself (%q): %v",
					tc.build, tc.expect, err)
			}
		})
	}
}

// TestBuildFloorIgnoresExecutorsWithoutTheirOwnBuild is the guard against the
// obvious way to get this wrong. A container executor runs *this* binary, so
// treating it as "build unknown" would take every sandbox out of the fleet the
// moment a floor was configured — turning a fleet hygiene setting into an
// outage.
func TestBuildFloorIgnoresExecutorsWithoutTheirOwnBuild(t *testing.T) {
	withFloor(t, "v99.0.0")
	box := isolatedBox{newFake("container")}

	if _, err := Select([]Candidate{candidate(box)}, Requirements{}); err != nil {
		t.Fatalf("a container executor was refused by the agent build floor: %v", err)
	}
	if blocked, _ := BlockedByBuildFloor(box); blocked {
		t.Error("BlockedByBuildFloor reported a non-device executor as blocked")
	}
}

// TestNoFloorPlacesAnything: the default must be exactly the behaviour that
// existed before this file, or an upgrade would strand fleets that never
// configured anything.
func TestNoFloorPlacesAnything(t *testing.T) {
	withFloor(t, "")
	for _, build := range []string{"", "1", "dev", "v0.0.1"} {
		if _, err := Select([]Candidate{candidate(&buildAgent{id: "edge", build: build})},
			Requirements{}); err != nil {
			t.Errorf("build %q was refused with no floor configured: %v", build, err)
		}
	}
}

// TestSelectPrefersTheNewerBuild is the ranking half. Without it a stale device
// keeps taking work simply because it sorts first by ID, and nothing ever
// surfaces that it is stale.
func TestSelectPrefersTheNewerBuild(t *testing.T) {
	withFloor(t, "")
	// IDs chosen so alphabetical order contradicts build order: if the tiebreak
	// were not consulted, "aaa-old" would win.
	old := &buildAgent{id: "aaa-old", build: "v1.0.0"}
	current := &buildAgent{id: "zzz-new", build: "v1.4.0"}

	got, err := Select([]Candidate{candidate(old), candidate(current)}, Requirements{})
	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	if got.ID() != current.ID() {
		t.Errorf("placed on %s, want the newer build %s", got.ID(), current.ID())
	}

	// Determinism is not sacrificed for it: two devices that cannot be ordered
	// by build must still place the same way every time.
	a := &buildAgent{id: "aaa", build: "dev"}
	b := &buildAgent{id: "bbb", build: "dev"}
	for i := 0; i < 5; i++ {
		got, err := Select([]Candidate{candidate(b), candidate(a)}, Requirements{})
		if err != nil {
			t.Fatalf("Select: %v", err)
		}
		if got.ID() != "aaa" {
			t.Fatalf("unorderable builds placed non-deterministically: got %s", got.ID())
		}
	}
}

// TestHealthOutranksBuild pins the ranking order. A current build on a node
// whose probes are failing is a worse bet than an older build on one that is
// answering, and reversing that would route work to nodes that cannot take it.
func TestHealthOutranksBuild(t *testing.T) {
	withFloor(t, "")
	sickButNew := Candidate{
		Executor: &buildAgent{id: "aaa-new", build: "v2.0.0"},
		Health:   Health{State: NodeDegraded},
	}
	healthyButOld := Candidate{
		Executor: &buildAgent{id: "zzz-old", build: "v1.0.0"},
		Health:   Health{State: NodeReady},
	}

	got, err := Select([]Candidate{sickButNew, healthyButOld}, Requirements{})
	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	if got.ID() != "zzz-old" {
		t.Errorf("placed on %s; a degraded node must not win on build currency alone", got.ID())
	}
}

// TestCheckSandboxSupportEnforcesTheFloor covers the other entry point. A
// project bound to a specific executor never goes through Select, and a floor
// enforced on only one of the two paths is a floor with a bypass.
func TestCheckSandboxSupportEnforcesTheFloor(t *testing.T) {
	withFloor(t, "v1.2.0")
	old := &buildAgent{id: "edge-old", build: "v1.0.0"}

	err := CheckSandboxSupport(old, Requirements{}, "/srv/projects/demo")
	if err == nil {
		t.Fatal("a project bound to an outdated device was allowed to dispatch")
	}
	var pe *PlacementError
	if !errors.As(err, &pe) || pe.Constraint != ConstraintAgentBuild {
		t.Errorf("bound-executor check did not name the build constraint: %v", err)
	}
	// Never the "bind this to a sandbox" remedy: the device *is* isolated, and
	// that advice would be one the operator has already taken.
	var denied *HostExecutionDeniedError
	if errors.As(err, &denied) {
		t.Errorf("build skew was reported as a host-execution denial: %v", err)
	}
}

// TestBlockedByBuildFloorAgreesWithPlacement is the anti-drift check between the
// Executors panel and the scheduler. A card that says a device is fine while
// placement silently skips it is worse than no card: the operator's next move is
// to wait, which is the one thing that will not help.
func TestBlockedByBuildFloorAgreesWithPlacement(t *testing.T) {
	withFloor(t, "v1.2.0")
	var blockedN, placedN int
	for _, build := range []string{"", "1", "dev", "v1.0.0", "v1.2.0", "v9.9.9"} {
		agent := &buildAgent{id: "edge", build: build}
		blocked, reason := BlockedByBuildFloor(agent)
		_, err := Select([]Candidate{candidate(agent)}, Requirements{})
		placed := err == nil
		if blocked == placed {
			t.Errorf("build %q: panel says blocked=%v but placement %s",
				build, blocked, map[bool]string{true: "succeeded", false: "refused"}[placed])
		}
		if blocked && !strings.Contains(reason, AgentUpgradeProcedure) {
			t.Errorf("build %q: the panel's reason does not name the fix: %s", build, reason)
		}
		if blocked {
			blockedN++
		}
		if placed {
			placedN++
		}
	}
	// Agreement is trivially satisfiable by never blocking and never refusing,
	// so the table has to be shown to exercise both answers. Without this the
	// test would keep passing if the floor stopped being consulted anywhere.
	if blockedN == 0 || placedN == 0 {
		t.Errorf("the table exercised only one outcome (%d blocked, %d placed); "+
			"agreement proves nothing unless both happen", blockedN, placedN)
	}
}

// TestApplyMinAgentBuildOnlyRatchetsUp is the security property. A hub reads
// many tenants' config.yaml; if a tenant-controlled file could lower the floor,
// the floor would be advice rather than a control.
func TestApplyMinAgentBuildOnlyRatchetsUp(t *testing.T) {
	withFloor(t, "")

	ApplyMinAgentBuild("v1.2.0")
	if got := MinAgentBuild(); got != "v1.2.0" {
		t.Fatalf("MinAgentBuild = %q, want v1.2.0", got)
	}
	for _, lower := range []string{"v1.1.0", "v0.9.9", ""} {
		ApplyMinAgentBuild(lower)
		if got := MinAgentBuild(); got != "v1.2.0" {
			t.Errorf("applying %q lowered the floor to %q", lower, got)
		}
	}
	ApplyMinAgentBuild("v1.3.0")
	if got := MinAgentBuild(); got != "v1.3.0" {
		t.Errorf("applying a higher floor did not tighten: %q", got)
	}
	// Garbage is ignored rather than treated as infinitely high. Config
	// validation refuses it at the door, so reaching here means validation was
	// bypassed — and "I cannot understand this rule" must not mean "refuse the
	// entire fleet".
	ApplyMinAgentBuild("not-a-version")
	if got := MinAgentBuild(); got != "v1.3.0" {
		t.Errorf("an unparseable floor changed the policy to %q", got)
	}
}

// TestAgentBuildDistinguishesDevicesFromLocalDrivers pins the two-return
// contract, which is what stops the floor from rejecting sandboxes.
func TestAgentBuildDistinguishesDevicesFromLocalDrivers(t *testing.T) {
	if _, reports := AgentBuild(newFake("local")); reports {
		t.Error("a driver with no separate binary was reported as having a build")
	}
	build, reports := AgentBuild(&buildAgent{id: "edge", build: "  v1.0.0  "})
	if !reports {
		t.Fatal("a remote agent was not recognised as reporting a build")
	}
	if build != "v1.0.0" {
		t.Errorf("build = %q, want it trimmed to v1.0.0", build)
	}
}
