package remote_test

// The hub side of a device's disk limit (Task 20405): which devices say they
// hold one, placement refusing a disk-limited spec to an agent that would turn
// it down, the start-time backstop, and the ceilings the hub fills in because
// the device cannot read them.

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
)

var containerMode = executor.SandboxSettings{Mode: executor.SandboxModeContainer}

// deviceAt is a device in the given sandbox mode whose agent speaks protocol.
func deviceAt(t *testing.T, s executor.SandboxSettings, protocol int) (*remote.Executor, *peer) {
	t.Helper()
	ex := sandboxExecutor(t, s, nil)
	p, sess := connect(t, ex, remote.AgentRecord{AgentID: "agent-1", Name: "edge-1"}, helloAt(protocol), nil)
	t.Cleanup(func() { _ = sess.Close() })
	return ex, p
}

func TestDiskEnforcementFollowsTheSandboxModeAndTheAgentsProtocol(t *testing.T) {
	for _, tc := range []struct {
		name     string
		mode     executor.SandboxSettings
		protocol int
		want     executor.DiskEnforcement
	}{
		{"container, current agent", containerMode, remote.MinDiskLimitVersion, executor.DiskEnforcementSampled},
		{"container, older agent", containerMode, remote.MinDiskLimitVersion - 1, executor.DiskEnforcementNone},
		{"host", executor.SandboxSettings{Mode: executor.SandboxModeHost}, remote.ProtocolVersion, executor.DiskEnforcementNone},
		{"unset", executor.SandboxSettings{}, remote.ProtocolVersion, executor.DiskEnforcementNone},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ex, _ := deviceAt(t, tc.mode, tc.protocol)
			if got := ex.Capabilities().DiskEnforcement; got != tc.want {
				t.Fatalf("DiskEnforcement = %q, want %q", got, tc.want)
			}
		})
	}
	if remote.ProtocolVersion < remote.MinDiskLimitVersion || !remote.SupportsDiskLimit(remote.ProtocolVersion) {
		t.Fatalf("this build speaks v%d and does not support disk limits (v%d)", remote.ProtocolVersion,
			remote.MinDiskLimitVersion)
	}
}

// TestPlacementRefusesAnOlderAgentForADiskLimitedSpec: an older agent's
// container driver refuses any disk limit, so the hub must not route one there
// — and must say why, in the device's own terms.
func TestPlacementRefusesAnOlderAgentForADiskLimitedSpec(t *testing.T) {
	withHubBuild(t, "dev+g8b418e2")
	old := remote.MinDiskLimitVersion - 1
	ex, _ := deviceAt(t, containerMode, old)
	spec := executor.Spec{WorkDir: "/srv/proj", Argv: []string{"x"},
		ResourceLimits: executor.ResourceLimits{DiskMB: 20480}}

	err := executor.CheckSandboxSupport(ex, spec.SandboxRequirements(), "/srv/proj")
	var perr *executor.PlacementError
	if !errors.As(err, &perr) || perr.Constraint != executor.ConstraintDiskLimit {
		t.Fatalf("CheckSandboxSupport = %v, want a disk_limit refusal", err)
	}
	want := strings.TrimSuffix(executor.NeedsProtocol("agent agent-1 (edge-1)", old, remote.MinDiskLimitVersion,
		"to hold a workload to a disk limit", ""), ".")
	if !strings.Contains(err.Error(), want) {
		t.Errorf("refusal = %v\nwant it to carry %q", err, want)
	}

	// Through the scheduler too, beside a device that can hold it.
	current, _ := deviceAt(t, containerMode, remote.MinDiskLimitVersion)
	got, err := executor.Select([]executor.Candidate{
		{Executor: ex, Health: executor.Health{State: executor.NodeReady}},
	}, spec.SandboxRequirements())
	if err == nil {
		t.Fatalf("placed a disk-limited spec on a v%d agent: %s", old, got.ID())
	}
	if _, err := executor.Select([]executor.Candidate{
		{Executor: current, Health: executor.Health{State: executor.NodeReady}},
	}, spec.SandboxRequirements()); err != nil {
		t.Fatalf("a current agent was refused a disk-limited spec: %v", err)
	}
}

func TestPlacementRefusesAHostModeDeviceForADiskLimitedSpec(t *testing.T) {
	ex, _ := deviceAt(t, executor.SandboxSettings{Mode: executor.SandboxModeHost}, remote.ProtocolVersion)
	req := executor.Requirements{RequireDiskLimit: true}
	_, err := executor.Select([]executor.Candidate{{Executor: ex, Health: executor.Health{State: executor.NodeReady}}}, req)
	if err == nil || !strings.Contains(err.Error(), "runs payloads on the device's host") {
		t.Fatalf("Select = %v, want a refusal naming the host mode", err)
	}
}

// TestStartRefusesADiskLimitTheDeviceWouldRefuse is the backstop for a
// dispatch that never asked placement.
func TestStartRefusesADiskLimitTheDeviceWouldRefuse(t *testing.T) {
	withHubBuild(t, "dev+g8b418e2")
	spec := plainSpec(t.TempDir())
	spec.ResourceLimits.DiskMB = 1024

	ex, _ := deviceAt(t, containerMode, remote.MinDiskLimitVersion-1)
	_, err := ex.Start(context.Background(), spec)
	if !errors.Is(err, executor.ErrUnsupported) || !strings.Contains(err.Error(), "v20") ||
		!strings.Contains(err.Error(), "disk limit of 1 GB") {
		t.Fatalf("Start on an older agent = %v, want a refusal naming v20 and the limit", err)
	}

	host, _ := deviceAt(t, executor.SandboxSettings{Mode: executor.SandboxModeHost}, remote.ProtocolVersion)
	_, err = host.Start(context.Background(), spec)
	if !errors.Is(err, executor.ErrUnsupported) || !strings.Contains(err.Error(), "device's host") {
		t.Fatalf("Start in host mode = %v, want a refusal naming the host mode", err)
	}
}

// answerStart replies to the next start frame and hands back what the hub
// sent.
func answerStart(t *testing.T, p *peer) chan remote.StartPayload {
	t.Helper()
	got := make(chan remote.StartPayload, 1)
	go func() {
		f := p.readUntil(remote.TypeStart)
		payload, err := remote.DecodeStart(f)
		if err != nil {
			t.Errorf("decode start: %v", err)
			close(got)
			return
		}
		got <- payload
		reply, err := remote.NewFrame(remote.TypeStarted, f.ID, f.Handle, remote.StartedPayload{
			HandleID: f.Handle, StartedAt: time.Now(),
		})
		if err == nil {
			p.write(reply)
		}
	}()
	return got
}

// TestTheDevicesCeilingsTravelInTheStartFrame: the device's container driver
// reads no ceiling of its own, so a limit the project did not ask for reaches
// it only if the hub fills it in — the disk one only where the device will
// hold it rather than refuse the run.
func TestTheDevicesCeilingsTravelInTheStartFrame(t *testing.T) {
	executor.ResetResourceCeiling()
	t.Cleanup(executor.ResetResourceCeiling)
	executor.SetExecutorCeilingLookup(func(id string) (executor.ResourceCeiling, bool) {
		if id == "agent-1" {
			return executor.ResourceCeiling{DiskMB: 20480, MemoryMB: 2048}, true
		}
		return executor.ResourceCeiling{}, false
	})

	ex, p := deviceAt(t, containerMode, remote.MinDiskLimitVersion)
	sent := answerStart(t, p)
	if _, err := ex.Start(context.Background(), plainSpec(t.TempDir())); err != nil {
		t.Fatalf("Start: %v", err)
	}
	payload := <-sent
	rl := payload.Spec.ResourceLimits
	if rl.DiskMB != 20480 || rl.MemoryMB != 2048 {
		t.Fatalf("limits sent = %+v, want the device's ceiling filled in", rl)
	}
	if payload.Spec.Labels[executor.LabelDiskLimitSource] != executor.DiskLimitFromCeiling {
		t.Fatalf("labels = %v: the device would name the wrong remedy", payload.Spec.Labels)
	}

	// An older agent is sent no disk limit it would refuse — the run goes
	// ahead, and the hub reports the ceiling as unenforced there instead.
	older, op := deviceAt(t, containerMode, remote.MinDiskLimitVersion-1)
	sent = answerStart(t, op)
	if _, err := older.Start(context.Background(), plainSpec(t.TempDir())); err != nil {
		t.Fatalf("Start on an older agent: %v", err)
	}
	rl = (<-sent).Spec.ResourceLimits
	if rl.DiskMB != 0 || rl.MemoryMB != 2048 {
		t.Fatalf("limits sent to an older agent = %+v, want memory filled and no disk limit", rl)
	}
	if !executor.CeilingUnenforceable(older, executor.CeilingFor("", "agent-1"), nil) {
		t.Fatal("a disk ceiling an older agent cannot hold is not reported as unenforced")
	}
}

// TestADevicesDiskLimitStopReachesTheHubsStatus: the device's container driver
// stops the workload and says why in its status frame, and that is what the
// hub's settlement reads — bounded, because it is the device's word.
func TestADevicesDiskLimitStopReachesTheHubsStatus(t *testing.T) {
	for _, tc := range []struct {
		name   string
		breach executor.DiskLimitBreach
		kept   bool
	}{
		{"a breach over its limit", executor.DiskLimitBreach{UsedBytes: 70 << 20, LimitMB: 64,
			Source: executor.DiskLimitFromSpec, Path: "/var/lib/cloop-agent/work/proj"}, true},
		{"a claim under its limit", executor.DiskLimitBreach{UsedBytes: 1 << 20, LimitMB: 64}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ex := newTestExecutor(t, nil)
			p, sess := connect(t, ex, remote.AgentRecord{AgentID: "agent-1"}, defaultHello(), nil)
			defer sess.Close()
			handle := startHandle(t, ex, p)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			// The stream closes on the terminal status; Status before then
			// would ask the device, which nothing here answers.
			lines, err := ex.Stream(ctx, handle.ID)
			if err != nil {
				t.Fatal(err)
			}

			b := tc.breach
			frame, err := remote.NewFrame(remote.TypeStatus, "", handle.ID, remote.StatusPayload{
				Status: executor.Status{HandleID: handle.ID, State: executor.StateKilled, ExitCode: 137,
					Error: "stopped at its disk limit", Outcome: executor.OutcomeDiskLimit, DiskLimit: &b},
			})
			if err != nil {
				t.Fatal(err)
			}
			p.write(frame)

			for range lines {
			}
			if ctx.Err() != nil {
				t.Fatal("the terminal status never closed the stream")
			}
			st, err := ex.Status(ctx, handle.ID)
			if err != nil || !st.State.Terminal() {
				t.Fatalf("Status = %+v, %v; want terminal", st, err)
			}
			if got := st.Outcome == executor.OutcomeDiskLimit && st.DiskLimit != nil; got != tc.kept {
				t.Fatalf("status = %+v, want the disk-limit account kept = %v", st, tc.kept)
			}
			if tc.kept && (st.DiskLimit.UsedMB() != 70 || st.DiskLimit.LimitMB != 64) {
				t.Fatalf("breach = %+v", st.DiskLimit)
			}
		})
	}
}

// TestADevicesStartRefusalComesBackTyped: a device that refuses a start
// because the workspace is already over its limit says so with the
// measurement, and the hub returns the refusal it can answer as one — bounded,
// because it is the device's word.
func TestADevicesStartRefusalComesBackTyped(t *testing.T) {
	for _, tc := range []struct {
		name   string
		breach *executor.DiskLimitBreach
		typed  bool
	}{
		{"a breach over its limit", &executor.DiskLimitBreach{UsedBytes: 73 << 20, LimitMB: 64,
			Source: executor.DiskLimitFromSpec, Path: "/var/lib/cloop-agent/work/proj"}, true},
		{"a claim under its limit", &executor.DiskLimitBreach{UsedBytes: 1 << 20, LimitMB: 64}, false},
		{"no measurement", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ex := newTestExecutor(t, nil)
			p, sess := connect(t, ex, remote.AgentRecord{AgentID: "agent-1"}, defaultHello(), nil)
			defer sess.Close()
			go func() {
				f := p.readUntil(remote.TypeStart)
				reply, err := remote.NewFrame(remote.TypeStarted, f.ID, f.Handle, remote.StartedPayload{
					HandleID: f.Handle, Error: "refusing to start: the workspace is over its disk limit",
					DiskLimit: tc.breach,
				})
				if err == nil {
					p.write(reply)
				}
			}()
			_, err := ex.Start(context.Background(), plainSpec(t.TempDir()))
			var refused *executor.DiskLimitError
			if got := errors.As(err, &refused); got != tc.typed {
				t.Fatalf("Start = %v, want typed = %v", err, tc.typed)
			}
			if tc.typed && (refused.Executor != "agent-1" || refused.Breach.UsedMB() != 73) {
				t.Fatalf("refusal = %+v", refused)
			}
			if err == nil {
				t.Fatal("a refused start returned no error")
			}
		})
	}
}

// TestAVirtualExecutorsCeilingTravelsInTheStartFrame: a virtual executor's own
// ceiling — keyed by its ID, not its device's — is filled in for the device,
// which reads none.
func TestAVirtualExecutorsCeilingTravelsInTheStartFrame(t *testing.T) {
	executor.ResetResourceCeiling()
	t.Cleanup(executor.ResetResourceCeiling)
	executor.SetExecutorCeilingLookup(func(id string) (executor.ResourceCeiling, bool) {
		switch id {
		case "virt-1":
			return executor.ResourceCeiling{DiskMB: 4096, PIDs: 256}, true
		case "agent-1":
			return executor.ResourceCeiling{DiskMB: 99999}, true
		}
		return executor.ResourceCeiling{}, false
	})
	ex, p := deviceAt(t, executor.SandboxSettings{}, remote.MinDiskLimitVersion)
	v, err := remote.NewVirtual(ex, "virt-1", "sandboxed", func() (executor.VirtualSpec, error) {
		return executor.VirtualSpec{Sandbox: containerMode}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := v.Capabilities().DiskEnforcement; got != executor.DiskEnforcementSampled {
		t.Fatalf("the virtual executor's DiskEnforcement = %q", got)
	}
	sent := answerStart(t, p)
	if _, err := v.Start(context.Background(), plainSpec(t.TempDir())); err != nil {
		t.Fatalf("virtual Start: %v", err)
	}
	rl := (<-sent).Spec.ResourceLimits
	if rl.DiskMB != 4096 || rl.PIDs != 256 {
		t.Fatalf("limits sent = %+v, want the virtual executor's own ceiling", rl)
	}
}
