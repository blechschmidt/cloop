package remote_test

// Tests for the hub side of per-executor sandbox mode (Task 20307).
//
// Two refusals and one advertisement. Both refusals exist because the failure
// they prevent is invisible: an agent that cannot honour a container mode does
// not say so, and a hub that cannot read the configuration has no way to know it
// is about to run a payload somewhere weaker than an admin chose. In each case
// the run failing loudly is the good outcome.

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
)

// sandboxExecutor builds an executor whose sandbox resolver returns a fixed
// answer, or a fixed failure.
func sandboxExecutor(t *testing.T, s executor.SandboxSettings, readErr error) *remote.Executor {
	t.Helper()
	ex, err := remote.NewExecutor(remote.Options{
		ID: "agent-1", Name: "edge-1",
		Sandbox: func() (executor.SandboxSettings, error) { return s, readErr },
	})
	if err != nil {
		t.Fatalf("NewExecutor: %v", err)
	}
	return ex
}

// plainSpec is a workload with nothing special about it: no workspace to clone,
// no credential files. It isolates the sandbox preflight from the three others
// that can refuse a start.
func plainSpec(workDir string) executor.Spec {
	return executor.Spec{WorkDir: workDir, Argv: []string{"/bin/sh", "-c", "true"}}
}

// briefly bounds a Start that is expected *not* to be refused.
//
// Nothing in these tests answers the start frame, so an unbounded Start waits out
// the full started-frame timeout — 45 seconds for an assertion about a check that
// runs entirely in memory before any I/O. The deadline is generous next to the
// preflight it is testing and negligible next to the timeout it replaces: if the
// sandbox check was going to refuse, it already has by the time the frame goes
// out.
func briefly(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// TestOldAgentIsRefusedContainerMode is the placement rule, and the least visible
// of the four the remote driver enforces.
//
// A pre-v8 agent does not reject StartPayload.Sandbox — it ignores a JSON key it
// does not know and runs the harness as a host process, reporting success.
// Nothing downstream can detect that, so refusing here is the only place the
// mismatch can be named.
func TestOldAgentIsRefusedContainerMode(t *testing.T) {
	ex := sandboxExecutor(t, executor.SandboxSettings{Mode: executor.SandboxModeContainer}, nil)
	_, sess := connect(t, ex, remote.AgentRecord{AgentID: "agent-1", Name: "edge-1"},
		helloAt(remote.MinSandboxModeVersion-1), nil)
	defer sess.Close()

	_, err := ex.Start(context.Background(), plainSpec(t.TempDir()))
	if !errors.Is(err, remote.ErrSandboxModeUnsupported) {
		t.Fatalf("Start error = %v, want ErrSandboxModeUnsupported", err)
	}
	// The diagnostic is what an operator reads, so it names the device, the
	// version it speaks, and both ways out.
	for _, want := range []string{"edge-1", "v7", "install --upgrade", "host"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("diagnostic should mention %q; got %q", want, err)
		}
	}
}

// TestOldAgentIsNotRefusedHostOrUnsetMode is the other half of the placement
// rule. Gating host and unset would strand a fleet mid-upgrade for no gain: they
// are what a pre-v8 agent does anyway, so telling it so is not a downgrade.
func TestOldAgentIsNotRefusedHostOrUnsetMode(t *testing.T) {
	for _, s := range []executor.SandboxSettings{{}, {Mode: executor.SandboxModeHost}} {
		ex := sandboxExecutor(t, s, nil)
		_, sess := connect(t, ex, remote.AgentRecord{AgentID: "agent-1", Name: "edge-1"},
			helloAt(remote.MinSandboxModeVersion-1), nil)

		_, err := ex.Start(briefly(t), plainSpec(t.TempDir()))
		// The start may still fail for unrelated reasons — nothing answers the
		// frame in this test — but it must not fail *for this reason*.
		if errors.Is(err, remote.ErrSandboxModeUnsupported) {
			t.Errorf("settings %+v were refused on an old agent; only container mode is gated", s)
		}
		sess.Close()
	}
}

// TestUnreadableSandboxConfigRefusesDispatch is the rule that makes the setting a
// control rather than a hint.
//
// "I could not read whether this executor is supposed to be contained" must not
// resolve to "run it on the host". The alternative is a containment decision made
// by a busy database, silently, in the weaker direction, on a hub too unhealthy
// to report it.
func TestUnreadableSandboxConfigRefusesDispatch(t *testing.T) {
	boom := errors.New("statedb: database is locked")
	ex := sandboxExecutor(t, executor.SandboxSettings{}, boom)
	_, sess := connect(t, ex, remote.AgentRecord{AgentID: "agent-1", Name: "edge-1"},
		defaultHello(), nil)
	defer sess.Close()

	_, err := ex.Start(context.Background(), plainSpec(t.TempDir()))
	if !errors.Is(err, remote.ErrSandboxModeUnavailable) {
		t.Fatalf("Start error = %v, want ErrSandboxModeUnavailable", err)
	}
	if !errors.Is(err, boom) {
		t.Error("the underlying read failure must stay in the chain; an operator needs to know " +
			"it was the database and not a configuration mistake")
	}
	if !strings.Contains(err.Error(), "refusing to dispatch") {
		t.Errorf("diagnostic %q should say that nothing was dispatched", err)
	}
}

// TestNilSandboxResolverIsThePreTaskBehaviour keeps a hub with no control-plane
// configuration source working exactly as it did.
func TestNilSandboxResolverIsThePreTaskBehaviour(t *testing.T) {
	ex := newTestExecutor(t, nil) // no Options.Sandbox at all
	_, sess := connect(t, ex, remote.AgentRecord{AgentID: "agent-1", Name: "edge-1"},
		defaultHello(), nil)
	defer sess.Close()

	_, err := ex.Start(briefly(t), plainSpec(t.TempDir()))
	if errors.Is(err, remote.ErrSandboxModeUnavailable) ||
		errors.Is(err, remote.ErrSandboxModeUnsupported) {
		t.Fatalf("a hub with no sandbox source must dispatch as before, got %v", err)
	}
}

// TestCapabilitiesReportContainmentOnlyWhenConfigured is what placement and the
// fleet card read.
//
// Before this configuration existed both flags were necessarily false for every
// remote executor — whether a payload sits behind a hypervisor is a property of
// the runtime the hub names, not of the device — so a Kata edge device could not
// be described as one. Now it can, and only when it has actually been told to be.
func TestCapabilitiesReportContainmentOnlyWhenConfigured(t *testing.T) {
	cases := []struct {
		name                    string
		settings                executor.SandboxSettings
		wantVirt, wantKernelIso bool
		wantImageOverride       bool
	}{
		{"unset claims nothing", executor.SandboxSettings{}, false, false, false},
		{"host claims nothing", executor.SandboxSettings{Mode: executor.SandboxModeHost}, false, false, false},
		{"container on runc is a container",
			executor.SandboxSettings{Mode: executor.SandboxModeContainer, Runtime: "runc"},
			false, false, true},
		{"container on runsc is kernel-isolated but not a VM",
			executor.SandboxSettings{Mode: executor.SandboxModeContainer, Runtime: "runsc"},
			false, true, true},
		{"container on kata is a VM",
			executor.SandboxSettings{Mode: executor.SandboxModeContainer, Runtime: "kata"},
			true, true, true},
		// A runtime recorded against host mode confines nothing.
		{"kata under host mode claims nothing",
			executor.SandboxSettings{Mode: executor.SandboxModeHost, Runtime: "kata"},
			false, false, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ex := sandboxExecutor(t, tc.settings, nil)
			// The device is stipulated to be capable of everything the
			// configuration might ask for, because this table is about the
			// mapping from configuration to capabilities and nothing else.
			// Since v9 a device also gets a say — one that reports no
			// /dev/kvm has its Kata claim withdrawn — and leaving that at the
			// zero value here would silently turn the "container on kata"
			// row into a test of the hardware probe. That probe has its own
			// table in virtualization_test.go.
			hello := defaultHello()
			hello.Capabilities.Virtualization = true
			_, sess := connect(t, ex, remote.AgentRecord{AgentID: "agent-1", Name: "edge-1"},
				hello, nil)
			defer sess.Close()

			caps := ex.Capabilities()
			if caps.Virtualized != tc.wantVirt {
				t.Errorf("Virtualized = %v, want %v", caps.Virtualized, tc.wantVirt)
			}
			if caps.KernelIsolated != tc.wantKernelIso {
				t.Errorf("KernelIsolated = %v, want %v", caps.KernelIsolated, tc.wantKernelIso)
			}
			if caps.SupportsImageOverride != tc.wantImageOverride {
				t.Errorf("SupportsImageOverride = %v, want %v — a project naming its own image "+
					"has nothing to run it on until the device is told to use a container",
					caps.SupportsImageOverride, tc.wantImageOverride)
			}
			// Whatever the mode, the workload is on another machine and the hub
			// cannot read its filesystem. That claim never changes.
			if caps.Isolation != executor.IsolationRemote {
				t.Errorf("Isolation = %q, want %q", caps.Isolation, executor.IsolationRemote)
			}
			if caps.SharesHostFilesystem {
				t.Error("a remote executor never shares the control plane's filesystem")
			}
		})
	}
}

// TestCapabilitiesWithholdContainmentFromAnAgentThatCannotHonourIt stops
// placement choosing an executor for work its own Start would then refuse.
func TestCapabilitiesWithholdContainmentFromAnAgentThatCannotHonourIt(t *testing.T) {
	ex := sandboxExecutor(t, executor.SandboxSettings{
		Mode: executor.SandboxModeContainer, Runtime: "kata",
	}, nil)
	_, sess := connect(t, ex, remote.AgentRecord{AgentID: "agent-1", Name: "edge-1"},
		helloAt(remote.MinSandboxModeVersion-1), nil)
	defer sess.Close()

	caps := ex.Capabilities()
	if caps.Virtualized || caps.KernelIsolated {
		t.Error("a pre-v8 session cannot deliver a container mode, so the executor must not " +
			"advertise the containment its configuration names — placement would route " +
			"virtualization-requiring work to a start that refuses it")
	}
}

// TestSupportsSandboxModeTracksTheProtocolVersion mirrors the other capability
// predicates, so the constant and the helper cannot drift apart.
func TestSupportsSandboxModeTracksTheProtocolVersion(t *testing.T) {
	if remote.SupportsSandboxMode(remote.MinSandboxModeVersion - 1) {
		t.Error("a version below the floor must not claim sandbox-mode support")
	}
	if !remote.SupportsSandboxMode(remote.MinSandboxModeVersion) {
		t.Error("the floor version must claim sandbox-mode support")
	}
	for v := 1; v <= remote.ProtocolVersion; v++ {
		if remote.SupportsSandboxMode(v) != (v >= remote.MinSandboxModeVersion) {
			t.Errorf("SupportsSandboxMode(%d) disagrees with MinSandboxModeVersion", v)
		}
	}
}

// TestStartPayloadCarriesTheSandboxSettings pins the wire format: the field has
// to survive a round trip, or the device never learns the mode.
func TestStartPayloadCarriesTheSandboxSettings(t *testing.T) {
	want := executor.SandboxSettings{
		Mode: executor.SandboxModeContainer, Engine: "podman", Runtime: "kata", Image: "img:1",
	}
	frame, err := remote.NewFrame(remote.TypeStart, "corr-1", "h-1", remote.StartPayload{
		HandleID: "h-1", Sandbox: want,
	})
	if err != nil {
		t.Fatalf("NewFrame: %v", err)
	}
	got, err := remote.DecodeStart(frame)
	if err != nil {
		t.Fatalf("DecodeStart: %v", err)
	}
	if got.Sandbox != want {
		t.Errorf("Sandbox survived decode as %+v, want %+v", got.Sandbox, want)
	}
}
