package agent

// Agent-side reconnect and confinement tests.
//
// pkg/executor/remote's tests cover the control plane's half of resume with a
// scripted agent. These cover the device's half with a scripted control plane:
// what the agent offers in its hello, and — the part that actually loses data
// if it is wrong — which bytes it resends once told where to restart.

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
)

// controlPlane is a scripted control-plane peer over an in-memory pipe.
type controlPlane struct {
	t    *testing.T
	conn remote.Conn
}

func (c *controlPlane) read(timeout time.Duration) (remote.Frame, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return c.conn.ReadFrame(ctx)
}

func (c *controlPlane) write(f remote.Frame) {
	c.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := c.conn.WriteFrame(ctx, f); err != nil {
		c.t.Fatalf("control plane write %s: %v", f.Type, err)
	}
}

// readUntil returns the first frame of the given type.
func (c *controlPlane) readUntil(want remote.FrameType, timeout time.Duration) remote.Frame {
	c.t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		f, err := c.read(time.Until(deadline))
		if err != nil {
			c.t.Fatalf("waiting for %s: %v", want, err)
		}
		if f.Type == want {
			return f
		}
	}
	c.t.Fatalf("timed out waiting for %s", want)
	return remote.Frame{}
}

// newScriptedAgent builds an agent whose Dial hands out successive pipe ends,
// so a test can drop one connection and observe the reconnect.
func newScriptedAgent(t *testing.T, credPath, root string) (*Agent, <-chan *controlPlane) {
	t.Helper()
	conns := make(chan *controlPlane, 4)

	a, err := New(Config{
		Server:         "wss://control-plane.invalid/api/executors/connect",
		Token:          "clet1.fake.fake.fake", // never used: Dial is overridden
		CredentialPath: credPath,
		WorkDirRoot:    root,
		Logf:           func(format string, args ...any) { t.Logf("agent: "+format, args...) },
		Dial: func(ctx context.Context, server, token string) (remote.Conn, error) {
			agentSide, cpSide := remote.NewPipe(64)
			conns <- &controlPlane{t: t, conn: cpSide}
			return agentSide, nil
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return a, conns
}

// handshake performs the control-plane side: read hello, send welcome.
func (c *controlPlane) handshake(t *testing.T, executorID string, resume []remote.ResumeAck, credential string) remote.HelloPayload {
	t.Helper()
	f := c.readUntil(remote.TypeHello, 5*time.Second)
	hello, err := remote.DecodeHello(f)
	if err != nil {
		t.Fatalf("DecodeHello: %v", err)
	}
	welcome, err := remote.NewFrame(remote.TypeWelcome, f.ID, "", remote.WelcomePayload{
		ProtocolVersion:  remote.ProtocolVersion,
		ExecutorID:       executorID,
		Credential:       credential,
		HeartbeatSeconds: int(remote.HeartbeatInterval / time.Second),
		ResumeAccepted:   resume,
	})
	if err != nil {
		t.Fatalf("build welcome: %v", err)
	}
	c.write(welcome)
	return hello
}

// TestAgentEnrollsAndPersistsCredential covers the first-contact path: an
// agent with no stored identity sends an empty AgentID, and persists whatever
// the control plane issues.
func TestAgentEnrollsAndPersistsCredential(t *testing.T) {
	dir := t.TempDir()
	credPath := filepath.Join(dir, "agent.json")
	root := filepath.Join(dir, "work")

	a, conns := newScriptedAgent(t, credPath, root)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = a.Run(ctx) }()

	cp := <-conns
	hello := cp.handshake(t, "assigned-agent-id", nil, "clac1.issued.secret.mac")

	if hello.AgentID != "" {
		t.Errorf("a device enrolling for the first time must not claim an ID, got %q", hello.AgentID)
	}
	if hello.ProtocolVersion != remote.ProtocolVersion {
		t.Errorf("hello version = %d, want %d", hello.ProtocolVersion, remote.ProtocolVersion)
	}
	if hello.Capabilities.CPUs <= 0 {
		t.Error("hello should advertise CPU count for scheduling")
	}
	if hello.Capabilities.WorkDirRoot == "" {
		t.Error("hello should advertise the confinement root so operators can see it")
	}

	waitFor(t, 5*time.Second, func() bool {
		_, err := os.Stat(credPath)
		return err == nil
	}, "the agent should persist the issued credential")

	cred, err := LoadCredential(credPath)
	if err != nil {
		t.Fatalf("LoadCredential: %v", err)
	}
	if cred.AgentID != "assigned-agent-id" {
		t.Errorf("stored agent ID = %q, want assigned-agent-id", cred.AgentID)
	}
	if cred.Credential != "clac1.issued.secret.mac" {
		t.Errorf("stored credential = %q", cred.Credential)
	}
	info, err := os.Stat(credPath)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("credential mode = %04o, want 0600", perm)
	}
}

// TestAgentReconnectsAndResumesFromOffset is the device-side resume assertion.
// The agent must resend from exactly the offset it is told — not from zero
// (duplicating) and not from its own head (skipping).
func TestAgentReconnectsAndResumesFromOffset(t *testing.T) {
	dir := t.TempDir()
	credPath := filepath.Join(dir, "agent.json")
	root := filepath.Join(dir, "work")

	a, conns := newScriptedAgent(t, credPath, root)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = a.Run(ctx) }()

	cp := <-conns
	cp.handshake(t, "agent-1", nil, "clac1.issued.secret.mac")

	// A workload that emits known output and then stays alive, so it is still
	// running when the link drops — which is the whole point of resume.
	const handleID = "handle-1"
	startFrame, err := remote.NewFrame(remote.TypeStart, "start-1", handleID, remote.StartPayload{
		HandleID: handleID,
		Spec: executor.Spec{
			// Relative: the agent provisions it beneath its root.
			WorkDir: "proj",
			Argv:    []string{"/bin/sh", "-c", "printf 'AAAABBBB'; sleep 30"},
		},
	})
	if err != nil {
		t.Fatalf("build start: %v", err)
	}
	cp.write(startFrame)

	started := cp.readUntil(remote.TypeStarted, 10*time.Second)
	sp, err := remote.DecodeStarted(started)
	if err != nil {
		t.Fatalf("DecodeStarted: %v", err)
	}
	if sp.Error != "" {
		t.Fatalf("agent refused the workload: %s", sp.Error)
	}

	if got := readLogText(t, cp, 8, 10*time.Second); got != "AAAABBBB" {
		t.Fatalf("streamed output = %q, want AAAABBBB", got)
	}

	// The link drops. The workload keeps running on the device, and the agent
	// must retain the output it produced.
	_ = cp.conn.Close("simulated network drop")

	// The agent reconnects on its own. Tell it the control plane received
	// nothing at all, so it must resend from offset 0.
	var cp2 *controlPlane
	select {
	case cp2 = <-conns:
	case <-time.After(20 * time.Second):
		t.Fatal("the agent should have reconnected after the link dropped")
	}

	hello := cp2.handshake(t, "agent-1", []remote.ResumeAck{{
		HandleID:   handleID,
		FromOffset: 0,
	}}, "")

	// The reconnecting agent must offer the handle it is still running,
	// otherwise the control plane would orphan the work.
	if len(hello.Resume) != 1 {
		t.Fatalf("reconnect hello should offer 1 resumable handle, got %d", len(hello.Resume))
	}
	if hello.Resume[0].HandleID != handleID {
		t.Errorf("resumed handle = %q, want %q", hello.Resume[0].HandleID, handleID)
	}
	if hello.Resume[0].LogOffset != 8 {
		t.Errorf("offered log offset = %d, want 8 (the bytes actually produced)", hello.Resume[0].LogOffset)
	}
	// A reconnect must reuse the stored identity, not re-enroll.
	if hello.AgentID != "agent-1" {
		t.Errorf("reconnect should claim the stored identity, got %q", hello.AgentID)
	}

	// Told to restart from 0, the agent must resend the retained bytes.
	if got := readLogText(t, cp2, 8, 10*time.Second); got != "AAAABBBB" {
		t.Fatalf("resent output = %q, want AAAABBBB", got)
	}
}

// readLogText accumulates log_chunk payloads until n bytes have arrived,
// asserting that offsets stay contiguous.
func readLogText(t *testing.T, cp *controlPlane, n int, timeout time.Duration) string {
	t.Helper()
	var sb strings.Builder
	deadline := time.Now().Add(timeout)
	for sb.Len() < n && time.Now().Before(deadline) {
		f, err := cp.read(time.Until(deadline))
		if err != nil {
			break
		}
		if f.Type != remote.TypeLogChunk {
			continue
		}
		chunk, err := remote.DecodeLogChunk(f)
		if err != nil {
			t.Fatalf("DecodeLogChunk: %v", err)
		}
		if chunk.Offset != int64(sb.Len()) {
			t.Fatalf("chunk offset = %d, want %d: offsets must be contiguous or the "+
				"control plane will record a phantom gap", chunk.Offset, sb.Len())
		}
		sb.WriteString(chunk.Text)
	}
	return sb.String()
}

// TestResolveWorkDirConfinement is the device's security boundary. The control
// plane is the party that could be compromised, so a workdir it supplies is
// untrusted input here.
func TestResolveWorkDirConfinement(t *testing.T) {
	root := filepath.Join(t.TempDir(), "root")
	a := &Agent{}
	resolved, err := resolveRoot(root)
	if err != nil {
		t.Fatalf("resolveRoot: %v", err)
	}
	a.root = resolved

	t.Run("relative paths land under the root", func(t *testing.T) {
		got, err := a.resolveWorkDir("myproject")
		if err != nil {
			t.Fatalf("resolveWorkDir: %v", err)
		}
		if !strings.HasPrefix(got, a.root) {
			t.Errorf("%q should be under %q", got, a.root)
		}
	})

	t.Run("empty means the root itself", func(t *testing.T) {
		got, err := a.resolveWorkDir("")
		if err != nil {
			t.Fatalf("resolveWorkDir: %v", err)
		}
		if got != a.root {
			t.Errorf("got %q, want %q", got, a.root)
		}
	})

	for _, escape := range []string{
		"/etc",
		"/",
		"../../../etc",
		"../sibling",
		"foo/../../..",
	} {
		t.Run("rejects "+escape, func(t *testing.T) {
			if _, err := a.resolveWorkDir(escape); !errors.Is(err, remote.ErrPathOutsideRoot) {
				t.Fatalf("resolveWorkDir(%q) should return ErrPathOutsideRoot, got %v", escape, err)
			}
		})
	}

	// A sibling directory whose name merely shares the root's prefix must not
	// pass: this is the classic "/srv/cloop-evil vs /srv/cloop" prefix bug.
	t.Run("rejects prefix-sharing sibling", func(t *testing.T) {
		sibling := a.root + "-evil"
		if err := os.MkdirAll(sibling, 0o700); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if _, err := a.resolveWorkDir(sibling); !errors.Is(err, remote.ErrPathOutsideRoot) {
			t.Fatalf("a sibling sharing the root's prefix must be rejected, got %v", err)
		}
	})

	// A symlink planted inside the root that points out of it must not be
	// honoured: lexical containment alone would accept it.
	t.Run("rejects symlink escape", func(t *testing.T) {
		outside := t.TempDir()
		link := filepath.Join(a.root, "escape-link")
		if err := os.Symlink(outside, link); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
		if _, err := a.resolveWorkDir("escape-link"); !errors.Is(err, remote.ErrPathOutsideRoot) {
			t.Fatalf("a symlink out of the root must be rejected, got %v", err)
		}
	})
}

func TestReconnectDelayIsBoundedAndJittered(t *testing.T) {
	// Early attempts grow; late attempts stay under the ceiling. Jitter means
	// individual values vary, so the assertions are on bounds, not equality.
	seen := make(map[time.Duration]bool)
	for attempt := 1; attempt <= 20; attempt++ {
		d := reconnectDelay(attempt)
		if d < 0 {
			t.Fatalf("attempt %d: negative delay %s", attempt, d)
		}
		upper := time.Duration(float64(reconnectMaxDelay) * (1 + remote.JitterFraction))
		if d > upper {
			t.Fatalf("attempt %d: delay %s exceeds the capped ceiling %s", attempt, d, upper)
		}
		seen[d] = true
	}
	// Jitter must actually vary, or a reconnecting fleet would stay
	// phase-locked and hammer the control plane in lockstep.
	if len(seen) < 5 {
		t.Errorf("expected jittered delays to vary, got %d distinct values", len(seen))
	}
}

func TestCredentialRoundTripAndPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "agent.json")
	cred := Credential{
		Server:      "wss://cp.example/api/executors/connect",
		AgentID:     "agent-1",
		Name:        "edge-1",
		Credential:  "clac1.a.b.c",
		WorkDirRoot: "/srv/work",
		EnrolledAt:  time.Now().Truncate(time.Second),
	}
	if err := SaveCredential(path, cred); err != nil {
		t.Fatalf("SaveCredential: %v", err)
	}

	got, err := LoadCredential(path)
	if err != nil {
		t.Fatalf("LoadCredential: %v", err)
	}
	if got.AgentID != cred.AgentID || got.Credential != cred.Credential || got.Server != cred.Server {
		t.Errorf("round trip mismatch: %+v vs %+v", got, cred)
	}
	if !got.Valid() {
		t.Error("a fully populated credential should be valid")
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("mode = %04o, want 0600", perm)
	}
	if warn := CheckCredentialPermissions(path); warn != "" {
		t.Errorf("a 0600 file should not warn, got %q", warn)
	}

	// Loosening the mode must produce a warning: a world-readable credential
	// on a shared device is an impersonation waiting to happen.
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	if warn := CheckCredentialPermissions(path); warn == "" {
		t.Error("a world-readable credential file must warn")
	}

	// Overwriting must re-assert 0600 rather than inherit the loose mode.
	if err := SaveCredential(path, cred); err != nil {
		t.Fatalf("SaveCredential (overwrite): %v", err)
	}
	info, err = os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("overwrite left mode %04o, want 0600", perm)
	}
}

func TestNewRequiresEnrollmentOrCredential(t *testing.T) {
	dir := t.TempDir()
	_, err := New(Config{
		Server:         "wss://cp.example/connect",
		CredentialPath: filepath.Join(dir, "missing.json"),
		WorkDirRoot:    filepath.Join(dir, "work"),
	})
	if err == nil {
		t.Fatal("an unenrolled agent with no token must refuse to start")
	}
	if !strings.Contains(err.Error(), "executor enroll") {
		t.Errorf("the error should tell the operator how to enroll, got %v", err)
	}
}

func TestCapabilitiesDetection(t *testing.T) {
	caps := Detect(DetectOptions{
		WorkDirRoot:   "/srv/work",
		MaxConcurrent: 4,
		Labels:        map[string]string{"site": "berlin"},
		LookPath: func(name string) (string, error) {
			if name == "docker" || name == "claude" {
				return "/usr/bin/" + name, nil
			}
			return "", errors.New("not found")
		},
		MemoryMB: 2048,
	})

	if caps.MemoryMB != 2048 {
		t.Errorf("MemoryMB = %d, want 2048", caps.MemoryMB)
	}
	if caps.MaxConcurrent != 4 {
		t.Errorf("MaxConcurrent = %d, want 4", caps.MaxConcurrent)
	}
	if !HasContainerRuntime(caps) {
		t.Error("docker on PATH should be advertised as a container runtime")
	}
	if !HasHarness(caps, "claude") {
		t.Error("claude on PATH should be advertised as a harness")
	}
	if HasHarness(caps, "codex") {
		t.Error("codex is not on PATH and must not be advertised")
	}
	if caps.Labels["site"] != "berlin" {
		t.Error("operator labels should be advertised for scheduling")
	}

	// The projection onto the driver-agnostic type must be honest about
	// isolation, or host-side tooling will look for files that are not there.
	ecaps := caps.Executor()
	if ecaps.SharesHostFilesystem {
		t.Error("a remote executor must never claim to share the host filesystem")
	}
}

// waitFor polls cond until it holds or the timeout expires.
func waitFor(t *testing.T, timeout time.Duration, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("timed out: %s", msg)
}

// TestAgentEnforcesConcurrencyCeiling checks that the limit the agent
// advertises is the limit it actually applies. Advertising a ceiling the
// device does not enforce would let a scheduler that trusts it overload a
// small box until the OOM killer intervened.
func TestAgentEnforcesConcurrencyCeiling(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "work")

	conns := make(chan *controlPlane, 4)
	a, err := New(Config{
		Server:         "wss://control-plane.invalid/connect",
		Token:          "clet1.fake.fake.fake",
		CredentialPath: filepath.Join(dir, "agent.json"),
		WorkDirRoot:    root,
		MaxConcurrent:  1,
		Logf:           func(format string, args ...any) { t.Logf("agent: "+format, args...) },
		Dial: func(ctx context.Context, server, token string) (remote.Conn, error) {
			agentSide, cpSide := remote.NewPipe(64)
			conns <- &controlPlane{t: t, conn: cpSide}
			return agentSide, nil
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if got := a.Capabilities().MaxConcurrent; got != 1 {
		t.Fatalf("advertised MaxConcurrent = %d, want 1", got)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = a.Run(ctx) }()

	cp := <-conns
	cp.handshake(t, "agent-1", nil, "clac1.a.b.c")

	sleeper := func(id string) remote.Frame {
		f, err := remote.NewFrame(remote.TypeStart, "req-"+id, id, remote.StartPayload{
			HandleID: id,
			Spec:     executor.Spec{WorkDir: "proj", Argv: []string{"/bin/sh", "-c", "sleep 30"}},
		})
		if err != nil {
			t.Fatalf("build start: %v", err)
		}
		return f
	}

	// The first start fills the single slot.
	cp.write(sleeper("h1"))
	if got := cp.readUntil(remote.TypeStarted, 10*time.Second); got.Handle != "h1" {
		t.Fatalf("expected h1 to start, got handle %q", got.Handle)
	}

	// The second must be refused as busy rather than admitted.
	cp.write(sleeper("h2"))
	errFrame := cp.readUntil(remote.TypeError, 10*time.Second)
	payload, err := remote.DecodeError(errFrame)
	if err != nil {
		t.Fatalf("DecodeError: %v", err)
	}
	if payload.Code != remote.CodeBusy {
		t.Fatalf("error code = %q, want %q", payload.Code, remote.CodeBusy)
	}
}

// TestKilledWorkloadKeepsItsOutputTail is a regression test for a defect where
// a signalled workload's dying output was silently discarded.
//
// The local backend marks a handle killed the instant the signal is delivered,
// while the process's remaining output is still in the pipe. The agent used to
// answer the signal with that terminal status; the control plane closes a log
// stream on terminal status, so every subsequent chunk was dropped without
// even a gap flag. For a killed or timed-out run that tail is where the useful
// output is, which made the loss maximally expensive.
func TestKilledWorkloadKeepsItsOutputTail(t *testing.T) {
	dir := t.TempDir()
	a, conns := newScriptedAgent(t, filepath.Join(dir, "agent.json"), filepath.Join(dir, "work"))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = a.Run(ctx) }()

	cp := <-conns
	cp.handshake(t, "agent-1", nil, "clac1.a.b.c")

	// A workload that installs a SIGTERM trap and prints on the way out, so
	// there is a deterministic tail to lose.
	const handleID = "h1"
	f, err := remote.NewFrame(remote.TypeStart, "req-1", handleID, remote.StartPayload{
		HandleID: handleID,
		Spec: executor.Spec{
			WorkDir: "proj",
			Argv: []string{"/bin/sh", "-c",
				`trap 'printf DYINGWORDS; exit 3' TERM; printf READY; while :; do sleep 0.05; done`},
		},
	})
	if err != nil {
		t.Fatalf("build start: %v", err)
	}
	cp.write(f)
	cp.readUntil(remote.TypeStarted, 10*time.Second)

	if got := readLogText(t, cp, 5, 10*time.Second); got != "READY" {
		t.Fatalf("startup output = %q, want READY", got)
	}

	sig, err := remote.NewFrame(remote.TypeSignal, "sig-1", handleID,
		remote.SignalPayload{Signal: executor.SignalTerminate})
	if err != nil {
		t.Fatalf("build signal: %v", err)
	}
	cp.write(sig)

	// Collect until the workload's genuine terminal status arrives. The reply
	// to the signal must NOT be terminal, or the control plane would close the
	// stream while DYINGWORDS was still in flight.
	var tail strings.Builder
	var final remote.StatusPayload
	sawTerminal := false
	deadline := time.Now().Add(15 * time.Second)
	for !sawTerminal && time.Now().Before(deadline) {
		frame, err := cp.read(time.Until(deadline))
		if err != nil {
			break
		}
		switch frame.Type {
		case remote.TypeLogChunk:
			chunk, err := remote.DecodeLogChunk(frame)
			if err != nil {
				t.Fatalf("DecodeLogChunk: %v", err)
			}
			tail.WriteString(chunk.Text)
		case remote.TypeStatus:
			sp, err := remote.DecodeStatus(frame)
			if err != nil {
				t.Fatalf("DecodeStatus: %v", err)
			}
			if sp.Status.State.Terminal() {
				final = sp
				sawTerminal = true
			}
		}
	}

	if !sawTerminal {
		t.Fatal("the agent never reported a terminal status for the killed workload")
	}
	if !strings.Contains(tail.String(), "DYINGWORDS") {
		t.Fatalf("the workload's dying output was lost; collected %q", tail.String())
	}
	// FinalOffset must account for every byte, so the control plane can tell
	// a complete stream from a truncated one.
	if final.FinalOffset != int64(len("READY")+len("DYINGWORDS")) {
		t.Errorf("FinalOffset = %d, want %d", final.FinalOffset, len("READY")+len("DYINGWORDS"))
	}
}

// TestWorkloadFinishingOfflineReportsOnReconnect is a regression test for a
// workload that exits while the link is down. The agent used to forget it
// unconditionally, so the exit code and the log tail were lost and the control
// plane eventually mis-resolved a clean exit as a failure.
func TestWorkloadFinishingOfflineReportsOnReconnect(t *testing.T) {
	dir := t.TempDir()
	a, conns := newScriptedAgent(t, filepath.Join(dir, "agent.json"), filepath.Join(dir, "work"))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = a.Run(ctx) }()

	cp := <-conns
	cp.handshake(t, "agent-1", nil, "clac1.a.b.c")

	// Drop the link first, then start a workload that exits quickly, so it
	// finishes with no session to report to.
	const handleID = "h1"
	f, err := remote.NewFrame(remote.TypeStart, "req-1", handleID, remote.StartPayload{
		HandleID: handleID,
		Spec: executor.Spec{
			WorkDir: "proj",
			Argv:    []string{"/bin/sh", "-c", "printf OFFLINEOUT; exit 5"},
		},
	})
	if err != nil {
		t.Fatalf("build start: %v", err)
	}
	cp.write(f)
	cp.readUntil(remote.TypeStarted, 10*time.Second)
	_ = cp.conn.Close("drop before the workload finishes")

	var cp2 *controlPlane
	select {
	case cp2 = <-conns:
	case <-time.After(20 * time.Second):
		t.Fatal("agent should reconnect")
	}
	// Ask for everything from the start: we received nothing.
	cp2.handshake(t, "agent-1", []remote.ResumeAck{{HandleID: handleID, FromOffset: 0}}, "")

	var out strings.Builder
	var final remote.StatusPayload
	sawTerminal := false
	deadline := time.Now().Add(15 * time.Second)
	for !sawTerminal && time.Now().Before(deadline) {
		frame, err := cp2.read(time.Until(deadline))
		if err != nil {
			break
		}
		switch frame.Type {
		case remote.TypeLogChunk:
			chunk, err := remote.DecodeLogChunk(frame)
			if err != nil {
				t.Fatalf("DecodeLogChunk: %v", err)
			}
			out.WriteString(chunk.Text)
		case remote.TypeStatus:
			sp, err := remote.DecodeStatus(frame)
			if err != nil {
				t.Fatalf("DecodeStatus: %v", err)
			}
			if sp.Status.State.Terminal() {
				final = sp
				sawTerminal = true
			}
		}
	}

	if !sawTerminal {
		t.Fatal("a workload that exited offline must report its outcome after reconnect")
	}
	if final.Status.ExitCode != 5 {
		t.Errorf("exit code = %d, want 5", final.Status.ExitCode)
	}
	if out.String() != "OFFLINEOUT" {
		t.Errorf("output produced offline should be resent, got %q", out.String())
	}
}
