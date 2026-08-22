package remote_test

// Loopback end-to-end test: a real control plane, a real agent, a real
// WebSocket, and a real command.
//
// Every other test in this package drives one side with a scripted peer. This
// one wires the actual halves together over an httptest server and runs a
// process, so the pieces that only exist at the seam are covered: the HTTP
// upgrade, bearer-token enrollment, inline credential issuance, capability
// advertisement, output streaming through two logbuses, and exit-code
// propagation from a device process back to executor.Run.
//
// It lives in the external test package because pkg/executor/agent imports
// pkg/executor/remote, so only a _test package outside remote can import both.

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/agent"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
)

// loopback wires a hub, an httptest server, and an enrolled agent together.
type loopback struct {
	hub      *remote.Hub
	registry *executor.Registry
	server   *httptest.Server
	agent    *agent.Agent
	credPath string
	root     string
	cancel   context.CancelFunc
}

// detachableLogf returns a t.Logf wrapper that goes silent once the test ends.
//
// The hub and the agent both log from goroutines that outlive the test body: a
// hijacked WebSocket connection is not tracked by httptest.Server.Close, so a
// disconnect message can land after tRunner has already marked the test done.
// Calling t.Logf at that point is a data race on testing.common (and, in newer
// Go, a panic), which made this suite fail under -race roughly two runs in
// five.
//
// The disable is registered as the first cleanup so it runs *last*, after the
// server is closed and the agent cancelled. Any straggler that logs after that
// takes the mutex, sees detached, and returns without touching t at all —
// which is what makes this airtight regardless of how long a goroutine lingers.
func detachableLogf(t *testing.T) func(string, ...any) {
	t.Helper()
	var (
		mu       sync.Mutex
		detached bool
	)
	t.Cleanup(func() {
		mu.Lock()
		detached = true
		mu.Unlock()
	})
	return func(format string, args ...any) {
		mu.Lock()
		defer mu.Unlock()
		if detached {
			return
		}
		t.Logf(format, args...)
	}
}

// newLoopback enrolls an agent against a live control plane and waits for it
// to connect.
func newLoopback(t *testing.T) *loopback {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the loopback test runs POSIX shell commands")
	}

	store := newMemStore()
	// A private registry: the process-wide default is shared with every other
	// test in the binary, and registering a live agent into it would leak
	// across tests.
	reg := executor.NewRegistry()

	logf := detachableLogf(t)

	hub, err := remote.NewHub(remote.HubOptions{
		Store:    store,
		Registry: reg,
		Logf:     func(format string, args ...any) { logf("hub: "+format, args...) },
	})
	if err != nil {
		t.Fatalf("NewHub: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(hub.ServeHTTP))
	t.Cleanup(srv.Close)

	root := filepath.Join(t.TempDir(), "work")
	token, _, err := remote.Mint(store, remote.MintOptions{
		Name:        "edge-1",
		TTL:         5 * time.Minute,
		WorkDirRoot: root,
	})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	credPath := filepath.Join(t.TempDir(), "agent.json")
	a, err := agent.New(agent.Config{
		Server:         "ws" + strings.TrimPrefix(srv.URL, "http"),
		Token:          token,
		CredentialPath: credPath,
		WorkDirRoot:    root,
		Logf:           func(format string, args ...any) { logf("agent: "+format, args...) },
	})
	if err != nil {
		t.Fatalf("agent.New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() {
		// logf, not t.Logf: a.Run commonly returns *after* the test body has
		// finished, which is the same post-completion logging race the
		// detachable wrapper exists to close.
		if err := a.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
			logf("agent.Run returned: %v", err)
		}
	}()

	lb := &loopback{
		hub: hub, registry: reg, server: srv, agent: a,
		credPath: credPath, root: root, cancel: cancel,
	}
	lb.waitConnected(t)
	return lb
}

// waitConnected blocks until the agent's executor is registered and online.
func (lb *loopback) waitConnected(t *testing.T) {
	t.Helper()
	waitFor(t, 15*time.Second, func() bool {
		for _, ex := range lb.hub.Executors() {
			if ex.Connected() {
				return true
			}
		}
		return false
	}, "the agent should dial in and attach a session")
}

// executorHandle returns the connected remote executor.
func (lb *loopback) executor(t *testing.T) *remote.Executor {
	t.Helper()
	for _, ex := range lb.hub.Executors() {
		if ex.Connected() {
			return ex
		}
	}
	t.Fatal("no connected executor")
	return nil
}

// TestLoopbackRunsRealCommand is the headline end-to-end assertion: work
// dispatched by the control plane actually executes on the agent and its
// output and exit code come back.
func TestLoopbackRunsRealCommand(t *testing.T) {
	lb := newLoopback(t)
	ex := lb.executor(t)

	res, err := executor.Run(context.Background(), ex, executor.Spec{
		// A relative workdir: the agent provisions it beneath its root, so
		// the control plane never has to know the device's filesystem layout.
		WorkDir: "e2e-project",
		Argv:    []string{"/bin/sh", "-c", "echo hello from the agent; pwd"},
		Labels:  map[string]string{"component": "e2e"},
	})
	if err != nil {
		t.Fatalf("Run: %v (output=%q)", err, res.Output)
	}

	out := string(res.Output)
	if !strings.Contains(out, "hello from the agent") {
		t.Errorf("workload output not streamed back; got %q", out)
	}
	// The command ran in the confined directory the agent provisioned, not
	// wherever the control plane happened to be.
	if !strings.Contains(out, "e2e-project") {
		t.Errorf("workload should have run in the provisioned workdir; got %q", out)
	}
	if res.Status.State != executor.StateExited {
		t.Errorf("state = %q, want exited", res.Status.State)
	}
	if res.Status.ExitCode != 0 {
		t.Errorf("exit code = %d, want 0", res.Status.ExitCode)
	}
	if res.Dropped {
		t.Error("no output should have been dropped for a tiny workload")
	}

	// The directory really was created under the agent's root.
	if _, err := os.Stat(filepath.Join(lb.root, "e2e-project")); err != nil {
		t.Errorf("agent should have provisioned the workdir under its root: %v", err)
	}
}

// TestLoopbackPropagatesNonZeroExit checks that a failing workload surfaces as
// a failure rather than a success with unread output.
func TestLoopbackPropagatesNonZeroExit(t *testing.T) {
	lb := newLoopback(t)
	ex := lb.executor(t)

	res, err := executor.Run(context.Background(), ex, executor.Spec{
		WorkDir: "failing",
		Argv:    []string{"/bin/sh", "-c", "echo to stderr >&2; exit 7"},
	})
	if err == nil {
		t.Fatal("a non-zero exit must be reported as an error")
	}
	if res.Status.ExitCode != 7 {
		t.Errorf("exit code = %d, want 7", res.Status.ExitCode)
	}
	if !strings.Contains(string(res.Output), "to stderr") {
		t.Errorf("stderr should be streamed back too; got %q", res.Output)
	}
}

// TestLoopbackEnrollmentPersistsCredential covers the enrollment half: the
// device must end up with a usable, correctly-permissioned credential, and the
// single-use token must be spent.
func TestLoopbackEnrollmentPersistsCredential(t *testing.T) {
	lb := newLoopback(t)

	// The control plane attaches the session (and so reports "connected")
	// while sending the welcome that carries the credential, so the agent
	// necessarily persists it a moment later. Wait for the write rather than
	// assuming connectivity implies it.
	waitFor(t, 10*time.Second, func() bool {
		_, err := os.Stat(lb.credPath)
		return err == nil
	}, "the agent should persist its issued credential")

	info, err := os.Stat(lb.credPath)
	if err != nil {
		t.Fatalf("the agent should have persisted its credential: %v", err)
	}
	// 0600 is the whole point: the credential is the device's identity, and a
	// world-readable copy on a shared machine is an impersonation waiting to
	// happen.
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("credential file mode = %04o, want 0600", perm)
	}

	if lb.agent.AgentID() == "" {
		t.Error("the agent should know its assigned identity after enrolling")
	}

	// The advertised capabilities must have reached the control plane, since
	// that is what makes scheduling possible at all.
	ex := lb.executor(t)
	caps := ex.AgentCapabilities()
	if caps.OS != runtime.GOOS || caps.Arch != runtime.GOARCH {
		t.Errorf("capabilities = %s/%s, want %s/%s", caps.OS, caps.Arch, runtime.GOOS, runtime.GOARCH)
	}
	if caps.CPUs <= 0 {
		t.Error("the agent should advertise its CPU count for scheduling")
	}
	if caps.WorkDirRoot != lb.root {
		t.Errorf("advertised root = %q, want %q", caps.WorkDirRoot, lb.root)
	}
	// Isolation must be reported honestly: the workload is on another
	// machine, so host-side tooling must not assume it can read the workdir.
	ecaps := ex.Capabilities()
	if ecaps.Isolation != executor.IsolationRemote {
		t.Errorf("isolation = %q, want remote", ecaps.Isolation)
	}
	if ecaps.SharesHostFilesystem {
		t.Error("a remote executor must not claim to share the host filesystem")
	}
}

// TestLoopbackRejectsWorkdirEscape is the device-side security boundary: a
// control plane (compromised or buggy) must not be able to make the device run
// work against an arbitrary path.
func TestLoopbackRejectsWorkdirEscape(t *testing.T) {
	lb := newLoopback(t)
	ex := lb.executor(t)

	for _, dir := range []string{"/etc", "../../..", "../escape"} {
		t.Run(dir, func(t *testing.T) {
			_, err := ex.Start(context.Background(), executor.Spec{
				WorkDir: dir,
				Argv:    []string{"/bin/sh", "-c", "echo pwned"},
			})
			if err == nil {
				t.Fatalf("workdir %q escapes the agent root and must be refused", dir)
			}
			if !strings.Contains(err.Error(), "outside this agent's root") {
				t.Errorf("error should name the confinement boundary, got %v", err)
			}
		})
	}
}

// TestLoopbackSignalStopsWorkload checks that the Stop button reaches a
// process on another machine.
func TestLoopbackSignalStopsWorkload(t *testing.T) {
	lb := newLoopback(t)
	ex := lb.executor(t)

	handle, err := ex.Start(context.Background(), executor.Spec{
		WorkDir: "long-running",
		Argv:    []string{"/bin/sh", "-c", "sleep 120"},
	})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	lines, err := ex.Stream(context.Background(), handle.ID)
	if err != nil {
		t.Fatalf("Stream: %v", err)
	}
	sink := newStreamSink(lines)

	if err := ex.Signal(context.Background(), handle.ID, executor.SignalKill); err != nil {
		t.Fatalf("Signal: %v", err)
	}

	// The workload's termination closes its stream.
	sink.waitClosed(t, 15*time.Second)

	st, err := ex.Status(context.Background(), handle.ID)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if !st.State.Terminal() {
		t.Errorf("state after kill = %q, want a terminal state", st.State)
	}
}

// TestLoopbackRejectsUnauthenticatedConnect checks the endpoint refuses
// connections without a valid credential, since it deliberately sits outside
// the dashboard's own auth.
func TestLoopbackRejectsUnauthenticatedConnect(t *testing.T) {
	store := newMemStore()
	hub, err := remote.NewHub(remote.HubOptions{Store: store, Registry: executor.NewRegistry()})
	if err != nil {
		t.Fatalf("NewHub: %v", err)
	}
	srv := httptest.NewServer(http.HandlerFunc(hub.ServeHTTP))
	defer srv.Close()

	for name, header := range map[string]string{
		"no token":       "",
		"garbage token":  "Bearer not-a-real-token",
		"wrong prefix":   "Bearer clet1.aaa.bbb.ccc",
		"malformed auth": "Basic dXNlcjpwYXNz",
	} {
		t.Run(name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, srv.URL, nil)
			if err != nil {
				t.Fatalf("NewRequest: %v", err)
			}
			if header != "" {
				req.Header.Set("Authorization", header)
			}
			resp, err := srv.Client().Do(req)
			if err != nil {
				t.Fatalf("Do: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusUnauthorized {
				t.Errorf("status = %d, want 401", resp.StatusCode)
			}
		})
	}
}

// TestLoopbackRevokeDisconnectsLiveAgent checks that revocation reaches an
// already-connected device. Revoking only in storage would leave a compromised
// agent running work until it happened to reconnect — which, for a long-lived
// outbound WebSocket, could be never.
func TestLoopbackRevokeDisconnectsLiveAgent(t *testing.T) {
	lb := newLoopback(t)
	ex := lb.executor(t)
	agentID := ex.ID()

	if err := lb.hub.Revoke(agentID); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	waitFor(t, 10*time.Second, func() bool { return !ex.Connected() },
		"revoking a credential must drop the live session")

	_, err := ex.Start(context.Background(), executor.Spec{
		WorkDir: "after-revoke",
		Argv:    []string{"/bin/sh", "-c", "echo should not run"},
	})
	if !errors.Is(err, remote.ErrAgentUnreachable) {
		t.Fatalf("Start after revoke should fail fast, got %v", err)
	}
}

// TestLoopbackSignalledWorkloadKeepsDyingOutput is the end-to-end regression
// for output lost at termination.
//
// The agent's local backend marks a handle killed the instant the signal is
// delivered, while the process's remaining output is still in the pipe. The
// agent used to answer the signal with that terminal status, and the control
// plane closes a log stream on terminal status — so everything the process
// printed on its way out was silently discarded. For a stopped or timed-out
// run that tail is usually the only evidence of what went wrong.
//
// SIGTERM is used rather than executor.Run's SIGKILL because only a catchable
// signal lets the workload produce dying output to lose in the first place.
func TestLoopbackSignalledWorkloadKeepsDyingOutput(t *testing.T) {
	lb := newLoopback(t)
	ex := lb.executor(t)

	handle, err := ex.Start(context.Background(), executor.Spec{
		WorkDir: "dying-proj",
		Argv: []string{"/bin/sh", "-c",
			`trap 'printf LASTGASP; exit 9' TERM; printf WORKING; while :; do sleep 0.05; done`},
	})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	lines, err := ex.Stream(context.Background(), handle.ID)
	if err != nil {
		t.Fatalf("Stream: %v", err)
	}
	sink := newStreamSink(lines)

	waitFor(t, 15*time.Second, func() bool { return strings.Contains(sink.text(), "WORKING") },
		"the workload's startup output should stream back")

	if err := ex.Signal(context.Background(), handle.ID, executor.SignalTerminate); err != nil {
		t.Fatalf("Signal: %v", err)
	}

	// The stream closes on the terminal status, which must not arrive until
	// the dying output has been forwarded.
	sink.waitClosed(t, 15*time.Second)

	out := sink.text()
	if !strings.Contains(out, "WORKING") {
		t.Errorf("output before the signal was lost; got %q", out)
	}
	if !strings.Contains(out, "LASTGASP") {
		t.Errorf("output produced while dying was lost; got %q", out)
	}

	st, err := ex.Status(context.Background(), handle.ID)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if !st.State.Terminal() {
		t.Errorf("state = %q, want a terminal state", st.State)
	}
	if ex.LogGapped(handle.ID) {
		t.Error("no output was actually lost, so the log must not be flagged as gapped")
	}
}
