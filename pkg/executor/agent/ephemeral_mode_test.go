package agent

// `cloop executor agent --ephemeral` (Task 20483): the runner's side of the
// contract, held by the agent itself — a runner token only, no stored
// credential, one run, exit after it, a farewell to the hub, a wipe, and a
// retirement report.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
)

const testRunnerToken = "clrt1.enrollid.secretsecret.mac"

type ephemeralRig struct {
	a        *Agent
	conns    <-chan *controlPlane
	root     string
	termLog  string
	mu       sync.Mutex
	tokens   []string
	credPath string
}

func newEphemeralAgent(t *testing.T, mutate func(*Config)) *ephemeralRig {
	t.Helper()
	dir := t.TempDir()
	r := &ephemeralRig{root: filepath.Join(dir, "work"), termLog: filepath.Join(dir, "termination-log"),
		credPath: filepath.Join(dir, "agent.json")}
	conns := make(chan *controlPlane, 4)
	cfg := Config{
		Server:         "wss://control-plane.invalid/api/executors/connect",
		Token:          testRunnerToken,
		CredentialPath: r.credPath,
		WorkDirRoot:    r.root,
		Ephemeral:      true,
		TerminationLog: r.termLog,
		RetireGrace:    300 * time.Millisecond,
		Logf:           func(format string, args ...any) { t.Logf("agent: "+format, args...) },
		Dial: func(ctx context.Context, server, token string) (remote.Conn, error) {
			r.mu.Lock()
			r.tokens = append(r.tokens, token)
			r.mu.Unlock()
			agentSide, cpSide := remote.NewPipe(64)
			conns <- &controlPlane{t: t, conn: cpSide}
			return agentSide, nil
		},
	}
	if mutate != nil {
		mutate(&cfg)
	}
	a, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	reapOnCleanup(t, a)
	r.a, r.conns = a, conns
	return r
}

// welcomeRunner answers the hello as a hub welcomes a runner.
func welcomeRunner(t *testing.T, cp *controlPlane, ephemeral bool) {
	t.Helper()
	f := cp.readUntil(remote.TypeHello, 5*time.Second)
	welcome, err := remote.NewFrame(remote.TypeWelcome, f.ID, "", remote.WelcomePayload{
		ProtocolVersion: remote.ProtocolVersion, ExecutorID: "runner-1",
		Credential:       "clrc1.runner-1.secret.mac",
		HeartbeatSeconds: int(remote.HeartbeatInterval / time.Second), Ephemeral: ephemeral,
	})
	if err != nil {
		t.Fatal(err)
	}
	cp.write(welcome)
}

func (r *ephemeralRig) report(t *testing.T) RetirementReport {
	t.Helper()
	raw, err := os.ReadFile(r.termLog)
	if err != nil {
		t.Fatalf("no termination log: %v", err)
	}
	var rep RetirementReport
	if err := json.Unmarshal(raw, &rep); err != nil {
		t.Fatalf("termination log %q: %v", raw, err)
	}
	return rep
}

func runAgent(a *Agent) (context.CancelFunc, <-chan error) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()
	return cancel, done
}

func waitRun(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(20 * time.Second):
		t.Fatal("the runner did not exit")
	}
	return nil
}

func TestEphemeralRefusesATokenThatIsNoRunnerToken(t *testing.T) {
	_, err := New(Config{Server: "wss://hub.invalid/api/executors/connect", Token: "clet1.id.secret.mac",
		WorkDirRoot: t.TempDir(), CredentialPath: filepath.Join(t.TempDir(), "agent.json"), Ephemeral: true})
	if err == nil || !strings.Contains(err.Error(), "runner token") {
		t.Fatalf("New with a device's token: %v", err)
	}
	_, err = New(Config{Server: "wss://hub.invalid/api/executors/connect", WorkDirRoot: t.TempDir(),
		CredentialPath: filepath.Join(t.TempDir(), "agent.json"), Ephemeral: true})
	if err == nil || !strings.Contains(err.Error(), "needs a runner token") {
		t.Fatalf("New with no token: %v", err)
	}
}

// A device's credential lying in the runner's home is not its identity.
func TestEphemeralNeverUsesAStoredCredential(t *testing.T) {
	dir := t.TempDir()
	cred := filepath.Join(dir, "agent.json")
	if err := SaveCredential(cred, Credential{Server: "wss://other.invalid/api/executors/connect", AgentID: "edge-1",
		Credential: "clac1.edge-1.secret.mac"}); err != nil {
		t.Fatal(err)
	}
	r := newEphemeralAgent(t, func(c *Config) { c.CredentialPath = cred })
	cancel, done := runAgent(r.a)
	defer cancel()
	cp := <-r.conns
	f := cp.readUntil(remote.TypeHello, 5*time.Second)
	hello, _ := remote.DecodeHello(f)
	if hello.AgentID != "" {
		t.Fatalf("the runner claimed %q from a stored credential", hello.AgentID)
	}
	r.mu.Lock()
	tok := r.tokens[0]
	r.mu.Unlock()
	if tok != testRunnerToken {
		t.Fatalf("the runner dialled with %q, not its runner token", tok)
	}
	cancel()
	_ = waitRun(t, done)
}

// A hub that welcomes it as a device is refused: the process must not become
// a permanent executor.
func TestEphemeralRefusesAWelcomeThatIsNotARunners(t *testing.T) {
	r := newEphemeralAgent(t, nil)
	_, done := runAgent(r.a)
	cp := <-r.conns
	welcomeRunner(t, cp, false)
	err := waitRun(t, done)
	if !errors.Is(err, errEphemeralNotRunner) {
		t.Fatalf("Run returned %v, want the not-a-runner refusal", err)
	}
	if _, err := os.Stat(r.credPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a refused runner wrote a credential (%v)", err)
	}
	rep := r.report(t)
	if rep.Retired || rep.By != "refused" {
		t.Fatalf("report %+v", rep)
	}
}

// One run, then out: a second start is refused, and once the run is over and
// reported the runner says goodbye and exits on its own when the hub does not
// retire it — wiping what the run left and reporting it.
func TestEphemeralTakesOneRunThenRetiresItselfAndWipes(t *testing.T) {
	r := newEphemeralAgent(t, nil)
	_, done := runAgent(r.a)
	cp := <-r.conns
	welcomeRunner(t, cp, true)

	start, err := remote.NewFrame(remote.TypeStart, "start-1", "h1", remote.StartPayload{HandleID: "h1",
		Spec: executor.Spec{WorkDir: "proj", Argv: []string{"/bin/sh", "-c", "echo one-run > out.txt; echo done"}}})
	if err != nil {
		t.Fatal(err)
	}
	cp.write(start)
	cp.readUntil(remote.TypeStarted, 10*time.Second)
	second, _ := remote.NewFrame(remote.TypeStart, "start-2", "h2", remote.StartPayload{HandleID: "h2",
		Spec: executor.Spec{WorkDir: "proj2", Argv: []string{"/bin/true"}}})

	var sawRefusal, sawStatus, sawBye bool
	var bye remote.ByePayload
	sentSecond := false
	deadline := time.Now().Add(15 * time.Second)
	for !sawBye && time.Now().Before(deadline) {
		f, err := cp.read(time.Until(deadline))
		if err != nil {
			break
		}
		switch f.Type {
		case remote.TypeStatus:
			st, _ := remote.DecodeStatus(f)
			if st.Status.State.Terminal() {
				sawStatus = true
				if !sentSecond {
					sentSecond = true
					cp.write(second)
				}
			}
		case remote.TypeError:
			if p, _ := remote.DecodeError(f); f.ID == "start-2" && strings.Contains(p.Message, "one run") {
				sawRefusal = true
			}
		case remote.TypeBye:
			bye, _ = remote.DecodeBye(f)
			sawBye = true
		}
	}
	if !sawStatus || !sawRefusal || !sawBye {
		t.Fatalf("status %v, second start refused %v, farewell %v", sawStatus, sawRefusal, sawBye)
	}
	if !bye.Retired || bye.Reconnect || !strings.Contains(bye.Reason, "retired itself") {
		t.Fatalf("farewell %+v", bye)
	}
	if err := waitRun(t, done); err != nil {
		t.Fatalf("Run returned %v, want nil for a runner that retired after its run", err)
	}
	rep := r.report(t)
	if !rep.Retired || rep.By != "self" || rep.Runs != 1 || !rep.Wiped || rep.ExecutorID != "runner-1" {
		t.Fatalf("report %+v", rep)
	}
	entries, _ := os.ReadDir(r.root)
	if len(entries) != 0 {
		t.Fatalf("the work root after the wipe holds %d entries, want none", len(entries))
	}
	if tok, _ := r.a.authToken(); tok != "" {
		t.Fatalf("the runner still holds %q after its wipe", tok)
	}
}

// Stopped before it took a run, it tells the hub it is leaving.
func TestEphemeralStoppedSaysGoodbyeToTheHub(t *testing.T) {
	r := newEphemeralAgent(t, nil)
	cancel, done := runAgent(r.a)
	cp := <-r.conns
	welcomeRunner(t, cp, true)
	waitFor(t, 5*time.Second, r.a.isEphemeral, "the runner should know it is a runner")
	waitFor(t, 5*time.Second, func() bool { return r.a.currentSession() != nil }, "a live session")
	cancel()
	f := cp.readUntil(remote.TypeBye, 5*time.Second)
	bye, _ := remote.DecodeBye(f)
	if !bye.Retired || !strings.Contains(bye.Reason, "before it was handed a run") {
		t.Fatalf("farewell %+v", bye)
	}
	if err := waitRun(t, done); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if rep := r.report(t); !rep.Retired || rep.By != "stopped" || rep.Runs != 0 {
		t.Fatalf("report %+v", rep)
	}
}

// Retired by the hub, it ends with success and says so.
func TestEphemeralRetiredByTheHubReportsIt(t *testing.T) {
	r := newEphemeralAgent(t, nil)
	_, done := runAgent(r.a)
	cp := <-r.conns
	welcomeRunner(t, cp, true)
	waitFor(t, 5*time.Second, r.a.isEphemeral, "the runner should know it is a runner")
	bye, _ := remote.NewFrame(remote.TypeBye, "", "", remote.ByePayload{Reason: "its controller scaled the pool down",
		Retired: true})
	cp.write(bye)
	if err := waitRun(t, done); err != nil {
		t.Fatalf("Run: %v", err)
	}
	rep := r.report(t)
	if !rep.Retired || rep.By != "hub" || !strings.Contains(rep.Reason, "scaled the pool down") {
		t.Fatalf("report %+v", rep)
	}
}

// The runner empties its work root on exit, so it starts only in an empty
// one of its own.
func TestEphemeralRefusesAWorkRootThatHoldsSomething(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "keep.txt"), []byte("mine"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := New(Config{Server: "wss://hub.invalid/api/executors/connect", Token: testRunnerToken, WorkDirRoot: root,
		CredentialPath: filepath.Join(t.TempDir(), "agent.json"), Ephemeral: true})
	if err == nil || !strings.Contains(err.Error(), "empty --workdir-root") {
		t.Fatalf("New with a root that holds a file: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "keep.txt")); err != nil {
		t.Fatalf("the refused runner touched the root: %v", err)
	}
}

// A runner refused before it ever enrolled — its token lapsed, or its pool was
// revoked — gives up and reports it, instead of retrying for ever.
func TestEphemeralRefusedAtEnrollmentGivesUp(t *testing.T) {
	r := newEphemeralAgent(t, func(c *Config) {
		c.Dial = func(context.Context, string, string) (remote.Conn, error) {
			return nil, fmt.Errorf("%w: control plane rejected the credential (HTTP 401)", remote.ErrCredentialInvalid)
		}
	})
	_, done := runAgent(r.a)
	err := waitRun(t, done)
	if err == nil || !errors.Is(err, remote.ErrCredentialInvalid) {
		t.Fatalf("Run returned %v, want the refusal", err)
	}
	if rep := r.report(t); rep.Retired || rep.By != "refused" || !strings.Contains(rep.Reason, "401") {
		t.Fatalf("report %+v", rep)
	}
}

// Stopped during its run, the runner stops the run too before it wipes, and
// tells the hub it left mid-run.
func TestEphemeralStoppedDuringItsRunStopsTheRun(t *testing.T) {
	r := newEphemeralAgent(t, nil)
	cancel, done := runAgent(r.a)
	cp := <-r.conns
	welcomeRunner(t, cp, true)
	pidFile := filepath.Join(t.TempDir(), "pid")
	start, err := remote.NewFrame(remote.TypeStart, "start-1", "h1", remote.StartPayload{HandleID: "h1",
		Spec: executor.Spec{WorkDir: "proj", Argv: []string{"/bin/sh", "-c", "echo $$ > " + pidFile + "; exec sleep 300"}}})
	if err != nil {
		t.Fatal(err)
	}
	cp.write(start)
	cp.readUntil(remote.TypeStarted, 10*time.Second)
	waitFor(t, 10*time.Second, func() bool { _, err := os.Stat(pidFile); return err == nil }, "the workload started")
	cancel()
	f := cp.readUntil(remote.TypeBye, 10*time.Second)
	bye, _ := remote.DecodeBye(f)
	if !bye.Retired || !strings.Contains(bye.Reason, "during its run") {
		t.Fatalf("farewell %+v", bye)
	}
	if err := waitRun(t, done); err != nil {
		t.Fatalf("Run: %v", err)
	}
	rep := r.report(t)
	if !rep.Retired || rep.By != "stopped" || !rep.Interrupted {
		t.Fatalf("report %+v", rep)
	}
	raw, _ := os.ReadFile(pidFile)
	pid, _ := strconv.Atoi(strings.TrimSpace(string(raw)))
	if pid > 0 && syscall.Kill(pid, 0) == nil {
		_ = syscall.Kill(pid, syscall.SIGKILL)
		t.Fatalf("the run (pid %d) outlived the runner", pid)
	}
	if entries, _ := os.ReadDir(r.root); len(entries) != 0 {
		t.Fatalf("the work root holds %d entries after the wipe", len(entries))
	}
}
