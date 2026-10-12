package cmd

// `cloop executor cordon|drain|revoke` take back what an edge device holds, as
// the dashboard's do (Task 20424). Before, the CLI wrote the scheduler row or
// the credential's revocation and stopped: a cordoned device kept every
// credential, and a revoked agent kept its session until it next reconnected —
// and the cordon could not even name a device, which no CLI process registers.
//
// The end-to-end tests run a real hub — Server.Run, so it reads the hub bus —
// and a real agent enrolled with it, in a child process: the agent hub, the
// executor registry and the hub's lease registry are process-wide, and the
// first hub a process builds binds the agent hub to its control plane. The
// commands are the package's own, run in the hub's directory as an operator
// would.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/agent"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
	"github.com/blechschmidt/cloop/pkg/executorstore"
	"github.com/blechschmidt/cloop/pkg/hubcluster"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/secretstore"
	"github.com/blechschmidt/cloop/pkg/securewipe"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
	"github.com/blechschmidt/cloop/pkg/ui"
)

// executorRevocationChild names the test a child process runs.
const executorRevocationChild = "CLOOP_CMD_EXECUTOR_REVOCATION_CHILD"

// revocationCanary is the device's copy of the lease's credential.
const revocationCanary = "cli-revocation-canary-6a1f02"

// inOwnProcess runs body in a child process of this test binary.
func inOwnProcess(t *testing.T, body func(t *testing.T)) {
	t.Helper()
	if os.Getenv(executorRevocationChild) == t.Name() {
		body(t)
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run", "^"+t.Name()+"$", "-test.v", "-test.timeout", "4m")
	cmd.Env = append(os.Environ(), executorRevocationChild+"="+t.Name())
	out, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(out), "--- PASS: "+t.Name()) {
		t.Fatalf("%s failed in its own process (%v):\n%s", t.Name(), err, out)
	}
}

// deviceHub is a hub serving dir, an agent enrolled with it, and a workload on
// the device holding a lease recorded as issued to it.
type deviceHub struct {
	dir       string
	db        *statedb.DB
	device    *remote.Executor
	agentDone chan error
	leaseID   string
	handleID  string
	// staged is the device's copy of the lease's file.
	staged string
}

func newDeviceHub(t *testing.T) *deviceHub {
	t.Helper()
	t.Setenv(secretbroker.EnvPassphraseKey, "cmd-executor-revocation-passphrase")
	w := &deviceHub{dir: hubDir(t)}
	if _, err := state.Init(w.dir, "executor revocation", 0); err != nil {
		t.Fatalf("state.Init: %v", err)
	}

	// ── the hub ──
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	base := fmt.Sprintf("127.0.0.1:%d", port)
	node, err := hubcluster.Join(hubcluster.Options{
		DBPath: state.DBPath(w.dir), AdvertiseURL: "http://" + base,
		Heartbeat: 40 * time.Millisecond, MemberTTL: 500 * time.Millisecond,
		BusPoll: 15 * time.Millisecond, BusFlush: 5 * time.Millisecond,
		Campaign: 30 * time.Millisecond, LeaderTTL: 600 * time.Millisecond, LeaderInterval: 60 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("join: %v", err)
	}
	srv := ui.NewInCluster(w.dir, port, "", node)
	ctx, stopHub := context.WithCancel(context.Background())
	hubDone := make(chan error, 1)
	go func() { hubDone <- srv.Run(ctx) }()
	t.Cleanup(func() {
		stopHub()
		select {
		case <-hubDone:
		case <-time.After(20 * time.Second):
			t.Error("the hub did not stop")
		}
		_ = node.Close()
	})
	waitUntil(t, 20*time.Second, "the hub to answer", func() bool {
		resp, err := http.Get("http://" + base + "/healthz")
		if err != nil {
			return false
		}
		_ = resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	})

	// ── an agent, enrolled with it ──
	w.db, err = statedb.Open(state.DBPath(w.dir))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = w.db.Close() })
	estore, err := executorstore.New(w.db)
	if err != nil {
		t.Fatal(err)
	}
	agentRoot := filepath.Join(t.TempDir(), "work")
	token, _, err := remote.Mint(estore, remote.MintOptions{Name: "edge-cli", TTL: time.Minute, WorkDirRoot: agentRoot})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	a, err := agent.New(agent.Config{
		Server: "ws://" + base + "/api/executors/connect", Token: token,
		CredentialPath: filepath.Join(t.TempDir(), "agent.json"), WorkDirRoot: agentRoot,
		Logf: func(string, ...any) {},
	})
	if err != nil {
		t.Fatalf("agent.New: %v", err)
	}
	agentCtx, stopAgent := context.WithCancel(context.Background())
	w.agentDone = make(chan error, 1)
	go func() { w.agentDone <- a.Run(agentCtx) }()
	t.Cleanup(stopAgent)
	waitUntil(t, 20*time.Second, "the agent to connect", func() bool {
		for _, ex := range executor.List() {
			if r, ok := ex.(*remote.Executor); ok && r.Connected() && r.SupportsRevocation() {
				w.device = r
				return true
			}
		}
		return false
	})
	waitUntil(t, 10*time.Second, "the hub to record that it holds the agent's connection", func() bool {
		o, found, err := node.Lookup("agent", w.device.ID())
		return err == nil && found && o.Self
	})

	// ── a lease issued to the device, recorded as this hub's ──
	store, err := secretstore.New(w.db)
	if err != nil {
		t.Fatal(err)
	}
	broker, err := secretbroker.New(store, secretbroker.WithAuditor(secretstore.NewAuditor(w.db)),
		secretbroker.WithLeaseRecords(node.ID()))
	if err != nil {
		t.Fatal(err)
	}
	project := filepath.Join(w.dir, "app")
	sec, err := broker.Mint(context.Background(), secretbroker.MintRequest{Name: "deploy", Kind: secretbroker.KindEnv,
		Payload: []byte(`{"DEPLOY_TOKEN":"value-of-deploy"}`), Actor: "test"})
	if err != nil {
		t.Fatalf("mint secret: %v", err)
	}
	grant, err := broker.Grant(context.Background(), secretbroker.GrantRequest{SecretRef: sec.ID,
		Subject:     secretbroker.Subject{Type: secretbroker.SubjectProject, Value: project},
		Constraints: secretbroker.Constraints{EnvKeys: []string{"DEPLOY_TOKEN"}}, TTL: time.Hour, Actor: "test"})
	if err != nil {
		t.Fatalf("grant: %v", err)
	}
	lease, err := broker.LeaseFor(context.Background(),
		secretbroker.Requester{ExecutorID: w.device.ID(), ProjectID: project}, "test")
	if err != nil {
		t.Fatalf("LeaseFor: %v", err)
	}
	w.leaseID = lease.ID

	// ── the device holds the lease's file ──
	const sandboxDir = "/run/cloop/" + securewipe.LeaseDirPrefix + "sandbox"
	if err := os.MkdirAll(filepath.Join(agentRoot, "app"), 0o755); err != nil {
		t.Fatal(err)
	}
	before := leaseFilesIn("/dev/shm", os.TempDir())
	h, err := w.device.Start(context.Background(), executor.Spec{
		WorkDir: filepath.Join(agentRoot, "app"), Argv: []string{"sleep", "60"},
		SecretFiles: []executor.SecretFile{{LeaseID: lease.ID, GrantID: grant.ID, Dir: sandboxDir,
			Name: "deploy.cred", Mode: 0o600, Content: []byte(revocationCanary)}},
		Secrets: []executor.SecretBinding{{LeaseID: lease.ID, GrantID: grant.ID, SecretName: "deploy", Kind: "env",
			Files: []string{filepath.Join(sandboxDir, "deploy.cred")}, Dir: sandboxDir}},
	})
	if err != nil {
		t.Fatalf("device start: %v", err)
	}
	w.handleID = h.ID
	t.Cleanup(func() {
		sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = w.device.Signal(sctx, h.ID, executor.SignalKill)
		if dir := filepath.Dir(w.staged); securewipe.IsLeaseDir(dir) {
			_ = securewipe.Dir(dir)
		}
	})
	waitUntil(t, 20*time.Second, "the device to place the lease's file", func() bool {
		for path := range leaseFilesIn("/dev/shm", os.TempDir()) {
			if before[path] {
				continue
			}
			if b, err := os.ReadFile(path); err == nil && string(b) == revocationCanary {
				w.staged = path
				return true
			}
		}
		return false
	})
	t.Chdir(w.dir)
	return w
}

// leaseFilesIn lists the files in lease directories under roots.
func leaseFilesIn(roots ...string) map[string]bool {
	out := map[string]bool{}
	for _, root := range roots {
		entries, err := os.ReadDir(root)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if !e.IsDir() || !strings.HasPrefix(e.Name(), securewipe.LeaseDirPrefix) {
				continue
			}
			files, _ := os.ReadDir(filepath.Join(root, e.Name()))
			for _, f := range files {
				out[filepath.Join(root, e.Name(), f.Name())] = true
			}
		}
	}
	return out
}

// waitUntil polls cond until it holds or limit passes.
func waitUntil(t *testing.T, limit time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(limit)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out after %s waiting for %s", limit, what)
}

// runExecutorCommand runs one of the executor commands through a fresh command
// carrying its RunE and flags, and returns what it printed.
func runExecutorCommand(t *testing.T, src *cobra.Command, args ...string) string {
	t.Helper()
	out, err := captureStdout(t, func() error {
		c := &cobra.Command{Use: src.Use, Args: src.Args, RunE: src.RunE, SilenceErrors: true, SilenceUsage: true}
		c.Flags().AddFlagSet(src.Flags())
		c.SetOut(io.Discard)
		c.SetErr(io.Discard)
		c.SetArgs(args)
		c.SetContext(context.Background())
		return c.Execute()
	})
	if err != nil {
		t.Fatalf("%s %v: %v\n%s", src.Use, args, err, out)
	}
	return out
}

// auditRows returns the trail's rows of action naming entity.
func auditRows(t *testing.T, db *statedb.DB, action auditaction.Action, entity string) []statedb.AuditEvent {
	t.Helper()
	rows, _, err := db.ListAuditEvents(statedb.AuditFilter{EventType: string(action), Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	var out []statedb.AuditEvent
	for _, r := range rows {
		if r.EntityID == entity || strings.Contains(r.Payload, entity) {
			out = append(out, r)
		}
	}
	return out
}

// TestCLICordonTakesTheDevicesLeaseBack: `cloop executor cordon <device>` at
// the terminal takes the device's lease back through the hub member holding
// its connection — the device's copy of the credential file is gone — and the
// workload it is running carries on, as a cordon promises.
func TestCLICordonTakesTheDevicesLeaseBack(t *testing.T) {
	inOwnProcess(t, func(t *testing.T) {
		w := newDeviceHub(t)
		id := w.device.ID()

		out := runExecutorCommand(t, executorCordonCmd, "--reason", "device stolen", id)
		for _, want := range []string{
			"holds " + id + "'s connection: took back 1 lease(s)",
			"lease " + w.leaseID + ": revoked",
			"Every recorded lease was taken back.",
		} {
			if !strings.Contains(out, want) {
				t.Errorf("the cordon's report does not say %q:\n%s", want, out)
			}
		}
		if _, err := os.Stat(w.staged); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("the device still holds the lease's file %s after the cordon (%v)", w.staged, err)
		}
		st, err := w.device.Status(context.Background(), w.handleID)
		if err != nil || st.State.Terminal() {
			t.Errorf("the cordon stopped the device's workload: %+v, %v", st, err)
		}

		// The trail the dashboard's cordon leaves: the cordon, by the operator
		// at the terminal, and the lease's revocation in their name.
		cordons := auditRows(t, w.db, auditaction.ActionExecutorCordon, id)
		if len(cordons) != 1 || !strings.HasPrefix(cordons[0].Actor, "cli:") ||
			!strings.Contains(cordons[0].Payload, "device stolen") {
			t.Errorf("executor.cordon rows = %+v, want one by the operator naming the reason", cordons)
		}
		sent := auditRows(t, w.db, auditaction.ActionLeaseRevokeSent, w.leaseID)
		if len(sent) != 1 || !strings.HasPrefix(sent[0].Actor, "cli:") ||
			!strings.Contains(sent[0].Payload, "executor cordoned: device stolen") {
			t.Errorf("lease.revoke_sent rows = %+v, want one by the operator, for the cordon", sent)
		}
		revs, err := w.db.LeaseRevocations(w.leaseID)
		if err != nil || len(revs) != 1 || revs[0].Pending() {
			t.Errorf("the lease's revocation on record = %+v, %v; want it enforced", revs, err)
		}
	})
}

// TestCLIRevokeDropsTheAgentWithinABound: `cloop executor revoke <agent>`
// drops the agent's live connection at once — its lease taken back first,
// while the link is up — rather than at its next reconnect, and the agent
// stops trying to come back.
func TestCLIRevokeDropsTheAgentWithinABound(t *testing.T) {
	inOwnProcess(t, func(t *testing.T) {
		w := newDeviceHub(t)
		id := w.device.ID()

		start := time.Now()
		out := runExecutorCommand(t, executorRevokeCmd, id)
		const bound = 10 * time.Second
		select {
		case err := <-w.agentDone:
			if err == nil || !strings.Contains(err.Error(), "declined reconnection") {
				t.Errorf("the agent stopped with %v, want the hub's refusal to have it back", err)
			}
			if took := time.Since(start); took > bound {
				t.Errorf("the agent was dropped %s after the revocation, want within %s", took, bound)
			}
		case <-time.After(bound):
			t.Fatalf("the agent was still connected %s after `cloop executor revoke`:\n%s", bound, out)
		}
		for _, want := range []string{"Revoked agent credential " + id, "took back 1 lease(s), and dropped the agent"} {
			if !strings.Contains(out, want) {
				t.Errorf("the revocation's report does not say %q:\n%s", want, out)
			}
		}
		if _, err := os.Stat(w.staged); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("the device still holds the lease's file %s after its agent was revoked (%v)", w.staged, err)
		}
		if _, err := executor.Get(id); err == nil {
			t.Error("the revoked agent is still in the hub's registry")
		}
		if rows := auditRows(t, w.db, auditaction.ActionExecutorRevoke, id); len(rows) != 1 ||
			!strings.HasPrefix(rows[0].Actor, "cli:") {
			t.Errorf("executor.revoke rows = %+v, want one by the operator", rows)
		}
	})
}

// TestCLICordonWithNoHubServingSaysSoAndRecordsTheRevocation: with no hub
// serving the control plane the device's leases are recorded revoked — the
// next hub to start takes them back — and the command says so rather than
// claiming a take-back nobody made.
func TestCLICordonWithNoHubServingSaysSoAndRecordsTheRevocation(t *testing.T) {
	dir := hubDir(t)
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	estore, err := executorstore.New(db)
	if err != nil {
		t.Fatal(err)
	}
	// An enrolled device and a lease recorded as issued to it, by a hub that
	// has since stopped.
	if err := estore.PutAgent(remote.AgentRecord{AgentID: "edge-offline", Name: "edge-offline",
		SecretHash: strings.Repeat("0", 64), CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := db.UpsertExecutor(statedb.ExecutorRow{ID: "edge-offline", Kind: executor.KindRemoteAgent, Name: "edge-offline"}); err != nil {
		t.Fatal(err)
	}
	if err := db.PutSecretLease(statedb.SecretLeaseRow{LeaseID: "lease-offline", Holder: "hub_gone",
		ExecutorID: "edge-offline", ProjectID: "/srv/app", Record: `{}`, IssuedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
	t.Chdir(dir)

	out := runExecutorCommand(t, executorCordonCmd, "edge-offline")
	for _, want := range []string{"cordoned", "1 lease(s) recorded as issued to edge-offline are recorded revoked",
		"No hub is serving this control plane", "the next hub to start"} {
		if !strings.Contains(out, want) {
			t.Errorf("output does not say %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "taken back.") {
		t.Errorf("the output claims a take-back nobody made:\n%s", out)
	}
	db, err = statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	revs, err := db.LeaseRevocations("lease-offline")
	if err != nil || len(revs) != 1 || !revs[0].Pending() || revs[0].Holder != "hub_gone" ||
		!strings.Contains(revs[0].Reason, "executor cordoned") {
		t.Fatalf("the lease's revocation on record = %+v, %v; want it pending for the next hub", revs, err)
	}
}
