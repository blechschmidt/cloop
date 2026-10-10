package security

// Revoking a grant takes its credential back from every running workload that
// holds it — and only that grant's (Task 20403).
//
// Before, DELETE /api/grants/{id} stamped the grant and stopped: the material
// already inside a running workload stayed usable until its lease lapsed, and
// on a container or a Pod until the workload exited. This test revokes one
// grant of a two-grant lease through the hub's own route and looks at what
// each kind of holder still has:
//
//   - a host process (pkg/executor/localprocess) reading its lease directory;
//   - a container (pkg/executor/container) against a stand-in runtime CLI,
//     whose staged lease files are what the sandbox has bind-mounted;
//   - a Kubernetes Pod (pkg/executor/kubernetes) against a stand-in API
//     server, whose lease Secret the kubelet projects into the Pod;
//   - an edge agent (pkg/executor/agent) enrolled with the hub and holding
//     the files in its own lease directory.
//
// The revoked grant's material must be gone from each, and the other grant's
// must still be there: a revocation that took the kubeconfig because a PAT
// was revoked would be as wrong as one that left the PAT.
//
// The body runs in a child process. The agent hub, the executor registry and
// the hub's lease registry are process-wide, and the first hub a process builds
// binds the agent hub to its control plane; a fresh process is the only way to
// make that this test's, and to leave nothing of it behind for the rest of the
// suite.

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/internal/drivertest"
	"github.com/blechschmidt/cloop/internal/statedbtest"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/agent"
	"github.com/blechschmidt/cloop/pkg/executor/container"
	"github.com/blechschmidt/cloop/pkg/executor/kubernetes"
	"github.com/blechschmidt/cloop/pkg/executor/localprocess"
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

// grantRevocationChild marks the child process that runs the test body.
const grantRevocationChild = "CLOOP_SECURITY_GRANT_REVOCATION_CHILD"

// The two grants' canaries. Each holder is given one file per grant; the
// revoked grant's file must be gone afterwards and the other's intact.
const (
	revokedCanary = "revoked-grant-canary-2c41f0"
	keptCanary    = "kept-grant-canary-9be713"
)

func TestRevokingAGrantReachesEveryHolder(t *testing.T) {
	if os.Getenv(grantRevocationChild) != "1" {
		cmd := exec.Command(os.Args[0], "-test.run", "^TestRevokingAGrantReachesEveryHolder$", "-test.v",
			"-test.timeout", "4m")
		cmd.Env = append(os.Environ(), grantRevocationChild+"=1")
		out, err := cmd.CombinedOutput()
		if err != nil || !strings.Contains(string(out), "--- PASS: TestRevokingAGrantReachesEveryHolder") {
			t.Fatalf("the revocation scenario failed in its own process (%v):\n%s", err, out)
		}
		return
	}
	revokingAGrantReachesEveryHolder(t)
}

// grantBindings is one lease carrying the revoked and the kept grant, each
// with one credential file in dir.
func grantBindings(leaseID, revokedGrant, keptGrant, dir string) []executor.SecretBinding {
	return []executor.SecretBinding{
		{LeaseID: leaseID, GrantID: revokedGrant, SecretName: "deploy", Kind: "env",
			Files: []string{filepath.Join(dir, "revoked.cred")}, Dir: dir},
		{LeaseID: leaseID, GrantID: keptGrant, SecretName: "metrics", Kind: "env",
			Files: []string{filepath.Join(dir, "kept.cred")}, Dir: dir},
	}
}

// grantSecretFiles is the same two files, for a driver that places them
// itself.
func grantSecretFiles(leaseID, revokedGrant, keptGrant, dir string) []executor.SecretFile {
	return []executor.SecretFile{
		{LeaseID: leaseID, GrantID: revokedGrant, Dir: dir, Name: "revoked.cred", Mode: 0o600,
			Content: []byte(revokedCanary)},
		{LeaseID: leaseID, GrantID: keptGrant, Dir: dir, Name: "kept.cred", Mode: 0o600,
			Content: []byte(keptCanary)},
	}
}

func revokingAGrantReachesEveryHolder(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	t.Setenv(secretbroker.EnvPassphraseKey, "grant-revocation-security-passphrase")

	// ── the hub ──
	dir := t.TempDir()
	statedbtest.SeedDir(t, dir)
	if _, err := state.Init(dir, "grant revocation", 0); err != nil {
		t.Fatalf("state.Init: %v", err)
	}
	var (
		mu      sync.RWMutex
		handler http.Handler = http.NotFoundHandler()
	)
	hubSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.RLock()
		h := handler
		mu.RUnlock()
		h.ServeHTTP(w, r)
	}))
	defer hubSrv.Close()
	node, err := hubcluster.Join(hubcluster.Options{
		DBPath: state.DBPath(dir), AdvertiseURL: hubSrv.URL,
		Heartbeat: 40 * time.Millisecond, MemberTTL: 500 * time.Millisecond,
		BusPoll: 15 * time.Millisecond, BusFlush: 5 * time.Millisecond,
		Campaign: 30 * time.Millisecond, LeaderTTL: 600 * time.Millisecond, LeaderInterval: 60 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("join: %v", err)
	}
	node.Start(ctx)
	defer node.Close()
	srv := ui.NewInCluster(dir, 0, "", node)
	mu.Lock()
	handler = srv.Handler()
	mu.Unlock()

	// ── one lease, two grants, recorded as this hub process's ──
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store, err := secretstore.New(db)
	if err != nil {
		t.Fatal(err)
	}
	broker, err := secretbroker.New(store, secretbroker.WithAuditor(secretstore.NewAuditor(db)),
		secretbroker.WithLeaseRecords(node.ID()))
	if err != nil {
		t.Fatal(err)
	}
	project := filepath.Join(dir, "app")
	grantEnv := func(name, key string) secretbroker.Grant {
		sec, err := broker.Mint(ctx, secretbroker.MintRequest{Name: name, Kind: secretbroker.KindEnv,
			Payload: []byte(`{"` + key + `":"value-of-` + name + `"}`), Actor: "test"})
		if err != nil {
			t.Fatalf("mint %s: %v", name, err)
		}
		g, err := broker.Grant(ctx, secretbroker.GrantRequest{SecretRef: sec.ID,
			Subject:     secretbroker.Subject{Type: secretbroker.SubjectProject, Value: project},
			Constraints: secretbroker.Constraints{EnvKeys: []string{key}}, TTL: time.Hour, Actor: "test"})
		if err != nil {
			t.Fatalf("grant %s: %v", name, err)
		}
		return g
	}
	revoked := grantEnv("deploy", "DEPLOY_TOKEN")
	kept := grantEnv("metrics", "METRICS_TOKEN")
	lease, err := broker.LeaseFor(ctx, secretbroker.Requester{ExecutorID: "holders", ProjectID: project}, "test")
	if err != nil || len(lease.Materials) != 2 {
		t.Fatalf("LeaseFor = %+v, %v; want both grants", lease, err)
	}
	if rec, err := broker.LeaseRecordFor(lease.ID); err != nil || rec.Holder != node.ID() {
		t.Fatalf("the lease is not recorded for this hub process: %+v, %v", rec, err)
	}

	// ── a host process ──
	hostDir := filepath.Join(t.TempDir(), securewipe.LeaseDirPrefix+"host")
	if err := os.MkdirAll(hostDir, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{"revoked.cred": revokedCanary, "kept.cred": keptCanary} {
		if err := os.WriteFile(filepath.Join(hostDir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	host := localprocess.New("security-revoke-host")
	register(t, host)
	hostHandle, err := host.Start(ctx, executor.Spec{WorkDir: t.TempDir(), Argv: []string{"sleep", "60"},
		Secrets: grantBindings(lease.ID, revoked.ID, kept.ID, hostDir)})
	if err != nil {
		t.Fatalf("host start: %v", err)
	}
	stop(t, host, hostHandle.ID)

	// ── a container ──
	runtimeDir := t.TempDir()
	ctr, err := container.New(container.Options{
		ID: "security-revoke-ctr", Runtime: drivertest.ContainerRuntime(t, runtimeDir), Image: drivertest.Image,
	})
	if err != nil {
		t.Fatalf("container.New: %v", err)
	}
	register(t, ctr)
	const sandboxDir = "/run/cloop/" + securewipe.LeaseDirPrefix + "sandbox"
	beforeCtr := leaseFilesUnder(t, "/dev/shm", os.TempDir())
	ctrHandle, err := ctr.Start(ctx, executor.Spec{WorkDir: nonRootWorkDir(t), Argv: []string{"sleep", "60"},
		SecretFiles: grantSecretFiles(lease.ID, revoked.ID, kept.ID, sandboxDir),
		Secrets:     grantBindings(lease.ID, revoked.ID, kept.ID, sandboxDir)})
	if err != nil {
		t.Fatalf("container start: %v", err)
	}
	stop(t, ctr, ctrHandle.ID)
	stagedRevoked, stagedKept := waitNewStaged(t, beforeCtr)
	removeLeaseDirAtCleanup(t, stagedKept)

	// ── a Kubernetes Pod ──
	api := drivertest.NewKubeAPI(t)
	pods, err := kubernetes.New(kubernetes.Options{
		ID: "security-revoke-k8s", Namespace: "cloop", Image: drivertest.Image,
		Credentials: drivertest.KubeSource{Rest: api.REST()},
	})
	if err != nil {
		t.Fatalf("kubernetes.New: %v", err)
	}
	defer pods.Close()
	register(t, pods)
	podHandle, err := pods.Start(ctx, executor.Spec{WorkDir: t.TempDir(), Argv: []string{"sleep", "60"},
		SecretFiles: grantSecretFiles(lease.ID, revoked.ID, kept.ID, sandboxDir),
		Secrets:     grantBindings(lease.ID, revoked.ID, kept.ID, sandboxDir)})
	if err != nil {
		t.Fatalf("kubernetes start: %v", err)
	}
	leaseSecret := api.WaitSecret(t, "cloop-lease-")
	revokedKey, keptKey := api.KeyHolding(leaseSecret, revokedCanary), api.KeyHolding(leaseSecret, keptCanary)
	if revokedKey == "" || keptKey == "" {
		t.Fatalf("the Pod's lease Secret %s does not carry both files", leaseSecret)
	}

	// ── an edge agent, enrolled with this hub ──
	estore, err := executorstore.New(db)
	if err != nil {
		t.Fatal(err)
	}
	agentRoot := filepath.Join(t.TempDir(), "work")
	token, _, err := remote.Mint(estore, remote.MintOptions{Name: "security-revoke-edge", TTL: time.Minute,
		WorkDirRoot: agentRoot})
	if err != nil {
		t.Fatalf("mint agent token: %v", err)
	}
	a, err := agent.New(agent.Config{
		Server: "ws" + strings.TrimPrefix(hubSrv.URL, "http") + "/api/executors/connect", Token: token,
		CredentialPath: filepath.Join(t.TempDir(), "agent.json"), WorkDirRoot: agentRoot,
		Logf: func(string, ...any) {},
	})
	if err != nil {
		t.Fatalf("agent.New: %v", err)
	}
	agentDone := make(chan struct{})
	agentCtx, stopAgent := context.WithCancel(ctx)
	go func() {
		defer close(agentDone)
		_ = a.Run(agentCtx)
	}()
	defer func() {
		stopAgent()
		select {
		case <-agentDone:
		case <-time.After(20 * time.Second):
		}
	}()
	device := waitRemoteExecutor(t)
	if err := os.MkdirAll(filepath.Join(agentRoot, "app"), 0o755); err != nil {
		t.Fatal(err)
	}
	before := leaseFilesUnder(t, "/dev/shm", os.TempDir())
	deviceHandle, err := device.Start(ctx, executor.Spec{WorkDir: filepath.Join(agentRoot, "app"), Argv: []string{"sleep", "60"},
		SecretFiles: grantSecretFiles(lease.ID, revoked.ID, kept.ID, sandboxDir),
		Secrets:     grantBindings(lease.ID, revoked.ID, kept.ID, sandboxDir)})
	if err != nil {
		t.Fatalf("device start: %v", err)
	}
	agentRevoked, agentKept := waitNewStaged(t, before)
	removeLeaseDirAtCleanup(t, agentKept)
	// Stopped before the agent is: the kill has to reach a connected device.
	defer func() {
		sctx, scancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer scancel()
		_ = device.Signal(sctx, deviceHandle.ID, executor.SignalKill)
	}()

	// ── revoke one grant through the hub's own route ──
	req, _ := http.NewRequest(http.MethodDelete, hubSrv.URL+"/api/grants/"+revoked.ID, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("DELETE: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("DELETE /api/grants/%s = %d: %s", revoked.ID, resp.StatusCode, body)
	}
	var out struct {
		State  string                   `json:"state"`
		Local  []executor.RevokeOutcome `json:"local"`
		Remote []executor.RevokeOutcome `json:"remote"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decode: %v\n%s", err, body)
	}
	if out.State != string(executor.RevokeStateRevoked) {
		t.Errorf("state = %q, want revoked:\n%s", out.State, body)
	}
	reached := map[string]bool{}
	for _, o := range append(append([]executor.RevokeOutcome(nil), out.Local...), out.Remote...) {
		if o.GrantID != revoked.ID || o.State != executor.RevokeStateRevoked || o.Ack == nil || !o.Ack.Known {
			t.Errorf("holder outcome %+v: want the revoked grant taken back where it was held", o)
		}
		reached[o.ExecutorID] = true
	}
	for _, id := range []string{host.ID(), ctr.ID(), pods.ID(), device.ID()} {
		if !reached[id] {
			t.Errorf("holder %s was not reached; the response named %v", id, reached)
		}
	}

	// ── what each holder has left ──
	gone := func(what, path string) {
		t.Helper()
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Errorf("%s: the revoked grant's file %s survived", what, path)
		}
	}
	intact := func(what, path, want string) {
		t.Helper()
		if got, err := os.ReadFile(path); err != nil || string(got) != want {
			t.Errorf("%s: the other grant's file %s was taken too: %v / %q", what, path, err, got)
		}
	}
	gone("host process", filepath.Join(hostDir, "revoked.cred"))
	intact("host process", filepath.Join(hostDir, "kept.cred"), keptCanary)
	gone("container", stagedRevoked)
	intact("container", stagedKept, keptCanary)
	gone("edge agent", agentRevoked)
	intact("edge agent", agentKept, keptCanary)

	data := api.SecretData(leaseSecret)
	if v, ok := data[revokedKey]; !ok || len(v) != 0 {
		t.Errorf("Pod: lease Secret key %s = %q (present=%v), want present and emptied", revokedKey, v, ok)
	}
	if string(data[keptKey]) != keptCanary {
		t.Errorf("Pod: the other grant's key %s = %q, want it untouched", keptKey, data[keptKey])
	}
	if api.PodDeleted() {
		t.Error("Pod: deleted for a grant it held only as files")
	}
	if st, err := pods.Status(ctx, podHandle.ID); err != nil || st.State.Terminal() {
		t.Errorf("Pod: status %+v (%v), want still running", st, err)
	}
}

// stop kills a workload the test started, when the test ends.
func stop(t *testing.T, ex executor.Executor, handleID string) {
	t.Helper()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = ex.Signal(ctx, handleID, executor.SignalKill)
	})
}

// removeLeaseDirAtCleanup removes the lease directory holding path, should the
// workload's own teardown not have run by the time the test ends.
func removeLeaseDirAtCleanup(t *testing.T, path string) {
	t.Helper()
	dir := filepath.Dir(path)
	if !securewipe.IsLeaseDir(dir) {
		return
	}
	t.Cleanup(func() { _ = securewipe.Dir(dir) })
}

// register adds ex to the process registry the hub's revocation walks.
func register(t *testing.T, ex executor.Executor) {
	t.Helper()
	if err := executor.Register(ex); err != nil {
		t.Fatalf("register %s: %v", ex.ID(), err)
	}
	t.Cleanup(func() { executor.DefaultRegistry.Unregister(ex.ID()) })
}

// waitRemoteExecutor returns the agent's executor once it is connected and can
// honour a revocation.
func waitRemoteExecutor(t *testing.T) *remote.Executor {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		for _, ex := range executor.List() {
			if r, ok := ex.(*remote.Executor); ok && r.SupportsRevocation() {
				return r
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("the agent never connected")
	return nil
}

// leaseFilesUnder lists the files in lease directories under roots.
func leaseFilesUnder(t *testing.T, roots ...string) map[string]bool {
	t.Helper()
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

// waitNewStaged waits for a driver to place the canaries in a lease directory
// that was not there before.
func waitNewStaged(t *testing.T, before map[string]bool) (revokedPath, keptPath string) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		for path := range leaseFilesUnder(t, "/dev/shm", os.TempDir()) {
			if before[path] {
				continue
			}
			b, err := os.ReadFile(path)
			if err != nil {
				continue
			}
			switch string(b) {
			case revokedCanary:
				revokedPath = path
			case keptCanary:
				keptPath = path
			}
		}
		if revokedPath != "" && keptPath != "" {
			return revokedPath, keptPath
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("the lease files were never placed where the test can see them")
	return "", ""
}
