package kubecontroller_test

// pool_test.go proves an executor pool end to end on a real cluster (Task
// 20487): the executor controller the Helm chart installs, its ephemeral
// runner Pods and their volumes, against a real hub.
//
// The hub runs here, on this host, as `cloop ui` over TLS on the address the
// cluster's node reaches it at — the docker bridge of a kind or
// k3s-in-docker node — and is protected by an admin token. It serves three
// projects, web, api and ops, each bound to one executor pool and granted a
// stand-in Claude credential. The chart installs the controller (two
// replicas, leader-elected, in a namespace that enforces the restricted Pod
// Security Standard) and an ExecutorPool from its values: minRunners 0,
// maxRunners 2, runner volumes on. One image is everything in the cluster:
// cloop under test, git, and the stand-in claude that runs the probe a task
// carries (probe.sh).
//
// The phases, each a subtest, in order:
//
//  1. scale-from-zero: a queued run scales the pool from 0 to 1; the runner
//     enrolls with its single-use token, runs the task, and its result
//     reaches the hub's plan.
//  2. scale-to-min: the runner Pod and its Secret are gone, and the pool is
//     back at minRunners.
//  3. persistence: web's second task, on a runner holding web's volume,
//     finds the file and the git commit the first left.
//  4. isolation: api's and ops's tasks find nothing another project left —
//     api on a fresh volume, ops on one wiped before it started.
//  5. reused-token and expired-token: a runner token already redeemed, and
//     one past its expiry, are refused.
//  6. runner-killed: a runner Pod is killed mid-run, twice under the same
//     task; the hub settles each loss through the failover path, and the
//     second quarantines the task as a node killer.
//  7. controller-killed: the controller's leader is killed while a run is in
//     flight; no runner is started twice or stopped, and the new leader
//     finishes the job.
//  8. credential-revoked: revoking the controller's credential kills the
//     live run and takes its leases back, refuses a runner token it minted,
//     and stops the controller starting runners.
//  9. no-credential-on-any-volume: every runner volume the pool kept is
//     released — a killed runner's too — and, read from a Pod of its own,
//     holds no credential.
//
// Opt in with CLOOP_KUBECONTROLLER_E2E_KUBECONFIG (cluster-admin on a
// throwaway cluster); see README.md for the rest.

import (
	"context"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/internal/hometest"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
)

func TestMain(m *testing.M) {
	realHome = os.Getenv("HOME")
	os.Exit(hometest.Isolate(m))
}

// Environment the suite reads. Only the first is required: it opts in.
const (
	// kubeconfigEnv names a kubeconfig with cluster-admin on a throwaway
	// cluster.
	kubeconfigEnv = "CLOOP_KUBECONTROLLER_E2E_KUBECONFIG"
	// kindEnv names the kind cluster to load the image into.
	kindEnv = "CLOOP_KUBECONTROLLER_E2E_KIND_CLUSTER"
	// importEnv is a shell command that reads an image tarball (docker save)
	// on stdin and loads it onto the nodes, for a cluster that is not kind:
	// "docker exec -i k3s ctr images import -".
	importEnv = "CLOOP_KUBECONTROLLER_E2E_IMAGE_IMPORT"
	// binEnv supplies a static cloop; unset, one is built.
	binEnv = "CLOOP_KUBECONTROLLER_E2E_CLOOP_BIN"
	// hubAddrEnv is the address the hub listens on, which the cluster's Pods
	// must reach; unset, this host's address on the node's network.
	hubAddrEnv = "CLOOP_KUBECONTROLLER_E2E_HUB_ADDR"
	// storageClassEnv names the runner volumes' StorageClass; unset, the
	// cluster's default.
	storageClassEnv = "CLOOP_KUBECONTROLLER_E2E_STORAGE_CLASS"
	// keepEnv leaves the namespace and the hub's directory behind.
	keepEnv = "CLOOP_KUBECONTROLLER_E2E_KEEP"
)

const (
	// alpineDigest is alpine:3.20 by digest, the base tests/kube pins.
	alpineDigest = "alpine@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc"
	imageRepo    = "cloop-kubecontroller-e2e"

	release  = "ctl"
	fullname = "ctl-cloop-executor-controller"
	// poolName is the ExecutorPool the chart creates from its values.
	poolName = fullname

	// storageRoot is where a runner's volume is mounted
	// (pkg/kubecontroller/persistence.go).
	storageRoot = "/var/lib/cloop-runner/storage"

	runnerPods    = "app.kubernetes.io/managed-by=cloop-executor-controller,app.kubernetes.io/name=cloop-runner"
	runnerSecrets = "app.kubernetes.io/managed-by=cloop-executor-controller,app.kubernetes.io/name=cloop-runner-config"
	controllerSel = "app.kubernetes.io/name=cloop-executor-controller,app.kubernetes.io/instance=" + release
)

//go:embed probe.sh
var probeScript string

// e2e is the world the phases share.
type e2e struct {
	t    *testing.T
	root *testing.T
	ctx  context.Context
	x    tool
	hub  hubClient

	stamp, ns, image   string
	work, hubDir       string
	hubLog             string
	cloop              string
	cliEnv             []string
	certPEM            []byte
	certPath           string
	adminToken         string
	secretKey          string
	harnessToken       string
	poolID, hubPool    string
	credID, credential string

	projects map[string]*project
	// seen is every runner Pod the test has seen, by name.
	seen map[string]bool
	// claims is every runner volume a runner was seen mounting.
	claims map[string]bool
	// enrollments is each runner Pod's enrollment ID, from its Secret.
	enrollments map[string]string
	// tokens are runner tokens the test saw, for the volume scan.
	tokens []string
	// firstBundle is the first runner's configuration, kept for the
	// reused-token phase.
	firstBundle []byte
	// firstRunner is the first runner's enrollment ID.
	firstRunner string
}

// project is one of the hub's projects.
type project struct {
	name   string
	dir    string
	idx    int
	mark   string
	partA  string
	partB  string
	commit string
	// workdir is the project's directory beneath the runners' workspace
	// root, as the hub names it (executor.DeviceWorkDir).
	workdir string
	// tenant is what the hub calls the project's data (the runner records'
	// project).
	tenant string
}

func TestExecutorPoolOnARealCluster(t *testing.T) {
	kubeconfig := os.Getenv(kubeconfigEnv)
	if kubeconfig == "" {
		t.Skipf("set %s to a throwaway cluster's kubeconfig to run this", kubeconfigEnv)
	}
	for _, bin := range []string{"kubectl", "helm", "docker"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Fatalf("%s is not on PATH: %v", bin, err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 28*time.Minute)
	defer cancel()

	w := setUp(ctx, t, kubeconfig)
	for _, ph := range []struct {
		name string
		run  func()
	}{
		{"scale-from-zero", w.scaleFromZero},
		{"scale-to-min", w.scaleToMin},
		{"persistence", w.persistence},
		{"isolation", w.isolation},
		{"reused-token", w.reusedToken},
		{"expired-token", w.expiredToken},
		{"runner-killed", w.runnerKilled},
		{"controller-killed", w.controllerKilled},
		{"credential-revoked", w.credentialRevoked},
		{"no-credential-on-any-volume", w.noCredentialOnAnyVolume},
	} {
		began := time.Now()
		ok := t.Run(ph.name, func(t *testing.T) {
			w.use(t)
			defer w.use(w.root)
			ph.run()
		})
		t.Logf("phase %s: %s after %s", ph.name, map[bool]string{true: "passed", false: "FAILED"}[ok],
			fmtDuration(time.Since(began)))
		if !ok {
			// Every phase builds on the ones before it.
			t.FailNow()
		}
	}
}

// use points the world's helpers at t.
func (w *e2e) use(t *testing.T) {
	w.t = t
	w.x.t = t
	w.hub.t = t
}

// ── set-up ─────────────────────────────────────────────────────────────────

func setUp(ctx context.Context, t *testing.T, kubeconfig string) *e2e {
	t.Helper()
	w := &e2e{t: t, root: t, ctx: ctx, x: tool{t: t, kubeconfig: kubeconfig}, projects: map[string]*project{},
		seen: map[string]bool{}, claims: map[string]bool{}, enrollments: map[string]string{}}
	w.stamp = randomAlnum(t, 6)
	keep := os.Getenv(keepEnv) != ""
	work, err := os.MkdirTemp("", "cloop-kubecontroller-e2e-")
	if err != nil {
		t.Fatal(err)
	}
	// The hub keys a run by its project's resolved path.
	if r, err := filepath.EvalSymlinks(work); err == nil {
		work = r
	}
	w.work = work
	t.Cleanup(func() {
		if keep {
			t.Logf("kept %s", work)
			return
		}
		_ = os.RemoveAll(work)
	})
	root := repoRoot(t)

	// ── the image ──────────────────────────────────────────────────────────
	w.cloop = os.Getenv(binEnv)
	if w.cloop == "" {
		w.cloop = filepath.Join(work, "bin", "cloop")
		if err := os.MkdirAll(filepath.Dir(w.cloop), 0o755); err != nil {
			t.Fatal(err)
		}
		goBuild(ctx, t, root, w.cloop)
	}
	w.image = imageRepo + ":" + w.stamp
	buildCtx := filepath.Join(work, "image")
	if err := os.MkdirAll(buildCtx, 0o755); err != nil {
		t.Fatal(err)
	}
	copyFile(t, w.cloop, filepath.Join(buildCtx, "cloop"))
	copyFile(t, filepath.Join(root, "scripts", "e2e", "gitproxy", "claude"), filepath.Join(buildCtx, "claude"))
	copyFile(t, filepath.Join(root, "tests", "kubecontroller", "runner.Dockerfile"), filepath.Join(buildCtx, "Dockerfile"))
	w.x.run(ctx, nil, false, "docker", "build", "--build-arg", "BASE="+alpineDigest, "-t", w.image, buildCtx)
	switch cluster, importCmd := os.Getenv(kindEnv), os.Getenv(importEnv); {
	case cluster != "":
		w.x.run(ctx, nil, false, "kind", "load", "docker-image", w.image, "--name", cluster)
	case importCmd != "":
		tarball, err := exec.CommandContext(ctx, "docker", "save", w.image).Output()
		if err != nil {
			t.Fatalf("docker save %s: %v", w.image, err)
		}
		w.x.run(ctx, tarball, false, "sh", "-c", importCmd)
	default:
		t.Fatalf("set %s or %s: the image must reach the cluster's nodes", kindEnv, importEnv)
	}
	// The nodes have their own copy; the daemon's is disk nobody needs.
	w.x.run(ctx, nil, true, "docker", "rmi", w.image)

	// ── the hub ────────────────────────────────────────────────────────────
	nodeIP := w.x.out(ctx, "get", "nodes", "-o", `jsonpath={.items[0].status.addresses[?(@.type=="InternalIP")].address}`)
	addr := envOr(hubAddrEnv, hostAddressFor(nodeIP))
	if addr == "" {
		t.Fatalf("no address of this host is on the network of the cluster's node %s; set %s", nodeIP, hubAddrEnv)
	}
	port := freePort(t, addr)
	w.hubDir = filepath.Join(work, "hub")
	home := filepath.Join(work, "home")
	for _, d := range []string{w.hubDir, home} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	w.adminToken = "e2e-admin-" + randomAlnum(t, 32)
	w.secretKey = "e2e-key-" + randomAlnum(t, 40)
	w.cliEnv = processEnv("HOME="+home, "XDG_CONFIG_HOME="+filepath.Join(home, ".config"), "NO_COLOR=1",
		"CLOOP_SECRET_KEY="+w.secretKey, "KUBECONFIG=/nonexistent")
	runIn(ctx, t, w.hubDir, w.cliEnv, w.cloop, "init", "--provider", "mock", "--skip-clarify",
		"executor pool end-to-end control plane")
	// The stand-in claude ignores it, but the hub dispatches a claudecode run
	// to a runner only with a Claude credential granted to the project (Task
	// 20379). Made of parts, so no literal here has a shape secret scanners
	// refuse a push over.
	w.harnessToken = "sk-" + "ant-oat01-" + randomAlnum(t, 48) + "-e2e"
	runIn(ctx, t, w.hubDir, w.cliEnv, w.cloop, "secret", "mint", "e2e-claude", "--kind", "env",
		"--value", `{"CLAUDE_CODE_OAUTH_TOKEN":"`+w.harnessToken+`"}`)
	var dirs []string
	for _, name := range []string{"web", "api", "ops"} {
		p := &project{name: name, dir: filepath.Join(work, name), mark: name + "-marker-" + w.stamp,
			partA: randomAlnum(t, 16), partB: randomAlnum(t, 16)}
		if err := os.MkdirAll(p.dir, 0o755); err != nil {
			t.Fatal(err)
		}
		runIn(ctx, t, p.dir, w.cliEnv, w.cloop, "init", "--provider", "claudecode", "--skip-clarify",
			"executor pool end-to-end project "+name)
		runIn(ctx, t, w.hubDir, w.cliEnv, w.cloop, "secret", "grant", "e2e-claude", "--to", "project:"+p.dir,
			"--env-keys", "CLAUDE_CODE_OAUTH_TOKEN", "--ttl", "2h")
		p.workdir = executor.DeviceWorkDir(p.dir)
		w.projects[name] = p
		dirs = append(dirs, p.dir)
	}
	tlsDir := filepath.Join(w.hubDir, ".cloop", "tls")
	runIn(ctx, t, w.hubDir, w.cliEnv, w.cloop, "hub", "tls-init", "--dir", tlsDir, "--host", addr)
	w.certPath = filepath.Join(tlsDir, "cert.pem")
	if w.certPEM, err = os.ReadFile(w.certPath); err != nil {
		t.Fatal(err)
	}
	w.hubLog = filepath.Join(work, "hub.log")
	w.startHub(addr, port, filepath.Join(tlsDir, "key.pem"), dirs)
	hubURL := fmt.Sprintf("https://%s:%d", addr, port)
	w.hub = newHubClient(t, hubURL, w.adminToken, w.certPEM)
	waitFor(t, "the hub to answer at "+hubURL, time.Minute, func() (bool, string) {
		code, body, err := w.hub.get("/healthz")
		if err != nil {
			return false, err.Error()
		}
		return code == 200, fmt.Sprintf("%d %s", code, tail(body, 1))
	})
	t.Logf("hub at %s (the cluster's node is %s)", hubURL, nodeIP)

	// The pool on the hub, its controller credential, and the projects bound
	// to it. The hub's max_runners matches the ExecutorPool's, so a runner
	// the controller started twice would fit — and be seen.
	var created struct {
		Pool struct {
			ID string `json:"id"`
		} `json:"pool"`
	}
	w.hubPool = "e2e-" + w.stamp
	w.hub.must("POST", "/api/executor-pools", map[string]any{"name": w.hubPool, "max_runners": 2}, &created)
	w.poolID = created.Pool.ID
	var minted struct {
		Token      string `json:"token"`
		Credential struct {
			ID string `json:"id"`
		} `json:"credential"`
	}
	w.hub.must("POST", "/api/executor-pools/"+w.poolID+"/credentials", map[string]any{}, &minted)
	w.credential, w.credID = minted.Token, minted.Credential.ID
	if !strings.HasPrefix(w.credential, "cloop_pool1_") || w.credID == "" {
		t.Fatalf("the hub minted a controller credential of the wrong shape (id %q)", w.credID)
	}
	for _, p := range w.projects {
		p.idx = w.projectIndex(p.dir)
		w.hub.must("POST", fmt.Sprintf("/api/projects/%d/executor", p.idx), map[string]any{"executor_id": "pool:" + w.poolID}, nil)
	}

	// ── the cluster ────────────────────────────────────────────────────────
	w.ns = "cloop-xctl-" + w.stamp
	w.x.apply(ctx, map[string]any{"apiVersion": "v1", "kind": "Namespace", "metadata": map[string]any{
		"name": w.ns, "labels": map[string]string{"pod-security.kubernetes.io/enforce": "restricted",
			"pod-security.kubernetes.io/enforce-version": "latest"}}})
	t.Cleanup(func() {
		if keep {
			t.Logf("kept namespace %s", w.ns)
			return
		}
		cctx, ccancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer ccancel()
		_, _ = w.x.run(cctx, nil, true, "helm", "uninstall", release, "--namespace", w.ns, "--wait", "--timeout", "2m")
		_, _ = w.x.run(cctx, nil, true, "kubectl", "delete", "namespace", w.ns, "--wait=false")
	})
	waitFor(t, "the namespace's default ServiceAccount", time.Minute, func() (bool, string) {
		_, err := w.x.may(ctx, "-n", w.ns, "get", "serviceaccount", "default")
		return err == nil, ""
	})
	w.x.apply(ctx, map[string]any{"apiVersion": "v1", "kind": "Secret", "type": "Opaque",
		"metadata":   map[string]any{"name": "pool-credential", "namespace": w.ns},
		"stringData": map[string]string{"credential": w.credential}})
	sets := []string{
		"image.repository=" + imageRepo, "image.tag=" + w.stamp, "image.pullPolicy=Never",
		"controller.resync=30s",
		"pool.create=true", "pool.hubURL=" + hubURL, "pool.credential.existingSecret=pool-credential",
		"pool.minRunners=0", "pool.maxRunners=2", "pool.scaleDownDelay=30s",
		"pool.template.image=" + w.image, "pool.template.imagePullPolicy=Never",
		"pool.persistence.enabled=true", "pool.persistence.size=1Gi", "pool.persistence.minFree=1Mi",
	}
	if sc := os.Getenv(storageClassEnv); sc != "" {
		sets = append(sets, "pool.persistence.storageClassName="+sc)
	}
	args := []string{"install", release, filepath.Join(root, "deploy", "helm", "cloop-executor-controller"),
		"--namespace", w.ns, "--set-file", "pool.hubCABundle=" + w.certPath, "--wait", "--timeout", "5m"}
	for _, s := range sets {
		args = append(args, "--set", s)
	}
	w.x.run(ctx, nil, false, "helm", args...)
	w.waitPool("the chart's pool served by the leader", 3*time.Minute, func(st poolStatus) (bool, string) {
		return st.ready() == "True" && st.Status.PoolID == w.poolID, st.describe()
	})
	t.Logf("the controller serves hub pool %s from ExecutorPool %s/%s", w.poolID, w.ns, poolName)
	return w
}

// startHub starts `cloop ui` and stops its process group when the test ends.
func (w *e2e) startHub(addr string, port int, keyPath string, projects []string) {
	t := w.root
	logFile, err := os.Create(w.hubLog)
	if err != nil {
		t.Fatal(err)
	}
	args := []string{"ui", "--listen", addr, "--port", strconv.Itoa(port), "--no-browser",
		"--tls-cert", w.certPath, "--tls-key", keyPath}
	for _, p := range projects {
		args = append(args, "--projects", p)
	}
	cmd := exec.Command(w.cloop, args...)
	cmd.Dir = w.hubDir
	cmd.Env = append(append([]string(nil), w.cliEnv...), "CLOOP_UI_TOKEN="+w.adminToken)
	cmd.Stdout, cmd.Stderr = logFile, logFile
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start the hub: %v", err)
	}
	t.Cleanup(func() {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
		done := make(chan struct{})
		go func() { _, _ = cmd.Process.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(20 * time.Second):
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		}
		_ = logFile.Close()
		if t.Failed() {
			if b, err := os.ReadFile(w.hubLog); err == nil {
				t.Logf("── hub log ──\n%s", tail(string(b), 150))
			}
			w.dumpCluster()
		}
	})
}

// dumpCluster logs what the namespace holds, for a failed run.
func (w *e2e) dumpCluster() {
	if w.ns == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	t := w.root
	out, _ := w.x.run(ctx, nil, true, "kubectl", "-n", w.ns, "get", "pods,pvc,secrets,leases,executorpools", "-o", "wide")
	t.Logf("── namespace %s ──\n%s", w.ns, out)
	out, _ = w.x.run(ctx, nil, true, "kubectl", "-n", w.ns, "get", "events", "--sort-by=.lastTimestamp")
	t.Logf("── events ──\n%s", tail(out, 60))
	out, _ = w.x.run(ctx, nil, true, "kubectl", "-n", w.ns, "logs", "-l", controllerSel, "--tail=80", "--prefix")
	t.Logf("── controller logs ──\n%s", out)
}

// ── phases ─────────────────────────────────────────────────────────────────

// scaleFromZero is phase 1: a queued run scales the pool from 0 to 1, the
// runner enrolls with a single-use token and runs the task, and its result
// reaches the hub's plan.
func (w *e2e) scaleFromZero() {
	t := w.t
	if pods := w.listRunners(); len(pods) != 0 {
		t.Fatalf("runner Pods before anything was queued: %v", names(pods))
	}
	if st := w.poolStatusNow(); st.Status.Runners != 0 || st.Status.DesiredRunners != 0 {
		t.Fatalf("the pool before anything was queued: %s", st.describe())
	}
	web := w.projects["web"]
	id := w.addTask(web, "Leave a file and a commit on the volume", "seed", nil, "")
	w.startRun(web)
	pod := w.awaitRunner("web's first runner")
	// Its configuration, while its Secret exists: the token is used again
	// below, where it must be refused.
	secret := w.runnerSecret(pod.Name)
	if secret.owner != "Pod/"+pod.Name || !secret.immutable {
		t.Errorf("runner Secret %s: owner %q, immutable %v; want owned by its Pod and immutable", pod.Name,
			secret.owner, secret.immutable)
	}
	w.firstBundle, w.firstRunner = secret.bundle, secret.enrollmentID
	w.tokens = append(w.tokens, bundleToken(t, secret.bundle))
	t.Logf("runner %s (enrollment %s) started for web's run", pod.Name, secret.enrollmentID)
	w.waitPool("the pool to count its runner", time.Minute, func(st poolStatus) (bool, string) {
		return st.Status.DesiredRunners == 1 && st.Status.Runners == 1, st.describe()
	})

	out := w.awaitTask(web, id, "done")
	res := parseResults(out)
	expectPass(t, "web's first run", res, "ENV", "S1")
	sha, ok := strings.CutPrefix(res["S1"].detail, "commit=")
	if !ok || len(sha) != 40 {
		t.Fatalf("the seed run reported no commit: %q", res["S1"].detail)
	}
	web.commit = sha
	if want := storageRoot + "/workspace/" + web.workdir; !strings.Contains(res["ENV"].detail, "pwd="+want+" ") {
		t.Errorf("web's run worked in %q, want %s on its runner's volume", res["ENV"].detail, want)
	}
	task := w.task(web, id)
	if task.ExecutorPool != w.hubPool || task.ExecutorRunner == "" {
		t.Errorf("task %d ran on pool %q, runner %q (executor %s); want pool %s", id, task.ExecutorPool,
			task.ExecutorRunner, task.ExecutorID, w.hubPool)
	}
	if !strings.Contains(task.Result, "RESULT S1 PASS") {
		t.Errorf("task %d's result on the hub does not carry the run's output: %q", id, tail(task.Result, 5))
	}

	// The hub's record of the runner: minted by the controller's credential,
	// enrolled once, given web's run, retired with it.
	var r poolRunner
	waitFor(t, "the hub to retire the runner after its run", time.Minute, func() (bool, string) {
		r = w.runner(secret.enrollmentID)
		return r.State == "retired", fmt.Sprintf("%+v", r)
	})
	if r.EnrolledAt.IsZero() || r.CredentialID != w.credID || r.Project == "" || !strings.Contains(r.RetireReason, "settled") {
		t.Errorf("the hub's record of the first runner: %+v", r)
	}
	web.tenant = r.Project
	if n := len(w.poolDetail().Runners); n != 1 {
		t.Errorf("the hub minted %d runners for one queued run", n)
	}
}

// scaleToMin is phase 2: after the run the runner Pod and its Secret are
// gone, and the pool is back at minRunners, with web's volume kept.
func (w *e2e) scaleToMin() {
	t := w.t
	w.awaitNoRunners("the first runner's Pod and Secret to go")
	w.waitPool("the pool back at minRunners", time.Minute, func(st poolStatus) (bool, string) {
		return st.Status.Runners == 0 && st.Status.DesiredRunners == 0 && st.ready() == "True", st.describe()
	})
	claims := w.listClaims()
	if len(claims) != 1 {
		t.Fatalf("the pool keeps %d volumes after one run, want 1: %v", len(claims), claims)
	}
	c := claims[0]
	if c.ClaimedBy != "" || c.Holds != w.projects["web"].tenant || c.Phase != "Bound" {
		t.Fatalf("web's volume after its run: %+v (web is %s)", c, w.projects["web"].tenant)
	}
	if !w.hasEvent("ScaledUp") {
		t.Error("no ScaledUp Event on the pool")
	}
}

// persistence is phase 3: web's next task runs on a runner holding web's
// volume, unwiped, and finds what the first left.
func (w *e2e) persistence() {
	t := w.t
	web := w.projects["web"]
	before := w.listClaims()
	id := w.addTask(web, "Find the file and the commit the first run left", "reuse", nil, "")
	w.startRun(web)
	pod := w.awaitRunner("web's second runner")
	if pod.Claim != before[0].Name || pod.Wipe != "false" || pod.Holds != web.tenant {
		t.Errorf("web's second runner: volume %q wipe=%s holds %q; want %s unwiped, holding %s", pod.Claim, pod.Wipe,
			pod.Holds, before[0].Name, web.tenant)
	}
	if !containsSeq(pod.Args, "--holds", web.tenant) {
		t.Errorf("web's second runner was started with %q, not --holds %s", pod.Args, web.tenant)
	}
	rep := w.awaitPrepared(pod.Name)
	if rep.Wiped {
		t.Errorf("web's own volume was wiped before its runner started: %+v", rep)
	}
	w.tokens = append(w.tokens, bundleToken(t, w.runnerSecret(pod.Name).bundle))
	res := parseResults(w.awaitTask(web, id, "done"))
	expectPass(t, "web's second run", res, "ENV", "P1", "P2")
	w.awaitNoRunners("web's second runner to go")
}

// isolation is phase 4: no project's run sees what another project's runs
// left — api's runs on a fresh volume, and ops's, once the pool keeps no room
// for another, on a volume wiped before its runner starts.
func (w *e2e) isolation() {
	t := w.t
	web, api, ops := w.projects["web"], w.projects["api"], w.projects["ops"]
	branches := map[string]string{}
	for _, c := range []struct {
		p      *project
		others []*project
	}{{api, []*project{web}}, {ops, []*project{web, api}}} {
		before := map[string]bool{}
		for _, cl := range w.listClaims() {
			before[cl.Name] = true
		}
		id := w.addTask(c.p, "Look for what other projects left, and leave something", "isolation seed", c.others, "")
		w.startRun(c.p)
		pod := w.awaitRunner(c.p.name + "'s runner")
		rep := w.awaitPrepared(pod.Name)
		switch {
		case !before[pod.Claim] && pod.Wipe == "true":
			branches[c.p.name] = "fresh"
			t.Logf("%s's runner got a fresh volume, %s", c.p.name, pod.Claim)
		case before[pod.Claim] && pod.Wipe == "true" && rep.Wiped:
			branches[c.p.name] = "wiped"
			t.Logf("%s's runner got %s, wiped first (%s)", c.p.name, pod.Claim, rep.WipeReason)
		default:
			t.Errorf("%s's runner mounts %s (known before: %v) with wipe=%s and a prepare report of %+v: neither a "+
				"fresh volume nor a wiped one", c.p.name, pod.Claim, before[pod.Claim], pod.Wipe, rep)
		}
		if pod.Holds != "" || containsSeq(pod.Args, "--holds") {
			t.Errorf("%s's runner was started holding %q (%q); a clean runner holds nothing", c.p.name, pod.Holds, pod.Args)
		}
		w.tokens = append(w.tokens, bundleToken(t, w.runnerSecret(pod.Name).bundle))
		res := parseResults(w.awaitTask(c.p, id, "done"))
		expectPass(t, c.p.name+"'s run", res, "ENV", "I1", "I2", "I3", "S1")
		if sha, ok := strings.CutPrefix(res["S1"].detail, "commit="); ok {
			c.p.commit = sha
		}
		c.p.tenant = w.runnerOfPod(pod.Name).Project
		w.awaitNoRunners(c.p.name + "'s runner to go")
	}
	// Both ways a project is kept from another's data were taken: maxClaims
	// is 2, so api's run fits a fresh volume and ops's has to wipe one.
	if branches["api"] != "fresh" || branches["ops"] != "wiped" {
		t.Errorf("the volumes went %v; want api on a fresh one and ops on a wiped one", branches)
	}
	if n := len(w.listClaims()); n != 2 {
		t.Errorf("the pool keeps %d volumes, want maxClaims, 2", n)
	}
}

// reusedToken is phase 5a: the first runner's token, redeemed when it
// enrolled, is refused.
func (w *e2e) reusedToken() {
	t := w.t
	if w.firstBundle == nil {
		t.Fatal("no runner configuration was kept from the first phase")
	}
	rep, logs := w.enrollLocally("reused", w.firstBundle)
	if rep.Retired || rep.By != "refused" {
		t.Errorf("a runner presenting a redeemed token: %+v\n%s", rep, tail(logs, 20))
	}
	w.expectHubLog("the reuse refused", "enrollment token already redeemed", w.firstRunner)
	if r := w.runner(w.firstRunner); r.State != "retired" {
		t.Errorf("the first runner's record after its token was replayed: %+v", r)
	}
}

// expiredToken is phase 5b: a runner token past its expiry is refused.
func (w *e2e) expiredToken() {
	t := w.t
	var minted struct {
		Runners []struct {
			EnrollmentID string    `json:"enrollment_id"`
			Bundle       string    `json:"bundle"`
			ExpiresAt    time.Time `json:"expires_at"`
		} `json:"runners"`
	}
	// As the controller mints one, with the shortest life the hub allows.
	w.hub.as(w.credential).must("POST", "/api/pool-controller/runners", map[string]any{"count": 1, "ttl_seconds": 1}, &minted)
	if len(minted.Runners) != 1 {
		t.Fatalf("minted %d runners, want 1", len(minted.Runners))
	}
	m := minted.Runners[0]
	w.tokens = append(w.tokens, bundleToken(t, []byte(m.Bundle)))
	if wait := time.Until(m.ExpiresAt) + 2*time.Second; wait > 0 {
		time.Sleep(wait)
	}
	rep, logs := w.enrollLocally("expired", []byte(m.Bundle))
	if rep.Retired || rep.By != "refused" {
		t.Errorf("a runner presenting an expired token: %+v\n%s", rep, tail(logs, 20))
	}
	w.expectHubLog("the expired token refused", "enrollment token expired", m.EnrollmentID)
	// Given back, as a controller gives back a runner it did not start.
	var retired struct {
		Results []struct {
			Outcome string `json:"outcome"`
		} `json:"results"`
	}
	w.hub.as(w.credential).must("POST", "/api/pool-controller/runners/retire",
		map[string]any{"runners": []string{m.EnrollmentID}}, &retired)
	if len(retired.Results) != 1 || retired.Results[0].Outcome != "retired" {
		t.Errorf("giving the expired runner back: %+v", retired.Results)
	}
}

// controllerKilled is phase 7: the controller's leader is killed while a run
// is in flight. The runner is neither started twice nor stopped, and the
// replica that takes the Lease adopts it and cleans up after it.
func (w *e2e) controllerKilled() {
	t := w.t
	web := w.projects["web"]
	releaseFile := "/tmp/cloop-e2e-release-" + w.stamp
	title := "Hold while the controller's leader dies"
	id := w.addTask(web, title, "hold", nil, releaseFile)
	mintedBefore := len(w.poolDetail().Runners)
	w.startRun(web)
	pod := w.awaitRunner("the held run's runner")
	enrollment := w.runnerSecret(pod.Name).enrollmentID
	w.tokens = append(w.tokens, bundleToken(t, w.runnerSecret(pod.Name).bundle))
	w.awaitHeld(web, enrollment, title)

	// A replica's identity is its Pod's name and a suffix of its own.
	leader := w.leaseHolder()
	leaderPod, _, _ := strings.Cut(leader, "_")
	controllers := w.controllerPods()
	if !controllers[leaderPod] || len(controllers) != 2 {
		t.Fatalf("the Lease is held by %q; the controller's Pods are %v", leader, controllers)
	}
	t.Logf("killing the leader %s while runner %s holds web's run", leaderPod, pod.Name)
	w.x.kubectl(w.ctx, "-n", w.ns, "delete", "pod", leaderPod, "--grace-period=0", "--force")
	var next string
	waitFor(t, "another replica to take the Lease", 2*time.Minute, func() (bool, string) {
		next = w.leaseHolder()
		return next != "" && next != leader, "held by " + next
	})
	nextPod, _, _ := strings.Cut(next, "_")
	t.Logf("%s took the Lease", next)

	// For two of the controller's resyncs, the runner stays the one it was —
	// running, the hub's busy runner — and no other runner is started.
	watchUntil := time.Now().Add(70 * time.Second)
	for time.Now().Before(watchUntil) {
		for _, p := range w.listRunners() {
			if p.Name != pod.Name {
				t.Fatalf("runner Pod %s was started while %s held the pool's only run", p.Name, pod.Name)
			}
			if p.UID != pod.UID {
				t.Fatalf("runner Pod %s was replaced (uid %s, was %s)", p.Name, p.UID, pod.UID)
			}
			if p.Phase != "Running" || p.Deleting {
				t.Fatalf("runner Pod %s is %s (deleting: %v) after the leader changed", p.Name, p.Phase, p.Deleting)
			}
		}
		if r := w.runner(enrollment); r.State != "busy" {
			t.Fatalf("the hub's runner is %q after the leader changed, want busy: %+v", r.State, r)
		}
		time.Sleep(3 * time.Second)
	}
	st := w.poolStatusNow()
	if st.Status.BusyRunners != 1 || st.Status.Runners != 1 {
		t.Errorf("the new leader's status: %s", st.describe())
	}
	if n := len(w.poolDetail().Runners); n != mintedBefore+1 {
		t.Errorf("the hub minted %d runners for one run across a leader change", n-mintedBefore)
	}

	// The run finishes on the runner that started it; the new leader
	// collects its Pod and Secret.
	w.x.kubectl(w.ctx, "-n", w.ns, "exec", pod.Name, "-c", "runner", "--", "touch", releaseFile)
	res := parseResults(w.awaitTask(web, id, "done"))
	expectPass(t, "the held run", res, "H0", "H1")
	w.awaitNoRunners("the held run's runner to go")
	w.waitPool("the new leader's pool back at minRunners", time.Minute, func(st poolStatus) (bool, string) {
		return st.Status.Runners == 0 && st.Status.BusyRunners == 0 && st.ready() == "True", st.describe()
	})
	if logs, _ := w.x.may(w.ctx, "-n", w.ns, "logs", nextPod); !strings.Contains(logs, next+" leads") {
		t.Errorf("the new leader %s never logged taking the lead:\n%s", next, tail(logs, 20))
	}
}

// runnerKilled is phase 6: a runner Pod killed mid-run is a lost node. The
// hub settles the run through the failover path — a pool's run is not moved
// off its pool — and the second runner lost under the same task quarantines
// it as a suspected node killer.
func (w *e2e) runnerKilled() {
	t := w.t
	api := w.projects["api"]
	title := "Hold until the runner is killed"
	id := w.addTask(api, title, "hold", nil, "/tmp/never-"+w.stamp)
	var lost []string
	for round := 1; round <= 2; round++ {
		w.startRun(api)
		pod := w.awaitRunner(fmt.Sprintf("api's runner, round %d", round))
		sec := w.runnerSecret(pod.Name)
		w.tokens = append(w.tokens, bundleToken(t, sec.bundle))
		executorID := w.awaitHeld(api, sec.enrollmentID, title)
		t.Logf("round %d: killing runner %s (executor %s) mid-run", round, pod.Name, executorID)
		killed := time.Now()
		w.x.kubectl(w.ctx, "-n", w.ns, "delete", "pod", pod.Name, "--grace-period=0", "--force")
		var r poolRunner
		waitFor(t, "the hub to settle the lost run", 5*time.Minute, func() (bool, string) {
			r = w.runner(sec.enrollmentID)
			return r.State == "retired", fmt.Sprintf("runner %s", r.State)
		})
		t.Logf("round %d: the hub retired the lost runner %s after %s: %s", round, executorID,
			fmtDuration(time.Since(killed)), r.RetireReason)
		if !strings.Contains(r.RetireReason, "lost") {
			t.Errorf("round %d: the runner was retired %q, not as lost with its run", round, r.RetireReason)
		}
		lost = append(lost, executorID)
		w.awaitNoRunners("the killed runner's Secret to go")
		task := w.awaitTaskSettled(api, id)
		t.Logf("round %d: task %d is %s (quarantine: %+v)", round, id, task.Status, task.Quarantine)
		if round == 1 {
			if task.Quarantine != nil || task.Status == "done" || task.Status == "in_progress" {
				t.Fatalf("round 1: one lost runner left task %d %s, quarantined %+v; want it back for the next run",
					id, task.Status, task.Quarantine)
			}
			continue
		}
		if task.Quarantine == nil || task.Status != "failed" {
			t.Fatalf("round 2: task %d is %s, quarantined %+v; two runners lost under it must quarantine it",
				id, task.Status, task.Quarantine)
		}
		for _, ex := range lost {
			if !strings.Contains(task.Quarantine.raw, ex) {
				t.Errorf("the quarantine does not name lost runner %s: %s", ex, task.Quarantine.raw)
			}
		}
	}
	if !w.hasAudit(api, "task.quarantine", fmt.Sprint(id)) {
		t.Error("no task.quarantine row in api's audit trail")
	}
	// Nothing is queued for a quarantined task: no runner is started.
	time.Sleep(20 * time.Second)
	if pods := w.listRunners(); len(pods) != 0 {
		t.Errorf("runners started after the task was quarantined: %v", names(pods))
	}
}

// credentialRevoked is phase 8: revoking the controller's credential takes
// back the live run's leases and kills it, refuses a runner token minted with
// the credential, and leaves the controller unable to start runners.
func (w *e2e) credentialRevoked() {
	t := w.t
	ops := w.projects["ops"]
	// A runner minted with the credential and not started: its token must
	// not enroll once the credential is revoked.
	var minted struct {
		Runners []struct {
			EnrollmentID string `json:"enrollment_id"`
			Bundle       string `json:"bundle"`
		} `json:"runners"`
	}
	w.hub.as(w.credential).must("POST", "/api/pool-controller/runners", map[string]any{"count": 1}, &minted)
	if len(minted.Runners) != 1 {
		t.Fatalf("minted %d runners, want 1", len(minted.Runners))
	}
	pending := minted.Runners[0]
	w.tokens = append(w.tokens, bundleToken(t, []byte(pending.Bundle)))

	title := "Hold until the credential is revoked"
	id := w.addTask(ops, title, "hold", nil, "/tmp/never-"+w.stamp)
	w.startRun(ops)
	pod := w.awaitRunner("ops's held runner")
	sec := w.runnerSecret(pod.Name)
	w.tokens = append(w.tokens, bundleToken(t, sec.bundle))
	executorID := w.awaitHeld(ops, sec.enrollmentID, title)
	since := time.Now().Add(-5 * time.Second)

	var revoked struct {
		Runners []string `json:"runners"`
		Tokens  int      `json:"tokens"`
	}
	w.hub.must("DELETE", "/api/executor-pools/"+w.poolID+"/credentials/"+w.credID, nil, &revoked)
	t.Logf("revoked the controller's credential: runners %v, %d tokens", revoked.Runners, revoked.Tokens)
	if !containsSeq(revoked.Runners, executorID) {
		t.Errorf("the revocation did not take runner %s with it: %v", executorID, revoked.Runners)
	}
	// The live run's leases go back, and the run is ended.
	waitFor(t, "the run's leases to be taken back", time.Minute, func() (bool, string) {
		return w.hasAuditSince(since, "lease.revoke_sent", executorID), ""
	})
	task := w.awaitTaskSettled(ops, id)
	if task.Status == "done" || strings.Contains(w.livelog(ops), "RESULT H1") {
		t.Errorf("the run went on after its runner's credential was revoked: task %s", task.Status)
	}
	w.awaitNoRunners("the revoked runner's Pod to go")
	if r := w.runner(sec.enrollmentID); r.State != "retired" || !strings.Contains(r.RetireReason, "revoked") {
		t.Errorf("the revoked runner's record: %+v", r)
	}
	// The token minted with it never enrolls.
	rep, logs := w.enrollLocally("revoked", []byte(pending.Bundle))
	if rep.Retired || rep.By != "refused" {
		t.Errorf("a runner presenting a token of a revoked credential: %+v\n%s", rep, tail(logs, 20))
	}
	w.expectHubLog("the revoked credential's token refused", "was revoked", pending.EnrollmentID)
	// The controller can no longer start a runner: the hub refuses it, and
	// the pool says so.
	w.waitPool("the pool to say the hub refused its credential", 2*time.Minute, func(st poolStatus) (bool, string) {
		return st.condition("Degraded") == "True" && st.reason("Degraded") == "HubRefused", st.describe()
	})
	next := w.addTask(ops, "Wait for a runner that cannot come", "hold", nil, "/tmp/never-"+w.stamp)
	w.startRun(ops)
	time.Sleep(45 * time.Second)
	if pods := w.listRunners(); len(pods) != 0 {
		t.Errorf("runner Pods started with a revoked credential: %v", names(pods))
	}
	if st := w.task(ops, next); st.Status != "pending" {
		t.Errorf("task %d is %s with no runner to take it", next, st.Status)
	}
	w.hub.must("POST", fmt.Sprintf("/api/stop?project_idx=%d", ops.idx), map[string]any{}, nil)
}

// noCredentialOnAnyVolume is phase 9: every volume the pool kept is
// released, and read from a Pod of its own, no credential is on any.
func (w *e2e) noCredentialOnAnyVolume() {
	t := w.t
	// A volume whose runner was killed stays claimed until the controller is
	// sure no Pod is being created for it — claimGrace, three minutes from
	// when it first saw the claim — and is released then, credential or not.
	var claims []claim
	waitFor(t, "every volume released", 5*time.Minute, func() (bool, string) {
		claims = w.listClaims()
		var held []string
		for _, c := range claims {
			if c.ClaimedBy != "" {
				held = append(held, c.Name+" by "+c.ClaimedBy)
			}
		}
		return len(held) == 0, strings.Join(held, ", ")
	})
	if len(claims) < 2 {
		t.Fatalf("the pool keeps %d volumes, want at least 2", len(claims))
	}
	// What the scan looks for: every credential the test made or saw, and
	// the prefixes of every kind cloop issues.
	patterns := []string{w.harnessToken, w.credential, w.adminToken, w.secretKey,
		"clrt1.", "clrc1.", "clet1.", "clac1.", "cloop_pool1_", "cloop_pat_", "cloop_git1_", "cloop_egress1_",
		"cloop_kube1_", "cloop_know1_", "sk-" + "ant-", "BEGIN PRIVATE KEY", "BEGIN EC PRIVATE KEY"}
	patterns = append(patterns, w.tokens...)
	// An empty pattern would match every line of every file.
	patterns = slices.DeleteFunc(patterns, func(p string) bool { return strings.TrimSpace(p) == "" })
	w.x.apply(w.ctx, map[string]any{"apiVersion": "v1", "kind": "Secret", "type": "Opaque",
		"metadata":   map[string]any{"name": "scan-patterns", "namespace": w.ns},
		"stringData": map[string]string{"patterns": strings.Join(patterns, "\n") + "\n"}})
	for _, c := range claims {
		if c.ClaimedBy != "" {
			t.Fatalf("volume %s is still claimed by %s", c.Name, c.ClaimedBy)
		}
		out := w.scanVolume(c.Name)
		files := -1
		var findings []string
		for _, l := range strings.Split(out, "\n") {
			switch {
			case strings.HasPrefix(l, "SCAN FILES "):
				files, _ = strconv.Atoi(strings.TrimPrefix(l, "SCAN FILES "))
			case strings.HasPrefix(l, "SCAN NAME "), strings.HasPrefix(l, "SCAN CONTENT "):
				findings = append(findings, l)
			}
		}
		if !strings.Contains(out, "SCAN SELFTEST ok") {
			t.Fatalf("the scan's own check could not find a pattern it was given:\n%s", tail(out, 20))
		}
		if !strings.Contains(out, "SCAN DONE") || files <= 0 {
			t.Errorf("volume %s: the scan read %d files and did not finish:\n%s", c.Name, files, tail(out, 20))
			continue
		}
		if len(findings) > 0 {
			t.Errorf("volume %s holds credentials:\n%s", c.Name, strings.Join(findings, "\n"))
			continue
		}
		t.Logf("volume %s (holds %q): %d files, no credential", c.Name, c.Holds, files)
	}
}

// ── the hub ────────────────────────────────────────────────────────────────

func (w *e2e) projectIndex(dir string) int {
	w.t.Helper()
	idx := -1
	waitFor(w.t, "the hub to list "+dir, time.Minute, func() (bool, string) {
		var resp struct {
			Projects []struct {
				Path string `json:"path"`
			} `json:"projects"`
		}
		w.hub.must("GET", "/api/projects", nil, &resp)
		for i, p := range resp.Projects {
			if p.Path == dir {
				idx = i
				return true, ""
			}
		}
		return false, fmt.Sprintf("%d projects", len(resp.Projects))
	})
	return idx
}

// probe is the probe script for a task, with its placeholders filled.
func (w *e2e) probe(p *project, mode string, others []*project, releaseFile string) string {
	var marks, objects []string
	for _, o := range others {
		marks = append(marks, o.mark)
		if o.commit != "" {
			objects = append(objects, o.commit[:2]+"/"+o.commit[2:])
		}
	}
	shaA, shaB := "", ""
	if len(p.commit) == 40 {
		shaA, shaB = p.commit[:20], p.commit[20:]
	}
	return strings.NewReplacer(
		"__MODE__", mode, "__ROOT__", storageRoot, "__MARK__", p.mark,
		"__CONTENT_A__", p.partA, "__CONTENT_B__", p.partB, "__SHA_A__", shaA, "__SHA_B__", shaB,
		"__OTHER_MARKS__", strings.Join(marks, " "), "__OTHER_OBJECTS__", strings.Join(objects, " "),
		"__RELEASE__", releaseFile,
	).Replace(probeScript)
}

// addTask adds a task running the probe in mode, and returns its id.
func (w *e2e) addTask(p *project, title, mode string, others []*project, releaseFile string) int {
	w.t.Helper()
	var added struct {
		Task struct {
			ID int `json:"id"`
		} `json:"task"`
	}
	w.hub.must("POST", fmt.Sprintf("/api/tasks?project_idx=%d", p.idx), map[string]any{
		"title":       title,
		"description": "E2E-SCRIPT-B64: " + base64.StdEncoding.EncodeToString([]byte(w.probe(p, mode, others, releaseFile))),
	}, &added)
	if added.Task.ID <= 0 {
		w.t.Fatal("the hub did not report the added task's id")
	}
	return added.Task.ID
}

// startRun presses Start on a project, which queues the run for the pool.
func (w *e2e) startRun(p *project) {
	w.t.Helper()
	code, body := w.hub.call("POST", fmt.Sprintf("/api/run?project_idx=%d", p.idx), map[string]any{}, nil)
	if code != 202 || !strings.Contains(body, `"queued":true`) {
		w.t.Fatalf("POST /api/run for %s: %d %s; want the run queued for the pool", p.name, code, tail(body, 5))
	}
}

// hubTask is a task as the hub's plan shows it.
type hubTask struct {
	ID             int         `json:"id"`
	Status         string      `json:"status"`
	Result         string      `json:"result"`
	ExecutorID     string      `json:"executor_id"`
	ExecutorKind   string      `json:"executor_kind"`
	ExecutorPool   string      `json:"executor_pool"`
	ExecutorRunner string      `json:"executor_runner"`
	Quarantine     *quarantine `json:"quarantine"`
}

// quarantine keeps the hub's quarantine mark as it came.
type quarantine struct{ raw string }

func (q *quarantine) UnmarshalJSON(b []byte) error {
	q.raw = string(b)
	return nil
}

func (w *e2e) task(p *project, id int) hubTask {
	w.t.Helper()
	var st struct {
		Plan *struct {
			Tasks []hubTask `json:"tasks"`
		} `json:"plan"`
	}
	w.hub.must("GET", fmt.Sprintf("/api/state?project_idx=%d", p.idx), nil, &st)
	if st.Plan != nil {
		for _, task := range st.Plan.Tasks {
			if task.ID == id {
				return task
			}
		}
	}
	w.t.Fatalf("the hub's plan of %s has no task %d", p.name, id)
	return hubTask{}
}

// livelog is the project's last run's output.
func (w *e2e) livelog(p *project) string {
	w.t.Helper()
	var live struct {
		Lines []string `json:"lines"`
	}
	w.hub.must("GET", fmt.Sprintf("/api/livelog?project_idx=%d", p.idx), nil, &live)
	return strings.Join(live.Lines, "")
}

// awaitTask waits for task id to reach status and returns its run's output.
func (w *e2e) awaitTask(p *project, id int, status string) string {
	w.t.Helper()
	var task hubTask
	waitFor(w.t, fmt.Sprintf("%s's task %d to be %s", p.name, id, status), 5*time.Minute, func() (bool, string) {
		task = w.task(p, id)
		return task.Status == status, task.Status
	})
	out := w.livelog(p)
	for _, l := range strings.Split(strings.TrimRight(out, "\n"), "\n") {
		if strings.Contains(l, "RESULT ") {
			w.t.Logf("%s | %s", p.name, strings.TrimSpace(l))
		}
	}
	return out + "\n" + task.Result
}

// awaitHeld waits until the runner minted as enrollment is the hub's busy
// runner and its run has started the harness on the task titled title, and
// returns the runner's executor ID. The probe's own lines come only when the
// harness exits — `cloop run` prints a harness's output once it is over — so
// the run's announcement of the task is what says it is in flight.
func (w *e2e) awaitHeld(p *project, enrollment, title string) string {
	w.t.Helper()
	var r poolRunner
	waitFor(w.t, "the runner to hold "+p.name+"'s run", 3*time.Minute, func() (bool, string) {
		r = w.runner(enrollment)
		log := w.livelog(p)
		return r.State == "busy" && strings.Contains(log, title) && strings.Contains(log, "Running claudecode on task"),
			fmt.Sprintf("runner %s; log: %s", r.State, tail(log, 2))
	})
	return r.ExecutorID
}

// awaitTaskSettled waits for task id to leave in_progress with the project's
// run over, and returns it.
func (w *e2e) awaitTaskSettled(p *project, id int) hubTask {
	w.t.Helper()
	var task hubTask
	waitFor(w.t, fmt.Sprintf("%s's run to end", p.name), 5*time.Minute, func() (bool, string) {
		task = w.task(p, id)
		var live struct {
			Running bool `json:"running"`
		}
		w.hub.must("GET", fmt.Sprintf("/api/livelog?project_idx=%d", p.idx), nil, &live)
		return task.Status != "in_progress" && !live.Running, fmt.Sprintf("task %s, running %v", task.Status, live.Running)
	})
	return task
}

// poolRunner is a runner as the hub's pool detail lists it.
type poolRunner struct {
	EnrollmentID string    `json:"enrollment_id"`
	Name         string    `json:"name"`
	ExecutorID   string    `json:"executor_id"`
	State        string    `json:"state"`
	EnrolledAt   time.Time `json:"enrolled_at"`
	RetiredAt    time.Time `json:"retired_at"`
	RetireReason string    `json:"retire_reason"`
	Holds        string    `json:"holds"`
	Project      string    `json:"project"`
	CredentialID string    `json:"credential_id"`
}

type poolDetail struct {
	Runners []poolRunner `json:"runners"`
}

func (w *e2e) poolDetail() poolDetail {
	w.t.Helper()
	var d poolDetail
	w.hub.must("GET", "/api/executor-pools/"+w.poolID, nil, &d)
	return d
}

// runner is the hub's record of the runner minted as enrollment.
func (w *e2e) runner(enrollment string) poolRunner {
	w.t.Helper()
	for _, r := range w.poolDetail().Runners {
		if r.EnrollmentID == enrollment {
			return r
		}
	}
	w.t.Fatalf("the hub lists no runner %s", enrollment)
	return poolRunner{}
}

// runnerOfPod is the hub's record of the runner a Pod ran, by the
// enrollment ID its Secret carried.
func (w *e2e) runnerOfPod(pod string) poolRunner {
	w.t.Helper()
	id := w.enrollments[pod]
	if id == "" {
		w.t.Fatalf("the test never saw runner %s's Secret", pod)
	}
	return w.runner(id)
}

// hasAudit reports whether p's audit trail holds an event of type typ whose
// payload contains every needle.
func (w *e2e) hasAudit(p *project, typ string, needles ...string) bool {
	w.t.Helper()
	var resp struct {
		Events []struct {
			EventType string `json:"event_type"`
			Payload   string `json:"payload"`
		} `json:"events"`
	}
	w.hub.must("GET", fmt.Sprintf("/api/audit?project_idx=%d&event_type=%s&limit=500", p.idx, typ), nil, &resp)
	for _, e := range resp.Events {
		ok := true
		for _, n := range needles {
			ok = ok && strings.Contains(e.Payload, n)
		}
		if ok {
			return true
		}
	}
	return false
}

// hasAuditSince is hasAudit over every chain the hub keeps.
func (w *e2e) hasAuditSince(since time.Time, typ string, needles ...string) bool {
	w.t.Helper()
	var resp struct {
		Events []struct {
			EventType string `json:"event_type"`
			Payload   string `json:"payload"`
		} `json:"events"`
	}
	w.hub.must("GET", fmt.Sprintf("/api/audit?source=all&event_type=%s&since=%s&limit=500", typ,
		since.UTC().Format(time.RFC3339)), nil, &resp)
	for _, e := range resp.Events {
		ok := true
		for _, n := range needles {
			ok = ok && strings.Contains(e.Payload, n)
		}
		if ok {
			return true
		}
	}
	return false
}

// expectHubLog waits for the hub's log to hold a line naming both needles.
func (w *e2e) expectHubLog(what, needle, id string) {
	w.t.Helper()
	waitFor(w.t, what+" in the hub's log", 30*time.Second, func() (bool, string) {
		b, _ := os.ReadFile(w.hubLog)
		for _, l := range strings.Split(string(b), "\n") {
			if strings.Contains(l, needle) && strings.Contains(l, id) {
				w.t.Logf("hub: %s", strings.TrimSpace(l))
				return true, ""
			}
		}
		return false, ""
	})
}

// enrollLocally runs a runner from this host with bundle, as a Pod would,
// and returns its retirement report and its output.
func (w *e2e) enrollLocally(name string, bundle []byte) (retirement, string) {
	w.t.Helper()
	dir := filepath.Join(w.work, "local-"+name)
	root := filepath.Join(dir, "work")
	if err := os.MkdirAll(root, 0o700); err != nil {
		w.t.Fatal(err)
	}
	tokenFile := filepath.Join(dir, "bundle")
	if err := os.WriteFile(tokenFile, bundle, 0o600); err != nil {
		w.t.Fatal(err)
	}
	report := filepath.Join(dir, "termination-log")
	ctx, cancel := context.WithTimeout(w.ctx, 90*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, w.cloop, "executor", "agent", "--ephemeral", "--token-file", tokenFile,
		"--workdir-root", root, "--ca-file", w.certPath, "--termination-log", report)
	cmd.Dir = dir
	cmd.Env = processEnv("HOME="+dir, "NO_COLOR=1")
	out, err := cmd.CombinedOutput()
	if err == nil {
		w.t.Errorf("runner %s exited 0", name)
	}
	var rep retirement
	b, rerr := os.ReadFile(report)
	if rerr != nil || json.Unmarshal(b, &rep) != nil {
		w.t.Errorf("runner %s left no retirement report (%v): %q\n%s", name, rerr, b, tail(string(out), 20))
	}
	return rep, string(out)
}

// retirement is the runner's report on how it ended (agent.RetirementReport).
type retirement struct {
	Retired bool   `json:"retired"`
	By      string `json:"by"`
	Reason  string `json:"reason"`
}

// ── the cluster ────────────────────────────────────────────────────────────

// runnerPod is a runner Pod as the test reads it.
type runnerPod struct {
	Name, UID, Phase   string
	Deleting           bool
	Claim, Holds, Wipe string
	Args               []string
}

func (w *e2e) listRunners() []runnerPod {
	w.t.Helper()
	out, err := w.x.may(w.ctx, "-n", w.ns, "get", "pods", "-l", runnerPods, "-o", "json")
	if err != nil {
		w.t.Fatalf("list runner Pods: %v\n%s", err, out)
	}
	var list struct {
		Items []struct {
			Metadata struct {
				Name              string            `json:"name"`
				UID               string            `json:"uid"`
				DeletionTimestamp string            `json:"deletionTimestamp"`
				Annotations       map[string]string `json:"annotations"`
			} `json:"metadata"`
			Spec struct {
				Containers []struct {
					Name string   `json:"name"`
					Args []string `json:"args"`
				} `json:"containers"`
			} `json:"spec"`
			Status struct {
				Phase string `json:"phase"`
			} `json:"status"`
		} `json:"items"`
	}
	if err := json.Unmarshal([]byte(out), &list); err != nil {
		w.t.Fatalf("decode runner Pods: %v", err)
	}
	var pods []runnerPod
	for _, it := range list.Items {
		p := runnerPod{Name: it.Metadata.Name, UID: it.Metadata.UID, Phase: it.Status.Phase,
			Deleting: it.Metadata.DeletionTimestamp != "",
			Claim:    it.Metadata.Annotations["cloop.dev/storage-claim"],
			Holds:    it.Metadata.Annotations["cloop.dev/storage-holds"],
			Wipe:     it.Metadata.Annotations["cloop.dev/storage-wipe"]}
		for _, c := range it.Spec.Containers {
			if c.Name == "runner" {
				p.Args = c.Args
			}
		}
		pods = append(pods, p)
	}
	return pods
}

func names(pods []runnerPod) []string {
	var out []string
	for _, p := range pods {
		out = append(out, p.Name)
	}
	return out
}

// awaitRunner waits for a runner Pod the test has not seen before and
// returns it.
func (w *e2e) awaitRunner(what string) runnerPod {
	w.t.Helper()
	var found runnerPod
	waitFor(w.t, what+" to be started", 3*time.Minute, func() (bool, string) {
		pods := w.listRunners()
		for _, p := range pods {
			if !w.seen[p.Name] {
				found = p
				return true, ""
			}
		}
		return false, fmt.Sprintf("runner Pods %v", names(pods))
	})
	w.seen[found.Name] = true
	if found.Claim != "" {
		w.claims[found.Claim] = true
	}
	// Its Secret is created after it; wait for it, and remember whose it is.
	waitFor(w.t, "runner "+found.Name+"'s Secret", time.Minute, func() (bool, string) {
		id := w.x.jsonpath(w.ctx, w.ns, "secret", found.Name, `{.metadata.annotations.cloop\.dev/enrollment-id}`)
		if id != "" {
			w.enrollments[found.Name] = id
		}
		return id != "", ""
	})
	return found
}

// awaitNoRunners waits until no runner Pod or Secret is left.
func (w *e2e) awaitNoRunners(what string) {
	w.t.Helper()
	waitFor(w.t, what, 3*time.Minute, func() (bool, string) {
		pods, _ := w.x.may(w.ctx, "-n", w.ns, "get", "pods", "-l", runnerPods, "-o", "name")
		secrets, _ := w.x.may(w.ctx, "-n", w.ns, "get", "secrets", "-l", runnerSecrets, "-o", "name")
		return pods == "" && secrets == "", strings.TrimSpace(pods + " " + secrets)
	})
}

// secretOf is a runner's Secret as the test reads it.
type secretOf struct {
	bundle       []byte
	enrollmentID string
	owner        string
	immutable    bool
}

func (w *e2e) runnerSecret(pod string) secretOf {
	w.t.Helper()
	out := w.x.out(w.ctx, "-n", w.ns, "get", "secret", pod, "-o", "json")
	var s struct {
		Metadata struct {
			Annotations     map[string]string `json:"annotations"`
			OwnerReferences []struct {
				Kind string `json:"kind"`
				Name string `json:"name"`
			} `json:"ownerReferences"`
		} `json:"metadata"`
		Data      map[string]string `json:"data"`
		Immutable bool              `json:"immutable"`
	}
	if err := json.Unmarshal([]byte(out), &s); err != nil {
		w.t.Fatal(err)
	}
	bundle, err := base64.StdEncoding.DecodeString(s.Data["bundle"])
	if err != nil || len(bundle) == 0 {
		w.t.Fatalf("runner Secret %s holds no bundle: %v", pod, err)
	}
	so := secretOf{bundle: bundle, enrollmentID: s.Metadata.Annotations["cloop.dev/enrollment-id"], immutable: s.Immutable}
	if len(s.Metadata.OwnerReferences) == 1 {
		so.owner = s.Metadata.OwnerReferences[0].Kind + "/" + s.Metadata.OwnerReferences[0].Name
	}
	return so
}

// bundleToken is the runner token inside a runner configuration.
func bundleToken(t *testing.T, bundle []byte) string {
	t.Helper()
	b, err := remote.DecodeBundle(string(bundle))
	if err != nil || b.Token == "" {
		t.Fatalf("a runner configuration the test cannot read: %v", err)
	}
	return b.Token
}

// prepared is the init container's report on a runner's volume.
type prepared struct {
	Wiped      bool   `json:"wiped"`
	WipeReason string `json:"wipe_reason"`
	Error      string `json:"error"`
}

// awaitPrepared waits for a runner's init container to prepare its volume
// and returns its report.
func (w *e2e) awaitPrepared(pod string) prepared {
	w.t.Helper()
	var code string
	waitFor(w.t, "runner "+pod+"'s volume to be prepared", 3*time.Minute, func() (bool, string) {
		code = w.x.jsonpath(w.ctx, w.ns, "pod", pod, "{.status.initContainerStatuses[0].state.terminated.exitCode}")
		return code != "", w.x.jsonpath(w.ctx, w.ns, "pod", pod, "{.status.phase}")
	})
	msg := w.x.jsonpath(w.ctx, w.ns, "pod", pod, "{.status.initContainerStatuses[0].state.terminated.message}")
	var rep prepared
	if code != "0" || json.Unmarshal([]byte(msg), &rep) != nil {
		w.t.Fatalf("runner %s's init container exited %s: %s", pod, code, msg)
	}
	return rep
}

// claim is a runner volume as the test reads it.
type claim struct {
	Name, Phase, ClaimedBy, Holds string
}

func (w *e2e) listClaims() []claim {
	w.t.Helper()
	out, err := w.x.may(w.ctx, "-n", w.ns, "get", "pvc", "-o", "json")
	if err != nil {
		w.t.Fatalf("list volumes: %v\n%s", err, out)
	}
	var list struct {
		Items []struct {
			Metadata struct {
				Name        string            `json:"name"`
				Annotations map[string]string `json:"annotations"`
			} `json:"metadata"`
			Status struct {
				Phase string `json:"phase"`
			} `json:"status"`
		} `json:"items"`
	}
	if err := json.Unmarshal([]byte(out), &list); err != nil {
		w.t.Fatal(err)
	}
	var claims []claim
	for _, it := range list.Items {
		a := it.Metadata.Annotations
		if a["cloop.dev/executor-pool"] != poolName {
			continue
		}
		claims = append(claims, claim{Name: it.Metadata.Name, Phase: it.Status.Phase,
			ClaimedBy: a["cloop.dev/claimed-by"], Holds: a["cloop.dev/holds"]})
	}
	sort.Slice(claims, func(i, j int) bool { return claims[i].Name < claims[j].Name })
	return claims
}

// poolStatus is the ExecutorPool's status.
type poolStatus struct {
	Status struct {
		PoolID         string `json:"poolID"`
		DesiredRunners int    `json:"desiredRunners"`
		Runners        int    `json:"runners"`
		BusyRunners    int    `json:"busyRunners"`
		QueuedRuns     int    `json:"queuedRuns"`
		Conditions     []struct {
			Type    string `json:"type"`
			Status  string `json:"status"`
			Reason  string `json:"reason"`
			Message string `json:"message"`
		} `json:"conditions"`
	} `json:"status"`
}

func (s poolStatus) condition(typ string) string {
	for _, c := range s.Status.Conditions {
		if c.Type == typ {
			return c.Status
		}
	}
	return ""
}

func (s poolStatus) reason(typ string) string {
	for _, c := range s.Status.Conditions {
		if c.Type == typ {
			return c.Reason
		}
	}
	return ""
}

func (s poolStatus) ready() string { return s.condition("Ready") }

func (s poolStatus) describe() string {
	var conds []string
	for _, c := range s.Status.Conditions {
		conds = append(conds, fmt.Sprintf("%s=%s(%s: %s)", c.Type, c.Status, c.Reason, c.Message))
	}
	return fmt.Sprintf("pool %q desired %d runners %d busy %d queued %d [%s]", s.Status.PoolID, s.Status.DesiredRunners,
		s.Status.Runners, s.Status.BusyRunners, s.Status.QueuedRuns, strings.Join(conds, "; "))
}

func (w *e2e) poolStatusNow() poolStatus {
	w.t.Helper()
	var st poolStatus
	out := w.x.out(w.ctx, "-n", w.ns, "get", "executorpool", poolName, "-o", "json")
	if err := json.Unmarshal([]byte(out), &st); err != nil {
		w.t.Fatal(err)
	}
	return st
}

func (w *e2e) waitPool(what string, timeout time.Duration, cond func(poolStatus) (bool, string)) {
	w.t.Helper()
	waitFor(w.t, what, timeout, func() (bool, string) {
		out, err := w.x.may(w.ctx, "-n", w.ns, "get", "executorpool", poolName, "-o", "json")
		var st poolStatus
		if err != nil || json.Unmarshal([]byte(out), &st) != nil {
			return false, out
		}
		return cond(st)
	})
}

func (w *e2e) hasEvent(reason string) bool {
	w.t.Helper()
	out, _ := w.x.may(w.ctx, "-n", w.ns, "get", "events", "--field-selector",
		"involvedObject.kind=ExecutorPool,involvedObject.name="+poolName+",reason="+reason, "-o", "name")
	return out != ""
}

func (w *e2e) leaseHolder() string {
	w.t.Helper()
	return w.x.jsonpath(w.ctx, w.ns, "lease", "cloop-executor-controller", "{.spec.holderIdentity}")
}

// controllerPods are the controller's live Pods, by name.
func (w *e2e) controllerPods() map[string]bool {
	w.t.Helper()
	out := w.x.out(w.ctx, "-n", w.ns, "get", "pods", "-l", controllerSel, "-o",
		`jsonpath={range .items[?(@.metadata.deletionTimestamp)]}{""}{end}{range .items[*]}{.metadata.name}{" "}{end}`)
	pods := map[string]bool{}
	for _, n := range strings.Fields(out) {
		pods[n] = true
	}
	return pods
}

// scanVolume reads a volume from a Pod of its own and returns what the scan
// printed: "SCAN FILES <n>", a "SCAN NAME <path>" or "SCAN CONTENT <path>"
// line for each finding, and "SCAN DONE".
func (w *e2e) scanVolume(claimName string) string {
	w.t.Helper()
	name := "scan-" + claimName
	if len(name) > 63 {
		name = name[:63]
	}
	// The self-test: a file outside the volume holding one of the patterns
	// must be found, or a scan that finds nothing proves nothing.
	script := `head -n 1 /patterns/patterns > /tmp/selftest
grep -q -F -f /patterns/patterns /tmp/selftest && echo "SCAN SELFTEST ok"
cd /scan || exit 1
find . -xdev \( -type f -o -type l \) 2>/dev/null > /tmp/files
echo "SCAN FILES $(wc -l < /tmp/files)"
grep -E '/(\.credentials\.json|agent\.json|\.git-credentials|git-credential-[^/]*|kubeconfig|[^/]*\.token)$' /tmp/files | sed 's/^/SCAN NAME /'
while IFS= read -r f; do
  [ -f "$f" ] && grep -q -F -f /patterns/patterns "$f" 2>/dev/null && echo "SCAN CONTENT $f"
done < /tmp/files
echo "SCAN DONE"`
	f, t := false, true
	uid := int64(65532)
	pod := map[string]any{"apiVersion": "v1", "kind": "Pod",
		"metadata": map[string]any{"name": name, "namespace": w.ns},
		"spec": map[string]any{
			"restartPolicy": "Never", "automountServiceAccountToken": f,
			"securityContext": map[string]any{"runAsNonRoot": t, "runAsUser": uid, "runAsGroup": uid, "fsGroup": uid,
				"seccompProfile": map[string]any{"type": "RuntimeDefault"}},
			"containers": []any{map[string]any{"name": "scan", "image": w.image, "imagePullPolicy": "Never",
				"command": []string{"/bin/sh", "-c", script},
				"securityContext": map[string]any{"allowPrivilegeEscalation": f, "readOnlyRootFilesystem": t,
					"capabilities": map[string]any{"drop": []string{"ALL"}}},
				"volumeMounts": []any{
					map[string]any{"name": "vol", "mountPath": "/scan", "readOnly": t},
					map[string]any{"name": "patterns", "mountPath": "/patterns", "readOnly": t},
					map[string]any{"name": "tmp", "mountPath": "/tmp"}}}},
			"volumes": []any{
				map[string]any{"name": "vol", "persistentVolumeClaim": map[string]any{"claimName": claimName, "readOnly": t}},
				map[string]any{"name": "patterns", "secret": map[string]any{"secretName": "scan-patterns"}},
				map[string]any{"name": "tmp", "emptyDir": map[string]any{}}},
		}}
	w.x.apply(w.ctx, pod)
	defer w.x.run(w.ctx, nil, true, "kubectl", "-n", w.ns, "delete", "pod", name, "--wait=false")
	waitFor(w.t, "the scan of "+claimName, 3*time.Minute, func() (bool, string) {
		phase := w.x.jsonpath(w.ctx, w.ns, "pod", name, "{.status.phase}")
		return phase == "Succeeded" || phase == "Failed", phase
	})
	out, err := w.x.may(w.ctx, "-n", w.ns, "logs", name)
	if err != nil {
		w.t.Fatalf("the scan's log: %v\n%s", err, out)
	}
	return out
}

func containsSeq(list []string, seq ...string) bool {
	for i := range list {
		if i+len(seq) > len(list) {
			return false
		}
		match := true
		for j, s := range seq {
			if list[i+j] != s {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
