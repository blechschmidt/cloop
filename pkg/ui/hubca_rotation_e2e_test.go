package ui

// End to end, rotating the hub's own CA under a serving hub (Task 20438):
// real git cloning and pushing through the real git proxy's TLS listener, a
// real kubectl — or, where none is installed, a TLS client reading the same
// kubeconfig — through the Kubernetes monitor's, each trusting exactly what the
// hub handed its dispatch; and every step taken through the dashboard's API,
// which takes the steps `cloop hub ca rotate` does.
//
// Three cases. A run dispatched after the stage keeps cloning and pushing
// across the activation and the retirement. A run dispatched before the stage
// holds the activation back, named; forced, it is the run that breaks, and an
// emergency rotation ends its proxy session. And the kube monitor path: a
// kubeconfig minted before the stage is the one an activation names, one
// minted after keeps working.

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/gitproxy"
	"github.com/blechschmidt/cloop/pkg/hubca"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/secretbroker/secretbrokertest"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

const caRigPAT = "ghp_hubca_rotation_e2e_forge_token_0000000000000000"

// caRig is a hub whose monitors issue from its own CA, the dashboard's API in
// front of it, and the control plane's database.
type caRig struct {
	t      *testing.T
	dir    string
	ts     *httptest.Server
	db     *statedb.DB
	gitBin string
	forge  *secretbrokertest.Forge
	gp     *gitProxyService
	kg     *kubeGuardService
}

// useControlPlane makes dir this process's control plane for the test.
func useControlPlane(t *testing.T, dir string) {
	t.Helper()
	controlPlaneDirMu.Lock()
	prev := controlPlaneDirValue
	controlPlaneDirValue = dir
	controlPlaneDirMu.Unlock()
	t.Cleanup(func() {
		controlPlaneDirMu.Lock()
		controlPlaneDirValue = prev
		controlPlaneDirMu.Unlock()
	})
}

func newCARig(t *testing.T) *caRig {
	t.Helper()
	dir := autoTLSDir(t)
	srv := New(dir, 0, "")
	srv.RPS, srv.Burst = 100000, 100000
	useControlPlane(t, dir)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return &caRig{t: t, dir: dir, ts: ts, db: db}
}

// withGitProxy starts the git proxy as startGitProxy does under tls: auto —
// its leaf from the hub's CA, refreshed on the hub's tick — in front of a
// forge, and installs it as this process's proxy.
func (r *caRig) withGitProxy() *caRig {
	t := r.t
	r.gitBin, _ = secretbrokertest.GitTools(t)
	gh := secretbrokertest.NewGitHub()
	gh.AcceptPAT(caRigPAT, "acme/tool")
	r.forge = secretbrokertest.NewForge(t, gh, "acme/tool")
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	base := "https://" + ln.Addr().String()
	mc, err := startMonitorCertificate(hubca.GitProxy, r.dir, base, ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	tlsCfg, err := mc.srv.TLSConfig("1.2")
	if err != nil {
		t.Fatal(err)
	}
	reg, err := gitproxy.NewRegistry(base)
	if err != nil {
		t.Fatal(err)
	}
	px, err := gitproxy.New(reg, gitproxy.Options{Transport: r.forge.Transport()})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = px.Serve(tls.NewListener(ln, tlsCfg)) }()
	pol := gitproxy.WriteBackPolicy()
	pol.AllowFetch = true
	r.gp = &gitProxyService{reg: reg, proxy: px, baseURL: base, policy: pol, ttl: time.Hour, listener: ln,
		certs: mc, githubUpstream: r.forge.URL}
	prev := gitProxySingleton.Load()
	gitProxySingleton.Store(r.gp)
	t.Cleanup(func() {
		gitProxySingleton.Store(prev)
		_ = px.Close()
		mc.close()
	})
	return r
}

// step takes a rotation step through the dashboard's API.
func (r *caRig) step(body string) (int, map[string]any) {
	r.t.Helper()
	return doJSON(r.t, http.DefaultClient, http.MethodPost, r.ts.URL+"/api/hub/ca/rotate", body)
}

func (r *caRig) status() map[string]any {
	r.t.Helper()
	code, out := doJSON(r.t, http.DefaultClient, http.MethodGet, r.ts.URL+"/api/hub/ca", "")
	if code != http.StatusOK {
		r.t.Fatalf("GET /api/hub/ca: %d %v", code, out)
	}
	return out
}

func (r *caRig) ca() *hubCA {
	if r.gp != nil {
		return r.gp.certs.ca
	}
	return r.kg.certs.ca
}

// until ticks this process's hub CA refresher — as the minute's tick, or the
// cluster bus, does — until cond holds.
func (r *caRig) until(what string, cond func() bool) {
	r.t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for {
		r.ca().tick()
		if cond() {
			return
		}
		if time.Now().After(deadline) {
			r.t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func (r *caRig) trusts(n int) {
	r.t.Helper()
	r.until(fmt.Sprintf("the hub to hand dispatches %d CA(s)", n), func() bool {
		return len(r.ca().trust.Serials()) == n
	})
}

func (r *caRig) active() string { return r.ca().trust.State().Active.Serial }

// leafFrom waits until monitor m serves a leaf the CA with serial signed.
func (r *caRig) leafFrom(m *monitorCert, serial string) {
	r.t.Helper()
	r.until("the "+m.srv.Monitor().Label()+" to serve a leaf from "+serial, func() bool {
		l := m.srv.Current()
		ca := r.ca().trust.State().ByIssuer(l.Cert)
		return ca != nil && ca.Serial == serial
	})
}

// recordDispatch is the supervisor's part of a dispatch: the executor
// session that keeps the spec, labels and all.
func (r *caRig) recordDispatch(runID string, spec executor.Spec) {
	r.t.Helper()
	b, err := json.Marshal(spec)
	if err != nil {
		r.t.Fatal(err)
	}
	if err := r.db.OpenExecutorSession(statedb.ExecutorSessionRow{ID: "sess_" + runID, ExecutorID: "ex_e2e",
		HandleID: "h_" + runID, ProjectPath: "/srv/" + runID, TaskID: 3, ClaimToken: "tok_" + runID,
		StartedAt: time.Now(), SpecJSON: string(b)}); err != nil {
		r.t.Fatal(err)
	}
}

// caSandbox is a dispatched run's git: a closed environment holding the proxy
// session's credential and trusting exactly the bundle its dispatch carried,
// for the proxy's URL and nothing else, as every driver configures it.
type caSandbox struct {
	r       *caRig
	run     string
	work    string
	env     []string
	repoURL string
	session string
	spec    executor.Spec
}

// dispatch makes a run's dispatch as startWorkload does it, as far as the
// hub's CA is concerned.
func (r *caRig) dispatch(runID string) *caSandbox {
	t := r.t
	t.Helper()
	m, err := r.gp.reg.Mint(gitproxy.MintRequest{
		Upstream:   r.forge.RepoURL("acme/tool"),
		Credential: gitproxy.Credential{Username: "x-access-token", Password: caRigPAT},
		Policy: gitproxy.Policy{AllowedRefs: []string{gitproxy.DefaultAllowedRef},
			AllowCreate: true, AllowUpdate: true, AllowFetch: true},
		TTL: time.Hour, Actor: "e2e", RunID: runID,
	})
	if err != nil {
		t.Fatal(err)
	}
	spec := executor.Spec{Argv: []string{"claude"}, Labels: map[string]string{executor.LabelRunID: runID}}
	spec = applyGitProxyTrust(spec)
	spec = labelHubCATrust(spec, nil)
	if spec.GitCA == nil {
		t.Fatal("the dispatch carries no hub CA")
	}
	r.recordDispatch(runID, spec)

	work := t.TempDir()
	caFile := filepath.Join(work, executor.SandboxGitCAFileName)
	if err := os.WriteFile(caFile, spec.GitCA.PEM, 0o644); err != nil {
		t.Fatal(err)
	}
	closed := []string{"HOME=" + work, "PATH=" + os.Getenv("PATH"), "GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_CONFIG_NOSYSTEM=1", "GIT_TERMINAL_PROMPT=0", "LC_ALL=C"}
	cred, err := executor.GitCredentialConfig(executor.Workspace{Kind: executor.WorkspaceGit, Repo: m.RepoURL},
		executor.GitCredential{Username: m.Session.ID, Password: m.Token})
	if err != nil {
		t.Fatal(err)
	}
	env, err := executor.WithGitConfig(closed, append(spec.GitCA.ConfigPairs(caFile), cred...))
	if err != nil {
		t.Fatal(err)
	}
	return &caSandbox{r: r, run: runID, work: work, env: env, repoURL: m.RepoURL, session: m.Session.ID, spec: spec}
}

func (s *caSandbox) git(dir string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, s.r.gitBin, args...)
	cmd.Dir, cmd.Env = dir, s.env
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	return out.String(), err
}

// clone clones the repository through the proxy into name.
func (s *caSandbox) clone(name string) {
	s.r.t.Helper()
	if out, err := s.git(s.work, "clone", "-q", s.repoURL, name); err != nil {
		s.r.t.Fatalf("%s: clone through the proxy: %v\n%s", s.run, err, out)
	}
}

// push commits a file in the first clone and pushes it to cloop/<name>.
func (s *caSandbox) push(name string) error {
	repo := filepath.Join(s.work, "repo")
	if err := os.WriteFile(filepath.Join(repo, name+".txt"), []byte(name+"\n"), 0o644); err != nil {
		return err
	}
	for _, args := range [][]string{{"add", "."}, {"-c", "user.email=e2e@cloop.invalid", "-c", "user.name=e2e",
		"commit", "-qm", name}} {
		if out, err := s.git(repo, args...); err != nil {
			return fmt.Errorf("git %s: %v\n%s", args[0], err, out)
		}
	}
	ref := "refs/heads/cloop/" + name
	if out, err := s.git(repo, "push", "-q", "origin", "HEAD:"+ref); err != nil {
		return fmt.Errorf("push %s: %v\n%s", name, err, out)
	}
	if s.r.forge.Ref(s.r.t, "acme/tool", ref) == "" {
		return fmt.Errorf("push %s did not reach the forge", name)
	}
	return nil
}

func (s *caSandbox) mustPush(name string) {
	s.r.t.Helper()
	if err := s.push(name); err != nil {
		s.r.t.Fatalf("%s: %v", s.run, err)
	}
}

func labelsOf(t *testing.T, db *statedb.DB, runID string) map[string]string {
	t.Helper()
	row, err := db.GetExecutorSession("sess_" + runID)
	if err != nil {
		t.Fatal(err)
	}
	var spec executor.Spec
	if err := json.Unmarshal([]byte(row.SpecJSON), &spec); err != nil {
		t.Fatal(err)
	}
	return spec.Labels
}

func auditCount(t *testing.T, db *statedb.DB, action auditaction.Action) (int, []string) {
	t.Helper()
	rows, _, err := db.ListAuditEvents(statedb.AuditFilter{EntityType: "hub_ca"})
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	var payloads []string
	for _, r := range rows {
		if r.EventType == string(action) {
			n++
			payloads = append(payloads, r.Payload)
		}
	}
	return n, payloads
}

// TestHubCARotation_ARunSpanningStageAndActivateKeepsCloningAndPushing: a
// run dispatched once the stage was taken is handed both CAs, and keeps
// cloning and pushing through the proxy while the leaf moves from the old CA
// to the new one and the old one is retired.
func TestHubCARotation_ARunSpanningStageAndActivateKeepsCloningAndPushing(t *testing.T) {
	r := newCARig(t).withGitProxy()
	ca1 := r.active()

	code, out := r.step(`{"step":"stage"}`)
	if code != http.StatusOK {
		t.Fatalf("stage: %d %v", code, out)
	}
	r.trusts(2)
	ca2 := r.ca().trust.State().Next.Serial
	if names := fmt.Sprint(r.status()["next"].(map[string]any)["names"]); !strings.Contains(names, "127.0.0.1") {
		t.Errorf("the staged CA's name constraints %s do not permit the proxy's address", names)
	}

	sb := r.dispatch("run_span")
	labels := labelsOf(t, r.db, "run_span")
	if got := labels[executor.LabelHubCATrust]; got != hubca.Label([]string{ca1, ca2}) {
		t.Fatalf("the run recorded trust %q, want both CAs", got)
	}
	if !strings.Contains(labels[executor.LabelHubCAUses], hubca.UseGitProxy) {
		t.Errorf("the run recorded uses %q", labels[executor.LabelHubCAUses])
	}
	sb.clone("repo")
	sb.mustPush("during-stage")
	if issuer := r.ca().trust.State().ByIssuer(r.gp.certs.srv.Current().Cert); issuer == nil || issuer.Serial != ca1 {
		t.Fatal("the proxy's leaf changed CA at the stage")
	}

	if code, out := r.step(`{"step":"activate"}`); code != http.StatusOK {
		t.Fatalf("activate with no run older than the stage: %d %v", code, out)
	}
	r.leafFrom(r.gp.certs, ca2)
	sb.mustPush("after-activate")
	sb.clone("again")

	if code, out := r.step(`{"step":"retire_previous"}`); code != http.StatusPreconditionRequired {
		t.Fatalf("retire without confirm: %d %v", code, out)
	}
	if code, out := r.step(`{"step":"retire_previous","confirm":"retire_previous"}`); code != http.StatusOK {
		t.Fatalf("retire: %d %v", code, out)
	}
	r.trusts(1)
	sb.mustPush("after-retire")

	// A run dispatched now is handed the new CA alone, and is served.
	after := r.dispatch("run_after")
	if got := labelsOf(t, r.db, "run_after")[executor.LabelHubCATrust]; got != ca2 {
		t.Fatalf("a run after the retirement recorded trust %q, want %s", got, ca2)
	}
	after.clone("repo")
	after.mustPush("dispatched-after")

	for _, a := range []auditaction.Action{auditaction.ActionHubCARotationStaged,
		auditaction.ActionHubCARotationActivated, auditaction.ActionHubCAPreviousRetired} {
		if n, payloads := auditCount(t, r.db, a); n != 1 || !strings.Contains(payloads[0], `"via":"dashboard"`) {
			t.Errorf("%s rows: %d %v", a, n, payloads)
		}
	}
	if n, payloads := auditCount(t, r.db, auditaction.ActionHubCALeafIssued); n < 2 ||
		!strings.Contains(strings.Join(payloads, " "), `"reason":"activation"`) {
		t.Errorf("no leaf reissued for the activation on the trail: %v", payloads)
	}
}

// TestHubCARotation_AnOlderRunRefusesTheActivation: a run dispatched before
// the stage was told to trust the old CA alone. The activation waits for it
// and names it; forced, it names it again and that run's git stops verifying
// the proxy; and the emergency that follows ends its proxy session.
func TestHubCARotation_AnOlderRunRefusesTheActivation(t *testing.T) {
	r := newCARig(t).withGitProxy()
	old := r.dispatch("run_old")
	old.clone("repo")
	old.mustPush("before-stage")

	if code, out := r.step(`{"step":"stage"}`); code != http.StatusOK {
		t.Fatalf("stage: %d %v", code, out)
	}
	r.trusts(2)
	ca2 := r.ca().trust.State().Next.Serial

	code, out := r.step(`{"step":"activate"}`)
	if code != http.StatusConflict || !strings.Contains(fmt.Sprint(out["error"]), "run run_old of /srv/run_old (task 3)") {
		t.Fatalf("activate with an older run: %d %v", code, out)
	}
	if runs, _ := out["runs"].([]any); len(runs) != 1 {
		t.Fatalf("the refusal lists %v", out["runs"])
	}
	st := r.status()
	if blocking, _ := st["blocking"].([]any); len(blocking) != 1 || st["ready"] != false {
		t.Fatalf("status while blocked: %v", st)
	}
	// The run itself still works: nothing changed for it yet.
	old.mustPush("during-stage")

	if code, _ := r.step(`{"step":"activate","force":true}`); code != http.StatusPreconditionRequired {
		t.Fatalf("a forced activation without confirm: %d", code)
	}
	code, out = r.step(`{"step":"activate","force":true,"confirm":"activate"}`)
	if code != http.StatusOK {
		t.Fatalf("forced activation: %d %v", code, out)
	}
	if broken := fmt.Sprint(out["result"].(map[string]any)["broken"]); !strings.Contains(broken, "run_old") {
		t.Fatalf("the forced activation did not name the run it breaks: %s", broken)
	}
	r.leafFrom(r.gp.certs, ca2)
	err := old.push("after-activate")
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "certificate") {
		t.Fatalf("the run trusting only the old CA kept verifying the proxy (err=%v)", err)
	}
	if n, payloads := auditCount(t, r.db, auditaction.ActionHubCARotationActivated); n != 1 ||
		!strings.Contains(payloads[0], `"forced":["run_old"]`) {
		t.Fatalf("activation row: %v", payloads)
	}

	// The emergency: a fresh CA, and the run's proxy session ended.
	if _, ok := sessionHeld(r.gp, old.session); !ok {
		t.Fatal("the run's proxy session is gone before the emergency")
	}
	code, out = r.step(`{"step":"now","confirm":"now"}`)
	if code != http.StatusOK {
		t.Fatalf("now: %d %v", code, out)
	}
	if cut := fmt.Sprint(out["result"].(map[string]any)["cut"]); !strings.Contains(cut, "run_old") {
		t.Fatalf("the emergency did not name the run: %s", cut)
	}
	r.until("the run's proxy session to be ended", func() bool { _, ok := sessionHeld(r.gp, old.session); return !ok })
	n, payloads := auditCount(t, r.db, auditaction.ActionHubCASessionsEnded)
	if n != 1 || !strings.Contains(payloads[0], `"git_proxy":1`) || !strings.Contains(payloads[0], `"runs":["run_old"]`) {
		t.Fatalf("hub_ca.sessions_ended: %d %v", n, payloads)
	}
	if n, _ := auditCount(t, r.db, auditaction.ActionHubCAEmergencyRotated); n != 1 {
		t.Fatalf("hub_ca.emergency_rotated rows: %d", n)
	}
	if r.ca().trust.State().Phase() != hubca.PhaseSteady || r.active() == ca2 {
		t.Fatalf("after the emergency the hub CA is %s, %s", r.ca().trust.State().Phase(), r.active())
	}
}

func sessionHeld(gp *gitProxyService, id string) (*gitproxy.Session, bool) {
	for _, s := range gp.reg.Sessions() {
		if s.ID == id {
			return s, true
		}
	}
	return nil, false
}

// TestHubCARotation_TheKubeMonitorPath: a kubeconfig carries the CAs its
// dispatch was handed. One minted before the stage holds the activation back
// and, forced past, stops verifying the monitor; one minted after keeps
// working through the activation and the retirement — with kubectl where it
// is installed, and a TLS client reading the same kubeconfig always.
func TestHubCARotation_TheKubeMonitorPath(t *testing.T) {
	r := newCARig(t)
	api := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"kind":"PodList","apiVersion":"v1","metadata":{},"items":[]}`)
	}))
	t.Cleanup(api.Close)
	cfg := autoTLSConfig()
	cfg.Executors.GitProxy.Enabled = false
	kg, err := startKubeGuard(cfg, r.dir)
	if err != nil {
		t.Fatalf("start the kube monitor under tls: auto: %v", err)
	}
	t.Cleanup(kg.Close)
	r.kg = kg
	prev := kubeGuardSingleton.Load()
	kubeGuardSingleton.Store(kg)
	t.Cleanup(func() { kubeGuardSingleton.Store(prev) })

	mint := func(runID string) []byte {
		t.Helper()
		res, err := kubeGuard{svc: kg}.GuardKubeconfig(context.Background(), secretbroker.KubeGuardRequest{
			Kubeconfig: []byte(restoreKubeconfig(api.URL)), Namespaces: []string{"app"}, RunID: runID,
			Verbs:   []string{"get", "list"},
			GrantID: "grant_" + runID, ProjectID: "/srv/" + runID, ExecutorID: "ex_e2e", Actor: "e2e",
		})
		if err != nil || !res.Guarded() {
			t.Fatalf("mint the kubeconfig: %v", err)
		}
		r.recordDispatch(runID, labelHubCATrust(executor.Spec{Argv: []string{"claude"},
			Labels: map[string]string{executor.LabelRunID: runID}}, nil))
		return res.Kubeconfig
	}
	k1 := mint("run_k1")
	if err := kubeGet(t, k1); err != nil {
		t.Fatalf("a kubeconfig before the stage: %v", err)
	}
	if got := labelsOf(t, r.db, "run_k1")[executor.LabelHubCAUses]; got != hubca.UseKubeGuard {
		t.Fatalf("the run recorded uses %q", got)
	}

	if code, out := r.step(`{"step":"stage"}`); code != http.StatusOK {
		t.Fatalf("stage: %d %v", code, out)
	}
	r.trusts(2)
	ca2 := r.ca().trust.State().Next.Serial
	k2 := mint("run_k2")
	if n := len(kubeconfigCAs(t, k2)); n != 2 {
		t.Fatalf("a kubeconfig minted during the stage carries %d CA(s), want both", n)
	}
	if err := kubeGet(t, k2); err != nil {
		t.Fatalf("a kubeconfig minted during the stage: %v", err)
	}

	code, out := r.step(`{"step":"activate"}`)
	if code != http.StatusConflict || !strings.Contains(fmt.Sprint(out["error"]), "run_k1") ||
		strings.Contains(fmt.Sprint(out["error"]), "run_k2") {
		t.Fatalf("activate with the older kubeconfig's run: %d %v", code, out)
	}
	if code, out := r.step(`{"step":"activate","force":true,"confirm":"activate"}`); code != http.StatusOK {
		t.Fatalf("forced activation: %d %v", code, out)
	}
	r.leafFrom(kg.certs, ca2)
	if err := kubeGet(t, k2); err != nil {
		t.Fatalf("the kubeconfig minted during the stage, after the activation: %v", err)
	}
	if err := kubeGet(t, k1); err == nil {
		t.Fatal("the kubeconfig minted before the stage verified a leaf from the new CA")
	}
	if code, out := r.step(`{"step":"retire_previous","confirm":"retire_previous"}`); code != http.StatusOK {
		t.Fatalf("retire: %d %v", code, out)
	}
	r.trusts(1)
	if err := kubeGet(t, k2); err != nil {
		t.Fatalf("the kubeconfig minted during the stage, after the retirement: %v", err)
	}
	if n := len(kubeconfigCAs(t, mint("run_k3"))); n != 1 {
		t.Fatalf("a kubeconfig minted after the retirement carries %d CAs, want the new one alone", n)
	}
}

// kubeconfigDoc is the part of a delivered kubeconfig a client reads.
type kubeconfigDoc struct {
	Clusters []struct {
		Cluster struct {
			Server string `yaml:"server"`
			CAData string `yaml:"certificate-authority-data"`
		} `yaml:"cluster"`
	} `yaml:"clusters"`
	Users []struct {
		User struct {
			Token string `yaml:"token"`
		} `yaml:"user"`
	} `yaml:"users"`
}

func kubeconfigCAs(t *testing.T, kc []byte) []*x509.Certificate {
	t.Helper()
	var doc kubeconfigDoc
	if err := yaml.Unmarshal(kc, &doc); err != nil || len(doc.Clusters) != 1 {
		t.Fatalf("kubeconfig: %v", err)
	}
	pemBytes, err := base64.StdEncoding.DecodeString(doc.Clusters[0].Cluster.CAData)
	if err != nil {
		t.Fatal(err)
	}
	return parsePEMs(pemBytes)
}

func parsePEMs(b []byte) []*x509.Certificate {
	var out []*x509.Certificate
	for {
		block, rest := pem.Decode(b)
		if block == nil {
			return out
		}
		b = rest
		if c, err := x509.ParseCertificate(block.Bytes); err == nil {
			out = append(out, c)
		}
	}
}

// kubeGet lists pods through the monitor with kc: with kubectl when it is
// installed, and always with a TLS client that trusts exactly the kubeconfig's
// certificate-authority-data. Either refusing is the answer.
func kubeGet(t *testing.T, kc []byte) error {
	t.Helper()
	var doc kubeconfigDoc
	if err := yaml.Unmarshal(kc, &doc); err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	for _, c := range kubeconfigCAs(t, kc) {
		pool.AddCert(c)
	}
	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}}
	req, err := http.NewRequest(http.MethodGet, doc.Clusters[0].Cluster.Server+"/api/v1/namespaces/app/pods", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+doc.Users[0].User.Token)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("the monitor answered %d: %s", resp.StatusCode, body)
	}
	kubectl, lerr := exec.LookPath("kubectl")
	if lerr != nil {
		return nil
	}
	path := filepath.Join(t.TempDir(), "kubeconfig")
	if err := os.WriteFile(path, kc, 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, kubectl, "--kubeconfig", path, "get", "--raw", "/api/v1/namespaces/app/pods")
	cmd.Env = []string{"HOME=" + filepath.Dir(path), "PATH=" + os.Getenv("PATH")}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("kubectl: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "PodList") {
		return fmt.Errorf("kubectl answered %s", out)
	}
	return nil
}
