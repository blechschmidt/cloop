package ui

// Tests for what the hub feeds the git proxy's push scan, and where it files a
// refusal (Task 20436).

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/gitproxy"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/redact"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/state"
)

// withPushScanProxy installs a running-proxy service for the test's length.
func withPushScanProxy(t *testing.T, mode gitproxy.ScanMode) *gitProxyService {
	t.Helper()
	reg, err := gitproxy.NewRegistry("https://hub.internal:8443")
	if err != nil {
		t.Fatal(err)
	}
	svc := &gitProxyService{reg: reg, baseURL: "https://hub.internal:8443", policy: gitproxy.WriteBackPolicy(),
		scanMode: mode}
	prev := gitProxySingleton.Load()
	gitProxySingleton.Store(svc)
	t.Cleanup(func() {
		gitProxySingleton.Store(prev)
		pushScans.Lock()
		pushScans.runs = map[string]*runPushScan{}
		pushScans.Unlock()
	})
	return svc
}

func mintFor(t *testing.T, svc *gitProxyService, runID, leaseID string) *gitproxy.Session {
	t.Helper()
	m, err := svc.reg.Mint(gitproxy.MintRequest{
		Upstream:   "https://github.com/acme/tool.git",
		Credential: gitproxy.Credential{Username: "x-access-token", Password: "forge-token-for-the-hub", LeaseID: leaseID},
		RunID:      runID,
	})
	if err != nil {
		t.Fatal(err)
	}
	return m.Session
}

func scanHas(scan gitproxy.PushScan, value string) bool {
	for _, s := range scan.Secrets {
		if s.Value == value {
			return true
		}
	}
	return false
}

// TestPushScanCarriesTheRunsLeaseAndSpecValues: a run's pushes are scanned for
// what its lease delivered and for what its spec declares sensitive — its
// egress session's proxy URL and password, its relay token — through every
// session that names the run or stands on its lease.
func TestPushScanCarriesTheRunsLeaseAndSpecValues(t *testing.T) {
	svc := withPushScanProxy(t, gitproxy.ScanValues)
	sl := &secretLease{lease: &secretbroker.Lease{ID: "lease_run1", Materials: []secretbroker.Material{{
		GrantID: "gr_1", SecretName: "svc-env", Kind: secretbroker.KindEnv,
		Env:          map[string]string{"SVC_KEY": "svc-key-value-0001", "CLOOP_NOTE": "not-a-credential"},
		SensitiveEnv: []string{"SVC_KEY"},
	}}}}
	spec := executor.Spec{Env: []string{
		"PATH=/usr/bin",
		"HTTPS_PROXY=http://egress_sess:egress-token-0001@hub.internal:3128",
		envAnthropicAuth + "=relay-token-value-0001",
		redact.EnvKey + "=HTTPS_PROXY," + envAnthropicAuth,
	}}
	end := registerRunPushScan("run_1", t.TempDir(), sl, spec)

	byRun := svc.pushScanFor(mintFor(t, svc, "run_1", ""))
	for _, v := range []string{"svc-key-value-0001", "http://egress_sess:egress-token-0001@hub.internal:3128",
		"egress-token-0001", "relay-token-value-0001"} {
		if !scanHas(byRun, v) {
			t.Errorf("a session naming the run is not scanned for %q", v)
		}
	}
	for _, v := range []string{"not-a-credential", "/usr/bin"} {
		if scanHas(byRun, v) {
			t.Errorf("a session is scanned for %q, which is no credential", v)
		}
	}
	if byRun.Mode != gitproxy.ScanValues {
		t.Errorf("mode = %q", byRun.Mode)
	}
	if byLease := svc.pushScanFor(mintFor(t, svc, "", "lease_run1")); !scanHas(byLease, "svc-key-value-0001") {
		t.Error("a session standing on the run's lease is not scanned for its values")
	}
	if other := svc.pushScanFor(mintFor(t, svc, "run_other", "")); len(other.Secrets) != 0 {
		t.Errorf("another run's session is scanned for %d of this run's values", len(other.Secrets))
	}

	// The run ends; the entry stays while a session names it — a
	// workspace's write-back push can come after — and goes with the last.
	end()
	if _, s := runPushScanFor(&gitproxy.Session{RunID: "run_1"}); len(s) == 0 {
		t.Fatal("the run's values went while a session still names it")
	}
	for _, sess := range svc.reg.Sessions() {
		svc.reg.Close(sess.ID, "test")
	}
	sweepRunPushScans()
	if _, s := runPushScanFor(&gitproxy.Session{RunID: "run_1"}); len(s) != 0 {
		t.Fatal("the run's values outlived the run and every session naming it")
	}
}

// TestNothingIsHeldWithoutAProxy: a hub that runs no git proxy scans no push,
// and keeps no run's values.
func TestNothingIsHeldWithoutAProxy(t *testing.T) {
	prev := gitProxySingleton.Load()
	gitProxySingleton.Store(nil)
	t.Cleanup(func() { gitProxySingleton.Store(prev) })
	registerRunPushScan("run_x", t.TempDir(), nil, executor.Spec{Env: []string{"K=v-12345678", redact.EnvKey + "=K"}})()
	pushScans.Lock()
	defer pushScans.Unlock()
	if len(pushScans.runs) != 0 {
		t.Fatalf("held %d runs' values with no proxy", len(pushScans.runs))
	}
}

// TestAnAdoptedRunScansWithWhatTheBrokerReDerives: after a hub restart the
// process that adopts the run scans with Broker.RedactionCredentials.
func TestAnAdoptedRunScansWithWhatTheBrokerReDerives(t *testing.T) {
	svc := withPushScanProxy(t, gitproxy.ScanValues)
	adoptRunPushScan("run_adopted", t.TempDir(), "lease_adopted", []secretbroker.CredentialValue{
		{Value: "re-derived-env-value-0001", GrantID: "gr_9", SecretName: "svc-env", Field: "env SVC_KEY"},
	})
	scan := svc.pushScanFor(mintFor(t, svc, "", "lease_adopted"))
	if !scanHas(scan, "re-derived-env-value-0001") {
		t.Fatalf("an adopted run's restored session is not scanned with the re-derived values: %+v", scan.Secrets)
	}
	for _, s := range scan.Secrets {
		if s.Value == "re-derived-env-value-0001" && (s.Grant != "gr_9" || s.Secret != "svc-env") {
			t.Fatalf("provenance lost: %+v", s)
		}
	}
}

func writeProjectConfig(t *testing.T, dir, yaml string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(dir, ".cloop"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".cloop", "config.yaml"), []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestAProjectMayTightenThePushScanAndNeverLoosenIt: a project's own
// executors.git_proxy.push_scan raises the hub's mode and cannot lower it; a
// project that says nothing leaves it as it is.
func TestAProjectMayTightenThePushScanAndNeverLoosenIt(t *testing.T) {
	cases := []struct {
		hub     gitproxy.ScanMode
		project string
		want    gitproxy.ScanMode
	}{
		{gitproxy.ScanValues, "off", gitproxy.ScanValues},
		{gitproxy.ScanValues, "shapes", gitproxy.ScanShapes},
		{gitproxy.ScanShapes, "values", gitproxy.ScanShapes},
		{gitproxy.ScanOff, "values", gitproxy.ScanValues},
		{gitproxy.ScanOff, "", gitproxy.ScanOff},
		{gitproxy.ScanValues, "", gitproxy.ScanValues},
	}
	for _, c := range cases {
		t.Run(fmt.Sprintf("hub %s project %q", c.hub, c.project), func(t *testing.T) {
			svc := withPushScanProxy(t, c.hub)
			dir := t.TempDir()
			yaml := "goal: x\n"
			if c.project != "" {
				yaml += "executors:\n  git_proxy:\n    push_scan: " + c.project + "\n"
			}
			writeProjectConfig(t, dir, yaml)
			registerRunPushScan("run_p", dir, nil, executor.Spec{})
			if got := svc.pushScanFor(mintFor(t, svc, "run_p", "")).Mode; got != c.want {
				t.Fatalf("mode = %q, want %q", got, c.want)
			}
		})
	}
}

// TestARefusedPushIsInTheRunsHistoryAndOnItsTask: the refusal is journaled on
// the project, bound to the task that was running, and shown as a line of that
// task's details — and none of it carries the value.
func TestARefusedPushIsInTheRunsHistoryAndOnItsTask(t *testing.T) {
	withPushScanProxy(t, gitproxy.ScanValues)
	started := time.Now().Add(-time.Minute)
	dir := setupProjectDir(t, cloopGoal, []*pm.Task{
		{ID: 1, Title: "Earlier", Status: pm.TaskDone},
		{ID: 2, Title: "Deploy config", Status: pm.TaskInProgress, StartedAt: &started},
	})
	registerRunPushScan("run_j", dir, nil, executor.Spec{})

	const value = "never-in-the-journal-0001"
	finding := gitproxy.ScanFinding{Object: strings.Repeat("ab", 20), Type: "blob", Where: "content",
		Path: "deploy.env", Commit: strings.Repeat("cd", 20), Grant: "gr_1", Secret: "svc-env", Field: "env SVC_KEY",
		Form: "as delivered"}
	journalPushScanRefusal(gitproxy.Event{
		Kind: gitproxy.EventPushSecretRefused, Scan: gitproxy.ScanResultSecret, RunID: "run_j",
		RepoPath: "acme/tool", Refs: []string{"refs/heads/cloop/run-j"},
		Detail:   "carries a credential the run was given: blob abababababab (deploy.env): env SVC_KEY (secret \"svc-env\", grant gr_1)",
		Findings: []gitproxy.ScanFinding{finding}, At: time.Now(),
	})

	rows, err := state.ListEventsOfType(dir, state.EventGitPushRefused, 10)
	if err != nil || len(rows) != 1 {
		t.Fatalf("journal rows = %+v, %v", rows, err)
	}
	if rows[0].TaskID != 2 || !strings.Contains(rows[0].Message, "deploy.env") || !strings.Contains(rows[0].Details, "gr_1") {
		t.Fatalf("journal row = %+v", rows[0])
	}
	if strings.Contains(rows[0].Message+rows[0].Details, value) {
		t.Fatal("the journal carries the value")
	}

	ts := newTestServer(t, dir, nil)
	body := apiGET(t, ts, "/api/tasks/2/details")
	task := body["task"].(map[string]interface{})
	annos, _ := task["annotations"].([]interface{})
	if len(annos) != 1 || !strings.Contains(fmt.Sprint(annos[0]), "refused a push") {
		t.Fatalf("the task's details show %v, want one line for the refused push", annos)
	}
	// The other task's details do not.
	if other := apiGET(t, ts, "/api/tasks/1/details")["task"].(map[string]interface{}); other["annotations"] != nil {
		t.Fatalf("task 1 shows %v", other["annotations"])
	}
	// And the stored task is untouched: the line is shown, not written.
	ps, err := state.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := ps.RequireTask(2); len(got.Annotations) != 0 {
		t.Fatalf("the refusal was written into the stored task: %+v", got.Annotations)
	}
}

// TestAProjectConfigTheWorkloadReplacedCannotStallTheProxy: a workload whose
// sandbox shares the project directory can put a FIFO, or a link to one,
// where config.yaml was. Reading the project's push_scan must neither block
// on it nor take it as a setting.
func TestAProjectConfigTheWorkloadReplacedCannotStallTheProxy(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".cloop"), 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, ".cloop", "config.yaml")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	read := func() (gitproxy.ScanMode, bool) {
		type res struct {
			m  gitproxy.ScanMode
			ok bool
		}
		done := make(chan res, 1)
		go func() { m, ok := projectPushScanMode(dir); done <- res{m, ok} }()
		select {
		case r := <-done:
			return r.m, r.ok
		case <-time.After(5 * time.Second):
			t.Fatal("reading the project's push_scan blocked on a FIFO")
			return "", false
		}
	}
	if _, ok := read(); ok {
		t.Fatal("a FIFO was read as a setting")
	}
	// A link to a real file that says off is not followed either.
	real := filepath.Join(t.TempDir(), "elsewhere.yaml")
	if err := os.WriteFile(real, []byte("executors:\n  git_proxy:\n    push_scan: shapes\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, path); err != nil {
		t.Fatal(err)
	}
	if _, ok := read(); ok {
		t.Fatal("a symbolic link was followed")
	}
	// An unreadable value asks for values, never for off.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	writeProjectConfig(t, dir, "executors:\n  git_proxy:\n    push_scan: strict\n")
	if m, ok := read(); !ok || m != gitproxy.ScanValues {
		t.Fatalf("an unreadable push_scan read as %q, %v", m, ok)
	}
}

// TestAnAdoptedRunsPushesAreScannedForWhatItsLeaseCarries: the hub process
// that takes a run's lease over after a restart scans the run's pushes with
// what Broker.RedactionCredentials re-derives — through the real takeover.
func TestAnAdoptedRunsPushesAreScannedForWhatItsLeaseCarries(t *testing.T) {
	withPushScanProxy(t, gitproxy.ScanValues)
	ex := newTakeoverExecutor("edge-pushscan")
	h := newTakeoverHub(t, ex.ID())
	old := h.dispatch(t, ex, "h-scan")
	ids := liveLeases.forHandle(ex.ID(), "h-scan")
	liveLeases.removeIf(old)
	h.clock.advance(2 * time.Minute)
	h.holder = "hub_adopter"
	(&Server{WorkDir: h.dir}).takeOverRunLeases(h.dir, ex, "h-scan", ids)
	if taken := registeredLease(old.lease.ID); taken != nil {
		stopKeepaliveForTest(taken)
	}
	_, secrets := runPushScanFor(&gitproxy.Session{RunID: "run_takeover"})
	found := false
	for _, s := range secrets {
		if s.Value == "takeover-credential-0123456789" && s.Field == "env CLAUDE_CODE_OAUTH_TOKEN" && s.Grant != "" {
			found = true
		}
	}
	if !found {
		t.Fatalf("the adopted run's pushes are not scanned for its lease's credential: %d values", len(secrets))
	}
	ex.finish()
}
