package ui

// Tests for adding an executor pool in one step and watching it (Task 20486):
// the one-step create and its credential, shown once; cordon; what a
// controller says of itself and its volumes; the pool health the list
// carries; the chart route; and the guards every route here stands behind —
// RBAC, a recent sign-in, the Origin and JSON-only rules.

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/deploy/helm"
	"github.com/blechschmidt/cloop/pkg/executorpool"
	"github.com/blechschmidt/cloop/pkg/kubecontroller"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// tlsCall is r.call as a browser that reached the hub over https at host
// would: through a loopback proxy that says so, as the hub believes only
// from loopback.
func (r *poolRig) tlsCall(method, path, host string, body any) (int, map[string]any) {
	r.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, r.ts.URL+path, rd)
	if err != nil {
		r.t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", host)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		r.t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	if out == nil {
		out = map[string]any{"raw": string(raw)}
	}
	return resp.StatusCode, out
}

func TestPoolCreateInOneStepShowsTheCredentialOnce(t *testing.T) {
	r := newPoolRig(t)
	st, body := r.tlsCall(http.MethodPost, "/api/executor-pools", "127.0.0.1:8443", map[string]any{
		"name": "gpu", "max_runners": 3, "labels": map[string]string{"gpu": "a100"},
		"audience":   []map[string]string{{"kind": "group", "value": "ml-team"}, {"kind": "user", "value": "Ada@Example.com"}},
		"credential": true,
		"kubernetes": map[string]any{"min_runners": 1,
			"persistence": map[string]any{"enabled": true, "size": "50Gi", "storage_class": "fast", "reclaim_policy": "Retain"}},
	})
	if st != http.StatusCreated {
		t.Fatalf("create: %d %v", st, body)
	}
	token, _ := body["token"].(string)
	if !strings.HasPrefix(token, executorpool.CredentialPrefix) {
		t.Fatalf("no credential in the create's answer: %v", body)
	}
	pool := body["pool"].(map[string]any)
	id := pool["id"].(string)
	install := body["install"].(map[string]any)
	cmd, _ := install["command"].(string)
	for _, want := range []string{
		"kubectl apply --server-side -f - <<'EOF'", "  name: cloop-gpu\n",
		"pod-security.kubernetes.io/enforce: restricted",
		"create secret generic gpu-pool-credential",
		"--from-literal=credential=" + token,
		"helm install gpu https://127.0.0.1:8443" + kubecontroller.ChartArchivePath,
		"--set-string pool.hubURL=https://127.0.0.1:8443",
		"--set-string pool.credential.existingSecret=gpu-pool-credential",
		"--set pool.maxRunners=3", "--set pool.minRunners=1",
		"--set pool.persistence.enabled=true", "--set-string pool.persistence.size=50Gi",
		"--set-string pool.persistence.storageClassName=fast", "--set-string pool.persistence.reclaimPolicy=Retain",
		"--set-string image.tag=",
	} {
		if !strings.Contains(cmd, want) {
			t.Errorf("the install commands lack %q:\n%s", want, cmd)
		}
	}
	// The credential reaches the cluster in a Secret, never as a helm value,
	// which the release's stored manifest would keep.
	if strings.Contains(cmd, "pool.credential.value") {
		t.Errorf("the credential is a helm value:\n%s", cmd)
	}

	// The access list was written with the pool.
	st, body = r.call(http.MethodGet, "/api/executor-pools/"+id+"/audience", "", nil)
	if st != http.StatusOK || body["restricted"] != true || len(body["audience"].([]any)) != 2 {
		t.Fatalf("the pool's access list: %d %v", st, body)
	}

	// Shown once: neither the list nor the detail carries the secret.
	_, secret, err := executorpool.ParseCredential(token)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/api/executor-pools", "/api/executor-pools/" + id} {
		st, body := r.call(http.MethodGet, path, "", nil)
		raw, _ := json.Marshal(body)
		if st != http.StatusOK || bytes.Contains(raw, []byte(secret)) {
			t.Fatalf("%s: %d, carries the credential's secret: %v", path, st, bytes.Contains(raw, []byte(secret)))
		}
	}

	// The credential works: the feed answers it.
	if st, snap := r.feed(token, "", 0); st != http.StatusOK || snap.PoolID != id {
		t.Fatalf("the minted credential's feed: %d %+v", st, snap)
	}
}

func TestPoolCreateRefusesBeforeCreatingAnything(t *testing.T) {
	r := newPoolRig(t)
	cases := []struct {
		name string
		body map[string]any
	}{
		{"an unknown principal kind", map[string]any{"name": "a", "max_runners": 1, "credential": true,
			"audience": []map[string]string{{"kind": "planet", "value": "mars"}}}},
		{"an empty principal", map[string]any{"name": "b", "max_runners": 1,
			"audience": []map[string]string{{"kind": "user", "value": " "}}}},
		{"a volume size that is no quantity", map[string]any{"name": "c", "max_runners": 1, "credential": true,
			"kubernetes": map[string]any{"persistence": map[string]any{"enabled": true, "size": "lots"}}}},
		{"a volume no larger than the space a runner starts with", map[string]any{"name": "d", "max_runners": 1,
			"credential": true, "kubernetes": map[string]any{"persistence": map[string]any{"enabled": true, "size": "512Mi"}}}},
		{"min_runners above max_runners", map[string]any{"name": "e", "max_runners": 1, "credential": true,
			"kubernetes": map[string]any{"min_runners": 2}}},
		{"a namespace that is no namespace", map[string]any{"name": "f", "max_runners": 1, "credential": true,
			"kubernetes": map[string]any{"namespace": "Not_A_Namespace"}}},
		{"an invalid pool", map[string]any{"name": "Bad Name", "max_runners": 1, "credential": true}},
	}
	for _, c := range cases {
		st, body := r.tlsCall(http.MethodPost, "/api/executor-pools", "127.0.0.1:8443", c.body)
		if st != http.StatusBadRequest {
			t.Errorf("%s: %d %v, want 400", c.name, st, body)
		}
	}
	st, body := r.call(http.MethodGet, "/api/executor-pools", "", nil)
	if st != http.StatusOK || len(body["pools"].([]any)) != 0 {
		t.Fatalf("a refused create left a pool behind: %v", body)
	}
}

// Over plaintext there is no URL a controller would accept: the credential is
// still shown, with why there is no command.
func TestPoolCreateOverPlaintextGivesNoCommand(t *testing.T) {
	r := newPoolRig(t)
	st, body := r.call(http.MethodPost, "/api/executor-pools", "", map[string]any{"name": "plain", "max_runners": 1,
		"credential": true})
	if st != http.StatusCreated {
		t.Fatalf("create: %d %v", st, body)
	}
	install := body["install"].(map[string]any)
	if install["command"] != nil || !strings.Contains(install["unavailable"].(string), "HTTPS") {
		t.Fatalf("a plaintext create's install block: %v", install)
	}
	if tok, _ := body["token"].(string); !strings.HasPrefix(tok, executorpool.CredentialPrefix) {
		t.Fatalf("no credential: %v", body)
	}
}

func TestCordonHoldsThePoolAndUncordonReleasesIt(t *testing.T) {
	r := newPoolRig(t)
	id, token := r.createPool(map[string]any{"name": "held", "max_runners": 2})
	r.bind(id)
	if st, body := r.call(http.MethodPost, "/api/run", "", map[string]any{}); st != http.StatusAccepted || body["queued"] != true {
		t.Fatalf("queue a run: %d %v", st, body)
	}

	st, body := r.call(http.MethodPost, "/api/executor-pools/"+id+"/cordon", "", map[string]any{"reason": "node upgrade"})
	if st != http.StatusOK || body["changed"] != true || body["pool"].(map[string]any)["cordoned"] != true {
		t.Fatalf("cordon: %d %v", st, body)
	}
	if st, body := r.call(http.MethodPost, "/api/executor-pools/"+id+"/cordon", "", nil); st != http.StatusOK || body["changed"] != false {
		t.Fatalf("cordon twice: %d %v, want 200 and no change", st, body)
	}
	// The controller is told no demand, and is minted nothing.
	st, snap := r.feed(token, "", 0)
	if st != http.StatusOK || !snap.Cordoned || snap.Demand != 0 || snap.Wanted != 0 || snap.Waiting != 1 {
		t.Fatalf("a cordoned pool's feed: %d %+v", st, snap)
	}
	if st, body := r.call(http.MethodPost, poolRunnersPath, token, map[string]int{"count": 1}); st != http.StatusConflict ||
		body["code"] != "executor_pool_cordoned" {
		t.Fatalf("a mint for a cordoned pool: %d %v, want 409 executor_pool_cordoned", st, body)
	}
	// The run waiting says why it waits.
	if pr := r.projectPause(); pr == nil || !strings.Contains(pr.Detail, "cordoned by an administrator: node upgrade") {
		t.Fatalf("the waiting project's pause: %+v", pr)
	}
	// The list says so, and names the run that waits.
	_, list := r.call(http.MethodGet, "/api/executor-pools", "", nil)
	p := list["pools"].([]any)[0].(map[string]any)
	health := p["health"].(map[string]any)
	if p["cordoned"] != true || p["cordon_reason"] != "node upgrade" || !hasProblem(health, executorpool.ProblemCordoned) {
		t.Fatalf("a cordoned pool in the list: %v", p)
	}

	st, body = r.call(http.MethodPost, "/api/executor-pools/"+id+"/uncordon", "", nil)
	if st != http.StatusOK || body["changed"] != true || body["pool"].(map[string]any)["cordoned"] != false {
		t.Fatalf("uncordon: %d %v", st, body)
	}
	if st, snap := r.feed(token, "", 0); st != http.StatusOK || snap.Cordoned || snap.Demand != 1 {
		t.Fatalf("an uncordoned pool's feed: %d %+v", st, snap)
	}
	if st, body := r.call(http.MethodPost, poolRunnersPath, token, map[string]int{"count": 1}); st != http.StatusCreated {
		t.Fatalf("a mint after the uncordon: %d %v", st, body)
	}

	// A revoked pool is neither cordoned nor uncordoned again.
	if st, _ := r.call(http.MethodPost, "/api/executor-pools/"+id+"/revoke", "", map[string]any{}); st != http.StatusOK {
		t.Fatal("revoke")
	}
	if st, _ := r.call(http.MethodPost, "/api/executor-pools/"+id+"/cordon", "", nil); st != http.StatusConflict {
		t.Fatalf("cordon a revoked pool: %d, want 409", st)
	}

	// Each change is on the trail, and only the changes.
	db, err := statedb.Open(state.DBPath(r.dir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows, _, err := db.ListAuditEvents(statedb.AuditFilter{Limit: 500, EventType: "executor_pool.cordon"})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("%d executor_pool.cordon rows, want 2 (cordon, uncordon)", len(rows))
	}
}

func hasProblem(health map[string]any, kind string) bool {
	for _, p := range health["problems"].([]any) {
		if p.(map[string]any)["kind"] == kind {
			return true
		}
	}
	return false
}

// What a controller says of itself — its build in its User-Agent, its
// protocol in a header — and of its volumes reaches the pool list.
func TestPoolListShowsWhatItsControllerSays(t *testing.T) {
	r := newPoolRig(t)
	id, token := r.createPool(map[string]any{"name": "talkative", "max_runners": 2})
	call := func(method, path, ua, protocol string, body any) int {
		b, _ := json.Marshal(body)
		req, _ := http.NewRequest(method, r.ts.URL+path, bytes.NewReader(b))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("User-Agent", ua)
		if protocol != "" {
			req.Header.Set(executorpool.ControllerProtocolHeader, protocol)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if st := call(http.MethodGet, poolFeedPath+"?wait=0", "cloop-executor-controller/v0.0.6", "3", nil); st != http.StatusOK {
		t.Fatalf("feed: %d", st)
	}
	usage := executorpool.StorageUsage{Claims: 4, Bound: 3, Pending: 1, InUse: 2, BytesUsed: 3 << 30, BytesCapacity: 80 << 30}
	if st := call(http.MethodPost, poolStatusPath, "cloop-executor-controller/v0.0.6", "3",
		map[string]any{"healthy": false, "reason": "StoragePending", "message": "claim held-storage-0 is Pending",
			"storage": usage}); st != http.StatusOK {
		t.Fatalf("status: %d", st)
	}
	_, list := r.call(http.MethodGet, "/api/executor-pools", "", nil)
	if list["hub_protocol"].(float64) != executorpool.ControllerProtocol {
		t.Fatalf("the list's hub protocol: %v", list["hub_protocol"])
	}
	health := list["pools"].([]any)[0].(map[string]any)["health"].(map[string]any)
	ctl := health["controller"].(map[string]any)
	if ctl["version"] != "v0.0.6" || ctl["protocol"].(float64) != 3 || ctl["behind"] != true {
		t.Fatalf("the controller as listed: %v", ctl)
	}
	storage := health["storage"].(map[string]any)
	if storage["claims"].(float64) != 4 || storage["pending"].(float64) != 1 || storage["bytes_capacity"].(float64) != 80<<30 {
		t.Fatalf("the volumes as listed: %v", storage)
	}
	if !hasProblem(health, executorpool.ProblemBehind) || !hasProblem(health, executorpool.ProblemPVCsPending) {
		t.Fatalf("the problems as listed: %v", health["problems"])
	}
	// A current controller is not behind; the hub writes only the change.
	if st := call(http.MethodGet, poolFeedPath+"?wait=0", executorpool.ControllerUserAgent("v0.0.9"),
		"4", nil); st != http.StatusOK {
		t.Fatalf("feed: %d", st)
	}
	_, detail := r.call(http.MethodGet, "/api/executor-pools/"+id, "", nil)
	cred := detail["credentials"].([]any)[0].(map[string]any)
	if cred["controller_version"] != "v0.0.9" || cred["controller_protocol"].(float64) != 4 {
		t.Fatalf("the credential's controller: %v", cred)
	}
	if hasProblem(detail["health"].(map[string]any), executorpool.ProblemBehind) {
		t.Fatalf("a current controller is reported behind: %v", detail["health"])
	}
	// Counts no controller could make are refused.
	if st := call(http.MethodPost, poolStatusPath, "x", "", map[string]any{"healthy": true,
		"storage": map[string]any{"claims": 1, "bound": 5}}); st != http.StatusBadRequest {
		t.Fatalf("impossible counts: %d, want 400", st)
	}
}

// The chart is served to anyone who asks — `helm install <URL>` presents no
// credential — and is this build's chart, exactly.
func TestExecutorControllerChartIsServed(t *testing.T) {
	dir := setupProjectDir(t, "chart", nil)
	srv := New(dir, 0, "a-static-token")
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	resp, err := http.Get(ts.URL + kubecontroller.ChartArchivePath)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Type") != "application/gzip" {
		t.Fatalf("the chart without a credential: %d %s", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	want, _, err := helm.ExecutorControllerChart()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(body, want) {
		t.Fatal("the served chart is not the embedded one")
	}
	gz, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(gz)
	found := false
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		found = found || h.Name == helm.ExecutorControllerChartName+"/Chart.yaml"
	}
	if !found {
		t.Fatal("the archive holds no Chart.yaml in the chart's directory")
	}
	req, _ := http.NewRequest(http.MethodGet, ts.URL+kubecontroller.ChartArchivePath, nil)
	req.Header.Set("If-None-Match", resp.Header.Get("ETag"))
	resp2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusNotModified {
		t.Fatalf("a conditional GET of an unchanged chart: %d, want 304", resp2.StatusCode)
	}
	resp3, err := http.Post(ts.URL+kubecontroller.ChartArchivePath, "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	resp3.Body.Close()
	if resp3.StatusCode == http.StatusOK {
		t.Fatal("the chart route answers a POST")
	}
}

// The pool routes are an administrator's: RBAC refuses everyone else, and a
// session signed in too long ago is asked to sign in again for any change.
func TestPoolRoutesAreAnAdministratorsAndAskForARecentSignIn(t *testing.T) {
	h := newSudoHub(t, true)
	t.Cleanup(h.srv.closePools)
	admin := h.signIn(t, "root@example.com", false, "owners")
	st, raw := h.call(t, admin, http.MethodPost, "/api/executor-pools", map[string]any{"name": "rbac", "max_runners": 1})
	if st.StatusCode != http.StatusCreated {
		t.Fatalf("an admin's create: %d %s", st.StatusCode, raw)
	}
	var created struct {
		Pool struct{ ID string } `json:"pool"`
	}
	_ = json.Unmarshal(raw, &created)
	id := created.Pool.ID

	writes := []struct{ method, path string }{
		{http.MethodPost, "/api/executor-pools"},
		{http.MethodPost, "/api/executor-pools/" + id + "/cordon"},
		{http.MethodPost, "/api/executor-pools/" + id + "/uncordon"},
		{http.MethodPost, "/api/executor-pools/" + id + "/credentials"},
		{http.MethodPost, "/api/executor-pools/" + id + "/revoke"},
	}
	body := map[string]any{"name": "rbac2", "max_runners": 1}
	for _, who := range []struct {
		name   string
		groups []string
	}{{"a viewer", []string{"readers"}}, {"a maintainer", []string{"leads"}}} {
		c := h.signIn(t, strings.ReplaceAll(who.name, " ", "")+"@example.com", false, who.groups...)
		if resp, _ := h.call(t, c, http.MethodGet, "/api/executor-pools", nil); resp.StatusCode != http.StatusForbidden {
			t.Errorf("%s lists pools: %d, want 403", who.name, resp.StatusCode)
		}
		for _, w := range writes {
			if resp, _ := h.call(t, c, w.method, w.path, body); resp.StatusCode != http.StatusForbidden {
				t.Errorf("%s %s %s: %d, want 403", who.name, w.method, w.path, resp.StatusCode)
			}
		}
	}
	stale := h.signIn(t, "root@example.com", true, "owners")
	if resp, raw := h.call(t, stale, http.MethodGet, "/api/executor-pools", nil); resp.StatusCode != http.StatusOK {
		t.Errorf("a stale admin lists pools: %d %s, want 200 (reads ask nothing)", resp.StatusCode, raw)
	}
	for _, w := range writes {
		resp, raw := h.call(t, stale, w.method, w.path, body)
		if resp.StatusCode != http.StatusUnauthorized || reauthCode(raw) != "REAUTH_REQUIRED" {
			t.Errorf("a stale admin's %s %s: %d %s, want 401 REAUTH_REQUIRED", w.method, w.path, resp.StatusCode, raw)
		}
	}
}

// The writes stand behind the hub's Origin and JSON-only rules like every
// dashboard write: a page on another origin cannot create a pool, cordon one
// or mint a credential with an administrator's cookie.
func TestPoolWritesStandBehindTheOriginAndJSONGuards(t *testing.T) {
	r := newPoolRig(t)
	id, _ := r.createPool(map[string]any{"name": "guarded", "max_runners": 1})
	for _, path := range []string{"/api/executor-pools", "/api/executor-pools/" + id + "/cordon",
		"/api/executor-pools/" + id + "/credentials", "/api/executor-pools/" + id + "/revoke"} {
		req, _ := http.NewRequest(http.MethodPost, r.ts.URL+path, strings.NewReader(`{"name":"x","max_runners":1}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", "https://evil.example")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("a cross-origin POST %s: %d, want 403", path, resp.StatusCode)
		}
		req, _ = http.NewRequest(http.MethodPost, r.ts.URL+path, strings.NewReader(`name=x`))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, err = http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnsupportedMediaType {
			t.Errorf("a form POST %s: %d, want 415", path, resp.StatusCode)
		}
	}
	_, detail := r.call(http.MethodGet, "/api/executor-pools/"+id, "", nil)
	if detail["cordoned"] != false || len(detail["credentials"].([]any)) != 1 {
		t.Fatalf("a refused write changed the pool: %v", detail)
	}
}

// A run handed to a pool's runner leaves the project a record of the pool
// and the runner, which its tasks are read back with.
func TestPoolPlacementNamesTheRunnerOnTheTask(t *testing.T) {
	r := newPoolRig(t)
	id, token := r.createPool(map[string]any{"name": "named", "max_runners": 1})
	r.enrollRunner(token, "agent-runner-1", "member")
	store, err := r.srv.poolStore()
	if err != nil {
		t.Fatal(err)
	}
	runner, err := store.RunnerByExecutor("agent-runner-1")
	if err != nil {
		t.Fatal(err)
	}
	r.srv.recordPoolPlacement(store, r.dir, id, "agent-runner-1")

	ps, err := state.Load(r.dir)
	if err != nil {
		t.Fatal(err)
	}
	ps.PMMode = true
	ps.Plan = &pm.Plan{Goal: ps.Goal, Tasks: []*pm.Task{{ID: 1, Title: "ran on a runner", Status: pm.TaskDone,
		ExecutorID: "agent-runner-1", ExecutorKind: "remote"}, {ID: 2, Title: "ran elsewhere", ExecutorID: "local"}}}
	if err := ps.Save(); err != nil {
		t.Fatal(err)
	}
	back, err := state.LoadLite(r.dir)
	if err != nil {
		t.Fatal(err)
	}
	got := back.Plan.Tasks[0]
	if got.ExecutorPool != "named" || got.ExecutorRunner != runner.Name {
		t.Fatalf("the task's pool and runner: %q %q, want named and %s", got.ExecutorPool, got.ExecutorRunner, runner.Name)
	}
	if other := back.Plan.Tasks[1]; other.ExecutorPool != "" || other.ExecutorRunner != "" {
		t.Fatalf("a task that ran elsewhere names a pool: %+v", other)
	}

	// And the runner is drawn as its pool's in the executor list.
	views := r.srv.applyPoolRunners([]executorView{{ID: "agent-runner-1", Kind: "remote"}, {ID: "local", Kind: "localprocess"}})
	if views[0].PoolRunner == nil || views[0].PoolRunner.PoolName != "named" || views[1].PoolRunner != nil {
		t.Fatalf("the list's pool runners: %+v", views)
	}
}

// A pool change reaches every open dashboard as one executor_update a moment
// later, however many changes the moment held.
func TestPoolChangesReachTheDashboardsCoalesced(t *testing.T) {
	r := newPoolRig(t)
	prev := poolDashboardDelay
	poolDashboardDelay = 50 * time.Millisecond
	t.Cleanup(func() { poolDashboardDelay = prev })
	ch := make(chan string, 16)
	r.srv.poolDash.mu.Lock()
	r.srv.poolDash.notify = func(id string) { ch <- id }
	r.srv.poolDash.mu.Unlock()
	for i := 0; i < 5; i++ {
		r.srv.notePoolDashboard("pool-x")
	}
	select {
	case id := <-ch:
		if id != "pool-x" {
			t.Fatalf("the notice named %q", id)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no notice reached the dashboards")
	}
	select {
	case id := <-ch:
		t.Fatalf("five changes made a second notice, for %s", id)
	case <-time.After(300 * time.Millisecond):
	}
}

// Nothing is scheduled once the hub has shut down.
func TestPoolDashboardNoticesStopAtShutdown(t *testing.T) {
	r := newPoolRig(t)
	ch := make(chan string, 4)
	r.srv.poolDash.mu.Lock()
	r.srv.poolDash.notify = func(id string) { ch <- id }
	r.srv.poolDash.mu.Unlock()
	r.srv.stopPoolDashboard()
	r.srv.notePoolDashboard("pool-late")
	r.srv.poolDash.mu.Lock()
	armed := r.srv.poolDash.timer != nil
	r.srv.poolDash.mu.Unlock()
	if armed {
		t.Fatal("a notice after shutdown armed a timer")
	}
	select {
	case id := <-ch:
		t.Fatalf("a notice after shutdown reached the dashboards: %s", id)
	case <-time.After(100 * time.Millisecond):
	}
}
