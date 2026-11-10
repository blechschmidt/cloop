package ui

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
	"github.com/blechschmidt/cloop/pkg/executorpool"
	"github.com/blechschmidt/cloop/pkg/pausereason"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// poolRig is a hub with its project, for the executor pool tests.
type poolRig struct {
	t   *testing.T
	dir string
	srv *Server
	ts  *httptest.Server
}

func newPoolRig(t *testing.T) *poolRig {
	t.Helper()
	dir := setupProjectDir(t, "executor pool project", nil)
	srv := New(dir, 0, "")
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	t.Cleanup(srv.closePools)
	t.Cleanup(func() { executor.DefaultRegistry.Unbind(dir) })
	return &poolRig{t: t, dir: dir, srv: srv, ts: ts}
}

// call makes a request with a JSON body (nil for none) and a bearer
// credential ("" for none), returning the status and the decoded body.
func (r *poolRig) call(method, path, bearer string, body any) (int, map[string]any) {
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
	if body != nil || method != http.MethodGet {
		req.Header.Set("Content-Type", "application/json")
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		r.t.Fatalf("%s %s: %v", method, path, err)
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

// createPool creates a pool and mints its controller credential.
func (r *poolRig) createPool(spec map[string]any) (id, credential string) {
	r.t.Helper()
	st, body := r.call(http.MethodPost, "/api/executor-pools", "", spec)
	if st != http.StatusCreated {
		r.t.Fatalf("create pool: %d %v", st, body)
	}
	id = body["pool"].(map[string]any)["id"].(string)
	st, body = r.call(http.MethodPost, "/api/executor-pools/"+id+"/credentials", "", map[string]any{})
	if st != http.StatusCreated {
		r.t.Fatalf("mint credential: %d %v", st, body)
	}
	return id, body["token"].(string)
}

// feed long-polls the pool's feed.
func (r *poolRig) feed(credential, after string, wait int) (int, executorpool.Snapshot) {
	r.t.Helper()
	path := poolFeedPath + "?wait=" + strconv.Itoa(wait)
	if after != "" {
		path += "&after=" + after
	}
	st, body := r.call(http.MethodGet, path, credential, nil)
	var msg poolFeedMessage
	raw, _ := json.Marshal(body)
	_ = json.Unmarshal(raw, &msg)
	return st, msg.Snapshot
}

func (r *poolRig) bind(poolID string) {
	r.t.Helper()
	st, body := r.call(http.MethodPost, "/api/projects/0/executor", "", map[string]any{"executor_id": "pool:" + poolID})
	if st != http.StatusOK {
		r.t.Fatalf("bind the project to the pool: %d %v", st, body)
	}
}

func (r *poolRig) projectPause() *pausereason.Reason {
	r.t.Helper()
	st, err := state.LoadLite(r.dir)
	if err != nil {
		r.t.Fatal(err)
	}
	if st.Status != "paused" {
		return nil
	}
	return st.PauseReason
}

func TestExecutorPoolAdminAPI(t *testing.T) {
	r := newPoolRig(t)
	spec := map[string]any{"name": "k8s-gpu", "max_runners": 4, "labels": map[string]string{"gpu": "a100"},
		"capabilities": map[string]any{"harnesses": []string{"claude"}}}
	st, body := r.call(http.MethodPost, "/api/executor-pools", "", spec)
	if st != http.StatusCreated {
		t.Fatalf("create: %d %v", st, body)
	}
	id := body["pool"].(map[string]any)["id"].(string)
	if st, _ := r.call(http.MethodPost, "/api/executor-pools", "", spec); st != http.StatusConflict {
		t.Fatalf("a second pool of the same name: %d, want 409", st)
	}
	if st, _ := r.call(http.MethodPost, "/api/executor-pools", "", map[string]any{"name": "Bad Name", "max_runners": 1}); st != http.StatusBadRequest {
		t.Fatalf("an invalid pool: %d, want 400", st)
	}

	st, body = r.call(http.MethodGet, "/api/executor-pools", "", nil)
	if st != http.StatusOK || len(body["pools"].([]any)) != 1 {
		t.Fatalf("list: %d %v", st, body)
	}
	st, body = r.call(http.MethodPut, "/api/executor-pools/"+id, "", map[string]any{"name": "k8s-gpu", "max_runners": 8})
	if st != http.StatusOK || body["pool"].(map[string]any)["max_runners"].(float64) != 8 {
		t.Fatalf("update: %d %v", st, body)
	}

	st, body = r.call(http.MethodPost, "/api/executor-pools/"+id+"/credentials", "", map[string]any{})
	if st != http.StatusCreated {
		t.Fatalf("mint credential: %d %v", st, body)
	}
	token := body["token"].(string)
	credID := body["credential"].(map[string]any)["id"].(string)
	if !strings.HasPrefix(token, executorpool.CredentialPrefix) || body["feed_url"] == nil {
		t.Fatalf("credential response %v", body)
	}
	st, body = r.call(http.MethodGet, "/api/executor-pools/"+id, "", nil)
	if st != http.StatusOK {
		t.Fatalf("detail: %d %v", st, body)
	}
	if raw, _ := json.Marshal(body); bytes.Contains(raw, []byte(strings.SplitN(strings.TrimPrefix(token, executorpool.CredentialPrefix), ".", 2)[1])) {
		t.Fatal("the pool's detail carries its credential's secret")
	}

	st, body = r.call(http.MethodPost, "/api/executor-pools/"+id+"/audience", "", map[string]string{"kind": "group", "value": "gpu-team"})
	if st != http.StatusOK || body["restricted"] != true {
		t.Fatalf("admit: %d %v", st, body)
	}
	if st, _ := r.call(http.MethodPost, "/api/executor-pools/"+id+"/audience", "", map[string]string{"kind": "planet", "value": "x"}); st != http.StatusBadRequest {
		t.Fatalf("an unknown principal kind: %d, want 400", st)
	}
	st, body = r.call(http.MethodDelete, "/api/executor-pools/"+id+"/audience", "", map[string]string{"kind": "group", "value": "gpu-team"})
	if st != http.StatusOK || body["restricted"] != false {
		t.Fatalf("withdraw: %d %v", st, body)
	}

	if st, _ := r.call(http.MethodDelete, "/api/executor-pools/"+id+"/credentials/"+credID, "", nil); st != http.StatusOK {
		t.Fatalf("revoke credential: %d", st)
	}
	if st, _ := r.feed(token, "", 0); st != http.StatusUnauthorized {
		t.Fatalf("feed with a revoked credential: %d, want 401", st)
	}

	st, body = r.call(http.MethodPost, "/api/executor-pools/"+id+"/revoke", "", map[string]any{})
	if st != http.StatusOK {
		t.Fatalf("revoke: %d %v", st, body)
	}
	if st, _ := r.call(http.MethodPost, "/api/executor-pools/"+id+"/revoke", "", map[string]any{}); st != http.StatusConflict {
		t.Fatalf("revoke twice: %d, want 409", st)
	}
	if st, _ := r.call(http.MethodPost, "/api/executor-pools/"+id+"/credentials", "", map[string]any{}); st != http.StatusConflict {
		t.Fatalf("credential for a revoked pool: %d, want 409", st)
	}
	if st, _ := r.call(http.MethodGet, "/api/executor-pools/pool-doesnotexist", "", nil); st != http.StatusNotFound {
		t.Fatalf("an unknown pool: %d, want 404", st)
	}

	// Every change was recorded on the control plane's chain.
	db, err := statedb.Open(state.DBPath(r.dir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows, _, err := db.ListAuditEvents(statedb.AuditFilter{Limit: 200})
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, ev := range rows {
		seen[ev.EventType] = true
	}
	for _, want := range []string{"executor_pool.create", "executor_pool.update", "executor_pool.credential_mint",
		"executor_pool.audience", "executor_pool.credential_revoke", "executor_pool.revoke"} {
		if !seen[want] {
			t.Errorf("no %s row in the audit trail", want)
		}
	}
}

func TestPoolControllerRefusesAnythingButItsCredential(t *testing.T) {
	r := newPoolRig(t)
	id, token := r.createPool(map[string]any{"name": "k8s", "max_runners": 2})
	_, otherSecret, _ := executorpool.ParseCredential(token)
	credID, _, _ := executorpool.ParseCredential(token)
	for name, bearer := range map[string]string{
		"none":           "",
		"static token":   "not-a-pool-credential",
		"wrong secret":   executorpool.CredentialPrefix + credID + "." + strings.Repeat("A", len(otherSecret)),
		"unknown id":     executorpool.CredentialPrefix + "unknownunknownun." + otherSecret,
		"enrollment tok": "clet1.abc.defdefdefdef.ghi",
	} {
		if st, _ := r.feed(bearer, "", 0); st != http.StatusUnauthorized {
			t.Errorf("%s: feed = %d, want 401", name, st)
		}
		if st, _ := r.call(http.MethodPost, poolRunnersPath, bearer, map[string]int{"count": 1}); st != http.StatusUnauthorized {
			t.Errorf("%s: runners = %d, want 401", name, st)
		}
	}
	// The credential in a query parameter, which proxies log, is not read.
	if st, _ := r.call(http.MethodGet, poolFeedPath+"?token="+token, "", nil); st != http.StatusUnauthorized {
		t.Errorf("credential in the query: %d, want 401", st)
	}
	if st, _ := r.feed(token, "", 0); st != http.StatusOK {
		t.Fatalf("the real credential: %d", st)
	}
	_ = id
}

func TestPoolControllerMintsWithinMaxRunners(t *testing.T) {
	r := newPoolRig(t)
	_, token := r.createPool(map[string]any{"name": "k8s", "max_runners": 2, "labels": map[string]string{"site": "lab"}})

	st, body := r.call(http.MethodPost, poolRunnersPath, token, map[string]int{"count": 2})
	if st != http.StatusCreated {
		t.Fatalf("mint 2: %d %v", st, body)
	}
	runners := body["runners"].([]any)
	if len(runners) != 2 {
		t.Fatalf("got %d runner configurations", len(runners))
	}
	for _, raw := range runners {
		cfg := raw.(map[string]any)
		tok := cfg["token"].(string)
		if !remote.IsRunnerToken(tok) || cfg["ephemeral"] != true {
			t.Fatalf("runner configuration %v", cfg)
		}
		b, err := remote.DecodeBundle(cfg["bundle"].(string))
		if err != nil || b.Token != tok || !strings.HasSuffix(b.Server, executorConnectPath) {
			t.Fatalf("bundle %+v, %v", b, err)
		}
		exp, _ := time.Parse(time.RFC3339Nano, cfg["expires_at"].(string))
		if until := time.Until(exp); until <= 0 || until > remote.MaxRunnerTTL {
			t.Fatalf("token valid for %s", until)
		}
	}
	st, body = r.call(http.MethodPost, poolRunnersPath, token, map[string]int{"count": 1})
	if st != http.StatusConflict || body["code"] != "executor_pool_max_runners" {
		t.Fatalf("mint past max_runners: %d %v", st, body)
	}
	for _, bad := range []map[string]int{{"count": 0}, {"count": executorpool.MaxRunnersPerRequest + 1},
		{"count": 1, "ttl_seconds": int(remote.MaxRunnerTTL/time.Second) + 1}} {
		if st, _ := r.call(http.MethodPost, poolRunnersPath, token, bad); st != http.StatusBadRequest {
			t.Errorf("mint %v: %d, want 400", bad, st)
		}
	}
	metrics := r.srv.gatherMetrics()
	for _, want := range []string{`cloop_executor_pool_mint_refusals_total{reason="max_runners"}`,
		`cloop_executor_pool_runners{state="pending"} 2`, "cloop_executor_pool_runners_minted_total"} {
		if !strings.Contains(metrics, want) {
			t.Errorf("metrics lack %s", want)
		}
	}
}

func TestPoolRunIsQueuedAndTheFeedIsPushed(t *testing.T) {
	r := newPoolRig(t)
	id, token := r.createPool(map[string]any{"name": "k8s", "max_runners": 3})
	other, otherToken := r.createPool(map[string]any{"name": "other-team", "max_runners": 3})
	r.bind(id)

	st, snap := r.feed(token, "", 0)
	if st != http.StatusOK || snap.Demand != 0 || snap.PoolID != id {
		t.Fatalf("feed before the run: %d %+v", st, snap)
	}

	// A long-poll waiting for a change is answered when the run is queued,
	// not when its wait runs out.
	type polled struct {
		st   int
		snap executorpool.Snapshot
		at   time.Duration
	}
	got := make(chan polled, 1)
	start := time.Now()
	go func() {
		st, s := r.feed(token, snap.Revision, 30)
		got <- polled{st, s, time.Since(start)}
	}()
	time.Sleep(200 * time.Millisecond)

	st, body := r.call(http.MethodPost, "/api/run", "", map[string]any{})
	if st != http.StatusAccepted || body["queued"] != true || body["pool_id"] != id {
		t.Fatalf("POST /api/run on a pool-bound project: %d %v", st, body)
	}
	select {
	case p := <-got:
		if p.st != http.StatusOK || p.snap.Demand != 1 || p.snap.Wanted != 1 || p.at > 10*time.Second {
			t.Fatalf("pushed snapshot after %s: %d %+v", p.at, p.st, p.snap)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("the long-poll was not answered when the run was queued")
	}
	if pr := r.projectPause(); pr == nil || pr.Code != pausereason.CodePoolCapacity ||
		!strings.Contains(pr.Detail, "waiting for pool capacity") {
		t.Fatalf("the project's pause reason is %+v, want pool_capacity", pr)
	}

	// Another pool learns nothing of it.
	if _, s := r.feed(otherToken, "", 0); s.Demand != 0 || s.PoolID != other {
		t.Fatalf("another pool's feed shows %+v", s)
	}

	// One queued run per project.
	st, body = r.call(http.MethodPost, "/api/run", "", map[string]any{})
	if st != http.StatusConflict || body["code"] != "executor_pool_run_queued" {
		t.Fatalf("a second run: %d %v", st, body)
	}
	// Anything else dispatched to the project is told why it cannot run.
	if _, err := executor.Resolve(r.dir); err == nil {
		t.Fatal("Resolve handed out an executor for a pool-bound project")
	}

	// Stop takes it out of the queue.
	st, body = r.call(http.MethodPost, "/api/stop", "", map[string]any{})
	if st != http.StatusOK || body["ok"] != true {
		t.Fatalf("stop: %d %v", st, body)
	}
	if pr := r.projectPause(); pr == nil || pr.Code != pausereason.CodeOperator {
		t.Fatalf("after stop the pause reason is %+v", pr)
	}
	if _, s := r.feed(token, "", 0); s.Demand != 0 {
		t.Fatalf("demand after the run was stopped: %+v", s)
	}
}

func TestPoolFeedOverWebSocketEndsWhenRevoked(t *testing.T) {
	r := newPoolRig(t)
	id, token := r.createPool(map[string]any{"name": "k8s", "max_runners": 2})
	r.bind(id)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	wsURL := "ws" + strings.TrimPrefix(r.ts.URL, "http") + poolFeedPath
	conn, resp, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{
		HTTPHeader: http.Header{"Authorization": []string{"Bearer " + token}}})
	if err != nil {
		t.Fatalf("dial the feed: %v (%v)", err, resp)
	}
	defer conn.CloseNow() //nolint:errcheck
	read := func() poolFeedMessage {
		t.Helper()
		_, data, err := conn.Read(ctx)
		if err != nil {
			t.Fatalf("read the feed: %v", err)
		}
		var m poolFeedMessage
		if err := json.Unmarshal(data, &m); err != nil {
			t.Fatal(err)
		}
		return m
	}
	if m := read(); m.Type != "snapshot" || m.Snapshot.Demand != 0 || m.Pool.Name != "k8s" {
		t.Fatalf("first message %+v", m)
	}
	if st, _ := r.call(http.MethodPost, "/api/run", "", map[string]any{}); st != http.StatusAccepted {
		t.Fatalf("queue a run: %d", st)
	}
	if m := read(); m.Snapshot.Demand != 1 {
		t.Fatalf("after a run was queued: %+v", m)
	}
	if st, _ := r.call(http.MethodPost, "/api/executor-pools/"+id+"/revoke", "", map[string]any{}); st != http.StatusOK {
		t.Fatal("revoke")
	}
	for {
		m := read()
		if m.Type == "revoked" {
			break
		}
	}
	if _, _, err := conn.Read(ctx); websocket.CloseStatus(err) != websocket.StatusPolicyViolation {
		t.Fatalf("the feed of a revoked pool closed with %v", err)
	}
	// The queued run was cancelled with the pool, and its project says why.
	if pr := r.projectPause(); pr == nil || pr.Code != pausereason.CodeAbort || !strings.Contains(pr.Detail, "revoked") {
		t.Fatalf("after revocation the pause reason is %+v", pr)
	}
	if st, _ := r.call(http.MethodPost, poolRunnersPath, token, map[string]int{"count": 1}); st != http.StatusUnauthorized {
		t.Fatalf("mint after revocation: %d", st)
	}
	// A run of a project bound to a revoked pool is refused, not queued.
	if st, body := r.call(http.MethodPost, "/api/run", "", map[string]any{}); st != http.StatusConflict || body["code"] != "executor_pool_revoked" {
		t.Fatalf("run on a revoked pool: %d %v", st, body)
	}
}

func TestPoolBindingRefusesAPoolThatCannotRunTheProject(t *testing.T) {
	r := newPoolRig(t)
	id, _ := r.createPool(map[string]any{"name": "plain", "max_runners": 2})
	// The project asks for a hypervisor; the pool's runners declare none.
	if err := os.WriteFile(filepath.Join(r.dir, ".cloop", "sandbox.yaml"),
		[]byte("capabilities:\n  virtualized: true\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	st, body := r.call(http.MethodPost, "/api/projects/0/executor", "", map[string]any{"executor_id": "pool:" + id})
	if st != http.StatusConflict {
		t.Fatalf("binding to a pool that cannot run the project: %d %v", st, body)
	}
	if st, _ := r.call(http.MethodPost, "/api/projects/0/executor", "", map[string]any{"executor_id": "pool:pool-nosuchpool"}); st != http.StatusNotFound {
		t.Fatalf("binding to an unknown pool: %d, want 404", st)
	}
}

// A pool's runner is never bound, defaulted to or dispatched to by name: that
// would be a way round the pool's access list and its queue.
func TestARunnerIsNeverBoundByName(t *testing.T) {
	r := newPoolRig(t)
	runner, err := remote.NewExecutor(remote.Options{ID: "runner-by-name", Name: "pool-runner", Ephemeral: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := executor.DefaultRegistry.Ensure(runner); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { executor.DefaultRegistry.Unregister(runner.ID()) })
	if executor.DefaultRegistry.DefaultID() == runner.ID() {
		t.Fatal("a runner became the registry's default executor")
	}

	st, body := r.call(http.MethodPost, "/api/projects/0/executor", "", map[string]any{"executor_id": runner.ID()})
	if st != http.StatusConflict || body["code"] != "executor_is_pool_runner" {
		t.Fatalf("binding a project to a runner by name: %d %v", st, body)
	}
	// However the binding got there, it resolves to nothing.
	if err := executor.Bind(r.dir, runner.ID()); err != nil {
		t.Fatal(err)
	}
	if _, err := executor.Resolve(r.dir); !errors.Is(err, executor.ErrEphemeralRunner) {
		t.Fatalf("Resolve of a project bound to a runner = %v, want ErrEphemeralRunner", err)
	}
	if _, _, err := startWorkloadAs(nil, nil, "", r.dir, []string{"true"}, nil); !errors.Is(err, executor.ErrEphemeralRunner) {
		t.Fatalf("a dispatch to a project bound to a runner = %v", err)
	}
}

// enrollRunner mints one runner of the pool and records it enrolled as
// executorID on member, as the agent endpoint would.
func (r *poolRig) enrollRunner(token, executorID, member string) {
	r.t.Helper()
	st, body := r.call(http.MethodPost, poolRunnersPath, token, map[string]int{"count": 1})
	if st != http.StatusCreated {
		r.t.Fatalf("mint: %d %v", st, body)
	}
	enrollment := body["runners"].([]any)[0].(map[string]any)["enrollment_id"].(string)
	store, err := r.srv.poolStore()
	if err != nil {
		r.t.Fatal(err)
	}
	if _, err := store.DB().MarkExecutorPoolRunnerEnrolled(enrollment, executorID, member, time.Now()); err != nil {
		r.t.Fatal(err)
	}
}

// A hand-over whose member died, or that never finished, is not left holding
// the run, the runner and the slot for ever.
func TestTheJanitorReclaimsAStuckHandOver(t *testing.T) {
	r := newPoolRig(t)
	id, token := r.createPool(map[string]any{"name": "k8s", "max_runners": 4})
	r.bind(id)
	store, err := r.srv.poolStore()
	if err != nil {
		t.Fatal(err)
	}
	db := store.DB()
	if st, _ := r.call(http.MethodPost, "/api/run", "", map[string]any{}); st != http.StatusAccepted {
		t.Fatalf("queue a run: %d", st)
	}
	q, ok, err := db.OpenPoolQueueEntry(r.dir)
	if err != nil || !ok {
		t.Fatalf("the queued run: %v %v", ok, err)
	}

	// Handed to a runner by a member that has since gone away, and never
	// started: the janitor puts it back in the queue and retires the runner.
	r.enrollRunner(token, "runner-gone-1", "member-gone")
	if ok, err := db.AssignPoolQueueEntry(q.ID, "runner-gone-1", "member-gone", time.Now()); err != nil || !ok {
		t.Fatalf("assign: %v %v", ok, err)
	}
	r.srv.poolJanitorPass(time.Now())
	got, err := db.GetPoolQueueEntry(q.ID)
	if err != nil || got.State != statedb.PoolQueueWaiting || got.Attempts != 1 {
		t.Fatalf("after the janitor the run is %+v (%v), want waiting again after one attempt", got, err)
	}
	if rr, _ := store.RunnerByExecutor("runner-gone-1"); rr.State != statedb.PoolRunnerRetired {
		t.Fatalf("the runner of the lost hand-over is %s, want retired", rr.State)
	}
	if _, s := r.feed(token, "", 0); s.Demand != 1 || s.Busy != 0 {
		t.Fatalf("the pool after the reclaim: %+v", s)
	}

	// Lost on runner after runner until it runs out of attempts: then it
	// fails, and its project says so.
	for i := 2; i <= 3; i++ {
		runner := fmt.Sprintf("runner-gone-%d", i)
		r.enrollRunner(token, runner, "member-gone")
		if ok, err := db.AssignPoolQueueEntry(q.ID, runner, "member-gone", time.Now()); err != nil || !ok {
			t.Fatalf("assign %d: %v %v", i, ok, err)
		}
		r.srv.poolJanitorPass(time.Now())
	}
	got, _ = db.GetPoolQueueEntry(q.ID)
	if got.State != statedb.PoolQueueFailed || got.Attempts != executorpool.MaxRunAttempts {
		t.Fatalf("after %d lost hand-overs the run is %s, want failed", got.Attempts, got.State)
	}
	if pr := r.projectPause(); pr == nil || pr.Code != pausereason.CodeAbort {
		t.Fatalf("the project after its run failed: %+v", pr)
	}
}

// A queued run whose member died while starting it can be stopped.
func TestStopCancelsAnOrphanedHandOver(t *testing.T) {
	r := newPoolRig(t)
	id, token := r.createPool(map[string]any{"name": "k8s", "max_runners": 2})
	r.bind(id)
	store, _ := r.srv.poolStore()
	if st, _ := r.call(http.MethodPost, "/api/run", "", map[string]any{}); st != http.StatusAccepted {
		t.Fatal("queue a run")
	}
	q, _, _ := store.DB().OpenPoolQueueEntry(r.dir)
	r.enrollRunner(token, "runner-orphaned", "member-gone")
	if ok, _ := store.DB().AssignPoolQueueEntry(q.ID, "runner-orphaned", "member-gone", time.Now()); !ok {
		t.Fatal("assign")
	}
	st, body := r.call(http.MethodPost, "/api/stop", "", map[string]any{})
	if st != http.StatusOK || body["ok"] != true {
		t.Fatalf("stop an orphaned hand-over: %d %v", st, body)
	}
	if got, _ := store.DB().GetPoolQueueEntry(q.ID); got.State != statedb.PoolQueueCancelled {
		t.Fatalf("the run is %s, want cancelled", got.State)
	}
	if rr, _ := store.RunnerByExecutor("runner-orphaned"); rr.State != statedb.PoolRunnerRetired {
		t.Fatalf("the orphaned hand-over's runner is %s, want retired", rr.State)
	}
}
