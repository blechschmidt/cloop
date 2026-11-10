package cluster_test

// pool_test.go: an executor pool served by a cluster of two hub members (Task
// 20482), with a real ephemeral runner.
//
// What only real processes show: a run queued on one member reaches a
// controller's feed served by the other through the shared database and the
// cluster bus, a runner minted by one member and enrolled by the other is
// handed the run another member queued, and it ends the way a controller needs
// it to — its run settled, its record retired, its process exited with
// success. Revoking the pool on one member is refused by the other at once.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// poolSnapshot is the part of a feed message this test reads.
type poolSnapshot struct {
	Type     string `json:"type"`
	Snapshot struct {
		PoolID   string `json:"pool_id"`
		Demand   int    `json:"demand"`
		Busy     int    `json:"busy"`
		Idle     int    `json:"idle"`
		Pending  int    `json:"pending"`
		Wanted   int    `json:"wanted"`
		Revision string `json:"revision"`
	} `json:"snapshot"`
}

func (w *world) poolFeed(h *hub, credential, after string, wait int) (int, poolSnapshot) {
	w.t.Helper()
	path := fmt.Sprintf("/api/pool-controller/feed?wait=%d", wait)
	if after != "" {
		path += "&after=" + after
	}
	r := w.doWith(credential, http.MethodGet, h.url(), path, nil)
	var s poolSnapshot
	_ = json.Unmarshal([]byte(r.body), &s)
	return r.status, s
}

func (w *world) createPool(h *hub, name string, maxRunners int) (id, credential string) {
	w.t.Helper()
	body, _ := json.Marshal(map[string]any{"name": name, "max_runners": maxRunners,
		"labels": map[string]string{"site": "e2e"}})
	r := w.do(http.MethodPost, h.url(), "/api/executor-pools", body)
	if r.status != http.StatusCreated {
		w.t.Fatalf("create pool %s: %d %s", name, r.status, r.body)
	}
	var created struct {
		Pool struct {
			ID string `json:"id"`
		} `json:"pool"`
	}
	_ = json.Unmarshal([]byte(r.body), &created)
	r = w.do(http.MethodPost, h.url(), "/api/executor-pools/"+created.Pool.ID+"/credentials", []byte(`{}`))
	if r.status != http.StatusCreated {
		w.t.Fatalf("mint credential: %d %s", r.status, r.body)
	}
	var cred struct {
		Token string `json:"token"`
	}
	_ = json.Unmarshal([]byte(r.body), &cred)
	return created.Pool.ID, cred.Token
}

func TestExecutorPoolOnAHubCluster(t *testing.T) {
	if os.Getenv(enableEnv) == "" {
		t.Skipf("%s is not set; this builds cloop and runs a cluster of hub processes", enableEnv)
	}
	w := newWorld(t)
	w.initProjects()
	a, b := w.startHub(), w.startHub()
	w.startLoadBalancer()
	st := w.waitCluster("two live members and a leader", func(s clusterStatus) bool {
		return s.live() == 2 && s.Leader != ""
	})
	a.id, b.id = w.memberFor(st, a.port), w.memberFor(st, b.port)

	// ── 1. Pools administered on A, their feeds served by B ───────────────
	poolID, cred := w.createPool(a, "e2e-pool", 1)
	otherID, otherCred := w.createPool(a, "other-team", 3)
	code, snap := w.poolFeed(b, cred, "", 0)
	if code != http.StatusOK || snap.Snapshot.PoolID != poolID || snap.Snapshot.Demand != 0 {
		t.Fatalf("B's feed of the pool A created: %d %+v", code, snap)
	}

	// ── 2. A run queued on A is pushed to the feed B serves ──────────────
	projIdx := w.projectIndex()
	w.bindProject(projIdx, "pool:"+poolID)
	type polled struct {
		code int
		snap poolSnapshot
		took time.Duration
	}
	pushed := make(chan polled, 1)
	began := time.Now()
	go func() {
		code, s := w.poolFeed(b, cred, snap.Snapshot.Revision, 45)
		pushed <- polled{code, s, time.Since(began)}
	}()
	time.Sleep(300 * time.Millisecond)
	if r := w.post(a, fmt.Sprintf("/api/run?project_idx=%d", projIdx)); r.status != http.StatusAccepted ||
		!strings.Contains(r.body, `"queued":true`) {
		t.Fatalf("POST /api/run on A: %d %s", r.status, r.body)
	}
	select {
	case p := <-pushed:
		if p.code != http.StatusOK || p.snap.Snapshot.Demand != 1 || p.snap.Snapshot.Wanted != 1 {
			t.Fatalf("B's long-poll answered after %s with %d %+v", p.took, p.code, p.snap)
		}
		if p.took > 20*time.Second {
			t.Fatalf("B's long-poll took %s to learn of a run queued on A", p.took)
		}
		t.Logf("the run queued on A reached B's feed after %s", p.took.Round(time.Millisecond))
	case <-time.After(50 * time.Second):
		t.Fatal("B's long-poll was never answered with the run A queued")
	}
	// Another pool learns nothing of it.
	if _, s := w.poolFeed(a, otherCred, "", 0); s.Snapshot.PoolID != otherID || s.Snapshot.Demand != 0 {
		t.Fatalf("another pool's feed shows %+v", s)
	}

	// ── 3. Runner tokens from B, within max_runners ──────────────────────
	r := w.doWith(cred, http.MethodPost, b.url(), "/api/pool-controller/runners", []byte(`{"count":2}`))
	if r.status != http.StatusConflict || !strings.Contains(r.body, "executor_pool_max_runners") {
		t.Fatalf("two runners from a pool of one: %d %s", r.status, r.body)
	}
	r = w.doWith(cred, http.MethodPost, b.url(), "/api/pool-controller/runners", []byte(`{"count":1}`))
	if r.status != http.StatusCreated {
		t.Fatalf("mint a runner on B: %d %s", r.status, r.body)
	}
	var minted struct {
		Runners []struct {
			EnrollmentID string `json:"enrollment_id"`
			Bundle       string `json:"bundle"`
		} `json:"runners"`
	}
	if err := json.Unmarshal([]byte(r.body), &minted); err != nil || len(minted.Runners) != 1 {
		t.Fatalf("runner configuration: %v %s", err, r.body)
	}

	// ── 4. The runner enrolls, takes the run, and is retired ─────────────
	bundle := filepath.Join(w.root, "runner-bundle")
	if err := os.WriteFile(bundle, []byte(minted.Runners[0].Bundle), 0o600); err != nil {
		t.Fatal(err)
	}
	runnerHome := filepath.Join(w.root, "runnerhome")
	runnerWork := filepath.Join(w.root, "runnerwork")
	for _, d := range []string{runnerHome, runnerWork} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	credPath := filepath.Join(runnerHome, "agent.json")
	runnerLog := filepath.Join(w.root, "runner.log")
	runner, exited := w.spawn(w.root, runnerLog, []string{
		"HOME=" + runnerHome,
		"PATH=" + w.binDir + string(os.PathListSeparator) + os.Getenv("PATH"),
		"NO_COLOR=1",
	}, "executor", "agent", "--token-file", bundle, "--credential", credPath, "--workdir-root", runnerWork)

	w.waitStubStarts(1)
	var runnerID string
	w.eventually("the runner to be recorded busy with the run", 30*time.Second, func() bool {
		v, err := w.queryControlPlane(`SELECT executor_id || '|' || state FROM executor_pool_runners WHERE enrollment_id = ?`,
			minted.Runners[0].EnrollmentID)
		id, state, _ := strings.Cut(v, "|")
		runnerID = id
		return err == nil && state == "busy"
	})
	if _, s := w.poolFeed(a, cred, "", 0); s.Snapshot.Busy != 1 || s.Snapshot.Demand != 0 {
		t.Fatalf("A's feed while the runner works: %+v", s)
	}
	if _, err := os.Stat(credPath); err == nil {
		t.Fatal("the ephemeral runner wrote its credential to disk")
	}
	if q, err := w.queryControlPlane(`SELECT state FROM executor_pool_queue WHERE pool_id = ? ORDER BY created_at DESC LIMIT 1`, poolID); err != nil || q != "dispatched" {
		t.Fatalf("the queued run is %q (%v), want dispatched", q, err)
	}

	if err := os.WriteFile(w.release, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	select {
	case <-exited:
	case <-time.After(120 * time.Second):
		data, _ := os.ReadFile(runnerLog)
		t.Fatalf("the runner did not exit after its run:\n%s", tail(string(data), 30))
	}
	if code := runner.ProcessState.ExitCode(); code != 0 {
		data, _ := os.ReadFile(runnerLog)
		t.Fatalf("the retired runner exited %d, want 0:\n%s", code, tail(string(data), 30))
	}
	w.eventually("the runner to be retired", 30*time.Second, func() bool {
		v, err := w.queryControlPlane(`SELECT state || '|' || retire_reason FROM executor_pool_runners WHERE executor_id = ?`, runnerID)
		return err == nil && strings.HasPrefix(v, "retired|its run settled")
	})
	if n, _ := w.queryControlPlane(`SELECT COUNT(1) FROM executors WHERE id = ?`, runnerID); n != "0" {
		t.Fatalf("the retired runner is still listed as an executor (%s rows)", n)
	}
	if revoked, _ := w.queryControlPlane(`SELECT revoked_at FROM executor_agent_credentials WHERE agent_id = ?`, runnerID); revoked == "" {
		t.Fatal("the retired runner's credential is still live")
	}
	if _, s := w.poolFeed(b, cred, "", 0); s.Snapshot.Busy != 0 || s.Snapshot.Idle != 0 || s.Snapshot.Pending != 0 {
		t.Fatalf("the pool after its runner retired: %+v", s)
	}
	for _, action := range []string{"executor_pool.create", "executor_pool.credential_mint", "executor_pool.token_mint",
		"executor_pool.runner_enroll", "executor_pool.run_queue", "executor_pool.runner_retire"} {
		if n, _ := w.queryControlPlane(`SELECT COUNT(1) FROM audit_events WHERE event_type = ?`, action); n == "0" || n == "" {
			t.Errorf("no %s row on the control plane's audit chain", action)
		}
	}

	// ── 5. Revoked on B, refused on A ────────────────────────────────────
	if r := w.do(http.MethodPost, b.url(), "/api/executor-pools/"+poolID+"/revoke", []byte(`{}`)); r.status != http.StatusOK {
		t.Fatalf("revoke on B: %d %s", r.status, r.body)
	}
	if code, _ := w.poolFeed(a, cred, "", 0); code != http.StatusUnauthorized {
		t.Fatalf("A's feed of a pool revoked on B: %d", code)
	}
	if r := w.doWith(cred, http.MethodPost, a.url(), "/api/pool-controller/runners", []byte(`{"count":1}`)); r.status != http.StatusUnauthorized {
		t.Fatalf("A minting for a pool revoked on B: %d %s", r.status, r.body)
	}
	if r := w.post(a, fmt.Sprintf("/api/run?project_idx=%d", projIdx)); r.status != http.StatusConflict ||
		!strings.Contains(r.body, "executor_pool_revoked") {
		t.Fatalf("a run of a project bound to a revoked pool: %d %s", r.status, r.body)
	}
	// The other pool is untouched.
	if code, _ := w.poolFeed(a, otherCred, "", 0); code != http.StatusOK {
		t.Fatalf("the other pool's feed after this one was revoked: %d", code)
	}
}
