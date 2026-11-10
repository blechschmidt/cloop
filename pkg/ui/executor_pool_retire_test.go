package ui

// The controller's retirement endpoint (Task 20483): the hub's record decides
// who is idle, a busy runner is never retired, a pending one is retired with
// its token, and another pool's runners are unknown.

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

func retireOutcomes(body map[string]any) map[string]string {
	out := map[string]string{}
	results, _ := body["results"].([]any)
	for _, raw := range results {
		r := raw.(map[string]any)
		out[r["enrollment_id"].(string)] = r["outcome"].(string)
	}
	return out
}

func TestTheControllerRetiresIdleAndPendingRunnersButNeverABusyOne(t *testing.T) {
	r := newPoolRig(t)
	id, token := r.createPool(map[string]any{"name": "k8s", "max_runners": 6})
	_, otherToken := r.createPool(map[string]any{"name": "other", "max_runners": 2})
	store, err := r.srv.poolStore()
	if err != nil {
		t.Fatal(err)
	}
	db := store.DB()

	mint := func(tok string) string {
		t.Helper()
		st, body := r.call(http.MethodPost, poolRunnersPath, tok, map[string]int{"count": 1})
		if st != http.StatusCreated {
			t.Fatalf("mint: %d %v", st, body)
		}
		return body["runners"].([]any)[0].(map[string]any)["enrollment_id"].(string)
	}
	pending := mint(token)
	idle := mint(token)
	busy := mint(token)
	foreign := mint(otherToken)
	if _, err := db.MarkExecutorPoolRunnerEnrolled(idle, "runner-idle", r.srv.hubInstanceID(), time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := db.MarkExecutorPoolRunnerEnrolled(busy, "runner-busy", r.srv.hubInstanceID(), time.Now()); err != nil {
		t.Fatal(err)
	}
	// Busy: handed a queued run in the store's own transaction.
	r.bind(id)
	if st, _ := r.call(http.MethodPost, "/api/run", "", map[string]any{}); st != http.StatusAccepted {
		t.Fatalf("queue a run: %d", st)
	}
	q, ok, err := db.OpenPoolQueueEntry(r.dir)
	if err != nil || !ok {
		t.Fatalf("queued run: %v %v", ok, err)
	}
	if ok, err := db.AssignPoolQueueEntry(q.ID, "runner-busy", r.srv.hubInstanceID(), time.Now()); err != nil || !ok {
		t.Fatalf("assign: %v %v", ok, err)
	}

	// The feed names each runner and its state.
	_, snap := r.feed(token, "", 0)
	states := map[string]string{}
	for _, rs := range snap.RunnerStates {
		states[rs.EnrollmentID] = rs.State
	}
	if states[pending] != statedb.PoolRunnerPending || states[idle] != statedb.PoolRunnerIdle ||
		states[busy] != statedb.PoolRunnerBusy || states[foreign] != "" {
		t.Fatalf("the feed's runner states: %v", states)
	}

	// Without the credential: refused, and nothing retired.
	if st, _ := r.call(http.MethodPost, poolRetirePath, "", map[string]any{"runners": []string{idle}}); st != http.StatusUnauthorized {
		t.Fatalf("retire without the credential: %d", st)
	}
	// A malformed request retires nothing, not even the IDs before the bad one.
	if st, _ := r.call(http.MethodPost, poolRetirePath, token, map[string]any{"runners": []string{idle, ""}}); st != http.StatusBadRequest {
		t.Fatalf("retire with an empty id: %d", st)
	}
	if row, _ := db.GetExecutorPoolRunner(idle); row.State != statedb.PoolRunnerIdle {
		t.Fatalf("a refused request retired the idle runner: %s", row.State)
	}

	st, body := r.call(http.MethodPost, poolRetirePath, token, map[string]any{
		"runners": []string{pending, idle, busy, foreign, "no-such-runner"}})
	if st != http.StatusOK {
		t.Fatalf("retire: %d %v", st, body)
	}
	got := retireOutcomes(body)
	want := map[string]string{pending: "retired", idle: "retired", busy: "busy", foreign: "unknown", "no-such-runner": "unknown"}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("runner %s: outcome %q, want %q (all: %v)", k, got[k], v, got)
		}
	}
	if row, _ := db.GetExecutorPoolRunner(busy); row.State != statedb.PoolRunnerBusy {
		t.Fatalf("the busy runner is %s after a retirement request", row.State)
	}
	if row, _ := db.GetExecutorPoolRunner(foreign); row.State != statedb.PoolRunnerPending {
		t.Fatalf("another pool's runner is %s after this pool's request", row.State)
	}
	// The pending runner's token cannot be redeemed afterwards.
	if err := store.AdmitRunner(pending); err == nil {
		t.Fatal("a retired pending runner's token is still admitted")
	}
	tok, err := db.GetEnrollmentToken(pending)
	if err != nil || tok.RevokedAt.IsZero() {
		t.Fatalf("the retired pending runner's token: %+v %v", tok, err)
	}
	// Retiring them again finds them gone.
	_, body = r.call(http.MethodPost, poolRetirePath, token, map[string]any{"runners": []string{pending, idle}})
	if got := retireOutcomes(body); got[pending] != "gone" || got[idle] != "gone" {
		t.Fatalf("a second retirement: %v", got)
	}
	// The feed no longer counts them; the busy runner remains.
	_, snap = r.feed(token, "", 0)
	if snap.Busy != 1 || snap.Idle != 0 || snap.Pending != 0 || len(snap.RunnerStates) != 1 {
		t.Fatalf("the feed after the retirement: %+v", snap)
	}
	if metrics := r.srv.gatherMetrics(); !strings.Contains(metrics,
		`cloop_executor_pool_runners_retired_total{reason="scaled_down"} 2`) {
		t.Errorf("metrics lack the scaled_down retirements")
	}
}

// ephemeralStub is a registered runner executor with no agent behind it.
type ephemeralStub struct{ stubExecutor }

func (e *ephemeralStub) ID() string      { return "runner-raced" }
func (e *ephemeralStub) Ephemeral() bool { return true }

// A runner retired between its enrollment and its handshake — a controller
// scaling down the moment the feed showed it idle — is retired again when the
// handshake completes, and the records the connect wrote are dropped, instead
// of it sitting connected and forgotten.
func TestARunnerRetiredBeforeItsHandshakeIsRetiredOnConnect(t *testing.T) {
	r := newPoolRig(t)
	_, token := r.createPool(map[string]any{"name": "k8s", "max_runners": 2})
	r.enrollRunner(token, "runner-raced", r.srv.hubInstanceID())
	store, err := r.srv.poolStore()
	if err != nil {
		t.Fatal(err)
	}
	if retired, err := store.RetireRunner("runner-raced", "its controller scaled the pool down",
		statedb.PoolRunnerIdle); err != nil || !retired {
		t.Fatalf("retire: %v %v", retired, err)
	}
	if err := executor.DefaultRegistry.Register(&ephemeralStub{}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { executor.DefaultRegistry.Unregister("runner-raced") })

	r.srv.poolRunnerConnected(remote.AgentRecord{AgentID: "runner-raced"})
	if _, err := executor.Get("runner-raced"); err == nil {
		t.Fatal("a retired runner that connected is still a registered executor")
	}
	if row, _ := store.RunnerByExecutor("runner-raced"); row.State != statedb.PoolRunnerRetired {
		t.Fatalf("the runner is %s", row.State)
	}
}
