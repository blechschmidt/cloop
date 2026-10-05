package ui

// An adopted run's egress session comes back with its counters (Task 20383):
// suspended — not closed — when its hub process stops gracefully, restored by
// the process that adopts the run under the same credential, and still counting
// against its quota; refused for good when its grant was revoked meanwhile.

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/internal/statedbtest"
	"github.com/blechschmidt/cloop/pkg/egressbroker"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

func TestAdoptedRunsEgressSessionIsRestoredWithItsCounters(t *testing.T) {
	// Swapped before the proxy starts, so its goroutines are ordered after it.
	prevHolder := leaseHolderID
	var holder atomic.Value
	holder.Store("hub_old")
	leaseHolderID = func() string { return holder.Load().(string) }
	t.Cleanup(func() { leaseHolderID = prevHolder })
	_, svc := hostEgress(t, nil)

	body := strings.Repeat("x", 600)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(origin.Close)
	port, _ := strconv.Atoi(origin.URL[strings.LastIndex(origin.URL, ":")+1:])

	project := statedbtest.Dir(t)
	grantEgress(t, svc, "project:"+project, func(r *egressbroker.GrantRequest) {
		r.Hosts, r.CIDRs, r.Ports = []string{"127.0.0.1"}, []string{"127.0.0.0/8"}, []int{port}
		r.MaxBytesDown = 1000
	})
	ex := newEgressStub("egress-restore", executor.KindLocalProcess)
	spec, egr, err := applyEgressSession(executor.Spec{Env: []string{}}, ex, project, nil, egressRun{runID: "run-e"})
	if err != nil || egr == nil {
		t.Fatalf("applyEgressSession = %v, %v", egr, err)
	}
	egr.bindHandle(ex, "h-e")
	id := egr.sess.ID
	if got := liveEgress.idsForHandle("h-e"); len(got) != 1 || got[0] != id {
		t.Fatalf("the run's owner row would name egress sessions %v", got)
	}
	client := proxyClient(t, spec.Env)
	get := func() (int, error) {
		resp, err := client.Get(origin.URL)
		if err != nil {
			return 0, err
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		return resp.StatusCode, nil
	}
	if code, err := get(); err != nil || code != http.StatusOK {
		t.Fatalf("a request before the restart = %d, %v", code, err)
	}
	moved := egr.sess.BytesDown()
	if moved < int64(len(body)) {
		t.Fatalf("the session counted %d bytes down", moved)
	}

	// The hub stops gracefully: the session is suspended, its counters in its
	// record, and the workload's credential answers nothing for now.
	suspendAllRunEgress("the hub is shutting down")
	row, err := svc.db.GetProxySession(statedb.ProxySessionEgress, id)
	if err != nil || !row.Open() || !strings.Contains(row.Counters, strconv.FormatInt(moved, 10)) {
		t.Fatalf("the suspended session's record = %+v, %v", row, err)
	}
	if svc.broker.Session(id) != nil {
		t.Fatal("a suspended session is still served")
	}

	// The process that adopts the run restores it.
	holder.Store("hub_new")
	(&Server{WorkDir: project}).restoreRunEgress(project, ex, "h-e", []string{id})
	restored := liveEgress.byHandle("h-e")
	if restored == nil || restored.sess.ID != id || restored.sess.BytesDown() != moved {
		t.Fatalf("restored = %+v", restored)
	}
	t.Cleanup(func() { restored.close("test over") })
	if row, _ := svc.db.GetProxySession(statedb.ProxySessionEgress, id); row.Holder != "hub_new" {
		t.Fatalf("record holder after the restore = %q", row.Holder)
	}
	waitEgressRow(t, project, "restored by the hub process that adopted this run")

	// The workload's own credential works again — and the quota the first
	// process half spent still binds: the second body crosses it.
	_, _ = get()
	if got := restored.sess.BytesDown(); got <= moved {
		t.Fatalf("the restored session did not count on: %d", got)
	}
	code, err := get()
	if err == nil && code == http.StatusOK {
		t.Fatalf("a request past the quota the session carried over was served (%d bytes down of 1000)",
			restored.sess.BytesDown())
	}
}

func TestEgressSessionOfARevokedGrantIsNotRestored(t *testing.T) {
	// Swapped before the proxy starts, so its goroutines are ordered after it.
	prevHolder := leaseHolderID
	var holder atomic.Value
	holder.Store("hub_old")
	leaseHolderID = func() string { return holder.Load().(string) }
	t.Cleanup(func() { leaseHolderID = prevHolder })
	_, svc := hostEgress(t, nil)

	project := statedbtest.Dir(t)
	g := grantEgress(t, svc, "project:"+project, nil)
	ex := newEgressStub("egress-revoked", executor.KindLocalProcess)
	_, egr, err := applyEgressSession(executor.Spec{Env: []string{}}, ex, project, nil, egressRun{runID: "run-r"})
	if err != nil || egr == nil {
		t.Fatalf("applyEgressSession = %v, %v", egr, err)
	}
	egr.bindHandle(ex, "h-r")
	id := egr.sess.ID
	suspendAllRunEgress("the hub is shutting down")

	// Revoked while no process serves the session.
	if err := svc.broker.Revoke(t.Context(), g.ID, "admin"); err != nil {
		t.Fatal(err)
	}
	holder.Store("hub_new")
	(&Server{WorkDir: project}).restoreRunEgress(project, ex, "h-r", []string{id})
	if liveEgress.byHandle("h-r") != nil || svc.broker.Session(id) != nil {
		t.Fatal("a session of a revoked grant was restored")
	}
	row, err := svc.db.GetProxySession(statedb.ProxySessionEgress, id)
	if err != nil || row.Open() || !strings.Contains(row.CloseReason, "revoked") {
		t.Fatalf("the refused session's record = %+v, %v", row, err)
	}
	waitEgressRow(t, project, "was not restored")
	// The broker's own denial is on the trail.
	var denied bool
	for _, ev := range controlAudit(t, svc.dir, secretbroker.ActionEgressRestore) {
		denied = denied || strings.Contains(ev.Payload, `"decision":"deny"`)
	}
	if !denied {
		t.Fatal("no denied egress.restore row")
	}
}

// TestEgressHeldRequestRetriesAPendingRestore: an egress session the adopting
// process took over but could not restore yet is tried again when the
// workload's next request arrives, and that request is served.
func TestEgressHeldRequestRetriesAPendingRestore(t *testing.T) {
	setSessionAdoptionWait(t, 20*time.Second)
	prevHolder := leaseHolderID
	var holder atomic.Value
	holder.Store("hub_old")
	leaseHolderID = func() string { return holder.Load().(string) }
	t.Cleanup(func() { leaseHolderID = prevHolder })
	_, svc := hostEgress(t, nil)

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(origin.Close)
	port, _ := strconv.Atoi(origin.URL[strings.LastIndex(origin.URL, ":")+1:])
	project := statedbtest.Dir(t)
	grantEgress(t, svc, "project:"+project, func(r *egressbroker.GrantRequest) {
		r.Hosts, r.CIDRs, r.Ports = []string{"127.0.0.1"}, []string{"127.0.0.0/8"}, []int{port}
	})
	ex := newEgressStub("egress-pending", executor.KindLocalProcess)
	spec, egr, err := applyEgressSession(executor.Spec{Env: []string{}}, ex, project, nil, egressRun{runID: "run-p"})
	if err != nil || egr == nil {
		t.Fatalf("applyEgressSession = %v, %v", egr, err)
	}
	egr.bindHandle(ex, "h-p")
	id := egr.sess.ID
	client := proxyClient(t, spec.Env)
	suspendAllRunEgress("the hub is shutting down")

	// The process that adopted the run took the record over, and its restore
	// failed for a reason that may pass.
	holder.Store("hub_new")
	if ok, err := svc.db.TakeProxySession(statedb.ProxySessionEgress, id, "hub_old", "hub_new"); err != nil || !ok {
		t.Fatalf("take the record over = %v, %v", ok, err)
	}
	addPendingEgress(id, pendingEgressRestore{workDir: project, ex: ex, handleID: "h-p"})
	t.Cleanup(func() { dropPendingEgress(id) })

	resp, err := client.Get(origin.URL)
	if err != nil {
		t.Fatalf("the workload's request = %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("the workload's request answered %d, want it served once the restore was retried", resp.StatusCode)
	}
	restored := liveEgress.byHandle("h-p")
	if restored == nil || restored.sess.ID != id {
		t.Fatalf("restored = %+v", restored)
	}
	t.Cleanup(func() { restored.close("test over") })
	pendingEgress.Lock()
	_, still := pendingEgress.m[id]
	pendingEgress.Unlock()
	if still {
		t.Fatal("a restored session is still pending")
	}
}

// TestEgressSessionOfALiveHolderIsLeftWithIt: nothing forwards egress between
// hub processes, so the process adopting a run restores its egress session
// only from a process that is gone; a live holder keeps serving it.
func TestEgressSessionOfALiveHolderIsLeftWithIt(t *testing.T) {
	prevHolder := leaseHolderID
	var holder atomic.Value
	holder.Store("hub_old")
	leaseHolderID = func() string { return holder.Load().(string) }
	t.Cleanup(func() { leaseHolderID = prevHolder })
	prevAlive := egressHolderAlive
	egressHolderAlive = func(h string) bool { return h == "hub_old" }
	t.Cleanup(func() { egressHolderAlive = prevAlive })
	_, svc := hostEgress(t, nil)

	project := statedbtest.Dir(t)
	grantEgress(t, svc, "project:"+project, nil)
	ex := newEgressStub("egress-live-holder", executor.KindLocalProcess)
	_, egr, err := applyEgressSession(executor.Spec{Env: []string{}}, ex, project, nil, egressRun{runID: "run-l"})
	if err != nil || egr == nil {
		t.Fatalf("applyEgressSession = %v, %v", egr, err)
	}
	egr.bindHandle(ex, "h-l")
	t.Cleanup(func() { egr.close("test over") })
	id := egr.sess.ID

	holder.Store("hub_new")
	(&Server{WorkDir: project}).restoreRunEgress(project, ex, "h-l", []string{id})
	row, err := svc.db.GetProxySession(statedb.ProxySessionEgress, id)
	if err != nil || row.Holder != "hub_old" || !row.Open() {
		t.Fatalf("the live holder's record after the adoption = %+v, %v", row, err)
	}
	if svc.broker.Session(id) == nil {
		t.Fatal("the live holder's session stopped being served")
	}
}
