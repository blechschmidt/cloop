package ui

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executorpool"
	"github.com/blechschmidt/cloop/pkg/hubcluster"
	"github.com/blechschmidt/cloop/pkg/pausereason"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

func TestPickPoolRunnerNeverHandsOneProjectsDataToAnother(t *testing.T) {
	const web, api = "prj-web", "prj-api"
	for _, c := range []struct {
		name       string
		holds      []string
		tenant     string
		mayUseHeld bool
		want       int
	}{
		{"the runner holding the project's data first", []string{"", api, web}, web, true, 2},
		{"a clean runner when none holds it", []string{api, ""}, web, true, 1},
		{"never a runner holding another project's", []string{api, api}, web, true, -1},
		{"a starter who may not read the project gets a clean one", []string{web, ""}, web, false, 1},
		{"…or waits", []string{web}, web, false, -1},
		{"an unnamed project goes to a clean runner only", []string{web, ""}, "", true, 1},
		{"…or waits", []string{web}, "", true, -1},
		{"no runners", nil, web, true, -1},
	} {
		if got := pickPoolRunner(c.holds, c.tenant, c.mayUseHeld); got != c.want {
			t.Errorf("%s: picked %d, want %d", c.name, got, c.want)
		}
	}
}

// TestPoolControllerMintsRunnersHoldingAProject is the mint half of the
// storage contract: the hub records and echoes what each runner holds, and
// refuses what is not a tenant.
func TestPoolControllerMintsRunnersHoldingAProject(t *testing.T) {
	r := newPoolRig(t)
	id, token := r.createPool(map[string]any{"name": "k8s", "max_runners": 5})
	r.bind(id)
	if st, _ := r.call(http.MethodPost, "/api/run", "", map[string]any{}); st != http.StatusAccepted {
		t.Fatalf("queue a run: %d", st)
	}
	_, snap := r.feed(token, "", 0)
	if len(snap.QueuedProjects) != 1 || snap.QueuedProjects[0].Queued != 1 || !executorpool.ValidTenant(snap.QueuedProjects[0].Tenant) {
		t.Fatalf("queued projects %+v", snap.QueuedProjects)
	}
	tenant := snap.QueuedProjects[0].Tenant
	if want := executorpool.ProjectTenant(id, r.dir, ""); tenant != want {
		t.Fatalf("the feed names the project %s, want %s", tenant, want)
	}

	st, body := r.call(http.MethodPost, poolRunnersPath, token, map[string]any{"count": 2, "holds": []string{tenant, ""}})
	if st != http.StatusCreated {
		t.Fatalf("mint: %d %v", st, body)
	}
	runners := body["runners"].([]any)
	if h, _ := runners[0].(map[string]any)["holds"].(string); h != tenant {
		t.Fatalf("the first runner echoes holds %q", h)
	}
	if _, has := runners[1].(map[string]any)["holds"]; has {
		t.Fatalf("a runner holding nothing echoes %v", runners[1])
	}
	_, snap = r.feed(token, "", 0)
	got := map[string]string{}
	for _, rs := range snap.RunnerStates {
		got[rs.EnrollmentID] = rs.Holds
	}
	if got[runners[0].(map[string]any)["enrollment_id"].(string)] != tenant {
		t.Fatalf("the feed's runner states %+v", snap.RunnerStates)
	}

	for _, bad := range []map[string]any{
		{"count": 1, "holds": []string{"/srv/web"}},
		{"count": 2, "holds": []string{tenant}},
	} {
		if st, body := r.call(http.MethodPost, poolRunnersPath, token, bad); st != http.StatusBadRequest {
			t.Errorf("%v: %d %v", bad, st, body)
		}
	}
}

// TestAControllerReportReachesTheWaitingRuns: a volume stuck Pending is said
// where the person waiting looks — the run's queue reason and the project's
// pause — and a healthy report takes it back.
func TestAControllerReportReachesTheWaitingRuns(t *testing.T) {
	saved := poolReportMinInterval
	poolReportMinInterval = 0
	t.Cleanup(func() { poolReportMinInterval = saved })
	r := newPoolRig(t)
	id, token := r.createPool(map[string]any{"name": "k8s", "max_runners": 2})
	r.bind(id)
	if st, _ := r.call(http.MethodPost, "/api/run", "", map[string]any{}); st != http.StatusAccepted {
		t.Fatalf("queue a run: %d", st)
	}

	if st, _ := r.call(http.MethodPost, poolStatusPath, "", map[string]any{"healthy": false, "reason": "StoragePending"}); st != http.StatusUnauthorized {
		t.Fatalf("a report without the credential: %d", st)
	}
	for _, bad := range []map[string]any{
		{"healthy": false},
		{"healthy": false, "reason": "no spaces allowed"},
		{"healthy": false, "reason": strings.Repeat("A", 65)},
	} {
		if st, body := r.call(http.MethodPost, poolStatusPath, token, bad); st != http.StatusBadRequest {
			t.Errorf("%v: %d %v", bad, st, body)
		}
	}

	msg := "runner volume k8s-storage-0 has been Pending for 4m: storageclass \"fast\" not found\n\x1b[31mred"
	st, body := r.call(http.MethodPost, poolStatusPath, token, map[string]any{"healthy": false, "reason": "StoragePending",
		"message": msg})
	if st != http.StatusOK || body["healthy"] != false {
		t.Fatalf("report: %d %v", st, body)
	}
	pr := r.projectPause()
	if pr == nil || pr.Code != pausereason.CodePoolCapacity || !strings.Contains(pr.Detail, `storageclass "fast" not found`) ||
		!strings.Contains(pr.Detail, "controller cannot start runners") || strings.ContainsAny(pr.Detail, "\n\x1b") {
		t.Fatalf("the project's pause after the report: %+v", pr)
	}
	store, err := r.srv.poolStore()
	if err != nil {
		t.Fatal(err)
	}
	db := store.DB()
	queue, _ := db.ListPoolQueue(id, statedb.PoolQueueWaiting)
	if len(queue) != 1 || !strings.Contains(queue[0].Reason, "Pending for 4m") {
		t.Fatalf("the waiting run says %+v", queue)
	}
	events, _, err := db.ListAuditEvents(statedb.AuditFilter{EventType: "executor_pool.controller_status"})
	if err != nil || len(events) != 1 {
		t.Fatalf("audit: %v, %d rows", err, len(events))
	}
	// The same report again records nothing new.
	r.call(http.MethodPost, poolStatusPath, token, map[string]any{"healthy": false, "reason": "StoragePending", "message": msg})
	if events, _, _ := db.ListAuditEvents(statedb.AuditFilter{EventType: "executor_pool.controller_status"}); len(events) != 1 {
		t.Fatalf("a repeated report was recorded again: %d rows", len(events))
	}

	// An administrator's view of the pool shows it.
	st, detail := r.call(http.MethodGet, "/api/executor-pools/"+id, "", nil)
	reports, _ := detail["controller_reports"].([]any)
	if st != http.StatusOK || len(reports) != 1 || reports[0].(map[string]any)["reason"] != "StoragePending" {
		t.Fatalf("pool detail: %d %v", st, detail["controller_reports"])
	}

	// A report older than its TTL speaks for nobody.
	savedTTL := poolControllerReportTTL
	poolControllerReportTTL = time.Nanosecond
	time.Sleep(2 * time.Millisecond)
	if _, ok := r.srv.poolControllerTrouble(store, id); ok {
		t.Fatal("a stale report still speaks for the pool")
	}
	poolControllerReportTTL = savedTTL

	if st, _ := r.call(http.MethodPost, poolStatusPath, token, map[string]any{"healthy": true}); st != http.StatusOK {
		t.Fatalf("healthy report: %d", st)
	}
	if pr := r.projectPause(); pr == nil || strings.Contains(pr.Detail, "controller cannot start runners") {
		t.Fatalf("the project's pause after the healthy report: %+v", pr)
	}
}

// TestAnOlderMemberTurnsRunnerStorageOff: a hub cluster member whose build
// does not enforce what a runner's storage holds would hand a runner holding
// web's data anybody's run. While one is live the feed names no project and
// no runner is recorded as holding one, so the controller wipes every volume.
func TestAnOlderMemberTurnsRunnerStorageOff(t *testing.T) {
	r := newPoolRig(t)
	id, token := r.createPool(map[string]any{"name": "k8s", "max_runners": 5})
	r.bind(id)
	if st, _ := r.call(http.MethodPost, "/api/run", "", map[string]any{}); st != http.StatusAccepted {
		t.Fatalf("queue a run: %d", st)
	}
	join := func(endpoints map[string]string) *hubcluster.Node {
		opts := fastClusterOptions(state.DBPath(r.dir), r.ts.URL)
		opts.Endpoints = endpoints
		node, err := hubcluster.Join(opts)
		if err != nil {
			t.Fatalf("Join: %v", err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		node.Start(ctx)
		t.Cleanup(func() {
			cancel()
			node.Close()
		})
		return node
	}
	r.srv.Cluster = join(map[string]string{executorpool.EndpointRunnerStorage: "1"})
	_, snap := r.feed(token, "", 0)
	if snap.QueuedProjects == nil || len(snap.QueuedProjects) != 1 {
		t.Fatalf("with every member new: %+v", snap.QueuedProjects)
	}
	tenant := snap.QueuedProjects[0].Tenant

	join(nil) // a member of an older build
	deadline := time.Now().Add(5 * time.Second)
	for len(r.srv.Cluster.LiveMembers()) < 2 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if _, snap = r.feed(token, "", 0); snap.QueuedProjects != nil {
		t.Fatalf("with an older member live the feed names projects: %+v", snap.QueuedProjects)
	}
	st, body := r.call(http.MethodPost, poolRunnersPath, token, map[string]any{"count": 1, "holds": []string{tenant}})
	if st != http.StatusCreated {
		t.Fatalf("mint: %d %v", st, body)
	}
	if h, has := body["runners"].([]any)[0].(map[string]any)["holds"]; has {
		t.Fatalf("a runner was recorded holding %v while an older member is live", h)
	}
}

func TestControllerReportsAreRateLimited(t *testing.T) {
	r := newPoolRig(t)
	_, token := r.createPool(map[string]any{"name": "k8s", "max_runners": 2})
	if st, _ := r.call(http.MethodPost, poolStatusPath, token, map[string]any{"healthy": true}); st != http.StatusOK {
		t.Fatalf("first report: %d", st)
	}
	if st, _ := r.call(http.MethodPost, poolStatusPath, token, map[string]any{"healthy": false, "reason": "StorageFull"}); st != http.StatusTooManyRequests {
		t.Fatalf("a second report at once: %d", st)
	}
}
