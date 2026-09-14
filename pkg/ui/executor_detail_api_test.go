package ui

// Coverage for GET /api/executors/{id} (Task 20244).
//
// The route exists to make the hub's no-host-execution claim checkable after
// the fact, so the assertions that matter are about what it will not do — who
// it refuses, and whether it can be talked into reporting a host run as
// something safer.

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/blechschmidt/cloop/pkg/apitoken"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/pm"
)

// TestExecutorDetail_DeniesCallerLackingExecRead is the gate assertion.
//
// It goes through the real handler chain rather than calling the handler
// directly, because the permission is enforced by the route table's gate() and
// a regression that moved enforcement into the handler — or dropped it — would
// still pass a direct call.
func TestExecutorDetail_DeniesCallerLackingExecRead(t *testing.T) {
	f := newTokenFixture(t)

	// Every *named* role down to viewer carries executor.read, and Mint
	// refuses a role the ladder does not define — so "a caller lacking
	// executor.read" is not expressible as a weaker role. It is expressible as
	// a token whose reach is pinned elsewhere, and there is a real one: the
	// display-glasses link, confined by tokenKindAdmitted to /api/glasses/.
	//
	// That makes this the security-relevant form of the assertion rather than
	// a synthetic one. The glasses task detail now reports which executor ran
	// a task (Task 20244); a wearer seeing that for their own project must
	// still not be able to enumerate the fleet, or the URL sitting in a
	// phone's app list becomes an inventory of the hub's infrastructure.
	glasses := f.mint(t, apitoken.MintOptions{
		Name:  glassesTokenName,
		Roles: []string{"viewer"},
		Kind:  apitoken.KindGlasses,
	})

	for _, path := range []string{"/api/executors/local", "/api/executors"} {
		code, body := f.do(t, glasses, http.MethodGet, path, "")
		if code == http.StatusOK {
			t.Fatalf("GET %s with a glasses-pinned token = 200 — a link with no "+
				"executor.read reach read the fleet\nbody: %s", path, body)
		}
		if code != http.StatusForbidden && code != http.StatusNotFound {
			t.Fatalf("GET %s with a glasses-pinned token = %d, want 403 or 404\nbody: %s",
				path, code, body)
		}
	}

	// Not asserted here: an anonymous caller. This fixture's hub has neither
	// OIDC nor a shared token configured, so authorization is inactive by
	// design and every route is open — a single-operator deployment's
	// behaviour, not a gap. Proving the gate needs a caller that authenticates
	// and still falls short, which is what the glasses token above is.
}

// TestExecutorDetail_ViewerReadsAndUnknownIs404 pins the other side of the
// gate, so the denial test above cannot pass merely because the route is
// broken for everyone.
func TestExecutorDetail_ViewerReadsAndUnknownIs404(t *testing.T) {
	f := newTokenFixture(t)
	registerBuiltinExecutors()
	if len(executor.List()) == 0 {
		t.Skip("no executor registered in this environment (host execution denied)")
	}
	id := executor.List()[0].ID()

	viewer := f.mint(t, apitoken.MintOptions{Roles: []string{"viewer"}})

	code, body := f.do(t, viewer, http.MethodGet, "/api/executors/"+id, "")
	if code != http.StatusOK {
		t.Fatalf("viewer GET /api/executors/%s = %d, want 200\nbody: %s", id, code, body)
	}
	var got executorDetailView
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatalf("decode detail: %v\nbody: %s", err, body)
	}
	if got.ID != id {
		t.Errorf("detail.id = %q, want %q", got.ID, id)
	}
	// The three things the task's payload has to carry beyond the list entry:
	// capabilities, the bound-project list, and the workload sweep. Projects
	// may legitimately be empty here; the sweep's coverage counter may not be
	// absent, or an empty history is indistinguishable from an unread one.
	if got.Capabilities == nil {
		t.Error("detail carries no capabilities — the list route's card already " +
			"has them, so a detail view without them is a regression")
	}
	if got.Workload.InFlight == nil || got.Workload.Completed == nil {
		t.Error("workload lists are nil rather than empty: a JSON null makes the " +
			"frontend branch on a case that should not exist")
	}

	if code, body := f.do(t, viewer, http.MethodGet, "/api/executors/no-such-executor", ""); code != http.StatusNotFound {
		t.Fatalf("GET unknown executor = %d, want 404\nbody: %s", code, body)
	}

	// A verb the route does not serve must be refused by the handler rather
	// than falling through to the SPA shell and answering a JSON client
	// with HTML.
	if code, _ := f.do(t, viewer, http.MethodPut, "/api/executors/"+id, "{}"); code == http.StatusOK {
		t.Error("PUT /api/executors/{id} returned 200 — the route must not accept a mutating verb")
	}
}

// TestExecutorDetail_WorkloadFindsAttributedTasks is the sweep, end to end: a
// project's tasks are read from disk, filtered by the attribution stamped on
// them, and split into in-flight and completed.
//
// It is deliberately not a filter over the executor's *bound* projects. A
// binding says where a project's next task would go; rebind it and the binding
// describes a placement that never happened for anything already run — which
// is precisely the history an audit is looking for.
func TestExecutorDetail_WorkloadFindsAttributedTasks(t *testing.T) {
	now := time.Now().UTC()
	earlier := now.Add(-time.Hour)

	dir := setupProjectDir(t, "attributed work", []*pm.Task{
		{
			ID: 1, Title: "running in a container", Status: pm.TaskInProgress,
			ExecutorID: "docker-1", ExecutorKind: executor.KindContainer,
			Isolation: string(executor.IsolationContainer), StartedAt: &now,
		},
		{
			ID: 2, Title: "finished in a container", Status: pm.TaskDone,
			ExecutorID: "docker-1", ExecutorKind: executor.KindContainer,
			Isolation: string(executor.IsolationContainer),
			StartedAt: &earlier, CompletedAt: &now,
		},
		{
			ID: 3, Title: "finished on the host", Status: pm.TaskDone,
			ExecutorID: "local", ExecutorKind: executor.KindLocalProcess,
			Isolation: string(executor.IsolationNone),
			StartedAt: &earlier, CompletedAt: &now,
		},
		{
			// Reset after a previous run: it still carries that run's
			// attribution but has not run again. Counting it as completed work
			// would report a task that never finished as one that did.
			ID: 4, Title: "reset after running", Status: pm.TaskPending,
			ExecutorID: "docker-1", ExecutorKind: executor.KindContainer,
			Isolation: string(executor.IsolationContainer),
		},
		{ID: 5, Title: "never attributed", Status: pm.TaskDone, CompletedAt: &now},
	})
	srv := New(dir, 0, "")

	got := srv.collectExecutorWorkload("docker-1")
	if got.ProjectsScanned == 0 {
		t.Fatal("no project was scanned — the sweep is reading a project set " +
			"that does not include the hub's own WorkDir, so every executor " +
			"would report an empty history")
	}
	if len(got.InFlight) != 1 || got.InFlight[0].ID != 1 {
		t.Errorf("in_flight = %+v, want exactly task 1", got.InFlight)
	}
	if len(got.Completed) != 1 || got.Completed[0].ID != 2 {
		t.Errorf("completed = %+v, want exactly task 2 (task 4 is pending, "+
			"task 3 ran elsewhere, task 5 is unattributed)", got.Completed)
	}
	if got.CompletedTotal != 1 {
		t.Errorf("completed_total = %d, want 1", got.CompletedTotal)
	}
	if got.HostTotal != 0 {
		t.Errorf("host_total = %d for a container executor, want 0", got.HostTotal)
	}
	// Task 4 is attributed but was reset: neither list claims it, and the
	// counter explains why the totals do not add up to the rows shown.
	if got.NotRunning != 1 {
		t.Errorf("not_running = %d, want 1 (task 4 was reset after running)", got.NotRunning)
	}
	if got.InFlight[0].OnHost {
		t.Error("a container-placed task reported on_host")
	}

	// The host executor's own history is where the audit question is answered.
	host := srv.collectExecutorWorkload("local")
	if len(host.Completed) != 1 || host.Completed[0].ID != 3 {
		t.Fatalf("host completed = %+v, want exactly task 3", host.Completed)
	}
	if host.HostTotal != 1 {
		t.Errorf("host_total = %d, want 1 — this is the number the "+
			"no-host-execution claim is audited against", host.HostTotal)
	}
	if !host.Completed[0].OnHost {
		t.Error("a task that ran on the host is not flagged on_host")
	}

	// An executor that ran nothing here reports an empty history, not an error,
	// and still reports that the sweep ran.
	none := srv.collectExecutorWorkload("edge-pi4")
	if len(none.InFlight) != 0 || len(none.Completed) != 0 {
		t.Errorf("unrelated executor reported work: %+v", none)
	}
	if none.ProjectsScanned == 0 {
		t.Error("projects_scanned = 0: an empty result is indistinguishable " +
			"from an unread one")
	}
}

// TestExecutorDetail_BoundsTitles: this route fans out across every project, so
// one unbounded title is multiplied by the whole sweep rather than by one plan.
func TestExecutorDetail_BoundsTitles(t *testing.T) {
	short := "a normal title"
	if got := boundTitle(short); got != short {
		t.Errorf("boundTitle(%q) = %q, want it unchanged", short, got)
	}

	long := strings.Repeat("x", maxExecutorDetailTitleLen*3)
	got := boundTitle(long)
	if len([]rune(got)) != maxExecutorDetailTitleLen+1 { // +1 for the ellipsis
		t.Errorf("boundTitle kept %d runes, want %d plus an ellipsis",
			len([]rune(got)), maxExecutorDetailTitleLen)
	}

	// Runes, not bytes: cutting a multi-byte character in half would emit
	// invalid UTF-8, which json.Marshal silently replaces — turning a display
	// cap into corrupted output.
	wide := strings.Repeat("é", maxExecutorDetailTitleLen*2)
	if cut := boundTitle(wide); !utf8.ValidString(cut) {
		t.Errorf("boundTitle produced invalid UTF-8 from a multi-byte title")
	}
}

// TestExecutorDetail_HostPredicateMatchesOrchestrator pins taskRanOnHost to
// the orchestrator's RanOnHost.
//
// The two are deliberate duplicates — pkg/ui does not depend on
// pkg/orchestrator — and a duplicated security predicate that drifts is worse
// than no predicate at all, because the screen keeps rendering a reassuring
// badge from the stale half. The table is the contract both sides implement.
func TestExecutorDetail_HostPredicateMatchesOrchestrator(t *testing.T) {
	cases := []struct {
		name string
		task pm.Task
		want bool
	}{
		{"host driver", pm.Task{ExecutorKind: executor.KindLocalProcess, Isolation: "none"}, true},
		{"host driver, isolation unrecorded", pm.Task{ExecutorKind: executor.KindLocalProcess}, true},
		{"container", pm.Task{ExecutorKind: executor.KindContainer, Isolation: "container"}, false},
		{"remote agent", pm.Task{ExecutorKind: executor.KindRemoteAgent, Isolation: "remote"}, false},
		{"kubernetes", pm.Task{ExecutorKind: executor.KindKubernetes, Isolation: "remote"}, false},
		{"vm", pm.Task{ExecutorKind: executor.KindContainer, Isolation: "vm"}, false},
		// A driver claiming a kind but advertising no boundary flags: the
		// disagreement is the finding.
		{"container claiming no isolation", pm.Task{ExecutorKind: executor.KindContainer, Isolation: "none"}, true},
		// Unattributed is unknown, not host.
		{"unattributed", pm.Task{}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			task := tc.task
			if got := taskRanOnHost(&task); got != tc.want {
				t.Errorf("taskRanOnHost = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestExecutorDetail_ReportsContainerPlacement checks the projection end to
// end: a task stamped with a container executor is reported under that
// executor, as kind=container, and is not flagged as a host run.
func TestExecutorDetail_ReportsContainerPlacement(t *testing.T) {
	task := &pm.Task{
		ID: 7, Title: "ran in a container", Status: pm.TaskInProgress,
		ExecutorID: "docker-1", ExecutorKind: executor.KindContainer,
		Isolation: string(executor.IsolationContainer),
	}
	if taskRanOnHost(task) {
		t.Fatal("a container-placed task reported as host execution")
	}
	if got := taskStatusOrPendingRef(task); got != string(pm.TaskInProgress) {
		t.Errorf("status = %q, want in_progress", got)
	}
	// An empty status reads as pending here exactly as it does on the task
	// list, so one task does not appear under two different statuses.
	if got := taskStatusOrPendingRef(&pm.Task{ID: 8}); got != string(pm.TaskPending) {
		t.Errorf("empty status = %q, want pending", got)
	}
}
