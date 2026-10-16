package ui

import (
	"fmt"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/denylog"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/fwpolicy"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// denials_test.go covers Task 20437's hub half: a run's refusals, reported by
// whichever process read its sandbox's packet log, land on its history, its
// task's Network section, the project's firewall card, the audit trail and
// the metrics — explained by the levels its firewall was composed of.

type denialTestExecutor struct {
	stubExecutor
	id, kind, parent string
	note             string
}

func (e *denialTestExecutor) ID() string       { return e.id }
func (e *denialTestExecutor) Kind() string     { return e.kind }
func (e *denialTestExecutor) ParentID() string { return e.parent }
func (e *denialTestExecutor) DenialLogStatus() (bool, string) {
	return e.note == "", e.note
}

func denialBatch(t0 time.Time) denylog.Batch {
	return denylog.Batch{Fingerprint: "0123456789ab", Entries: []denylog.Entry{
		{Dst: netip.MustParseAddr("203.0.113.7"), Port: 443, Proto: "tcp", Rule: "default", Count: 14, First: t0, Last: t0.Add(time.Second)},
		{Dst: netip.MustParseAddr("10.0.0.5"), Port: 5432, Proto: "tcp", Rule: "block:10.0.0.0/8", Count: 1, First: t0, Last: t0},
	}}
}

func projectLevels() []fwpolicy.Level {
	project := executor.FirewallRules{AllowCIDRs: []string{"1.1.1.1/32"}, AllowPorts: []int{443}}
	return []fwpolicy.Level{
		{Kind: "config", Name: "executor dev-1's configuration"},
		{Kind: "project", Name: "this project's firewall", Rules: &project},
	}
}

func newDenialHub(t *testing.T) (string, *Server, *httptest.Server) {
	t.Helper()
	dir := setupProjectWithTasks(t, cloopGoal, []*pm.Task{
		{ID: 1, Title: "fetch the data", Status: pm.TaskInProgress},
		{ID: 2, Title: "later", Status: pm.TaskPending},
	})
	srv := New(dir, 0, "")
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return dir, srv, ts
}

// TestARunsRefusalsReachItsHistoryAuditAndMetrics is the whole path from a
// report to everything a developer reads.
func TestARunsRefusalsReachItsHistoryAuditAndMetrics(t *testing.T) {
	dir, srv, ts := newDenialHub(t)
	ex := &denialTestExecutor{id: "dev-1", kind: executor.KindRemoteAgent}
	bindDenialRoute(ex, "h1", "run-1", dir, projectLevels())
	t0 := time.Now().Add(-time.Second)
	const defaultSample = `cloop_firewall_denials_total{executor_kind="remote",rule="default"}`
	const blockSample = `cloop_firewall_denials_total{executor_kind="remote",rule="block"}`
	defaultBefore, blockBefore := metricValue(srv, defaultSample), metricValue(srv, blockSample)

	if !executor.ReportDenials("dev-1", "h1", denialBatch(t0)) {
		t.Fatal("no sink is installed after New")
	}
	// The same destination again: counted, and no second history line.
	again := denialBatch(t0)
	again.Entries = again.Entries[:1]
	again.Entries[0].Count = 2
	executor.ReportDenials("dev-1", "h1", again)
	endRunDenials(ex, "h1")

	rows, err := state.ListEventsOfType(dir, state.EventNetworkBlocked, 10)
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	for _, r := range rows {
		lines = append(lines, r.Message)
	}
	all := strings.Join(lines, "\n")
	for _, want := range []string{
		"blocked 203.0.113.7:443/tcp x14, not in the project's allow list",
		"blocked 10.0.0.5:5432/tcp, private (RFC1918/ULA) range 10.0.0.0/8, which the project's allow list does not name",
		"the firewall refused 17 connection attempts during this run: 203.0.113.7:443/tcp x16, 10.0.0.5:5432/tcp x1",
	} {
		if !strings.Contains(all, want) {
			t.Errorf("history lacks %q:\n%s", want, all)
		}
	}
	if len(rows) != 3 {
		t.Errorf("%d history rows, want two first sightings and the summary:\n%s", len(rows), all)
	}
	for _, r := range rows {
		if strings.HasPrefix(r.Message, "blocked ") && (r.TaskID != 1 || r.TaskTitle != "fetch the data") {
			t.Errorf("%q is not filed under the running task: %d %q", r.Message, r.TaskID, r.TaskTitle)
		}
	}

	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	audit, _, err := db.ListAuditEvents(statedb.AuditFilter{EventType: string(auditaction.ActionRunFirewallDenied)})
	db.Close()
	if err != nil {
		t.Fatal(err)
	}
	if len(audit) != 2 {
		t.Fatalf("%d run.firewall_denied rows, want one per deny path: %+v", len(audit), audit)
	}
	for _, a := range audit {
		if !strings.Contains(a.Payload, `"run_id":"run-1"`) || !strings.Contains(a.Payload, `"executor_id":"dev-1"`) {
			t.Errorf("audit row does not name its run and executor: %s", a.Payload)
		}
	}

	if d := metricValue(srv, defaultSample) - defaultBefore; d != 16 {
		t.Errorf("%s grew by %v, want 16", defaultSample, d)
	}
	if d := metricValue(srv, blockSample) - blockBefore; d != 1 {
		t.Errorf("%s grew by %v, want 1", blockSample, d)
	}

	net := apiGET(t, ts, "/api/tasks/1/network")
	denials, _ := net["denials"].([]any)
	if net["observable"] != true || len(denials) != 2 {
		t.Fatalf("GET /api/tasks/1/network = %v", net)
	}
	first := denials[0].(map[string]any)
	if first["dst"] != "203.0.113.7" || first["count"] != float64(16) || first["proposable"] != true {
		t.Errorf("first refusal = %v", first)
	}
	if net2 := apiGET(t, ts, "/api/tasks/2/network"); len(net2["denials"].([]any)) != 0 {
		t.Errorf("a task that did not run shows refusals: %v", net2)
	}

	// Once the run is over its route is gone: a late report is not filed.
	if lookupDenialRoute("dev-1", "h1") != nil {
		t.Error("the route outlived the run")
	}
	const dropped = `cloop_firewall_denial_reports_dropped_total{reason="unknown_run"}`
	before := metricValue(srv, dropped)
	executor.ReportDenials("dev-1", "h1", denialBatch(t0))
	endRunDenials(ex, "h1") // no route: returns at once
	waitForDenialQueue(t)
	if d := metricValue(srv, dropped) - before; d != 1 {
		t.Errorf("a report for no run: %s grew by %v, want 1", dropped, d)
	}
}

// metricValue reads one sample out of the hub's exposition, 0 when absent.
func metricValue(srv *Server, sample string) float64 {
	for _, line := range strings.Split(srv.gatherMetrics(), "\n") {
		if rest, ok := strings.CutPrefix(line, sample+" "); ok {
			var v float64
			if _, err := fmt.Sscan(rest, &v); err == nil {
				return v
			}
		}
	}
	return 0
}

// waitForDenialQueue waits until the recorder has drained what is queued, by
// queueing an end for a run that exists only for this.
func waitForDenialQueue(t *testing.T) {
	t.Helper()
	ex := &denialTestExecutor{id: "drain", kind: executor.KindContainer}
	bindDenialRoute(ex, "drain", "drain", t.TempDir(), nil)
	endRunDenials(ex, "drain")
}

// TestAVirtualExecutorsRefusalsArriveUnderItsDevice: a virtual executor's
// workload is started on its device, whose session carries the reports.
func TestAVirtualExecutorsRefusalsArriveUnderItsDevice(t *testing.T) {
	dir, _, _ := newDenialHub(t)
	vx := &denialTestExecutor{id: "vx-1", kind: executor.KindVirtual, parent: "dev-1"}
	own := executor.FirewallRules{AllowPublicInternet: true, DenyCIDRs: []string{"1.0.0.1/32"}}
	bindDenialRoute(vx, "h2", "run-2", dir, []fwpolicy.Level{
		{Kind: "own", Name: "virtual executor vx-1's firewall", Rules: &own}})
	executor.ReportDenials("dev-1", "h2", denylog.Batch{Entries: []denylog.Entry{{
		Dst: netip.MustParseAddr("1.0.0.1"), Port: 443, Proto: "tcp", Rule: "deny:1.0.0.1/32", Count: 1,
		First: time.Now(), Last: time.Now()}}})
	endRunDenials(vx, "h2")
	rows, _ := state.ListEventsOfType(dir, state.EventNetworkBlocked, 10)
	found := false
	for _, r := range rows {
		found = found || r.Message == "blocked 1.0.0.1:443/tcp, in virtual executor vx-1's deny list (1.0.0.1/32)"
	}
	if !found {
		t.Errorf("the device's report for its virtual executor's run was not filed: %+v", rows)
	}
}

// TestDenialObservabilitySaysWhyNot: where nothing can be recorded the views
// say so rather than show an empty list.
func TestDenialObservabilitySaysWhyNot(t *testing.T) {
	for _, c := range []struct {
		ex   executor.Executor
		ok   bool
		want string
	}{
		{&denialTestExecutor{id: "k", kind: executor.KindKubernetes}, false,
			"Denials are not observable on this executor: a Kubernetes NetworkPolicy has no portable log"},
		// No sandbox firewall at all: nothing to observe, and nothing to say.
		{&denialTestExecutor{id: "l", kind: executor.KindLocalProcess}, false, ""},
		{&denialTestExecutor{id: "r", kind: executor.KindRemoteAgent, note: "agent r speaks protocol v23, and the hub needs v24"},
			false, "Denials are not observable on this executor: agent r speaks protocol v23"},
		{&denialTestExecutor{id: "r2", kind: executor.KindRemoteAgent}, true, ""},
		{nil, false, "no executor resolves"},
	} {
		ok, note := denialObservability(c.ex)
		if ok != c.ok || !strings.Contains(note, c.want) {
			t.Errorf("%v: (%v, %q), want (%v, …%q…)", c.ex, ok, note, c.ok, c.want)
		}
	}
}

// TestTheFirewallCardListsWhatWasRecentlyBlocked: the card's list is the
// project's refusals, each with whether an allow could let it through.
func TestTheFirewallCardListsWhatWasRecentlyBlocked(t *testing.T) {
	dir, _, ts := newDenialHub(t)
	ex := &denialTestExecutor{id: "dev-1", kind: executor.KindRemoteAgent}
	bindDenialRoute(ex, "h3", "run-3", dir, projectLevels())
	b := denialBatch(time.Now().Add(-time.Second))
	b.Entries = append(b.Entries, denylog.Entry{Dst: netip.MustParseAddr("203.0.113.9"), Port: 53, Proto: "udp",
		Rule: "deny:203.0.113.0/24", Count: 3, First: time.Now(), Last: time.Now()})
	executor.ReportDenials("dev-1", "h3", b)
	endRunDenials(ex, "h3")

	view := apiGET(t, ts, "/api/firewall/blocked")
	list, _ := view["blocked"].([]any)
	if view["visible"] != true || len(list) != 3 {
		t.Fatalf("GET /api/firewall/blocked = %v", view)
	}
	prop := map[string]bool{}
	for _, it := range list {
		m := it.(map[string]any)
		prop[m["rule"].(string)] = m["proposable"] == true
	}
	if !prop["default"] || !prop["block:10.0.0.0/8"] || prop["deny:203.0.113.0/24"] {
		t.Errorf("proposable = %v: an allow opens the default deny and the block set, never a deny list", prop)
	}
}
