package ui

// The knowledge sync scheduler on the hub (Task 20470): who may ask for a
// sync and what the route answers, that only the cluster leader runs the
// schedule, and that only the leader exports the index gauges.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/knowledge"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// gatedConnector lists each source's documents once its gate opens: a source
// names its gate in its configuration, and a gate nobody made is open. It
// counts every listing per gate.
type gatedConnector struct {
	kind string
	mu   sync.Mutex
	// gates holds each gate's channel, closed to open it.
	gates map[string]chan struct{}
	lists map[string]int
}

func newGatedConnector(kind string) *gatedConnector {
	return &gatedConnector{kind: kind, gates: map[string]chan struct{}{}, lists: map[string]int{}}
}

func (c *gatedConnector) Kind() string                             { return c.kind }
func (c *gatedConnector) Validate(knowledge.ValidateRequest) error { return nil }

func gateOf(config json.RawMessage) string {
	var cfg struct {
		Gate string `json:"gate"`
	}
	_ = json.Unmarshal(config, &cfg)
	return cfg.Gate
}

// shut makes gate closed until open is called.
func (c *gatedConnector) shut(gate string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.gates[gate] = make(chan struct{})
}

func (c *gatedConnector) open(gate string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if ch, ok := c.gates[gate]; ok {
		close(ch)
		delete(c.gates, gate)
	}
}

func (c *gatedConnector) listed(gate string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lists[gate]
}

func (c *gatedConnector) List(ctx context.Context, req knowledge.ListRequest) (knowledge.Page, error) {
	gate := gateOf(req.Config)
	c.mu.Lock()
	c.lists[gate]++
	ch := c.gates[gate]
	c.mu.Unlock()
	if ch != nil {
		select {
		case <-ch:
		case <-ctx.Done():
			return knowledge.Page{}, ctx.Err()
		}
	}
	return knowledge.Page{Cursor: "end", Documents: []knowledge.Document{
		{ExternalID: gate + "-1", Title: "Runbook", Body: "how to roll the " + gate + " deploy back"},
		{ExternalID: gate + "-2", Title: "Postmortem", Body: "what broke in the " + gate + " deploy"},
	}}, nil
}

func (c *gatedConnector) Fetch(context.Context, knowledge.FetchRequest) (knowledge.Document, error) {
	return knowledge.Document{}, fmt.Errorf("no fetch")
}

// uniqueGate names a gate no other run of a test in this process uses.
func uniqueGate(prefix string) string {
	return fmt.Sprintf("%s-%d", prefix, gateSeq.Add(1))
}

var gateSeq atomic.Int64

// uiGated is the gated connector the hub's default registry reads "uigated"
// sources with.
var (
	uiGated         = newGatedConnector("uigated")
	registerUIGated sync.Once
)

// TestKnowledgeSyncAPI: an administrator may sync any source and a person
// their own; everyone else is refused as the other knowledge routes refuse
// them. A sync starts at once, in the background, holding the source's lease:
// a second request while it runs is answered 409 naming the member running
// it, the source shows it running, the request is audited when the sync
// starts, and the sync records what it did when it ends.
func TestKnowledgeSyncAPI(t *testing.T) {
	registerUIGated.Do(func() { knowledge.MustRegister(uiGated) })
	// The connector is the process's, so its gates are this run's alone.
	orgGate, mineGate := uniqueGate("org"), uniqueGate("mine")
	h := knowledgeHub(t)
	h.srv.knowledgeSync.tune = func(o *knowledge.RunnerOptions) { o.LeaseTTL = 3 * time.Second }
	t.Cleanup(func() { h.srv.stopKnowledgeSyncs(10 * time.Second) })
	engineer := h.signIn(t, "eng@example.com", false, "engineers")
	lead := h.signIn(t, "lead@example.com", false, "leads")
	admin := h.signIn(t, "ada@example.com", false, "owners")

	expect := func(c *http.Client, method, path string, body any, want int) []byte {
		t.Helper()
		resp, raw := h.call(t, c, method, path, body)
		if resp.StatusCode != want {
			t.Fatalf("%s %s = %d %s, want %d", method, path, resp.StatusCode, raw, want)
		}
		return raw
	}
	type sourceResp struct {
		Source knowledgeSourceView   `json:"source"`
		Sync   *knowledgeRunningView `json:"sync"`
	}

	// A source's interval: the default, or 5 minutes to a day.
	expect(admin, "POST", "/api/knowledge/sources", map[string]any{"kind": "uigated", "name": "Too often", "scope": "org",
		"config": map[string]any{"gate": "x"}, "sync_interval_minutes": 3}, http.StatusBadRequest)
	var created sourceResp
	decodeBody(t, expect(admin, "POST", "/api/knowledge/sources", map[string]any{"kind": "uigated", "name": "Eng wiki",
		"scope": "org", "config": map[string]any{"gate": orgGate}, "sync_interval_minutes": 60}, http.StatusCreated), &created)
	org := created.Source
	if org.Sync.IntervalMinutes != 60 || org.Sync.DefaultInterval || org.Sync.NextAt == "" {
		t.Fatalf("the new source's schedule = %+v", org.Sync)
	}
	decodeBody(t, expect(engineer, "POST", "/api/knowledge/sources", map[string]any{"kind": "uigated", "name": "My notes",
		"config": map[string]any{"gate": mineGate}}, http.StatusCreated), &created)
	mine := created.Source
	if mine.Sync.IntervalMinutes != 30 || !mine.Sync.DefaultInterval {
		t.Fatalf("a source with no interval of its own = %+v", mine.Sync)
	}

	// Who may ask.
	orgSync := fmt.Sprintf("/api/knowledge/sources/%d/sync", org.ID)
	mineSync := fmt.Sprintf("/api/knowledge/sources/%d/sync", mine.ID)
	raw := expect(engineer, "POST", orgSync, map[string]any{}, http.StatusForbidden)
	if requiredPermission(raw) != "knowledge.admin" {
		t.Fatalf("an engineer syncing the org source was refused for %q: %s", requiredPermission(raw), raw)
	}
	expect(lead, "POST", mineSync, map[string]any{}, http.StatusNotFound)

	// An administrator syncs the org source; it runs until its gate opens.
	uiGated.shut(orgGate)
	var started sourceResp
	decodeBody(t, expect(admin, "POST", orgSync, map[string]any{}, http.StatusAccepted), &started)
	member := h.srv.knowledgeRunner().Member()
	if started.Sync == nil || started.Sync.Member == "" || started.Sync.Member != member ||
		started.Sync.Origin != "manual" || started.Sync.Actor == "" {
		t.Fatalf("the started sync = %+v", started.Sync)
	}
	waitCluster(t, "the sync to reach its listing", func() bool { return uiGated.listed(orgGate) == 1 })
	raw = expect(admin, "POST", orgSync, map[string]any{}, http.StatusConflict)
	if !strings.Contains(string(raw), member) || !strings.Contains(string(raw), `"running"`) {
		t.Fatalf("a second sync while one runs was refused with %s", raw)
	}
	var shown sourceResp
	decodeBody(t, expect(admin, "GET", fmt.Sprintf("/api/knowledge/sources/%d", org.ID), nil, http.StatusOK), &shown)
	if shown.Source.Sync.Running == nil || shown.Source.Sync.Running.Member != member {
		t.Fatalf("the source while it syncs = %+v", shown.Source.Sync)
	}
	uiGated.open(orgGate)
	waitKnowledgeSync(t, func() knowledgeSyncView {
		shown = sourceResp{} // a field the answer leaves out must not keep the last one's value
		decodeBody(t, expect(admin, "GET", fmt.Sprintf("/api/knowledge/sources/%d", org.ID), nil, http.StatusOK), &shown)
		return shown.Source.Sync
	})
	sync := shown.Source.Sync
	if sync.Origin != "manual" || sync.Counts == nil || sync.Counts.Created != 2 || sync.LastOKAt == "" ||
		shown.Source.Documents != 2 || sync.StartedAt == "" {
		t.Fatalf("the source after its sync = %+v (documents %d)", sync, shown.Source.Documents)
	}

	// The owner syncs their own personal source.
	expect(engineer, "POST", mineSync, map[string]any{}, http.StatusAccepted)
	waitKnowledgeSync(t, func() knowledgeSyncView {
		shown = sourceResp{}
		decodeBody(t, expect(engineer, "GET", fmt.Sprintf("/api/knowledge/sources/%d", mine.ID), nil, http.StatusOK), &shown)
		return shown.Source.Sync
	})

	// A disabled source is synced by no one.
	expect(admin, "PATCH", fmt.Sprintf("/api/knowledge/sources/%d", org.ID), map[string]any{"enabled": false}, http.StatusOK)
	expect(admin, "POST", orgSync, map[string]any{}, http.StatusConflict)

	// Every sync that started is on the audit trail, by who asked; the
	// refusals are not.
	db, err := statedb.Open(state.DBPath(h.srv.WorkDir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows, _, err := db.ListAuditEvents(statedb.AuditFilter{EventType: string(auditaction.ActionKnowledgeSourceSync), Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	var actors []string
	for _, r := range rows {
		actors = append(actors, r.Actor)
	}
	if len(rows) != 2 || !strings.Contains(strings.Join(actors, ","), "ada@example.com") ||
		!strings.Contains(strings.Join(actors, ","), "eng@example.com") {
		t.Fatalf("the audited syncs were by %v, want ada's and eng's", actors)
	}
}

// TestKnowledgeSyncRunsOnTheLeaderOnly: two members serve one control plane,
// each with the schedule registered as a leader duty. Only the leader syncs
// — the follower's connector is never asked — only the leader exports the
// index gauges, and when the leader goes, the member that takes over syncs
// what is due next.
func TestKnowledgeSyncRunsOnTheLeaderOnly(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("CLOOP_HOME", t.TempDir())
	dir := setupProjectDir(t, "one control plane, two hubs", nil)
	members := []*clusterMember{newClusterMember(t, dir), newClusterMember(t, dir)}
	waitCluster(t, "the members to see each other", func() bool {
		return members[0].node.HasPeers() && members[1].node.HasPeers()
	})
	conns := map[*clusterMember]*gatedConnector{}
	for _, m := range members {
		conn := newGatedConnector("uicluster")
		reg := knowledge.NewRegistry()
		if err := reg.Register(conn); err != nil {
			t.Fatal(err)
		}
		conns[m] = conn
		m.srv.knowledgeSync.tune = func(o *knowledge.RunnerOptions) {
			o.StartDelay, o.Tick, o.LeaseTTL = -1, 25*time.Millisecond, 2*time.Second
		}
		m.srv.knowledgeSync.serviceOptions = []knowledge.Option{knowledge.WithRegistry(reg)}
		t.Cleanup(func() { m.srv.stopKnowledgeSyncs(10 * time.Second) })
	}

	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	newSource := func(gate string) int64 {
		t.Helper()
		row, err := db.CreateKnowledgeSource(statedb.KnowledgeSourceRow{Kind: "uicluster", Name: "Wiki " + gate, Scope: "org",
			Config: fmt.Sprintf(`{"gate":%q}`, gate), Enabled: true}, "admin@example.com")
		if err != nil {
			t.Fatal(err)
		}
		return row.ID
	}
	synced := func(id int64) bool {
		row, err := db.GetKnowledgeSource(id)
		return err == nil && row.SyncStatus == knowledge.StatusOK
	}
	first := newSource("first")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	for _, m := range members {
		m.srv.runLeaderDuty(ctx, "knowledge-sync", m.srv.watchKnowledgeSync)
	}
	waitCluster(t, "the first source to be synced", func() bool { return synced(first) })

	var leader, follower *clusterMember
	for _, m := range members {
		if m.node.IsLeader() {
			leader = m
		} else {
			follower = m
		}
	}
	if leader == nil || follower == nil {
		t.Fatal("the cluster has no leader and follower")
	}
	// Many passes later, the follower has synced nothing.
	time.Sleep(300 * time.Millisecond)
	if n := conns[follower].listed("first"); n != 0 {
		t.Fatalf("the follower listed the source %d time(s)", n)
	}
	if n := conns[leader].listed("first"); n != 1 {
		t.Fatalf("the leader listed the source %d time(s) in one interval, want once", n)
	}

	// The index gauges come from the leader alone.
	gauge := `cloop_knowledge_index_documents{kind="unknown"} 2`
	if text := leader.srv.gatherMetrics(); !strings.Contains(text, gauge) {
		t.Fatalf("the leader does not export %s:\n%s", gauge, grepLines(text, "cloop_knowledge_index"))
	}
	if text := follower.srv.gatherMetrics(); strings.Contains(text, "cloop_knowledge_index_documents{") {
		t.Fatalf("the follower exports the index gauges:\n%s", grepLines(text, "cloop_knowledge_index"))
	}

	// The leader goes; the other takes over and syncs what is due next.
	_ = leader.node.Close()
	waitCluster(t, "the follower to lead", func() bool { return follower.node.IsLeader() })
	second := newSource("second")
	waitCluster(t, "the new leader to sync the second source", func() bool { return synced(second) })
	if n := conns[follower].listed("second"); n != 1 {
		t.Fatalf("the new leader listed the second source %d time(s), want once", n)
	}
	if n := conns[leader].listed("second"); n != 0 {
		t.Fatalf("the member that stepped down listed the second source %d time(s)", n)
	}
}

// waitKnowledgeSync waits for the sync read reports to have ended ok, and
// says what it reports if it does not.
func waitKnowledgeSync(t *testing.T, read func() knowledgeSyncView) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	var last knowledgeSyncView
	for time.Now().Before(deadline) {
		if last = read(); last.Status == knowledge.StatusOK && last.Running == nil {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	if last.Running != nil {
		t.Logf("running: %+v", *last.Running)
	}
	t.Fatalf("the sync did not end ok: %+v", last)
}

// TestAStoppingHubStartsNoSync: a hub that has begun to stop refuses a sync
// asked of it — even one that never ran a sync before — rather than start one
// nothing would interrupt.
func TestAStoppingHubStartsNoSync(t *testing.T) {
	registerUIGated.Do(func() { knowledge.MustRegister(uiGated) })
	gate := uniqueGate("late")
	h := knowledgeHub(t)
	admin := h.signIn(t, "ada@example.com", false, "owners")
	resp, raw := h.call(t, admin, "POST", "/api/knowledge/sources", map[string]any{"kind": "uigated", "name": "Late",
		"scope": "org", "config": map[string]any{"gate": gate}})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create = %d %s", resp.StatusCode, raw)
	}
	var created struct {
		Source knowledgeSourceView `json:"source"`
	}
	decodeBody(t, raw, &created)
	h.srv.stopKnowledgeSyncs(time.Second)
	resp, raw = h.call(t, admin, "POST", fmt.Sprintf("/api/knowledge/sources/%d/sync", created.Source.ID),
		map[string]any{})
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("a sync asked of a stopping hub = %d %s, want 503", resp.StatusCode, raw)
	}
	if n := uiGated.listed(gate); n != 0 {
		t.Fatalf("the stopping hub listed the source %d time(s)", n)
	}
}
