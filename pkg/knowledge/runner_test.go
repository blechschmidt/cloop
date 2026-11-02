package knowledge

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/hubmetrics"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// script is how one source of the scripted connector behaves.
type script struct {
	docs []Document
	// block, when set, holds List until it is closed or the sync stops.
	block chan struct{}
	// entered is signalled each time List is entered.
	entered chan struct{}
	// panicList and panicNarrow make List and Narrow panic, with the
	// credential in the value.
	panicList, panicNarrow bool
	// stuck, when set, holds the first List until it is closed, whatever the
	// sync's context says: a sync wedged in a connector that ignores it.
	stuck     chan struct{}
	stuckUsed atomic.Bool
	lists     atomic.Int32
}

// scriptedConnector serves each source as its script says; a source names
// its script in its configuration.
type scriptedConnector struct {
	mu      sync.Mutex
	scripts map[string]*script
}

func (c *scriptedConnector) Kind() string                   { return "scripted" }
func (c *scriptedConnector) Validate(ValidateRequest) error { return nil }

func (c *scriptedConnector) script(config json.RawMessage) *script {
	var cfg struct {
		Script string `json:"script"`
	}
	_ = json.Unmarshal(config, &cfg)
	c.mu.Lock()
	defer c.mu.Unlock()
	if sc, ok := c.scripts[cfg.Script]; ok {
		return sc
	}
	return &script{}
}

func (c *scriptedConnector) List(ctx context.Context, req ListRequest) (Page, error) {
	sc := c.script(req.Config)
	sc.lists.Add(1)
	if sc.entered != nil {
		select {
		case sc.entered <- struct{}{}:
		default:
		}
	}
	if sc.panicList {
		panic("the connector broke while holding " + string(req.Credential.Value()))
	}
	if sc.stuck != nil && sc.stuckUsed.CompareAndSwap(false, true) {
		<-sc.stuck
		return Page{Documents: sc.docs, Cursor: "end"}, nil
	}
	if sc.block != nil {
		select {
		case <-sc.block:
		case <-ctx.Done():
			return Page{}, ctx.Err()
		}
	}
	return Page{Documents: sc.docs, Cursor: "end"}, nil
}

func (c *scriptedConnector) Fetch(context.Context, FetchRequest) (Document, error) {
	return Document{}, errors.New("not here")
}

func (c *scriptedConnector) ValidateQuery(json.RawMessage, string) error { return nil }

func (c *scriptedConnector) Narrow(_ context.Context, req NarrowRequest) ([]string, error) {
	sc := c.script(req.Config)
	if sc.panicNarrow {
		panic("narrowing broke while holding " + string(req.Credential.Value()))
	}
	var ids []string
	for _, d := range sc.docs {
		ids = append(ids, d.ExternalID)
	}
	return ids, nil
}

// runnerFixture is a fixture whose database runners open handles of their
// own on, as hub members do.
type runnerFixture struct {
	*fixture
	conn *scriptedConnector
	path string

	logMu sync.Mutex
	logs  []string
}

func newRunnerFixture(t *testing.T) *runnerFixture {
	t.Helper()
	f := newFixture(t)
	conn := &scriptedConnector{scripts: map[string]*script{}}
	if err := f.svc.registry.Register(conn); err != nil {
		t.Fatal(err)
	}
	return &runnerFixture{fixture: f, conn: conn, path: f.db.Path()}
}

// open is what a runner opens for each sync: a handle of its own on the
// database, with the fixture's connectors and secrets.
func (rf *runnerFixture) open() (*Service, func(), error) {
	db, err := statedb.Open(rf.path)
	if err != nil {
		return nil, nil, err
	}
	svc := New(db.AsControlPlane(), WithRegistry(rf.svc.registry), WithCredentials(rf.svc.credentials),
		WithChunking(rf.svc.chunking))
	return svc, func() { _ = db.Close() }, nil
}

func (rf *runnerFixture) logf(format string, args ...any) {
	rf.logMu.Lock()
	defer rf.logMu.Unlock()
	rf.logs = append(rf.logs, fmt.Sprintf(format, args...))
}

func (rf *runnerFixture) logged(substr string) bool {
	rf.logMu.Lock()
	defer rf.logMu.Unlock()
	for _, l := range rf.logs {
		if strings.Contains(l, substr) {
			return true
		}
	}
	return false
}

// runner is a runner for one hub member, stopped when the test ends.
func (rf *runnerFixture) runner(t *testing.T, member string, mod func(*RunnerOptions)) *Runner {
	t.Helper()
	o := RunnerOptions{Member: member, Open: rf.open, StartDelay: -1, Tick: 20 * time.Millisecond,
		LeaseTTL: 3 * time.Second, Logf: rf.logf}
	if mod != nil {
		mod(&o)
	}
	r := NewRunner(o)
	t.Cleanup(func() { r.Stop(10 * time.Second) })
	return r
}

// scripted connects an organisation source the script serves.
func (rf *runnerFixture) scripted(t *testing.T, name string, sc *script) Source {
	t.Helper()
	rf.conn.mu.Lock()
	rf.conn.scripts[name] = sc
	rf.conn.mu.Unlock()
	admin := rf.svc.For(as(t, "root@corp.example", "admins"))
	return mustCreate(t, admin, SourceInput{Kind: "scripted", Name: name, Scope: ScopeOrg, SecretRef: "wiki-bot",
		Config: json.RawMessage(fmt.Sprintf(`{"script":%q}`, name))})
}

// waitFor polls cond until it holds or ten seconds pass.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func entered(t *testing.T, sc *script) {
	t.Helper()
	select {
	case <-sc.entered:
	case <-time.After(10 * time.Second):
		t.Fatal("the sync never reached its listing")
	}
}

func sourceRow(t *testing.T, rf *runnerFixture, id int64) statedb.KnowledgeSourceRow {
	t.Helper()
	row, err := rf.db.GetKnowledgeSource(id)
	if err != nil {
		t.Fatal(err)
	}
	return row
}

// TestOneSyncPerSourceAtATime: a source's lease admits one sync at a time,
// wherever it was asked for. A person asking member A for a sync holds the
// source; another asking member B, and B's schedule reaching it, are refused
// and told where it runs; of many asking at once exactly one starts; and once
// the sync ends, the next is admitted.
func TestOneSyncPerSourceAtATime(t *testing.T) {
	rf := newRunnerFixture(t)
	sc := &script{docs: pageOfDocs("d", 3), block: make(chan struct{}), entered: make(chan struct{}, 1)}
	src := rf.scripted(t, "wiki", sc)
	a := rf.runner(t, "member-a", nil)
	b := rf.runner(t, "member-b", nil)

	running, err := a.Start(src.ID, OriginManual, "ada@corp.example")
	if err != nil || running.Member != "member-a" || running.Origin != OriginManual {
		t.Fatalf("start = %+v, %v", running, err)
	}
	entered(t, sc)

	_, err = b.Start(src.ID, OriginManual, "bob@corp.example")
	var busy *BusyError
	if !errors.As(err, &busy) || busy.Running.Member != "member-a" || busy.Running.Actor != "ada@corp.example" ||
		!strings.Contains(err.Error(), "member-a") {
		t.Fatalf("a manual sync asked of member B meanwhile = %v", err)
	}
	if _, err := b.SyncNow(context.Background(), src.ID, OriginSchedule, ""); !errors.Is(err, statedb.ErrKnowledgeSyncLeaseHeld) {
		t.Fatalf("member B's scheduled sync meanwhile = %v", err)
	}
	// What the source shows while it syncs.
	admin := rf.svc.For(as(t, "root@corp.example", "admins"))
	shown, _, err := admin.Source(context.Background(), src.ID)
	if err != nil || shown.Sync.Running == nil || shown.Sync.Running.Member != "member-a" {
		t.Fatalf("the source while it syncs = %+v, %v", shown.Sync, err)
	}

	close(sc.block)
	waitFor(t, "the sync to end", func() bool { return sourceRow(t, rf, src.ID).SyncStatus == StatusOK })
	if n := sc.lists.Load(); n != 1 {
		t.Fatalf("the connector was listed %d times while one sync held the source, want once", n)
	}
	waitFor(t, "the lease to be released", func() bool {
		live, _ := rf.db.LiveKnowledgeSyncLeases(time.Now())
		return len(live) == 0
	})
	res, err := b.SyncNow(context.Background(), src.ID, OriginManual, "bob@corp.example")
	if err != nil || res.Status != StatusOK || res.Report.Unchanged != 3 {
		t.Fatalf("the next sync = %+v, %v", res, err)
	}

	// Many at once, across both members: exactly one starts.
	raceScript := &script{docs: pageOfDocs("r", 2), block: make(chan struct{}), entered: make(chan struct{}, 1)}
	race := rf.scripted(t, "race", raceScript)
	var (
		wg      sync.WaitGroup
		started atomic.Int32
		refused atomic.Int32
		gate    = make(chan struct{})
	)
	for i := 0; i < 12; i++ {
		r := a
		if i%2 == 1 {
			r = b
		}
		wg.Add(1)
		go func(r *Runner, i int) {
			defer wg.Done()
			<-gate
			_, err := r.Start(race.ID, OriginManual, fmt.Sprintf("person%d@corp.example", i))
			switch {
			case err == nil:
				started.Add(1)
			case errors.Is(err, statedb.ErrKnowledgeSyncLeaseHeld):
				refused.Add(1)
			default:
				t.Errorf("start %d: %v", i, err)
			}
		}(r, i)
	}
	close(gate)
	wg.Wait()
	if started.Load() != 1 || refused.Load() != 11 {
		t.Fatalf("%d of 12 concurrent manual syncs started and %d were refused; want 1 and 11",
			started.Load(), refused.Load())
	}
	close(raceScript.block)
	waitFor(t, "the raced sync to end", func() bool { return sourceRow(t, rf, race.ID).SyncStatus == StatusOK })
	if n := raceScript.lists.Load(); n != 1 {
		t.Fatalf("the raced source was listed %d times, want once", n)
	}
}

// TestAPanickingConnectorFailsOnlyItsOwnSync: a connector that panics in its
// listing, or in answering a binding's query, fails that source's sync —
// recorded, its credential scrubbed from what is recorded, its lease released
// and its binding cleared — while the schedule syncs every other source and
// keeps running.
func TestAPanickingConnectorFailsOnlyItsOwnSync(t *testing.T) {
	rf := newRunnerFixture(t)
	bad := rf.scripted(t, "bad", &script{panicList: true})
	good := rf.scripted(t, "good", &script{docs: pageOfDocs("g", 2)})
	narrow := rf.scripted(t, "narrow", &script{docs: pageOfDocs("n", 2), panicNarrow: true})
	admin := rf.svc.For(as(t, "root@corp.example", "admins"))
	b, _, err := admin.Bind(context.Background(), projectA, narrow.ID, Filter{Query: "labels = x"})
	if err != nil {
		t.Fatal(err)
	}
	if err := rf.db.SetKnowledgeBindingDocuments(b.ID, "labels = x", []string{"n-0"}, time.Now()); err != nil {
		t.Fatal(err)
	}

	r := rf.runner(t, "leader", nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { r.Schedule(ctx); close(done) }()
	defer func() { cancel(); <-done }()

	for _, id := range []int64{bad.ID, good.ID, narrow.ID} {
		waitFor(t, fmt.Sprintf("source %d to be synced", id), func() bool { return sourceRow(t, rf, id).SyncStatus != "" })
	}
	row := sourceRow(t, rf, bad.ID)
	if row.SyncStatus != StatusError || !strings.Contains(row.SyncError, "panicked in list") ||
		strings.Contains(row.SyncError, "org-token-value-123") {
		t.Fatalf("the panicking source recorded %q %q", row.SyncStatus, row.SyncError)
	}
	if row := sourceRow(t, rf, good.ID); row.SyncStatus != StatusOK {
		t.Fatalf("the source beside it recorded %q %q", row.SyncStatus, row.SyncError)
	}
	if counts, _ := rf.db.CountKnowledge(good.ID); counts[good.ID].Documents != 2 {
		t.Fatalf("the good source indexed %+v", counts[good.ID])
	}
	row = sourceRow(t, rf, narrow.ID)
	if row.SyncStatus != StatusError || !strings.Contains(row.SyncError, "panicked in narrow") ||
		strings.Contains(row.SyncError, "org-token-value-123") {
		t.Fatalf("the source whose narrowing panicked recorded %q %q", row.SyncStatus, row.SyncError)
	}
	if binding, err := rf.db.GetKnowledgeBinding(b.ID); err != nil || !binding.NarrowedAt.IsZero() {
		t.Fatalf("the binding whose query panicked kept its answer: %+v, %v", binding, err)
	}
	waitFor(t, "every lease to be released", func() bool {
		live, _ := rf.db.LiveKnowledgeSyncLeases(time.Now())
		return len(live) == 0
	})
	if !rf.logged("the panic in source") {
		t.Fatal("the panic's stack was not logged")
	}
	if text := hubmetrics.Default.Gather(); !strings.Contains(text, `cloop_knowledge_sync_errors_total{kind="scripted",reason="panic"}`) {
		t.Fatal("the panics were not counted")
	}

	// And the schedule goes on: a source connected now is synced.
	later := rf.scripted(t, "later", &script{docs: pageOfDocs("l", 1)})
	waitFor(t, "a source connected after the panics to be synced", func() bool {
		return sourceRow(t, rf, later.ID).SyncStatus == StatusOK
	})
}

// TestStoppingInterruptsSyncsCleanly: a hub that stops interrupts its syncs,
// which record that — to resume from their cursor at once — and release their
// leases before Stop returns; a schedule whose leader duty ends does the same,
// saying so; and a stopped runner starts nothing more.
func TestStoppingInterruptsSyncsCleanly(t *testing.T) {
	rf := newRunnerFixture(t)
	sc := &script{docs: pageOfDocs("d", 2), block: make(chan struct{}), entered: make(chan struct{}, 1)}
	src := rf.scripted(t, "wiki", sc)
	r := rf.runner(t, "member-a", nil)
	if _, err := r.Start(src.ID, OriginManual, "ada@corp.example"); err != nil {
		t.Fatal(err)
	}
	entered(t, sc)
	began := time.Now()
	r.Stop(10 * time.Second)
	if took := time.Since(began); took > 5*time.Second {
		t.Fatalf("stopping took %s", took)
	}
	row := sourceRow(t, rf, src.ID)
	if row.SyncStatus != StatusInterrupted || !row.SyncMore || !strings.Contains(row.SyncError, "stopped") {
		t.Fatalf("an interrupted sync recorded %q %q more=%v", row.SyncStatus, row.SyncError, row.SyncMore)
	}
	if live, _ := rf.db.LiveKnowledgeSyncLeases(time.Now()); len(live) != 0 {
		t.Fatalf("the interrupted sync kept its lease: %+v", live)
	}
	if next := nextSync(row); !next.Equal(row.SyncedAt.Add(resumeAfter)) {
		t.Fatalf("an interrupted sync resumes at %s, want %s", next, row.SyncedAt.Add(resumeAfter))
	}
	if _, err := r.Start(src.ID, OriginManual, "ada@corp.example"); !errors.Is(err, ErrRunnerStopped) {
		t.Fatalf("a stopped runner started a sync: %v", err)
	}

	// The schedule's duty ends — the member stopped leading.
	other := &script{docs: pageOfDocs("o", 1), block: make(chan struct{}), entered: make(chan struct{}, 1)}
	src2 := rf.scripted(t, "other", other)
	leader := rf.runner(t, "member-b", nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { leader.Schedule(ctx); close(done) }()
	entered(t, other)
	cancel()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the schedule did not return when its duty ended")
	}
	row = sourceRow(t, rf, src2.ID)
	if row.SyncStatus != StatusInterrupted || !strings.Contains(row.SyncError, "stopped leading") {
		t.Fatalf("a sync whose leader stepped down recorded %q %q", row.SyncStatus, row.SyncError)
	}
	if live, _ := rf.db.LiveKnowledgeSyncLeases(time.Now()); len(live) != 0 {
		t.Fatalf("the stepped-down leader's sync kept its lease: %+v", live)
	}
}

// TestASyncThatLosesItsLeaseWritesNothingMore: a sync whose lease another
// took over — its process stalled past it — stops, and none of its writes
// lands: not its documents, not its cursor, not its outcome.
func TestASyncThatLosesItsLeaseWritesNothingMore(t *testing.T) {
	rf := newRunnerFixture(t)
	sc := &script{docs: pageOfDocs("d", 3), block: make(chan struct{}), entered: make(chan struct{}, 1)}
	src := rf.scripted(t, "wiki", sc)
	r := rf.runner(t, "member-a", func(o *RunnerOptions) { o.LeaseTTL = 600 * time.Millisecond })

	resCh := make(chan SyncResult, 1)
	go func() {
		res, _ := r.SyncNow(context.Background(), src.ID, OriginSchedule, "")
		resCh <- res
	}()
	entered(t, sc)
	// Another member takes the lease over, as it would one that lapsed.
	thief, err := statedb.OpenConn(rf.path, statedb.ReadWrite)
	if err != nil {
		t.Fatal(err)
	}
	defer thief.Close()
	if _, err := thief.Exec(`UPDATE knowledge_sync_leases SET holder = 'member-b/thief', member = 'member-b',
		expires_ns = ? WHERE source_id = ?`, time.Now().Add(time.Hour).UnixNano(), src.ID); err != nil {
		t.Fatal(err)
	}
	var res SyncResult
	select {
	case res = <-resCh:
	case <-time.After(10 * time.Second):
		close(sc.block)
		t.Fatal("a sync that lost its lease did not stop")
	}
	if res.Status != StatusError || FailureReason(res.Err) != ReasonLease {
		t.Fatalf("a sync that lost its lease = %+v (reason %q)", res, FailureReason(res.Err))
	}
	if counts, _ := rf.db.CountKnowledge(src.ID); counts[src.ID].Documents != 0 {
		t.Fatalf("the sync that lost its lease indexed %+v", counts[src.ID])
	}
	row := sourceRow(t, rf, src.ID)
	if row.SyncCursor != "" || row.SyncStatus != "" {
		t.Fatalf("the sync that lost its lease recorded cursor %q, status %q", row.SyncCursor, row.SyncStatus)
	}
	live, _ := rf.db.LiveKnowledgeSyncLeases(time.Now())
	if live[src.ID].Holder != "member-b/thief" {
		t.Fatalf("releasing a lost lease freed the new holder's: %+v", live)
	}
}

// TestNextSync: when the schedule syncs a source next.
func TestNextSync(t *testing.T) {
	t0 := time.Date(2026, 11, 2, 9, 0, 0, 0, time.UTC)
	base := statedb.KnowledgeSourceRow{Enabled: true, CreatedAt: t0.Add(-time.Hour), UpdatedAt: t0.Add(-time.Hour),
		SyncStatus: StatusOK, SyncStartedAt: t0.Add(-time.Minute), SyncedAt: t0}
	for _, tc := range []struct {
		name string
		edit func(*statedb.KnowledgeSourceRow)
		want time.Time
	}{
		{"on the default interval", func(*statedb.KnowledgeSourceRow) {}, t0.Add(DefaultSyncInterval)},
		{"on its own interval", func(r *statedb.KnowledgeSourceRow) { r.SyncIntervalMin = 5 }, t0.Add(5 * time.Minute)},
		{"a failure waits its interval", func(r *statedb.KnowledgeSourceRow) { r.SyncStatus = StatusError }, t0.Add(DefaultSyncInterval)},
		{"never synced: when it was created", func(r *statedb.KnowledgeSourceRow) { r.SyncedAt, r.SyncStatus = time.Time{}, "" }, t0.Add(-time.Hour)},
		{"interrupted: soon", func(r *statedb.KnowledgeSourceRow) { r.SyncStatus = StatusInterrupted }, t0.Add(resumeAfter)},
		{"stopped short of its end: soon", func(r *statedb.KnowledgeSourceRow) { r.SyncMore = true }, t0.Add(resumeAfter)},
		{"changed during its last sync: soon", func(r *statedb.KnowledgeSourceRow) {
			r.UpdatedAt, r.SyncStatus = t0.Add(-30*time.Second), StatusError
		}, t0.Add(resumeAfter)},
		{"disabled: never", func(r *statedb.KnowledgeSourceRow) { r.Enabled = false }, time.Time{}},
	} {
		row := base
		tc.edit(&row)
		if got := nextSync(row); !got.Equal(tc.want) {
			t.Errorf("%s: next sync %s, want %s", tc.name, got, tc.want)
		}
	}
}

// TestSyncIntervalBounds: a source's interval is the default, or whole
// minutes from five to a day; a change to it is recorded and resyncs nothing.
func TestSyncIntervalBounds(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	admin := f.svc.For(as(t, "root@corp.example", "admins"))
	for _, bad := range []time.Duration{time.Minute, 4 * time.Minute, 25 * time.Hour, 90 * time.Second, -time.Minute} {
		_, err := admin.CreateSource(ctx, SourceInput{Kind: "fake", Name: "Wiki " + bad.String(), Scope: ScopeOrg,
			Config: wikiConfig, SyncInterval: bad})
		wantErr(t, "an interval of "+bad.String(), err, ErrInvalid)
	}
	src := mustCreate(t, admin, SourceInput{Kind: "fake", Name: "Wiki", Scope: ScopeOrg, Config: wikiConfig,
		SyncInterval: 5 * time.Minute})
	if src.SyncInterval != 5*time.Minute || src.Interval() != 5*time.Minute {
		t.Fatalf("the source's interval = %s", src.SyncInterval)
	}
	if err := f.db.SetKnowledgeSyncCursor(src.ID, src.UpdatedAt, "page-2"); err != nil {
		t.Fatal(err)
	}
	day := 24 * time.Hour
	updated, err := admin.UpdateSource(ctx, src.ID, SourceUpdate{SyncInterval: &day})
	if err != nil || updated.SyncInterval != day || !updated.Sync.Resumes {
		t.Fatalf("a day's interval = %+v, %v; want it kept and the cursor with it", updated, err)
	}
	zero := time.Duration(0)
	if updated, err = admin.UpdateSource(ctx, src.ID, SourceUpdate{SyncInterval: &zero}); err != nil ||
		updated.SyncInterval != 0 || updated.Interval() != DefaultSyncInterval {
		t.Fatalf("back to the default = %+v, %v", updated, err)
	}
	rows, _, err := f.db.ListAuditEvents(statedb.AuditFilter{EntityType: "knowledge_source", Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	var changed int
	for _, e := range rows {
		if strings.Contains(e.Payload, `"sync_interval"`) && strings.Contains(e.Payload, `"resync":false`) {
			changed++
		}
	}
	if changed != 2 {
		t.Fatalf("%d audited interval changes, want 2", changed)
	}
}

// TestOnlyAdminsAndOwnersAskForASync: an administrator may sync any source;
// a person their own personal one, and no one else's — which they cannot even
// see — nor an organisation's; a disabled source is synced by no one.
func TestOnlyAdminsAndOwnersAskForASync(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	admin := f.svc.For(as(t, "root@corp.example", "admins"))
	alice := f.svc.For(as(t, "alice@corp.example", "operators"))
	bob := f.svc.For(as(t, "bob@corp.example", "operators"))
	org := mustCreate(t, admin, SourceInput{Kind: "fake", Name: "Org", Scope: ScopeOrg, Config: wikiConfig})
	mine := mustCreate(t, alice, SourceInput{Kind: "fake", Name: "Mine", Scope: ScopePersonal, Config: wikiConfig})

	if _, err := admin.MaySync(ctx, org.ID); err != nil {
		t.Fatalf("an admin syncing the org source: %v", err)
	}
	if _, err := admin.MaySync(ctx, mine.ID); err != nil {
		t.Fatalf("an admin syncing a personal source: %v", err)
	}
	if _, err := alice.MaySync(ctx, mine.ID); err != nil {
		t.Fatalf("the owner syncing her source: %v", err)
	}
	_, err := alice.MaySync(ctx, org.ID)
	wantErr(t, "an operator syncing the org source", err, ErrForbidden)
	_, err = bob.MaySync(ctx, mine.ID)
	wantErr(t, "someone else's personal source", err, ErrNotFound)
	if _, err := admin.UpdateSource(ctx, org.ID, SourceUpdate{Enabled: ptr(false)}); err != nil {
		t.Fatal(err)
	}
	_, err = admin.MaySync(ctx, org.ID)
	wantErr(t, "a disabled source", err, ErrDisabled)
}

// TestStopReachesEverySyncItRuns: a sync whose lease another took over while
// it was wedged, and the sync this runner then started for the same source,
// are two syncs to the runner. When the wedged one finally unwinds it takes
// nothing of the other with it: stopping the runner still interrupts the
// newer sync, which records that and releases its lease.
func TestStopReachesEverySyncItRuns(t *testing.T) {
	rf := newRunnerFixture(t)
	sc := &script{docs: pageOfDocs("d", 2), stuck: make(chan struct{}), block: make(chan struct{}),
		entered: make(chan struct{}, 2)}
	src := rf.scripted(t, "wiki", sc)
	r := rf.runner(t, "member-a", func(o *RunnerOptions) { o.LeaseTTL = 600 * time.Millisecond })

	if _, err := r.Start(src.ID, OriginManual, "ada@corp.example"); err != nil {
		t.Fatal(err)
	}
	entered(t, sc)
	// Its lease lapses while it is wedged, and is free to take.
	conn, err := statedb.OpenConn(rf.path, statedb.ReadWrite)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Exec(`UPDATE knowledge_sync_leases SET expires_ns = 1 WHERE source_id = ?`, src.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Start(src.ID, OriginManual, "bob@corp.example"); err != nil {
		t.Fatalf("a sync of the source once the wedged one's lease lapsed: %v", err)
	}
	entered(t, sc)
	// The wedged sync unwinds; its writes are refused, and it goes.
	close(sc.stuck)
	waitFor(t, "the wedged sync to unwind", func() bool {
		r.mu.Lock()
		defer r.mu.Unlock()
		return len(r.running) == 1
	})
	began := time.Now()
	r.Stop(10 * time.Second)
	if took := time.Since(began); took > 5*time.Second {
		t.Fatalf("stopping took %s: the newer sync was not interrupted", took)
	}
	row := sourceRow(t, rf, src.ID)
	if row.SyncStatus != StatusInterrupted {
		t.Fatalf("the newer sync recorded %q %q, want interrupted", row.SyncStatus, row.SyncError)
	}
	if live, _ := rf.db.LiveKnowledgeSyncLeases(time.Now()); len(live) != 0 {
		t.Fatalf("a lease outlived the stop: %+v", live)
	}
	if counts, _ := rf.db.CountKnowledge(src.ID); counts[src.ID].Documents != 0 {
		t.Fatalf("the wedged sync wrote after its lease lapsed: %+v", counts[src.ID])
	}
}

// TestAScheduledSyncOfASourceSyncedMeanwhileIsDropped: the schedule chose a
// source before its last sync recorded anything; once that sync has, a
// scheduled sync of it holds the lease, finds it no longer due, and lets it go
// without listing it again. A manual sync is never dropped so.
func TestAScheduledSyncOfASourceSyncedMeanwhileIsDropped(t *testing.T) {
	rf := newRunnerFixture(t)
	sc := &script{docs: pageOfDocs("d", 1)}
	src := rf.scripted(t, "wiki", sc)
	r := rf.runner(t, "leader", nil)
	if res, err := r.SyncNow(context.Background(), src.ID, OriginSchedule, ""); err != nil || res.Status != StatusOK {
		t.Fatalf("the first scheduled sync = %+v, %v", res, err)
	}
	res, err := r.SyncNow(context.Background(), src.ID, OriginSchedule, "")
	if err != nil || res.Status != "" || sc.lists.Load() != 1 {
		t.Fatalf("a scheduled sync of a source just synced = %+v, %v; listed %d time(s), want once", res, err, sc.lists.Load())
	}
	if live, _ := rf.db.LiveKnowledgeSyncLeases(time.Now()); len(live) != 0 {
		t.Fatalf("the dropped sync kept its lease: %+v", live)
	}
	if res, err := r.SyncNow(context.Background(), src.ID, OriginManual, "ada@corp.example"); err != nil ||
		res.Status != StatusOK || sc.lists.Load() != 2 {
		t.Fatalf("a manual sync of a source just synced = %+v, %v", res, err)
	}
}
