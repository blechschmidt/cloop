package quotastore

// Round-trips through the real SQLite schema, because that is the path a
// deployed hub actually takes. The in-memory store in pkg/quota proves the
// admission logic; this proves the rows survive.

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/quota"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

func openStore(t *testing.T) (*Store, *statedb.DB) {
	t.Helper()
	db, err := statedb.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("statedb.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	s, err := New(db)
	if err != nil {
		t.Fatalf("quotastore.New: %v", err)
	}
	return s, db
}

func TestOverrideRoundTrip(t *testing.T) {
	t.Parallel()
	s, _ := openStore(t)

	now := time.Now().UTC().Truncate(time.Second)
	in := quota.Override{
		Identity:  "alice@example.com",
		Limits:    quota.Limits{quota.ResProjects: 5, quota.ResDailyCostUSD: 12.50},
		UpdatedAt: now,
		UpdatedBy: "admin@example.com",
	}
	if err := s.PutOverride(in); err != nil {
		t.Fatalf("PutOverride: %v", err)
	}

	got, err := s.LoadOverrides()
	if err != nil {
		t.Fatalf("LoadOverrides: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("LoadOverrides returned %d rows, want 1", len(got))
	}
	if got[0].Identity != in.Identity || got[0].UpdatedBy != in.UpdatedBy {
		t.Errorf("round trip = %+v, want identity/updated_by preserved", got[0])
	}
	if v, ok := got[0].Limits.Get(quota.ResProjects); !ok || v != 5 {
		t.Errorf("max_projects = (%v, %v), want (5, true)", v, ok)
	}
	// Money must survive as money: an integer column would silently round a
	// $12.50 ceiling to $12 or $13.
	if v, ok := got[0].Limits.Get(quota.ResDailyCostUSD); !ok || v != 12.50 {
		t.Errorf("daily_cost_usd = (%v, %v), want (12.5, true)", v, ok)
	}

	// Upsert, not a duplicate row.
	in.Limits = quota.Limits{quota.ResProjects: 9}
	if err := s.PutOverride(in); err != nil {
		t.Fatalf("PutOverride (update): %v", err)
	}
	got, _ = s.LoadOverrides()
	if len(got) != 1 {
		t.Fatalf("after update there are %d rows, want 1 — the write duplicated instead of replacing", len(got))
	}
	if v, _ := got[0].Limits.Get(quota.ResProjects); v != 9 {
		t.Errorf("max_projects = %v after update, want 9", v)
	}

	existed, err := s.DeleteOverride("alice@example.com")
	if err != nil || !existed {
		t.Fatalf("DeleteOverride = (%v, %v), want (true, nil)", existed, err)
	}
	if existed, _ := s.DeleteOverride("alice@example.com"); existed {
		t.Error("DeleteOverride reported a second deletion — it is not idempotent")
	}
}

// TestMalformedOverrideIsSkippedNotFatal: refusing to start because one
// hand-edited row will not parse takes down every tenant to protect one
// ceiling.
func TestMalformedOverrideIsSkippedNotFatal(t *testing.T) {
	t.Parallel()
	s, db := openStore(t)

	if err := db.PutQuotaOverride(statedb.QuotaOverrideRow{
		Identity: "broken@example.com", LimitsJSON: "{not json",
	}); err != nil {
		t.Fatalf("seed malformed row: %v", err)
	}
	if err := s.PutOverride(quota.Override{
		Identity: "ok@example.com", Limits: quota.Limits{quota.ResProjects: 2},
	}); err != nil {
		t.Fatalf("PutOverride: %v", err)
	}

	got, err := s.LoadOverrides()
	if err != nil {
		t.Fatalf("LoadOverrides returned an error for one bad row: %v", err)
	}
	if len(got) != 1 || got[0].Identity != "ok@example.com" {
		t.Fatalf("LoadOverrides = %+v, want only the well-formed row", got)
	}
}

func TestCounterRoundTripAndZeroDeletes(t *testing.T) {
	t.Parallel()
	s, _ := openStore(t)

	rows := []quota.CounterRow{
		{Identity: "alice@example.com", Resource: quota.ResProjects, Bucket: "", Value: 2},
		{Identity: "alice@example.com", Resource: quota.ResDailyTokens, Bucket: "2026-08-22", Value: 1500},
		{Identity: "bob@example.com", Resource: quota.ResExecutors, Bucket: "", Value: 1},
	}
	for _, r := range rows {
		if err := s.PutCounter(r); err != nil {
			t.Fatalf("PutCounter %+v: %v", r, err)
		}
	}
	got, err := s.LoadCounters()
	if err != nil {
		t.Fatalf("LoadCounters: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("LoadCounters returned %d rows, want 3", len(got))
	}

	// Dropping to zero deletes the row: an identity holding nothing should
	// not keep a row per resource forever, and "0" must not be a second way
	// of spelling "absent" that every reader has to reconcile.
	if err := s.PutCounter(quota.CounterRow{
		Identity: "bob@example.com", Resource: quota.ResExecutors, Bucket: "", Value: 0,
	}); err != nil {
		t.Fatalf("PutCounter zero: %v", err)
	}
	got, _ = s.LoadCounters()
	for _, r := range got {
		if r.Identity == "bob@example.com" {
			t.Errorf("a zeroed counter survived as %+v", r)
		}
	}
}

// TestReplaceGaugesSwapsOnlyGauges — reconciliation must erase stale gauges
// without touching the daily counters, which have no live equivalent to
// rebuild from.
func TestReplaceGaugesSwapsOnlyGauges(t *testing.T) {
	t.Parallel()
	s, _ := openStore(t)

	seed := []quota.CounterRow{
		{Identity: "ghost@example.com", Resource: quota.ResConcurrentTasks, Value: 3},
		{Identity: "alice@example.com", Resource: quota.ResProjects, Value: 1},
		{Identity: "alice@example.com", Resource: quota.ResDailyTokens, Bucket: "2026-08-22", Value: 900},
	}
	for _, r := range seed {
		if err := s.PutCounter(r); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}

	// The world as it really is: alice owns two projects, the ghost is gone.
	if err := s.ReplaceGauges([]quota.CounterRow{
		{Identity: "alice@example.com", Resource: quota.ResProjects, Value: 2},
	}); err != nil {
		t.Fatalf("ReplaceGauges: %v", err)
	}

	got, err := s.LoadCounters()
	if err != nil {
		t.Fatalf("LoadCounters: %v", err)
	}
	gauges, daily := map[string]float64{}, map[string]float64{}
	for _, r := range got {
		key := r.Identity + "/" + string(r.Resource)
		if r.Bucket == "" {
			gauges[key] = r.Value
		} else {
			daily[key] = r.Value
		}
	}
	if _, stale := gauges["ghost@example.com/max_concurrent_tasks"]; stale {
		t.Error("a gauge for an identity absent from live state survived reconciliation — " +
			"that tenant stays narrowed forever")
	}
	if gauges["alice@example.com/max_projects"] != 2 {
		t.Errorf("alice's project gauge = %v, want the reconciled 2",
			gauges["alice@example.com/max_projects"])
	}
	if daily["alice@example.com/daily_token_budget"] != 900 {
		t.Errorf("daily spend = %v after reconciliation, want 900 untouched — "+
			"rebuilding it would refund a budget on every restart",
			daily["alice@example.com/daily_token_budget"])
	}
}

// TestPruneKeepsGauges. Gauge rows carry bucket "", which sorts before every
// date, so an unguarded `bucket < ?` would delete all of them — silently
// handing every tenant a clean slate on the first prune.
func TestPruneKeepsGauges(t *testing.T) {
	t.Parallel()
	s, _ := openStore(t)

	for _, r := range []quota.CounterRow{
		{Identity: "alice@example.com", Resource: quota.ResProjects, Bucket: "", Value: 2},
		{Identity: "alice@example.com", Resource: quota.ResDailyTokens, Bucket: "2020-01-01", Value: 5},
		{Identity: "alice@example.com", Resource: quota.ResDailyCostUSD, Bucket: "2026-08-22", Value: 3},
	} {
		if err := s.PutCounter(r); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	if err := s.PruneCountersBefore("2026-08-22"); err != nil {
		t.Fatalf("PruneCountersBefore: %v", err)
	}

	got, _ := s.LoadCounters()
	var gauge, old, today bool
	for _, r := range got {
		switch {
		case r.Bucket == "":
			gauge = true
		case r.Bucket == "2020-01-01":
			old = true
		case r.Bucket == "2026-08-22":
			today = true
		}
	}
	if !gauge {
		t.Error("the prune deleted a gauge row — '' sorts before every date, so the " +
			"comparison must exclude it explicitly")
	}
	if old {
		t.Error("a 2020 day bucket survived the prune")
	}
	if !today {
		t.Error("today's bucket was pruned")
	}

	// An empty bucket must be a no-op, not a table wipe.
	if err := s.PruneCountersBefore(""); err != nil {
		t.Fatalf("PruneCountersBefore(\"\"): %v", err)
	}
	if after, _ := s.LoadCounters(); len(after) != len(got) {
		t.Errorf("pruning with an empty bucket deleted %d rows", len(got)-len(after))
	}
}

// TestEnforcerOverSQLiteSurvivesRestart is the integration the two halves
// exist for: admission through pkg/quota, persistence through this store, and
// the caps still standing after a fresh process reads them back.
func TestEnforcerOverSQLiteSurvivesRestart(t *testing.T) {
	t.Parallel()
	store, _ := openStore(t)

	resolver, err := quota.New(quota.Config{
		Defaults: quota.Limits{quota.ResProjects: 2, quota.ResDailyTokens: 1000},
	})
	if err != nil {
		t.Fatalf("quota.New: %v", err)
	}

	subj := quota.SubjectForIdentity("alice@example.com")
	e := quota.NewEnforcer(resolver, store)
	for i := 0; i < 2; i++ {
		if _, err := e.Admit(subj, quota.ResProjects, 1); err != nil {
			t.Fatalf("admit %d: %v", i, err)
		}
	}
	e.Spend("alice@example.com", 1000, 0)

	restarted := quota.NewEnforcer(resolver, store)
	if err := restarted.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if _, err := restarted.Admit(subj, quota.ResProjects, 1); err == nil {
		t.Error("the project cap did not survive a restart — two projects were already owned")
	}
	if err := restarted.CheckSpend(subj); err == nil {
		t.Error("the daily token budget did not survive a restart — it was fully spent")
	}
}
