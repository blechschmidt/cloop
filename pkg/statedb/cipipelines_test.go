package statedb

// Storage-level tests for CI/CD pipeline federation (Task 20278).
//
// Rule validation and matching are tested against pkg/ciauth, which owns them.
// What is tested here is the part only a real database can answer: that the
// migration is classified additive so the older hub sharing this control plane
// keeps working, that a rule round-trips without a field being silently
// dropped, that evaluation order is stable, and that a corrupted row degrades
// to "no allowlist" rather than to "any model".

import (
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func openCIDB(t *testing.T) *DB {
	t.Helper()
	db, err := Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// TestCIPipelinesMigrationIsAdditive is the compatibility gate.
//
// :8080 and :8888 run from the same directory and therefore share one
// control-plane database, and dev builds migrate every registered project's
// state.db. A migration classified breaking makes the older binary refuse to
// open them, which blanks its dashboard until the nightly rebuild.
//
// This asserts the verdict for *this* migration rather than trusting that two
// CREATE TABLEs look additive: the classifier is conservative and refuses
// shapes it cannot parse, so a future edit adding an ALTER — or a UNIQUE index
// over a pre-existing table — must fail here rather than in production.
func TestCIPipelinesMigrationIsAdditive(t *testing.T) {
	migrations, err := loadMigrations()
	if err != nil {
		t.Fatalf("load migrations: %v", err)
	}
	var found bool
	for _, m := range migrations {
		if m.Version != 40 {
			continue
		}
		found = true
		if got := classifyMigration(string(m.SQL)); got != CompatAdditive {
			t.Errorf("0040_ci_pipelines classified %q, want %q — an older hub "+
				"sharing this control plane would refuse to open the database",
				got, CompatAdditive)
		}
	}
	if !found {
		t.Fatal("migration 40 is not in the embedded set")
	}
}

func TestCIPipelineRule_RoundTrip(t *testing.T) {
	db := openCIDB(t)
	created := time.Now().UTC().Truncate(time.Millisecond)
	want := CIPipelineRuleRow{
		ID:              "rule-1",
		Name:            "acme tool releases",
		Enabled:         true,
		Repository:      "acme/tool",
		Ref:             "refs/heads/main",
		Workflow:        "release",
		Environment:     "production",
		Actor:           "dana",
		EventName:       "push",
		Condition:       `assertion.runner_environment == "github-hosted"`,
		Models:          []string{"claude-sonnet-4-*", "claude-haiku-4-5-20251001"},
		MaxRequests:     250,
		MaxOutputTokens: 8000,
		TTLSeconds:      1800,
		Project:         "tool",
		CreatedBy:       "dana@example.com",
		CreatedAt:       created,
		UpdatedAt:       created,
	}
	if err := db.PutCIPipelineRule(want); err != nil {
		t.Fatalf("PutCIPipelineRule: %v", err)
	}
	got, err := db.GetCIPipelineRule("rule-1")
	if err != nil {
		t.Fatalf("GetCIPipelineRule: %v", err)
	}
	// Compared field by field rather than with reflect.DeepEqual so a new
	// column that is written but not read is named by the failure.
	if got.Name != want.Name || got.Enabled != want.Enabled {
		t.Errorf("name/enabled = %q/%v", got.Name, got.Enabled)
	}
	if got.Repository != want.Repository || got.Ref != want.Ref ||
		got.Workflow != want.Workflow || got.Environment != want.Environment ||
		got.Actor != want.Actor || got.EventName != want.EventName {
		t.Errorf("matcher did not round-trip: %+v", got)
	}
	if got.Condition != want.Condition {
		t.Errorf("condition = %q, want %q", got.Condition, want.Condition)
	}
	if len(got.Models) != 2 || got.Models[0] != "claude-sonnet-4-*" {
		t.Errorf("models = %v", got.Models)
	}
	if got.MaxRequests != 250 || got.MaxOutputTokens != 8000 || got.TTLSeconds != 1800 {
		t.Errorf("policy did not round-trip: %+v", got)
	}
	if got.Project != "tool" || got.CreatedBy != "dana@example.com" {
		t.Errorf("provenance did not round-trip: %+v", got)
	}
	if !got.CreatedAt.Equal(created) {
		t.Errorf("CreatedAt = %v, want %v", got.CreatedAt, created)
	}
	if !got.LastMatchedAt.IsZero() {
		t.Errorf("LastMatchedAt = %v, want zero on a rule nothing has matched", got.LastMatchedAt)
	}
}

func TestCIPipelineRule_UpsertEditsRatherThanDuplicating(t *testing.T) {
	db := openCIDB(t)
	base := CIPipelineRuleRow{ID: "r", Name: "before", Enabled: true,
		Repository: "acme/tool", Models: []string{"a"}, CreatedAt: time.Now()}
	if err := db.PutCIPipelineRule(base); err != nil {
		t.Fatalf("put: %v", err)
	}
	base.Name = "after"
	base.Enabled = false
	base.Models = []string{"b", "c"}
	base.UpdatedAt = time.Now()
	if err := db.PutCIPipelineRule(base); err != nil {
		t.Fatalf("re-put: %v", err)
	}
	all, err := db.ListCIPipelineRules()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(all) != 1 {
		t.Fatalf("got %d rules, want the edit to have replaced the original", len(all))
	}
	if all[0].Name != "after" || all[0].Enabled || len(all[0].Models) != 2 {
		t.Errorf("edit did not take: %+v", all[0])
	}
}

func TestCIPipelineRule_MissingIsNotFound(t *testing.T) {
	db := openCIDB(t)
	_, err := db.GetCIPipelineRule("nope")
	if !errors.Is(err, ErrCIPipelineRuleNotFound) {
		t.Fatalf("err = %v, want ErrCIPipelineRuleNotFound", err)
	}
	if err := db.PutCIPipelineRule(CIPipelineRuleRow{}); err == nil {
		t.Error("PutCIPipelineRule accepted a row with no id")
	}
}

func TestCIPipelineRule_ListIsInStableEvaluationOrder(t *testing.T) {
	db := openCIDB(t)
	base := time.Now().UTC()
	// Inserted newest-first so a naive "insertion order" implementation would
	// disagree with the answer.
	for i, r := range []CIPipelineRuleRow{
		{ID: "c", Name: "third", Repository: "acme/c", CreatedAt: base.Add(2 * time.Minute)},
		{ID: "a", Name: "first", Repository: "acme/a", CreatedAt: base},
		{ID: "b", Name: "second", Repository: "acme/b", CreatedAt: base.Add(time.Minute)},
	} {
		if err := db.PutCIPipelineRule(r); err != nil {
			t.Fatalf("put %d: %v", i, err)
		}
	}
	got, err := db.ListCIPipelineRules()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	want := []string{"a", "b", "c"}
	if len(got) != len(want) {
		t.Fatalf("got %d rules, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i].ID != want[i] {
			t.Fatalf("order = %v, want %v — first-match-wins needs a stable order",
				[]string{got[0].ID, got[1].ID, got[2].ID}, want)
		}
	}
}

func TestCIPipelineRule_DeleteReportsWhetherItRemovedAnything(t *testing.T) {
	db := openCIDB(t)
	if err := db.PutCIPipelineRule(CIPipelineRuleRow{ID: "r", Name: "n",
		Repository: "acme/tool", CreatedAt: time.Now()}); err != nil {
		t.Fatalf("put: %v", err)
	}
	ok, err := db.DeleteCIPipelineRule("r")
	if err != nil || !ok {
		t.Fatalf("Delete = (%v, %v), want (true, nil)", ok, err)
	}
	ok, err = db.DeleteCIPipelineRule("r")
	if err != nil || ok {
		t.Fatalf("second Delete = (%v, %v), want (false, nil)", ok, err)
	}
}

func TestCIPipelineRule_TouchStampsTheMatch(t *testing.T) {
	db := openCIDB(t)
	if err := db.PutCIPipelineRule(CIPipelineRuleRow{ID: "r", Name: "n",
		Repository: "acme/tool", CreatedAt: time.Now()}); err != nil {
		t.Fatalf("put: %v", err)
	}
	at := time.Now().UTC().Truncate(time.Millisecond)
	if err := db.TouchCIPipelineRule("r", at); err != nil {
		t.Fatalf("touch: %v", err)
	}
	got, err := db.GetCIPipelineRule("r")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if !got.LastMatchedAt.Equal(at) {
		t.Errorf("LastMatchedAt = %v, want %v", got.LastMatchedAt, at)
	}
	// Touching a rule that is gone is not an error the exchange path should
	// have to care about.
	if err := db.TouchCIPipelineRule("gone", at); err != nil {
		t.Errorf("touch on a missing rule = %v, want nil", err)
	}
}

func TestCIPipelineRule_CorruptModelsColumnDegradesToNoAllowlist(t *testing.T) {
	db := openCIDB(t)
	if err := db.PutCIPipelineRule(CIPipelineRuleRow{ID: "r", Name: "n",
		Repository: "acme/tool", Models: []string{"claude-sonnet-4-6"},
		CreatedAt: time.Now()}); err != nil {
		t.Fatalf("put: %v", err)
	}
	// Hand-edit the column to something that will not decode, the way a
	// direct sqlite3 session would.
	db.mu.Lock()
	_, err := db.conn.Exec(`UPDATE ci_pipeline_rules SET models_json = ? WHERE id = 'r'`, "{not json")
	db.mu.Unlock()
	if err != nil {
		t.Fatalf("corrupt: %v", err)
	}
	got, err := db.GetCIPipelineRule("r")
	if err != nil {
		t.Fatalf("get after corruption: %v", err)
	}
	// The safe direction: an unreadable allowlist is no allowlist, which
	// pkg/ciauth then refuses to mint a session from. The unsafe reading of
	// the same failure would be "no restriction".
	if len(got.Models) != 0 {
		t.Errorf("Models = %v, want empty so minting refuses", got.Models)
	}
}

func TestCIExchange_RoundTripAndPrune(t *testing.T) {
	db := openCIDB(t)
	base := time.Now().UTC()
	for i := 0; i < 5; i++ {
		if err := db.PutCIExchange(CIExchangeRow{
			ID:         string(rune('a' + i)),
			At:         base.Add(time.Duration(i) * time.Minute),
			Accepted:   i%2 == 0,
			Issuer:     "https://token.actions.githubusercontent.com",
			Subject:    "repo:acme/tool:ref:refs/heads/main",
			Repository: "acme/tool",
			Ref:        "refs/heads/main",
			RuleID:     "rule-1",
			Reason:     "no_rule",
			Detail:     "no rule admits this pipeline",
			Claims:     map[string]any{"repository": "acme/tool", "run_id": "42"},
		}); err != nil {
			t.Fatalf("put %d: %v", i, err)
		}
	}
	got, err := db.ListCIExchanges(0)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 5 {
		t.Fatalf("got %d exchanges, want 5", len(got))
	}
	// Newest first: an operator debugging a pipeline wants the last attempt.
	if got[0].ID != "e" {
		t.Errorf("first row = %q, want the newest", got[0].ID)
	}
	if got[0].Claims["repository"] != "acme/tool" {
		t.Errorf("claims did not round-trip: %v", got[0].Claims)
	}
	if !got[0].Accepted {
		t.Errorf("accepted flag did not round-trip")
	}

	n, err := db.PruneCIExchanges(2)
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if n != 3 {
		t.Errorf("pruned %d rows, want 3", n)
	}
	got, err = db.ListCIExchanges(0)
	if err != nil {
		t.Fatalf("list after prune: %v", err)
	}
	if len(got) != 2 || got[0].ID != "e" || got[1].ID != "d" {
		t.Errorf("prune kept the wrong rows: %+v", got)
	}
}

func TestCIExchange_RequiresAnID(t *testing.T) {
	db := openCIDB(t)
	if err := db.PutCIExchange(CIExchangeRow{}); err == nil {
		t.Error("PutCIExchange accepted a row with no id")
	}
}
