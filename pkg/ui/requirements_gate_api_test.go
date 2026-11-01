package ui

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/requirements"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// The overview's requirements gate control (Task 20461) stores the setting on
// its own — a running orchestrator's stale copy cannot put the old one back —
// and refuses a mode it does not know.
func TestRequirementsGateOption(t *testing.T) {
	dir := setupProjectDir(t, cloopGoal, nil)
	ts := newTestServer(t, dir, nil)
	run, err := state.Load(dir) // a run's copy, read before the change
	if err != nil {
		t.Fatal(err)
	}
	body := apiPOST(t, ts, "/api/options/requirements-gate", map[string]any{"mode": "linked+must"})
	if body["ok"] != true || body["declared"] != false {
		t.Fatalf("set = %v", body)
	}
	if g := loadStateOrFail(t, dir).RequirementsGate; !g.IncludesMust() || g.Assess {
		t.Fatalf("stored gate = %+v", g)
	}
	apiPOST(t, ts, "/api/options/requirements-gate", map[string]any{"assess": true})
	if err := run.SaveDirect(); err != nil {
		t.Fatal(err)
	}
	if g := loadStateOrFail(t, dir).RequirementsGate; !g.IncludesMust() || !g.Assess {
		t.Fatalf("after a stale save: %+v", g)
	}
	if st := apiGET(t, ts, "/api/state"); st["requirements_gate"] == nil {
		t.Fatalf("/api/state carries no requirements_gate: %v", st)
	}

	for _, bad := range []map[string]any{{"mode": "always"}, {}} {
		data, _ := json.Marshal(bad)
		resp, err := http.Post(ts.URL+"/api/options/requirements-gate", "application/json", bytes.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("POST %v = %d, want 400", bad, resp.StatusCode)
		}
	}
	if g := loadStateOrFail(t, dir).RequirementsGate; !g.IncludesMust() {
		t.Errorf("a refused change changed the gate: %+v", g)
	}
}

// A project whose config.yaml declares the gate has the declaration rewritten
// with the setting, so the next `cloop run` does not put the old one back.
func TestRequirementsGateOptionRewritesTheDeclaration(t *testing.T) {
	dir := setupProjectDir(t, cloopGoal, nil)
	if err := os.WriteFile(filepath.Join(dir, ".cloop", "config.yaml"), []byte("provider: claudecode\nrequirements:\n  gate: linked\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ts := newTestServer(t, dir, nil)
	body := apiPOST(t, ts, "/api/options/requirements-gate", map[string]any{"mode": "off", "assess": true})
	if body["ok"] != true || body["declared"] != true {
		t.Fatalf("set = %v", body)
	}
	cfg, err := config.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Requirements.Gate != "off" || cfg.Requirements.Assess == nil || !*cfg.Requirements.Assess {
		t.Fatalf("declaration = %+v", cfg.Requirements)
	}
}

// The journal rows the gate writes tell the Requirements tab to read again.
func TestGateCheckRowsAreRecognised(t *testing.T) {
	row := func(t statedb.EventType) statedb.HistoryRow {
		return statedb.HistoryRow{Event: &statedb.EventRow{Type: t}}
	}
	if gateCheckRows([]statedb.HistoryRow{row(statedb.EventTaskDone), {Step: &statedb.StepRow{}}}) {
		t.Error("an ordinary row was taken for a gate check")
	}
	for _, typ := range []statedb.EventType{statedb.EventTaskRequirements, statedb.EventRequirementRegression} {
		if !gateCheckRows([]statedb.HistoryRow{row(statedb.EventTaskDone), row(typ)}) {
			t.Errorf("%s was not recognised", typ)
		}
	}
}

// The notifier reads every project's recent regressions, with the titles a
// message names them by, and reads a project's database again only once it
// has changed.
func TestRecentRegressionsAreReadFromTheHubsProjects(t *testing.T) {
	dir := setupProjectDir(t, cloopGoal, []*pm.Task{{ID: 4, Title: "Add coupons", Status: pm.TaskDone}})
	srv := New(dir, 0, "")
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.AsProject()
	req, err := db.AddRequirement(requirements.Requirement{Title: "Checkout works", Tests: []requirements.Test{{Command: "make checkout"}}}, "t")
	if err != nil {
		t.Fatal(err)
	}
	at := time.Now().Add(-time.Minute).UTC()
	res := func(v string, at time.Time) []requirements.Result {
		return []requirements.Result{{RequirementID: req.ID, Fingerprint: req.Fingerprint(), Method: requirements.MethodTests, Verdict: v, StartedAt: at}}
	}
	if _, err := db.RecordRequirementChecks(statedb.CheckRecord{Commit: strings.Repeat("a", 40)}, res(requirements.VerdictFulfilled, at)); err != nil {
		t.Fatal(err)
	}
	if got := srv.recentRegressions(time.Now()); len(got) != 0 {
		t.Fatalf("regressions before one happened: %+v", got)
	}
	if _, err := db.RecordRequirementChecks(statedb.CheckRecord{Commit: strings.Repeat("b", 40), TaskID: 4},
		res(requirements.VerdictUnfulfilled, at.Add(time.Second))); err != nil {
		t.Fatal(err)
	}
	// The cache keys on the state files' modification time, which a write in
	// the same instant may not move.
	srv.regressions.mu.Lock()
	srv.regressions.entries = nil
	srv.regressions.mu.Unlock()
	got := srv.recentRegressions(time.Now())
	if len(got) != 1 {
		t.Fatalf("regressions = %+v", got)
	}
	g := got[0]
	if g.RequirementTitle != "Checkout works" || g.TaskID != 4 || g.TaskTitle != "Add coupons" ||
		g.WasCommit != strings.Repeat("a", 40) || g.Commit != strings.Repeat("b", 40) || g.ProjectKey == "" {
		t.Errorf("regression = %+v", g)
	}
}
