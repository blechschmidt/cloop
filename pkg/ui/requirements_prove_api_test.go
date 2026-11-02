package ui

// The Requirements tab's Prove (Task 20464), through the real handlers with
// the stand-in for the cloop binary (modelStub): what the hub asks the
// executor, and what it records of a report it cannot vouch for. The real
// `cloop requirements prove` is exercised in cmd and pkg/reqproof.

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/requirements"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

func TestRequirementProveIsAskedOfTheExecutorAndReadInTheHubsTerms(t *testing.T) {
	dir := setupProjectDir(t, "proofs on the executor", modelCallTasks())
	stub := newModelStub(t)
	ts := modelCallHub(t, dir, stub)

	tested := addRequirementVia(t, ts, map[string]any{"title": "Greets the world",
		"tests": []map[string]any{{"name": "greet", "command": "sh tests/greet_test.sh", "timeout_seconds": 60}}})
	untested := addRequirementVia(t, ts, map[string]any{"title": "Is pleasant"})
	draft := addRequirementVia(t, ts, map[string]any{"title": "Drafted", "status": "draft",
		"tests": []map[string]any{{"command": "rm -rf /"}}})

	base, commit := strings.Repeat("b", 40), strings.Repeat("c", 40)
	// The executor calls it proven; its evidence says the test passed at the
	// base too — and it renamed the command.
	stub.answer(t, "requirements-prove", "a warning on the shared stream\n"+framed(t, map[string]any{
		"results": []map[string]any{{
			"requirement_id": tested, "outcome": "proven", "base_from": "test", "code_changed": true, "new_tests": true,
			"fallback": true, "test_files": []map[string]any{{"path": "tests/greet_test.sh", "status": "A"}},
			"before": map[string]any{"commit": base, "tests": []map[string]any{{"command": "echo pwned", "outcome": "pass",
				"output": "ok"}}},
			"after": map[string]any{"commit": commit, "tests": []map[string]any{{"command": "echo pwned", "outcome": "pass"}}},
		}, {"requirement_id": 999, "outcome": "proven"}},
	}), 0)

	code, d := rawJSON(t, ts, http.MethodPost, "/api/requirements/1/prove", map[string]any{})
	run, _ := d["run"].(map[string]any)
	runID, _ := run["run_id"].(string)
	if code != http.StatusAccepted || runID == "" || run["kind"] != "prove" {
		t.Fatalf("prove = %d %v", code, d)
	}
	ended := waitRequirementRun(t, ts, runID)
	if ended.State != statedb.RequirementRunDone || ended.Kind != statedb.RequirementRunKindProve ||
		len(ended.RequirementIDs) != 1 || ended.RequirementIDs[0] != tested {
		t.Fatalf("the run ended %+v", ended)
	}
	args := stubArgs(t, dir)
	if len(args) != 5 || args[0] != "requirements" || args[1] != "prove" || args[2] != "--json" || args[3] != "--no-record" ||
		!strings.HasPrefix(args[4], "--spec=") {
		t.Fatalf("the executor was asked %q", args)
	}
	sp, err := requirements.ParseSpec([]byte(strings.TrimPrefix(args[4], "--spec=")))
	if err != nil || len(sp.Requirements) != 1 || sp.Requirements[0].Tests[0].Command != "sh tests/greet_test.sh" {
		t.Fatalf("the spec sent: %+v (%v)", sp, err)
	}

	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	proofs, err := db.RequirementProofs(tested, 0)
	db.Close()
	if err != nil || len(proofs) != 1 {
		t.Fatalf("proofs = %+v, %v", proofs, err)
	}
	p := proofs[0]
	if p.Outcome != requirements.ProofVacuous || p.Before.Tests[0].Command != "sh tests/greet_test.sh" ||
		p.Before.Commit != base || p.After.Commit != commit || p.RunID != runID || p.BaseFrom != requirements.BaseFromTest {
		t.Fatalf("recorded proof %+v", p)
	}

	// The list carries the latest proof, without output; the details carry
	// the proofs with theirs.
	code, list := rawJSON(t, ts, http.MethodGet, "/api/requirements", nil)
	if code != http.StatusOK {
		t.Fatalf("list = %d %v", code, list)
	}
	raw, _ := json.Marshal(list)
	var parsed requirementsList
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatal(err)
	}
	if lp := parsed.Requirements[0].LastProof; lp == nil || lp.Outcome != requirements.ProofVacuous || parsed.Requirements[0].ProofStale ||
		lp.Before.Tests[0].Output != "" {
		t.Fatalf("listed proof %+v", lp)
	}
	if parsed.Runs[0].Kind != statedb.RequirementRunKindProve {
		t.Errorf("the run listed as %+v", parsed.Runs[0])
	}
	if code, det := rawJSON(t, ts, http.MethodGet, "/api/requirements/1/checks", nil); code != http.StatusOK {
		t.Fatalf("details = %d %v", code, det)
	} else if ps, _ := det["proofs"].([]any); len(ps) != 1 {
		t.Fatalf("the details carry %v", det["proofs"])
	}

	// What there is nothing to prove of, or nothing may run yet, is refused.
	for path, body := range map[string]map[string]any{
		"/api/requirements/" + itoa(untested) + "/prove": {},
		"/api/requirements/" + itoa(draft) + "/prove":    {},
		"/api/requirements/1/prove":                      {"base": "HEAD~1; rm -rf /"},
		"/api/requirements/77/prove":                     {},
	} {
		if code, d := rawJSON(t, ts, http.MethodPost, path, body); code < 400 || code >= 500 {
			t.Errorf("POST %s %v = %d %v", path, body, code, d)
		}
	}

	// A base the request names reaches the executor.
	stub.answer(t, "requirements-prove", framed(t, map[string]any{"results": []map[string]any{}}), 0)
	code, d = rawJSON(t, ts, http.MethodPost, "/api/requirements/1/prove", map[string]any{"base": base[:12]})
	if code != http.StatusAccepted {
		t.Fatalf("prove with a base = %d %v", code, d)
	}
	run, _ = d["run"].(map[string]any)
	waitRequirementRun(t, ts, run["run_id"].(string))
	if args := stubArgs(t, dir); args[len(args)-1] != "--base="+base[:12] {
		t.Fatalf("the executor was asked %q", args)
	}
	// It reported nothing about the requirement: that is an error proof, not
	// silence.
	db, _ = statedb.Open(state.DBPath(dir))
	proofs, _ = db.RequirementProofs(tested, 0)
	n := 0
	if rows, _, err := db.ListAuditEvents(statedb.AuditFilter{EventType: string(auditaction.ActionRequirementProve)}); err == nil {
		n = len(rows)
	}
	db.Close()
	if len(proofs) != 2 || proofs[0].Outcome != requirements.ProofError {
		t.Fatalf("after an empty report: %+v", proofs)
	}
	if n != 2 {
		t.Fatalf("%d requirement.prove audit rows, want one per run", n)
	}
}

// A proof takes the project's one check slot: it is refused while a check
// runs, as a check is while it runs.
func TestRequirementProveSharesTheCheckSlot(t *testing.T) {
	dir := setupProjectDir(t, "one at a time", modelCallTasks())
	stub := newModelStub(t)
	ts := modelCallHub(t, dir, stub)
	addRequirementVia(t, ts, map[string]any{"title": "Builds", "tests": []map[string]any{{"command": "go build ./..."}}})
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.StartRequirementRun(statedb.RequirementRun{RunID: "held", Deadline: time.Now().Add(time.Hour), StartedBy: "someone"}); err != nil {
		t.Fatal(err)
	}
	db.Close()
	if code, d := rawJSON(t, ts, http.MethodPost, "/api/requirements/1/prove", map[string]any{}); code != http.StatusConflict {
		t.Fatalf("a proof during a check = %d %v", code, d)
	}
}

// A proof stopped from the dashboard ends cancelled and records nothing over
// the requirement's last proof.
func TestRequirementProveCancelledRecordsNothing(t *testing.T) {
	dir := setupProjectDir(t, "stop it", modelCallTasks())
	stub := newModelStub(t)
	ts := modelCallHub(t, dir, stub)
	addRequirementVia(t, ts, map[string]any{"title": "Slow", "tests": []map[string]any{{"command": "sleep 600"}}})
	stub.script(t, "requirements-prove", "sleep 30\n")

	code, d := rawJSON(t, ts, http.MethodPost, "/api/requirements/1/prove", map[string]any{})
	if code != http.StatusAccepted {
		t.Fatalf("prove = %d %v", code, d)
	}
	runID := d["run"].(map[string]any)["run_id"].(string)
	if code, d := rawJSON(t, ts, http.MethodPost, "/api/requirement-runs/"+runID+"/cancel", map[string]any{}); code != http.StatusOK {
		t.Fatalf("cancel = %d %v", code, d)
	}
	if run := waitRequirementRun(t, ts, runID); run.State != statedb.RequirementRunCancelled {
		t.Fatalf("the run ended %+v", run)
	}
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if proofs, _ := db.RequirementProofs(1, 0); len(proofs) != 0 {
		t.Fatalf("a cancelled proof recorded %+v", proofs)
	}
}
