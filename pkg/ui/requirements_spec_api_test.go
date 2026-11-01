package ui

// Requirements as code from the dashboard (Task 20459), through the real
// handlers with the stand-in for the cloop binary (modelStub): the hub asks the
// project's executor for its spec file, parses what comes back itself, and
// imports only what was reviewed. The real `cloop requirements validate` on
// the far end, and the permissions, are exercised in cmd
// (requirements_spec_test.go), through a hub with sign-on.

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/requirements"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// noSpecCooldown lets a test read the spec file again at once.
func noSpecCooldown(t *testing.T) {
	t.Helper()
	old := specReadCooldown
	specReadCooldown = 0
	t.Cleanup(func() { specReadCooldown = old })
}

// executorHasSpec scripts what the executor's `cloop requirements validate
// --json` prints for a checkout holding content.
func executorHasSpec(t *testing.T, stub *modelStub, content string, extra map[string]any) {
	t.Helper()
	rep := map[string]any{"path": requirements.SpecFileName, "found": true, "content": []byte(content),
		"commit": "ABCDEF0123456789abcdef0123456789abcdef01", "valid": true, "requirements": 99}
	for k, v := range extra {
		rep[k] = v
	}
	stub.answer(t, "requirements-validate", "a diagnostic on the shared stream\n"+framed(t, rep), 0)
}

// specOf decodes the spec view a response carries.
func specOf(t *testing.T, d map[string]any) specView {
	t.Helper()
	raw, err := json.Marshal(d["spec"])
	if err != nil {
		t.Fatal(err)
	}
	var v specView
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("no spec in %v: %v", d, err)
	}
	return v
}

// readSpecVia asks for a read of the spec file and waits for it to end.
func readSpecVia(t *testing.T, ts *httptest.Server) specView {
	t.Helper()
	return readSpecAs(t, ts, map[string]any{})
}

func readSpecAs(t *testing.T, ts *httptest.Server, body map[string]any) specView {
	t.Helper()
	code, d := rawJSON(t, ts, http.MethodPost, "/api/requirements/spec/read", body)
	switch code {
	case http.StatusOK:
		return specOf(t, d)
	case http.StatusAccepted:
	default:
		t.Fatalf("read = %d %v", code, d)
	}
	return waitSpecRead(t, ts)
}

// waitSpecRead waits for this member's read of the spec file to end.
func waitSpecRead(t *testing.T, ts *httptest.Server) specView {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for {
		code, d := rawJSON(t, ts, http.MethodGet, "/api/requirements/spec", nil)
		if code != http.StatusOK {
			t.Fatalf("spec = %d %v", code, d)
		}
		if v := specOf(t, d); !v.Reading {
			return v
		}
		if time.Now().After(deadline) {
			t.Fatal("the read of the spec file is still running after a minute")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func renderSpec(t *testing.T, reqs ...requirements.Requirement) string {
	t.Helper()
	out, err := requirements.RenderSpecFile(reqs)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

func TestTheSpecFileIsReadOnTheExecutorAndImportedAsReviewed(t *testing.T) {
	noSpecCooldown(t)
	dir := setupProjectDir(t, "requirements as code", modelCallTasks())
	stub := newModelStub(t)
	ts := modelCallHub(t, dir, stub)

	one := addRequirementVia(t, ts, map[string]any{"title": "Builds", "tests": []map[string]any{{"command": "go build ./..."}}})
	two := addRequirementVia(t, ts, map[string]any{"title": "Is documented", "status": "draft"})
	r1 := requirements.Requirement{ID: one, Title: "Builds", Status: "approved", Tests: []requirements.Test{{Command: "go build ./..."}}}
	r2 := requirements.Requirement{ID: two, Title: "Is documented", Status: "draft"}

	// The checkout holds what the hub does: they agree, and that becomes the
	// base. The executor's own claims about the file are not taken.
	executorHasSpec(t, stub, renderSpec(t, r1, r2), map[string]any{"valid": false, "errors": []map[string]any{{"message": "forged"}}})
	v := readSpecVia(t, ts)
	if v.State != specInSync || v.InSync != 2 || v.Read == nil || v.Read.Commit != "abcdef0123456789abcdef0123456789abcdef01" ||
		len(v.Errors) != 0 || v.Read.ExecutorID == "" {
		t.Fatalf("the first read: %+v", v)
	}
	if args := stubArgs(t, dir); strings.Join(args, " ") != "requirements validate --json" {
		t.Fatalf("the executor was asked %q", args)
	}

	// A pull request approves R-2, tightens R-1 and adds R-9.
	r1b, r2b := r1, r2
	r1b.Priority, r2b.Status = "must", "approved"
	r9 := requirements.Requirement{ID: 9, Title: "Ships a changelog", Status: "approved"}
	content := renderSpec(t, r1b, r2b, r9)
	executorHasSpec(t, stub, content, nil)
	v = readSpecVia(t, ts)
	if v.State != specChanged || v.Imports != 3 || v.Plan == nil || v.Digest == "" || v.Read.SHA256 != requirements.SpecSHA256([]byte(content)) {
		t.Fatalf("after the pull request: %+v", v)
	}
	// The list says so too, without the plan.
	code, d := rawJSON(t, ts, http.MethodGet, "/api/requirements", nil)
	if lv := specOf(t, d); code != http.StatusOK || lv.State != specChanged || lv.Plan != nil {
		t.Fatalf("the list's spec = %d %+v", code, lv)
	}

	// An import must name what was reviewed.
	if code, _ := rawJSON(t, ts, http.MethodPost, "/api/requirements/import", map[string]any{}); code != http.StatusBadRequest {
		t.Errorf("an import naming nothing = %d", code)
	}
	if code, _ := rawJSON(t, ts, http.MethodPost, "/api/requirements/import",
		map[string]any{"sha256": strings.Repeat("0", 64), "digest": v.Digest}); code != http.StatusConflict {
		t.Errorf("an import of another file = %d", code)
	}
	if code, _ := rawJSON(t, ts, http.MethodPost, "/api/requirements/import",
		map[string]any{"sha256": v.Read.SHA256, "digest": "not-the-plan"}); code != http.StatusConflict {
		t.Errorf("an import of another plan = %d", code)
	}
	code, d = rawJSON(t, ts, http.MethodPost, "/api/requirements/import", map[string]any{"sha256": v.Read.SHA256, "digest": v.Digest})
	if code != http.StatusOK {
		t.Fatalf("import = %d %v", code, d)
	}
	if after := specOf(t, d); after.State != specInSync {
		t.Errorf("after the import the spec reads %+v", after)
	}
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	got, err := db.Requirements()
	if err != nil || len(got) != 3 || got[0].Priority != "must" || got[1].Status != "approved" || got[2].ID != 9 {
		t.Fatalf("after the import: %+v %v", got, err)
	}
	rows, _, err := db.ListAuditEvents(statedb.AuditFilter{EventType: string(auditaction.ActionRequirementImport)})
	if err != nil || len(rows) != 1 || !strings.Contains(rows[0].Payload, `"dashboard"`) {
		t.Fatalf("the import's audit rows: %+v %v", rows, err)
	}

	// Both sides change R-1's title: a conflict, settled by a choice.
	if code, d := rawJSON(t, ts, http.MethodPut, "/api/requirements/"+itoa(one), map[string]any{
		"title": "Builds, says the hub", "priority": "must", "tests": []map[string]any{{"command": "go build ./..."}},
	}); code != http.StatusOK {
		t.Fatalf("edit = %d %v", code, d)
	}
	r1c := r1b
	r1c.Title = "Builds, says the file"
	executorHasSpec(t, stub, renderSpec(t, r1c, r2b, r9), nil)
	v = readSpecVia(t, ts)
	if v.State != specConflict || v.Conflicts != 1 {
		t.Fatalf("a conflict reads %+v", v)
	}
	code, d = rawJSON(t, ts, http.MethodPost, "/api/requirements/import", map[string]any{"sha256": v.Read.SHA256, "digest": v.Digest})
	if code != http.StatusConflict || !strings.Contains(d["error"].(string), "R-"+itoa(one)) {
		t.Fatalf("an unsettled import = %d %v", code, d)
	}
	if r, _ := db.Requirement(one); r.Title != "Builds, says the hub" {
		t.Fatalf("an unsettled import changed R-1: %+v", r)
	}
	code, d = rawJSON(t, ts, http.MethodPost, "/api/requirements/import", map[string]any{"sha256": v.Read.SHA256,
		"digest": v.Digest, "resolutions": map[string]string{"R-" + itoa(one): "file"}})
	if code != http.StatusOK {
		t.Fatalf("a settled import = %d %v", code, d)
	}
	if r, _ := db.Requirement(one); r.Title != "Builds, says the file" {
		t.Fatalf("the settled import left R-1 as %+v", r)
	}
}

// TestTheHubTakesNothingOfTheSpecReadOnTheExecutorsWord: a file the executor
// says is fine is parsed here, and one too large, not there, or not sent at
// all is recorded as such — never as requirements.
func TestTheHubTakesNothingOfTheSpecReadOnTheExecutorsWord(t *testing.T) {
	noSpecCooldown(t)
	dir := setupProjectDir(t, "hostile spec", modelCallTasks())
	stub := newModelStub(t)
	ts := modelCallHub(t, dir, stub)
	addRequirementVia(t, ts, map[string]any{"title": "Exists"})

	executorHasSpec(t, stub, "version: 1\nrequirements:\n  - id: R-1\n    titel: x\n    status: approved\n", nil)
	if v := readSpecVia(t, ts); v.State != specInvalid || v.ErrorCount != 2 || v.Errors[0].Line != 3 {
		t.Errorf("an invalid file the executor called valid: %+v", v)
	}

	stub.answer(t, "requirements-validate", framed(t, map[string]any{"path": requirements.SpecFileName, "found": false}), 0)
	if v := readSpecVia(t, ts); v.State != specMissing {
		t.Errorf("no file: %+v", v)
	}

	big := strings.Repeat("#", requirements.MaxSpecFileBytes+1)
	executorHasSpec(t, stub, big, nil)
	if v := readSpecVia(t, ts); v.State != specFailed || !strings.Contains(v.Read.Error, "more than a spec file may hold") {
		t.Errorf("an oversized file: %+v", v.Read)
	}

	// What the executor said of a file it would not send is shown, bounded —
	// and nothing else of it is taken.
	stub.answer(t, "requirements-validate", framed(t, map[string]any{"path": requirements.SpecFileName, "found": true,
		"errors": []map[string]any{{"message": strings.Repeat("too large ", 100)}}}), 0)
	if v := readSpecVia(t, ts); v.State != specFailed || len(v.Read.Error) > 400 {
		t.Errorf("a file not sent: %+v", v.Read)
	}

	// An executor that sent no report: the attempt says why, and the last
	// read stands.
	executorHasSpec(t, stub, "version: 1\nrequirements: []\n", nil)
	good := readSpecVia(t, ts)
	stub.answer(t, "requirements-validate", "panic: something\n", 2)
	if v := readSpecVia(t, ts); v.Attempt == nil || !strings.Contains(v.Attempt.Error, "panic: something") ||
		v.Read == nil || v.Read.SHA256 != good.Read.SHA256 || v.State != good.State {
		t.Errorf("no report: %+v (attempt %+v)", v, v.Attempt)
	}
	// An old cloop on a device that does not know the subcommand says so.
	stub.answer(t, "requirements-validate", `Error: unknown command "validate" for "cloop requirements"`+"\n", 1)
	if v := readSpecVia(t, ts); v.Attempt == nil || !strings.Contains(v.Attempt.Error, "older than this hub") {
		t.Errorf("an old executor: %+v", v.Attempt)
	}
	// A read that works again clears the failed attempt.
	executorHasSpec(t, stub, "version: 1\nrequirements: []\n", nil)
	if v := readSpecVia(t, ts); v.Attempt != nil {
		t.Errorf("a good read left the failed attempt: %+v", v.Attempt)
	}

	// The download is the hub's requirements as a spec file, and nothing is
	// written into the project.
	code, d := rawJSON(t, ts, http.MethodGet, "/api/requirements/export", nil)
	content, _ := d["content"].(string)
	if f, err := requirements.ParseSpecFile([]byte(content)); code != http.StatusOK || err != nil || len(f.Requirements) != 1 {
		t.Errorf("export = %d %v (%v)", code, d, err)
	}
	if _, err := os.Stat(filepath.Join(dir, requirements.SpecFileName)); !os.IsNotExist(err) {
		t.Errorf("the export wrote into the project: %v", err)
	}
}

// TestCheckAllChecksTheApprovedRequirements: a draft is not yet agreed and a
// deprecated requirement is no longer, so "check all" passes them by. A
// deprecated one is checked when named, or when every one is asked for; a
// draft never is until a person approves it (Task 20462).
func TestCheckAllChecksTheApprovedRequirements(t *testing.T) {
	dir := setupProjectDir(t, "statuses", modelCallTasks())
	stub := newModelStub(t)
	ts := modelCallHub(t, dir, stub)
	test := []map[string]any{{"command": "true"}}
	approved := addRequirementVia(t, ts, map[string]any{"title": "Approved", "tests": test})
	draft := addRequirementVia(t, ts, map[string]any{"title": "Draft", "status": "draft", "tests": test})
	gone := addRequirementVia(t, ts, map[string]any{"title": "Deprecated", "status": "deprecated", "tests": test})

	ids := func(d map[string]any, key string) []int {
		var out []int
		var list []any
		if key == "requirement_ids" {
			run, _ := d["run"].(map[string]any)
			list, _ = run[key].([]any)
		} else {
			list, _ = d[key].([]any)
		}
		for _, x := range list {
			out = append(out, int(x.(float64)))
		}
		return out
	}
	code, d, runID := startRequirementRun(t, ts, map[string]any{})
	if code != http.StatusAccepted || len(ids(d, "requirement_ids")) != 1 || ids(d, "requirement_ids")[0] != approved ||
		len(ids(d, "unapproved")) != 2 {
		t.Fatalf("check all = %d %v", code, d)
	}
	waitRequirementRun(t, ts, runID)
	for _, named := range [][]int{{draft}, {approved, draft}} {
		if code, d, _ := startRequirementRun(t, ts, map[string]any{"ids": named}); code != http.StatusBadRequest ||
			!strings.Contains(fmt.Sprint(d["error"]), "not checked until a person approves it") {
			t.Fatalf("a draft by name %v = %d %v", named, code, d)
		}
	}
	code, d, runID = startRequirementRun(t, ts, map[string]any{"ids": []int{gone}})
	if code != http.StatusAccepted || ids(d, "requirement_ids")[0] != gone {
		t.Fatalf("a deprecated one by name = %d %v", code, d)
	}
	waitRequirementRun(t, ts, runID)
	code, d, runID = startRequirementRun(t, ts, map[string]any{"all": true})
	if got := ids(d, "requirement_ids"); code != http.StatusAccepted || len(got) != 2 || got[0] != approved || got[1] != gone ||
		len(ids(d, "unapproved")) != 1 {
		t.Fatalf("every one = %d %v", code, d)
	}
	waitRequirementRun(t, ts, runID)

	// Statuses through the API: kept when an edit names none, changed when
	// one does, refused when it is not one.
	if code, d := rawJSON(t, ts, http.MethodPut, "/api/requirements/"+itoa(gone), map[string]any{"title": "Deprecated, renamed"}); code != http.StatusOK ||
		d["requirement"].(map[string]any)["status"] != "deprecated" {
		t.Errorf("an edit naming no status = %d %v", code, d)
	}
	if code, d := rawJSON(t, ts, http.MethodPut, "/api/requirements/"+itoa(draft), map[string]any{"title": "Draft", "status": "approved"}); code != http.StatusOK ||
		d["requirement"].(map[string]any)["status"] != "approved" {
		t.Errorf("approving = %d %v", code, d)
	}
	if code, _ := rawJSON(t, ts, http.MethodPost, "/api/requirements", map[string]any{"title": "x", "status": "shipped"}); code != http.StatusBadRequest {
		t.Errorf("an unknown status = %d", code)
	}
	// With nothing approved, check all says what to do.
	dir2 := setupProjectDir(t, "drafts only", modelCallTasks())
	ts2 := modelCallHub(t, dir2, stub)
	addRequirementVia(t, ts2, map[string]any{"title": "Draft", "status": "draft", "tests": test})
	if code, d, _ := startRequirementRun(t, ts2, map[string]any{}); code != http.StatusBadRequest || !strings.Contains(d["error"].(string), "approved") {
		t.Errorf("check all with nothing approved = %d %v", code, d)
	}
}

// TestTheListCarriesNoSpecFileContent: the file's bytes are kept as read, to
// be parsed and imported, and no answer carries them: a reader sees the
// requirements and the problems, never the file.
func TestTheListCarriesNoSpecFileContent(t *testing.T) {
	noSpecCooldown(t)
	dir := setupProjectDir(t, "no content in the list", modelCallTasks())
	stub := newModelStub(t)
	ts := modelCallHub(t, dir, stub)
	addRequirementVia(t, ts, map[string]any{"title": "Exists"})
	const token = "only-in-the-file-7f3a9c"
	executorHasSpec(t, stub, "version: 1\nrequirements: []\n# "+token+"\n", nil)
	readSpecVia(t, ts)
	for _, path := range []string{"/api/requirements", "/api/requirements/spec"} {
		req, _ := http.NewRequest(http.MethodGet, ts.URL+path, nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		var b strings.Builder
		_, _ = io.Copy(&b, resp.Body)
		resp.Body.Close()
		if strings.Contains(b.String(), token) || strings.Contains(b.String(), "content") {
			t.Errorf("%s carries the file's content: %.300s", path, b.String())
		}
	}
}

// TestTheHubDecidesWhenTheTabReadsTheSpecFile: every read starts a workload
// where the project runs, so the read a tab asks for when it opens runs only
// when the last is old — and a person's Read again is refused only a second
// read at once.
func TestTheHubDecidesWhenTheTabReadsTheSpecFile(t *testing.T) {
	dir := setupProjectDir(t, "how often", modelCallTasks())
	stub := newModelStub(t)
	ts := modelCallHub(t, dir, stub)
	args := filepath.Join(dir, "model-call.args")
	dispatched := func() bool {
		_, err := os.Stat(args)
		_ = os.Remove(args)
		return err == nil
	}

	executorHasSpec(t, stub, "version: 1\nrequirements: []\n", nil)
	if v := readSpecAs(t, ts, map[string]any{"auto": true}); !dispatched() || v.State != specInSync {
		t.Fatalf("the first automatic read: %+v", v)
	}
	if v := readSpecAs(t, ts, map[string]any{"auto": true}); dispatched() || v.Read == nil {
		t.Errorf("a fresh read was read again for an opening tab: %+v", v)
	}
	if readSpecAs(t, ts, map[string]any{}); dispatched() {
		t.Error("Read again ran inside the cooldown")
	}
	noSpecCooldown(t)
	if readSpecAs(t, ts, map[string]any{}); !dispatched() {
		t.Error("Read again did not read")
	}

	// A checkout with no file is asked hourly, not every five minutes.
	stub.answer(t, "requirements-validate", framed(t, map[string]any{"path": requirements.SpecFileName, "found": false}), 0)
	readSpecVia(t, ts)
	dispatched()
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Now()
	if due, _ := specReadDue(db, true, now.Add(10*time.Minute)); due {
		t.Error("a missing file was due again after ten minutes")
	}
	if due, _ := specReadDue(db, true, now.Add(61*time.Minute)); !due {
		t.Error("a missing file was not due after an hour")
	}
	// A failed attempt is not retried by every opening tab either.
	if err := db.RecordRequirementSpecAttempt(statedb.RequirementSpecAttempt{Error: "offline"}); err != nil {
		t.Fatal(err)
	}
	if due, _ := specReadDue(db, true, time.Now().Add(time.Minute)); due {
		t.Error("a failed attempt was retried at once for an opening tab")
	}
	if due, _ := specReadDue(db, true, time.Now().Add(6*time.Minute)); !due {
		t.Error("a failed attempt was not retried after five minutes")
	}
}
