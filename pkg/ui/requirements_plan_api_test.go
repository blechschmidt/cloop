package ui

// Planning with the requirements in view (Task 20463), driven through the real
// handlers with the model-call stub standing in for the cloop the executor
// runs: what the hub asks for, the requirement status it sends, and what it
// does with whatever comes back.

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/executor/projectseed"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/requirements"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
	"github.com/blechschmidt/cloop/pkg/suggest"
)

// gapHub is a project whose task #1 implements R-4, with R-1 a must
// requirement found unfulfilled, R-2 a should one never checked, R-3 a must
// one with no test that holds by a person's word, R-4 a must one task #1
// implements, R-5 a must draft and R-6 a deprecated must one; served with the
// model-call stub as its cloop.
func gapHub(t *testing.T) (string, *modelStub, *httptest.Server) {
	t.Helper()
	dir := setupProjectDir(t, "Keep the CLI honest", modelCallTasks())
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	db.AsProject()
	tested := []requirements.Test{{Command: "true"}}
	for _, r := range []requirements.Requirement{
		{Title: "Config errors exit 2", Priority: requirements.PriorityMust, Tests: tested},
		{Title: "Exports are paginated", Priority: requirements.PriorityShould, Tests: tested},
		{Title: "The audit log is signed", Priority: requirements.PriorityMust},
		{Title: "Sessions expire", Priority: requirements.PriorityMust, Tests: tested},
		{Title: "A must draft", Priority: requirements.PriorityMust, Status: requirements.StatusDraft},
		{Title: "A deprecated must", Priority: requirements.PriorityMust, Status: requirements.StatusDeprecated},
	} {
		if _, err := db.AddRequirement(r, "alice@example.com"); err != nil {
			t.Fatal(err)
		}
	}
	for id, v := range map[int]string{1: requirements.VerdictUnfulfilled, 3: requirements.VerdictFulfilled} {
		if _, err := db.RecordRequirementVerdict(id, v, "", "alice@example.com"); err != nil {
			t.Fatal(err)
		}
	}
	db.Close()
	ps, err := state.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	ps.Plan.TaskByID(1).Requirements = []int{4}
	if err := ps.SaveDirect(); err != nil {
		t.Fatal(err)
	}
	stub := newModelStub(t)
	return dir, stub, modelCallHub(t, dir, stub)
}

// sentStatus is the requirement status summary the hub sent with the call
// the stub saw last in dir.
func sentStatus(t *testing.T, dir string) requirements.StatusSummary {
	t.Helper()
	raw, ok := argValue(stubArgs(t, dir), "--requirements=")
	if !ok {
		t.Fatalf("no --requirements in %q", stubArgs(t, dir))
	}
	sum, err := requirements.ParseStatusSummary([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	return sum
}

func standingActions(sum requirements.StatusSummary) string {
	var parts []string
	for _, st := range sum.Requirements {
		parts = append(parts, fmt.Sprintf("R-%d:%s", st.ID, st.Action))
	}
	return strings.Join(parts, " ")
}

func TestPlanFromRequirementsIsAPlanOnTheExecutor(t *testing.T) {
	dir, stub, ts := gapHub(t)
	// What the executor's cloop answers: links to a draft, a deprecated and
	// an unknown requirement, a task repeating open task #1, and no task for
	// R-3 — whatever a device's cloop sends is read again here.
	stub.answer(t, "requirements-plan", framed(t, suggest.Result{Summary: "close the gaps", Request: "whatever", Suggestions: []*suggest.Suggestion{
		{ID: 1, Title: "Paginate exports", Description: "d", Requirements: requirements.LooseRefs{2, 5, 6, 99}, Kind: "fix", Priority: 9},
		{ID: 2, Title: "Restore the exit code", Description: "d", Requirements: requirements.LooseRefs{1}, DependsOn: []int{1}},
		{ID: 3, Title: "Expire sessions sooner", Description: "d", Requirements: requirements.LooseRefs{4}},
	}}), 0)

	code, body := rawJSON(t, ts, http.MethodPost, "/api/requirements/plan", map[string]any{})
	if code != http.StatusOK || body["started"] != true || body["targets"] != float64(3) || body["must"] != float64(2) {
		t.Fatalf("plan = %d %v", code, body)
	}
	st := waitSuggest(t, ts, "")
	args := stubArgs(t, dir)
	if strings.Join(args[:5], " ") != "requirements plan --json --timeout 5m0s" {
		t.Errorf("the executor was asked for %q", args)
	}
	sum := sentStatus(t, dir)
	if got := standingActions(sum); got != "R-1:fix R-3:test R-4:covered R-2:implement" {
		t.Errorf("the status sent: %s — never a draft's or a deprecated requirement's", got)
	}

	if st["request"] != suggest.RequirementsRequest {
		t.Errorf("request %v", st["request"])
	}
	var cards []suggest.Suggestion
	raw, _ := json.Marshal(st["suggestions"])
	if err := json.Unmarshal(raw, &cards); err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, c := range cards {
		got = append(got, fmt.Sprintf("%d %s %v %s P%d %v", c.ID, c.Title, []int(c.Requirements), c.Kind, c.Priority, c.DependsOn))
	}
	want := []string{
		"1 Paginate exports [2] implement P1 []", // the must task needs it
		"2 Restore the exit code [1] fix P1 [1]",
		"3 Add a test for R-3: The audit log is signed [3] test P1 []",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("the cards\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	notes, _ := json.Marshal(st["notes"])
	if !strings.Contains(string(notes), `Left out \"Expire sessions sooner\"`) || !strings.Contains(string(notes), "R-3 had no task") {
		t.Errorf("notes %s", notes)
	}
	reqView, _ := st["requirements"].(map[string]any)
	refs, _ := json.Marshal(reqView["refs"])
	if !strings.Contains(string(refs), `{"gap":true,"id":1,"priority":"must","title":"Config errors exit 2"}`) ||
		!strings.Contains(string(refs), `{"id":2,"priority":"should","title":"Exports are paginated"}`) ||
		strings.Contains(string(refs), "draft") || strings.Contains(string(refs), "deprecated") {
		t.Errorf("refs %s", refs)
	}

	// Accepted: each task implements what it closes, at its priority.
	code, added := rawJSON(t, ts, http.MethodPost, "/api/suggest/add", map[string]any{"gen": st["gen"], "ids": []int{1, 2, 3}})
	if code != http.StatusOK {
		t.Fatalf("add = %d %v", code, added)
	}
	ps, _ := state.LoadLite(dir)
	var tasks []string
	for _, task := range ps.Plan.Tasks[2:] {
		tasks = append(tasks, fmt.Sprintf("#%d P%d %s %v %v %v", task.ID, task.Priority, task.Title, task.Requirements, task.Tags, task.DependsOn))
	}
	wantTasks := []string{
		"#3 P1 Paginate exports [2] [requirement] []",
		"#4 P1 Restore the exit code [1] [requirement] [3]",
		"#5 P1 Add a test for R-3: The audit log is signed [3] [requirement test-only] []",
	}
	if strings.Join(tasks, "\n") != strings.Join(wantTasks, "\n") {
		t.Errorf("tasks\n%s\nwant\n%s", strings.Join(tasks, "\n"), strings.Join(wantTasks, "\n"))
	}
	st = apiGET(t, ts, "/api/suggest/status")
	reqView, _ = st["requirements"].(map[string]any)
	if added, _ := json.Marshal(reqView["added"]); string(added) != "[2,1,3]" {
		t.Errorf("the requirements the added tasks close: %s", added)
	}

	// Every gap has an open task now: nothing to plan, and nothing asked.
	_ = os.Remove(filepath.Join(dir, "model-call.args"))
	code, body = rawJSON(t, ts, http.MethodPost, "/api/requirements/plan", map[string]any{})
	if code != http.StatusOK || body["started"] != false || !strings.Contains(fmt.Sprint(body["message"]), "Nothing to plan") {
		t.Errorf("a second plan = %d %v", code, body)
	}
	if args := stubArgs(t, dir); args != nil {
		t.Errorf("nothing to plan asked the executor %q", args)
	}
	if code, body := rawJSON(t, ts, http.MethodPost, "/api/requirements/plan", map[string]any{"count": 99}); code != http.StatusBadRequest {
		t.Errorf("count 99 = %d %v", code, body)
	}
}

// The panel's Generate sends the status with a brainstorm or a plan, and a
// proposal sent whole by a client links nothing.
func TestSuggestCarriesTheRequirementStatus(t *testing.T) {
	dir, stub, ts := gapHub(t)
	stub.answer(t, "suggest---json", framed(t, suggest.Result{Summary: "ideas", Suggestions: []*suggest.Suggestion{
		{ID: 1, Title: "Dark mode", Effort: suggest.EffortS},
		{ID: 2, Title: "Sign the audit log", Requirements: requirements.LooseRefs{3, 5}},
	}}), 0)
	st := generate(t, ts, "", map[string]any{"count": 2})
	if sum := sentStatus(t, dir); len(sum.MustGaps()) != 2 {
		t.Errorf("the status sent with a brainstorm: %s", standingActions(sum))
	}
	raw, _ := json.Marshal(st["suggestions"])
	if !strings.Contains(string(raw), `"title":"Sign the audit log"`) || !strings.Contains(string(raw), `"requirements":[3]`) ||
		!strings.Contains(string(raw), `"title":"Restore R-1: Config errors exit 2"`) {
		t.Errorf("the ideas %s", raw)
	}

	// A proposal sent whole is added as an idea, and links nothing.
	code, body := rawJSON(t, ts, http.MethodPost, "/api/suggest/add", map[string]any{
		"suggestions": []map[string]any{{"title": "Smuggled", "requirements": []int{1}, "kind": "fix", "priority": 1}}})
	if code != http.StatusOK {
		t.Fatalf("add = %d %v", code, body)
	}
	ps, _ := state.LoadLite(dir)
	last := ps.Plan.Tasks[len(ps.Plan.Tasks)-1]
	if last.Title != "Smuggled" || last.Requirements != nil || last.Priority == 1 {
		t.Errorf("a client's proposal: %+v", last)
	}

	// A project without approved requirements is planned as it always was.
	plain := setupProjectDir(t, "no requirements", modelCallTasks())
	stub2 := newModelStub(t)
	stub2.answer(t, "suggest---json", framed(t, suggest.Result{Summary: "s", Suggestions: []*suggest.Suggestion{{ID: 1, Title: "x"}}}), 0)
	ts2 := modelCallHub(t, plain, stub2)
	generate(t, ts2, "", map[string]any{"count": 1})
	if _, ok := argValue(stubArgs(t, plain), "--requirements"); ok {
		t.Errorf("a project without requirements sent %q", stubArgs(t, plain))
	}
}

// The plan assistant is sent the status, and the end of an answer that
// proposed tasks says what each covers and which must gaps none does.
func TestPlanChatSaysWhatEachProposedTaskCovers(t *testing.T) {
	dir, stub, ts := gapHub(t)
	answer := "Do these next.\n\n```tasks\n[{\"title\":\"Fix the exit code\",\"requirements\":[1,5]},{\"title\":\"Dark mode\",\"requirements\":[]}]\n```"
	stub.answer(t, "plan-chat", framed(t, map[string]string{"answer": answer}), 0)

	payload, _ := json.Marshal(map[string]any{"message": "What next?"})
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/chat/plan", strings.NewReader(string(payload)))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var done string
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	event := ""
	for sc.Scan() {
		line := sc.Text()
		if v, ok := strings.CutPrefix(line, "event: "); ok {
			event = v
		} else if v, ok := strings.CutPrefix(line, "data: "); ok && event == "done" {
			done = v
		}
	}
	if len(sentStatus(t, dir).MustGaps()) != 2 {
		t.Errorf("the plan assistant was not sent the status: %q", stubArgs(t, dir))
	}
	var d planChatDone
	if err := json.Unmarshal([]byte(done), &d); err != nil {
		t.Fatalf("done %q: %v", done, err)
	}
	if d.Text != "Do these next." || len(d.Proposals) != 2 {
		t.Fatalf("done %+v", d)
	}
	if p := d.Proposals[0]; p.Title != "Fix the exit code" || len(p.Requirements) != 1 || p.Requirements[0].ID != 1 ||
		p.Requirements[0].Title != "Config errors exit 2" {
		t.Errorf("the first proposal %+v — never a draft", p)
	}
	if len(d.Uncovered) != 1 || d.Uncovered[0].ID != 3 {
		t.Errorf("uncovered %+v, want R-3: R-4 has an open task", d.Uncovered)
	}

	// An answer that proposes nothing ends as it always did.
	if got := planChatProposals("Task 1 is next.", sentStatus(t, dir)); got.Text != "" || got.Proposals != nil {
		t.Errorf("no proposals: %+v", got)
	}
}

// The Split preview says which of the task's approved requirements each
// sub-task covers, and applying links them; a sub-task never takes one the
// task does not implement.
func TestSplitKeepsTheTasksRequirementsOnItsSubTasks(t *testing.T) {
	dir, stub, ts := gapHub(t)
	ps, _ := state.Load(dir)
	ps.Plan.TaskByID(1).Requirements = []int{1, 2, 4, 5}
	if err := ps.SaveDirect(); err != nil {
		t.Fatal(err)
	}
	stub.answer(t, "task-decompose", framed(t, map[string]any{"subtasks": []map[string]any{
		{"title": "Fix the exit code", "requirements": []int{1, 5, 3}},
		{"title": "Paginate", "requirements": []int{2}},
	}}), 0)
	code, body := rawJSON(t, ts, http.MethodPost, "/api/tasks/1/decompose", map[string]any{})
	if code != http.StatusOK {
		t.Fatalf("decompose = %d %v", code, body)
	}
	subs, _ := json.Marshal(body["subtasks"])
	refs, _ := json.Marshal(body["requirements"])
	if string(subs) != `[{"description":"","requirements":[1],"title":"Fix the exit code"},`+
		`{"description":"","requirements":[2],"title":"Paginate"}]` {
		t.Errorf("sub-tasks %s", subs)
	}
	if string(refs) != `[{"gap":true,"id":1,"priority":"must","title":"Config errors exit 2"},`+
		`{"id":2,"priority":"should","title":"Exports are paginated"},{"gap":true,"id":4,"priority":"must","title":"Sessions expire"}]` {
		t.Errorf("the task's requirements %s — its draft left out", refs)
	}

	code, body = rawJSON(t, ts, http.MethodPost, "/api/tasks/1/decompose/apply", map[string]any{"subtasks": []map[string]any{
		{"title": "Fix the exit code", "requirements": []int{1, 3}},
		{"title": "Expire", "requirements": []int{4, 2}},
	}})
	if code != http.StatusOK {
		t.Fatalf("apply = %d %v", code, body)
	}
	ps, _ = state.LoadLite(dir)
	if a, b := ps.Plan.TaskByID(3), ps.Plan.TaskByID(4); fmt.Sprint(a.Requirements) != "[1]" || fmt.Sprint(b.Requirements) != "[2 4]" {
		t.Errorf("the sub-tasks implement %v and %v", a.Requirements, b.Requirements)
	}
}

func TestRequirementsListSaysWhatClosesEachGap(t *testing.T) {
	_, _, ts := gapHub(t)
	d := apiGET(t, ts, "/api/requirements")
	if d["targets"] != float64(3) || d["must_gaps"] != float64(2) {
		t.Errorf("targets %v, must gaps %v", d["targets"], d["must_gaps"])
	}
	list, _ := d["requirements"].([]any)
	var got []string
	for _, it := range list {
		r, _ := it.(map[string]any)
		got = append(got, fmt.Sprintf("R-%v:%v", r["id"], r["action"]))
	}
	if strings.Join(got, " ") != "R-1:fix R-2:implement R-3:test R-4:covered R-5:<nil> R-6:<nil>" {
		t.Errorf("actions %v", got)
	}
}

// A device's auto-evolve plans from the status its seed carries.
func TestTheSeedCarriesTheRequirementStatus(t *testing.T) {
	dir, _, _ := gapHub(t)
	seed, err := projectSeedFor(dir)
	if err != nil {
		t.Fatal(err)
	}
	sandbox := t.TempDir()
	if err := projectseed.Write(sandbox, seed); err != nil {
		t.Fatal(err)
	}
	if _, err := state.Load(sandbox); err != nil {
		t.Fatal(err)
	}
	db, err := statedb.Open(state.DBPath(sandbox))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	facts, _, err := db.AsProject().RequirementFacts()
	if err != nil {
		t.Fatal(err)
	}
	ps, _ := state.LoadLite(sandbox)
	sum := requirements.Summarize(facts, pm.TaskViews(ps.Plan))
	if got := standingActions(sum); got != "R-1:fix R-3:test R-4:covered R-2:implement" {
		t.Errorf("the device's status: %s", got)
	}
}

// A device's cloop older than the requirement status refuses the argument:
// the panel's Generate asks again without it, and the hub still holds what
// comes back to the requirements — the must gaps get their tasks.
func TestSuggestAsksAnOlderCloopAgainWithoutTheStatus(t *testing.T) {
	dir, stub, ts := gapHub(t)
	stub.script(t, "suggest---json", `for a in "$@"; do case "$a" in --requirements=*) echo "Error: unknown flag: --requirements"; exit 1;; esac; done
cat <<'CLOOP_STUB'
`+framed(t, suggest.Result{Summary: "ideas", Suggestions: []*suggest.Suggestion{{ID: 1, Title: "Dark mode"}}})+`
CLOOP_STUB
`)
	st := generate(t, ts, "", map[string]any{"count": 1})
	if _, ok := argValue(stubArgs(t, dir), "--requirements="); ok {
		t.Errorf("the second ask still carried the status: %q", stubArgs(t, dir))
	}
	raw, _ := json.Marshal(st["suggestions"])
	if !strings.Contains(string(raw), "Restore R-1: Config errors exit 2") || !strings.Contains(string(raw), "Dark mode") {
		t.Errorf("the ideas %s", raw)
	}
}

// A card accepted after its requirement went back to draft links nothing to
// it, and a proposal sent as null is no proposal.
func TestAcceptingAPlanLinksOnlyWhatIsStillApproved(t *testing.T) {
	dir, stub, ts := gapHub(t)
	stub.answer(t, "requirements-plan", framed(t, suggest.Result{Summary: "s", Suggestions: []*suggest.Suggestion{
		{ID: 1, Title: "Paginate exports", Requirements: requirements.LooseRefs{2}},
		{ID: 2, Title: "Restore the exit code", Requirements: requirements.LooseRefs{1}},
	}}), 0)
	if code, body := rawJSON(t, ts, http.MethodPost, "/api/requirements/plan", map[string]any{}); code != http.StatusOK {
		t.Fatalf("plan = %d %v", code, body)
	}
	st := waitSuggest(t, ts, "")
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	r2, err := db.AsProject().Requirement(2)
	if err == nil {
		r2.Status = requirements.StatusDraft
		_, err = db.UpdateRequirement(r2, "alice@example.com")
	}
	db.Close()
	if err != nil {
		t.Fatal(err)
	}
	if code, body := rawJSON(t, ts, http.MethodPost, "/api/suggest/add", map[string]any{"gen": st["gen"], "ids": []int{1, 2}}); code != http.StatusOK {
		t.Fatalf("add = %d %v", code, body)
	}
	ps, _ := state.LoadLite(dir)
	for _, task := range ps.Plan.Tasks[2:] {
		for _, id := range task.Requirements {
			if id == 2 {
				t.Errorf("task #%d links R-2, a draft now: %v", task.ID, task.Requirements)
			}
		}
	}
	if code, body := rawJSON(t, ts, http.MethodPost, "/api/suggest/add", map[string]any{"suggestions": []any{nil}}); code != http.StatusBadRequest {
		t.Errorf("a null proposal = %d %v, want 400", code, body)
	}
}

// The plan assistant asks a cloop older than the requirement status again
// without it, before anything streamed.
func TestPlanChatAsksAnOlderCloopAgainWithoutTheStatus(t *testing.T) {
	dir, stub, ts := gapHub(t)
	stub.script(t, "plan-chat", `for a in "$@"; do case "$a" in --requirements=*) echo "Error: unknown flag: --requirements"; exit 1;; esac; done
cat <<'CLOOP_STUB'
`+framed(t, map[string]string{"answer": "Task 1 is next."})+`
CLOOP_STUB
`)
	payload, _ := json.Marshal(map[string]any{"message": "What next?"})
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/chat/plan", strings.NewReader(string(payload)))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var body strings.Builder
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		body.WriteString(sc.Text() + "\n")
	}
	if !strings.Contains(body.String(), "Task 1 is next.") || strings.Contains(body.String(), "event: error") {
		t.Errorf("the stream:\n%s", body.String())
	}
	if _, ok := argValue(stubArgs(t, dir), "--requirements="); ok {
		t.Errorf("the second ask still carried the status: %q", stubArgs(t, dir))
	}
}
