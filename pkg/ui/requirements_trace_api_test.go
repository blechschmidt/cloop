package ui

// The traceability matrix's endpoint and its push (Task 20465): pages, filters
// and the coverage through the real handler; who may read it, and only in
// their own project; and requirements_coverage reaching an open dashboard
// when — and only when — the matrix moved.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/authz"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/requirements"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
	"github.com/blechschmidt/cloop/pkg/trace"
)

// seedTraceProject makes a project whose matrix has every kind of row: R-1 a
// must that holds, proven, implemented by a done task with a traced commit and
// an open one; R-2 a should nothing implements; R-3 a must last checked for a
// task since deleted; R-4 a draft; R-5 a tagged could.
func seedTraceProject(t *testing.T) string {
	t.Helper()
	done := time.Now().Add(-2 * time.Hour)
	dir := setupProjectDir(t, "trace the requirements", []*pm.Task{
		{ID: 1, Title: "Audit every dispatch", Status: pm.TaskDone, CompletedAt: &done, Requirements: []int{1}},
		{ID: 2, Title: "Second pass", Status: pm.TaskPending, Requirements: []int{1, 3}},
		{ID: 3, Title: "Unrelated", Status: pm.TaskDone, CompletedAt: &done},
	})
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	add := func(r requirements.Requirement) requirements.Requirement {
		t.Helper()
		got, err := db.AddRequirement(r, "alice@example.com")
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	r1 := add(requirements.Requirement{Title: "Every dispatch is audited", Priority: requirements.PriorityMust,
		Tests: []requirements.Test{{Command: "go test ./audit"}}})
	add(requirements.Requirement{Title: "Nothing implements this", Priority: requirements.PriorityShould})
	r3 := add(requirements.Requirement{Title: "Checked for a deleted task", Priority: requirements.PriorityMust,
		Tests: []requirements.Test{{Command: "go test ./gone"}}})
	add(requirements.Requirement{Title: "A draft", Priority: requirements.PriorityMust, Status: requirements.StatusDraft})
	add(requirements.Requirement{Title: "Tagged", Priority: requirements.PriorityCould, Tags: []string{"ui"}})
	if _, err := db.RecordRequirementChecks(statedb.CheckRecord{RunID: "r1", Commit: "abcdef1234567890", TaskID: 1},
		[]requirements.Result{{RequirementID: r1.ID, Fingerprint: r1.Fingerprint(), Method: requirements.MethodTests,
			Verdict: requirements.VerdictFulfilled, StartedAt: time.Now().Add(-time.Hour)}}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.RecordRequirementChecks(statedb.CheckRecord{RunID: "r3", TaskID: 77},
		[]requirements.Result{{RequirementID: r3.ID, Fingerprint: r3.Fingerprint(), Method: requirements.MethodTests,
			Verdict: requirements.VerdictUnfulfilled, StartedAt: time.Now().Add(-30 * time.Minute)}}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.RecordRequirementProofs(statedb.ProofRecord{RunID: "p1", TaskID: 1}, []requirements.Proof{{
		RequirementID: r1.ID, Fingerprint: r1.Fingerprint(), Outcome: requirements.ProofProven}}); err != nil {
		t.Fatal(err)
	}
	if err := trace.WriteTraceJSON(dir, &trace.TraceMap{Entries: []trace.TraceEntry{
		{Hash: "1234567aaaa", Subject: `feat(audit): every dispatch <b>audited</b> (Task 1)`, MatchedTaskID: 1, Confidence: trace.ConfidenceHigh},
		{Hash: "7777777bbbb", Subject: "the deleted task's work", MatchedTaskID: 77, Confidence: trace.ConfidenceHigh},
	}}); err != nil {
		t.Fatal(err)
	}
	return dir
}

type traceAnswerJSON struct {
	OK       bool                    `json:"ok"`
	Error    string                  `json:"error"`
	Rows     []requirements.TraceRow `json:"rows"`
	Next     int                     `json:"next"`
	Coverage *requirements.Coverage  `json:"coverage"`
	Matched  *int                    `json:"matched"`
	Digest   string                  `json:"digest"`
}

func getTrace(t *testing.T, ts *httptest.Server, query string) (int, traceAnswerJSON) {
	t.Helper()
	resp, err := http.Get(ts.URL + "/api/requirements/trace" + query)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out traceAnswerJSON
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("GET trace%s: %v", query, err)
	}
	return resp.StatusCode, out
}

func traceIDs(rows []requirements.TraceRow) string {
	ids := make([]int, len(rows))
	for i, r := range rows {
		ids[i] = r.ID
	}
	return fmt.Sprint(ids)
}

// TestRequirementsTraceAPI_PagesFiltersAndCoverage: the first page carries the
// coverage, the match count and the digest; later pages follow by cursor; the
// filters narrow; what no requirement could match is a 400.
func TestRequirementsTraceAPI_PagesFiltersAndCoverage(t *testing.T) {
	dir := seedTraceProject(t)
	srv := New(dir, 0, "")
	srv.RPS, srv.Burst = 1e6, 1e6
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	code, d := getTrace(t, ts, "")
	if code != http.StatusOK || !d.OK || traceIDs(d.Rows) != "[1 2 3 5]" || d.Next != 0 {
		t.Fatalf("the matrix = %d %+v", code, d)
	}
	c := d.Coverage
	if c == nil || d.Matched == nil || *d.Matched != 4 || d.Digest == "" || c.Approved != 4 ||
		c.Musts != (requirements.CoverageCounts{Total: 2, Tested: 2, Proven: 1, Passing: 1, Linked: 2,
			TestedPct: 100, ProvenPct: 50, PassingPct: 50, LinkedPct: 100}) || fmt.Sprint(c.Tags) != "[ui]" {
		t.Fatalf("the coverage: %+v, matched %v, digest %q", c, d.Matched, d.Digest)
	}
	r1, r2, r3 := d.Rows[0], d.Rows[1], d.Rows[2]
	if !r1.Passing || !r1.Proven || len(r1.Tasks) != 2 || r1.Tasks[0].Status != string(pm.TaskDone) {
		t.Errorf("R-1: %+v", r1)
	}
	var commits []string
	for _, c := range r1.Commits {
		commits = append(commits, c.Hash+"/"+c.Source)
	}
	if fmt.Sprint(commits) != "[1234567aaaa/trace]" || r1.Commits[0].Subject != `feat(audit): every dispatch <b>audited</b> (Task 1)` {
		t.Errorf("R-1's commits: %v %+v", commits, r1.Commits)
	}
	if r2.Linked || len(r2.Tasks) != 0 || r2.Verification != requirements.VerificationNone {
		t.Errorf("R-2 (nothing implements it): %+v", r2)
	}
	if r3.Verdict == nil || r3.Verdict.Task == nil || !r3.Verdict.Task.Deleted || r3.Verdict.Task.ID != 77 || len(r3.Commits) != 0 {
		t.Errorf("R-3 (checked for a deleted task): %+v", r3)
	}

	// By cursor, two at a time, the coverage on the first page only.
	_, p1 := getTrace(t, ts, "?limit=2")
	_, p2 := getTrace(t, ts, fmt.Sprintf("?limit=2&after=%d", p1.Next))
	if traceIDs(p1.Rows) != "[1 2]" || p1.Next != 2 || p1.Coverage == nil || traceIDs(p2.Rows) != "[3 5]" || p2.Next != 0 ||
		p2.Coverage != nil || p2.Matched != nil {
		t.Errorf("pages: %s next %d, then %s next %d (coverage %v)", traceIDs(p1.Rows), p1.Next, traceIDs(p2.Rows), p2.Next, p2.Coverage)
	}
	for query, want := range map[string]string{
		"?priority=must":          "[1 3]",
		"?priority=none":          "[]",
		"?tag=UI":                 "[5]",
		"?gap=unlinked":           "[2 5]",
		"?gap=unfulfilled":        "[3]",
		"?priority=must&gap=none": "[1]",
		"?limit=999":              "[1 2 3 5]",
	} {
		code, d := getTrace(t, ts, query)
		if code != http.StatusOK || traceIDs(d.Rows) != want {
			t.Errorf("GET trace%s = %d %s, want %s (%s)", query, code, traceIDs(d.Rows), want, d.Error)
		}
	}
	if _, d := getTrace(t, ts, "?gap=unlinked"); d.Matched == nil || *d.Matched != 2 || d.Coverage.Approved != 4 {
		t.Errorf("a filtered first page counts %v of %+v", d.Matched, d.Coverage)
	}
	// The coverage alone, as the Overview's card asks.
	if code, d := getTrace(t, ts, "?limit=0"); code != http.StatusOK || len(d.Rows) != 0 || d.Coverage == nil || d.Coverage.Approved != 4 {
		t.Errorf("limit=0 = %d %+v", code, d)
	}
	for _, bad := range []string{"?priority=urgent", "?gap=broken", "?limit=-1", "?limit=ten", "?after=-3", "?tag=%3Cb%3E"} {
		if code, d := getTrace(t, ts, bad); code != http.StatusBadRequest || d.Error == "" {
			t.Errorf("GET trace%s = %d %+v, want 400", bad, code, d)
		}
	}
}

// TestRequirementsTraceAPI_ReadOnlyInOnesOwnProject is the RBAC and
// cross-tenant case: a member who may read the project reads its matrix, a
// caller with no role on it gets nothing, and an index past a caller's own
// list reaches no other tenant's project — even one whose requirement ids are
// the same.
func TestRequirementsTraceAPI_ReadOnlyInOnesOwnProject(t *testing.T) {
	// Carol maintains whatever she owns; bob has no role anywhere.
	f := newMemberFixture(t, true, authz.Binding{Claim: authz.ClaimEmail, Value: carolEmail, Role: authz.RoleMaintainer})
	at := func(i int, q string) string { return "/api/requirements/trace?project_idx=" + itoa(i) + q }
	idx := f.idx(t, f.alice, f.project)
	if idx < 0 {
		t.Fatal("alice does not see her own project")
	}
	if code, d := f.call(t, f.alice, http.MethodPost, "/api/requirements?project_idx="+itoa(idx),
		map[string]any{"title": "alice's must", "priority": "must"}); code != http.StatusOK {
		t.Fatalf("alice adds a requirement: %d %v", code, d)
	}
	code, d := f.call(t, f.alice, http.MethodGet, at(idx, ""), nil)
	rows, _ := d["rows"].([]any)
	if code != http.StatusOK || len(rows) != 1 || !strings.Contains(fmt.Sprint(rows[0]), "alice's must") {
		t.Fatalf("alice reads her matrix: %d %v", code, d)
	}

	// Bob has no role anywhere: nothing to read, at any index.
	for _, i := range []int{0, idx, idx + 1} {
		if code, d := f.call(t, f.bob, http.MethodGet, at(i, ""), nil); code < 400 {
			t.Errorf("bob, with no role, read project %d's matrix: %d %v", i, code, d)
		}
	}

	// Shared with him as a viewer, he reads it — project.read is enough.
	members := f.membersURL(t, f.alice)
	if code, d := f.call(t, f.alice, http.MethodPost, members, map[string]any{"identity": bobEmail, "role": "viewer"}); code != http.StatusCreated {
		t.Fatalf("alice shares with bob: %d %v", code, d)
	}
	bobIdx := f.idx(t, f.bob, f.project)
	if code, d := f.call(t, f.bob, http.MethodGet, at(bobIdx, "&limit=0"), nil); code != http.StatusOK ||
		d["coverage"].(map[string]any)["approved"].(float64) != 1 {
		t.Errorf("a viewer reads the coverage: %d %v", code, d)
	}

	// Carol's own project has a requirement with the same id: each owner sees
	// their own, and carol's index past her list reaches neither alice's nor
	// anyone's.
	carols := setupProjectDir(t, "carol's goal", nil)
	registerOwned(t, carols, carolEmail)
	carolIdx := f.idx(t, f.carol, carols)
	if carolIdx < 0 || f.idx(t, f.carol, f.project) >= 0 || f.idx(t, f.alice, carols) >= 0 {
		t.Fatal("test assumption broken: a tenant sees the other's project, or carol not her own")
	}
	if code, d := f.call(t, f.carol, http.MethodPost, "/api/requirements?project_idx="+itoa(carolIdx),
		map[string]any{"title": "carol's own", "priority": "should"}); code != http.StatusOK {
		t.Fatalf("carol adds a requirement: %d %v", code, d)
	}
	code, d = f.call(t, f.carol, http.MethodGet, at(carolIdx, ""), nil)
	rows, _ = d["rows"].([]any)
	if code != http.StatusOK || len(rows) != 1 || !strings.Contains(fmt.Sprint(rows[0]), "carol's own") ||
		strings.Contains(fmt.Sprint(d), "alice's must") {
		t.Errorf("carol's matrix: %d %v", code, d)
	}
	_, paths := f.projects(t, f.carol)
	if code, d := f.call(t, f.carol, http.MethodGet, at(len(paths), ""), nil); code < 400 || strings.Contains(fmt.Sprint(d), "alice's must") {
		t.Errorf("carol read past her own list: %d %v", code, d)
	}
	if code, d := f.call(t, f.alice, http.MethodGet, at(idx, ""), nil); code != http.StatusOK || strings.Contains(fmt.Sprint(d), "carol's own") {
		t.Errorf("alice's matrix after carol's: %d %v", code, d)
	}
}

// TestCoveragePush_FollowsTheMatrix: an open dashboard is pushed the coverage
// when the matrix moved — a requirement added, a task linked, a trace written
// — and not when nothing did; with nobody watching nothing is read, and what
// was sent is forgotten.
func TestCoveragePush_FollowsTheMatrix(t *testing.T) {
	dir := seedTraceProject(t)
	srv := New(dir, 0, "")
	pushes := func(hc *hubClient) []coveragePush {
		var out []coveragePush
		for _, m := range drainAll(hc) {
			if m.Type == "requirements_coverage" {
				var p coveragePush
				if err := json.Unmarshal(m.Data, &p); err != nil {
					t.Fatal(err)
				}
				out = append(out, p)
			}
		}
		return out
	}

	// Nobody watching: nothing is computed, nothing remembered.
	srv.pushCoverage(dir, nil)
	if len(srv.covFeed.sent) != 0 {
		t.Fatalf("a push with nobody watching left %v", srv.covFeed.sent)
	}

	hc := attachHubClient(srv, dir)
	srv.pushCoverage(dir, nil)
	got := pushes(hc)
	if len(got) != 1 || got[0].Coverage == nil || got[0].Coverage.Approved != 4 || got[0].Digest == "" {
		t.Fatalf("the first push: %+v", got)
	}
	first := got[0].Digest
	// The endpoint's digest is the push's: a dashboard compares the two.
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	if _, d := getTrace(t, ts, "?limit=0"); d.Digest != first {
		t.Errorf("the endpoint's digest %q is not the push's %q", d.Digest, first)
	}

	srv.pushCoverage(dir, nil)
	if got := pushes(hc); len(got) != 0 {
		t.Errorf("nothing moved, and it pushed %+v", got)
	}

	// A must added: the coverage moves.
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.AddRequirement(requirements.Requirement{Title: "One more must", Priority: requirements.PriorityMust}, "bob"); err != nil {
		t.Fatal(err)
	}
	db.Close()
	srv.pushCoverage(dir, nil)
	got = pushes(hc)
	if len(got) != 1 || got[0].Coverage.Musts.Total != 3 || got[0].Digest == first {
		t.Fatalf("after a must was added: %+v", got)
	}

	// A task linked: the coverage counts are the same, the matrix is not.
	ps, err := state.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	ps.Plan.Tasks[2].Requirements = []int{2}
	if err := ps.Save(); err != nil {
		t.Fatal(err)
	}
	before := got[0].Digest
	srv.pushCoverage(dir, ps.Plan)
	got = pushes(hc)
	if len(got) != 1 || got[0].Digest == before || got[0].Coverage.All.Linked != 3 {
		t.Fatalf("after task 3 was linked to R-2: %+v", got)
	}

	// A trace written: a commit appears in a row.
	before = got[0].Digest
	if err := trace.WriteTraceJSON(dir, &trace.TraceMap{Entries: []trace.TraceEntry{
		{Hash: "abcabcabc1", Subject: "fix: R-2 (Task 3)", MatchedTaskID: 3, Confidence: trace.ConfidenceHigh}}}); err != nil {
		t.Fatal(err)
	}
	srv.pushCoverage(dir, nil)
	if got = pushes(hc); len(got) != 1 || got[0].Digest == before {
		t.Fatalf("after the trace was written: %+v", got)
	}

	// The dashboard closes: what was sent is forgotten.
	srv.hubMu.Lock()
	delete(srv.hubClients[dir], hc)
	srv.hubMu.Unlock()
	srv.pushCoverage(dir, nil)
	if _, kept := srv.covFeed.sent[dir]; kept {
		t.Error("with nobody watching, the last digest was kept")
	}
}
