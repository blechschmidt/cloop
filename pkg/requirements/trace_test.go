package requirements

import (
	"bytes"
	"encoding/csv"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"
)

// traceNow is the matrix's now in these tests.
var traceNow = time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)

func traceReq(id int, title, priority string, tests ...string) Requirement {
	r := Requirement{ID: id, Title: title, Priority: priority, Status: StatusApproved,
		CreatedAt: traceNow.Add(-72 * time.Hour), UpdatedAt: traceNow.Add(-48 * time.Hour)}
	for _, c := range tests {
		r.Tests = append(r.Tests, Test{Command: c})
	}
	return r
}

func traceCheck(r Requirement, verdict, method string, at time.Time) *TraceCheckFact {
	return &TraceCheckFact{Verdict: verdict, Method: method, Fingerprint: r.Fingerprint(), CheckedAt: at,
		Summary: verdict + " by " + method}
}

func planTask(id int, title, status string, done time.Time, reqs ...int) TracePlanTask {
	return TracePlanTask{TaskView: TaskView{ID: id, Status: status, CompletedAt: done, Requirements: reqs}, Title: title}
}

func rowOf(t *testing.T, rows []TraceRow, id int) TraceRow {
	t.Helper()
	for _, r := range rows {
		if r.ID == id {
			return r
		}
	}
	t.Fatalf("no row for R-%d in %+v", id, rows)
	return TraceRow{}
}

// TestTraceRows_AssembleTheMatrix covers the rows the matrix must get right: a
// requirement no task implements, one whose check and proof name a task since
// deleted, and stale verdicts of both kinds — beside one that holds, is
// proven and has commits from all three sources.
func TestTraceRows_AssembleTheMatrix(t *testing.T) {
	holds := traceReq(1, "Every dispatch is audited", PriorityMust, "go test ./audit")
	lonely := traceReq(2, "Nothing implements this", PriorityMust, "go test ./lonely")
	orphan := traceReq(3, "Checked for a deleted task", PriorityShould, "go test ./orphan")
	changed := traceReq(4, "Changed since it held", PriorityMust, "go test ./changed")
	busy := traceReq(5, "Tasks done since", PriorityCould)
	model := traceReq(6, "The model read it", "")

	changedCheck := traceCheck(changed, VerdictFulfilled, MethodTests, traceNow.Add(-5*time.Hour))
	changed.Description = "now it says more" // the verdict above is of the old definition

	facts := []TraceFacts{
		{Requirement: holds, Check: &TraceCheckFact{Verdict: VerdictFulfilled, Method: MethodTests, Fingerprint: holds.Fingerprint(),
			CheckedAt: traceNow.Add(-30 * time.Minute), Commit: "AbCdEf1234567890", TaskID: 10},
			HeldAt: traceNow.Add(-30 * time.Minute),
			Proof:  &TraceProofFact{Outcome: ProofProven, Fingerprint: holds.Fingerprint(), ProvedAt: traceNow.Add(-20 * time.Minute), TaskID: 10}},
		{Requirement: lonely},
		{Requirement: orphan, Check: &TraceCheckFact{Verdict: VerdictUnfulfilled, Method: MethodTests, Fingerprint: orphan.Fingerprint(),
			CheckedAt: traceNow.Add(-2 * time.Hour), TaskID: 99, Regression: true},
			Proof: &TraceProofFact{Outcome: ProofVacuous, Fingerprint: orphan.Fingerprint(), TaskID: 98}},
		{Requirement: changed, Check: changedCheck, HeldAt: traceNow.Add(-5 * time.Hour),
			Proof: &TraceProofFact{Outcome: ProofProven, Fingerprint: changedCheck.Fingerprint}},
		{Requirement: busy, Check: traceCheck(busy, VerdictFulfilled, MethodManual, traceNow.Add(-6*time.Hour))},
		{Requirement: model, Check: traceCheck(model, VerdictUnfulfilled, MethodAI, traceNow.Add(-time.Hour))},
	}
	plan := TracePlan{
		Tasks: []TracePlanTask{
			{TaskView: TaskView{ID: 10, Status: taskDone, CompletedAt: traceNow.Add(-40 * time.Minute), Requirements: []int{1}},
				Title: "Audit every dispatch", Commits: []TraceCommit{
					{Hash: "abcdef1234567890", Source: CommitFromGate},
					{Hash: "1111111aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Source: CommitFromWriteBack}}},
			planTask(11, "Second pass", taskInProgress, time.Time{}, 1, 1),
			planTask(12, "Orphan's sibling", taskPending, time.Time{}, 3),
			planTask(13, "Busy work", taskDone, traceNow.Add(-4*time.Hour), 5),
			planTask(14, "More busy work", taskDone, traceNow.Add(-3*time.Hour)),
		},
		Traced: map[int][]TraceCommit{
			// Task 10's gate commit again, short — the same commit.
			10: {{Hash: "abcdef1", Subject: "feat(audit): audit dispatches (Task 10)", Source: CommitFromTrace, Confidence: "high"}},
			11: {{Hash: "2222222bbb", Subject: "fix: second pass\n\nwith a body", Source: CommitFromTrace, Confidence: "medium"}},
			// A deleted task's commits are nobody's.
			99: {{Hash: "9999999fff", Subject: "the deleted task's work", Source: CommitFromTrace}},
		},
	}
	rows := TraceRows(facts, plan, traceNow)
	if len(rows) != 6 {
		t.Fatalf("%d rows, want 6: %+v", len(rows), rows)
	}

	// Holds, proven, linked, its commits once each from every source.
	r := rowOf(t, rows, 1)
	if !r.Passing || !r.Proven || !r.Linked || r.Verification != VerificationTests || r.Tests != 1 {
		t.Errorf("R-1 reads passing=%v proven=%v linked=%v %s", r.Passing, r.Proven, r.Linked, r.Verification)
	}
	if got := fmt.Sprint(r.Tasks); got != fmt.Sprint([]TraceTask{{ID: 10, Title: "Audit every dispatch", Status: taskDone},
		{ID: 11, Title: "Second pass", Status: taskInProgress}}) {
		t.Errorf("R-1's tasks: %s", got)
	}
	var hashes []string
	for _, c := range r.Commits {
		hashes = append(hashes, c.Hash+"/"+c.Source+fmt.Sprintf("/#%d", c.TaskID))
	}
	if want := []string{"abcdef1234567890/gate/#10", "1111111aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/write-back/#10", "2222222bbb/trace/#11"}; !slices.Equal(hashes, want) {
		t.Errorf("R-1's commits: %v, want %v", hashes, want)
	}
	if r.Commits[0].Subject != "feat(audit): audit dispatches (Task 10)" || r.Commits[2].Subject != "fix: second pass with a body" {
		t.Errorf("R-1's commit subjects: %q, %q", r.Commits[0].Subject, r.Commits[2].Subject)
	}
	if v := r.Verdict; v == nil || v.Stale != "" || v.AgeSeconds != 1800 || v.Commit != "abcdef1234567890" ||
		v.Task == nil || v.Task.Deleted || v.Task.Title != "Audit every dispatch" {
		t.Errorf("R-1's verdict: %+v (task %+v)", r.Verdict, r.Verdict.Task)
	}
	if len(r.Gaps) != 0 || r.Action != ActionCovered {
		t.Errorf("R-1: gaps %v, action %q (an open task implements it)", r.Gaps, r.Action)
	}

	// No task implements it: no tasks, no commits, the unlinked gap.
	r = rowOf(t, rows, 2)
	if r.Linked || len(r.Tasks) != 0 || len(r.Commits) != 0 || r.Verdict != nil || r.Proof != nil || r.Passing {
		t.Errorf("R-2 (no tasks) reads %+v", r)
	}
	if !slices.Contains(r.Gaps, GapUnlinked) || !slices.Contains(r.Gaps, GapUnchecked) || r.Action != ActionImplement {
		t.Errorf("R-2: gaps %v, action %q", r.Gaps, r.Action)
	}
	if r.Tasks == nil || r.Commits == nil {
		t.Error("R-2's empty lists are nil: they encode as null, not []")
	}

	// Its check and proof name tasks since deleted: shown deleted, with no
	// state, and their commits are not the requirement's.
	r = rowOf(t, rows, 3)
	if v := r.Verdict; v == nil || v.Task == nil || !v.Task.Deleted || v.Task.ID != 99 || v.Task.Status != "" || !v.Regression {
		t.Errorf("R-3's verdict names %+v", r.Verdict)
	}
	if p := r.Proof; p == nil || p.Task == nil || !p.Task.Deleted || p.Task.ID != 98 || p.Outcome != ProofVacuous || r.Proven {
		t.Errorf("R-3's proof: %+v", r.Proof)
	}
	if len(r.Tasks) != 1 || r.Tasks[0].ID != 12 || len(r.Commits) != 0 {
		t.Errorf("R-3's tasks %+v and commits %+v: only the live link, no deleted task's commits", r.Tasks, r.Commits)
	}
	if r.Verdict.Task.Label() != "#99 deleted" {
		t.Errorf("a deleted task reads %q", r.Verdict.Task.Label())
	}

	// Stale because it changed: not passing, its proof stale, verify.
	r = rowOf(t, rows, 4)
	if v := r.Verdict; v == nil || v.Stale != StaleChanged || r.Passing {
		t.Errorf("R-4 (changed since) reads verdict %+v, passing %v", r.Verdict, r.Passing)
	}
	if r.Proof == nil || !r.Proof.Stale || r.Proven {
		t.Errorf("R-4's proof of tests it no longer has: %+v, proven %v", r.Proof, r.Proven)
	}
	if !slices.Contains(r.Gaps, GapStale) || r.Action != ActionVerify {
		t.Errorf("R-4: gaps %v, action %q", r.Gaps, r.Action)
	}

	// Stale because tasks finished since: still passing on its definition,
	// a person's word on an untested requirement.
	r = rowOf(t, rows, 5)
	if v := r.Verdict; v == nil || v.Stale != StaleTasks || v.TasksDoneSince != 3 || !r.Passing {
		t.Errorf("R-5 (tasks since) reads %+v, passing %v", r.Verdict, r.Passing)
	}
	if r.Verification != VerificationPerson || r.Proof != nil {
		t.Errorf("R-5 is %s with proof %+v", r.Verification, r.Proof)
	}

	r = rowOf(t, rows, 6)
	if r.Verification != VerificationModel || r.Passing || !slices.Contains(r.Gaps, GapUnfulfilled) {
		t.Errorf("R-6 reads %s, passing %v, gaps %v", r.Verification, r.Passing, r.Gaps)
	}

	// What it all adds up to.
	cov := CoverageOf(rows)
	if cov.Approved != 6 || cov.Musts != (CoverageCounts{Total: 3, Tested: 3, Proven: 1, Passing: 1, Linked: 1,
		TestedPct: 100, ProvenPct: 33, PassingPct: 33, LinkedPct: 33}) {
		t.Errorf("must coverage: %+v", cov.Musts)
	}
	if cov.All.Total != 6 || cov.All.Tested != 4 || cov.All.Passing != 2 || cov.All.Linked != 3 || cov.All.TestedPct != 66 {
		t.Errorf("coverage of all: %+v", cov.All)
	}
	// R-3 and R-6 too: task 10 finished after their checks.
	if cov.Stale != 4 || cov.Gaps[GapUnlinked] != 3 || cov.Verification[VerificationTests] != 4 ||
		cov.Verification[VerificationModel] != 1 || cov.Verification[VerificationPerson] != 1 {
		t.Errorf("coverage: stale %d, gaps %v, verification %v", cov.Stale, cov.Gaps, cov.Verification)
	}
	lines := strings.Join(cov.Lines(), "\n")
	for _, want := range []string{"Musts: 3 — 3 tested (100%), 1 proven (33%), 1 passing (33%), 1 linked to a task (33%)",
		"Open gaps:", "3 unlinked", "Verified: 4 tested, 1 model-assessed, 1 person-assessed"} {
		if !strings.Contains(lines, want) {
			t.Errorf("the coverage lines lack %q:\n%s", want, lines)
		}
	}
}

// TestTraceRows_ClassifyVerification: a test makes a requirement tested
// whatever its verdict; without one, only a decision counts — the model's or a
// person's — and a verdict nobody could reach, or a check that did not work,
// leaves it unverified.
func TestTraceRows_ClassifyVerification(t *testing.T) {
	r := traceReq(1, "untested", "")
	for _, c := range []struct {
		check *TraceCheckFact
		want  string
	}{
		{nil, VerificationNone},
		{traceCheck(r, VerdictUnverified, MethodAI, traceNow), VerificationNone},
		{traceCheck(r, VerdictError, MethodAI, traceNow), VerificationNone},
		{traceCheck(r, VerdictFulfilled, MethodAI, traceNow), VerificationModel},
		{traceCheck(r, VerdictUnfulfilled, MethodManual, traceNow), VerificationPerson},
		{traceCheck(r, VerdictFulfilled, MethodTests, traceNow), VerificationNone}, // its tests are gone
	} {
		if got := verification(r, c.check); got != c.want {
			t.Errorf("untested, check %+v: %s, want %s", c.check, got, c.want)
		}
	}
	if got := verification(traceReq(2, "tested", "", "true"), nil); got != VerificationTests {
		t.Errorf("tested, never checked: %s", got)
	}
}

// TestTraceRows_BoundTheirLists: a requirement fifty-odd tasks implement, and
// whose tasks made more commits than a row names, counts what it leaves out.
func TestTraceRows_BoundTheirLists(t *testing.T) {
	r := traceReq(1, "popular", PriorityMust, "true")
	plan := TracePlan{Traced: map[int][]TraceCommit{}}
	for i := 1; i <= MaxTraceTasks+5; i++ {
		plan.Tasks = append(plan.Tasks, planTask(i, fmt.Sprint("task ", i), taskDone, traceNow, 1))
		plan.Traced[i] = []TraceCommit{{Hash: fmt.Sprintf("%07x0", i), Source: CommitFromTrace}}
	}
	row := TraceRows([]TraceFacts{{Requirement: r}}, plan, traceNow)[0]
	if len(row.Tasks) != MaxTraceTasks || row.TasksOmitted != 5 || len(row.Commits) != MaxTraceCommits ||
		row.CommitsOmitted != MaxTraceTasks+5-MaxTraceCommits {
		t.Errorf("tasks %d (+%d), commits %d (+%d)", len(row.Tasks), row.TasksOmitted, len(row.Commits), row.CommitsOmitted)
	}
	// A task's title is held to one line of 200 characters.
	plan.Tasks[0].Title = strings.Repeat("long title ", 50) + "\nsecond line"
	row = TraceRows([]TraceFacts{{Requirement: r}}, plan, traceNow)[0]
	if got := row.Tasks[0].Title; len([]rune(got)) != maxTraceSubjectRunes || strings.Contains(got, "\n") {
		t.Errorf("a long task title reads %q", got)
	}
	// A hash that is not one, or too short to name a commit, is dropped.
	plan = TracePlan{Tasks: []TracePlanTask{planTask(1, "t", taskDone, traceNow, 1)}, Traced: map[int][]TraceCommit{
		1: {{Hash: "<script>"}, {Hash: "abc"}, {Hash: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0"}, {Hash: "DEADBEEF"}}}}
	row = TraceRows([]TraceFacts{{Requirement: r}}, plan, traceNow)[0]
	if len(row.Commits) != 1 || row.Commits[0].Hash != "deadbeef" {
		t.Errorf("commits %+v", row.Commits)
	}
}

// TestTraceFilter: each filter narrows to what it names, none selects the
// rows without one, and what no requirement could match is refused.
func TestTraceFilter(t *testing.T) {
	rows := []TraceRow{
		{ID: 1, Priority: PriorityMust, Tags: []string{"api"}, Gaps: []string{GapUnfulfilled}},
		{ID: 2, Priority: PriorityShould, Tags: []string{"ui", "api"}},
		{ID: 3, Gaps: []string{GapUntested, GapUnlinked}},
	}
	match := func(f TraceFilter) []int {
		var out []int
		for _, r := range rows {
			if f.Match(r) {
				out = append(out, r.ID)
			}
		}
		return out
	}
	for _, c := range []struct {
		priority, tag, gap string
		want               []int
	}{
		{"", "", "", []int{1, 2, 3}},
		{"MUST", "", "", []int{1}},
		{"none", "", "", []int{3}},
		{"", " API ", "", []int{1, 2}},
		{"", "", "none", []int{2}},
		{"", "", "unlinked", []int{3}},
		{"should", "api", "", []int{2}},
		{"must", "ui", "", nil},
	} {
		f, err := ParseTraceFilter(c.priority, c.tag, c.gap)
		if err != nil {
			t.Fatalf("ParseTraceFilter(%q, %q, %q): %v", c.priority, c.tag, c.gap, err)
		}
		if got := match(f); fmt.Sprint(got) != fmt.Sprint(c.want) {
			t.Errorf("filter %+v: %v, want %v", f, got, c.want)
		}
	}
	for _, bad := range [][3]string{{"urgent", "", ""}, {"", "", "broken"}, {"", "a tag with spaces", ""}, {"", "<b>", ""},
		{"", strings.Repeat("t", MaxTagRunes+1), ""}} {
		if _, err := ParseTraceFilter(bad[0], bad[1], bad[2]); !errors.Is(err, ErrInvalid) {
			t.Errorf("ParseTraceFilter(%q) = %v, want ErrInvalid", bad, err)
		}
	}
}

// fakeTraceSource serves facts as the database would: approved only, in id
// order, filtered by priority and tag, after a cursor, a limit at a time —
// and counts what it was asked.
type fakeTraceSource struct {
	facts []TraceFacts
	calls []TraceQuery
}

func (s *fakeTraceSource) TraceFacts(q TraceQuery) ([]TraceFacts, error) {
	s.calls = append(s.calls, q)
	var out []TraceFacts
	for _, f := range s.facts {
		r := f.Requirement
		switch {
		case r.ID <= q.After,
			q.Priority == FilterNone && r.Priority != "",
			q.Priority != "" && q.Priority != FilterNone && r.Priority != q.Priority,
			q.Tag != "" && !slices.Contains(r.Tags, q.Tag):
			continue
		}
		if len(out) == q.Limit {
			break
		}
		out = append(out, f)
	}
	return out, nil
}

// TestTrace_PagesThroughTheKeyset: pages follow one another by their Next
// without a row twice or a row missed; a gap filter reads on until its page is
// full; the coverage is of every requirement whatever the filter; and a page
// of none asks for the coverage alone.
func TestTrace_PagesThroughTheKeyset(t *testing.T) {
	src := &fakeTraceSource{}
	plan := TracePlan{}
	for i := 1; i <= 23; i++ {
		r := traceReq(i, fmt.Sprint("requirement ", i), Priorities[i%3])
		f := TraceFacts{Requirement: r}
		if i%4 == 0 {
			// Every fourth is tested and passing, the rest untested.
			r.Tests = []Test{{Command: "true"}}
			f = TraceFacts{Requirement: r, Check: traceCheck(r, VerdictFulfilled, MethodTests, traceNow.Add(-time.Hour))}
			plan.Tasks = append(plan.Tasks, planTask(100+i, "t", taskDone, traceNow.Add(-2*time.Hour), i))
		}
		src.facts = append(src.facts, f)
	}
	var seen []int
	after := 0
	for n := 0; ; n++ {
		page, err := Trace(src, plan, TraceRequest{After: after, Limit: 5, Coverage: n == 0}, traceNow)
		if err != nil {
			t.Fatal(err)
		}
		if n == 0 && (page.Coverage == nil || page.Coverage.Approved != 23 || page.Matched == nil || *page.Matched != 23 || page.Digest == "") {
			t.Fatalf("the first page's coverage: %+v, matched %v, digest %q", page.Coverage, page.Matched, page.Digest)
		}
		if n > 0 && page.Coverage != nil {
			t.Error("a later page worked the coverage out again")
		}
		for _, r := range page.Rows {
			seen = append(seen, r.ID)
		}
		if page.Next == 0 {
			break
		}
		if n > 10 {
			t.Fatal("pages never end")
		}
		after = page.Next
	}
	if len(seen) != 23 || !slices.IsSorted(seen) || seen[0] != 1 || seen[22] != 23 {
		t.Errorf("paged through %v", seen)
	}

	// A gap only the tested ones lack: a page of "no gap" reads on past the
	// rows without it, in chunks larger than the page.
	src.calls = nil
	f, _ := ParseTraceFilter("", "", "untested")
	page, err := Trace(src, plan, TraceRequest{Filter: f, Limit: 3, Coverage: true}, traceNow)
	if err != nil {
		t.Fatal(err)
	}
	if ids := []int{page.Rows[0].ID, page.Rows[1].ID, page.Rows[2].ID}; fmt.Sprint(ids) != "[1 2 3]" || page.Next != 3 {
		t.Errorf("untested page: %v, next %d", ids, page.Next)
	}
	if *page.Matched != 18 || page.Coverage.Approved != 23 {
		t.Errorf("untested matched %d of %d", *page.Matched, page.Coverage.Approved)
	}
	f, _ = ParseTraceFilter("", "", FilterNone)
	src.calls = nil
	page, _ = Trace(src, plan, TraceRequest{Filter: f, Limit: 2}, traceNow)
	var ids []int
	for _, r := range page.Rows {
		ids = append(ids, r.ID)
	}
	if fmt.Sprint(ids) != "[4 8]" || page.Next != 8 {
		t.Errorf("a page of rows with no gap: %v, next %d", ids, page.Next)
	}
	if len(src.calls) != 1 || src.calls[0].Limit != gapChunk {
		t.Errorf("a gap page asked %+v: one chunk of %d covers it", src.calls, gapChunk)
	}
	page, _ = Trace(src, plan, TraceRequest{Filter: f, After: 8, Limit: 2}, traceNow)
	if len(page.Rows) != 2 || page.Rows[0].ID != 12 || page.Rows[1].ID != 16 || page.Next != 16 {
		t.Errorf("the next page of rows with no gap: %+v, next %d", page.Rows, page.Next)
	}
	page, _ = Trace(src, plan, TraceRequest{Filter: f, After: 20, Limit: 2}, traceNow)
	if len(page.Rows) != 0 || page.Next != 0 {
		t.Errorf("past the last: %+v, next %d", page.Rows, page.Next)
	}

	// The coverage alone: no row is read for a page.
	src.calls = nil
	page, _ = Trace(src, plan, TraceRequest{Coverage: true}, traceNow)
	if len(page.Rows) != 0 || page.Coverage == nil || len(src.calls) != 1 || src.calls[0].Limit != MaxRequirements {
		t.Errorf("coverage alone: rows %d, calls %+v", len(page.Rows), src.calls)
	}
	if page.Rows == nil {
		t.Error("rows encode as null")
	}

	// The digest moves with what a row says, not with time.
	later, _ := Trace(src, plan, TraceRequest{Coverage: true}, traceNow.Add(time.Hour))
	if later.Digest != page.Digest {
		t.Error("the digest changed with the verdicts' age alone")
	}
	plan.Tasks = append(plan.Tasks, planTask(500, "new", taskPending, time.Time{}, 1))
	moved, _ := Trace(src, plan, TraceRequest{Coverage: true}, traceNow)
	if moved.Digest == page.Digest {
		t.Error("a task linked to R-1 left the digest as it was")
	}
}

// TestTraceRender: the CSV keeps every cell from being a formula and holds
// one line per requirement; the Markdown keeps each row one table row, with
// no raw HTML.
func TestTraceRender(t *testing.T) {
	hostile := traceReq(7, `=HYPERLINK("http://x","click") | <img src=x onerror=alert(1)>`, PriorityMust, "go test")
	hostile.Tags = []string{"-danger", "@at"}
	plan := TracePlan{Tasks: []TracePlanTask{planTask(3, "+SUM(A1)", taskDone, traceNow, 7)},
		Traced: map[int][]TraceCommit{3: {{Hash: "abcdef0123", Subject: "line one\n| line two", Source: CommitFromTrace}}}}
	rows := TraceRows([]TraceFacts{{Requirement: hostile, Check: traceCheck(hostile, VerdictFulfilled, MethodTests, traceNow.Add(-90*time.Minute))}},
		plan, traceNow)

	var b bytes.Buffer
	if err := WriteTraceCSV(&b, rows); err != nil {
		t.Fatal(err)
	}
	recs, err := csv.NewReader(&b).ReadAll()
	if err != nil || len(recs) != 2 || !slices.Equal(recs[0], TraceCSVHeader) {
		t.Fatalf("the CSV reads %v, %v", recs, err)
	}
	for i, cell := range recs[1] {
		if cell != "" && strings.ContainsRune("=+-@", rune(cell[0])) {
			t.Errorf("column %s starts a formula: %q", recs[0][i], cell)
		}
	}
	if recs[1][1] != `'=HYPERLINK("http://x","click") | <img src=x onerror=alert(1)>` || recs[1][3] != "'-danger @at" ||
		recs[1][6] != "#3 done" || recs[1][7] != "abcdef0123 #3" || recs[1][16] != "true" {
		t.Errorf("the CSV row: %q", recs[1])
	}

	b.Reset()
	cov := CoverageOf(rows)
	if err := WriteTraceMarkdown(&b, rows, &cov); err != nil {
		t.Fatal(err)
	}
	md := b.String()
	if strings.Contains(md, "<img") || strings.Contains(md, "| <") {
		t.Errorf("raw HTML in the Markdown:\n%s", md)
	}
	var table []string
	for _, l := range strings.Split(md, "\n") {
		if strings.HasPrefix(l, "| ") {
			table = append(table, l)
		}
	}
	if len(table) != 2 || !strings.Contains(table[1], `R-7 =HYPERLINK("http://x","click") \| &lt;img`) ||
		!strings.Contains(table[1], "fulfilled (tests), 1h ago") || !strings.Contains(md, "## Spec coverage") {
		t.Errorf("the Markdown table:\n%s", md)
	}
	if strings.Count(table[1], " | ") != 7 {
		t.Errorf("a row's pipes split it: %q", table[1])
	}
	b.Reset()
	if err := WriteTraceMarkdown(&b, nil, nil); err != nil || !strings.Contains(b.String(), "No approved requirement matches.") {
		t.Errorf("an empty matrix reads %q, %v", b.String(), err)
	}
}
