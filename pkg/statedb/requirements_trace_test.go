package statedb

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/requirements"
)

// explainPlan returns the plan SQLite chooses for query, one detail per step.
func explainPlan(t *testing.T, db *DB, query string, args ...any) []string {
	t.Helper()
	rows, err := db.conn.Query(`EXPLAIN QUERY PLAN `+query, args...)
	if err != nil {
		t.Fatalf("explain %s: %v", query, err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id, parent, notused int
		var detail string
		if err := rows.Scan(&id, &parent, &notused, &detail); err != nil {
			t.Fatal(err)
		}
		out = append(out, detail)
	}
	return out
}

// seedTraceRows fills db with n requirements of every status and priority,
// each approved one checked and proved a few times, then has SQLite gather
// statistics: the planner then chooses as it would on a project's database
// that `cloop db maintain` has analysed.
func seedTraceRows(t *testing.T, db *DB, n int) {
	t.Helper()
	statuses := []string{requirements.StatusApproved, requirements.StatusApproved, requirements.StatusDraft, requirements.StatusDeprecated}
	priorities := []string{requirements.PriorityMust, requirements.PriorityShould, requirements.PriorityCould, ""}
	for i := 0; i < n; i++ {
		r, err := db.AddRequirement(requirements.Requirement{Title: fmt.Sprintf("requirement %d", i),
			Priority: priorities[i%len(priorities)], Status: statuses[i%len(statuses)],
			Tags:  []string{fmt.Sprintf("area-%d", i%5)},
			Tests: []requirements.Test{{Command: fmt.Sprintf("go test ./pkg/%d", i)}}}, "alice")
		if err != nil {
			t.Fatal(err)
		}
		if r.Status != requirements.StatusApproved {
			continue
		}
		for k := 0; k < 3; k++ {
			verdict := requirements.VerdictFulfilled
			if k == 2 && i%3 == 0 {
				verdict = requirements.VerdictUnfulfilled
			}
			if _, err := db.RecordRequirementChecks(CheckRecord{RunID: fmt.Sprintf("run-%d-%d", i, k)}, []requirements.Result{{
				RequirementID: r.ID, Fingerprint: r.Fingerprint(), Method: requirements.MethodTests, Verdict: verdict,
				StartedAt: time.Now().Add(time.Duration(k-3) * time.Hour)}}); err != nil {
				t.Fatal(err)
			}
		}
		if i%2 == 0 {
			if _, err := db.RecordRequirementProofs(ProofRecord{RunID: fmt.Sprintf("proof-%d", i)}, []requirements.Proof{{
				RequirementID: r.ID, Fingerprint: r.Fingerprint(), Outcome: requirements.ProofProven}}); err != nil {
				t.Fatal(err)
			}
		}
	}
	if _, err := db.conn.Exec(`ANALYZE`); err != nil {
		t.Fatal(err)
	}
}

// TestTraceFacts_SeekTheIndexes holds every query the traceability matrix makes
// to its plan (Task 20465): each page seeks its first requirement through an
// index and walks it in id order — no scan of the table, no sort — and each
// row's latest check and latest proof are a seek apiece. Asked of an empty
// database and of one with statistics, since the planner may choose
// differently once it has them.
func TestTraceFacts_SeekTheIndexes(t *testing.T) {
	queries := map[string]requirements.TraceQuery{
		"every requirement":     {Limit: 51},
		"after a cursor":        {After: 40, Limit: 51},
		"must":                  {Priority: requirements.PriorityMust, After: 12, Limit: 51},
		"no priority":           {Priority: requirements.FilterNone, Limit: 51},
		"a tag":                 {Tag: "area-3", Limit: 51},
		"a priority and a tag":  {Priority: requirements.PriorityShould, Tag: "area-1", After: 3, Limit: 51},
		"the whole coverage":    {Limit: requirements.MaxRequirements},
		"a gap filter's chunks": {After: 120, Limit: 100},
	}
	for _, seeded := range []bool{false, true} {
		db := openFresh(t)
		if seeded {
			seedTraceRows(t, db, 240)
		}
		for name, q := range queries {
			query, args := traceFactsQuery(q)
			steps := explainPlan(t, db, query, args...)
			plan := strings.Join(steps, "; ")
			var page string
			for _, s := range steps {
				if strings.HasPrefix(s, "SEARCH r ") || strings.HasPrefix(s, "SCAN r") {
					page = s
				}
			}
			// A seek, through the status index when it narrows the rows —
			// or the primary key when the statistics say it would not.
			if !strings.HasPrefix(page, "SEARCH r USING INDEX requirements_status") &&
				!strings.HasPrefix(page, "SEARCH r USING INTEGER PRIMARY KEY (rowid>?)") {
				t.Errorf("seeded=%v %s: the page reads requirements by %q, want a seek\nplan: %s", seeded, name, page, plan)
			}
			if q.Priority != "" && !strings.Contains(page, "priority=?") && strings.Contains(page, "requirements_status") {
				t.Errorf("seeded=%v %s: a priority page seeks %q, not by its priority\nplan: %s", seeded, name, page, plan)
			}
			for _, s := range steps {
				switch {
				case strings.Contains(s, "TEMP B-TREE"):
					t.Errorf("seeded=%v %s: the page sorts (%q)\nplan: %s", seeded, name, s, plan)
				case strings.HasPrefix(s, "SCAN") && !strings.Contains(s, "json_each"):
					t.Errorf("seeded=%v %s: the page scans (%q)\nplan: %s", seeded, name, s, plan)
				}
			}
			for _, want := range []string{
				"SEARCH requirement_checks USING COVERING INDEX requirement_checks_requirement (requirement_id=?)",
				"SEARCH requirement_proofs USING COVERING INDEX requirement_proofs_requirement (requirement_id=?)",
				"SEARCH c USING INTEGER PRIMARY KEY (rowid=?)",
				"SEARCH p USING INTEGER PRIMARY KEY (rowid=?)",
			} {
				if !strings.Contains(plan, want) {
					t.Errorf("seeded=%v %s: the plan lacks %q\nplan: %s", seeded, name, want, plan)
				}
			}
		}
		// When each of a page's requirements last held: a seek per id.
		plan := strings.Join(explainPlan(t, db, traceHeldSQL, "[1,2,3]", requirements.VerdictFulfilled), "; ")
		if !strings.Contains(plan, "SEARCH requirement_checks USING INDEX requirement_checks_requirement (requirement_id=?)") ||
			strings.Contains(plan, "SCAN requirement_checks") {
			t.Errorf("seeded=%v: the held query's plan is %s", seeded, plan)
		}
	}
}

// TestTraceFacts_ReadEachApprovedRequirementWithItsLatestVerdictAndProof: a
// page holds the approved requirements only, in id order after its cursor,
// each with its newest check and newest proof; the filters narrow it; HeldAt
// is when its current definition last held, not an earlier one.
func TestTraceFacts_ReadEachApprovedRequirementWithItsLatestVerdictAndProof(t *testing.T) {
	db := openFresh(t)
	add := func(title, priority, status string, tags []string, tests ...string) requirements.Requirement {
		t.Helper()
		r := requirements.Requirement{Title: title, Priority: priority, Status: status, Tags: tags}
		for _, c := range tests {
			r.Tests = append(r.Tests, requirements.Test{Command: c})
		}
		got, err := db.AddRequirement(r, "alice")
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	check := func(r requirements.Requirement, verdict string, at time.Time, task int) {
		t.Helper()
		if _, err := db.RecordRequirementChecks(CheckRecord{RunID: "run", Commit: "abc1234def", TaskID: task}, []requirements.Result{{
			RequirementID: r.ID, Fingerprint: r.Fingerprint(), Method: requirements.MethodTests, Verdict: verdict,
			Summary: verdict + " at " + at.Format(time.Kitchen), StartedAt: at}}); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now().UTC().Truncate(time.Second)
	must := add("must hold", requirements.PriorityMust, "", []string{"core", "api"}, "go test ./core")
	draft := add("a draft", requirements.PriorityMust, requirements.StatusDraft, []string{"core"}, "go test ./draft")
	should := add("should hold", requirements.PriorityShould, "", []string{"ui"})
	_ = add("retired", requirements.PriorityMust, requirements.StatusDeprecated, []string{"core"})
	unranked := add("unranked", "", "", nil, "go test ./x")

	check(must, requirements.VerdictFulfilled, now.Add(-3*time.Hour), 0)
	check(must, requirements.VerdictUnfulfilled, now.Add(-time.Hour), 7)
	if _, err := db.RecordRequirementProofs(ProofRecord{RunID: "p1", TaskID: 7}, []requirements.Proof{{
		RequirementID: must.ID, Fingerprint: must.Fingerprint(), Outcome: requirements.ProofVacuous}}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.RecordRequirementProofs(ProofRecord{RunID: "p2", TaskID: 9}, []requirements.Proof{{
		RequirementID: must.ID, Fingerprint: must.Fingerprint(), Outcome: requirements.ProofProven, Summary: "red then green"}}); err != nil {
		t.Fatal(err)
	}
	// The unranked one held, then changed: its hold was of a definition it no
	// longer has.
	check(unranked, requirements.VerdictFulfilled, now.Add(-2*time.Hour), 0)
	unranked.Tests = []requirements.Test{{Command: "go test ./y"}}
	if _, err := db.UpdateRequirement(unranked, "bob"); err != nil {
		t.Fatal(err)
	}

	all, err := db.TraceFacts(requirements.TraceQuery{Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	var ids []int
	for _, f := range all {
		ids = append(ids, f.Requirement.ID)
	}
	if fmt.Sprint(ids) != fmt.Sprint([]int{must.ID, should.ID, unranked.ID}) {
		t.Fatalf("the approved requirements read as %v (draft R-%d must be left out)", ids, draft.ID)
	}
	m := all[0]
	if m.Check == nil || m.Check.Verdict != requirements.VerdictUnfulfilled || m.Check.TaskID != 7 ||
		m.Check.Commit != "abc1234def" || !m.Check.CheckedAt.Equal(now.Add(-time.Hour)) {
		t.Errorf("R-%d's latest check reads %+v", must.ID, m.Check)
	}
	if !m.HeldAt.Equal(now.Add(-3 * time.Hour)) {
		t.Errorf("R-%d last held at %v, want %v", must.ID, m.HeldAt, now.Add(-3*time.Hour))
	}
	if m.Proof == nil || m.Proof.Outcome != requirements.ProofProven || m.Proof.TaskID != 9 || m.Proof.Summary != "red then green" {
		t.Errorf("R-%d's latest proof reads %+v", must.ID, m.Proof)
	}
	if len(m.Requirement.Tests) != 1 || m.Requirement.Fingerprint() != must.Fingerprint() {
		t.Errorf("R-%d reads %+v, its fingerprint changed", must.ID, m.Requirement)
	}
	if s := all[1]; s.Check != nil || s.Proof != nil || !s.HeldAt.IsZero() {
		t.Errorf("never-checked R-%d reads %+v", should.ID, s)
	}
	if u := all[2]; u.Check == nil || u.Check.Verdict != requirements.VerdictFulfilled || !u.HeldAt.IsZero() {
		t.Errorf("changed R-%d reads check %+v, held %v: a hold of its old definition is no hold of this one", unranked.ID, u.Check, u.HeldAt)
	}

	page := func(q requirements.TraceQuery) []int {
		t.Helper()
		got, err := db.TraceFacts(q)
		if err != nil {
			t.Fatalf("TraceFacts(%+v): %v", q, err)
		}
		var out []int
		for _, f := range got {
			out = append(out, f.Requirement.ID)
		}
		return out
	}
	for name, c := range map[string]struct {
		q    requirements.TraceQuery
		want []int
	}{
		"the first page":      {requirements.TraceQuery{Limit: 2}, []int{must.ID, should.ID}},
		"after the first":     {requirements.TraceQuery{After: should.ID, Limit: 2}, []int{unranked.ID}},
		"musts":               {requirements.TraceQuery{Priority: requirements.PriorityMust}, []int{must.ID}},
		"no priority":         {requirements.TraceQuery{Priority: requirements.FilterNone}, []int{unranked.ID}},
		"a tag":               {requirements.TraceQuery{Tag: "core"}, []int{must.ID}},
		"a tag and priority":  {requirements.TraceQuery{Tag: "ui", Priority: requirements.PriorityShould}, []int{should.ID}},
		"a tag no row has":    {requirements.TraceQuery{Tag: "nowhere"}, nil},
		"a priority and none": {requirements.TraceQuery{Tag: "api", Priority: requirements.PriorityShould}, nil},
	} {
		if got := page(c.q); fmt.Sprint(got) != fmt.Sprint(c.want) {
			t.Errorf("%s: %v, want %v", name, got, c.want)
		}
	}

	// A row something else wrote, its tags not JSON: the tag page passes it
	// by rather than failing.
	if _, err := db.conn.Exec(`UPDATE requirements SET tags = '[oops' WHERE id = ?`, should.ID); err != nil {
		t.Fatal(err)
	}
	if got := page(requirements.TraceQuery{Tag: "core"}); fmt.Sprint(got) != fmt.Sprint([]int{must.ID}) {
		t.Errorf("with a malformed row, the tag page reads %v", got)
	}
	if got := page(requirements.TraceQuery{}); len(got) != 3 {
		t.Errorf("with a malformed row, the page reads %v", got)
	}
}
