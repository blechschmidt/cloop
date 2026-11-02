package cmd

// `cloop requirements trace` and the coverage in `cloop report` (Task 20465),
// run as a person runs them: this test binary acting as cloop, in a project
// with a git history whose commits name their tasks, traced by `cloop trace
// --no-model` — no model is asked anywhere.

import (
	"encoding/csv"
	"encoding/json"
	"os/exec"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/requirements"
)

func TestRequirementsTraceCommand(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	exe := cliSelfExe(t)
	dir := reqTestProject(t)
	git := func(args ...string) {
		t.Helper()
		c := exec.Command("git", append([]string{"-c", "user.name=t", "-c", "user.email=t@example.com",
			"-c", "commit.gpgsign=false"}, args...)...)
		c.Dir = dir
		if out, err := c.CombinedOutput(); err != nil {
			t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
		}
	}

	mustRun(t, exe, dir, "requirements", "add", "Holds", "--test", "true", "--priority", "must", "--tag", "core")
	mustRun(t, exe, dir, "requirements", "add", "Nobody implements this", "--priority", "must")
	mustRun(t, exe, dir, "requirements", "add", "=cmd|' /C calc'!A0", "--priority", "could", "--tag", "ui")
	mustRun(t, exe, dir, "task", "add", "Make it hold", "--no-ai", "--requirement", "R-1")
	mustRun(t, exe, dir, "task", "add", "Something else", "--no-ai")
	mustRun(t, exe, dir, "requirements", "check", "1")

	git("init", "-q")
	git("commit", "-q", "--allow-empty", "-m", "feat: make it hold (Task 1)")
	git("commit", "-q", "--allow-empty", "-m", "chore: unrelated")
	if out := mustRun(t, exe, dir, "trace", "--no-model"); !strings.Contains(out, "2 commits  |  1 linked") {
		t.Fatalf("cloop trace --no-model:\n%s", out)
	}

	// JSON: the rows, the coverage, and the commit the trace linked.
	var page struct {
		Rows     []requirements.TraceRow `json:"rows"`
		Coverage *requirements.Coverage  `json:"coverage"`
		Matched  int                     `json:"matched"`
		Next     int                     `json:"next"`
	}
	out := mustRun(t, exe, dir, "requirements", "trace", "--json")
	if err := json.Unmarshal([]byte(out), &page); err != nil {
		t.Fatalf("trace --json: %v\n%s", err, out)
	}
	if len(page.Rows) != 3 || page.Coverage == nil || page.Coverage.Musts.Total != 2 || page.Coverage.Musts.Passing != 1 ||
		page.Coverage.Musts.Linked != 1 || page.Matched != 3 || page.Next != 0 {
		t.Fatalf("trace --json: %+v / %+v", page.Rows, page.Coverage)
	}
	r1 := page.Rows[0]
	if len(r1.Tasks) != 1 || r1.Tasks[0].ID != 1 || len(r1.Commits) != 1 || r1.Commits[0].Source != requirements.CommitFromTrace ||
		r1.Commits[0].Subject != "feat: make it hold (Task 1)" || !r1.Passing || r1.Verdict == nil || r1.Verdict.Verdict != requirements.VerdictFulfilled {
		t.Errorf("R-1: %+v", r1)
	}
	if r2 := page.Rows[1]; r2.Linked || len(r2.Commits) != 0 || r2.Verdict != nil {
		t.Errorf("R-2: %+v", r2)
	}

	// One page at a time, by cursor.
	out = mustRun(t, exe, dir, "requirements", "trace", "--json", "--priority", "must", "--limit", "1")
	if err := json.Unmarshal([]byte(out), &page); err != nil || len(page.Rows) != 1 || page.Rows[0].ID != 1 || page.Next != 1 {
		t.Fatalf("a page of musts: %v %+v", err, page)
	}
	page.Rows, page.Next, page.Coverage = nil, 0, nil
	out = mustRun(t, exe, dir, "requirements", "trace", "--json", "--priority", "must", "--limit", "1", "--after", "1")
	if err := json.Unmarshal([]byte(out), &page); err != nil || len(page.Rows) != 1 || page.Rows[0].ID != 2 || page.Next != 0 || page.Coverage != nil {
		t.Fatalf("the next page: %v %+v", err, page)
	}

	// CSV: a header, a line per requirement, no cell a formula.
	recs, err := csv.NewReader(strings.NewReader(mustRun(t, exe, dir, "requirements", "trace", "--csv"))).ReadAll()
	if err != nil || len(recs) != 4 || recs[0][0] != "requirement" {
		t.Fatalf("trace --csv: %v %q", err, recs)
	}
	if recs[3][1] != "'=cmd|' /C calc'!A0" {
		t.Errorf("a title that is a formula reads %q in the CSV", recs[3][1])
	}

	md := mustRun(t, exe, dir, "requirements", "trace", "--markdown", "--gap", "unlinked")
	if !strings.Contains(md, "## Spec coverage") || !strings.Contains(md, "| R-2 Nobody implements this |") ||
		strings.Contains(md, "| R-1 ") || !strings.Contains(md, `=cmd\|' /C calc'!A0`) {
		t.Errorf("trace --markdown --gap unlinked:\n%s", md)
	}
	term := mustRun(t, exe, dir, "requirements", "trace")
	for _, want := range []string{"Spec coverage", "Musts: 2 — 1 tested (50%)", "R-1", "tasks: #1 pending", "commits: ", "R-2", "open: "} {
		if !strings.Contains(term, want) {
			t.Errorf("trace lacks %q:\n%s", want, term)
		}
	}
	for _, bad := range [][]string{{"--json", "--csv"}, {"--gap", "broken"}, {"--priority", "urgent"}, {"--limit", "-1"}, {"--limit", "500"}} {
		if out, err := runHelper(t, exe, dir, append([]string{"requirements", "trace"}, bad...)...); err == nil {
			t.Errorf("trace %v was taken:\n%s", bad, out)
		}
	}

	// The report carries the coverage.
	rep := mustRun(t, exe, dir, "report", "--format", "md")
	if !strings.Contains(rep, "## Spec Coverage") || !strings.Contains(rep, "| Passing | 1 (50%) | 1 (33%) |") {
		t.Errorf("the report's coverage:\n%s", rep)
	}
	if rep := mustRun(t, exe, dir, "report"); !strings.Contains(rep, "Spec coverage") || !strings.Contains(rep, "Musts: 2") {
		t.Errorf("the terminal report:\n%s", rep)
	}
	if rep := mustRun(t, exe, dir, "report", "--format", "html"); !strings.Contains(rep, "<h2>Spec Coverage</h2>") {
		t.Errorf("the HTML report lacks the coverage")
	}
}

// TestReportWithoutRequirementsLeavesCoverageOut: a project with no approved
// requirement has no coverage section to show.
func TestReportWithoutRequirementsLeavesCoverageOut(t *testing.T) {
	exe := cliSelfExe(t)
	dir := reqTestProject(t)
	mustRun(t, exe, dir, "requirements", "add", "Only a draft", "--status", "draft")
	if rep := mustRun(t, exe, dir, "report", "--format", "md"); strings.Contains(rep, "Spec Coverage") {
		t.Errorf("a report with no approved requirement shows a coverage:\n%s", rep)
	}
}
