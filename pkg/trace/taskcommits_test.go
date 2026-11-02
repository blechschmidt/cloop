package trace

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/requirements"
)

// TestSubjectTasks reads the conventions a commit names its task by (Task
// 20465), and nothing that merely looks like a number.
func TestSubjectTasks(t *testing.T) {
	for subject, want := range map[string][]int{
		"feat(ui): a matrix (Task 20465)":                         {20465},
		"fix(x): two at once (Tasks 10, 11)":                      {10, 11},
		"docs: a list (Tasks 10,\t12 and 14)":                     {10, 12, 14},
		"cloop(task-7): Add the thing":                            {7},
		"cloop(task-7): Add the thing (Task 8) (Task 7)":          {7, 8},
		"fix: (Task #12)":                                         {12},
		"chore: bump to v20465":                                   nil,
		"test: Task 12 without parentheses":                       nil,
		"refactor: (Tasks)":                                       nil,
		"feat: (Task 0)":                                          nil,
		"feat: (Task 99999999999)":                                nil,
		"merge: cloop(task-3) without a colon":                    nil,
		"feat(ci): see https://example.com/(Task 5) in the notes": {5},
	} {
		if got := SubjectTasks(subject); fmt.Sprint(got) != fmt.Sprint(want) {
			t.Errorf("SubjectTasks(%q) = %v, want %v", subject, got, want)
		}
	}
}

// TestRun_LinksSubjectsWithoutAModel: a commit naming its task is linked to it
// at high confidence, every task it names, and with no provider the rest stay
// unmatched — no model is asked. The tasks come from the caller, as state.Load
// reads them from a project with no state.json.
func TestRun_LinksSubjectsWithoutAModel(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	dir := t.TempDir()
	git := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-c", "user.name=t", "-c", "user.email=t@example.com",
			"-c", "commit.gpgsign=false"}, args...)...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
		}
	}
	git("init", "-q")
	for _, subject := range []string{"feat: first (Task 1)", "chore: unrelated", "fix: both (Tasks 1, 2)", "cloop(task-3): third"} {
		git("commit", "-q", "--allow-empty", "-m", subject)
	}
	tasks := []*pm.Task{{ID: 1, Title: "First"}, {ID: 2, Title: "Second"}}
	tm, err := Run(context.Background(), nil, "", dir, tasks, 10, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(tm.Entries) != 4 {
		t.Fatalf("entries: %+v", tm.Entries)
	}
	got := map[string]TraceEntry{}
	for _, e := range tm.Entries {
		got[e.Subject] = e
	}
	if e := got["feat: first (Task 1)"]; e.MatchedTaskID != 1 || e.MatchedTaskTitle != "First" || e.Confidence != ConfidenceHigh {
		t.Errorf("the first commit: %+v", e)
	}
	if e := got["fix: both (Tasks 1, 2)"]; e.MatchedTaskID != 1 || fmt.Sprint(e.Tasks) != "[1 2]" {
		t.Errorf("the commit naming two: %+v", e)
	}
	if e := got["cloop(task-3): third"]; e.MatchedTaskID != 3 || e.MatchedTaskTitle != "" || e.Confidence != ConfidenceHigh {
		t.Errorf("a task the plan no longer holds is still the one its commit names: %+v", e)
	}
	if e := got["chore: unrelated"]; e.MatchedTaskID != 0 || e.Confidence != ConfidenceNone {
		t.Errorf("an unrelated commit with no model: %+v", e)
	}

	by := tm.TaskCommits()
	if len(by[1]) != 2 || len(by[2]) != 1 || len(by[3]) != 1 || by[2][0].Source != requirements.CommitFromTrace ||
		by[2][0].Confidence != "high" || by[2][0].Subject != "fix: both (Tasks 1, 2)" {
		t.Errorf("by task: %+v", by)
	}
}

// TestTaskCommits_TrustsNothing: a link at no confidence, or one the trace
// does not name, is no link, and a hash that is not one is dropped.
func TestTaskCommits_TrustsNothing(t *testing.T) {
	tm := &TraceMap{Entries: []TraceEntry{
		{Hash: "abc1234", MatchedTaskID: 1, Confidence: ConfidenceLow},
		{Hash: "abc1235", MatchedTaskID: 1, Confidence: ConfidenceNone},
		{Hash: "abc1236", MatchedTaskID: 1, Confidence: "certain"},
		{Hash: "<script>", MatchedTaskID: 1, Confidence: ConfidenceHigh},
		{Hash: "abc1237", MatchedTaskID: 0, Confidence: ConfidenceHigh},
		{Hash: "abc1238", MatchedTaskID: -4, Confidence: ConfidenceHigh, Tasks: []int{-4, 5}},
	}}
	by := tm.TaskCommits()
	if len(by) != 1 || len(by[1]) != 1 || by[1][0].Hash != "abc1234" {
		t.Errorf("by task: %+v", by)
	}
	if got := (*TraceMap)(nil).TaskCommits(); len(got) != 0 {
		t.Errorf("a nil trace: %+v", got)
	}
}

// TestPeek_ReadsOnlyWhatItShould: Peek reads a trace, and changes nothing: an
// unparsable file stays where it is (LoadTraceJSON would quarantine it), an
// oversized one is no trace, and a symbolic link out of .cloop — to another
// project's trace — is never followed.
func TestPeek_ReadsOnlyWhatItShould(t *testing.T) {
	dir := t.TempDir()
	if tm, err := Peek(dir); tm != nil || err != nil {
		t.Fatalf("no .cloop: %v, %v", tm, err)
	}
	if err := WriteTraceJSON(dir, &TraceMap{Entries: []TraceEntry{{Hash: "abc1234", MatchedTaskID: 2, Confidence: ConfidenceHigh}}}); err != nil {
		t.Fatal(err)
	}
	tm, err := Peek(dir)
	if err != nil || tm == nil || len(tm.Entries) != 1 {
		t.Fatalf("a trace reads %+v, %v", tm, err)
	}

	path := filepath.Join(dir, ".cloop", "trace.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if tm, err := Peek(dir); tm != nil || err != nil {
		t.Errorf("an unparsable trace: %v, %v", tm, err)
	}
	if left, _ := filepath.Glob(path + ".corrupt-*"); len(left) != 0 {
		t.Errorf("Peek quarantined the file: %v", left)
	}
	if b, _ := os.ReadFile(path); string(b) != "{not json" {
		t.Errorf("Peek changed the file: %q", b)
	}

	big := `{"entries":[` + strings.Repeat(`{"hash":"abc1234","matched_task_id":1,"confidence":"high"},`, MaxTraceFileBytes/50) +
		`{"hash":"abc1234"}]}`
	if err := os.WriteFile(path, []byte(big), 0o644); err != nil {
		t.Fatal(err)
	}
	if tm, err := Peek(dir); tm != nil || err != nil {
		t.Errorf("a %d-byte trace: %d entries, %v", len(big), len(tm.Entries), err)
	}

	other := t.TempDir()
	if err := WriteTraceJSON(other, &TraceMap{Entries: []TraceEntry{{Hash: "fedcba9", Subject: "another tenant's secret"}}}); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(other, ".cloop", "trace.json"), path); err != nil {
		t.Fatal(err)
	}
	if tm, err := Peek(dir); tm != nil {
		t.Errorf("Peek followed a link out of .cloop: %+v (%v)", tm, err)
	}
}
