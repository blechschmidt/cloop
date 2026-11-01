package requirements

import (
	"strings"
	"testing"
)

// findingsOf are fs's findings of kind about id.
func findingsOf(fs []Finding, kind string, id int) []Finding {
	var out []Finding
	for _, f := range fs {
		if f.Kind == kind && f.ID == id {
			out = append(out, f)
		}
	}
	return out
}

func TestLintFindsAmbiguousWording(t *testing.T) {
	reqs := []Requirement{
		{ID: 1, Title: "The dashboard shall load fast and be user-friendly.", Description: "It should handle errors, etc."},
		{ID: 2, Title: "When a config is malformed, the CLI shall exit with status 2 within 100 ms."},
		{ID: 3, Title: "The API should answer health probes."},
		{ID: 4, Title: "The importer should handle huge files gracefully."},
		// Words that only contain a vague one are not it.
		{ID: 5, Title: "When fasting mode is on, the scheduler shall skip breakfast tasks."},
	}
	fs := Lint(reqs, nil)
	a := findingsOf(fs, LintAmbiguous, 1)
	if len(a) != 1 || strings.Join(a[0].Words, ",") != "etc,fast,should handle,user-friendly" || a[0].Severity != SeverityWarning ||
		a[0].By != LintByRules || !strings.Contains(a[0].Hint, "“fast”: say how fast") {
		t.Fatalf("R-1: %+v", a)
	}
	if got := findingsOf(fs, LintAmbiguous, 2); len(got) != 0 {
		t.Errorf("R-2 is measurable, and lint says %+v", got)
	}
	if got := findingsOf(fs, LintAmbiguous, 3); len(got) != 1 || strings.Join(got[0].Words, ",") != "should" {
		t.Errorf("R-3: %+v", got)
	}
	// "should handle" is one finding, not "should" again beside it.
	if got := findingsOf(fs, LintAmbiguous, 4); len(got) != 1 || strings.Join(got[0].Words, ",") != "gracefully,should handle" {
		t.Errorf("R-4: %+v", got)
	}
	if got := findingsOf(fs, LintAmbiguous, 5); len(got) != 0 {
		t.Errorf("R-5: %+v", got)
	}
}

func TestLintFindsCompoundRequirements(t *testing.T) {
	reqs := []Requirement{
		{ID: 1, Title: "The CLI shall exit 2 and shall print the line."},
		{ID: 2, Title: "The CLI shall exit 2; the hub logs it."},
		{ID: 3, Title: "The CLI shall exit 2. It prints the line."},
		{ID: 4, Title: "When a config is malformed, the CLI shall exit 2 and name the line."},
		{ID: 5, Title: "The hub shall store the run and then notify its starter."},
		{ID: 6, Title: "The CLI shall accept JSON and YAML configs."},
		{ID: 7, Title: "The CLI shall exit 2, e.g. When a config is malformed."},
		{ID: 8, Title: "If the read and write fail, then the CLI shall exit 2."},
	}
	fs := Lint(reqs, nil)
	for id, want := range map[int]string{
		1: "it says shall (or must) more than once",
		2: "a semicolon joins two statements",
		3: "it is more than one sentence",
		4: "“and name” starts a second behaviour",
		5: "“and then” starts a second behaviour",
	} {
		got := findingsOf(fs, LintCompound, id)
		if len(got) != 1 || !strings.Contains(got[0].Message, want) {
			t.Errorf("R-%d: %+v, want %q", id, got, want)
		}
	}
	// A list of objects, an abbreviation, and an "and" in the condition
	// before the shall are one behaviour each.
	for _, id := range []int{6, 7, 8} {
		if got := findingsOf(fs, LintCompound, id); len(got) != 0 {
			t.Errorf("R-%d is one requirement, and lint says %+v", id, got)
		}
	}
}

func TestLintFindsRepeatsAndContradictions(t *testing.T) {
	reqs := []Requirement{
		{ID: 1, Title: "When a config is malformed, the CLI shall exit with status 2."},
		{ID: 2, Title: "When the config is malformed, the CLI shall exit with status 2"},
		{ID: 3, Title: "When a config is malformed, the CLI shall not exit with status 2."},
		{ID: 4, Title: "Logs are kept for thirty days."},
		{ID: 5, Title: "Logs are kept for thirty days!", Status: StatusDeprecated},
		{ID: 6, Title: "When a config is malformed, the CLI shall exit with status 2.", Status: StatusDraft},
	}
	fs := Lint(reqs, nil)
	if got := findingsOf(fs, LintDuplicate, 2); len(got) != 1 || got[0].Others[0] != 1 || got[0].Severity != SeverityError {
		t.Errorf("R-2 repeats R-1: %+v", got)
	}
	if got := findingsOf(fs, LintContradiction, 3); len(got) != 2 {
		t.Errorf("R-3 contradicts R-1 and R-2: %+v", got)
	}
	// A draft that repeats is the one reported, whatever its id.
	if got := findingsOf(fs, LintDuplicate, 6); len(got) != 2 {
		t.Errorf("the draft R-6 repeats R-1 and R-2: %+v", got)
	}
	// The deprecated one is history: neither linted nor compared.
	for _, f := range fs {
		if f.ID == 5 || (len(f.Others) > 0 && f.Others[0] == 5) {
			t.Errorf("a finding about the deprecated R-5: %+v", f)
		}
	}
	// Subjects: only R-4 is linted, and it repeats nothing that is not deprecated.
	if got := Lint(reqs, []int{4}); len(got) != 0 {
		t.Errorf("lint of R-4 alone: %+v", got)
	}
	// Named, a deprecated requirement is linted.
	if got := Lint(reqs, []int{5}); len(got) != 0 {
		t.Errorf("lint of R-5, which is compared with nothing: %+v", got)
	}
}

func TestLintFindsApprovedMustsWithoutTests(t *testing.T) {
	reqs := []Requirement{
		{ID: 1, Title: "The CLI shall exit 2.", Priority: PriorityMust},
		{ID: 2, Title: "The CLI shall exit 3.", Priority: PriorityMust, Tests: []Test{{Command: "make t"}}},
		{ID: 3, Title: "The CLI shall exit 4.", Priority: PriorityMust, Status: StatusDraft},
		{ID: 4, Title: "The CLI shall exit 5.", Priority: PriorityShould},
	}
	fs := Lint(reqs, nil)
	if got := findingsOf(fs, LintUntestedMust, 1); len(got) != 1 || got[0].Severity != SeverityError {
		t.Errorf("R-1: %+v", got)
	}
	for _, id := range []int{2, 3, 4} {
		if got := findingsOf(fs, LintUntestedMust, id); len(got) != 0 {
			t.Errorf("R-%d: %+v", id, got)
		}
	}
	rep := LintReport{Findings: fs}
	if e, w := rep.Counts(); e != 1 || w != 0 {
		t.Errorf("counts = %d errors, %d warnings", e, w)
	}
}

// The model's contradictions are read strictly, and only about requirements
// it was shown.
func TestParseContradictions(t *testing.T) {
	known := []Requirement{{ID: 1, Title: "a"}, {ID: 2, Title: "b"}, {ID: 3, Title: "c", Status: StatusDraft}}
	fs, err := ParseContradictions(`{"contradictions": [
		{"a": "R-1", "b": 3, "why": "one\nsays never"},
		{"a": "R-3", "b": "R-1", "why": "the same pair, the other way round"},
		{"a": "R-1", "b": "R-9", "why": "R-9 is not one of them"},
		{"a": 2, "b": 2, "why": "itself"}]}`, known)
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 1 || fs[0].ID != 3 || fs[0].Others[0] != 1 || fs[0].By != LintByModel || fs[0].Hint != "one says never" ||
		fs[0].Message != "R-3 contradicts R-1, the model says" {
		t.Fatalf("findings = %+v", fs)
	}
	for _, bad := range []string{
		"No contradictions.",
		`{"contradictions": [], "approved": true}`,
		`{"contradictions": [{"a": "R-1", "b": "R-2", "why": "x", "fix": "delete R-2"}]}`,
		`{"contradictions": [{"a": "seven", "b": "R-2"}]}`,
		"```json\n{\"contradictions\": []}\n```\nThat is all.",
	} {
		if fs, err := ParseContradictions(bad, known); err == nil {
			t.Errorf("%q read as %+v", bad, fs)
		}
	}
	if fs, err := ParseContradictions("```json\n{\"contradictions\": []}\n```", known); err != nil || len(fs) != 0 {
		t.Errorf("none: %+v, %v", fs, err)
	}
}

// The hub keeps of a model finding only which requirements it names and its
// reason: kind, message and severity are lint's.
func TestCheckModelFindingsTrustsOnlyTheIDs(t *testing.T) {
	known := []Requirement{{ID: 1, Title: "a"}, {ID: 2, Title: "b"}}
	got := CheckModelFindings([]Finding{
		{Kind: LintDuplicate, ID: 2, Others: []int{1, 1, 2, 9}, By: LintByModel, Message: "<img src=x>", Severity: "info",
			Hint: strings.Repeat("h", MaxHintRunes+10)},
		{Kind: LintAmbiguous, ID: 1, By: LintByModel},
		{Kind: LintDuplicate, ID: 9, By: LintByModel},
		{Kind: LintContradiction, ID: 1, By: LintByModel},
		{Kind: LintDuplicate, ID: 1, Others: []int{2}, By: LintByRules},
		{Kind: LintDuplicate, ID: 1, Others: []int{2}, By: LintByModel, Hint: "a repeat of the first, the other way round"},
	}, known)
	if len(got) != 1 {
		t.Fatalf("kept %+v", got)
	}
	f := got[0]
	if f.Message != "R-2 repeats R-1 in other words, the model says" || f.Severity != SeverityError || len(f.Others) != 1 ||
		len([]rune(f.Hint)) != MaxHintRunes {
		t.Errorf("kept %+v", f)
	}
	merged := MergeFindings([]Finding{{Kind: LintDuplicate, ID: 2, Others: []int{1}, By: LintByRules}}, got)
	if len(merged) != 1 || merged[0].By != LintByRules {
		t.Errorf("merged = %+v", merged)
	}
}

// LintSpec carries the subjects first and as much of the rest as fits, never
// a deprecated requirement, and never a test.
func TestLintSpecIsBounded(t *testing.T) {
	var all []Requirement
	for i := 1; i <= 400; i++ {
		st := StatusApproved
		if i%4 == 0 {
			st = StatusDeprecated
		}
		all = append(all, Requirement{ID: i, Title: strings.Repeat("t", 200), Description: strings.Repeat("d", 3000),
			Status: st, Tests: []Test{{Command: "make t"}}})
	}
	raw, n, err := LintSpec("goal", all, []int{400, 3})
	if err != nil {
		t.Fatal(err)
	}
	sp, err := ParseSpec(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) > lintSpecBytes+2100 || n != len(sp.Requirements) || n < 10 || n >= 300 {
		t.Fatalf("%d bytes, %d requirements", len(raw), n)
	}
	// The subjects, in the project's order — a deprecated one named too.
	if sp.Requirements[0].ID != 3 || sp.Requirements[1].ID != 400 || sp.Goal != "goal" {
		t.Fatalf("the subjects are not first: %d, %d", sp.Requirements[0].ID, sp.Requirements[1].ID)
	}
	for _, r := range sp.Requirements[2:] {
		if r.CurrentStatus() == StatusDeprecated || r.Tests != nil || len([]rune(r.Description)) > maxLintDescriptionRunes {
			t.Fatalf("sent %+v", r)
		}
	}
}

func TestWords(t *testing.T) {
	got := strings.Join(words("The user-friendly CLI—and/or the API's “fast” path, e.g. v1.2; can’t."), "|")
	if got != "the|user-friendly|cli|and/or|the|api's|fast|path|e|g|v1|2|can't" {
		t.Errorf("words = %s", got)
	}
}
