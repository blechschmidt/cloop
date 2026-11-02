package main

// The recordings testdata/recorded/requirements*.txt are what `cloop
// requirements check --json` printed, stdout and stderr together, for the
// spec testdata/requirements/spec.yaml (one requirement passing, one failing,
// one whose test timed out, one untested, one draft) and for a spec file that
// does not validate, laid out as .cloop/requirements.yaml:
//
//	cloop requirements check --file spec.yaml --json                 > requirements.txt
//	cloop requirements check --file .cloop/requirements.yaml --json  > requirements-invalid.txt
//
// (both 2>&1, in a scratch directory with no git checkout).

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/clijson"
	"github.com/blechschmidt/cloop/pkg/requirements"
)

const fixtureSpec = "scripts/ci-annotate/testdata/requirements/spec.yaml"

func specModule(t *testing.T, spec string) module {
	t.Helper()
	m := testModule(t)
	m.spec = spec
	return m
}

// TestFailingRequirementsAreAnnotatedByKey: each requirement the check found
// unfulfilled, or could not check, is one finding named by its R-<n> and its
// title, pointing at its id's line in the spec file and quoting the end of
// what its failing test printed; a requirement that held, one that was
// skipped and a draft say nothing, and neither do the lines the check prints
// on stderr as it goes.
func TestFailingRequirementsAreAnnotatedByKey(t *testing.T) {
	mod := specModule(t, fixtureSpec)
	fs := rank(analyze(mod, "make requirements-check", 3, recorded(t, "requirements.txt")))
	if len(fs) != 2 {
		t.Fatalf("%d findings, want 2: %+v", len(fs), fs)
	}
	type wantReq struct {
		what   string
		line   int
		saying []string
	}
	wants := []wantReq{
		{"R-2 is unfulfilled: A failing requirement, named: with a colon", 10, []string{
			`1 of 2 tests failed: "the failing one"`,
			`$ for i in $(seq 1 60); do echo "line $i of the failing test"; done; echo "the failure after sixty lines" >&2; exit 3`,
			"failed with exit status 3", "… 41 earlier lines …", "line 42 of the failing test", "the failure after sixty lines"}},
		{"R-3 could not be checked: A requirement whose check cannot finish", 21, []string{
			`test "sleep 5" timed out after 1s`, "$ sleep 5", "timed out after 1s"}},
	}
	for i, w := range wants {
		f := fs[i]
		if f.kind != kindRequirement || f.what != w.what || f.step != 3 {
			t.Errorf("finding %d is %d %q (step %d), want %q", i, f.kind, f.what, f.step, w.what)
		}
		if f.file != fixtureSpec || f.line != w.line {
			t.Errorf("%s points at %s:%d, want %s:%d", w.what, f.file, f.line, fixtureSpec, w.line)
		}
		for _, s := range w.saying {
			if !slices.Contains(f.body, s) {
				t.Errorf("%s: no line of its body is %q:\n%q", w.what, s, f.body)
			}
		}
		if slices.Contains(f.body, "line 41 of the failing test") {
			t.Errorf("%s quotes more than the last %d lines of the output", w.what, outputTail)
		}
	}

	// As the job's last step reads it: one annotation each, titled and
	// anchored, the title's ':' and ',' escaped as a property's must be.
	dir := t.TempDir()
	writeStep(t, dir, 1, "make requirements-check\n", string(recorded(t, "requirements.txt")), "1")
	ps := annotations(t, nil, "-summary", "", "-spec", fixtureSpec, "-steps", dir)
	if len(ps) != 2 {
		t.Fatalf("%d annotations, want 2", len(ps))
	}
	if p := ps[0]; p.props["title"] != wants[0].what || p.props["file"] != fixtureSpec || p.props["line"] != "10" ||
		!strings.HasSuffix(p.data, "the failure after sixty lines") {
		t.Errorf("the first annotation is %+v", p)
	}
}

// TestARequirementTheSpecDoesNotName: with no spec file, or none naming the
// requirement, its finding is still named by its key — and points nowhere.
func TestARequirementTheSpecDoesNotName(t *testing.T) {
	for _, spec := range []string{"", "testdata/requirements/no-such-file.yaml", "go.mod"} {
		fs := rank(analyze(specModule(t, spec), "x", 0, recorded(t, "requirements.txt")))
		if len(fs) != 2 || fs[0].what != "R-2 is unfulfilled" || fs[1].what != "R-3 could not be checked" ||
			fs[0].file != "" || fs[0].line != 0 {
			t.Errorf("spec %q: %+v", spec, fs)
		}
	}
}

// TestAnInvalidSpecIsAnnotatedProblemByProblem: a check that could not read
// its spec file prints why, framed, each problem with its line; each is an
// annotation on that line.
func TestAnInvalidSpecIsAnnotatedProblemByProblem(t *testing.T) {
	fs := rank(analyze(specModule(t, DefaultSpec), "make requirements-check", 0, recorded(t, "requirements-invalid.txt")))
	want := []struct {
		line int
		what string
	}{
		{3, "R-1 has no title"},
		{4, `R-1 has an unknown key "titel" (did you mean "title"?): the keys are id, title, status, priority, tags, details, tests`},
		{6, "R-1 is already the id of the requirement on line 3: an id names one requirement"},
	}
	if len(fs) != len(want) {
		t.Fatalf("%d findings, want %d: %+v", len(fs), len(want), fs)
	}
	for i, w := range want {
		if f := fs[i]; f.kind != kindRequirement || f.file != DefaultSpec || f.line != w.line || f.col != 5 || f.what != w.what {
			t.Errorf("finding %d is %s:%d:%d %q, want line %d %q", i, f.file, f.line, f.col, f.what, w.line, w.what)
		}
	}
	// A failure that names no line is one finding, its first line the title.
	frame := framed(t, map[string]string{"error": "open the project: permission denied\nsecond line"})
	fs = analyze(specModule(t, DefaultSpec), "x", 0, frame)
	if len(fs) != 1 || fs[0].what != "cloop failed: open the project: permission denied" || fs[0].file != "" ||
		!slices.Equal(fs[0].body, []string{"open the project: permission denied", "second line"}) {
		t.Errorf("an unanchored failure: %+v", fs)
	}
}

// TestTheReportIsReadAsPkgRequirementsWritesIt holds this tool's copy of the
// report's shape to the one cloop writes, which it cannot import: a report
// built from pkg/requirements' types, framed by pkg/clijson, is read back
// with every field a finding states.
func TestTheReportIsReadAsPkgRequirementsWritesIt(t *testing.T) {
	if frameBegin != clijson.BeginMarker || frameEnd != clijson.EndMarker {
		t.Fatalf("the frame is %q…%q, pkg/clijson's %q…%q", frameBegin, frameEnd, clijson.BeginMarker, clijson.EndMarker)
	}
	if DefaultSpec != requirements.SpecFileName {
		t.Errorf("the default spec is %q, pkg/requirements' %q", DefaultSpec, requirements.SpecFileName)
	}
	rep := requirements.Report{Commit: "0123abcd", Results: []requirements.Result{
		{RequirementID: 1, Verdict: requirements.VerdictFulfilled, Summary: "1 test passed",
			Tests: []requirements.TestResult{{Command: "true", Outcome: requirements.OutcomePass}}},
		{RequirementID: 7, Verdict: requirements.VerdictUnfulfilled, Summary: `test "t" failed (exit 2)`, StartedAt: time.Now(),
			Tests: []requirements.TestResult{{Name: "t", Command: "go test ./x", Outcome: requirements.OutcomeFail,
				ExitCode: 2, Output: "--- FAIL: TestX (0.00s)\n    x_test.go:9: boom\nFAIL\n"}}},
		{RequirementID: 8, Verdict: requirements.VerdictError, Summary: "could not run",
			Tests: []requirements.TestResult{{Command: "nope", Outcome: requirements.OutcomeError, ExitCode: -1,
				Error: "exec: no such file"}}},
		{RequirementID: 9, Verdict: requirements.VerdictUnverified, Summary: "no tests"},
	}}
	var buf bytes.Buffer
	if err := clijson.Emit(&buf, rep); err != nil {
		t.Fatal(err)
	}
	fs := rank(analyze(specModule(t, ""), "x", 0, buf.Bytes()))
	if len(fs) != 2 || fs[0].what != "R-7 is unfulfilled" || fs[1].what != "R-8 could not be checked" {
		t.Fatalf("findings %+v", fs)
	}
	for _, s := range []string{`test "t" failed (exit 2)`, "$ go test ./x", "failed with exit status 2", "    x_test.go:9: boom"} {
		if !slices.Contains(fs[0].body, s) {
			t.Errorf("R-7's body has no line %q: %q", s, fs[0].body)
		}
	}
	if !slices.Contains(fs[1].body, "could not run: exec: no such file") {
		t.Errorf("R-8's body: %q", fs[1].body)
	}
}

// TestFramesAreFoundWhateverSurroundsThem: a log holds the frame among other
// lines, perhaps more than one, perhaps one cut short by a killed command, or
// a frame that is not a report at all.
func TestFramesAreFoundWhateverSurroundsThem(t *testing.T) {
	one := framed(t, map[string]any{"results": []map[string]any{{"requirement_id": 4, "verdict": "unfulfilled"}}})
	two := framed(t, map[string]any{"results": []map[string]any{{"requirement_id": 5, "verdict": "error"}}})
	cases := []struct {
		name string
		log  string
		want []string
	}{
		{"no frame", "R-4    unfulfilled not framed\n", nil},
		{"amid other output", "go: downloading x\n" + string(one) + "Error: not every requirement is fulfilled\n",
			[]string{"R-4 is unfulfilled"}},
		{"two reports", string(one) + "and more\n" + string(two), []string{"R-4 is unfulfilled", "R-5 could not be checked"}},
		{"cut short", string(one) + "\n" + frameBegin + "\n{\"results\": [{\"requirement_id\": 5, ", []string{"R-4 is unfulfilled"}},
		{"not a report", string(framed(t, map[string]any{"summary": "ideas", "suggestions": []string{"a"}})), nil},
		{"not JSON", frameBegin + "\nnot json\n" + frameEnd + "\n", nil},
		{"no id", string(framed(t, map[string]any{"results": []map[string]any{{"verdict": "unfulfilled"}}})), nil},
		{"passing", string(framed(t, map[string]any{"results": []map[string]any{{"requirement_id": 1, "verdict": "fulfilled"},
			{"requirement_id": 2, "verdict": "unverified"}}})), nil},
	}
	for _, c := range cases {
		var got []string
		for _, f := range rank(analyze(specModule(t, ""), "x", 0, []byte(c.log))) {
			got = append(got, f.what)
		}
		if !slices.Equal(got, c.want) {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
}

// TestSpecEntryReadsTheItemTheKeyIsIn: a title is taken from the item the id
// is in, whichever comes first and however it is quoted, and never from the
// next item.
func TestSpecEntryReadsTheItemTheKeyIsIn(t *testing.T) {
	dir := t.TempDir()
	spec := `version: 1
requirements:
  - title: 'Title first, it''s quoted'
    id: R-1
    status: approved
  - id: "R-2"   # quoted id
    status: approved
    title: "An \"escaped\" title"
  - id: R-3
    status: draft
  - id: R-30
    title: Not R-3's
    status: approved
`
	if err := os.WriteFile(filepath.Join(dir, "spec.yaml"), []byte(spec), 0o644); err != nil {
		t.Fatal(err)
	}
	m := module{root: dir, spec: "spec.yaml"}
	for key, want := range map[string]struct {
		title string
		line  int
	}{
		"R-1": {"Title first, it's quoted", 4}, "R-2": {`An "escaped" title`, 6}, "R-3": {"", 9},
		"R-30": {"Not R-3's", 11}, "R-4": {"", 0},
	} {
		if title, line := m.specEntry(key); title != want.title || line != want.line {
			t.Errorf("%s: %q on line %d, want %q on line %d", key, title, line, want.title, want.line)
		}
	}
}

// framed is v as cloop prints it for a tool.
func framed(t *testing.T, v any) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := clijson.Emit(&buf, v); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}
