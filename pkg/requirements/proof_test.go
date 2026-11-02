package requirements

import (
	"strings"
	"testing"
	"time"
)

func side(outcomes ...string) ProofSide {
	s := ProofSide{Commit: "abcdef0123456789"}
	for _, o := range outcomes {
		t := TestResult{Command: "t", Outcome: o}
		if o == OutcomeFail {
			t.ExitCode = 1
		}
		s.Tests = append(s.Tests, t)
	}
	s.Verdict, s.Summary = TestsVerdict(s.Tests)
	return s
}

func TestDecideProof(t *testing.T) {
	withOutput := func(s ProofSide, out string, code int) ProofSide {
		s.Tests[0].Output, s.Tests[0].ExitCode = out, code
		return s
	}
	cases := []struct {
		name string
		p    Proof
		want string
		says string
	}{
		{"red before, green after", Proof{Before: side(OutcomeFail), After: side(OutcomePass), CodeChanged: true}, ProofProven, "fail at the base"},
		{"a hang at the base is red", Proof{Before: side(OutcomeTimeout), After: side(OutcomePass), CodeChanged: true}, ProofProven, ""},
		{"green before", Proof{Before: side(OutcomePass), After: side(OutcomePass), CodeChanged: true}, ProofVacuous, "pass at the base"},
		{"one of two red before", Proof{Before: side(OutcomePass, OutcomeFail), After: side(OutcomePass, OutcomePass), CodeChanged: true}, ProofProven, ""},
		{"red after", Proof{Before: side(OutcomeFail), After: side(OutcomeFail), CodeChanged: true}, ProofBroken, "fail on the change"},
		{"timed out after", Proof{After: side(OutcomeTimeout), CodeChanged: true}, ProofBroken, ""},
		{"could not run after", Proof{After: side(OutcomeError), CodeChanged: true}, ProofError, "could not run on the change"},
		{"not run after", Proof{After: ProofSide{Skipped: "it has no tests"}}, ProofError, "it has no tests"},
		{"tests only", Proof{After: side(OutcomePass), CodeChanged: false}, ProofInconclusive, "nothing but"},
		{"base missing", Proof{After: side(OutcomePass), Before: ProofSide{Skipped: "not in this checkout"}}, ProofError, "not in this checkout"},
		{"could not run before", Proof{Before: side(OutcomeError), After: side(OutcomePass), CodeChanged: true}, ProofError, "could not run at the base"},
		{"command missing before", Proof{Before: withOutput(side(OutcomeFail), "sh: tools/x: not found", 127), After: side(OutcomePass),
			CodeChanged: true, Fallback: true}, ProofInconclusive, "even with the change's test files"},
		{"no tests ran before", Proof{Before: withOutput(side(OutcomePass), "ok  \tpkg/x\t0.01s [no tests to run]", 0),
			After: withOutput(side(OutcomePass), "ok  \tpkg/x\t0.02s", 0), CodeChanged: true}, ProofInconclusive, "no test to run"},
		{"pytest collected nothing before", Proof{Before: withOutput(side(OutcomeFail), "collected 0 items\n\nno tests ran in 0.01s", 5),
			After: side(OutcomePass), CodeChanged: true}, ProofInconclusive, ""},
		{"no tests ran on either side", Proof{Before: withOutput(side(OutcomePass), "[no test files]", 0),
			After: withOutput(side(OutcomePass), "[no test files]", 0), CodeChanged: true}, ProofVacuous, ""},
		{"10 passing is not 0 passing", Proof{Before: withOutput(side(OutcomePass), "  10 passing (4ms)", 0),
			After: side(OutcomePass), CodeChanged: true}, ProofVacuous, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, says := DecideProof(c.p)
			if got != c.want || !strings.Contains(says, c.says) {
				t.Fatalf("DecideProof = %s, %q; want %s saying %q", got, says, c.want, c.says)
			}
		})
	}
}

func TestIsTestFile(t *testing.T) {
	for p, want := range map[string]bool{
		"pkg/x/foo_test.go": true, "tests/e2e/harness.go": true, "pkg/ui/testdata/x.js": true, "test_api.py": true,
		"app/foo_test.py": true, "conftest.py": true, "src/a.test.ts": true, "web/b.spec.jsx": true,
		"src/test/java/FooTest.java": true, "spec/models/user_spec.rb": true, "check.bats": true,
		"__tests__/x.js": true, "Foo.Tests.cs": true, "FooTests.cs": true,
		"pkg/x/foo.go": false, "main.py": false, "src/latest.js": false, "testing.go": false, "contest.py": false,
		"pkg/requirements/specfile.go": false, "attestation/x.go": false, "docs/testing.md": false,
	} {
		if got := IsTestFile(p); got != want {
			t.Errorf("IsTestFile(%q) = %v, want %v", p, got, want)
		}
	}
}

func TestTestFilesFor(t *testing.T) {
	changes := []ProofFile{
		{Path: "pkg/x/foo.go", Status: FileModified},
		{Path: "pkg/x/foo_test.go", Status: FileModified},
		{Path: "pkg/x/testdata/in.json", Status: FileAdded},
		{Path: "pkg/y/bar_test.go", Status: FileAdded},
		{Path: "scripts/check.sh", Status: FileAdded},
		{Path: "tests/test_api.py", Status: FileAdded},
	}
	dirs := map[string]bool{"pkg/x": true, "pkg/y": true, "pkg": true, "tests": true, "scripts": true}
	exists := func(p string) bool { return dirs[p] }
	paths := func(fs []ProofFile) string {
		var out []string
		for _, f := range fs {
			out = append(out, f.Path)
		}
		return strings.Join(out, ",")
	}
	for _, c := range []struct {
		command, want string
	}{
		{"go test ./pkg/x -run '^TestFoo$'", "pkg/x/foo_test.go,pkg/x/testdata/in.json"},
		{"go test ./pkg/...", "pkg/x/foo_test.go,pkg/x/testdata/in.json,pkg/y/bar_test.go"},
		{"go test ./...", "pkg/x/foo_test.go,pkg/x/testdata/in.json,pkg/y/bar_test.go,tests/test_api.py"},
		{"bash scripts/check.sh", "scripts/check.sh"},
		{"pytest -q tests/test_api.py::test_create", "tests/test_api.py"},
		{"npm test", "pkg/x/foo_test.go,pkg/x/testdata/in.json,pkg/y/bar_test.go,tests/test_api.py"},
		{"cd ../elsewhere && make check", "pkg/x/foo_test.go,pkg/x/testdata/in.json,pkg/y/bar_test.go,tests/test_api.py"},
		{"go test -coverprofile=/tmp/c.out ./pkg/y", "pkg/y/bar_test.go"},
		// A file a command reads is what the test looks at, not the test.
		{"grep -qx done pkg/x/foo.go", ""},
		{"test -f pkg/x/foo.go && grep -q Foo pkg/x/foo_test.go", "pkg/x/foo_test.go"},
		{"timeout 60 ./scripts/check.sh", "scripts/check.sh"},
		{"CI=1 sh -c 'cd pkg/y && go test .'", "pkg/y/bar_test.go"},
		{"cd pkg && go test ./x/...", "pkg/x/foo_test.go,pkg/x/testdata/in.json,pkg/y/bar_test.go"},
		{"python3 -m pytest tests", "tests/test_api.py"},
	} {
		got := paths(TestFilesFor([]Test{{Command: c.command}}, changes, exists))
		if got != c.want {
			t.Errorf("TestFilesFor(%q) = %s, want %s", c.command, got, c.want)
		}
	}
}

func TestAddsTestDeclaration(t *testing.T) {
	for diff, want := range map[string]bool{
		"+func TestNew(t *testing.T) {":       true,
		"+	def test_create(client):":          true,
		"+  it('greets', () => {":             true,
		"+    @Test":                          true,
		"+#[test]":                            true,
		"+func helper(t *testing.T) {":        false,
		"-func TestOld(t *testing.T) {":       false,
		" func TestUnchanged(t *testing.T) {": false,
	} {
		if got := AddsTestDeclaration(diff); got != want {
			t.Errorf("AddsTestDeclaration(%q) = %v, want %v", diff, got, want)
		}
	}
}

// TestSanitizeProofsReadsTheReportInTheHubsTerms: the hub's copy of the
// rules — the definition it sent, the outcome recomputed from the evidence.
func TestSanitizeProofsReadsTheReportInTheHubsTerms(t *testing.T) {
	asked := []Requirement{
		{ID: 1, Title: "a", Tests: []Test{{Command: "sh t1.sh"}}},
		{ID: 2, Title: "b", Tests: []Test{{Command: "sh t2.sh"}}},
		{ID: 3, Title: "c", Tests: []Test{{Command: "sh t3.sh"}, {Command: "sh t4.sh"}}},
		{ID: 4, Title: "d", Tests: []Test{{Command: "sh t5.sh"}}},
	}
	now := time.Now().UTC()
	forged := side(OutcomePass)
	forged.Tests[0].Command = "rm -rf /"
	rep := ProofReport{
		Results: []Proof{
			// Claims proven; its evidence says vacuous.
			{RequirementID: 1, Outcome: ProofProven, Before: forged, After: side(OutcomePass), CodeChanged: true,
				TestFiles: []ProofFile{{Path: "../escape", Status: "A"}, {Path: "t1.sh", Status: "A"}, {Path: "x", Status: "Q"}}},
			// One test result for two tests.
			{RequirementID: 3, Outcome: ProofProven, Before: side(OutcomeFail), After: side(OutcomePass), CodeChanged: true},
			{RequirementID: 99, Outcome: ProofProven},
		},
		Untouched: []int{4},
	}
	clean := SanitizeProofs(rep, asked, func(s string) string { return strings.ReplaceAll(s, "secret", "[x]") }, now)
	if len(clean.Results) != 3 || len(clean.Untouched) != 1 || clean.Untouched[0] != 4 {
		t.Fatalf("results %+v untouched %v", clean.Results, clean.Untouched)
	}
	p1 := clean.Results[0]
	if p1.Outcome != ProofVacuous || p1.Before.Tests[0].Command != "sh t1.sh" || p1.Fingerprint != asked[0].Fingerprint() {
		t.Fatalf("R-1 read as %+v", p1)
	}
	if len(p1.TestFiles) != 1 || p1.TestFiles[0].Path != "t1.sh" {
		t.Fatalf("R-1's files: %+v", p1.TestFiles)
	}
	if p2 := clean.Results[1]; p2.RequirementID != 2 || p2.Outcome != ProofError || !strings.Contains(p2.Summary, "no proof") {
		t.Fatalf("the requirement the report left out: %+v", p2)
	}
	if p3 := clean.Results[2]; p3.Outcome != ProofError || !strings.Contains(p3.Summary, "1 test results for 2 tests") {
		t.Fatalf("a report that does not fit the tests: %+v", p3)
	}
}

func TestBoundProofKeepsWhatDecidesIt(t *testing.T) {
	p := Proof{
		Before: side(OutcomePass),
		After:  side(OutcomePass, OutcomeFail),
	}
	p.Before.Tests[0].Output = strings.Repeat("noise\n", 1000) + "ok  \tpkg/x\t0.01s [no tests to run]\n" + strings.Repeat("tail\n", 10)
	p.After.Tests[0].Output = "passed output"
	p.After.Tests[1].Output = strings.Repeat("x", 10000)
	BoundProof(&p, 100)
	if p.Before.Tests[0].Output != "ok  \tpkg/x\t0.01s [no tests to run]" {
		t.Fatalf("the no-tests line was not kept: %q", p.Before.Tests[0].Output)
	}
	if p.After.Tests[0].Output != "" || len(p.After.Tests[1].Output) != 100 || !p.After.Tests[1].Truncated {
		t.Fatalf("outputs after bounding: %q / %d", p.After.Tests[0].Output, len(p.After.Tests[1].Output))
	}
	if got, _ := DecideProof(Proof{Before: p.Before, After: side(OutcomePass), CodeChanged: true}); got != ProofInconclusive {
		t.Fatalf("a bounded proof decides %s, want inconclusive", got)
	}
}

func TestProofBudget(t *testing.T) {
	reqs := []Requirement{{ID: 1, Tests: []Test{{Command: "a", TimeoutSeconds: 60}, {Command: "b"}}}}
	if got, want := ProofBudget(reqs, false), DispatchSlack+2*(time.Minute+DefaultTestTimeout); got != want {
		t.Fatalf("ProofBudget = %s, want %s", got, want)
	}
	if got, want := ProofBudget(reqs, true), DispatchSlack+time.Minute+DefaultTestTimeout; got != want {
		t.Fatalf("ProofBudget(before only) = %s, want %s", got, want)
	}
}

func TestProofCloneSharesNothing(t *testing.T) {
	p := Proof{TestFiles: []ProofFile{{Path: "a_test.go", Status: FileAdded}},
		Before: side(OutcomeFail), After: side(OutcomePass)}
	p.Before.Tests[0].Output = strings.Repeat("x", 100)
	c := p.Clone()
	BoundProof(&c, 10)
	c.TestFiles[0].Path = "changed"
	if len(p.Before.Tests[0].Output) != 100 || p.TestFiles[0].Path != "a_test.go" {
		t.Fatalf("bounding a clone changed the original: %+v", p)
	}
}
