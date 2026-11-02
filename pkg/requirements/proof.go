package requirements

// proof.go: red-green proofs of a requirement's tests (Task 20464).
//
// A check says whether a requirement's tests pass. It cannot say whether they
// test anything: a test that always passes makes a requirement look fulfilled
// whether it is or not. A proof runs the tests twice — once on the code before
// a change, in a throwaway checkout of the base commit, and once on the change
// itself — and records what the two runs add up to:
//
//	proven        red before, green after: the tests fail without the change
//	              and pass with it
//	vacuous       green before: they pass without the change too, so they do
//	              not show it
//	broken        red after: they do not pass on the change itself
//	inconclusive  the test does not exist at the base, so the proof fell back
//	              to the base code plus the new test files only — and that
//	              could not settle it: the command still does not run there,
//	              found no test to run, or the change holds nothing but test
//	              files for them to fail without
//	error         the proof itself did not work — a run could not start, was
//	              stopped, or the base is not in the checkout. Not a statement
//	              about the tests.
//
// # The base, and the fallback
//
// For a task the base is the commit the task's work started from; asked for
// by hand, it is the commit before the test's implementation (pkg/reqproof).
// A test the change added or changed does not exist at the base as it reads
// in the change, so running the base as it is would run the old test, or
// none: `go test -run TestNew` passes with "no tests to run". The proof then
// falls back to the base code with the change's test files laid over it
// (Fallback, TestFiles) — exactly the experiment red-green asks for: the new
// test against the old code.
//
// This file is the model and the rules: what a proof reports, what its two
// runs add up to (DecideProof), which of a change's files are a requirement's
// tests (TestFilesFor), and SanitizeProofs, the hub's copy of the rules for a
// report an executor sent back. The runs themselves happen where the
// project's runs happen, in pkg/reqproof; the hub never runs a test.

import (
	"fmt"
	"path"
	"regexp"
	"strings"
	"time"
)

// Proof outcomes.
const (
	ProofProven       = "proven"
	ProofVacuous      = "vacuous"
	ProofBroken       = "broken"
	ProofInconclusive = "inconclusive"
	ProofError        = "error"
)

// ProofOutcomes lists the outcomes, the four statements about a test first.
var ProofOutcomes = []string{ProofProven, ProofVacuous, ProofBroken, ProofInconclusive, ProofError}

// ValidProofOutcome reports whether o is one of ProofOutcomes.
func ValidProofOutcome(o string) bool {
	for _, q := range ProofOutcomes {
		if o == q {
			return true
		}
	}
	return false
}

// How a proof's base was chosen.
const (
	// BaseFromTask: the commit the task's work started from.
	BaseFromTask = "task"
	// BaseFromTest: the commit before the one that last changed the test's
	// files — the commit before the test's implementation.
	BaseFromTest = "test"
	// BaseFromWorktree: the test's files have uncommitted changes, so the
	// change is the working tree and the base its HEAD.
	BaseFromWorktree = "worktree"
	// BaseFromGiven: a person named it.
	BaseFromGiven = "given"
)

// Bounds on what a proof carries.
const (
	// MaxProofFiles bounds the test files a proof names.
	MaxProofFiles = 64
	// MaxProofPathBytes bounds one of their paths.
	MaxProofPathBytes = 512
)

// Change statuses a proof's files carry: added, modified, deleted.
const (
	FileAdded    = "A"
	FileModified = "M"
	FileDeleted  = "D"
)

// ProofFile is one file a change added, changed or removed.
type ProofFile struct {
	Path   string `json:"path"`
	Status string `json:"status"`
}

// ProofSide is one of a proof's two runs of a requirement's tests.
type ProofSide struct {
	// Commit is HEAD of the tree the run used. Dirty reports that the tree
	// was not that commit alone: the change's uncommitted work, or — for the
	// base under Fallback — the test files laid over it.
	Commit string `json:"commit,omitempty"`
	Dirty  bool   `json:"dirty,omitempty"`
	// Verdict and Summary are what the run's tests add up to (TestsVerdict).
	Verdict string       `json:"verdict,omitempty"`
	Summary string       `json:"summary,omitempty"`
	Tests   []TestResult `json:"tests,omitempty"`
	// Skipped says why the run did not happen; empty when it ran.
	Skipped string `json:"skipped,omitempty"`
}

// ran reports whether the side has test results to read.
func (s ProofSide) ran() bool { return len(s.Tests) > 0 }

// Proof is one red-green proof of a requirement's tests.
type Proof struct {
	RequirementID int `json:"requirement_id"`
	// Fingerprint is the requirement's Fingerprint as it was proved.
	Fingerprint string `json:"fingerprint"`
	Outcome     string `json:"outcome"`
	Summary     string `json:"summary,omitempty"`
	// BaseFrom says how the base was chosen (BaseFrom*).
	BaseFrom string `json:"base_from,omitempty"`
	// Before is the run at the base, After the run on the change.
	Before ProofSide `json:"before"`
	After  ProofSide `json:"after"`
	// Fallback reports that the requirement's tests did not exist at the base
	// as they read in the change, so the base run used the base code with
	// TestFiles laid over it.
	Fallback bool `json:"fallback,omitempty"`
	// TestFiles are the requirement's test files the change added, changed or
	// removed.
	TestFiles []ProofFile `json:"test_files,omitempty"`
	// CodeChanged reports that the change holds more than TestFiles: something
	// for the tests to fail without.
	CodeChanged bool `json:"code_changed,omitempty"`
	// NewTests reports that the change added a test — a test file, a test
	// declared in one, or a test command — rather than only changing one. A
	// vacuous proof of a new test is what the requirements gate refuses in
	// linked+must mode.
	NewTests   bool      `json:"new_tests,omitempty"`
	StartedAt  time.Time `json:"started_at"`
	DurationMS int64     `json:"duration_ms"`
}

// ProofReport is what one `cloop requirements prove` found.
type ProofReport struct {
	Results []Proof `json:"results"`
	// Untouched are the requirements a proof of only what the change touched
	// passed over: the change added or changed none of their tests.
	Untouched []int `json:"untouched,omitempty"`
}

// Base is the commit the proof's base run used.
func (p Proof) Base() string { return p.Before.Commit }

// Clone returns a copy of p that shares no slice with it: BoundProof trims in
// place.
func (p Proof) Clone() Proof {
	p.TestFiles = append([]ProofFile(nil), p.TestFiles...)
	p.Before.Tests = append([]TestResult(nil), p.Before.Tests...)
	p.After.Tests = append([]TestResult(nil), p.After.Tests...)
	return p
}

// sideState is what one side's tests add up to, for a proof.
type sideState int

const (
	sideNone  sideState = iota // nothing ran
	sideGreen                  // every test passed
	sideRed                    // a test failed, or timed out
	sideError                  // a test could not run, and none failed
)

// stateOf reads a side. A timeout is red here, where TestsVerdict calls it an
// error: a test that hangs without the change does fail without it, and one
// that hangs on the change does not pass on it.
func stateOf(s ProofSide) sideState {
	if !s.ran() {
		return sideNone
	}
	red, broken := false, false
	for _, t := range s.Tests {
		switch t.Outcome {
		case OutcomePass:
		case OutcomeFail, OutcomeTimeout:
			red = true
		default:
			broken = true
		}
	}
	switch {
	case red:
		return sideRed
	case broken:
		return sideError
	}
	return sideGreen
}

// noTestsRe matches what common test runners print when they ran no test:
// go test -run with no match, pytest and jest with nothing collected, cargo
// and mocha with nothing to do. Word bounded: "10 passing" is not "0 passing".
var noTestsRe = regexp.MustCompile(`(?i)(no tests to run|\[no test files\]|no test files|matched no packages|` +
	`no tests ran|\bcollected 0 items\b|no tests found|\brunning 0 tests\b|\bran 0 tests?\b|(^|[^0-9])0 passing\b)`)

// noTestsMarker is what a run's test printed to say it ran no test, when the
// same test on the change said nothing of the kind; "" otherwise.
func noTestsMarker(before, after ProofSide) string {
	for i, t := range before.Tests {
		m := noTestsRe.FindString(t.Output)
		if m == "" {
			continue
		}
		if i < len(after.Tests) && noTestsRe.MatchString(after.Tests[i].Output) {
			continue
		}
		return strings.TrimSpace(m)
	}
	return ""
}

// missingCommand says how a base run's test showed that its command does not
// exist there: the shell's "not found" (127) or "cannot execute" (126), or a
// runner that found no test to run. "" when no test says so.
func missingCommand(before, after ProofSide) string {
	for _, t := range before.Tests {
		if t.Outcome != OutcomeFail {
			continue
		}
		switch t.ExitCode {
		case 127:
			return fmt.Sprintf("%q exited 127: the shell did not find the command", t.label())
		case 126:
			return fmt.Sprintf("%q exited 126: the command could not be executed", t.label())
		}
	}
	if m := noTestsMarker(before, after); m != "" {
		return "the test runner found no test to run (" + m + ")"
	}
	return ""
}

// DecideProof is what a proof's two runs add up to, and a sentence saying so.
// It reads only the evidence — the runs' test outcomes and output, and what
// the change held — so the hub reaching it again from a report decides as the
// executor did.
func DecideProof(p Proof) (string, string) {
	base := shortRev(p.Before.Commit)
	fallback := ""
	if p.Fallback {
		fallback = " (the test did not exist at the base as it reads in the change, so the base run used the base " +
			"code with the change's test files laid over it)"
	}
	switch stateOf(p.After) {
	case sideNone:
		why := p.After.Skipped
		if why == "" {
			why = "nothing ran"
		}
		return ProofError, "the tests were not run on the change: " + why
	case sideError:
		return ProofError, "the tests could not run on the change: " + p.After.Summary
	case sideRed:
		return ProofBroken, "the tests fail on the change itself: " + p.After.Summary
	}
	// A base run that could not happen — the base is not in the checkout,
	// could not be checked out — leaves nothing to compare, whatever the
	// change holds.
	if !p.Before.ran() && p.Before.Skipped != "" {
		return ProofError, "the tests were not run at the base: " + p.Before.Skipped
	}
	if !p.CodeChanged {
		return ProofInconclusive, "nothing but the requirement's test files differs between the base " + base +
			" and the change, so there is nothing for the tests to fail without — a test of behaviour the code " +
			"already had cannot be proved red-green"
	}
	switch stateOf(p.Before) {
	case sideNone:
		return ProofError, "the tests were not run at the base"
	case sideError:
		return ProofError, "the tests could not run at the base " + base + ": " + p.Before.Summary
	case sideGreen:
		if m := noTestsMarker(p.Before, p.After); m != "" {
			return ProofInconclusive, "the test does not exist at the base " + base + fallbackClause(p.Fallback) +
				": the test runner found no test to run (" + m + ")"
		}
		return ProofVacuous, "the tests pass at the base " + base + " too, so they do not show the change" + fallback
	}
	if m := missingCommand(p.Before, p.After); m != "" {
		return ProofInconclusive, "the test command does not exist at the base " + base + fallbackClause(p.Fallback) + ": " + m
	}
	return ProofProven, "the tests fail at the base " + base + " and pass on the change" + fallback
}

func fallbackClause(fallback bool) string {
	if fallback {
		return ", even with the change's test files laid over the base code"
	}
	return ""
}

func shortRev(c string) string {
	if c == "" {
		return "(unknown)"
	}
	if len(c) > 12 {
		return c[:12]
	}
	return c
}

// ── which files are a requirement's tests ───────────────────────────────────

// testDirs are directory names whose contents are tests, or what tests read.
var testDirs = map[string]bool{
	"test": true, "tests": true, "__tests__": true, "testdata": true, "spec": true,
	"__snapshots__": true, "__mocks__": true, "__fixtures__": true,
}

// testSuffixes end the names of test files, by the conventions of the common
// languages' test runners.
var testSuffixes = []string{
	"_test.go", "_test.py", "_tests.py", "_spec.rb", "_test.rb", "_test.exs", "_test.sh", "_test.rs",
	"_test.c", "_test.cc", "_test.cpp", ".bats",
}

// testNameRe matches a JavaScript or TypeScript test file (x.test.ts,
// x.spec.js) and a JVM, .NET, PHP or Swift one (FooTest.java, FooTests.cs,
// FooSpec.scala, FooIT.java).
var testNameRe = regexp.MustCompile(`(\.(test|spec)\.(js|jsx|ts|tsx|mjs|cjs|mts|cts|vue|svelte)$)|` +
	`((Test|Tests|Spec|IT)\.(java|kt|kts|cs|php|swift|scala|groovy)$)`)

// IsTestFile reports whether a repository path is a test by the usual
// conventions: a name test runners collect, or a path under a directory that
// holds tests or what they read. Deliberately conservative: a proof lays the
// test files of a change over the base code, and code mistaken for a test
// would carry part of the change into the base run — and could make a real
// test look vacuous.
func IsTestFile(p string) bool {
	p = strings.TrimPrefix(path.Clean(strings.ReplaceAll(p, "\\", "/")), "./")
	name := path.Base(p)
	if strings.HasPrefix(name, "test_") || name == "conftest.py" {
		return true
	}
	for _, s := range testSuffixes {
		if strings.HasSuffix(name, s) {
			return true
		}
	}
	if testNameRe.MatchString(name) {
		return true
	}
	dir := path.Dir(p)
	for dir != "." && dir != "/" && dir != "" {
		if testDirs[path.Base(dir)] {
			return true
		}
		dir = path.Dir(dir)
	}
	return false
}

// interpreters run the script named after them.
var interpreters = map[string]bool{
	"sh": true, "bash": true, "dash": true, "zsh": true, "ksh": true, "python": true, "python2": true, "python3": true,
	"node": true, "ruby": true, "perl": true, "php": true, "bats": true, "deno": true, "bun": true, "tsx": true,
	"ts-node": true, "Rscript": true, "pwsh": true,
}

// wrappers run the command that follows them; a numeric argument (timeout
// 60) is theirs.
var wrappers = map[string]bool{"env": true, "exec": true, "time": true, "nice": true, "timeout": true, "xvfb-run": true,
	"stdbuf": true, "command": true}

// shells run the command line they are given with -c.
var shells = map[string]bool{"sh": true, "bash": true, "dash": true, "zsh": true, "ksh": true}

// commandPaths are the repository paths a test's commands name. scripts are
// the ones a command runs: a path in a command's own position (./check.sh,
// tools/check) or the script an interpreter is given (sh tests/x.sh). args
// are the rest — the packages and directories a test runner is pointed at,
// and the files a command reads — each cleaned of quotes, of a flag's name
// and of pytest's ::node; Go's ./pkg/... names pkg, and ./... the whole tree.
// A `cd dir` names dir, and the words after it are read from there; a
// shell's -c line is read as a command of its own.
func commandPaths(tests []Test) (scripts, args []string) {
	seenScript, seenArg := map[string]bool{}, map[string]bool{}
	add := func(list *[]string, seen map[string]bool, w string) {
		w = strings.TrimSuffix(strings.TrimSuffix(strings.TrimRight(w, ","), "..."), "/")
		if w == "" {
			w = "."
		}
		w = path.Clean(w)
		if w == ".." || strings.HasPrefix(w, "../") || strings.HasPrefix(w, "/") || seen[w] {
			return
		}
		seen[w] = true
		*list = append(*list, w)
	}
	for _, t := range tests {
		dir := ""
		// clean is a word as a path relative to the project, or "".
		clean := func(w string) string {
			if i := strings.LastIndexByte(w, '='); i >= 0 {
				w = w[i+1:]
			}
			if w == "" || strings.HasPrefix(w, "-") || strings.HasPrefix(w, "/") || strings.HasPrefix(w, "$") ||
				strings.HasPrefix(w, "~") {
				return ""
			}
			if i := strings.Index(w, "::"); i >= 0 {
				w = w[:i]
			}
			if dir != "" {
				w = path.Join(dir, w)
			}
			return w
		}
		cmd := strings.NewReplacer("&&", ";", "||", ";").Replace(t.Command)
		for _, segment := range strings.FieldsFunc(cmd, func(r rune) bool { return strings.ContainsRune(";|&()\n", r) }) {
			words := strings.Fields(strings.Map(func(r rune) rune {
				if strings.ContainsRune("'\"`<>", r) {
					return ' '
				}
				return r
			}, segment))
			i := commandStart(words, 0)
			// A shell given a command line runs that line.
			if i < len(words) && shells[words[i]] {
				for j := i + 1; j < len(words); j++ {
					if words[j] == "-c" {
						i = commandStart(words, j+1)
						break
					}
					if !strings.HasPrefix(words[j], "-") {
						break
					}
				}
			}
			if i >= len(words) {
				continue
			}
			program, rest := words[i], words[i+1:]
			switch {
			case program == "cd":
				for _, w := range rest {
					if c := clean(w); c != "" {
						dir = path.Clean(c)
						add(&args, seenArg, dir)
						break
					}
				}
				continue
			case strings.Contains(program, "/"):
				if c := clean(program); c != "" {
					add(&scripts, seenScript, c)
				}
			case interpreters[program]:
				for j, w := range rest {
					if !strings.HasPrefix(w, "-") {
						if c := clean(w); c != "" {
							add(&scripts, seenScript, c)
						}
						rest = rest[j+1:]
						break
					}
				}
			}
			for _, w := range rest {
				if c := clean(w); c != "" {
					add(&args, seenArg, c)
				}
			}
		}
	}
	return scripts, args
}

// commandStart is where the command in words from i begins: past variable
// assignments and the wrappers that run what follows them.
func commandStart(words []string, i int) int {
	for i < len(words) {
		w := words[i]
		switch {
		case strings.Contains(w, "=") && !strings.HasPrefix(w, "-") && !strings.Contains(w, "/"):
			i++
		case wrappers[w]:
			i++
			for i < len(words) && (strings.HasPrefix(words[i], "-") || isNumber(words[i])) {
				i++
			}
		default:
			return i
		}
	}
	return i
}

func isNumber(w string) bool {
	if w == "" {
		return false
	}
	for _, r := range w {
		if (r < '0' || r > '9') && r != '.' && !strings.ContainsRune("smhd", r) {
			return false
		}
	}
	return true
}

// TestFilesFor picks, from a change's files, the requirement's test files: a
// script one of its commands runs, and a test file (IsTestFile) at or inside
// a path one names. A file a command only reads — `grep -q done
// feature.txt` — is what the test looks at, not the test: laid over the base,
// it would carry the change there. exists says whether a path names a file or
// directory of the change's tree; a word that names neither, nor a file of
// the change, is not a path. When the commands name no path at all — `npm
// test`, `make check` — every test file of the change is the requirement's.
func TestFilesFor(tests []Test, changes []ProofFile, exists func(rel string) bool) []ProofFile {
	scripts, words := commandPaths(tests)
	changed := make(map[string]bool, len(changes))
	for _, c := range changes {
		changed[c.Path] = true
	}
	isPath := func(w string) bool {
		return w == "." || changed[w] || (exists != nil && exists(w)) || hasChangeUnder(changes, w)
	}
	var named []string
	for _, w := range words {
		if isPath(w) {
			named = append(named, w)
		}
	}
	run := map[string]bool{}
	for _, w := range scripts {
		run[w] = true
	}
	var out []ProofFile
	for _, c := range changes {
		switch {
		case run[c.Path]:
			out = append(out, c)
		case !IsTestFile(c.Path):
		case len(named) == 0 && len(scripts) == 0, underAny(c.Path, named):
			out = append(out, c)
		}
	}
	return out
}

func hasChangeUnder(changes []ProofFile, dir string) bool {
	for _, c := range changes {
		if strings.HasPrefix(c.Path, dir+"/") {
			return true
		}
	}
	return false
}

// underAny reports whether p is one of named or inside one.
func underAny(p string, named []string) bool {
	for _, n := range named {
		if n == "." || p == n || strings.HasPrefix(p, n+"/") {
			return true
		}
	}
	return false
}

// testDeclRe matches a line a diff adds that declares a test, in the common
// languages: Go's func TestX, Python's def test_x and class TestX, a
// JavaScript it/test/describe, Ruby's it/describe/context, JUnit's @Test,
// Rust's #[test], a bats @test.
var testDeclRe = regexp.MustCompile(`(?m)^\+\s*(func\s+(Test|Fuzz|Example)\w*\s*\(|(async\s+)?def\s+test_\w*\s*\(|` +
	`class\s+Test\w*|(it|test|describe)(\.\w+)?\s*\(\s*['"\x60]|(it|describe|context)\s+['"]|@Test\b|#\[test\]|@test\s)`)

// AddsTestDeclaration reports whether a unified diff adds a line declaring a
// test: a new test in a file the change modified.
func AddsTestDeclaration(diff string) bool { return testDeclRe.MatchString(diff) }

// ── the hub's reading of a report ───────────────────────────────────────────

// SanitizeProofs is the hub's reading of a proof report an executor sent back
// about asked, the requirements the hub asked it to prove. As Sanitize does
// for a check:
//
//   - only the requirements asked about, once each, in the order asked; one the
//     report left out is an error proof saying so — unless the report names it
//     untouched, which is passed on;
//   - the definition as the hub sent it: fingerprint, test names and commands
//     come from asked, with exactly one result per test on each side that ran;
//   - each side's verdict recomputed from its tests, and the outcome from both
//     sides (DecideProof), whatever the report claims;
//   - every text bounded, and every output passed through scrub.
//
// scrub may be nil. now stamps a proof that carries no start time.
func SanitizeProofs(rep ProofReport, asked []Requirement, scrub func(string) string, now time.Time) ProofReport {
	if scrub == nil {
		scrub = func(s string) string { return s }
	}
	got := map[int]Proof{}
	for _, p := range rep.Results {
		if _, dup := got[p.RequirementID]; !dup {
			got[p.RequirementID] = p
		}
	}
	untouched := map[int]bool{}
	for _, id := range rep.Untouched {
		untouched[id] = true
	}
	out := ProofReport{Results: []Proof{}}
	for _, req := range asked {
		p, ok := got[req.ID]
		if !ok {
			if untouched[req.ID] {
				out.Untouched = append(out.Untouched, req.ID)
				continue
			}
			out.Results = append(out.Results, Proof{
				RequirementID: req.ID, Fingerprint: req.Fingerprint(), Outcome: ProofError,
				Summary: "the executor reported no proof for this requirement", StartedAt: now,
			})
			continue
		}
		out.Results = append(out.Results, SanitizeProof(p, req, scrub, now))
	}
	return out
}

// SanitizeProof reads one proof against req, the definition it is about; see
// SanitizeProofs.
func SanitizeProof(p Proof, req Requirement, scrub func(string) string, now time.Time) Proof {
	if scrub == nil {
		scrub = func(s string) string { return s }
	}
	clean := Proof{
		RequirementID: req.ID,
		Fingerprint:   req.Fingerprint(),
		BaseFrom:      cleanBaseFrom(p.BaseFrom),
		Fallback:      p.Fallback,
		CodeChanged:   p.CodeChanged,
		NewTests:      p.NewTests,
		StartedAt:     p.StartedAt.UTC(),
		DurationMS:    clampMS(p.DurationMS),
	}
	if clean.StartedAt.IsZero() || clean.StartedAt.After(now.Add(time.Hour)) {
		clean.StartedAt = now
	}
	for _, f := range p.TestFiles {
		if len(clean.TestFiles) == MaxProofFiles {
			break
		}
		if f, ok := cleanProofFile(f); ok {
			clean.TestFiles = append(clean.TestFiles, f)
		}
	}
	var broken []string
	clean.Before, broken = sanitizeSide(p.Before, req, scrub, "base", broken)
	clean.After, broken = sanitizeSide(p.After, req, scrub, "change", broken)
	if len(broken) > 0 {
		clean.Outcome = ProofError
		clean.Summary = truncateRunes("the executor's report did not fit the requirement's tests: "+strings.Join(broken, "; "),
			MaxSummaryRunes)
		return clean
	}
	clean.Outcome, clean.Summary = DecideProof(clean)
	clean.Summary = truncateRunes(scrub(clean.Summary), MaxRationaleRunes)
	return clean
}

func sanitizeSide(s ProofSide, req Requirement, scrub func(string) string, which string, broken []string) (ProofSide, []string) {
	out := ProofSide{Commit: cleanCommit(s.Commit), Dirty: s.Dirty}
	if len(s.Tests) == 0 {
		out.Skipped = truncateRunes(scrub(oneLine(s.Skipped)), MaxSummaryRunes)
		return out, broken
	}
	if len(s.Tests) != len(req.Tests) {
		return out, append(broken, fmt.Sprintf("the %s run reported %d test results for %d tests", which, len(s.Tests), len(req.Tests)))
	}
	out.Tests = make([]TestResult, len(req.Tests))
	for i, t := range req.Tests {
		out.Tests[i] = sanitizeTest(s.Tests[i], t, scrub)
	}
	out.Verdict, out.Summary = TestsVerdict(out.Tests)
	return out, broken
}

func cleanBaseFrom(s string) string {
	switch s {
	case BaseFromTask, BaseFromTest, BaseFromWorktree, BaseFromGiven:
		return s
	}
	return ""
}

// cleanProofFile is f as a repository path and a status, or false when it is
// not one: what an executor reports is not trusted to be one.
func cleanProofFile(f ProofFile) (ProofFile, bool) {
	p := strings.TrimSpace(strings.ReplaceAll(f.Path, "\\", "/"))
	if p == "" || len(p) > MaxProofPathBytes || strings.ContainsAny(p, "\x00\r\n") {
		return f, false
	}
	p = path.Clean(p)
	if p == "." || p == ".." || strings.HasPrefix(p, "../") || strings.HasPrefix(p, "/") {
		return f, false
	}
	switch f.Status {
	case FileAdded, FileModified, FileDeleted:
	default:
		return f, false
	}
	return ProofFile{Path: strings.ToValidUTF8(p, "?"), Status: f.Status}, true
}

// CleanProofFile is f bounded and checked as a repository path, or false.
func CleanProofFile(f ProofFile) (ProofFile, bool) { return cleanProofFile(f) }

// BoundProof trims p to its stored sizes in place — its slices too, so bound
// a Clone of a proof the caller still holds: the files it names, its
// summaries, and the output of each test — none for a test that passed, the
// last outputBytes of one that did not. It is applied wherever a proof is
// kept beside something it should not crowd out, a task's record above all.
func BoundProof(p *Proof, outputBytes int) {
	if p == nil {
		return
	}
	p.Outcome = truncateRunes(p.Outcome, 16)
	p.Summary = truncateRunes(p.Summary, MaxRationaleRunes)
	p.Fingerprint = truncateRunes(p.Fingerprint, 128)
	p.BaseFrom = cleanBaseFrom(p.BaseFrom)
	if len(p.TestFiles) > MaxProofFiles {
		p.TestFiles = p.TestFiles[:MaxProofFiles]
	}
	kept := p.TestFiles[:0]
	for _, f := range p.TestFiles {
		if f, ok := cleanProofFile(f); ok {
			kept = append(kept, f)
		}
	}
	p.TestFiles = kept
	for _, s := range []*ProofSide{&p.Before, &p.After} {
		s.Commit = cleanCommit(s.Commit)
		s.Summary = truncateRunes(s.Summary, MaxSummaryRunes)
		s.Skipped = truncateRunes(s.Skipped, MaxSummaryRunes)
		s.Verdict = truncateRunes(s.Verdict, 16)
		if len(s.Tests) > MaxTests {
			s.Tests = s.Tests[:MaxTests]
		}
		for i := range s.Tests {
			t := &s.Tests[i]
			t.Name = truncateRunes(t.Name, MaxTestNameRunes)
			if len(t.Command) > MaxCommandBytes {
				t.Command = strings.ToValidUTF8(t.Command[:MaxCommandBytes], "")
			}
			t.Error = truncateRunes(t.Error, MaxSummaryRunes)
			if t.Outcome == OutcomePass {
				// A test that passed keeps no output — except the line that
				// says it ran no test, which is what a proof decides by.
				t.Output, t.Truncated = noTestsLine(t.Output), false
				continue
			}
			if len(t.Output) > outputBytes {
				t.Output = strings.ToValidUTF8(t.Output[len(t.Output)-outputBytes:], "")
				t.Truncated = true
			}
		}
	}
}

// noTestsLine is the line of out that says its test runner ran no test, or
// "".
func noTestsLine(out string) string {
	loc := noTestsRe.FindStringIndex(out)
	if loc == nil {
		return ""
	}
	start := strings.LastIndexByte(out[:loc[0]], '\n') + 1
	end := len(out)
	if i := strings.IndexByte(out[loc[1]:], '\n'); i >= 0 {
		end = loc[1] + i
	}
	line := out[start:end]
	if len(line) > 512 {
		line = strings.ToValidUTF8(out[loc[0]:loc[1]], "")
	}
	return line
}

// ProofBudget is how long a proof of reqs may take: each test's own timeout
// on each side it runs — the after run is skipped by a caller that has just
// run it — and starting the proof.
func ProofBudget(reqs []Requirement, beforeOnly bool) time.Duration {
	sides := time.Duration(2)
	if beforeOnly {
		sides = 1
	}
	d := DispatchSlack
	for _, q := range reqs {
		for _, t := range q.Tests {
			d += sides * t.Timeout()
		}
	}
	return d
}

// ProofHeadline is a proof in a few words, for a card or a log line:
// "proven", "vacuous: its new test passes without the change".
func ProofHeadline(p Proof) string {
	switch p.Outcome {
	case ProofVacuous:
		if p.NewTests {
			return "vacuous: its new test passes without the change"
		}
		return "vacuous: its tests pass without the change"
	case ProofBroken:
		return "broken: its tests fail on the change"
	case ProofProven:
		return "proven: red without the change, green with it"
	case ProofInconclusive:
		return "inconclusive"
	}
	return "the proof did not run"
}
