package requirements

import (
	"fmt"
	"strings"
	"time"
	"unicode/utf8"
)

// Verdicts: what a check concluded about a requirement.
const (
	// VerdictFulfilled: every test passed, or the model or a person said so.
	VerdictFulfilled = "fulfilled"
	// VerdictUnfulfilled: a test failed, or the model or a person said so.
	VerdictUnfulfilled = "unfulfilled"
	// VerdictUnverified: nothing could say — the requirement has no tests,
	// and the model was not asked or could not tell.
	VerdictUnverified = "unverified"
	// VerdictError: the check itself did not work — a test timed out or could
	// not be started, the model call failed, the executor reported nothing.
	// Not a statement about the requirement.
	VerdictError = "error"
)

// Methods: how a verdict was reached.
const (
	MethodTests  = "tests"
	MethodAI     = "ai"
	MethodManual = "manual"
	MethodNone   = "none"
)

// Test outcomes.
const (
	OutcomePass    = "pass"
	OutcomeFail    = "fail"
	OutcomeTimeout = "timeout"
	OutcomeError   = "error"
)

// Bounds on what a report carries back. Output is a test's last bytes: when a
// test fails, its end is what says why.
const (
	MaxOutputBytes    = 16 << 10
	MaxSummaryRunes   = 1000
	MaxRationaleRunes = 4000
	MaxEvidence       = 8
	MaxEvidenceRunes  = 500
	maxCommitLen      = 64
)

// TestResult is one test's run.
type TestResult struct {
	Name       string `json:"name,omitempty"`
	Command    string `json:"command"`
	Outcome    string `json:"outcome"`
	ExitCode   int    `json:"exit_code"`
	DurationMS int64  `json:"duration_ms"`
	// Output is the end of what the test printed, stdout and stderr in the
	// order they arrived, scrubbed of credentials.
	Output string `json:"output,omitempty"`
	// Truncated reports that Output is only the end of it.
	Truncated bool `json:"truncated,omitempty"`
	// Error says why a test that did not run to an exit status did not.
	Error string `json:"error,omitempty"`
}

// Result is one requirement's check.
type Result struct {
	RequirementID int `json:"requirement_id"`
	// Fingerprint is the requirement's Fingerprint as it was checked.
	Fingerprint string       `json:"fingerprint"`
	Method      string       `json:"method"`
	Verdict     string       `json:"verdict"`
	Summary     string       `json:"summary,omitempty"`
	Tests       []TestResult `json:"tests,omitempty"`
	// Evidence is what the model pointed at, for a verdict it reached.
	Evidence   []string  `json:"evidence,omitempty"`
	StartedAt  time.Time `json:"started_at"`
	DurationMS int64     `json:"duration_ms"`
}

// Report is what one `cloop requirements check` found: a result per
// requirement it was asked about, and the tree it found them in.
type Report struct {
	// Commit is HEAD of the tree the tests ran in, when it is a git checkout.
	Commit string `json:"commit,omitempty"`
	// Dirty reports uncommitted changes in that tree: the commit alone does
	// not say what was tested.
	Dirty   bool     `json:"dirty,omitempty"`
	Results []Result `json:"results"`
}

// Counts tallies a set of results by verdict.
type Counts struct {
	Fulfilled   int `json:"fulfilled"`
	Unfulfilled int `json:"unfulfilled"`
	Unverified  int `json:"unverified"`
	Error       int `json:"error"`
}

// Add counts one verdict.
func (c *Counts) Add(verdict string) {
	switch verdict {
	case VerdictFulfilled:
		c.Fulfilled++
	case VerdictUnfulfilled:
		c.Unfulfilled++
	case VerdictUnverified:
		c.Unverified++
	default:
		c.Error++
	}
}

// Tally counts results by verdict.
func Tally(results []Result) Counts {
	var c Counts
	for _, r := range results {
		c.Add(r.Verdict)
	}
	return c
}

// Failing reports whether c holds a verdict that should fail a gate: a
// requirement not fulfilled, or one whose check did not work.
func (c Counts) Failing() bool { return c.Unfulfilled > 0 || c.Error > 0 }

// ValidVerdict reports whether v is one of the four verdicts.
func ValidVerdict(v string) bool {
	switch v {
	case VerdictFulfilled, VerdictUnfulfilled, VerdictUnverified, VerdictError:
		return true
	}
	return false
}

// TestsVerdict is what a requirement's test runs add up to, and a sentence
// saying so: unfulfilled when any test failed, an error when none failed but
// one could not say — timed out, could not start — and fulfilled when every
// test passed.
func TestsVerdict(results []TestResult) (string, string) {
	var failed, broken []TestResult
	for _, t := range results {
		switch t.Outcome {
		case OutcomePass:
		case OutcomeFail:
			failed = append(failed, t)
		default:
			broken = append(broken, t)
		}
	}
	switch {
	case len(results) == 0:
		return VerdictUnverified, "no tests to run"
	case len(failed) == 1 && len(results) == 1:
		return VerdictUnfulfilled, fmt.Sprintf("test %q failed (exit %d)", failed[0].label(), failed[0].ExitCode)
	case len(failed) > 0:
		return VerdictUnfulfilled, fmt.Sprintf("%d of %d tests failed: %s", len(failed), len(results), labels(failed))
	case len(broken) > 0:
		b := broken[0]
		var msg string
		switch {
		case b.Outcome == OutcomeTimeout && strings.HasPrefix(b.Error, "timed out"):
			msg = fmt.Sprintf("test %q %s", b.label(), b.Error)
		case b.Outcome == OutcomeTimeout:
			msg = fmt.Sprintf("test %q timed out", b.label())
		case b.Error != "":
			msg = fmt.Sprintf("test %q could not run: %s", b.label(), b.Error)
		default:
			msg = fmt.Sprintf("test %q could not run", b.label())
		}
		if len(broken) > 1 {
			msg += fmt.Sprintf(" (and %d more)", len(broken)-1)
		}
		return VerdictError, msg
	case len(results) == 1:
		return VerdictFulfilled, "1 test passed"
	}
	return VerdictFulfilled, fmt.Sprintf("%d tests passed", len(results))
}

func (t TestResult) label() string {
	return Test{Name: t.Name, Command: t.Command}.Label()
}

func labels(ts []TestResult) string {
	names := make([]string, 0, len(ts))
	for i, t := range ts {
		if i == 3 {
			names = append(names, fmt.Sprintf("and %d more", len(ts)-3))
			break
		}
		names = append(names, fmt.Sprintf("%q", t.label()))
	}
	return strings.Join(names, ", ")
}

// Sanitize is the hub's reading of a report an executor sent back about
// asked, the requirements the hub asked it to check. Whatever cloop the
// executor runs, what is recorded is decided here:
//
//   - only the requirements asked about, once each, in the order asked; one
//     the report left out is an error result saying so;
//   - the definition as the hub sent it — fingerprint, test names and
//     commands come from asked, never from the report;
//   - a tested requirement's verdict recomputed from its tests' outcomes,
//     with exactly one outcome per test asked; an untested one's verdict the
//     model's (fulfilled, unfulfilled, unverified) when assess says the model
//     was asked, and unverified otherwise — whatever the report claims;
//   - every text bounded, and every output passed through scrub.
//
// scrub may be nil. now stamps a result that carries no start time.
func Sanitize(rep Report, asked []Requirement, assess bool, scrub func(string) string, now time.Time) Report {
	if scrub == nil {
		scrub = func(s string) string { return s }
	}
	got := map[int]Result{}
	for _, r := range rep.Results {
		if _, dup := got[r.RequirementID]; !dup {
			got[r.RequirementID] = r
		}
	}
	out := Report{Commit: cleanCommit(rep.Commit), Dirty: rep.Dirty}
	for _, req := range asked {
		r, ok := got[req.ID]
		if !ok {
			out.Results = append(out.Results, Result{
				RequirementID: req.ID, Fingerprint: req.Fingerprint(), Method: methodFor(req),
				Verdict: VerdictError, Summary: "the executor reported no result for this requirement",
				StartedAt: now,
			})
			continue
		}
		out.Results = append(out.Results, sanitizeResult(r, req, assess, scrub, now))
	}
	return out
}

func methodFor(req Requirement) string {
	if req.Tested() {
		return MethodTests
	}
	return MethodNone
}

func sanitizeResult(r Result, req Requirement, assess bool, scrub func(string) string, now time.Time) Result {
	clean := Result{
		RequirementID: req.ID,
		Fingerprint:   req.Fingerprint(),
		StartedAt:     r.StartedAt.UTC(),
		DurationMS:    clampMS(r.DurationMS),
	}
	if clean.StartedAt.IsZero() || clean.StartedAt.After(now.Add(time.Hour)) {
		clean.StartedAt = now
	}
	if req.Tested() {
		clean.Method = MethodTests
		if len(r.Tests) != len(req.Tests) {
			clean.Verdict = VerdictError
			clean.Summary = fmt.Sprintf("the executor reported %d test results for %d tests", len(r.Tests), len(req.Tests))
			return clean
		}
		clean.Tests = make([]TestResult, len(req.Tests))
		for i, t := range req.Tests {
			clean.Tests[i] = sanitizeTest(r.Tests[i], t, scrub)
		}
		clean.Verdict, clean.Summary = TestsVerdict(clean.Tests)
		return clean
	}
	switch {
	case r.Method == MethodAI && assess:
		clean.Method = MethodAI
		clean.Verdict = r.Verdict
		switch r.Verdict {
		case VerdictFulfilled, VerdictUnfulfilled, VerdictUnverified, VerdictError:
		default:
			clean.Verdict = VerdictError
		}
		clean.Summary = truncateRunes(scrub(oneLine(r.Summary)), MaxRationaleRunes)
		if clean.Summary == "" && clean.Verdict == VerdictError {
			clean.Summary = "the model's assessment could not be read"
		}
		for _, e := range r.Evidence {
			if e = truncateRunes(scrub(oneLine(e)), MaxEvidenceRunes); e != "" && len(clean.Evidence) < MaxEvidence {
				clean.Evidence = append(clean.Evidence, e)
			}
		}
	default:
		clean.Method = MethodNone
		clean.Verdict = VerdictUnverified
		clean.Summary = "no tests, and the model was not asked"
	}
	return clean
}

func sanitizeTest(got TestResult, t Test, scrub func(string) string) TestResult {
	out := TestResult{
		Name:       t.Name,
		Command:    t.Command,
		Outcome:    got.Outcome,
		ExitCode:   got.ExitCode,
		DurationMS: clampMS(got.DurationMS),
		Truncated:  got.Truncated,
	}
	switch got.Outcome {
	case OutcomePass:
		out.ExitCode = 0
	case OutcomeFail:
		if out.ExitCode == 0 {
			// A failure that exited 0 is not one this runner reports.
			out.Outcome, out.Error = OutcomeError, "reported as failed with exit status 0"
		}
	case OutcomeTimeout, OutcomeError:
	default:
		out.Outcome, out.Error = OutcomeError, "the executor reported an unknown outcome"
	}
	if out.Error == "" {
		out.Error = truncateRunes(scrub(oneLine(got.Error)), MaxSummaryRunes)
	}
	output := got.Output
	if !utf8.ValidString(output) {
		output = strings.ToValidUTF8(output, "�")
	}
	if len(output) > MaxOutputBytes {
		output, out.Truncated = output[len(output)-MaxOutputBytes:], true
		output = strings.ToValidUTF8(output, "")
	}
	out.Output = scrub(output)
	return out
}

// clampMS keeps a reported duration inside what a check can take.
func clampMS(ms int64) int64 {
	switch {
	case ms < 0:
		return 0
	case ms > int64(24*time.Hour/time.Millisecond):
		return int64(24 * time.Hour / time.Millisecond)
	}
	return ms
}

func cleanCommit(c string) string {
	c = strings.ToLower(strings.TrimSpace(c))
	if c == "" || len(c) > maxCommitLen {
		return ""
	}
	for _, r := range c {
		if !strings.ContainsRune("0123456789abcdef", r) {
			return ""
		}
	}
	return c
}

// oneLine collapses whitespace runs, newlines included, to single spaces.
func oneLine(s string) string { return strings.Join(strings.Fields(s), " ") }
