package pm

import (
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/blechschmidt/cloop/pkg/requirements"
)

// This file carries requirement-gated completion (Task 20461): an opt-in,
// per-project post-condition under which a task whose agent says it is done is
// accepted only once the requirements it implements pass — and, in
// linked+must mode, every approved must requirement too — and the record of
// what the gate found on the task's latest attempt.
//
// Like the commit policy and the review gate, the setting lives in project
// state: a run on an isolating executor is seeded with the project state and
// never sees the hub's config.yaml, and the check runs inside that run, beside
// the work. config.yaml may declare it as well (requirements.gate), and `cloop
// run` then writes the declaration into the project before it starts.

// The modes `cloop requirements gate`, `cloop run --requirements-gate`, the
// dashboard and config.yaml's requirements.gate accept.
const (
	// RequirementsGateOff accepts a task's TASK_DONE as before.
	RequirementsGateOff = "off"
	// RequirementsGateLinked checks the requirements the task implements.
	RequirementsGateLinked = "linked"
	// RequirementsGateLinkedMust checks those and every approved must
	// requirement: a task may not leave one of them failing.
	RequirementsGateLinkedMust = "linked+must"
)

// RequirementsGateModes lists the modes, in the order help text shows them.
var RequirementsGateModes = []string{RequirementsGateOff, RequirementsGateLinked, RequirementsGateLinkedMust}

// ParseRequirementsGateMode reads a mode as a person or a config file writes
// it. Case and surrounding space do not matter, and linked-must and
// linked_must stand for linked+must, which a URL or a shell would otherwise
// mangle. The empty string is not a mode.
func ParseRequirementsGateMode(v string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case RequirementsGateOff:
		return RequirementsGateOff, nil
	case RequirementsGateLinked:
		return RequirementsGateLinked, nil
	case RequirementsGateLinkedMust, "linked-must", "linked_must":
		return RequirementsGateLinkedMust, nil
	}
	return "", fmt.Errorf("%q is not one of %s", v, strings.Join(RequirementsGateModes, ", "))
}

// RequirementsGate is what "done" requires of a task's requirements. The zero
// value — and nil — is off.
type RequirementsGate struct {
	// Mode is one of RequirementsGateModes; empty reads as off.
	Mode string `json:"mode"`
	// Assess asks the model about the requirements in the gate's scope that
	// have no tests. Without it they are reported unverified and never keep a
	// task from being done; with it, one the model finds unfulfilled does.
	// Kept while the gate is off, so switching it off and on again does not
	// lose the choice.
	Assess bool `json:"assess,omitempty"`
}

// EffectiveMode is g's mode: off for nil, for an empty mode and for one this
// build does not know — a gate it cannot read is not one it can enforce, and
// the dashboard says so (Validate) rather than guessing a stricter one.
func (g *RequirementsGate) EffectiveMode() string {
	if g == nil {
		return RequirementsGateOff
	}
	switch g.Mode {
	case RequirementsGateLinked, RequirementsGateLinkedMust:
		return g.Mode
	}
	return RequirementsGateOff
}

// Active reports whether g checks anything.
func (g *RequirementsGate) Active() bool { return g.EffectiveMode() != RequirementsGateOff }

// IncludesMust reports whether g checks every approved must requirement as
// well as the task's own.
func (g *RequirementsGate) IncludesMust() bool {
	return g.EffectiveMode() == RequirementsGateLinkedMust
}

// AssessUntested reports whether g asks the model about untested
// requirements.
func (g *RequirementsGate) AssessUntested() bool { return g.Active() && g.Assess }

// Validate reports a mode this build does not know. Nil and empty are off.
func (g *RequirementsGate) Validate() error {
	if g == nil || g.Mode == "" {
		return nil
	}
	if _, err := ParseRequirementsGateMode(g.Mode); err != nil {
		return fmt.Errorf("requirements gate: %w", err)
	}
	return nil
}

// Clone returns an independent copy (nil for nil).
func (g *RequirementsGate) Clone() *RequirementsGate {
	if g == nil {
		return nil
	}
	c := *g
	return &c
}

// Describe says in a few words what "done" requires under g.
func (g *RequirementsGate) Describe() string {
	var s string
	switch g.EffectiveMode() {
	case RequirementsGateLinked:
		s = "its linked requirements pass"
	case RequirementsGateLinkedMust:
		s = "its linked requirements and every approved must requirement pass"
	default:
		return "off"
	}
	if g.Assess {
		s += " (the model assesses untested ones)"
	}
	return s
}

// Outcomes of a requirements gate check.
const (
	// RequirementsMet: nothing in the gate's scope kept the task from being
	// done. Untested requirements may still be unverified.
	RequirementsMet = "met"
	// RequirementsUnmet: a requirement in scope failed its tests (or could
	// not be tested), or the model, asked, found it unfulfilled.
	RequirementsUnmet = "unmet"
)

// Bounds on the record a task keeps of the gate's latest check. The full
// output of every test is in the project's requirement_checks rows; the task
// keeps what its next attempt is told and what its page shows.
const (
	// MaxTaskRequirementsChecked bounds the requirements one record names.
	MaxTaskRequirementsChecked = 50
	// MaxTaskRequirementOutputBytes bounds the output tail kept per test,
	// and only a test that did not pass keeps one.
	MaxTaskRequirementOutputBytes = 4 << 10
	// maxTaskRequirementNoteBytes bounds the record's note.
	maxTaskRequirementNoteBytes = 1000
)

// TaskRequirementsCheck is what the requirements gate found when it last
// checked a task's attempt (Task 20461).
type TaskRequirementsCheck struct {
	// Mode is the gate's mode when it checked.
	Mode string `json:"mode"`
	// Outcome is RequirementsMet or RequirementsUnmet.
	Outcome string `json:"outcome"`
	// RunID names the check's requirement_runs row; its requirement_checks
	// rows carry the same id and the task's.
	RunID string `json:"run_id,omitempty"`
	// Commit is HEAD of the tree the tests ran in, and Dirty reports
	// uncommitted changes in it.
	Commit string `json:"commit,omitempty"`
	Dirty  bool   `json:"dirty,omitempty"`
	// Decision is what the orchestrator did with the check: "met" (the gate
	// let the task through), "requeued" (back to pending) or "failed"
	// (requirements_unmet). Empty until it is applied.
	Decision string `json:"decision,omitempty"`
	// Consecutive is how many attempts in a row, this one included, the gate
	// found unmet: what bounds its re-queues. Zero for a check that was met.
	Consecutive int `json:"consecutive,omitempty"`
	// CheckedAt is when the check ended.
	CheckedAt time.Time `json:"checked_at"`
	// Note says what could not be checked as asked, when anything.
	Note string `json:"note,omitempty"`
	// Requirements are the verdicts, linked requirements first.
	Requirements []RequirementVerdict `json:"requirements,omitempty"`
}

// RequirementVerdict is one requirement's result in a gate check: the result
// as the check's report had it after requirements.Sanitize, and what the gate
// made of it.
type RequirementVerdict struct {
	requirements.Result
	// Title is the requirement's title when it was checked.
	Title string `json:"title,omitempty"`
	// Linked reports that the task implements the requirement; Must that it
	// is a must requirement.
	Linked bool `json:"linked,omitempty"`
	Must   bool `json:"must,omitempty"`
	// Blocking reports that this result kept the task from being done.
	Blocking bool `json:"blocking,omitempty"`
	// Regression reports a requirement that was fulfilled at its last check
	// of the same definition and is not now. Was and WasCommit are that
	// earlier verdict and where it was reached.
	Regression bool   `json:"regression,omitempty"`
	Was        string `json:"was,omitempty"`
	WasCommit  string `json:"was_commit,omitempty"`
}

// Met reports whether the check let the task be done.
func (c *TaskRequirementsCheck) Met() bool { return c != nil && c.Outcome == RequirementsMet }

// Unmet reports whether the check kept the task from being done.
func (c *TaskRequirementsCheck) Unmet() bool { return c != nil && c.Outcome == RequirementsUnmet }

// Blocking returns the verdicts that kept the task from being done.
func (c *TaskRequirementsCheck) Blocking() []RequirementVerdict {
	if c == nil {
		return nil
	}
	var out []RequirementVerdict
	for _, v := range c.Requirements {
		if v.Blocking {
			out = append(out, v)
		}
	}
	return out
}

// Regressions returns the verdicts that are regressions.
func (c *TaskRequirementsCheck) Regressions() []RequirementVerdict {
	if c == nil {
		return nil
	}
	var out []RequirementVerdict
	for _, v := range c.Requirements {
		if v.Regression {
			out = append(out, v)
		}
	}
	return out
}

// Unverified returns the ids of the requirements nothing could verify.
func (c *TaskRequirementsCheck) Unverified() []int {
	if c == nil {
		return nil
	}
	var out []int
	for _, v := range c.Requirements {
		if v.Verdict == requirements.VerdictUnverified {
			out = append(out, v.RequirementID)
		}
	}
	return out
}

// Counts tallies the verdicts.
func (c *TaskRequirementsCheck) Counts() requirements.Counts {
	var n requirements.Counts
	if c == nil {
		return n
	}
	for _, v := range c.Requirements {
		n.Add(v.Verdict)
	}
	return n
}

// Headline renders the record as one line: "Requirements unmet: R-3 failed
// (regression), R-7 failed; R-9 unverified."
func (c *TaskRequirementsCheck) Headline() string {
	if c == nil {
		return ""
	}
	var failed, unverified, passed []string
	for _, v := range c.Requirements {
		key := requirements.Key(v.RequirementID)
		switch {
		case v.Blocking && v.Regression:
			failed = append(failed, key+" "+v.Verdict+" (regression)")
		case v.Blocking:
			failed = append(failed, key+" "+v.Verdict)
		case v.Verdict == requirements.VerdictUnverified:
			unverified = append(unverified, key)
		case v.Verdict == requirements.VerdictFulfilled:
			passed = append(passed, key)
		}
	}
	var b strings.Builder
	if c.Unmet() {
		b.WriteString("Requirements unmet: ")
		b.WriteString(listOrNone(failed))
	} else {
		b.WriteString("Requirements met")
		if len(passed) > 0 {
			b.WriteString(": " + strings.Join(passed, ", ") + " fulfilled")
		}
	}
	if len(unverified) > 0 {
		b.WriteString("; " + strings.Join(unverified, ", ") + " unverified (no tests)")
	}
	if c.Commit != "" {
		short := c.Commit
		if len(short) > 12 {
			short = short[:12]
		}
		b.WriteString(" at " + short)
		if c.Dirty {
			b.WriteString(" (with uncommitted changes)")
		}
	}
	b.WriteString(".")
	return b.String()
}

func listOrNone(items []string) string {
	if len(items) == 0 {
		return "none"
	}
	return strings.Join(items, ", ")
}

// Clone returns an independent copy (nil for nil).
func (c *TaskRequirementsCheck) Clone() *TaskRequirementsCheck {
	if c == nil {
		return nil
	}
	out := *c
	out.Requirements = make([]RequirementVerdict, len(c.Requirements))
	for i, v := range c.Requirements {
		v.Tests = append([]requirements.TestResult(nil), v.Tests...)
		v.Evidence = append([]string(nil), v.Evidence...)
		out.Requirements[i] = v
	}
	if c.Requirements == nil {
		out.Requirements = nil
	}
	return &out
}

// Bound trims the record to its stored sizes in place: at most
// MaxTaskRequirementsChecked requirements, and an output tail of at most
// MaxTaskRequirementOutputBytes for each test that did not pass — none for one
// that did. It is applied where the record is made and again wherever one is
// read from somewhere that is not trusted for size.
func (c *TaskRequirementsCheck) Bound() {
	if c == nil {
		return
	}
	c.Mode = clipRunes(c.Mode, 32)
	c.Outcome = clipRunes(c.Outcome, 16)
	c.RunID = clipRunes(c.RunID, 64)
	c.Commit = requirements.CleanCommit(c.Commit)
	c.Note = clipRunes(c.Note, maxTaskRequirementNoteBytes)
	c.Decision = clipRunes(c.Decision, 16)
	if c.Consecutive < 0 {
		c.Consecutive = 0
	}
	if len(c.Requirements) > MaxTaskRequirementsChecked {
		c.Requirements = c.Requirements[:MaxTaskRequirementsChecked]
	}
	for i := range c.Requirements {
		v := &c.Requirements[i]
		v.Title = clipRunes(v.Title, requirements.MaxTitleRunes)
		v.Was = clipRunes(v.Was, 16)
		v.WasCommit = requirements.CleanCommit(v.WasCommit)
		v.Summary = clipRunes(v.Summary, requirements.MaxRationaleRunes)
		v.Method = clipRunes(v.Method, 16)
		v.Verdict = clipRunes(v.Verdict, 16)
		v.Fingerprint = clipRunes(v.Fingerprint, 128)
		if len(v.Evidence) > requirements.MaxEvidence {
			v.Evidence = v.Evidence[:requirements.MaxEvidence]
		}
		for j := range v.Evidence {
			v.Evidence[j] = clipRunes(v.Evidence[j], requirements.MaxEvidenceRunes)
		}
		if len(v.Tests) > requirements.MaxTests {
			v.Tests = v.Tests[:requirements.MaxTests]
		}
		for j := range v.Tests {
			t := &v.Tests[j]
			t.Name = clipRunes(t.Name, requirements.MaxTestNameRunes)
			t.Command = clipBytes(t.Command, requirements.MaxCommandBytes)
			t.Error = clipRunes(t.Error, requirements.MaxSummaryRunes)
			if t.Outcome == requirements.OutcomePass {
				t.Output, t.Truncated = "", false
				continue
			}
			if len(t.Output) > MaxTaskRequirementOutputBytes {
				t.Output = strings.ToValidUTF8(t.Output[len(t.Output)-MaxTaskRequirementOutputBytes:], "")
				t.Truncated = true
			}
		}
	}
}

// clipRunes cuts s to at most n runes.
func clipRunes(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	r := []rune(s)
	return string(r[:n])
}

// clipBytes cuts s to at most n bytes, on a rune boundary.
func clipBytes(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return strings.ToValidUTF8(s[:n], "")
}
