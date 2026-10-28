package requirements

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Assessment is the model's answer about a requirement with no tests.
type Assessment struct {
	// Verdict is fulfilled, unfulfilled or unknown.
	Verdict   string   `json:"verdict"`
	Rationale string   `json:"rationale"`
	Evidence  []string `json:"evidence,omitempty"`
}

// verdict maps the model's word onto a check's: unknown, or anything else it
// may say, is unverified — the model could not tell, which is not an error of
// the check.
func (a Assessment) verdict() string {
	switch strings.ToLower(strings.TrimSpace(a.Verdict)) {
	case "fulfilled", "fulfiled", "met", "pass", "passed", "yes", "true":
		return VerdictFulfilled
	case "unfulfilled", "not fulfilled", "not_fulfilled", "unmet", "fail", "failed", "no", "false":
		return VerdictUnfulfilled
	}
	return VerdictUnverified
}

// AssessPrompt is the question put to the model about r, a requirement with
// no tests: does the project, as it is in the current directory, fulfil it?
// codeContext, when the model cannot read the tree itself, is what it reads
// instead.
func AssessPrompt(goal string, r Requirement, codeContext string) string {
	var b strings.Builder
	b.WriteString("You are verifying whether a software project fulfils one of its requirements.\n")
	b.WriteString("Examine the project in the current working directory: read its source, its tests and its ")
	b.WriteString("documentation. You may run read-only commands. Do NOT modify, create or delete any file, ")
	b.WriteString("and do not commit or push anything.\n\n")
	if goal = strings.TrimSpace(goal); goal != "" {
		fmt.Fprintf(&b, "## PROJECT GOAL\n%s\n\n", goal)
	}
	fmt.Fprintf(&b, "## REQUIREMENT %s\n%s\n", Key(r.ID), r.Title)
	if r.Description != "" {
		fmt.Fprintf(&b, "\n%s\n", r.Description)
	}
	b.WriteString("\n")
	if codeContext = strings.TrimSpace(codeContext); codeContext != "" {
		b.WriteString("## RELEVANT CODE\n")
		b.WriteString(codeContext)
		b.WriteString("\n\n")
	}
	b.WriteString("## ANSWER\n")
	b.WriteString("Decide from evidence in the code, not from intent. Say \"unknown\" when the code does not ")
	b.WriteString("let you decide either way.\n")
	b.WriteString("Reply with one JSON object and nothing else:\n")
	b.WriteString(`{"verdict": "fulfilled" | "unfulfilled" | "unknown", "rationale": "<two or three sentences>", ` +
		`"evidence": ["<file:line — what it shows>", "..."]}` + "\n")
	return b.String()
}

// ErrNoAssessment reports a model answer holding no assessment.
var ErrNoAssessment = errors.New("the model's answer held no assessment")

// Bounds on reading an answer: only its end, and only so many places in it
// where an object might start, so an answer of a megabyte of braces costs a
// bounded scan rather than one decode per brace over everything after it.
const (
	maxAnswerTail   = 64 << 10
	maxObjectStarts = 512
)

// ParseAssessment reads the model's answer: the JSON object with a verdict
// that is nearest its end, so a model that thinks aloud — or quotes an example
// — before answering is read for its answer.
func ParseAssessment(out string) (Assessment, error) {
	if len(out) > maxAnswerTail {
		out = out[len(out)-maxAnswerTail:]
	}
	starts := 0
	for i := len(out) - 1; i >= 0; i-- {
		if out[i] != '{' {
			continue
		}
		if starts++; starts > maxObjectStarts {
			break
		}
		var a Assessment
		if err := json.NewDecoder(strings.NewReader(out[i:])).Decode(&a); err == nil && strings.TrimSpace(a.Verdict) != "" {
			return a, nil
		}
	}
	return Assessment{}, ErrNoAssessment
}
