package reviewgate

import (
	"encoding/json"
	"errors"
	"regexp"
	"sort"
	"strings"

	"github.com/blechschmidt/cloop/pkg/pm"
)

// Verdict is one review round's decision.
type Verdict struct {
	Approved bool
	Summary  string
	Findings []pm.ReviewFinding
}

// ErrNoVerdict is returned when a reviewer's answer contains no verdict.
var ErrNoVerdict = errors.New("the reviewer's answer contained no verdict")

// rawVerdict is the JSON the prompt asks for. Field types are loose on
// purpose — a model that writes "line": "12" has still answered.
type rawVerdict struct {
	Verdict  string            `json:"verdict"`
	Summary  string            `json:"summary"`
	Findings []json.RawMessage `json:"findings"`
}

type rawFinding struct {
	Severity string          `json:"severity"`
	File     string          `json:"file"`
	Line     json.RawMessage `json:"line"`
	Title    string          `json:"title"`
	Detail   string          `json:"detail"`
}

// verdictLineRe is the fallback for a reviewer that answered in prose: a line
// that states the verdict outright.
var verdictLineRe = regexp.MustCompile(`(?im)^\W*verdict\W*[:=]\W*(approve[d]?|request[_ ]changes|changes[_ ]requested|reject(?:ed)?|pass|fail)\b`)

// ParseVerdict reads a reviewer's answer.
//
// It fails closed. An answer that states no verdict is an error, never an
// approval; and an "approve" that lists a blocker or major finding is read as
// a request for changes, because the prompt defines approval as having none —
// a reviewer contradicting itself does not get the benefit of the doubt.
func ParseVerdict(output string) (*Verdict, error) {
	for _, cand := range jsonObjects(output) {
		var rv rawVerdict
		if json.Unmarshal([]byte(cand), &rv) != nil {
			continue
		}
		approved, ok := normalizeVerdict(rv.Verdict)
		if !ok {
			continue
		}
		v := &Verdict{Approved: approved, Summary: strings.TrimSpace(rv.Summary)}
		for _, rf := range rv.Findings {
			if f, ok := parseFinding(rf); ok {
				v.Findings = append(v.Findings, f)
			}
		}
		finish(v)
		return v, nil
	}
	// The prose fallback is for a reviewer that ignored the format, not for
	// one whose JSON was cut off: an answer that began the object and never
	// finished it may have lost its findings, so it is not a verdict.
	if strings.Contains(output, `"verdict"`) {
		return nil, ErrNoVerdict
	}
	if m := verdictLineRe.FindStringSubmatch(output); m != nil {
		approved, _ := normalizeVerdict(m[1])
		v := &Verdict{Approved: approved, Summary: clip(strings.TrimSpace(output), 1500)}
		finish(v)
		return v, nil
	}
	return nil, ErrNoVerdict
}

// finish sorts the findings most severe first, bounds them, and applies the
// contradiction rule.
func finish(v *Verdict) {
	sort.SliceStable(v.Findings, func(i, j int) bool {
		return severityRank(v.Findings[i].Severity) < severityRank(v.Findings[j].Severity)
	})
	if len(v.Findings) > pm.MaxReviewFindings {
		v.Findings = v.Findings[:pm.MaxReviewFindings]
	}
	if v.Approved {
		for _, f := range v.Findings {
			if f.Severity == "blocker" || f.Severity == "major" {
				v.Approved = false
				break
			}
		}
	}
}

func normalizeVerdict(s string) (approved, ok bool) {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.NewReplacer(" ", "_", "-", "_").Replace(s)
	switch s {
	case "approve", "approved", "pass", "passed", "lgtm", "accept", "accepted":
		return true, true
	case "request_changes", "changes_requested", "request_change", "reject", "rejected", "fail", "failed", "block", "blocked":
		return false, true
	}
	return false, false
}

func parseFinding(raw json.RawMessage) (pm.ReviewFinding, bool) {
	var rf rawFinding
	if json.Unmarshal(raw, &rf) != nil {
		// A bare string is still a finding.
		var s string
		if json.Unmarshal(raw, &s) != nil || strings.TrimSpace(s) == "" {
			return pm.ReviewFinding{}, false
		}
		return pm.ReviewFinding{Severity: "major", Title: clip(strings.TrimSpace(s), 300)}, true
	}
	f := pm.ReviewFinding{
		Severity: normalizeSeverity(rf.Severity),
		File:     strings.TrimSpace(rf.File),
		Title:    strings.TrimSpace(rf.Title),
		Detail:   strings.TrimSpace(rf.Detail),
	}
	if f.Title == "" {
		f.Title = clip(f.Detail, 200)
	}
	if f.Title == "" {
		return pm.ReviewFinding{}, false
	}
	var n json.Number
	if json.Unmarshal(rf.Line, &n) == nil {
		if i, err := n.Int64(); err == nil && i > 0 && i < 1<<31 {
			f.Line = int(i)
		}
	} else {
		var s string
		if json.Unmarshal(rf.Line, &s) == nil {
			if i, err := json.Number(strings.TrimSpace(s)).Int64(); err == nil && i > 0 && i < 1<<31 {
				f.Line = int(i)
			}
		}
	}
	return f, true
}

// normalizeSeverity maps the vocabularies models use onto the four the gate
// records. An unrecognised severity is major: when a reviewer's severity
// cannot be read, it is safer to treat the finding as one that matters.
func normalizeSeverity(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "blocker", "critical", "severe", "error", "security":
		return "blocker"
	case "major", "high", "important", "bug":
		return "major"
	case "minor", "medium", "moderate", "warning", "low":
		return "minor"
	case "nit", "nitpick", "trivial", "info", "suggestion", "style", "optional":
		return "nit"
	}
	return "major"
}

func severityRank(s string) int {
	switch s {
	case "blocker":
		return 0
	case "major":
		return 1
	case "minor":
		return 2
	}
	return 3
}

// jsonObjects returns every balanced {...} span in s that begins at a
// top-level brace, last first: a model that thinks aloud before answering
// puts its answer at the end.
func jsonObjects(s string) []string {
	var spans []string
	depth, start := 0, -1
	inString, escaped := false, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if inString {
			switch {
			case escaped:
				escaped = false
			case c == '\\':
				escaped = true
			case c == '"':
				inString = false
			}
			continue
		}
		switch c {
		case '"':
			if depth > 0 {
				inString = true
			}
		case '{':
			if depth == 0 {
				start = i
			}
			depth++
		case '}':
			if depth > 0 {
				depth--
				if depth == 0 && start >= 0 {
					spans = append(spans, s[start:i+1])
					start = -1
				}
			}
		}
	}
	for i, j := 0, len(spans)-1; i < j; i, j = i+1, j-1 {
		spans[i], spans[j] = spans[j], spans[i]
	}
	return spans
}
