// Package requirements describes what a project must keep doing, and checks
// whether it still does (Task 20458).
//
// A requirement is a statement about the project — "the CLI exits non-zero on
// a malformed config", "every API route declares a permission" — with an
// optional list of tests: shell commands, run in the project's tree, whose exit
// status is the evidence. A requirement may have none. Its check is then the
// model's reading of the code (Assess), a person's recorded verdict, or
// nothing, and the report says which.
//
// The package owns the model, its bounds, and the two halves of a check: the
// runner (Check), which executes the tests where it is called, and Sanitize,
// which is the hub's copy of the rules for a report that came back from an
// executor whose cloop it cannot vouch for. The hub never calls Check: a
// requirement's tests run where the project's runs run, dispatched as `cloop
// requirements check --json` to the project's executor. The store is
// pkg/statedb (requirements.go there).
package requirements

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Bounds on what a requirement carries. A requirement is loaded with every
// listing the dashboard renders, and its tests travel to the executor as one
// argument of the command that checks them (Linux caps one at 128 KiB), so
// every field is bounded where it is written and again where it is read back.
const (
	MaxTitleRunes       = 300
	MaxDescriptionRunes = 8000
	MaxTags             = 16
	MaxTagRunes         = 64
	MaxTests            = 16
	MaxTestNameRunes    = 120
	// MaxCommandBytes bounds one test's shell command.
	MaxCommandBytes = 4096
	// MaxRequirements bounds a project's requirements.
	MaxRequirements = 1000
	// MaxActorRunes bounds who created, changed or checked a requirement.
	MaxActorRunes = 200
)

// Test timeouts. A test with no timeout of its own gets DefaultTestTimeout;
// none may ask for more than MaxTestTimeout, which is what keeps a check
// bounded without a deadline of its own.
const (
	DefaultTestTimeout = 10 * time.Minute
	MaxTestTimeout     = 2 * time.Hour
)

// Priorities, MoSCoW without the W: a requirement nobody will do is not one.
const (
	PriorityMust   = "must"
	PriorityShould = "should"
	PriorityCould  = "could"
)

// Priorities lists the priorities in order of weight.
var Priorities = []string{PriorityMust, PriorityShould, PriorityCould}

// ErrInvalid wraps every validation failure, so a caller can answer it as the
// caller's mistake (400) rather than its own.
var ErrInvalid = errors.New("invalid requirement")

// Test is one way of showing a requirement holds: a shell command run in the
// project's root, which passes when it exits 0.
type Test struct {
	// Name labels the test in reports. Optional; the command stands in.
	Name string `json:"name,omitempty"`
	// Command is run with /bin/sh -c in the project's root.
	Command string `json:"command"`
	// TimeoutSeconds bounds one run of the test; 0 is DefaultTestTimeout.
	TimeoutSeconds int `json:"timeout_seconds,omitempty"`
}

// Timeout is how long one run of t may take.
func (t Test) Timeout() time.Duration {
	if t.TimeoutSeconds <= 0 {
		return DefaultTestTimeout
	}
	d := time.Duration(t.TimeoutSeconds) * time.Second
	if d > MaxTestTimeout {
		return MaxTestTimeout
	}
	return d
}

// Label is how a report names t: its name, else its command's first line.
func (t Test) Label() string {
	if t.Name != "" {
		return t.Name
	}
	line, _, _ := strings.Cut(strings.TrimSpace(t.Command), "\n")
	return truncateRunes(line, MaxTestNameRunes)
}

// Requirement is one thing a project must keep doing.
type Requirement struct {
	ID          int       `json:"id"`
	Title       string    `json:"title"`
	Description string    `json:"description,omitempty"`
	Priority    string    `json:"priority,omitempty"`
	Tags        []string  `json:"tags,omitempty"`
	Tests       []Test    `json:"tests,omitempty"`
	CreatedAt   time.Time `json:"created_at,omitzero"`
	UpdatedAt   time.Time `json:"updated_at,omitzero"`
	CreatedBy   string    `json:"created_by,omitempty"`
	UpdatedBy   string    `json:"updated_by,omitempty"`
}

// Spec is what `cloop requirements check --spec` is handed: the requirements
// to check, as the hub has them, and the project's goal for the model. The hub
// sends one rather than letting the executor read its own copy of the project,
// which on a device or a Pod has no requirements in it — and so that what runs
// is exactly what the hub decided to run.
type Spec struct {
	Goal         string        `json:"goal,omitempty"`
	Requirements []Requirement `json:"requirements"`
}

// MaxSpecBytes bounds a spec: it travels as one argument, which Linux caps at
// 128 KiB. MaxEncodedBytes bounds one requirement as a spec carries it, so
// every requirement that can be stored can be sent.
const (
	MaxSpecBytes    = 120 << 10
	MaxEncodedBytes = 64 << 10
)

// EncodeSpec is sp as the hub sends it: JSON without HTML escaping, which
// would make every & in a command six bytes.
func EncodeSpec(sp Spec) ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(sp); err != nil {
		return nil, err
	}
	return bytes.TrimRight(b.Bytes(), "\n"), nil
}

// EncodedSize is how many bytes r takes in a spec.
func (r Requirement) EncodedSize() int {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(r.ForSpec()); err != nil {
		return MaxSpecBytes + 1
	}
	return b.Len() - 1
}

// ParseSpec reads a spec and checks every requirement in it.
func ParseSpec(raw []byte) (Spec, error) {
	var sp Spec
	if len(raw) > MaxSpecBytes {
		return sp, invalid("the spec is %d bytes, more than %d", len(raw), MaxSpecBytes)
	}
	if err := json.Unmarshal(raw, &sp); err != nil {
		return sp, invalid("the spec is not JSON: %v", err)
	}
	if len(sp.Requirements) > MaxRequirements {
		return sp, invalid("the spec names %d requirements, more than %d", len(sp.Requirements), MaxRequirements)
	}
	seen := map[int]bool{}
	for i := range sp.Requirements {
		r := &sp.Requirements[i]
		if r.ID <= 0 || seen[r.ID] {
			return sp, invalid("requirement %d of the spec has no id of its own", i+1)
		}
		seen[r.ID] = true
		if err := r.Normalize(); err != nil {
			return sp, fmt.Errorf("%s: %w", Key(r.ID), err)
		}
	}
	sp.Goal = truncateRunes(strings.TrimSpace(sp.Goal), MaxDescriptionRunes)
	return sp, nil
}

// ForSpec is r as a spec carries it: what a check needs, and nothing else.
func (r Requirement) ForSpec() Requirement {
	return Requirement{ID: r.ID, Title: r.Title, Description: r.Description, Tests: r.Tests}
}

// Key is how a requirement is named to people: R-<id>.
func Key(id int) string { return fmt.Sprintf("R-%d", id) }

// Tested reports whether r has a test to run.
func (r Requirement) Tested() bool { return len(r.Tests) > 0 }

// Normalize trims r's fields and checks them against the bounds, reporting the
// first field that does not fit as an ErrInvalid. Tags are lower-cased and
// de-duplicated; a test's name and command are trimmed. It never truncates:
// a requirement saved shorter than it was written would say something else.
func (r *Requirement) Normalize() error {
	r.Title = strings.TrimSpace(r.Title)
	switch {
	case r.Title == "":
		return invalid("a requirement needs a title")
	case !utf8.ValidString(r.Title) || strings.ContainsAny(r.Title, "\r\n"):
		return invalid("the title must be one line of text")
	case utf8.RuneCountInString(r.Title) > MaxTitleRunes:
		return invalid("the title is longer than %d characters", MaxTitleRunes)
	}
	r.Description = strings.TrimSpace(r.Description)
	if !utf8.ValidString(r.Description) {
		return invalid("the description is not valid text")
	}
	if utf8.RuneCountInString(r.Description) > MaxDescriptionRunes {
		return invalid("the description is longer than %d characters", MaxDescriptionRunes)
	}
	r.Priority = strings.ToLower(strings.TrimSpace(r.Priority))
	if r.Priority != "" && !validPriority(r.Priority) {
		return invalid("priority %q is not one of %s", r.Priority, strings.Join(Priorities, ", "))
	}
	tags, err := normalizeTags(r.Tags)
	if err != nil {
		return err
	}
	r.Tags = tags
	if len(r.Tests) > MaxTests {
		return invalid("a requirement has at most %d tests", MaxTests)
	}
	tests := make([]Test, 0, len(r.Tests))
	for i, t := range r.Tests {
		if err := t.normalize(); err != nil {
			return fmt.Errorf("test %d: %w", i+1, err)
		}
		tests = append(tests, t)
	}
	if len(tests) == 0 {
		tests = nil
	}
	r.Tests = tests
	r.CreatedBy = truncateRunes(strings.TrimSpace(r.CreatedBy), MaxActorRunes)
	r.UpdatedBy = truncateRunes(strings.TrimSpace(r.UpdatedBy), MaxActorRunes)
	if n := r.EncodedSize(); n > MaxEncodedBytes {
		return invalid("the requirement and its tests take %d bytes to send to an executor, more than %d: "+
			"shorten its description or move a long command into a script in the repository", n, MaxEncodedBytes)
	}
	return nil
}

func (t *Test) normalize() error {
	t.Name = strings.TrimSpace(t.Name)
	t.Command = strings.TrimSpace(t.Command)
	switch {
	case t.Command == "":
		return invalid("a test needs a command")
	case len(t.Command) > MaxCommandBytes:
		return invalid("the command is longer than %d bytes", MaxCommandBytes)
	case !utf8.ValidString(t.Command) || strings.ContainsRune(t.Command, 0):
		return invalid("the command is not valid text")
	case !utf8.ValidString(t.Name) || strings.ContainsAny(t.Name, "\r\n"):
		return invalid("the test's name must be one line of text")
	case utf8.RuneCountInString(t.Name) > MaxTestNameRunes:
		return invalid("the test's name is longer than %d characters", MaxTestNameRunes)
	case t.TimeoutSeconds < 0:
		return invalid("a timeout cannot be negative")
	case time.Duration(t.TimeoutSeconds)*time.Second > MaxTestTimeout:
		return invalid("a test may run for at most %s", MaxTestTimeout)
	}
	return nil
}

func validPriority(p string) bool {
	for _, q := range Priorities {
		if p == q {
			return true
		}
	}
	return false
}

func normalizeTags(in []string) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	for _, t := range in {
		t = strings.ToLower(strings.TrimSpace(t))
		if t == "" || seen[t] {
			continue
		}
		if utf8.RuneCountInString(t) > MaxTagRunes {
			return nil, invalid("tag %q is longer than %d characters", truncateRunes(t, MaxTagRunes), MaxTagRunes)
		}
		for _, c := range t {
			if !unicode.IsLetter(c) && !unicode.IsDigit(c) && !strings.ContainsRune("-_.:/", c) {
				return nil, invalid("tag %q may hold only letters, digits and - _ . : /", t)
			}
		}
		seen[t] = true
		out = append(out, t)
	}
	if len(out) > MaxTags {
		return nil, invalid("a requirement has at most %d tags", MaxTags)
	}
	return out, nil
}

// Fingerprint identifies what a verdict about r is a verdict on: its title,
// description and tests. A check records it, and a verdict whose fingerprint
// is not the requirement's current one is about a requirement that has since
// been changed — stale, however recent. Priority and tags are not in it: they
// say how much the requirement matters, not what it is.
func (r Requirement) Fingerprint() string {
	tests := r.Tests
	if tests == nil {
		tests = []Test{}
	}
	b, _ := json.Marshal(struct {
		Title       string `json:"title"`
		Description string `json:"description"`
		Tests       []Test `json:"tests"`
	}{r.Title, r.Description, tests})
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:16])
}

func invalid(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, a...))
}

// truncateRunes cuts s to at most n runes.
func truncateRunes(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	r := []rune(s)
	return string(r[:n])
}
