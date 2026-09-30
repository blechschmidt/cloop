package pm

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/provider"
)

// This file carries the review gate (Task 20357): the optional reviewer a
// project can configure to check each task's changes before cloop pushes or
// merges them, and the record of what that reviewer decided about a task.
//
// The settings live here, beside the plan, rather than in config.yaml because
// they have to travel with the project: a run on a remote executor is seeded
// with the project state and never sees the hub's config.yaml, and a gate
// that silently switched itself off on exactly the executors whose work is
// hardest to inspect afterwards would be worse than no gate.

// Review gate modes: what a review that does not approve does to the task.
const (
	// ReviewModeFix sends the reviewer's findings back to the agent — in the
	// same conversation when the provider can resume one — and reviews the
	// result again, up to MaxFixRounds times. Work the reviewer still does not
	// approve after that is blocked, exactly as in ReviewModeBlock.
	ReviewModeFix = "fix"
	// ReviewModeBlock fails the task at once. Its changes stay where the agent
	// left them and are neither pushed nor merged.
	ReviewModeBlock = "block"
	// ReviewModeAdvisory records the review and publishes regardless.
	ReviewModeAdvisory = "advisory"
)

// ReviewModes lists the valid modes, in the order the UI offers them.
var ReviewModes = []string{ReviewModeFix, ReviewModeBlock, ReviewModeAdvisory}

// Bounds on the review gate settings.
const (
	// DefaultReviewFixRounds is how many times a fix-mode gate sends a task
	// back when MaxFixRounds is unset.
	DefaultReviewFixRounds = 2
	// MaxReviewFixRounds caps MaxFixRounds. Each round is a full agent turn
	// plus a review; past a handful the reviewer and the agent are arguing,
	// and a person should look.
	MaxReviewFixRounds = 5
	// MaxReviewInstructionsBytes caps the operator's extra review criteria,
	// which are sent with every review.
	MaxReviewInstructionsBytes = 4000
)

// reviewProviders are the providers a reviewer may use: the ones the
// dashboard's provider picker offers for the work itself.
var reviewProviders = map[string]bool{
	"claudecode": true, "anthropic": true, "openai": true, "ollama": true,
}

// reviewModelRe bounds a reviewer model name. The value becomes an argument to
// the claude CLI, so a leading "-" — which would be read as a flag — is
// refused along with anything outside the characters model names use
// ("claude-opus-5-5", "gpt-5", "llama3:70b", "claude-sonnet-5[1m]").
var reviewModelRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/@\[\]-]{0,127}$`)

// ReviewGate configures the reviewer that checks a task's changes before cloop
// publishes them. The zero value is a disabled gate.
type ReviewGate struct {
	// Enabled turns the gate on. Everything else is kept while it is off, so
	// switching it off and on again does not lose the reviewer's settings.
	Enabled bool `json:"enabled"`
	// Provider is the reviewer's provider; empty means the project's own.
	Provider string `json:"provider,omitempty"`
	// Model is the reviewer's model; empty means that provider's default —
	// or, when Provider is empty too, the model the project works with.
	Model string `json:"model,omitempty"`
	// Effort is the reviewer's reasoning effort (claudecode only).
	Effort string `json:"effort,omitempty"`
	// Mode is what a review that does not approve does: ReviewModeFix
	// (the default when empty), ReviewModeBlock or ReviewModeAdvisory.
	Mode string `json:"mode,omitempty"`
	// MaxFixRounds bounds how often ReviewModeFix sends a task back.
	// 0 means DefaultReviewFixRounds.
	MaxFixRounds int `json:"max_fix_rounds,omitempty"`
	// Instructions are extra review criteria from the operator, appended to
	// every review ("reject anything that touches the migrations").
	Instructions string `json:"instructions,omitempty"`
}

// Active reports whether g is a gate that reviews. A nil gate is off.
func (g *ReviewGate) Active() bool { return g != nil && g.Enabled }

// EffectiveMode returns the mode in force, applying the default.
func (g *ReviewGate) EffectiveMode() string {
	if g == nil || g.Mode == "" {
		return ReviewModeFix
	}
	return g.Mode
}

// EffectiveFixRounds returns how many times a fix-mode gate sends a task back.
// It is 0 for the other modes, which never do.
func (g *ReviewGate) EffectiveFixRounds() int {
	if g.EffectiveMode() != ReviewModeFix {
		return 0
	}
	if g.MaxFixRounds <= 0 {
		return DefaultReviewFixRounds
	}
	if g.MaxFixRounds > MaxReviewFixRounds {
		return MaxReviewFixRounds
	}
	return g.MaxFixRounds
}

// Clone returns an independent copy (nil for nil).
func (g *ReviewGate) Clone() *ReviewGate {
	if g == nil {
		return nil
	}
	c := *g
	return &c
}

// Normalize trims and lower-cases the enumerated fields in place, so a value
// typed as " Anthropic " is stored the way it is compared.
func (g *ReviewGate) Normalize() {
	if g == nil {
		return
	}
	g.Provider = strings.ToLower(strings.TrimSpace(g.Provider))
	g.Model = strings.TrimSpace(g.Model)
	g.Effort = strings.ToLower(strings.TrimSpace(g.Effort))
	g.Mode = strings.ToLower(strings.TrimSpace(g.Mode))
	g.Instructions = strings.TrimSpace(g.Instructions)
}

// Validate reports the first setting that cannot be used. It checks settings
// even while the gate is disabled: a stored value is one enabling the gate
// will start using, and the moment to refuse it is when it is typed.
func (g *ReviewGate) Validate() error {
	if g == nil {
		return nil
	}
	if g.Provider != "" && !reviewProviders[g.Provider] {
		return fmt.Errorf("reviewer provider %q is not supported (use claudecode, anthropic, openai, ollama, or leave it empty for the project's provider)", g.Provider)
	}
	if g.Model != "" && !reviewModelRe.MatchString(g.Model) {
		return fmt.Errorf("reviewer model %q is not a model name (letters, digits and . _ : / @ [ ] -, up to 128 characters, not starting with a symbol)", g.Model)
	}
	if !provider.ValidEffort(g.Effort) {
		return fmt.Errorf("reviewer effort %q is not one of %s", g.Effort, strings.Join(provider.EffortLevels, ", "))
	}
	switch g.Mode {
	case "", ReviewModeFix, ReviewModeBlock, ReviewModeAdvisory:
	default:
		return fmt.Errorf("review mode %q is not one of %s", g.Mode, strings.Join(ReviewModes, ", "))
	}
	if g.MaxFixRounds < 0 || g.MaxFixRounds > MaxReviewFixRounds {
		return fmt.Errorf("max fix rounds must be between 0 (default %d) and %d", DefaultReviewFixRounds, MaxReviewFixRounds)
	}
	if len(g.Instructions) > MaxReviewInstructionsBytes {
		return fmt.Errorf("review instructions are %d bytes; at most %d are allowed", len(g.Instructions), MaxReviewInstructionsBytes)
	}
	return nil
}

// ReviewVerdict is the outcome of a task's review.
type ReviewVerdict string

const (
	// ReviewApproved means the reviewer approved the changes.
	ReviewApproved ReviewVerdict = "approved"
	// ReviewChangesRequested means the reviewer found problems that should be
	// fixed before the changes are published.
	ReviewChangesRequested ReviewVerdict = "changes_requested"
	// ReviewUnavailable means no verdict could be reached: the reviewer could
	// not be built or called, or answered with something that is not a
	// verdict. The gate fails closed on it, as it does on a rejection.
	ReviewUnavailable ReviewVerdict = "unavailable"
	// ReviewNothing means the task changed nothing in any repository, so
	// there was nothing to review and nothing to publish.
	ReviewNothing ReviewVerdict = "no_changes"
)

// Bounds on a stored review record. The record is on every task row the
// dashboard renders, so it is a summary; the full reviewer output is in the
// provider call log.
const (
	MaxReviewFindings      = 20
	maxReviewSummaryBytes  = 2000
	maxReviewFindingBytes  = 600
	maxReviewPublishDetail = 400
)

// TaskReview records what the review gate decided about a task, and what was
// published because of it.
type TaskReview struct {
	// Verdict is the final outcome across every round.
	Verdict ReviewVerdict `json:"verdict"`
	// Mode is the gate's mode when the review ran.
	Mode string `json:"mode"`
	// Blocked reports that the gate stopped the task's changes from being
	// published: the verdict was not an approval and the mode was not
	// advisory.
	Blocked bool `json:"blocked,omitempty"`
	// Provider and Model name the reviewer.
	Provider string `json:"provider,omitempty"`
	Model    string `json:"model,omitempty"`
	// Rounds is how many reviews ran; FixRounds how often the agent was sent
	// back with findings.
	Rounds    int `json:"rounds"`
	FixRounds int `json:"fix_rounds,omitempty"`
	// Summary is the reviewer's one-paragraph assessment of the last round.
	Summary string `json:"summary,omitempty"`
	// Findings are the last round's findings, most severe first.
	Findings []ReviewFinding `json:"findings,omitempty"`
	// Error says why no verdict was reached (ReviewUnavailable).
	Error string `json:"error,omitempty"`
	// Repos describes what the last round reviewed, per repository.
	Repos []ReviewedRepo `json:"repos,omitempty"`
	// Published records each push the agent attempted while the gate held it,
	// and what became of it.
	Published []ReviewPublish `json:"published,omitempty"`
	// ReviewedAt is when the last round finished.
	ReviewedAt time.Time `json:"reviewed_at"`
}

// ReviewFinding is one problem the reviewer reported.
type ReviewFinding struct {
	// Severity is "blocker", "major", "minor" or "nit".
	Severity string `json:"severity"`
	File     string `json:"file,omitempty"`
	Line     int    `json:"line,omitempty"`
	Title    string `json:"title"`
	Detail   string `json:"detail,omitempty"`
}

// ReviewedRepo describes the changes one repository contributed to a review.
type ReviewedRepo struct {
	// Path is the repository's directory relative to the project ("." for
	// the project's own repository).
	Path string `json:"path"`
	// Base and Head are the commits the diff was taken between; the working
	// tree's uncommitted changes were included on top of Head.
	Base string `json:"base,omitempty"`
	Head string `json:"head,omitempty"`
	// Files, Insertions and Deletions summarise the diff.
	Files      int `json:"files"`
	Insertions int `json:"insertions,omitempty"`
	Deletions  int `json:"deletions,omitempty"`
	// Commits is how many commits Base..Head holds.
	Commits int `json:"commits,omitempty"`
	// Uncommitted reports that the working tree held changes not in Head.
	Uncommitted bool `json:"uncommitted,omitempty"`
	// Truncated reports that the diff was cut to fit the review prompt.
	Truncated bool `json:"truncated,omitempty"`
}

// Outcomes of a held push.
const (
	// PublishPushed: cloop pushed it after the reviewer approved.
	PublishPushed = "pushed"
	// PublishWithheld: the reviewer did not approve, so it was not pushed.
	PublishWithheld = "withheld"
	// PublishRefused: approved, but the push would have sent commits the
	// reviewer never saw, so cloop did not send it.
	PublishRefused = "refused"
	// PublishFailed: cloop tried to push it and git failed.
	PublishFailed = "failed"
)

// ReviewPublish is one push the gate held, and its fate.
type ReviewPublish struct {
	Repo    string `json:"repo"`
	Remote  string `json:"remote"`
	Ref     string `json:"ref"`
	Commit  string `json:"commit,omitempty"`
	Outcome string `json:"outcome"`
	Detail  string `json:"detail,omitempty"`
}

// Clone returns a deep copy (nil for nil).
func (r *TaskReview) Clone() *TaskReview {
	if r == nil {
		return nil
	}
	c := *r
	c.Findings = append([]ReviewFinding(nil), r.Findings...)
	c.Repos = append([]ReviewedRepo(nil), r.Repos...)
	c.Published = append([]ReviewPublish(nil), r.Published...)
	return &c
}

// ValidVerdict reports whether v is a verdict this build knows.
func ValidVerdict(v ReviewVerdict) bool {
	switch v {
	case ReviewApproved, ReviewChangesRequested, ReviewUnavailable, ReviewNothing:
		return true
	}
	return false
}

// Approved reports whether the review let the task's changes through: an
// approval, a task with nothing to review, or any verdict in advisory mode.
func (r *TaskReview) Approved() bool {
	if r == nil {
		return true
	}
	return !r.Blocked
}

// Bound trims the free-text fields to their stored sizes in place. The
// reviewer is a model and its output is untrusted in size.
func (r *TaskReview) Bound() {
	if r == nil {
		return
	}
	r.Summary = clipReview(r.Summary, maxReviewSummaryBytes)
	r.Error = clipReview(r.Error, maxReviewSummaryBytes)
	if len(r.Findings) > MaxReviewFindings {
		r.Findings = r.Findings[:MaxReviewFindings]
	}
	for i := range r.Findings {
		f := &r.Findings[i]
		f.Severity = clipReview(f.Severity, 16)
		f.File = clipReview(f.File, 300)
		f.Title = clipReview(f.Title, 300)
		f.Detail = clipReview(f.Detail, maxReviewFindingBytes)
		if f.Line < 0 {
			f.Line = 0
		}
	}
	for i := range r.Published {
		r.Published[i].Detail = clipReview(r.Published[i].Detail, maxReviewPublishDetail)
	}
}

// Headline renders the review as one line for annotations, logs and events.
func (r *TaskReview) Headline() string {
	if r == nil {
		return ""
	}
	who := r.Model
	if who == "" {
		who = r.Provider
	}
	if who != "" {
		who = " by " + who
	}
	rounds := ""
	if r.FixRounds > 0 {
		rounds = fmt.Sprintf(" after %d fix round(s)", r.FixRounds)
	}
	switch r.Verdict {
	case ReviewApproved:
		return "Review gate: approved" + who + rounds + "."
	case ReviewNothing:
		return "Review gate: nothing to review — the task changed no repository."
	case ReviewUnavailable:
		msg := "Review gate: no verdict" + who
		if r.Error != "" {
			msg += " — " + r.Error
		}
		if r.Blocked {
			msg += " (failing closed: nothing was published)"
		}
		return msg + "."
	default:
		msg := fmt.Sprintf("Review gate: changes requested%s%s (%d finding(s))", who, rounds, len(r.Findings))
		if r.Blocked {
			msg += " — not published"
		} else {
			msg += " — published anyway (advisory)"
		}
		return msg + "."
	}
}

// Diagnosis renders the review for Task.FailureDiagnosis when the gate
// blocked the task: what to fix, in the reviewer's words.
func (r *TaskReview) Diagnosis() string {
	if r == nil {
		return ""
	}
	var b strings.Builder
	b.WriteString(r.Headline())
	if r.Summary != "" {
		b.WriteString("\n")
		b.WriteString(r.Summary)
	}
	for _, f := range r.Findings {
		b.WriteString("\n- [")
		b.WriteString(f.Severity)
		b.WriteString("] ")
		if f.File != "" {
			b.WriteString(f.File)
			if f.Line > 0 {
				fmt.Fprintf(&b, ":%d", f.Line)
			}
			b.WriteString(": ")
		}
		b.WriteString(f.Title)
	}
	return clipReview(b.String(), 4000)
}

// clipReview cuts s to at most n bytes on a rune boundary.
func clipReview(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	cut := n
	for cut > 0 && !utf8RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "…"
}

func utf8RuneStart(b byte) bool { return b&0xC0 != 0x80 }
