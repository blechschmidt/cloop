package orchestrator

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// This file implements the "aborted" task outcome (Task 20211).
//
// The orchestrator used to infer success from the agent process exiting: the
// `default:` arm of the signal switch promoted any unsignalled output to
// TaskDone. That turned every provider refusal into a completed task. Fourteen
// tasks in this project's own ledger are recorded as done whose entire stored
// summary is a provider error — "You've hit your limit · resets 2:50pm (UTC)",
// "You've hit your org's monthly usage limit", or the harness declining to run
// --dangerously-skip-permissions as root. Four of them left the working tree
// broken, and auto-evolve went on to plan follow-up work on the belief that
// they had shipped.
//
// An abort is not a fourth task status. A failed task is a judgement about the
// work; an aborted one is the absence of any work to judge, so it resets to
// pending and is recorded as its own event. The distinction matters because
// failed tasks are terminal in the plan's accounting while aborted ones must
// stay visibly retryable.

// AbortClass names why a run produced no usable work.
type AbortClass string

const (
	// AbortUsageLimit is a subscription or rate window the caller has
	// exhausted. These carry a reset time and are retryable by waiting.
	AbortUsageLimit AbortClass = "usage_limit"
	// AbortQuotaExceeded is a hard billing or organisation quota. Waiting
	// out the current window does not help; a human has to raise the cap.
	AbortQuotaExceeded AbortClass = "quota_exceeded"
	// AbortAuth is a credential the provider rejected.
	AbortAuth AbortClass = "auth_refused"
	// AbortHarnessRefusal is the agent harness declining to start at all.
	AbortHarnessRefusal AbortClass = "harness_refused"
	// AbortEmptyOutput is a provider that returned successfully with nothing
	// in it.
	AbortEmptyOutput AbortClass = "empty_output"
	// AbortZeroArtifact is a run whose persisted artifact is zero bytes.
	AbortZeroArtifact AbortClass = "zero_artifact"
	// AbortNoEvidence is a run that left no diff and no artifact behind and
	// never signalled TASK_DONE — nothing to show it did anything.
	AbortNoEvidence AbortClass = "no_evidence"
)

// Retryable reports whether waiting is likely to make the next attempt
// succeed. Quota, auth and harness refusals need an operator, so the run
// should stop rather than burn the remaining tasks against the same wall.
func (c AbortClass) Retryable() bool {
	switch c {
	case AbortQuotaExceeded, AbortAuth, AbortHarnessRefusal:
		return false
	default:
		return true
	}
}

// Abort describes one aborted run.
type Abort struct {
	Class AbortClass
	// Reason is operator-facing prose naming what the provider said.
	Reason string
	// Evidence is the matched excerpt of the agent's output, so the event
	// journal records what was actually seen rather than our paraphrase.
	Evidence string
	// RetryAfter is when the limit lifts, when the message says so. Zero
	// otherwise.
	RetryAfter time.Time
}

func (a Abort) String() string {
	if a.RetryAfter.IsZero() {
		return fmt.Sprintf("%s: %s", a.Class, a.Reason)
	}
	return fmt.Sprintf("%s: %s (retry after %s)", a.Class, a.Reason,
		a.RetryAfter.UTC().Format(time.RFC1123))
}

// abortShortOutput bounds what counts as "the message is the whole response".
// Every corrupted summary in the ledger is a single line under 80 bytes; the
// margin is for harnesses that wrap a refusal in a little framing.
const abortShortOutput = 2000

// abortTailLines is how far back from the end a long response is scanned,
// matching pm.CheckTaskSignal's convention: a real refusal is the last thing
// an agent says, and scanning the whole body would trip on any transcript
// that merely discusses rate limits — including this project's own tasks
// about rate limiting.
const abortTailLines = 5

// abortPattern is one recognised refusal. Matching is on a lowercased scan
// region, so needles must be lowercase.
type abortPattern struct {
	class  AbortClass
	needle string
	reason string
	// wholeOnly restricts the pattern to responses that are *entirely* the
	// message. Harness refusals happen before the agent produces anything,
	// so they are never a postscript to real work — and their needles
	// ("command not found") are common enough in genuine transcripts that
	// tail matching alone would misfire.
	wholeOnly bool
}

// abortPatterns is scanned in order, so specific entries precede general ones:
// "hit your org's monthly usage limit" is a quota, not the retryable
// five-hour window that the broader "usage limit" needle would classify it as.
var abortPatterns = []abortPattern{
	// --- Hard quotas: waiting does not help. ---
	{class: AbortQuotaExceeded, needle: "org's monthly usage limit", reason: "organisation monthly usage limit reached"},
	{class: AbortQuotaExceeded, needle: "org monthly usage limit", reason: "organisation monthly usage limit reached"},
	{class: AbortQuotaExceeded, needle: "monthly usage limit", reason: "monthly usage limit reached"},
	{class: AbortQuotaExceeded, needle: "credit balance is too low", reason: "provider credit balance exhausted"},
	{class: AbortQuotaExceeded, needle: "insufficient_quota", reason: "provider reported insufficient quota"},
	{class: AbortQuotaExceeded, needle: "exceeded your current quota", reason: "provider quota exceeded"},
	{class: AbortQuotaExceeded, needle: "quota exceeded", reason: "provider quota exceeded"},
	{class: AbortQuotaExceeded, needle: "billing_hard_limit_reached", reason: "provider billing limit reached"},

	// --- Usage windows: retryable once the window rolls over. ---
	{class: AbortUsageLimit, needle: "hit your weekly limit", reason: "weekly subscription limit reached"},
	{class: AbortUsageLimit, needle: "hit your 5-hour limit", reason: "five-hour subscription limit reached"},
	{class: AbortUsageLimit, needle: "hit your usage limit", reason: "subscription usage limit reached"},
	{class: AbortUsageLimit, needle: "hit your limit", reason: "subscription limit reached"},
	{class: AbortUsageLimit, needle: "usage limit reached", reason: "subscription usage limit reached"},
	{class: AbortUsageLimit, needle: "rate limit exceeded", reason: "provider rate limit exceeded"},
	{class: AbortUsageLimit, needle: "rate_limit_error", reason: "provider rate limit exceeded"},
	{class: AbortUsageLimit, needle: "too many requests", reason: "provider rate limit exceeded"},
	{class: AbortUsageLimit, needle: "overloaded_error", reason: "provider overloaded"},

	// --- Credentials. ---
	{class: AbortAuth, needle: "authentication_error", reason: "provider rejected the credentials"},
	{class: AbortAuth, needle: "invalid api key", reason: "provider rejected the API key"},
	{class: AbortAuth, needle: "invalid x-api-key", reason: "provider rejected the API key"},
	{class: AbortAuth, needle: "invalid bearer token", reason: "provider rejected the bearer token"},
	{class: AbortAuth, needle: "oauth token has expired", reason: "OAuth token expired — re-authenticate"},
	{class: AbortAuth, needle: "oauth authentication is currently not supported", reason: "provider refused OAuth authentication"},
	{class: AbortAuth, needle: "please run /login", reason: "harness requires re-authentication"},
	{class: AbortAuth, needle: "invalid_api_key", reason: "provider rejected the API key"},
	{class: AbortAuth, needle: "401 unauthorized", reason: "provider returned 401 Unauthorized"},
	{class: AbortAuth, needle: "403 forbidden", reason: "provider returned 403 Forbidden"},

	// --- Harness refused to start. ---
	{class: AbortHarnessRefusal, needle: "cannot be used with root/sudo", reason: "harness refused to run under root/sudo", wholeOnly: true},
	{class: AbortHarnessRefusal, needle: "dangerously-skip-permissions cannot be used", reason: "harness refused --dangerously-skip-permissions", wholeOnly: true},
	{class: AbortHarnessRefusal, needle: "command not found", reason: "agent harness binary not found", wholeOnly: true},
	{class: AbortHarnessRefusal, needle: "executable file not found", reason: "agent harness binary not found", wholeOnly: true},
	{class: AbortHarnessRefusal, needle: "no such file or directory", reason: "agent harness could not start", wholeOnly: true},
}

// ClassifyAbort decides whether an agent's output is a provider or harness
// refusal rather than work. It never inspects a response that signalled
// TASK_DONE — callers must check the signal first, because a completed task is
// allowed to *discuss* rate limits (several in this very project do).
func ClassifyAbort(output string) (Abort, bool) {
	return classifyAbortAt(output, time.Now())
}

func classifyAbortAt(output string, now time.Time) (Abort, bool) {
	trimmed := strings.TrimSpace(output)
	if trimmed == "" {
		return Abort{
			Class:  AbortEmptyOutput,
			Reason: "provider returned empty output",
		}, true
	}

	whole := len(trimmed) <= abortShortOutput
	region := trimmed
	if !whole {
		region = tailLines(trimmed, abortTailLines)
	}
	lower := strings.ToLower(region)

	for _, p := range abortPatterns {
		if p.wholeOnly && !whole {
			continue
		}
		if !strings.Contains(lower, p.needle) {
			continue
		}
		ab := Abort{
			Class:    p.class,
			Reason:   p.reason,
			Evidence: excerpt(region, p.needle),
		}
		// Only usage windows publish a reset time; a quota message that
		// happens to contain a date is not a window that will reopen.
		if p.class == AbortUsageLimit {
			if t, ok := parseResetTime(region, now); ok {
				ab.RetryAfter = t
			}
		}
		return ab, true
	}
	return Abort{}, false
}

// tailLines returns the last n non-discarded lines of s.
func tailLines(s string, n int) string {
	lines := strings.Split(s, "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

// excerpt returns the line containing needle, trimmed and bounded, so the
// event journal records the provider's own words.
func excerpt(region, needle string) string {
	for _, line := range strings.Split(region, "\n") {
		if strings.Contains(strings.ToLower(line), needle) {
			return truncate(strings.TrimSpace(line), 200)
		}
	}
	return truncate(strings.TrimSpace(region), 200)
}

// resetTimeRe matches the reset clause of a usage-limit message. The observed
// shapes are "resets 2:50pm (UTC)", "resets 10pm (UTC)" and
// "resets Aug 28, 10pm (UTC)"; the optional leading month/day group covers the
// third without requiring a separate pattern.
var resetTimeRe = regexp.MustCompile(
	`(?i)resets?\s+(?:at\s+)?(?:([a-z]{3,9})\.?\s+(\d{1,2})(?:st|nd|rd|th)?,?\s+)?(\d{1,2})(?::(\d{2}))?\s*(am|pm)?`)

var monthByPrefix = map[string]time.Month{
	"jan": time.January, "feb": time.February, "mar": time.March,
	"apr": time.April, "may": time.May, "jun": time.June,
	"jul": time.July, "aug": time.August, "sep": time.September,
	"oct": time.October, "nov": time.November, "dec": time.December,
}

// parseResetTime extracts when a usage window reopens. It returns false
// whenever the message does not carry an unambiguous time — a wrong guess
// would either hot-loop against the wall or park the run for hours, and
// falling back to the caller's default backoff is better than either.
func parseResetTime(msg string, now time.Time) (time.Time, bool) {
	m := resetTimeRe.FindStringSubmatch(msg)
	if m == nil {
		return time.Time{}, false
	}
	monthStr, dayStr, hourStr, minStr, ampm := m[1], m[2], m[3], m[4], strings.ToLower(m[5])

	hour, err := strconv.Atoi(hourStr)
	if err != nil {
		return time.Time{}, false
	}
	minute := 0
	if minStr != "" {
		if minute, err = strconv.Atoi(minStr); err != nil {
			return time.Time{}, false
		}
	}
	switch ampm {
	case "am":
		if hour == 12 {
			hour = 0
		}
	case "pm":
		if hour != 12 {
			hour += 12
		}
	case "":
		// A bare hour is already 24-hour; anything above 23 is not a time.
	}
	if hour > 23 || minute > 59 {
		return time.Time{}, false
	}

	// "(UTC)" is what the harness actually prints. Without it we cannot know
	// the provider's zone, and assuming the hub's would silently shift the
	// wait by hours, so treat the timestamp as UTC either way and let the
	// caller's ceiling bound the damage.
	loc := time.UTC
	nowIn := now.In(loc)

	if monthStr != "" && dayStr != "" {
		month, ok := monthByPrefix[strings.ToLower(monthStr)[:3]]
		if !ok {
			return time.Time{}, false
		}
		day, err := strconv.Atoi(dayStr)
		if err != nil || day < 1 || day > 31 {
			return time.Time{}, false
		}
		t := time.Date(nowIn.Year(), month, day, hour, minute, 0, 0, loc)
		// A date that already passed by more than a month is last year's
		// rendering of next year's reset (a December message naming January).
		if t.Before(nowIn.Add(-31 * 24 * time.Hour)) {
			t = t.AddDate(1, 0, 0)
		}
		return t, true
	}

	// Time only: the next occurrence of that clock time.
	t := time.Date(nowIn.Year(), nowIn.Month(), nowIn.Day(), hour, minute, 0, 0, loc)
	if !t.After(nowIn) {
		t = t.AddDate(0, 0, 1)
	}
	return t, true
}

// CompletionEvidence is what a run left behind, and is the only thing that may
// promote an unsignalled task to done.
type CompletionEvidence struct {
	// Summary is the agent's response.
	Summary string
	// Diff reports whether the repository changed while the task ran.
	Diff bool
	// ArtifactBytes is the size of the persisted artifact. For a run whose
	// artifact has not been written yet this is the length of the output
	// that is about to become one.
	ArtifactBytes int64
}

// Positive implements the completion rule: a task without a TASK_DONE signal
// reaches done only on a non-empty summary plus a non-empty diff or artifact.
func (e CompletionEvidence) Positive() bool {
	if strings.TrimSpace(e.Summary) == "" {
		return false
	}
	return e.Diff || e.ArtifactBytes > 0
}

// artifactSize returns the size of an already-persisted artifact, or -1 when
// there is no artifact to measure. Paths are resolved relative to workDir the
// same way the rest of the orchestrator resolves them.
func artifactSize(workDir, artifactPath string) int64 {
	if artifactPath == "" {
		return -1
	}
	p := artifactPath
	if !filepath.IsAbs(p) {
		p = filepath.Join(workDir, p)
	}
	fi, err := os.Stat(p)
	if err != nil {
		return -1
	}
	return fi.Size()
}

// decideUnsignalled returns the abort for a run that produced no TASK_*
// signal, or ok=false when the run may be accepted as implicitly done.
//
// It is the single place that answers "may this become done?", shared by the
// sequential and parallel loops so the two cannot drift apart — they already
// had independently written `default:` arms, which is how the parallel path
// acquired the same fail-open bug as the sequential one.
//
// workDir and artifactPath let it see an artifact that a previous phase
// already persisted; output is what is about to be persisted if none was. A
// zero-byte artifact on disk outranks the output: it means the run was
// recorded, and recorded nothing.
func decideUnsignalled(workDir, artifactPath, output string, diff bool) (Abort, bool) {
	if ab, ok := ClassifyAbort(output); ok {
		return ab, true
	}

	size := artifactSize(workDir, artifactPath)
	if size == 0 {
		return Abort{
			Class:    AbortZeroArtifact,
			Reason:   "run produced a zero-byte artifact",
			Evidence: artifactPath,
		}, true
	}
	if size < 0 {
		// No artifact on disk yet: the output is what will become one.
		size = int64(len(strings.TrimSpace(output)))
	}

	ev := CompletionEvidence{Summary: output, Diff: diff, ArtifactBytes: size}
	if ev.Positive() {
		return Abort{}, false
	}
	return Abort{
		Class:  AbortNoEvidence,
		Reason: "no TASK_DONE signal and no diff or artifact to show for the run",
	}, true
}
