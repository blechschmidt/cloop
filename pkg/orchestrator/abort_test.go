package orchestrator

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The strings in this file are verbatim from cloop's own corrupted ledger —
// the fourteen tasks recorded as done whose entire stored summary is a
// provider or harness error. They are the regression corpus: if the classifier
// stops recognising one of them, the orchestrator goes back to recording that
// refusal as completed work.
const (
	limitResetAfternoon = "You've hit your limit · resets 2:50pm (UTC)"                                                  // tasks 193–197
	limitResetDashed    = "You have hit your limit - resets 2:50pm (UTC)"                                                // same, ASCII rendering
	orgMonthlyQuota     = "You've hit your org's monthly usage limit"                                                    // tasks 20103–20105
	weeklyLimitEvening  = "You've hit your weekly limit · resets 10pm (UTC)"                                             // task 20160
	weeklyLimitDated    = "You've hit your weekly limit · resets Aug 28, 10pm (UTC)"                                     // tasks 20198–20201
	harnessRootRefusal  = "--dangerously-skip-permissions cannot be used with root/sudo privileges for security reasons" // task 20015
)

func TestClassifyAbort(t *testing.T) {
	tests := []struct {
		name      string
		output    string
		wantOK    bool
		wantClass AbortClass
	}{
		// --- The real ledger corpus. ---
		{"ledger: hit your limit with reset", limitResetAfternoon, true, AbortUsageLimit},
		{"ledger: hit your limit, ASCII dash", limitResetDashed, true, AbortUsageLimit},
		{"ledger: org monthly usage limit", orgMonthlyQuota, true, AbortQuotaExceeded},
		{"ledger: weekly limit with reset", weeklyLimitEvening, true, AbortUsageLimit},
		{"ledger: weekly limit with dated reset", weeklyLimitDated, true, AbortUsageLimit},
		{"ledger: harness refused under root", harnessRootRefusal, true, AbortHarnessRefusal},

		// --- Empty output is its own class, not a no-evidence fallthrough. ---
		{"empty output", "", true, AbortEmptyOutput},
		{"whitespace-only output", "   \n\t\n  ", true, AbortEmptyOutput},

		// --- Other provider refusals in the same family. ---
		{"anthropic rate limit error", `{"type":"error","error":{"type":"rate_limit_error"}}`, true, AbortUsageLimit},
		{"http 429 prose", "Error: too many requests, please slow down", true, AbortUsageLimit},
		{"overloaded", `{"type":"overloaded_error","message":"Overloaded"}`, true, AbortUsageLimit},
		{"openai insufficient quota", "You exceeded your current quota, please check your plan and billing details", true, AbortQuotaExceeded},
		{"credit balance", "Your credit balance is too low to access the Anthropic API", true, AbortQuotaExceeded},

		// --- Credentials. ---
		{"invalid api key", "authentication_error: invalid x-api-key", true, AbortAuth},
		{"expired oauth", "OAuth token has expired. Please run /login again.", true, AbortAuth},
		{"401", "request failed: 401 Unauthorized", true, AbortAuth},

		// --- Harness never started. ---
		{"binary missing", "claude: command not found", true, AbortHarnessRefusal},
		{"exec lookup failed", `exec: "claude": executable file not found in $PATH`, true, AbortHarnessRefusal},

		// --- Negatives: real work must never be classified as an abort. ---
		{
			name:   "task that implemented rate limiting",
			output: "Implemented per-IP token-bucket rate limiting in pkg/ratelimit.\nAdded tests covering the 429 path.\nAll tests pass.",
			wantOK: false,
		},
		{
			name: "task documenting the limit strings themselves",
			// This project's own Task 20211 quotes every needle above. A
			// classifier that scanned the whole body of a long response would
			// abort the very task that fixed the bug.
			output: strings.Repeat("Analysed the ledger corruption in depth.\n", 80) +
				"Tasks 193-197 summarise as '" + limitResetAfternoon + "'.\n" +
				"Task 20015 summarises as the harness refusing to run.\n" +
				strings.Repeat("Wrote the classifier and its tests.\n", 80) +
				"Build and vet are clean.",
			wantOK: false,
		},
		{
			name:   "ordinary completion summary",
			output: "Refactored the executor placement logic and added three tests.",
			wantOK: false,
		},
		{
			name:   "harness needle deep inside a long transcript is not a refusal",
			output: strings.Repeat("Investigated the build failure.\n", 120) + "The error was 'command not found' for a helper script; added it to the Makefile.\nEverything builds now.",
			wantOK: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := ClassifyAbort(tt.output)
			if ok != tt.wantOK {
				t.Fatalf("ClassifyAbort(%q) ok = %v, want %v (got %+v)", truncate(tt.output, 120), ok, tt.wantOK, got)
			}
			if ok && got.Class != tt.wantClass {
				t.Errorf("class = %q, want %q (reason: %s)", got.Class, tt.wantClass, got.Reason)
			}
		})
	}
}

// TestClassifyAbort_TailOfLongOutput covers the case that motivated scanning
// the tail as well as short whole responses: an agent that works for a while
// and then runs into the wall reports it as the last thing it says.
func TestClassifyAbort_TailOfLongOutput(t *testing.T) {
	long := strings.Repeat("Working on the migration.\n", 200) + limitResetAfternoon
	got, ok := ClassifyAbort(long)
	if !ok {
		t.Fatal("a usage limit at the end of a long transcript must be classified as an abort")
	}
	if got.Class != AbortUsageLimit {
		t.Errorf("class = %q, want %q", got.Class, AbortUsageLimit)
	}
	if !strings.Contains(got.Evidence, "hit your limit") {
		t.Errorf("evidence should quote the provider's line, got %q", got.Evidence)
	}
}

// TestAbortClassRetryable pins which classes are worth waiting on. Getting
// this backwards either parks a run for an hour on a credential that will
// never fix itself, or burns the rest of the plan against a hard quota.
func TestAbortClassRetryable(t *testing.T) {
	retryable := []AbortClass{AbortUsageLimit, AbortEmptyOutput, AbortZeroArtifact, AbortNoEvidence}
	terminal := []AbortClass{AbortQuotaExceeded, AbortAuth, AbortHarnessRefusal}
	for _, c := range retryable {
		if !c.Retryable() {
			t.Errorf("%s should be retryable", c)
		}
	}
	for _, c := range terminal {
		if c.Retryable() {
			t.Errorf("%s needs an operator, so it must not be retryable", c)
		}
	}
}

func TestParseResetTime(t *testing.T) {
	// A fixed "now" so the relative assertions below are deterministic.
	now := time.Date(2026, time.August, 27, 13, 0, 0, 0, time.UTC)

	tests := []struct {
		name   string
		msg    string
		want   time.Time
		wantOK bool
	}{
		{
			name:   "ledger: 2:50pm later the same day",
			msg:    limitResetAfternoon,
			want:   time.Date(2026, time.August, 27, 14, 50, 0, 0, time.UTC),
			wantOK: true,
		},
		{
			name:   "ledger: bare 10pm later the same day",
			msg:    weeklyLimitEvening,
			want:   time.Date(2026, time.August, 27, 22, 0, 0, 0, time.UTC),
			wantOK: true,
		},
		{
			name:   "ledger: dated Aug 28, 10pm",
			msg:    weeklyLimitDated,
			want:   time.Date(2026, time.August, 28, 22, 0, 0, 0, time.UTC),
			wantOK: true,
		},
		{
			name: "time already passed today rolls to tomorrow",
			msg:  "You've hit your limit · resets 9am (UTC)",
			// 09:00 is behind the 13:00 "now", so the next occurrence is
			// tomorrow — not eight hours in the past, which would hot-loop.
			want:   time.Date(2026, time.August, 28, 9, 0, 0, 0, time.UTC),
			wantOK: true,
		},
		{
			name:   "12am is midnight, not noon",
			msg:    "resets 12am (UTC)",
			want:   time.Date(2026, time.August, 28, 0, 0, 0, 0, time.UTC),
			wantOK: true,
		},
		{
			name:   "12pm is noon",
			msg:    "resets 12:30pm (UTC)",
			want:   time.Date(2026, time.August, 28, 12, 30, 0, 0, time.UTC),
			wantOK: true,
		},
		{
			name:   "'resets at' phrasing",
			msg:    "Limit reached; resets at 03:15 (UTC)",
			want:   time.Date(2026, time.August, 28, 3, 15, 0, 0, time.UTC),
			wantOK: true,
		},
		{
			name: "January date seen from December rolls to next year",
			msg:  "You've hit your weekly limit · resets Jan 3, 10pm (UTC)",
			// Evaluated against a December "now" below.
			wantOK: true,
		},
		{name: "no reset clause", msg: orgMonthlyQuota, wantOK: false},
		{name: "vague reset", msg: "resets soon", wantOK: false},
		{name: "weekday, not a time", msg: "resets Monday", wantOK: false},
		{name: "impossible hour", msg: "resets 47 (UTC)", wantOK: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ref := now
			if strings.Contains(tt.name, "December") {
				ref = time.Date(2026, time.December, 30, 13, 0, 0, 0, time.UTC)
			}
			got, ok := parseResetTime(tt.msg, ref)
			if ok != tt.wantOK {
				t.Fatalf("parseResetTime(%q) ok = %v, want %v (got %s)", tt.msg, ok, tt.wantOK, got)
			}
			if !ok {
				return
			}
			if !got.After(ref) {
				t.Errorf("reset time %s is not after now %s — retrying then would hot-loop", got, ref)
			}
			if !tt.want.IsZero() && !got.Equal(tt.want) {
				t.Errorf("parseResetTime(%q) = %s, want %s", tt.msg, got, tt.want)
			}
		})
	}
}

// TestClassifyAbort_CarriesResetTime checks the two halves meet: a usage-limit
// message must surface its reset time on the Abort, since that is what stops
// the retry from hot-looping.
func TestClassifyAbort_CarriesResetTime(t *testing.T) {
	now := time.Date(2026, time.August, 27, 13, 0, 0, 0, time.UTC)

	ab, ok := classifyAbortAt(weeklyLimitDated, now)
	if !ok {
		t.Fatal("weekly limit must classify as an abort")
	}
	want := time.Date(2026, time.August, 28, 22, 0, 0, 0, time.UTC)
	if !ab.RetryAfter.Equal(want) {
		t.Errorf("RetryAfter = %s, want %s", ab.RetryAfter, want)
	}

	// A quota is not a window that reopens, so it must not carry one even
	// when the message happens to mention a date.
	quota, ok := classifyAbortAt(orgMonthlyQuota, now)
	if !ok {
		t.Fatal("org quota must classify as an abort")
	}
	if !quota.RetryAfter.IsZero() {
		t.Errorf("a hard quota must not advertise a reset time, got %s", quota.RetryAfter)
	}
}

func TestCompletionEvidence_Positive(t *testing.T) {
	tests := []struct {
		name string
		ev   CompletionEvidence
		want bool
	}{
		{"summary plus diff", CompletionEvidence{Summary: "did the thing", Diff: true}, true},
		{"summary plus artifact", CompletionEvidence{Summary: "did the thing", ArtifactBytes: 42}, true},
		{"summary alone is not evidence", CompletionEvidence{Summary: "did the thing"}, false},
		{"empty summary with a diff is not evidence", CompletionEvidence{Diff: true, ArtifactBytes: 10}, false},
		{"whitespace summary", CompletionEvidence{Summary: "  \n ", Diff: true}, false},
		{"nothing at all", CompletionEvidence{}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.ev.Positive(); got != tt.want {
				t.Errorf("Positive() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDecideUnsignalled(t *testing.T) {
	dir := t.TempDir()

	zero := filepath.Join(dir, "zero.md")
	if err := os.WriteFile(zero, nil, 0o644); err != nil {
		t.Fatalf("writing zero-byte artifact: %v", err)
	}
	full := filepath.Join(dir, "full.md")
	if err := os.WriteFile(full, []byte("real output"), 0o644); err != nil {
		t.Fatalf("writing artifact: %v", err)
	}

	tests := []struct {
		name         string
		artifactPath string
		output       string
		diff         bool
		wantAbort    bool
		wantClass    AbortClass
	}{
		{
			name:      "provider refusal outranks everything",
			output:    limitResetAfternoon,
			diff:      true,
			wantAbort: true,
			wantClass: AbortUsageLimit,
		},
		{
			name:         "zero-byte artifact is an abort even with output",
			artifactPath: zero,
			output:       "I did some work but forgot to emit a signal.",
			wantAbort:    true,
			wantClass:    AbortZeroArtifact,
		},
		{
			name:         "non-empty artifact plus summary is positive evidence",
			artifactPath: full,
			output:       "I did some work but forgot to emit a signal.",
			wantAbort:    false,
		},
		{
			name:      "output about to become an artifact counts",
			output:    "I did some work but forgot to emit a signal.",
			wantAbort: false,
		},
		{
			name:      "empty output",
			output:    "",
			wantAbort: true,
			wantClass: AbortEmptyOutput,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ab, aborted := decideUnsignalled(dir, tt.artifactPath, tt.output, tt.diff)
			if aborted != tt.wantAbort {
				t.Fatalf("aborted = %v, want %v (abort: %+v)", aborted, tt.wantAbort, ab)
			}
			if aborted && ab.Class != tt.wantClass {
				t.Errorf("class = %q, want %q", ab.Class, tt.wantClass)
			}
		})
	}
}

func TestRepoChanged(t *testing.T) {
	// An unfingerprintable repository (not a git checkout, git missing) must
	// not be reported as changed — that would manufacture evidence.
	if repoChanged("", "abc") {
		t.Error("an empty 'before' fingerprint must not count as a change")
	}
	if repoChanged("abc", "") {
		t.Error("an empty 'after' fingerprint must not count as a change")
	}
	if repoChanged("abc", "abc") {
		t.Error("identical fingerprints are not a change")
	}
	if !repoChanged("abc", "def") {
		t.Error("differing fingerprints are a change")
	}
}
