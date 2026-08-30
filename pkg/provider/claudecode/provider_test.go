package claudecode

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/provider"
)

// --- Name / DefaultModel ---

func TestName(t *testing.T) {
	if got := New().Name(); got != ProviderName {
		t.Errorf("expected %q, got %q", ProviderName, got)
	}
}

func TestDefaultModel(t *testing.T) {
	if got := New().DefaultModel(); got != "" {
		t.Errorf("expected empty default model, got %q", got)
	}
}

// --- loadEnvFile ---

func TestLoadEnvFile_ParsesKeyValue(t *testing.T) {
	k1, k2 := "CLOOP_TEST_K1", "CLOOP_TEST_K2"
	os.Unsetenv(k1)
	os.Unsetenv(k2)
	t.Cleanup(func() { os.Unsetenv(k1); os.Unsetenv(k2) })

	loadEnvFile(writeTempEnv(t, k1+"=bar\n"+k2+"=qux\n"))

	if got := os.Getenv(k1); got != "bar" {
		t.Errorf("%s: expected bar, got %q", k1, got)
	}
	if got := os.Getenv(k2); got != "qux" {
		t.Errorf("%s: expected qux, got %q", k2, got)
	}
}

func TestLoadEnvFile_SkipsComments(t *testing.T) {
	key := "CLOOP_TEST_COMMENT"
	os.Unsetenv(key)
	t.Cleanup(func() { os.Unsetenv(key) })

	loadEnvFile(writeTempEnv(t, "# this is a comment\n"+key+"=set\n"))

	if got := os.Getenv(key); got != "set" {
		t.Errorf("expected set, got %q", got)
	}
}

func TestLoadEnvFile_SkipsBlankLines(t *testing.T) {
	key := "CLOOP_TEST_BLANK"
	os.Unsetenv(key)
	t.Cleanup(func() { os.Unsetenv(key) })

	loadEnvFile(writeTempEnv(t, "\n   \n"+key+"=hello\n\n"))

	if got := os.Getenv(key); got != "hello" {
		t.Errorf("expected hello, got %q", got)
	}
}

func TestLoadEnvFile_DoesNotOverrideExisting(t *testing.T) {
	key := "CLOOP_TEST_EXISTING"
	os.Setenv(key, "original")
	t.Cleanup(func() { os.Unsetenv(key) })

	loadEnvFile(writeTempEnv(t, key+"=replaced\n"))

	if got := os.Getenv(key); got != "original" {
		t.Errorf("should not override existing env var, got %q", got)
	}
}

func TestLoadEnvFile_MissingFile(t *testing.T) {
	// Must not panic or error.
	loadEnvFile("/nonexistent/__cloop_test_missing.env")
}

func TestLoadEnvFile_ValueContainsEquals(t *testing.T) {
	key := "CLOOP_TEST_URL"
	os.Unsetenv(key)
	t.Cleanup(func() { os.Unsetenv(key) })

	loadEnvFile(writeTempEnv(t, key+"=http://example.com?a=b\n"))

	if got := os.Getenv(key); got != "http://example.com?a=b" {
		t.Errorf("expected full URL value, got %q", got)
	}
}

func TestLoadEnvFile_EmptyFile(t *testing.T) {
	// Must not panic on empty file.
	loadEnvFile(writeTempEnv(t, ""))
}

// --- Complete ---

func TestComplete_ReturnsFakeOutput(t *testing.T) {
	binDir := fakeClaudeScript(t, "#!/bin/sh\necho 'hello from fake claude'\n")
	t.Setenv("PATH", binDir+":"+os.Getenv("PATH"))

	p := New()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := p.Complete(ctx, "test prompt", provider.Options{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(result.Output, "hello from fake claude") {
		t.Errorf("unexpected output: %q", result.Output)
	}
	if result.Provider != ProviderName {
		t.Errorf("expected provider %q, got %q", ProviderName, result.Provider)
	}
	if result.Duration <= 0 {
		t.Error("expected positive duration")
	}
}

func TestComplete_UsesWorkDir(t *testing.T) {
	// Fake claude echoes its working directory via pwd.
	binDir := fakeClaudeScript(t, "#!/bin/sh\npwd\n")
	t.Setenv("PATH", binDir+":"+os.Getenv("PATH"))

	workDir := t.TempDir()
	p := New()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := p.Complete(ctx, "test", provider.Options{WorkDir: workDir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Output should contain the work directory path.
	if !strings.Contains(result.Output, workDir) {
		t.Errorf("expected workdir %q in output, got %q", workDir, result.Output)
	}
}

func TestComplete_FallsBackToStderr(t *testing.T) {
	// When stdout is empty and stderr has content, output should use stderr.
	binDir := fakeClaudeScript(t, "#!/bin/sh\necho 'stderr content' >&2\n")
	t.Setenv("PATH", binDir+":"+os.Getenv("PATH"))

	p := New()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := p.Complete(ctx, "test", provider.Options{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(result.Output, "stderr content") {
		t.Errorf("expected stderr fallback in output, got %q", result.Output)
	}
}

func TestComplete_PassesModelFlag(t *testing.T) {
	// Fake claude echoes its arguments so we can verify --model is passed.
	binDir := fakeClaudeScript(t, "#!/bin/sh\necho \"$@\"\n")
	t.Setenv("PATH", binDir+":"+os.Getenv("PATH"))

	p := New()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := p.Complete(ctx, "test", provider.Options{Model: "claude-opus-4-6"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(result.Output, "--model") || !strings.Contains(result.Output, "claude-opus-4-6") {
		t.Errorf("expected --model flag in args, got output: %q", result.Output)
	}
}

func TestComplete_ReturnsErrorOnAuthFailure(t *testing.T) {
	// When the CLI exits non-zero with an authentication error message, the
	// provider must surface this as an error rather than silently returning the
	// failure text as if it were a normal model response. Otherwise an
	// autonomous loop will spin on the same auth failure indefinitely.
	binDir := fakeClaudeScript(t,
		"#!/bin/sh\n"+
			"echo 'Failed to authenticate. API Error: 401 Invalid authentication credentials' >&2\n"+
			"exit 1\n",
	)
	t.Setenv("PATH", binDir+":"+os.Getenv("PATH"))

	p := New()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := p.Complete(ctx, "test", provider.Options{})
	if err == nil {
		t.Fatalf("expected error on CLI auth failure, got result=%+v", result)
	}
	if !strings.Contains(err.Error(), "401") || !strings.Contains(strings.ToLower(err.Error()), "authenticate") {
		t.Errorf("error should mention the underlying auth failure, got: %v", err)
	}
}

func TestComplete_ReturnsErrorOnAuthFailureWithExitZero(t *testing.T) {
	// In production the claude CLI has been observed exiting 0 while writing
	// an auth failure to stdout. Without surfacing this as an error, the
	// orchestrator records the failure text as "successful" output and the
	// autonomous loop spins indefinitely (2000+ steps observed in one session).
	binDir := fakeClaudeScript(t,
		"#!/bin/sh\n"+
			"echo 'Failed to authenticate. API Error: 401 Invalid authentication credentials'\n"+
			"exit 0\n",
	)
	t.Setenv("PATH", binDir+":"+os.Getenv("PATH"))

	p := New()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := p.Complete(ctx, "test", provider.Options{})
	if err == nil {
		t.Fatalf("expected error on CLI auth failure with exit 0, got result=%+v", result)
	}
	if !strings.Contains(err.Error(), "401") || !strings.Contains(strings.ToLower(err.Error()), "authenticate") {
		t.Errorf("error should mention the underlying auth failure, got: %v", err)
	}
}

func TestComplete_ZeroExitWithBenignOutputIsSuccess(t *testing.T) {
	// Guard against false positives in the exit-0 fatal-error check: a normal
	// successful response must still pass through unmodified.
	binDir := fakeClaudeScript(t,
		"#!/bin/sh\n"+
			"echo 'Sure, here is the function you asked for.'\n"+
			"exit 0\n",
	)
	t.Setenv("PATH", binDir+":"+os.Getenv("PATH"))

	p := New()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := p.Complete(ctx, "test", provider.Options{})
	if err != nil {
		t.Fatalf("unexpected error on benign exit-0 output: %v", err)
	}
	if !strings.Contains(result.Output, "function you asked for") {
		t.Errorf("expected benign output preserved, got %q", result.Output)
	}
}

func TestComplete_NonZeroExitWithoutAuthSignalIsBenign(t *testing.T) {
	// A non-zero exit without recognised auth/API markers must remain
	// non-fatal so the orchestrator can keep running. (Existing behaviour
	// callers depend on; the auth-error fix must not regress this.)
	binDir := fakeClaudeScript(t,
		"#!/bin/sh\n"+
			"echo 'partial output before unrelated failure'\n"+
			"exit 2\n",
	)
	t.Setenv("PATH", binDir+":"+os.Getenv("PATH"))

	p := New()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := p.Complete(ctx, "test", provider.Options{})
	if err != nil {
		t.Fatalf("unexpected error on benign non-zero exit: %v", err)
	}
	if !strings.Contains(result.Output, "partial output") {
		t.Errorf("expected partial output preserved, got %q", result.Output)
	}
}

func TestIsFatalCLIError(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"empty", "", false},
		{"plain output", "Hello, this is a model response.", false},
		{"failed to authenticate", "Failed to authenticate. API Error: 401 Invalid authentication credentials", true},
		{"invalid auth credentials only", "API Error: 401 Invalid authentication credentials", true},
		{"authentication_error in JSON", `{"type":"error","error":{"type":"authentication_error","message":"..."}}`, true},
		{"unrelated 401-ish text", "the function returned 401 lines of output", false},
		{"case-insensitive failed auth", "FAILED TO AUTHENTICATE: see logs", true},
		{"bare API Error 401", "API Error: 401 Unauthorized", true},
		{"bare API Error 403", "API Error: 403 Forbidden", true},
		// 5xx/429 are surfaced as errors so the orchestrator's MaxFailures
		// counter can stop a sustained upstream outage (a single transient
		// failure won't trip; consecutive ones will).
		{"5xx 500 surfaced", "API Error: 500 Internal Server Error", true},
		{"5xx 502 surfaced", "API Error: 502 Bad Gateway", true},
		{"5xx 503 surfaced", "API Error: 503 Service Unavailable", true},
		{"5xx 504 surfaced", "API Error: 504 Gateway Timeout", true},
		{"5xx 529 surfaced", "API Error: 529 Overloaded", true},
		{"429 rate-limit surfaced", "API Error: 429 Too Many Requests", true},
		{"bare digit 5 not 5xx", "API Error: 5 retries exceeded", false},
		{"unrelated 5xx-ish text", "function returned 502 results", false},
		{"HTML error page with doctype", "<!DOCTYPE html><html><body>401 Unauthorized</body></html>", true},
		{"HTML error page no doctype", "<html><head><title>Error</title></head><body>nope</body></html>", true},
		{"plain text mentioning html tag", "the function emits an <html> snippet but is not an error", false},
		// Bare "</html>" as the *entire* response (after trimming) is an error
		// artifact — observed in autonomous loops as a residue of a stripped
		// HTML error page. A real model answer is never just the closing tag.
		{"truncated HTML tail only", "</html>", true},
		{"truncated HTML tail with surrounding whitespace", "  \n</html>\n  ", true},
		// Guard: the bare-tag rule must NOT fire when "</html>" is embedded in
		// a longer legitimate response (e.g. code-snippet documentation).
		{"plain text mentioning closing tag", "use </html> to close the document body", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isFatalCLIError(tc.in); got != tc.want {
				t.Errorf("isFatalCLIError(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestComplete_ContextTimeoutSurfacedAsError(t *testing.T) {
	// When the per-call context times out, the subprocess is killed by
	// exec.CommandContext and cmd.Run returns a *exec.ExitError that looks
	// indistinguishable from a benign non-zero exit. Without an explicit
	// ctx.Err() check, the provider would swallow the cancellation and return
	// the partial output as "successful" — letting a recurring timeout re-fire
	// indefinitely without tripping the orchestrator's MaxFailures gate.
	binDir := fakeClaudeScript(t,
		"#!/bin/sh\n"+
			"echo 'partial output before sleep'\n"+
			"sleep 1\n",
	)
	t.Setenv("PATH", binDir+":"+os.Getenv("PATH"))

	p := New()
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	result, err := p.Complete(ctx, "test", provider.Options{})
	if err == nil {
		t.Fatalf("expected error on context timeout, got result=%+v", result)
	}
	if !strings.Contains(err.Error(), "cancelled") && !strings.Contains(err.Error(), "deadline") {
		t.Errorf("expected context cancellation in error, got: %v", err)
	}
	if result != nil {
		t.Errorf("expected nil result on context cancellation, got %+v", result)
	}
}

func TestComplete_ParentContextCancelSurfacedAsError(t *testing.T) {
	// Same defense as the timeout case but for explicit parent cancellation:
	// if the caller cancels mid-call, propagate the cancellation as an error
	// rather than returning whatever partial output was captured.
	binDir := fakeClaudeScript(t,
		"#!/bin/sh\n"+
			"echo 'partial'\n"+
			"sleep 1\n",
	)
	t.Setenv("PATH", binDir+":"+os.Getenv("PATH"))

	p := New()
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(150 * time.Millisecond)
		cancel()
	}()
	defer cancel()

	result, err := p.Complete(ctx, "test", provider.Options{})
	if err == nil {
		t.Fatalf("expected error on parent cancel, got result=%+v", result)
	}
	if result != nil {
		t.Errorf("expected nil result on parent cancel, got %+v", result)
	}
}

func TestComplete_OutputTrimmed(t *testing.T) {
	// Provider trims whitespace from output.
	binDir := fakeClaudeScript(t, "#!/bin/sh\nprintf '  trimmed output  '\n")
	t.Setenv("PATH", binDir+":"+os.Getenv("PATH"))

	p := New()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := p.Complete(ctx, "test", provider.Options{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Output != "trimmed output" {
		t.Errorf("expected trimmed output, got %q", result.Output)
	}
}

// --- helpers ---

// writeTempEnv writes content to a temp .env file and returns its path.
func writeTempEnv(t *testing.T, content string) string {
	t.Helper()
	f := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(f, []byte(content), 0o644); err != nil {
		t.Fatalf("write env file: %v", err)
	}
	return f
}

// fakeClaudeScript creates a 'claude' executable in a temp dir with the given
// script content, and returns the directory path (suitable for prepending to PATH).
func fakeClaudeScript(t *testing.T, script string) string {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "claude")
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake claude script: %v", err)
	}
	return dir
}

// --- buildArgs ---

func TestBuildArgs_Effort(t *testing.T) {
	base := []string{"--print", "--output-format", "text", "--permission-mode", "bypassPermissions"}

	// Valid effort levels are passed through as --effort <level>.
	for _, lvl := range provider.EffortLevels {
		args := buildArgs(provider.Options{Effort: lvl})
		want := append(append([]string{}, base...), "--effort", lvl)
		if strings.Join(args, " ") != strings.Join(want, " ") {
			t.Errorf("effort %q: args = %v, want %v", lvl, args, want)
		}
	}

	// Empty effort adds no flag.
	if args := buildArgs(provider.Options{}); strings.Contains(strings.Join(args, " "), "--effort") {
		t.Errorf("empty effort must not add --effort, got %v", args)
	}

	// Invalid effort (e.g. corrupted state) is dropped rather than passed to the CLI.
	if args := buildArgs(provider.Options{Effort: "turbo"}); strings.Contains(strings.Join(args, " "), "--effort") {
		t.Errorf("invalid effort must not add --effort, got %v", args)
	}
}

func TestBuildArgs_ModelAndMaxTokens(t *testing.T) {
	args := buildArgs(provider.Options{Model: "claude-sonnet-4-6", MaxTokens: 500, Effort: "high"})
	joined := strings.Join(args, " ")
	for _, want := range []string{"--model claude-sonnet-4-6", "--max-tokens 500", "--effort high"} {
		if !strings.Contains(joined, want) {
			t.Errorf("args missing %q: %v", want, args)
		}
	}
}

// --- 401 auth retry (Task 20204) ---

// recordingClaudeScript installs a fake claude that records one line per
// invocation into a log file (the attempt's CLAUDE_CODE_OAUTH_TOKEN), and
// replays the given per-attempt behaviours. Behaviours beyond the list reuse
// the last one, so an "always fails" fake needs only a single entry.
//
// Returns the PATH dir and a func reading back the per-attempt token log.
func recordingClaudeScript(t *testing.T, behaviours ...string) (string, func() []string) {
	t.Helper()
	dir := t.TempDir()
	log := filepath.Join(dir, "attempts.log")

	var cases string
	for i, b := range behaviours {
		// The last behaviour is the catch-all (*) so extra attempts reuse it,
		// which is what makes "retried more than once" detectable.
		pattern := fmt.Sprintf("%d", i+1)
		if i == len(behaviours)-1 {
			pattern = "*"
		}
		cases += fmt.Sprintf("  %s)\n%s\n    ;;\n", pattern, b)
	}

	script := "#!/bin/sh\n" +
		"echo \"${CLAUDE_CODE_OAUTH_TOKEN:-<unset>}\" >> " + log + "\n" +
		"n=$(wc -l < " + log + " | tr -d ' ')\n" +
		"case \"$n\" in\n" + cases + "esac\n"

	bin := filepath.Join(dir, "claude")
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake claude script: %v", err)
	}
	return dir, func() []string {
		data, err := os.ReadFile(log)
		if err != nil {
			return nil // never invoked
		}
		return strings.Split(strings.TrimSpace(string(data)), "\n")
	}
}

const authFailOutput = "Failed to authenticate. API Error: 401 " +
	`{"type":"error","error":{"type":"authentication_error","message":"Invalid authentication credentials"}}`

// stubRefresher installs a credential refresher for the duration of the test
// and restores the previous one afterwards.
func stubRefresher(t *testing.T, fn func() string) {
	t.Helper()
	prev := refreshCredential
	SetCredentialRefresher(fn)
	t.Cleanup(func() { SetCredentialRefresher(prev) })
}

// TestComplete_RetriesOnceAfter401 is the headline behaviour for Task 20204.
// A 401 is usually a lost race for a rotating single-use refresh token, so the
// second attempt — after refreshing — normally succeeds. Without the retry the
// task fails outright even though the credential is healthy by then, which is
// the reported "sometimes 401, next task is fine" symptom.
func TestComplete_RetriesOnceAfter401(t *testing.T) {
	binDir, attempts := recordingClaudeScript(t,
		"    echo '"+authFailOutput+"'\n    exit 1",
		"    echo 'recovered output'\n    exit 0",
	)
	t.Setenv("PATH", binDir+":"+os.Getenv("PATH"))

	var refreshed int
	stubRefresher(t, func() string { refreshed++; return "fresh-token" })

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	result, err := New().Complete(ctx, "test", provider.Options{})
	if err != nil {
		t.Fatalf("expected the retry to succeed, got error: %v", err)
	}
	if !strings.Contains(result.Output, "recovered output") {
		t.Errorf("expected the retry's output, got %q", result.Output)
	}
	if got := attempts(); len(got) != 2 {
		t.Fatalf("expected exactly 2 CLI invocations (original + one retry), got %d: %v", len(got), got)
	}
	if refreshed != 1 {
		t.Errorf("expected exactly 1 credential refresh, got %d", refreshed)
	}
}

// TestComplete_RetryUsesRefreshedToken pins the refreshed credential into the
// retry's environment. cloop itself injects a CLAUDE_CODE_OAUTH_TOKEN from
// ~/.openclaw/workspace/.env (loadEnvFiles), and that value is a snapshot that
// is never refreshed — so without the override the retry could re-send exactly
// the credential the server just rejected and be guaranteed to fail.
func TestComplete_RetryUsesRefreshedToken(t *testing.T) {
	binDir, attempts := recordingClaudeScript(t,
		"    echo '"+authFailOutput+"'\n    exit 1",
		"    echo ok\n    exit 0",
	)
	t.Setenv("PATH", binDir+":"+os.Getenv("PATH"))
	t.Setenv("CLAUDE_CODE_OAUTH_TOKEN", "stale-token")

	stubRefresher(t, func() string { return "rotated-token" })

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	if _, err := New().Complete(ctx, "test", provider.Options{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got := attempts()
	if len(got) != 2 {
		t.Fatalf("expected 2 invocations, got %d: %v", len(got), got)
	}
	if got[0] != "stale-token" {
		t.Errorf("first attempt should use the ambient token, got %q", got[0])
	}
	if got[1] != "rotated-token" {
		t.Errorf("retry should use the refreshed token, got %q", got[1])
	}
}

// TestComplete_RetriesAtMostOnce guards the budget: a genuinely dead
// credential must surface as a failure after exactly one retry, never loop.
func TestComplete_RetriesAtMostOnce(t *testing.T) {
	binDir, attempts := recordingClaudeScript(t,
		"    echo '"+authFailOutput+"'\n    exit 1",
	)
	t.Setenv("PATH", binDir+":"+os.Getenv("PATH"))
	stubRefresher(t, func() string { return "still-bad" })

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	_, err := New().Complete(ctx, "test", provider.Options{})
	if err == nil {
		t.Fatal("expected an error when both attempts fail")
	}
	if !errors.Is(err, ErrAuthFailure) {
		t.Errorf("error should still classify as ErrAuthFailure, got: %v", err)
	}
	if !strings.Contains(err.Error(), "retried once") {
		t.Errorf("error should record that a retry was spent, got: %v", err)
	}
	if got := attempts(); len(got) != 2 {
		t.Fatalf("expected exactly 2 invocations, got %d: %v", len(got), got)
	}
}

// TestComplete_DoesNotRetryNonAuthFailures keeps the retry scoped. Retrying a
// 429 immediately cannot help and feeds the loop that sustains the rate limit;
// 5xx and HTML error pages are upstream problems the MaxFailures gate handles.
func TestComplete_DoesNotRetryNonAuthFailures(t *testing.T) {
	for _, tc := range []struct{ name, output string }{
		{"rate limited", "API Error: 429 rate_limit_error"},
		{"server error", "API Error: 503 upstream unavailable"},
		{"forbidden", "API Error: 403 oauth_scope_insufficient"},
		{"html error page", "<!doctype html><html><body>nope</body></html>"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			binDir, attempts := recordingClaudeScript(t,
				"    echo '"+tc.output+"'\n    exit 1",
			)
			t.Setenv("PATH", binDir+":"+os.Getenv("PATH"))

			refreshed := false
			stubRefresher(t, func() string { refreshed = true; return "x" })

			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()

			_, err := New().Complete(ctx, "test", provider.Options{})
			if err == nil {
				t.Fatal("expected a fatal error")
			}
			if errors.Is(err, ErrAuthFailure) {
				t.Errorf("%s must not be classified as an auth failure: %v", tc.name, err)
			}
			if got := attempts(); len(got) != 1 {
				t.Errorf("expected exactly 1 invocation (no retry), got %d: %v", len(got), got)
			}
			if refreshed {
				t.Error("must not refresh credentials for a non-auth failure")
			}
		})
	}
}

// TestComplete_RetryWithoutRefresherWired covers the degraded path: if the
// cmd/providers.go wiring is ever missed, the retry must still happen. The CLI
// re-reads the credentials file itself, which is what recovers the common case
// where a peer process already won the refresh race.
func TestComplete_RetryWithoutRefresherWired(t *testing.T) {
	binDir, attempts := recordingClaudeScript(t,
		"    echo '"+authFailOutput+"'\n    exit 1",
		"    echo 'recovered'\n    exit 0",
	)
	t.Setenv("PATH", binDir+":"+os.Getenv("PATH"))
	stubRefresher(t, nil) // nothing wired

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	result, err := New().Complete(ctx, "test", provider.Options{})
	if err != nil {
		t.Fatalf("retry must happen even with no refresher wired, got: %v", err)
	}
	if !strings.Contains(result.Output, "recovered") {
		t.Errorf("expected the retry's output, got %q", result.Output)
	}
	if got := attempts(); len(got) != 2 {
		t.Errorf("expected 2 invocations, got %d: %v", len(got), got)
	}
}

// TestComplete_NoRetryOnCancelledContext: once the caller's context is done a
// second attempt would fail instantly and replace a clear auth diagnosis with
// a cancellation one.
func TestComplete_NoRetryOnCancelledContext(t *testing.T) {
	binDir, attempts := recordingClaudeScript(t,
		"    echo '"+authFailOutput+"'\n    exit 1",
	)
	t.Setenv("PATH", binDir+":"+os.Getenv("PATH"))

	refreshed := false
	stubRefresher(t, func() string { refreshed = true; return "x" })

	ctx, cancel := context.WithCancel(context.Background())
	// The first attempt runs to completion; cancelling here means ctx is
	// already done by the time the retry decision is made.
	cancel()

	if _, err := New().Complete(ctx, "test", provider.Options{}); err == nil {
		t.Fatal("expected an error")
	}
	if got := attempts(); len(got) > 1 {
		t.Errorf("must not retry on a done context, got %d invocations: %v", len(got), got)
	}
	if refreshed {
		t.Error("must not refresh credentials when the context is done")
	}
}

// TestClassifyCLIError separates the failures a credential refresh can fix
// from those it cannot.
func TestClassifyCLIError(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want cliErrorKind
	}{
		{"401", "API Error: 401 unauthorized", cliErrorAuth},
		{"failed to authenticate", "Failed to authenticate. API Error: 401", cliErrorAuth},
		{"authentication_error", `{"type":"authentication_error"}`, cliErrorAuth},
		{"invalid credentials", "Invalid authentication credentials", cliErrorAuth},
		// Observed in production: a 401 status carrying an upstream HTML 502
		// body. Auth markers must win over the HTML-page check, because this
		// is transient and a retry is exactly right.
		{"401 with html body", "Failed to authenticate. API Error: 401 <html><head><title>502 Bad Gateway</title></head></html>", cliErrorAuth},
		{"403 scope", "API Error: 403 oauth_scope_insufficient", cliErrorOther},
		{"429", "API Error: 429 rate limited", cliErrorOther},
		{"502", "API Error: 502 Bad Gateway", cliErrorOther},
		{"html page", "<!doctype html><html></html>", cliErrorOther},
		{"benign", "Sure, here is the function you asked for.", cliErrorNone},
		{"mentions 401 in prose", "The handler should return 401 when the token is missing.", cliErrorNone},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyCLIError(tc.in); got != tc.want {
				t.Errorf("classifyCLIError(%q) = %v, want %v", tc.in, got, tc.want)
			}
			// isFatalCLIError must stay consistent with the classifier, since
			// existing callers and tests depend on it.
			if gotFatal, wantFatal := isFatalCLIError(tc.in), tc.want != cliErrorNone; gotFatal != wantFatal {
				t.Errorf("isFatalCLIError(%q) = %v, want %v", tc.in, gotFatal, wantFatal)
			}
		})
	}
}
