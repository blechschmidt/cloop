package claudecodeauth

// paste_test.go covers the authorization-code paste path (Task 20321).
//
// The reported failure was "Login failed: Request failed with status code 400"
// after pasting a code, rendered as a paragraph that also contained the banner,
// the authorize URL and the paste prompt. Two separate defects: nothing
// validated the paste against the session it was about to be fed to, and the
// panel rendered the whole transcript as the error.
//
// The CLI cannot make the first check itself. Verified against the real binary
// (v2.1.181): its readline handler splits the paste on "#" and calls
// handleManualAuthCodeInput({authorizationCode, state}), whose body is
//
//	if (this.manualAuthCodeResolver)
//	    this.manualAuthCodeResolver(e.authorizationCode), ...
//
// — the state is accepted and dropped. So a code carrying another attempt's
// state is exchanged against this attempt's PKCE verifier, and the token
// endpoint answers 400. Only the hub holds both states at once.

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	liveState  = "hA_zcP6wi9MJBFVhWxvxnWdp3X9WbYTflkspzic0TVM"
	staleState = "yP_o9ix5y8EoR5LxMQckfZJD1O2LPaCQAUNxl2DjWaM"
)

func TestNormalizePastedCode(t *testing.T) {
	cases := []struct {
		name   string
		paste  string
		expect string
		want   string
		errIs  error
	}{{
		name:   "canonical code#state passes through",
		paste:  "ac_abc123#" + liveState,
		expect: liveState,
		want:   "ac_abc123#" + liveState,
	}, {
		// The shape that used to hang: the CLI answers "Invalid code" and
		// returns to a readline SubmitCode has already closed.
		name:   "bare code is repaired with the session's own state",
		paste:  "ac_abc123",
		expect: liveState,
		want:   "ac_abc123#" + liveState,
	}, {
		name:   "whole callback URL is unpacked",
		paste:  "https://platform.claude.com/oauth/code/callback?code=ac_abc123&state=" + liveState,
		expect: liveState,
		want:   "ac_abc123#" + liveState,
	}, {
		name:   "surrounding quotes and whitespace are stripped",
		paste:  "  \"ac_abc123#" + liveState + "\"  ",
		expect: liveState,
		want:   "ac_abc123#" + liveState,
	}, {
		// The reported 400, caught before it becomes one.
		name:   "code from a superseded attempt is refused",
		paste:  "ac_abc123#" + staleState,
		expect: liveState,
		errIs:  ErrCodeFromAnotherLogin,
	}, {
		name:   "the authorize link pasted back is refused",
		paste:  "https://claude.com/cai/oauth/authorize?code=true&state=" + liveState,
		expect: liveState,
		errIs:  ErrCodeMalformed,
	}, {
		// stdin is line-oriented and the CLI reads one line: a newline would
		// become a second, caller-chosen line.
		name:   "embedded newline is refused",
		paste:  "ac_abc123\nac_evil#" + liveState,
		expect: liveState,
		errIs:  ErrCodeMalformed,
	}, {
		name:   "empty paste is refused",
		paste:  "   ",
		expect: liveState,
	}, {
		// Fail open: an inoperative check must not become a wrong one.
		name:   "no session state means the paste is forwarded untouched",
		paste:  "ac_abc123",
		expect: "",
		want:   "ac_abc123",
	}, {
		name:   "no session state forwards a stale-looking paste too",
		paste:  "ac_abc123#" + staleState,
		expect: "",
		want:   "ac_abc123#" + staleState,
	}, {
		// Even with nothing to compare against, a URL must still be unpacked:
		// forwarding it verbatim would hand the CLI a line it cannot read.
		name:   "no session state still unpacks a callback URL",
		paste:  "https://platform.claude.com/oauth/code/callback?code=ac_abc123&state=" + staleState,
		expect: "",
		want:   "ac_abc123#" + staleState,
	}}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := normalizePastedCode(tc.paste, tc.expect)
			if tc.want == "" {
				if err == nil {
					t.Fatalf("expected a refusal, got %q", got)
				}
				if tc.errIs != nil && !errors.Is(err, tc.errIs) {
					t.Fatalf("wrong refusal: got %v, want %v", err, tc.errIs)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected refusal: %v", err)
			}
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestOAuthStateFromURL(t *testing.T) {
	const authorize = "https://claude.com/cai/oauth/authorize?code=true&client_id=9d1c250a&" +
		"code_challenge=rtWBWmIjec0U&code_challenge_method=S256&state=" + liveState + "&login_method=sso"
	if got := oauthStateFromURL(authorize); got != liveState {
		t.Fatalf("got %q, want %q", got, liveState)
	}
	if got := oauthStateFromURL("https://claude.com/cai/oauth/authorize?code=true"); got != "" {
		t.Fatalf("invented a state: %q", got)
	}
	if got := oauthStateFromURL("::not a url::"); got != "" {
		t.Fatalf("invented a state from junk: %q", got)
	}
}

// The transcript below is the one from the bug report, verbatim. Before the
// fix all four lines reached the panel as a single run-on error.
func TestSummarizeLoginFailureKeepsOnlyTheActionableLine(t *testing.T) {
	transcript := "Opening browser to sign in…\n" +
		"If the browser didn't open, visit: https://claude.com/cai/oauth/authorize?code=true&state=" + liveState + "\n" +
		"Paste code here if prompted > \n" +
		"Login failed: Request failed with status code 400\n"

	got := summarizeLoginFailure(transcript)
	if !strings.HasPrefix(got, "Login failed: Request failed with status code 400") {
		t.Fatalf("lost the failure line: %q", got)
	}
	for _, noise := range []string{"Opening browser", "If the browser didn't open", "Paste code here", "claude.com/cai/oauth"} {
		if strings.Contains(got, noise) {
			t.Fatalf("summary still carries %q: %s", noise, got)
		}
	}
	if !strings.Contains(got, "used once") {
		t.Fatalf("400 was not translated into anything actionable: %s", got)
	}
}

func TestSummarizeLoginFailureKeepsInvalidCodeAndFallsBack(t *testing.T) {
	if got := summarizeLoginFailure("Invalid code. Please make sure the full code was copied.\n"); !strings.HasPrefix(got, "Invalid code") {
		t.Fatalf("dropped the CLI's own complaint: %q", got)
	}
	// Nothing recognisable must yield "", so Snapshot falls back to the full
	// transcript rather than to an empty error.
	if got := summarizeLoginFailure("some future wording\n"); got != "" {
		t.Fatalf("expected no summary, got %q", got)
	}
}

// fakeClaudeLoginWithState is a stand-in `claude` that emits a stateful
// authorize URL and echoes the exact line it was handed, so a test can prove
// what reached the CLI's stdin rather than only what SubmitCode returned.
func fakeClaudeLoginWithState(t *testing.T, state string) {
	t.Helper()
	dir := t.TempDir()
	script := "#!/bin/sh\n" +
		"echo \"If the browser didn't open, visit: https://claude.com/cai/oauth/authorize?code=true&state=" + state + "\"\n" +
		"read code\n" +
		"echo \"received:$code\"\n"
	path := filepath.Join(dir, "claude")
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake claude: %v", err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

// A code from a superseded attempt must be refused without disturbing the
// session — otherwise correcting the paste would require restarting the login,
// which mints a new challenge and invalidates the code the user is holding.
func TestSubmitCodeRefusesAnotherLoginsCodeAndKeepsTheSessionUsable(t *testing.T) {
	fakeClaudeLoginWithState(t, liveState)
	m := NewManager()
	t.Cleanup(m.Shutdown)

	if _, err := m.Start(context.Background(), "alice@example.com", "/homes/alice", LoginOptions{}); err != nil {
		t.Fatalf("start: %v", err)
	}

	_, err := m.SubmitCode("alice@example.com", "ac_stale#"+staleState)
	if !errors.Is(err, ErrCodeFromAnotherLogin) {
		t.Fatalf("a code from another attempt was accepted: err=%v", err)
	}
	if msg := err.Error(); !strings.Contains(msg, "Open the link shown above again") {
		t.Fatalf("refusal names no remedy: %s", msg)
	}

	// Still live, and still the same URL: nothing was consumed.
	if snap := m.Snapshot("alice@example.com"); !snap.Active {
		t.Fatal("the rejected paste killed the session the user must now correct")
	}

	st, err := m.SubmitCode("alice@example.com", "ac_good#"+liveState)
	if err != nil {
		t.Fatalf("the corrected paste was refused: %v", err)
	}
	if !strings.Contains(st.Output, "received:ac_good#"+liveState) {
		t.Fatalf("the corrected code did not reach the CLI: %q", st.Output)
	}
}

// A bare code is the common mis-paste. It must reach the CLI in the canonical
// form rather than as a line the CLI rejects into a closed readline.
func TestSubmitCodeRepairsABareCodeBeforeItReachesTheCLI(t *testing.T) {
	fakeClaudeLoginWithState(t, liveState)
	m := NewManager()
	t.Cleanup(m.Shutdown)

	if _, err := m.Start(context.Background(), "alice@example.com", "/homes/alice", LoginOptions{}); err != nil {
		t.Fatalf("start: %v", err)
	}
	st, err := m.SubmitCode("alice@example.com", "ac_bare")
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	if !strings.Contains(st.Output, "received:ac_bare#"+liveState) {
		t.Fatalf("the CLI was handed a line it would reject as invalid: %q", st.Output)
	}
}
