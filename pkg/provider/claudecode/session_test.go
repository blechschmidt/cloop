package claudecode

// Conversation ids and resume (Task 20349). A task whose agent ends its turn
// while waiting on its own background work is given the turn back in the same
// conversation; that needs every call to run under an id the caller learns.

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/blechschmidt/cloop/pkg/provider"
)

// argvEcho is a fake claude that prints the arguments it was given, one per
// line, so a test can read back exactly what the provider passed.
const argvEcho = "#!/bin/sh\nfor a in \"$@\"; do printf '%s\\n' \"$a\"; done\n"

// flagValue returns the argument following flag in a printed argv, or "".
func flagValue(argv, flag string) string {
	lines := strings.Split(argv, "\n")
	for i, l := range lines {
		if l == flag && i+1 < len(lines) {
			return lines[i+1]
		}
	}
	return ""
}

func TestCompleteRunsUnderASessionIDItReports(t *testing.T) {
	sessionIDUnsupported.Store(false)
	t.Cleanup(func() { sessionIDUnsupported.Store(false) })
	binDir := fakeClaudeScript(t, argvEcho)
	t.Setenv("PATH", binDir+":"+os.Getenv("PATH"))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res, err := New().Complete(ctx, "prompt", provider.Options{})
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	passed := flagValue(res.Output, "--session-id")
	if passed == "" {
		t.Fatalf("no --session-id was passed; argv:\n%s", res.Output)
	}
	if _, err := uuid.Parse(passed); err != nil {
		t.Fatalf("--session-id %q is not a UUID, which the CLI requires", passed)
	}
	if res.SessionID != passed {
		t.Errorf("Result.SessionID = %q, but the CLI ran under %q — a resume would continue the wrong conversation",
			res.SessionID, passed)
	}
	if strings.Contains(res.Output, "--resume") {
		t.Errorf("a new conversation asked to resume one; argv:\n%s", res.Output)
	}
}

func TestCompleteResumesTheConversationItWasGiven(t *testing.T) {
	sessionIDUnsupported.Store(false)
	t.Cleanup(func() { sessionIDUnsupported.Store(false) })
	binDir := fakeClaudeScript(t, argvEcho)
	t.Setenv("PATH", binDir+":"+os.Getenv("PATH"))

	id := uuid.NewString()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res, err := New().Complete(ctx, "carry on", provider.Options{ResumeSession: id})
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if got := flagValue(res.Output, "--resume"); got != id {
		t.Fatalf("--resume = %q, want %q; argv:\n%s", got, id, res.Output)
	}
	if strings.Contains(res.Output, "--session-id") {
		t.Errorf("a resumed call also started a new conversation; argv:\n%s", res.Output)
	}
	if res.SessionID != id {
		t.Errorf("Result.SessionID = %q, want the resumed %q", res.SessionID, id)
	}
}

// TestResumeRefusesAnythingButAUUID: the value becomes an argument, and one
// beginning with "-" would be read as a flag.
func TestResumeRefusesAnythingButAUUID(t *testing.T) {
	for _, bad := range []string{"--dangerously-skip-permissions", "-c", "not-a-uuid", "  "} {
		args := buildArgs(provider.Options{ResumeSession: bad})
		for _, a := range args {
			if a == "--resume" {
				t.Errorf("ResumeSession %q produced a --resume: %v", bad, args)
			}
		}
	}
}

// TestSessionIDIsDroppedByACLIThatDoesNotKnowIt: a CLI older than --session-id
// answers every call that passes it with "unknown option", which would fail
// every task. The provider runs the call again without it, and stops asking.
func TestSessionIDIsDroppedByACLIThatDoesNotKnowIt(t *testing.T) {
	sessionIDUnsupported.Store(false)
	t.Cleanup(func() { sessionIDUnsupported.Store(false) })
	binDir := fakeClaudeScript(t, "#!/bin/sh\n"+
		"for a in \"$@\"; do\n"+
		"  if [ \"$a\" = --session-id ]; then echo \"error: unknown option '--session-id'\" >&2; exit 1; fi\n"+
		"done\n"+
		"echo 'answered without a session id'\n")
	t.Setenv("PATH", binDir+":"+os.Getenv("PATH"))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res, err := New().Complete(ctx, "prompt", provider.Options{})
	if err != nil {
		t.Fatalf("Complete failed on a CLI without --session-id: %v", err)
	}
	if !strings.Contains(res.Output, "answered without a session id") {
		t.Fatalf("output = %q; the call was not re-run without the flag", res.Output)
	}
	if res.SessionID != "" {
		t.Errorf("Result.SessionID = %q for a conversation that has none", res.SessionID)
	}
	if !sessionIDUnsupported.Load() {
		t.Error("the provider will keep passing a flag this CLI rejects")
	}
}
