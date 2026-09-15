// cli_errors_test.go: what the binary says when it fails (Task 20294).
//
// These run the built binary rather than calling cmd.Execute in-process,
// because the defects they cover live in the seam between cobra and Execute —
// who prints, how many times, and to which stream. An in-process test would
// have to reach past that seam and would keep passing while a user saw four
// lines of noise.
//
// The subject is a new user's very first command: cloop, in a directory that
// is not a project. Everything it prints is a first impression.

package e2e_test

import (
	"strings"
	"testing"
)

// countOccurrences reports how many times substr appears in s, so a test can
// say "exactly once" rather than "at least once" — which is the whole point
// here, since the bug was a duplicate rather than a missing line.
func countOccurrences(s, substr string) int {
	return strings.Count(s, substr)
}

// TestErrorOutsideProjectPrintsOnceAndCleanly covers all three defects of
// Task 20294 in the exact scenario that surfaced them: a clean build, an empty
// directory, one command.
//
// Before the fix this printed four lines — an executor warning about a SQLite
// errno, cobra's copy of the error, and Execute's copy of the same error, the
// last two both carrying an internal sentinel's text.
func TestErrorOutsideProjectPrintsOnceAndCleanly(t *testing.T) {
	dir := newWorkDir(t)

	out, err := run(t, dir, "status")
	if err == nil {
		t.Fatalf("cloop status outside a project must fail; got success:\n%s", out)
	}

	// (1) Exactly one print. rootCmd sets SilenceErrors so cobra stays quiet
	// and Execute owns the single line.
	const msg = "no cloop project found (run 'cloop init' first)"
	if n := countOccurrences(out, msg); n != 1 {
		t.Errorf("the error must be printed exactly once, got %d copies:\n%s", n, out)
	}
	if n := countOccurrences(out, "Error:"); n != 1 {
		t.Errorf("want exactly one \"Error:\" line, got %d:\n%s", n, out)
	}

	// (2) No executor warning. This command dispatches nothing, so handle
	// persistence has nothing to persist and no business commenting.
	assertNotContains(t, out, "handle persistence unavailable")
	assertNotContains(t, out, "will not survive a restart")

	// (3) No sentinel text. errors.Is still matches ErrProjectNotFound — see
	// TestLoadOutsideProjectKeepsTheSentinel in pkg/state — but the name of a
	// Go variable is not something a user can act on.
	assertNotContains(t, out, "statedb:")
	assertNotContains(t, out, "project not found")

	// Nothing else at all: the whole output is that one line.
	if got := strings.TrimSpace(out); got != "Error: "+msg {
		t.Errorf("unexpected output outside a project:\nwant: %q\ngot:  %q", "Error: "+msg, got)
	}
}

// TestMalformedFlagStillPrintsUsage guards the other half of the SilenceErrors
// change. Silencing cobra's error print must not silence usage: a user who
// mistypes a flag needs to see the flags.
//
// The mechanism is that SilenceUsage is set in PersistentPreRunE, which runs
// only after flag parsing and Args validation have succeeded — so a flag error
// never reaches it. That is subtle enough to be worth a test rather than a
// comment alone.
func TestMalformedFlagStillPrintsUsage(t *testing.T) {
	dir := newWorkDir(t)

	out, err := run(t, dir, "status", "--not-a-real-flag")
	if err == nil {
		t.Fatalf("an unknown flag must fail; got success:\n%s", out)
	}

	assertContains(t, out, "Usage:")
	assertContains(t, out, "cloop status")
	assertContains(t, out, "unknown flag: --not-a-real-flag")

	// Still exactly one copy of the error, even alongside usage.
	if n := countOccurrences(out, "unknown flag: --not-a-real-flag"); n != 1 {
		t.Errorf("want one copy of the flag error, got %d:\n%s", n, out)
	}
}

// TestWrongArgCountStillPrintsUsage is the second kind of genuine CLI misuse
// that must keep its usage output: Args validation, which like flag parsing
// fails before PersistentPreRunE can set SilenceUsage.
func TestWrongArgCountStillPrintsUsage(t *testing.T) {
	dir := newWorkDir(t)

	out, err := run(t, dir, "workspace", "add")
	if err == nil {
		t.Fatalf("a missing required argument must fail; got success:\n%s", out)
	}
	assertContains(t, out, "Usage:")
	assertContains(t, out, "workspace add")
}

// TestRuntimeErrorOmitsUsage is the converse, and the behaviour Task 20076
// established: a failure that is not CLI misuse must not answer with the flag
// list. Asserted here because SilenceErrors and SilenceUsage are easy to
// confuse, and a future edit that set SilenceUsage on rootCmd to "fix" the
// duplicate would pass every other test in this file.
func TestRuntimeErrorOmitsUsage(t *testing.T) {
	dir := newWorkDir(t)

	out, err := run(t, dir, "status")
	if err == nil {
		t.Fatalf("cloop status outside a project must fail; got success:\n%s", out)
	}
	assertNotContains(t, out, "Usage:")
	assertNotContains(t, out, "Global Flags:")
}
