// Package hometest isolates a test binary from the developer's real home
// directory.
//
// cloop keeps per-user state outside the working tree: the multi-project
// registry at $HOME/.cloop/projects.json, the global budget ledger and cost
// journal under $HOME/.config/cloop, profiles, plugins and cached provider
// credentials. None of that is addressed by a parameter — it is resolved from
// the ambient environment at the point of use, so a test that exercises the
// code path writes to the machine it runs on and leaves it there.
//
// That is not a tidiness concern, it is a correctness one, and it fails in the
// worst possible direction. A single dashboard test accumulated 99 entries into
// one developer's real projects.json, one per run. Past ~100, project index 99
// began resolving to a long-deleted /tmp directory, and three unrelated
// authorization tests started failing — in isolation, on every run, for that
// developer only. Ephemeral CI runners always start from an empty HOME, so the
// pipeline was green by construction while the developer was red, and the
// failures presented as authorization assertions, which invites weakening the
// assertion rather than finding the leak.
//
// Isolate makes that class of bug impossible rather than merely unlikely: the
// redirection happens once in TestMain, before any test runs, so it protects
// tests whose authors never considered it — including tests not yet written.
package hometest

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// EnvRoot must match multiui.EnvRoot. It is duplicated as a literal rather than
// imported because this package is imported by multiui's own tests, and an
// import back would be a cycle in that test binary. TestEnvRootMatchesHometest
// in pkg/multiui pins the two together.
const EnvRoot = "CLOOP_HOME"

// redirectedVars are pointed at the sandbox. HOME is the one that matters on
// Unix — os.UserHomeDir reads it, and every ~/.cloop and ~/.config/cloop path
// in the tree derives from it. USERPROFILE is its Windows equivalent, set so
// this keeps working if the suite is ever run there.
var redirectedVars = []string{"HOME", "USERPROFILE"}

// clearedVars are unset rather than redirected, because each of them *overrides*
// HOME. Setting them here would defeat the established per-test idiom
// — t.Setenv("HOME", t.TempDir()), used by 25 tests in this repository — by
// pinning every such test to one shared root, where they would see each
// other's writes. Unsetting achieves the same protection without that: an
// inherited CLOOP_HOME from the developer's shell cannot redirect a test back
// out of the sandbox, and resolution falls through to the sandboxed HOME.
//
// XDG_CONFIG_HOME is not consulted by cloop today and is cleared for the same
// reason, so that adding a lookup for it later cannot silently reopen the hole.
var clearedVars = []string{EnvRoot, "XDG_CONFIG_HOME"}

// Isolate points every per-user state path at a fresh temporary directory for
// the lifetime of the whole test binary, runs m, and removes the directory.
// It returns the exit code, so TestMain is:
//
//	func TestMain(m *testing.M) { os.Exit(hometest.Isolate(m)) }
//
// Individual tests may still narrow further with t.Setenv("HOME", t.TempDir())
// — that keeps working and is worth doing where a test needs a home of its
// own. The point of doing it here as well is that it does not depend on the
// author of the next test remembering to.
func Isolate(m *testing.M) int {
	restore, cleanup, err := isolate()
	if err != nil {
		fmt.Fprintf(os.Stderr, "hometest: %v\n", err)
		return 1
	}
	// Deliberately not deferred: os.Exit in the caller would skip a defer, and
	// running the cleanup before returning the code is the whole point.
	code := m.Run()
	restore()
	cleanup()
	return code
}

// isolate performs the redirection and returns a function restoring the
// previous environment plus one removing the sandbox.
func isolate() (restore func(), cleanup func(), err error) {
	// os.MkdirTemp, not testing's TempDir: there is no *testing.T in TestMain
	// before m.Run, and this must be in place before the first test starts.
	dir, err := os.MkdirTemp("", "cloop-hometest-")
	if err != nil {
		return nil, nil, fmt.Errorf("create sandbox home: %w", err)
	}
	// Resolve symlinks now. On macOS os.MkdirTemp hands back /var/... while
	// os.Getwd and friends report /private/var/..., and a test comparing the
	// two would fail for a reason that has nothing to do with what it tests.
	if resolved, rerr := filepath.EvalSymlinks(dir); rerr == nil {
		dir = resolved
	}

	prev := make(map[string]*string, len(redirectedVars)+len(clearedVars))
	remember := func(k string) {
		if v, ok := os.LookupEnv(k); ok {
			prev[k] = &v
		} else {
			prev[k] = nil
		}
	}
	for _, k := range redirectedVars {
		remember(k)
	}
	for _, k := range clearedVars {
		remember(k)
	}

	restore = func() {
		for k, v := range prev {
			if v == nil {
				_ = os.Unsetenv(k)
			} else {
				_ = os.Setenv(k, *v)
			}
		}
	}
	cleanup = func() { _ = os.RemoveAll(dir) }

	fail := func(format string, a ...any) (func(), func(), error) {
		restore()
		cleanup()
		return nil, nil, fmt.Errorf(format, a...)
	}
	for _, k := range redirectedVars {
		if serr := os.Setenv(k, dir); serr != nil {
			return fail("set %s: %w", k, serr)
		}
	}
	for _, k := range clearedVars {
		if uerr := os.Unsetenv(k); uerr != nil {
			return fail("unset %s: %w", k, uerr)
		}
	}

	// Fail loudly rather than run hundreds of tests against the real home
	// because a Setenv silently did not take effect.
	if verr := verify(dir); verr != nil {
		return fail("%w", verr)
	}
	return restore, cleanup, nil
}

// verify asserts the redirection actually took, using the same call the code
// under test uses rather than trusting that Setenv did what it was asked.
func verify(dir string) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("sandbox home is unusable: %w", err)
	}
	if !within(dir, home) {
		return fmt.Errorf("os.UserHomeDir() = %q, which is outside the sandbox %q; "+
			"the test binary would write to the real home directory", home, dir)
	}
	for _, k := range clearedVars {
		if v, ok := os.LookupEnv(k); ok {
			return fmt.Errorf("%s is still set to %q; it overrides HOME and would "+
				"redirect writes out of the sandbox %q", k, v, dir)
		}
	}
	return nil
}

// Guard fails the calling test if per-user state still resolves outside a
// temporary directory. Use it in a test that asserts the isolation itself, or
// at the top of one that is about to write to the registry; TestMain callers
// get the same check for free via Isolate.
func Guard(tb testing.TB) {
	tb.Helper()
	home, err := os.UserHomeDir()
	if err != nil {
		tb.Fatalf("hometest.Guard: os.UserHomeDir: %v", err)
	}
	if !isTemp(home) {
		tb.Fatalf("hometest.Guard: HOME is %q, not a temporary directory — this test "+
			"would write to the real home directory. Add a TestMain calling "+
			"hometest.Isolate, or t.Setenv(\"HOME\", t.TempDir()).", home)
	}
	for _, k := range clearedVars {
		if v := os.Getenv(k); v != "" && !isTemp(v) {
			tb.Fatalf("hometest.Guard: %s is %q, which overrides HOME and points "+
				"outside a temporary directory", k, v)
		}
	}
}

// isTemp reports whether p lies under the system temp directory. It is a
// heuristic — the point is to catch "this is the developer's actual home",
// which it does reliably, not to prove provenance.
func isTemp(p string) bool {
	return within(os.TempDir(), p)
}

// within reports whether p is parent or lies beneath it, comparing cleaned
// absolute paths so that a sibling sharing a name prefix does not match.
func within(parent, p string) bool {
	if parent == "" || p == "" {
		return false
	}
	pa, err := filepath.Abs(parent)
	if err != nil {
		return false
	}
	pb, err := filepath.Abs(p)
	if err != nil {
		return false
	}
	if resolved, rerr := filepath.EvalSymlinks(pa); rerr == nil {
		pa = resolved
	}
	if resolved, rerr := filepath.EvalSymlinks(pb); rerr == nil {
		pb = resolved
	}
	pa = filepath.Clean(pa)
	pb = filepath.Clean(pb)
	return pb == pa || strings.HasPrefix(pb, pa+string(filepath.Separator))
}
