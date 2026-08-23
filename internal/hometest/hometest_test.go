package hometest

// The isolation helper is load-bearing for every other test binary in this
// repository, so its own behaviour is pinned here rather than assumed. In
// particular: if isolate() silently stopped redirecting, nothing else would
// fail — the suite would simply go back to writing to the developer's home.

import (
	"os"
	"path/filepath"
	"testing"
)

// TestIsolateRedirectsHomeAndClearsOverrides covers the whole contract in one
// pass: HOME moves into a fresh sandbox, the variables that would override it
// are gone, and restore/cleanup put the environment back and take the
// directory with them.
func TestIsolateRedirectsHomeAndClearsOverrides(t *testing.T) {
	realHome := os.Getenv("HOME")
	// An inherited override is the interesting precondition: a developer with
	// CLOOP_HOME exported in their shell must not thereby escape the sandbox.
	t.Setenv(EnvRoot, "/definitely/not/a/sandbox")

	restore, cleanup, err := isolate()
	if err != nil {
		t.Fatalf("isolate: %v", err)
	}

	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("UserHomeDir: %v", err)
	}
	if home == realHome {
		t.Fatal("isolate() left HOME pointing at the real home directory")
	}
	if !isTemp(home) {
		t.Errorf("isolate() set HOME to %q, which is not under %q", home, os.TempDir())
	}
	for _, k := range clearedVars {
		if v, ok := os.LookupEnv(k); ok {
			t.Errorf("isolate() left %s set to %q; it overrides HOME", k, v)
		}
	}

	// A write to the sandbox home must land in the sandbox.
	probe := filepath.Join(home, ".cloop", "probe")
	if err := os.MkdirAll(filepath.Dir(probe), 0o700); err != nil {
		t.Fatalf("write into sandbox: %v", err)
	}

	restore()
	if got := os.Getenv("HOME"); got != realHome {
		t.Errorf("after restore, HOME = %q, want the original %q", got, realHome)
	}
	if got := os.Getenv(EnvRoot); got != "/definitely/not/a/sandbox" {
		t.Errorf("after restore, %s = %q, want the inherited value back", EnvRoot, got)
	}

	cleanup()
	if _, err := os.Stat(home); !os.IsNotExist(err) {
		t.Errorf("cleanup() left the sandbox %q behind (stat err = %v)", home, err)
	}
}

// TestIsolateRestoresAnUnsetVariable covers the other half of restore: a
// variable that was absent must be absent again, not present and empty.
func TestIsolateRestoresAnUnsetVariable(t *testing.T) {
	t.Setenv(EnvRoot, "placeholder")
	if err := os.Unsetenv(EnvRoot); err != nil {
		t.Fatalf("unsetenv: %v", err)
	}

	restore, cleanup, err := isolate()
	if err != nil {
		t.Fatalf("isolate: %v", err)
	}
	restore()
	cleanup()

	if v, ok := os.LookupEnv(EnvRoot); ok {
		t.Errorf("restore() set %s to %q, but it was unset beforehand", EnvRoot, v)
	}
}

// TestWithinDoesNotMatchASiblingSharingAPrefix is the bug this kind of
// containment check usually has: a naive strings.HasPrefix would report
// /tmp/sandbox-evil as being inside /tmp/sandbox, which would let Guard pass
// for a directory outside the sandbox.
func TestWithinDoesNotMatchASiblingSharingAPrefix(t *testing.T) {
	base := t.TempDir()
	inside := filepath.Join(base, "sandbox")
	sibling := inside + "-evil"
	for _, d := range []string{inside, sibling} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}

	cases := []struct {
		parent, p string
		want      bool
		why       string
	}{
		{inside, inside, true, "a directory contains itself"},
		{inside, filepath.Join(inside, "a", "b"), true, "a descendant is inside"},
		{inside, sibling, false, "a sibling sharing a name prefix is not inside"},
		{inside, base, false, "the parent is not inside its child"},
		{"", inside, false, "an empty parent contains nothing"},
		{inside, "", false, "an empty path is inside nothing"},
	}
	for _, c := range cases {
		if got := within(c.parent, c.p); got != c.want {
			t.Errorf("within(%q, %q) = %v, want %v — %s", c.parent, c.p, got, c.want, c.why)
		}
	}
}

// TestGuardPassesUnderIsolation asserts Guard agrees with isolate(). This test
// binary has no TestMain, so it runs against the real HOME — which makes it
// the one place that can check both answers.
func TestGuardPassesUnderIsolation(t *testing.T) {
	restore, cleanup, err := isolate()
	if err != nil {
		t.Fatalf("isolate: %v", err)
	}
	defer func() { restore(); cleanup() }()

	// Guard must not fail here. If it does, every TestMain in the repository
	// is asserting something different from what Isolate establishes.
	Guard(t)
}

// TestGuardRejectsTheRealHome is the negative case, run through a recording
// TB so a passing Guard is distinguishable from a failing one.
func TestGuardRejectsTheRealHome(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil || isTemp(home) {
		t.Skip("this environment's real HOME is already temporary; nothing to reject")
	}
	rec := &recordingTB{TB: t}
	Guard(rec)
	if !rec.failed {
		t.Errorf("Guard accepted the real home directory %q", home)
	}
}

// recordingTB captures Fatalf instead of aborting, so the negative case above
// can assert that Guard rejected rather than merely not crashing.
type recordingTB struct {
	testing.TB
	failed bool
}

func (r *recordingTB) Helper() {}

func (r *recordingTB) Fatalf(format string, args ...any) { r.failed = true }

func (r *recordingTB) Errorf(format string, args ...any) { r.failed = true }
