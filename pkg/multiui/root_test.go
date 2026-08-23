package multiui

// Tests for the injection seam that keeps the registry out of the developer's
// real home directory (Task 20190).

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/internal/hometest"
)

// TestEnvRootMatchesHometest pins the two spellings of the variable name
// together. internal/hometest cannot import this package — multiui's own tests
// import hometest, so the reverse edge would be an import cycle in this very
// binary — so the name is duplicated there as a literal. If they ever drift,
// TestMain would set a variable Root no longer reads and every test in every
// package would quietly go back to writing to the real ~/.cloop.
func TestEnvRootMatchesHometest(t *testing.T) {
	if EnvRoot != hometest.EnvRoot {
		t.Fatalf("multiui.EnvRoot = %q but hometest.EnvRoot = %q — hometest would "+
			"isolate a variable this package does not consult, silently restoring "+
			"the leak both are meant to prevent", EnvRoot, hometest.EnvRoot)
	}
}

func TestRootPrefersEnvOverHome(t *testing.T) {
	want := t.TempDir()
	t.Setenv("HOME", filepath.Join(t.TempDir(), "not-this-one"))
	t.Setenv(EnvRoot, want)

	got, err := Root()
	if err != nil {
		t.Fatalf("Root: %v", err)
	}
	if got != want {
		t.Errorf("Root() = %q, want %q", got, want)
	}

	// And the registry lands inside it, which is the property callers rely on.
	p, err := registryPath()
	if err != nil {
		t.Fatalf("registryPath: %v", err)
	}
	if filepath.Dir(p) != want {
		t.Errorf("registryPath() = %q, want it under %q", p, want)
	}
	if filepath.Base(p) != "projects.json" {
		t.Errorf("registryPath() base = %q, want projects.json", filepath.Base(p))
	}
}

func TestRootFallsBackToHomeDotCloop(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv(EnvRoot, "")

	got, err := Root()
	if err != nil {
		t.Fatalf("Root: %v", err)
	}
	if want := filepath.Join(home, ".cloop"); got != want {
		t.Errorf("Root() = %q, want %q — an unset %s must not change the "+
			"historical layout", got, want, EnvRoot)
	}
}

// TestRootTreatsBlankEnvAsUnset: an env var exported as empty (or as
// whitespace, which a templated systemd unit or Helm values file can easily
// produce) must not resolve the registry to the process's working directory.
func TestRootTreatsBlankEnvAsUnset(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	for _, blank := range []string{"", "   ", "\t"} {
		t.Setenv(EnvRoot, blank)
		got, err := Root()
		if err != nil {
			t.Fatalf("Root with %s=%q: %v", EnvRoot, blank, err)
		}
		if want := filepath.Join(home, ".cloop"); got != want {
			t.Errorf("Root with %s=%q = %q, want the %q fallback", EnvRoot, blank, got, want)
		}
	}
}

// TestRootResolvesRelativeEnvToAbsolute keeps a relative CLOOP_HOME from
// meaning two different directories to two callers with different working
// directories — the hub changes directory per project, so this is reachable.
func TestRootResolvesRelativeEnvToAbsolute(t *testing.T) {
	t.Setenv(EnvRoot, "relative-cloop-home")
	got, err := Root()
	if err != nil {
		t.Fatalf("Root: %v", err)
	}
	if !filepath.IsAbs(got) {
		t.Errorf("Root() = %q, want an absolute path", got)
	}
	if !strings.HasSuffix(got, "relative-cloop-home") {
		t.Errorf("Root() = %q, want it to end in the requested directory", got)
	}
}

// TestSaveAndLoadRoundTripThroughEnvRoot is the end-to-end check: a write goes
// to the injected root and nowhere else. It is the property that makes every
// TestMain in this repository effective, so it is worth asserting directly
// rather than inferring from the absence of damage.
func TestSaveAndLoadRoundTripThroughEnvRoot(t *testing.T) {
	root := t.TempDir()
	decoy := t.TempDir()
	t.Setenv("HOME", decoy)
	t.Setenv(EnvRoot, root)

	want := []ProjectEntry{{Name: "alpha", Path: "/srv/alpha"}}
	if err := Save(want); err != nil {
		t.Fatalf("Save: %v", err)
	}

	if _, err := os.Stat(filepath.Join(root, "projects.json")); err != nil {
		t.Fatalf("registry was not written under %s: %v", EnvRoot, err)
	}
	// The decoy home must be untouched — that is the whole point.
	if _, err := os.Stat(filepath.Join(decoy, ".cloop")); !os.IsNotExist(err) {
		t.Errorf("Save created %s in the home directory despite %s being set", ".cloop", EnvRoot)
	}

	got, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(got) != 1 || got[0] != want[0] {
		t.Errorf("Load() = %+v, want %+v", got, want)
	}
}

// TestTestMainIsolationIsActuallyInEffect asserts that this binary is running
// under hometest.Isolate. Without it, every other test in this package would
// still pass while writing to the real registry.
func TestTestMainIsolationIsActuallyInEffect(t *testing.T) {
	hometest.Guard(t)

	root, err := Root()
	if err != nil {
		t.Fatalf("Root: %v", err)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("UserHomeDir: %v", err)
	}
	if !strings.HasPrefix(root, os.TempDir()) {
		t.Errorf("Root() = %q, which is not under %q — this test binary is not isolated",
			root, os.TempDir())
	}
	if home == "/root" || strings.HasPrefix(root, "/root/.cloop") {
		t.Errorf("this test binary resolves the real home (%q / %q)", home, root)
	}
}
