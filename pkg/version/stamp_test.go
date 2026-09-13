package version

import (
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

// stampSymbol is the fully-qualified linker symbol the release tooling must
// patch. It is derived from the running package rather than written out, so a
// package move updates the expectation automatically and the test keeps
// checking the build scripts instead of a stale literal.
func stampSymbol(t *testing.T) string {
	t.Helper()
	pkgPath := reflect.TypeOf(parsed{}).PkgPath()
	if pkgPath == "" {
		t.Fatal("could not determine this package's import path")
	}
	return pkgPath + ".Version"
}

// TestBuildScriptsStampTheRightSymbol is a drift gate on a silent failure.
//
// `go build -ldflags "-X does/not/exist.Version=v1"` does not error — the
// linker ignores symbols it cannot find. So when this variable moved out of
// package cmd, every build script still naming cmd.Version kept succeeding and
// would have produced release binaries reporting "dev" forever, which in turn
// makes `cloop upgrade --check` conclude there is nothing to do and makes every
// executor agent in a fleet report the same useless version.
//
// There is no compiler check for "this shell string matches that Go symbol",
// so this test is the check.
func TestBuildScriptsStampTheRightSymbol(t *testing.T) {
	want := stampSymbol(t)
	root := repoRoot(t)

	// Every file that stamps a version into a binary. A new build path that
	// stamps a version belongs in this list.
	for _, rel := range []string{
		"scripts/build-release.sh",
		"Dockerfile",
		"docs/getting-started/installation.md",
	} {
		t.Run(rel, func(t *testing.T) {
			body, err := os.ReadFile(filepath.Join(root, rel))
			if err != nil {
				t.Fatalf("read %s: %v", rel, err)
			}
			text := string(body)

			if !strings.Contains(text, want) {
				t.Errorf("%s does not stamp %s.\n"+
					"Without the right symbol the -X is silently ignored and the build reports %q.",
					rel, want, DevVersion)
			}
			// The old symbol must be gone, not merely joined by the new one:
			// a leftover -X naming it is dead weight that reads as though it
			// still works.
			if strings.Contains(text, "cloop/cmd.Version") {
				t.Errorf("%s still references the retired symbol cloop/cmd.Version.\n"+
					"It no longer exists; use %s.", rel, want)
			}
		})
	}
}

// TestVersionSymbolIsPatchable asserts the declaration shape -X requires.
//
// The linker only patches a string variable "declared uninitialized or
// initialized to a constant string expression". A refactor to
// `var Version = something()` would compile, pass every other test, and break
// releases — so the declaration itself is asserted.
func TestVersionSymbolIsPatchable(t *testing.T) {
	root := repoRoot(t)
	body, err := os.ReadFile(filepath.Join(root, "pkg", "version", "version.go"))
	if err != nil {
		t.Fatalf("read version.go: %v", err)
	}
	const want = "var Version = DevVersion"
	if !strings.Contains(string(body), want) {
		t.Errorf("version.go no longer declares %q.\n"+
			"Version must be initialised to a constant expression or -ldflags -X stops working silently.",
			want)
	}
}

// repoRoot locates the repository from this file's compile-time path, so the
// test works regardless of the working directory it runs in.
func repoRoot(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller could not locate stamp_test.go")
	}
	// pkg/version/stamp_test.go -> repo root
	return filepath.Dir(filepath.Dir(filepath.Dir(thisFile)))
}
