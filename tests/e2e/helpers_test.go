package e2e_test

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"
)

// updateGolden regenerates golden files when -update is passed.
var updateGolden = flag.Bool("update", false, "update golden files")

// binaryPath returns the path to the cloop binary under test.
// It looks for ./cloop relative to the repo root (two levels up from tests/e2e/).
func binaryPath(t *testing.T) string {
	t.Helper()
	// __file__ is tests/e2e/helpers_test.go, so repo root is ../..
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("could not determine caller file path")
	}
	repoRoot := filepath.Join(filepath.Dir(thisFile), "..", "..")
	bin := filepath.Join(repoRoot, "cloop")
	if _, err := os.Stat(bin); os.IsNotExist(err) {
		t.Fatalf("cloop binary not found at %s — run 'go build -o cloop .' first", bin)
	}
	return bin
}

// newWorkDir creates a temp directory and registers cleanup.
func newWorkDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "cloop-e2e-*")
	if err != nil {
		t.Fatalf("creating temp workdir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

// run executes the cloop binary with the given args in workDir.
// It returns combined stdout+stderr output. The test fails if the binary
// cannot be started; non-zero exit codes are returned via the error.
func run(t *testing.T, workDir string, args ...string) (string, error) {
	t.Helper()
	bin := binaryPath(t)
	cmd := exec.Command(bin, args...)
	cmd.Dir = workDir
	// Disable color output so golden files are plain text.
	cmd.Env = append(os.Environ(), "NO_COLOR=1", "TERM=dumb")
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// mustRun is like run but fails the test on any error.
func mustRun(t *testing.T, workDir string, args ...string) string {
	t.Helper()
	out, err := run(t, workDir, args...)
	if err != nil {
		t.Fatalf("cloop %v failed: %v\nOutput:\n%s", args, err, out)
	}
	return out
}

// normalizeOutput replaces dynamic values (timestamps, paths, versions) with
// stable placeholders so golden files don't drift on each run.
var (
	rePath      = regexp.MustCompile(`(/tmp|/var/folders|C:\\Users)[^\s"']+`)
	reTimestamp = regexp.MustCompile(`\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}(:\d{2})?(\.\d+)?(Z|[+-]\d{2}:?\d{2})?`)
	reVersion   = regexp.MustCompile(`v\d+\.\d+\.\d+`)
	reDuration  = regexp.MustCompile(`\d+(\.\d+)?(ms|s|m|h)\b`)
	reUUID      = regexp.MustCompile(`[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)
)

func normalizeOutput(s, workDir string) string {
	// Replace the specific workdir path first.
	if workDir != "" {
		s = strings.ReplaceAll(s, workDir, "<WORKDIR>")
	}
	s = rePath.ReplaceAllString(s, "<PATH>")
	s = reTimestamp.ReplaceAllString(s, "<TIMESTAMP>")
	s = reVersion.ReplaceAllString(s, "<VERSION>")
	s = reDuration.ReplaceAllString(s, "<DURATION>")
	s = reUUID.ReplaceAllString(s, "<UUID>")
	return s
}

// goldenPath returns the path to the golden file for a given test name.
func goldenPath(name string) string {
	_, thisFile, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(thisFile), "testdata", name+".golden")
}

// assertGolden compares got against the golden file. If -update is set, it
// writes the golden file instead. The comparison is line-by-line so diffs
// show clearly on failure.
func assertGolden(t *testing.T, name, got string) {
	t.Helper()
	path := goldenPath(name)

	if *updateGolden {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("mkdir testdata: %v", err)
		}
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatalf("write golden %s: %v", path, err)
		}
		t.Logf("updated golden file: %s", path)
		return
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("golden file missing (%s) — run with -update to create it", path)
	}

	want := string(data)
	if want != got {
		wantLines := strings.Split(want, "\n")
		gotLines := strings.Split(got, "\n")
		maxLines := len(wantLines)
		if len(gotLines) > maxLines {
			maxLines = len(gotLines)
		}
		var diff strings.Builder
		for i := 0; i < maxLines; i++ {
			var wl, gl string
			if i < len(wantLines) {
				wl = wantLines[i]
			}
			if i < len(gotLines) {
				gl = gotLines[i]
			}
			if wl != gl {
				diff.WriteString(fmt.Sprintf("line %d:\n  want: %q\n  got:  %q\n", i+1, wl, gl))
			}
		}
		t.Fatalf("golden mismatch for %s:\n%s", name, diff.String())
	}
}

// assertContains fails the test if s does not contain substr.
func assertContains(t *testing.T, s, substr string) {
	t.Helper()
	if !strings.Contains(s, substr) {
		t.Errorf("expected output to contain %q\nGot:\n%s", substr, s)
	}
}

// assertNotContains fails the test if s contains substr.
func assertNotContains(t *testing.T, s, substr string) {
	t.Helper()
	if strings.Contains(s, substr) {
		t.Errorf("expected output NOT to contain %q\nGot:\n%s", substr, s)
	}
}

// writeFixtureState writes a pre-built state.json to workDir/.cloop/.
func writeFixtureState(t *testing.T, workDir string, state map[string]interface{}) {
	t.Helper()
	cloopDir := filepath.Join(workDir, ".cloop")
	if err := os.MkdirAll(cloopDir, 0o755); err != nil {
		t.Fatalf("mkdir .cloop: %v", err)
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		t.Fatalf("marshal fixture state: %v", err)
	}
	if err := os.WriteFile(filepath.Join(cloopDir, "state.json"), data, 0o644); err != nil {
		t.Fatalf("write fixture state: %v", err)
	}
}

// now returns a stable time string for fixtures.
func fixedTime() string {
	return time.Date(2026, 1, 15, 10, 0, 0, 0, time.UTC).Format(time.RFC3339)
}
