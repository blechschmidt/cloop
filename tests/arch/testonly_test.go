package arch_test

// Test-only packages stay out of the binary (Task 20372).
//
// internal/ holds four packages written for tests: hometest sandboxes $HOME,
// taskfill builds fully populated tasks, and dbtemplate and statedbtest hand
// tests a migrated state.db by copying a file instead of migrating one. Go's
// internal/ rule only stops other modules from importing them; nothing stops a
// production file in this one from doing so.
//
// That would be worse than dead weight. Each imports "testing", which
// registers the test flags on any binary that links it. And statedbtest's
// whole purpose is to put a database in place that no migration produced —
// correct in a test, where it is proven identical to a migrated one, and a
// way past the schema guard, the version-skew refusal and every migration if
// a production path ever reached it. The CI race step got faster by copying
// databases; this keeps the copying in the tests.
//
// So: a non-test file may import one of these only if it is itself one of
// them, or part of a harness under tests/, which `go test` runs and nothing
// links.

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// testOnly are the module's test-helper packages, relative to the repository
// root, each with what it is for.
var testOnly = map[string]string{
	"internal/hometest":    "points $HOME at a sandbox for a whole test binary",
	"internal/taskfill":    "builds a pm.Task with every field set, for persistence tests",
	"internal/dbtemplate":  "captures a database once per test binary and copies it into place",
	"internal/statedbtest": "seeds a migrated state.db without migrating one",
}

func TestTestOnlyPackagesAreImportedOnlyByTests(t *testing.T) {
	root := repoRoot(t)
	for dir := range testOnly {
		if _, err := os.Stat(filepath.Join(root, dir)); err != nil {
			t.Errorf("%s is listed as test-only but does not exist: %v — remove it from testOnly", dir, err)
		}
	}
	violations, err := testOnlyViolations(root, modulePath(t, root))
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range violations {
		t.Errorf("%s. Production code must not link a test-only package; move the import "+
			"into a _test.go file.", v)
	}
}

// The gate must flag what it exists for, and only that.
func TestTestOnlyGateFlagsAProductionImport(t *testing.T) {
	root := t.TempDir()
	const mod = "example.com/m"
	write := func(rel, src string) {
		t.Helper()
		path := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("go.mod", "module "+mod+"\n")
	write("pkg/prod/prod.go", "package prod\nimport _ \""+mod+"/internal/statedbtest\"\n")
	write("pkg/prod/prod_test.go", "package prod\nimport _ \""+mod+"/internal/dbtemplate\"\n")
	write("internal/statedbtest/s.go", "package statedbtest\nimport _ \""+mod+"/internal/dbtemplate\"\n")
	write("tests/harness/h.go", "package harness\nimport _ \""+mod+"/internal/statedbtest\"\n")

	got, err := testOnlyViolations(root, mod)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || !strings.HasPrefix(got[0], "pkg/prod/prod.go imports internal/statedbtest") {
		t.Fatalf("violations = %q, want exactly the production file's import", got)
	}
}

// testOnlyViolations lists every non-test file under root, outside the
// test-only packages themselves and the tests/ harnesses, that imports one of
// them.
func testOnlyViolations(root, mod string) ([]string, error) {
	var violations []string
	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "testdata", "vendor":
				return filepath.SkipDir
			}
			if path != root {
				if _, err := os.Stat(filepath.Join(path, "go.mod")); err == nil {
					return filepath.SkipDir // another module
				}
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		dir, err := filepath.Rel(root, filepath.Dir(path))
		if err != nil {
			return err
		}
		dir = filepath.ToSlash(dir)
		if _, ok := testOnly[dir]; ok || isTestHarness(dir) {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		for _, imp := range f.Imports {
			ip, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				continue
			}
			pkg, ok := strings.CutPrefix(ip, mod+"/")
			if !ok {
				continue
			}
			if why, ok := testOnly[pkg]; ok {
				file, _ := filepath.Rel(root, path)
				violations = append(violations, filepath.ToSlash(file)+" imports "+pkg+" ("+why+")")
			}
		}
		return nil
	})
	sort.Strings(violations)
	return violations, err
}
