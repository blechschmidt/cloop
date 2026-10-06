package docs_test

// Every test the security docs cite must exist (Task 20391).
//
// docs/security/model.md and threat-model.md back their claims with test
// names — "a mutating verb is never authorized by a read permission
// (TestReadOnlyRoutesRejectMutatingMethods)" — and a reader takes the name as
// evidence that the claim is machine-checked. Nothing checked the citation
// itself. A renamed test leaves the sentence citing a name that proves
// nothing, and a test that was deleted leaves a guarantee standing on air,
// with a citation that still looks exactly like evidence.
//
// So every Test… and Fuzz… name in docs/security/*.md has to be the name of a
// test function in this module. Not in a nested module (polyauth carries its
// own), not in testdata, not in a feature worktree under .cloop/ — a name only
// counts where `go test ./...` would run it.

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// citedTestName matches a Go test or fuzz function name in prose: the prefix
// followed by what Go requires of a test name — not a lowercase letter. The
// bare word "Test", as in a table's "| Guarantee | Test |" header, is not one.
var citedTestName = regexp.MustCompile(`\b((?:Test|Fuzz)[A-Z0-9_][A-Za-z0-9_]*)`)

// definedTestFunc matches a top-level test or fuzz function declaration.
// gofmt, which CI enforces, puts every top-level func at column 0.
var definedTestFunc = regexp.MustCompile(`(?m)^func ((?:Test|Fuzz)[A-Z0-9_][A-Za-z0-9_]*)\(`)

// testCitation is where a doc cites a test.
type testCitation struct {
	file string
	line int
}

// citedTests returns every test name cited in the markdown files directly in
// dir, with where each is cited.
func citedTests(t *testing.T, dir string) map[string][]testCitation {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(dir, "*.md"))
	if err != nil {
		t.Fatal(err)
	}
	out := map[string][]testCitation{}
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for i, line := range strings.Split(string(data), "\n") {
			for _, m := range citedTestName.FindAllStringSubmatch(line, -1) {
				out[m[1]] = append(out[m[1]], testCitation{file: filepath.Base(f), line: i + 1})
			}
		}
	}
	return out
}

// definedTests returns the name of every test and fuzz function in the
// module rooted at root.
func definedTests(t *testing.T, root string) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path == root {
				return nil
			}
			switch d.Name() {
			case ".git", ".cloop", "node_modules", "vendor", "testdata":
				return filepath.SkipDir
			}
			// A nested module is not this module: its tests run under its own
			// go.mod, or not at all.
			if _, err := os.Stat(filepath.Join(path, "go.mod")); err == nil {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, "_test.go") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, m := range definedTestFunc.FindAllSubmatch(data, -1) {
			out[string(m[1])] = true
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// missingTests returns the cited names that are not defined, sorted, each with
// where it is cited.
func missingTests(cited map[string][]testCitation, defined map[string]bool) []string {
	var out []string
	for name, where := range cited {
		if defined[name] {
			continue
		}
		locs := make([]string, 0, len(where))
		for _, w := range where {
			locs = append(locs, w.file+":"+strconv.Itoa(w.line))
		}
		out = append(out, name+" (cited at "+strings.Join(locs, ", ")+")")
	}
	sort.Strings(out)
	return out
}

// TestSecurityDocsCiteOnlyRealTests is the gate.
func TestSecurityDocsCiteOnlyRealTests(t *testing.T) {
	root := repoRoot(t)
	cited := citedTests(t, filepath.Join(root, "docs", "security"))
	// Without a floor the gate passes on docs that cite nothing — a moved
	// directory, a regexp that stopped matching. 473 names resolved when this
	// gate was written; a drop far below that is the gate going blind, not
	// the docs getting shorter.
	if len(cited) < 400 {
		t.Fatalf("only %d test names cited in docs/security; this gate is not seeing the docs it was written for", len(cited))
	}
	defined := definedTests(t, root)
	if len(defined) < 5000 {
		t.Fatalf("only %d test functions found in the module; the walk is not seeing the tree", len(defined))
	}
	for _, m := range missingTests(cited, defined) {
		t.Errorf("docs/security cites %s, which is not a test in this module.\n"+
			"    A citation is what tells a reader a claim is machine-checked. Cite the test that\n"+
			"    checks it now, or — if nothing does — say so instead of citing a name.", m)
	}
}

// TestTestCitationGateCatchesAMissingTest is the gate's falsification
// control: a doc citing a test that does not exist is reported, the bare word
// "Test" is not a citation, and a real name passes.
func TestTestCitationGateCatchesAMissingTest(t *testing.T) {
	dir := t.TempDir()
	doc := "| Guarantee | Test |\n| --- | --- |\n" +
		"| Holds | `TestSecurityDocsCiteOnlyRealTests` |\n" +
		"| Holds too | `TestThisGuaranteeWasNeverTested` and FuzzNorThis |\n" +
		"Testing, Tests and TestingFrameworks are prose.\n"
	if err := os.WriteFile(filepath.Join(dir, "model.md"), []byte(doc), 0o644); err != nil {
		t.Fatal(err)
	}
	cited := citedTests(t, dir)
	for _, prose := range []string{"Test", "Tests", "Testing", "TestingFrameworks"} {
		if _, ok := cited[prose]; ok {
			t.Errorf("%q was read as a citation", prose)
		}
	}
	missing := missingTests(cited, map[string]bool{"TestSecurityDocsCiteOnlyRealTests": true})
	if len(missing) != 2 ||
		!strings.HasPrefix(missing[0], "FuzzNorThis (cited at model.md:4)") ||
		!strings.HasPrefix(missing[1], "TestThisGuaranteeWasNeverTested (cited at model.md:4)") {
		t.Fatalf("missing = %q, want the two invented names, each with where it is cited", missing)
	}
}
