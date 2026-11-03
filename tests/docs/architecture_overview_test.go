package docs_test

// The architecture overview places every package, and names nothing that is
// not there (Task 20475).
//
// docs/architecture/README.md is the one page that draws the whole system: the
// processes, what each component is for, and where each security control sits.
// A map like that rots in two directions, and neither fails anything on its
// own. A package is added, the feature works, the tests pass, and the map is
// quietly no longer the whole map — which is how ten subsystems once shipped
// before docs/ existed (see drift_test.go). Or a package is renamed, folded
// into another or deleted, and the page goes on naming a path that reads
// exactly like a pointer to code and leads nowhere.
//
// So both directions are read from the tree rather than from a list kept here,
// which would rot the same way:
//
//   - every package directly under pkg/, and every suite directly under
//     tests/, is named on the page as a backticked path;
//   - every backticked repository path the page names — pkg/…, cmd/…,
//     internal/…, tests/… — exists, and every test it cites is a test in this
//     module.

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// architectureOverview is the page this file gates, relative to the repository
// root.
const architectureOverview = "docs/architecture/README.md"

// citedRepoPath matches a repository path written in backticks — `pkg/ui`,
// `pkg/executor/remote`, `cmd/cloop-forward`, `tests/security/`,
// `pkg/ui/server.go` — and captures it without a trailing slash. A path with a
// line suffix (`pkg/ui/server.go:42`) is not matched: line numbers rot faster
// than any check could keep up with, and the page does not use them.
var citedRepoPath = regexp.MustCompile("`((?:pkg|cmd|internal|tests)(?:/[A-Za-z0-9_.-]+)*)/?`")

// overviewProblems checks page against the tree: every path in required must
// be named, every named path must exist, and every cited test must be in
// defined. It returns one message per problem, sorted within each kind.
func overviewProblems(page string, required []string, exists func(string) bool, defined map[string]bool) []string {
	cited := map[string]bool{}
	for _, m := range citedRepoPath.FindAllStringSubmatch(page, -1) {
		cited[m[1]] = true
	}

	var problems []string
	for _, p := range required {
		if !cited[p] {
			problems = append(problems, fmt.Sprintf("%s is not placed on %s.\n"+
				"    Add it to the component map under the layer it belongs to: a row saying what it\n"+
				"    is for, or the list under \"The rest of the CLI\" if it is one more command.",
				p, architectureOverview))
		}
	}

	named := make([]string, 0, len(cited))
	for p := range cited {
		named = append(named, p)
	}
	sort.Strings(named)
	for _, p := range named {
		if !exists(p) {
			problems = append(problems, fmt.Sprintf("%s names `%s`, which does not exist.\n"+
				"    It was renamed, merged or deleted; name what replaced it, or drop the sentence.",
				architectureOverview, p))
		}
	}

	var tests []string
	seen := map[string]bool{}
	for _, m := range citedTestName.FindAllStringSubmatch(page, -1) {
		if !seen[m[1]] {
			seen[m[1]] = true
			tests = append(tests, m[1])
		}
	}
	sort.Strings(tests)
	for _, name := range tests {
		if !defined[name] {
			problems = append(problems, fmt.Sprintf("%s cites %s, which is not a test in this module.\n"+
				"    A citation tells a reader a claim is machine-checked; cite the test that checks it.",
				architectureOverview, name))
		}
	}
	return problems
}

// requiredOnOverview returns every package directly under pkg/ — a directory
// holding at least one non-test .go file — and every directory directly under
// tests/, as repository paths.
func requiredOnOverview(t *testing.T, root string) []string {
	t.Helper()
	var out []string

	pkgs, err := os.ReadDir(filepath.Join(root, "pkg"))
	if err != nil {
		t.Fatalf("reading pkg/: %v", err)
	}
	for _, d := range pkgs {
		if !d.IsDir() {
			continue
		}
		files, err := os.ReadDir(filepath.Join(root, "pkg", d.Name()))
		if err != nil {
			t.Fatalf("reading pkg/%s: %v", d.Name(), err)
		}
		for _, f := range files {
			name := f.Name()
			if !f.IsDir() && strings.HasSuffix(name, ".go") && !strings.HasSuffix(name, "_test.go") {
				out = append(out, "pkg/"+d.Name())
				break
			}
		}
	}

	suites, err := os.ReadDir(filepath.Join(root, "tests"))
	if err != nil {
		t.Fatalf("reading tests/: %v", err)
	}
	for _, d := range suites {
		if d.IsDir() {
			out = append(out, "tests/"+d.Name())
		}
	}
	return out
}

// TestArchitectureOverviewPlacesEveryPackage is the gate.
func TestArchitectureOverviewPlacesEveryPackage(t *testing.T) {
	root := repoRoot(t)
	page, err := os.ReadFile(filepath.Join(root, architectureOverview))
	if err != nil {
		t.Fatalf("%s is missing: %v", architectureOverview, err)
	}

	required := requiredOnOverview(t, root)
	// Floors, so that a moved directory or a walk that stopped matching shows
	// up as the gate going blind rather than as the gate passing: 261 packages
	// and 13 suites existed when it was written.
	if len(required) < 250 {
		t.Fatalf("only %d packages and suites found under pkg/ and tests/; the walk is not seeing the tree", len(required))
	}
	if n := len(citedRepoPath.FindAllString(string(page), -1)); n < 300 {
		t.Fatalf("%s names only %d repository paths; this gate is not reading the page it was written for",
			architectureOverview, n)
	}

	exists := func(rel string) bool {
		_, err := os.Stat(filepath.Join(root, filepath.FromSlash(rel)))
		return err == nil
	}
	for _, p := range overviewProblems(string(page), required, exists, definedTests(t, root)) {
		t.Error(p)
	}
}

// TestArchitectureOverviewGateCatchesDrift is the gate's falsification
// control: an unplaced package, a path that is gone and a test that does not
// exist are each reported, and a page that gets everything right is not.
func TestArchitectureOverviewGateCatchesDrift(t *testing.T) {
	tree := map[string]bool{"pkg/ui": true, "pkg/gitproxy": true, "tests/security": true, "cmd": true}
	exists := func(rel string) bool { return tree[rel] }
	defined := map[string]bool{"TestArchitectureOverviewPlacesEveryPackage": true}
	required := []string{"pkg/gitproxy", "pkg/ui", "tests/security"}

	good := "The hub is `pkg/ui`, behind `cmd`; pushes go through `pkg/gitproxy`, " +
		"checked by `tests/security/` and TestArchitectureOverviewPlacesEveryPackage.\n"
	if problems := overviewProblems(good, required, exists, defined); len(problems) != 0 {
		t.Fatalf("a page that names everything that exists was refused:\n%s", strings.Join(problems, "\n"))
	}

	drifted := "The hub is `pkg/ui`; pushes go through `pkg/gitproxyv0`, checked by " +
		"`tests/security` and TestThisWasNeverWritten.\n"
	problems := overviewProblems(drifted, required, exists, defined)
	want := []string{
		"pkg/gitproxy is not placed",
		"names `pkg/gitproxyv0`, which does not exist",
		"cites TestThisWasNeverWritten, which is not a test",
	}
	if len(problems) != len(want) {
		t.Fatalf("got %d problems, want %d:\n%s", len(problems), len(want), strings.Join(problems, "\n"))
	}
	for i, w := range want {
		if !strings.Contains(problems[i], w) {
			t.Errorf("problem %d = %q, want it to say %q", i, problems[i], w)
		}
	}
}
