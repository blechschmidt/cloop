// Package arch_test gates the shape of the module against decay that no
// behavioural test can see.
//
// The failure it exists to catch: pkg/adr was a complete 433-line feature —
// a decision-record store with a Proposed/Accepted/Superseded lifecycle and
// atomic writes — that nothing imported. It compiled, it vetted clean, `go
// test ./...` was green, and it was dead. Nothing was wrong with the code; the
// command that would have called it was never written. It sat that way for
// months and was found by someone grepping by hand.
//
// That is the whole class: an unreferenced package is invisible to the
// compiler (it still builds), to vet (it is still correct), and to the test
// suite (its own tests still pass). It costs a reader who greps for a symbol
// and finds a plausible implementation that no code path can reach, and it
// costs a maintainer who refactors it. So the check has to be structural, and
// it has to run on every commit rather than whenever someone thinks to look.
//
// Two outcomes are legitimate when this fails, and the gate deliberately does
// not prefer one: delete the package, or wire it up. What it refuses is the
// third state, where the code stays and the decision is never made.
package arch_test

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/internal/hometest"
)

// exempt lists packages that are unreferenced on purpose, each with the reason.
//
// It is empty, and that is the intended steady state. An entry here is a hole
// in the gate, so anything added needs an argument a reader can check — "we
// might need it later" is the position that produced pkg/adr.
// TestExemptionsAreStillWarranted rejects entries that have gone stale.
var exempt = map[string]string{}

// TestMain isolates the per-user state directory. This package has no non-test
// source, which the tests/hermetic gate treats as a harness that could drive a
// subprocess inheriting $HOME. It does not, but satisfying the rule costs two
// lines and arguing for an exception costs more.
func TestMain(m *testing.M) {
	os.Exit(hometest.Isolate(m))
}

// pkgNode is one directory of Go source in this module.
type pkgNode struct {
	dir        string          // slash-separated, relative to the repo root; "." for the root
	importPath string          // full import path
	name       string          // package clause of its non-test files
	hasSource  bool            // has at least one non-test .go file
	hasTests   bool            // has at least one _test.go file
	imports    map[string]bool // every import path appearing in any of its files
}

// isTestHarness reports whether a directory is part of the module's test
// tree, whose packages are meant to be run by `go test` rather than imported.
//
// The directory is the criterion rather than "has no non-test source", which
// is what this originally used and got wrong: tests/security carries a
// non-test helper (callgraph.go) beside its twenty test files, which made it
// look like an unreferenced library. Keying on the tests/ root states the
// convention instead of inferring it, and it does not quietly break the next
// time a harness grows a helper.
func isTestHarness(dir string) bool {
	return dir == "tests" || strings.HasPrefix(dir, "tests/")
}

// orphans returns the packages in nodes that nothing else imports.
//
// Three kinds of package are unreferenced by construction and must never be
// reported:
//
//   - A main package is an entry point. Being imported by nothing is what
//     makes it a binary rather than a library.
//   - A package under tests/ is a harness; see isTestHarness.
//   - A package with no non-test source at all has nothing to import.
//
// Note that a package is judged by directory, not by package clause, so an
// external test file (package foo_test living alongside package foo) importing
// its own subject does not count as a reference. That case matters: it is
// exactly what a well-tested orphan looks like, and counting it would let
// pkg/adr pass by adding a test file to it.
func orphans(nodes []pkgNode, exempt map[string]string) []pkgNode {
	referenced := make(map[string]bool)
	for _, n := range nodes {
		for imp := range n.imports {
			// A directory importing its own import path is the external-test
			// case above, never a real dependency.
			if imp != n.importPath {
				referenced[imp] = true
			}
		}
	}

	var out []pkgNode
	for _, n := range nodes {
		switch {
		case !n.hasSource, n.name == "main", isTestHarness(n.dir), referenced[n.importPath]:
			continue
		}
		if _, ok := exempt[n.dir]; ok {
			continue
		}
		out = append(out, n)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].dir < out[j].dir })
	return out
}

// scanTree parses every Go package directory in the module rooted at root.
//
// Source is parsed rather than resolved with `go list` so the gate needs no
// toolchain subprocess and no network, matching tests/hermetic. One consequence
// is deliberate: build constraints are ignored, so a file excluded on this
// platform still contributes its imports. That errs toward calling a package
// referenced, which is the safe direction — a false orphan report would be a
// test that fails for a reason the author cannot act on.
func scanTree(root, modulePath string) ([]pkgNode, error) {
	byDir := make(map[string]*pkgNode)
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
			// A directory with its own go.mod belongs to a different module.
			// `go build ./...` never compiles it, so this module's import
			// graph says nothing about whether it is reachable — and an
			// unrelated Go project checked out into the tree (polyauth/ is
			// one) would otherwise be reported as a tree full of orphans.
			if path != root {
				if _, statErr := os.Stat(filepath.Join(path, "go.mod")); statErr == nil {
					return filepath.SkipDir
				}
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}

		relDir, rerr := filepath.Rel(root, filepath.Dir(path))
		if rerr != nil {
			return rerr
		}
		relDir = filepath.ToSlash(relDir)

		node := byDir[relDir]
		if node == nil {
			node = &pkgNode{
				dir:        relDir,
				importPath: importPathFor(modulePath, relDir),
				imports:    make(map[string]bool),
			}
			byDir[relDir] = node
		}

		// ImportsOnly stops after the import block, which is all this gate
		// reads, and still populates the package clause.
		f, perr := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if perr != nil {
			// An unparseable file is a build failure, which belongs to
			// `go build` rather than to this gate.
			return nil
		}

		if strings.HasSuffix(path, "_test.go") {
			node.hasTests = true
		} else {
			node.hasSource = true
			if f.Name != nil {
				node.name = f.Name.Name
			}
		}
		for _, imp := range f.Imports {
			p, uerr := strconv.Unquote(imp.Path.Value)
			if uerr != nil {
				continue
			}
			node.imports[p] = true
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	out := make([]pkgNode, 0, len(byDir))
	for _, n := range byDir {
		out = append(out, *n)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].dir < out[j].dir })
	return out, nil
}

// importPathFor joins a module path and a root-relative directory.
func importPathFor(modulePath, relDir string) string {
	if relDir == "." || relDir == "" {
		return modulePath
	}
	return modulePath + "/" + relDir
}

// repoRoot locates the repository from this file's compile-time path, so the
// gate works regardless of the working directory it runs in.
func repoRoot(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller could not locate orphan_test.go")
	}
	// tests/arch/orphan_test.go -> repo root
	return filepath.Dir(filepath.Dir(filepath.Dir(thisFile)))
}

// modulePath reads the module path out of go.mod.
func modulePath(t *testing.T, root string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		t.Fatalf("read go.mod: %v", err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		if rest, ok := strings.CutPrefix(strings.TrimSpace(line), "module "); ok {
			return strings.TrimSpace(rest)
		}
	}
	t.Fatalf("no module directive in %s/go.mod", root)
	return ""
}

// TestNoOrphanedPackages is the gate.
func TestNoOrphanedPackages(t *testing.T) {
	root := repoRoot(t)
	nodes, err := scanTree(root, modulePath(t, root))
	if err != nil {
		t.Fatalf("scan %s: %v", root, err)
	}

	// A gate that inspects nothing passes. If a layout change or a bug in the
	// walk left this with no packages to judge, that must be a failure rather
	// than a green run reporting on an empty set.
	judged := 0
	for _, n := range nodes {
		if n.hasSource && n.name != "main" {
			judged++
		}
	}
	if judged < 50 {
		t.Fatalf("this gate judged only %d importable packages, which cannot be right for "+
			"this module — the walk or the module path has drifted and it is no longer "+
			"checking anything", judged)
	}
	t.Logf("judged %d importable packages across %d source directories", judged, len(nodes))

	for _, o := range orphans(nodes, exempt) {
		t.Errorf("package %s is imported by nothing in this module.\n"+
			"    It compiles and its own tests pass, so no other check can see this.\n"+
			"    Resolve it one way or the other — the state to avoid is leaving it undecided:\n"+
			"      (a) delete %s if the feature is abandoned, or\n"+
			"      (b) wire it up behind a command or an existing call path, with tests.\n"+
			"    If it is genuinely meant to be unreferenced, add %q to exempt in\n"+
			"    tests/arch/orphan_test.go with a reason a reader can check.",
			o.importPath, o.dir, o.dir)
	}
}

// TestExemptionsAreStillWarranted stops the escape hatch from becoming the way
// the gate is satisfied. An exemption is legitimate only while the package
// still exists and is still unreferenced; once either stops being true the
// entry is dead weight that would silently cover a future orphan.
func TestExemptionsAreStillWarranted(t *testing.T) {
	root := repoRoot(t)
	nodes, err := scanTree(root, modulePath(t, root))
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	byDir := make(map[string]pkgNode, len(nodes))
	for _, n := range nodes {
		byDir[n.dir] = n
	}
	// Which packages would be reported if nothing were exempt.
	orphaned := make(map[string]bool)
	for _, o := range orphans(nodes, nil) {
		orphaned[o.dir] = true
	}

	for dir, why := range exempt {
		if strings.TrimSpace(why) == "" {
			t.Errorf("exemption for %s carries no reason", dir)
		}
		if _, ok := byDir[dir]; !ok {
			t.Errorf("exempt package %s no longer exists — remove the exemption", dir)
			continue
		}
		if !orphaned[dir] {
			t.Errorf("exempt package %s is now referenced — remove the exemption so the "+
				"gate covers it again", dir)
		}
	}
}

// --- tests for the gate's own logic -------------------------------------
//
// The checks above are only as good as the two functions they rest on, and
// both fail silently when wrong: a bug in orphans() that marks everything
// referenced, or one in scanTree() that finds no files, turns the gate green.

func TestOrphansClassification(t *testing.T) {
	const mod = "example.com/m"
	node := func(dir, name string, hasSource bool, imports ...string) pkgNode {
		n := pkgNode{
			dir:        dir,
			importPath: importPathFor(mod, dir),
			name:       name,
			hasSource:  hasSource,
			imports:    make(map[string]bool),
		}
		for _, i := range imports {
			n.imports[i] = true
		}
		return n
	}

	cases := map[string]struct {
		nodes []pkgNode
		want  []string
	}{
		"an unreferenced library is an orphan": {
			nodes: []pkgNode{
				node(".", "main", true, mod+"/used"),
				node("used", "used", true),
				node("dead", "dead", true),
			},
			want: []string{"dead"},
		},
		"a main package is never an orphan": {
			nodes: []pkgNode{
				node(".", "main", true),
				node("cmd/tool", "main", true),
			},
			want: nil,
		},
		"a test-only harness is never an orphan": {
			nodes: []pkgNode{
				node(".", "main", true),
				// hasSource false: only _test.go files live here.
				node("tests/e2e", "", false),
			},
			want: nil,
		},
		"an external test importing its own subject is not a reference": {
			nodes: []pkgNode{
				node(".", "main", true),
				// pkg/a holds both package a and package a_test; the test file's
				// import of pkg/a lands in the same directory's import set.
				node("pkg/a", "a", true, mod+"/pkg/a"),
			},
			want: []string{"pkg/a"},
		},
		"an import from another package's test counts as a reference": {
			nodes: []pkgNode{
				node(".", "main", true, mod+"/pkg/b"),
				node("pkg/a", "a", true),
				// pkg/b's import of pkg/a comes from one of its _test.go files;
				// the scan merges a directory's test and non-test imports.
				node("pkg/b", "b", true, mod+"/pkg/a"),
			},
			want: nil,
		},
		"a harness under tests/ is never an orphan": {
			nodes: []pkgNode{
				node(".", "main", true),
				// tests/security has a non-test helper beside its test files,
				// so hasSource is true and only the tests/ rule saves it.
				node("tests/security", "security", true),
				node("tests/e2e", "", false),
			},
			want: nil,
		},
		"a package merely named tests elsewhere is still judged": {
			nodes: []pkgNode{
				node(".", "main", true),
				node("pkg/tests", "tests", true),
			},
			want: []string{"pkg/tests"},
		},
		"a third-party import never marks a local package referenced": {
			nodes: []pkgNode{
				node(".", "main", true, "github.com/spf13/cobra"),
				node("pkg/a", "a", true),
			},
			want: []string{"pkg/a"},
		},
		"a chain is fully referenced": {
			nodes: []pkgNode{
				node(".", "main", true, mod+"/pkg/a"),
				node("pkg/a", "a", true, mod+"/pkg/b"),
				node("pkg/b", "b", true),
			},
			want: nil,
		},
		"a mutually-importing island is still orphaned": {
			// Neither is reachable from any entry point, though each is
			// imported. This is the limit of the check and worth pinning:
			// it reports nothing here.
			nodes: []pkgNode{
				node(".", "main", true),
				node("pkg/a", "a", true, mod+"/pkg/b"),
				node("pkg/b", "b", true, mod+"/pkg/a"),
			},
			want: nil,
		},
	}

	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			var got []string
			for _, o := range orphans(c.nodes, nil) {
				got = append(got, o.dir)
			}
			if strings.Join(got, ",") != strings.Join(c.want, ",") {
				t.Errorf("orphans = %v, want %v", got, c.want)
			}
		})
	}
}

func TestOrphansHonoursExemptions(t *testing.T) {
	nodes := []pkgNode{
		{dir: ".", importPath: "m", name: "main", hasSource: true, imports: map[string]bool{}},
		{dir: "pkg/dead", importPath: "m/pkg/dead", name: "dead", hasSource: true, imports: map[string]bool{}},
	}
	if got := orphans(nodes, nil); len(got) != 1 {
		t.Fatalf("without an exemption got %d orphans, want 1", len(got))
	}
	if got := orphans(nodes, map[string]string{"pkg/dead": "a reason"}); len(got) != 0 {
		t.Errorf("with an exemption got %d orphans, want 0", len(got))
	}
}

func TestImportPathFor(t *testing.T) {
	cases := map[string]string{
		".":       "example.com/m",
		"":        "example.com/m",
		"pkg/a":   "example.com/m/pkg/a",
		"cmd":     "example.com/m/cmd",
		"a/b/c/d": "example.com/m/a/b/c/d",
	}
	for in, want := range cases {
		if got := importPathFor("example.com/m", in); got != want {
			t.Errorf("importPathFor(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestScanTreeWalksTheRightDirectories builds a synthetic module and checks
// that the walk reads what it should and skips what it must — in particular the
// nested module, whose packages are not part of this module's graph.
func TestScanTreeWalksTheRightDirectories(t *testing.T) {
	root := t.TempDir()
	write := func(rel, content string) {
		t.Helper()
		full := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	write("go.mod", "module example.com/m\n\ngo 1.25\n")
	write("main.go", "package main\n\nimport \"example.com/m/pkg/a\"\n")
	write("pkg/a/a.go", "package a\n")
	write("pkg/a/a_test.go", "package a_test\n\nimport \"example.com/m/pkg/a\"\n")
	write("pkg/dead/dead.go", "package dead\n")
	// None of the following may be judged.
	write("vendor/x/x.go", "package x\n")
	write("pkg/a/testdata/fixture.go", "package fixture\n")
	write("nested/go.mod", "module example.com/nested\n")
	write("nested/n.go", "package n\n")
	write("notes.md", "not go\n")

	nodes, err := scanTree(root, "example.com/m")
	if err != nil {
		t.Fatalf("scanTree: %v", err)
	}

	byDir := make(map[string]pkgNode)
	var dirs []string
	for _, n := range nodes {
		byDir[n.dir] = n
		dirs = append(dirs, n.dir)
	}

	want := []string{".", "pkg/a", "pkg/dead"}
	if strings.Join(dirs, ",") != strings.Join(want, ",") {
		t.Errorf("scanned dirs = %v, want %v (vendor, testdata and the nested module excluded)", dirs, want)
	}

	if root := byDir["."]; root.name != "main" || !root.hasSource {
		t.Errorf("root node = %+v, want package main with source", root)
	}
	a := byDir["pkg/a"]
	if !a.hasSource || !a.hasTests || a.name != "a" {
		t.Errorf("pkg/a node = %+v, want source+tests and package name a", a)
	}
	if !a.imports["example.com/m/pkg/a"] {
		t.Error("pkg/a should have recorded its external test's self-import")
	}

	// And the whole point: the synthetic tree has exactly one orphan.
	var got []string
	for _, o := range orphans(nodes, nil) {
		got = append(got, o.dir)
	}
	if strings.Join(got, ",") != "pkg/dead" {
		t.Errorf("orphans = %v, want [pkg/dead] — pkg/a is referenced by main, and its "+
			"own test file must not rescue it", got)
	}
}

// TestScanTreeReportsAWalkFailure guards the error path: a scan that silently
// returned an empty slice would disable the gate.
func TestScanTreeReportsAWalkFailure(t *testing.T) {
	if _, err := scanTree(filepath.Join(t.TempDir(), "does-not-exist"), "example.com/m"); err == nil {
		t.Error("scanTree on a missing root returned no error")
	}
}

// TestGateSeesTheRealModule is a sanity check on the live scan, independent of
// the assertions in TestNoOrphanedPackages: the packages named here are load
// bearing and must be found, with cmd referenced and the root a main package.
func TestGateSeesTheRealModule(t *testing.T) {
	root := repoRoot(t)
	mod := modulePath(t, root)
	if mod != "github.com/blechschmidt/cloop" {
		t.Fatalf("module path = %q, unexpected for this repository", mod)
	}
	nodes, err := scanTree(root, mod)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	byDir := make(map[string]pkgNode, len(nodes))
	for _, n := range nodes {
		byDir[n.dir] = n
	}
	for _, dir := range []string{".", "cmd", "pkg/pm", "pkg/state", "pkg/ui", "pkg/adr"} {
		if _, ok := byDir[dir]; !ok {
			t.Errorf("scan did not find %s", dir)
		}
	}
	if got := byDir["."].name; got != "main" {
		t.Errorf("root package name = %q, want main", got)
	}
	if _, ok := byDir["polyauth"]; ok {
		t.Error("the nested polyauth module was scanned; it is not part of this module")
	}
}
