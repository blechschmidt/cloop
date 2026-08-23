// Package hermetic_test asserts that the test suite cannot write to the
// machine it runs on.
//
// This is a structural gate rather than a behavioural one, and it exists
// because the failure it prevents is invisible to every other kind of test. A
// package whose tests write to $HOME still passes its own assertions; the
// damage lands in a file outside the working tree, on one developer's machine,
// and surfaces later as an unrelated test failing for reasons that look like a
// bug in the code under test. The specific instance that motivated this: a
// dashboard test appended one entry per run to the real
// ~/.cloop/projects.json until project index 99 resolved, at which point three
// authorization tests started failing — for that developer only, since CI
// always starts from an empty HOME.
//
// So the rule is enforced against the source, not against a run: a package
// that can reach per-user state and has tests must isolate that state in
// TestMain. That catches a new package on the day it is added rather than
// whenever someone next notices their home directory has been edited.
package hermetic_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/internal/hometest"
)

// perUserStatePackages are the packages that resolve a path under the user's
// home directory. A package importing one of these can write outside the
// working tree even if it never calls os.UserHomeDir itself.
var perUserStatePackages = map[string]string{
	"github.com/blechschmidt/cloop/pkg/multiui":        "~/.cloop/projects.json (the multi-project registry)",
	"github.com/blechschmidt/cloop/pkg/globalbudget":   "~/.config/cloop/{budget.yaml,costs.jsonl,global.db}",
	"github.com/blechschmidt/cloop/pkg/workspace":      "~/.config/cloop/workspaces.json",
	"github.com/blechschmidt/cloop/pkg/profile":        "~/.cloop/profiles.yaml",
	"github.com/blechschmidt/cloop/pkg/plugin":         "~/.cloop/plugins/",
	"github.com/blechschmidt/cloop/pkg/ratelimit":      "~/.claude/ usage snapshots",
	"github.com/blechschmidt/cloop/pkg/claudecodeauth": "~/.claude/ credentials",
}

// isolateHelper is the call a qualifying package's TestMain must make.
const isolateHelper = "hometest.Isolate"

// exempt lists packages that reach per-user state but must not isolate in
// TestMain, each with the reason. It is deliberately tiny: an exemption is a
// hole in this gate, so anything added here needs an argument that a reader
// can check, not just a name. TestExemptionsAreStillWarranted below rejects
// entries that have gone stale.
var exempt = map[string]string{
	"internal/hometest": "it is the isolation mechanism itself. Its tests call " +
		"isolate() explicitly where they need a sandbox, and TestGuardRejectsTheRealHome " +
		"has to observe the un-isolated environment in order to check that Guard " +
		"refuses it — which a package-wide TestMain would make impossible.",
}

// TestMain isolates this package too. It has no need of its own — the gate
// reads source from the working tree, never from $HOME — but a gate that
// exempted itself from its own rule would be arguing that the rule is
// negotiable.
func TestMain(m *testing.M) {
	os.Exit(hometest.Isolate(m))
}

// repoRoot walks up from this file to the module root.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not locate go.mod above the test's working directory")
		}
		dir = parent
	}
}

// pkgInfo is what the gate needs to know about one directory of Go source.
type pkgInfo struct {
	dir            string // relative to repo root
	hasTests       bool
	hasSource      bool     // has at least one non-test .go file
	reachesState   []string // human-readable reasons, sorted
	isolatesInMain bool
}

// scan parses every Go package directory in the module and records whether it
// can reach per-user state, whether it has tests, and whether its TestMain
// isolates.
func scan(t *testing.T, root string) []pkgInfo {
	t.Helper()

	byDir := map[string]*pkgInfo{}
	fset := token.NewFileSet()

	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			// Only directories that can hold Go this gate must not judge:
			// vendored or generated third-party code, and fuzz/golden corpora.
			// Trees with no Go in them (docs/, deploy/, plugins/) are not
			// listed — walking them costs nothing, and an earlier version that
			// did list them skipped tests/docs, a real package with tests,
			// because it matched on basename. Under-coverage that silent is
			// precisely what this gate exists to prevent elsewhere.
			switch d.Name() {
			case ".git", "node_modules", "testdata", "vendor":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		rel, rerr := filepath.Rel(root, filepath.Dir(path))
		if rerr != nil {
			return rerr
		}
		info := byDir[rel]
		if info == nil {
			info = &pkgInfo{dir: rel}
			byDir[rel] = info
		}

		isTest := strings.HasSuffix(path, "_test.go")
		if isTest {
			info.hasTests = true
		} else {
			info.hasSource = true
		}

		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			// A file this package cannot parse is a build failure that
			// belongs to `go build`, not to this gate.
			return nil
		}

		if isTest {
			if callsIsolateInTestMain(f) {
				info.isolatesInMain = true
			}
			// Test files are not evidence that the *package* reaches state;
			// only its buildable source is.
			return nil
		}

		for _, imp := range f.Imports {
			p, uerr := strconv.Unquote(imp.Path.Value)
			if uerr != nil {
				continue
			}
			if why, ok := perUserStatePackages[p]; ok {
				info.reachesState = append(info.reachesState,
					"imports "+filepath.Base(p)+", which owns "+why)
			}
		}
		if callsUserHomeDir(f) {
			info.reachesState = append(info.reachesState, "calls os.UserHomeDir")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}

	out := make([]pkgInfo, 0, len(byDir))
	for _, info := range byDir {
		// A package made only of test files exists to drive the built binary
		// rather than to call this module's packages — tests/e2e is the
		// example. The scan above cannot see that, because it reads reach out
		// of non-test source and there is none. And it is the case that needs
		// isolating most: a subprocess inherits $HOME, so the write happens in
		// a different process where no in-process safeguard applies.
		if info.hasTests && !info.hasSource {
			info.reachesState = append(info.reachesState,
				"has no non-test source, so it drives subprocesses that inherit $HOME")
		}
		info.reachesState = dedupe(info.reachesState)
		out = append(out, *info)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].dir < out[j].dir })
	return out
}

// callsUserHomeDir reports whether f contains an os.UserHomeDir call.
func callsUserHomeDir(f *ast.File) bool {
	found := false
	ast.Inspect(f, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "UserHomeDir" {
			return true
		}
		if ident, ok := sel.X.(*ast.Ident); ok && ident.Name == "os" {
			found = true
			return false
		}
		return true
	})
	return found
}

// callsIsolateInTestMain reports whether f declares TestMain and that TestMain
// calls hometest.Isolate. Both halves matter: a TestMain that exists but does
// not isolate is exactly the state this gate is meant to reject.
func callsIsolateInTestMain(f *ast.File) bool {
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "TestMain" || fn.Recv != nil || fn.Body == nil {
			continue
		}
		found := false
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "Isolate" {
				return true
			}
			if ident, ok := sel.X.(*ast.Ident); ok && ident.Name == "hometest" {
				found = true
				return false
			}
			return true
		})
		if found {
			return true
		}
	}
	return false
}

func dedupe(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := map[string]bool{}
	out := in[:0]
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

// TestPackagesReachingPerUserStateIsolateIt is the gate.
//
// Adding a package that reads $HOME and giving it a test is entirely
// reasonable; doing so without a TestMain that redirects $HOME is what this
// refuses. The remedy is three lines, and the failure message carries them.
func TestPackagesReachingPerUserStateIsolateIt(t *testing.T) {
	root := repoRoot(t)
	pkgs := scan(t, root)

	// The gate is only meaningful if it is actually looking at something. A
	// refactor that moves these packages or renames the helper would
	// otherwise turn it into a test that passes by inspecting nothing.
	checked := 0
	for _, p := range pkgs {
		if p.hasTests && len(p.reachesState) > 0 {
			checked++
		}
	}
	if checked == 0 {
		t.Fatal("this gate examined no packages at all — perUserStatePackages or the " +
			"repository layout has drifted, and it is no longer checking anything")
	}
	t.Logf("checked %d packages that have tests and can reach per-user state", checked)

	for _, p := range pkgs {
		if !p.hasTests || len(p.reachesState) == 0 || p.isolatesInMain {
			continue
		}
		if why, ok := exempt[filepath.ToSlash(p.dir)]; ok {
			t.Logf("exempt: %s — %s", p.dir, why)
			continue
		}
		t.Errorf("package %s has tests and can reach the user's home directory (%s), "+
			"but its TestMain does not call %s.\n"+
			"    Its tests will write to the machine they run on and leave it there.\n"+
			"    Add %s/main_test.go:\n\n"+
			"\t\tfunc TestMain(m *testing.M) { os.Exit(hometest.Isolate(m)) }\n\n"+
			"    importing github.com/blechschmidt/cloop/internal/hometest.",
			p.dir, strings.Join(p.reachesState, "; "), isolateHelper, p.dir)
	}
}

// TestExemptionsAreStillWarranted stops the escape hatch above from becoming
// the way the gate is satisfied. An exemption is only legitimate while the
// package still exists, still has tests, still reaches per-user state, and
// still does not isolate — once any of those stops being true the entry is
// dead weight that would silently cover a future regression in that package.
func TestExemptionsAreStillWarranted(t *testing.T) {
	root := repoRoot(t)
	byDir := map[string]pkgInfo{}
	for _, p := range scan(t, root) {
		byDir[filepath.ToSlash(p.dir)] = p
	}

	for dir, why := range exempt {
		if strings.TrimSpace(why) == "" {
			t.Errorf("exemption for %s carries no reason", dir)
		}
		p, ok := byDir[dir]
		if !ok {
			t.Errorf("exempt package %s no longer exists — remove the exemption", dir)
			continue
		}
		if !p.hasTests {
			t.Errorf("exempt package %s has no tests — the exemption is unnecessary", dir)
		}
		if len(p.reachesState) == 0 {
			t.Errorf("exempt package %s no longer reaches per-user state — "+
				"remove the exemption so the gate covers it again", dir)
		}
		if p.isolatesInMain {
			t.Errorf("exempt package %s now isolates in TestMain — remove the "+
				"exemption, it is granting a hole nothing needs", dir)
		}
	}
}

// TestGateRecognisesTheCanonicalTestMain guards the AST matcher itself. If
// callsIsolateInTestMain silently stopped matching, the gate above would go
// quiet and report success for a suite that had stopped isolating anything.
func TestGateRecognisesTheCanonicalTestMain(t *testing.T) {
	cases := map[string]struct {
		src  string
		want bool
	}{
		"canonical form": {
			src:  "package p\nfunc TestMain(m *testing.M) { os.Exit(hometest.Isolate(m)) }\n",
			want: true,
		},
		"isolate behind a branch still counts": {
			src: "package p\nfunc TestMain(m *testing.M) {\n" +
				"if os.Getenv(\"X\") != \"\" { os.Exit(0) }\n" +
				"os.Exit(hometest.Isolate(m)) }\n",
			want: true,
		},
		"a TestMain that does not isolate": {
			src:  "package p\nfunc TestMain(m *testing.M) { os.Exit(m.Run()) }\n",
			want: false,
		},
		"Isolate called outside TestMain does not count": {
			src:  "package p\nfunc helper() { hometest.Isolate(nil) }\n",
			want: false,
		},
		"no TestMain at all": {
			src:  "package p\nfunc TestThing(t *testing.T) {}\n",
			want: false,
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			f, err := parser.ParseFile(token.NewFileSet(), "x_test.go", c.src, 0)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if got := callsIsolateInTestMain(f); got != c.want {
				t.Errorf("callsIsolateInTestMain = %v, want %v", got, c.want)
			}
		})
	}
}

// TestGateDetectsUserHomeDir guards the other matcher, including the case that
// matters most: a package-level qualifier that merely ends in the right name.
func TestGateDetectsUserHomeDir(t *testing.T) {
	cases := map[string]struct {
		src  string
		want bool
	}{
		"direct call":           {"package p\nfunc f() { os.UserHomeDir() }\n", true},
		"assigned":              {"package p\nfunc f() { h, _ := os.UserHomeDir(); _ = h }\n", true},
		"unrelated UserHomeDir": {"package p\nfunc f() { fake.UserHomeDir() }\n", false},
		"unrelated os call":     {"package p\nfunc f() { os.Getenv(\"HOME\") }\n", false},
		"no call":               {"package p\nfunc f() {}\n", false},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			f, err := parser.ParseFile(token.NewFileSet(), "x.go", c.src, 0)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if got := callsUserHomeDir(f); got != c.want {
				t.Errorf("callsUserHomeDir = %v, want %v", got, c.want)
			}
		})
	}
}
