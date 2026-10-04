package hubmetrics

// The gate against silent families (Task 20377).
//
// The catalog once declared eighteen families nothing ever recorded. Each was
// registered, so each rendered in every scrape with HELP and TYPE and no
// samples — the most convincing possible impression of a metric that is merely
// quiet. docs/operations/metrics.md admitted it in a section of its own, its
// own PromQL for task success rate and infrastructure faults returned nothing,
// and an alert an operator wrote on any of those families could never fire.
//
// This file makes that state a build failure. A family is recorded when some
// production file — any non-_test.go file outside the tests/ harnesses — calls
// a recording method on it (hubmetrics.X.Inc, Add, Set or Observe) or names it
// among the Families of a scrape-time collector (a CollectorSpec, or the
// trailing arguments of RegisterCollector). Anything else does not count: a
// Reset alone records nothing, and a reference in a test proves only that the
// test can record it.
//
// The scan is of source rather than of a running hub because the question is
// structural — is there anything at all that puts a sample in this family? —
// and it has to be answerable for every family at once. Whether the call
// sites actually fire is the end-to-end scrape's job (pkg/ui
// TestMetricsEndToEnd).
//
// The doc may keep a "Declared but not yet recorded" list, and it must equal
// the computed set: a family that is silent has to say so where operators
// look, and one that records must not be listed as silent. With every family
// recorded the set is empty and the section is gone.

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// recordingMethods are the Metric methods that put a sample in a family.
var recordingMethods = map[string]bool{"Inc": true, "Add": true, "Set": true, "Observe": true}

// docDeclaredHeading is the doc section that lists silent families.
const docDeclaredHeading = "Declared but not yet recorded"

// catalogVars maps each package-level variable in catalog.go that is assigned
// Default.MustRegister(Definition{...}) to the metric name it registers.
func catalogVars(t *testing.T) map[string]string {
	t.Helper()

	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "catalog.go", nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse catalog.go: %v", err)
	}
	out := map[string]string{}
	for _, decl := range f.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || gd.Tok != token.VAR {
			continue
		}
		for _, spec := range gd.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for i, ident := range vs.Names {
				if i >= len(vs.Values) {
					continue
				}
				if name, ok := registeredName(vs.Values[i]); ok {
					out[ident.Name] = name
				}
			}
		}
	}
	return out
}

// registeredName reads the Name out of Default.MustRegister(Definition{...}).
func registeredName(e ast.Expr) (string, bool) {
	call, ok := e.(*ast.CallExpr)
	if !ok || len(call.Args) != 1 {
		return "", false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "MustRegister" {
		return "", false
	}
	if recv, ok := sel.X.(*ast.Ident); !ok || recv.Name != "Default" {
		return "", false
	}
	lit, ok := call.Args[0].(*ast.CompositeLit)
	if !ok {
		return "", false
	}
	for _, elt := range lit.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		if key, ok := kv.Key.(*ast.Ident); !ok || key.Name != "Name" {
			continue
		}
		bl, ok := kv.Value.(*ast.BasicLit)
		if !ok || bl.Kind != token.STRING {
			return "", false
		}
		name, err := strconv.Unquote(bl.Value)
		return name, err == nil
	}
	return "", false
}

// familyUses is where the module records each catalog variable, keyed by
// variable name, each site as "file:line".
type familyUses struct {
	recorded  map[string][]string
	collected map[string][]string
}

func (u familyUses) has(v string) bool { return len(u.recorded[v]) > 0 || len(u.collected[v]) > 0 }

// scanFamilyUses walks the Go module rooted at root (module path module) and
// reports which of vars its production code records.
//
// Skipped: _test.go files; the tests/ tree, whose packages are harnesses that
// `go test` runs and nothing links; nested modules; and hidden, testdata,
// vendor and node_modules directories. Inside pkg/hubmetrics itself a family is
// named unqualified, and is recognised that way.
func scanFamilyUses(root, module string, vars map[string]bool) (familyUses, error) {
	uses := familyUses{recorded: map[string][]string{}, collected: map[string][]string{}}
	importPath := module + "/pkg/hubmetrics"
	fset := token.NewFileSet()

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			return rerr
		}
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if path == root {
				return nil
			}
			switch name := d.Name(); {
			case strings.HasPrefix(name, "."), name == "testdata", name == "vendor", name == "node_modules":
				return filepath.SkipDir
			}
			if rel == "tests" {
				return filepath.SkipDir
			}
			if _, err := os.Stat(filepath.Join(path, "go.mod")); err == nil {
				return filepath.SkipDir // another module
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		inPkg := filepath.ToSlash(filepath.Dir(rel)) == "pkg/hubmetrics"
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if !inPkg && !bytes.Contains(src, []byte(strconv.Quote(importPath))) {
			return nil
		}
		f, err := parser.ParseFile(fset, path, src, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		scanFile(fset, f, rel, inPkg, importPath, vars, uses)
		return nil
	})
	return uses, err
}

// scanFile records one file's uses of the catalog.
func scanFile(fset *token.FileSet, f *ast.File, rel string, inPkg bool, importPath string,
	vars map[string]bool, uses familyUses) {

	aliases := map[string]bool{}
	for _, imp := range f.Imports {
		p, err := strconv.Unquote(imp.Path.Value)
		if err != nil || p != importPath {
			continue
		}
		name := "hubmetrics"
		if imp.Name != nil {
			name = imp.Name.Name
		}
		if name == "_" || name == "." {
			continue // a dot import hides the qualifier this scan reads
		}
		aliases[name] = true
	}
	if !inPkg && len(aliases) == 0 {
		return
	}

	// family resolves an expression to the catalog variable it names, or "".
	family := func(e ast.Expr) string {
		switch x := e.(type) {
		case *ast.SelectorExpr:
			if id, ok := x.X.(*ast.Ident); ok && aliases[id.Name] && vars[x.Sel.Name] {
				return x.Sel.Name
			}
		case *ast.Ident:
			if inPkg && vars[x.Name] {
				return x.Name
			}
		}
		return ""
	}
	site := func(n ast.Node) string { return fmt.Sprintf("%s:%d", rel, fset.Position(n.Pos()).Line) }
	collect := func(n ast.Node, e ast.Expr) {
		if v := family(e); v != "" {
			uses.collected[v] = append(uses.collected[v], site(n))
		}
	}

	ast.Inspect(f, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.CallExpr:
			sel, ok := x.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if recordingMethods[sel.Sel.Name] {
				if v := family(sel.X); v != "" {
					uses.recorded[v] = append(uses.recorded[v], site(x))
				}
			}
			// RegisterCollector(name, fn, families...): everything after the
			// function is a family the collector owns.
			if sel.Sel.Name == "RegisterCollector" && len(x.Args) > 2 {
				for _, arg := range x.Args[2:] {
					collect(x, arg)
				}
			}
		case *ast.CompositeLit:
			if !isCollectorSpec(x.Type, aliases, inPkg) {
				return true
			}
			for _, elt := range x.Elts {
				kv, ok := elt.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				if key, ok := kv.Key.(*ast.Ident); !ok || key.Name != "Families" {
					continue
				}
				if list, ok := kv.Value.(*ast.CompositeLit); ok {
					for _, e := range list.Elts {
						collect(x, e)
					}
				}
			}
		}
		return true
	})
}

// isCollectorSpec reports whether a composite literal's type is CollectorSpec.
func isCollectorSpec(e ast.Expr, aliases map[string]bool, inPkg bool) bool {
	switch x := e.(type) {
	case *ast.SelectorExpr:
		id, ok := x.X.(*ast.Ident)
		return ok && aliases[id.Name] && x.Sel.Name == "CollectorSpec"
	case *ast.Ident:
		return inPkg && x.Name == "CollectorSpec"
	}
	return false
}

// silentFamilies returns the metric names of the catalog variables nothing
// records, sorted.
func silentFamilies(vars map[string]string, uses familyUses) []string {
	var out []string
	for v, name := range vars {
		if !uses.has(v) {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// docDeclaredNotRecorded returns the metric names listed under the doc's
// "Declared but not yet recorded" heading, sorted and deduplicated, and
// whether the section exists at all. The list runs to the next heading of any
// level: it is a flat list, and a subsection under it is about something else.
func docDeclaredNotRecorded(doc string) ([]string, bool) {
	heading := regexp.MustCompile(`^#+\s+(.*?)\s*$`)
	name := regexp.MustCompile(`cloop_[a-z0-9_]*[a-z0-9]`)

	inSection, found := false, false
	seen := map[string]bool{}
	for _, line := range strings.Split(doc, "\n") {
		if m := heading.FindStringSubmatch(line); m != nil {
			if inSection {
				break
			}
			if m[1] == docDeclaredHeading {
				inSection, found = true, true
			}
			continue
		}
		if !inSection {
			continue
		}
		for _, n := range name.FindAllString(line, -1) {
			seen[n] = true
		}
	}
	out := make([]string, 0, len(seen))
	for n := range seen {
		out = append(out, n)
	}
	sort.Strings(out)
	return out, found
}

// moduleOf reads the module path out of root's go.mod.
func moduleOf(t *testing.T, root string) string {
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
	t.Fatalf("no module directive in %s", filepath.Join(root, "go.mod"))
	return ""
}

// repoUses scans this repository for the catalog's uses.
func repoUses(t *testing.T) (map[string]string, familyUses) {
	t.Helper()
	const root = "../.."
	vars := catalogVars(t)
	names := make(map[string]bool, len(vars))
	for v := range vars {
		names[v] = true
	}
	uses, err := scanFamilyUses(root, moduleOf(t, root), names)
	if err != nil {
		t.Fatalf("scan the module: %v", err)
	}
	return vars, uses
}

// TestCatalogVarsCoverTheRegistry keeps the gate honest about what it can see.
// A family registered some other way than `X = Default.MustRegister(...)` in
// catalog.go has no variable for the scan to look for, and would pass the gate
// by being invisible to it.
func TestCatalogVarsCoverTheRegistry(t *testing.T) {
	byName := map[string]string{}
	for v, name := range catalogVars(t) {
		byName[name] = v
	}
	for _, name := range catalogNames(t) {
		if _, ok := byName[name]; !ok {
			t.Errorf("%s is registered on Default but not as `X = Default.MustRegister(...)` in "+
				"catalog.go, so TestEveryFamilyIsRecorded cannot see whether anything records it", name)
		}
	}
	if len(byName) < 25 {
		t.Errorf("found %d catalog variables; the parse is not reading catalog.go", len(byName))
	}
}

// TestEveryFamilyIsRecorded is the gate.
func TestEveryFamilyIsRecorded(t *testing.T) {
	vars, uses := repoUses(t)
	byName := map[string]string{}
	for v, name := range vars {
		byName[name] = v
	}
	for _, name := range silentFamilies(vars, uses) {
		t.Errorf("%s (hubmetrics.%s) is registered, but no production code records it: no "+
			"hubmetrics.%s.Inc/Add/Set/Observe outside a _test.go file, and no collector names it "+
			"in its Families. It renders in every scrape with no samples, and an alert on it can "+
			"never fire. Record it where the event happens, register a collector for it, or "+
			"remove it from the catalog.", name, byName[name], byName[name])
	}
}

// TestDocListsExactlyTheSilentFamilies keeps the doc's admission in step with
// the code, in both directions.
func TestDocListsExactlyTheSilentFamilies(t *testing.T) {
	const doc = "../../docs/operations/metrics.md"
	body, err := os.ReadFile(doc)
	if err != nil {
		t.Fatalf("read %s: %v", doc, err)
	}
	listed, present := docDeclaredNotRecorded(string(body))

	vars, uses := repoUses(t)
	silent := silentFamilies(vars, uses)

	if strings.Join(listed, " ") == strings.Join(silent, " ") {
		if present && len(silent) == 0 {
			t.Errorf("%s keeps a %q section although every family is recorded — remove it, and "+
				"any caveat elsewhere that points at it", doc, docDeclaredHeading)
		}
		return
	}
	in := func(list []string) map[string]bool {
		m := map[string]bool{}
		for _, n := range list {
			m[n] = true
		}
		return m
	}
	isListed, isSilent := in(listed), in(silent)
	for _, n := range silent {
		if !isListed[n] {
			t.Errorf("%s records nothing but %s does not list it under %q", n, doc, docDeclaredHeading)
		}
	}
	for _, n := range listed {
		if !isSilent[n] {
			t.Errorf("%s lists %s under %q, but it is recorded — remove it from the list", doc, n, docDeclaredHeading)
		}
	}
}

// TestRecordedGateFlagsWhatItShould runs the scan over a module built for it,
// so each rule is shown to hold rather than assumed.
func TestRecordedGateFlagsWhatItShould(t *testing.T) {
	root := t.TempDir()
	const mod = "example.com/m"
	write := func(rel, src string) {
		t.Helper()
		path := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("go.mod", "module "+mod+"\n")
	write("pkg/hubmetrics/catalog.go", `package hubmetrics
func own() { InPkg.Set(1) }
`)
	write("pkg/a/a.go", `package a
import "`+mod+`/pkg/hubmetrics"
func f() {
	hubmetrics.Counted.Inc("x")
	hubmetrics.OnlyReset.Reset()
}
`)
	write("pkg/a/a_test.go", `package a
import "`+mod+`/pkg/hubmetrics"
func g() { hubmetrics.OnlyInTest.Inc() }
`)
	write("pkg/b/b.go", `package b
import hm "`+mod+`/pkg/hubmetrics"
func h(v float64) { hm.Aliased.Observe(v) }
`)
	write("pkg/c/c.go", `package c
import "`+mod+`/pkg/hubmetrics"
func init() {
	hubmetrics.RegisterCollectors(hubmetrics.CollectorSpec{
		Name:     "c",
		Families: []*hubmetrics.Metric{hubmetrics.ViaSpec},
		Collect:  func() {},
	})
	hubmetrics.Default.RegisterCollector("d", func() {}, hubmetrics.ViaArgs)
}
`)
	write("pkg/d/d.go", `package d
import "`+mod+`/pkg/hubmetrics"
func k() { _ = hubmetrics.Referenced.SeriesCount() }
`)
	write("tests/harness/h.go", `package harness
import "`+mod+`/pkg/hubmetrics"
func m() { hubmetrics.OnlyInHarness.Inc() }
`)
	write("other/go.mod", "module example.com/other\n")
	write("other/o.go", `package other
import "`+mod+`/pkg/hubmetrics"
func n() { hubmetrics.OnlyInOtherModule.Inc() }
`)
	write(".hidden/x.go", `package x
import "`+mod+`/pkg/hubmetrics"
func p() { hubmetrics.OnlyHidden.Inc() }
`)

	vars := map[string]string{}
	names := map[string]bool{}
	for _, v := range []string{"InPkg", "Counted", "OnlyReset", "OnlyInTest", "Aliased", "ViaSpec",
		"ViaArgs", "Referenced", "OnlyInHarness", "OnlyInOtherModule", "OnlyHidden"} {
		vars[v] = "cloop_" + strings.ToLower(v)
		names[v] = true
	}
	uses, err := scanFamilyUses(root, mod, names)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(silentFamilies(vars, uses), " ")
	want := "cloop_onlyhidden cloop_onlyinharness cloop_onlyinothermodule cloop_onlyintest " +
		"cloop_onlyreset cloop_referenced"
	if got != want {
		t.Fatalf("silent families = %q\nwant              %q", got, want)
	}
	if s := uses.recorded["Counted"]; len(s) != 1 || s[0] != "pkg/a/a.go:4" {
		t.Errorf("Counted recorded at %v, want pkg/a/a.go:4", s)
	}
	if len(uses.collected["ViaSpec"]) != 1 || len(uses.collected["ViaArgs"]) != 1 {
		t.Errorf("collector ownership = %v, want ViaSpec and ViaArgs once each", uses.collected)
	}
}

func TestDocDeclaredNotRecordedParser(t *testing.T) {
	doc := `# Metrics

Mentions cloop_outside_total in prose.

## Declared but not yet recorded

` + "```" + `
cloop_a_total          cloop_b
cloop_c_seconds
` + "```" + `

### A subsection is about something else

cloop_d_total

## Next section

cloop_e_total
`
	got, present := docDeclaredNotRecorded(doc)
	if !present || strings.Join(got, " ") != "cloop_a_total cloop_b cloop_c_seconds" {
		t.Errorf("parsed %v (present %v)", got, present)
	}
	if got, present := docDeclaredNotRecorded("# Metrics\n\ncloop_x_total\n"); present || len(got) != 0 {
		t.Errorf("a doc without the section parsed as %v (present %v)", got, present)
	}
}
