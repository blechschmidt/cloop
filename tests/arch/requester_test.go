package arch_test

// A secretbroker.Requester is built in one place (Task 20432).
//
// A grant's subject names a project, an executor, or a set of labels, and a
// label grant is matched against the requester's labels. Every dispatch path
// used to assemble its own Requester from an executor ID and a project — the
// run's lease, the harness preflight, the egress session, the workspace fetch,
// the Kubernetes driver's credential, the GitHub App picker, hub doctor's
// smoke — and not one of them set Labels, so a label grant was accepted,
// listed and audited and delivered nothing.
//
// secretbroker.NewRequester is now the only function that writes a Requester
// literal, and it takes the executor as a RecordedExecutor: the hub's own
// record of it, never what a device's agent says about itself. This gate keeps
// both halves:
//
//   - No Requester composite literal in production code outside NewRequester.
//   - No RecordedExecutor composite literal outside the functions listed in
//     recordedExecutorAllowed: the hub's records, the lookup that has no
//     record to read, a requester re-reading its own identity, the decoders
//     that restore what a lease or a proxy session recorded when it was
//     issued, and the CLI's hypothetical executor.
//
// A literal with its type elided inside a slice or map of either type counts.
// Tests may build requesters however they like.

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// secretbrokerDir is where both types are declared.
const secretbrokerDir = "pkg/secretbroker"

// requesterLiteralAllowed is the one function that may write a Requester
// literal, keyed file:function.
var requesterLiteralAllowed = map[string]string{
	"pkg/secretbroker/requester.go:NewRequester": "the constructor every requester comes from",
}

// recordedExecutorAllowed are the functions that may assemble a
// RecordedExecutor, keyed file:function, each with why. Anything else gets one
// from secretbroker.LookupExecutor (or RequesterFor) over the hub's records.
var recordedExecutorAllowed = map[string]string{
	"pkg/executorstore/records.go:(Records).RecordedExecutor": "the hub's records: an agent credential, a " +
		"virtual executor's device, the configuration",
	"pkg/secretbroker/requester.go:LookupExecutor": "no records to read, or no executor: the ID alone, " +
		"which no label grant matches",
	"pkg/secretbroker/requester.go:(Requester).Executor": "a requester re-reading the identity it was built " +
		"with, to rebuild it under another scope",
	"pkg/secretstore/leases.go:leaseFromRow": "the identity a lease recorded when it was issued (or " +
		"relabeled), for the process taking it over",
	"pkg/egressbroker/durable.go:(*Broker).RestoreSession": "the identity a proxy session recorded when it " +
		"was redeemed (or relabeled), for the process restoring it",
	"cmd/egress_cmd.go:egressTestRequester": "`cloop egress test --to label:…`: a hypothetical executor " +
		"carrying the labels its operator typed, which no lease or session outlives",
}

func TestRequesterIsBuiltOnlyFromTheHubsRecord(t *testing.T) {
	root := repoRoot(t)
	found, err := requesterLiterals(root, modulePath(t, root))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range found {
		key := f.file + ":" + f.fn
		switch f.typ {
		case "Requester":
			if _, ok := requesterLiteralAllowed[key]; ok {
				continue
			}
			t.Errorf("%s:%d: a secretbroker.Requester literal in %s. Build it with secretbroker.NewRequester "+
				"(or RequesterFor), from the executor as the hub records it — secretbroker.LookupExecutor over "+
				"the hub's executor records — so a label grant is matched against the labels the hub "+
				"recorded, and never against none, or against what an agent says about itself.",
				f.file, f.line, describeFn(f.fn))
		case "RecordedExecutor":
			if _, ok := recordedExecutorAllowed[key]; ok {
				continue
			}
			t.Errorf("%s:%d: a secretbroker.RecordedExecutor literal in %s. An executor's identity comes "+
				"from the hub's records (secretbroker.LookupExecutor), not from a call site: labels assembled "+
				"here decide which label grants the executor receives. If this function restores a recorded "+
				"identity, add it to recordedExecutorAllowed with the reason.",
				f.file, f.line, describeFn(f.fn))
		}
	}
}

func TestRequesterAllowancesAreStillUsed(t *testing.T) {
	root := repoRoot(t)
	found, err := requesterLiterals(root, modulePath(t, root))
	if err != nil {
		t.Fatal(err)
	}
	used := map[string]bool{}
	for _, f := range found {
		used[f.typ+" "+f.file+":"+f.fn] = true
	}
	for key := range requesterLiteralAllowed {
		if !used["Requester "+key] {
			t.Errorf("%s is allowed a Requester literal but writes none — remove it from requesterLiteralAllowed", key)
		}
	}
	for key := range recordedExecutorAllowed {
		if !used["RecordedExecutor "+key] {
			t.Errorf("%s is allowed a RecordedExecutor literal but writes none — remove it from "+
				"recordedExecutorAllowed", key)
		}
	}
}

// The gate must flag what it exists for, and only that.
func TestRequesterGateFlagsWhatItShould(t *testing.T) {
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
	write("pkg/secretbroker/model.go", `package secretbroker
type Requester struct{ ExecutorID string; Labels map[string]string }
type RecordedExecutor struct{ ID string; Labels map[string]string }
func NewRequester(ex RecordedExecutor) Requester { return Requester{ExecutorID: ex.ID} }
func leak() Requester { return Requester{} }
func LookupExecutor(id string) RecordedExecutor { return RecordedExecutor{ID: id} }
`)
	write("pkg/ui/dispatch.go", `package ui
import sb "`+mod+`/pkg/secretbroker"
func lease(id string) sb.Requester { return sb.Requester{ExecutorID: id} }
func ptr() *sb.Requester { return &sb.Requester{} }
func many() []sb.Requester { return []sb.Requester{{ExecutorID: "a"}, {ExecutorID: "b"}} }
func byID() map[string]sb.RecordedExecutor { return map[string]sb.RecordedExecutor{"a": {ID: "a"}} }
func spoof(labels map[string]string) sb.Requester {
	return sb.NewRequester(sb.RecordedExecutor{ID: "x", Labels: labels})
}
func fine(id string) sb.Requester { return sb.NewRequester(sb.LookupExecutor(id)) }
`)
	write("pkg/ui/default.go", `package ui
import "`+mod+`/pkg/secretbroker"
var zero = secretbroker.Requester{}
`)
	write("pkg/ui/dot.go", `package ui
import . "`+mod+`/pkg/secretbroker"
func dotted() Requester { return Requester{} }
`)
	write("pkg/ui/shadow.go", `package ui
type Requester struct{}
func own() Requester { return Requester{} }
`)
	write("pkg/ui/ui_test.go", `package ui
import "`+mod+`/pkg/secretbroker"
func inTest() secretbroker.Requester { return secretbroker.Requester{} }
`)
	write("tests/harness/h.go", `package harness
import "`+mod+`/pkg/secretbroker"
func inHarness() secretbroker.Requester { return secretbroker.Requester{} }
`)

	got, err := requesterLiterals(root, mod)
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	for _, f := range got {
		lines = append(lines, fmt.Sprintf("%s:%d %s %s", f.file, f.line, f.typ, f.fn))
	}
	want := []string{
		"pkg/secretbroker/model.go:4 Requester NewRequester",
		"pkg/secretbroker/model.go:5 Requester leak",
		"pkg/secretbroker/model.go:6 RecordedExecutor LookupExecutor",
		"pkg/ui/default.go:3 Requester ",
		"pkg/ui/dispatch.go:3 Requester lease",
		"pkg/ui/dispatch.go:4 Requester ptr",
		"pkg/ui/dispatch.go:5 Requester many",
		"pkg/ui/dispatch.go:5 Requester many",
		"pkg/ui/dispatch.go:6 RecordedExecutor byID",
		"pkg/ui/dispatch.go:8 RecordedExecutor spoof",
		"pkg/ui/dot.go:2 dot-import ",
	}
	if strings.Join(lines, "\n") != strings.Join(want, "\n") {
		t.Fatalf("flagged:\n%s\nwant:\n%s", strings.Join(lines, "\n"), strings.Join(want, "\n"))
	}
}

// requesterLiteral is one composite literal of a gated type.
type requesterLiteral struct {
	file string // slash-separated, relative to the repository root
	line int
	// typ is "Requester", "RecordedExecutor", or "dot-import" for a file that
	// dot-imports secretbroker and so hides its literals from this check.
	typ string
	// fn is the enclosing function as an allowlist spells it, or "" at file
	// scope.
	fn string
}

// describeFn renders fn for a message.
func describeFn(fn string) string {
	if fn == "" {
		return "a file-scope declaration"
	}
	return fn
}

// requesterLiterals lists every Requester and RecordedExecutor composite
// literal in root's production code — outside _test.go files, the tests/
// harnesses and the test-only packages.
func requesterLiterals(root, mod string) ([]requesterLiteral, error) {
	var out []requesterLiteral
	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", ".cloop", "node_modules", "testdata", "vendor":
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
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		dir := filepath.ToSlash(filepath.Dir(rel))
		if _, ok := testOnly[dir]; ok || isTestHarness(dir) {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return err
		}
		out = append(out, requesterLiteralsIn(fset, f, rel, dir == secretbrokerDir, mod)...)
		return nil
	})
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].file != out[j].file {
			return out[i].file < out[j].file
		}
		return out[i].line < out[j].line
	})
	return out, err
}

func requesterLiteralsIn(fset *token.FileSet, f *ast.File, rel string, inSecretbroker bool, mod string) []requesterLiteral {
	var out []requesterLiteral
	aliases := map[string]bool{}
	for _, imp := range f.Imports {
		path, err := strconv.Unquote(imp.Path.Value)
		if err != nil || path != mod+"/"+secretbrokerDir {
			continue
		}
		switch {
		case imp.Name == nil:
			aliases["secretbroker"] = true
		case imp.Name.Name == ".":
			out = append(out, requesterLiteral{file: rel, line: fset.Position(imp.Pos()).Line, typ: "dot-import"})
		case imp.Name.Name != "_":
			aliases[imp.Name.Name] = true
		}
	}
	if !inSecretbroker && len(aliases) == 0 {
		return out
	}

	// gated names a type expression as one of the two, or "".
	gated := func(e ast.Expr) string {
		var name string
		switch t := e.(type) {
		case *ast.SelectorExpr:
			x, ok := t.X.(*ast.Ident)
			if !ok || !aliases[x.Name] {
				return ""
			}
			name = t.Sel.Name
		case *ast.Ident:
			if !inSecretbroker {
				return ""
			}
			name = t.Name
		default:
			return ""
		}
		if name == "Requester" || name == "RecordedExecutor" {
			return name
		}
		return ""
	}

	walk := func(node ast.Node, fn string) {
		ast.Inspect(node, func(n ast.Node) bool {
			lit, ok := n.(*ast.CompositeLit)
			if !ok || lit.Type == nil {
				return true
			}
			if typ := gated(lit.Type); typ != "" {
				out = append(out, requesterLiteral{file: rel, line: fset.Position(lit.Pos()).Line, typ: typ, fn: fn})
				return true
			}
			// []T{{…}} and map[K]T{k: {…}}: the elements' type is elided.
			var elem ast.Expr
			switch t := lit.Type.(type) {
			case *ast.ArrayType:
				elem = t.Elt
			case *ast.MapType:
				elem = t.Value
			}
			typ := gated(elem)
			if typ == "" {
				return true
			}
			for _, e := range lit.Elts {
				if kv, ok := e.(*ast.KeyValueExpr); ok {
					e = kv.Value
				}
				if inner, ok := e.(*ast.CompositeLit); ok && inner.Type == nil {
					out = append(out, requesterLiteral{file: rel, line: fset.Position(inner.Pos()).Line, typ: typ, fn: fn})
				}
			}
			return true
		})
	}

	for _, decl := range f.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if !ok {
			walk(decl, "")
			continue
		}
		if fd.Body == nil {
			continue
		}
		walk(fd.Body, harnessFuncName(fd))
	}
	return out
}
