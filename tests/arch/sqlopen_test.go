package arch_test

// Every SQLite handle opens under statedb's connection policy (Task 20374).
//
// The policy — busy_timeout before anything else, on every connection the pool
// opens; foreign keys; transactions that take the write lock at BEGIN;
// read-only handles that SQLite enforces — exists because each part of it was
// once missing somewhere and failed on a live hub. Eight packages had opened
// cloop's databases with a bare sql.Open and set up what they remembered of it
// by hand, and what they set with Exec reached one connection out of the pool:
// taskqueue's MarkDone failed instantly with SQLITE_BUSY as soon as the pool
// replaced the connection that had run the pragma.
//
// statedb.OpenConn and statedb.DSN make the policy one call. This gate makes it
// the only way in: production code may call sql.Open only with a DSN built by
// statedb.DSN (or, inside pkg/statedb, by the functions that build it), and
// sql.OpenDB not at all — a connector carries no DSN to check. Tests may open
// however they like; they routinely play the other process holding a lock.

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

// bareOpenAllowed lists the production files that may open a database outside
// the policy, each with the reason. TestBareOpenAllowancesAreStillUsed rejects
// an entry whose file no longer needs it.
var bareOpenAllowed = map[string]string{
	"pkg/chaos/sqlite_busy.go": "the sqlite-busy fault's holder, which exists to take and hold the write " +
		"lock the policy is written to survive; it is configured for that job alone",
}

// statedbDir is the policy's home. Inside it, the DSN may come from the
// unexported builders as well as from DSN itself.
const statedbDir = "pkg/statedb"

// statedbPolicyBuilders are the functions in pkg/statedb that return a policy
// DSN.
var statedbPolicyBuilders = map[string]bool{"DSN": true, "policyDSN": true, "connString": true}

func TestNoBareSQLOpenOutsideTheConnectionPolicy(t *testing.T) {
	root := repoRoot(t)
	found, err := bareOpens(root, modulePath(t, root))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range found {
		if _, ok := bareOpenAllowed[f.file]; ok {
			continue
		}
		t.Errorf("%s:%d: %s. Open SQLite through statedb.OpenConn (or pass statedb.DSN to sql.Open), "+
			"so the handle gets the connection policy: busy_timeout on every connection, foreign keys, "+
			"BEGIN IMMEDIATE for writers, mode=ro for readers.", f.file, f.line, f.what)
	}
}

func TestBareOpenAllowancesAreStillUsed(t *testing.T) {
	root := repoRoot(t)
	found, err := bareOpens(root, modulePath(t, root))
	if err != nil {
		t.Fatal(err)
	}
	used := map[string]bool{}
	for _, f := range found {
		used[f.file] = true
	}
	for file := range bareOpenAllowed {
		if !used[file] {
			t.Errorf("%s is allowed a bare sql.Open but no longer has one — remove it from bareOpenAllowed", file)
		}
	}
}

// The gate must flag what it exists for, and only that.
func TestBareOpenGateFlagsWhatItShould(t *testing.T) {
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
	write("pkg/prod/bare.go", `package prod
import "database/sql"
func a(p string) { sql.Open("sqlite", p) }
`)
	write("pkg/prod/policy.go", `package prod
import (
	dbsql "database/sql"
	sdb "`+mod+`/pkg/statedb"
)
func b(p string) { dbsql.Open("sqlite", sdb.DSN(p, sdb.ReadOnly)) }
`)
	write("pkg/prod/alias.go", `package prod
import q "database/sql"
func c(p string) { q.Open("sqlite", p+"?_pragma=busy_timeout(5000)") }
`)
	write("pkg/prod/connector.go", `package prod
import "database/sql"
func d() { sql.OpenDB(nil) }
`)
	write("pkg/prod/dot.go", `package prod
import . "database/sql"
func e(p string) { Open("sqlite", p) }
`)
	write("pkg/prod/prod_test.go", `package prod
import "database/sql"
func f(p string) { sql.Open("sqlite", p) }
`)
	write("tests/harness/h.go", `package harness
import "database/sql"
func g(p string) { sql.Open("sqlite", p) }
`)
	write("pkg/statedb/db.go", `package statedb
import "database/sql"
func connString(p string) string { return p }
func h(p string) { sql.Open("sqlite", connString(p)) }
func i(p string) { sql.Open("sqlite", p) }
`)
	write("pkg/other/shadow.go", `package other
func DSN(p string) string { return p }
type opener struct{}
func (opener) Open(a, b string) {}
var sql opener
func j(p string) { sql.Open("sqlite", DSN(p)) }
`)

	got, err := bareOpens(root, mod)
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	for _, f := range got {
		lines = append(lines, fmt.Sprintf("%s:%d", f.file, f.line))
	}
	want := []string{
		"pkg/prod/alias.go:3",
		"pkg/prod/bare.go:3",
		"pkg/prod/connector.go:3",
		"pkg/prod/dot.go:2",
		"pkg/statedb/db.go:5",
	}
	if strings.Join(lines, " ") != strings.Join(want, " ") {
		t.Fatalf("flagged %q, want %q", lines, want)
	}
}

// bareOpen is one call that opens a database outside the policy.
type bareOpen struct {
	file string // slash-separated, relative to the repository root
	line int
	what string
}

// bareOpens lists every sql.Open, sql.OpenDB and dot-import of database/sql in
// root's production code — outside _test.go files, the tests/ harnesses and the
// test-only packages — that does not take its DSN from the connection policy.
func bareOpens(root, mod string) ([]bareOpen, error) {
	var out []bareOpen
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
		out = append(out, bareOpensIn(fset, f, rel, dir == statedbDir, mod)...)
		return nil
	})
	sort.Slice(out, func(i, j int) bool {
		if out[i].file != out[j].file {
			return out[i].file < out[j].file
		}
		return out[i].line < out[j].line
	})
	return out, err
}

func bareOpensIn(fset *token.FileSet, f *ast.File, rel string, inStatedb bool, mod string) []bareOpen {
	var (
		out        []bareOpen
		sqlNames   = map[string]bool{}
		statedbAls = map[string]bool{}
	)
	for _, imp := range f.Imports {
		path, err := strconv.Unquote(imp.Path.Value)
		if err != nil {
			continue
		}
		name := ""
		if imp.Name != nil {
			name = imp.Name.Name
		}
		switch path {
		case "database/sql":
			switch name {
			case "_":
			case ".":
				out = append(out, bareOpen{rel, fset.Position(imp.Pos()).Line,
					"dot-imports database/sql, which hides its opens from this check"})
			case "":
				sqlNames["sql"] = true
			default:
				sqlNames[name] = true
			}
		case mod + "/pkg/statedb":
			if name == "" {
				name = "statedb"
			}
			statedbAls[name] = true
		}
	}
	if len(sqlNames) == 0 {
		return out
	}

	// A file-scope declaration of the same name shadows the import for the
	// whole file; the import is then not what the selector refers to.
	for _, decl := range f.Decls {
		if gd, ok := decl.(*ast.GenDecl); ok {
			for _, spec := range gd.Specs {
				if vs, ok := spec.(*ast.ValueSpec); ok {
					for _, n := range vs.Names {
						delete(sqlNames, n.Name)
					}
				}
			}
		}
	}

	policyDSN := func(arg ast.Expr) bool {
		call, ok := arg.(*ast.CallExpr)
		if !ok {
			return false
		}
		switch fn := call.Fun.(type) {
		case *ast.SelectorExpr:
			x, ok := fn.X.(*ast.Ident)
			return ok && statedbAls[x.Name] && fn.Sel.Name == "DSN"
		case *ast.Ident:
			return inStatedb && statedbPolicyBuilders[fn.Name]
		}
		return false
	}

	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		x, ok := sel.X.(*ast.Ident)
		if !ok || !sqlNames[x.Name] {
			return true
		}
		line := fset.Position(call.Pos()).Line
		switch sel.Sel.Name {
		case "OpenDB":
			out = append(out, bareOpen{rel, line, "sql.OpenDB opens from a connector, which carries no DSN to check"})
		case "Open":
			if len(call.Args) < 2 || !policyDSN(call.Args[1]) {
				out = append(out, bareOpen{rel, line, "sql.Open with a DSN that is not the connection policy's"})
			}
		}
		return true
	})
	return out
}
