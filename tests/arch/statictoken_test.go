package arch_test

// The static admin token is compared with a presented credential in one
// function (Task 20406).
//
// Before Task 20406 the comparison lived in two places that had to agree:
// authMiddleware for a token-only hub and oidcGate for one with single
// sign-on. Retiring the token at runtime adds a second question to the first —
// is this the token, and is it still live — and two copies of a two-part
// question are how a retired token ends up refused by one gate and admitted by
// the other. So pkg/ui holds the value in an unexported field that three
// functions may read, each for one purpose:
//
//   - checkStaticToken compares a presented value with it, in constant time,
//     and asks the retired set. The only comparison.
//   - staticTokenConfigured asks whether one is configured at all: the field
//     against "", nothing else. A retired token is a configured one, which is
//     what keeps a token-only hub closed after its only credential retired.
//   - staticTokenFingerprint hashes it to look it up among the retirements.
//
// This gate keeps it that way, and keeps both gates asking checkStaticToken:
//
//   - No other function in pkg/ui reads the field — not to compare it, not to
//     hand it out through an accessor, not to copy it somewhere a comparison
//     can reach it. The field is unexported, so no other package can.
//   - The two presence readers use it only as the gate allows: compared with
//     "", or passed to statictoken.Fingerprint.
//   - authMiddleware and oidcGate call checkStaticToken.
//   - Exactly one struct in pkg/ui declares a field by that name, so a read
//     of it names the token and nothing else.

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

// staticTokenField is pkg/ui's Server field holding the static token's value.
const staticTokenField = "staticToken"

// staticTokenReaders lists the functions that may read the field, and how:
// "compare" for the one comparison, "presence" for the readers held to
// comparing it with "" or fingerprinting it.
var staticTokenReaders = map[string]string{
	"(*Server).checkStaticToken":       "compare",
	"(*Server).staticTokenConfigured":  "presence",
	"(*Server).staticTokenFingerprint": "presence",
}

// staticTokenGates are the authentication gates that must take their verdict
// from checkStaticToken.
var staticTokenGates = []struct{ file, fn string }{
	{"pkg/ui/server.go", "(*Server).authMiddleware"},
	{"pkg/ui/oidc.go", "(*Server).oidcGate"},
}

// staticTokenScan is what scanStaticToken found in one package directory.
type staticTokenScan struct {
	violations []string
	// readers maps each function that read the field to true.
	readers map[string]bool
	// fieldDecls counts struct fields named staticTokenField.
	fieldDecls []string
	// compares records whether the "compare" reader calls a constant-time
	// comparison.
	compares bool
}

func TestStaticTokenIsComparedInOneFunction(t *testing.T) {
	scan, err := scanStaticToken(filepath.Join(repoRoot(t), "pkg/ui"))
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range scan.violations {
		t.Error(v + ". The static token is compared in Server.checkStaticToken alone, and both " +
			"authentication gates act on its verdict (Task 20406): a second comparison is how a retired " +
			"token ends up admitted by one gate. Ask checkStaticToken, or staticTokenConfigured for " +
			"whether one is configured at all.")
	}
	if len(scan.fieldDecls) != 1 {
		t.Errorf("pkg/ui declares %d fields named %s (%v), want exactly Server's: with two, a read "+
			"of the name no longer identifies the token, and this gate stops meaning anything",
			len(scan.fieldDecls), staticTokenField, scan.fieldDecls)
	}
	if !scan.compares {
		t.Error("checkStaticToken no longer compares with subtle.ConstantTimeCompare: the comparison moved, " +
			"or lost its constant time")
	}
}

// TestStaticTokenReadersAreStillListed rejects an allowlist entry whose
// function no longer reads the field: a stale entry is a pass waiting for
// whatever takes that name next.
func TestStaticTokenReadersAreStillListed(t *testing.T) {
	scan, err := scanStaticToken(filepath.Join(repoRoot(t), "pkg/ui"))
	if err != nil {
		t.Fatal(err)
	}
	for fn := range staticTokenReaders {
		if !scan.readers[fn] {
			t.Errorf("%s no longer reads %s — remove it from staticTokenReaders", fn, staticTokenField)
		}
	}
}

func TestBothAuthenticationGatesAskCheckStaticToken(t *testing.T) {
	root := repoRoot(t)
	for _, g := range staticTokenGates {
		calls, err := funcCalls(filepath.Join(root, g.file), g.fn)
		if err != nil {
			t.Errorf("%s: %v", g.file, err)
			continue
		}
		if !calls["checkStaticToken"] {
			t.Errorf("%s: %s no longer calls checkStaticToken, so whether it admits the static token "+
				"— and whether a retired one is refused — is decided somewhere else", g.file, g.fn)
		}
	}
}

// The gate must flag what it exists for, and only that.
func TestStaticTokenGateFlagsASecondComparison(t *testing.T) {
	dir := t.TempDir()
	write := func(name, src string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("server.go", `package ui
import (
	"crypto/subtle"
	"github.com/blechschmidt/cloop/pkg/statictoken"
)
type Server struct{ staticToken string }
func (s *Server) checkStaticToken(v string) bool {
	own := s.staticToken
	return subtle.ConstantTimeCompare([]byte(v), []byte(own)) == 1
}
func (s *Server) staticTokenConfigured() bool { return s.staticToken != "" }
func (s *Server) staticTokenFingerprint() string { return statictoken.Fingerprint(s.staticToken) }
`)
	write("bad.go", `package ui
import "crypto/subtle"
type other struct{ staticToken string }
func (s *Server) gate(v string) bool { return subtle.ConstantTimeCompare([]byte(v), []byte(s.staticToken)) == 1 }
func (s *Server) Token() string { return s.staticToken }
var leak = func(s *Server) string { return s.staticToken }
`)
	write("presence.go", `package ui
func (s *Server) staticTokenConfiguredBadly() bool { return s.staticToken == "guess" }
`)
	write("fine_test.go", `package ui
func (s *Server) inATest() bool { return s.staticToken == "t" }
`)
	scan, err := scanStaticToken(dir)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(scan.violations, "\n")
	for _, want := range []string{"(*Server).gate", "(*Server).Token", "outside any function", "(*Server).staticTokenConfiguredBadly"} {
		if !strings.Contains(joined, want) {
			t.Errorf("the gate missed %s:\n%s", want, joined)
		}
	}
	if strings.Contains(joined, "inATest") || strings.Contains(joined, "checkStaticToken") ||
		strings.Contains(joined, "(*Server).staticTokenConfigured ") || strings.Contains(joined, "staticTokenFingerprint") {
		t.Errorf("the gate flagged an allowed use:\n%s", joined)
	}
	if len(scan.fieldDecls) != 2 {
		t.Errorf("field declarations = %v, want Server's and other's", scan.fieldDecls)
	}
	if !scan.compares {
		t.Error("the gate did not see the constant-time comparison in checkStaticToken")
	}
}

// scanStaticToken walks the non-test Go files of dir.
func scanStaticToken(dir string) (*staticTokenScan, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	scan := &staticTokenScan{readers: map[string]bool{}}
	fset := token.NewFileSet()
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
		if err != nil {
			return nil, err
		}
		ast.Inspect(f, func(n ast.Node) bool {
			if st, ok := n.(*ast.StructType); ok {
				for _, field := range st.Fields.List {
					for _, id := range field.Names {
						if id.Name == staticTokenField {
							scan.fieldDecls = append(scan.fieldDecls, fset.Position(id.Pos()).String())
						}
					}
				}
			}
			return true
		})
		for _, decl := range f.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok {
				walkStaticToken(fset, decl, "", "", scan)
				continue
			}
			if fd.Body == nil {
				continue
			}
			fn := harnessFuncName(fd)
			walkStaticToken(fset, fd.Body, fn, staticTokenReaders[fn], scan)
		}
	}
	sort.Strings(scan.violations)
	return scan, nil
}

// walkStaticToken checks every read of the field under root, which belongs to
// fn (empty outside a function) with the given role.
func walkStaticToken(fset *token.FileSet, root ast.Node, fn, role string, scan *staticTokenScan) {
	var stack []ast.Node
	ast.Inspect(root, func(n ast.Node) bool {
		if n == nil {
			stack = stack[:len(stack)-1]
			return true
		}
		stack = append(stack, n)
		if call, ok := n.(*ast.CallExpr); ok && role == "compare" && calleeName(call) == "ConstantTimeCompare" {
			scan.compares = true
		}
		sel, ok := n.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != staticTokenField {
			return true
		}
		pos := fset.Position(sel.Pos()).String()
		if fn == "" {
			scan.violations = append(scan.violations, fmt.Sprintf("%s: the static token is read outside any function", pos))
			return true
		}
		scan.readers[fn] = true
		switch role {
		case "compare":
		case "presence":
			if !presenceUse(stack) {
				scan.violations = append(scan.violations, fmt.Sprintf(
					"%s: %s may only compare the static token with \"\" or fingerprint it", pos, fn))
			}
		default:
			scan.violations = append(scan.violations, fmt.Sprintf("%s: %s reads the static token", pos, fn))
		}
		return true
	})
}

// presenceUse reports whether the selector on top of stack is compared with
// the empty string or passed straight to statictoken.Fingerprint.
func presenceUse(stack []ast.Node) bool {
	if len(stack) < 2 {
		return false
	}
	sel := stack[len(stack)-1]
	switch parent := stack[len(stack)-2].(type) {
	case *ast.BinaryExpr:
		if parent.Op != token.EQL && parent.Op != token.NEQ {
			return false
		}
		other := parent.X
		if other == sel {
			other = parent.Y
		}
		lit, ok := other.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return false
		}
		v, err := strconv.Unquote(lit.Value)
		return err == nil && v == ""
	case *ast.CallExpr:
		fun, ok := parent.Fun.(*ast.SelectorExpr)
		if !ok || fun.Sel.Name != "Fingerprint" {
			return false
		}
		pkg, ok := fun.X.(*ast.Ident)
		return ok && pkg.Name == "statictoken"
	}
	return false
}

// funcCalls returns the names of every function fn in path calls, closures
// included, by the callee's own name.
func funcCalls(path, fn string) (map[string]bool, error) {
	f, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if err != nil {
		return nil, err
	}
	for _, decl := range f.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if !ok || fd.Body == nil || harnessFuncName(fd) != fn {
			continue
		}
		calls := map[string]bool{}
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			if c, ok := n.(*ast.CallExpr); ok {
				calls[calleeName(c)] = true
			}
			return true
		})
		return calls, nil
	}
	return nil, fmt.Errorf("no function %s", fn)
}
