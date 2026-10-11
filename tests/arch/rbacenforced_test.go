package arch_test

// Whether RBAC is in force has one definition (Task 20395).
//
// The rule — single sign-on is on, and an operator wrote a policy: a role
// mapping or an explicit default_role — is authz.Enforced. Before it was, the
// request gate applied it while three reporters restated it, wrongly: `cloop
// hub doctor` and the startup log treated an unset default_role as the "none"
// it would mean under a policy, and the Settings panel pre-selected "none" for
// it. So an SSO hub with admin_emails and no mapping — every identity the issuer
// authenticates holding every permission but executor administration — was
// reported as deny-by-default by everything that described it, and the one
// thing that knew better was the gate.
//
// This gate keeps it that way, from both ends:
//
//   - No second copy. In the reporter packages (pkg/ui, pkg/hubdoctor, cmd),
//     no code asks whether a default_role was written — compares a DefaultRole
//     with "" — since that is the half of the rule nothing else needs; and
//     inside pkg/authz only Enforced reads the resolver's policy-written bit,
//     so the definition cannot fork at its source either. (The bit has no
//     exported accessor, so no other package can read it at all.)
//   - No unclassified reading of the default role. The old misreports did not
//     compare anything with "": the banner rendered an unset role as "none" and
//     the doctor called "none" deny-by-default, on hubs no policy governed. So
//     every use of a DefaultRole in a reporter is listed below with why it is
//     right — a copy of the configured value, or a read that runs only where
//     the predicate said a policy is in force — and a new one fails until it is.
//   - Every reporter asks. Each function that reports or enforces the state
//     calls the predicate, so a reporter rewritten to work it out again fails
//     here rather than at an operator's desk.
//
// The panel's JavaScript is held to the same rule behaviourally: it renders the
// verdict the hub serves (TestDashboard_OIDCPanelShowsTheHubsRBACVerdict).

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// rbacReporterDirs are the packages that report or act on RBAC enforcement,
// relative to the repository root, searched recursively.
var rbacReporterDirs = []string{"pkg/ui", "pkg/hubdoctor", "cmd"}

// defaultRoleUses lists every function in the reporter packages that touches a
// DefaultRole (field or method), as "file:function", with why that is not a
// restatement of the rule. TestDefaultRoleUsesAreStillListed rejects an entry
// whose function no longer does.
var defaultRoleUses = map[string]string{
	"pkg/ui/authz.go:warnUnsatisfiableBindings": "names the role an inert mapping's users fall back to; it returns " +
		"at once unless authzActive",
	"pkg/ui/oidc_config_api.go:oidcViewOf": "copies the saved value into the view as it is, unset included, " +
		"for the panel's select to show",
	"pkg/ui/oidc_config_api.go:oidcRBACOf": "what an unmapped identity gets, read only once authz.Enforced " +
		"says the saved block enforces",
	"pkg/ui/oidc_config_api.go:applyOIDCRequest":     "copies the submitted value into the block",
	"pkg/ui/oidc_config_api.go:handleOIDCEnforce":    "records the value the enforce action wrote",
	"pkg/ui/oidc_config_api.go:enforceDenyByDefault": "writes none, after RBACEnforced found no policy",
	"pkg/ui/oidc_config_api.go:rbacChangeOf": "names the role a save turning RBAC on hands an unmapped " +
		"identity, in the branch where RBACEnforced said it does",
	"pkg/ui/oidc_config_api.go:auditOIDCConfig":   "records the saved value",
	"pkg/ui/oidc_config_api.go:oidcChangedFields": "records whether the value moved",
	"pkg/ui/oidcconfig.go:wouldStrandTheHub": "a default role of admin makes everybody an administrator; " +
		"its wording asks authz.Enforced",
	"pkg/hubdoctor/rbac.go:checkEnforced": "names what an unmapped identity gets, in the branch " +
		"authz.Enforced decided",
	"pkg/hubdoctor/rbac.go:checkDefaultRole": "the default_role finding, which checkRBAC runs only where " +
		"authz.Enforced says a policy is in force",
	"cmd/ui_rbac.go:reportRBAC":        "the banner's default role, in the branch authz.Enforced decided",
	"cmd/config_cmd.go:applyConfigKey": "sets the value from `cloop config set`",
}

// rbacAsks lists, per reporter, the function that has to call the predicate:
// file, function, and the callee as written (package.Func or receiver.Method).
var rbacAsks = []struct{ file, fn, callee string }{
	{"pkg/ui/authz.go", "authzActive", "authz.Enforced"},
	{"pkg/ui/oidc.go", "handleMe", "s.authzActive"},
	{"pkg/ui/oidc_config_api.go", "oidcRBACOf", "s.authzActive"},
	{"pkg/ui/oidc_config_api.go", "oidcRBACOf", "authz.Enforced"},
	{"pkg/ui/oidcconfig.go", "wouldDemoteCaller", "authz.Enforced"},
	{"pkg/hubdoctor/rbac.go", "checkRBAC", "authz.Enforced"},
	{"pkg/hubdoctor/statictoken.go", "checkStaticToken", "oc.RBACEnforced"},
	{"cmd/ui_rbac.go", "reportRBAC", "authz.Enforced"},
	{"pkg/config/oidc.go", "RBACEnforced", "authz.Enforced"},
}

func TestRBACEnforcementHasOneDefinition(t *testing.T) {
	root := repoRoot(t)
	found, err := rbacRestatements(root, rbacReporterDirs)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range found {
		t.Errorf("%s: %s. Whether RBAC is in force is authz.Enforced's to decide — ask it (in pkg/ui, "+
			"through s.authzActive; for a saved block, config.OIDCConfig.RBACEnforced) instead of "+
			"testing whether a default_role was written.", f.pos, f.what)
	}

	uses, err := defaultRoleUsers(root, rbacReporterDirs)
	if err != nil {
		t.Fatal(err)
	}
	for key, pos := range uses {
		if _, ok := defaultRoleUses[key]; !ok {
			t.Errorf("%s: %s uses a DefaultRole, and defaultRoleUses does not say why that is right. "+
				"A default role means something only where a policy is in force: read it under "+
				"authz.Enforced (or s.authzActive), or list it with the reason it is a copy of the "+
				"configured value.", pos, key)
		}
	}

	readers, err := policyBitReaders(filepath.Join(root, "pkg/authz"))
	if err != nil {
		t.Fatal(err)
	}
	if len(readers) != 1 || readers[0] != "Enforced" {
		t.Errorf("pkg/authz reads the resolver's policy-written bit in %v; only Enforced may, "+
			"or the definition forks at its source", readers)
	}
}

func TestDefaultRoleUsesAreStillListed(t *testing.T) {
	uses, err := defaultRoleUsers(repoRoot(t), rbacReporterDirs)
	if err != nil {
		t.Fatal(err)
	}
	for key := range defaultRoleUses {
		if _, ok := uses[key]; !ok {
			t.Errorf("%s no longer uses a DefaultRole — remove it from defaultRoleUses", key)
		}
	}
}

func TestEveryRBACReporterAsksThePredicate(t *testing.T) {
	root := repoRoot(t)
	for _, a := range rbacAsks {
		calls, err := callsIn(filepath.Join(root, a.file), a.fn)
		if err != nil {
			t.Errorf("%s: %v", a.file, err)
			continue
		}
		if !calls[a.callee] {
			t.Errorf("%s: %s no longer calls %s, so what it reports about RBAC is no longer the "+
				"answer the request gate acts on", a.file, a.fn, a.callee)
		}
	}
}

// The gate must flag what it exists for, and only that.
func TestRBACGateFlagsASecondCopy(t *testing.T) {
	root := t.TempDir()
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
	write("pkg/ui/copy.go", `package ui
import "strings"
type oidc struct{ DefaultRole string; RoleMappings []int }
func a(o oidc) bool { return len(o.RoleMappings) > 0 || o.DefaultRole != "" }
func b(o oidc) bool { return "" == strings.TrimSpace(o.DefaultRole) }
func c(o oidc) string { switch o.DefaultRole { case "": return "none" }; return o.DefaultRole }
`)
	write("pkg/hubdoctor/fine.go", `package hubdoctor
type oidc struct{ DefaultRole string }
type resolver struct{}
func (resolver) DefaultRole() string { return "none" }
func d(o oidc, role string) bool { return o.DefaultRole == "viewer" || role == "" }
func e(r resolver) string { switch r.DefaultRole() { case "admin": return "x" }; return "" }
`)
	write("pkg/hubdoctor/method.go", `package hubdoctor
type res struct{}
func (res) DefaultRole() string { return "" }
func f(r res) bool { return r.DefaultRole() == "" }
`)
	write("pkg/ui/copy_test.go", `package ui
type tcfg struct{ DefaultRole string }
func g(o tcfg) bool { return o.DefaultRole == "" }
`)

	found, err := rbacRestatements(root, []string{"pkg/ui", "pkg/hubdoctor"})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, f := range found {
		got = append(got, f.pos)
	}
	want := []string{"pkg/hubdoctor/method.go:4", "pkg/ui/copy.go:4", "pkg/ui/copy.go:5", "pkg/ui/copy.go:6"}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("flagged %v, want %v", got, want)
	}

	uses, err := defaultRoleUsers(root, []string{"pkg/ui", "pkg/hubdoctor"})
	if err != nil {
		t.Fatal(err)
	}
	var keys []string
	for k := range uses {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if want := "pkg/hubdoctor/fine.go:d pkg/hubdoctor/fine.go:e pkg/hubdoctor/method.go:f " +
		"pkg/ui/copy.go:a pkg/ui/copy.go:b pkg/ui/copy.go:c"; strings.Join(keys, " ") != want {
		t.Errorf("default-role users = %v, want %s", keys, want)
	}

	write("pkg/authz/a.go", `package authz
type Resolver struct{ configured bool }
func New(b bool) *Resolver { return &Resolver{configured: b} }
func Enforced(sso bool, r *Resolver) bool { return sso && r != nil && r.configured }
func (r *Resolver) Configured() bool { return r.configured }
`)
	readers, err := policyBitReaders(filepath.Join(root, "pkg/authz"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(readers, ",") != "Configured,Enforced" {
		t.Errorf("readers = %v, want the second accessor found beside Enforced (New only sets it)", readers)
	}

	write("pkg/ui/asks.go", `package ui
type srv struct{}
func (s *srv) authzActive() bool { return false }
func (s *srv) handleMe() { _ = s.authzActive() }
func (s *srv) other() {}
`)
	calls, err := callsIn(filepath.Join(root, "pkg/ui/asks.go"), "handleMe")
	if err != nil || !calls["s.authzActive"] {
		t.Errorf("calls = %v, %v", calls, err)
	}
	if calls, _ = callsIn(filepath.Join(root, "pkg/ui/asks.go"), "other"); calls["s.authzActive"] {
		t.Error("a function that does not call the predicate was credited with it")
	}
	if _, err := callsIn(filepath.Join(root, "pkg/ui/asks.go"), "gone"); err == nil {
		t.Error("a function that does not exist was not reported")
	}
}

type rbacFinding struct{ pos, what string }

// rbacRestatements finds, in the production files under dirs, every comparison
// of a DefaultRole — a field or a method — with the empty string: "was a
// default_role written", the half of the enforcement rule only authz.Enforced
// may evaluate. Positions are "dir/file.go:line", sorted.
func rbacRestatements(root string, dirs []string) ([]rbacFinding, error) {
	var out []rbacFinding
	for _, dir := range dirs {
		base := filepath.Join(root, dir)
		err := filepath.WalkDir(base, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if name := d.Name(); path != base && (name == "testdata" || strings.HasPrefix(name, ".")) {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			fset := token.NewFileSet()
			file, err := parser.ParseFile(fset, path, nil, 0)
			if err != nil {
				return err
			}
			rel, _ := filepath.Rel(root, path)
			at := func(n ast.Node) string {
				return fmt.Sprintf("%s:%d", filepath.ToSlash(rel), fset.Position(n.Pos()).Line)
			}
			ast.Inspect(file, func(n ast.Node) bool {
				switch n := n.(type) {
				case *ast.BinaryExpr:
					if n.Op != token.EQL && n.Op != token.NEQ {
						return true
					}
					if (isEmptyString(n.X) && mentionsDefaultRole(n.Y)) || (isEmptyString(n.Y) && mentionsDefaultRole(n.X)) {
						out = append(out, rbacFinding{at(n), "compares a DefaultRole with \"\""})
					}
				case *ast.SwitchStmt:
					if n.Tag == nil || !mentionsDefaultRole(n.Tag) {
						return true
					}
					for _, stmt := range n.Body.List {
						cc, ok := stmt.(*ast.CaseClause)
						if !ok {
							continue
						}
						for _, e := range cc.List {
							if isEmptyString(e) {
								out = append(out, rbacFinding{at(n), "switches on a DefaultRole with a case for \"\""})
							}
						}
					}
				}
				return true
			})
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].pos < out[j].pos })
	return out, nil
}

// defaultRoleUsers maps "file:function" to the first position at which that
// function, in a production file under dirs, uses a DefaultRole selector.
// Declarations outside any function are keyed "file:<package scope>".
func defaultRoleUsers(root string, dirs []string) (map[string]string, error) {
	out := map[string]string{}
	for _, dir := range dirs {
		base := filepath.Join(root, dir)
		err := filepath.WalkDir(base, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if name := d.Name(); path != base && (name == "testdata" || strings.HasPrefix(name, ".")) {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			fset := token.NewFileSet()
			file, err := parser.ParseFile(fset, path, nil, 0)
			if err != nil {
				return err
			}
			rel, _ := filepath.Rel(root, path)
			rel = filepath.ToSlash(rel)
			for _, decl := range file.Decls {
				scope := "<package scope>"
				if fn, ok := decl.(*ast.FuncDecl); ok {
					scope = fn.Name.Name
				}
				key := rel + ":" + scope
				ast.Inspect(decl, func(n ast.Node) bool {
					sel, ok := n.(*ast.SelectorExpr)
					if !ok || sel.Sel.Name != "DefaultRole" {
						return true
					}
					if _, seen := out[key]; !seen {
						out[key] = fmt.Sprintf("%s:%d", rel, fset.Position(sel.Pos()).Line)
					}
					return true
				})
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

func isEmptyString(e ast.Expr) bool {
	lit, ok := e.(*ast.BasicLit)
	return ok && lit.Kind == token.STRING && (lit.Value == `""` || lit.Value == "``")
}

func mentionsDefaultRole(e ast.Expr) bool {
	found := false
	ast.Inspect(e, func(n ast.Node) bool {
		if sel, ok := n.(*ast.SelectorExpr); ok && sel.Sel.Name == "DefaultRole" {
			found = true
		}
		return !found
	})
	return found
}

// policyBitReaders names the functions in the package at dir that read a
// `.configured` selector — the resolver's "an operator wrote a policy" bit.
// Setting it in a composite literal is not a read.
func policyBitReaders(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), filepath.Join(dir, name), nil, 0)
		if err != nil {
			return nil, err
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				if sel, ok := n.(*ast.SelectorExpr); ok && sel.Sel.Name == "configured" {
					seen[fn.Name.Name] = true
				}
				return true
			})
		}
	}
	var out []string
	for name := range seen {
		out = append(out, name)
	}
	sort.Strings(out)
	return out, nil
}

// callsIn returns the callees of function fn in file, as written: "pkg.Func"
// or "recv.Method" for a selector call, "Func" for a plain one.
func callsIn(path, fn string) (map[string]bool, error) {
	file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if err != nil {
		return nil, err
	}
	for _, decl := range file.Decls {
		f, ok := decl.(*ast.FuncDecl)
		if !ok || f.Name.Name != fn || f.Body == nil {
			continue
		}
		calls := map[string]bool{}
		ast.Inspect(f.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			switch fun := call.Fun.(type) {
			case *ast.SelectorExpr:
				if x, ok := fun.X.(*ast.Ident); ok {
					calls[x.Name+"."+fun.Sel.Name] = true
				}
			case *ast.Ident:
				calls[fun.Name] = true
			}
			return true
		})
		return calls, nil
	}
	return nil, fmt.Errorf("no function %s", fn)
}
