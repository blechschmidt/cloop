package arch_test

// The host sandbox is decided in every dispatch primitive (Task 20480).
//
// pkg/ui starts every workload it dispatches through two primitives,
// startWorkloadAs and runWorkloadEnvFor, and each shapes the workload's spec
// step by step: the lease, the grants, the sandbox file, the firewall, the
// workspace, the relay, the ceilings, and last the Copilot pin, which
// copilotenv_test.go keeps after every step that writes the environment. The
// host sandbox has to come after all of them, because it starts from the
// environment and the lease they produced, and before the workload starts —
// or a person's run on the hub's host reaches everything the hub's user can.
//
// A dispatch function is recognised by the pin: every function that pins the
// Copilot home must put the host sandbox on the spec after it, and before it
// starts the workload. A future third primitive that copies the shaping steps
// and forgets this one fails here.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// hostSandboxScan is what the gate found.
type hostSandboxScan struct {
	dispatchers int
	violations  []string
}

func scanHostSandbox(dir string) (*hostSandboxScan, error) {
	files, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil {
		return nil, err
	}
	sort.Strings(files)
	scan := &hostSandboxScan{}
	fset := token.NewFileSet()
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return nil, err
		}
		for _, decl := range f.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Body == nil || fd.Name.Name == "pinCopilotHome" || fd.Name.Name == "applyHostSandbox" {
				continue
			}
			var pin, sandbox, start token.Pos
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				c, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				switch name := calleeName(c); {
				case name == "pinCopilotHome":
					if c.Pos() > pin {
						pin = c.Pos()
					}
				case name == "applyHostSandbox":
					if sandbox == token.NoPos {
						sandbox = c.Pos()
					}
				case name == "Start" || (name == "Run" && isSelectorOf(c, "executor")):
					if start == token.NoPos || c.Pos() < start {
						start = c.Pos()
					}
				}
				return true
			})
			if pin == token.NoPos {
				continue
			}
			scan.dispatchers++
			fn := harnessFuncName(fd)
			switch {
			case sandbox == token.NoPos:
				scan.violations = append(scan.violations, fset.Position(fd.Pos()).String()+": "+fn+
					" pins the Copilot home but never decides the host sandbox: a person's workload it "+
					"starts on the hub's host would reach every other person's files")
			case sandbox < pin:
				scan.violations = append(scan.violations, fset.Position(sandbox).String()+": "+fn+
					" decides the host sandbox before the Copilot pin, which is the last step that shapes the "+
					"spec — move applyHostSandbox after it")
			case start != token.NoPos && start < sandbox:
				scan.violations = append(scan.violations, fset.Position(start).String()+": "+fn+
					" starts the workload before deciding the host sandbox")
			}
		}
	}
	return scan, nil
}

// isSelectorOf reports a call pkg.Fn(…) on the package named pkg.
func isSelectorOf(c *ast.CallExpr, pkg string) bool {
	sel, ok := c.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	id, ok := sel.X.(*ast.Ident)
	return ok && id.Name == pkg
}

func TestEveryDispatchDecidesTheHostSandbox(t *testing.T) {
	scan, err := scanHostSandbox(filepath.Join(repoRoot(t), uiDir))
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range scan.violations {
		t.Error(v)
	}
	if scan.dispatchers < 2 {
		t.Fatalf("the gate found %d dispatch functions in pkg/ui, want startWorkloadAs and runWorkloadEnvFor at "+
			"least — it is looking in the wrong place, and would pass anything", scan.dispatchers)
	}
}

// The gate must flag what it exists for, and only that.
func TestHostSandboxGateFlagsWhatItShould(t *testing.T) {
	dir := t.TempDir()
	src := `package ui
import "github.com/blechschmidt/cloop/pkg/executor"
func pinCopilotHome(spec, pin []string) []string { return spec }
func applyHostSandbox(spec []string) ([]string, error) { return spec, nil }
func good(ex executor.Executor) {
	spec := pinCopilotHome(nil, nil)
	spec, _ = applyHostSandbox(spec)
	ex.Start(nil, spec)
}
func forgets(ex executor.Executor) {
	spec := pinCopilotHome(nil, nil)
	ex.Start(nil, spec)
}
func early(ex executor.Executor) {
	spec, _ := applyHostSandbox(nil)
	spec = pinCopilotHome(spec, nil)
	ex.Start(nil, spec)
}
func late(ex executor.Executor) {
	spec := pinCopilotHome(nil, nil)
	executor.Run(nil, ex, spec)
	spec, _ = applyHostSandbox(spec)
}
func unrelated() { _ = 1 }
`
	if err := os.WriteFile(filepath.Join(dir, "prims.go"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	scan, err := scanHostSandbox(dir)
	if err != nil {
		t.Fatal(err)
	}
	if scan.dispatchers != 4 {
		t.Errorf("found %d dispatchers, want 4", scan.dispatchers)
	}
	want := map[string]bool{"forgets": false, "early": false, "late": false}
	for _, v := range scan.violations {
		for name := range want {
			if strings.Contains(v, ": "+name+" ") {
				want[name] = true
			}
		}
		if strings.Contains(v, ": good ") {
			t.Errorf("flagged the correct primitive: %s", v)
		}
	}
	for name, flagged := range want {
		if !flagged {
			t.Errorf("%s was not flagged; violations: %q", name, scan.violations)
		}
	}
}
