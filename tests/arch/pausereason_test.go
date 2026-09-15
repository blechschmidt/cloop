package arch_test

import (
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

// This gate keeps a paused run explainable (Task 20285).
//
// The failure it exists to catch is not a crash. Before the pause reason
// existed, ~26 sites across the orchestrator, the hub and the recovery sweep
// each wrote the same literal:
//
//	s.Status = "paused"
//
// An approval gate waiting on a human, a spent budget, an operator's Ctrl-C, a
// killed process and an exhausted five-hour subscription window all produced
// that one word, so the API, the dashboard and the audit trail could not tell
// them apart. A fleet could sit stalled for a week and the only way to find out
// why was to read the scrollback of a process that had already exited.
//
// Converting the sites once fixes the sites that existed. It does not stop the
// twenty-seventh from being written next month — and that one would be invisible
// exactly the way the first twenty-six were, because a bare status assignment
// compiles, vets clean and passes every behavioural test. So the rule is
// structural: reaching "paused" goes through state.SetPaused, which cannot be
// called without naming a reason.
//
// The legitimate ways to satisfy this gate are to call SetPaused, or to argue
// for an entry in pausedStatusExempt. What it refuses is the third state, where
// a run stops and nothing records why.

// pausedStatusExempt lists file:function sites allowed to assign the literal
// directly, each with the reason.
//
// SetPaused is the sanctioned funnel and must be able to perform the
// assignment itself; everything else is a hole in the gate.
var pausedStatusExempt = map[string]string{
	"pkg/state/state.go:SetPaused": "the funnel itself — it is what every other site is required to call",
}

// TestPausedStatusAlwaysCarriesAReason fails when a non-test file assigns the
// literal "paused" to a Status field outside the sanctioned funnel.
func TestPausedStatusAlwaysCarriesAReason(t *testing.T) {
	root := repoRoot(t)

	var offenders []string
	seenExempt := map[string]bool{}

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "vendor", "testdata":
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}

		fset := token.NewFileSet()
		file, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			// A file this package cannot parse is not silently skipped: the
			// gate would then pass by failing to look.
			return perr
		}

		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			rel = path
		}
		rel = filepath.ToSlash(rel)

		// Track the enclosing function so the report — and the exemption key —
		// name something a reader can go and look at.
		var fnStack []string
		ast.Inspect(file, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.FuncDecl:
				fnStack = append(fnStack, node.Name.Name)
			case *ast.AssignStmt:
				for _, lhs := range node.Lhs {
					if !isStatusTarget(lhs) {
						continue
					}
					for _, rhs := range node.Rhs {
						if !isPausedLiteral(rhs) {
							continue
						}
						fn := "<file scope>"
						if len(fnStack) > 0 {
							fn = fnStack[len(fnStack)-1]
						}
						key := rel + ":" + fn
						if _, ok := pausedStatusExempt[key]; ok {
							seenExempt[key] = true
							continue
						}
						offenders = append(offenders, key+" (line "+
							itoa(fset.Position(node.Pos()).Line)+")")
					}
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("walking the module: %v", err)
	}

	if len(offenders) > 0 {
		sort.Strings(offenders)
		t.Errorf("%d site(s) assign Status = \"paused\" directly instead of calling "+
			"state.SetPaused:\n  %s\n\n"+
			"A bare \"paused\" is the silent stall this gate exists to prevent: it tells an "+
			"operator that work stopped but not whether to wait, raise a budget, approve "+
			"something, or do nothing because a usage window reopens at 14:50.\n"+
			"Fix by naming the cause:\n"+
			"    s.SetPaused(pausereason.New(pausereason.CodeBudget, \"daily budget spent\"))\n"+
			"and, when the condition ends at a known instant, record it so the hub can "+
			"resume without a human:\n"+
			"    s.SetPaused(pausereason.NewUntil(pausereason.CodeUsageCap, detail, resetsAt))",
			len(offenders), strings.Join(offenders, "\n  "))
	}

	// An exemption that no longer matches a real site is a hole left open for
	// a reason that has gone away.
	for key, why := range pausedStatusExempt {
		if !seenExempt[key] {
			t.Errorf("stale exemption %q (%s): no such site assigns Status = \"paused\" any more — remove it", key, why)
		}
	}
}

// TestEveryPauseReasonCodeIsRenderable checks that each code the orchestrator
// can persist is one the rest of the system recognises.
//
// Known() is what the persistence layer filters on, so a code that fails it is
// silently dropped on the way to disk — the run would pause with no reason at
// all, which is the state this whole mechanism replaced.
func TestEveryPauseReasonCodeIsRenderable(t *testing.T) {
	root := repoRoot(t)

	// The frontend renders labels from the same code strings. A code with no
	// entry in the dashboard's map degrades to the raw identifier, which is
	// survivable but ugly, so it is worth naming here.
	labels := pauseReasonJSLabels(t, root)

	for _, code := range pauseReasonCodes(t, root) {
		if !labels[code] {
			t.Errorf("pause reason code %q has no entry in pauseReasonLabels in "+
				"pkg/ui/assets/js/00-core.js: a paused project would render the raw code "+
				"to the operator.", code)
		}
	}

	// And the other way: a label for a code Go no longer emits is dead text
	// that suggests a state the system cannot reach.
	declared := map[string]bool{}
	for _, code := range pauseReasonCodes(t, root) {
		declared[code] = true
	}
	for code := range labels {
		if !declared[code] {
			t.Errorf("pauseReasonLabels in 00-core.js has an entry for %q, which is not a "+
				"pausereason.Code any more — remove it", code)
		}
	}
}

// pauseReasonJSLabels returns the keys of the pauseReasonLabels object literal
// in the dashboard bundle.
//
// Parsed rather than substring-matched: a bare Contains check passes on a code
// that merely appears somewhere in a 700-line file, which is how this gate
// first "passed" for codes that had no label at all.
func pauseReasonJSLabels(t *testing.T, root string) map[string]bool {
	t.Helper()
	path := filepath.Join(root, "pkg/ui/assets/js/00-core.js")
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading the dashboard core bundle: %v", err)
	}

	const marker = "const pauseReasonLabels = {"
	start := strings.Index(string(src), marker)
	if start < 0 {
		t.Fatalf("%s no longer declares pauseReasonLabels — this gate needs updating", path)
	}
	rest := string(src)[start+len(marker):]
	end := strings.Index(rest, "};")
	if end < 0 {
		t.Fatalf("pauseReasonLabels in %s is not terminated by '};'", path)
	}

	out := map[string]bool{}
	for _, line := range strings.Split(rest[:end], "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}
		key, _, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key = strings.Trim(strings.TrimSpace(key), `'"`)
		if key != "" {
			out[key] = true
		}
	}
	if len(out) == 0 {
		t.Fatal("parsed no keys out of pauseReasonLabels — the literal's shape changed")
	}
	return out
}

// pauseReasonCodes reads the declared codes out of the package source, so the
// gate cannot drift from the enum by importing a stale copy of it.
func pauseReasonCodes(t *testing.T, root string) []string {
	t.Helper()
	path := filepath.Join(root, "pkg/pausereason/pausereason.go")
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("parsing %s: %v", path, err)
	}

	var codes []string
	ast.Inspect(file, func(n ast.Node) bool {
		vs, ok := n.(*ast.ValueSpec)
		if !ok {
			return true
		}
		for _, v := range vs.Values {
			lit, ok := v.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				continue
			}
			s := strings.Trim(lit.Value, `"`)
			// Only the Code constants; the label map holds prose.
			if s != "" && !strings.Contains(s, " ") {
				codes = append(codes, s)
			}
		}
		return true
	})
	if len(codes) == 0 {
		t.Fatal("found no pause reason codes — the parser or the package layout changed")
	}
	return codes
}

// isStatusTarget reports whether an assignment target is a .Status field.
func isStatusTarget(e ast.Expr) bool {
	sel, ok := e.(*ast.SelectorExpr)
	return ok && sel.Sel != nil && sel.Sel.Name == "Status"
}

// isPausedLiteral reports whether an expression is the string "paused".
func isPausedLiteral(e ast.Expr) bool {
	lit, ok := e.(*ast.BasicLit)
	return ok && lit.Kind == token.STRING && strings.Trim(lit.Value, "`\"") == "paused"
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
