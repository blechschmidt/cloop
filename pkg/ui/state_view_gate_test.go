package ui

// state_view_gate_test.go keeps the read-only routes on the dashboard's one
// view of a project (Task 20518).
//
// A run on an executor that cannot read the hub's filesystem works through its
// own copy of the project, and the hub's copy keeps the previous run's
// statuses until it ends. /api/state and the state pushes fold the run's
// account in (overlaySeededRun); a task's details, the glasses, GET /api/tasks,
// the Requirements tab and the charts read the hub's copy directly, so for the
// length of every such run they called a task pending that the list showed
// running or done. Nothing at the call site shows which kind of read it is, so
// the classification is written down here and checked against the source: a
// GET route's handler that reads the project with state.Load or state.LoadLite
// must fold a seeded run in itself (s.loadStateView, or s.overlaySeededRun
// beside the load), or be listed in stateRecordReads with the reason its read
// is about the record. When this test fails on a new handler, the fix is almost
// never a new entry: read the project with s.loadStateView.
//
// The gate reads handler bodies, so a read inside a helper the handler calls is
// the helper's to get right: planView is the Requirements tab's.
// TestTaskViewsShowWhatASeededRunDid drives the routes this covers.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// stateImportPath is the package whose loaders the gate tracks.
const stateImportPath = "github.com/blechschmidt/cloop/pkg/state"

// stateRecordReads are the GET handlers that read the hub's own copy and show
// none of a seeded run's tasks, each with the reason.
var stateRecordReads = map[string]string{
	"handleSteps": "the steps journal: a run on another machine sends its steps with its outcome, " +
		"and its progress reports carry none",
	"handleGoal": "the goal is the hub's to keep, and a run on another machine does not report one; " +
		"the same handler saves it on POST",
	"handleInstructions": "the instructions are the hub's to keep, like the goal; the same handler " +
		"saves them on POST",
	"handleReviewGateGet":             "the review gate's settings, which only the hub changes",
	"handleProjectKnowledgeRetrieval": "the project's knowledge retrieval settings, which only the hub changes",
}

// stateCalls is what the gate found in one function.
type stateCalls struct {
	loads    int    // state.Load / state.LoadLite references
	overlays int    // s.loadStateView / s.overlaySeededRun calls
	where    string // the first load, for messages
}

func TestReadOnlyRoutesShowASeededRunsPlan(t *testing.T) {
	// The GET routes, by handler method.
	gets := map[string][]string{}
	for _, rs := range (&Server{}).routeTable() {
		serves := false
		for _, m := range rs.methods() {
			serves = serves || m == "GET"
		}
		if !serves || rs.Handler == nil {
			continue
		}
		name := runtime.FuncForPC(reflect.ValueOf(rs.Handler).Pointer()).Name()
		name = strings.TrimSuffix(name[strings.LastIndex(name, ".")+1:], "-fm")
		gets[name] = append(gets[name], rs.Pattern)
	}
	if len(gets) < 50 {
		t.Fatalf("found %d GET handlers in the route table; the gate is not reading it", len(gets))
	}

	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	found := map[string]stateCalls{}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		file, err := parser.ParseFile(fset, f, src, 0)
		if err != nil {
			t.Fatal(err)
		}
		names := map[string]bool{}
		for _, imp := range file.Imports {
			path, err := strconv.Unquote(imp.Path.Value)
			if err != nil || path != stateImportPath {
				continue
			}
			switch {
			case imp.Name == nil:
				names["state"] = true
			case imp.Name.Name == ".":
				t.Errorf("%s dot-imports pkg/state, so its loaders cannot be told apart; import it by name", f)
			case imp.Name.Name != "_":
				names[imp.Name.Name] = true
			}
		}
		for _, d := range file.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok || fn.Recv == nil || fn.Body == nil || gets[fn.Name.Name] == nil {
				continue
			}
			if configCallFuncName(fn) != "(*Server)."+fn.Name.Name {
				continue
			}
			c := found[fn.Name.Name]
			// Closures belong to the handler: a read inside one is still the
			// handler's read.
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				sel, ok := n.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				id, ok := sel.X.(*ast.Ident)
				if !ok {
					return true
				}
				switch {
				case names[id.Name] && (sel.Sel.Name == "Load" || sel.Sel.Name == "LoadLite"):
					c.loads++
					if c.where == "" {
						p := fset.Position(sel.Pos())
						c.where = filepath.Base(p.Filename) + ":" + strconv.Itoa(p.Line)
					}
				case sel.Sel.Name == "loadStateView" || sel.Sel.Name == "overlaySeededRun":
					c.overlays++
				}
				return true
			})
			found[fn.Name.Name] = c
		}
	}

	var unclassified, stale []string
	for name, c := range found {
		if c.loads == 0 || c.overlays > 0 {
			continue
		}
		if _, ok := stateRecordReads[name]; ok {
			continue
		}
		unclassified = append(unclassified, c.where+" "+name+" ("+strings.Join(gets[name], ", ")+")")
	}
	for name := range stateRecordReads {
		if c, ok := found[name]; !ok || c.loads == 0 || c.overlays > 0 {
			stale = append(stale, name)
		}
	}
	sort.Strings(unclassified)
	sort.Strings(stale)
	for _, u := range unclassified {
		t.Errorf("%s reads the hub's own copy of the project. While a run works through it on another "+
			"machine that copy holds the statuses the tasks had when the run was sent, and the task list "+
			"shows the run's: read the project with s.loadStateView, or list the handler in "+
			"stateRecordReads with the reason its read is about the record", u)
	}
	for _, s := range stale {
		t.Errorf("stateRecordReads lists %s, which is no GET handler reading the record without a seeded "+
			"run any more: remove the entry", s)
	}
}
