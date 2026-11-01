package security

// The hub reads a project's requirements spec file only on the project's
// executor (Task 20459).
//
// .cloop/requirements.yaml lives in the project's checkout, which is where the
// project's executor has it: a container's workspace, a device's directory, a
// Pod's clone. The hub's own copy of the project directory, when it has one,
// is not what the project's runs see — and read on the hub's host, a symbolic
// link committed to the repository would be followed among the hub's own
// files, with the hub's privileges, by anyone who may press Read again. So the
// hub dispatches `cloop requirements validate --json` to the project's
// executor and parses the bytes it prints (pkg/ui/requirements_spec_api.go);
// it never calls what opens the file. This holds it to that: no HTTP handler,
// and nothing the hub runs in the background, reaches ReadSpecFile,
// LoadSpecFile or WriteSpecFile in its own process. A dispatch through an
// executor driver is the sanctioned door, as for every other workload.

import (
	"strings"
	"testing"
)

// specFileAccess are the functions that open a spec file.
var specFileAccess = []string{"ReadSpecFile", "LoadSpecFile", "WriteSpecFile"}

const requirementsPkg = ModulePath + "/pkg/requirements"

func TestTheHubReadsTheSpecFileOnlyOnTheProjectsExecutor(t *testing.T) {
	g, err := LoadGraph()
	if err != nil {
		t.Fatalf("build reference graph: %v", err)
	}
	if n := g.HandlerCount(); n < minExpectedHandlers {
		t.Fatalf("only %d HTTP handlers discovered — the check would pass vacuously", n)
	}
	var access []string
	for _, name := range specFileAccess {
		key, ok := g.FindFunc(requirementsPkg, name)
		if !ok {
			t.Fatalf("requirements.%s is not in the graph — it moved or was renamed, and this check would pass anything", name)
		}
		access = append(access, key)
	}
	for _, v := range specFileViolations(g, access) {
		t.Error(v)
	}
	// The hub does parse spec files — the ones its executors send — so the
	// graph has the package, and the handlers that need it.
	parse, ok := g.FindFunc(requirementsPkg, "ParseSpecFile")
	if !ok {
		t.Fatal("requirements.ParseSpecFile is not in the graph")
	}
	parses := false
	for _, h := range g.HandlerKeys() {
		if _, ok := g.ReachesWithin(h, parse); ok {
			parses = true
			break
		}
	}
	if !parses {
		t.Fatal("no handler parses a spec file: the graph lost pkg/requirements, and the check would pass anything")
	}
}

// specFileViolations reports every handler and background root that reaches
// one of access outside the executor boundary.
func specFileViolations(g *Graph, access []string) []string {
	var out []string
	for _, key := range access {
		for _, h := range g.HandlerKeys() {
			if path, ok := g.ReachesWithin(h, key); ok {
				out = append(out, "handler "+h+" opens the requirements spec file in the hub's own process:\n    "+
					strings.Join(path, "\n    ")+"\nDispatch `cloop requirements validate --json` to the project's "+
					"executor and parse what it prints, as requirements_spec_api.go does.")
			}
		}
		for _, root := range BackgroundRoots {
			if path, ok := g.BackgroundReachesWithin(root, key); ok {
				out = append(out, "the hub's background opens the requirements spec file in its own process:\n    "+
					strings.Join(path, "\n    "))
			}
		}
	}
	return out
}

// The check must flag what it exists for, and only that.
func TestSpecFileCheckFlagsWhatItShould(t *testing.T) {
	g := &Graph{nodes: map[string]*node{}, handlers: map[string]string{}}
	add := func(key, pkg string, callees ...string) {
		n := &node{key: key, pkgPath: pkg, callees: map[string]bool{}}
		for _, c := range callees {
			n.callees[c] = true
		}
		g.nodes[key] = n
	}
	const (
		ui      = ModulePath + "/pkg/ui"
		load    = requirementsPkg + ".LoadSpecFile"
		parse   = requirementsPkg + ".ParseSpecFile"
		driver  = "(*" + ModulePath + "/pkg/executor/local.Driver).Start"
		reads   = "(*" + ModulePath + "/pkg/ui.Server).readsHere"
		parses  = "(*" + ModulePath + "/pkg/ui.Server).parsesWhatItWasSent"
		through = "(*" + ModulePath + "/pkg/ui.Server).dispatches"
	)
	add(load, requirementsPkg, parse)
	add(parse, requirementsPkg)
	add(driver, ModulePath+"/pkg/executor/local", load)
	add(reads, ui, load)
	add(parses, ui, parse)
	add(through, ui, driver)
	for _, h := range []string{reads, parses, through} {
		g.handlers[h] = h
	}
	got := strings.Join(specFileViolations(g, []string{load}), "\n")
	if !strings.Contains(got, "handler "+reads+" opens") {
		t.Errorf("a handler that opens the file was not flagged:\n%s", got)
	}
	if strings.Contains(got, parses) || strings.Contains(got, through) {
		t.Errorf("flagged a handler that only parses, or one that dispatches through an executor:\n%s", got)
	}
}
