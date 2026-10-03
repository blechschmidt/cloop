package ui

// hubconfig_gate_test.go keeps hub-scope settings reading the hub's
// per-instance overlay (Task 20364).
//
// The bug this gate exists for was not a wrong value somewhere. It was a
// call that looked right. config.Load(s.WorkDir) reads the hub's directory,
// so it reads like "the hub's configuration", but it skips
// .cloop/config.ui-<port>.yaml. All but four of the package's hub-scope reads
// did that. An overlay that set allow_host_process: false, an image policy or
// a git proxy was merged for the startup banner and ignored by the code that
// enforces each of them, so every one of those controls failed open.
//
// Nothing about the call site shows which kind of setting it reads, so the
// classification is written down here and checked against the source:
//
//   - every config.Load in the package must be listed in configLoadSites with
//     the reason its read is project-scope (or, inside hubconfig.go, why the
//     accessor itself has to read config.yaml alone);
//   - every config.Save must be listed in configSaveSites, because a writer
//     that saves a merged view copies this hub's overlay into the config.yaml
//     another dashboard reads;
//   - config.LoadUIInstance appears once, in loadHubConfigAt.
//
// The lists record a count per function, so a second read added to an
// allowlisted function fails too, and an entry that no longer matches the
// source fails as stale. When this test fails on a new read, the fix is
// almost never a new entry. Read a hub-scope setting with s.loadHubConfig()
// or controlPlaneConfig(), or with s.governingConfig(dir) when a project may
// state the setting for itself (retention, backup, dictation).

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// configImportPath is the package whose loaders the gate tracks.
const configImportPath = "github.com/blechschmidt/cloop/pkg/config"

// configCallSite allows calls in one function. fn is the function's name,
// with its receiver for a method, as configCallSites renders it.
type configCallSite struct {
	fn    string
	calls int
	why   string
}

// configLoadSites are the reads of a config.yaml without the hub's overlay.
// Outside hubconfig.go every one is project-scope: the setting belongs to a
// project, and the `cloop run` that uses it reads that project's config.yaml
// and never an overlay, so the dashboard must read the same file.
var configLoadSites = []configCallSite{
	// Project-scope reads: provider, model and step timeout.
	{"resolveProviderName", 1, "the provider a project's run will use, which `cloop run` reads from its config.yaml"},
	{"resolveProjectModel", 1, "the model a project's run will use"},
	{"buildProjectProvider", 1, "builds a provider from a project's own settings and keys"},
	{"marshalStateForWire", 1, "a project's step_timeout, as its run will apply it"},
	{"(*Server).handleState", 1, "a project's model, for the dashboard's state view"},
	{"(*Server).handleConfig", 1, "a project's provider settings, for the provider picker"},
	{"(*Server).handleConfigSet", 1, "loads a project's config.yaml to rewrite it from itself (provider keys)"},
	{"(*Server).handleTaskBlocker", 1, "builds a provider from a project's settings"},
	{"(*Server).handlePlanChat", 1, "builds a provider from a project's settings"},
	{"(*Server).handleReplayRunCreate", 1, "builds a replay provider from a project's settings"},
	{"(*Server).handleProviderCallReplay", 1, "builds a replay provider from a project's settings"},
	// Project-scope reads: budget, Claude Code caps.
	{"(*Server).handleBudgetGet", 1, "a project's budget section"},
	{"(*Server).handleBudgetProjectSave", 1, "loads a project's config.yaml to rewrite it from itself (budget)"},
	{"(*Server).handleClaudeCodeLimitsGet", 1, "a project's Claude Code caps"},
	{"(*Server).handleClaudeCodeLimitsSave", 1, "loads a project's config.yaml to rewrite it from itself (caps)"},
	{"(*Server).handleStepTimeoutSet", 1, "loads a project's config.yaml to rewrite it from itself (step_timeout)"},

	// The accessor's own reads of config.yaml alone (hubconfig.go).
	{"(*Server).governingConfig", 1, "the branch for a directory that is not the hub's own: a project's config.yaml"},
	{"governingConfigFor", 1, "the same branch, for code with no Server"},
	{"(*Server).beginHubSettingsSave", 1, "with no overlay, a hub save rewrites config.yaml from config.yaml alone"},
	{"bootstrapHubConfig", 1, "the fallback when the overlay cannot be read, which is what bootstrap read before Task 20364"},
}

// configSaveSites are the writes of a whole config.yaml.
var configSaveSites = []configCallSite{
	{"(*Server).handleConfigSet", 1, "a project's provider keys, into the config.yaml they were loaded from"},
	{"(*Server).handleBudgetProjectSave", 1, "a project's budget, into the config.yaml it was loaded from"},
	{"(*Server).handleClaudeCodeLimitsSave", 1, "a project's caps, into the config.yaml they were loaded from"},
	{"(*Server).handleStepTimeoutSet", 1, "a project's step_timeout, into the config.yaml it was loaded from"},
	{"(*hubSettingsSave).commit", 1, "every hub settings save; reached only when the hub has no overlay"},
}

// configOverlaySites are the reads that merge an overlay. One, so there is one
// definition of "the hub's configuration".
var configOverlaySites = []configCallSite{
	{"loadHubConfigAt", 1, "the accessor"},
}

// configCallScan is what one pass over a set of files found.
type configCallScan struct {
	// calls counts references per loader ("Load", "Save", "LoadUIInstance")
	// and enclosing function.
	calls map[string]map[string]int
	// where records a position per loader and function, for messages.
	where map[string]map[string]string
	// problems are references the gate cannot attribute to a function at all:
	// a dot import, or a loader referenced at package scope.
	problems []string
}

// configCallFuncName renders a function's name as the allowlists spell it.
func configCallFuncName(fd *ast.FuncDecl) string {
	if fd.Recv == nil || len(fd.Recv.List) == 0 {
		return fd.Name.Name
	}
	recv := fd.Recv.List[0].Type
	// Strip type parameters: (*T[K]) is still the method set of T.
	if idx, ok := recv.(*ast.IndexExpr); ok {
		recv = idx.X
	}
	switch t := recv.(type) {
	case *ast.StarExpr:
		x := t.X
		if idx, ok := x.(*ast.IndexExpr); ok {
			x = idx.X
		}
		if id, ok := x.(*ast.Ident); ok {
			return "(*" + id.Name + ")." + fd.Name.Name
		}
	case *ast.Ident:
		return "(" + t.Name + ")." + fd.Name.Name
	}
	return fd.Name.Name
}

// scanConfigCalls finds every reference to the tracked loaders in files.
// References are counted whether or not they are called: `load := config.Load`
// followed by `load(dir)` is the same read.
func scanConfigCalls(fset *token.FileSet, files []*ast.File) configCallScan {
	scan := configCallScan{
		calls: map[string]map[string]int{},
		where: map[string]map[string]string{},
	}
	tracked := map[string]bool{"Load": true, "Save": true, "LoadUIInstance": true}
	record := func(loader, fn string, pos token.Pos) {
		if scan.calls[loader] == nil {
			scan.calls[loader] = map[string]int{}
			scan.where[loader] = map[string]string{}
		}
		scan.calls[loader][fn]++
		if _, ok := scan.where[loader][fn]; !ok {
			p := fset.Position(pos)
			scan.where[loader][fn] = fmt.Sprintf("%s:%d", filepath.Base(p.Filename), p.Line)
		}
	}

	for _, file := range files {
		names := map[string]bool{}
		for _, imp := range file.Imports {
			path, err := strconv.Unquote(imp.Path.Value)
			if err != nil || path != configImportPath {
				continue
			}
			switch {
			case imp.Name == nil:
				names["config"] = true
			case imp.Name.Name == ".":
				p := fset.Position(imp.Pos())
				scan.problems = append(scan.problems, fmt.Sprintf(
					"%s:%d dot-imports pkg/config, so its loaders cannot be told apart from local "+
						"functions; import it by name", filepath.Base(p.Filename), p.Line))
			case imp.Name.Name != "_":
				names[imp.Name.Name] = true
			}
		}
		if len(names) == 0 {
			continue
		}
		isTracked := func(n ast.Node) (string, token.Pos, bool) {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return "", 0, false
			}
			id, ok := sel.X.(*ast.Ident)
			if !ok || !names[id.Name] || !tracked[sel.Sel.Name] {
				return "", 0, false
			}
			return sel.Sel.Name, sel.Pos(), true
		}
		for _, decl := range file.Decls {
			if fd, ok := decl.(*ast.FuncDecl); ok {
				fn := configCallFuncName(fd)
				// Function literals inside fd belong to fd: a closure is where
				// the AutoInstallHarness read lived, and it is still that
				// function's read.
				ast.Inspect(fd, func(n ast.Node) bool {
					if loader, pos, ok := isTracked(n); ok {
						record(loader, fn, pos)
					}
					return true
				})
				continue
			}
			ast.Inspect(decl, func(n ast.Node) bool {
				if loader, pos, ok := isTracked(n); ok {
					p := fset.Position(pos)
					scan.problems = append(scan.problems, fmt.Sprintf(
						"%s:%d references config.%s at package scope, where no function can be "+
							"held to account for which file it reads", filepath.Base(p.Filename), p.Line, loader))
				}
				return true
			})
		}
	}
	return scan
}

// checkConfigCallSites compares what scanConfigCalls found for one loader with
// its allowlist, and returns one message per disagreement.
func checkConfigCallSites(loader string, found map[string]int, where map[string]string, allowed []configCallSite, remedy string) []string {
	var out []string
	want := map[string]int{}
	for _, site := range allowed {
		want[site.fn] = site.calls
	}
	fns := make([]string, 0, len(found))
	for fn := range found {
		fns = append(fns, fn)
	}
	sort.Strings(fns)
	for _, fn := range fns {
		got := found[fn]
		allowedCalls, listed := want[fn]
		switch {
		case !listed:
			out = append(out, fmt.Sprintf("%s: config.%s in %s is not on the allowlist. %s",
				where[fn], loader, fn, remedy))
		case got > allowedCalls:
			out = append(out, fmt.Sprintf("%s: %s now makes %d config.%s calls, but %d are allowlisted. "+
				"The new one is not classified. %s", where[fn], fn, got, loader, allowedCalls, remedy))
		case got < allowedCalls:
			out = append(out, fmt.Sprintf("%s: %s makes %d config.%s calls, but %d are allowlisted. "+
				"Lower the count so the list says what the code does", where[fn], fn, got, loader, allowedCalls))
		}
	}
	for _, site := range allowed {
		if _, ok := found[site.fn]; !ok {
			out = append(out, fmt.Sprintf("allowlist entry %s (config.%s) matches no call any more. "+
				"Remove it, so a later call cannot inherit its classification", site.fn, loader))
		}
	}
	return out
}

const (
	hubScopeLoadRemedy = "If the setting is hub-scope (executors.*, sandbox.image_policy, ui.*, stt, " +
		"retention, audit, backup, github.token), read it with s.loadHubConfig() or controlPlaneConfig(), " +
		"or s.governingConfig(dir) when a project may state it too. A config.Load of the hub's " +
		"directory skips this hub's .cloop/config.ui-<port>.yaml. If it is project-scope, add the " +
		"function to configLoadSites with the reason"
	hubScopeSaveRemedy = "Hub settings are written through beginHubSettingsSave and commit, which " +
		"choose the overlay or config.yaml before loading anything. A config.Save of a merged view " +
		"copies this hub's overlay into the config.yaml other dashboards read. If this writes a " +
		"project's config.yaml, loaded from that same file, add it to configSaveSites with the reason"
	overlayLoadRemedy = "Call loadHubConfigAt (or s.loadHubConfig / controlPlaneConfig) instead, " +
		"so the package has one definition of the hub's configuration"
)

// TestHubScopeConfigReadsHonourTheOverlay is the gate described at the top of
// this file.
func TestHubScopeConfigReadsHonourTheOverlay(t *testing.T) {
	// From this file's own path, not the working directory: tests in this
	// package t.Chdir, and a cwd-relative glob that found nothing would pass.
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller could not locate this test file")
	}
	paths, err := filepath.Glob(filepath.Join(filepath.Dir(thisFile), "*.go"))
	if err != nil {
		t.Fatalf("glob package sources: %v", err)
	}
	fset := token.NewFileSet()
	var files []*ast.File
	for _, path := range paths {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		files = append(files, f)
	}
	if len(files) < 10 {
		t.Fatalf("found only %d source files: the gate would pass vacuously", len(files))
	}

	scan := scanConfigCalls(fset, files)
	for _, p := range scan.problems {
		t.Error(p)
	}
	// The scan must have seen the accessor, or it is not looking where the
	// code is, and an empty result would read as a clean one.
	if scan.calls["LoadUIInstance"]["loadHubConfigAt"] == 0 {
		t.Fatal("the scan did not find loadHubConfigAt's call to config.LoadUIInstance")
	}
	for _, msg := range checkConfigCallSites("Load", scan.calls["Load"], scan.where["Load"],
		configLoadSites, hubScopeLoadRemedy) {
		t.Error(msg)
	}
	for _, msg := range checkConfigCallSites("Save", scan.calls["Save"], scan.where["Save"],
		configSaveSites, hubScopeSaveRemedy) {
		t.Error(msg)
	}
	for _, msg := range checkConfigCallSites("LoadUIInstance", scan.calls["LoadUIInstance"],
		scan.where["LoadUIInstance"], configOverlaySites, overlayLoadRemedy) {
		t.Error(msg)
	}
}

// TestHubConfigGateDetectsViolations proves the gate fires. Without it, a
// refactor that broke the scan (the wrong node type, a missed alias) would
// leave the gate above passing on an empty result.
func TestHubConfigGateDetectsViolations(t *testing.T) {
	const offending = `package ui

import (
	cfgpkg "github.com/blechschmidt/cloop/pkg/config"
)

var eager = cfgpkg.Load

func (s *Server) newHubThing() bool {
	go func() {
		cfg, _ := cfgpkg.Load(s.WorkDir)
		_ = cfg.Executors.HostProcessAllowed()
	}()
	cfg, _ := cfgpkg.Load(s.WorkDir)
	_ = cfgpkg.Save(s.WorkDir, cfg)
	return true
}

func resolveProviderName(workDir string) string {
	cfg, _ := cfgpkg.Load(workDir)
	_, _ = cfgpkg.Load(workDir)
	return cfg.Provider
}
`
	const dotImport = `package ui

import . "github.com/blechschmidt/cloop/pkg/config"

func sneaky(dir string) { _, _ = Load(dir) }
`
	fset := token.NewFileSet()
	var files []*ast.File
	for name, src := range map[string]string{"offending.go": offending, "dot.go": dotImport} {
		f, err := parser.ParseFile(fset, name, src, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse fixture %s: %v", name, err)
		}
		files = append(files, f)
	}
	scan := scanConfigCalls(fset, files)

	if got := scan.calls["Load"]["(*Server).newHubThing"]; got != 2 {
		t.Errorf("the aliased reads in newHubThing, one inside a closure, counted %d, want 2", got)
	}
	if got := scan.calls["Save"]["(*Server).newHubThing"]; got != 1 {
		t.Errorf("the aliased save counted %d, want 1", got)
	}
	var sawPackageScope, sawDotImport bool
	for _, p := range scan.problems {
		sawPackageScope = sawPackageScope || strings.Contains(p, "package scope")
		sawDotImport = sawDotImport || strings.Contains(p, "dot-imports")
	}
	if !sawPackageScope || !sawDotImport {
		t.Errorf("problems = %q: want the package-scope reference and the dot import reported", scan.problems)
	}

	allowed := []configCallSite{
		{"resolveProviderName", 1, "fixture"},
		{"someFunctionThatIsGone", 1, "fixture"},
	}
	msgs := checkConfigCallSites("Load", scan.calls["Load"], scan.where["Load"], allowed, "remedy")
	joined := strings.Join(msgs, "\n")
	for _, want := range []string{
		"config.Load in (*Server).newHubThing is not on the allowlist", // a new, unclassified read
		"resolveProviderName now makes 2 config.Load calls",            // a second read in a listed function
		"someFunctionThatIsGone (config.Load) matches no call",         // a stale entry
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("the gate did not report %q; it said:\n%s", want, joined)
		}
	}
}
