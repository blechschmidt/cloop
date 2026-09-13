package security

// Guarantee: every `claude` CLI invocation scopes its environment, so a hub
// with per-user logins cannot silently fall back to the host's account
// (Task 20241).
//
// Per-user Claude logins rest on one CLI behaviour: CLAUDE_CONFIG_DIR selects
// which account the binary authenticates as. It has a sharp edge. An ambient
// CLAUDE_CODE_OAUTH_TOKEN *outranks* the directory — measured against the real
// CLI, an empty config dir plus an ambient token answers
//
//	{"loggedIn": true, "authMethod": "oauth_token"}
//
// and prompts execute on that token's account. cloop populates exactly such a
// token from ~/.openclaw/workspace/.env. So a spawn site that sets
// CLAUDE_CONFIG_DIR but forgets to clear the ambient variables — or that
// simply inherits os.Environ() — produces isolation that looks correct on the
// dashboard and pools every tenant onto one subscription in reality.
//
// That failure is invisible at runtime: no error, no warning, and a status
// panel that cheerfully reports the wrong account as "signed in". A feature
// test would not catch it, because every feature still works. The only durable
// defence is structural, which is what this file asserts: no invocation of the
// claude binary anywhere in the tree may build its environment by hand.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/claudecodeauth"
)

// claudeSpawnPackages are the packages allowed to exec the claude binary.
// Both resolve the path through findClaude().
var claudeSpawnPackages = []string{
	"pkg/claudecodeauth",
	"pkg/provider/claudecode",
}

// scopingHelpers are the only acceptable right-hand sides for a claude
// subprocess's Env. Each clears the ambient credential variables before
// pinning CLAUDE_CONFIG_DIR.
var scopingHelpers = []string{"cliEnv", "ScopeEnv"}

// TestEveryClaudeSpawnScopesItsEnvironment walks every function that execs the
// claude binary and requires it to assign cmd.Env from a scoping helper.
func TestEveryClaudeSpawnScopesItsEnvironment(t *testing.T) {
	root, err := moduleRoot()
	if err != nil {
		t.Fatalf("locate module root: %v", err)
	}

	checked := map[string]bool{}
	for _, pkgDir := range claudeSpawnPackages {
		dir := filepath.Join(root, pkgDir)
		fset := token.NewFileSet()
		pkgs, err := parser.ParseDir(fset, dir, func(fi fs.FileInfo) bool {
			return !strings.HasSuffix(fi.Name(), "_test.go")
		}, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", dir, err)
		}
		for _, pkg := range pkgs {
			for _, file := range pkg.Files {
				ast.Inspect(file, func(n ast.Node) bool {
					fn, ok := n.(*ast.FuncDecl)
					if !ok || fn.Body == nil {
						return true
					}
					if !spawnsClaude(fn) {
						return true
					}
					checked[fn.Name.Name] = true
					if !scopesEnv(fn) {
						t.Errorf("%s: %s execs the claude binary but does not set Env from one of %v.\n"+
							"An inherited CLAUDE_CODE_OAUTH_TOKEN outranks CLAUDE_CONFIG_DIR, so this "+
							"invocation would authenticate as the host account no matter which user it "+
							"is running for.",
							fset.Position(fn.Pos()), fn.Name.Name, scopingHelpers)
					}
					return true
				})
			}
		}
	}

	// Name the sites that must be covered. A bare count>0 check is not enough:
	// it passed while the scan was missing runCLI entirely, because the other
	// three sites still matched. If one of these is renamed, this fails and
	// whoever renamed it updates the list deliberately.
	for _, required := range []string{
		"runCLI",      // executes every task — the site that actually matters
		"FetchStatus", // decides whether the dashboard says "signed in"
		"Logout",
		"Start", // spawns `claude auth login`
	} {
		if !checked[required] {
			t.Errorf("%s is no longer recognised as a claude spawn site; the scan has gone "+
				"stale and is not protecting it", required)
		}
	}
}

// spawnsClaude reports whether fn both resolves the claude binary and execs
// something.
//
// It deliberately does NOT try to prove the resolved path flows into the exec
// call. An earlier version did, by matching findClaude() among the call's
// arguments, and it silently skipped the single most important site in the
// tree: runCLI assigns `claudeBin := findClaude()` and passes the variable, so
// the pattern never matched and the check passed while testing nothing. A
// coarser predicate that cannot be evaded by an ordinary refactor is worth far
// more here than a precise one that can.
func spawnsClaude(fn *ast.FuncDecl) bool {
	resolves, execs := false, false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if ident, ok := call.Fun.(*ast.Ident); ok && ident.Name == "findClaude" {
			resolves = true
		}
		if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
			if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "exec" &&
				(sel.Sel.Name == "Command" || sel.Sel.Name == "CommandContext") {
				execs = true
			}
		}
		return true
	})
	return resolves && execs
}

// scopesEnv reports whether fn assigns an .Env field from a scoping helper.
func scopesEnv(fn *ast.FuncDecl) bool {
	scoped := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok {
			return true
		}
		targetsEnv := false
		for _, lhs := range assign.Lhs {
			if sel, ok := lhs.(*ast.SelectorExpr); ok && sel.Sel.Name == "Env" {
				targetsEnv = true
			}
		}
		if !targetsEnv {
			return true
		}
		for _, rhs := range assign.Rhs {
			for _, helper := range scopingHelpers {
				if callsIdent(rhs, helper) {
					scoped = true
				}
			}
		}
		return true
	})
	return scoped
}

// callsIdent reports whether expr contains a call whose function name is name,
// whether referenced bare or through a package selector.
func callsIdent(expr ast.Expr, name string) bool {
	found := false
	ast.Inspect(expr, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		switch fun := call.Fun.(type) {
		case *ast.Ident:
			if fun.Name == name {
				found = true
			}
		case *ast.SelectorExpr:
			if fun.Sel.Name == name {
				found = true
			}
		}
		return true
	})
	return found
}

// TestAmbientTokenVarsCoverTheCLIsCredentialInputs pins the list that ScopeEnv
// clears. Dropping an entry silently reopens the fallback: the CLI would find
// a credential outside the per-user directory and use it.
func TestAmbientTokenVarsCoverTheCLIsCredentialInputs(t *testing.T) {
	required := []string{
		// Populated by cloop itself from ~/.openclaw/workspace/.env and
		// ~/.env, which is what makes this concrete rather than theoretical.
		"CLAUDE_CODE_OAUTH_TOKEN",
		// Both are honoured by the CLI for direct API authentication.
		"ANTHROPIC_API_KEY",
		"ANTHROPIC_AUTH_TOKEN",
	}
	for _, want := range required {
		if !contains(claudecodeauth.AmbientTokenVars, want) {
			t.Errorf("%s is not in AmbientTokenVars: the claude CLI would accept it "+
				"in preference to the per-user CLAUDE_CONFIG_DIR, pooling every tenant "+
				"onto whichever account it names", want)
		}
	}

	// The harness list is deliberately narrower — it must not confiscate
	// another provider's key — but it has to keep the Claude one.
	if !contains(claudecodeauth.ClaudeOnlyTokenVars, "CLAUDE_CODE_OAUTH_TOKEN") {
		t.Error("ClaudeOnlyTokenVars must clear CLAUDE_CODE_OAUTH_TOKEN for dispatched runs")
	}
	for _, other := range []string{"ANTHROPIC_API_KEY", "OPENAI_API_KEY"} {
		if contains(claudecodeauth.ClaudeOnlyTokenVars, other) {
			t.Errorf("ClaudeOnlyTokenVars clears %s, which belongs to another provider: "+
				"a dispatched run using that provider would fail with a missing key", other)
		}
	}
}

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}
