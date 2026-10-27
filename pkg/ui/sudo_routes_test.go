package ui

// The route table's half of sudo mode (Task 20448): which routes ask a session
// for a recent interactive sign-in, and why the ones that do not, do not.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/authz"
)

// sudoExempt names every write whose permission authz.RequiresRecentSignIn
// covers that nevertheless takes any live session, with the reason. Each one is
// a decision; a route added under such a permission without declaring Sudo and
// without a line here fails TestPrivilegedRoutesAskForARecentSignIn.
var sudoExempt = map[string]string{
	// secret.own, held from operator up for the personal half of the secret
	// store. A Claude login is custody of the caller's own Anthropic account,
	// written to the caller's own home: the worst a stolen cookie does with it
	// is bind the victim's runs to an account the thief pays for, or end a
	// login its owner signs back in to, and every operator does it once.
	"POST /api/claudecode/auth/login":        "custody of the caller's own Claude login, in their own home",
	"POST /api/claudecode/auth/login/code":   "the second step of the caller's own Claude login",
	"POST /api/claudecode/auth/login/cancel": "abandons the caller's own Claude login in progress",
	"POST /api/claudecode/auth/logout":       "ends the caller's own Claude login",

	// Containment: actions that take access away. Asking the identity provider
	// first would slow down the person pulling a leaked credential at the
	// moment it matters, and each is undone by the action that does ask.
	"DELETE /api/projects/{idx}/members":    "withdraws a membership; granting one at maintainer asks",
	"POST /api/executors/{id}/cordon":       "stops new work landing on an executor; uncordoning asks",
	"POST /api/executors/{id}/drain":        "moves work off an executor and revokes its leases; uncordoning asks",
	"POST /api/leases/{id}/revoke":          "pulls a lease back before it lapses; granting asks",
	"DELETE /api/ci/sessions/{id}":          "ends a pipeline's relay session; the rules that admit one ask",
	"DELETE /api/forwarders/bindings/{bid}": "withdraws a device from a project's runs; binding one asks",
	"POST /api/grant-requests/{id}/deny":    "refuses an access request; approving one asks",

	// The terminal's own read: the task details modal asks it whenever it
	// opens, and it says whether opening the terminal would ask, so the
	// Attach button asks before a handshake whose refusal a page cannot see.
	"GET /api/tasks/{id}/attach/info": "a read the details modal makes on open; it reports whether the socket would ask",

	// Writes that store nothing.
	"POST /api/executors/{id}/isolation-probe": "re-runs the isolation probe; its verdict only narrows where work may go",
	"POST /api/github-app/installations":       "lists what an App key reaches and stores nothing; saving the App is POST /api/secrets, which asks",
	"POST /api/ci/rules/test":                  "evaluates a rule against a sample token and stores nothing",
	"POST /api/config/oidc/test":               "contacts an issuer and saves nothing",
	"POST /api/config/notifications/test":      "sends one fixed message to an already configured webhook",
}

// TestPrivilegedRoutesAskForARecentSignIn is the gate the task asks for: every
// route whose permission authz.RequiresRecentSignIn covers either asks a
// session for a recent interactive sign-in, or is exempted above by name with a
// reason. Reads never ask — opening Settings must not send anybody to their
// identity provider — except the one read that is an action: sandbox.attach,
// which opens a terminal over a GET.
func TestPrivilegedRoutesAskForARecentSignIn(t *testing.T) {
	used := map[string]bool{}
	for _, rs := range (&Server{}).routeTable() {
		_, path, ok := splitPattern(rs.Pattern)
		if !ok {
			path = rs.Pattern
		}
		for _, m := range rs.methods() {
			p := rs.permFor(m)
			if !authz.RequiresRecentSignIn(p) {
				continue
			}
			if safeMethod(m) && p != authz.PermSandboxAttach {
				continue
			}
			key := m + " " + path
			if rs.sudoFor(m) != sudoNone {
				if _, exempt := sudoExempt[key]; exempt {
					t.Errorf("%s asks for a recent sign-in and is also exempted: drop the exemption", key)
				}
				continue
			}
			reason, exempt := sudoExempt[key]
			if !exempt {
				t.Errorf("%s carries %s, which asks for a recent sign-in (sudo mode), but declares no Sudo: "+
					"add Sudo to its routeSpec, or an entry to sudoExempt saying why it may take any live session", key, p)
				continue
			}
			if strings.TrimSpace(reason) == "" {
				t.Errorf("%s is exempted with no reason", key)
			}
			used[key] = true
		}
	}
	var stale []string
	for key := range sudoExempt {
		if !used[key] {
			stale = append(stale, key)
		}
	}
	sort.Strings(stale)
	for _, key := range stale {
		t.Errorf("sudoExempt names %s, which is no route the rule covers: remove the entry", key)
	}
}

// TestSudoCoversTheNamedActions pins the actions Task 20448 named, so none of
// them can drift onto the exempt list or lose its declaration in a refactor.
// Changing the sealing root or the KMS has no route: it is `cloop hub key` on
// the hub's host, which acts with the operating system's authority, not a
// session's.
func TestSudoCoversTheNamedActions(t *testing.T) {
	named := []string{
		"POST /api/secrets", "DELETE /api/secrets/{id}",
		"POST /api/grants", "DELETE /api/grants/{id}",
		"POST /api/grant-requests/{id}/approve",
		"POST /api/tokens/{id}/approve", "POST /api/tokens",
		"PUT /api/config/oidc", "POST /api/config/oidc/enforce",
		"POST /api/static-token/retire",
		"POST /api/hub/ca/rotate",
		"POST /api/executors/enroll", "POST /api/executors/{id}/upgrade", "DELETE /api/executors/{id}",
		"GET /api/tasks/{id}/attach",
		"POST /api/projects/{idx}/members", "PATCH /api/projects/{idx}/members",
		"DELETE /api/sessions/{id}",
		"POST /api/users/offboard",
		"POST /api/scim/credentials",
		// Found in review: the relay's upstream URL is where the hub's
		// Anthropic key goes, a glasses link is a thirty-day token, a
		// provider key or base URL is a credential.
		"PUT /api/ci/config", "POST /api/glasses/link", "POST /api/config/set",
		"PUT /api/config/stt", "DELETE /api/config/stt",
	}
	got := map[string]sudoRule{}
	for _, rs := range (&Server{}).routeTable() {
		_, path, ok := splitPattern(rs.Pattern)
		if !ok {
			path = rs.Pattern
		}
		for _, m := range rs.methods() {
			got[m+" "+path] = rs.sudoFor(m)
		}
	}
	for _, key := range named {
		rule, ok := got[key]
		switch {
		case !ok:
			t.Errorf("%s is not in the route table", key)
		case rule == sudoNone:
			t.Errorf("%s must ask for a recent sign-in", key)
		}
	}
}

// TestSudoHandlerRoutesAskInTheirHandler holds a route that leaves the decision
// to its handler (sudoHandler) to it: the handler's body must call
// requireSudo. Without this a sudoHandler declaration would satisfy the
// route-table gate and enforce nothing.
func TestSudoHandlerRoutesAskInTheirHandler(t *testing.T) {
	want := map[string]bool{}
	for _, rs := range (&Server{}).routeTable() {
		if rs.Sudo != sudoHandler {
			continue
		}
		name := runtime.FuncForPC(reflect.ValueOf(rs.Handler).Pointer()).Name()
		name = strings.TrimSuffix(name[strings.LastIndex(name, ".")+1:], "-fm")
		want[name] = false
	}
	if len(want) == 0 {
		t.Fatal("no route declares sudoHandler; the conditional cases (member grants, other people's sessions) lost theirs")
	}
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
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
		for _, d := range file.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok || fn.Recv == nil || fn.Body == nil {
				continue
			}
			if _, tracked := want[fn.Name.Name]; !tracked {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				if call, ok := n.(*ast.CallExpr); ok {
					if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "requireSudo" {
						want[fn.Name.Name] = true
					}
				}
				return true
			})
		}
	}
	for name, asks := range want {
		if !asks {
			t.Errorf("%s serves a sudoHandler route but never calls requireSudo", name)
		}
	}
}

// TestSudoRuleValidation: a declaration that could not be enforced as written
// is refused at registration, like a missing permission.
func TestSudoRuleValidation(t *testing.T) {
	h := func(w http.ResponseWriter, r *http.Request) {}
	cases := []struct {
		name string
		rs   routeSpec
		ok   bool
	}{
		{"writes on a write", routeSpec{Pattern: "POST /x", Handler: h, Perm: authz.PermUserManage, Sudo: sudoWrites}, true},
		{"writes on a read-only route", routeSpec{Pattern: "GET /x", Handler: h, Perm: authz.PermUserManage, Sudo: sudoWrites}, false},
		{"all on a read", routeSpec{Pattern: "GET /x", Handler: h, Perm: authz.PermSandboxAttach, Sudo: sudoAll}, true},
		{"on a public route", routeSpec{Pattern: "POST /x", Handler: h, Perm: authz.PermPublic, Sudo: sudoWrites}, false},
		{"writes on a mixed route", routeSpec{Pattern: "/x", Handler: h, Methods: []string{"GET", "PUT"},
			Perm: authz.PermExecutorManage, Sudo: sudoWrites}, true},
	}
	for _, c := range cases {
		err := c.rs.validate()
		if (err == nil) != c.ok {
			t.Errorf("%s: validate() = %v, want ok=%v", c.name, err, c.ok)
		}
	}
	mixed := routeSpec{Pattern: "/x", Methods: []string{"GET", "PUT"}, Sudo: sudoWrites}
	if mixed.sudoFor("GET") != sudoNone || mixed.sudoFor("PUT") != sudoWrites {
		t.Error("sudoWrites must leave the route's reads open and ask on its writes")
	}
}
