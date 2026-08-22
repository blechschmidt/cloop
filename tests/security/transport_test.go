package security

// Guarantee 7: the hub<->agent channel is authenticated in both directions.
//
// Every other guarantee in this suite assumes the two ends of that channel are
// who they say they are. Enrollment tokens, credential hashing, lease TTLs,
// RBAC — all of it is reasoning about a conversation whose participants were
// established by TLS. If an agent will complete a handshake with any server
// that answers DNS, the token it presents is not proof of anything: the
// attacker now holds it, and because an agent retries forever and never
// re-enrolls, holds it indefinitely.
//
// Two properties are machine-checked here.
//
//	(1) No outbound agent dial disables certificate verification. This is a
//	    static, type-aware check over the whole module rather than a test of
//	    one code path, because InsecureSkipVerify is a single field that any
//	    future refactor could set in a helper three packages away — and the
//	    resulting deployment would work perfectly, right up until someone
//	    intercepted it. Pinning does not save us here: a pin is checked in
//	    VerifyPeerCertificate, and with InsecureSkipVerify set that callback
//	    becomes the *only* check, so an unpinned agent (the default) would
//	    have no transport authenticity at all.
//
//	(2) The hub refuses a cross-origin WebSocket upgrade. Agents send no
//	    Origin header, so this costs them nothing; a browser cannot suppress
//	    one, so it is the only signal that separates "an edge device" from
//	    "script on a page an operator was tricked into loading".

import (
	"bytes"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/printer"
	"go/types"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"golang.org/x/tools/go/packages"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
)

// ---------------------------------------------------------------------------
// (1) No outbound dial disables certificate verification
// ---------------------------------------------------------------------------

// tlsSkipVerifySite is one place the module sets crypto/tls.Config's
// InsecureSkipVerify field.
type tlsSkipVerifySite struct {
	pkg   string
	pos   string
	value string // the expression assigned, for the failure message
}

func (s tlsSkipVerifySite) String() string {
	return fmt.Sprintf("%s\n      package: %s\n      value:   %s", s.pos, s.pkg, s.value)
}

// declaredSkipVerify enumerates the places in this module that legitimately set
// tls.Config.InsecureSkipVerify, with the reason each is defensible.
//
// It is an inventory, not a suppression list. None of these are reachable from
// the executor agent's dial — TestNoInsecureSkipVerifyOnAgentDial proves that
// separately and admits no exemptions at all. This map exists so that adding a
// *new* one anywhere in the module is a deliberate act with a written
// justification, rather than a line in a diff nobody questions.
//
// Keys are "<package path>:<file base>".
var declaredSkipVerify = map[string]string{
	ModulePath + "/pkg/executor/kubernetes:kubeconfig.go": "honours insecure-skip-tls-verify from " +
		"the operator's own kubeconfig, which is their declared decision about their own API " +
		"server — not cloop's about its control plane. Surfaced in RESTConfig.Describe() as " +
		"`tls=INSECURE` so it cannot be set without appearing in the executor listing.",
}

// TestNoInsecureSkipVerifyOnAgentDial fails if any package in the executor
// agent's transitive import closure sets tls.Config.InsecureSkipVerify to
// anything but a literal false. There are no exemptions here by design.
//
// Scoping to the closure — rather than to pkg/executor/agent alone, or to the
// whole module — is what makes this both sound and precise. Sound, because the
// dangerous refactor is not "someone edits transport.go"; it is "someone adds a
// helper two packages down that builds a lax tls.Config", and a per-package
// check would never see it. Precise, because the guarantee under test is about
// the agent's outbound link specifically, and a module-wide ban would sweep in
// unrelated clients whose TLS posture is somebody else's call to make (see
// declaredSkipVerify).
//
// The check is type-aware rather than textual. Grepping for the identifier
// matches websocket.AcceptOptions.InsecureSkipVerify — a different type with
// different meaning, which cloop sets deliberately on the *server* side because
// the library's Origin matcher cannot express "absent Origin is fine, and this
// proxy's hostname is fine" (Hub.checkOrigin and Server.wsOriginAllowed are the
// replacement; TestHubRejectsCrossOriginUpgrade proves the hub's one runs).
// Matching on the type means that case needs no exemption, and exemption lists
// are exactly how a real violation eventually gets waved through.
func TestNoInsecureSkipVerifyOnAgentDial(t *testing.T) {
	pkgs := loadModulePackages(t)

	tlsConfigType := findTLSConfigType(t, pkgs)
	closure := agentImportClosure(t, pkgs)
	var sites []tlsSkipVerifySite

	for _, p := range pkgs {
		if !strings.HasPrefix(p.PkgPath, ModulePath) {
			continue // dependency; we audit our own code
		}
		if !closure[p.PkgPath] {
			continue // not on the agent's dial path; see the module-wide test
		}
		for _, file := range p.Syntax {
			ast.Inspect(file, func(n ast.Node) bool {
				switch node := n.(type) {
				case *ast.CompositeLit:
					// tls.Config{..., InsecureSkipVerify: X, ...}
					if !isTLSConfigType(p.TypesInfo.TypeOf(node), tlsConfigType) {
						return true
					}
					for _, elt := range node.Elts {
						kv, ok := elt.(*ast.KeyValueExpr)
						if !ok {
							continue
						}
						key, ok := kv.Key.(*ast.Ident)
						if !ok || key.Name != "InsecureSkipVerify" {
							continue
						}
						if isFalseLiteral(kv.Value) {
							continue
						}
						sites = append(sites, tlsSkipVerifySite{
							pkg:   p.PkgPath,
							pos:   p.Fset.Position(kv.Pos()).String(),
							value: exprString(p, kv.Value),
						})
					}
				case *ast.AssignStmt:
					// cfg.InsecureSkipVerify = X
					for i, lhs := range node.Lhs {
						sel, ok := lhs.(*ast.SelectorExpr)
						if !ok || sel.Sel.Name != "InsecureSkipVerify" {
							continue
						}
						if !isTLSConfigType(deref(p.TypesInfo.TypeOf(sel.X)), tlsConfigType) {
							continue
						}
						var rhs ast.Expr
						if i < len(node.Rhs) {
							rhs = node.Rhs[i]
						}
						if rhs != nil && isFalseLiteral(rhs) {
							continue
						}
						sites = append(sites, tlsSkipVerifySite{
							pkg:   p.PkgPath,
							pos:   p.Fset.Position(sel.Pos()).String(),
							value: exprString(p, rhs),
						})
					}
				}
				return true
			})
		}
	}

	if len(sites) > 0 {
		msgs := make([]string, 0, len(sites))
		for _, s := range sites {
			msgs = append(msgs, "  - "+s.String())
		}
		sort.Strings(msgs)
		t.Fatalf("tls.Config.InsecureSkipVerify is enabled in %d place(s) reachable from the "+
			"executor agent:\n%s\n\n"+
			"An outbound dial that skips verification trusts whatever answers DNS. For the\n"+
			"executor agent that is fatal: it retries forever with a long-lived credential,\n"+
			"so one interception is permanent. Certificate pinning does NOT compensate —\n"+
			"VerifyPeerCertificate becomes the only check, and agents without a pin (the\n"+
			"default) get no authenticity at all.\n\n"+
			"To reach a server whose certificate the system store does not know, add it as a\n"+
			"root instead: tlsconf.ClientOptions.RootCAFile, exposed as\n"+
			"`cloop executor agent --ca-file`.",
			len(sites), strings.Join(msgs, "\n"))
	}
}

// TestInsecureSkipVerifyElsewhereIsDeclared inventories every remaining
// tls.Config.InsecureSkipVerify in the module and requires each to appear in
// declaredSkipVerify.
//
// The agent's link is the one this task set out to secure, but it is not the
// only TLS client cloop has, and a check that stopped at the agent's closure
// would let the next lax client in silently. This does not judge whether a site
// is acceptable — it forces someone to write down why, at the moment they add
// it, which is the only time the reasoning is actually available.
func TestInsecureSkipVerifyElsewhereIsDeclared(t *testing.T) {
	pkgs := loadModulePackages(t)
	tlsConfigType := findTLSConfigType(t, pkgs)
	closure := agentImportClosure(t, pkgs)

	seen := map[string]bool{}
	var undeclared []string
	for _, p := range pkgs {
		if !strings.HasPrefix(p.PkgPath, ModulePath) || closure[p.PkgPath] {
			continue
		}
		for _, site := range skipVerifySites(p, tlsConfigType) {
			key := p.PkgPath + ":" + filepath.Base(strings.SplitN(site.pos, ":", 2)[0])
			seen[key] = true
			if _, ok := declaredSkipVerify[key]; !ok {
				undeclared = append(undeclared, "  - "+key+"\n      at "+site.pos+
					"\n      value: "+site.value)
			}
		}
	}
	if len(undeclared) > 0 {
		sort.Strings(undeclared)
		t.Errorf("undeclared tls.Config.InsecureSkipVerify site(s):\n%s\n\n"+
			"Disabling certificate verification makes the connection interceptable by anything\n"+
			"on the path. If it is genuinely the right call, add an entry to\n"+
			"declaredSkipVerify in this file explaining why — and check first whether\n"+
			"tlsconf.ClientOptions.RootCAFile (trust a specific CA) or a pin solves the real\n"+
			"problem instead.", strings.Join(undeclared, "\n"))
	}

	// A declaration for a site that no longer exists is stale. Left alone,
	// these accumulate until the list reads as "we allow this everywhere".
	for key := range declaredSkipVerify {
		if !seen[key] {
			t.Errorf("declaredSkipVerify has a stale entry %q — "+
				"the code no longer sets InsecureSkipVerify there; remove it", key)
		}
	}
}

// skipVerifySites returns every place p sets tls.Config.InsecureSkipVerify to
// something other than a literal false.
func skipVerifySites(p *packages.Package, tlsConfigType types.Type) []tlsSkipVerifySite {
	var sites []tlsSkipVerifySite
	for _, file := range p.Syntax {
		ast.Inspect(file, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.CompositeLit:
				if !isTLSConfigType(p.TypesInfo.TypeOf(node), tlsConfigType) {
					return true
				}
				for _, elt := range node.Elts {
					kv, ok := elt.(*ast.KeyValueExpr)
					if !ok {
						continue
					}
					key, ok := kv.Key.(*ast.Ident)
					if !ok || key.Name != "InsecureSkipVerify" || isFalseLiteral(kv.Value) {
						continue
					}
					sites = append(sites, tlsSkipVerifySite{
						pkg:   p.PkgPath,
						pos:   p.Fset.Position(kv.Pos()).String(),
						value: exprString(p, kv.Value),
					})
				}
			case *ast.AssignStmt:
				for i, lhs := range node.Lhs {
					sel, ok := lhs.(*ast.SelectorExpr)
					if !ok || sel.Sel.Name != "InsecureSkipVerify" {
						continue
					}
					if !isTLSConfigType(deref(p.TypesInfo.TypeOf(sel.X)), tlsConfigType) {
						continue
					}
					var rhs ast.Expr
					if i < len(node.Rhs) {
						rhs = node.Rhs[i]
					}
					if rhs != nil && isFalseLiteral(rhs) {
						continue
					}
					sites = append(sites, tlsSkipVerifySite{
						pkg:   p.PkgPath,
						pos:   p.Fset.Position(sel.Pos()).String(),
						value: exprString(p, rhs),
					})
				}
			}
			return true
		})
	}
	return sites
}

// agentImportClosure returns every cloop package the executor agent depends on,
// transitively — the exact set of code that can influence its outbound dial.
func agentImportClosure(t *testing.T, pkgs []*packages.Package) map[string]bool {
	t.Helper()
	byPath := make(map[string]*packages.Package, len(pkgs))
	for _, p := range pkgs {
		byPath[p.PkgPath] = p
	}
	root := byPath[ModulePath+"/pkg/executor/agent"]
	if root == nil {
		t.Fatal("pkg/executor/agent did not load — the guard would silently pass")
	}

	closure := map[string]bool{}
	var walk func(p *packages.Package)
	walk = func(p *packages.Package) {
		if p == nil || closure[p.PkgPath] || !strings.HasPrefix(p.PkgPath, ModulePath) {
			return
		}
		closure[p.PkgPath] = true
		for _, imp := range p.Imports {
			walk(byPath[imp.PkgPath])
		}
	}
	walk(root)

	// Sanity: the closure must contain the packages that actually build the
	// dial, or a load failure would silently shrink the audited surface to
	// nothing and this test would pass by examining no code.
	for _, must := range []string{
		ModulePath + "/pkg/executor/agent",
		ModulePath + "/pkg/tlsconf",
		ModulePath + "/pkg/executor/remote",
	} {
		if !closure[must] {
			t.Fatalf("%s is missing from the agent import closure — the guard would silently pass", must)
		}
	}
	return closure
}

// TestAgentDialUsesPinnedTLSConfig is the positive half: the check above only
// proves nothing disables verification, which a build that never configures
// TLS at all would also satisfy. This asserts the agent's transport really is
// constructed through pkg/tlsconf, so the TLS floor and the pin hook are
// actually on the path a device dials with.
func TestAgentDialUsesPinnedTLSConfig(t *testing.T) {
	pkgs := loadModulePackages(t)

	var agentPkg *packages.Package
	for _, p := range pkgs {
		if p.PkgPath == ModulePath+"/pkg/executor/agent" {
			agentPkg = p
			break
		}
	}
	if agentPkg == nil {
		t.Fatal("pkg/executor/agent did not load — the guard would silently pass")
	}

	imports := agentPkg.Imports
	if _, ok := imports[ModulePath+"/pkg/tlsconf"]; !ok {
		t.Fatalf("pkg/executor/agent no longer imports pkg/tlsconf.\n"+
			"The agent's dial must build its tls.Config through tlsconf.ClientConfig, which is\n"+
			"where the TLS 1.2 floor and the SPKI pin hook live. Imports: %v", importPaths(imports))
	}

	// The dial must actually install a client on the websocket dial, or the
	// carefully-built tls.Config would sit unused while the library reached
	// for http.DefaultClient.
	src := packageSource(t, agentPkg)
	for _, want := range []string{"tlsconf.ClientConfig", "TLSClientConfig", "HTTPClient"} {
		if !strings.Contains(src, want) {
			t.Errorf("pkg/executor/agent no longer references %q; "+
				"the pinned tls.Config may not be reaching the dial", want)
		}
	}
}

// ---------------------------------------------------------------------------
// (2) The hub refuses a cross-origin upgrade
// ---------------------------------------------------------------------------

// TestHubRejectsCrossOriginUpgrade drives the hub as an HTTP handler and
// asserts a browser-shaped cross-origin upgrade is refused with 403, while the
// agent-shaped request (no Origin) is not.
//
// Both halves are needed. A hub that refused everything would pass the first
// assertion and be entirely broken; a hub that accepted everything would pass
// the second and be the vulnerability.
func TestHubRejectsCrossOriginUpgrade(t *testing.T) {
	t.Parallel()

	hub, err := remote.NewHub(remote.HubOptions{
		Store:       newTransportStore(),
		Registry:    executor.NewRegistry(),
		ExternalURL: "https://hub.example.com",
	})
	if err != nil {
		t.Fatalf("NewHub: %v", err)
	}
	srv := httptest.NewServer(hub)
	defer srv.Close()

	upgradeHeaders := func(r *http.Request) {
		r.Header.Set("Connection", "Upgrade")
		r.Header.Set("Upgrade", "websocket")
		r.Header.Set("Sec-WebSocket-Version", "13")
		r.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
		r.Header.Set("Authorization", "Bearer clac1.aaaa.bbbb.cccc")
	}
	client := &http.Client{Timeout: 10 * time.Second}

	t.Run("cross-origin browser upgrade is refused", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, srv.URL, nil)
		if err != nil {
			t.Fatal(err)
		}
		upgradeHeaders(req)
		req.Host = "hub.example.com"
		req.Header.Set("Origin", "https://evil.example")

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("status = %d, want 403.\n"+
				"A cross-origin upgrade reaching the hub means a page on any site can drive the\n"+
				"agent endpoint from an operator's browser, including spending a single-use\n"+
				"enrollment token passed in the query string.", resp.StatusCode)
		}
		var body map[string]string
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			t.Fatalf("body is not JSON: %v", err)
		}
		if !strings.Contains(body["error"], "evil.example") {
			t.Errorf("refusal %q does not name the origin it rejected", body["error"])
		}
		if strings.EqualFold(resp.Header.Get("Upgrade"), "websocket") {
			t.Error("the connection was upgraded despite the 403")
		}
	})

	t.Run("agent without Origin is not refused by the origin check", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, srv.URL, nil)
		if err != nil {
			t.Fatal(err)
		}
		upgradeHeaders(req)
		req.Host = "hub.example.com"

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusForbidden {
			t.Fatal("an agent sending no Origin was rejected by the origin check — " +
				"no Go, Python or embedded client sends Origin, so this refuses the whole fleet")
		}
		// 401: the origin passed, the fabricated credential did not.
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", resp.StatusCode)
		}
	})

	t.Run("the deployment's own origin is accepted", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, srv.URL, nil)
		if err != nil {
			t.Fatal(err)
		}
		upgradeHeaders(req)
		req.Host = "hub.example.com"
		req.Header.Set("Origin", "https://hub.example.com")

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusForbidden {
			t.Fatal("the hub refused its own configured external origin; " +
				"the Executors panel could never open a socket")
		}
	})
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// loadModulePackages type-checks the module with syntax and type info, which
// the InsecureSkipVerify check needs and LoadGraph's Graph does not expose.
func loadModulePackages(t *testing.T) []*packages.Package {
	t.Helper()
	root, err := moduleRoot()
	if err != nil {
		t.Fatalf("locate module root: %v", err)
	}
	cfg := &packages.Config{
		Mode: packages.NeedName | packages.NeedFiles | packages.NeedSyntax |
			packages.NeedTypes | packages.NeedTypesInfo | packages.NeedDeps |
			packages.NeedImports,
		Dir: root,
		// Test files are excluded: a _test.go may legitimately stand up a
		// server with a throwaway certificate. The guarantee is about the
		// code that ships.
		Tests: false,
	}
	loaded, err := packages.Load(cfg, ModulePath+"/...")
	if err != nil {
		t.Fatalf("load packages: %v", err)
	}
	var all []*packages.Package
	packages.Visit(loaded, nil, func(p *packages.Package) { all = append(all, p) })
	if len(all) == 0 {
		t.Fatal("no packages loaded — the guard would silently pass")
	}
	return all
}

// findTLSConfigType resolves crypto/tls.Config from the loaded graph, so the
// comparison below is on identity rather than on a name that any package could
// reuse.
func findTLSConfigType(t *testing.T, pkgs []*packages.Package) types.Type {
	t.Helper()
	for _, p := range pkgs {
		if p.PkgPath != "crypto/tls" || p.Types == nil {
			continue
		}
		obj := p.Types.Scope().Lookup("Config")
		if obj == nil {
			continue
		}
		return obj.Type()
	}
	t.Fatal("crypto/tls.Config not found in the loaded packages — the guard would silently pass")
	return nil
}

func isTLSConfigType(t types.Type, tlsConfig types.Type) bool {
	if t == nil || tlsConfig == nil {
		return false
	}
	return types.Identical(deref(t), tlsConfig)
}

func deref(t types.Type) types.Type {
	if t == nil {
		return nil
	}
	if ptr, ok := t.Underlying().(*types.Pointer); ok {
		return ptr.Elem()
	}
	if ptr, ok := t.(*types.Pointer); ok {
		return ptr.Elem()
	}
	return t
}

// isFalseLiteral reports whether e is the untyped constant false. Anything
// else — a variable, a function call, a config field — is flagged: whether it
// is true at runtime is not something this check can decide, and "it depends"
// is not an acceptable answer for this field.
func isFalseLiteral(e ast.Expr) bool {
	id, ok := e.(*ast.Ident)
	return ok && id.Name == "false"
}

// exprString renders an expression back to source for the failure message, so
// a violation reads as "InsecureSkipVerify: cfg.SkipTLS" rather than as a bare
// file:line the reader has to go look up.
func exprString(p *packages.Package, e ast.Expr) string {
	if e == nil {
		return "<none>"
	}
	var buf bytes.Buffer
	if err := printer.Fprint(&buf, p.Fset, e); err != nil {
		return "<expression>"
	}
	return buf.String()
}

// packageSource concatenates a package's non-test source. It backs the coarse
// "is the pinned config still wired to the dial" assertion, which is a
// tripwire for a refactor that drops the wiring, not a proof of behaviour —
// pkg/executor/agent's transport_test.go proves the behaviour against a real
// TLS handshake.
func packageSource(t *testing.T, p *packages.Package) string {
	t.Helper()
	var sb strings.Builder
	for _, f := range p.GoFiles {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		sb.Write(data)
	}
	if sb.Len() == 0 {
		t.Fatalf("no source read for %s — the guard would silently pass", p.PkgPath)
	}
	return sb.String()
}

func importPaths(m map[string]*packages.Package) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// newTransportStore returns an empty enrollment store. Every credential
// presented in these tests is fabricated, so authentication always fails —
// which is what makes 401-vs-403 a clean readout of the origin decision alone.
func newTransportStore() remote.Store { return &emptyStore{} }

type emptyStore struct{}

func (*emptyStore) PutEnrollment(remote.EnrollmentRecord) error { return nil }
func (*emptyStore) GetEnrollment(id string) (remote.EnrollmentRecord, error) {
	return remote.EnrollmentRecord{}, fmt.Errorf("%w: %s", remote.ErrTokenInvalid, id)
}
func (*emptyStore) RedeemEnrollment(string, string, time.Time) error { return nil }
func (*emptyStore) RevokeEnrollment(string, time.Time) error         { return nil }
func (*emptyStore) ListEnrollments() ([]remote.EnrollmentRecord, error) {
	return nil, nil
}
func (*emptyStore) PutAgent(remote.AgentRecord) error { return nil }
func (*emptyStore) GetAgent(agentID string) (remote.AgentRecord, error) {
	return remote.AgentRecord{}, fmt.Errorf("%w: %s", remote.ErrAgentNotFound, agentID)
}
func (*emptyStore) RevokeAgent(string, time.Time) error       { return nil }
func (*emptyStore) TouchAgent(string, time.Time) error        { return nil }
func (*emptyStore) ListAgents() ([]remote.AgentRecord, error) { return nil, nil }
