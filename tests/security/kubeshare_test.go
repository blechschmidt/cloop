package security

// kubeshare_test.go — Kubernetes shares (Task 20416).
//
// Two guarantees a share rests on, checked against the code that ships:
//
//  1. The hub never runs a kubeconfig's credential plugin. `cloop remote kube
//     share` runs it on the developer's machine through pkg/kubeexec; nothing
//     the hub, the monitor, the broker or an executor runs may import that
//     package at all. Structural rather than a call-graph question: a package
//     nothing on the hub's side imports cannot be reached from there by any
//     path, static or dynamic.
//  2. The monitor never forwards a TokenRequest. A share the hub renews holds a
//     ServiceAccount that may create its own token; through the monitor that
//     permission must be the hub's alone, under every grant a sandbox can hold.

import (
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync/atomic"
	"testing"

	"golang.org/x/tools/go/packages"

	"github.com/blechschmidt/cloop/pkg/kubeguard"
)

// pluginRunner is the package that runs exec credential plugins.
const pluginRunner = ModulePath + "/pkg/kubeexec"

// pluginRunnerImporters may import it: the CLI, which is the binary's
// terminal half. The hub is the same binary, but none of the packages it runs
// may reach this one, which is what the test below holds.
var pluginRunnerImporters = map[string]bool{
	ModulePath + "/cmd": true,
}

// TestOnlyTheTerminalImportsTheCredentialPluginRunner.
func TestOnlyTheTerminalImportsTheCredentialPluginRunner(t *testing.T) {
	pkgs, err := loadModule()
	if err != nil {
		t.Fatalf("load module: %v", err)
	}
	seen := map[string]bool{}
	var importers []string
	var visit func(p *packages.Package)
	visit = func(p *packages.Package) {
		if p == nil || seen[p.PkgPath] {
			return
		}
		seen[p.PkgPath] = true
		if _, ok := p.Imports[pluginRunner]; ok {
			importers = append(importers, p.PkgPath)
		}
		for _, dep := range p.Imports {
			if strings.HasPrefix(dep.PkgPath, ModulePath) {
				visit(dep)
			}
		}
	}
	for _, p := range pkgs {
		visit(p)
	}
	if !seen[pluginRunner] {
		t.Fatalf("%s is not in the module graph; the test would pass vacuously", pluginRunner)
	}
	sort.Strings(importers)
	var bad []string
	for _, imp := range importers {
		if !pluginRunnerImporters[imp] {
			bad = append(bad, imp)
		}
	}
	if len(bad) > 0 {
		t.Errorf("%s imports %s, which runs a kubeconfig's exec credential plugin. Only the terminal may: a "+
			"plugin named in a kubeconfig the hub holds is a program chosen by whoever uploaded it, and running "+
			"it on the control-plane host is what the hub's kubeconfig parser refuses. Keep the import in cmd",
			strings.Join(bad, ", "), pluginRunner)
	}
	if len(importers) == 0 {
		t.Errorf("nothing imports %s; `cloop remote kube share` must", pluginRunner)
	}
}

// TestTheMonitorNeverForwardsATokenRequest drives the monitor the way a sandbox
// would, under the widest grant there is, against a stand-in cluster that
// counts what reaches it.
func TestTheMonitorNeverForwardsATokenRequest(t *testing.T) {
	var reached atomic.Int64
	cluster := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"kind":"TokenRequest","status":{"token":"minted-cluster-credential"}}`)
	}))
	t.Cleanup(cluster.Close)

	reg, err := kubeguard.NewRegistry("https://monitor.example.test:8444")
	if err != nil {
		t.Fatal(err)
	}
	policy := kubeguard.Policy{Verbs: []string{"get", "list", "watch", "create", "update", "patch", "delete", "deletecollection"}}
	minted, err := reg.Mint(kubeguard.MintRequest{
		Kubeconfig: []byte("apiVersion: v1\nkind: Config\ncurrent-context: c\nclusters:\n- name: c\n  cluster:\n" +
			"    server: " + cluster.URL + "\n    insecure-skip-tls-verify: true\ncontexts:\n- name: c\n  context: " +
			"{cluster: c, user: u}\nusers:\n- name: u\n  user: {token: shared-serviceaccount-token}\n"),
		Policy: policy,
	})
	if err != nil {
		t.Fatal(err)
	}
	px, err := kubeguard.New(reg, kubeguard.Options{})
	if err != nil {
		t.Fatal(err)
	}
	front := httptest.NewServer(px)
	t.Cleanup(func() { front.Close(); _ = px.Close() })

	for _, method := range []string{http.MethodPost, http.MethodGet, http.MethodPut, http.MethodPatch} {
		for _, path := range []string{
			"/api/v1/namespaces/cloop-shares/serviceaccounts/cloop-aks-dev-3f9c2a1b/token",
			"/api/v1/namespaces/team-a/serviceaccounts/default/token",
			"/api/v1/namespaces/team-a/serviceaccounts/default/../cloop-aks-dev-3f9c2a1b/token",
		} {
			req, _ := http.NewRequest(method, front.URL+path, strings.NewReader(`{"spec":{}}`))
			req.Header.Set("Authorization", "Bearer "+minted.Token)
			req.Header.Set("Content-Type", "application/json")
			resp, err := front.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode != http.StatusForbidden || strings.Contains(string(body), "minted-cluster-credential") {
				t.Errorf("%s %s under a grant of every verb: %d %s", method, path, resp.StatusCode, body)
			}
		}
	}
	if n := reached.Load(); n != 0 {
		t.Fatalf("%d token requests reached the cluster through the monitor", n)
	}

	// Non-vacuity: the same session does reach the cluster for an ordinary
	// write its grant allows.
	req, _ := http.NewRequest(http.MethodPost, front.URL+"/api/v1/namespaces/team-a/configmaps", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer "+minted.Token)
	resp, err := front.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || reached.Load() != 1 {
		t.Fatalf("an allowed write was not forwarded (%d, %d requests reached the cluster)", resp.StatusCode, reached.Load())
	}
}
