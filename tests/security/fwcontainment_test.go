package security

// Guarantee 14: a sandbox never reaches further than the firewall of the device
// it runs on (Task 20363).
//
// The firewall is set at up to four levels — an executor's configuration file,
// the admin's rule set per device, a virtual executor's own firewall, and the
// rule set a project's maintainers edit — and each inner level may only narrow
// the one above it. Without that, the inner levels would be privilege
// escalations with a text box: a maintainer who can name their own CIDRs on a
// device whose admin kept it off 10.0.0.0/8 has given themselves the
// operator's network.
//
// The rule is one function (fwpolicy.Permits), checked at save time, at
// dispatch and in the driver. These tests hold the function to the property
// against the attacks a project would try; hold the compiled result to the
// block set on the wire; and hold the code to calling the check on every path
// that starts a workload — the failure this guards against is the second way
// to build a Spec that nobody remembered to route through it.

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/localprocess"
	"github.com/blechschmidt/cloop/pkg/fwpolicy"
	"github.com/blechschmidt/cloop/pkg/netfilter"
)

// typicalDevice is the bound a realistic admin sets: out to the Internet on
// web ports, into one internal range, through one resolver, and never into a
// provider's range the organisation has blocked.
var typicalDevice = executor.FirewallRules{
	AllowPublicInternet: true,
	AllowCIDRs:          []string{"10.20.0.0/16"},
	DenyCIDRs:           []string{"198.51.100.0/24"},
	AllowPorts:          []int{80, 443},
	Resolvers:           []string{"1.1.1.1"},
}

// TestProjectRulesCannotEscapeTheDevice is the attack list: every rule set a
// project would write to reach past its device is refused, naming what is
// outside.
func TestProjectRulesCannotEscapeTheDevice(t *testing.T) {
	for name, c := range map[string]struct {
		attack executor.FirewallRules
		names  string // what the refusal must name
	}{
		"the operator's network":         {executor.FirewallRules{AllowCIDRs: []string{"10.0.0.0/8"}, AllowPorts: []int{443}}, "10.0.0.0/8"},
		"a home router range":            {executor.FirewallRules{AllowCIDRs: []string{"192.168.0.0/16"}, AllowPorts: []int{443}}, "192.168.0.0/16"},
		"the metadata endpoint":          {executor.FirewallRules{AllowCIDRs: []string{"169.254.169.254"}, AllowPorts: []int{80}}, "169.254.169.254"},
		"half of IPv4":                   {executor.FirewallRules{AllowCIDRs: []string{"0.0.0.0/1"}, AllowPorts: []int{443}}, "0.0.0.0/1"},
		"a /7 covering private space":    {executor.FirewallRules{AllowCIDRs: []string{"10.0.0.0/7"}, AllowPorts: []int{443}}, "10.0.0.0/7"},
		"IPv6 private space":             {executor.FirewallRules{AllowCIDRs: []string{"fc00::/7"}, AllowPorts: []int{443}}, "fc00::/7"},
		"loopback":                       {executor.FirewallRules{AllowCIDRs: []string{"127.0.0.0/8"}, AllowPorts: []int{443}}, "127.0.0.0/8"},
		"SSH":                            {executor.FirewallRules{AllowPublicInternet: true, AllowPorts: []int{22}}, "port 22"},
		"every port":                     {executor.FirewallRules{AllowPublicInternet: true}, "every port"},
		"a resolver of its own":          {executor.FirewallRules{Resolvers: []string{"8.8.8.8"}}, "8.8.8.8"},
		"a public range on another port": {executor.FirewallRules{AllowCIDRs: []string{"1.1.1.0/24"}, AllowPorts: []int{8443}}, "port 8443"},
	} {
		reasons := fwpolicy.Permits(&typicalDevice, c.attack)
		if len(reasons) == 0 {
			t.Errorf("%s: %s was accepted under %s", name, c.attack.Describe(), typicalDevice.Describe())
			continue
		}
		if joined := strings.Join(reasons, "; "); !strings.Contains(joined, c.names) {
			t.Errorf("%s: the refusal does not name %q: %q", name, c.names, joined)
		}
	}
}

// TestTheDeviceDenylistBindsEveryLevelBelow: a project cannot reach a range its
// device denies, whatever its own rules say — the denylist is inherited.
func TestTheDeviceDenylistBindsEveryLevelBelow(t *testing.T) {
	project := executor.FirewallRules{AllowCIDRs: []string{"198.51.100.0/24"}, AllowPorts: []int{443}}
	eff, err := fwpolicy.Effective(&typicalDevice, project)
	if err != nil {
		t.Fatal(err)
	}
	in, err := fwpolicy.Input(eff)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := netfilter.Compile(in)
	if err != nil {
		t.Fatal(err)
	}
	if v, _ := policy.WireOnly().Evaluate(netip.MustParseAddr("198.51.100.7"), 443, netfilter.ProtoTCP); v != netfilter.VerdictDrop {
		t.Error("a range the device denies is reachable through a project rule set naming it")
	}
}

// TestPermittedRulesStillDropBlockedSpace: whatever fits inside the device
// compiles to a policy that still drops the metadata endpoint, private space
// and loopback on the wire.
func TestPermittedRulesStillDropBlockedSpace(t *testing.T) {
	for _, project := range []executor.FirewallRules{
		{AllowPublicInternet: true, AllowPorts: []int{443}, Resolvers: []string{"1.1.1.1"}},
		{AllowCIDRs: []string{"0.0.0.0/1"}, DenyCIDRs: []string{"10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
			"0.0.0.0/8"}, AllowPorts: []int{443}},
		{AllowCIDRs: []string{"10.20.3.0/24"}, AllowPorts: []int{80}},
	} {
		if r := fwpolicy.Permits(&typicalDevice, project); len(r) != 0 {
			continue // not a permitted rule set; nothing to check
		}
		eff, _ := fwpolicy.Effective(&typicalDevice, project)
		in, err := fwpolicy.Input(eff)
		if err != nil {
			t.Fatal(err)
		}
		policy, err := netfilter.Compile(in)
		if err != nil {
			t.Fatal(err)
		}
		for _, a := range []string{"169.254.169.254", "10.1.2.3", "192.168.1.1", "127.0.0.1", "fd00::1"} {
			if v, _ := policy.WireOnly().Evaluate(netip.MustParseAddr(a), 443, netfilter.ProtoTCP); v != netfilter.VerdictDrop {
				t.Errorf("%s permitted under the device reaches %s", project.Describe(), a)
			}
		}
	}
}

// TestAbsentAndEmptyBoundsAreOpposites: no rule set bounds nothing; an empty
// one bounds everything down to nothing; an unreadable one refuses.
func TestAbsentAndEmptyBoundsAreOpposites(t *testing.T) {
	wide := executor.FirewallRules{AllowPublicInternet: true, AllowCIDRs: []string{"10.0.0.0/8"}}
	if len(fwpolicy.Permits(nil, wide)) != 0 {
		t.Error("an absent bound refused a rule set")
	}
	if len(fwpolicy.Permits(&executor.FirewallRules{}, wide)) == 0 {
		t.Error("an empty bound — reach nothing — permitted a rule set reaching something")
	}
	bad := executor.FirewallRules{AllowCIDRs: []string{"garbage"}}
	if len(fwpolicy.Permits(&bad, executor.FirewallRules{})) == 0 {
		t.Error("an unreadable bound permitted something")
	}
}

// brokenStore is a control plane whose firewall rows cannot be read.
type brokenStore struct{}

func (brokenStore) DeviceFirewall(string) (*executor.FirewallRules, error) {
	return nil, errors.New("database disk image is malformed")
}
func (brokenStore) ProjectFirewall(string) (*executor.FirewallRules, error) {
	return nil, errors.New("database disk image is malformed")
}

// TestAnUnreadableStoreRefusesTheRun: a storage fault is never "no rules".
func TestAnUnreadableStoreRefusesTheRun(t *testing.T) {
	restore := fwpolicy.SetSource(brokenStore{})
	defer restore()
	ex := localprocess.New("fw-conformance")
	spec := executor.Spec{WorkDir: t.TempDir(), Argv: []string{"true"}}
	if _, err := fwpolicy.Resolve(&spec, ex, spec.WorkDir); err == nil {
		t.Fatal("dispatch went ahead when the firewall store could not be read")
	}
	if err := fwpolicy.CheckAtDriver(executor.Spec{}, nil, "", "fw-conformance"); err == nil {
		t.Fatal("a driver went ahead when the firewall store could not be read")
	}
}

// TestTheHostProcessDriverRefusesRules: no per-workload network namespace, no
// firewall — and so no workload that carries one.
func TestTheHostProcessDriverRefusesRules(t *testing.T) {
	ex := localprocess.New("fw-conformance-host")
	rules := executor.FirewallRules{AllowPublicInternet: true, AllowPorts: []int{443}}
	_, err := ex.Start(context.Background(), executor.Spec{WorkDir: t.TempDir(), Argv: []string{"true"},
		EgressRules: &rules})
	if !errors.Is(err, executor.ErrUnsupported) {
		t.Fatalf("the host-process driver started a workload carrying firewall rules: %v", err)
	}
}

// TestEveryDispatchPathResolvesTheFirewall is structural: every function that
// shapes a workload's sandbox (applySandbox) also composes its firewall
// (applyFirewall) before the workspace step; the REST server's dispatch calls
// fwpolicy.Resolve; and the drivers that install a firewall check the rules in
// their start path. A new dispatch path that forgets the step fails here, not
// in production with a sandbox outside its device's rules.
func TestEveryDispatchPathResolvesTheFirewall(t *testing.T) {
	root, err := moduleRoot()
	if err != nil {
		t.Fatal(err)
	}
	callers := func(dir, callee string) map[string]string {
		out := map[string]string{} // function → its source, for a further check
		fset := token.NewFileSet()
		entries, err := os.ReadDir(filepath.Join(root, dir))
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			if !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
				continue
			}
			path := filepath.Join(root, dir, e.Name())
			src, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			f, err := parser.ParseFile(fset, path, src, 0)
			if err != nil {
				t.Fatal(err)
			}
			for _, d := range f.Decls {
				fn, ok := d.(*ast.FuncDecl)
				if !ok || fn.Body == nil {
					continue
				}
				found := false
				ast.Inspect(fn.Body, func(n ast.Node) bool {
					if c, ok := n.(*ast.CallExpr); ok {
						if exprName(c.Fun) == callee {
							found = true
						}
					}
					return true
				})
				if found {
					body := string(src[fset.Position(fn.Body.Pos()).Offset:fset.Position(fn.Body.End()).Offset])
					out[e.Name()+":"+fn.Name.Name] = body
				}
			}
		}
		return out
	}

	shaped := callers("pkg/ui", "applySandbox")
	if len(shaped) < 3 {
		t.Fatalf("found only %d dispatch paths in pkg/ui; the scan is not seeing the tree", len(shaped))
	}
	for fn, body := range shaped {
		s, f, w := strings.Index(body, "applySandbox("), strings.Index(body, "applyFirewall("),
			strings.Index(body, "applyWorkspace(")
		if f < 0 {
			t.Errorf("%s shapes a sandbox but never composes its firewall (applyFirewall)", fn)
			continue
		}
		if f < s || (w >= 0 && f > w) {
			t.Errorf("%s composes the firewall outside applySandbox → applyFirewall → applyWorkspace", fn)
		}
	}
	// Every path that bounds a workload's resources is a dispatch path, the
	// failover's re-dispatch included, and must compose its firewall too.
	for fn, body := range callers("pkg/ui", "applyResourceCeiling") {
		if !strings.Contains(body, "applyFirewall(") {
			t.Errorf("%s dispatches (it applies resource ceilings) without composing the firewall", fn)
		}
	}
	for fn, body := range callers("pkg/apiserver", "executor.BoundSpec") {
		if !strings.Contains(body, "fwpolicy.Resolve(") {
			t.Errorf("%s dispatches without composing the firewall (fwpolicy.Resolve)", fn)
		}
	}
	for _, want := range []struct{ dir, fn, call string }{
		{"pkg/executor/container", "start", "checkRules"},
		{"pkg/executor/kubernetes", "Start", "checkRules"},
		{"pkg/executor/remote", "start", "checkEgressRules"},
	} {
		found := false
		for name := range callers(want.dir, want.call) {
			if strings.HasSuffix(name, ":"+want.fn) {
				found = true
			}
		}
		if !found {
			t.Errorf("%s's %s does not call %s before starting a workload", want.dir, want.fn, want.call)
		}
	}
}

// exprName renders a call's function as written: "applyFirewall",
// "e.checkRules" → "checkRules" for a method, "fwpolicy.Resolve" for a
// package function.
func exprName(e ast.Expr) string {
	switch v := e.(type) {
	case *ast.Ident:
		return v.Name
	case *ast.SelectorExpr:
		if x, ok := v.X.(*ast.Ident); ok && (x.Name == "executor" || x.Name == "fwpolicy") {
			return x.Name + "." + v.Sel.Name
		}
		return v.Sel.Name
	}
	return ""
}
