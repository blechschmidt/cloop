package container

// The hub's egress proxy as a container sandbox reaches it (Task 20378): the
// bridge's gateway, opened in the ruleset when there is one, and proven open
// with the compiled policy's own semantics before anything is installed.

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/netfilter"
)

// TestHubProxyIsOpenedInTheCompiledPolicy: a filter that drops private space
// — as every direct filter does — drops the bridge's gateway, which is where
// the hub's proxy answers. The proxy's address and port, and nothing else
// beside them, are what the driver opens.
func TestHubProxyIsOpenedInTheCompiledPolicy(t *testing.T) {
	gw := netip.MustParseAddr("172.19.0.1")
	proxy := netip.AddrPortFrom(gw, 41000)
	base := EgressFilter{
		Enabled:             true,
		AllowPublicInternet: true,
		AllowPorts:          []int{443},
		Resolvers:           []string{"1.1.1.1"},
	}

	without, err := base.Policy()
	if err != nil {
		t.Fatal(err)
	}
	if v, _ := without.Evaluate(gw, 41000, netfilter.ProtoTCP); v != netfilter.VerdictDrop {
		t.Fatalf("precondition: a direct filter should drop the bridge gateway, got %s", v)
	}

	with := base
	with.hubProxy = proxy
	policy, err := with.Policy()
	if err != nil {
		t.Fatal(err)
	}
	if v, why := policy.Evaluate(gw, 41000, netfilter.ProtoTCP); v != netfilter.VerdictAllow {
		t.Fatalf("the hub's proxy at %s is dropped (%s)", proxy, why)
	}
	for _, other := range []struct {
		addr  string
		port  uint16
		proto netfilter.Proto
	}{
		{"172.19.0.1", 41001, netfilter.ProtoTCP}, // another port on the gateway
		{"172.19.0.1", 22, netfilter.ProtoTCP},    // the host's ssh
		{"172.19.0.5", 41000, netfilter.ProtoTCP}, // a neighbouring sandbox
		{"172.19.0.1", 41000, netfilter.ProtoUDP}, // the same port, another protocol
		{"169.254.169.254", 80, netfilter.ProtoTCP},
	} {
		if v, why := policy.Evaluate(netip.MustParseAddr(other.addr), other.port, other.proto); v != netfilter.VerdictDrop {
			t.Errorf("%s:%d/%s is %s (%s); only the proxy itself may be opened", other.addr, other.port,
				other.proto, v, why)
		}
	}
	// The rest of the policy is untouched.
	if v, _ := policy.Evaluate(netip.MustParseAddr("140.82.112.3"), 443, netfilter.ProtoTCP); v != netfilter.VerdictAllow {
		t.Error("opening the proxy closed the public Internet the filter allowed")
	}
}

// TestADenyCoveringTheProxyWins: the operator's deny list is ahead of every
// allow, the proxy's included, so a filter that denies the gateway's range
// keeps it dropped — which is why provisioning proves the opening and refuses
// rather than start a sandbox that holds a session it cannot reach.
func TestADenyCoveringTheProxyWins(t *testing.T) {
	f := EgressFilter{
		Enabled: true, AllowPublicInternet: true, AllowPorts: []int{443},
		DenyCIDRs: []string{"172.16.0.0/12"},
		hubProxy:  netip.MustParseAddrPort("172.19.0.1:41000"),
	}
	p, err := f.Policy()
	if err != nil {
		t.Fatal(err)
	}
	v, why := p.Evaluate(netip.MustParseAddr("172.19.0.1"), 41000, netfilter.ProtoTCP)
	if v != netfilter.VerdictDrop || !strings.Contains(why, "deny") {
		t.Fatalf("a denied gateway is %s (%s)", v, why)
	}
	var warned bool
	for _, w := range p.Warnings {
		if strings.Contains(w, "egress broker 172.19.0.1:41000") {
			warned = true
		}
	}
	if !warned {
		t.Errorf("the compiled policy should warn that the proxy is shadowed: %v", p.Warnings)
	}
}

// TestHubProxyOpensThroughRulesFromTheHub: rules a device or project firewall
// stored in the hub are composed into this executor's filter, and the proxy is
// opened in what they compile to.
func TestHubProxyOpensThroughRulesFromTheHub(t *testing.T) {
	e := &Executor{id: "rules", opts: Options{Network: NetworkBridge}}
	f, err := e.filterForRules(executor.FirewallRules{AllowCIDRs: []string{"10.8.0.0/24"}, AllowPorts: []int{5432}})
	if err != nil {
		t.Fatal(err)
	}
	f.hubProxy = netip.MustParseAddrPort("172.20.0.1:41000")
	p, err := f.Policy()
	if err != nil {
		t.Fatal(err)
	}
	if v, why := p.Evaluate(netip.MustParseAddr("172.20.0.1"), 41000, netfilter.ProtoTCP); v != netfilter.VerdictAllow {
		t.Fatalf("the proxy is %s under the hub's rules (%s)", v, why)
	}
	if v, _ := p.Evaluate(netip.MustParseAddr("10.8.0.9"), 5432, netfilter.ProtoTCP); v != netfilter.VerdictAllow {
		t.Error("the rules' own allowance was lost")
	}
	if v, _ := p.Evaluate(netip.MustParseAddr("10.8.0.9"), 41000, netfilter.ProtoTCP); v != netfilter.VerdictDrop {
		t.Error("opening the proxy widened the rules' port list for their own range")
	}
}

// TestAProxyRouteGetsANetworkOfItsOwnOnlyUnderARuleset: two workloads whose
// rulesets differ by the proxy opening must not share a bridge, or the second
// Apply would close the first's way out; a ruleset-free bridge needs no split.
func TestAProxyRouteGetsANetworkOfItsOwnOnlyUnderARuleset(t *testing.T) {
	rules := &executor.FirewallRules{AllowPublicInternet: true, AllowPorts: []int{443}}
	route := &executor.EgressProxyRoute{Host: "host.containers.internal", Port: 41000, Gateway: true}

	plain := confinement{rules: rules}
	proxied := confinement{rules: rules, proxy: route}
	if networkName("ex", plain) == networkName("ex", proxied) || firewallTable("ex", plain) == firewallTable("ex", proxied) {
		t.Fatal("a workload that opens the proxy shares a bridge and table with one that does not")
	}
	other := confinement{rules: rules, proxy: &executor.EgressProxyRoute{Host: "x", Port: 41001, Gateway: true}}
	if networkName("ex", proxied) == networkName("ex", other) {
		t.Error("two proxy ports share a bridge")
	}
	if err := validateNetworkName(networkName("ex", proxied)); err != nil {
		t.Errorf("unusable network name: %v", err)
	}
	if err := netfilter.ValidateNftName(firewallTable("ex", proxied)); err != nil {
		t.Errorf("unusable table name: %v", err)
	}
	if got := networkName("ex", confinement{proxy: route}); got != "cloop-sbx-ex-x41000" {
		t.Errorf("the executor's own policy with a proxy = %q", got)
	}
}

// TestGatewayDecodesFromBothRuntimes: real payloads, as the inspection test
// next door uses — docker reports IPAM.Config, podman subnets.
func TestGatewayDecodesFromBothRuntimes(t *testing.T) {
	cases := map[string]struct {
		payload string
		want    string
		fails   bool
	}{
		"docker internal": {payload: `{"Name":"t20378-probe","Id":"dba1b346ddc1","Internal":true,` +
			`"IPAM":{"Driver":"default","Options":null,"Config":[{"Subnet":"172.19.0.0/16","IPRange":"","Gateway":"172.19.0.1"}]}}`,
			want: "172.19.0.1"},
		"docker dual-stack, v6 first": {payload: `{"IPAM":{"Config":[{"Subnet":"fd00::/64","Gateway":"fd00::1"},` +
			`{"Subnet":"172.30.0.0/16","Gateway":"172.30.0.1"}]}}`, want: "172.30.0.1"},
		"podman": {payload: `{"name":"podman","id":"2f259bab93aa","driver":"bridge","network_interface":"podman0",` +
			`"subnets":[{"subnet":"10.88.0.0/16","gateway":"10.88.0.1"}],"internal":false}`, want: "10.88.0.1"},
		"no gateway": {payload: `{"IPAM":{"Config":[]}}`, fails: true},
		"garbage":    {payload: `not json`, fails: true},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := gatewayFromInspection([]byte(c.payload))
			if c.fails {
				if err == nil {
					t.Fatalf("decoded %s from %s", got, c.payload)
				}
				return
			}
			if err != nil || got.String() != c.want {
				t.Fatalf("gateway = %s, %v; want %s", got, err, c.want)
			}
		})
	}
}

// TestRouteEgressProxyPinsTheNameFirst: the pin goes ahead of an operator's
// allow_hosts entry for the same name, so the URL the hub issued resolves to
// the gateway; nothing is pinned for a route that dials an address, or for a
// sandbox with no network.
func TestRouteEgressProxyPinsTheNameFirst(t *testing.T) {
	e := &Executor{id: "pin", opts: Options{Network: NetworkBridge}}
	gw := netip.MustParseAddr("172.19.0.1")
	route := executor.EgressProxyRoute{Host: "host.containers.internal", Port: 41000, Gateway: true}

	req := runRequest{Network: "cloop-sbx-pin", AddHosts: []string{"host.containers.internal:10.9.9.9"}}
	if err := e.routeEgressProxy(context.Background(), &req, route, gw); err != nil {
		t.Fatal(err)
	}
	if len(req.AddHosts) != 2 || req.AddHosts[0] != "host.containers.internal:172.19.0.1" {
		t.Fatalf("AddHosts = %v", req.AddHosts)
	}

	direct := runRequest{Network: NetworkBridge}
	if err := e.routeEgressProxy(context.Background(), &direct,
		executor.EgressProxyRoute{Host: "203.0.113.5", Port: 41000}, netip.Addr{}); err != nil || len(direct.AddHosts) != 0 {
		t.Fatalf("an address route pinned %v (%v)", direct.AddHosts, err)
	}
	none := runRequest{Network: NetworkNone}
	if err := e.routeEgressProxy(context.Background(), &none, route, gw); err != nil || len(none.AddHosts) != 0 {
		t.Fatalf("a sandbox with no network was pinned %v (%v)", none.AddHosts, err)
	}
	args, err := buildRunArgs(runRequest{
		Image: "alpine", Name: "cloop-x-1", Argv: []string{"true"}, Network: "cloop-sbx-pin", AllowRoot: true,
		AddHosts:  req.AddHosts,
		Workspace: mount{HostPath: "/tmp", TargetPath: ContainerWorkspace},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(args.Args, " "), "--add-host host.containers.internal:172.19.0.1") {
		t.Errorf("argv = %v", args.Args)
	}
}

// TestEgressProxyRouteValidates: a route reaching a driver over the wire is
// checked where it is used.
func TestEgressProxyRouteValidates(t *testing.T) {
	for _, bad := range []executor.EgressProxyRoute{
		{Host: "", Port: 1},
		{Host: "h", Port: 0},
		{Host: "h", Port: 70000},
		{Host: "10.0.0.1", Port: 8899, Gateway: true}, // nothing to pin
		{Host: "bad host", Port: 8899},
		{Host: "-flag", Port: 8899},
		{Host: "a:b", Port: 8899, Gateway: true},
	} {
		spec := executor.Spec{Argv: []string{"x"}, EgressProxy: &bad}
		if err := spec.Validate(); err == nil {
			t.Errorf("route %+v validated", bad)
		}
	}
	for _, good := range []executor.EgressProxyRoute{
		{Host: "host.containers.internal", Port: 41000, Gateway: true},
		{Host: "203.0.113.5", Port: 8899},
		{Host: "egress.cloop.svc", Port: 8899},
	} {
		spec := executor.Spec{Argv: []string{"x"}, EgressProxy: &good}
		if err := spec.Validate(); err != nil {
			t.Errorf("route %+v: %v", good, err)
		}
	}
}

// TestInternalOnlyFilterNeedsNoPacketFilterPrivilege: `internal: true` with no
// direct rules installs nothing, so a hub that may not use nft — CI's runner,
// any hub without CAP_NET_ADMIN — must still start sandboxes under it. The
// stale-table cleanup on that path used to refuse every run there (Task
// 20378's container test found it). An nft this process may use and that
// still fails stays a refusal: as root the same failure is a fault.
func TestInternalOnlyFilterNeedsNoPacketFilterPrivilege(t *testing.T) {
	dir := t.TempDir()
	fake := "#!/bin/sh\necho 'netlink: Error: cache initialization failed: Operation not permitted' >&2\nexit 1\n"
	if err := os.WriteFile(filepath.Join(dir, "nft"), []byte(fake), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	e := &Executor{id: "internal-only", opts: Options{Network: NetworkBridge,
		EgressFilter: EgressFilter{Enabled: true, Internal: true}}}
	err := e.removeFirewall(context.Background(), confinement{})
	if os.Geteuid() == 0 {
		if err == nil {
			t.Fatal("as root, an nft that refuses is a fault and must be reported")
		}
		return
	}
	if err != nil {
		t.Fatalf("an unprivileged hub refused an internal-only sandbox: %v", err)
	}
}
