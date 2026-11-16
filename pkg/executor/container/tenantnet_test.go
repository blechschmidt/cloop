package container

// Unit tests for the tenant networks of Task 20502: what names a network, a
// bridge and a table, what `network create` is asked for, and what a handle
// row and the host's resolver configuration are read back as. The end-to-end
// proof — two projects' containers that cannot reach each other — is
// TestIntegration_TwoProjectsSandboxesCannotReachEachOther.

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/netfilter"
)

// testTenant is a tenant tag for tests that are about something else.
var testTenant = tenantTag("project:/srv/app")

// TestEveryProjectGetsItsOwnNetworkBridgeAndTable is the naming half of the
// guarantee: two projects never share a network, a bridge or a table, under
// any confinement, and a project's own workloads always do.
func TestEveryProjectGetsItsOwnNetworkBridgeAndTable(t *testing.T) {
	rules := &executor.FirewallRules{AllowPublicInternet: true, AllowPorts: []int{443}}
	proxy := &executor.EgressProxyRoute{Host: "host.containers.internal", Port: 41000, Gateway: true}
	confinements := map[string]confinement{
		"executor's own":   {},
		"public scope":     scoped(executor.EgressScopePublic),
		"rules":            {rules: rules},
		"rules with proxy": {rules: rules, proxy: proxy},
	}
	alpha := tenantTag(tenantOf(executor.Spec{Labels: map[string]string{"project": "/srv/alpha"}}, "h1"))
	alphaAgain := tenantTag(tenantOf(executor.Spec{WorkDir: "/var/lib/agent/trees/alpha-1",
		Labels: map[string]string{"project": "/srv/alpha/"}}, "h2"))
	bravo := tenantTag(tenantOf(executor.Spec{Labels: map[string]string{"project": "/srv/bravo"}}, "h1"))
	if alpha != alphaAgain {
		t.Fatalf("two workloads of one project have tenants %q and %q", alpha, alphaAgain)
	}
	if alpha == bravo {
		t.Fatalf("two projects share the tenant %q", alpha)
	}
	for name, c := range confinements {
		for _, ex := range []string{"container", "vx-0123456789abcdef", strings.Repeat("long-executor-", 6)} {
			na, nb := networkName(ex, c, alpha), networkName(ex, c, bravo)
			if na == nb {
				t.Errorf("%s on %s: both projects join %q", name, ex, na)
			}
			if bridgeName(na) == bridgeName(nb) {
				t.Errorf("%s on %s: both projects' bridges are %q", name, ex, bridgeName(na))
			}
			ta, tb := firewallTable(ex, c, alpha), firewallTable(ex, c, bravo)
			if ta == tb {
				t.Errorf("%s on %s: both projects' rulesets would be the table %q, so the second Apply "+
					"would replace the first project's ruleset", name, ex, ta)
			}
			for _, n := range []string{na, nb} {
				if err := validateNetworkName(n); err != nil {
					t.Errorf("%s on %s: network %q: %v", name, ex, n, err)
				}
				if err := netfilter.ValidateInterfaceName(bridgeName(n)); err != nil {
					t.Errorf("%s on %s: bridge %q: %v", name, ex, bridgeName(n), err)
				}
				if !strings.HasPrefix(bridgeName(n), sandboxBridgePrefix) {
					t.Errorf("%s on %s: bridge %q does not match %s", name, ex, bridgeName(n), siblingBridges)
				}
			}
			for _, tbl := range []string{ta, tb} {
				if err := netfilter.ValidateNftName(tbl); err != nil {
					t.Errorf("%s on %s: table %q: %v", name, ex, tbl, err)
				}
			}
		}
	}
	// A workload that names no project shares a network with nothing: two of
	// them are two tenants, and neither is a project's.
	h1 := tenantTag(tenantOf(executor.Spec{}, "h1"))
	h2 := tenantTag(tenantOf(executor.Spec{}, "h2"))
	if h1 == h2 || h1 == alpha || h2 == alpha {
		t.Errorf("project-less workloads share a tenant: %q %q (alpha %q)", h1, h2, alpha)
	}
	// Nothing of a project's path survives into a name.
	if strings.Contains(networkName("container", confinement{}, alpha), "alpha") {
		t.Error("a network name carries the project's path")
	}
}

// TestNetworkCreateIsolatesAndNamesTheBridge pins `network create`: the bridge
// named so the sibling pattern matches it, the labels the sweep reads, and on
// podman the isolation netavark does not give by default — plus no engine DNS
// for an unfiltered sandbox, which resolves through the host's resolvers as it
// did on the default bridge.
func TestNetworkCreateIsolatesAndNamesTheBridge(t *testing.T) {
	n := networkSpec{name: "cloop-sbx-x-p" + testTenant, bridge: "clsb0123456789a", tenant: testTenant}
	docker := (&Executor{id: "x", rt: Runtime{Name: RuntimeDocker}}).networkCreateArgs(n)
	want := []string{"network", "create", "--driver", "bridge",
		"--label", "cloop.managed=true", "--label", "cloop.executor=x", "--label", "cloop.tenant=" + testTenant,
		"--opt", "com.docker.network.bridge.name=clsb0123456789a", n.name}
	if !reflect.DeepEqual(docker, want) {
		t.Errorf("docker network create:\n got %q\nwant %q", docker, want)
	}
	n.internal, n.table, n.engineDNS = true, "cloop_sbx_x", true
	podman := (&Executor{id: "x", rt: Runtime{Name: RuntimePodman}}).networkCreateArgs(n)
	want = []string{"network", "create", "--driver", "bridge", "--internal",
		"--label", "cloop.managed=true", "--label", "cloop.executor=x", "--label", "cloop.tenant=" + testTenant,
		"--label", "cloop.nft_table=cloop_sbx_x", "--interface-name", "clsb0123456789a", "--opt", "isolate=true", n.name}
	if !reflect.DeepEqual(podman, want) {
		t.Errorf("podman network create:\n got %q\nwant %q", podman, want)
	}
	n.engineDNS = false
	if args := (&Executor{id: "x", rt: Runtime{Name: RuntimePodman}}).networkCreateArgs(n); !contains(args, "--disable-dns") {
		t.Errorf("an unfiltered podman network keeps the engine's DNS: %q", args)
	}
	if last := podman[len(podman)-1]; last != n.name {
		t.Errorf("the network name is not the last argument: %q", podman)
	}
}

// TestAnExistingNetworkMustMeanWhatItsNameSays: a network found under a
// tenant network's name is reused only when it is internal as asked, has the
// sandbox bridge, and — on podman — is isolated. Anything else is refused,
// because the sandbox would join a segment its rulesets do not recognise or
// that the engine routes to its other networks.
func TestAnExistingNetworkMustMeanWhatItsNameSays(t *testing.T) {
	n := networkSpec{name: "cloop-sbx-x-p" + testTenant, bridge: "clsb0123456789a", tenant: testTenant}
	podman := &Executor{rt: Runtime{Name: RuntimePodman}}
	docker := &Executor{rt: Runtime{Name: RuntimeDocker}}
	good := networkFacts{bridge: n.bridge, isolated: true}
	if why := podman.networkMismatch(good, n); why != "" {
		t.Errorf("a matching podman network is refused: %s", why)
	}
	if why := docker.networkMismatch(networkFacts{bridge: n.bridge}, n); why != "" {
		t.Errorf("a matching docker network is refused: %s", why)
	}
	for name, f := range map[string]networkFacts{
		"internal":     {bridge: n.bridge, isolated: true, internal: true},
		"other bridge": {bridge: "br-0123456789ab", isolated: true},
		"not isolated": {bridge: n.bridge},
	} {
		if why := podman.networkMismatch(f, n); why == "" {
			t.Errorf("podman: a network that is %s is reused", name)
		}
	}
}

// TestInspectNetworkReadsANamedBridge: a bridge cloop named is read back from
// where each engine reports it — docker's Options, podman's network_interface —
// with podman's isolate and both engines' labels and creation time.
func TestInspectNetworkReadsANamedBridge(t *testing.T) {
	for name, c := range map[string]struct {
		rt, json string
		want     networkFacts
	}{
		"docker": {RuntimeDocker, `{"Id":"696aaf9c14509c2c7f0e","Internal":false,` +
			`"Options":{"com.docker.network.bridge.name":"clsb0123456789a"},` +
			`"Labels":{"cloop.tenant":"0123456789"},"Created":"2026-11-16T05:20:00.123456789Z"}`,
			networkFacts{bridge: "clsb0123456789a", labels: map[string]string{"cloop.tenant": "0123456789"}}},
		"podman": {RuntimePodman, `{"id":"1c6ac636947d0000","internal":true,"network_interface":"clsb0123456789a",` +
			`"options":{"isolate":"true"},"labels":{"cloop.tenant":"0123456789"},"created":"2026-11-16T05:20:00.5Z"}`,
			networkFacts{bridge: "clsb0123456789a", internal: true, isolated: true,
				labels: map[string]string{"cloop.tenant": "0123456789"}}},
		"docker default bridge": {RuntimeDocker, `{"Id":"b70c01483849aaaa","Options":{"com.docker.network.bridge.name":"docker0"}}`,
			networkFacts{bridge: "docker0"}},
		"docker unnamed": {RuntimeDocker, `{"Id":"f3ff171817fa0000","Internal":false}`,
			networkFacts{bridge: "br-f3ff171817fa"}},
	} {
		e := fakeInspectExecutor(t, c.rt, c.json)
		got, err := e.inspectNetwork(t.Context(), "cloop-sbx-x")
		if err != nil {
			t.Fatalf("%s: inspectNetwork: %v", name, err)
		}
		if got.bridge != c.want.bridge || got.internal != c.want.internal || got.isolated != c.want.isolated ||
			!reflect.DeepEqual(got.labels, c.want.labels) {
			t.Errorf("%s: got %+v, want %+v", name, got, c.want)
		}
		if strings.Contains(c.json, "2026-11-16") && got.created.IsZero() {
			t.Errorf("%s: the creation time was not read", name)
		}
	}
}

// fakeInspectExecutor is an executor whose engine answers every command with
// out on stdout.
func fakeInspectExecutor(t *testing.T, name, out string) *Executor {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, name)
	script := "#!/bin/sh\ncat <<'EOF'\n" + out + "\nEOF\n"
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return &Executor{id: "x", rt: Runtime{Name: name, Path: bin}}
}

// TestNetworkMetaRoundTrips: a handle row carries the tenant network and its
// table to an adopter, and nothing a row could be edited to say makes the
// adopter count a network this driver would never have made.
func TestNetworkMetaRoundTrips(t *testing.T) {
	meta := withNetworkMeta(nil, "cloop-sbx-x-p"+testTenant, "cloop_sbx_x_p"+testTenant)
	n, tbl := restoreNetworkMeta(meta)
	if n != "cloop-sbx-x-p"+testTenant || tbl != "cloop_sbx_x_p"+testTenant {
		t.Errorf("round trip = %q, %q", n, tbl)
	}
	if got := withNetworkMeta(map[string]string{"k": "v"}, "", "x"); len(got) != 1 {
		t.Errorf("a container on no tenant network recorded one: %v", got)
	}
	for _, bad := range []map[string]string{
		{metaNetwork: "bridge"},
		{metaNetwork: "-cloop-sbx-x"},
		{metaNetwork: "cloop-sbx-x;rm"},
	} {
		if n, _ := restoreNetworkMeta(bad); n != "" {
			t.Errorf("restoreNetworkMeta(%v) = %q", bad, n)
		}
	}
	if _, tbl := restoreNetworkMeta(map[string]string{metaNetwork: "cloop-sbx-x", metaNetworkTable: "x; flush ruleset"}); tbl != "" {
		t.Errorf("an unusable table was restored: %q", tbl)
	}
}

// TestHostResolversAreWhatTheDefaultBridgeGave: an unfiltered sandbox on its
// project's network resolves through the host's resolvers, as the default
// bridge gave them — loopback stubs replaced by systemd-resolved's upstream
// list, IPv6 left out, search and options kept, and nothing from the file able
// to add a line of its own.
func TestHostResolversAreWhatTheDefaultBridgeGave(t *testing.T) {
	dir := t.TempDir()
	stub := filepath.Join(dir, "resolv.conf")
	upstream := filepath.Join(dir, "upstream.conf")
	write := func(p, s string) {
		if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(stub, "nameserver 127.0.0.53\noptions edns0 trust-ad\nsearch corp.example\n")
	write(upstream, "# upstream\nnameserver 10.0.0.2\nnameserver fd00::53\nnameserver 192.0.2.53 # second\n"+
		"search corp.example lab.example\noptions edns0\n")
	servers, search, options := hostResolvers([]string{stub, upstream})
	if !reflect.DeepEqual(servers, []string{"10.0.0.2", "192.0.2.53"}) {
		t.Errorf("servers = %v, want the IPv4 upstreams", servers)
	}
	if !reflect.DeepEqual(search, []string{"corp.example", "lab.example"}) || !reflect.DeepEqual(options, []string{"edns0"}) {
		t.Errorf("search %v options %v", search, options)
	}
	// Only a loopback stub, and nothing upstream: what docker gives a
	// default-bridge container there, its public fallback, which a sandbox
	// can reach — never the stub, which it cannot.
	write(stub, "nameserver 127.0.0.53\nsearch corp.example\n")
	servers, search, _ = hostResolvers([]string{stub, filepath.Join(dir, "missing")})
	if !reflect.DeepEqual(servers, dockerFallbackResolvers) || !reflect.DeepEqual(search, []string{"corp.example"}) {
		t.Errorf("a host with only a loopback stub gave the sandbox %v (search %v)", servers, search)
	}
	if !hasDNSFlag([]string{"--memory=1g", "--dns=10.0.0.53"}) || !hasDNSFlag([]string{"--dns"}) ||
		hasDNSFlag([]string{"--dns-search=x"}) {
		t.Error("hasDNSFlag misreads extra args")
	}
	_, search, options = parseResolvConf("search good.example bad\x00.example\noptions ndots:1 evil\"\n")
	if !reflect.DeepEqual(search, []string{"good.example"}) || !reflect.DeepEqual(options, []string{"ndots:1"}) {
		t.Errorf("unsafe tokens survived: search %q options %q", search, options)
	}

	e := &Executor{id: "x", opts: Options{StageDir: t.TempDir()}}
	path, err := e.writeResolvConf("# test\n", []string{"10.0.0.2"}, []string{"corp.example"}, []string{"edns0"})
	if err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	if want := "# test\nnameserver 10.0.0.2\nsearch corp.example\noptions edns0\n"; string(data) != want {
		t.Errorf("resolv.conf:\n%s\nwant\n%s", data, want)
	}
	if _, err := e.writeResolvConf("# test\n", []string{"10.0.0.2"}, []string{"a\nnameserver 6.6.6.6"}, nil); err == nil {
		t.Error("a search domain added a line of its own")
	}
}

// TestPreflightSaysHowProjectsAreKeptApart: the finding is OK when each
// project gets a network of its own and a warning when every sandbox joins
// the operator's network.
func TestPreflightSaysHowProjectsAreKeptApart(t *testing.T) {
	for name, c := range map[string]struct {
		opts  Options
		level string
	}{
		"bridge":   {Options{Network: NetworkBridge}, LevelOK},
		"none":     {Options{Network: NetworkNone}, LevelOK},
		"internal": {Options{Network: NetworkBridge, EgressFilter: EgressFilter{Enabled: true, Internal: true}}, LevelOK},
		"operator": {Options{Network: "lab-net"}, LevelWarn},
	} {
		e := &Executor{id: "x", rt: Runtime{Name: RuntimeDocker}, opts: c.opts}
		var got string
		e.preflightNetworkIsolation(t.Context(), func(n, level, msg, fix string) {
			if n == "network-isolation" {
				got = level
			}
		})
		if got != c.level {
			t.Errorf("%s: network-isolation is %q, want %q", name, got, c.level)
		}
	}
}

// TestNetworkLockIsHostWide: the lock that keeps one process's release of a
// network from interleaving with another's creation of it is a file lock any
// process on the host takes — a second holder waits until the first lets go,
// the startup sweep's try finds it held, and a release frees it once however
// often it is called.
func TestNetworkLockIsHostWide(t *testing.T) {
	name := "cloop-sbx-locktest-p" + tenantTag("project:"+t.TempDir())
	t.Cleanup(func() { _ = os.Remove(netLockPath(name)) })
	unlock, err := lockNetwork(t.Context(), name)
	if err != nil {
		t.Fatalf("lockNetwork: %v", err)
	}
	if again, ok := tryLockNetwork(name); ok {
		again()
		t.Fatal("a second holder took a held network lock")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
	defer cancel()
	if _, err := lockNetwork(ctx, name); err == nil {
		t.Fatal("a waiting holder took a held lock before its deadline")
	}
	unlock()
	unlock()
	again, ok := tryLockNetwork(name)
	if !ok {
		t.Fatal("the lock was not free after its release")
	}
	again()
	if _, err := lockNetwork(t.Context(), "-not a network"); err == nil {
		t.Error("a lock was taken for a name no network may have")
	}
}
