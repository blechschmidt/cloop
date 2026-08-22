package container

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/netfilter"
)

// TestEgressFilterDefaultsToOff: enabling this on upgrade would firewall a
// running deployment, and the failure would read as a network outage rather
// than as a policy cloop applied on its own initiative.
func TestEgressFilterDefaultsToOff(t *testing.T) {
	var f EgressFilter
	if f.Enabled {
		t.Fatal("the zero EgressFilter is enabled")
	}
	if err := f.Validate(); err != nil {
		t.Fatalf("the zero EgressFilter does not validate: %v", err)
	}
	opts, err := Options{}.Normalize()
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	if opts.EgressFilter.Enabled {
		t.Error("the default Options enable an egress filter")
	}
}

// TestEnabledFilterMustAllowSomething: a filter that is on, is not internal
// and names no destination compiles to "drop everything", which is
// indistinguishable from a broken sandbox. Refusing it at configuration time
// puts the error where the operator can act on it.
func TestEnabledFilterMustAllowSomething(t *testing.T) {
	if err := (EgressFilter{Enabled: true}).Validate(); err == nil {
		t.Fatal("an enabled filter that allows nothing was accepted")
	}
	if err := (EgressFilter{Enabled: true, Internal: true}).Validate(); err != nil {
		t.Fatalf("an internal-only filter was refused: %v", err)
	}
}

// TestFilterWithNoNetworkIsRefused: "none" already means no interfaces, so a
// filter on top of it is a contradiction — and one that would leave an
// operator believing the CIDRs they listed are reachable.
func TestFilterWithNoNetworkIsRefused(t *testing.T) {
	_, err := Options{
		Network:      NetworkNone,
		EgressFilter: EgressFilter{Enabled: true, Internal: true},
	}.Normalize()
	if err == nil {
		t.Fatal("an egress filter combined with network \"none\" was accepted")
	}
	if !strings.Contains(err.Error(), "egress filter") {
		t.Errorf("error does not name the conflict: %v", err)
	}
}

// TestPolicyCompilesTheConfiguredAllowance walks the config-to-policy
// translation, because a silently-misparsed CIDR is a rule that matches
// nothing and a sandbox that cannot reach what it was granted.
func TestPolicyCompilesTheConfiguredAllowance(t *testing.T) {
	f := EgressFilter{
		Enabled:    true,
		AllowCIDRs: []string{"10.8.0.0/24"},
		AllowPorts: []int{443, 6443},
		Broker:     "10.7.0.2:8118",
		Resolvers:  []string{"10.7.0.10"},
	}
	if err := f.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	p, err := f.Policy()
	if err != nil {
		t.Fatalf("Policy: %v", err)
	}
	joined := renderRules(p)
	for _, want := range []string{"10.8.0.0/24", "10.7.0.2/32", "10.7.0.10/32"} {
		if !strings.Contains(joined, want) {
			t.Errorf("compiled policy is missing %s:\n%s", want, joined)
		}
	}
	// A bare resolver address means port 53. A broker endpoint has no
	// standard port, so it does not get the same courtesy — see parseEndpoint.
	if !strings.Contains(joined, "port 53") {
		t.Errorf("a resolver written without a port did not default to 53:\n%s", joined)
	}
}

func renderRules(p netfilter.Policy) string {
	var b strings.Builder
	for _, r := range p.Rules {
		b.WriteString(r.String())
		b.WriteString("\n")
	}
	return b.String()
}

// TestBrokerMustBeAnAddressLiteral: resolving a name at configuration time
// would pin whatever the DNS answered then, silently, forever — the rebinding
// hazard the broker's resolve-once discipline exists to avoid.
func TestBrokerMustBeAnAddressLiteral(t *testing.T) {
	f := EgressFilter{Enabled: true, Broker: "proxy.internal:8118"}
	if err := f.Validate(); err == nil {
		t.Fatal("a broker named by hostname was accepted")
	}
	if err := (EgressFilter{Enabled: true, Broker: "10.7.0.2"}).Validate(); err == nil {
		t.Fatal("a broker with no port was accepted")
	}
}

// TestBadConfigIsRefusedNotIgnored: every one of these would otherwise
// compile to a filter that allows less, or more, than the operator wrote.
func TestBadConfigIsRefusedNotIgnored(t *testing.T) {
	cases := map[string]EgressFilter{
		"malformed CIDR":         {Enabled: true, AllowCIDRs: []string{"10.8.0.0/33"}, AllowPorts: []int{443}},
		"not a CIDR at all":      {Enabled: true, AllowCIDRs: []string{"10.8.0.1"}, AllowPorts: []int{443}},
		"port out of range":      {Enabled: true, AllowCIDRs: []string{"10.8.0.0/24"}, AllowPorts: []int{70000}},
		"destinations, no ports": {Enabled: true, AllowCIDRs: []string{"10.8.0.0/24"}},
		"internet, no ports":     {Enabled: true, AllowPublicInternet: true},
		"a /0 waives everything": {Enabled: true, AllowCIDRs: []string{"0.0.0.0/0"}, AllowPorts: []int{443}},
		"bad resolver":           {Enabled: true, AllowCIDRs: []string{"10.8.0.0/24"}, AllowPorts: []int{443}, Resolvers: []string{"nope"}},
	}
	for name, f := range cases {
		if err := f.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// TestNetworkNameIsDerivedAndSafe: the name reaches the runtime CLI as an
// argument, and it has to be stable so a restart reuses the same bridge
// rather than leaking a new one on every boot.
func TestNetworkNameIsDerivedAndSafe(t *testing.T) {
	cases := map[string]string{
		"container":             "cloop-sbx-container",
		"Build Fleet":           "cloop-sbx-build-fleet",
		"a/../../etc":           "cloop-sbx-a-------etc",
		"":                      "cloop-sbx-default",
		"--dangerous":           "cloop-sbx-dangerous",
		strings.Repeat("x", 80): "cloop-sbx-" + strings.Repeat("x", 32),
	}
	for in, want := range cases {
		got := networkName(in)
		if got != want {
			t.Errorf("networkName(%q) = %q, want %q", in, got, want)
		}
		if err := validateNetworkName(got); err != nil {
			t.Errorf("networkName(%q) produced an invalid name: %v", in, err)
		}
	}
}

// TestValidateNetworkNameRejectsInjection: the name is passed to `docker
// network create` as argv, so a leading dash would become a flag and
// whitespace would become extra arguments.
func TestValidateNetworkNameRejectsInjection(t *testing.T) {
	for _, bad := range []string{
		"", "-rm", "a b", "a;rm -rf /", "a\nb", "a$(id)", "a/b", strings.Repeat("x", 129),
	} {
		if err := validateNetworkName(bad); err == nil {
			t.Errorf("validateNetworkName(%q) accepted", bad)
		}
	}
}

// TestTableNameIsStableAndValid: the table is deleted and recreated by name
// on every apply, so a name that drifted between runs would leave the old
// ruleset installed on a bridge nothing is filtering any more.
func TestTableNameIsStableAndValid(t *testing.T) {
	first := netfilter.TableName("sbx", "Build Fleet/1")
	second := netfilter.TableName("sbx", "Build Fleet/1")
	if first != second {
		t.Fatalf("TableName is not stable: %q vs %q", first, second)
	}
	if err := netfilter.ValidateNftName(first); err != nil {
		t.Fatalf("TableName produced an invalid nft identifier %q: %v", first, err)
	}
}

// TestPreflightWarnsAboutUnfilteredEgress: silence about egress reads as a
// constraint that is not there. An operator running an unfiltered bridge
// should be told before a harness runs on it with their credentials.
func TestPreflightWarnsAboutUnfilteredEgress(t *testing.T) {
	findings := func(opts Options) map[string]Finding {
		t.Helper()
		e := &Executor{id: "test", opts: mustNormalize(t, opts)}
		out := map[string]Finding{}
		e.preflightEgressFilter(context.Background(), func(name, level, msg, fix string) {
			out[name] = Finding{Name: name, Level: level, Message: msg, Fix: fix}
		})
		return out
	}

	if f := findings(Options{Network: NetworkBridge}); f["egress"].Level != LevelWarn {
		t.Errorf("an unfiltered bridge produced %q, want a warning", f["egress"].Level)
	}
	if f := findings(Options{Network: NetworkNone}); f["egress"].Level != LevelOK {
		t.Errorf("network \"none\" produced %q, want ok", f["egress"].Level)
	}
	f := findings(Options{
		Network:      NetworkBridge,
		EgressFilter: EgressFilter{Enabled: true, Internal: true},
	})
	if f["egress"].Level != LevelOK {
		t.Errorf("an internal filter produced %q, want ok", f["egress"].Level)
	}
	if !strings.Contains(f["egress"].Message, "internal") {
		t.Errorf("the internal-filter finding does not say so: %q", f["egress"].Message)
	}
}

// TestPreflightSurfacesTheWideningWarning: "*.github.com became the public
// Internet" is the single most important thing an operator can be told about
// a direct-egress filter, and burying it inside an OK line would hide it.
func TestPreflightSurfacesTheWideningWarning(t *testing.T) {
	if _, err := netfilter.NewApplier(); err != nil {
		t.Skipf("nft(8) is not installed: %v", err)
	}
	if os.Geteuid() != 0 {
		t.Skip("host packet filtering needs CAP_NET_ADMIN; skipping")
	}
	e := &Executor{id: "test", opts: mustNormalize(t, Options{
		Network: NetworkBridge,
		EgressFilter: EgressFilter{
			Enabled:             true,
			AllowPublicInternet: true,
			AllowPorts:          []int{443},
			HostPatterns:        []string{"*.github.com"},
		},
	})}
	var scoped []string
	e.preflightEgressFilter(context.Background(), func(name, level, msg, fix string) {
		if name == "egress-scope" && level == LevelWarn {
			scoped = append(scoped, msg)
		}
	})
	if len(scoped) == 0 {
		t.Fatal("no egress-scope warning for a host-pattern filter compiled to a public-Internet allow")
	}
	if !strings.Contains(strings.Join(scoped, " "), "*.github.com") {
		t.Errorf("the warning does not name the unenforced allowlist: %v", scoped)
	}
}

func mustNormalize(t *testing.T, o Options) Options {
	t.Helper()
	n, err := o.Normalize()
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	return n
}

// TestEnsureNetworkIsIdempotent runs against a real runtime: the second call
// must reuse the first network rather than fail, because Start calls this on
// every task and a hub that leaked a bridge per task would exhaust the host's
// address space in a day.
func TestEnsureNetworkIsIdempotent(t *testing.T) {
	rt, err := DetectRuntime("")
	if err != nil {
		if errors.Is(err, ErrNoRuntime) {
			t.Skip("no container runtime installed (podman/docker); skipping integration test")
		}
		t.Skipf("container runtime unavailable: %v", err)
	}
	ctx := context.Background()
	if res, err := runCLITimeout(ctx, rt, shortCmdTimeout, "info"); err != nil || res.ExitCode != 0 {
		t.Skipf("%s is installed but not responding; skipping", rt.Name)
	}

	e := &Executor{id: "fwtest", rt: rt, opts: mustNormalize(t, Options{Network: NetworkBridge})}
	name := networkName("cloop-selftest-" + t.Name())
	t.Cleanup(func() {
		_, _ = runCLITimeout(context.Background(), rt, shortCmdTimeout, "network", "rm", name)
	})

	bridge, err := e.ensureNetwork(ctx, name, true)
	if err != nil {
		t.Skipf("could not create a test network (the runtime may be unprivileged): %v", err)
	}
	if err := netfilter.ValidateInterfaceName(bridge); err != nil {
		t.Fatalf("ensureNetwork returned an unusable interface %q: %v", bridge, err)
	}
	again, err := e.ensureNetwork(ctx, name, true)
	if err != nil {
		t.Fatalf("second ensureNetwork failed instead of reusing the network: %v", err)
	}
	if again != bridge {
		t.Fatalf("ensureNetwork is not stable: %q then %q", bridge, again)
	}
}

// TestNetworkInspectionDecodesBothRuntimes is a regression test for a bug that
// unit tests could not have caught, because DetectRuntime prefers podman and
// the bug only appeared under docker.
//
// The original code asked for `--format '{{.Id}}|{{.NetworkInterface}}|
// {{.Internal}}'`. Naming a field a runtime does not have is a template
// *error*, not an empty string, so docker failed the whole inspect and the
// driver reported "network does not exist" for a network it had just created.
// Every sandbox on docker failed to start.
//
// The two runtimes share no spelling: docker capitalises and omits the
// interface entirely, podman lower-cases and names it something not derivable
// from the id ("podman1", not "br-<id>"). Both payloads below are real output.
func TestNetworkInspectionDecodesBothRuntimes(t *testing.T) {
	cases := map[string]struct {
		payload      string
		wantBridge   string
		wantInternal bool
	}{
		"docker": {
			payload: `{"Name":"cloop-sbx-x","Id":"1a1cf5b291364a963bc1d44c5a8e8a9ec95b39e60e38b7891a601c374f0b9e59",` +
				`"Internal":false,"Driver":"bridge"}`,
			wantBridge:   "br-1a1cf5b29136",
			wantInternal: false,
		},
		"docker internal": {
			payload: `{"Name":"cloop-sbx-x","Id":"1a1cf5b291364a963bc1d44c5a8e8a9ec95b39e60e38b7891a601c374f0b9e59",` +
				`"Internal":true}`,
			wantBridge:   "br-1a1cf5b29136",
			wantInternal: true,
		},
		"podman": {
			payload: `{"name":"cloop-sbx-x","id":"15ab2e1d8b12993d82a593f07b57a278d80c93f8972a053a482080dd021290b5",` +
				`"network_interface":"podman1","internal":false,"driver":"bridge"}`,
			wantBridge:   "podman1",
			wantInternal: false,
		},
		"podman internal": {
			payload: `{"name":"cloop-sbx-x","id":"15ab2e1d8b12993d82a593f07b57a278d80c93f8972a053a482080dd021290b5",` +
				`"network_interface":"podman2","internal":true}`,
			wantBridge:   "podman2",
			wantInternal: true,
		},
	}

	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			var got networkInspection
			if err := json.Unmarshal([]byte(c.payload), &got); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			bridge, internal := resolveInspection(got)
			if bridge != c.wantBridge {
				t.Errorf("bridge = %q, want %q", bridge, c.wantBridge)
			}
			if internal != c.wantInternal {
				t.Errorf("internal = %t, want %t", internal, c.wantInternal)
			}
		})
	}
}

// TestUnknownInternalReadsAsNotInternal: "internal" is a security claim — it
// means the kernel installs no route off this bridge. An answer this code
// could not parse must never be mistaken for one, because the caller would
// then skip installing the nftables rules that were the alternative.
func TestUnknownInternalReadsAsNotInternal(t *testing.T) {
	var got networkInspection
	if err := json.Unmarshal([]byte(`{"Id":"abcdef0123456789","Driver":"bridge"}`), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, internal := resolveInspection(got); internal {
		t.Fatal("a network that reported no internal flag was read as internal")
	}
}

// resolveInspection mirrors inspectNetwork's field selection so the decoding
// can be tested without a runtime. Kept next to the test it serves; the
// production path calls the same logic inline against live CLI output, and
// TestEnsureNetworkIsIdempotent covers that end.
func resolveInspection(got networkInspection) (bridge string, internal bool) {
	switch {
	case got.Internal != nil:
		internal = *got.Internal
	case got.InternalLower != nil:
		internal = *got.InternalLower
	}
	if iface := strings.TrimSpace(got.NetworkInterface); iface != "" {
		return iface, internal
	}
	id := strings.TrimSpace(got.ID)
	if id == "" {
		id = strings.TrimSpace(got.IDLower)
	}
	if len(id) < 12 {
		return "", internal
	}
	return "br-" + id[:12], internal
}
