package netfilter

// Sandboxes of different projects on one host never reach each other through
// it (Task 20502). The container driver puts every project's sandbox on a
// bridge of its own, named so one pattern matches all of them, and each
// sandbox's host-side ruleset refuses traffic between its bridge and any
// other the pattern matches — both ways, ahead of every allow, so an allow
// list that happens to cover an engine's subnet pool (10.0.0.0/8 for a
// corporate network) does not open one project's sandbox to another's.

import (
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"
)

const (
	testSandboxBridge = "clsb0123456789a"
	testSiblings      = "clsb*"
)

// containingPolicy allows a range that covers every engine's default subnet
// pools: the case in which only the sibling rules keep two sandboxes apart.
func containingPolicy(t *testing.T) Policy {
	t.Helper()
	return mustCompilePolicy(t, Input{
		AllowCIDRs: []netip.Prefix{
			netip.MustParsePrefix("10.0.0.0/8"),
			netip.MustParsePrefix("172.16.0.0/12"),
			netip.MustParsePrefix("192.168.0.0/16"),
		},
		AllowPorts:          []uint16{443, 8080},
		AllowPublicInternet: true,
		Resolvers:           []netip.AddrPort{netip.MustParseAddrPort("1.1.1.1:53")},
	})
}

func chainNamed(t *testing.T, script, name string) []string {
	t.Helper()
	for _, c := range splitChains(t, script) {
		if c.name == name {
			return strings.Split(strings.TrimSpace(c.body), "\n")
		}
	}
	t.Fatalf("no chain %q in:\n%s", name, script)
	return nil
}

func indexOfLine(lines []string, sub string) int {
	for i, l := range lines {
		if strings.Contains(l, sub) {
			return i
		}
	}
	return -1
}

// TestSiblingBridgesAreRefusedBothWays pins the forward chain's shape: the
// inbound refusal — of every connection opened into the bridge from any other
// interface — comes before the early return (such a packet is not this
// sandbox's, and would otherwise be handed back to the chain policy, accept),
// the outbound refusal comes before the first allow, and both spare the
// sandbox's own bridge and replies to what the sandbox opened.
func TestSiblingBridgesAreRefusedBothWays(t *testing.T) {
	out := mustRenderNft(t, containingPolicy(t), NftablesOptions{Table: "cloop_sbx_t", Bridge: testSandboxBridge,
		Siblings: testSiblings})
	forward := chainNamed(t, out, "forward")

	inbound := indexOfLine(forward, `oifname "`+testSandboxBridge+`" iifname != "`+testSandboxBridge+
		`" ct state { new, invalid, untracked } counter jump deny`)
	ret := indexOfLine(forward, `iifname != "`+testSandboxBridge+`" return`)
	invalid := indexOfLine(forward, "ct state invalid counter drop")
	outbound := indexOfLine(forward, `oifname "clsb*" oifname != "`+testSandboxBridge+`" counter jump deny`)
	firstAllow := -1
	for i, l := range forward {
		if strings.Contains(l, "ct state established") {
			continue
		}
		if strings.HasSuffix(strings.TrimSpace(l), "accept") || strings.Contains(l, " accept ") {
			firstAllow = i
			break
		}
	}
	switch {
	case inbound < 0:
		t.Fatalf("the forward chain does not refuse connections opened into this sandbox from elsewhere:\n%s", out)
	case outbound < 0:
		t.Fatalf("the forward chain does not refuse this sandbox sending to another's bridge:\n%s", out)
	case ret < 0 || invalid < 0 || firstAllow < 0:
		t.Fatalf("the forward chain lost its scaffolding:\n%s", out)
	}
	if inbound > ret {
		t.Errorf("the inbound refusal (line %d) sits after the early return (line %d), which hands another "+
			"sandbox's packet back to the chain policy before it is seen:\n%s", inbound, ret, out)
	}
	if outbound < invalid || outbound > firstAllow {
		t.Errorf("the outbound refusal (line %d) is not between the conntrack rules (line %d) and the first "+
			"allow (line %d), so an allow could open another project's sandbox:\n%s", outbound, invalid, firstAllow, out)
	}

	// Only the forward hook routes between bridges: the input hook delivers to
	// this host, which is no sandbox, and carries neither rule.
	for _, l := range chainNamed(t, out, "input") {
		if strings.Contains(l, testSiblings) {
			t.Errorf("the input chain carries a sibling rule: %q", l)
		}
	}
}

// TestSiblingRulesLogOnlyWhatTheSandboxSent: the outbound refusal is one of
// this sandbox's deny paths and is logged ahead of its verdict under the peer
// tag; the inbound one refuses someone else's packet, and logging it under
// this rule set would file the attempt against the wrong run.
func TestSiblingRulesLogOnlyWhatTheSandboxSent(t *testing.T) {
	out := mustRenderNft(t, containingPolicy(t), NftablesOptions{Table: "cloop_sbx_t", Bridge: testSandboxBridge,
		Siblings: testSiblings, Log: testLog})
	forward := chainNamed(t, out, "forward")
	outbound := indexOfLine(forward, `oifname "clsb*" oifname != "`+testSandboxBridge+`" counter jump deny`)
	if outbound < 1 {
		t.Fatalf("no outbound sibling refusal:\n%s", out)
	}
	m := logLine.FindStringSubmatch(forward[outbound-1])
	if m == nil {
		t.Fatalf("the outbound sibling refusal is not preceded by its log statement: %q", forward[outbound-1])
	}
	if want := `oifname "clsb*" oifname != "` + testSandboxBridge + `"`; m[1] != want {
		t.Errorf("the log matches %q, the refusal %q", m[1], want)
	}
	if fp, tag, ok := ParseLogPrefix(m[2]); !ok || fp != testLog.Fingerprint || tag != TagPeer {
		t.Errorf("the outbound refusal logs under %q (%q, %q, %v), want the peer tag", m[2], fp, tag, ok)
	}
	inbound := indexOfLine(forward, `oifname "`+testSandboxBridge+`" iifname != "`+testSandboxBridge+`" ct state`)
	if inbound < 0 {
		t.Fatalf("no inbound refusal:\n%s", out)
	}
	if inbound > 0 && strings.Contains(forward[inbound-1], " log ") {
		t.Errorf("the inbound sibling refusal is logged under this rule set: %q", forward[inbound-1])
	}
	if strings.Contains(forward[inbound], " log ") {
		t.Errorf("the inbound sibling refusal carries a log statement: %q", forward[inbound])
	}
}

// TestNoSiblingsRendersNoSiblingRule: the option is the only thing that puts
// the rule in, and the in-namespace form, which has no bridge, refuses it.
func TestNoSiblingsRendersNoSiblingRule(t *testing.T) {
	out := mustRenderNft(t, containingPolicy(t), NftablesOptions{Table: "cloop_sbx_t", Bridge: testSandboxBridge})
	if strings.Contains(out, "another sandbox") || strings.Contains(out, "clsb*") {
		t.Errorf("a ruleset rendered without siblings refuses them anyway:\n%s", out)
	}
	if _, err := RenderNftables(containingPolicy(t), NftablesOptions{Table: "cloop_sbx_t", Siblings: testSiblings}); err == nil {
		t.Error("the in-namespace form accepted a sibling pattern it has no bridge to apply it to")
	}
	for _, bad := range []string{"*", "clsb**", "cl*sb", "clsb\"*", "clsb 1*", "abcdefghijklmnop*"} {
		if _, err := RenderNftables(containingPolicy(t), NftablesOptions{Table: "cloop_sbx_t", Bridge: testSandboxBridge,
			Siblings: bad}); err == nil {
			t.Errorf("RenderNftables accepted the sibling pattern %q", bad)
		}
	}
}

func TestValidateInterfacePattern(t *testing.T) {
	for _, ok := range []string{"clsb*", "clsb0123456789a", "br-*", "a*", "abcdefghijklmn*"} {
		if err := ValidateInterfacePattern(ok); err != nil {
			t.Errorf("ValidateInterfacePattern(%q) = %v", ok, err)
		}
	}
	for _, bad := range []string{"", "*", "**", "a**", "*a", "a*b", "abcdefghijklmno*", "abcdefghijklmnop",
		"a b*", "a\"*", "a;*"} {
		if err := ValidateInterfacePattern(bad); err == nil {
			t.Errorf("ValidateInterfacePattern(%q) accepted it", bad)
		}
	}
}

func TestPeerTagParses(t *testing.T) {
	kind, prefix, ok := ParseTag(TagPeer)
	if !ok || kind != TagPeer || prefix.IsValid() {
		t.Errorf("ParseTag(%q) = %q, %v, %v", TagPeer, kind, prefix, ok)
	}
	s, err := LogPrefix("0123456789ab", TagPeer)
	if err != nil {
		t.Fatalf("LogPrefix(peer): %v", err)
	}
	if fp, tag, ok := ParseLogPrefix(s); !ok || fp != "0123456789ab" || tag != TagPeer {
		t.Errorf("ParseLogPrefix(%q) = %q, %q, %v", s, fp, tag, ok)
	}
	for _, bad := range []string{"peer:10.0.0.0/8", "peers", "Peer"} {
		if _, _, ok := ParseTag(bad); ok {
			t.Errorf("ParseTag(%q) accepted it", bad)
		}
	}
}

// TestSiblingRulesetParsesWithNft hands the sibling form to the real nft(8)
// in check mode: two oifname matches in one rule, an iifname inequality and a
// wildcard are each something nft could refuse, and a refused script fails the
// whole transaction — the sandbox would not start. Needs root.
func TestSiblingRulesetParsesWithNft(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("nft -c needs CAP_NET_ADMIN")
	}
	if _, err := exec.LookPath("nft"); err != nil {
		t.Skip("nft(8) is not installed")
	}
	if err := exec.Command("nft", "list", "tables").Run(); err != nil {
		t.Skipf("nft cannot list tables here: %v", err)
	}
	for name, opts := range map[string]NftablesOptions{
		"siblings":     {Table: "cloop_t20502_check", Bridge: testSandboxBridge, Siblings: testSiblings},
		"siblings+log": {Table: "cloop_t20502_check", Bridge: testSandboxBridge, Siblings: testSiblings, Log: testLog},
	} {
		script := mustRenderNft(t, containingPolicy(t), opts)
		cmd := exec.Command("nft", "-c", "-f", "-")
		cmd.Stdin = strings.NewReader(script)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Errorf("%s: nft -c refused the ruleset: %v\n%s\n%s", name, err, out, script)
		}
	}
}

// TestInboundGuardAloneLeavesEgressOpen: the ruleset an unfiltered sandbox
// network gets refuses every connection opened into its bridge from anywhere
// else, governs nothing the sandbox sends, and never drops by policy.
func TestInboundGuardAloneLeavesEgressOpen(t *testing.T) {
	out, err := RenderInboundGuard(NftablesOptions{Table: "cloop_sbx_t", Bridge: testSandboxBridge})
	if err != nil {
		t.Fatalf("RenderInboundGuard: %v", err)
	}
	forward := chainNamed(t, out, "forward")
	if len(forward) != 2 || !strings.Contains(forward[0], "policy accept;") ||
		!strings.Contains(forward[1], `oifname "`+testSandboxBridge+`" iifname != "`+testSandboxBridge+
			`" ct state { new, invalid, untracked } counter jump deny`) {
		t.Errorf("the guard's forward chain is not the policy and the inbound refusal alone:\n%s", out)
	}
	if strings.Contains(out, "policy drop") || strings.Contains(out, "hook input") || strings.Contains(out, "hook output") {
		t.Errorf("the guard governs more than connections into the sandbox:\n%s", out)
	}
	for _, bad := range []NftablesOptions{{Table: "cloop_sbx_t"}, {Bridge: testSandboxBridge}, {Table: "x y", Bridge: testSandboxBridge}} {
		if _, err := RenderInboundGuard(bad); err == nil {
			t.Errorf("RenderInboundGuard(%+v) rendered", bad)
		}
	}
	if os.Geteuid() == 0 && exec.Command("nft", "list", "tables").Run() == nil {
		cmd := exec.Command("nft", "-c", "-f", "-")
		cmd.Stdin = strings.NewReader(out)
		if b, err := cmd.CombinedOutput(); err != nil {
			t.Errorf("nft -c refused the guard: %v\n%s\n%s", err, b, out)
		}
	}
}
