package netfilter

import (
	"net/netip"
	"strings"
	"testing"
)

// nftables_test.go guards the properties of the rendered script that a human
// reading it would not notice were missing.
//
// A firewall renderer fails quietly. A dropped rule, a chain policy that reads
// "accept" where it should read "drop", a comment that ends its own string —
// none of these produce an error, and all of them produce a sandbox with more
// reach than its authorisation. So the assertions here are about the shape of
// the emitted text rather than about whether rendering succeeded.

// mustCompilePolicy compiles an authorisation or fails the test.
func mustCompilePolicy(t *testing.T, in Input) Policy {
	t.Helper()
	p, err := Compile(in)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	return p
}

// mustRenderNft renders a policy or fails the test.
func mustRenderNft(t *testing.T, p Policy, opts NftablesOptions) string {
	t.Helper()
	out, err := RenderNftables(p, opts)
	if err != nil {
		t.Fatalf("RenderNftables: %v", err)
	}
	return out
}

// widePolicyForNft is the widest shape the compiler emits: granted CIDRs in
// both families, a broker, a resolver and the public-Internet allow. Rendering
// the widest policy is what makes the rule-coverage checks meaningful — a
// narrow one would not exercise the /0 or IPv6 paths at all.
func widePolicyForNft(t *testing.T) Policy {
	t.Helper()
	return mustCompilePolicy(t, Input{
		AllowCIDRs:          []netip.Prefix{netip.MustParsePrefix("10.8.0.0/24"), netip.MustParsePrefix("2001:db8::/32")},
		AllowPorts:          []uint16{443, 6443},
		Brokers:             []netip.AddrPort{netip.MustParseAddrPort("10.7.0.2:8118")},
		Resolvers:           []netip.AddrPort{netip.MustParseAddrPort("10.7.0.10:53")},
		AllowPublicInternet: true,
		HostPatterns:        []string{"*.github.com"},
	})
}

// nftLinesWith returns every rendered line containing sub.
func nftLinesWith(out, sub string) []string {
	var hits []string
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, sub) {
			hits = append(hits, line)
		}
	}
	return hits
}

// nftAddressMatch re-derives, independently of the renderer, the address
// expression a rule has to carry. Deriving it here rather than calling
// renderNftRule is the point: a test that asks the renderer what it rendered
// cannot catch the renderer dropping a rule.
func nftAddressMatch(r Rule) string {
	family, nfproto := "ip", "ipv4"
	if !r.Prefix.Addr().Is4() {
		family, nfproto = "ip6", "ipv6"
	}
	if r.Prefix.Bits() == 0 {
		return "meta nfproto " + nfproto
	}
	return family + " daddr " + r.Prefix.String()
}

// nftCommentText extracts the text inside a rule's comment "...".
func nftCommentText(t *testing.T, line string) string {
	t.Helper()
	const open = "comment \""
	i := strings.Index(line, open)
	if i < 0 {
		t.Fatalf("no comment in rule line %q", line)
	}
	rest := line[i+len(open):]
	j := strings.LastIndex(rest, "\"")
	if j < 0 {
		t.Fatalf("unterminated comment in rule line %q", line)
	}
	return rest[:j]
}

// TestBridgeChainPolicyIsAcceptAndDropsExplicitly is the single most dangerous
// thing this renderer could get wrong.
//
// The host-side form hangs a base chain on the forward hook, and every base
// chain on a hook runs — a drop in any of them kills the packet. So a `policy
// drop` here would not firewall one sandbox, it would take down every other
// container on the host and any routing the host does, and it would do it the
// moment a single task started. The safe construction is the opposite: accept
// as the policy, an immediate `return` for traffic that did not come from this
// sandbox's bridge (return from a base chain applies the policy, which is
// accept), and an explicit terminal drop that only this sandbox's packets can
// ever reach.
func TestBridgeChainPolicyIsAcceptAndDropsExplicitly(t *testing.T) {
	out := mustRenderNft(t, widePolicyForNft(t), NftablesOptions{Table: "cloop_sbx", Bridge: "br-abc123"})

	if !strings.Contains(out, "type filter hook forward priority 0; policy accept;") {
		t.Errorf("bridge forward chain does not use policy accept:\n%s", out)
	}
	if strings.Contains(out, "policy drop;") {
		t.Errorf("bridge form contains a policy drop chain — it would drop the host's own traffic:\n%s", out)
	}
	if !strings.Contains(out, `iifname != "br-abc123" return`) {
		t.Errorf("bridge form does not return early for traffic from other interfaces:\n%s", out)
	}
	if !strings.Contains(out, "counter drop comment \"default deny\"") {
		t.Errorf("bridge form has no explicit terminal drop:\n%s", out)
	}

	// The terminal drop has to be the *last* rule: a rule after it would be
	// unreachable, and a rule before it that the drop was meant to cover
	// would be a hole. Both are ordering bugs a substring check misses.
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) < 3 {
		t.Fatalf("rendered script is too short:\n%s", out)
	}
	if got := strings.TrimSpace(lines[len(lines)-1]); got != "}" {
		t.Errorf("script does not end by closing the table, got %q", got)
	}
	if got := strings.TrimSpace(lines[len(lines)-2]); got != "}" {
		t.Errorf("script does not end by closing the chain, got %q", got)
	}
	if got := strings.TrimSpace(lines[len(lines)-3]); !strings.HasPrefix(got, "counter drop") {
		t.Errorf("last rule in the forward chain is %q, want an explicit counter drop", got)
	}
}

// TestNamespaceChainsAllDefaultToDrop: inside the sandbox's own namespace
// there is no other traffic to be careful of, so the default has to be deny in
// all three directions. An accept default on any one of them turns the rule
// list from an allowlist into a set of suggestions — output would leak egress,
// input would let anything on the bridge reach into the sandbox, and forward
// would let a sandbox with two interfaces bridge two networks an operator kept
// apart on purpose.
func TestNamespaceChainsAllDefaultToDrop(t *testing.T) {
	out := mustRenderNft(t, widePolicyForNft(t), NftablesOptions{Table: "cloop_sbx"})

	for _, hook := range []string{"output", "input", "forward"} {
		want := "type filter hook " + hook + " priority 0; policy drop;"
		if !strings.Contains(out, want) {
			t.Errorf("in-namespace %s chain is missing %q:\n%s", hook, want, out)
		}
	}
	if strings.Contains(out, "policy accept;") {
		t.Errorf("an in-namespace chain defaults to accept:\n%s", out)
	}
}

// TestLoopbackAllowIsNamespaceOnly: a packet addressed to 127.0.0.1 never
// crosses a bridge, so a loopback accept in the host-side forward chain would
// not be harmless clutter. It would read — and to a reviewer, mean — "packets
// from this sandbox may be forwarded to the host's loopback", which is the
// opposite of what the filter is for. Inside the sandbox's own namespace the
// same rule is mandatory, because there the only thing on 127.0.0.0/8 is the
// sandbox itself and a harness that binds a local port breaks without it.
func TestLoopbackAllowIsNamespaceOnly(t *testing.T) {
	p := widePolicyForNft(t)
	bridge := mustRenderNft(t, p, NftablesOptions{Table: "cloop_sbx", Bridge: "br-abc123"})
	namespace := mustRenderNft(t, p, NftablesOptions{Table: "cloop_sbx"})

	for _, loop := range []string{"127.0.0.0/8", "::1/128"} {
		for _, line := range nftLinesWith(bridge, loop) {
			if strings.Contains(line, "accept") {
				t.Errorf("bridge form accepts %s: %q", loop, strings.TrimSpace(line))
			}
		}
		// The block-set drop for loopback is ScopeWire and must survive.
		if len(nftLinesWith(bridge, loop)) == 0 {
			t.Errorf("bridge form mentions %s nowhere; the block-set drop went missing", loop)
		}

		var accepted bool
		for _, line := range nftLinesWith(namespace, loop) {
			if strings.Contains(line, "counter accept") {
				accepted = true
			}
		}
		if !accepted {
			t.Errorf("in-namespace form has no accept for %s; a harness binding a local port would break", loop)
		}
	}
}

// TestIdempotencyPreambleOrder: the script is applied with `nft -f`, which
// commits as one transaction. add-then-delete-then-create is what makes a
// re-apply safe — `add table` on an existing table is a no-op, so the delete
// never fails on a first run, and the delete makes the replacement atomic so
// there is no instant at which the sandbox runs under half a ruleset. Get the
// order wrong and either the first apply errors out or a re-apply appends its
// rules to the previous ones.
func TestIdempotencyPreambleOrder(t *testing.T) {
	out := mustRenderNft(t, widePolicyForNft(t), NftablesOptions{Table: "cloop_sbx"})

	add := strings.Index(out, "add table inet cloop_sbx\n")
	del := strings.Index(out, "delete table inet cloop_sbx\n")
	create := strings.Index(out, "table inet cloop_sbx {\n")
	if add < 0 || del < 0 || create < 0 {
		t.Fatalf("preamble incomplete (add=%d delete=%d create=%d):\n%s", add, del, create, out)
	}
	if !(add < del && del < create) {
		t.Errorf("preamble out of order: add=%d delete=%d create=%d", add, del, create)
	}
}

// TestEveryWireRuleIsRendered is the anti-drift check. A renderer that skips a
// rule produces a script that installs cleanly and reads plausibly, and the
// only symptom is that some address the compiler decided to drop is reachable.
// So every ScopeWire rule the compiler produced is looked up in the output by
// an address expression derived here, not by asking the renderer.
func TestEveryWireRuleIsRendered(t *testing.T) {
	p := widePolicyForNft(t)
	for name, opts := range map[string]NftablesOptions{
		"bridge":    {Table: "cloop_sbx", Bridge: "br-abc123"},
		"namespace": {Table: "cloop_sbx"},
	} {
		t.Run(name, func(t *testing.T) {
			out := mustRenderNft(t, p, opts)
			for i, r := range p.WireOnly().Rules {
				match := nftAddressMatch(r)
				lines := nftLinesWith(out, match)
				if len(lines) == 0 {
					t.Errorf("rule %d (%s) is not in the rendered script: no line matches %q", i, r, match)
					continue
				}
				// The verdict has to be on the same line, or the rule was
				// rendered as something other than what it means. nft spells
				// an allow "accept".
				want := "counter drop"
				if r.Verdict == VerdictAllow {
					want = "counter accept"
				}
				var found bool
				for _, line := range lines {
					if strings.Contains(line, want) {
						found = true
					}
				}
				if !found {
					t.Errorf("rule %d (%s) renders without %q:\n%s", i, r, want, strings.Join(lines, "\n"))
				}
			}
		})
	}
}

// TestAddressFamilyIsAlwaysExplicit: the ruleset lives in an inet table, where
// a rule with no family word matches both families. That is how a v4 drop
// silently fails to cover the v6 address behind the same name, and an AAAA
// record becomes the whole firewall bypassed. A /0 gets `meta nfproto` rather
// than `daddr 0.0.0.0/0` for the same reason plus a practical one: some
// kernels reject the all-zero address match outright, which would fail the
// entire transaction and leave the sandbox with no filter at all.
func TestAddressFamilyIsAlwaysExplicit(t *testing.T) {
	out := mustRenderNft(t, widePolicyForNft(t), NftablesOptions{Table: "cloop_sbx"})

	if !strings.Contains(out, "ip daddr 10.8.0.0/24") {
		t.Errorf("IPv4 rule does not use `ip daddr`:\n%s", out)
	}
	if !strings.Contains(out, "ip6 daddr 2001:db8::/32") {
		t.Errorf("IPv6 rule does not use `ip6 daddr`:\n%s", out)
	}
	if !strings.Contains(out, "meta nfproto ipv4") {
		t.Errorf("the v4 default route does not render as `meta nfproto ipv4`:\n%s", out)
	}
	if !strings.Contains(out, "meta nfproto ipv6") {
		t.Errorf("the v6 default route does not render as `meta nfproto ipv6`:\n%s", out)
	}
	for _, bad := range []string{"daddr 0.0.0.0/0", "daddr ::/0"} {
		if strings.Contains(out, bad) {
			t.Errorf("a /0 rendered as %q; some kernels reject it and take the transaction with it", bad)
		}
	}
	// Every address match carries a family word.
	for _, line := range nftLinesWith(out, "daddr") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "ip daddr ") && !strings.HasPrefix(trimmed, "ip6 daddr ") {
			t.Errorf("rule without an explicit address family: %q", trimmed)
		}
	}
}

// TestCommentInjectionCannotEscapeTheString is an injection boundary, not a
// cosmetic one. A rule's Reason is assembled from operator input — a granted
// CIDR's reason quotes the block-set entry it waives — and it lands inside a
// double-quoted nft comment in a script handed to a root-privileged `nft -f`.
// A reason carrying a quote could close the string, a `;` or a newline could
// start a new statement, and `#` could comment out the rest of the line
// including a drop. So the test asserts two things: none of those characters
// survive into the comment, and the injected text could not add or remove a
// single line of the script.
func TestCommentInjectionCannotEscapeTheString(t *testing.T) {
	const nasty = "waives \"private\"; counter accept comment \"pwned\"\n\t\tip daddr 0.0.0.0/0 counter accept # }"

	shape := func(reason string) Policy {
		return Policy{
			Mode: ModeFiltered,
			Rules: []Rule{{
				Verdict: VerdictAllow,
				Prefix:  netip.MustParsePrefix("203.0.113.0/24"),
				Ports:   []uint16{443},
				Proto:   ProtoTCP,
				Reason:  reason,
			}},
		}
	}
	opts := NftablesOptions{Table: "cloop_sbx"}
	benign := mustRenderNft(t, shape("granted CIDR"), opts)
	injected := mustRenderNft(t, shape(nasty), opts)

	if a, b := strings.Count(benign, "\n"), strings.Count(injected, "\n"); a != b {
		t.Errorf("injected reason changed the line count: %d vs %d\n%s", a, b, injected)
	}
	if a, b := len(nftLinesWith(benign, "daddr")), len(nftLinesWith(injected, "daddr")); a != b {
		t.Errorf("injected reason changed the number of address-matching rules: %d vs %d\n%s", a, b, injected)
	}

	lines := nftLinesWith(injected, "203.0.113.0/24")
	if len(lines) != 1 {
		t.Fatalf("want exactly one rule for the injected policy, got %d:\n%s", len(lines), injected)
	}
	comment := nftCommentText(t, lines[0])
	for _, bad := range []string{"\"", "\n", "\r", ";", "{", "}", "#", "\\"} {
		if strings.Contains(comment, bad) {
			t.Errorf("comment %q still contains %q — it can escape the string or the line", comment, bad)
		}
	}
	// The surviving text is inert prose, so the rule still says what it said.
	if !strings.Contains(comment, "waives") {
		t.Errorf("escaping destroyed the reason entirely: %q", comment)
	}
}

// TestOverlongCommentIsTruncated: nft's comment limit is 128 bytes and it
// rejects a longer one — not the rule, the whole `nft -f` transaction. A
// verbose reason (a warning about a long CIDR list, say) would therefore leave
// the sandbox with no firewall at all rather than with an ugly comment.
func TestOverlongCommentIsTruncated(t *testing.T) {
	long := strings.TrimSpace(strings.Repeat("blocked-range ", 20)) // ~279 bytes
	if len(long) < 200 {
		t.Fatalf("test fixture is only %d bytes, want >200", len(long))
	}
	out := mustRenderNft(t, Policy{Rules: []Rule{{
		Verdict: VerdictDrop,
		Prefix:  netip.MustParsePrefix("203.0.113.0/24"),
		Reason:  long,
	}}}, NftablesOptions{Table: "cloop_sbx"})

	lines := nftLinesWith(out, "203.0.113.0/24")
	if len(lines) != 1 {
		t.Fatalf("want one rule, got %d:\n%s", len(lines), out)
	}
	comment := nftCommentText(t, lines[0])
	if len(comment) >= 128 {
		t.Errorf("comment is %d bytes; nft rejects the transaction above 128", len(comment))
	}
	if !strings.HasSuffix(comment, "...") {
		t.Errorf("truncated comment %q does not say it was truncated", comment)
	}
}

// TestWarningsAreRenderedAsComments: a Policy's warnings record where the
// filter is necessarily wider than the authorisation it came from — most
// importantly that a hostname allowlist became "the whole public Internet". An
// operator reads the ruleset, not the compiler's return value, so a warning
// that does not reach the script is a widening nobody was told about.
func TestWarningsAreRenderedAsComments(t *testing.T) {
	p := mustCompilePolicy(t, Input{
		AllowPublicInternet: true,
		AllowPorts:          []uint16{443},
		HostPatterns:        []string{"*.github.com"},
	})
	if len(p.Warnings) == 0 {
		t.Fatal("fixture produced no warnings")
	}
	out := mustRenderNft(t, p, NftablesOptions{Table: "cloop_sbx"})

	var rendered []string
	for _, line := range nftLinesWith(out, "# WARNING: ") {
		rendered = append(rendered, strings.TrimPrefix(strings.TrimSpace(line), "# WARNING: "))
	}
	if len(rendered) == 0 {
		t.Fatalf("no `# WARNING:` lines in the script:\n%s", out)
	}
	joined := strings.Join(rendered, " ")
	for _, w := range p.Warnings {
		// wrapComment re-flows on whitespace, so compare against the
		// whitespace-normalised warning.
		want := strings.Join(strings.Fields(w), " ")
		if !strings.Contains(joined, want) {
			t.Errorf("warning did not survive rendering:\nwant %q\n got %q", want, joined)
		}
	}
	if !strings.Contains(joined, "*.github.com") {
		t.Errorf("the host allowlist that could not be enforced is not named in the script:\n%s", joined)
	}
}

// TestRenderNftablesRefusesUnsafeNames: the table and bridge names are pasted
// into a script executed by `nft -f` as root. Rendering an unvalidated name
// would turn "the runtime told us the bridge is called X" into arbitrary
// firewall statements on the host, so the refusal has to happen in the
// renderer rather than in whichever caller remembered to check.
func TestRenderNftablesRefusesUnsafeNames(t *testing.T) {
	p := mustCompilePolicy(t, Input{})
	for name, opts := range map[string]NftablesOptions{
		"empty table":     {Table: ""},
		"table with ;":    {Table: "cloop; flush ruleset"},
		"table with a /":  {Table: "cloop/evil"},
		"bad bridge":      {Table: "cloop_sbx", Bridge: "br0; flush ruleset"},
		"bridge with $":   {Table: "cloop_sbx", Bridge: "br$IFS"},
		"overlong bridge": {Table: "cloop_sbx", Bridge: strings.Repeat("e", 16)},
	} {
		t.Run(name, func(t *testing.T) {
			out, err := RenderNftables(p, opts)
			if err == nil {
				t.Fatalf("RenderNftables accepted %+v and produced:\n%s", opts, out)
			}
			if out != "" {
				t.Errorf("RenderNftables returned a script alongside its error:\n%s", out)
			}
		})
	}
}

// TestValidateNftName: the grammar is deliberately narrower than nft's,
// because cloop generates these names — anything outside [A-Za-z0-9_-] is a
// bug or an injection attempt, never a use case. A leading '-' is rejected
// separately: nft would read it as the start of an option.
func TestValidateNftName(t *testing.T) {
	bad := map[string]string{
		"empty":       "",
		"too long":    strings.Repeat("a", nftMaxNameLen+1),
		"leading -":   "-cloop",
		"space":       "cloop sbx",
		"semicolon":   "cloop;flush",
		"quote":       "cloop\"x",
		"newline":     "cloop\nflush ruleset",
		"dollar":      "cloop$IFS",
		"slash":       "cloop/sbx",
		"backtick":    "cloop`id`",
		"brace":       "cloop{}",
		"hash":        "cloop#x",
		"unicode dot": "cloop.sbx",
	}
	for name, in := range bad {
		if err := ValidateNftName(in); err == nil {
			t.Errorf("%s: ValidateNftName(%q) accepted an unsafe name", name, in)
		}
	}
	good := []string{
		"cloop",
		"cloop_sbx",
		"cloop-sbx",
		"cloop_sbx-01",
		"A9",
		strings.Repeat("a", nftMaxNameLen), // the boundary is inclusive
	}
	for _, in := range good {
		if err := ValidateNftName(in); err != nil {
			t.Errorf("ValidateNftName(%q) = %v, want accepted", in, err)
		}
	}
}

// TestValidateInterfaceName: unlike a table name, this one can come from a
// container runtime's output rather than from cloop, so it is the more likely
// of the two to carry something unexpected. The 15-byte bound is IFNAMSIZ - 1:
// a longer name is not a name the kernel could have produced, which makes it a
// name somebody made up.
func TestValidateInterfaceName(t *testing.T) {
	bad := map[string]string{
		"empty":     "",
		"too long":  strings.Repeat("e", 16),
		"space":     "br 0",
		"semicolon": "br0;flush ruleset",
		"quote":     "br0\"",
		"newline":   "br0\nflush ruleset",
		"dollar":    "br$IFS",
		"slash":     "../br0",
		"backtick":  "br`id`",
		"brace":     "br{0}",
		"hash":      "br0#",
		"asterisk":  "br*",
	}
	for name, in := range bad {
		if err := ValidateInterfaceName(in); err == nil {
			t.Errorf("%s: ValidateInterfaceName(%q) accepted an unsafe name", name, in)
		}
	}
	good := []string{
		"br-abc123",
		"eth0.5", // a VLAN subinterface is a real name and must keep working
		"lo",
		"veth_0",
		strings.Repeat("e", 15), // IFNAMSIZ - 1, the boundary is inclusive
	}
	for _, in := range good {
		if err := ValidateInterfaceName(in); err != nil {
			t.Errorf("ValidateInterfaceName(%q) = %v, want accepted", in, err)
		}
	}
}

// TestBridgeFormFiltersBothHooks is a regression test for a hole found by
// running the filter against a real container on a real bridge.
//
// A ruleset with only a forward chain filters the Internet and leaves the
// host wide open. The routing decision picks the hook: a destination the host
// forwards on reaches the forward hook, but a destination that *is* the host
// — the bridge gateway, or anything bound on any of its interfaces — reaches
// the input hook instead. With one chain, a sandbox could still open a
// connection to a service on the host's RFC1918 bridge address while the
// policy said 10.0.0.0/8 and 172.16.0.0/12 were dropped. That is exactly the
// lateral movement egressbroker.BlockReason refuses, so the packet filter has
// to refuse it too.
//
// Verified by hand before and after the fix: a listener bound to the bridge
// gateway was reachable from inside the sandbox with one chain and timed out
// with two.
func TestBridgeFormFiltersBothHooks(t *testing.T) {
	p, err := Compile(Input{
		AllowCIDRs: []netip.Prefix{netip.MustParsePrefix("1.1.1.1/32")},
		AllowPorts: []uint16{443},
	})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	out, err := RenderNftables(p, NftablesOptions{Table: "cloop_t", Bridge: "br-abc123"})
	if err != nil {
		t.Fatalf("RenderNftables: %v", err)
	}

	for _, hook := range []string{"hook forward", "hook input"} {
		if !strings.Contains(out, hook) {
			t.Errorf("the bridge form has no %s chain:\n%s", hook, out)
		}
	}

	// Both chains have to carry the block set, not just one: a drop that
	// exists only in the forward chain does not protect the host.
	for _, chain := range splitChains(t, out) {
		if !strings.Contains(chain.body, "iifname != \"br-abc123\" return") {
			t.Errorf("chain %s does not scope itself to the sandbox bridge:\n%s", chain.name, chain.body)
		}
		for _, blocked := range []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.169.254/32"} {
			if !strings.Contains(chain.body, blocked+" counter drop") {
				t.Errorf("chain %s does not drop %s — a sandbox could reach it on that hook",
					chain.name, blocked)
			}
		}
		if !strings.Contains(chain.body, "counter drop comment \"default deny\"") {
			t.Errorf("chain %s has no terminal drop:\n%s", chain.name, chain.body)
		}
		// policy accept, never drop: base chains on one hook all run, and a
		// drop policy here would take down the host's own traffic and every
		// other container on it.
		if !strings.Contains(chain.body, "policy accept;") {
			t.Errorf("chain %s does not use policy accept:\n%s", chain.name, chain.body)
		}
	}
}

type namedChain struct {
	name string
	body string
}

// splitChains carves the rendered script into its chains so a test can assert
// per-chain rather than on the whole document, where a rule present in one
// chain would satisfy a check meant for both.
func splitChains(t *testing.T, script string) []namedChain {
	t.Helper()
	var out []namedChain
	var cur *namedChain
	for _, line := range strings.Split(script, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "chain ") && strings.HasSuffix(trimmed, "{") {
			name := strings.TrimSuffix(strings.TrimPrefix(trimmed, "chain "), " {")
			out = append(out, namedChain{name: name})
			cur = &out[len(out)-1]
			continue
		}
		if cur != nil {
			if trimmed == "}" {
				cur = nil
				continue
			}
			cur.body += trimmed + "\n"
		}
	}
	if len(out) == 0 {
		t.Fatalf("no chains parsed out of:\n%s", script)
	}
	return out
}
