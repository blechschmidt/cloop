package netfilter

import (
	"net/netip"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"
)

// refuse_test.go covers Task 20437's two changes to the rendered ruleset: a
// denied connection is refused rather than dropped, and every deny path logs,
// rate-limited, to the NFLOG group the installing process reads.

var testLog = &LogOptions{Group: 27437, Fingerprint: "0123456789ab"}

// denyRichPolicy has every kind of deny path the compiler emits: a deny list,
// a metadata service carved out of an allow, the block set, the translation
// prefixes and the implicit final deny.
func denyRichPolicy(t *testing.T) Policy {
	t.Helper()
	return mustCompilePolicy(t, Input{
		AllowCIDRs: []netip.Prefix{netip.MustParsePrefix("1.1.1.1/32"), netip.MustParsePrefix("169.254.0.0/16")},
		AllowPorts: []uint16{443},
		DenyCIDRs:  []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")},
		Resolvers:  []netip.AddrPort{netip.MustParseAddrPort("1.1.1.1:53")},
	})
}

// TestDeniesAreRefusedNotDropped: the workload's connect must fail at once.
// Every deny path jumps to the deny chain, the chain answers TCP with a reset
// and everything else with an ICMP "administratively prohibited", and nothing
// a sandbox sends is dropped on its way to a verdict except invalid packets,
// which are no connection attempt.
func TestDeniesAreRefusedNotDropped(t *testing.T) {
	p := denyRichPolicy(t)
	for name, opts := range map[string]NftablesOptions{
		"bridge":    {Table: "cloop_sbx", Bridge: "br-abc123"},
		"namespace": {Table: "cloop_sbx"},
	} {
		t.Run(name, func(t *testing.T) {
			out := mustRenderNft(t, p, opts)
			var deny *namedChain
			for _, c := range splitChains(t, out) {
				c := c
				if c.name == "deny" {
					deny = &c
				}
			}
			if deny == nil {
				t.Fatalf("no deny chain:\n%s", out)
			}
			lines := strings.Split(strings.TrimSpace(deny.body), "\n")
			if len(lines) != 2 ||
				!strings.HasPrefix(lines[0], "meta l4proto tcp reject with tcp reset") ||
				!strings.HasPrefix(lines[1], "reject with icmpx type admin-prohibited") {
				t.Errorf("deny chain does not refuse TCP with a reset and the rest with icmpx:\n%s", deny.body)
			}
			// What reaches a deny verdict any other way would be a silent
			// drop of something the sandbox sent.
			for _, line := range strings.Split(out, "\n") {
				l := strings.TrimSpace(line)
				if strings.Contains(l, " drop") && l != "ct state invalid counter drop" &&
					!strings.HasPrefix(l, "type filter hook input") && !strings.HasPrefix(l, "type filter hook forward") &&
					!strings.HasPrefix(l, "type filter hook output") && !strings.Contains(l, "a sandbox does not route") {
					t.Errorf("a sandbox's packet can still be dropped silently: %q", l)
				}
			}
			for _, r := range p.WireOnly().Rules {
				if r.Verdict == VerdictAllow {
					continue
				}
				if !strings.Contains(out, nftAddressMatch(r)+" counter jump deny") {
					t.Errorf("deny path %s does not jump to the deny chain", r)
				}
			}
		})
	}
}

// TestDropDeniedKeepsSilence: the rule-set option that keeps the old drop.
// Only the deny chain changes; every path still reaches it.
func TestDropDeniedKeepsSilence(t *testing.T) {
	p := denyRichPolicy(t)
	p.DropDenied = true
	out := mustRenderNft(t, p, NftablesOptions{Table: "cloop_sbx", Bridge: "br-abc123"})
	for _, c := range splitChains(t, out) {
		if c.name != "deny" {
			continue
		}
		if strings.Contains(c.body, "reject") || !strings.HasPrefix(strings.TrimSpace(c.body), "drop") {
			t.Errorf("a drop_denied policy still refuses:\n%s", c.body)
		}
	}
	if !strings.Contains(out, "counter jump deny comment \"default deny\"") {
		t.Errorf("the final deny no longer jumps to the deny chain:\n%s", out)
	}
	// WireOnly keeps the option: the bridge form renders from it.
	if !p.WireOnly().DropDenied {
		t.Error("WireOnly forgot DropDenied")
	}
	if c, err := Compile(Input{DropDenied: true}); err != nil || !c.DropDenied {
		t.Errorf("Compile(DropDenied) = %v, %v", c.DropDenied, err)
	}
}

// logLine matches one log statement as the renderer writes it.
var logLine = regexp.MustCompile(`^(.*?) ?limit rate 10/second burst 20 packets log prefix "([^"]+)" group 27437 snaplen 80$`)

// TestEveryDenyPathLogsAheadOfItsVerdict: each deny path is preceded by its
// own rate-limited log statement, matching exactly what the verdict line
// matches, under a prefix naming the rule set and the rule. A log after the
// verdict would never run; a log with a different match would name the wrong
// rule; a log carrying the verdict would let the rate limit decide the verdict.
func TestEveryDenyPathLogsAheadOfItsVerdict(t *testing.T) {
	p := denyRichPolicy(t)
	out := mustRenderNft(t, p, NftablesOptions{Table: "cloop_sbx", Bridge: "br-abc123", Log: testLog})

	for _, c := range splitChains(t, out) {
		if c.name == "deny" {
			if strings.Contains(c.body, " log ") {
				t.Errorf("the verdict chain logs; the paths jumping to it already have:\n%s", c.body)
			}
			continue
		}
		lines := strings.Split(strings.TrimSpace(c.body), "\n")
		seen := map[string]bool{}
		for i, l := range lines {
			if !strings.Contains(l, "jump deny") {
				if strings.Contains(l, " log ") && (strings.Contains(l, "accept") || strings.Contains(l, "jump")) {
					t.Errorf("a log statement carries a verdict: %q", l)
				}
				continue
			}
			if i == 0 {
				t.Fatalf("chain %s opens with a deny", c.name)
			}
			m := logLine.FindStringSubmatch(lines[i-1])
			if m == nil {
				t.Errorf("chain %s: %q is not preceded by its log statement (got %q)", c.name, l, lines[i-1])
				continue
			}
			match := strings.TrimSuffix(l[:strings.Index(l, "counter jump deny")], " ")
			if m[1] != match {
				t.Errorf("chain %s: the log matches %q but the deny %q", c.name, m[1], match)
			}
			fp, tag, ok := ParseLogPrefix(m[2])
			if !ok || fp != testLog.Fingerprint {
				t.Errorf("chain %s: prefix %q does not parse back to the rule set", c.name, m[2])
				continue
			}
			kind, prefix, _ := ParseTag(tag)
			if kind == TagDefault {
				if match != "" {
					t.Errorf("the default deny's log carries a match %q", match)
				}
			} else if !strings.Contains(match, prefix.String()) {
				t.Errorf("chain %s: tag %q names a range the rule does not match (%q)", c.name, tag, match)
			}
			seen[kind] = true
		}
		for _, kind := range []string{TagDefault, TagKindDeny, TagKindMetadata, TagKindBlock, TagKindTranslation} {
			if !seen[kind] {
				t.Errorf("chain %s logs no %q deny path", c.name, kind)
			}
		}
	}

	// No log statements without LogOptions: a process that cannot read the
	// group has no use for its entries.
	if plain := mustRenderNft(t, p, NftablesOptions{Table: "cloop_sbx", Bridge: "br-abc123"}); strings.Contains(plain, " log ") {
		t.Errorf("rendered log statements with no LogOptions:\n%s", plain)
	}
}

// TestCompileTagsEveryDropAndNoAllow: the tag is the only thing the packet log
// knows about a rule, so a drop without one would log nothing and an allow
// with one would be a lie.
func TestCompileTagsEveryDropAndNoAllow(t *testing.T) {
	p := denyRichPolicy(t)
	want := map[string]string{
		"203.0.113.0/24":     "deny:203.0.113.0/24",
		"169.254.169.254/32": "meta:169.254.169.254/32",
		"10.0.0.0/8":         "block:10.0.0.0/8",
		"64:ff9b::/96":       "xlat:64:ff9b::/96",
	}
	for _, r := range p.Rules {
		if r.Verdict == VerdictAllow {
			if r.Tag != "" {
				t.Errorf("allow %s carries tag %q", r, r.Tag)
			}
			continue
		}
		if _, _, ok := ParseTag(r.Tag); !ok {
			t.Errorf("drop %s carries no parseable tag (%q)", r, r.Tag)
		}
		if w, ok := want[r.Prefix.String()]; ok && r.Tag != w && !(r.Carve && strings.HasPrefix(r.Tag, "meta:")) {
			t.Errorf("drop %s tagged %q, want %q", r, r.Tag, w)
		}
	}
}

func TestLogPrefixGrammar(t *testing.T) {
	for _, tag := range []string{"default", "deny:203.0.113.0/24", "meta:169.254.169.254/32",
		"block:fc00::/7", "xlat:64:ff9b:1::/48", "block:ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128"} {
		s, err := LogPrefix("0123456789ab", tag)
		if err != nil {
			t.Fatalf("LogPrefix(%q): %v", tag, err)
		}
		if len(s) > nfLogPrefixMax {
			t.Errorf("%q is longer than the kernel keeps", s)
		}
		fp, got, ok := ParseLogPrefix(s)
		if !ok || fp != "0123456789ab" || got != tag {
			t.Errorf("ParseLogPrefix(%q) = %q, %q, %v", s, fp, got, ok)
		}
	}
	for _, bad := range []string{
		"", "cloop:", "cloop:0123456789ab", "cloop:0123456789AB:default", "cloop:0123456789a:default",
		"cloop:0123456789ab:allow:1.1.1.1/32", "cloop:0123456789ab:deny:1.1.1.1/24", // not canonical
		"cloop:0123456789ab:deny:1.1.1.1", "other:0123456789ab:default", "cloop:0123456789ab:default\"",
		"cloop:0123456789ab:deny:10.0.0.0/8 extra",
	} {
		if _, _, ok := ParseLogPrefix(bad); ok {
			t.Errorf("ParseLogPrefix(%q) accepted it", bad)
		}
	}
	if _, err := LogPrefix("not-hex", "default"); err == nil {
		t.Error("LogPrefix accepted a fingerprint that is not hex")
	}
	if _, err := RenderNftables(denyRichPolicy(t), NftablesOptions{Table: "cloop_sbx",
		Log: &LogOptions{Group: 1, Fingerprint: "x\" accept"}}); err == nil {
		t.Error("RenderNftables accepted an unloggable fingerprint")
	}
}

// TestRenderedRulesetsParseWithNft hands each form to the real nft(8) in
// check mode, which is the kernel's validation without the commit: a reject in
// a hook that does not allow it, a log statement nft cannot parse or a prefix
// it refuses would fail the whole transaction on a device, and a substring
// check cannot see any of them. Needs root (nft talks to the kernel).
func TestRenderedRulesetsParseWithNft(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("nft -c needs CAP_NET_ADMIN")
	}
	if _, err := exec.LookPath("nft"); err != nil {
		t.Skip("nft(8) is not installed")
	}
	if err := exec.Command("nft", "list", "tables").Run(); err != nil {
		t.Skipf("nft cannot list tables here: %v", err)
	}
	p := denyRichPolicy(t)
	drop := p
	drop.DropDenied = true
	for name, c := range map[string]struct {
		p    Policy
		opts NftablesOptions
	}{
		"bridge+log":    {p, NftablesOptions{Table: "cloop_t20437_check", Bridge: "br-t20437", Log: testLog}},
		"namespace+log": {p, NftablesOptions{Table: "cloop_t20437_check", Log: testLog}},
		"bridge drop":   {drop, NftablesOptions{Table: "cloop_t20437_check", Bridge: "br-t20437"}},
		"wide+log":      {widePolicyForNft(t), NftablesOptions{Table: "cloop_t20437_check", Bridge: "br-t20437", Log: testLog}},
	} {
		script := mustRenderNft(t, c.p, c.opts)
		cmd := exec.Command("nft", "-c", "-f", "-")
		cmd.Stdin = strings.NewReader(script)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Errorf("%s: nft -c refused the ruleset: %v\n%s\n%s", name, err, out, script)
		}
	}
}
