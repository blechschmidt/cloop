package fwpolicy

// explain.go says why a sandbox's firewall refused a connection, in the terms a
// developer set it up in (Task 20437).
//
// The packet log names a deny path and nothing else: "default", or a deny-list,
// metadata, block-set or translation prefix. Which allowlist did not name the
// address, whose deny list did — that depends on the levels the workload's
// firewall was composed of, which only the hub knows, from the dispatch. So
// the sentence is built here, from those levels, and stored with the refusal:
// "not in the project's allow list", "in device sgx's deny list
// (203.0.113.0/24)".

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/blechschmidt/cloop/pkg/cloudmeta"
	"github.com/blechschmidt/cloop/pkg/netfilter"
)

// Explain says why the deny path rule refused a packet to dst:port over proto,
// given the levels that composed the workload's firewall, outermost first. With
// no levels it speaks of "the sandbox's firewall".
func Explain(levels []Level, rule string, dst netip.Addr, port uint16, proto string) string {
	kind, prefix, ok := netfilter.ParseTag(rule)
	if !ok {
		return "refused by the sandbox's firewall"
	}
	dst = dst.Unmap()
	inner := innermost(levels)
	switch kind {
	case netfilter.TagKindDeny:
		var who []string
		for _, l := range levels {
			if l.Rules == nil {
				continue
			}
			for _, raw := range l.Rules.DenyCIDRs {
				if p, err := netip.ParsePrefix(raw); err == nil && p.Contains(dst) {
					who = append(who, possessive(l)+" deny list ("+raw+")")
					break
				}
			}
		}
		if len(who) == 0 {
			return "in the deny list (" + prefix.String() + ")"
		}
		return "in " + strings.Join(who, " and ")
	case netfilter.TagKindMetadata:
		what := "a cloud metadata service"
		if svc, ok := cloudmeta.Lookup(dst); ok {
			what = "the cloud metadata service at " + svc.Describe()
		}
		return what + ", which a firewall opens only when every level names its own address"
	case netfilter.TagKindTranslation:
		return "an IPv6 translation prefix (" + prefix.String() + "), which no allow list waives — allow the IPv4 " +
			"range it stands for instead"
	case netfilter.TagKindBlock:
		reason := "blocked address space"
		for _, b := range netfilter.BlockedPrefixes() {
			if b.Prefix == prefix {
				reason = b.Reason
				break
			}
		}
		return fmt.Sprintf("%s range %s, which %s does not name", reason, prefix, allowNoun(inner))
	}
	return explainDefault(inner, dst, port, proto)
}

// explainDefault says what nothing allowed: the address, the port or the
// protocol — whichever the innermost rule set did not open.
func explainDefault(inner *Level, dst netip.Addr, port uint16, proto string) string {
	list := allowNoun(inner)
	if inner == nil || inner.Rules == nil {
		return "not allowed by the sandbox's firewall"
	}
	r := inner.Rules
	if n, err := r.Normalize(); err == nil {
		r = &n
	}
	if proto != "tcp" {
		if proto == "udp" && resolverAddr(r, dst) {
			return fmt.Sprintf("port %d is not where %s names this resolver", port, list)
		}
		tail := ""
		if proto == "udp" {
			tail = ", and UDP reaches only the resolvers it names"
		}
		return fmt.Sprintf("%s is not allowed: %s opens TCP only%s", protoNoun(proto), list, tail)
	}
	if addrAllowed(r, dst) && len(r.AllowPorts) > 0 && !slices.Contains(r.AllowPorts, int(port)) {
		ports := make([]string, len(r.AllowPorts))
		for i, p := range r.AllowPorts {
			ports[i] = fmt.Sprint(p)
		}
		return fmt.Sprintf("port %d is not one %s opens (%s)", port, list, strings.Join(ports, ", "))
	}
	return "not in " + list
}

// innermost is the level whose allowlist the workload ran under: the last one
// that set rules.
func innermost(levels []Level) *Level {
	for i := len(levels) - 1; i >= 0; i-- {
		if levels[i].Rules != nil {
			l := levels[i]
			return &l
		}
	}
	return nil
}

// allowNoun names a level's allowlist: "the project's allow list".
func allowNoun(l *Level) string {
	if l == nil {
		return "the sandbox's firewall"
	}
	if l.Kind == "scope" {
		return "the project's sandbox.yaml (egress: public)"
	}
	return possessive(*l) + " allow list"
}

// possessive names a level as an owner: "the project's", "device sgx's",
// "virtual executor vx-1's", "executor container-1's configured". The levels
// name themselves in a sentence ("device sgx's firewall"), and the owner is
// what comes before its last "'s".
func possessive(l Level) string {
	switch l.Kind {
	case "project":
		return "the project's"
	case "scope":
		return "the project's sandbox.yaml's"
	}
	if i := strings.LastIndex(l.Name, "'s "); i > 0 {
		owner := l.Name[:i] + "'s"
		if l.Kind == "config" {
			owner += " configured"
		}
		return owner
	}
	return "the executor's"
}

func protoNoun(p string) string {
	switch p {
	case "udp", "icmp", "sctp":
		return strings.ToUpper(p)
	case "icmpv6":
		return "ICMPv6"
	case "udplite":
		return "UDP-Lite"
	}
	return "this protocol"
}

// addrAllowed reports whether a normalized rule set's TCP allows cover dst,
// before ports: its CIDRs, or the public Internet when it opens that.
func addrAllowed(r *Rules, dst netip.Addr) bool {
	for _, raw := range r.AllowCIDRs {
		if p, err := netip.ParsePrefix(raw); err == nil && p.Contains(dst) {
			return true
		}
	}
	return r.AllowPublicInternet && netfilter.BlockReasonForPrefix(netip.PrefixFrom(dst, dst.BitLen())) == ""
}

func resolverAddr(r *Rules, dst netip.Addr) bool {
	for _, raw := range r.Resolvers {
		if ap, err := netip.ParseAddrPort(raw); err == nil && ap.Addr().Unmap() == dst {
			return true
		}
	}
	return false
}
