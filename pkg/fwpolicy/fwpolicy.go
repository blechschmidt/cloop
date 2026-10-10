// Package fwpolicy decides whether one IP-layer egress firewall is contained
// in another, and narrows one until it is (Task 20363, re-landing Task 20319
// on top of the virtual executors of Tasks 20345 and 20356).
//
// # The levels
//
// A sandbox's reach is decided at up to four levels, outermost first:
//
//  1. the executor's own configuration — executors.*.egress_filter for the
//     hub's container and Kubernetes executors, written by whoever deploys
//     the hub;
//  2. the device's rule set, set by an admin in the dashboard and stored in
//     the control plane (executor_firewall_rules);
//  3. a virtual executor's firewall, part of its definition
//     (executor.VirtualSpec.Firewall), or the network a device's own
//     sandboxes are given;
//  4. the project's rule set, set by the project's maintainers
//     (project_firewall_rules).
//
// Each level may only narrow the one above it. Without that, the inner levels
// would be privilege escalations with a text box: a maintainer able to name
// their own CIDRs on a device whose admin deliberately kept it off 10.0.0.0/8
// would have given themselves the operator's network.
//
// # The model
//
// Every level is an executor.FirewallRules, the form the virtual-executor
// dialog already edits, so all four share one vocabulary and one parser. What
// a rule set reaches is what pkg/netfilter compiles it to:
//
//   - TCP to an address in AllowCIDRs, or outside the hard-block set when
//     AllowPublicInternet is on, on a port in AllowPorts (any when empty);
//   - UDP and TCP to each resolver's own address and port;
//   - nothing in DenyCIDRs, whatever the allows say; and nothing else.
//
// One rule is inherited rather than restated: a level's effective deny list is
// its own plus every deny list above it. A deny only ever removes reach, so
// inheriting one cannot widen anything, and requiring every project to copy its
// device's denylist would make the first forgotten copy a hole. Nothing else is
// inherited — an inner level states the ports and resolvers it means, because
// "empty" already means something in this form (every port; no resolver) and a
// second meaning would leave a narrowing unable to say "no DNS at all".
//
// # Nil and empty
//
// A nil *Rules is a level that does not filter: the absence of a bound, which
// permits everything. A zero Rules is the opposite: a level that permits
// nothing at all. The two look alike in a debugger and are opposites in a
// firewall, and every function here keeps them apart.
package fwpolicy

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/blechschmidt/cloop/pkg/cloudmeta"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/netfilter"
)

// Rules is the editable firewall shared by every level.
type Rules = executor.FirewallRules

// Effective returns child as it is enforced under parent: child's own allows,
// ports and resolvers, with parent's deny list added to child's.
//
// A nil parent bounds nothing and adds nothing. The result is normalized.
func Effective(parent *Rules, child Rules) (Rules, error) {
	c, err := child.Normalize()
	if err != nil {
		return Rules{}, err
	}
	if parent == nil {
		return c, nil
	}
	p, err := parent.Normalize()
	if err != nil {
		return Rules{}, fmt.Errorf("the governing rule set is unreadable: %w", err)
	}
	if len(p.DenyCIDRs) == 0 {
		return c, nil
	}
	denies := aggregate(append(prefixes(c.DenyCIDRs), prefixes(p.DenyCIDRs)...))
	if len(denies) > executor.MaxFirewallCIDRs {
		return Rules{}, fmt.Errorf("%w: deny_cidrs: with the %d inherited from the governing rule set, "+
			"%d entries exceeds the maximum of %d", executor.ErrInvalidSpec, len(p.DenyCIDRs),
			len(denies), executor.MaxFirewallCIDRs)
	}
	c.DenyCIDRs = formatPrefixes(denies)
	return c.Normalize()
}

// Permits reports whether child, enforced under parent, reaches only what
// parent reaches. It returns one sentence per way in which it does not, so an
// empty result means contained.
//
// A nil parent permits everything; an unreadable parent permits nothing, since
// a bound this binary cannot read is not one it can prove anything against.
//
// The reasons are the body of a refused save. An admin told only "not
// permitted" widens the parent until the form saves; one told "port 22 is not
// allowed by the governing rule set (80, 443)" fixes the field they meant.
func Permits(parent *Rules, child Rules) []string {
	if parent == nil {
		return nil
	}
	p, err := parent.Normalize()
	if err != nil {
		return []string{"the governing rule set is unreadable (" + err.Error() +
			"), so no rule set can be proven to fit inside it"}
	}
	c, err := child.Normalize()
	if err != nil {
		return []string{err.Error()}
	}

	pDeny := prefixes(p.DenyCIDRs)
	cDeny := append(prefixes(c.DenyCIDRs), pDeny...)
	pTCP := subtract(subtract(allowSet(p), mappedV4), pDeny)
	cTCP := subtract(subtract(allowSet(c), mappedV4), cDeny)

	var reasons []string
	if len(cTCP) > 0 {
		// Ports first, once: every address check below is really "(address,
		// port)", and repeating a port violation per range would bury it.
		if len(p.AllowPorts) > 0 {
			if len(c.AllowPorts) == 0 {
				reasons = append(reasons, fmt.Sprintf(
					"it allows every port, but the governing rule set allows only %s; list the ports it needs",
					portList(p.AllowPorts)))
			} else {
				for _, port := range c.AllowPorts {
					if !containsInt(p.AllowPorts, port) {
						reasons = append(reasons, fmt.Sprintf(
							"port %d is not allowed by the governing rule set (%s)", port, portList(p.AllowPorts)))
					}
				}
			}
		}

		if c.AllowPublicInternet && !p.AllowPublicInternet {
			if rest := subtract(subtract(publicSpace, cDeny), pTCP); len(rest) > 0 {
				reasons = append(reasons, fmt.Sprintf(
					"it allows the public Internet, which the governing rule set does not (it reaches %s)",
					destinationList(p)))
			}
		}
		for _, raw := range c.AllowCIDRs {
			cp := netip.MustParsePrefix(raw)
			// What this entry reaches by itself: never a metadata service
			// strictly inside it, which only its own host prefix opens — as a
			// separate entry, judged on its own below (Task 20397).
			rest := subtract(subtract(subtract(subtract([]netip.Prefix{cp}, mappedV4), cDeny),
				hostPrefixes(cloudmeta.Within(cp))), pTCP)
			if len(rest) == 0 {
				continue
			}
			// A metadata service the child names and the parent does not open.
			// "Outside the governing rule set" would be a puzzle when the parent
			// allows a range around it; the rule is what needs saying.
			if svc, ok := cloudmeta.Lookup(cp.Addr()); ok && cp.Bits() == cp.Addr().BitLen() {
				reasons = append(reasons, fmt.Sprintf(
					"%s is the cloud metadata service at %s, which the governing rule set does not open: a "+
						"metadata service is reached only through its own address, and only where every level "+
						"above names it", raw, svc.Describe()))
				continue
			}
			// The common case when the parent allows the Internet: the range is
			// private. Saying which block it falls in is the difference between
			// an admin naming that range on the device and an admin "fixing" the
			// device by widening it until nothing is refused.
			if why := netfilter.BlockReasonForPrefix(cp); why != "" && p.AllowPublicInternet && !isPublic(rest[0]) {
				reasons = append(reasons, fmt.Sprintf(
					"%s is %s, which the governing rule set does not reach: it allows the public Internet, "+
						"and non-public space has to be named on the governing rule set first", raw, why))
				continue
			}
			if len(rest) == 1 && rest[0] == cp {
				reasons = append(reasons, fmt.Sprintf("%s is outside the governing rule set (it reaches %s)",
					raw, destinationList(p)))
				continue
			}
			reasons = append(reasons, fmt.Sprintf("%s reaches beyond the governing rule set (%s of it is outside; "+
				"the governing rule set reaches %s)", raw, describeSpan(rest), destinationList(p)))
		}
	}

	for _, raw := range c.Resolvers {
		ap := netip.MustParseAddrPort(raw)
		if covered([]netip.Prefix{hostPrefix(ap.Addr())}, cDeny) {
			// Unreachable under its own (or an inherited) deny list, so it opens
			// nothing — a configuration mistake, but not a widening.
			continue
		}
		if !containsString(p.Resolvers, raw) {
			reasons = append(reasons, fmt.Sprintf(
				"resolver %s is not one of the governing rule set's resolvers (%s): a resolver is opened on "+
					"UDP as well as TCP, so only a resolver the governing rule set names may be used",
				raw, resolverList(p.Resolvers)))
		}
	}
	return reasons
}

// Constrain returns the widest rule set that is contained in both child and
// parent, and one sentence for each thing it had to take away.
//
// It is what keeps rules saved under a level honest after that level is
// tightened. An admin narrowing a device does not have to find every virtual
// executor and project that was relying on the old reach: each is rewritten to
// the part of its old rule set the device still allows, and the sentences go to
// the audit trail and back to the admin's form, so nothing narrows silently.
//
// A child already contained is returned unchanged with no sentences. The result
// is never wider than the child — Constrain only removes — and when it cannot
// be expressed within the rule set's bounds the destinations are dropped rather
// than kept: the failure direction is "reaches less", never "reaches more".
func Constrain(parent *Rules, child Rules) (Rules, []string) {
	c, err := child.Normalize()
	if err != nil {
		return Rules{}, []string{"its rule set was unreadable (" + err.Error() + "), so every destination was removed"}
	}
	if parent == nil {
		return c, nil
	}
	p, err := parent.Normalize()
	if err != nil {
		return Rules{DenyCIDRs: c.DenyCIDRs}, []string{"the governing rule set is unreadable (" + err.Error() +
			"), so every destination was removed"}
	}
	if len(Permits(&p, c)) == 0 {
		return c, nil
	}

	out := Rules{DenyCIDRs: c.DenyCIDRs}
	var notes []string
	cDeny := append(prefixes(c.DenyCIDRs), prefixes(p.DenyCIDRs)...)
	// The parent's allows without its deny list: the child inherits that list
	// when it is enforced, so cutting the holes out here as well would only
	// spend the child's prefix budget spelling them twice. pAllow is what the
	// parent reaches; pRaw is its ranges as written, which a narrowed range is
	// cut to so it does not fragment around metadata services the narrowed
	// rule set closes again by itself.
	pAllow, pRaw := allowSet(p), rawAllowSet(p)

	if len(subtract(subtract(allowSet(c), mappedV4), cDeny)) == 0 {
		// Its allows reach nothing already; leave them as written.
		out.AllowPublicInternet, out.AllowCIDRs, out.AllowPorts = c.AllowPublicInternet, c.AllowCIDRs, c.AllowPorts
	} else {
		ports, dropTCP := c.AllowPorts, false
		switch {
		case len(p.AllowPorts) == 0:
			// The parent allows every port, so the child's list stands.
		case len(c.AllowPorts) == 0:
			ports = append([]int(nil), p.AllowPorts...)
			notes = append(notes, "its ports were narrowed from every port to "+portList(ports))
		default:
			ports = intersectInts(c.AllowPorts, p.AllowPorts)
			if len(ports) == 0 {
				dropTCP = true
				notes = append(notes, fmt.Sprintf("none of its ports (%s) is allowed any more (%s), so its "+
					"TCP destinations were removed", portList(c.AllowPorts), portList(p.AllowPorts)))
			} else if len(ports) < len(c.AllowPorts) {
				notes = append(notes, fmt.Sprintf("its ports were narrowed from %s to %s",
					portList(c.AllowPorts), portList(ports)))
			}
		}

		if !dropTCP {
			var cidrs, named []netip.Prefix
			if c.AllowPublicInternet {
				if p.AllowPublicInternet {
					out.AllowPublicInternet = true
				} else if pub := withoutMetadataHosts(intersect(publicOrMetadata, pRaw)); len(pub) > 0 {
					// Public space with the metadata services put back, so a
					// range like 168.63.0.0/16 comes out whole rather than cut
					// around Azure's WireServer — which it then contains without
					// naming, and closes.
					cidrs = append(cidrs, pub...)
					notes = append(notes, "the public Internet was narrowed to the public ranges the governing "+
						"rule set reaches ("+joinPrefixes(pub, 6)+")")
				} else {
					notes = append(notes, "the public Internet was removed: the governing rule set does not reach it")
				}
			}
			for _, raw := range c.AllowCIDRs {
				cp := netip.MustParsePrefix(raw)
				if svc, ok := cloudmeta.Lookup(cp.Addr()); ok && cp.Bits() == cp.Addr().BitLen() {
					// A metadata service the child names. It keeps the name only
					// where the parent opens the service as well (Task 20397).
					if covered([]netip.Prefix{cp}, pAllow) {
						named = append(named, cp)
					} else {
						notes = append(notes, raw+" was removed: it is the cloud metadata service at "+
							svc.Describe()+", which the governing rule set does not open")
					}
					continue
				}
				// A fragment that is a metadata service's own host prefix would
				// name it, and this range never opened it.
				inside := withoutMetadataHosts(intersect([]netip.Prefix{cp}, pRaw))
				switch {
				case len(inside) == 1 && inside[0] == cp:
					cidrs = append(cidrs, cp)
				case len(inside) == 0:
					notes = append(notes, raw+" was removed: it is outside the governing rule set")
				default:
					cidrs = append(cidrs, inside...)
					notes = append(notes, raw+" was narrowed to "+joinPrefixes(inside, 6))
				}
			}
			// The names stay out of the aggregation: merged into a wider
			// prefix, a host prefix would stop naming its service.
			cidrs = append(aggregate(cidrs), named...)
			if len(cidrs) > executor.MaxFirewallCIDRs {
				notes = append(notes, fmt.Sprintf("its allowlist could not be narrowed within %d ranges, so its "+
					"TCP destinations were removed", executor.MaxFirewallCIDRs))
				cidrs, out.AllowPublicInternet = nil, false
			}
			out.AllowCIDRs = formatPrefixes(cidrs)
			if out.AllowPublicInternet || len(out.AllowCIDRs) > 0 {
				out.AllowPorts = ports
			}
		}
	}

	for _, raw := range c.Resolvers {
		ap := netip.MustParseAddrPort(raw)
		if containsString(p.Resolvers, raw) || covered([]netip.Prefix{hostPrefix(ap.Addr())}, cDeny) {
			out.Resolvers = append(out.Resolvers, raw)
			continue
		}
		notes = append(notes, "resolver "+raw+" was removed: the governing rule set does not name it")
	}

	n, err := out.Normalize()
	if err == nil {
		// Say in the rule set what it already does: a range left containing a
		// metadata service it does not name closes it, and a narrowing must
		// not write back a rule set its own save would refuse.
		var closed []cloudmeta.Service
		if n, closed = closeMetadata(n); len(closed) > 0 {
			notes = append(notes, "its denylist now names the cloud metadata services its allowlist contains "+
				"without naming ("+describeServices(closed)+"), which were closed already")
		}
	}
	// Permits against the child as well as the parent: the narrowed rule set
	// must fit inside both, and checking only one is how a narrowing could
	// hand a child the parent's reach.
	if err != nil || len(Permits(&p, n)) > 0 || len(Permits(&c, n)) > 0 {
		// Unreachable by construction; refusing to guess keeps it fail-closed if
		// a future change to the model makes it reachable.
		return Rules{DenyCIDRs: c.DenyCIDRs}, append(notes,
			"it could not be narrowed automatically, so every destination was removed")
	}
	return n, notes
}

// CloseMetadata returns r with each cloud metadata service its allowlist
// contains without naming written into its denylist, and the services it
// wrote (Task 20397).
//
// It changes nothing a filter built by this binary does — Compile drops those
// services ahead of the allows that contain them — and that is the point: the
// dispatch step ships rule sets through it, so a device whose agent predates
// the containment rule, and would compile the containing range as an open
// door, closes them too, because a deny list is something every agent honours.
//
// A service that is one of r's own resolvers is left out. A deny closes every
// port, the resolver's included, and a Google Cloud VM's resolver is its
// metadata server; Compile carves it from the containing range and keeps its
// port 53, and an old agent is the one place it stays open on that range's
// ports.
func CloseMetadata(r Rules) Rules {
	n, err := r.Normalize()
	if err != nil {
		return r
	}
	out, _ := closeMetadata(n)
	return out
}

// closeMetadata is CloseMetadata on a normalized rule set, reporting what it
// added. When the denylist cannot take the entries the rule set is returned as
// it was: every filter this binary compiles carves them regardless.
func closeMetadata(n Rules) (Rules, []cloudmeta.Service) {
	resolverAddr := map[netip.Addr]bool{}
	for _, raw := range n.Resolvers {
		if ap, err := netip.ParseAddrPort(raw); err == nil {
			resolverAddr[ap.Addr().Unmap()] = true
		}
	}
	var add []cloudmeta.Service
	for _, s := range cloudmeta.Carved(prefixes(n.AllowCIDRs), prefixes(n.DenyCIDRs)) {
		if !resolverAddr[s.Addr] {
			add = append(add, s)
		}
	}
	if len(add) == 0 {
		return n, nil
	}
	out := n
	out.DenyCIDRs = append(append([]string(nil), n.DenyCIDRs...), formatPrefixes(hostPrefixes(add))...)
	norm, err := out.Normalize()
	if err != nil {
		return n, nil
	}
	return norm, add
}

// publicOrMetadata is public space with the metadata services put back: what
// a narrowing of "the public Internet" may intersect with without cutting a
// range around a service the narrowed rule set closes by itself.
var publicOrMetadata = aggregate(append(append([]netip.Prefix(nil), publicSpace...),
	hostPrefixes(cloudmeta.Services())...))

// withoutMetadataHosts drops every metadata service's own host prefix from ps.
func withoutMetadataHosts(ps []netip.Prefix) []netip.Prefix {
	out := ps[:0:0]
	for _, p := range ps {
		if _, ok := cloudmeta.Lookup(p.Addr()); ok && p.Bits() == p.Addr().BitLen() {
			continue
		}
		out = append(out, p)
	}
	return out
}

func describeServices(ss []cloudmeta.Service) string {
	parts := make([]string, len(ss))
	for i, s := range ss {
		parts[i] = s.Describe()
	}
	return strings.Join(parts, ", ")
}

// Fingerprint is a short stable digest of the canonical rule set.
//
// The container driver names a sandbox bridge and its nftables table after it
// when a workload carries rules of its own. Two workloads with different rules
// must never share a bridge — the second Apply would replace the first's
// ruleset, and one of them would run under the other's firewall — and deriving
// the name from the rules makes that collision impossible rather than unlikely.
// Two spellings of one policy normalize to one fingerprint and share.
func Fingerprint(r Rules) string {
	n, err := r.Normalize()
	if err != nil {
		// Unnormalizable rules never reach a driver; digesting the raw form
		// keeps this total and still tells two bad values apart.
		n = r
	}
	h := sha256.New()
	fmt.Fprintf(h, "public=%t\nallow=%s\ndeny=%s\nports=%v\nresolvers=%s\n",
		n.AllowPublicInternet, strings.Join(n.AllowCIDRs, ","), strings.Join(n.DenyCIDRs, ","),
		n.AllowPorts, strings.Join(n.Resolvers, ","))
	return hex.EncodeToString(h.Sum(nil))[:12]
}

// Equal reports whether two rule sets name the same policy.
func Equal(a, b Rules) bool { return Fingerprint(a) == Fingerprint(b) }

// Input projects a rule set onto the authorisation pkg/netfilter compiles,
// exactly as the container driver installs it: an empty port list next to a
// destination means every port.
func Input(r Rules) (netfilter.Input, error) {
	n, err := r.Normalize()
	if err != nil {
		return netfilter.Input{}, err
	}
	in := netfilter.Input{
		AllowPublicInternet: n.AllowPublicInternet,
		AllowCIDRs:          prefixes(n.AllowCIDRs),
		DenyCIDRs:           prefixes(n.DenyCIDRs),
		AllowAllPorts:       (n.AllowPublicInternet || len(n.AllowCIDRs) > 0) && len(n.AllowPorts) == 0,
	}
	for _, p := range n.AllowPorts {
		in.AllowPorts = append(in.AllowPorts, uint16(p))
	}
	for _, raw := range n.Resolvers {
		in.Resolvers = append(in.Resolvers, netip.MustParseAddrPort(raw))
	}
	return in, nil
}

// Describe renders a level for a sentence: "no network" for an empty rule set,
// "unfiltered" for a nil one, the rules otherwise.
func Describe(r *Rules) string {
	if r == nil {
		return "unfiltered"
	}
	if !r.HasDestination() {
		return "no network"
	}
	return r.Describe()
}

// ─── helpers ────────────────────────────────────────────────────────────────

// allowSet is the address set a normalized rule set's TCP allows reach, before
// its deny list: its CIDRs, and every address outside the block set when it
// allows the public Internet — less the cloud metadata services its CIDRs
// contain without naming, which every compiled filter drops ahead of them
// (Task 20397). Containment is decided against what the filter does, so a
// parent allowing 169.254.0.0/16 does not contain a child naming
// 169.254.169.254/32: the child would open what the parent keeps closed.
func allowSet(r Rules) []netip.Prefix {
	set := prefixes(r.AllowCIDRs)
	if r.AllowPublicInternet {
		set = append(set, publicSpace...)
	}
	return aggregate(subtract(aggregate(set), carvedOf(r)))
}

// rawAllowSet is allowSet before the metadata carves: the ranges as written.
// Constrain intersects with it so a narrowed range is not cut into fragments
// around addresses the narrowed rule set would carve again anyway.
func rawAllowSet(r Rules) []netip.Prefix {
	set := prefixes(r.AllowCIDRs)
	if r.AllowPublicInternet {
		set = append(set, publicSpace...)
	}
	return aggregate(set)
}

// carvedOf is the metadata services r's CIDRs contain without naming, as host
// prefixes. Its deny list is not consulted: everything it covers is
// subtracted wherever this is, so a denied service carved as well changes
// nothing.
func carvedOf(r Rules) []netip.Prefix {
	return hostPrefixes(cloudmeta.Carved(prefixes(r.AllowCIDRs), nil))
}

func hostPrefixes(ss []cloudmeta.Service) []netip.Prefix {
	out := make([]netip.Prefix, len(ss))
	for i, s := range ss {
		out[i] = s.Prefix()
	}
	return out
}

// prefixes parses a normalized CIDR list. Normalize has already refused
// anything that would not parse.
func prefixes(in []string) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(in))
	for _, s := range in {
		if p, err := executor.ParseFirewallPrefix(s); err == nil {
			out = append(out, p)
		}
	}
	return out
}

func formatPrefixes(in []netip.Prefix) []string {
	if len(in) == 0 {
		return nil
	}
	ps := append([]netip.Prefix(nil), in...)
	sortPrefixes(ps)
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = p.String()
	}
	return out
}

func hostPrefix(a netip.Addr) netip.Prefix {
	a = a.Unmap()
	return netip.PrefixFrom(a, a.BitLen())
}

// joinPrefixes renders up to max prefixes, then a count, so a narrowing that
// produced forty fragments is still one readable line.
func joinPrefixes(ps []netip.Prefix, max int) string {
	ss := formatPrefixes(ps)
	if len(ss) <= max {
		return strings.Join(ss, ", ")
	}
	return strings.Join(ss[:max], ", ") + fmt.Sprintf(" and %d more", len(ss)-max)
}

// describeSpan names the part of a range that falls outside its bound.
func describeSpan(ps []netip.Prefix) string { return joinPrefixes(ps, 3) }

func destinationList(r Rules) string {
	var parts []string
	if r.AllowPublicInternet {
		parts = append(parts, "the public Internet")
	}
	if len(r.AllowCIDRs) > 0 {
		parts = append(parts, strings.Join(r.AllowCIDRs, ", "))
	}
	if len(parts) == 0 {
		return "no TCP destination"
	}
	return strings.Join(parts, " and ")
}

func portList(ports []int) string {
	if len(ports) == 0 {
		return "any port"
	}
	ss := make([]string, len(ports))
	for i, p := range ports {
		ss[i] = strconv.Itoa(p)
	}
	return strings.Join(ss, ", ")
}

func resolverList(rs []string) string {
	if len(rs) == 0 {
		return "it names none"
	}
	return strings.Join(rs, ", ")
}

func containsInt(xs []int, x int) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

func containsString(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

func intersectInts(a, b []int) []int {
	var out []int
	for _, x := range a {
		if containsInt(b, x) {
			out = append(out, x)
		}
	}
	sort.Ints(out)
	return out
}
