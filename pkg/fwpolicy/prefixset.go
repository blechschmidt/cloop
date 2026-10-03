package fwpolicy

// prefixset.go is exact set arithmetic over address ranges.
//
// Containment between two firewalls is a question about sets of addresses,
// and the sets in question are not single prefixes: "the public Internet" is
// every address minus the hard-block set, and a deny list carves holes out of
// whatever the allows name. Comparing rule lists entry by entry gets both of
// those wrong — it cannot see that 10.0.0.0/8 minus 10.1.0.0/16 is inside a
// parent naming only 10.0.0.0/8, nor that 0.0.0.0/1 under a parent allowing
// the public Internet still reaches 10.0.0.0/8. So everything here works on
// lists of prefixes, and every operation is exact: two prefixes either nest or
// are disjoint, which is what makes subtraction a finite split rather than an
// approximation.

import (
	"net/netip"
	"sort"

	"github.com/blechschmidt/cloop/pkg/netfilter"
)

// subtractOne returns a − b as a list of disjoint prefixes.
//
// When a strictly contains b, a is halved repeatedly; the half not holding b is
// kept whole, the half holding b is halved again, until b itself is reached and
// dropped. That costs at most b.Bits()−a.Bits() prefixes, so even a /128 hole
// in ::/0 is 128 entries rather than a range scan.
func subtractOne(a, b netip.Prefix) []netip.Prefix {
	a, b = a.Masked(), b.Masked()
	if a.Addr().Is4() != b.Addr().Is4() || !a.Overlaps(b) {
		return []netip.Prefix{a}
	}
	if b.Bits() <= a.Bits() {
		// They overlap and b is at least as wide, so b contains a.
		return nil
	}
	var out []netip.Prefix
	cur := a
	for cur.Bits() < b.Bits() {
		lo, hi := halves(cur)
		if lo.Contains(b.Addr()) {
			out = append(out, hi)
			cur = lo
		} else {
			out = append(out, lo)
			cur = hi
		}
	}
	return out
}

// halves splits p into its two children, one bit longer.
func halves(p netip.Prefix) (netip.Prefix, netip.Prefix) {
	bits := p.Bits() + 1
	lo := netip.PrefixFrom(p.Addr(), bits)
	if p.Addr().Is4() {
		a := p.Addr().As4()
		a[p.Bits()/8] |= 0x80 >> (p.Bits() % 8)
		return lo, netip.PrefixFrom(netip.AddrFrom4(a), bits)
	}
	a := p.Addr().As16()
	a[p.Bits()/8] |= 0x80 >> (p.Bits() % 8)
	return lo, netip.PrefixFrom(netip.AddrFrom16(a), bits)
}

// subtract returns every address in a that is in no prefix of b.
func subtract(a, b []netip.Prefix) []netip.Prefix {
	out := append([]netip.Prefix(nil), a...)
	for _, hole := range b {
		var next []netip.Prefix
		for _, p := range out {
			next = append(next, subtractOne(p, hole)...)
		}
		out = next
		if len(out) == 0 {
			return nil
		}
	}
	return out
}

// intersect returns every address in both a and b. Two prefixes that overlap
// nest, so their intersection is simply the narrower one.
func intersect(a, b []netip.Prefix) []netip.Prefix {
	var out []netip.Prefix
	for _, x := range a {
		for _, y := range b {
			if x.Addr().Is4() != y.Addr().Is4() || !x.Overlaps(y) {
				continue
			}
			if x.Bits() >= y.Bits() {
				out = append(out, x)
			} else {
				out = append(out, y)
			}
		}
	}
	return aggregate(out)
}

// covered reports whether every address in a is also in b.
func covered(a, b []netip.Prefix) bool { return len(subtract(a, b)) == 0 }

// aggregate returns the smallest list of prefixes naming the same addresses:
// contained prefixes dropped and sibling pairs merged into their parent.
//
// It matters for the rule sets Constrain writes back. A narrowing that splits
// one allowed range around a hole produces siblings, and storing them unmerged
// would spend the rule set's prefix budget on a spelling.
func aggregate(in []netip.Prefix) []netip.Prefix {
	if len(in) == 0 {
		return nil
	}
	ps := make([]netip.Prefix, 0, len(in))
	for _, p := range in {
		ps = append(ps, p.Masked())
	}
	for {
		sortPrefixes(ps)
		// Drop prefixes contained in an earlier (wider or equal) one. Sorted
		// by address then length, a container always precedes what it holds.
		kept := ps[:0]
		for _, p := range ps {
			if n := len(kept); n > 0 {
				last := kept[n-1]
				if last.Addr().Is4() == p.Addr().Is4() && last.Bits() <= p.Bits() && last.Contains(p.Addr()) {
					continue
				}
			}
			kept = append(kept, p)
		}
		ps = kept
		merged := false
		out := ps[:0:0]
		for i := 0; i < len(ps); i++ {
			if i+1 < len(ps) && siblings(ps[i], ps[i+1]) {
				parent, _ := ps[i].Addr().Prefix(ps[i].Bits() - 1)
				out = append(out, parent)
				i++
				merged = true
				continue
			}
			out = append(out, ps[i])
		}
		ps = out
		if !merged {
			return ps
		}
	}
}

// siblings reports whether a and b are the two halves of one prefix.
func siblings(a, b netip.Prefix) bool {
	if a.Addr().Is4() != b.Addr().Is4() || a.Bits() != b.Bits() || a.Bits() == 0 {
		return false
	}
	pa, err1 := a.Addr().Prefix(a.Bits() - 1)
	pb, err2 := b.Addr().Prefix(b.Bits() - 1)
	return err1 == nil && err2 == nil && pa == pb && a != b
}

// sortPrefixes orders IPv4 before IPv6, then by address, then widest first —
// the order netfilter and executor.FirewallRules already use, so a rule set
// Constrain writes reads the same as one an admin typed.
func sortPrefixes(ps []netip.Prefix) {
	sort.Slice(ps, func(i, j int) bool {
		a, b := ps[i], ps[j]
		if a.Addr().Is4() != b.Addr().Is4() {
			return a.Addr().Is4()
		}
		if c := a.Addr().Compare(b.Addr()); c != 0 {
			return c < 0
		}
		return a.Bits() < b.Bits()
	})
}

// everything is the whole address space of both families, less the IPv4-mapped
// IPv6 range.
//
// That range never carries a packet: the kernel delivers ::ffff:a.b.c.d as an
// IPv4 packet to a.b.c.d, and netfilter.Policy.Evaluate unmaps the address
// before it consults a rule, so an IPv6 rule cannot match it. Leaving it out of
// both sides keeps a parent allowing "the public Internet" from appearing to
// contain ::ffff:10.0.0.0/104 — which would be harmless, since nothing could
// use it, but would be the one place where this package's answer and the
// compiled filter's disagreed.
var everything = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/0"),
	netip.MustParsePrefix("::/0"),
}

// mappedV4 is the IPv4-mapped IPv6 range removed from every set; see
// everything.
var mappedV4 = []netip.Prefix{netip.MustParsePrefix("::ffff:0:0/96")}

// publicSpace is every address outside netfilter's hard-block set: what
// AllowPublicInternet opens.
//
// Derived from netfilter.BlockedPrefixes rather than restated, because the
// compiler is what decides what "public" means on the wire, and a second copy
// of the block set here would be a place for the two to disagree about the
// metadata endpoint.
var publicSpace = func() []netip.Prefix {
	var blocked []netip.Prefix
	for _, b := range netfilter.BlockedPrefixes() {
		blocked = append(blocked, b.Prefix)
	}
	return aggregate(subtract(subtract(everything, mappedV4), blocked))
}()

// isPublic reports whether every address in p is outside the block set.
func isPublic(p netip.Prefix) bool { return covered([]netip.Prefix{p}, publicSpace) }
