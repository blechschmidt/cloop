package fwpolicy

import (
	"math/rand"
	"net/netip"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/netfilter"
)

// device is the bound most tests narrow: the public Internet and one private
// range on two ports, one resolver, and a denied provider range.
var device = Rules{
	AllowPublicInternet: true,
	AllowCIDRs:          []string{"10.20.0.0/16"},
	DenyCIDRs:           []string{"203.0.113.0/24"},
	AllowPorts:          []int{80, 443},
	Resolvers:           []string{"1.1.1.1"},
}

func TestPublicSpaceExcludesEveryBlockedRange(t *testing.T) {
	for _, s := range []string{"1.1.1.1", "8.8.8.8", "2606:4700::1111", "203.0.113.9"} {
		if !isPublic(hostPrefix(netip.MustParseAddr(s))) {
			t.Errorf("%s should be public", s)
		}
	}
	for _, s := range []string{"10.0.0.1", "172.16.5.5", "192.168.1.1", "169.254.169.254", "127.0.0.1",
		"100.64.0.1", "224.0.0.1", "0.0.0.0", "::1", "fe80::1", "fc00::1", "64:ff9b::808:808", "2002::1",
		"::ffff:10.0.0.1"} {
		if isPublic(hostPrefix(netip.MustParseAddr(s))) {
			t.Errorf("%s should not be public", s)
		}
	}
	// A wide prefix that contains a blocked range is not public, even though
	// most of it is: "public" is a statement about every address in it.
	if isPublic(netip.MustParsePrefix("0.0.0.0/1")) {
		t.Error("0.0.0.0/1 contains 10.0.0.0/8 and must not count as public")
	}
}

func TestSubtractIsExact(t *testing.T) {
	got := subtract([]netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
		[]netip.Prefix{netip.MustParsePrefix("10.1.0.0/16")})
	if covered([]netip.Prefix{netip.MustParsePrefix("10.1.2.0/24")}, got) {
		t.Fatal("the hole is still covered")
	}
	if !covered([]netip.Prefix{netip.MustParsePrefix("10.0.0.0/16"), netip.MustParsePrefix("10.2.0.0/15"),
		netip.MustParsePrefix("10.128.0.0/9")}, got) {
		t.Fatalf("subtract lost addresses outside the hole: %v", got)
	}
	if n := len(got); n != 8 {
		t.Errorf("a /16 hole in a /8 should leave 8 prefixes, got %d: %v", n, got)
	}
	back := aggregate(append(got, netip.MustParsePrefix("10.1.0.0/16")))
	if len(back) != 1 || back[0] != netip.MustParsePrefix("10.0.0.0/8") {
		t.Errorf("aggregate did not reassemble the /8: %v", back)
	}
}

func TestNilBoundPermitsEverythingAndEmptyBoundNothing(t *testing.T) {
	wide := Rules{AllowPublicInternet: true, AllowCIDRs: []string{"10.0.0.0/8"}, Resolvers: []string{"8.8.8.8"}}
	if r := Permits(nil, wide); len(r) != 0 {
		t.Errorf("a nil bound must permit everything, got %v", r)
	}
	if r := Permits(&Rules{}, wide); len(r) == 0 {
		t.Error("an empty bound must permit no destination")
	}
	if r := Permits(&Rules{}, Rules{}); len(r) != 0 {
		t.Errorf("reaching nothing fits inside anything, got %v", r)
	}
	// Ports alone reach nothing, so they fit inside an empty bound.
	if r := Permits(&Rules{}, Rules{AllowPorts: []int{22}}); len(r) != 0 {
		t.Errorf("a port list with no destination reaches nothing, got %v", r)
	}
}

func TestUnreadableBoundRefusesEverything(t *testing.T) {
	bad := Rules{AllowCIDRs: []string{"not-a-cidr"}}
	if r := Permits(&bad, Rules{}); len(r) == 0 || !strings.Contains(r[0], "unreadable") {
		t.Fatalf("an unreadable bound must refuse, got %v", r)
	}
}

func TestPermitsRefusesEveryWidening(t *testing.T) {
	cases := []struct {
		name  string
		child Rules
		want  string // a fragment the reason must name
	}{
		{"private range", Rules{AllowCIDRs: []string{"192.168.0.0/16"}, AllowPorts: []int{443}}, "192.168.0.0/16"},
		{"wider than the granted range", Rules{AllowCIDRs: []string{"10.0.0.0/8"}, AllowPorts: []int{443}}, "10.0.0.0/8"},
		{"metadata endpoint", Rules{AllowCIDRs: []string{"169.254.169.254"}, AllowPorts: []int{80}}, "169.254.169.254/32"},
		{"a supernet of public space", Rules{AllowCIDRs: []string{"0.0.0.0/1"}, AllowPorts: []int{443}}, "0.0.0.0/1"},
		{"ULA", Rules{AllowCIDRs: []string{"fc00::/7"}, AllowPorts: []int{443}}, "fc00::/7"},
		{"loopback", Rules{AllowCIDRs: []string{"127.0.0.0/8"}, AllowPorts: []int{443}}, "127.0.0.0/8"},
		{"another port", Rules{AllowPublicInternet: true, AllowPorts: []int{22}}, "port 22"},
		{"every port", Rules{AllowPublicInternet: true}, "every port"},
		{"public range on another port", Rules{AllowCIDRs: []string{"1.1.1.0/24"}, AllowPorts: []int{22}}, "port 22"},
		{"another resolver", Rules{Resolvers: []string{"8.8.8.8"}}, "8.8.8.8:53"},
		{"resolver on another port", Rules{Resolvers: []string{"1.1.1.1:5353"}}, "1.1.1.1:5353"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reasons := Permits(&device, tc.child)
			if len(reasons) == 0 {
				t.Fatalf("%v must not fit inside %v", tc.child.Describe(), device.Describe())
			}
			if !strings.Contains(strings.Join(reasons, "; "), tc.want) {
				t.Errorf("reasons %q do not name %q", reasons, tc.want)
			}
		})
	}
}

func TestPermitsAcceptsGenuineNarrowing(t *testing.T) {
	for name, child := range map[string]Rules{
		"same rules":            device,
		"nothing":               {},
		"one port":              {AllowPublicInternet: true, AllowPorts: []int{443}},
		"a CDN range":           {AllowCIDRs: []string{"151.101.0.0/16"}, AllowPorts: []int{443}},
		"inside the private":    {AllowCIDRs: []string{"10.20.5.0/24"}, AllowPorts: []int{80}},
		"a resolver only":       {Resolvers: []string{"1.1.1.1:53"}},
		"own deny":              {AllowPublicInternet: true, AllowPorts: []int{443}, DenyCIDRs: []string{"8.8.8.0/24"}},
		"inherits the denylist": {AllowCIDRs: []string{"203.0.113.0/25"}, AllowPorts: []int{443}},
		// The device denies 203.0.113.0/24; a child allowing a supernet that is
		// otherwise public reaches only what is left once the inherited deny
		// applies, so it fits.
		"public supernet of a denied range": {AllowCIDRs: []string{"203.0.112.0/23"}, AllowPorts: []int{443}},
		// The public Internet minus a private range the child also names.
		"private carved by its own deny": {AllowCIDRs: []string{"10.20.0.0/16"}, DenyCIDRs: []string{"10.20.9.0/24"},
			AllowPorts: []int{443}},
	} {
		if r := Permits(&device, child); len(r) != 0 {
			t.Errorf("%s: %v should fit inside %v, got %v", name, child.Describe(), device.Describe(), r)
		}
	}
}

func TestEffectiveInheritsTheDenylistOnly(t *testing.T) {
	child := Rules{AllowPublicInternet: true, AllowPorts: []int{443}, DenyCIDRs: []string{"8.8.8.0/24"}}
	got, err := Effective(&device, child)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(got.DenyCIDRs, ",") != "8.8.8.0/24,203.0.113.0/24" {
		t.Errorf("deny list = %v, want both", got.DenyCIDRs)
	}
	if len(got.AllowCIDRs) != 0 || len(got.Resolvers) != 0 || strings.Join(intsToStrings(got.AllowPorts), ",") != "443" {
		t.Errorf("only the denylist may be inherited, got %+v", got)
	}
	if same, _ := Effective(nil, child); !Equal(same, child) {
		t.Error("a nil parent must leave the child unchanged")
	}
}

func TestContainmentIsTransitive(t *testing.T) {
	config := Rules{AllowPublicInternet: true, AllowCIDRs: []string{"10.0.0.0/8"}, AllowPorts: []int{22, 80, 443},
		Resolvers: []string{"1.1.1.1", "10.0.0.53"}}
	vx := Rules{AllowPublicInternet: true, AllowCIDRs: []string{"10.20.0.0/16"}, AllowPorts: []int{80, 443},
		Resolvers: []string{"1.1.1.1"}}
	project := Rules{AllowCIDRs: []string{"10.20.1.0/24", "140.82.112.0/20"}, AllowPorts: []int{443},
		Resolvers: []string{"1.1.1.1"}}
	if r := Permits(&config, vx); len(r) != 0 {
		t.Fatal(r)
	}
	vxEff, _ := Effective(&config, vx)
	if r := Permits(&vxEff, project); len(r) != 0 {
		t.Fatal(r)
	}
	if r := Permits(&config, project); len(r) != 0 {
		t.Errorf("config ⊇ vx ⊇ project, so config ⊇ project; got %v", r)
	}
}

func TestConstrainNarrowsToTheBound(t *testing.T) {
	cases := []struct {
		name  string
		child Rules
		want  Rules
	}{
		{"ports intersected",
			Rules{AllowPublicInternet: true, AllowPorts: []int{22, 443}},
			Rules{AllowPublicInternet: true, AllowPorts: []int{443}}},
		{"any port becomes the bound's",
			Rules{AllowCIDRs: []string{"1.1.1.0/24"}},
			Rules{AllowCIDRs: []string{"1.1.1.0/24"}, AllowPorts: []int{80, 443}}},
		{"private range narrowed to the granted part",
			Rules{AllowCIDRs: []string{"10.0.0.0/8"}, AllowPorts: []int{443}},
			Rules{AllowCIDRs: []string{"10.20.0.0/16"}, AllowPorts: []int{443}}},
		{"private range outside is dropped",
			Rules{AllowCIDRs: []string{"192.168.0.0/16", "1.0.0.0/8"}, AllowPorts: []int{443}},
			Rules{AllowCIDRs: []string{"1.0.0.0/8"}, AllowPorts: []int{443}}},
		{"foreign resolver dropped",
			Rules{Resolvers: []string{"1.1.1.1", "8.8.8.8"}},
			Rules{Resolvers: []string{"1.1.1.1"}}},
		{"no common port drops TCP and keeps DNS",
			Rules{AllowPublicInternet: true, AllowPorts: []int{22}, Resolvers: []string{"1.1.1.1"}},
			Rules{Resolvers: []string{"1.1.1.1"}}},
		{"own deny list kept",
			Rules{AllowPublicInternet: true, AllowPorts: []int{443, 8443}, DenyCIDRs: []string{"9.9.9.0/24"}},
			Rules{AllowPublicInternet: true, AllowPorts: []int{443}, DenyCIDRs: []string{"9.9.9.0/24"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, notes := Constrain(&device, tc.child)
			if !Equal(got, tc.want) {
				t.Errorf("Constrain = %v, want %v", got.Describe(), tc.want.Describe())
			}
			if len(notes) == 0 {
				t.Error("a narrowing must say what it removed")
			}
			if r := Permits(&device, got); len(r) != 0 {
				t.Errorf("the constrained rules still exceed the bound: %v", r)
			}
		})
	}
	if got, notes := Constrain(&device, Rules{AllowPublicInternet: true, AllowPorts: []int{443}}); len(notes) != 0 ||
		!Equal(got, Rules{AllowPublicInternet: true, AllowPorts: []int{443}}) {
		t.Errorf("a contained child must come back unchanged and silent, got %v %v", got.Describe(), notes)
	}
}

func TestConstrainPublicUnderAPrivateBound(t *testing.T) {
	lab := Rules{AllowCIDRs: []string{"10.8.0.0/24", "140.82.112.0/20"}, AllowPorts: []int{443}}
	got, notes := Constrain(&lab, Rules{AllowPublicInternet: true, AllowPorts: []int{443}})
	if got.AllowPublicInternet {
		t.Fatal("the public Internet must not survive a bound that does not allow it")
	}
	if strings.Join(got.AllowCIDRs, ",") != "140.82.112.0/20" {
		t.Errorf("want the public part of the bound, got %v", got.AllowCIDRs)
	}
	if len(notes) == 0 {
		t.Error("the narrowing must be explained")
	}
}

func TestFingerprintIgnoresSpelling(t *testing.T) {
	a := Rules{AllowCIDRs: []string{"10.1.2.3/8", " 1.1.1.0/24"}, AllowPorts: []int{443, 80, 443}, Resolvers: []string{"1.1.1.1"}}
	b := Rules{AllowCIDRs: []string{"1.1.1.0/24", "10.0.0.0/8"}, AllowPorts: []int{80, 443}, Resolvers: []string{"1.1.1.1:53"}}
	if Fingerprint(a) != Fingerprint(b) {
		t.Error("two spellings of one policy must share a fingerprint")
	}
	c := b
	c.DenyCIDRs = []string{"10.9.0.0/16"}
	if Fingerprint(c) == Fingerprint(b) {
		t.Error("a deny list must change the fingerprint")
	}
	if len(Fingerprint(a)) != 12 {
		t.Error("fingerprint must be 12 hex characters")
	}
}

// TestPermitsAgreesWithTheCompiledFilter is the property the package exists
// for, checked against pkg/netfilter rather than against itself: whenever
// Permits says a child fits, no packet the compiled child lets out is one the
// compiled parent drops. And whatever Constrain returns fits, and lets out
// nothing the child or the parent would not.
func TestPermitsAgreesWithTheCompiledFilter(t *testing.T) {
	rng := rand.New(rand.NewSource(20363))
	permitted, refused := 0, 0
	for i := 0; i < 400; i++ {
		parent := randomRules(rng)
		child := randomRules(rng)
		if rng.Intn(3) == 0 {
			// Bias a third of the children towards genuine narrowings, which
			// random generation alone almost never produces.
			child, _ = Constrain(&parent, child)
		}
		reasons := Permits(&parent, child)
		eff, err := Effective(&parent, child)
		if err != nil {
			t.Fatalf("Effective: %v", err)
		}
		probes := probesFor(rng, parent, child)
		if len(reasons) == 0 {
			permitted++
			if leak, ok := firstLeak(t, eff, parent, probes); ok {
				t.Fatalf("Permits accepted %v under %v, but the compiled child lets out %s",
					child.Describe(), parent.Describe(), leak)
			}
		} else {
			refused++
		}

		got, _ := Constrain(&parent, child)
		if r := Permits(&parent, got); len(r) != 0 {
			t.Fatalf("Constrain(%v, %v) = %v still exceeds the bound: %v",
				parent.Describe(), child.Describe(), got.Describe(), r)
		}
		gotEff, _ := Effective(&parent, got)
		if leak, ok := firstLeak(t, gotEff, parent, probes); ok {
			t.Fatalf("Constrain result %v lets out %s, which %v drops", got.Describe(), leak, parent.Describe())
		}
		if leak, ok := firstLeak(t, gotEff, child, probes); ok {
			t.Fatalf("Constrain result %v lets out %s, which the child %v never allowed",
				got.Describe(), leak, child.Describe())
		}
	}
	if permitted < 100 || refused < 100 {
		t.Errorf("the sample is lopsided (%d permitted, %d refused); widen the generator", permitted, refused)
	}
}

type probe struct {
	addr  netip.Addr
	port  uint16
	proto netfilter.Proto
}

func (p probe) String() string {
	return p.proto.String() + " " + netip.AddrPortFrom(p.addr, p.port).String()
}

// firstLeak reports a probe inner allows and outer drops.
func firstLeak(t *testing.T, inner, outer Rules, probes []probe) (probe, bool) {
	t.Helper()
	ip, op := compile(t, inner), compile(t, outer)
	for _, pr := range probes {
		iv, _ := ip.Evaluate(pr.addr, pr.port, pr.proto)
		ov, _ := op.Evaluate(pr.addr, pr.port, pr.proto)
		if iv == netfilter.VerdictAllow && ov != netfilter.VerdictAllow {
			return pr, true
		}
	}
	return probe{}, false
}

func compile(t *testing.T, r Rules) netfilter.Policy {
	t.Helper()
	in, err := Input(r)
	if err != nil {
		t.Fatalf("Input(%v): %v", r.Describe(), err)
	}
	p, err := netfilter.Compile(in)
	if err != nil {
		t.Fatalf("Compile(%v): %v", r.Describe(), err)
	}
	return p.WireOnly()
}

var interesting = []string{
	"10.0.0.0/8", "10.20.0.0/16", "10.20.5.0/24", "172.16.0.0/12", "192.168.1.0/24", "169.254.169.254/32",
	"1.1.1.0/24", "1.0.0.0/8", "8.8.8.0/24", "203.0.113.0/24", "140.82.112.0/20", "100.64.0.0/10",
	"0.0.0.0/1", "128.0.0.0/2", "2606:4700::/32", "fc00::/7", "2001:db8::/32",
}

var interestingResolvers = []string{"1.1.1.1", "8.8.8.8", "10.20.0.53", "1.1.1.1:5353", "[2606:4700::1111]:53"}

func randomRules(rng *rand.Rand) Rules {
	var r Rules
	r.AllowPublicInternet = rng.Intn(2) == 0
	for n := rng.Intn(3); n > 0; n-- {
		r.AllowCIDRs = append(r.AllowCIDRs, interesting[rng.Intn(len(interesting))])
	}
	for n := rng.Intn(3); n > 0; n-- {
		r.DenyCIDRs = append(r.DenyCIDRs, interesting[rng.Intn(len(interesting))])
	}
	ports := []int{22, 53, 80, 443, 8443}
	for n := rng.Intn(3); n > 0; n-- {
		r.AllowPorts = append(r.AllowPorts, ports[rng.Intn(len(ports))])
	}
	for n := rng.Intn(3); n > 0; n-- {
		r.Resolvers = append(r.Resolvers, interestingResolvers[rng.Intn(len(interestingResolvers))])
	}
	n, err := r.Normalize()
	if err != nil {
		panic(err)
	}
	return n
}

// probesFor samples packets at every boundary either rule set draws — the
// first and last address of each range and the address either side — plus
// random addresses, on every port either names and a few neither does.
func probesFor(rng *rand.Rand, rs ...Rules) []probe {
	var addrs []netip.Addr
	edge := func(p netip.Prefix) {
		first := p.Masked().Addr()
		last := lastAddr(p)
		addrs = append(addrs, first, last, first.Prev(), last.Next())
	}
	ports := []uint16{22, 53, 80, 443, 5353, 8443, 9999}
	for _, r := range rs {
		for _, c := range append(append([]string{}, r.AllowCIDRs...), r.DenyCIDRs...) {
			edge(netip.MustParsePrefix(c))
		}
		for _, res := range r.Resolvers {
			ap := netip.MustParseAddrPort(res)
			addrs = append(addrs, ap.Addr())
			ports = append(ports, ap.Port())
		}
	}
	for _, c := range interesting {
		edge(netip.MustParsePrefix(c))
	}
	for i := 0; i < 64; i++ {
		var b [4]byte
		rng.Read(b[:])
		addrs = append(addrs, netip.AddrFrom4(b))
	}
	var out []probe
	for _, a := range addrs {
		if !a.IsValid() {
			continue
		}
		for _, port := range ports {
			out = append(out, probe{a, port, netfilter.ProtoTCP}, probe{a, port, netfilter.ProtoUDP})
		}
	}
	return out
}

func lastAddr(p netip.Prefix) netip.Addr {
	p = p.Masked()
	if p.Addr().Is4() {
		a := p.Addr().As4()
		for i := p.Bits(); i < 32; i++ {
			a[i/8] |= 0x80 >> (i % 8)
		}
		return netip.AddrFrom4(a)
	}
	a := p.Addr().As16()
	for i := p.Bits(); i < 128; i++ {
		a[i/8] |= 0x80 >> (i % 8)
	}
	return netip.AddrFrom16(a)
}

func intsToStrings(xs []int) []string {
	out := make([]string, len(xs))
	for i, x := range xs {
		out[i] = netip.AddrPortFrom(netip.IPv4Unspecified(), uint16(x)).String()[len("0.0.0.0:"):]
	}
	return out
}
