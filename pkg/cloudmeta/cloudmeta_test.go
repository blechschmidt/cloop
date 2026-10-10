package cloudmeta

import (
	"net/netip"
	"strings"
	"testing"
)

func pfx(t *testing.T, ss ...string) []netip.Prefix {
	t.Helper()
	out := make([]netip.Prefix, 0, len(ss))
	for _, s := range ss {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			t.Fatalf("parse %q: %v", s, err)
		}
		out = append(out, p)
	}
	return out
}

func addrsOf(ss []Service) string {
	parts := make([]string, len(ss))
	for i, s := range ss {
		parts[i] = s.Addr.String()
	}
	return strings.Join(parts, " ")
}

// TestTableIsWellFormed: every entry is one unzoned address, named, listed
// once, and in the order every sentence renders them in. A zoned address would
// match nothing — netip.Prefix.Contains is false for one — and a duplicate
// would list one service twice in a refusal.
func TestTableIsWellFormed(t *testing.T) {
	seen := map[netip.Addr]bool{}
	ss := Services()
	if len(ss) < 3 {
		t.Fatalf("the table has %d entries", len(ss))
	}
	for i, s := range ss {
		if !s.Addr.IsValid() || s.Addr.Zone() != "" || s.Addr.Is4In6() {
			t.Errorf("entry %d: %v is not a plain address", i, s.Addr)
		}
		if strings.TrimSpace(s.Name) == "" {
			t.Errorf("%s has no name", s.Addr)
		}
		if seen[s.Addr] {
			t.Errorf("%s is listed twice", s.Addr)
		}
		seen[s.Addr] = true
		if !strings.Contains(s.Reason(), s.Addr.String()) {
			t.Errorf("%s: reason %q does not name the address", s.Addr, s.Reason())
		}
		if p := s.Prefix(); p.Bits() != s.Addr.BitLen() || !p.Contains(s.Addr) {
			t.Errorf("%s: host prefix %s", s.Addr, p)
		}
		if i > 0 {
			prev := ss[i-1].Addr
			if prev.Is4() == s.Addr.Is4() && !prev.Less(s.Addr) || !prev.Is4() && s.Addr.Is4() {
				t.Errorf("table out of order at %s after %s", s.Addr, prev)
			}
		}
	}
	// The three the task names, by address: the one every cloud shares, AWS's
	// over IPv6 (inside fc00::/7) and Alibaba's (inside 100.64.0.0/10).
	for _, a := range []string{"169.254.169.254", "fd00:ec2::254", "100.100.100.200"} {
		if _, ok := Lookup(netip.MustParseAddr(a)); !ok {
			t.Errorf("%s is not in the table", a)
		}
	}
}

// TestServicesIsACopy: the table is what every filter is compiled against, so
// a caller sorting the result must not reorder it for everyone.
func TestServicesIsACopy(t *testing.T) {
	ss := Services()
	want := ss[0]
	ss[0] = Service{Addr: netip.MustParseAddr("203.0.113.1"), Name: "tampered"}
	if Services()[0] != want {
		t.Fatal("Services shares its backing array with the table")
	}
}

func TestLookupSeesThroughAMappedSpelling(t *testing.T) {
	if s, ok := Lookup(netip.MustParseAddr("::ffff:169.254.169.254")); !ok || s.Addr.String() != "169.254.169.254" {
		t.Errorf("::ffff:169.254.169.254 = %v %v, want the metadata service", s, ok)
	}
	for _, a := range []string{"169.254.169.253", "8.8.8.8", "fd00:ec2::255"} {
		if _, ok := Lookup(netip.MustParseAddr(a)); ok {
			t.Errorf("%s is not a metadata service", a)
		}
	}
	if _, ok := Lookup(netip.Addr{}); ok {
		t.Error("the zero address is not a metadata service")
	}
}

func TestCanonical(t *testing.T) {
	cases := map[string]string{
		"169.254.0.0/16":         "169.254.0.0/16",
		"169.254.1.2/16":         "169.254.0.0/16",
		"::ffff:169.254.0.0/112": "169.254.0.0/16",
		"::ffff:0.0.0.0/96":      "0.0.0.0/0",
		"fd00::1/8":              "fd00::/8",
	}
	for in, want := range cases {
		got, ok := Canonical(netip.MustParsePrefix(in))
		if !ok || got.String() != want {
			t.Errorf("Canonical(%s) = %v %v, want %s", in, got, ok, want)
		}
	}
	if _, ok := Canonical(netip.MustParsePrefix("::ffff:0.0.0.0/80")); ok {
		t.Error("a mapped prefix shorter than /96 mixes mapped and native space")
	}
	if _, ok := Canonical(netip.Prefix{}); ok {
		t.Error("the zero prefix is not a prefix")
	}
}

// TestWithin is the containment half of the rule: strictly inside, so a
// service's own host prefix is not "containing" it — that is how it is named.
func TestWithin(t *testing.T) {
	cases := map[string]string{
		"169.254.0.0/16":         "169.254.0.23 169.254.42.42 169.254.169.252 169.254.169.254 169.254.170.2 169.254.170.23",
		"169.254.169.0/24":       "169.254.169.252 169.254.169.254",
		"169.254.169.254/32":     "",
		"169.254.100.0/24":       "",
		"100.64.0.0/10":          "100.100.100.200",
		"0.0.0.0/1":              "100.100.100.200",
		"128.0.0.0/1":            "168.63.129.16 169.254.0.23 169.254.42.42 169.254.169.252 169.254.169.254 169.254.170.2 169.254.170.23",
		"168.63.0.0/16":          "168.63.129.16",
		"fc00::/7":               "fd00:42::42 fd00:ec2::23 fd00:ec2::254 fd00:a9fe:a9fe::1 fd20:ce::254",
		"fd00:ec2::/32":          "fd00:ec2::23 fd00:ec2::254",
		"fe80::/10":              "fe80::a9fe:a9fe",
		"2001:db8::/32":          "",
		"10.0.0.0/8":             "",
		"::ffff:169.254.0.0/112": "169.254.0.23 169.254.42.42 169.254.169.252 169.254.169.254 169.254.170.2 169.254.170.23",
	}
	for in, want := range cases {
		if got := addrsOf(Within(netip.MustParsePrefix(in))); got != want {
			t.Errorf("Within(%s) = %q, want %q", in, got, want)
		}
	}
}

// TestCheckIsTheRule: an entry that contains a service is reported unless the
// same list names the service's host prefix or a deny list closes it.
func TestCheckIsTheRule(t *testing.T) {
	cases := []struct {
		name   string
		allow  []string
		closed []string
		want   string // "prefix: addrs; prefix: addrs"
	}{
		{"a containing prefix", []string{"169.254.169.0/24"}, nil, "169.254.169.0/24: 169.254.169.252 169.254.169.254"},
		{"named alongside", []string{"169.254.169.0/24", "169.254.169.254/32"}, nil,
			"169.254.169.0/24: 169.254.169.252"},
		{"named, every one", []string{"169.254.169.0/24", "169.254.169.254/32", "169.254.169.252/32"}, nil, ""},
		{"the host prefix alone", []string{"169.254.169.254/32"}, nil, ""},
		{"an unmasked host prefix names it", []string{"169.254.169.0/24", "169.254.169.254/32", "169.254.169.252/32"}, nil, ""},
		{"closed by a deny", []string{"169.254.169.0/24"}, []string{"169.254.169.252/32", "169.254.169.254/32"}, ""},
		{"closed by a wider deny", []string{"fc00::/7"}, []string{"fd00::/8"}, ""},
		{"partly closed", []string{"fc00::/7"}, []string{"fd00:ec2::/32"},
			"fc00::/7: fd00:42::42 fd00:a9fe:a9fe::1 fd20:ce::254"},
		{"a mapped spelling", []string{"::ffff:100.64.0.0/106"}, nil, "100.64.0.0/10: 100.100.100.200"},
		{"named by a mapped spelling", []string{"100.64.0.0/10", "::ffff:100.100.100.200/128"}, nil, ""},
		{"duplicates once", []string{"168.63.0.0/16", "168.63.1.2/16"}, nil, "168.63.0.0/16: 168.63.129.16"},
		{"nothing to say", []string{"10.0.0.0/8", "140.82.112.0/20"}, nil, ""},
		{"two entries", []string{"fe80::/10", "100.64.0.0/10"}, nil,
			"100.64.0.0/10: 100.100.100.200; fe80::/10: fe80::a9fe:a9fe"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var parts []string
			for _, f := range Check(pfx(t, c.allow...), pfx(t, c.closed...)) {
				parts = append(parts, f.Allow.String()+": "+addrsOf(f.Services))
			}
			if got := strings.Join(parts, "; "); got != c.want {
				t.Errorf("Check = %q, want %q", got, c.want)
			}
		})
	}
	if got := Check([]netip.Prefix{{}}, nil); len(got) != 0 {
		t.Errorf("an unparsable entry is each surface's own check, got %v", got)
	}
}

func TestCarvedListsEachServiceOnce(t *testing.T) {
	got := Carved(pfx(t, "169.254.169.0/24", "169.254.0.0/16", "169.254.170.2/32"), pfx(t, "169.254.0.23/32"))
	if want := "169.254.42.42 169.254.169.252 169.254.169.254 169.254.170.23"; addrsOf(got) != want {
		t.Errorf("Carved = %q, want %q", addrsOf(got), want)
	}
}

// TestSentencesNameTheServiceAndTheAlternative: the refusal is the only thing
// an operator reads, so it says which service, where it is, and both ways out.
func TestSentencesNameTheServiceAndTheAlternative(t *testing.T) {
	one := Check(pfx(t, "fc00::/7"), pfx(t, "fd00:42::42/128", "fd00:ec2::23/128", "fd20:ce::254/128",
		"fd00:a9fe:a9fe::1/128"))
	if len(one) != 1 {
		t.Fatalf("Check = %v", one)
	}
	got := one[0].Explain("the allowlist", "the denylist")
	for _, want := range []string{"fc00::/7 contains the cloud metadata service at fd00:ec2::254 (AWS instance metadata over IPv6) without naming it",
		"Add fd00:ec2::254/128 to the allowlist if a sandbox should reach it, or to the denylist so it stays closed"} {
		if !strings.Contains(got, want) {
			t.Errorf("sentence %q lacks %q", got, want)
		}
	}

	many := Check(pfx(t, "169.254.169.0/24"), nil)[0]
	got = many.Explain("allow_cidrs", "")
	for _, want := range []string{"169.254.169.0/24 contains 2 cloud metadata services without naming them",
		"169.254.169.252 (GKE metadata server for Workload Identity)", "169.254.169.254 (instance metadata on AWS",
		"Add their addresses (169.254.169.252/32, 169.254.169.254/32) to allow_cidrs if a sandbox should reach them, " +
			"or allow a range that leaves them out"} {
		if !strings.Contains(got, want) {
			t.Errorf("sentence %q lacks %q", got, want)
		}
	}
	if r := many.Remedy("the allowlist", "the denylist"); !strings.Contains(r, "so they stay closed") {
		t.Errorf("plural remedy %q", r)
	}
}
