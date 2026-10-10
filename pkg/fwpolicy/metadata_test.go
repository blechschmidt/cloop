package fwpolicy

// metadata_test.go pins the containment algebra's half of Task 20397: a level
// reaches a cloud metadata service only where it names the service, so a
// level beneath one that merely contains a service may not name it; a
// narrowing never names one by accident; and what is shipped to an executor
// says in its denylist what the compiled filter would carve anyway.

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/cloudmeta"
	"github.com/blechschmidt/cloop/pkg/executor"
)

var linkLocal = Rules{AllowCIDRs: []string{"169.254.0.0/16"}, AllowPorts: []int{80}}

// TestPermitsRefusesNamingWhatTheParentOnlyContains: the parent allows the
// range around 169.254.169.254 and every filter compiled from it drops the
// service, so a child naming the service would open what the parent keeps
// closed — and the reason says why rather than calling an address "outside"
// a range it is visibly inside.
func TestPermitsRefusesNamingWhatTheParentOnlyContains(t *testing.T) {
	reasons := Permits(&linkLocal, Rules{AllowCIDRs: []string{"169.254.169.254"}, AllowPorts: []int{80}})
	if len(reasons) != 1 {
		t.Fatalf("reasons = %v, want one", reasons)
	}
	for _, want := range []string{"169.254.169.254/32 is the cloud metadata service at 169.254.169.254",
		"which the governing rule set does not open"} {
		if !strings.Contains(reasons[0], want) {
			t.Errorf("reason %q lacks %q", reasons[0], want)
		}
	}
	// A parent that names it lets the child name it.
	named := Rules{AllowCIDRs: []string{"169.254.0.0/16", "169.254.169.254/32"}, AllowPorts: []int{80}}
	if r := Permits(&named, Rules{AllowCIDRs: []string{"169.254.169.254"}, AllowPorts: []int{80}}); len(r) != 0 {
		t.Errorf("a child naming a service its parent names was refused: %v", r)
	}
}

// TestPermitsAcceptsTheContainingRangeUnderItself: the child's own range
// contains the services as well, so it reaches what the parent reaches and no
// more. Counting the services against it would refuse every copy of a stored
// rule set.
func TestPermitsAcceptsTheContainingRangeUnderItself(t *testing.T) {
	if r := Permits(&linkLocal, linkLocal); len(r) != 0 {
		t.Errorf("a rule set must fit inside itself: %v", r)
	}
	// And a child that names every service its own range contains, under a
	// parent that names them all, fits too.
	var hosts []string
	for _, s := range cloudmeta.Within(netip.MustParsePrefix("169.254.0.0/16")) {
		hosts = append(hosts, s.Prefix().String())
	}
	all := Rules{AllowCIDRs: append([]string{"169.254.0.0/16"}, hosts...), AllowPorts: []int{80}}
	if r := Permits(&all, all); len(r) != 0 {
		t.Errorf("a fully named rule set must fit inside itself: %v", r)
	}
	if r := Permits(&linkLocal, all); len(r) != len(hosts) {
		t.Errorf("under a parent naming none, each of the %d names is a reason; got %v", len(hosts), r)
	}
}

// TestConstrainRemovesANameTheParentDoesNotOpen: tightening a device whose
// rules contain a service without naming it narrows a child that named it —
// the name goes, with a note saying which service and why — and the narrowed
// rule set closes what its own range contains in its denylist, so it is not
// one its next save would refuse.
func TestConstrainRemovesANameTheParentDoesNotOpen(t *testing.T) {
	child := Rules{AllowCIDRs: []string{"169.254.0.0/16", "169.254.169.254/32", "8.8.8.0/24"}, AllowPorts: []int{80}}
	got, notes := Constrain(&linkLocal, child)
	if strings.Join(got.AllowCIDRs, ",") != "169.254.0.0/16" {
		t.Errorf("allowlist = %v, want the parent's range alone", got.AllowCIDRs)
	}
	joined := strings.Join(notes, "; ")
	for _, want := range []string{"169.254.169.254/32 was removed: it is the cloud metadata service at 169.254.169.254",
		"8.8.8.0/24 was removed", "its denylist now names the cloud metadata services"} {
		if !strings.Contains(joined, want) {
			t.Errorf("notes %q lack %q", joined, want)
		}
	}
	if f := got.MetadataFindings(); len(f) != 0 {
		t.Errorf("the narrowed rule set is one its own save would refuse: %v", f)
	}
	if r := Permits(&linkLocal, got); len(r) != 0 {
		t.Errorf("the narrowed rule set does not fit: %v", r)
	}
}

// TestConstrainNeverNamesAServiceByAccident: intersecting a child's range with
// a parent that names a service yields that service's host prefix, and a
// rule set holding it reaches the service — which the child's range never
// did. The narrowing must not hand it over.
func TestConstrainNeverNamesAServiceByAccident(t *testing.T) {
	parent := Rules{AllowCIDRs: []string{"169.254.169.254/32", "1.1.1.0/24"}, AllowPorts: []int{80}}
	child := Rules{AllowCIDRs: []string{"169.254.0.0/16", "8.8.8.0/24"}, AllowPorts: []int{80}}
	got, _ := Constrain(&parent, child)
	for _, c := range got.AllowCIDRs {
		if c == "169.254.169.254/32" {
			t.Fatalf("the narrowing named the metadata service the child only contained: %v", got.AllowCIDRs)
		}
	}
	if r := Permits(&child, got); len(r) != 0 {
		t.Errorf("the narrowing reaches beyond the child: %v", r)
	}
}

// TestCloseMetadataWritesTheCarvesIntoTheDenylist: what the dispatch step
// ships, so an agent that predates the rule closes the services too. A
// resolver on a service is left out: a deny would close its port 53 as well.
func TestCloseMetadataWritesTheCarvesIntoTheDenylist(t *testing.T) {
	r := Rules{AllowCIDRs: []string{"169.254.0.0/16"}, AllowPorts: []int{53, 80}, Resolvers: []string{"169.254.169.254"},
		DenyCIDRs: []string{"169.254.0.23/32"}}
	got := CloseMetadata(r)
	want := []string{"169.254.0.23/32", "169.254.42.42/32", "169.254.169.252/32", "169.254.170.2/32", "169.254.170.23/32"}
	if strings.Join(got.DenyCIDRs, ",") != strings.Join(want, ",") {
		t.Errorf("denylist = %v, want %v", got.DenyCIDRs, want)
	}
	if strings.Join(got.AllowCIDRs, ",") != "169.254.0.0/16" || len(got.Resolvers) != 1 {
		t.Errorf("CloseMetadata changed more than the denylist: %+v", got)
	}
	if again := CloseMetadata(got); !Equal(again, got) {
		t.Errorf("CloseMetadata is not idempotent: %v then %v", got.Describe(), again.Describe())
	}
	clean := Rules{AllowPublicInternet: true, AllowPorts: []int{443}}
	if got := CloseMetadata(clean); !Equal(got, clean) {
		t.Errorf("a rule set with nothing to close came back changed: %v", got.Describe())
	}
}

// TestResolveShipsTheClosedRules: the dispatched rules carry the closure, and
// still pass the driver's own containment proof.
func TestResolveShipsTheClosedRules(t *testing.T) {
	device := Rules{AllowPublicInternet: true, AllowCIDRs: []string{"fc00::/7"}, AllowPorts: []int{443},
		Resolvers: []string{"1.1.1.1"}}
	withSource(t, fakeSource{devices: map[string]*Rules{"sgx": &device}})
	ex := fakeExecutor{id: "sgx", posture: executor.EgressPosture{Enforceable: true, RemovesNetwork: true}}
	spec := executor.Spec{}
	if _, err := Resolve(&spec, ex, "/srv/p"); err != nil {
		t.Fatal(err)
	}
	if spec.EgressRules == nil {
		t.Fatal("no rules were composed")
	}
	deny := strings.Join(spec.EgressRules.DenyCIDRs, ",")
	for _, s := range cloudmeta.Within(netip.MustParsePrefix("fc00::/7")) {
		if !strings.Contains(deny, s.Prefix().String()) {
			t.Errorf("the shipped denylist %q does not close %s", deny, s.Describe())
		}
	}
	if err := CheckAtDriver(spec, nil, "", "sgx"); err != nil {
		t.Errorf("the driver must accept the closed rules: %v", err)
	}
}
