package authz

// Provisioned groups and the account identifiers a SCIM directory matches on
// (Task 20415).

import (
	"strings"
	"sync/atomic"
	"testing"
)

// fakeDirectory answers from a map keyed by email, and counts the questions.
type fakeDirectory struct {
	groups map[string][]string
	asked  atomic.Int64
}

func (d *fakeDirectory) DirectoryGroups(s *Subject) []string {
	d.asked.Add(1)
	return d.groups[strings.ToLower(s.Email)]
}

func TestProvisionedGroupsComeFromTheDirectoryAtEveryDecision(t *testing.T) {
	dir := &fakeDirectory{groups: map[string][]string{"alice@example.com": {"cloop-admins", "0f3b-ext"}}}
	r, err := New(Config{
		Bindings: []Binding{
			{Claim: ClaimSCIMGroup, Value: "cloop-admins", Role: RoleAdmin},
			{Claim: ClaimSCIMGroup, Value: "0F3B-EXT", Role: RoleViewer, Project: "payments"},
		},
		Directory: dir,
	})
	if err != nil {
		t.Fatal(err)
	}
	alice := &Subject{Sub: "a", Email: "alice@example.com"}
	if d := r.Resolve(alice, GlobalScope); d.Role != RoleAdmin {
		t.Fatalf("provisioned member resolves to %s", d.Role)
	}
	// The project-scoped binding names the group by external id, case
	// folded, and narrows the global admin there.
	if d := r.Resolve(alice, Scope{Project: "payments"}); d.Role != RoleViewer {
		t.Fatalf("on payments: %s", d.Role)
	}
	if alice.SCIMGroups != nil {
		t.Fatal("Resolve wrote the directory's answer into the caller's subject")
	}
	// The directory changes; the next decision sees it.
	dir.groups["alice@example.com"] = nil
	if d := r.Resolve(alice, GlobalScope); d.Role != RoleNone {
		t.Fatalf("after the removal: %s", d.Role)
	}
	if dir.asked.Load() < 3 {
		t.Fatalf("the directory was asked %d times for 3 decisions", dir.asked.Load())
	}
}

// TestASubjectCannotAssertProvisionedGroups: SCIMGroups on a subject is
// discarded, with a directory and without one.
func TestASubjectCannotAssertProvisionedGroups(t *testing.T) {
	forged := &Subject{Sub: "m", Email: "mallory@example.com", SCIMGroups: []string{"cloop-admins"}}
	bindings := []Binding{{Claim: ClaimSCIMGroup, Value: "cloop-admins", Role: RoleAdmin}}
	for name, cfg := range map[string]Config{
		"no directory":    {Bindings: bindings},
		"with directory":  {Bindings: bindings, Directory: &fakeDirectory{}},
		"runtime binding": {Runtime: listRuntime(bindings)},
	} {
		r, err := New(cfg)
		if err != nil {
			t.Fatal(err)
		}
		if d := r.Resolve(forged, GlobalScope); d.Role == RoleAdmin {
			t.Fatalf("%s: a subject's own SCIMGroups were believed", name)
		}
	}
}

type listRuntime []Binding

func (s listRuntime) RuntimeBindings() []Binding { return s }

func TestADenyMayNameAProvisionedGroup(t *testing.T) {
	dir := &fakeDirectory{groups: map[string][]string{"bob@example.com": {"contractors"}}}
	deny, err := NormalizeBinding(Binding{Claim: ClaimSCIMGroup, Value: "Contractors", Deny: true})
	if err != nil {
		t.Fatal(err)
	}
	r, err := New(Config{AdminEmails: []string{"bob@example.com"}, Runtime: listRuntime{deny}, Directory: dir})
	if err != nil {
		t.Fatal(err)
	}
	bob := &Subject{Sub: "b", Email: "bob@example.com"}
	if b := r.DeniedBy(bob, GlobalScope); b == nil {
		t.Fatal("a deny on a provisioned group did not reach its member")
	}
	if d := r.Resolve(bob, GlobalScope); d.Source != SourceRuntimeDeny {
		t.Fatalf("Resolve: %s from %s", d.Role, d.Source)
	}
	// A runtime layer with no group deny does not ask the directory at all.
	quiet := &fakeDirectory{}
	other, _ := NormalizeBinding(Binding{Claim: ClaimEmail, Value: "eve@example.com", Deny: true})
	r2, _ := New(Config{Runtime: listRuntime{other}, Directory: quiet})
	r2.DeniedBy(bob, GlobalScope)
	if quiet.asked.Load() != 0 {
		t.Fatal("DeniedBy asked the directory with no scim_group deny in force")
	}
}

func TestAccountClaimsMatch(t *testing.T) {
	s := &Subject{Sub: "pairwise-sub", Email: "a@example.com", Username: "Alice@Contoso.com",
		OID: "6F9A0C3E-6C1B-4B7E-9D36-0A5B5C3F1E01"}
	for _, b := range []Binding{
		{Claim: ClaimUsername, Value: "alice@contoso.com"},
		{Claim: ClaimOID, Value: "6f9a0c3e-6c1b-4b7e-9d36-0a5b5c3f1e01"},
	} {
		nb, err := NormalizeBinding(Binding{Claim: b.Claim, Value: b.Value, Deny: true})
		if err != nil {
			t.Fatalf("NormalizeBinding(%s): %v", b.Claim, err)
		}
		if !nb.matches(s) {
			t.Errorf("%s=%s does not match %+v", nb.Claim, nb.Value, s)
		}
		if nb.matches(&Subject{Sub: "x", Email: "x@example.com"}) {
			t.Errorf("%s matched a subject that released no such claim", nb.Claim)
		}
	}
	if !s.released(ClaimUsername) || !s.released(ClaimOID) || s.released(ClaimSCIMGroup) {
		t.Fatalf("PresentClaims = %v", s.PresentClaims())
	}
}

// TestAProvisionedGroupBindingIsNeverUnsatisfiable: the token carries no
// provisioned groups, and that says nothing about a scim_group binding.
func TestAProvisionedGroupBindingIsNeverUnsatisfiable(t *testing.T) {
	r, err := New(Config{Bindings: []Binding{
		{Claim: ClaimSCIMGroup, Value: "eng", Role: RoleOperator},
		{Claim: ClaimGroup, Value: "eng", Role: RoleOperator},
	}})
	if err != nil {
		t.Fatal(err)
	}
	gaps := r.UnsatisfiableBindings(&Subject{Sub: "s", Email: "e@example.com"})
	if len(gaps) != 1 || gaps[0].Claim != ClaimGroup {
		t.Fatalf("UnsatisfiableBindings = %+v", gaps)
	}
}
