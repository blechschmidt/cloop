package authz

import "testing"

type fixedDirectory map[string][]string

func (d fixedDirectory) DirectoryGroups(s *Subject) []string { return d[s.Email] }

type fixedRuntime []Binding

func (r fixedRuntime) RuntimeBindings() []Binding { return r }

// Task 20478: a project somebody owns is private, and the one kind of policy
// answer that reaches into it for a non-admin is a binding naming it.
func TestProjectPinnedTellsABindingNamingTheProjectFromAHubWideOne(t *testing.T) {
	r, err := New(Config{
		DefaultRole: RoleViewer,
		Bindings: []Binding{
			{Claim: ClaimGroup, Value: "eng", Role: RoleOperator},
			{Claim: ClaimGroup, Value: "eng", Role: RoleMaintainer, Project: "payments"},
		},
		AdminEmails: []string{"root@example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}
	eng := &Subject{Sub: "s1", Email: "bob@example.com", Groups: []string{"eng"}}
	other := &Subject{Sub: "s2", Email: "carol@example.com"}
	payments := Scope{Project: "payments", ProjectPath: "/srv/payments"}
	infra := Scope{Project: "infra", ProjectPath: "/srv/infra"}

	if d := r.Resolve(eng, payments); !d.ProjectPinned() || d.Role != RoleMaintainer {
		t.Errorf("a binding naming the project: %s pinned=%v", d.Role, d.ProjectPinned())
	}
	if d := r.Resolve(eng, infra); d.ProjectPinned() {
		t.Errorf("a hub-wide binding read as pinned on another project: %+v", d)
	}
	if d := r.Resolve(other, payments); d.ProjectPinned() || d.Source != SourceDefaultRole {
		t.Errorf("the default role read as pinned: %+v", d)
	}
	if d := r.Resolve(&Subject{Sub: "s3", Email: "root@example.com"}, payments); d.ProjectPinned() {
		t.Errorf("admin_emails, a hub-wide binding, read as pinned: %+v", d)
	}
	if !r.PinsProjects() {
		t.Error("PinsProjects missed a binding naming a project")
	}

	flat, _ := New(Config{Bindings: []Binding{{Claim: ClaimGroup, Value: "eng", Role: RoleOperator}}})
	if flat.PinsProjects() {
		t.Error("PinsProjects reported a policy that names no project")
	}
	// A runtime binding naming a project pins it too; a deny does not admit.
	withRuntime, _ := New(Config{Runtime: fixedRuntime{{Claim: ClaimEmail, Value: "bob@example.com", Role: RoleViewer, Project: "/srv/x"}}})
	if !withRuntime.PinsProjects() {
		t.Error("PinsProjects missed a runtime binding naming a project")
	}
	denyOnly, _ := New(Config{Runtime: fixedRuntime{{Claim: ClaimEmail, Value: "bob@example.com", Deny: true, Project: "/srv/x"}}})
	if denyOnly.PinsProjects() {
		t.Error("a deny binding was counted as admitting anyone to a project")
	}
	if d := withRuntime.Resolve(eng, Scope{ProjectPath: "/srv/x"}); !d.ProjectPinned() || d.Source != SourceRuntimeBinding {
		t.Errorf("a runtime binding naming the project: %+v", d)
	}
	var nilResolver *Resolver
	if nilResolver.PinsProjects() || nilResolver.DirectoryGroups(eng) != nil {
		t.Error("a nil resolver must answer nothing")
	}
}

func TestClaimValueInMatchesLikeABinding(t *testing.T) {
	for _, c := range []struct {
		values []string
		want   string
		ok     bool
	}{
		{[]string{"Engineering"}, "engineering", true},
		{[]string{"/engineering"}, "Engineering", true},
		{[]string{" eng "}, "/eng", true},
		{[]string{"eng-ops"}, "eng", false},
		{nil, "eng", false},
		{[]string{""}, "", false},
	} {
		if got := ClaimValueIn(c.values, c.want); got != c.ok {
			t.Errorf("ClaimValueIn(%q, %q) = %v, want %v", c.values, c.want, got, c.ok)
		}
	}
	if NormalizeClaimValue(" /Ops ") != "Ops" {
		t.Errorf("NormalizeClaimValue = %q", NormalizeClaimValue(" /Ops "))
	}
}

func TestDirectoryGroupsIsTheBindingsAnswer(t *testing.T) {
	r, err := New(Config{Directory: fixedDirectory{"bob@example.com": {"Payments"}}})
	if err != nil {
		t.Fatal(err)
	}
	if got := r.DirectoryGroups(&Subject{Email: "bob@example.com"}); len(got) != 1 || got[0] != "Payments" {
		t.Errorf("DirectoryGroups = %v", got)
	}
	plain, _ := New(Config{})
	if plain.DirectoryGroups(&Subject{Email: "bob@example.com"}) != nil {
		t.Error("a hub without a directory reported groups")
	}
}

// The project-access sources are wire strings in audit payloads: pinned like
// every other source.
func TestProjectAccessSourcesAreStable(t *testing.T) {
	for src, want := range map[Source]string{
		SourceProjectMember:  "project_member",
		SourceProjectOwner:   "project_owner",
		SourceProjectTeam:    "project_team",
		SourceProjectPrivate: "project_private",
	} {
		if string(src) != want {
			t.Errorf("source %q, want %q", src, want)
		}
	}
}
