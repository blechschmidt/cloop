package hubteam

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/internal/statedbtest"
	"github.com/blechschmidt/cloop/pkg/authz"
	"github.com/blechschmidt/cloop/pkg/projectmember"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

func openStore(t *testing.T, opts ...Option) (*Store, *statedb.DB) {
	t.Helper()
	db := statedbtest.Open(t)
	s, err := New(db, opts...)
	if err != nil {
		t.Fatal(err)
	}
	return s, db
}

func TestSlugs(t *testing.T) {
	for _, ok := range []string{"payments", "Payments", " sre-oncall ", "team.a_b", "a", strings.Repeat("x", MaxSlugLen)} {
		if _, err := ParseSlug(ok); err != nil {
			t.Errorf("ParseSlug(%q) = %v, want ok", ok, err)
		}
	}
	for _, bad := range []string{"", "-lead", ".x", "a b", "a/b", "team:x", "x@y", strings.Repeat("x", MaxSlugLen+1), "ü"} {
		if _, err := ParseSlug(bad); err == nil {
			t.Errorf("ParseSlug(%q) accepted", bad)
		}
	}
	if got := ShareKey(" Payments "); got != "team:payments" {
		t.Errorf("ShareKey = %q", got)
	}
	if slug, ok := SlugOfShareKey("TEAM:Payments"); !ok || slug != "payments" {
		t.Errorf("SlugOfShareKey = %q %v", slug, ok)
	}
	for _, key := range []string{"payments", "alice@example.com", "sub:team:x", "team:", "team:-x"} {
		if _, ok := SlugOfShareKey(key); ok {
			t.Errorf("SlugOfShareKey(%q) named a team", key)
		}
	}
	// A team's member is a person; a share key is the namespace's other half.
	if _, err := ParseMemberKey("team:payments"); err == nil {
		t.Error("a team was accepted as a team's member")
	}
	if k, err := ParseMemberKey("Bob@Example.com"); err != nil || k != "bob@example.com" {
		t.Errorf("ParseMemberKey = %q %v", k, err)
	}
}

func TestCreateUpdateDeleteAndAudit(t *testing.T) {
	s, db := openStore(t)
	var audited []statedb.TeamChange
	audit := func(c statedb.TeamChange) ([]*statedb.AuditEvent, error) {
		audited = append(audited, c)
		return []*statedb.AuditEvent{{Actor: "root@example.com", EventType: "team.test", EntityType: "team", EntityID: "x"}}, nil
	}

	created, err := s.Create(Team{Slug: "Payments", Name: " Payments team ", IdPGroup: "/payments-devs", CreatedBy: "root@example.com"}, audit)
	if err != nil {
		t.Fatal(err)
	}
	if created.Slug != "payments" || created.Name != "Payments team" || created.IdPGroup != "payments-devs" {
		t.Errorf("created %+v: slug, name and group are normalised", created)
	}
	if _, err := s.Create(Team{Slug: "payments"}, audit); !errors.Is(err, statedb.ErrTeamExists) {
		t.Errorf("a second team under one slug: %v", err)
	}
	if _, err := s.Create(Team{Slug: Everyone}, audit); err == nil {
		t.Error("the built-in team was created")
	}
	if _, err := s.Create(Team{Slug: "x", Name: strings.Repeat("n", MaxNameLen+1)}, audit); err == nil {
		t.Error("an over-long name was stored")
	}

	if _, _, err := s.AddMember("payments", "Bob@Example.com", "root@example.com", audit); err != nil {
		t.Fatal(err)
	}
	if _, existed, err := s.AddMember("payments", "bob@example.com", "root@example.com", audit); err != nil || !existed {
		t.Errorf("adding a member twice: existed %v, %v", existed, err)
	}
	if _, _, err := s.AddMember("nope", "bob@example.com", "root", audit); !errors.Is(err, statedb.ErrTeamNotFound) {
		t.Errorf("adding to a missing team: %v", err)
	}
	if _, _, err := s.AddMember(Everyone, "bob@example.com", "root", audit); err == nil {
		t.Error("a member was added to the built-in team")
	}

	updated, prev, err := s.Update(Team{Slug: "payments", Name: "Payments", SCIMGroup: "Payments Engineering", UpdatedBy: "root"}, audit)
	if err != nil {
		t.Fatal(err)
	}
	if updated.IdPGroup != "" || updated.SCIMGroup != "Payments Engineering" || prev.IdPGroup != "payments-devs" {
		t.Errorf("update: now %+v, was %+v", updated, prev)
	}
	if len(updated.Members) != 1 {
		t.Errorf("an update dropped the members: %+v", updated.Members)
	}

	// A project shared with the team, then the team deleted: the share goes
	// in the same commit, and is reported.
	members, err := projectmember.New(db)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := members.Grant(projectmember.Member{ProjectPath: "/srv/payments", IdentityKey: "team:payments", Role: authz.RoleOperator}, nil); err != nil {
		t.Fatal(err)
	}
	gone, shares, err := s.Delete("payments", audit)
	if err != nil {
		t.Fatal(err)
	}
	if gone.Slug != "payments" || len(gone.Members) != 1 || len(shares) != 1 || shares[0].ProjectPath != "/srv/payments" {
		t.Errorf("delete reported %+v and shares %+v", gone, shares)
	}
	if _ = members.Refresh(); len(members.All()) != 0 {
		t.Errorf("the team's share outlived it: %+v", members.All())
	}
	if _, ok := s.Get("payments"); ok {
		t.Error("the deleted team is still listed")
	}
	// Create, add, update, delete: a repeated add and a refused one changed
	// nothing and recorded nothing.
	if len(audited) != 4 {
		t.Errorf("audit callbacks = %d, want one per write that changed something (4)", len(audited))
	}
	evs, _, err := db.ListAuditEvents(statedb.AuditFilter{EntityType: "team"})
	if err != nil || len(evs) != 4 {
		t.Errorf("audit rows committed = %d (%v), want 4", len(evs), err)
	}
}

// A share naming a team that does not exist is refused inside its own
// transaction: otherwise it would grant nothing today and everything to
// whoever is on a team created under that slug later.
func TestAShareNeedsItsTeam(t *testing.T) {
	_, db := openStore(t)
	members, err := projectmember.New(db)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = members.Grant(projectmember.Member{ProjectPath: "/srv/x", IdentityKey: "team:ghosts", Role: authz.RoleViewer}, nil)
	if !errors.Is(err, statedb.ErrTeamNotFound) {
		t.Fatalf("a share with a missing team: %v", err)
	}
	// Everyone needs no row.
	if _, _, err := members.Grant(projectmember.Member{ProjectPath: "/srv/x", IdentityKey: "team:everyone", Role: authz.RoleViewer}, nil); err != nil {
		t.Fatalf("a share with everyone: %v", err)
	}
}

func TestWhoIsOnATeam(t *testing.T) {
	s, _ := openStore(t)
	for _, team := range []Team{
		{Slug: "named"},
		{Slug: "devs", IdPGroup: "Engineering"},
		{Slug: "provisioned", SCIMGroup: "Payments"},
	} {
		if _, err := s.Create(team, nil); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := s.AddMember("named", "alice@example.com", "root", nil); err != nil {
		t.Fatal(err)
	}
	if !s.NeedsDirectory() {
		t.Error("a team following a provisioned group must ask the directory")
	}

	cases := []struct {
		name string
		f    Facts
		want []string
	}{
		{"nobody", Facts{}, nil},
		{"a key spelled like a share is nobody's", Facts{Key: "team:named"}, nil},
		{"a stranger is on Everyone alone", Facts{Key: "carol@example.com"}, []string{Everyone}},
		{"by name, case-insensitively", Facts{Key: "Alice@Example.com"}, []string{Everyone, "named"}},
		{"by group claim, like a binding", Facts{Key: "bob@example.com", Groups: []string{"/engineering"}}, []string{Everyone, "devs"}},
		{"by provisioned group", Facts{Key: "dana@example.com", SCIMGroups: []string{"payments"}}, []string{Everyone, "provisioned"}},
		{"a group claim is not a provisioned group", Facts{Key: "erin@example.com", Groups: []string{"Payments"}}, []string{Everyone}},
	}
	for _, c := range cases {
		got := s.TeamsOf(c.f)
		if len(got) != len(c.want) {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
			continue
		}
		for _, slug := range c.want {
			if !got[slug] {
				t.Errorf("%s: %v, want %v", c.name, got, c.want)
			}
		}
	}
	if !s.IsMember("devs", Facts{Key: "bob@example.com", Groups: []string{"ENGINEERING"}}) {
		t.Error("IsMember disagrees with TeamsOf")
	}
	var nilStore *Store
	if got := nilStore.TeamsOf(Facts{Key: "a@b.c"}); len(got) != 1 || !got[Everyone] {
		t.Errorf("a hub without teams knows only Everyone: %v", got)
	}
}

// Every reload that finds the list changed says which teams changed — so a hub
// can close the streams of somebody who left one — and a display-only edit
// is not an access change.
func TestChangesAreReported(t *testing.T) {
	var mu sync.Mutex
	var changes []Change
	got := make(chan struct{}, 8)
	s, db := openStore(t, WithOnChange(func(c Change) {
		mu.Lock()
		changes = append(changes, c)
		mu.Unlock()
		got <- struct{}{}
	}))
	wait := func(what string) Change {
		t.Helper()
		select {
		case <-got:
		case <-time.After(5 * time.Second):
			t.Fatalf("no change reported for %s", what)
		}
		mu.Lock()
		defer mu.Unlock()
		return changes[len(changes)-1]
	}
	if _, err := s.Create(Team{Slug: "ops"}, nil); err != nil {
		t.Fatal(err)
	}
	if c := wait("a creation"); len(c.Teams) != 1 || c.Teams[0] != "ops" {
		t.Errorf("creation reported %+v", c)
	}
	// Another writer: seen at the next refresh.
	if _, _, err := db.AddTeamMember(statedb.TeamMemberRow{TeamSlug: "ops", IdentityKey: "bob@example.com"}, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.Refresh(); err != nil {
		t.Fatal(err)
	}
	if c := wait("another writer's member"); len(c.Teams) != 1 || c.Teams[0] != "ops" {
		t.Errorf("a member added elsewhere reported %+v", c)
	}
	if _, _, err := s.Update(Team{Slug: "ops", Name: "Operations"}, nil); err != nil {
		t.Fatal(err)
	}
	select {
	case <-got:
		t.Errorf("a rename was reported as an access change: %+v", changes[len(changes)-1])
	case <-time.After(200 * time.Millisecond):
	}
}

// A refresh that cannot read the table keeps the last good answer: an empty
// one would take every project a team was given away from its members.
func TestAFailedRefreshKeepsTheLastAnswer(t *testing.T) {
	var reported []error
	var mu sync.Mutex
	s, db := openStore(t, WithErrorHandler(func(err error) { mu.Lock(); reported = append(reported, err); mu.Unlock() }))
	if _, err := s.Create(Team{Slug: "ops"}, nil); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.AddMember("ops", "bob@example.com", "root", nil); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s.Refresh(); err == nil {
		t.Fatal("a refresh of a closed database succeeded")
	}
	if !s.IsMember("ops", Facts{Key: "bob@example.com"}) {
		t.Error("a failed refresh dropped a member")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(reported) == 0 {
		t.Error("the failure was not reported")
	}
}
