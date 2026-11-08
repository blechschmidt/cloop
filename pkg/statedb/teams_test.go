package statedb

import (
	"errors"
	"strings"
	"testing"
)

func TestValidTeamSlug(t *testing.T) {
	for _, ok := range []string{"a", "payments", "sre-oncall", "a.b_c", strings.Repeat("x", MaxTeamSlugLen)} {
		if !ValidTeamSlug(ok) {
			t.Errorf("ValidTeamSlug(%q) = false", ok)
		}
	}
	for _, bad := range []string{"", "Payments", "-x", ".x", "a b", "a:b", "a@b", strings.Repeat("x", MaxTeamSlugLen+1)} {
		if ValidTeamSlug(bad) {
			t.Errorf("ValidTeamSlug(%q) = true", bad)
		}
	}
	if slug, ok := TeamSlugOfKey("team:ops"); !ok || slug != "ops" {
		t.Errorf("TeamSlugOfKey = %q %v", slug, ok)
	}
	if _, ok := TeamSlugOfKey("ops@example.com"); ok {
		t.Error("a person's key named a team")
	}
}

// Deleting a team takes its named members and every project share naming it
// in the same commit, so no share outlives its team (Task 20478).
func TestDeleteTeamTakesItsSharesWithIt(t *testing.T) {
	db := newAuditDB(t)
	if _, err := db.CreateTeam(TeamRow{Slug: "ops", Name: "Ops", CreatedBy: "root"}, nil); err != nil {
		t.Fatal(err)
	}
	if _, _, err := db.AddTeamMember(TeamMemberRow{TeamSlug: "ops", IdentityKey: "bob@corp.example"}, nil); err != nil {
		t.Fatal(err)
	}
	for _, r := range []ProjectMemberRow{
		{ProjectPath: "/srv/a", IdentityKey: "team:ops", Role: "operator"},
		{ProjectPath: "/srv/b", IdentityKey: "team:ops", Role: "viewer"},
		{ProjectPath: "/srv/a", IdentityKey: "carol@corp.example", Role: "viewer"},
	} {
		if _, _, err := db.PutProjectMember(r, nil); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := db.PutProjectMember(ProjectMemberRow{ProjectPath: "/srv/a", IdentityKey: "team:nobody", Role: "viewer"}, nil); !errors.Is(err, ErrTeamNotFound) {
		t.Fatalf("a share with a missing team: %v", err)
	}
	var change TeamChange
	team, members, shares, err := db.DeleteTeam("ops", func(c TeamChange) ([]*AuditEvent, error) {
		change = c
		return []*AuditEvent{{Actor: "root", EventType: "team.delete", EntityType: "team", EntityID: "ops"}}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if team.Slug != "ops" || len(members) != 1 || len(shares) != 2 {
		t.Fatalf("deleted %+v with %d members and %d shares", team, len(members), len(shares))
	}
	if change.Prev == nil || len(change.RemovedShares) != 2 || len(change.RemovedMembers) != 1 {
		t.Errorf("the audit saw %+v", change)
	}
	rows, _ := db.ListProjectMembers()
	if len(rows) != 1 || rows[0].IdentityKey != "carol@corp.example" {
		t.Errorf("after the delete project_members holds %+v", rows)
	}
	if left, _ := db.ListTeamMembers(); len(left) != 0 {
		t.Errorf("the team's members outlived it: %+v", left)
	}
	if _, _, _, err := db.DeleteTeam("ops", nil); !errors.Is(err, ErrTeamNotFound) {
		t.Errorf("deleting it again: %v", err)
	}
	// A refused audit refuses the change.
	if _, err := db.CreateTeam(TeamRow{Slug: "ops2"}, func(TeamChange) ([]*AuditEvent, error) {
		return nil, errors.New("no record, no change")
	}); err == nil {
		t.Error("a team was created without its audit row")
	}
	if teams, _ := db.ListTeams(); len(teams) != 0 {
		t.Errorf("the refused team was stored: %+v", teams)
	}
}

// Offboarding severs every named team membership of every spelling of the
// person, in the credential transaction.
func TestOffboardSeversTeamMemberships(t *testing.T) {
	db := newAuditDB(t)
	for _, slug := range []string{"ops", "payments"} {
		if _, err := db.CreateTeam(TeamRow{Slug: slug}, nil); err != nil {
			t.Fatal(err)
		}
	}
	for _, m := range []TeamMemberRow{
		{TeamSlug: "ops", IdentityKey: "bob@corp.example"},
		{TeamSlug: "payments", IdentityKey: "sub:bob-7"},
		{TeamSlug: "ops", IdentityKey: "carol@corp.example"},
	} {
		if _, _, err := db.AddTeamMember(m, nil); err != nil {
			t.Fatal(err)
		}
	}
	applied, err := db.OffboardIdentity(OffboardWrite{
		IdentityKey: "bob@corp.example",
		MemberKeys:  []string{"bob@corp.example", "sub:bob-7"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(applied.TeamMembers) != 2 || !applied.Severed() {
		t.Fatalf("severed %+v, want bob's two team memberships", applied.TeamMembers)
	}
	left, _ := db.ListTeamMembers()
	if len(left) != 1 || left[0].IdentityKey != "carol@corp.example" {
		t.Errorf("after offboarding bob the teams hold %+v", left)
	}
}
