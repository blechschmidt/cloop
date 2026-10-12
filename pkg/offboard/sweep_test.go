package offboard

// Which identities' Claude homes no hub member keeps (Task 20422).

import (
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/statedb"
)

func putDeny(t *testing.T, db *statedb.DB, claim, value, project, reason string) {
	t.Helper()
	if _, err := db.PutRoleBinding(statedb.RoleBindingRow{Effect: statedb.RoleEffectDeny, Claim: claim, Value: value,
		Project: project, Reason: reason}); err != nil {
		t.Fatal(err)
	}
}

// TestDeniedIdentitiesFollowsTheDenyAndItsExceptions: a hub-wide deny names
// the person under every spelling the hub resolves — a subject a session
// carries beside the email, the email a SCIM user carries for a
// preferred_username deny — and a SCIM suspension still in force, a legal
// hold, a project-scoped deny and an allow name nobody.
func TestDeniedIdentitiesFollowsTheDenyAndItsExceptions(t *testing.T) {
	db := testDB(t)
	// alice: offboarded; a session links her email to her subject.
	putSession(t, db, "s-alice", "u-alice", "alice@example.com")
	putDeny(t, db, "email", "alice@example.com", "", "left")
	// bob: denied by subject alone.
	putDeny(t, db, "sub", "u-bob", "", "left")
	// carol: a preferred_username deny, resolved through the SCIM directory.
	if _, err := db.WriteSCIMUser(statedb.SCIMUserWrite{Create: true, Row: statedb.SCIMUserRow{
		ID: "scim-carol", UserName: "carol", Email: "carol@example.com", Active: true}}); err != nil {
		t.Fatal(err)
	}
	putDeny(t, db, "username", "carol", "", "left")
	// dave: suspended at the identity provider, the suspension still in force.
	reason := "deactivated at the identity provider"
	if _, err := db.WriteSCIMUser(statedb.SCIMUserWrite{Create: true, Row: statedb.SCIMUserRow{
		ID: "scim-dave", UserName: "dave", Email: "dave@example.com", Active: false},
		Suspend: &statedb.SCIMSuspendWrite{
			Denies: []statedb.RoleBindingRow{{Effect: statedb.RoleEffectDeny, Claim: "email",
				Value: "dave@example.com", Reason: reason}},
			Record: statedb.SCIMSuspensionRecord{By: "scim:entra", Reason: reason, Identity: "dave@example.com"},
		}}); err != nil {
		t.Fatal(err)
	}
	// erin: offboarded under a legal hold placed on her subject, which a
	// session links to the email the deny names.
	putSession(t, db, "s-erin", "u-erin", "erin@example.com")
	putDeny(t, db, "email", "erin@example.com", "", "left")
	if err := db.PutLegalHold(statedb.LegalHoldRow{Identity: "sub:u-erin", Reason: "LH-1", PlacedAt: time.Now()}, nil); err != nil {
		t.Fatal(err)
	}
	// frank: denied on one project only. gina: allowed.
	putDeny(t, db, "email", "frank@example.com", "/srv/app", "not here")
	if _, err := db.PutRoleBinding(statedb.RoleBindingRow{Effect: statedb.RoleEffectAllow, Claim: "email",
		Value: "gina@example.com", Role: "viewer"}); err != nil {
		t.Fatal(err)
	}

	denied, held, err := DeniedIdentities(db)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(OwnerKeysOf(denied), " ")
	if want := "alice@example.com carol@example.com sub:u-alice sub:u-bob"; got != want {
		t.Fatalf("denied keys = %q, want %q", got, want)
	}
	if strings.Join(held, ",") != "erin@example.com" {
		t.Fatalf("held = %v, want erin by her canonical key", held)
	}
	for _, id := range denied {
		if id.Keys[0] == "alice@example.com" && (len(id.Keys) != 2 || id.Denies[0] != "email=alice@example.com") {
			t.Fatalf("alice is %+v, want both spellings and the deny naming her", id)
		}
	}

	// Once the suspension is lifted into an offboarding — the record cleared,
	// the deny an offboarding's — dave is swept like anyone.
	putDeny(t, db, "sub", "u-dave", "", "offboarded after 30 days")
	denied, _, err = DeniedIdentities(db)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(OwnerKeysOf(denied), " "), "sub:u-dave") {
		t.Fatalf("an offboarding's deny beside a suspension's was not followed: %v", OwnerKeysOf(denied))
	}
}

// TestAKeptOffboardingRecordsItsHold: --keep-credentials is a legal hold, and
// the members' sweep only honours one it can read — so the run records it on
// the identity before it denies anything, and the sweep then leaves the
// person's homes alone.
func TestAKeptOffboardingRecordsItsHold(t *testing.T) {
	db := testDB(t)
	putSession(t, db, "s-alice", "u-alice", "alice@example.com")
	o := baseOptions(db, "alice@example.com")
	o.KeepCredentials = true
	rep, err := Run(o)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range rep.Failures {
		if f.Surface == "hold" {
			t.Fatalf("the hold was not recorded: %s", f.Detail)
		}
	}
	h, ok, err := db.LegalHoldFor([]string{"alice@example.com"})
	if err != nil || !ok {
		t.Fatalf("no hold recorded: %v %v", ok, err)
	}
	if h.Reason != o.Reason || h.PlacedBy != o.Actor {
		t.Fatalf("hold = %+v, want the run's reason and actor", h)
	}
	denied, held, err := DeniedIdentities(db)
	if err != nil {
		t.Fatal(err)
	}
	if len(denied) != 0 || len(held) != 1 {
		t.Fatalf("denied %+v held %v: a kept identity's homes must be left alone", denied, held)
	}
	if auditCounts(t, db)["user.hold_place"] != 1 {
		t.Fatalf("the hold's placement was not audited: %v", auditCounts(t, db))
	}

	// Without --keep-credentials no hold is recorded.
	db2 := testDB(t)
	putSession(t, db2, "s-bob", "u-bob", "bob@example.com")
	if _, err := Run(baseOptions(db2, "bob@example.com")); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := db2.LegalHoldFor([]string{"bob@example.com"}); ok {
		t.Fatal("an offboarding that kept nothing placed a hold")
	}
}
