package offboard

// Offboarding (Task 20261).
//
// These tests exist because the failure mode is silent. An offboarding that
// matches too narrowly reports success — the operator sees "severed" and moves
// on — while a credential the departed user holds keeps working. So the cases
// below are mostly about what must be *found*, not about what happens once it
// is.

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/apitoken"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

func testDB(t *testing.T) *statedb.DB {
	t.Helper()
	db, err := statedb.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func putSession(t *testing.T, db *statedb.DB, id, sub, email string) {
	t.Helper()
	now := time.Now().UTC()
	if err := db.PutSession(statedb.SessionRow{
		ID: id, Subject: sub, Email: email,
		OwnerKey:  ownerKeyFor(sub, email),
		IssuedAt:  now,
		LastSeen:  now,
		ExpiresAt: now.Add(24 * time.Hour),
	}); err != nil {
		t.Fatalf("put session %s: %v", id, err)
	}
}

func ownerKeyFor(sub, email string) string {
	if email != "" {
		return strings.ToLower(email)
	}
	return "sub:" + sub
}

// putToken writes a token owned by (sub, email). A nil owner is written by
// passing both empty, which is how an unbound service-account token looks.
func putToken(t *testing.T, db *statedb.DB, id, kind, sub, email string) {
	t.Helper()
	ownerJSON := ""
	if sub != "" || email != "" {
		blob, err := json.Marshal(apitoken.Owner{Sub: sub, Email: email})
		if err != nil {
			t.Fatal(err)
		}
		ownerJSON = string(blob)
	}
	if err := db.PutAPIToken(statedb.APITokenRow{
		ID: id, Name: "token-" + id, Hash: "h_" + id, Prefix: "cloop_pat_" + id,
		Roles: []string{"operator"}, CreatedAt: time.Now().UTC(),
		Kind: kind, OwnerJSON: ownerJSON,
	}); err != nil {
		t.Fatalf("put token %s: %v", id, err)
	}
}

func baseOptions(db *statedb.DB, identity string) Options {
	return Options{
		DB: db, Identity: identity, Reason: "left the company, HR-882",
		Actor: "admin@example.com", Via: "test",
	}
}

// ---------------------------------------------------------------------------
// Resolution
// ---------------------------------------------------------------------------

// TestResolvesSubjectKeyedTokenFromAnEmail is the case the whole design turns
// on. The operator types an email. A session carries that email and a subject.
// A token's owner carries only that subject — no email at all, which is what a
// token minted while the IdP withheld the email claim looks like.
//
// Matching literally on what was typed finds the session and misses the token,
// and the token is the credential that would then keep working for ninety days.
func TestResolvesSubjectKeyedTokenFromAnEmail(t *testing.T) {
	db := testDB(t)
	putSession(t, db, "sess1", "u-42", "alice@example.com")
	putToken(t, db, "tok1", "", "u-42", "") // owner has a sub, no email

	plan, err := BuildPlan(baseOptions(db, "alice@example.com"))
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Sessions) != 1 {
		t.Fatalf("sessions = %d, want 1", len(plan.Sessions))
	}
	if len(plan.Tokens) != 1 {
		t.Fatalf("tokens = %d, want 1 — a token owned by the same subject was "+
			"missed because the operator happened to type the email", len(plan.Tokens))
	}
	if !contains(plan.Target.Subjects, "u-42") {
		t.Fatalf("subjects = %v, want the subject resolved from the session",
			plan.Target.Subjects)
	}
}

// TestResolvesEmailKeyedSessionFromASubject is the same chain walked the other
// way, for an operator who has a subject from the dashboard and nothing else.
func TestResolvesEmailKeyedSessionFromASubject(t *testing.T) {
	db := testDB(t)
	putSession(t, db, "sess1", "u-42", "alice@example.com")
	putToken(t, db, "tok1", "", "u-42", "")

	for _, input := range []string{"u-42", "sub:u-42"} {
		t.Run(input, func(t *testing.T) {
			plan, err := BuildPlan(baseOptions(db, input))
			if err != nil {
				t.Fatal(err)
			}
			if len(plan.Sessions) != 1 || len(plan.Tokens) != 1 {
				t.Fatalf("sessions=%d tokens=%d, want 1 and 1",
					len(plan.Sessions), len(plan.Tokens))
			}
			if !contains(plan.Target.Emails, "alice@example.com") {
				t.Fatalf("emails = %v, want the address resolved from the session",
					plan.Target.Emails)
			}
		})
	}
}

// TestResolutionChainsThroughTwoHops: email → session → subject → token whose
// owner carries a *different* email spelling. A single expansion pass stops one
// hop short of this, which is why resolve is a fixpoint.
func TestResolutionChainsThroughTwoHops(t *testing.T) {
	db := testDB(t)
	putSession(t, db, "sess1", "u-42", "alice@example.com")
	putToken(t, db, "tok1", "", "u-42", "alice.dev@example.com")
	putToken(t, db, "tok2", "", "", "alice.dev@example.com")

	plan, err := BuildPlan(baseOptions(db, "alice@example.com"))
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Tokens) != 2 {
		t.Fatalf("tokens = %d, want 2 — resolution stopped before the second hop",
			len(plan.Tokens))
	}
}

// TestDoesNotMatchOtherPeople is the containment direction. Over-matching is
// the other way to get this wrong, and it locks out colleagues.
func TestDoesNotMatchOtherPeople(t *testing.T) {
	db := testDB(t)
	putSession(t, db, "sess1", "u-42", "alice@example.com")
	putSession(t, db, "sess2", "u-99", "bob@example.com")
	putToken(t, db, "tok1", "", "u-99", "bob@example.com")
	putToken(t, db, "tok2", "", "", "") // unbound service account

	plan, err := BuildPlan(baseOptions(db, "alice@example.com"))
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Sessions) != 1 || plan.Sessions[0].ID != "sess1" {
		t.Fatalf("sessions = %+v, want only alice's", plan.Sessions)
	}
	if len(plan.Tokens) != 0 {
		t.Fatalf("tokens = %+v, want none — bob's token and an unbound service "+
			"account were caught by somebody else's offboarding", plan.Tokens)
	}
}

// TestEmailMatchingIsCaseInsensitive: IdPs are inconsistent about case, and an
// offboarding that missed "Alice@Example.com" because the operator typed it in
// lower case would be trivially defeated.
func TestEmailMatchingIsCaseInsensitive(t *testing.T) {
	db := testDB(t)
	putSession(t, db, "sess1", "u-42", "Alice@Example.com")
	putToken(t, db, "tok1", "", "", "ALICE@EXAMPLE.COM")

	plan, err := BuildPlan(baseOptions(db, "alice@example.com"))
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Sessions) != 1 || len(plan.Tokens) != 1 {
		t.Fatalf("sessions=%d tokens=%d, want 1 and 1 — case defeated the match",
			len(plan.Sessions), len(plan.Tokens))
	}
}

// TestGlassesLinksAreASeparateSurface: they live in the same table as PATs and
// differ only by Kind, but "their PAT still works" and "their glasses link
// still works" are different incidents and are counted and audited separately.
func TestGlassesLinksAreASeparateSurface(t *testing.T) {
	db := testDB(t)
	putToken(t, db, "tok1", "", "u-42", "alice@example.com")
	putToken(t, db, "gl1", apitoken.KindGlasses, "u-42", "alice@example.com")

	plan, err := BuildPlan(baseOptions(db, "alice@example.com"))
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Tokens) != 1 || plan.Tokens[0].ID != "tok1" {
		t.Fatalf("tokens = %+v, want just the PAT", plan.Tokens)
	}
	if len(plan.Glasses) != 1 || plan.Glasses[0].ID != "gl1" {
		t.Fatalf("glasses = %+v, want just the link", plan.Glasses)
	}
}

// TestAlreadyRevokedCredentialsAreNotReplanned keeps the blast radius honest:
// an operator approving a dry run should see what is live, not a tally inflated
// by credentials that stopped working months ago.
func TestAlreadyRevokedCredentialsAreNotReplanned(t *testing.T) {
	db := testDB(t)
	putToken(t, db, "live", "", "u-42", "alice@example.com")
	putToken(t, db, "dead", "", "u-42", "alice@example.com")
	if err := db.RevokeAPIToken("dead", time.Now()); err != nil {
		t.Fatal(err)
	}

	plan, err := BuildPlan(baseOptions(db, "alice@example.com"))
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Tokens) != 1 || plan.Tokens[0].ID != "live" {
		t.Fatalf("tokens = %+v, want only the live one", plan.Tokens)
	}
}

// TestUnreadableOwnerIsWarnedAboutNotIgnored. A token whose owner binding does
// not decode cannot be matched — and cannot be proven *not* to be this
// person's. Silently skipping it would let the run report success over a
// credential that may well be theirs.
func TestUnreadableOwnerIsWarnedAboutNotIgnored(t *testing.T) {
	db := testDB(t)
	if err := db.PutAPIToken(statedb.APITokenRow{
		ID: "broken", Name: "broken", Hash: "h", Prefix: "cloop_pat_broken",
		CreatedAt: time.Now().UTC(), OwnerJSON: "{not json",
	}); err != nil {
		t.Fatal(err)
	}

	plan, err := BuildPlan(baseOptions(db, "alice@example.com"))
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Tokens) != 0 {
		t.Fatalf("an undecodable owner must not be matched to an identity, got %+v",
			plan.Tokens)
	}
	if !warnsAbout(plan.Warnings, "broken") {
		t.Fatalf("warnings = %v, want the unmatched token named so an operator "+
			"can deal with it by hand", plan.Warnings)
	}
}

// ---------------------------------------------------------------------------
// Execution
// ---------------------------------------------------------------------------

// TestRunSeversEverySurface is the end-to-end proof.
func TestRunSeversEverySurface(t *testing.T) {
	db := testDB(t)
	putSession(t, db, "sess1", "u-42", "alice@example.com")
	putSession(t, db, "sess2", "u-42", "alice@example.com")
	putToken(t, db, "tok1", "", "u-42", "alice@example.com")
	putToken(t, db, "gl1", apitoken.KindGlasses, "u-42", "")

	rep, err := Run(baseOptions(db, "alice@example.com"))
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OK() {
		t.Fatalf("failures: %+v", rep.Failures)
	}
	if len(rep.SessionsRevoked) != 2 {
		t.Fatalf("sessions revoked = %d, want 2", len(rep.SessionsRevoked))
	}
	if len(rep.TokensRevoked) != 1 || len(rep.GlassesRevoked) != 1 {
		t.Fatalf("tokens=%d glasses=%d, want 1 and 1",
			len(rep.TokensRevoked), len(rep.GlassesRevoked))
	}

	// The rows really are gone / stamped, not merely reported.
	if rows, err := db.ListSessions(); err != nil || len(rows) != 0 {
		t.Fatalf("sessions remaining = %d (err %v), want 0", len(rows), err)
	}
	toks, err := db.ListAPITokens()
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range toks {
		if row.RevokedAt.IsZero() {
			t.Fatalf("token %s is still live after offboarding", row.ID)
		}
	}

	// A deny binding per identifier, so a re-issued session keyed by subject
	// alone is refused too.
	bindings, err := db.ListRoleBindings()
	if err != nil {
		t.Fatal(err)
	}
	var denyEmail, denySub bool
	for _, b := range bindings {
		if b.Effect != statedb.RoleEffectDeny {
			continue
		}
		switch b.Claim {
		case "email":
			denyEmail = b.Value == "alice@example.com"
		case "sub":
			denySub = b.Value == "u-42"
		}
	}
	if !denyEmail || !denySub {
		t.Fatalf("deny bindings = %+v, want one for the email and one for the "+
			"subject — denying only the email leaves a re-issued session that "+
			"carries no email claim matching nothing", bindings)
	}
}

// TestDryRunChangesNothing. The dry run is what an operator approves against,
// so it must be exactly the read half of the real run and nothing more.
func TestDryRunChangesNothing(t *testing.T) {
	db := testDB(t)
	putSession(t, db, "sess1", "u-42", "alice@example.com")
	putToken(t, db, "tok1", "", "u-42", "alice@example.com")

	o := baseOptions(db, "alice@example.com")
	o.DryRun = true
	rep, err := Run(o)
	if err != nil {
		t.Fatal(err)
	}
	if !rep.DryRun || len(rep.Sessions) != 1 || len(rep.Tokens) != 1 {
		t.Fatalf("dry run must still report the blast radius, got %+v", rep)
	}
	if len(rep.SessionsRevoked) != 0 || len(rep.TokensRevoked) != 0 ||
		len(rep.DeniesWritten) != 0 {
		t.Fatalf("dry run severed something: %+v", rep)
	}
	if rows, _ := db.ListSessions(); len(rows) != 1 {
		t.Fatalf("dry run deleted a session")
	}
	if bindings, _ := db.ListRoleBindings(); len(bindings) != 0 {
		t.Fatalf("dry run wrote a deny binding: %+v", bindings)
	}
	if evs, _, _ := db.ListAuditEvents(statedb.AuditFilter{Limit: 100}); len(evs) != 0 {
		t.Fatalf("dry run wrote %d audit event(s); it changed nothing to record", len(evs))
	}
}

// TestAuditChainRecordsEachSurface. The trail is what proves the offboarding
// happened, so one event per surface touched — and the summary, so a reviewer
// meets the operation before its parts.
func TestAuditChainRecordsEachSurface(t *testing.T) {
	db := testDB(t)
	putSession(t, db, "sess1", "u-42", "alice@example.com")
	putToken(t, db, "tok1", "", "u-42", "alice@example.com")
	putToken(t, db, "gl1", apitoken.KindGlasses, "u-42", "alice@example.com")

	if _, err := Run(baseOptions(db, "alice@example.com")); err != nil {
		t.Fatal(err)
	}
	evs, _, err := db.ListAuditEvents(statedb.AuditFilter{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]int{}
	for _, ev := range evs {
		seen[ev.EventType]++
		if ev.EntityID != "alice@example.com" {
			t.Fatalf("event %s has entity id %q, want the identity so the trail "+
				"is greppable by person", ev.EventType, ev.EntityID)
		}
	}
	for _, want := range []string{
		"user.offboard", "user.offboard_session",
		"user.offboard_token", "user.offboard_glasses", "user.offboard_deny",
	} {
		if seen[want] != 1 {
			t.Fatalf("audit events %v: want exactly one %s", seen, want)
		}
	}

	// And the chain is intact — the events were written inside the same
	// transaction as the mutation, not appended afterwards.
	report, err := db.VerifyAuditChain()
	if err != nil {
		t.Fatal(err)
	}
	if !report.OK {
		t.Fatalf("audit chain broken after offboarding at id %d: %s",
			report.BreakAtID, report.Reason)
	}
}

// TestSeveringIsAtomic: a failure building the audit events must roll the whole
// thing back. A half-applied offboarding is the state the single transaction
// exists to make impossible — sessions gone so it looks handled, token still
// live.
func TestSeveringIsAtomic(t *testing.T) {
	db := testDB(t)
	putSession(t, db, "sess1", "u-42", "alice@example.com")
	putToken(t, db, "tok1", "", "u-42", "alice@example.com")

	_, err := db.OffboardIdentity(statedb.OffboardWrite{
		IdentityKey: "alice@example.com",
		SessionIDs:  []string{"sess1"},
		TokenIDs:    []string{"tok1"},
		DenyBindings: []statedb.RoleBindingRow{{
			Effect: statedb.RoleEffectDeny, Claim: "email",
			Value: "alice@example.com", Role: "none",
		}},
		Audit: func(statedb.OffboardApplied) ([]*statedb.AuditEvent, error) {
			// An event with no type is rejected by the writer, standing in for
			// any failure between the mutation and its record.
			return []*statedb.AuditEvent{{EventType: ""}}, nil
		},
	})
	if err == nil {
		t.Fatal("an unrecordable severing must fail, not commit silently")
	}

	if rows, _ := db.ListSessions(); len(rows) != 1 {
		t.Fatal("the session was deleted even though the transaction failed")
	}
	toks, _ := db.ListAPITokens()
	if len(toks) != 1 || !toks[0].RevokedAt.IsZero() {
		t.Fatal("the token was revoked even though the transaction failed")
	}
	if bindings, _ := db.ListRoleBindings(); len(bindings) != 0 {
		t.Fatal("the deny binding survived a rolled-back transaction")
	}
}

// TestReRunIsIdempotent: an operator who runs it twice — or who re-runs after a
// partial failure — must not get an error or a second set of audit noise for
// credentials that are already gone.
func TestReRunIsIdempotent(t *testing.T) {
	db := testDB(t)
	putSession(t, db, "sess1", "u-42", "alice@example.com")
	putToken(t, db, "tok1", "", "u-42", "alice@example.com")

	if _, err := Run(baseOptions(db, "alice@example.com")); err != nil {
		t.Fatal(err)
	}
	rep, err := Run(baseOptions(db, "alice@example.com"))
	if err != nil {
		t.Fatalf("second run failed: %v", err)
	}
	if !rep.OK() {
		t.Fatalf("second run reported failures: %+v", rep.Failures)
	}
	if len(rep.SessionsRevoked) != 0 || len(rep.TokensRevoked) != 0 {
		t.Fatalf("second run claimed to sever already-severed credentials: %+v", rep)
	}
	// The deny binding is content-addressed, so re-writing it is an upsert
	// rather than a duplicate row.
	bindings, _ := db.ListRoleBindings()
	if len(bindings) != 2 {
		t.Fatalf("role bindings = %d, want 2 (email + sub), not duplicated per run",
			len(bindings))
	}
}

// TestProjectsAreReportedNeverDeleted. The one surface that must survive.
func TestProjectsAreReportedNeverDeleted(t *testing.T) {
	db := testDB(t)
	putSession(t, db, "sess1", "u-42", "alice@example.com")

	o := baseOptions(db, "alice@example.com")
	o.Projects = fakeProjects{{Name: "payments", Path: "/srv/payments", Owner: "alice@example.com"}}
	rep, err := Run(o)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Projects) != 1 || rep.Projects[0].Name != "payments" {
		t.Fatalf("projects = %+v, want the owned project reported", rep.Projects)
	}
	evs, _, _ := db.ListAuditEvents(statedb.AuditFilter{Limit: 100})
	var found bool
	for _, ev := range evs {
		if ev.EventType == "user.offboard_project" {
			found = true
			if !strings.Contains(ev.Payload, "reported_for_reassignment") {
				t.Fatalf("project event must say it only reported: %s", ev.Payload)
			}
		}
	}
	if !found {
		t.Fatal("no user.offboard_project event: an operator is never told a " +
			"reassignment is owed")
	}
}

// TestMissingCollaboratorsAreWarnedAbout. A run with no broker must not report
// "0 leases" as though it had checked and found none: that reads as clean when
// it means unknown.
func TestMissingCollaboratorsAreWarnedAbout(t *testing.T) {
	db := testDB(t)
	plan, err := BuildPlan(baseOptions(db, "alice@example.com"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"secret leases were not checked", "project ownership was not checked"} {
		if !warnsAbout(plan.Warnings, want) {
			t.Fatalf("warnings = %v, want one mentioning %q", plan.Warnings, want)
		}
	}
}

// TestTaskStopFailureIsReportedNotSwallowed. Credentials are severed first and
// on purpose; a task that will not stop must not undo that, but it must also
// not be reported as a clean offboarding.
func TestTaskStopFailureIsReportedNotSwallowed(t *testing.T) {
	db := testDB(t)
	putSession(t, db, "sess1", "u-42", "alice@example.com")

	o := baseOptions(db, "alice@example.com")
	o.Projects = fakeProjects{{Name: "payments", Path: "/srv/payments", Owner: "alice@example.com"}}
	o.Tasks = &fakeTasks{
		running: []TaskRef{{ProjectPath: "/srv/payments", ID: 7, Title: "deploy"}},
		stopErr: errStopRefused,
	}
	rep, err := Run(o)
	if err != nil {
		t.Fatal(err)
	}
	if rep.OK() {
		t.Fatal("a task that could not be stopped was reported as a clean offboarding")
	}
	if len(rep.SessionsRevoked) != 1 {
		t.Fatal("credentials must still be severed when a task refuses to stop")
	}
	if len(rep.Failures) != 1 || rep.Failures[0].Surface != "task" {
		t.Fatalf("failures = %+v, want one naming the task surface", rep.Failures)
	}
}

// TestLeasesReleasedOnlyForOwnedProjects: leases are matched by project, and a
// colleague's lease on a shared executor must not be torn down.
func TestLeasesReleasedOnlyForOwnedProjects(t *testing.T) {
	db := testDB(t)
	putSession(t, db, "sess1", "u-42", "alice@example.com")

	leases := &fakeLeases{live: []LeaseRef{
		{ID: "lease-mine", ProjectID: "/srv/payments"},
		{ID: "lease-theirs", ProjectID: "/srv/billing"},
	}}
	o := baseOptions(db, "alice@example.com")
	o.Projects = fakeProjects{{Name: "payments", Path: "/srv/payments", Owner: "alice@example.com"}}
	o.Leases = leases

	rep, err := Run(o)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.LeasesReleased) != 1 || rep.LeasesReleased[0] != "lease-mine" {
		t.Fatalf("released = %v, want only the lease on the owned project",
			rep.LeasesReleased)
	}
	if len(leases.released) != 1 || leases.released[0] != "lease-mine" {
		t.Fatalf("broker saw %v, want only lease-mine", leases.released)
	}
}

// TestReasonIsRequired: an offboarding with no stated cause is not reviewable,
// and reviewability is the point of writing it down.
func TestReasonIsRequired(t *testing.T) {
	db := testDB(t)
	o := baseOptions(db, "alice@example.com")
	o.Reason = ""
	if _, err := Run(o); err == nil {
		t.Fatal("a run with no reason was accepted")
	}

	// A dry run changes nothing and records nothing, so it must not demand
	// one: an operator forced to invent a reason to *look* would reuse that
	// same placeholder for the write.
	o.DryRun = true
	if _, err := Run(o); err != nil {
		t.Fatalf("a dry run must not require a reason: %v", err)
	}
}

// TestUnknownIdentityStillWritesADeny covers pre-emptive offboarding: a name
// from an HR feed that never signed in here. There is nothing to revoke, but
// the deny must still land or the account is free to sign in tomorrow.
func TestUnknownIdentityStillWritesADeny(t *testing.T) {
	db := testDB(t)
	rep, err := Run(baseOptions(db, "never-seen@example.com"))
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.DeniesWritten) != 1 {
		t.Fatalf("denies = %v, want one for an identity this hub has never seen",
			rep.DeniesWritten)
	}
	bindings, _ := db.ListRoleBindings()
	if len(bindings) != 1 || bindings[0].Claim != "email" {
		t.Fatalf("bindings = %+v, want an email deny", bindings)
	}
}

// TestLiveSessionAuthorityIsPreferredOverTheTable is the memory-store case.
//
// A hub with no durable session store keeps sessions in process memory, where
// the control-plane table is empty however many people are signed in. Driving
// the offboarding off that table would report "0 sessions severed" and leave
// the person signed in — which reads as success.
func TestLiveSessionAuthorityIsPreferredOverTheTable(t *testing.T) {
	db := testDB(t) // deliberately empty: nothing in the sessions table
	sessions := &fakeSessions{live: []SessionRef{
		{ID: "mem1", Subject: "u-42", Email: "alice@example.com"},
		{ID: "mem2", Subject: "u-42", Email: "alice@example.com"},
		{ID: "mem3", Subject: "u-99", Email: "bob@example.com"},
	}}
	o := baseOptions(db, "alice@example.com")
	o.Sessions = sessions

	rep, err := Run(o)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Sessions) != 2 {
		t.Fatalf("planned sessions = %d, want 2 from the live authority — the "+
			"empty control-plane table was believed instead", len(rep.Sessions))
	}
	if len(rep.SessionsRevoked) != 2 {
		t.Fatalf("revoked = %v, want both of alice's", rep.SessionsRevoked)
	}
	if len(sessions.revoked) != 2 {
		t.Fatalf("the authenticator saw %v, want alice's two sessions — going "+
			"round it leaves its cache serving them", sessions.revoked)
	}
	for _, id := range sessions.revoked {
		if id == "mem3" {
			t.Fatal("bob's session was revoked by alice's offboarding")
		}
	}
}

// TestSessionRevokeFailureIsReportedButDoesNotBlockTheRest: a session that will
// not end must not stop the tokens being revoked. Leaving a PAT live because a
// session refused to die is the wrong failure direction.
func TestSessionRevokeFailureIsReportedButDoesNotBlockTheRest(t *testing.T) {
	db := testDB(t)
	putToken(t, db, "tok1", "", "u-42", "alice@example.com")

	o := baseOptions(db, "alice@example.com")
	o.Sessions = &fakeSessions{
		live:      []SessionRef{{ID: "mem1", Subject: "u-42", Email: "alice@example.com"}},
		revokeErr: errStopRefused,
	}
	rep, err := Run(o)
	if err != nil {
		t.Fatal(err)
	}
	if rep.OK() {
		t.Fatal("a session that could not be revoked was reported as clean")
	}
	if len(rep.TokensRevoked) != 1 {
		t.Fatalf("tokens revoked = %v, want the PAT severed anyway", rep.TokensRevoked)
	}
	if len(rep.DeniesWritten) == 0 {
		t.Fatal("the deny binding was skipped because a session refused to end")
	}
}

// ---------------------------------------------------------------------------
// fakes
// ---------------------------------------------------------------------------

type fakeSessions struct {
	live      []SessionRef
	revokeErr error
	revoked   []string
}

func (f *fakeSessions) List() ([]SessionRef, error) { return f.live, nil }

func (f *fakeSessions) Revoke(id, _, _ string) (bool, error) {
	if f.revokeErr != nil {
		return false, f.revokeErr
	}
	f.revoked = append(f.revoked, id)
	return true, nil
}

var errStopRefused = &stopError{}

type stopError struct{}

func (*stopError) Error() string { return "executor refused" }

type fakeProjects []ProjectRef

func (p fakeProjects) Owned(keys []string) ([]ProjectRef, error) {
	want := map[string]struct{}{}
	for _, k := range keys {
		want[strings.ToLower(k)] = struct{}{}
	}
	var out []ProjectRef
	for _, ref := range p {
		if _, ok := want[strings.ToLower(ref.Owner)]; ok {
			out = append(out, ref)
		}
	}
	return out, nil
}

type fakeTasks struct {
	running []TaskRef
	stopErr error
	stopped []TaskRef
}

func (f *fakeTasks) Running(path string) ([]TaskRef, error) {
	var out []TaskRef
	for _, t := range f.running {
		if t.ProjectPath == path {
			out = append(out, t)
		}
	}
	return out, nil
}

func (f *fakeTasks) Stop(t TaskRef, _, _ string) error {
	if f.stopErr != nil {
		return f.stopErr
	}
	f.stopped = append(f.stopped, t)
	return nil
}

type fakeLeases struct {
	live     []LeaseRef
	released []string
}

func (f *fakeLeases) LiveLeases() []LeaseRef { return f.live }
func (f *fakeLeases) Release(id string)      { f.released = append(f.released, id) }

func contains(hay []string, needle string) bool {
	for _, v := range hay {
		if v == needle {
			return true
		}
	}
	return false
}

func warnsAbout(warnings []string, substr string) bool {
	for _, w := range warnings {
		if strings.Contains(w, substr) {
			return true
		}
	}
	return false
}
