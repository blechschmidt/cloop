package secretstore_test

// The request path end to end through a real database (Task 20271).
//
// pkg/secretbroker tests the policy against an in-memory store and pkg/statedb
// tests the SQL against a real one. The seam between them — that a request
// survives the round trip with its subject, constraints and decision intact, and
// that an approval made here produces a grant a *lease* actually delivers — is
// only exercised when both halves run together, which is what this file does.
//
// It is the same shape and the same argument as TestRoundTripThroughSQLite
// above it: the bug this catches is a column dropped in the adapter, which both
// unit suites pass straight through.

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// TestRequestApprovalThroughSQLite files, approves, and then leases — proving
// the approval produced authority the delivery path honours, not just a row.
func TestRequestApprovalThroughSQLite(t *testing.T) {
	db, _ := openTestDB(t)
	b := newBroker(t, db)
	ctx := context.Background()

	if _, err := b.Mint(ctx, secretbroker.MintRequest{
		Name: "deploy-pat", Kind: secretbroker.KindGitHubPAT,
		Payload: []byte(testToken), Actor: "operator",
	}); err != nil {
		t.Fatalf("mint: %v", err)
	}

	req, err := b.RequestAccess(ctx, secretbroker.AccessRequestInput{
		SecretRef:     "deploy-pat",
		Subject:       mustSubject(t, "project:/srv/app"),
		Constraints:   secretbroker.Constraints{Repos: []string{"acme/app"}},
		Scope:         "ci",
		TTL:           2 * time.Hour,
		Justification: "shipping the INC-2291 fix",
		Actor:         "alice",
	})
	if err != nil {
		t.Fatalf("request: %v", err)
	}

	// Read it back through the adapter: this is where a dropped column shows up.
	stored, err := b.GetRequest(req.ID)
	if err != nil {
		t.Fatalf("get request: %v", err)
	}
	if stored.Subject.String() != "project:/srv/app" {
		t.Errorf("subject round-tripped as %q", stored.Subject.String())
	}
	if got := strings.Join(stored.Constraints.Repos, ","); got != "acme/app" {
		t.Errorf("constraints round-tripped as %q, want acme/app", got)
	}
	if stored.TTL != 2*time.Hour {
		t.Errorf("ttl round-tripped as %s, want 2h", stored.TTL)
	}
	if stored.Justification != "shipping the INC-2291 fix" || stored.RequestedBy != "alice" {
		t.Errorf("request round-tripped as %+v", stored)
	}
	if stored.ExpiresAt.IsZero() {
		t.Error("the decision deadline did not survive the round trip, so this request " +
			"would sit pending forever")
	}

	// The two-person rule holds across the adapter too — it compares the stored
	// requester, so a requester lost in translation would silently disable it.
	if _, _, aerr := b.ApproveRequest(ctx, secretbroker.DecideInput{
		RequestID: req.ID, Actor: "alice",
	}); !errors.Is(aerr, secretbroker.ErrSelfApproval) {
		t.Fatalf("self-approval through SQLite: err = %v, want ErrSelfApproval", aerr)
	}

	decided, grant, err := b.ApproveRequest(ctx, secretbroker.DecideInput{
		RequestID: req.ID, Actor: "bob", Note: "one repo only",
	})
	if err != nil {
		t.Fatalf("approve: %v", err)
	}
	if decided.State != secretbroker.RequestApproved || decided.GrantID != grant.ID {
		t.Fatalf("after approval: %+v", decided)
	}

	// The point of the whole exercise: the grant is real, and a lease delivers it.
	lease, err := b.Lease(ctx, "edge-1", "/srv/app")
	if err != nil {
		t.Fatalf("lease: %v", err)
	}
	if lease.Empty() {
		t.Fatal("an approved request produced a grant that leases nothing — the " +
			"approval path minted a row rather than authority")
	}

	// And the consumption trail records what the approval did.
	uses, err := b.RequestUses(req.ID)
	if err != nil {
		t.Fatalf("request uses: %v", err)
	}
	if len(uses) != 1 || uses[0].LeaseID != lease.ID {
		t.Fatalf("uses = %+v, want one row naming lease %s", uses, lease.ID)
	}
	if uses[0].ExecutorID != "edge-1" || uses[0].ProjectID != "/srv/app" {
		t.Errorf("use = %+v, want edge-1 / /srv/app", uses[0])
	}

	// The whole story is on the hash chain, and the approval names its request.
	events, _, err := db.ListAuditEvents(statedb.AuditFilter{Limit: 500})
	if err != nil {
		t.Fatalf("list audit: %v", err)
	}
	seen := map[string]bool{}
	var approvalPayload string
	for _, ev := range events {
		seen[ev.EventType] = true
		if ev.EventType == string(secretbroker.ActionRequestApprove) {
			approvalPayload = ev.Payload
		}
	}
	for _, want := range []string{
		string(secretbroker.ActionRequestOpen),
		string(secretbroker.ActionRequestApprove),
		string(secretbroker.ActionGrant),
		string(secretbroker.ActionLease),
	} {
		if !seen[want] {
			t.Errorf("no %q row on the audit chain", want)
		}
	}
	if !strings.Contains(approvalPayload, req.ID) {
		t.Errorf("the approval's audit payload does not name its request, so "+
			"\"which grants came through review\" is unanswerable: %s", approvalPayload)
	}

	// And no credential reached the trail along the way.
	for _, ev := range events {
		if strings.Contains(ev.Payload, testToken) {
			t.Fatalf("the stored token appears in audit row %d", ev.ID)
		}
	}
}

// TestExpiredRequestThroughSQLite covers the sweep against a real database,
// including the audit row a lapse produces.
func TestExpiredRequestThroughSQLite(t *testing.T) {
	db, _ := openTestDB(t)
	b := newBroker(t, db)
	ctx := context.Background()

	if _, err := b.Mint(ctx, secretbroker.MintRequest{
		Name: "deploy-pat", Kind: secretbroker.KindGitHubPAT,
		Payload: []byte(testToken), Actor: "operator",
	}); err != nil {
		t.Fatalf("mint: %v", err)
	}
	req, err := b.RequestAccess(ctx, secretbroker.AccessRequestInput{
		SecretRef:     "deploy-pat",
		Subject:       mustSubject(t, "project:/srv/app"),
		Constraints:   secretbroker.Constraints{Repos: []string{"acme/app"}},
		Justification: "one-off",
		// A deadline already in the past relative to the wall clock this broker
		// uses, so the sweep has something to find without the test sleeping.
		RequestTTL: time.Nanosecond,
		Actor:      "alice",
	})
	if err != nil {
		t.Fatalf("request: %v", err)
	}

	lapsed, err := b.ExpireRequests(ctx)
	if err != nil {
		t.Fatalf("expire: %v", err)
	}
	if len(lapsed) != 1 || lapsed[0].ID != req.ID {
		t.Fatalf("expired %+v, want the one request", lapsed)
	}
	got, err := b.GetRequest(req.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.State != secretbroker.RequestExpired {
		t.Errorf("state after sweep = %q, want expired", got.State)
	}
	if _, _, aerr := b.ApproveRequest(ctx, secretbroker.DecideInput{
		RequestID: req.ID, Actor: "bob",
	}); !errors.Is(aerr, secretbroker.ErrRequestNotPending) {
		t.Errorf("approving a swept request: err = %v, want ErrRequestNotPending", aerr)
	}

	events, _, err := db.ListAuditEvents(statedb.AuditFilter{Limit: 200})
	if err != nil {
		t.Fatalf("list audit: %v", err)
	}
	var found bool
	for _, ev := range events {
		if ev.EventType == string(secretbroker.ActionRequestExpire) {
			found = true
		}
	}
	if !found {
		t.Error("a lapse produced no audit row, so the requester has no way to learn " +
			"the answer was no")
	}
}
