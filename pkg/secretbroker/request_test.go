package secretbroker

// Tests for the request side (Task 20271).
//
// The properties worth pinning here are the ones that are cheap to break by
// accident and expensive to discover in production: that approving cannot widen
// what was asked for, that a person cannot approve their own ask, that a lapsed
// request cannot be revived by an approver who was slow, and that a failure to
// record an approval does not leave a live credential behind.

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// seedSecret mints a github_pat for the request tests to point at.
func seedSecret(t *testing.T, b *Broker, name string) Secret {
	t.Helper()
	s, err := b.Mint(context.Background(), MintRequest{
		Name:    name,
		Kind:    KindGitHubPAT,
		Payload: []byte("ghp_" + strings.Repeat("a", 36)),
		Actor:   "operator",
	})
	if err != nil {
		t.Fatalf("mint %s: %v", name, err)
	}
	return s
}

// fileRequest files a well-formed request from alice against one project.
func fileRequest(t *testing.T, b *Broker, secretName string, mutate func(*AccessRequestInput)) AccessRequest {
	t.Helper()
	in := AccessRequestInput{
		SecretRef:     secretName,
		Subject:       Subject{Type: SubjectProject, Value: "/srv/app"},
		Constraints:   Constraints{Repos: []string{"acme/app"}},
		TTL:           2 * time.Hour,
		Justification: "shipping the INC-2291 fix",
		Actor:         "alice",
	}
	if mutate != nil {
		mutate(&in)
	}
	req, err := b.RequestAccess(context.Background(), in)
	if err != nil {
		t.Fatalf("file request: %v", err)
	}
	return req
}

// TestApprovalMintsTheRequestedGrant is the happy path, and it checks the thing
// that makes the whole feature trustworthy: what gets minted is what was asked
// for, and the request points back at it.
func TestApprovalMintsTheRequestedGrant(t *testing.T) {
	b, _, audit, _ := newTestBroker(t)
	seedSecret(t, b, "deploy-pat")
	req := fileRequest(t, b, "deploy-pat", nil)

	if req.State != RequestPending {
		t.Fatalf("a filed request is %q, want pending", req.State)
	}
	decided, grant, err := b.ApproveRequest(context.Background(), DecideInput{
		RequestID: req.ID, Actor: "bob", Note: "scoped to one repo",
	})
	if err != nil {
		t.Fatalf("approve: %v", err)
	}

	if grant.Subject.String() != req.Subject.String() {
		t.Errorf("minted subject %q, want the requested %q",
			grant.Subject.String(), req.Subject.String())
	}
	if got := strings.Join(grant.Constraints.Repos, ","); got != "acme/app" {
		t.Errorf("minted repos %q, want the requested acme/app", got)
	}
	if decided.State != RequestApproved || decided.GrantID != grant.ID {
		t.Errorf("request after approval = %q/%q, want approved/%s",
			decided.State, decided.GrantID, grant.ID)
	}
	if decided.DecidedBy != "bob" {
		t.Errorf("decided_by = %q, want bob", decided.DecidedBy)
	}

	// The grant must be reachable through the ordinary listing, because that is
	// what Lease walks: an approval that produced a row only the request path
	// can see would grant nothing.
	grants, err := b.ListGrants(GrantFilter{ActiveOnly: true})
	if err != nil {
		t.Fatalf("list grants: %v", err)
	}
	var found bool
	for _, g := range grants {
		if g.ID == grant.ID {
			found = true
		}
	}
	if !found {
		t.Error("the approved grant is not in ListGrants, so no lease would ever include it")
	}

	// Both halves of the story are in the trail, and the approval names the
	// request — which is how "which grants came through review" is answerable.
	if evs := audit.byAction(ActionRequestOpen); len(evs) != 1 || evs[0].Actor != "alice" {
		t.Errorf("secret.request events = %+v, want one from alice", evs)
	}
	evs := audit.byAction(ActionRequestApprove)
	if len(evs) != 1 {
		t.Fatalf("secret.request_approve events = %d, want 1", len(evs))
	}
	if evs[0].RequestID != req.ID || evs[0].GrantID != grant.ID {
		t.Errorf("approval event = request %q grant %q, want %q/%q",
			evs[0].RequestID, evs[0].GrantID, req.ID, grant.ID)
	}
	if evs[0].Decision != DecisionAllow {
		t.Errorf("approval decision = %q, want allow", evs[0].Decision)
	}
}

// TestSelfApprovalIsRefused is the two-person rule. It is the single most
// important test in this file: on a small team the requester very often holds
// the approving permission, so a rule enforced only by the route's permission
// check would not exist exactly when it matters.
func TestSelfApprovalIsRefused(t *testing.T) {
	b, _, audit, _ := newTestBroker(t)
	seedSecret(t, b, "deploy-pat")
	req := fileRequest(t, b, "deploy-pat", nil)

	for _, actor := range []string{"alice", "ALICE", "  alice  "} {
		t.Run(actor, func(t *testing.T) {
			_, _, err := b.ApproveRequest(context.Background(), DecideInput{
				RequestID: req.ID, Actor: actor,
			})
			if !errors.Is(err, ErrSelfApproval) {
				t.Fatalf("approve as %q: err = %v, want ErrSelfApproval — casing and "+
					"padding must not be a way around the two-person rule", actor, err)
			}
		})
	}
	// Denying your own request is refused for the same reason: it would let a
	// requester close their own ask and re-file a wider one without the refusal
	// ever appearing.
	if _, err := b.DenyRequest(context.Background(), DecideInput{
		RequestID: req.ID, Actor: "alice", Note: "never mind",
	}); !errors.Is(err, ErrSelfApproval) {
		t.Errorf("self-deny: err = %v, want ErrSelfApproval", err)
	}

	// And no grant came into existence along the way.
	grants, _ := b.ListGrants(GrantFilter{})
	if len(grants) != 0 {
		t.Errorf("a refused self-approval minted %d grant(s)", len(grants))
	}
	for _, ev := range audit.byAction(ActionRequestApprove) {
		if ev.Decision != DecisionDeny {
			t.Errorf("a refused self-approval was audited as %q", ev.Decision)
		}
	}
}

// TestApprovalClampsTTL checks that every input can only narrow the lifetime.
func TestApprovalClampsTTL(t *testing.T) {
	cases := []struct {
		name       string
		requested  time.Duration
		approver   time.Duration
		delegation Delegation
		want       time.Duration
	}{
		{"unclamped", 2 * time.Hour, 0, Delegation{MaxTTL: 24 * time.Hour}, 2 * time.Hour},
		{"approver shortens", 8 * time.Hour, time.Hour, Delegation{MaxTTL: 24 * time.Hour}, time.Hour},
		{"delegation caps", 48 * time.Hour, 0, Delegation{MaxTTL: 6 * time.Hour}, 6 * time.Hour},
		// The one that matters: an approver typing a longer TTL than was asked
		// for is granting something nobody justified.
		{"approver cannot lengthen", time.Hour, 100 * time.Hour, Delegation{MaxTTL: 200 * time.Hour}, time.Hour},
		// A caller that computed its own ceiling wrongly is still bounded by the
		// product-wide maximum.
		{"product ceiling holds", 365 * 24 * time.Hour, 0, Delegation{MaxTTL: 10 * 365 * 24 * time.Hour}, MaxDelegationTTL},
		{"zero delegation uses the default", 365 * 24 * time.Hour, 0, Delegation{}, DefaultDelegationMaxTTL},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, _, _, clock := newTestBroker(t)
			seedSecret(t, b, "deploy-pat")
			req := fileRequest(t, b, "deploy-pat", func(in *AccessRequestInput) {
				in.TTL = tc.requested
				in.RequestTTL = MaxRequestTTL
			})
			_, grant, err := b.ApproveRequest(context.Background(), DecideInput{
				RequestID: req.ID, Actor: "bob", TTL: tc.approver, Delegation: tc.delegation,
			})
			if err != nil {
				t.Fatalf("approve: %v", err)
			}
			if got := grant.ExpiresAt.Sub(clock.Now().UTC()); got != tc.want {
				t.Errorf("minted lifetime = %s, want %s (requested %s, approver %s, ceiling %s)",
					got, tc.want, tc.requested, tc.approver, tc.delegation.MaxTTL)
			}
		})
	}
}

// TestWildcardSubjectNeedsDelegation checks the scope ceiling. A grant aimed at
// every project reaches every tenant for as long as it lasts, so it must not be
// creatable by approving somebody else's ask without reading it.
func TestWildcardSubjectNeedsDelegation(t *testing.T) {
	wildcards := []Subject{
		{Type: SubjectProject, Value: "*"},
		{Type: SubjectExecutor, Value: "*"},
		{Type: SubjectAny},
		{Type: SubjectLabel, Labels: map[string]string{"region": "eu"}},
	}
	for _, sub := range wildcards {
		t.Run(sub.String(), func(t *testing.T) {
			b, _, _, _ := newTestBroker(t)
			seedSecret(t, b, "deploy-pat")
			req := fileRequest(t, b, "deploy-pat", func(in *AccessRequestInput) { in.Subject = sub })

			_, _, err := b.ApproveRequest(context.Background(), DecideInput{
				RequestID: req.ID, Actor: "bob",
			})
			if !errors.Is(err, ErrDelegationExceeded) {
				t.Fatalf("approve %s without delegation: err = %v, want ErrDelegationExceeded",
					sub.String(), err)
			}
			if grants, _ := b.ListGrants(GrantFilter{}); len(grants) != 0 {
				t.Fatalf("a refused fleet-wide approval still minted %d grant(s)", len(grants))
			}

			// And it succeeds for an approver who is entitled to delegate that far.
			if _, _, err := b.ApproveRequest(context.Background(), DecideInput{
				RequestID: req.ID, Actor: "bob",
				Delegation: Delegation{AllowWildcardSubject: true},
			}); err != nil {
				t.Fatalf("approve %s with delegation: %v", sub.String(), err)
			}
		})
	}

	// A named project is not a wildcard and needs no special entitlement.
	b, _, _, _ := newTestBroker(t)
	seedSecret(t, b, "deploy-pat")
	req := fileRequest(t, b, "deploy-pat", nil)
	if _, _, err := b.ApproveRequest(context.Background(), DecideInput{
		RequestID: req.ID, Actor: "bob",
	}); err != nil {
		t.Errorf("approving a single-project request should not need a fleet-wide delegation: %v", err)
	}
}

// TestLapsedRequestCannotBeApproved checks that whether a stale request can
// still be granted does not depend on how recently the expiry sweep ran.
func TestLapsedRequestCannotBeApproved(t *testing.T) {
	b, _, _, clock := newTestBroker(t)
	seedSecret(t, b, "deploy-pat")
	req := fileRequest(t, b, "deploy-pat", func(in *AccessRequestInput) {
		in.RequestTTL = time.Hour
	})

	clock.advance(time.Hour + time.Minute)

	// No sweep has run: the row still says "pending".
	stored, err := b.GetRequest(req.ID)
	if err != nil {
		t.Fatalf("get request: %v", err)
	}
	if stored.State != RequestPending {
		t.Fatalf("precondition: stored state is %q, want a pending row nobody has swept", stored.State)
	}
	if stored.Pending(clock.Now()) {
		t.Error("Pending() must consult the clock, not just the state column")
	}

	_, _, err = b.ApproveRequest(context.Background(), DecideInput{RequestID: req.ID, Actor: "bob"})
	if !errors.Is(err, ErrRequestExpired) {
		t.Fatalf("approve a lapsed request: err = %v, want ErrRequestExpired", err)
	}
	if grants, _ := b.ListGrants(GrantFilter{}); len(grants) != 0 {
		t.Errorf("approving a lapsed request minted %d grant(s)", len(grants))
	}
}

// TestExpireSweepEmitsOneEventEach checks that a lapsed request produces an
// outcome the requester can see. Without it, an expiry and an approval nobody
// mentioned look identical from the requester's side.
func TestExpireSweepEmitsOneEventEach(t *testing.T) {
	b, _, audit, clock := newTestBroker(t)
	seedSecret(t, b, "deploy-pat")
	a := fileRequest(t, b, "deploy-pat", func(in *AccessRequestInput) { in.RequestTTL = time.Hour })
	bb := fileRequest(t, b, "deploy-pat", func(in *AccessRequestInput) { in.RequestTTL = 10 * time.Hour })

	clock.advance(2 * time.Hour)
	lapsed, err := b.ExpireRequests(context.Background())
	if err != nil {
		t.Fatalf("expire: %v", err)
	}
	if len(lapsed) != 1 || lapsed[0].ID != a.ID {
		t.Fatalf("expired %d request(s) %v, want only the one past its deadline (%s)",
			len(lapsed), lapsed, a.ID)
	}
	if evs := audit.byAction(ActionRequestExpire); len(evs) != 1 || evs[0].RequestID != a.ID {
		t.Errorf("expiry events = %+v, want one naming %s", evs, a.ID)
	}

	// The one still inside its window is untouched and remains approvable.
	if still, _ := b.GetRequest(bb.ID); still.State != RequestPending {
		t.Errorf("request %s inside its window became %q", bb.ID, still.State)
	}
	if _, _, err := b.ApproveRequest(context.Background(), DecideInput{
		RequestID: bb.ID, Actor: "bob",
	}); err != nil {
		t.Errorf("approving a request still inside its window: %v", err)
	}
}

// TestExpireLeavesDecidedRequestsAlone guards the approval-versus-sweep race.
// An expiry that moved an approved row would contradict a credential that
// already exists.
func TestExpireLeavesDecidedRequestsAlone(t *testing.T) {
	b, _, _, clock := newTestBroker(t)
	seedSecret(t, b, "deploy-pat")
	req := fileRequest(t, b, "deploy-pat", func(in *AccessRequestInput) { in.RequestTTL = time.Hour })

	if _, _, err := b.ApproveRequest(context.Background(), DecideInput{
		RequestID: req.ID, Actor: "bob",
	}); err != nil {
		t.Fatalf("approve: %v", err)
	}
	clock.advance(48 * time.Hour)
	lapsed, err := b.ExpireRequests(context.Background())
	if err != nil {
		t.Fatalf("expire: %v", err)
	}
	if len(lapsed) != 0 {
		t.Fatalf("the sweep expired %d already-decided request(s)", len(lapsed))
	}
	if got, _ := b.GetRequest(req.ID); got.State != RequestApproved {
		t.Errorf("an approved request became %q after a sweep", got.State)
	}
}

// TestDoubleDecisionIsRefused checks that two approvers racing produce one
// grant, not two.
func TestDoubleDecisionIsRefused(t *testing.T) {
	b, _, _, _ := newTestBroker(t)
	seedSecret(t, b, "deploy-pat")
	req := fileRequest(t, b, "deploy-pat", nil)

	if _, _, err := b.ApproveRequest(context.Background(), DecideInput{
		RequestID: req.ID, Actor: "bob",
	}); err != nil {
		t.Fatalf("first approve: %v", err)
	}
	_, _, err := b.ApproveRequest(context.Background(), DecideInput{
		RequestID: req.ID, Actor: "carol",
	})
	if !errors.Is(err, ErrRequestNotPending) {
		t.Fatalf("second approve: err = %v, want ErrRequestNotPending", err)
	}
	if grants, _ := b.ListGrants(GrantFilter{}); len(grants) != 1 {
		t.Errorf("two approvals of one request minted %d grants, want 1", len(grants))
	}
	if _, err := b.DenyRequest(context.Background(), DecideInput{
		RequestID: req.ID, Actor: "carol", Note: "too late",
	}); !errors.Is(err, ErrRequestNotPending) {
		t.Errorf("denying an approved request: err = %v, want ErrRequestNotPending", err)
	}
}

// TestFailedApprovalRecordLeavesNothingLive is the rollback. If the approval
// cannot be recorded, the grant it minted must not survive — a live credential
// no record points at is precisely what this feature exists to prevent.
func TestFailedApprovalRecordLeavesNothingLive(t *testing.T) {
	b, store, _, clock := newTestBroker(t)
	seedSecret(t, b, "deploy-pat")
	req := fileRequest(t, b, "deploy-pat", nil)

	store.mu.Lock()
	store.putRequestErr = errors.New("disk full")
	store.mu.Unlock()

	_, _, err := b.ApproveRequest(context.Background(), DecideInput{RequestID: req.ID, Actor: "bob"})
	if err == nil {
		t.Fatal("approve should fail when the approval cannot be recorded")
	}
	if !strings.Contains(err.Error(), "revoked") {
		t.Errorf("error should say the minted grant was taken back, got: %v", err)
	}

	grants, lerr := b.ListGrants(GrantFilter{ActiveOnly: true})
	if lerr != nil {
		t.Fatalf("list grants: %v", lerr)
	}
	if len(grants) != 0 {
		t.Fatalf("%d grant(s) are still active after the approval failed to record", len(grants))
	}
	// And a lease would deliver nothing, which is the property the count above
	// is standing in for.
	lease, lerr := b.Lease(context.Background(), "edge-1", "/srv/app")
	if lerr != nil {
		t.Fatalf("lease: %v", lerr)
	}
	if !lease.Empty() {
		t.Errorf("a lease still carries %d material(s) from the rolled-back approval",
			len(lease.Materials))
	}
	_ = clock
}

// TestWithdrawIsTheRequestersOwn checks that an approver cannot make an
// inconvenient ask disappear without it appearing as a refusal.
func TestWithdrawIsTheRequestersOwn(t *testing.T) {
	b, _, _, _ := newTestBroker(t)
	seedSecret(t, b, "deploy-pat")
	req := fileRequest(t, b, "deploy-pat", nil)

	if _, err := b.WithdrawRequest(context.Background(), req.ID, "bob"); !errors.Is(err, ErrNotRequester) {
		t.Fatalf("withdraw by an approver: err = %v, want ErrNotRequester", err)
	}
	got, err := b.WithdrawRequest(context.Background(), req.ID, "alice")
	if err != nil {
		t.Fatalf("withdraw by the requester: %v", err)
	}
	if got.State != RequestWithdrawn {
		t.Errorf("state after withdraw = %q, want withdrawn", got.State)
	}
	if _, _, err := b.ApproveRequest(context.Background(), DecideInput{
		RequestID: req.ID, Actor: "bob",
	}); !errors.Is(err, ErrRequestNotPending) {
		t.Errorf("approving a withdrawn request: err = %v, want ErrRequestNotPending", err)
	}
}

// TestRequestValidationFailsInFrontOfItsAuthor checks that an ask which could
// never be approved is rejected at filing time, by the same rule the grant path
// applies — not days later in front of an approver who has to guess what was
// meant.
func TestRequestValidationFailsInFrontOfItsAuthor(t *testing.T) {
	b, _, _, _ := newTestBroker(t)
	seedSecret(t, b, "deploy-pat")

	cases := []struct {
		name   string
		mutate func(*AccessRequestInput)
		want   error
	}{
		{"no justification", func(in *AccessRequestInput) { in.Justification = "  " }, ErrInvalidRequest},
		{"anonymous", func(in *AccessRequestInput) { in.Actor = "" }, ErrInvalidRequest},
		{"unknown secret", func(in *AccessRequestInput) { in.SecretRef = "nope" }, ErrSecretNotFound},
		{"github without a repo allowlist", func(in *AccessRequestInput) {
			in.Constraints = Constraints{}
		}, ErrInvalidConstraint},
		{"empty subject", func(in *AccessRequestInput) { in.Subject = Subject{} }, ErrInvalidSubject},
		{"oversized justification", func(in *AccessRequestInput) {
			in.Justification = strings.Repeat("x", MaxJustificationBytes+1)
		}, ErrInvalidRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := AccessRequestInput{
				SecretRef:     "deploy-pat",
				Subject:       Subject{Type: SubjectProject, Value: "/srv/app"},
				Constraints:   Constraints{Repos: []string{"acme/app"}},
				TTL:           time.Hour,
				Justification: "because",
				Actor:         "alice",
			}
			tc.mutate(&in)
			if _, err := b.RequestAccess(context.Background(), in); !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

// TestDenialNeedsAReason checks that a refusal the requester cannot act on is
// refused. A denial with no reason produces the queue this feature drains.
func TestDenialNeedsAReason(t *testing.T) {
	b, _, audit, _ := newTestBroker(t)
	seedSecret(t, b, "deploy-pat")
	req := fileRequest(t, b, "deploy-pat", nil)

	if _, err := b.DenyRequest(context.Background(), DecideInput{
		RequestID: req.ID, Actor: "bob", Note: "   ",
	}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("deny with no reason: err = %v, want ErrInvalidRequest", err)
	}
	got, err := b.DenyRequest(context.Background(), DecideInput{
		RequestID: req.ID, Actor: "bob", Note: "use the staging cluster",
	})
	if err != nil {
		t.Fatalf("deny: %v", err)
	}
	if got.State != RequestDenied || got.DecisionNote != "use the staging cluster" {
		t.Errorf("after deny = %q/%q", got.State, got.DecisionNote)
	}
	// A carried-out denial is DecisionAllow: the field says whether the
	// operation happened, not whether the answer was yes. Recording it as a deny
	// would make it indistinguishable from an approver who was refused the right
	// to decide at all.
	evs := audit.byAction(ActionRequestDeny)
	var allowed int
	for _, ev := range evs {
		if ev.Decision == DecisionAllow {
			allowed++
		}
	}
	if allowed != 1 {
		t.Errorf("recorded denials with decision=allow = %d, want 1 (events: %+v)", allowed, evs)
	}
}

// TestLeaseRecordsWhatTheApprovalDid checks the consumption trail — the thing
// that lets an approver answer "did anything actually use this" a week later,
// which broker_grants alone cannot.
func TestLeaseRecordsWhatTheApprovalDid(t *testing.T) {
	b, _, _, clock := newTestBroker(t)
	seedSecret(t, b, "deploy-pat")
	req := fileRequest(t, b, "deploy-pat", nil)
	if _, _, err := b.ApproveRequest(context.Background(), DecideInput{
		RequestID: req.ID, Actor: "bob",
	}); err != nil {
		t.Fatalf("approve: %v", err)
	}

	if uses, err := b.RequestUses(req.ID); err != nil || len(uses) != 0 {
		t.Fatalf("before any lease: uses = %v, err = %v; an unredeemed grant must "+
			"be distinguishable from a used one", uses, err)
	}

	lease, err := b.Lease(context.Background(), "edge-1", "/srv/app")
	if err != nil {
		t.Fatalf("lease: %v", err)
	}
	if lease.Empty() {
		t.Fatal("the approved grant produced no material, so there is nothing to attribute")
	}

	uses, err := b.RequestUses(req.ID)
	if err != nil {
		t.Fatalf("request uses: %v", err)
	}
	if len(uses) != 1 {
		t.Fatalf("uses = %d, want 1", len(uses))
	}
	if uses[0].LeaseID != lease.ID || uses[0].ExecutorID != "edge-1" || uses[0].ProjectID != "/srv/app" {
		t.Errorf("use = %+v, want lease %s on edge-1 for /srv/app", uses[0], lease.ID)
	}
	first := uses[0].FirstSeen

	// A renewal advances last_seen and does not rewrite when the credential came
	// into use — the pair is what bounds how long it was actually held.
	clock.advance(10 * time.Minute)
	if _, err := b.Renew(context.Background(), lease.ID); err != nil {
		t.Fatalf("renew: %v", err)
	}
	uses, err = b.RequestUses(req.ID)
	if err != nil {
		t.Fatalf("request uses after renew: %v", err)
	}
	// The renewal issues a *new* lease id, so it is a second row; the original
	// must keep its first_seen.
	for _, u := range uses {
		if u.LeaseID == lease.ID && !u.FirstSeen.Equal(first) {
			t.Errorf("first_seen moved from %s to %s on renewal", first, u.FirstSeen)
		}
	}
	if len(uses) < 1 {
		t.Errorf("uses after renewal = %d, want at least the original", len(uses))
	}
}

// TestRequestsRefusedOnAStoreThatCannotHoldThem checks that a broker over a
// store without the request contract says so, rather than reporting an empty
// queue — which would be indistinguishable from a queue nobody has filed into.
func TestRequestsRefusedOnAStoreThatCannotHoldThem(t *testing.T) {
	cipher, err := NewCipherWithKey(testKey)
	if err != nil {
		t.Fatalf("cipher: %v", err)
	}
	b, err := New(grantsOnlyStore{newMemStore()}, WithCipher(cipher))
	if err != nil {
		t.Fatalf("new broker: %v", err)
	}

	if _, err := b.ListRequests(RequestFilter{}); !errors.Is(err, ErrRequestsUnsupported) {
		t.Errorf("ListRequests: err = %v, want ErrRequestsUnsupported", err)
	}
	if _, err := b.RequestAccess(context.Background(), AccessRequestInput{
		SecretRef: "x", Actor: "alice", Justification: "why",
		Subject: Subject{Type: SubjectProject, Value: "/srv/app"},
	}); !errors.Is(err, ErrRequestsUnsupported) {
		t.Errorf("RequestAccess: err = %v, want ErrRequestsUnsupported", err)
	}
	if _, _, err := b.ApproveRequest(context.Background(), DecideInput{
		RequestID: "req_x", Actor: "bob",
	}); !errors.Is(err, ErrRequestsUnsupported) {
		t.Errorf("ApproveRequest: err = %v, want ErrRequestsUnsupported", err)
	}
	// And leasing still works: the request path being unavailable must not take
	// credential delivery down with it.
	if _, err := b.Lease(context.Background(), "edge-1", "/srv/app"); err != nil {
		t.Errorf("Lease on a request-less store: %v", err)
	}
}

// grantsOnlyStore hides memStore's RequestStore methods behind an interface
// value that only promises Store, which is what a third-party or legacy store
// looks like to the broker.
type grantsOnlyStore struct{ inner *memStore }

func (s grantsOnlyStore) PutSecret(sec Secret) error          { return s.inner.PutSecret(sec) }
func (s grantsOnlyStore) GetSecret(id string) (Secret, error) { return s.inner.GetSecret(id) }
func (s grantsOnlyStore) ListSecrets() ([]Secret, error)      { return s.inner.ListSecrets() }
func (s grantsOnlyStore) DeleteSecret(id string) error        { return s.inner.DeleteSecret(id) }
func (s grantsOnlyStore) PutGrant(g Grant) error              { return s.inner.PutGrant(g) }
func (s grantsOnlyStore) GetGrant(id string) (Grant, error)   { return s.inner.GetGrant(id) }
func (s grantsOnlyStore) ListGrants() ([]Grant, error)        { return s.inner.ListGrants() }
func (s grantsOnlyStore) Meta(k string) (string, bool, error) { return s.inner.Meta(k) }
func (s grantsOnlyStore) SetMeta(k, v string) error           { return s.inner.SetMeta(k, v) }
func (s grantsOnlyStore) RevokeGrant(id string, at time.Time) error {
	return s.inner.RevokeGrant(id, at)
}

// TestRequestListIsFilterable covers the scoping the REST layer depends on: a
// caller who may ask but not approve is narrowed to their own requests, and the
// narrowing is a filter the server applies rather than a parameter it trusts.
func TestRequestListIsFilterable(t *testing.T) {
	b, _, _, _ := newTestBroker(t)
	seedSecret(t, b, "deploy-pat")
	mine := fileRequest(t, b, "deploy-pat", nil)
	theirs := fileRequest(t, b, "deploy-pat", func(in *AccessRequestInput) { in.Actor = "carol" })

	if _, err := b.DenyRequest(context.Background(), DecideInput{
		RequestID: theirs.ID, Actor: "bob", Note: "no",
	}); err != nil {
		t.Fatalf("deny: %v", err)
	}

	byRequester, err := b.ListRequests(RequestFilter{RequestedBy: "alice"})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(byRequester) != 1 || byRequester[0].ID != mine.ID {
		t.Errorf("RequestedBy=alice returned %d row(s), want only %s", len(byRequester), mine.ID)
	}

	pending, err := b.ListRequests(RequestFilter{PendingOnly: true})
	if err != nil {
		t.Fatalf("list pending: %v", err)
	}
	if len(pending) != 1 || pending[0].ID != mine.ID {
		t.Errorf("PendingOnly returned %d row(s), want only %s", len(pending), mine.ID)
	}

	denied, err := b.ListRequests(RequestFilter{State: RequestDenied})
	if err != nil {
		t.Fatalf("list denied: %v", err)
	}
	if len(denied) != 1 || denied[0].ID != theirs.ID {
		t.Errorf("State=denied returned %d row(s), want only %s", len(denied), theirs.ID)
	}
}

// TestRequestAuditCarriesNoMaterial checks the non-disclosure invariant on the
// one field that could plausibly carry a credential: the free-text
// justification, which a requester might paste a token into.
func TestRequestAuditCarriesNoMaterial(t *testing.T) {
	b, _, audit, _ := newTestBroker(t)
	seedSecret(t, b, "deploy-pat")

	token := "ghp_" + strings.Repeat("Z", 36)
	if _, err := b.RequestAccess(context.Background(), AccessRequestInput{
		SecretRef:     "deploy-pat",
		Subject:       Subject{Type: SubjectProject, Value: "/srv/app"},
		Constraints:   Constraints{Repos: []string{"acme/app"}},
		TTL:           time.Hour,
		Justification: "here is my token " + token + " please help",
		Actor:         "alice",
	}); err != nil {
		t.Fatalf("file: %v", err)
	}
	for _, ev := range audit.all() {
		if strings.Contains(ev.Reason, token) || strings.Contains(ev.Fields(), token) {
			t.Fatalf("a credential pasted into a justification reached the audit trail: %+v", ev)
		}
	}
}
