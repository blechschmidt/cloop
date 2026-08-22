package ui

// Tests for the hub-side revocation policy: how per-executor outcomes fold
// into the one state a panel renders, what the operator is told about it, and
// which actions the API will accept.
//
// These are the decisions that turn a distributed result into a claim, and
// getting them wrong is how a security feature ends up lying rather than
// failing.

import (
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor/remote"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
)

// TestAggregateStateTakesTheWorstHolder is the honesty rule.
//
// An operator who revoked a credential across four devices and reached three
// of them has not revoked that credential. A panel that reported the majority,
// the first, or the most recent would let them close an incident on a token
// that is still live on the fourth.
func TestAggregateStateTakesTheWorstHolder(t *testing.T) {
	res := func(states ...remote.RevokeState) []remote.RevokeResult {
		out := make([]remote.RevokeResult, 0, len(states))
		for i, s := range states {
			out = append(out, remote.RevokeResult{ExecutorID: string(rune('a' + i)), State: s})
		}
		return out
	}

	tests := []struct {
		name    string
		results []remote.RevokeResult
		wiped   bool
		want    remote.RevokeState
	}{
		{
			name:  "no remote holders, hub copy wiped",
			wiped: true,
			want:  remote.RevokeStateRevoked,
		},
		{
			// Nothing was found anywhere. Claiming "revoked" would assert a
			// wipe that never happened.
			name: "no holders and nothing wiped",
			want: remote.RevokeStatePending,
		},
		{
			name:    "every holder acked",
			results: res(remote.RevokeStateRevoked, remote.RevokeStateRevoked),
			wiped:   true,
			want:    remote.RevokeStateRevoked,
		},
		{
			name:    "one holder offline drags the whole result down",
			results: res(remote.RevokeStateRevoked, remote.RevokeStateRevoked, remote.RevokeStateUnreachable),
			wiped:   true,
			want:    remote.RevokeStateUnreachable,
		},
		{
			name:    "a failure outranks a pending",
			results: res(remote.RevokeStatePending, remote.RevokeStateFailed),
			want:    remote.RevokeStateFailed,
		},
		{
			// Unreachable is the worst: a failure at least came from a device
			// that answered, so the operator knows what it is dealing with.
			name:    "unreachable outranks a failure",
			results: res(remote.RevokeStateFailed, remote.RevokeStateUnreachable),
			want:    remote.RevokeStateUnreachable,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := aggregateState(tc.results, tc.wiped); got != tc.want {
				t.Errorf("aggregateState = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestRevokeNoteStatesTheLimit checks that the operator-facing sentence never
// claims more than the system delivered.
//
// Scrubbing removes files and allowlist entries for good, but an environment
// variable already handed to a running process cannot be taken out of that
// process's memory by anyone. A note that said "revoked" without that caveat
// is exactly how someone closes an incident on a live token.
func TestRevokeNoteStatesTheLimit(t *testing.T) {
	unreachable := revokeNote(leaseRevocation{
		State:  remote.RevokeStateUnreachable,
		Remote: []remote.RevokeResult{{State: remote.RevokeStateUnreachable}},
	})
	for _, want := range []string{"offline", "queued", "treat the credential as live"} {
		if !strings.Contains(unreachable, want) {
			t.Errorf("the unreachable note must mention %q; got %q", want, unreachable)
		}
	}

	revoked := revokeNote(leaseRevocation{
		State:        remote.RevokeStateRevoked,
		WipedLocally: true,
		Remote:       []remote.RevokeResult{{State: remote.RevokeStateRevoked}},
	})
	// The env caveat, and the escape hatch for it.
	for _, want := range []string{"Environment variables", "keeps it", "kill"} {
		if !strings.Contains(revoked, want) {
			t.Errorf("the success note must state the env limit and name the remedy (%q); got %q",
				want, revoked)
		}
	}

	failed := revokeNote(leaseRevocation{State: remote.RevokeStateFailed})
	if !strings.Contains(failed, "live") {
		t.Errorf("a failed scrub must tell the operator to treat the credential as live; got %q", failed)
	}

	// A hub-only revocation is honest about its narrower scope: it says what
	// it wiped, and does not imply anything about a fleet it never talked to.
	local := revokeNote(leaseRevocation{State: remote.RevokeStateRevoked, WipedLocally: true})
	if strings.Contains(local, "every holder") {
		t.Errorf("a hub-only revocation must not claim fleet-wide effect; got %q", local)
	}
	if !strings.Contains(local, "already read") {
		t.Errorf("even the local case must state that a process keeps what it read; got %q", local)
	}
}

// TestParseRevokeActionRefusesUnknownActions.
//
// Defaulting an unrecognised action to the safe one is tempting and wrong: an
// operator who typed "terminate" meaning kill would get a scrub, be told it
// succeeded, and find out otherwise from the task that kept running.
func TestParseRevokeActionRefusesUnknownActions(t *testing.T) {
	if got, err := parseRevokeAction(""); err != nil || got != remote.RevokeScrub {
		t.Errorf(`parseRevokeAction("") = %q, %v; want scrub with no error`, got, err)
	}
	if got, err := parseRevokeAction(" kill "); err != nil || got != remote.RevokeKill {
		t.Errorf(`parseRevokeAction(" kill ") = %q, %v; want kill with no error`, got, err)
	}
	for _, bad := range []string{"terminate", "SCRUB", "wipe", "destroy"} {
		got, err := parseRevokeAction(bad)
		if err == nil {
			t.Errorf("parseRevokeAction(%q) = %q with no error; an unknown action must be refused", bad, got)
			continue
		}
		// The message has to name the alternatives, or the operator is left
		// guessing at a vocabulary they cannot see.
		if !strings.Contains(err.Error(), "scrub") || !strings.Contains(err.Error(), "kill") {
			t.Errorf("the refusal should name both actions; got %v", err)
		}
	}
}

// TestSweepExpiredLeasesFindsOnlyLapsedOnes checks the janitor's selection.
//
// This is what makes a lease TTL bind the whole system rather than just the
// hub: before it, Lease.Expired was consulted only by the caller that minted
// the lease, so an executor handed a fifteen-minute credential kept it for as
// long as its task ran. Sweeping too eagerly would be just as bad in the other
// direction — every long run would lose its credentials mid-task.
func TestSweepExpiredLeasesFindsOnlyLapsedOnes(t *testing.T) {
	// The registry is process-wide, so leave it as we found it or the rest of
	// the package's tests inherit our leases.
	t.Cleanup(func() {
		for _, sl := range liveLeases.snapshot() {
			if sl.lease != nil {
				liveLeases.remove(sl.lease.ID)
			}
		}
	})

	s := &Server{}
	now := time.Now()

	live := &secretLease{lease: newTestLease("lease_live", now.Add(10*time.Minute))}
	lapsed := &secretLease{lease: newTestLease("lease_lapsed", now.Add(-time.Minute))}
	liveLeases.add(live)
	liveLeases.add(lapsed)

	expired := s.sweepExpiredLeases(now)

	if len(expired) != 1 {
		t.Fatalf("sweep returned %d leases, want only the lapsed one: %+v", len(expired), expired)
	}
	if expired[0].LeaseID != "lease_lapsed" {
		t.Errorf("swept %q, want lease_lapsed", expired[0].LeaseID)
	}
	// The reason reaches the device and the audit trail, so it has to say why
	// rather than just that.
	if !strings.Contains(expired[0].Reason, "TTL expired") {
		t.Errorf("the sweep reason should name TTL expiry; got %q", expired[0].Reason)
	}
	// The lapsed lease's hub-side copy is wiped too — a lapsed lease is lapsed
	// everywhere, and the fan-out only reaches agents that hold it.
	for _, sl := range liveLeases.snapshot() {
		if sl.lease != nil && sl.lease.ID == "lease_lapsed" {
			t.Error("a swept lease should no longer be registered on the hub")
		}
	}
	if !leaseIsRegistered("lease_live") {
		t.Error("a lease inside its TTL must not be swept")
	}
}

// newTestLease builds a lease with the one field the janitor reads.
func newTestLease(id string, expiresAt time.Time) *secretbroker.Lease {
	return &secretbroker.Lease{
		ID:         id,
		ExecutorID: "edge-01",
		ProjectID:  "/srv/project",
		IssuedAt:   expiresAt.Add(-15 * time.Minute),
		ExpiresAt:  expiresAt,
	}
}

func leaseIsRegistered(id string) bool {
	for _, sl := range liveLeases.snapshot() {
		if sl.lease != nil && sl.lease.ID == id {
			return true
		}
	}
	return false
}
