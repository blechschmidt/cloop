package hubcluster

// runclaim.go: whether a claim on a project's run means the run is executing.
//
// A member that dispatches a run claims (OwnerKindRun, project directory) first,
// and the claim is how everything that did not start the run learns of it: the
// other members (Task 20354), and since Task 20374 processes that are not
// members at all — `cloop config validate --fix`, which must not reset a task a
// run is executing. Both ask the same question of the same row, so the rule
// lives here once rather than in each of them, where the two copies could drift
// apart on exactly the case that matters: a claim whose owner just died.

import (
	"time"

	"github.com/blechschmidt/cloop/pkg/statedb"
)

// OwnerKindRun is the ownership kind of a project's run. The key is the project
// directory as the hub registered it.
const OwnerKindRun = "run"

// DefaultOrphanRunGrace is how long a run whose owner died keeps its project
// marked running while no member has adopted it. Long enough for the agent
// behind the run to reconnect to another member and be adopted there; short
// enough that a run nobody can reach does not wedge its project.
const DefaultOrphanRunGrace = 2 * time.Minute

// RunClaimMeta is the part of a run claim's metadata every observer judges by.
// The hub's own run metadata embeds it, so the field is written and read under
// one name.
type RunClaimMeta struct {
	// Dispatching marks a claim taken before its workload is on record. A
	// member that dies inside that window leaves a claim the leader clears
	// rather than tries to adopt — once it has stopped whatever workload the
	// dispatch started (RunID, Task 20419).
	Dispatching bool `json:"dispatching,omitempty"`
	// RunID names the run the dispatch is starting, set as soon as its
	// executor is asked (Task 20419). A dispatching claim with one may have a
	// workload behind it, which the dispatch intent of that run names.
	RunID string `json:"run_id,omitempty"`
}

// RunTakeover is a credential the member owning an adopted run has not been
// able to take over yet (Task 20451): the lease, workspace lease or egress
// session the run's owner row names, which an attempt could neither take over
// nor rule out — the secret store unreadable for a moment, the database
// locked, a KMS down. The member retries it until the outcome is decided or
// Until passes; the id stays in the row's credential lists meanwhile, so a
// member adopting the run after this one tries it too.
type RunTakeover struct {
	// Kind is what it is: "run" (a secret lease), "workspace" (the lease a
	// pinned git session stands on) or "egress" (an egress proxy session).
	Kind string `json:"kind"`
	// ID is the lease's or the session's id.
	ID string `json:"id"`
	// Since is when the first attempt decided nothing.
	Since time.Time `json:"since"`
	// Attempts counts the attempts so far.
	Attempts int `json:"attempts,omitempty"`
	// Reason is the last attempt's error, with any credential redacted.
	Reason string `json:"reason,omitempty"`
	// Until is the recorded expiry it is tried until.
	Until time.Time `json:"until,omitzero"`
}

// RunTakeoverMeta is the part of a run claim's metadata naming the takeovers
// still undecided. The hub's own run metadata embeds it, so it is written and
// read — by `cloop hub doctor`, which is not a member — under one name.
type RunTakeoverMeta struct {
	Takeovers []RunTakeover `json:"takeovers,omitempty"`
}

// MayHaveWorkload reports whether a claim may have a workload behind it: one
// past dispatch, or one whose dispatch got as far as its executor.
func (m RunClaimMeta) MayHaveWorkload() bool {
	return !m.Dispatching || m.RunID != ""
}

// RunClaimLive reports whether o, a claim on a project's run held by a member
// other than the observer, means the run is — or may still be — executing.
//
// A live owner is conclusive. A dead owner's claim fails closed for grace after
// the owner was last seen: the run may be adopted by the member its agent
// reconnects to, and acting on the project in that window would reset tasks
// under a run that is about to resume. A claim the owner took before it asked
// any executor for anything has nothing behind it once the owner is gone, and
// does not count; one whose dispatch reached an executor may have started a
// workload, and counts until the grace runs out (Task 20419) — the leader
// stops that workload in the meantime. Metadata that cannot be decoded is
// judged as a claim with a workload, the reading that fails closed.
func RunClaimLive(o Owner, now time.Time, grace time.Duration) bool {
	if o.Alive {
		return true
	}
	var meta RunClaimMeta
	if err := o.Meta(&meta); err == nil && !meta.MayHaveWorkload() {
		return false
	}
	since := o.Member.HeartbeatAt
	if since.IsZero() {
		since = o.ClaimedAt()
	}
	return now.Sub(since) < grace
}

// PeekRunClaims returns every run claim recorded in the control plane at
// dbPath, each with its owner judged from this process the way members judge
// each other (RowAlive). For processes that are not members: it reads through
// a read-only handle, so it neither migrates the hub's database nor is refused
// by one whose schema is ahead of this binary, and it never writes. A control
// plane no clustered hub has served has no claims.
func PeekRunClaims(dbPath string, now time.Time) ([]Owner, error) {
	members, rows, err := statedb.PeekHubCluster(dbPath, OwnerKindRun)
	if err != nil {
		return nil, err
	}
	byID := make(map[string]statedb.HubMemberRow, len(members))
	for _, m := range members {
		byID[m.InstanceID] = m
	}
	out := make([]Owner, 0, len(rows))
	for _, row := range rows {
		o := Owner{Kind: row.Kind, Key: row.Key, InstanceID: row.InstanceID, Row: row}
		if m, ok := byID[row.InstanceID]; ok {
			o.Member = memberFromRow(m)
			o.Alive = RowAlive(m, now)
		}
		out = append(out, o)
	}
	return out, nil
}
