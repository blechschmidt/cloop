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
	// Dispatching marks a claim taken before its workload exists. A member
	// that dies inside that window leaves a claim with nothing behind it,
	// which the leader clears rather than tries to adopt.
	Dispatching bool `json:"dispatching,omitempty"`
}

// RunClaimLive reports whether o, a claim on a project's run held by a member
// other than the observer, means the run is — or may still be — executing.
//
// A live owner is conclusive. A dead owner's claim fails closed for grace after
// the owner was last seen: the run may be adopted by the member its agent
// reconnects to, and acting on the project in that window would reset tasks
// under a run that is about to resume. A claim the owner took before it had
// dispatched anything has nothing behind it once the owner is gone, and does
// not count. Metadata that cannot be decoded is judged as a claim with a
// workload, the reading that fails closed.
func RunClaimLive(o Owner, now time.Time, grace time.Duration) bool {
	if o.Alive {
		return true
	}
	var meta RunClaimMeta
	if err := o.Meta(&meta); err == nil && meta.Dispatching {
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
