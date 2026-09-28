package hubcluster

// owners.go: which member holds a thing that cannot be shared.
//
// Some state is a process, not a row: an agent's WebSocket, the goroutine
// streaming a run's output, a `claude auth login` child waiting for its code.
// Moving it into the database is not possible, so the database records *where*
// it is instead, and requests about it are forwarded there. When the member
// holding it dies, another member that can reach the underlying thing — the
// container, the Pod, the agent after it reconnects — adopts it.
//
// Two write disciplines, for two kinds of fact:
//
//	Claim is mutual exclusion. It succeeds only if nobody live holds the key,
//	and is how a run is started: a second member racing to start the same
//	project's run loses the compare-and-swap and answers 409 instead of
//	dispatching a second harness into one working directory.
//
//	Assert is observation. The agent is connected *here*, now, whatever an
//	earlier row says — the member it left may not have noticed yet and must
//	not be able to keep the row by having written it first.

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/blechschmidt/cloop/pkg/statedb"
)

// Owner describes who holds (Kind, Key).
type Owner struct {
	Kind string
	Key  string
	// InstanceID is the owning member's id.
	InstanceID string
	// Member is the owning member as of the last refresh; zero when the row
	// names an instance this node has never seen.
	Member Member
	// Self reports that this member is the owner.
	Self bool
	// Alive reports whether the owner is alive.
	Alive bool
	// Row is the stored claim, needed to adopt or drop it.
	Row statedb.HubOwnerRow
}

// Meta decodes the owner's recorded metadata into v.
func (o Owner) Meta(v any) error {
	if o.Row.Meta == "" {
		return nil
	}
	return json.Unmarshal([]byte(o.Row.Meta), v)
}

// ClaimedAt is when the current owner took the key.
func (o Owner) ClaimedAt() time.Time { return o.Row.ClaimedAt }

func encodeMeta(meta any) (string, error) {
	switch m := meta.(type) {
	case nil:
		return "{}", nil
	case string:
		if m == "" {
			return "{}", nil
		}
		return m, nil
	case json.RawMessage:
		return string(m), nil
	}
	b, err := json.Marshal(meta)
	if err != nil {
		return "", fmt.Errorf("hubcluster: encode owner meta: %w", err)
	}
	return string(b), nil
}

func (n *Node) ownerFrom(row statedb.HubOwnerRow) Owner {
	o := Owner{
		Kind:       row.Kind,
		Key:        row.Key,
		InstanceID: row.InstanceID,
		Row:        row,
		Self:       row.InstanceID == n.self.ID,
	}
	if m, ok := n.Member(row.InstanceID); ok {
		o.Member = m
	}
	o.Alive = o.Self || n.IsAlive(row.InstanceID)
	return o
}

// Lookup reports who owns (kind, key). found is false when nobody does.
func (n *Node) Lookup(kind, key string) (o Owner, found bool, err error) {
	if n == nil {
		return Owner{}, false, nil
	}
	row, err := n.store.GetHubOwner(kind, key)
	if errors.Is(err, statedb.ErrHubOwnerNotFound) {
		return Owner{}, false, nil
	}
	if err != nil {
		return Owner{}, false, err
	}
	return n.ownerFrom(row), true, nil
}

// Claim takes (kind, key) for this member unless a live member holds it, in
// which case it returns that owner and false. A key held by a dead member is
// taken over. A key this member already holds has its meta refreshed.
func (n *Node) Claim(kind, key string, meta any) (Owner, bool, error) {
	if n == nil {
		return Owner{}, true, nil
	}
	encoded, err := encodeMeta(meta)
	if err != nil {
		return Owner{}, false, err
	}
	// Three attempts: each lost race re-reads and re-judges, and a key that
	// changes hands three times in the span of one call is contended enough
	// that "someone else has it" is the honest answer.
	for attempt := 0; attempt < 3; attempt++ {
		cur, found, err := n.Lookup(kind, key)
		if err != nil {
			return Owner{}, false, err
		}
		if found && cur.Self {
			if _, err := n.store.UpdateHubOwnerMeta(kind, key, n.self.ID, encoded, n.now()); err != nil {
				return Owner{}, false, err
			}
			cur.Row.Meta = encoded
			return cur, true, nil
		}
		if found && cur.Alive {
			return cur, false, nil
		}
		now := n.now()
		row := statedb.HubOwnerRow{
			Kind: kind, Key: key, InstanceID: n.self.ID, Meta: encoded,
			ClaimedAt: now, UpdatedAt: now,
		}
		var expect statedb.HubOwnerRow
		if found {
			expect = cur.Row
		}
		ok, err := n.store.ClaimHubOwner(row, expect)
		if err != nil {
			return Owner{}, false, err
		}
		if ok {
			return n.ownerFrom(row), true, nil
		}
	}
	cur, found, err := n.Lookup(kind, key)
	if err != nil {
		return Owner{}, false, err
	}
	if found && cur.Self {
		return cur, true, nil
	}
	return cur, false, nil
}

// Assert records this member as the owner of (kind, key), whoever held it.
func (n *Node) Assert(kind, key string, meta any) error {
	if n == nil {
		return nil
	}
	encoded, err := encodeMeta(meta)
	if err != nil {
		return err
	}
	now := n.now()
	return n.store.PutHubOwner(statedb.HubOwnerRow{
		Kind: kind, Key: key, InstanceID: n.self.ID, Meta: encoded,
		ClaimedAt: now, UpdatedAt: now,
	})
}

// UpdateMeta rewrites the meta of a key this member still owns, and reports
// whether it still did.
func (n *Node) UpdateMeta(kind, key string, meta any) (bool, error) {
	if n == nil {
		return true, nil
	}
	encoded, err := encodeMeta(meta)
	if err != nil {
		return false, err
	}
	return n.store.UpdateHubOwnerMeta(kind, key, n.self.ID, encoded, n.now())
}

// Release gives up (kind, key) if this member still owns it.
func (n *Node) Release(kind, key string) (bool, error) {
	if n == nil {
		return true, nil
	}
	return n.store.ReleaseHubOwner(kind, key, n.self.ID)
}

// Owns reports whether this member currently owns (kind, key), read from the
// database rather than remembered: ownership can be taken by a member that
// judged this one dead, and the only way to learn that is to look.
func (n *Node) Owns(kind, key string) bool {
	if n == nil {
		return true
	}
	o, found, err := n.Lookup(kind, key)
	if err != nil {
		// A read failure is not evidence of losing ownership; acting as the
		// owner on a transient error is what the owner was doing anyway.
		return true
	}
	return found && o.Self
}

// Owned lists every row of kind ("" for all kinds), with liveness verdicts.
func (n *Node) Owned(kind string) ([]Owner, error) {
	if n == nil {
		return nil, nil
	}
	rows, err := n.store.ListHubOwners(kind)
	if err != nil {
		return nil, err
	}
	out := make([]Owner, 0, len(rows))
	for _, r := range rows {
		out = append(out, n.ownerFrom(r))
	}
	return out, nil
}

// Orphans lists the rows of kind whose owner is not alive.
func (n *Node) Orphans(kind string) ([]Owner, error) {
	all, err := n.Owned(kind)
	if err != nil {
		return nil, err
	}
	var out []Owner
	for _, o := range all {
		if !o.Alive {
			out = append(out, o)
		}
	}
	return out, nil
}

// Adopt takes over an orphan, conditioned on the claim being exactly the one
// o was read from. false means another member got there first, or the owner
// came back.
func (n *Node) Adopt(o Owner, meta any) (bool, error) {
	if n == nil {
		return true, nil
	}
	if meta == nil {
		meta = o.Row.Meta
	}
	encoded, err := encodeMeta(meta)
	if err != nil {
		return false, err
	}
	now := n.now()
	return n.store.ClaimHubOwner(statedb.HubOwnerRow{
		Kind: o.Kind, Key: o.Key, InstanceID: n.self.ID, Meta: encoded,
		ClaimedAt: now, UpdatedAt: now,
	}, o.Row)
}

// Drop deletes an orphan that nothing can adopt, under the same condition as
// Adopt.
func (n *Node) Drop(o Owner) (bool, error) {
	if n == nil {
		return true, nil
	}
	return n.store.ReleaseHubOwnerIfClaim(o.Row)
}
