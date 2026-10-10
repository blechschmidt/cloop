package secretbroker

// grantrevoke.go: revoking a grant reaches the workloads already holding it
// (Task 20403).
//
// Revoke used to stamp the grant and stop there. The next lease left the grant
// out, and the keepalive refused to extend a lease that still carried it, so
// the material already inside a running workload stayed usable until that
// lease lapsed — up to fifteen minutes — and, on a container or a Pod, until
// the workload exited. Three pieces close that:
//
//   - Every revocation made through any Broker in this process is announced to
//     the process's subscribers (OnGrantRevoked). The hub subscribes once and
//     takes the grant's material back from every lease carrying it, so no
//     caller — the Secrets panel, offboarding, a secret's deletion, a request's
//     rollback — can revoke a grant and forget to cascade it.
//   - A lease can give up one grant and keep the others (DropLeaseGrant):
//     revoking a GitHub PAT does not end the kubeconfig delivered beside it.
//   - A superseded grant is not withdrawn (Supersede). An edited repository
//     assignment, or a credential granted again for longer, replaces the old
//     grant with one that still authorises the work, and the grant row names
//     it. A running lease keeps what it was given and stands on the
//     successor's authority — every hub process reads that off the grant, so
//     neither the edit nor the lapse that would otherwise follow cuts the run
//     off — until the successor is revoked in its turn.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"
)

// GrantRevocation is one grant a Broker in this process has just stamped
// revoked.
type GrantRevocation struct {
	GrantID    string
	SecretID   string
	SecretName string
	Kind       Kind
	Subject    Subject
	Actor      string
	Cause      RevocationCause
	Reason     string
	At         time.Time
	// SupersededBy names the grant that replaced this one, for a
	// supersession (Cause RevokedSuperseded).
	SupersededBy string
	// ControlPlane is where the store keeps its data — the database file —
	// when the store can say (Locator). A process serving more than one
	// control plane uses it to tell whose revocation this is.
	ControlPlane string
}

// Superseded reports whether the grant was replaced rather than withdrawn.
func (r GrantRevocation) Superseded() bool { return r.Cause == RevokedSuperseded }

// Locator is an optional Store extension that names where the store keeps its
// data. pkg/secretstore answers with its database file.
type Locator interface {
	Location() string
}

var revocationHooks struct {
	mu   sync.RWMutex
	next int
	fns  map[int]func(context.Context, GrantRevocation)
}

// OnGrantRevoked registers fn to run after every grant revocation any Broker in
// this process makes — Revoke, a secret's deletion, a supersession — and
// returns the function that unregisters it.
//
// fn runs synchronously, on the revoking goroutine, after the grant is stamped
// in the store: a caller that wants the cascade's outcome passes it back
// through ctx, and a caller that does not is still not finished revoking until
// the material is taken back. It is not called for a grant that was already
// revoked: a revocation is idempotent, and one that cascaded once must not
// cascade again. A panicking fn is recovered, so one subscriber cannot leave a
// grant stamped and the rest of the process uninformed.
func OnGrantRevoked(fn func(context.Context, GrantRevocation)) (cancel func()) {
	if fn == nil {
		return func() {}
	}
	revocationHooks.mu.Lock()
	if revocationHooks.fns == nil {
		revocationHooks.fns = make(map[int]func(context.Context, GrantRevocation))
	}
	id := revocationHooks.next
	revocationHooks.next++
	revocationHooks.fns[id] = fn
	revocationHooks.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			revocationHooks.mu.Lock()
			delete(revocationHooks.fns, id)
			revocationHooks.mu.Unlock()
		})
	}
}

// announceRevoked runs the subscribers for each revocation, in registration
// order.
func (b *Broker) announceRevoked(ctx context.Context, revs ...GrantRevocation) {
	revocationHooks.mu.RLock()
	ids := make([]int, 0, len(revocationHooks.fns))
	for id := range revocationHooks.fns {
		ids = append(ids, id)
	}
	sort.Ints(ids)
	fns := make([]func(context.Context, GrantRevocation), 0, len(ids))
	for _, id := range ids {
		fns = append(fns, revocationHooks.fns[id])
	}
	revocationHooks.mu.RUnlock()
	for _, rev := range revs {
		for _, fn := range fns {
			func() {
				defer func() {
					if r := recover(); r != nil {
						fmt.Fprintf(os.Stderr, "secretbroker: a subscriber to the revocation of grant %s panicked: %v\n",
							rev.GrantID, r)
					}
				}()
				fn(ctx, rev)
			}()
		}
	}
}

// location is the store's Location, or "".
func (b *Broker) location() string {
	if l, ok := b.store.(Locator); ok {
		return l.Location()
	}
	return ""
}

// RevokeGrantRequest describes a revocation.
type RevokeGrantRequest struct {
	GrantID string
	Actor   string
	// Cause is recorded on the grant; see RevocationCause.
	Cause RevocationCause
	// Reason goes on the secret.revoke row.
	Reason string
	// SupersededBy names the replacing grant, with Cause RevokedSuperseded.
	SupersededBy string
}

// RevokeGrant marks a grant unusable and announces it to this process's
// subscribers (OnGrantRevoked), which take its material back from the
// workloads holding it. It reports what was revoked and whether this call
// revoked it: false, with a nil error, for a grant that was already revoked —
// a retry is not an error, and announces nothing.
func (b *Broker) RevokeGrant(ctx context.Context, req RevokeGrantRequest) (GrantRevocation, bool, error) {
	if err := ctx.Err(); err != nil {
		return GrantRevocation{}, false, err
	}
	grantID := strings.TrimSpace(req.GrantID)
	ev := Event{Action: ActionRevoke, Actor: req.Actor, GrantID: grantID}

	g, err := b.store.GetGrant(grantID)
	if err != nil {
		return GrantRevocation{}, false, b.denyf(ev, ErrGrantNotFound, "grant %q: %v", grantID, err)
	}
	ev.SecretID = g.SecretID
	ev.Subject = g.Subject.String()
	ev.Constraints = g.Constraints.Summary()
	rev := GrantRevocation{
		GrantID: g.ID, SecretID: g.SecretID, Subject: g.Subject, Actor: req.Actor,
		Cause: req.Cause, Reason: strings.TrimSpace(req.Reason), SupersededBy: strings.TrimSpace(req.SupersededBy),
		ControlPlane: b.location(),
	}
	if s, serr := b.store.GetSecret(g.SecretID); serr == nil {
		ev.SecretName, ev.Kind = s.Name, s.Kind
		rev.SecretName, rev.Kind = s.Name, s.Kind
	}

	if !g.RevokedAt.IsZero() {
		// Idempotent: report success so a retry is not an error.
		ev.Decision = DecisionAllow
		ev.Reason = "already revoked at " + g.RevokedAt.UTC().Format(time.RFC3339)
		b.emit(ev)
		rev.At = g.RevokedAt
		rev.Cause = g.RevokedCause
		return rev, false, nil
	}
	now := b.now()
	stamp := func() error { return b.revokeStored(grantID, now, req.Cause) }
	if rev.Superseded() && rev.SupersededBy != "" {
		if sr, ok := b.store.(SupersedingRevoker); ok {
			stamp = func() error { return sr.RevokeGrantSuperseded(grantID, now, rev.SupersededBy) }
		}
	}
	if err := stamp(); err != nil {
		return GrantRevocation{}, false, b.denyf(ev, ErrInvalidGrant, "revoke: %v", err)
	}
	rev.At = now
	if !rev.Superseded() {
		// For a github_app grant the hub minted the credential, so it can end
		// it now instead of waiting out the lease period. Done after the store
		// write: if the write fails the grant is still live, and killing its
		// tokens would break a running workload that the grant still
		// authorises. A superseded grant's tokens are not ended: the leases
		// holding them stand on the successor from here on, and re-mint at
		// the successor's terms (refreshAuthority).
		b.destroyGrantTokens(ctx, grantID, "grant "+grantID+" revoked")
	} else {
		b.ReconfirmSupersededSlots()
	}

	ev.Decision = DecisionAllow
	ev.Reason = rev.Reason
	b.emit(ev)
	b.announceRevoked(ctx, rev)
	return rev, true, nil
}

// Supersede revokes grantID because successorID replaces it — an edited
// assignment, a credential granted again for longer — and records the
// successor on the grant, so the leases carrying grantID stand on successorID
// instead of giving the material back, and announces it as a supersession. The
// successor must be live and issued to the same subject: a grant replaced by
// one that reaches somebody else, or by nothing, is withdrawn, which is Revoke.
func (b *Broker) Supersede(ctx context.Context, grantID, successorID, actor string) (GrantRevocation, bool, error) {
	grantID, successorID = strings.TrimSpace(grantID), strings.TrimSpace(successorID)
	ev := Event{Action: ActionRevoke, Actor: actor, GrantID: grantID}
	if successorID == "" || successorID == grantID {
		return GrantRevocation{}, false, b.denyf(ev, ErrInvalidGrant,
			"grant %s cannot be superseded by %q", grantID, successorID)
	}
	old, err := b.store.GetGrant(grantID)
	if err != nil {
		return GrantRevocation{}, false, b.denyf(ev, ErrGrantNotFound, "grant %q: %v", grantID, err)
	}
	next, err := b.store.GetGrant(successorID)
	if err != nil {
		return GrantRevocation{}, false, b.denyf(ev, ErrGrantNotFound, "successor grant %q: %v", successorID, err)
	}
	if reason := next.DenyReason(b.now()); reason != "" {
		return GrantRevocation{}, false, b.denyf(ev, ErrInvalidGrant,
			"grant %s cannot be superseded by %s: %s", grantID, successorID, reason)
	}
	if old.Subject.String() != next.Subject.String() {
		return GrantRevocation{}, false, b.denyf(ev, ErrInvalidGrant,
			"grant %s is issued to %s and %s to %s; only a grant issued to the same subject supersedes it",
			grantID, old.Subject, successorID, next.Subject)
	}
	return b.RevokeGrant(ctx, RevokeGrantRequest{
		GrantID: grantID, Actor: actor, Cause: RevokedSuperseded,
		Reason: "superseded by grant " + successorID, SupersededBy: successorID,
	})
}

// LookupGrant returns a grant as stored: who it is issued to, its constraints,
// when and why it was revoked. Metadata only — a grant carries no material.
func (b *Broker) LookupGrant(id string) (Grant, error) {
	return b.store.GetGrant(strings.TrimSpace(id))
}

// WithdrawnGrant is a grant a live lease carries that no longer authorises it.
type WithdrawnGrant struct {
	GrantID string `json:"grant_id"`
	// Reason says why, in the denial's words.
	Reason string `json:"reason"`
}

// maxSupersessions bounds how far a superseded grant's successors are followed.
// A successor must be live when it supersedes, so the chain cannot loop; the
// bound is for a store that says otherwise.
const maxSupersessions = 16

// authorityFor returns the grant a lease holding grant id stands on: id itself,
// or — for a superseded grant — its successor, followed through any later
// supersession to the first grant that was not superseded. That grant may be
// revoked or expired; standing decides what it means.
func (b *Broker) authorityFor(id string) (Grant, error) {
	g, err := b.store.GetGrant(id)
	for hops := 0; err == nil && hops < maxSupersessions; hops++ {
		next := strings.TrimSpace(g.SupersededBy)
		if g.RevokedAt.IsZero() || g.RevokedCause != RevokedSuperseded || next == "" {
			return g, nil
		}
		g, err = b.store.GetGrant(next)
	}
	if err != nil {
		return Grant{}, err
	}
	return Grant{}, fmt.Errorf("grant %s is superseded more than %d times over", id, maxSupersessions)
}

// standing reports whether held grant id still authorises a lease issued to
// requester, and on what: the grant itself, or — for a superseded grant — the
// successor it stands on (authorityFor). On refusal it returns the sentinel and
// the end of the sentence that explains it, and whether that answer will
// stand: a grant or secret that is gone is final, a store that did not answer
// is not.
func (b *Broker) standing(id string, requester Requester, now time.Time) (authority Grant, sentinel error, why string, final bool) {
	g, err := b.authorityFor(id)
	if err != nil {
		return Grant{}, ErrGrantNotFound, fmt.Sprintf(", which can no longer be read: %v", err),
			errors.Is(err, ErrGrantNotFound)
	}
	via := ""
	if g.ID != id {
		via = ", superseded by grant " + g.ID
	}
	if reason := g.DenyReason(now); reason != "" {
		if !g.RevokedAt.IsZero() {
			return Grant{}, ErrGrantRevoked, via + ": " + reason, true
		}
		return Grant{}, ErrGrantExpired, via + ": " + reason, true
	}
	if !g.Subject.Matches(requester) {
		return Grant{}, ErrInvalidGrant, via + ", which is no longer issued to this requester", true
	}
	if _, err := b.store.GetSecret(g.SecretID); err != nil {
		return Grant{}, ErrSecretNotFound, fmt.Sprintf("%s, whose secret %s is gone", via, g.SecretID),
			errors.Is(err, ErrSecretNotFound)
	}
	if g.ID != id {
		// What the lease holds came from the superseded grant's own secret,
		// which a successor over another secret does not keep alive: deleted,
		// its material goes, whatever the successor still authorises.
		if orig, err := b.store.GetGrant(id); err == nil && orig.SecretID != g.SecretID {
			if _, err := b.store.GetSecret(orig.SecretID); err != nil {
				return Grant{}, ErrSecretNotFound, fmt.Sprintf(", whose secret %s is gone", orig.SecretID),
					errors.Is(err, ErrSecretNotFound)
			}
		}
	}
	return g, nil, "", false
}

// WithdrawnGrants returns the grants the live lease leaseID carries that no
// longer authorise it: revoked, superseded with no successor it stands on, or
// gone with their secret. An expired grant is not among them — the lease's
// deadline is clamped to its grants' expiry, so the lease lapses with it — and
// neither is a grant the store could not be asked about just now. Nil for a
// lease this broker does not hold.
func (b *Broker) WithdrawnGrants(leaseID string) []WithdrawnGrant {
	b.mu.Lock()
	st, ok := b.leases[leaseID]
	var (
		requester Requester
		grantIDs  []string
	)
	if ok {
		requester = st.requester
		grantIDs = append(grantIDs, st.grantIDs...)
	}
	b.mu.Unlock()
	if !ok {
		return nil
	}
	now := b.now()
	var out []WithdrawnGrant
	for _, id := range grantIDs {
		_, sentinel, why, final := b.standing(id, requester, now)
		if sentinel == nil || !final || errors.Is(sentinel, ErrGrantExpired) {
			continue
		}
		out = append(out, WithdrawnGrant{GrantID: id, Reason: "grant " + id + strings.TrimPrefix(why, ",")})
	}
	return out
}

// HeldGrantIDs returns the grants the live lease leaseID carries, sorted. Nil
// for a lease this broker does not hold.
func (b *Broker) HeldGrantIDs(leaseID string) []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	st, ok := b.leases[leaseID]
	if !ok {
		return nil
	}
	out := append([]string(nil), st.grantIDs...)
	sort.Strings(out)
	return out
}

// HeldOn returns the grants the live lease leaseID carries on grantID's
// authority: grantID itself when the lease carries it, and every superseded
// grant whose successors lead to it. A revocation of grantID withdraws those; a
// supersession of it leaves them standing on its successor.
func (b *Broker) HeldOn(leaseID, grantID string) []string {
	return b.heldOn(b.HeldGrantIDs(leaseID), grantID)
}

// HeldOn returns the grants rec carries on grantID's authority, as Broker.HeldOn
// does for a lease this broker holds.
func (b *Broker) RecordHeldOn(rec LeaseRecord, grantID string) []string {
	return b.heldOn(rec.GrantIDs, grantID)
}

// heldOn is HeldOn over a list of held grants.
func (b *Broker) heldOn(held []string, grantID string) []string {
	grantID = strings.TrimSpace(grantID)
	if grantID == "" {
		return nil
	}
	var out []string
	for _, id := range held {
		if id == grantID {
			out = append(out, id)
			continue
		}
		g, err := b.store.GetGrant(id)
		for hops := 0; err == nil && hops < maxSupersessions; hops++ {
			next := strings.TrimSpace(g.SupersededBy)
			if g.RevokedCause != RevokedSuperseded || next == "" {
				break
			}
			if next == grantID {
				out = append(out, id)
				break
			}
			g, err = b.store.GetGrant(next)
		}
	}
	return out
}

// DropLeaseGrant takes grantID out of the live lease leaseID once its material
// has been taken back from the workload (Task 20403): the lease keeps the
// grants nobody revoked, is extended on those alone, and is recorded so for
// any process that takes it over. Any App token minted for the grant in this
// lease is destroyed at GitHub. It reports how many grants the lease still
// carries; dropping a grant the lease does not carry changes nothing.
func (b *Broker) DropLeaseGrant(ctx context.Context, leaseID, grantID, reason string) (int, error) {
	grantID = strings.TrimSpace(grantID)
	b.recordMu.Lock()
	defer b.recordMu.Unlock()

	b.mu.Lock()
	st, ok := b.leases[leaseID]
	if !ok {
		b.mu.Unlock()
		return 0, wrapf(ErrLeaseNotFound, "lease %s is not held by this broker", leaseID)
	}
	idx := slices.Index(st.grantIDs, grantID)
	if idx < 0 {
		n := len(st.grantIDs)
		b.mu.Unlock()
		return n, nil
	}
	st.grantIDs = slices.Delete(slices.Clone(st.grantIDs), idx, idx+1)
	grantIDs, recorded := append([]string(nil), st.grantIDs...), st.recorded

	var (
		doomed []appToken
		keep   []*appTokenSlot
		hadApp bool
	)
	for _, slot := range b.minted[leaseID] {
		if slot.grantID == grantID {
			hadApp = true
			doomed = append(doomed, slot.end()...)
			continue
		}
		keep = append(keep, slot)
	}
	if len(keep) == 0 {
		delete(b.minted, leaseID)
	} else {
		b.minted[leaseID] = keep
	}
	b.mu.Unlock()

	if hadApp {
		b.forgetSlotRecords(leaseID, grantID)
	}
	if strings.TrimSpace(reason) == "" {
		reason = "grant " + grantID + " withdrawn from lease " + leaseID
	}
	b.destroyAppTokens(ctx, doomed, reason)
	if recorded {
		if err := b.rewriteLeaseGrants(leaseID, grantIDs); err != nil {
			return len(grantIDs), err
		}
	}
	return len(grantIDs), nil
}

// ReconfirmSupersededSlots marks every GitHub App token slot this broker holds
// whose grant was superseded since its scope was last held to it, so its next
// refresh holds the scope to the successor's constraints — and, for a token in
// the workload's files, so that refresh is the keepalive's next tick (Task
// 20403). An edit that narrowed an assignment narrows the running workload's
// token this way; one that widened it cannot widen it.
func (b *Broker) ReconfirmSupersededSlots() {
	b.mu.Lock()
	var slots []*appTokenSlot
	for _, held := range b.minted {
		for _, slot := range held {
			if !slot.ended && !slot.abandoned {
				slots = append(slots, slot)
			}
		}
	}
	b.mu.Unlock()
	for _, slot := range slots {
		b.mu.Lock()
		grantID, confirmedFor := slot.grantID, slot.confirmedFor
		b.mu.Unlock()
		if confirmedFor == "" {
			confirmedFor = grantID
		}
		g, err := b.authorityFor(grantID)
		if err != nil || g.ID == confirmedFor {
			continue
		}
		b.mu.Lock()
		slot.reconfirm = true
		b.mu.Unlock()
	}
}

// rewriteLeaseGrants writes a held lease's grants into its durable record. A
// record another process holds now is that process's: ErrLeaseMoved.
func (b *Broker) rewriteLeaseGrants(leaseID string, grantIDs []string) error {
	ls, ok := b.leaseRecords()
	if !ok {
		return nil
	}
	gs, ok := ls.(LeaseGrantStore)
	if !ok {
		return nil
	}
	wrote, err := gs.SetLeaseGrants(leaseID, b.leaseHolder, grantIDs)
	if err != nil {
		return fmt.Errorf("secretbroker: record the grants of lease %s: %w", leaseID, err)
	}
	if !wrote {
		return wrapf(ErrLeaseMoved, "lease %s is held by another hub process now", leaseID)
	}
	return nil
}
