package ui

// A run's concurrency slot goes where the run goes (Task 20452).
//
// Starting a run admits it against its tenant's concurrent-task quota: one
// slot, held while the run lasts and given back when it ends. The member that
// dispatched the run gave it back when the run's output stream closed there —
// so a run that moved to another member never came back the right way. A
// member that stopped mid-run exited before its stream closed, so the slot
// was never given back; the member that adopted the run did not know the run
// held one. And a live member that let go of a run (its agent reconnected
// elsewhere) gave the slot back when its stream was cancelled, while the run
// went on. The upgrade rehearsal (tests/upgrade) found the first: a run handed
// over twice in a rolling update left its tenant a slot short for good — the
// gauges are rebuilt only by a member starting alone — so a tenant capped at
// one run could never start another.
//
// So the slot is recorded on the run's owner row beside the leases it holds,
// and given back once by whichever member settles the run: the one streaming
// it when it ends, the one that adopts it, or the one that clears it as lost.
// A member that lets go of a run to another gives nothing back.
//
// A run dispatched by a build before this one carries no record of its slot,
// and one adopted by such a build is settled without giving it back: those
// slots are held until a member starting alone rebuilds the gauges.

import (
	"sync"

	"github.com/blechschmidt/cloop/pkg/quota"
)

// runQuotaSlot is the slot a run holds, as its owner row records it: whose,
// of which resource, and how many units.
type runQuotaSlot struct {
	Identity string  `json:"identity"`
	Resource string  `json:"resource"`
	N        float64 `json:"n"`
}

// heldSlot is a slot this member holds for a run. It is given back at most
// once, and not at all once the run has moved to another member.
type heldSlot struct {
	s    *Server
	slot runQuotaSlot

	mu       sync.Mutex
	done     bool // given back, or gone with its run
	exID     string
	handleID string
}

// holdRunSlot is the slot a request just admitted for identity, nil when it
// admitted none: no identity to account against, which quota.Enforcer.Admit
// takes no slot for either.
func (s *Server) holdRunSlot(identity string, res quota.Resource, n float64) *heldSlot {
	if identity == "" || identity == "anonymous" || n <= 0 {
		return nil
	}
	return &heldSlot{s: s, slot: runQuotaSlot{Identity: identity, Resource: string(res), N: n}}
}

// giveBack returns the slot to the enforcer, once. Nil-safe, and a no-op for
// a slot that went to another member with its run.
func (h *heldSlot) giveBack() {
	if h == nil {
		return
	}
	h.mu.Lock()
	if h.done {
		h.mu.Unlock()
		return
	}
	h.done = true
	exID, handleID := h.exID, h.handleID
	h.mu.Unlock()
	if handleID != "" {
		h.s.slots().drop(exID, handleID, h)
	}
	h.s.releaseQuota(h.slot.Identity, quota.Resource(h.slot.Resource), h.slot.N)
}

// bind makes the slot the run's: its owner row names it from now on, for the
// member that adopts the run. Nil-safe.
func (h *heldSlot) bind(exID, handleID string) {
	if h == nil {
		return
	}
	h.mu.Lock()
	h.exID, h.handleID = exID, handleID
	h.mu.Unlock()
	h.s.slots().put(exID, handleID, h)
}

// slotRegistry is the slots a member holds, by the run that holds each.
type slotRegistry struct {
	mu sync.Mutex
	m  map[string]*heldSlot
}

// slots is this member's registry: the runs it streams are its own.
func (s *Server) slots() *slotRegistry {
	s.runSlotsOnce.Do(func() { s.runSlots = &slotRegistry{m: map[string]*heldSlot{}} })
	return s.runSlots
}

func slotKey(exID, handleID string) string { return exID + "\x00" + handleID }

func (r *slotRegistry) put(exID, handleID string, h *heldSlot) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.m[slotKey(exID, handleID)] = h
}

// get is the slot recorded for a run, as its owner row names it; nil when the
// run holds none here.
func (r *slotRegistry) get(exID, handleID string) *runQuotaSlot {
	r.mu.Lock()
	defer r.mu.Unlock()
	h := r.m[slotKey(exID, handleID)]
	if h == nil {
		return nil
	}
	rec := h.slot
	return &rec
}

// drop forgets a run's slot if it is still h.
func (r *slotRegistry) drop(exID, handleID string, h *heldSlot) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.m[slotKey(exID, handleID)] == h {
		delete(r.m, slotKey(exID, handleID))
	}
}

// moved lets go of a run's slot without giving it back: the run went to
// another member, which holds it now and gives it back when the run ends.
func (r *slotRegistry) moved(exID, handleID string) {
	r.mu.Lock()
	h := r.m[slotKey(exID, handleID)]
	delete(r.m, slotKey(exID, handleID))
	r.mu.Unlock()
	if h != nil {
		h.mu.Lock()
		h.done = true
		h.mu.Unlock()
	}
}

// adoptRunSlot holds, for a run this member adopts, the slot its owner row
// names; nil when it names none — a run that holds no slot, or one a build
// before Task 20452 dispatched.
func (s *Server) adoptRunSlot(exID, handleID string, rec *runQuotaSlot) *heldSlot {
	if rec == nil || rec.Identity == "" || rec.N <= 0 {
		return nil
	}
	h := &heldSlot{s: s, slot: *rec}
	h.bind(exID, handleID)
	return h
}

// releaseRecordedSlot gives back the slot an owner row names, for a member
// clearing a run nobody streams any more.
func (s *Server) releaseRecordedSlot(rec *runQuotaSlot) {
	if rec == nil || rec.Identity == "" || rec.N <= 0 {
		return
	}
	s.releaseQuota(rec.Identity, quota.Resource(rec.Resource), rec.N)
}

// recordedRunSlot is the slot the owner row of workDir's run names, nil when
// there is no run or it names none.
func (s *Server) recordedRunSlot(workDir string) *runQuotaSlot {
	_, meta, ok := s.clusterRunOwner(workDir)
	if !ok {
		return nil
	}
	return meta.Slot
}
