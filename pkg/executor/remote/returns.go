package remote

// returns.go decides what a workload may send back to the hub, and when the
// hub lets go of what it sent (Task 20399).
//
// Three rules, each closing a way a compromised agent could pin hub memory:
//
//   - A handle accepts only what its spec asked for. A bundle write-back is
//     capped at the bytes the spec named (WriteBack.BundleCap), a push or no
//     write-back at none, and a project-state document comes back only from a
//     run that was seeded with one. The device was told what to send in the
//     start frame; anything else is refused before its bytes are kept.
//   - Nothing is accepted late. Once a handle has reported its final status,
//     or its write-back has closed with a result frame, every further chunk or
//     result is refused without allocating. An honest agent sends chunks, then
//     the result, then the status (pkg/executor/agent runs performWriteBack
//     before deliverFinal, and reports a finished workload as still running
//     until then) and never anything after. A restart from offset 0 stays
//     legal before the result, which is where a device that lost its link
//     mid-transfer can need it.
//   - What is held is let go of: when it is collected; when the handle ends
//     without the result that would make it collectable; when the handle is
//     abandoned or evicted, or its executor revoked or deregistered; and, for
//     a result nobody collected, resultRetention after the handle ended. Never
//     when a session detaches: the handle outlives the link, and in a hub
//     cluster other members still track it as running.
//
// Every byte held is counted against the executor's ResultBudget when it is
// kept and given back when it is dropped, under the handle's lock, so the
// budget and the bytes cannot drift apart; see resultbudget.go.

import (
	"fmt"
	"strconv"
	"time"
	"unicode/utf8"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/hubmetrics"
)

// resultAllowance is what one handle may send back, fixed at dispatch.
type resultAllowance struct {
	// known is false for a handle adopted from a row an older hub wrote,
	// which recorded none of this. Such a handle is held to the hard
	// ceilings rather than refused: refusing would lose the work of every
	// run in flight across the upgrade.
	known bool
	// mode is the write-back the spec asked for.
	mode executor.WriteBackMode
	// bundleCap is the most bundle bytes the handle may send: the spec's
	// BundleCap in bundle mode, zero otherwise.
	bundleCap int64
	// seeded reports that the run was dispatched with a project seed, so a
	// project-state document may come back.
	seeded bool
}

// allowanceFor reads a handle's allowance off the spec it is dispatched with.
func allowanceFor(spec executor.Spec) resultAllowance {
	a := resultAllowance{known: true, mode: spec.WriteBack.Mode, seeded: len(spec.ProjectSeed) > 0}
	if spec.WriteBack.Mode == executor.WriteBackBundle {
		a.bundleCap = spec.WriteBack.BundleCap()
	}
	return a
}

// unknownAllowance is the allowance of a handle whose row recorded none:
// whatever the protocol itself permits, up to the hard bundle ceiling.
func unknownAllowance() resultAllowance {
	return resultAllowance{bundleCap: executor.MaxWriteBackBundleBytes}
}

// acceptsResult reports whether a result frame may arrive at all. A push
// sends one with no bytes; a handle that asked for no write-back sends none.
func (a resultAllowance) acceptsResult() bool {
	return !a.known || a.mode != executor.WriteBackNone
}

// acceptsProjectResult reports whether a project-state document may arrive.
func (a resultAllowance) acceptsProjectResult() bool {
	return !a.known || a.seeded
}

// The HandleRecord.Meta keys an allowance is persisted under. Values only,
// never material: Meta is stored verbatim.
const (
	metaWriteBackMode = "writeback_mode"
	metaWriteBackCap  = "writeback_cap"
	metaProjectSeeded = "project_seeded"
)

// metaNoWriteBack spells WriteBackNone in Meta, whose zero value — a missing
// key — has to keep meaning "written by a hub that recorded nothing".
const metaNoWriteBack = "none"

// meta renders the allowance for the handle's durable row.
func (a resultAllowance) meta() map[string]string {
	mode := string(a.mode)
	if a.mode == executor.WriteBackNone {
		mode = metaNoWriteBack
	}
	return map[string]string{
		metaWriteBackMode: mode,
		metaWriteBackCap:  strconv.FormatInt(a.bundleCap, 10),
		metaProjectSeeded: strconv.FormatBool(a.seeded),
	}
}

// allowanceFromMeta reads a persisted allowance back. A row without one is an
// older hub's and gets the hard ceilings; a row whose values this build cannot
// read gets them too, with an error saying why, so a newer hub's row in a
// mixed cluster costs a looser bound rather than a refused result.
func allowanceFromMeta(m map[string]string) (resultAllowance, error) {
	raw, ok := m[metaWriteBackMode]
	if !ok {
		return unknownAllowance(), nil
	}
	a := resultAllowance{known: true}
	switch raw {
	case metaNoWriteBack:
		a.mode = executor.WriteBackNone
	case string(executor.WriteBackPush), string(executor.WriteBackBundle):
		a.mode = executor.WriteBackMode(raw)
	default:
		return unknownAllowance(), fmt.Errorf("write-back mode %q is not one this build knows", raw)
	}
	limit, err := strconv.ParseInt(m[metaWriteBackCap], 10, 64)
	switch {
	case err != nil:
		return unknownAllowance(), fmt.Errorf("write-back cap %q is not a byte count", m[metaWriteBackCap])
	case limit < 0 || limit > executor.MaxWriteBackBundleBytes:
		return unknownAllowance(), fmt.Errorf("write-back cap %d is outside 0..%d", limit,
			executor.MaxWriteBackBundleBytes)
	case a.mode != executor.WriteBackBundle && limit != 0:
		return unknownAllowance(), fmt.Errorf("a %q write-back carries a bundle cap of %d", raw, limit)
	}
	a.bundleCap = limit
	if a.seeded, err = strconv.ParseBool(m[metaProjectSeeded]); err != nil {
		return unknownAllowance(), fmt.Errorf("project_seeded %q is not a boolean", m[metaProjectSeeded])
	}
	return a, nil
}

// resultRetention is how long a finished handle's returned work waits for a
// consumer before the hub lets go of it.
//
// The consumers collect within moments of the final status — executor.Run
// reads it the instant the stream closes, and the hub settles a seeded run on
// the same signal — so this only ever fires for work nobody is going to ask
// for: a run whose follower died with a hub process, or one dispatched without
// a collector. Without it such work stays held until its handle is evicted,
// counted against its executor's budget the whole time.
const resultRetention = 15 * time.Minute

// maxReturnedTextBytes bounds the prose a device returns about one handle and
// the hub keeps with it: a status's error, a write-back's error and skip
// reason. The frame cap would otherwise let each of those be a megabyte, kept
// for every retained handle.
const maxReturnedTextBytes = 8 << 10

// clipText bounds s at n bytes, on a rune boundary, saying it did.
func clipText(s string, n int) string {
	if len(s) <= n {
		return s
	}
	cut := n
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + " …[truncated by the hub]"
}

// refuseFrame counts a result frame refused before its bytes were kept.
func refuseFrame(reason string) {
	hubmetrics.WriteBackFrameRefusals.Inc(reason)
}

// metricReason maps a budget refusal onto its metric label.
func (r *budgetRefusal) metricReason() string {
	if r.process {
		return hubmetrics.WriteBackRefusedProcessBudget
	}
	return hubmetrics.WriteBackRefusedExecutorBudget
}

// holdsResultsLocked reports whether hs holds any returned work. hs.mu must
// be held.
func (h *handleState) holdsResultsLocked() bool {
	return (h.writeBack != nil && h.writeBack.size > 0) || h.projectResult != nil
}

// dropBundleLocked lets go of an assembly's bytes and gives them back to the
// budget. The handle's mu must be held.
func (e *Executor) dropBundleLocked(wb *writeBackState) {
	if wb == nil {
		return
	}
	e.budget.release(e.id, wb.held)
	wb.chunks, wb.size, wb.held = nil, 0, 0
}

// dropProjectResultLocked lets go of a held project-state document. hs.mu must
// be held.
func (e *Executor) dropProjectResultLocked(hs *handleState) {
	if pr := hs.projectResult; pr != nil {
		e.budget.release(e.id, int64(len(pr.data)))
		hs.projectResult = nil
	}
}

// dropResultsLocked lets go of everything hs holds for collection, recording
// why on a bundle that was waiting, so a collector arriving afterwards is told
// what became of it rather than that nothing ever came. hs.mu must be held.
func (e *Executor) dropResultsLocked(hs *handleState, why string) {
	if wb := hs.writeBack; wb != nil {
		if wb.size > 0 && wb.failed == "" {
			wb.failed = why
		}
		e.dropBundleLocked(wb)
	}
	e.dropProjectResultLocked(hs)
}

// releaseResults lets go of everything one handle holds, for Abandon, which
// ends a handle from outside the session and holds no handle lock to do it
// under.
func (e *Executor) releaseResults(hs *handleState, why string) {
	if hs == nil {
		return
	}
	hs.mu.Lock()
	e.dropResultsLocked(hs, why)
	hs.mu.Unlock()
}

// releaseUncollected lets go of the returned work of every handle that ended
// more than resultRetention ago and still holds some. Run on each heartbeat,
// which is a clock this executor already has whenever its device is
// connected — and a device that is not connected adds nothing new to hold.
func (e *Executor) releaseUncollected() {
	now := e.opts.now()
	why := fmt.Sprintf("the hub let go of it after %s with nobody collecting it", resultRetention)
	e.mu.RLock()
	defer e.mu.RUnlock()
	for _, hs := range e.handles {
		hs.mu.Lock()
		if hs.closed && !hs.closedAt.IsZero() && now.Sub(hs.closedAt) >= resultRetention &&
			hs.holdsResultsLocked() {
			e.dropResultsLocked(hs, why)
		}
		hs.mu.Unlock()
	}
}

// PinnedResultBytes reports how much returned work this executor has the hub
// hold right now, as its budget counts it (bundle chunks with their
// ResultChunkOverhead), for diagnostics and tests.
func (e *Executor) PinnedResultBytes() int64 { return e.budget.Pinned(e.id) }
