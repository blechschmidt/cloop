package remote

// writeback.go is the control plane's half of getting a finished task's work
// *off* a device — workspace.go's mirror image.
//
// The device streams a git bundle back as result chunks and closes with a
// result frame. This file assembles the one from the other, and everything in
// it is a refusal to be optimistic about a peer that is, by construction, the
// least trusted party in the system:
//
//   - a chunk that does not start exactly where the last one ended fails the
//     write-back rather than leaving a hole. Log output is deliberately lossy —
//     a slow subscriber has chunks dropped so the workload is never blocked —
//     but a bundle with a gap is not a smaller bundle, it is a corrupt one, and
//     git would report the damage as something that sounds unrelated.
//   - the running total is checked on every chunk, not at the end, against the
//     cap the handle's own spec asked for and against the hub's memory budget
//     for returned work. A cap enforced after assembly is a cap on the error
//     message.
//   - the reported length and SHA-256 are both verified before the bytes are
//     handed to anything. A truncated transfer and a tampered one produce the
//     same symptom otherwise: a bundle git declines to open.
//   - nothing arrives late. A chunk or a result for a handle that has reported
//     its final status, or whose write-back already closed, is refused before
//     anything is allocated for it (Task 20399; see returns.go).
//
// The bytes live in memory, as the chunks that carried them, counted against
// the executor's ResultBudget, and are dropped as soon as the consumer has
// collected them — or as soon as it is clear nobody will.

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/hubmetrics"
)

// ResultChunkOverhead is what the hub counts against the budget for each
// result chunk it keeps, on top of the chunk's bytes: the slice header that
// holds it in the assembly, that header's share of the list's growth, and the
// allocator's rounding of a small allocation. Without it a device sending
// one-byte chunks would have the hub hold some fifty bytes of memory for each
// byte the budget counted; with it, what is held stays within the allocator's
// rounding — an eighth at most — of what is counted.
const ResultChunkOverhead = 64

// writeBackState is the in-flight assembly for one handle.
type writeBackState struct {
	// chunks is what has arrived so far, in order, one exactly-sized copy per
	// chunk. Kept as separate slices rather than appended into one growing
	// buffer so that the memory held is the memory counted: a buffer grown by
	// append holds up to twice what has arrived while it copies, and the
	// budget would describe neither figure.
	chunks [][]byte
	// size is the chunks' total length. It is the next expected offset, so no
	// separate cursor can disagree with it.
	size int64
	// held is what this assembly has reserved from the executor's budget:
	// size, plus ResultChunkOverhead for every chunk.
	held int64
	// result is the closing frame's metadata once it has arrived and been
	// verified. Nil until then.
	result *executor.WriteBackResult
	// failed records why assembly was abandoned. A failed write-back keeps
	// failing: once bytes have been refused, later chunks cannot restore the
	// stream, and silently accepting them would produce a bundle assembled
	// from two different attempts.
	failed string
}

// appendResultChunk accepts one slice of a handle's bundle and returns the
// offset the agent should continue from.
func (e *Executor) appendResultChunk(handleID string, p ResultChunkPayload) (int64, error) {
	hs, err := e.lookup(handleID)
	if err != nil {
		return 0, err
	}
	hs.mu.Lock()
	defer hs.mu.Unlock()

	// The three refusals that come before anything is allocated. Each is a
	// frame no honest agent sends, and each used to be accepted: a finished
	// handle took chunks, a collected bundle was refilled from offset 0, and a
	// handle that asked for no bundle took the hard ceiling's worth.
	if hs.closed {
		refuseFrame(hubmetrics.WriteBackRefusedLate)
		return 0, fmt.Errorf("%w: handle %s already reported its final status, so no more of its "+
			"bundle is accepted", ErrProtocol, handleID)
	}
	if hs.writeBack != nil && hs.writeBack.result != nil {
		refuseFrame(hubmetrics.WriteBackRefusedLate)
		return hs.writeBack.size, fmt.Errorf("%w: the write-back for handle %s already closed with "+
			"its result frame", ErrProtocol, handleID)
	}
	if hs.returns.bundleCap <= 0 {
		refuseFrame(hubmetrics.WriteBackRefusedNotRequested)
		return 0, fmt.Errorf("%w: handle %s was dispatched with no bundle write-back, so it has no "+
			"bundle to send", ErrProtocol, handleID)
	}

	if hs.writeBack == nil {
		hs.writeBack = &writeBackState{}
	}
	wb := hs.writeBack
	if wb.failed != "" {
		return wb.size, fmt.Errorf("%w: this write-back already failed: %s", ErrProtocol, wb.failed)
	}
	fail := func(sentinel error, reason string) (int64, error) {
		wb.failed = reason
		e.dropBundleLocked(wb)
		return 0, fmt.Errorf("%w: %s", sentinel, reason)
	}

	switch {
	case p.Offset == 0 && wb.size > 0:
		// A restart. The device reconnected and began the transfer again,
		// which is the only correct way to recover a partial one — the
		// alternative, resuming into a buffer whose provenance is a session
		// that no longer exists, would splice two attempts together. The
		// first attempt's bytes are given back before the second is counted.
		e.dropBundleLocked(wb)
	case p.Offset < wb.size:
		// An overlap. Unlike a log chunk this is not trimmed and accepted: a
		// re-sent slice that differs from what was stored would rewrite bytes
		// already counted toward the digest, and there is no way to tell the
		// benign case from the hostile one.
		return fail(ErrProtocol, fmt.Sprintf("chunk at offset %d overlaps %d bytes already received",
			p.Offset, wb.size-p.Offset))
	case p.Offset > wb.size:
		return fail(ErrProtocol, fmt.Sprintf("chunk at offset %d leaves a %d-byte hole",
			p.Offset, p.Offset-wb.size))
	}

	if p.End() > hs.returns.bundleCap {
		refuseFrame(hubmetrics.WriteBackRefusedOverCap)
		return fail(ErrProtocol, fmt.Sprintf("the bundle exceeded the %d-byte cap this workload's "+
			"write-back allows", hs.returns.bundleCap))
	}
	n := int64(len(p.Data))
	cost := n + ResultChunkOverhead
	if refused := e.budget.reserve(e.id, cost); refused != nil {
		refuseFrame(refused.metricReason())
		return fail(ErrWriteBackBudget, refused.reason("this bundle", e.id))
	}
	// Kept as a copy the size of what arrived, never as the decoded slice. That
	// slice's backing array is sized from the frame's base64 text, and the
	// decoder reads past newlines in it: a device can pad a one-byte chunk's
	// frame to the frame limit and leave three quarters of a megabyte behind a
	// one-byte slice — held, and counted as one byte.
	wb.chunks = append(wb.chunks, append([]byte(nil), p.Data...))
	wb.size += n
	wb.held += cost
	return wb.size, nil
}

// fingerprint is the hex SHA-256 of an assembly's bytes, the form the device
// reports (gitwriteback.SHA256). Computed over the chunks in order, so no
// contiguous copy is made just to hash it.
func (wb *writeBackState) fingerprint() string {
	h := sha256.New()
	for _, c := range wb.chunks {
		h.Write(c)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// applyResult records the closing frame, verifying it against what arrived.
//
// It returns the error the agent is told about, and stores it on the handle so
// the consumer sees the same reason the device did. A write-back that fails
// here is a delivery failure, never a workload failure: the harness ran, and
// the status frame that follows still reports whatever the harness did.
func (e *Executor) applyResult(handleID string, p ResultPayload) error {
	hs, err := e.lookup(handleID)
	if err != nil {
		return err
	}
	hs.mu.Lock()
	defer hs.mu.Unlock()

	// Refused before anything is allocated, like a late chunk. A second
	// result would replace a verified one after the consumer may already
	// have read it; one after the final status lands on a handle whose run
	// has been settled without it.
	if hs.closed {
		refuseFrame(hubmetrics.WriteBackRefusedLate)
		return fmt.Errorf("%w: handle %s already reported its final status, so its write-back can "+
			"no longer close", ErrProtocol, handleID)
	}
	if hs.writeBack != nil && hs.writeBack.result != nil {
		refuseFrame(hubmetrics.WriteBackRefusedLate)
		return fmt.Errorf("%w: the write-back for handle %s already closed with its result frame",
			ErrProtocol, handleID)
	}
	if !hs.returns.acceptsResult() {
		refuseFrame(hubmetrics.WriteBackRefusedNotRequested)
		return fmt.Errorf("%w: handle %s was dispatched with no write-back, so it has no result to "+
			"report", ErrProtocol, handleID)
	}

	if hs.writeBack == nil {
		hs.writeBack = &writeBackState{}
	}
	wb := hs.writeBack
	res := p.Result
	// The prose is the device's, and kept for as long as the handle is.
	res.Err = clipText(res.Err, maxReturnedTextBytes)
	res.SkipReason = clipText(res.SkipReason, maxReturnedTextBytes)

	// Record the metadata whatever the verdict below is. A rejected write-back
	// still has to say which branch it was and why it did not land, or the
	// operator is left with a task that reports nothing at all.
	store := func(reason string) error {
		verified := res
		if reason != "" {
			verified.Err = reason
			wb.failed = reason
			e.dropBundleLocked(wb)
		}
		wb.result = &verified
		if reason != "" {
			return fmt.Errorf("%w: %s", executor.ErrWriteBackUnavailable, reason)
		}
		return nil
	}

	if wb.failed != "" {
		return store(wb.failed)
	}
	if res.Err != "" || res.Skipped || res.Mode != executor.WriteBackBundle {
		// Nothing was supposed to arrive: the device reported a failure, a
		// clean tree, or a push whose objects went straight to the origin.
		// Bytes turning up anyway is a protocol violation, not a bonus.
		if wb.size > 0 {
			return store(fmt.Sprintf("the device sent %d bundle bytes for a %q write-back "+
				"that reported none", wb.size, res.Mode))
		}
		return store("")
	}

	if wb.size != res.BundleBytes {
		return store(fmt.Sprintf("the device reported a %d-byte bundle and %d bytes arrived",
			res.BundleBytes, wb.size))
	}
	if want := strings.TrimSpace(res.BundleSHA256); want != "" {
		if got := wb.fingerprint(); got != want {
			return store("the assembled bundle's digest does not match the one the device reported")
		}
	} else {
		// A digest is not optional. Without one the length check is the only
		// integrity evidence, and a length is trivially preserved by a
		// substitution.
		return store("the device reported a bundle with no digest to verify it against")
	}
	return store("")
}

// writeBackResult returns the verified metadata for a handle, or nil.
func (e *Executor) writeBackResult(handleID string) *executor.WriteBackResult {
	hs, err := e.lookup(handleID)
	if err != nil {
		return nil
	}
	hs.mu.Lock()
	defer hs.mu.Unlock()
	if hs.writeBack == nil {
		return nil
	}
	return hs.writeBack.result
}

// WriteBackBundle implements executor.WriteBackFetcher.
//
// The bytes are released to the caller and dropped here in the same breath.
// Holding them after the consumer has taken them would keep a bundle alive for
// as long as the handle is retained, which for a finished workload is long
// enough to matter across a fleet.
func (e *Executor) WriteBackBundle(handleID string) ([]byte, error) {
	hs, err := e.lookup(handleID)
	if err != nil {
		return nil, err
	}
	hs.mu.Lock()
	wb := hs.writeBack
	switch {
	case wb == nil || wb.result == nil:
		hs.mu.Unlock()
		return nil, fmt.Errorf("%w: no write-back was received for handle %s",
			executor.ErrWriteBackUnavailable, handleID)
	case wb.failed != "":
		reason := wb.failed
		hs.mu.Unlock()
		return nil, fmt.Errorf("%w: %s", executor.ErrWriteBackUnavailable, reason)
	case wb.size == 0:
		hs.mu.Unlock()
		return nil, fmt.Errorf("%w: the write-back for handle %s carried no bundle",
			executor.ErrWriteBackUnavailable, handleID)
	}
	// Taken under the lock, so nothing else can count or drop them twice;
	// joined outside it, so the copy does not hold the handle up.
	chunks, size, held := wb.chunks, wb.size, wb.held
	wb.chunks, wb.size, wb.held = nil, 0, 0
	hs.mu.Unlock()

	bundle := make([]byte, 0, size)
	for _, c := range chunks {
		bundle = append(bundle, c...)
	}
	// Given back once the copy exists, so the budget never claims less than
	// this process is actually holding.
	e.budget.release(e.id, held)
	return bundle, nil
}

var _ executor.WriteBackFetcher = (*Executor)(nil)

// SupportsWriteBack reports whether the currently attached agent can return a
// finished task's work product.
//
// Both halves have to hold: the session's negotiated version has to carry the
// result frames, and the device has to have advertised that it can produce a
// bundle. A device with git but an old build, and a new build on a device
// without git, fail in the same silent way — the work stays on the device — so
// neither is allowed to look like support.
func (e *Executor) SupportsWriteBack() bool {
	sess := e.currentSession()
	if sess == nil {
		return false
	}
	return SupportsWriteBack(sess.Version()) && e.AgentCapabilities().WriteBack
}
