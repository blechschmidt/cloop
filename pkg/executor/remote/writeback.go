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
//   - the running total is checked against the ceiling on every chunk, not at
//     the end. A cap enforced after assembly is a cap on the error message.
//   - the reported length and SHA-256 are both verified before the bytes are
//     handed to anything. A truncated transfer and a tampered one produce the
//     same symptom otherwise: a bundle git declines to open.
//
// The bytes live in memory, bounded by executor.MaxWriteBackBundleBytes per
// handle, and are dropped as soon as the consumer has collected them.

import (
	"fmt"
	"strings"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/gitwriteback"
)

// writeBackState is the in-flight assembly for one handle.
type writeBackState struct {
	// bundle is what has arrived so far. Its length is the next expected
	// offset, so no separate cursor can disagree with it.
	bundle []byte
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

	if hs.writeBack == nil {
		hs.writeBack = &writeBackState{}
	}
	wb := hs.writeBack
	if wb.failed != "" {
		return int64(len(wb.bundle)), fmt.Errorf("%w: this write-back already failed: %s",
			ErrProtocol, wb.failed)
	}

	switch {
	case p.Offset == 0 && len(wb.bundle) > 0:
		// A restart. The device reconnected and began the transfer again,
		// which is the only correct way to recover a partial one — the
		// alternative, resuming into a buffer whose provenance is a session
		// that no longer exists, would splice two attempts together.
		wb.bundle = wb.bundle[:0]
	case p.Offset < int64(len(wb.bundle)):
		// An overlap. Unlike a log chunk this is not trimmed and accepted: a
		// re-sent slice that differs from what was stored would rewrite bytes
		// already counted toward the digest, and there is no way to tell the
		// benign case from the hostile one.
		wb.failed = fmt.Sprintf("chunk at offset %d overlaps %d bytes already received",
			p.Offset, int64(len(wb.bundle))-p.Offset)
		return int64(len(wb.bundle)), fmt.Errorf("%w: %s", ErrProtocol, wb.failed)
	case p.Offset > int64(len(wb.bundle)):
		wb.failed = fmt.Sprintf("chunk at offset %d leaves a %d-byte hole",
			p.Offset, p.Offset-int64(len(wb.bundle)))
		return int64(len(wb.bundle)), fmt.Errorf("%w: %s", ErrProtocol, wb.failed)
	}

	if int64(len(wb.bundle))+int64(len(p.Data)) > executor.MaxWriteBackBundleBytes {
		wb.failed = fmt.Sprintf("the bundle exceeded the %d-byte ceiling",
			executor.MaxWriteBackBundleBytes)
		wb.bundle = nil
		return 0, fmt.Errorf("%w: %s", ErrProtocol, wb.failed)
	}
	wb.bundle = append(wb.bundle, p.Data...)
	return int64(len(wb.bundle)), nil
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

	if hs.writeBack == nil {
		hs.writeBack = &writeBackState{}
	}
	wb := hs.writeBack
	res := p.Result

	// Record the metadata whatever the verdict below is. A rejected write-back
	// still has to say which branch it was and why it did not land, or the
	// operator is left with a task that reports nothing at all.
	store := func(reason string) error {
		verified := res
		if reason != "" {
			verified.Err = reason
			wb.failed = reason
			wb.bundle = nil
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
		if len(wb.bundle) > 0 {
			return store(fmt.Sprintf("the device sent %d bundle bytes for a %q write-back "+
				"that reported none", len(wb.bundle), res.Mode))
		}
		return store("")
	}

	if int64(len(wb.bundle)) != res.BundleBytes {
		return store(fmt.Sprintf("the device reported a %d-byte bundle and %d bytes arrived",
			res.BundleBytes, len(wb.bundle)))
	}
	if want := strings.TrimSpace(res.BundleSHA256); want != "" {
		if got := gitwriteback.SHA256(wb.bundle); got != want {
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
	defer hs.mu.Unlock()

	wb := hs.writeBack
	switch {
	case wb == nil || wb.result == nil:
		return nil, fmt.Errorf("%w: no write-back was received for handle %s",
			executor.ErrWriteBackUnavailable, handleID)
	case wb.failed != "":
		return nil, fmt.Errorf("%w: %s", executor.ErrWriteBackUnavailable, wb.failed)
	case len(wb.bundle) == 0:
		return nil, fmt.Errorf("%w: the write-back for handle %s carried no bundle",
			executor.ErrWriteBackUnavailable, handleID)
	}
	bundle := wb.bundle
	wb.bundle = nil
	return bundle, nil
}

// discardWriteBack drops any in-flight assembly for a handle. Called when the
// handle is forgotten, so an abandoned transfer does not pin its bytes.
func (e *Executor) discardWriteBack(handleID string) {
	hs, err := e.lookup(handleID)
	if err != nil {
		return
	}
	hs.mu.Lock()
	defer hs.mu.Unlock()
	if hs.writeBack != nil {
		hs.writeBack.bundle = nil
	}
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
