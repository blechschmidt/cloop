package agent

// logbuf.go bounds what a device holds in memory on behalf of the control
// plane.
//
// The problem it solves: an agent's link can be down for minutes while a
// harness keeps printing. Retaining that output so it can be resumed is the
// whole point of resumable streaming — but retaining it *without a bound* on a
// device with 512 MiB of RAM turns a network blip into an OOM kill, taking
// down the workload the retention was meant to protect.
//
// So retention is capped. When the cap is exceeded the oldest bytes are
// dropped, which is the right trade: the tail of a log is where the error
// message is, and the control plane detects the loss as a gap in byte offsets
// rather than being silently handed a truncated log that looks complete.

import "sync"

// DefaultRetainBytes is how much unacknowledged output one workload may hold.
// 1 MiB comfortably covers a multi-second reconnect for a chatty harness while
// staying negligible against even a small device's memory.
const DefaultRetainBytes = 1 << 20

// retainBuffer is a bounded window over one workload's output stream, indexed
// by absolute byte offset.
//
// Absolute offsets, not indices, are the public currency: the control plane
// acknowledges "I have everything below offset N", and after a reconnect the
// agent may re-chunk the same bytes differently, so nothing except a byte
// position identifies a resume point unambiguously.
type retainBuffer struct {
	mu sync.Mutex
	// base is the absolute offset of buf[0].
	base int64
	// buf holds bytes in [base, base+len(buf)).
	buf []byte
	// total is the absolute offset just past the last byte ever appended,
	// i.e. the total output produced. It keeps advancing after eviction,
	// which is what lets the control plane see a gap.
	total int64
	cap   int
	// evicted records that data was dropped to stay within cap, so the agent
	// can report a partial stream honestly.
	evicted bool
}

func newRetainBuffer(capBytes int) *retainBuffer {
	if capBytes <= 0 {
		capBytes = DefaultRetainBytes
	}
	return &retainBuffer{cap: capBytes}
}

// Append adds output to the buffer, evicting the oldest bytes if it would
// exceed the cap.
func (r *retainBuffer) Append(text string) {
	if text == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	r.buf = append(r.buf, text...)
	r.total += int64(len(text))
	if over := len(r.buf) - r.cap; over > 0 {
		// Drop from the front. Re-slicing alone would keep the evicted bytes
		// alive behind the slice header, so copy down to let them be
		// collected — on a memory-constrained device that distinction is the
		// difference between a bounded buffer and a leak.
		remaining := len(r.buf) - over
		copy(r.buf, r.buf[over:])
		r.buf = r.buf[:remaining]
		r.base += int64(over)
		r.evicted = true
	}
}

// Ack discards everything below offset, which the control plane has confirmed
// it holds.
func (r *retainBuffer) Ack(offset int64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if offset <= r.base {
		return
	}
	drop := offset - r.base
	if drop > int64(len(r.buf)) {
		drop = int64(len(r.buf))
	}
	remaining := len(r.buf) - int(drop)
	copy(r.buf, r.buf[drop:])
	r.buf = r.buf[:remaining]
	r.base += drop
}

// Slice returns the retained bytes starting at or after from, together with
// the offset the returned data actually begins at.
//
// The returned offset may be greater than from when the requested bytes were
// already evicted. Callers must send the returned offset rather than the one
// they asked for; sending the requested offset would silently mislabel the
// data and corrupt the control plane's view of the stream.
func (r *retainBuffer) Slice(from int64) (data []byte, at int64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if from < r.base {
		from = r.base
	}
	if from >= r.total {
		return nil, r.total
	}
	idx := int(from - r.base)
	if idx < 0 || idx > len(r.buf) {
		return nil, from
	}
	// Copy: the caller sends this without holding the lock, and a concurrent
	// Append that grows buf could otherwise reallocate underneath it.
	out := make([]byte, len(r.buf)-idx)
	copy(out, r.buf[idx:])
	return out, from
}

// Total returns the total number of bytes ever appended.
func (r *retainBuffer) Total() int64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.total
}

// Evicted reports whether any output was dropped to respect the cap.
func (r *retainBuffer) Evicted() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.evicted
}

// Len returns the number of bytes currently retained.
func (r *retainBuffer) Len() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.buf)
}
