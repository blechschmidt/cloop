package agent

// Bounded log retention tests.
//
// The invariant these protect: an agent whose link is down keeps producing
// output but must never grow its buffer without limit. A device with 512 MiB
// of RAM turning a network blip into an OOM kill would destroy the very
// workload the retention exists to protect.

import (
	"strings"
	"testing"
)

func TestRetainBufferAppendAndSlice(t *testing.T) {
	b := newRetainBuffer(1024)
	b.Append("hello ")
	b.Append("world")

	if got := b.Total(); got != 11 {
		t.Fatalf("Total = %d, want 11", got)
	}
	data, at := b.Slice(0)
	if at != 0 || string(data) != "hello world" {
		t.Fatalf("Slice(0) = (%q, %d), want (%q, 0)", data, at, "hello world")
	}
	data, at = b.Slice(6)
	if at != 6 || string(data) != "world" {
		t.Fatalf("Slice(6) = (%q, %d), want (%q, 6)", data, at, "world")
	}
	// Asking past the end yields nothing, positioned at the end.
	data, at = b.Slice(11)
	if len(data) != 0 || at != 11 {
		t.Fatalf("Slice(11) = (%q, %d), want (empty, 11)", data, at)
	}
}

func TestRetainBufferAckReleasesMemory(t *testing.T) {
	b := newRetainBuffer(1024)
	b.Append(strings.Repeat("a", 500))
	b.Append(strings.Repeat("b", 500))

	if got := b.Len(); got != 1000 {
		t.Fatalf("Len = %d, want 1000", got)
	}
	b.Ack(500)
	if got := b.Len(); got != 500 {
		t.Fatalf("after Ack(500), Len = %d, want 500", got)
	}
	// The acked bytes are gone; a slice from below the ack point starts at
	// the new base rather than silently mislabelling data.
	data, at := b.Slice(0)
	if at != 500 {
		t.Fatalf("Slice(0) after ack should start at 500, got %d", at)
	}
	if string(data) != strings.Repeat("b", 500) {
		t.Fatalf("unexpected retained data %q", data)
	}
	if b.Total() != 1000 {
		t.Fatalf("Total must keep counting produced bytes, got %d", b.Total())
	}
}

// TestRetainBufferEvictsOldestWhenFull is the memory-bound assertion. It also
// pins the *direction* of eviction: the tail must survive, because that is
// where a failing workload's error message is.
func TestRetainBufferEvictsOldestWhenFull(t *testing.T) {
	b := newRetainBuffer(100)
	b.Append(strings.Repeat("x", 80))
	b.Append(strings.Repeat("y", 60)) // total 140, cap 100 → 40 evicted

	if got := b.Len(); got > 100 {
		t.Fatalf("buffer grew past its cap: Len = %d", got)
	}
	if !b.Evicted() {
		t.Error("eviction must be recorded so the loss can be reported honestly")
	}
	if b.Total() != 140 {
		t.Fatalf("Total = %d, want 140 (eviction must not rewrite history)", b.Total())
	}

	data, at := b.Slice(0)
	// Bytes 0..39 are gone, so the slice must start at 40 and the caller must
	// send that offset — labelling it 0 would corrupt the control plane's
	// offset accounting.
	if at != 40 {
		t.Fatalf("Slice(0) should report its true start of 40, got %d", at)
	}
	want := strings.Repeat("x", 40) + strings.Repeat("y", 60)
	if string(data) != want {
		t.Fatalf("retained window mismatch:\n got %q\nwant %q", data, want)
	}
}

// TestRetainBufferStaysBoundedUnderSustainedWrites is the property that
// matters in production: an offline agent with a chatty workload must plateau,
// not grow.
func TestRetainBufferStaysBoundedUnderSustainedWrites(t *testing.T) {
	const cap = 4096
	b := newRetainBuffer(cap)
	chunk := strings.Repeat("z", 512)
	for i := 0; i < 1000; i++ {
		b.Append(chunk)
		if got := b.Len(); got > cap {
			t.Fatalf("iteration %d: buffer exceeded cap (%d > %d)", i, got, cap)
		}
	}
	if b.Total() != int64(512*1000) {
		t.Fatalf("Total = %d, want %d", b.Total(), 512*1000)
	}
}

func TestRetainBufferAckBeyondTotalIsSafe(t *testing.T) {
	b := newRetainBuffer(256)
	b.Append("short")
	// A control plane that somehow acks past what was produced must not panic
	// or corrupt the buffer.
	b.Ack(9999)
	if got := b.Len(); got != 0 {
		t.Fatalf("Len = %d, want 0", got)
	}
	data, at := b.Slice(0)
	if len(data) != 0 {
		t.Fatalf("expected empty slice, got %q at %d", data, at)
	}
}
