package remote

// White-box: what a kept result chunk actually holds in memory, which no
// external observer can see — the budget counts its length either way.

import (
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/internal/logbus"
)

// TestKeptChunkHoldsOnlyWhatArrived (Task 20399): encoding/json decodes a
// []byte from base64 into a buffer sized from the text, and skips the newlines
// a device may pad that text with. A one-byte chunk in a frame padded to the
// frame limit decodes to a one-byte slice over most of a megabyte. Kept as
// decoded, that megabyte would be held for a one-byte charge, chunk after
// chunk; the hub keeps a copy the size of what arrived.
func TestKeptChunkHoldsOnlyWhatArrived(t *testing.T) {
	f, err := NewFrame(TypeResultChunk, "", "h1", struct {
		Offset int64  `json:"offset"`
		Data   string `json:"data"`
	}{0, "QQ==" + strings.Repeat("\n", MaxFrameBytes/2)})
	if err != nil {
		t.Fatal(err)
	}
	p, err := DecodeResultChunk(f)
	if err != nil {
		t.Fatalf("DecodeResultChunk: %v", err)
	}
	if len(p.Data) != 1 || cap(p.Data) < 1<<16 {
		t.Fatalf("the padded frame decoded to len %d cap %d; the test no longer builds the "+
			"oversized buffer it is about", len(p.Data), cap(p.Data))
	}

	ex, err := NewExecutor(Options{ID: "agent-1", ResultBudget: NewResultBudget(1<<20, 1<<20)})
	if err != nil {
		t.Fatal(err)
	}
	hs := &handleState{
		id:      "h1",
		bus:     logbus.New("h1", executor.StreamCombined, logbus.Options{}),
		returns: resultAllowance{known: true, mode: executor.WriteBackBundle, bundleCap: 1 << 20},
	}
	ex.handles["h1"] = hs
	if _, err := ex.appendResultChunk("h1", p); err != nil {
		t.Fatalf("appendResultChunk: %v", err)
	}
	kept := hs.writeBack.chunks[0]
	if len(kept) != 1 || cap(kept) > 64 {
		t.Errorf("the hub keeps a slice of len %d over %d bytes for a one-byte chunk", len(kept), cap(kept))
	}
	if got := ex.PinnedResultBytes(); got != 1+ResultChunkOverhead {
		t.Errorf("the chunk is charged %d, want %d", got, 1+ResultChunkOverhead)
	}
}

// TestAttachInboxHoldsOnlyWhatArrived: the same padding against the one other
// place the hub queues bytes a device sent, a sandbox terminal's inbox, whose
// depth is sized on the assumption that a chunk holds what it carries.
func TestAttachInboxHoldsOnlyWhatArrived(t *testing.T) {
	f, err := NewFrame(TypeAttachData, "", "h1", struct {
		SessionID string `json:"session_id"`
		Data      string `json:"data"`
	}{"s1", "QQ==" + strings.Repeat("\n", MaxFrameBytes/2)})
	if err != nil {
		t.Fatal(err)
	}
	p, err := DecodeAttachData(f)
	if err != nil {
		t.Fatalf("DecodeAttachData: %v", err)
	}
	if len(p.Data) != 1 || cap(p.Data) < 1<<16 {
		t.Fatalf("the padded frame decoded to len %d cap %d", len(p.Data), cap(p.Data))
	}
	a := &attachSession{inbox: make(chan []byte, 1), closed: make(chan struct{})}
	a.deliver(p.Data)
	if got := <-a.inbox; len(got) != 1 || cap(got) > 64 {
		t.Errorf("the terminal's inbox holds a slice of len %d over %d bytes for a one-byte chunk",
			len(got), cap(got))
	}
}
