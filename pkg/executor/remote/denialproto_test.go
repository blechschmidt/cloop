package remote_test

import (
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/denylog"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
)

// denialproto_test.go covers protocol v24's denials frame from the hub's
// side: a device's report of what its sandbox firewall refused reaches the
// hub's sink for the handle it names — and only for a live handle of that
// device, at a bounded rate, and only once it has been validated.

type sinkRecord struct {
	mu   sync.Mutex
	got  map[string][]denylog.Batch
	seen int
}

func (s *sinkRecord) sink(executorID, handleID string, b denylog.Batch) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.got == nil {
		s.got = map[string][]denylog.Batch{}
	}
	s.got[executorID+"/"+handleID] = append(s.got[executorID+"/"+handleID], b)
	s.seen++
}

func (s *sinkRecord) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.seen
}

func denialsFrame(t *testing.T, handle string, b denylog.Batch) remote.Frame {
	t.Helper()
	f, err := remote.NewFrame(remote.TypeDenials, "", handle, remote.DenialsPayload{Batch: b})
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func goodBatch() denylog.Batch {
	now := time.Now()
	return denylog.Batch{Fingerprint: "0123456789ab", Entries: []denylog.Entry{{
		Dst: netip.MustParseAddr("203.0.113.7"), Port: 443, Proto: "tcp", Rule: "default", Count: 3,
		First: now, Last: now,
	}}}
}

func TestDenialsFrameReachesTheSinkForALiveHandle(t *testing.T) {
	rec := &sinkRecord{}
	defer executor.SetDenialSink(rec.sink)()
	ex := pinnedExecutor(t, "agent-1", nil, nil, nil)
	p, _ := connect(t, ex, remote.AgentRecord{AgentID: "agent-1"}, defaultHello(), nil)
	handle := startedHandle(t, ex, p, noWriteBackSpec())

	p.write(denialsFrame(t, handle, goodBatch()))
	if refused := barrier(t, p, handle); len(refused) != 0 {
		t.Fatalf("a good report was refused: %+v", refused)
	}
	rec.mu.Lock()
	got := rec.got["agent-1/"+handle]
	rec.mu.Unlock()
	if len(got) != 1 || got[0].Entries[0].Count != 3 || got[0].Fingerprint != "0123456789ab" {
		t.Fatalf("sink got %+v", rec.got)
	}

	// Malformed: refused with a protocol error, nothing reaches the sink.
	bad := goodBatch()
	bad.Entries[0].Rule = "allow:1.1.1.1/32"
	p.write(denialsFrame(t, handle, bad))
	if refused := barrier(t, p, handle); len(refused) != 1 || refused[0].Code != remote.CodeProtocol {
		t.Errorf("a malformed report: %+v", refused)
	}
	// Another device's handle, or none at all: refused as unknown.
	p.write(denialsFrame(t, "not-a-handle", goodBatch()))
	if refused := barrier(t, p, handle); len(refused) != 1 || refused[0].Code != remote.CodeUnknownHandle {
		t.Errorf("a report for an unknown handle: %+v", refused)
	}
	// A flood is cut to the per-handle rate, silently: the device's next
	// report goes through once the bucket refills.
	before := rec.count()
	for i := 0; i < 50; i++ {
		p.write(denialsFrame(t, handle, goodBatch()))
	}
	barrier(t, p, handle)
	if n := rec.count() - before; n < 1 || n > 6 {
		t.Errorf("a flood of 50 reports delivered %d; the per-handle bucket holds 5", n)
	}

	// After the final status the handle is closed: a late report is refused.
	// Frames are handled in order, so the status is applied first.
	finish(t, p, handle, 0)
	p.write(denialsFrame(t, handle, goodBatch()))
	refused := barrier(t, p)
	if len(refused) != 1 || !strings.Contains(refused[0].Message, "final status") {
		t.Errorf("a report after the final status: %+v", refused)
	}
}

// TestDenialsFrameNeedsAV24Session: an agent sends the frame only on a
// session that negotiated v24, and the hub refuses it on an older one.
func TestDenialsFrameNeedsAV24Session(t *testing.T) {
	rec := &sinkRecord{}
	defer executor.SetDenialSink(rec.sink)()
	ex := pinnedExecutor(t, "agent-1", nil, nil, nil)
	hello := defaultHello()
	hello.ProtocolVersion = remote.MinDenialLogVersion - 1
	p, _ := connect(t, ex, remote.AgentRecord{AgentID: "agent-1"}, hello, nil)
	handle := startedHandle(t, ex, p, noWriteBackSpec())
	f := denialsFrame(t, handle, goodBatch())
	f.V = remote.MinDenialLogVersion - 1
	p.write(f)
	if refused := barrier(t, p, handle); len(refused) != 1 || !strings.Contains(refused[0].Message, "v24") {
		t.Errorf("a denials frame on a v23 session: %+v", refused)
	}
	if rec.count() != 0 {
		t.Error("the sink got a report from a v23 session")
	}
	if ok, note := ex.DenialLogStatus(); ok || !strings.Contains(note, "speaks protocol v23, and the hub needs v24") {
		t.Errorf("DenialLogStatus of a v23 device = %v, %q", ok, note)
	}
}

func TestDenialLogStatusReadsTheHello(t *testing.T) {
	ex := pinnedExecutor(t, "agent-1", nil, nil, nil)
	if ok, note := ex.DenialLogStatus(); ok || !strings.Contains(note, "not connected") {
		t.Errorf("offline: %v %q", ok, note)
	}
	hello := defaultHello()
	hello.Capabilities.DenialLogIssue = "denylog: binding NFLOG group 27437 needs CAP_NET_ADMIN"
	connect(t, ex, remote.AgentRecord{AgentID: "agent-1"}, hello, nil)
	if ok, note := ex.DenialLogStatus(); ok || !strings.Contains(note, "needs CAP_NET_ADMIN") {
		t.Errorf("no packet log: %v %q", ok, note)
	}

	ex2 := pinnedExecutor(t, "agent-2", nil, nil, nil)
	h2 := helloFor("agent-2")
	h2.Capabilities.DenialLog = true
	connect(t, ex2, remote.AgentRecord{AgentID: "agent-2"}, h2, nil)
	if ok, note := ex2.DenialLogStatus(); !ok || note != "" {
		t.Errorf("a device that reads its log: %v %q", ok, note)
	}
}
