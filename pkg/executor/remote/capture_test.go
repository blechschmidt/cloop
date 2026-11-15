package remote_test

// What an agent can make the hub hold through a capture's answer (Task
// 20495), played by a hand-written agent: the same rules write-back's
// assembly follows (writeback_pinning_test.go), for frames no honest agent
// sends.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor/remote"
)

// captureCall is a CaptureProject in flight.
type captureCall struct {
	done chan struct{}
	got  *remote.Captured
	err  error
}

func startCapture(t *testing.T, ex *remote.Executor, req remote.CaptureRequest) *captureCall {
	t.Helper()
	c := &captureCall{done: make(chan struct{})}
	go func() {
		defer close(c.done)
		c.got, c.err = ex.CaptureProject(context.Background(), req)
	}()
	return c
}

func (c *captureCall) wait(t *testing.T) {
	t.Helper()
	select {
	case <-c.done:
	case <-time.After(5 * time.Second):
		t.Fatal("CaptureProject did not return")
	}
}

// readRequest reads the capture request the hub sent.
func readRequest(t *testing.T, p *peer) (remote.Frame, remote.CaptureRequestPayload) {
	t.Helper()
	f := p.readUntil(remote.TypeCaptureReq)
	req, err := remote.DecodeCaptureRequest(f)
	if err != nil {
		t.Fatalf("decode the capture request: %v", err)
	}
	return f, req
}

func (p *peer) sendCaptureChunk(id, part string, offset int64, data []byte) {
	p.t.Helper()
	f, err := remote.NewFrame(remote.TypeCaptureChunk, "", id, remote.CaptureChunkPayload{Part: part, Offset: offset, Data: data})
	if err != nil {
		p.t.Fatal(err)
	}
	p.write(f)
}

func (p *peer) sendCaptureResult(reqID, id string, res remote.CaptureResultPayload) {
	p.t.Helper()
	res.CaptureID = id
	f, err := remote.NewFrame(remote.TypeCaptureResult, reqID, id, res)
	if err != nil {
		p.t.Fatal(err)
	}
	p.write(f)
}

func digestOf(part string, data []byte) remote.CapturePartDigest {
	sum := sha256.Sum256(data)
	return remote.CapturePartDigest{Part: part, Bytes: int64(len(data)), SHA256: hex.EncodeToString(sum[:])}
}

func captureReq() remote.CaptureRequest {
	return remote.CaptureRequest{Mode: remote.CaptureFull, MoveID: "0123456789abcdef", WorkDir: "proj-0a1b2c3d",
		Limits: remote.CaptureLimits{Document: 1024, Bundle: 2048, Files: 512}}
}

func TestCaptureAnswerIsAssembledVerifiedAndReleased(t *testing.T) {
	budget := remote.NewResultBudget(8192, 16384)
	ex := pinnedExecutor(t, "agent-1", budget, nil, nil)
	p, _ := connect(t, ex, remoteAgent("agent-1"), helloFor("agent-1"), nil)
	call := startCapture(t, ex, captureReq())
	f, req := readRequest(t, p)
	if req.WorkDir != "proj-0a1b2c3d" || req.MoveID != "0123456789abcdef" || req.Limits.Bundle != 2048 {
		t.Fatalf("the request = %+v", req)
	}
	doc := []byte(`{"version":1}`)
	bundle := bytes.Repeat([]byte("b"), 1500)
	p.sendCaptureChunk(req.CaptureID, remote.CapturePartDocument, 0, doc)
	p.sendCaptureChunk(req.CaptureID, remote.CapturePartBundle, 0, bundle[:1000])
	p.sendCaptureChunk(req.CaptureID, remote.CapturePartBundle, 1000, bundle[1000:])
	p.sendCaptureResult(f.ID, req.CaptureID, remote.CaptureResultPayload{Parts: []remote.CapturePartDigest{
		digestOf(remote.CapturePartDocument, doc), digestOf(remote.CapturePartBundle, bundle)}})
	call.wait(t)
	if call.err != nil {
		t.Fatalf("CaptureProject: %v", call.err)
	}
	if ex.PinnedCaptureBytes() == 0 || budget.Usage().Pinned == 0 {
		t.Fatal("a verified answer is not counted against the budget while it is held")
	}
	var got bytes.Buffer
	if _, err := call.got.WriteTo(remote.CapturePartBundle, &got); err != nil || !bytes.Equal(got.Bytes(), bundle) {
		t.Fatalf("WriteTo = %d bytes, %v", got.Len(), err)
	}
	if call.got.Has(remote.CapturePartFiles) {
		t.Error("a part that never came is reported held")
	}
	// A chunk after the answer closed is refused, and nothing more is held.
	held := ex.PinnedCaptureBytes()
	p.sendCaptureChunk(req.CaptureID, remote.CapturePartFiles, 0, []byte("late"))
	wantRefusals(t, barrier(t, p), 1, "already closed")
	if ex.PinnedCaptureBytes() != held {
		t.Errorf("a late chunk changed what is held: %d → %d", held, ex.PinnedCaptureBytes())
	}
	call.got.Release()
	if ex.PinnedCaptureBytes() != 0 || budget.Usage().Pinned != 0 {
		t.Errorf("after Release: executor %d, budget %d; want both 0", ex.PinnedCaptureBytes(), budget.Usage().Pinned)
	}
	if _, err := call.got.WriteTo(remote.CapturePartBundle, &got); err == nil {
		t.Error("a released answer still writes")
	}
}

// captureBarrier is barrier, also reporting whether a capture_cancel arrived
// before the heartbeat's ack: the hub sends it from a goroutine of its own.
func captureBarrier(t *testing.T, p *peer) ([]remote.ErrorPayload, bool) {
	t.Helper()
	f, err := remote.NewFrame(remote.TypeHeartbeat, "hb-barrier", "", remote.HeartbeatPayload{Seq: 1})
	if err != nil {
		t.Fatal(err)
	}
	p.write(f)
	var (
		refused   []remote.ErrorPayload
		cancelled bool
	)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		fr, err := p.read()
		if err != nil {
			t.Fatalf("waiting for the heartbeat ack: %v", err)
		}
		switch fr.Type {
		case remote.TypeHeartbeatAck:
			return refused, cancelled
		case remote.TypeCaptureCancel:
			cancelled = true
		case remote.TypeError:
			e, err := remote.DecodeError(fr)
			if err != nil {
				t.Fatal(err)
			}
			refused = append(refused, e)
		}
	}
	t.Fatal("the hub never acknowledged the barrier heartbeat")
	return nil, false
}

// remoteAgent is the record connect accepts for agentID.
func remoteAgent(agentID string) remote.AgentRecord {
	return remote.AgentRecord{AgentID: agentID, Name: agentID}
}

func TestCaptureRefusesBeforeKeeping(t *testing.T) {
	cases := []struct {
		name string
		// play sends the offending frames for the capture asked as req.
		play func(p *peer, f remote.Frame, req remote.CaptureRequestPayload)
		want string
		// refusals is how many error frames the hub answers with.
		refusals int
	}{
		{"a chunk for a capture never asked", func(p *peer, f remote.Frame, req remote.CaptureRequestPayload) {
			p.sendCaptureChunk("cap-not-asked", remote.CapturePartBundle, 0, []byte("x"))
		}, "no capture", 1},
		{"a part the request did not ask for", func(p *peer, f remote.Frame, req remote.CaptureRequestPayload) {
			p.sendCaptureChunk(req.CaptureID, remote.CapturePartFiles, 0, []byte("x"))
		}, "asked for no files", 1},
		{"a chunk past its part's cap", func(p *peer, f remote.Frame, req remote.CaptureRequestPayload) {
			p.sendCaptureChunk(req.CaptureID, remote.CapturePartBundle, 0, bytes.Repeat([]byte("x"), 300))
		}, "cap the request set", 1},
		{"past the executor's budget", func(p *peer, f remote.Frame, req remote.CaptureRequestPayload) {
			p.sendCaptureChunk(req.CaptureID, remote.CapturePartDocument, 0, bytes.Repeat([]byte("d"), 150))
			p.sendCaptureChunk(req.CaptureID, remote.CapturePartDocument, 150, bytes.Repeat([]byte("d"), 150))
		}, "budget", 1},
		{"a hole", func(p *peer, f remote.Frame, req remote.CaptureRequestPayload) {
			p.sendCaptureChunk(req.CaptureID, remote.CapturePartDocument, 10, []byte("x"))
		}, "offset 10", 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// A budget the fourth case crosses on its second chunk.
			budget := remote.NewResultBudget(300, 4096)
			ex := pinnedExecutor(t, "agent-1", budget, nil, nil)
			p, _ := connect(t, ex, remoteAgent("agent-1"), helloFor("agent-1"), nil)
			req := captureReq()
			req.Limits = remote.CaptureLimits{Document: 400, Bundle: 200}
			call := startCapture(t, ex, req)
			f, sent := readRequest(t, p)
			tc.play(p, f, sent)
			refused, cancelled := captureBarrier(t, p)
			wantRefusals(t, refused, tc.refusals, tc.want)
			if tc.name != "a chunk for a capture never asked" {
				// The capture fails at once, the device is told to stop, and
				// nothing stays held.
				call.wait(t)
				if call.err == nil {
					t.Fatal("CaptureProject succeeded")
				}
				if !cancelled {
					p.readUntil(remote.TypeCaptureCancel)
				}
			} else {
				p.sendCaptureResult(f.ID, sent.CaptureID, remote.CaptureResultPayload{Code: remote.CaptureCodeRefused, Error: "no"})
				call.wait(t)
			}
			if ex.PinnedCaptureBytes() != 0 || budget.Usage().Pinned != 0 {
				t.Errorf("held after the refusal: executor %d, budget %d", ex.PinnedCaptureBytes(), budget.Usage().Pinned)
			}
		})
	}
}

func TestCaptureDigestMismatchIsRefused(t *testing.T) {
	budget := remote.NewResultBudget(8192, 16384)
	ex := pinnedExecutor(t, "agent-1", budget, nil, nil)
	p, _ := connect(t, ex, remoteAgent("agent-1"), helloFor("agent-1"), nil)
	call := startCapture(t, ex, captureReq())
	f, req := readRequest(t, p)
	doc := []byte(`{"version":1}`)
	p.sendCaptureChunk(req.CaptureID, remote.CapturePartDocument, 0, doc)
	other := digestOf(remote.CapturePartDocument, []byte(`{"version":2}`))
	other.Bytes = int64(len(doc))
	p.sendCaptureResult(f.ID, req.CaptureID, remote.CaptureResultPayload{Parts: []remote.CapturePartDigest{other}})
	call.wait(t)
	if call.err == nil || !strings.Contains(call.err.Error(), "digest") {
		t.Fatalf("err = %v, want a digest mismatch", call.err)
	}
	if budget.Usage().Pinned != 0 {
		t.Errorf("a refused answer is still held: %d", budget.Usage().Pinned)
	}
}

func TestCaptureRefusalFromTheDeviceIsReported(t *testing.T) {
	ex := pinnedExecutor(t, "agent-1", remote.NewResultBudget(8192, 16384), nil, nil)
	p, _ := connect(t, ex, remoteAgent("agent-1"), helloFor("agent-1"), nil)
	for code, want := range map[string]error{remote.CaptureCodeBusy: remote.ErrCaptureBusy, remote.CaptureCodeRefused: remote.ErrCaptureRefused} {
		call := startCapture(t, ex, captureReq())
		f, req := readRequest(t, p)
		p.sendCaptureResult(f.ID, req.CaptureID, remote.CaptureResultPayload{Code: code, Error: "the device says no"})
		call.wait(t)
		if !errors.Is(call.err, want) || !strings.Contains(call.err.Error(), "the device says no") {
			t.Errorf("%s: err = %v, want %v", code, call.err, want)
		}
	}
}

// TestCaptureEndsWithItsSession: a capture is never resumed on another
// session; what arrived is let go of when the one it was asked on ends.
func TestCaptureEndsWithItsSession(t *testing.T) {
	budget := remote.NewResultBudget(8192, 16384)
	ex := pinnedExecutor(t, "agent-1", budget, nil, nil)
	p, sess := connect(t, ex, remoteAgent("agent-1"), helloFor("agent-1"), nil)
	call := startCapture(t, ex, captureReq())
	_, req := readRequest(t, p)
	p.sendCaptureChunk(req.CaptureID, remote.CapturePartBundle, 0, bytes.Repeat([]byte("b"), 500))
	barrier(t, p)
	if budget.Usage().Pinned == 0 {
		t.Fatal("the chunk was not counted")
	}
	sess.Close()
	call.wait(t)
	if call.err == nil {
		t.Fatal("CaptureProject succeeded after its session ended")
	}
	deadline := time.Now().Add(3 * time.Second)
	for budget.Usage().Pinned != 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := budget.Usage().Pinned; got != 0 {
		t.Errorf("held after the session ended: %d", got)
	}
}

// TestCaptureNeedsProtocol29: an agent below v29 is never asked, and the
// refusal names the upgrade.
func TestCaptureNeedsProtocol29(t *testing.T) {
	ex := pinnedExecutor(t, "agent-1", remote.NewResultBudget(8192, 16384), nil, nil)
	hello := helloFor("agent-1")
	hello.ProtocolVersion = remote.MinProjectCaptureVersion - 1
	connect(t, ex, remoteAgent("agent-1"), hello, nil)
	_, err := ex.CaptureProject(context.Background(), captureReq())
	if !errors.Is(err, remote.ErrCaptureUnsupported) {
		t.Fatalf("err = %v, want ErrCaptureUnsupported", err)
	}
	if !strings.Contains(err.Error(), "v29") || !strings.Contains(strings.ToLower(err.Error()), "upgrade") {
		t.Errorf("the refusal does not name the upgrade: %v", err)
	}
}

// TestAVerifiedAnswerWakesItsCaller: a result that verifies the answer wakes
// the caller even when its frame names another correlation ID.
func TestAVerifiedAnswerWakesItsCaller(t *testing.T) {
	ex := pinnedExecutor(t, "agent-1", remote.NewResultBudget(8192, 16384), nil, nil)
	p, _ := connect(t, ex, remoteAgent("agent-1"), helloFor("agent-1"), nil)
	call := startCapture(t, ex, captureReq())
	_, req := readRequest(t, p)
	doc := []byte(`{"version":1}`)
	p.sendCaptureChunk(req.CaptureID, remote.CapturePartDocument, 0, doc)
	p.sendCaptureResult("not-the-request", req.CaptureID, remote.CaptureResultPayload{Parts: []remote.CapturePartDigest{
		digestOf(remote.CapturePartDocument, doc)}})
	call.wait(t)
	if call.err != nil {
		t.Fatalf("CaptureProject: %v", call.err)
	}
	call.got.Release()
}
