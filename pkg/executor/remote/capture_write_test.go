package remote_test

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor/remote"
)

// writeRacingConn is the hub's end of a pipe whose capture-request writes
// return only once the device's answer to them has been read and handled,
// as a write still returning can on a busy machine. A write whose context
// ended by then is treated the way coder/websocket treats it: the
// connection is closed.
type writeRacingConn struct {
	remote.Conn
	handled       chan struct{}
	mu            sync.Mutex
	sawResult     bool
	closedByWrite atomic.Bool
}

func (c *writeRacingConn) ReadFrame(ctx context.Context) (remote.Frame, error) {
	c.mu.Lock()
	if c.sawResult {
		// The read loop asks for its next frame only once it has handled
		// the last one.
		c.sawResult = false
		select {
		case c.handled <- struct{}{}:
		default:
		}
	}
	c.mu.Unlock()
	f, err := c.Conn.ReadFrame(ctx)
	if err == nil && f.Type == remote.TypeCaptureResult {
		c.mu.Lock()
		c.sawResult = true
		c.mu.Unlock()
	}
	return f, err
}

func (c *writeRacingConn) WriteFrame(ctx context.Context, f remote.Frame) error {
	if err := c.Conn.WriteFrame(ctx, f); err != nil || f.Type != remote.TypeCaptureReq {
		return err
	}
	select {
	case <-c.handled:
	case <-time.After(5 * time.Second):
	}
	if ctx.Err() != nil {
		c.closedByWrite.Store(true)
		_ = c.Conn.Close("a write's context ended before the write returned")
	}
	return nil
}

// TestARefusedCaptureLeavesTheSessionUp: the read loop wakes a capture's
// caller once the device's answer is handled, without ending the context the
// request was written under. Ending it before the write has returned makes
// coder/websocket close the connection, and a device can refuse a capture
// before the hub's writer has returned: the next capture then found the
// device's session closed (TestLoopbackRunnerCapturesOnlyItsTenant, about
// one run in 250 under -race on two CPUs).
func TestARefusedCaptureLeavesTheSessionUp(t *testing.T) {
	ex := pinnedExecutor(t, "agent-1", remote.NewResultBudget(8192, 16384), nil, nil)
	cpConn, agentConn := remote.NewPipe(64)
	hub := &writeRacingConn{Conn: cpConn, handled: make(chan struct{}, 1)}
	accepted := make(chan error, 1)
	go func() {
		_, err := remote.Accept(context.Background(), hub, remote.AcceptOptions{
			Agent: remoteAgent("agent-1"), Executor: ex, HeartbeatPoll: 5 * time.Millisecond,
		})
		accepted <- err
	}()
	p := &peer{t: t, conn: agentConn}
	hello, err := remote.NewFrame(remote.TypeHello, "hello", "", helloFor("agent-1"))
	if err != nil {
		t.Fatal(err)
	}
	p.write(hello)
	select {
	case err := <-accepted:
		if err != nil {
			t.Fatalf("Accept: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Accept did not complete")
	}
	p.readUntil(remote.TypeWelcome)

	for i := 1; i <= 2; i++ {
		call := startCapture(t, ex, captureReq())
		f, req := readRequest(t, p)
		p.sendCaptureResult(f.ID, req.CaptureID, remote.CaptureResultPayload{Code: remote.CaptureCodeRefused, Error: "not this tenant"})
		call.wait(t)
		if hub.closedByWrite.Load() {
			t.Fatalf("capture %d: the hub ended the context its request was written under before the write returned, which closes a websocket", i)
		}
		if !errors.Is(call.err, remote.ErrCaptureRefused) {
			t.Fatalf("capture %d: err = %v, want the device's refusal", i, call.err)
		}
	}
}
