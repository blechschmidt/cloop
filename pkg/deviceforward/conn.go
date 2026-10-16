package deviceforward

// conn.go is the transport under the frame protocol.
//
// wsConn is the one implementation of frameConn: one WebSocket binary message
// per frame, which is how a forwarder and the hub actually talk. The
// length-prefixed stream form the frames can also take (readStreamFrame) exists
// so the wire format can be round-tripped in a test without a WebSocket.

import (
	"context"
	"sync"
	"time"

	"github.com/coder/websocket"
)

// frameConn is a bidirectional frame transport. Writes are serialised by the
// implementation; reads are single-consumer.
type frameConn interface {
	ReadFrame(ctx context.Context) (Frame, error)
	WriteFrame(ctx context.Context, f Frame) error
	Close() error
}

// wsConn carries frames as WebSocket binary messages.
type wsConn struct {
	ws      *websocket.Conn
	writeMu sync.Mutex
}

// newWSConn wraps a websocket connection. The read limit is set generously
// above MaxFramePayload so a legitimate maximum-size Data frame is not cut off
// by the library's own default limit.
func newWSConn(ws *websocket.Conn) *wsConn {
	ws.SetReadLimit(MaxFramePayload + frameHeaderLen + 1024)
	return &wsConn{ws: ws}
}

func (c *wsConn) ReadFrame(ctx context.Context) (Frame, error) {
	typ, data, err := c.ws.Read(ctx)
	if err != nil {
		return Frame{}, err
	}
	if typ != websocket.MessageBinary {
		return Frame{}, ErrProtocol
	}
	return parseFrame(data)
}

func (c *wsConn) WriteFrame(ctx context.Context, f Frame) error {
	b, err := f.Marshal()
	if err != nil {
		return err
	}
	// One writer at a time: the session heartbeat, the per-channel relays and
	// a bye can all write concurrently, and the WebSocket library requires
	// writes to be serialised.
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return c.ws.Write(ctx, websocket.MessageBinary, b)
}

func (c *wsConn) Close() error {
	// A normal close; the peer reads it as "session ended". Best-effort.
	return c.ws.Close(websocket.StatusNormalClosure, "")
}

// Timing constants shared by both ends.
const (
	// heartbeatInterval is the nominal gap between forwarder pings.
	heartbeatInterval = 20 * time.Second
	// sessionTimeout is how long without a frame before a side gives up on
	// the peer. Comfortably more than two heartbeats so a single lost ping
	// does not drop a healthy link.
	sessionTimeout = 70 * time.Second
	// writeTimeout bounds one frame write, so a wedged peer cannot block a
	// relay goroutine forever.
	writeTimeout = 15 * time.Second
	// openTimeout bounds how long the hub waits for an OpenAck.
	openTimeout = 20 * time.Second
)
