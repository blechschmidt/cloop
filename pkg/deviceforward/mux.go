package deviceforward

// mux.go multiplexes many device streams over one forwarder connection.
//
// Channel 0 is the session: hello, welcome, heartbeat, bye. Every positive
// channel is one open stream to the on-prem device. The hub opens a channel
// each time a consumer wants the device (a vhci attach, an L2 bridge); the
// forwarder answers by opening its local endpoint and binding it to that
// channel. Either side closes a channel when its end of the stream ends.
//
// A muxChannel is an io.ReadWriteCloser so the two ends can splice it to a
// local resource with an ordinary io.Copy: on the hub a loopback TCP
// connection, on the forwarder the device endpoint. Read returns bytes that
// arrived in Data frames; Write chunks into Data frames; Close sends a Close
// frame and never reuses the channel number.

import (
	"context"
	"io"
	"sync"
)

// chunkSize bounds one outbound Data frame's payload. Well under
// MaxFramePayload so a maximal read still fits with header overhead, and large
// enough that a USB/IP bulk transfer or a jumbo frame is one or two frames.
const chunkSize = 128 * 1024

// mux owns the channel table over one frame connection.
type mux struct {
	conn frameConn

	mu       sync.Mutex
	channels map[uint32]*muxChannel
	closed   bool
	nextID   uint32
}

func newMux(conn frameConn) *mux {
	return &mux{conn: conn, channels: make(map[uint32]*muxChannel), nextID: 1}
}

// allocate registers a new channel with a hub-chosen id and returns it. Used
// by the hub, which initiates channels.
func (m *mux) allocate() (*muxChannel, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil, false
	}
	id := m.nextID
	m.nextID++
	ch := m.newChannelLocked(id)
	return ch, true
}

// accept registers a channel with a peer-chosen id and returns it, or reports
// that the id is already in use. Used by the forwarder, which answers Opens.
func (m *mux) accept(id uint32) (*muxChannel, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil, false
	}
	if _, exists := m.channels[id]; exists {
		return nil, false
	}
	return m.newChannelLocked(id), true
}

func (m *mux) newChannelLocked(id uint32) *muxChannel {
	pr, pw := io.Pipe()
	ch := &muxChannel{
		id:   id,
		mux:  m,
		in:   pr,
		inW:  pw,
		done: make(chan struct{}),
	}
	m.channels[id] = ch
	return ch
}

func (m *mux) lookup(id uint32) (*muxChannel, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	ch, ok := m.channels[id]
	return ch, ok
}

func (m *mux) remove(id uint32) {
	m.mu.Lock()
	delete(m.channels, id)
	m.mu.Unlock()
}

// deliverData writes an inbound Data payload to its channel. It blocks until
// the channel's reader consumes it — backpressure, bounded by the pipe — which
// is why the session read loop that calls this tolerates a slow consumer
// rather than buffering without limit.
func (m *mux) deliverData(id uint32, payload []byte) {
	ch, ok := m.lookup(id)
	if !ok {
		return
	}
	_, _ = ch.inW.Write(payload)
}

// deliverClose ends a channel's inbound side.
func (m *mux) deliverClose(id uint32) {
	ch, ok := m.lookup(id)
	if !ok {
		return
	}
	ch.closeInbound()
	m.remove(id)
}

// shutdown tears down every channel, for when the whole connection ends.
func (m *mux) shutdown() {
	m.mu.Lock()
	m.closed = true
	chans := make([]*muxChannel, 0, len(m.channels))
	for _, ch := range m.channels {
		chans = append(chans, ch)
	}
	m.channels = map[uint32]*muxChannel{}
	m.mu.Unlock()
	for _, ch := range chans {
		ch.closeInbound()
	}
}

// muxChannel is one stream, presented to its owner as an io.ReadWriteCloser.
type muxChannel struct {
	id  uint32
	mux *mux
	in  *io.PipeReader
	inW *io.PipeWriter

	closeOnce sync.Once
	done      chan struct{}
}

// ID is the channel number.
func (c *muxChannel) ID() uint32 { return c.id }

// Read returns bytes that arrived in Data frames for this channel.
func (c *muxChannel) Read(p []byte) (int, error) { return c.in.Read(p) }

// Write sends p as one or more Data frames. A write that cannot complete
// within writeTimeout fails rather than blocking a relay forever.
func (c *muxChannel) Write(p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		n := len(p)
		if n > chunkSize {
			n = chunkSize
		}
		ctx, cancel := context.WithTimeout(context.Background(), writeTimeout)
		err := c.mux.conn.WriteFrame(ctx, Frame{Type: TypeData, Channel: c.id, Payload: p[:n]})
		cancel()
		if err != nil {
			return total, err
		}
		total += n
		p = p[n:]
	}
	return total, nil
}

// Close sends a Close frame for this channel and tears down its inbound side.
// Idempotent.
func (c *muxChannel) Close() error {
	c.closeOnce.Do(func() {
		close(c.done)
		ctx, cancel := context.WithTimeout(context.Background(), writeTimeout)
		_ = c.mux.conn.WriteFrame(ctx, Frame{Type: TypeClose, Channel: c.id})
		cancel()
		c.closeInbound()
		c.mux.remove(c.id)
	})
	return nil
}

// closeInbound ends the reader with EOF without sending a Close frame — used
// when the peer closed the channel or the whole connection went away.
func (c *muxChannel) closeInbound() {
	_ = c.inW.Close()
}
