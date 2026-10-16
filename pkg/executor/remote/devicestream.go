package remote

// devicestream.go is one end of a device channel (Task 20430), shared by the
// hub and the agent: an io.ReadWriteCloser whose writes become device_data
// frames on the session and whose reads are fed, by the session's read loop,
// with the device_data frames that arrive for it.
//
// It is attach's mailbox shape (attach.go) without the terminal: the read loop
// that delivers into it is shared by every workload on the connection, so
// Deliver never blocks. A bounded inbox decouples it from the consumer — the
// kernel's vhci on the agent, the forwarder's stream on the hub — and a
// consumer that falls a few megabytes behind ends its channel rather than
// stalling the heartbeat or buffering without bound. A USB/IP stream with a
// hole in it is not a slower stream, it is a broken one, so ending it is also
// the only honest outcome.

import (
	"errors"
	"io"
	"strings"
	"sync"
)

// deviceInboxDepth is how many chunks one channel may buffer: at most
// MaxDeviceChunk each, so 2 MiB per channel.
const deviceInboxDepth = 64

// DeviceStream is one end of a device channel.
type DeviceStream struct {
	id   string
	send func(t FrameType, payload any) error
	// onEnd runs once, when the stream ends for any reason, to unregister it.
	onEnd func()

	pr *io.PipeReader
	pw *io.PipeWriter

	inbox        chan []byte
	closeOnce    sync.Once
	overflowOnce sync.Once
	closed       chan struct{}
	endErr       error
	writeMu      sync.Mutex
}

// NewDeviceStream builds one end of channel id. send writes one frame on the
// session; onEnd unregisters the stream.
func NewDeviceStream(id string, send func(t FrameType, payload any) error, onEnd func()) *DeviceStream {
	pr, pw := io.Pipe()
	d := &DeviceStream{
		id: id, send: send, onEnd: onEnd,
		pr: pr, pw: pw,
		inbox:  make(chan []byte, deviceInboxDepth),
		closed: make(chan struct{}),
	}
	go d.pump()
	return d
}

// ID is the channel id.
func (d *DeviceStream) ID() string { return d.id }

// Done is closed once the stream has ended.
func (d *DeviceStream) Done() <-chan struct{} { return d.closed }

// Reason is why the stream ended, once it has.
func (d *DeviceStream) Reason() string {
	select {
	case <-d.closed:
		if d.endErr != nil {
			return d.endErr.Error()
		}
		return "closed"
	default:
		return ""
	}
}

// Read returns bytes the peer sent, then the reason the stream ended.
func (d *DeviceStream) Read(p []byte) (int, error) { return d.pr.Read(p) }

// Write sends p to the peer as device_data frames.
func (d *DeviceStream) Write(p []byte) (int, error) {
	select {
	case <-d.closed:
		return 0, io.ErrClosedPipe
	default:
	}
	// One writer at a time, so two goroutines' chunks cannot interleave
	// inside one logical write.
	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	total := 0
	for len(p) > 0 {
		n := len(p)
		if n > MaxDeviceChunk {
			n = MaxDeviceChunk
		}
		if err := d.send(TypeDeviceData, DeviceDataPayload{ChannelID: d.id, Data: p[:n]}); err != nil {
			d.Abort("send to the peer failed: " + err.Error())
			return total, err
		}
		total += n
		p = p[n:]
	}
	return total, nil
}

// Close ends the stream from this side and tells the peer. Idempotent.
func (d *DeviceStream) Close() error {
	d.end("closed", true, false)
	return nil
}

// Abort ends the stream from this side without delivering what is still
// queued, and tells the peer.
func (d *DeviceStream) Abort(reason string) {
	d.end(reason, true, false)
}

// Finish ends the stream because the peer said so or the connection carrying
// it is gone: what already arrived is still delivered, then the reader sees
// reason. Nothing is sent back.
func (d *DeviceStream) Finish(reason string) {
	d.end(reason, false, true)
}

func (d *DeviceStream) end(reason string, tellPeer, drain bool) {
	d.closeOnce.Do(func() {
		if strings.TrimSpace(reason) == "" {
			reason = "device channel ended"
		}
		d.endErr = errors.New(reason)
		if !drain {
			// Hang the reader up now; the pump's next write fails and it
			// stops without draining.
			_ = d.pw.CloseWithError(d.endErr)
		}
		close(d.closed)
		if tellPeer {
			_ = d.send(TypeDeviceClose, DeviceClosePayload{ChannelID: d.id, Reason: reason})
		}
		if d.onEnd != nil {
			d.onEnd()
		}
	})
}

// Deliver hands one inbound chunk to the stream. It never blocks: it runs on
// the session read loop every workload on the connection shares.
func (d *DeviceStream) Deliver(data []byte) {
	if len(data) == 0 {
		return
	}
	select {
	// A copy sized to the chunk, not the decoded slice whose backing array is
	// sized from the frame's base64 text (see attachSession.deliver).
	case d.inbox <- append([]byte(nil), data...):
	case <-d.closed:
	default:
		// Aborted off the read loop: telling the peer is a frame write, and
		// the read loop must not wait on one.
		d.overflowOnce.Do(func() { go d.Abort("the device stream's consumer fell too far behind") })
	}
}

// pump is the only writer to the pipe.
func (d *DeviceStream) pump() {
	for {
		select {
		case chunk := <-d.inbox:
			if _, err := d.pw.Write(chunk); err != nil {
				return
			}
		case <-d.closed:
			for {
				select {
				case chunk := <-d.inbox:
					if _, err := d.pw.Write(chunk); err != nil {
						return
					}
				default:
					_ = d.pw.CloseWithError(d.endErr)
					return
				}
			}
		}
	}
}

// deviceRegistry is a connection's map of live device channels.
type deviceRegistry struct {
	mu      sync.Mutex
	streams map[string]*DeviceStream
}

func (r *deviceRegistry) add(d *DeviceStream) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.streams == nil {
		r.streams = make(map[string]*DeviceStream)
	}
	if len(r.streams) >= maxDeviceChannelsPerConnection {
		return false
	}
	r.streams[d.id] = d
	return true
}

func (r *deviceRegistry) remove(id string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.streams, id)
}

func (r *deviceRegistry) get(id string) *DeviceStream {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.streams[id]
}

func (r *deviceRegistry) drain() []*DeviceStream {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*DeviceStream, 0, len(r.streams))
	for _, d := range r.streams {
		out = append(out, d)
	}
	r.streams = nil
	return out
}

// DeviceRegistry is the agent's handle on a connection's device channels: the
// same registry the hub's Session keeps, exported for the other end.
type DeviceRegistry struct{ r deviceRegistry }

// Add registers a stream, refusing past the per-connection bound.
func (r *DeviceRegistry) Add(d *DeviceStream) bool { return r.r.add(d) }

// Remove unregisters one.
func (r *DeviceRegistry) Remove(id string) { r.r.remove(id) }

// Get looks one up.
func (r *DeviceRegistry) Get(id string) *DeviceStream { return r.r.get(id) }

// Drain empties the registry and returns what it held.
func (r *DeviceRegistry) Drain() []*DeviceStream { return r.r.drain() }
