package deviceforward

// session.go is the hub's live view of one connected forwarder.
//
// It owns the frame connection after the HTTP handshake: it reads frames,
// answers the heartbeat, routes OpenAck/Data/Close to the right channel, and
// lets the hub open a fresh stream to the device on demand. A session's
// lifetime is the connection's lifetime; when the socket drops the session
// ends and every open stream is torn down.

import (
	"context"
	"sync"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor"
)

// session is one connected forwarder.
type session struct {
	rec     ForwarderRecord
	conn    frameConn
	mux     *mux
	hello   HelloPayload
	logf    func(string, ...any)
	version int

	mu       sync.Mutex
	acks     map[uint32]chan OpenAckPayload
	resolved *executor.USBDevice

	done     chan struct{}
	closeOne sync.Once
}

func newSession(rec ForwarderRecord, conn frameConn, hello HelloPayload, version int, logf func(string, ...any)) *session {
	s := &session{
		rec:      rec,
		conn:     conn,
		mux:      newMux(conn),
		hello:    hello,
		logf:     logf,
		version:  version,
		acks:     make(map[uint32]chan OpenAckPayload),
		resolved: hello.Resolved,
		done:     make(chan struct{}),
	}
	return s
}

// Done is closed when the session ends.
func (s *session) Done() <-chan struct{} { return s.done }

func (s *session) close() {
	s.closeOne.Do(func() {
		close(s.done)
		s.mux.shutdown()
		_ = s.conn.Close()
		// Fail any opener still waiting for an ack.
		s.mu.Lock()
		for id, ch := range s.acks {
			close(ch)
			delete(s.acks, id)
		}
		s.mu.Unlock()
	})
}

// run is the read loop. It returns when the connection ends.
func (s *session) run(ctx context.Context) {
	defer s.close()
	// The hub also pings, so an idle forwarder behind a proxy that reaps
	// silent connections stays up.
	hbCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		t := time.NewTicker(heartbeatInterval)
		defer t.Stop()
		for {
			select {
			case <-hbCtx.Done():
				return
			case <-t.C:
				wctx, wc := context.WithTimeout(hbCtx, writeTimeout)
				_ = s.conn.WriteFrame(wctx, Frame{Type: TypePing})
				wc()
			}
		}
	}()

	for {
		rctx, rcancel := context.WithTimeout(ctx, sessionTimeout)
		frame, err := s.conn.ReadFrame(rctx)
		rcancel()
		if err != nil {
			return
		}
		switch frame.Type {
		case TypePing:
			wctx, wc := context.WithTimeout(ctx, writeTimeout)
			_ = s.conn.WriteFrame(wctx, Frame{Type: TypePong})
			wc()
		case TypePong:
		case TypeOpenAck:
			var ack OpenAckPayload
			_ = unmarshalJSON(frame.Payload, &ack)
			s.deliverAck(frame.Channel, ack)
		case TypeData:
			s.mux.deliverData(frame.Channel, frame.Payload)
		case TypeClose:
			s.mux.deliverClose(frame.Channel)
		case TypeError:
			var e ErrorPayload
			_ = unmarshalJSON(frame.Payload, &e)
			if s.logf != nil {
				s.logf("forwarder %s error: %s", s.rec.ForwarderID, e.Message)
			}
		default:
			// Unknown or unexpected (a second hello); ignored, non-fatal.
		}
	}
}

func (s *session) deliverAck(channel uint32, ack OpenAckPayload) {
	s.mu.Lock()
	ch := s.acks[channel]
	delete(s.acks, channel)
	s.mu.Unlock()
	if ch != nil {
		ch <- ack
		close(ch)
	}
}

// openStream asks the forwarder to open its device and returns a stream to it,
// with the forwarder's acknowledgement (which describes what it opened).
func (s *session) openStream(ctx context.Context, purpose string) (*muxChannel, OpenAckPayload, error) {
	select {
	case <-s.done:
		return nil, OpenAckPayload{}, ErrForwarderOffline
	default:
	}
	ch, ok := s.mux.allocate()
	if !ok {
		return nil, OpenAckPayload{}, ErrForwarderOffline
	}
	ackCh := make(chan OpenAckPayload, 1)
	s.mu.Lock()
	s.acks[ch.ID()] = ackCh
	s.mu.Unlock()

	wctx, cancel := context.WithTimeout(ctx, writeTimeout)
	err := s.conn.WriteFrame(wctx, Frame{
		Type:    TypeOpen,
		Channel: ch.ID(),
		Payload: marshalJSON(OpenPayload{Purpose: purpose}),
	})
	cancel()
	if err != nil {
		s.failOpen(ch.ID())
		_ = ch.Close()
		return nil, OpenAckPayload{}, err
	}

	timer := time.NewTimer(openTimeout)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		s.failOpen(ch.ID())
		_ = ch.Close()
		return nil, OpenAckPayload{}, ctx.Err()
	case <-timer.C:
		s.failOpen(ch.ID())
		_ = ch.Close()
		return nil, OpenAckPayload{}, ErrChannelRefused
	case <-s.done:
		_ = ch.Close()
		return nil, OpenAckPayload{}, ErrForwarderOffline
	case ack, ok := <-ackCh:
		if !ok {
			_ = ch.Close()
			return nil, OpenAckPayload{}, ErrForwarderOffline
		}
		if !ack.OK {
			_ = ch.Close()
			if ack.Error != "" {
				return nil, ack, wrapRefused(ack.Error)
			}
			return nil, ack, ErrChannelRefused
		}
		return ch, ack, nil
	}
}

func (s *session) failOpen(channel uint32) {
	s.mu.Lock()
	if ch := s.acks[channel]; ch != nil {
		delete(s.acks, channel)
	}
	s.mu.Unlock()
}

func wrapRefused(msg string) error {
	return &refusedError{msg: msg}
}

type refusedError struct{ msg string }

func (e *refusedError) Error() string {
	return "deviceforward: forwarder refused to open the device: " + e.msg
}
func (e *refusedError) Unwrap() error { return ErrChannelRefused }
