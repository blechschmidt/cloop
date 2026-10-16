package deviceforward

// relay.go splices a mux channel to a local byte stream.
//
// This is the whole data path, and it is deliberately dumb: once a channel is
// open, bytes move in both directions with no interpretation. The device's own
// protocol — USB/IP URBs, raw Ethernet frames — passes through untouched,
// which is what makes one relay serve both device kinds. The only policy a
// forwarder applies is at Open time (which device, by whom); after that it is
// a pipe.

import (
	"encoding/json"
	"fmt"
	"io"
	"sync"
)

// splice copies between a mux channel and a local stream until either side
// ends, then closes both. It blocks until the copy is done, so the caller — a
// forwarder's Open handler or the hub's accept loop — holds the stream open
// for exactly as long as it is live.
func splice(ch, local io.ReadWriteCloser) {
	var once sync.Once
	stop := func() {
		once.Do(func() {
			_ = ch.Close()
			_ = local.Close()
		})
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		defer stop()
		_, _ = io.Copy(local, ch)
	}()
	go func() {
		defer wg.Done()
		defer stop()
		_, _ = io.Copy(ch, local)
	}()
	wg.Wait()
}

// unmarshalJSON decodes a control-frame payload, wrapping a parse error as a
// protocol error so callers can branch on it.
func unmarshalJSON(b []byte, v any) error {
	if err := json.Unmarshal(b, v); err != nil {
		return fmt.Errorf("%w: %v", ErrProtocol, err)
	}
	return nil
}
