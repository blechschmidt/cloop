package webhook

import (
	"net/http"
	"sync"
	"testing"
	"time"
)

// panicRoundTripper panics on every Do() — used to inject a synthetic panic
// inside the goroutine spawned by Send().
type panicRoundTripper struct {
	once sync.Once
	hit  chan struct{}
}

func (p *panicRoundTripper) RoundTrip(_ *http.Request) (*http.Response, error) {
	p.once.Do(func() { close(p.hit) })
	panic("synthetic panic from RoundTripper")
}

// TestSend_PanicInGoroutineRecovered pins the regression that a panic in the
// goroutine Send() spawns is caught by the deferred recover, instead of taking
// down the entire process. Without the recover() the test binary would crash
// outright and this test would never report a failure.
//
// The test substitutes http.DefaultClient.Transport so that c.send() →
// http.DefaultClient.Do(req) panics during transport. We restore the original
// transport on cleanup. Tests in this package run sequentially within the
// package so the substitution does not race with peer tests.
func TestSend_PanicInGoroutineRecovered(t *testing.T) {
	origTransport := http.DefaultClient.Transport
	t.Cleanup(func() { http.DefaultClient.Transport = origTransport })

	prt := &panicRoundTripper{hit: make(chan struct{})}
	http.DefaultClient.Transport = prt

	c := New("http://127.0.0.1:1/panic-recover-test", nil, nil, "")

	// Send must return immediately (it spawns a goroutine).
	c.Send(EventTaskDone, Payload{Goal: "panic-recover-test"})

	// Wait for the round-tripper to be hit (proves the goroutine actually
	// ran and reached c.send).
	select {
	case <-prt.hit:
	case <-time.After(2 * time.Second):
		t.Fatal("RoundTripper was not invoked within 2s — Send goroutine never reached c.send")
	}

	// Give the deferred recover a moment to run. If recovery were missing
	// the test process would have already crashed by this point.
	time.Sleep(50 * time.Millisecond)

	// Survival is the assertion: the test reaching this line proves the
	// panic was recovered. Add an explicit second Send to confirm the
	// client and DefaultClient are still usable after a recovered panic.
	c.Send(EventTaskDone, Payload{Goal: "second-send-after-panic"})
	time.Sleep(50 * time.Millisecond)
}
