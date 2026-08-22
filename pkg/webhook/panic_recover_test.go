package webhook

import (
	"net/http"
	"testing"
	"time"
)

// panicRoundTripper panics on every Do() — used to inject a synthetic panic
// inside the goroutine spawned by Send().
//
// Each call announces itself on hits before panicking. That announcement is not
// just an assertion aid: it is the happens-before edge that lets the test
// restore http.DefaultClient.Transport safely. http.Client reads Transport at
// the top of Do, so a test that has received one signal per Send knows every
// read is already done and the cleanup's write cannot race it.
type panicRoundTripper struct {
	hits chan struct{}
}

func (p *panicRoundTripper) RoundTrip(_ *http.Request) (*http.Response, error) {
	// Non-blocking: an unexpected extra call (a retry, say) must not wedge
	// the transport goroutine on a full channel.
	select {
	case p.hits <- struct{}{}:
	default:
	}
	panic("synthetic panic from RoundTripper")
}

// awaitHit blocks until the round-tripper is entered once more.
func (p *panicRoundTripper) awaitHit(t *testing.T, what string) {
	t.Helper()
	select {
	case <-p.hits:
	case <-time.After(2 * time.Second):
		t.Fatalf("RoundTripper was not invoked within 2s — %s goroutine never reached c.send", what)
	}
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

	prt := &panicRoundTripper{hits: make(chan struct{}, 8)}
	http.DefaultClient.Transport = prt

	c := New("http://127.0.0.1:1/panic-recover-test", nil, nil, "")

	// Send must return immediately (it spawns a goroutine).
	c.Send(EventTaskDone, Payload{Goal: "panic-recover-test"})
	prt.awaitHit(t, "first Send")

	// Survival is the assertion: reaching this line proves the panic was
	// recovered rather than crashing the test binary. The second Send
	// confirms the client and DefaultClient are still usable afterwards.
	c.Send(EventTaskDone, Payload{Goal: "second-send-after-panic"})
	prt.awaitHit(t, "second Send")

	// Both sends have now entered the transport, so both have finished
	// reading http.DefaultClient.Transport and the deferred restore below
	// cannot race them. The previous version slept 50ms here instead, which
	// is why this test failed under -race: a sleep orders nothing.
}
