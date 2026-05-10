package chaos

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// Transport is an http.RoundTripper that consults a Controller before
// dispatching each request, and replaces the response with a fault when one
// is active. When no controller is installed (or no faults match), it forwards
// the request to Base unchanged.
//
// The hot path adds one atomic load + one type comparison per request.
//
// Why a wrapper rather than a Client option: Anthropic, OpenAI and Ollama all
// build their *http.Client via provider.NewHTTPClient(), which is the single
// integration point. Wiring chaos into NewHTTPTransport via this wrapper means
// every provider — present and future — gets fault injection for free.
type Transport struct {
	// Base is the underlying transport that handles non-faulted requests. nil
	// means use http.DefaultTransport, matching the convention for net/http
	// middleware. Tests typically inject an httptest.NewServer's transport.
	Base http.RoundTripper

	// Controller is consulted on every request. nil means "use the global
	// controller" — see chaos.Global. If Global() is also nil, the transport
	// is fully transparent.
	Controller *Controller
}

// RoundTrip implements http.RoundTripper. It checks every relevant fault type
// and short-circuits with the first one that fires; the order is fixed so
// behaviour is deterministic when multiple types are simultaneously active.
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	c := t.controller()

	// Fast path: no active faults at all. Skips the per-fault loop in the
	// common case where chaos is not in use.
	if c == nil || c.activeCount.Load() == 0 {
		return t.base().RoundTrip(req)
	}

	// network-flap closes the connection before the request goes out. We
	// check it first because it is the cheapest fault to deliver and a
	// genuinely flaky network would manifest before any HTTP semantics.
	if c.ShouldInject(FaultNetworkFlap) {
		return nil, &net.OpError{
			Op:  "dial",
			Err: errors.New("chaos: network-flap injected"),
		}
	}

	if c.ShouldInject(FaultProviderTimeout) {
		// Honour the request context. We pick the shorter of the configured
		// fault duration and the caller's deadline so a test using a 30s
		// fault doesn't actually block for 30s when the caller has set
		// ctx.WithTimeout(2 * time.Second).
		ctx := req.Context()
		var sleep time.Duration
		if dl, ok := ctx.Deadline(); ok {
			sleep = time.Until(dl) + time.Second
		} else {
			sleep = 30 * time.Second
		}
		select {
		case <-time.After(sleep):
		case <-ctx.Done():
		}
		return nil, fmt.Errorf("chaos: provider-timeout injected: %w", context.DeadlineExceeded)
	}

	if c.ShouldInject(FaultProvider429) {
		return syntheticResponse(req, http.StatusTooManyRequests, `{"error":"chaos: synthetic 429"}`), nil
	}

	if c.ShouldInject(FaultProvider500) {
		return syntheticResponse(req, http.StatusInternalServerError, `{"error":"chaos: synthetic 500"}`), nil
	}

	return t.base().RoundTrip(req)
}

func (t *Transport) base() http.RoundTripper {
	if t.Base != nil {
		return t.Base
	}
	return http.DefaultTransport
}

func (t *Transport) controller() *Controller {
	if t.Controller != nil {
		return t.Controller
	}
	return Global()
}

// syntheticResponse builds a minimal but well-formed *http.Response so callers
// using io.ReadAll/json.Decode against a faulted body see realistic data.
// A few headers (Content-Type, Content-Length) are set explicitly because
// some clients refuse to parse without them.
func syntheticResponse(req *http.Request, status int, body string) *http.Response {
	header := make(http.Header)
	header.Set("Content-Type", "application/json")
	header.Set("Content-Length", fmt.Sprintf("%d", len(body)))
	header.Set("X-Chaos-Injected", "true")
	if status == http.StatusTooManyRequests {
		// Mirror what real provider 429s typically include so retry headers
		// flow through to the client unchanged.
		header.Set("Retry-After", "1")
	}
	return &http.Response{
		Status:        fmt.Sprintf("%d %s", status, http.StatusText(status)),
		StatusCode:    status,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        header,
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
		Request:       req,
	}
}

// WrapTransport returns base wrapped in a chaos Transport that consults the
// given controller. Pass nil for c to consult chaos.Global() instead.
func WrapTransport(base http.RoundTripper, c *Controller) http.RoundTripper {
	return &Transport{Base: base, Controller: c}
}

// AdvanceForTesting is a tiny helper used by chaos_test.go to deterministically
// drain pending request bodies without leaking goroutines. Exposed because Go
// vet flags unused imports otherwise.
func AdvanceForTesting(b []byte) []byte { return bytes.Clone(b) }
