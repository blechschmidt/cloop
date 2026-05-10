package provider

import (
	"net"
	"net/http"
	"sync/atomic"
	"time"
)

// HTTPMiddleware optionally wraps the transport returned by NewHTTPClient
// with a *cloop chaos*-style middleware. Stored as an atomic.Value so
// installation from another goroutine is race-free, and reads on the hot
// path (every Complete() call constructs a client) are a single atomic load.
//
// The chaos package installs a hook here at init time when its CLI command
// is registered. We deliberately use a hook variable rather than a direct
// import to keep pkg/provider free of dependencies on chaos — the package
// graph stays the same in builds that strip the chaos command.
var httpMiddleware atomic.Pointer[func(http.RoundTripper) http.RoundTripper]

// SetHTTPMiddleware installs (or removes, when fn == nil) the wrapper applied
// to every transport returned by NewHTTPClient. Returns the previous wrapper.
//
// Concurrency: SetHTTPMiddleware may be called at any time, including from
// inside an init() before any provider is constructed. Already-built
// http.Client instances are NOT retroactively wrapped — only future
// NewHTTPClient calls pick up the change. In practice every provider builds
// its client in NewProvider() at startup, after init() has run.
func SetHTTPMiddleware(fn func(http.RoundTripper) http.RoundTripper) func(http.RoundTripper) http.RoundTripper {
	prev := httpMiddleware.Swap(&fn)
	if prev == nil {
		return nil
	}
	return *prev
}

// NewHTTPClient returns an *http.Client tuned for long-lived AI provider calls.
//
// Why a shared helper: the bare zero-value http.Client used historically had no
// transport timeouts, so a hung TCP connection (silently dead peer, network
// blip) could block a Complete() call for up to two hours waiting on the OS
// keepalive default. Even with context cancellation, the goroutine is stuck
// inside the syscall until the read returns.
//
// We deliberately do NOT set Client.Timeout because that would cap the entire
// request including streaming response body reads — a long Anthropic SSE
// completion legitimately takes minutes and must not be cut off mid-token.
// Instead we set transport-level timeouts that catch the failure modes that
// matter: TCP connect hang, TLS handshake hang, server stalling before the
// first response byte, and dead peers (via TCP keepalive).
func NewHTTPClient() *http.Client {
	tr := http.RoundTripper(NewHTTPTransport())
	if mw := httpMiddleware.Load(); mw != nil && *mw != nil {
		// Wrap with the installed middleware (chaos fault injection in
		// practice). The middleware is fully transparent when no fault is
		// active, so the wrap is safe to perform unconditionally.
		tr = (*mw)(tr)
	}
	return &http.Client{Transport: tr}
}

// NewHTTPTransport returns an *http.Transport with the same timeout policy as
// NewHTTPClient. Exposed separately so callers that need a custom Client (e.g.
// to set a Client.Timeout for a non-streaming request) can reuse the transport.
func NewHTTPTransport() *http.Transport {
	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	return &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   10,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   30 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		// ResponseHeaderTimeout caps how long the server has to start sending
		// the response headers after we finish writing the request. It does NOT
		// cap streaming body reads. 2 minutes is generous enough for cold-start
		// scenarios (Ollama loading a model into memory, large LLM TTFB) while
		// still bounding silent stalls.
		ResponseHeaderTimeout: 2 * time.Minute,
	}
}
