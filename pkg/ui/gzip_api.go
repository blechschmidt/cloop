package ui

import (
	"bufio"
	"compress/gzip"
	"errors"
	"net"
	"net/http"
	"strings"
	"sync"
)

// Dynamic API responses are compressed here; the embedded dashboard assets are
// not, because static.go already stores a prepared gzip representation per file
// alongside its own ETag (Task 20174). That split is why this exists at all:
// gzip arrived with the asset extraction and was scoped to the asset handler,
// so every JSON body the dashboard actually polls went out identity-encoded.
//
// It measured as the dominant cost of opening the hub's own project. /api/state
// for cloop is 734 KB of JSON that compresses to 231 KB — a 3.2x reduction on
// the single largest thing the browser downloads, repeated on every page load
// and every project switch (Task 20280).
//
// nginx does not cover this either. The deployment in front of :8888 sets
// `gzip on` but leaves `gzip_types` at its default, which is `text/html` alone,
// so application/json was passed through uncompressed no matter what the
// browser asked for.

// gzipAPIMinBytes is the response size below which compressing costs more than
// it saves. A gzip member carries ~20 bytes of framing and the round trip
// through the compressor is not free on either end, so small JSON — the
// {"ok":true} acknowledgements that most mutating endpoints return — is passed
// through untouched. Matches gzipMinBytes in static.go.
const gzipAPIMinBytes = 1024

// gzipWriterPool reuses compressors across requests. The dashboard's polling
// endpoints make this a hot path, and a gzip.Writer carries a 32 KB window plus
// its Huffman tables — allocating one per response would hand the GC ~50 KB of
// garbage per request for no benefit.
var gzipWriterPool = sync.Pool{
	New: func() any {
		// DefaultCompression, not BestCompression: these bodies are generated
		// per request rather than prepared once at startup like the static
		// assets, so the CPU is spent on every response. On the 734 KB state
		// payload the extra level buys ~3% off the wire for ~2.5x the time.
		w, _ := gzip.NewWriterLevel(nil, gzip.DefaultCompression)
		return w
	},
}

// gzipAPIMiddleware compresses eligible response bodies on the fly.
//
// It decides lazily, at the moment the handler commits a status, because
// whether a response may be compressed is not knowable from the request alone:
//
//   - text/event-stream is passed through. The SSE fallback delivers events by
//     flushing partial bodies, and buffering those into compressor blocks would
//     stall the stream — the failure would look like the live log going quiet,
//     not like a compression bug.
//   - an existing Content-Encoding is left alone, which is what keeps this off
//     the static assets: their handler has already set gzip and emitted the
//     matching ETag, and re-encoding would produce a body no client can read.
//   - a WebSocket upgrade never reaches WriteHeader at all; it hijacks the
//     connection, so Hijack below hands back the raw socket untouched.
func (s *Server) gzipAPIMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// A protocol upgrade is not a response body and must not be wrapped at
		// all. websocket.Accept writes the 101 and then takes the socket over;
		// deferring that status — which is what this writer does to every
		// other response while it decides on an encoding — meant the handshake
		// never reached the client and the first data frame arrived where the
		// HTTP response line should have been. The browser reported a
		// malformed response and fell back to SSE, silently.
		if !acceptsGzip(r) || isUpgradeRequest(r) {
			next.ServeHTTP(w, r)
			return
		}
		gw := &gzipResponseWriter{ResponseWriter: w}
		defer gw.Close()
		next.ServeHTTP(gw, r)
	})
}

// gzipResponseWriter compresses writes when the committed response turns out to
// be eligible, and otherwise forwards them verbatim.
type gzipResponseWriter struct {
	http.ResponseWriter

	decided bool
	gz      *gzip.Writer // non-nil only while compressing

	// pending buffers the start of the body until there is enough of it to
	// judge. Without this, a handler that writes its JSON in several small
	// calls would be compressed from the first byte and the size threshold
	// would never apply.
	pending []byte
	// committed records that a status has gone to the client, after which
	// headers are frozen.
	committed bool
	status    int
}

// eligible reports whether the response as described by the headers so far may
// be compressed.
func (g *gzipResponseWriter) eligible() bool {
	h := g.Header()
	if h.Get("Content-Encoding") != "" {
		return false
	}
	ct := h.Get("Content-Type")
	// A streaming response must not be buffered into compressor blocks.
	if strings.HasPrefix(ct, "text/event-stream") {
		return false
	}
	// 204 and 304 carry no body; compressing one would advertise an encoding
	// for content that is not there.
	if g.status == http.StatusNoContent || g.status == http.StatusNotModified {
		return false
	}
	return true
}

func (g *gzipResponseWriter) WriteHeader(code int) {
	if g.committed {
		return
	}
	// 1xx is informational — a 101 switching protocols, or an early hint —
	// and carries no body to encode. It must reach the client immediately;
	// holding it back is what broke the WebSocket handshake.
	if code < http.StatusOK {
		g.ResponseWriter.WriteHeader(code)
		return
	}
	g.status = code
	// The status is recorded but not forwarded yet: whether Content-Encoding
	// and Content-Length belong on this response is still unknown, and both
	// must be settled before the header block goes out.
	g.decided = false
}

func (g *gzipResponseWriter) Write(p []byte) (int, error) {
	if g.status == 0 {
		g.status = http.StatusOK
	}
	if g.gz != nil {
		return g.gz.Write(p)
	}
	if g.decided {
		return g.ResponseWriter.Write(p)
	}

	if !g.eligible() {
		g.commitIdentity()
		return g.ResponseWriter.Write(p)
	}

	g.pending = append(g.pending, p...)
	if len(g.pending) < gzipAPIMinBytes {
		// Not yet enough to judge; report the bytes as accepted. They are
		// held in pending and flushed by commit or Close.
		return len(p), nil
	}

	g.startGzip()
	buffered := g.pending
	g.pending = nil
	if _, err := g.gz.Write(buffered); err != nil {
		return 0, err
	}
	return len(p), nil
}

// startGzip commits the response as gzip-encoded and installs the compressor.
func (g *gzipResponseWriter) startGzip() {
	h := g.Header()
	h.Set("Content-Encoding", "gzip")
	// The length of the identity body is meaningless once encoded, and Go
	// will not recompute it for a streamed response.
	h.Del("Content-Length")
	// Caches key on the encoding, so a shared cache must not hand a gzip body
	// to a client that asked for identity.
	addVaryAcceptEncoding(h)

	zw := gzipWriterPool.Get().(*gzip.Writer)
	zw.Reset(g.ResponseWriter)
	g.gz = zw
	g.decided = true
	g.commitStatus()
}

// commitIdentity commits the response uncompressed.
func (g *gzipResponseWriter) commitIdentity() {
	g.decided = true
	g.commitStatus()
	if len(g.pending) > 0 {
		_, _ = g.ResponseWriter.Write(g.pending)
		g.pending = nil
	}
}

func (g *gzipResponseWriter) commitStatus() {
	if g.committed {
		return
	}
	g.committed = true
	// A handler can reach here having set headers but never a status — it
	// flushed, or simply returned. net/http's own implicit status is 200, and
	// forwarding the zero value instead panics with "invalid WriteHeader code
	// 0", turning a handler that did nothing wrong into a 500.
	if g.status == 0 {
		g.status = http.StatusOK
	}
	g.ResponseWriter.WriteHeader(g.status)
}

// Close flushes whatever the handler produced. A body that never reached the
// size threshold is written through uncompressed, which is the common case for
// the small JSON acknowledgements.
func (g *gzipResponseWriter) Close() {
	if g.gz != nil {
		_ = g.gz.Close()
		g.gz.Reset(nil) // drop the reference to the ResponseWriter before reuse
		gzipWriterPool.Put(g.gz)
		g.gz = nil
		return
	}
	// A handler that produced nothing at all is left entirely alone, so
	// net/http emits its own implicit 200 exactly as it would without this
	// wrapper. Committing here instead would turn every bodyless handler into
	// one that has already sent its header block, which forecloses anything
	// downstream — an error page, a redirect — that still wanted to set one.
	if !g.decided && (g.status != 0 || len(g.pending) > 0) {
		g.commitIdentity()
	}
}

// Flush forwards a handler's explicit flush.
//
// A compressed response must flush the compressor first, or the bytes sit in
// the deflate window and the flush delivers nothing — which for a progressive
// renderer looks exactly like a hung request.
func (g *gzipResponseWriter) Flush() {
	if g.gz != nil {
		_ = g.gz.Flush()
	} else if !g.decided {
		// A handler that flushes before reaching the threshold is streaming,
		// whatever its Content-Type says. Commit identity so the bytes leave
		// now rather than waiting for more input that may never come.
		g.commitIdentity()
	}
	if f, ok := g.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Hijack hands back the underlying connection.
//
// Load-bearing for the dashboard: websocket.Accept hijacks the connection to
// take over the socket, and a ResponseWriter that does not implement
// http.Hijacker fails that upgrade. Wrapping the handler chain without this
// would break every WebSocket in the hub.
func (g *gzipResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hj, ok := g.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, errors.New("ui: ResponseWriter does not support hijacking")
	}
	// Nothing may have been compressed into this connection before it is
	// handed over as a raw socket.
	g.decided = true
	g.committed = true
	g.pending = nil
	return hj.Hijack()
}

// Unwrap lets http.ResponseController reach the underlying writer for
// deadlines and any other capability not forwarded explicitly above.
func (g *gzipResponseWriter) Unwrap() http.ResponseWriter { return g.ResponseWriter }

// isUpgradeRequest reports whether the client is asking to leave HTTP — a
// WebSocket handshake in practice. Per RFC 9110 §7.6.1 Connection is a
// comma-separated list of tokens, so a browser sending "keep-alive, Upgrade"
// must still match.
func isUpgradeRequest(r *http.Request) bool {
	if r.Header.Get("Upgrade") == "" {
		return false
	}
	for _, v := range r.Header.Values("Connection") {
		for _, tok := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(tok), "upgrade") {
				return true
			}
		}
	}
	return false
}

// addVaryAcceptEncoding appends Accept-Encoding to Vary without disturbing a
// value already there — the hub sets Vary: Origin on CORS-relevant routes, and
// overwriting it would let a cache serve one origin's response to another.
func addVaryAcceptEncoding(h http.Header) {
	for _, v := range h.Values("Vary") {
		for _, tok := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(tok), "Accept-Encoding") {
				return
			}
		}
	}
	h.Add("Vary", "Accept-Encoding")
}
