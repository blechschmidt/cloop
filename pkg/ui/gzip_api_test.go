package ui

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"nhooyr.io/websocket"
)

// gzipProbeHandler builds the middleware around a handler that emits body of
// the given content type and size, so each case below exercises the decision
// path rather than a whole route.
func gzipProbeHandler(contentType string, body []byte, preEncoded bool) http.Handler {
	s := &Server{}
	return s.gzipAPIMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if contentType != "" {
			w.Header().Set("Content-Type", contentType)
		}
		if preEncoded {
			w.Header().Set("Content-Encoding", "gzip")
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	}))
}

// TestGzipAPICompressesLargeJSON is the case the middleware exists for: the
// /api/state document for the hub's own project, which measured 734 KB
// uncompressed and was the single largest thing the dashboard downloaded
// (Task 20280).
func TestGzipAPICompressesLargeJSON(t *testing.T) {
	// Repetitive JSON, like a task list: compresses the way the real payload
	// does rather than like random bytes.
	body := []byte(`{"tasks":[` + strings.Repeat(`{"id":1,"title":"a task","status":"done"},`, 2000) + `{}]}`)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/state", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	gzipProbeHandler("application/json", body, false).ServeHTTP(rec, req)

	res := rec.Result()
	defer res.Body.Close()
	if got := res.Header.Get("Content-Encoding"); got != "gzip" {
		t.Fatalf("Content-Encoding = %q, want gzip", got)
	}
	if !strings.Contains(res.Header.Get("Vary"), "Accept-Encoding") {
		t.Errorf("Vary = %q, must include Accept-Encoding or a shared cache "+
			"could serve a gzip body to a client that asked for identity",
			res.Header.Get("Vary"))
	}
	// Content-Length describing the identity body would make the client stop
	// reading early or reject the response outright.
	if cl := res.Header.Get("Content-Length"); cl != "" && cl != "0" {
		if cl == string(rune(len(body))) {
			t.Errorf("Content-Length %q still describes the uncompressed body", cl)
		}
	}

	wire := rec.Body.Len()
	zr, err := gzip.NewReader(rec.Body)
	if err != nil {
		t.Fatalf("response is not valid gzip: %v", err)
	}
	got, err := io.ReadAll(zr)
	if err != nil {
		t.Fatalf("read gzip body: %v", err)
	}
	if string(got) != string(body) {
		t.Fatalf("decompressed body differs from what the handler wrote (%d vs %d bytes)",
			len(got), len(body))
	}
	if wire >= len(body) {
		t.Fatalf("compressed to %d bytes, no smaller than the %d-byte original", wire, len(body))
	}
	t.Logf("%d bytes -> %d on the wire (%.1fx)", len(body), wire, float64(len(body))/float64(wire))
}

// TestGzipAPISkipsEventStream guards the SSE fallback. Buffering a stream into
// compressor blocks stalls it, and the symptom is the live log going quiet
// rather than anything that points at compression.
func TestGzipAPISkipsEventStream(t *testing.T) {
	body := []byte("data: " + strings.Repeat("x", 4096) + "\n\n")
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/events", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	gzipProbeHandler("text/event-stream", body, false).ServeHTTP(rec, req)

	res := rec.Result()
	defer res.Body.Close()
	if got := res.Header.Get("Content-Encoding"); got != "" {
		t.Fatalf("SSE response was encoded %q; it must stream unbuffered", got)
	}
	if rec.Body.String() != string(body) {
		t.Fatal("SSE body was altered in transit")
	}
}

// TestGzipAPILeavesPreEncodedAlone keeps the middleware off the static assets,
// which carry a prepared gzip representation and a matching ETag from
// static.go (Task 20174). Re-encoding would produce a body no client can read.
func TestGzipAPILeavesPreEncodedAlone(t *testing.T) {
	var buf strings.Builder
	zw := gzip.NewWriter(&buf)
	_, _ = zw.Write([]byte(strings.Repeat("static asset bytes ", 500)))
	_ = zw.Close()
	prepared := []byte(buf.String())

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/assets/js/bundle.js", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	gzipProbeHandler("application/javascript", prepared, true).ServeHTTP(rec, req)

	res := rec.Result()
	defer res.Body.Close()
	if got := res.Header.Get("Content-Encoding"); got != "gzip" {
		t.Fatalf("Content-Encoding = %q, want the handler's own gzip", got)
	}
	// Exactly one gzip member: decompressing once must yield the plain text,
	// not another gzip stream.
	zr, err := gzip.NewReader(strings.NewReader(rec.Body.String()))
	if err != nil {
		t.Fatalf("not valid gzip: %v", err)
	}
	out, err := io.ReadAll(zr)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !strings.HasPrefix(string(out), "static asset bytes") {
		t.Fatal("asset was double-encoded: one decompression did not reach the plain bytes")
	}
}

// TestGzipAPISkipsSmallAndUnwilling covers the two pass-through paths: a body
// too small to be worth a gzip member, and a client that did not offer gzip.
func TestGzipAPISkipsSmallAndUnwilling(t *testing.T) {
	small := []byte(`{"ok":true}`)
	big := []byte(`{"d":"` + strings.Repeat("y", 8192) + `"}`)

	for _, tc := range []struct {
		name, accept string
		body         []byte
	}{
		{"small body", "gzip", small},
		{"client sent no Accept-Encoding", "", big},
		{"client refused gzip explicitly", "gzip;q=0, *;q=1.0", big},
		{"identity only", "identity", big},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest("GET", "/api/x", nil)
			if tc.accept != "" {
				req.Header.Set("Accept-Encoding", tc.accept)
			}
			gzipProbeHandler("application/json", tc.body, false).ServeHTTP(rec, req)

			res := rec.Result()
			defer res.Body.Close()
			if got := res.Header.Get("Content-Encoding"); got != "" {
				t.Fatalf("Content-Encoding = %q, want identity", got)
			}
			if rec.Body.String() != string(tc.body) {
				t.Fatalf("body altered: got %d bytes, want %d", rec.Body.Len(), len(tc.body))
			}
		})
	}
}

// TestGzipAPIPreservesStatusAndEmptyBody checks that a status-only response
// still reaches the client. The writer defers WriteHeader until it knows
// whether to compress, so a handler that never writes a body must still be
// flushed on Close.
func TestGzipAPIPreservesStatusAndEmptyBody(t *testing.T) {
	for _, code := range []int{http.StatusNoContent, http.StatusNotFound, http.StatusOK} {
		s := &Server{}
		h := s.gzipAPIMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(code)
		}))
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/api/x", nil)
		req.Header.Set("Accept-Encoding", "gzip")
		h.ServeHTTP(rec, req)
		if rec.Code != code {
			t.Errorf("status %d was delivered as %d", code, rec.Code)
		}
		if got := rec.Header().Get("Content-Encoding"); got != "" {
			t.Errorf("empty %d body was encoded %q", code, got)
		}
	}
}

// TestGzipAPIWebSocketStillUpgrades is the regression this middleware could
// most easily cause. websocket.Accept hijacks the connection; a wrapper that
// does not implement http.Hijacker fails every upgrade in the hub, and the
// dashboard would fall back to SSE without any error the operator would see.
func TestGzipAPIWebSocketStillUpgrades(t *testing.T) {
	s := &Server{}
	h := s.gzipAPIMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := websocket.Accept(w, r, &websocket.AcceptOptions{
			InsecureSkipVerify: true,
			CompressionMode:    websocket.CompressionContextTakeover,
		})
		if err != nil {
			return
		}
		defer c.CloseNow() //nolint:errcheck
		_ = c.Write(r.Context(), websocket.MessageText, []byte(`{"type":"task_update"}`))
	}))
	ts := httptest.NewServer(h)
	defer ts.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(ts.URL, "http")+"/api/ws", nil)
	if err != nil {
		t.Fatalf("WebSocket upgrade failed through the gzip middleware: %v", err)
	}
	defer conn.CloseNow() //nolint:errcheck

	_, data, err := conn.Read(ctx)
	if err != nil {
		t.Fatalf("read frame: %v", err)
	}
	var msg map[string]any
	if err := json.Unmarshal(data, &msg); err != nil {
		t.Fatalf("frame is not the JSON the server sent: %v", err)
	}
	if msg["type"] != "task_update" {
		t.Fatalf("got frame %v, want task_update", msg)
	}
}

// TestGzipAPINoStatusNoBody covers the handler that writes nothing and never
// calls WriteHeader. Forwarding the zero status would panic with "invalid
// WriteHeader code 0", and committing a header block the handler never asked
// for would foreclose anything downstream that still wanted to set one.
func TestGzipAPINoStatusNoBody(t *testing.T) {
	s := &Server{}
	reached := false
	h := s.gzipAPIMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		reached = true
	}))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/x", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	h.ServeHTTP(rec, req) // must not panic

	if !reached {
		t.Fatal("handler never ran")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want the implicit 200", rec.Code)
	}
	if rec.Body.Len() != 0 {
		t.Errorf("body = %q, want empty", rec.Body.String())
	}
}

// TestGzipAPIFlushBeforeAnyStatus is the shape an SSE handler takes: set the
// headers, flush to open the stream, then write as events arrive. The flush
// must not carry a zero status into WriteHeader.
func TestGzipAPIFlushBeforeAnyStatus(t *testing.T) {
	s := &Server{}
	h := s.gzipAPIMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.(http.Flusher).Flush() // opens the stream before any body
		_, _ = w.Write([]byte("data: hello\n\n"))
	}))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/events", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	h.ServeHTTP(rec, req) // must not panic

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if got := rec.Body.String(); got != "data: hello\n\n" {
		t.Errorf("body = %q, want the event delivered verbatim", got)
	}
	if enc := rec.Header().Get("Content-Encoding"); enc != "" {
		t.Errorf("event stream was encoded %q", enc)
	}
}

// TestGzipAPIFlushCommits covers a handler that flushes before reaching the
// size threshold. Those bytes must leave immediately: holding them back
// waiting for input that never arrives is indistinguishable from a hang.
func TestGzipAPIFlushCommits(t *testing.T) {
	s := &Server{}
	h := s.gzipAPIMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"partial":true}`))
		w.(http.Flusher).Flush()
	}))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/x", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	h.ServeHTTP(rec, req)

	if got := rec.Body.String(); got != `{"partial":true}` {
		t.Fatalf("flushed body = %q, want it delivered verbatim", got)
	}
}
