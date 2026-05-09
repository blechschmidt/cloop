package ui

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestPanicRecoveryMiddleware_PanickedHandlerReturns500 verifies that a
// panic from a downstream handler is recovered and converted into a clean
// 500 JSON response, instead of leaving the client with an aborted
// connection. This protects every API route from crashing the request even
// if a handler dereferences a nil pointer or trips an unchecked invariant.
func TestPanicRecoveryMiddleware_PanickedHandlerReturns500(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/boom", func(w http.ResponseWriter, r *http.Request) {
		panic("synthetic panic")
	})
	h := panicRecoveryMiddleware(mux)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/boom", nil)
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status: got %d want %d", rec.Code, http.StatusInternalServerError)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Fatalf("content-type: got %q want json", ct)
	}
	body, _ := io.ReadAll(rec.Body)
	if !strings.Contains(string(body), `"error"`) {
		t.Fatalf("body: got %q, expected JSON error envelope", string(body))
	}
}

// TestPanicRecoveryMiddleware_NormalRequestPassesThrough verifies that a
// non-panicking handler is unaffected by the middleware — its response code,
// headers, and body must reach the client untouched.
func TestPanicRecoveryMiddleware_NormalRequestPassesThrough(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/ok", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Custom", "yes")
		w.WriteHeader(http.StatusTeapot)
		_, _ = w.Write([]byte(`{"ok":true}`))
	})
	h := panicRecoveryMiddleware(mux)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/ok", nil)
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusTeapot {
		t.Fatalf("status: got %d want %d", rec.Code, http.StatusTeapot)
	}
	if got := rec.Header().Get("X-Custom"); got != "yes" {
		t.Fatalf("header passthrough: got %q want %q", got, "yes")
	}
	body, _ := io.ReadAll(rec.Body)
	if string(body) != `{"ok":true}` {
		t.Fatalf("body passthrough: got %q", string(body))
	}
}

// TestPanicRecoveryMiddleware_AbortHandlerRePanics verifies the documented
// http.ErrAbortHandler escape hatch: a handler that intentionally aborts the
// request must NOT be caught by our middleware — net/http's own recover
// machinery has special handling for it (silent log, no stack dump). If we
// suppressed it, we'd defeat the abort semantics callers rely on.
func TestPanicRecoveryMiddleware_AbortHandlerRePanics(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/abort", func(w http.ResponseWriter, r *http.Request) {
		panic(http.ErrAbortHandler)
	})
	h := panicRecoveryMiddleware(mux)

	defer func() {
		rec := recover()
		if rec == nil {
			t.Fatal("expected http.ErrAbortHandler to propagate, got nil")
		}
		if rec != http.ErrAbortHandler {
			t.Fatalf("expected http.ErrAbortHandler, got %v", rec)
		}
	}()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/abort", nil)
	h.ServeHTTP(rec, req)
	t.Fatal("expected panic, did not panic")
}

// TestPanicRecoveryMiddleware_ServerStaysAlive end-to-end check via httptest:
// after a panicking request returns 500, a subsequent request to a working
// endpoint must succeed. This is the load-bearing invariant — a single buggy
// handler must not poison the whole UI server.
func TestPanicRecoveryMiddleware_ServerStaysAlive(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/boom", func(w http.ResponseWriter, r *http.Request) {
		panic("boom")
	})
	mux.HandleFunc("/ok", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("hello"))
	})

	srv := httptest.NewServer(panicRecoveryMiddleware(mux))
	defer srv.Close()

	resp1, err := http.Get(srv.URL + "/boom")
	if err != nil {
		t.Fatalf("/boom: %v", err)
	}
	_, _ = io.ReadAll(resp1.Body)
	resp1.Body.Close()
	if resp1.StatusCode != http.StatusInternalServerError {
		t.Fatalf("/boom status: got %d want 500", resp1.StatusCode)
	}

	resp2, err := http.Get(srv.URL + "/ok")
	if err != nil {
		t.Fatalf("/ok: %v", err)
	}
	body, _ := io.ReadAll(resp2.Body)
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("/ok status: got %d want 200", resp2.StatusCode)
	}
	if string(body) != "hello" {
		t.Fatalf("/ok body: got %q want %q", string(body), "hello")
	}
}
