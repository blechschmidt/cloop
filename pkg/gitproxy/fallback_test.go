package gitproxy

// Options.Fallback (Task 20354): a request naming a session this registry has
// never heard of is offered to the fallback before it is refused; a request
// naming one it knows — right token or wrong — is decided here and never
// leaves.

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestFallbackIsOfferedOnlyUnknownSessions(t *testing.T) {
	reg := newTestRegistry(t, time.Now())
	known := mintOne(t, reg, MintRequest{})

	var offered []string
	px, err := New(reg, Options{Fallback: func(w http.ResponseWriter, r *http.Request, id string) bool {
		offered = append(offered, id)
		w.WriteHeader(http.StatusTeapot)
		return true
	}})
	if err != nil {
		t.Fatal(err)
	}

	do := func(user, pass string) int {
		req := httptest.NewRequest(http.MethodGet, "/acme/tool/info/refs?service=git-upload-pack", nil)
		req.SetBasicAuth(user, pass)
		rec := httptest.NewRecorder()
		px.ServeHTTP(rec, req)
		return rec.Code
	}

	if code := do("sess-on-another-hub", "whatever"); code != http.StatusTeapot {
		t.Fatalf("unknown session = %d, want the fallback's answer", code)
	}
	if len(offered) != 1 || offered[0] != "sess-on-another-hub" {
		t.Fatalf("fallback offered %v", offered)
	}

	// A known session with the wrong token is refused here: forwarding it
	// would let a caller probe other hubs with a stolen session id.
	if code := do(known.Session.ID, "wrong"); code != http.StatusUnauthorized {
		t.Fatalf("known session, wrong token = %d, want 401", code)
	}
	if len(offered) != 1 {
		t.Fatal("a request naming a known session was offered to the fallback")
	}

	// A fallback that declines leaves the refusal to the proxy.
	px2, err := New(reg, Options{Fallback: func(http.ResponseWriter, *http.Request, string) bool { return false }})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/acme/tool/info/refs?service=git-upload-pack", nil)
	req.SetBasicAuth("nobody-has-this", "x")
	rec := httptest.NewRecorder()
	px2.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("declined fallback = %d, want 401", rec.Code)
	}
}
