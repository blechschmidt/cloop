package claudeproxy

// Options.Fallback (Task 20354): see pkg/gitproxy/fallback_test.go.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestFallbackIsOfferedOnlyUnknownSessions(t *testing.T) {
	r := NewRegistry("https://hub.example.com/api/ci/anthropic")
	m := testMint(t, r)
	var offered []string
	px, err := New(r, Options{
		Upstream:   Upstream{APIKey: "k", BaseURL: "https://api.example.com"},
		PathPrefix: "/api/ci/anthropic",
		Fallback: func(w http.ResponseWriter, req *http.Request, id string) bool {
			offered = append(offered, id)
			w.WriteHeader(http.StatusTeapot)
			return true
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	do := func(header, token string) int {
		req := httptest.NewRequest(http.MethodPost, "/api/ci/anthropic/v1/messages", strings.NewReader("{}"))
		if header == "Authorization" {
			req.Header.Set(header, "Bearer "+token)
		} else {
			req.Header.Set(header, token)
		}
		rec := httptest.NewRecorder()
		px.ServeHTTP(rec, req)
		return rec.Code
	}
	foreign := TokenPrefix + "sess-elsewhere.secret"
	if code := do("Authorization", foreign); code != http.StatusTeapot {
		t.Fatalf("unknown session via Authorization = %d", code)
	}
	if code := do("X-Api-Key", foreign); code != http.StatusTeapot {
		t.Fatalf("unknown session via x-api-key = %d", code)
	}
	if len(offered) != 2 || offered[0] != "sess-elsewhere" {
		t.Fatalf("offered %v", offered)
	}
	wrong := TokenPrefix + m.Session.ID + ".wrong"
	if code := do("Authorization", wrong); code != http.StatusUnauthorized || len(offered) != 2 {
		t.Fatalf("known session, wrong secret = %d (offered %v), want a local 401", code, offered)
	}
}
