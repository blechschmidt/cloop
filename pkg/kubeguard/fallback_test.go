package kubeguard

// Options.Fallback (Task 20354): see pkg/gitproxy/fallback_test.go.

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestFallbackIsOfferedOnlyUnknownSessions(t *testing.T) {
	reg := newTestRegistry(t)
	m, err := reg.Mint(MintRequest{Kubeconfig: testKubeconfig("")})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	var offered []string
	px, err := New(reg, Options{Fallback: func(w http.ResponseWriter, r *http.Request, id string) bool {
		offered = append(offered, id)
		w.WriteHeader(http.StatusTeapot)
		return true
	}})
	if err != nil {
		t.Fatal(err)
	}
	do := func(token string) int {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/namespaces/default/pods", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		px.ServeHTTP(rec, req)
		return rec.Code
	}
	if code := do("elsewhere.secret"); code != http.StatusTeapot || len(offered) != 1 || offered[0] != "elsewhere" {
		t.Fatalf("unknown session = %d, offered %v", code, offered)
	}
	if code := do(m.Session.ID + ".wrong"); code != http.StatusUnauthorized || len(offered) != 1 {
		t.Fatalf("known session with a wrong secret = %d (offered %v), want a local 401", code, offered)
	}
}
