package gitproxy

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestRoutesServeTheirPrefixAheadOfGit: a route on the proxy's listener (the
// hub's model relay, Task 20435) answers its own prefix at a "/" boundary and
// nothing else; a path that only starts like it, and every git route, still
// reach the proxy, which refuses them as it always did.
func TestRoutesServeTheirPrefixAheadOfGit(t *testing.T) {
	reg, err := NewRegistry("https://hub.example.com:8443")
	if err != nil {
		t.Fatal(err)
	}
	hit := 0
	px, err := New(reg, Options{Routes: []Route{{Prefix: "/_anthropic",
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit++; w.WriteHeader(299) })}}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	for path, want := range map[string]int{
		"/_anthropic/v1/messages":       299,
		"/_anthropic":                   299,
		"/_anthropicx/v1/messages":      http.StatusNotFound,
		"/owner/repo.git/info/refs":     http.StatusUnauthorized,
		"/_forge/ghe.example.com/a/b/x": http.StatusNotFound,
		"/anthropic/v1/messages":        http.StatusNotFound,
	} {
		rec := httptest.NewRecorder()
		px.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != want {
			t.Errorf("%s: %d, want %d", path, rec.Code, want)
		}
	}
	if hit != 2 {
		t.Errorf("the route served %d requests, want 2", hit)
	}
	for _, bad := range []string{"anthropic", "/anthropic", "/_a/b", "/_x/", "/_forge", ""} {
		if _, err := New(reg, Options{Routes: []Route{{Prefix: bad, Handler: http.NotFoundHandler()}}}); err == nil {
			t.Errorf("route prefix %q was accepted", bad)
		}
	}
	if _, err := New(reg, Options{Routes: []Route{{Prefix: "/_x"}}}); err == nil {
		t.Error("a route with no handler was accepted")
	}
}
