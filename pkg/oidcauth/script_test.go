package oidcauth

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

// TestServeScript: the sign-in documents' script is served as script, with a
// validator, and answers a revalidation with no body (Task 20408).
func TestServeScript(t *testing.T) {
	t.Parallel()
	rec := httptest.NewRecorder()
	ServeScript(rec, httptest.NewRequest(http.MethodGet, ScriptPath, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/javascript") {
		t.Errorf("Content-Type = %q, want text/javascript — under nosniff a browser refuses to run anything else", ct)
	}
	if rec.Body.String() != signInScript {
		t.Errorf("body is not the script:\n%s", rec.Body.String())
	}
	etag := rec.Header().Get("ETag")
	if etag == "" || !strings.Contains(rec.Header().Get("Cache-Control"), "no-cache") {
		t.Fatalf("ETag = %q, Cache-Control = %q: want a validator and revalidation", etag, rec.Header().Get("Cache-Control"))
	}

	again := httptest.NewRequest(http.MethodGet, ScriptPath, nil)
	again.Header.Set("If-None-Match", etag)
	rec = httptest.NewRecorder()
	ServeScript(rec, again)
	if rec.Code != http.StatusNotModified || rec.Body.Len() != 0 {
		t.Errorf("revalidation = %d with %d bytes, want 304 and none", rec.Code, rec.Body.Len())
	}
}

// TestSignInDocumentsLoadOnlyTheScript: neither document carries inline script
// — the hub's policy would refuse to run it — and each loads the sign-in
// script by its path.
func TestSignInDocumentsLoadOnlyTheScript(t *testing.T) {
	t.Parallel()
	docs := map[string]string{
		"landing": loginLandingHTML("/?project_idx=2"),
		"renewal": renewResultHTML(renewVerdict{outcome: RenewOK, schedule: true}),
	}
	for name, page := range docs {
		if n := strings.Count(page, "<script"); n != 1 {
			t.Errorf("%s: %d script elements, want the one that loads the sign-in script:\n%s", name, n, page)
		}
		if !strings.Contains(page, `<script src="`+ScriptPath+`"></script>`) {
			t.Errorf("%s: does not load %s:\n%s", name, ScriptPath, page)
		}
		if m := regexp.MustCompile(`\son[a-z]+\s*=`).FindString(page); m != "" {
			t.Errorf("%s: carries an inline handler (%s):\n%s", name, m, page)
		}
	}
}
