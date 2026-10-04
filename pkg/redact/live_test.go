package redact

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestLiveFollowsALeaseFileRewrite: a token file the hub rewrote mid-run is
// scrubbed from then on, and the token it replaced still is (Task 20375).
func TestLiveFollowsALeaseFileRewrite(t *testing.T) {
	dir := t.TempDir()
	token := filepath.Join(dir, "github-token")
	if err := os.WriteFile(token, []byte("ghs_first_token_value\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	l := NewLive([]string{LeaseDirKey + "=" + dir})
	l.now = func() time.Time { return now }
	if !l.Active() {
		t.Fatal("a process holding a lease file is not redacting")
	}
	if got := l.Current().String("a ghs_first_token_value b"); strings.Contains(got, "ghs_first") {
		t.Fatalf("the first token is not scrubbed: %q", got)
	}

	tmp := filepath.Join(dir, ".swap")
	if err := os.WriteFile(tmp, []byte("ghs_second_token_value\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, token); err != nil {
		t.Fatal(err)
	}
	// The directory is looked at no more than once per interval; one interval
	// on, the rewrite is seen.
	now = now.Add(liveCheckInterval)
	got := l.Current().String("x ghs_second_token_value y ghs_first_token_value z")
	if strings.Contains(got, "ghs_second") || strings.Contains(got, "ghs_first") {
		t.Fatalf("after the rewrite = %q; both tokens must be scrubbed", got)
	}
}

func TestLiveWithNoLeaseIsInactive(t *testing.T) {
	if NewLive([]string{"PATH=/usr/bin"}).Active() {
		t.Fatal("a process with no lease is redacting")
	}
}

func TestSetWithKeepsWhatItHad(t *testing.T) {
	s := New("first-secret-value")
	w := s.With("second-secret-value")
	if got := w.String("first-secret-value second-secret-value"); strings.Contains(got, "secret-value") {
		t.Fatalf("With lost a value: %q", got)
	}
	if s.With() != s || s.With("short") != s {
		t.Error("With that adds nothing should return the same set")
	}
	var nilSet *Set
	if nilSet.With("third-secret-value").Len() != 1 {
		t.Error("With on a nil set should start one")
	}
}
