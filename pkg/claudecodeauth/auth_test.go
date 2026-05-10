package claudecodeauth

import (
	"strings"
	"testing"
	"time"
)

func TestExtractOAuthURL(t *testing.T) {
	cases := []struct {
		name string
		line string
		want string
	}{
		{
			"claude.ai auth URL",
			"If the browser didn't open, visit: https://claude.com/cai/oauth/authorize?code=true&client_id=abc",
			"https://claude.com/cai/oauth/authorize?code=true&client_id=abc",
		},
		{
			"console oauth URL",
			"Open https://console.anthropic.com/oauth/authorize?x=1 in your browser",
			"https://console.anthropic.com/oauth/authorize?x=1",
		},
		{
			"no URL",
			"Opening browser to sign in…",
			"",
		},
		{
			"trailing whitespace stripped",
			"  https://example.com/oauth?x=1   ",
			"https://example.com/oauth?x=1",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := extractOAuthURL(c.line)
			if got != c.want {
				t.Fatalf("extractOAuthURL(%q) = %q, want %q", c.line, got, c.want)
			}
		})
	}
}

func TestBufferedReaderAppend(t *testing.T) {
	br := newBufferedReader()
	br.append("hello\n")
	br.append("world\n")
	if got := br.snapshot(); got != "hello\nworld\n" {
		t.Fatalf("snapshot = %q, want %q", got, "hello\nworld\n")
	}
}

func TestBufferedReaderAppendBounded(t *testing.T) {
	br := newBufferedReader()
	big := strings.Repeat("x", maxBufferedBytes+1024)
	br.append(big)
	if got := br.snapshot(); len(got) != maxBufferedBytes {
		t.Fatalf("snapshot len = %d, want %d", len(got), maxBufferedBytes)
	}
	// Subsequent appends are silently dropped — buffer is full.
	br.append("y")
	if got := br.snapshot(); len(got) != maxBufferedBytes {
		t.Fatalf("snapshot len after second append = %d, want %d", len(got), maxBufferedBytes)
	}
}

func TestManagerSnapshotInactive(t *testing.T) {
	m := NewManager()
	st := m.Snapshot()
	if st.Active {
		t.Fatalf("fresh manager should be inactive, got %+v", st)
	}
}

func TestManagerSubmitCodeWithoutSession(t *testing.T) {
	m := NewManager()
	if _, err := m.SubmitCode("code"); err == nil {
		t.Fatal("expected error when submitting code with no active session")
	}
}

func TestManagerCancelNoSession(t *testing.T) {
	m := NewManager()
	// Should not panic or deadlock.
	done := make(chan struct{})
	go func() { m.Cancel(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Cancel blocked on empty manager")
	}
}

func TestBufferedReaderWaitForURLTimeout(t *testing.T) {
	br := newBufferedReader()
	start := time.Now()
	url := br.waitForURL(50 * time.Millisecond)
	if url != "" {
		t.Fatalf("waitForURL = %q, want empty", url)
	}
	if elapsed := time.Since(start); elapsed < 50*time.Millisecond {
		t.Fatalf("waitForURL returned early: %v", elapsed)
	}
}
