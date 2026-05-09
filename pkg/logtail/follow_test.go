package logtail

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// safeBuf is a thread-safe bytes.Buffer for test writers.
type safeBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *safeBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *safeBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// fastFollowConfig is a tight config so tests don't have to wait 500ms+.
func fastFollowConfig() followConfig {
	return followConfig{
		pollInterval:   10 * time.Millisecond,
		fastPoll:       5 * time.Millisecond,
		backoffInitial: 10 * time.Millisecond,
		backoffMax:     50 * time.Millisecond,
		bufSize:        4 * 1024,
	}
}

// waitFor polls cond until it returns true or until timeout. Returns the
// final state of cond.
func waitFor(timeout time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return cond()
}

func appendTo(t *testing.T, path, s string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatalf("append open %s: %v", path, err)
	}
	defer f.Close()
	if _, err := f.WriteString(s); err != nil {
		t.Fatalf("append write %s: %v", path, err)
	}
}

func TestFollow_StreamsAppendedBytes(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "log")
	if err := os.WriteFile(p, []byte("preamble — should NOT be replayed\n"), 0644); err != nil {
		t.Fatal(err)
	}

	out := &safeBuf{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- followWithConfig(ctx, p, out, fastFollowConfig()) }()

	// Give Follow a beat to seek to EOF before we append.
	time.Sleep(30 * time.Millisecond)

	appendTo(t, p, "first\n")
	appendTo(t, p, "second\n")

	if !waitFor(2*time.Second, func() bool {
		return strings.Contains(out.String(), "first\n") && strings.Contains(out.String(), "second\n")
	}) {
		t.Fatalf("expected appended bytes, got %q", out.String())
	}
	if strings.Contains(out.String(), "preamble") {
		t.Errorf("preamble was replayed: %q", out.String())
	}

	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Follow returned err: %v", err)
	}
}

func TestFollow_WaitsForMissingFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "later.log")

	out := &safeBuf{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- followWithConfig(ctx, p, out, fastFollowConfig()) }()

	// File doesn't exist yet — Follow should be backing off, not erroring.
	time.Sleep(40 * time.Millisecond)

	if err := os.WriteFile(p, []byte(""), 0644); err != nil {
		t.Fatal(err)
	}

	// Give Follow time to open and seek-to-end.
	time.Sleep(60 * time.Millisecond)

	appendTo(t, p, "after-create\n")

	if !waitFor(2*time.Second, func() bool {
		return strings.Contains(out.String(), "after-create\n")
	}) {
		t.Fatalf("expected after-create, got %q", out.String())
	}

	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Follow returned err: %v", err)
	}
}

func TestFollow_HandlesFileReplacement(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "rot.log")
	if err := os.WriteFile(p, []byte(""), 0644); err != nil {
		t.Fatal(err)
	}

	out := &safeBuf{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- followWithConfig(ctx, p, out, fastFollowConfig()) }()

	time.Sleep(30 * time.Millisecond)
	appendTo(t, p, "before-rotation\n")

	if !waitFor(2*time.Second, func() bool {
		return strings.Contains(out.String(), "before-rotation\n")
	}) {
		t.Fatalf("did not see pre-rotation line: %q", out.String())
	}

	// Replace the file with a fresh inode.
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("post-rotation\n"), 0644); err != nil {
		t.Fatal(err)
	}

	if !waitFor(2*time.Second, func() bool {
		return strings.Contains(out.String(), "post-rotation\n")
	}) {
		t.Fatalf("did not see post-rotation line: %q", out.String())
	}

	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Follow returned err: %v", err)
	}
}

func TestFollow_HandlesTruncation(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "trunc.log")
	if err := os.WriteFile(p, []byte("filler-line-1\nfiller-line-2\nfiller-line-3\n"), 0644); err != nil {
		t.Fatal(err)
	}

	out := &safeBuf{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- followWithConfig(ctx, p, out, fastFollowConfig()) }()

	time.Sleep(30 * time.Millisecond)
	appendTo(t, p, "pre-truncate\n")

	if !waitFor(2*time.Second, func() bool {
		return strings.Contains(out.String(), "pre-truncate\n")
	}) {
		t.Fatalf("did not see pre-truncate: %q", out.String())
	}

	// Truncate in place (same inode, smaller size).
	if err := os.Truncate(p, 0); err != nil {
		t.Fatal(err)
	}
	// Give Follow time to detect truncation and reopen at offset 0.
	time.Sleep(60 * time.Millisecond)
	appendTo(t, p, "post-truncate\n")

	if !waitFor(2*time.Second, func() bool {
		return strings.Contains(out.String(), "post-truncate\n")
	}) {
		t.Fatalf("did not see post-truncate: %q", out.String())
	}

	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Follow returned err: %v", err)
	}
}

func TestFollow_ReturnsOnContextCancel(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "log")
	if err := os.WriteFile(p, []byte(""), 0644); err != nil {
		t.Fatal(err)
	}

	out := &safeBuf{}
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() { done <- followWithConfig(ctx, p, out, fastFollowConfig()) }()

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Follow err: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Follow did not return after ctx cancel")
	}
}

func TestFollow_MissingFileThenCancel(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "never-appears.log")

	out := &safeBuf{}
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() { done <- followWithConfig(ctx, p, out, fastFollowConfig()) }()

	// Cancel while Follow is still in initial-open backoff.
	time.Sleep(30 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Follow err: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Follow did not return on cancel during initial backoff")
	}
}

func TestNextBackoff_DoublesCappedAndJittered(t *testing.T) {
	maxD := 1 * time.Second
	cur := 100 * time.Millisecond
	for i := 0; i < 20; i++ {
		next := nextBackoff(cur, maxD)
		if next > maxD+maxD/4 {
			t.Errorf("backoff exceeded cap+jitter: %v > %v", next, maxD+maxD/4)
		}
		if next < 50*time.Millisecond {
			t.Errorf("backoff floor breached: %v", next)
		}
		cur = next
	}
}
