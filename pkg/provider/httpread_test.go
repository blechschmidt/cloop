package provider

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

// errReader returns the configured err on Read; used to confirm we propagate
// transport-layer errors verbatim rather than masking them as size errors.
type errReader struct{ err error }

func (e errReader) Read(_ []byte) (int, error) { return 0, e.err }

func TestReadResponseBody_UnderLimit(t *testing.T) {
	t.Parallel()
	want := []byte("hello world")
	got, err := ReadResponseBody(bytes.NewReader(want), 64)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestReadResponseBody_ExactlyAtLimit(t *testing.T) {
	t.Parallel()
	// A body exactly maxBytes long must succeed — the +1 read window is what
	// distinguishes "at the limit" from "over the limit".
	want := bytes.Repeat([]byte{'a'}, 100)
	got, err := ReadResponseBody(bytes.NewReader(want), 100)
	if err != nil {
		t.Fatalf("body of exactly maxBytes should succeed, got %v", err)
	}
	if len(got) != 100 {
		t.Fatalf("got len %d, want 100", len(got))
	}
}

func TestReadResponseBody_OverLimit(t *testing.T) {
	t.Parallel()
	body := bytes.Repeat([]byte{'a'}, 101)
	_, err := ReadResponseBody(bytes.NewReader(body), 100)
	if err == nil {
		t.Fatalf("expected error for body over limit, got nil")
	}
	if !errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf("want ErrResponseTooLarge, got %v", err)
	}
	if !strings.Contains(err.Error(), "100") {
		t.Fatalf("error %q should include the limit", err.Error())
	}
}

func TestReadResponseBody_PropagatesReadError(t *testing.T) {
	t.Parallel()
	sentinel := errors.New("transport boom")
	_, err := ReadResponseBody(errReader{err: sentinel}, 1024)
	if !errors.Is(err, sentinel) {
		t.Fatalf("want sentinel error, got %v", err)
	}
}

func TestReadResponseBody_EmptyBody(t *testing.T) {
	t.Parallel()
	got, err := ReadResponseBody(bytes.NewReader(nil), 1024)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("want empty buffer, got %d bytes", len(got))
	}
}

func TestReadResponseBodyTruncated_UnderLimit(t *testing.T) {
	t.Parallel()
	want := []byte("short")
	got, truncated, err := ReadResponseBodyTruncated(bytes.NewReader(want), 64)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if truncated {
		t.Fatalf("did not expect truncation flag")
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestReadResponseBodyTruncated_OverLimit(t *testing.T) {
	t.Parallel()
	body := bytes.Repeat([]byte{'a'}, 5000)
	got, truncated, err := ReadResponseBodyTruncated(bytes.NewReader(body), 100)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !truncated {
		t.Fatalf("expected truncation flag to be set")
	}
	if len(got) != 100 {
		t.Fatalf("buffer should be capped at 100, got %d", len(got))
	}
}

func TestReadResponseBodyTruncated_ExactlyAtLimit(t *testing.T) {
	t.Parallel()
	body := bytes.Repeat([]byte{'a'}, 100)
	got, truncated, err := ReadResponseBodyTruncated(bytes.NewReader(body), 100)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if truncated {
		t.Fatalf("at-limit body should not be marked truncated")
	}
	if len(got) != 100 {
		t.Fatalf("got len %d, want 100", len(got))
	}
}

// Pathological case: pretend we got a single-line gigabyte response. The
// limited reader must stop at the cap rather than try to allocate everything.
func TestReadResponseBody_RefusesHugeBody(t *testing.T) {
	t.Parallel()
	// io.LimitReader is what makes this safe — we wrap a never-EOF reader
	// and verify ReadResponseBody returns promptly with ErrResponseTooLarge.
	r := io.MultiReader(
		bytes.NewReader(bytes.Repeat([]byte{'x'}, 256)),
		neverEOF{},
	)
	_, err := ReadResponseBody(r, 128)
	if !errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf("want ErrResponseTooLarge, got %v", err)
	}
}

// neverEOF returns a single byte forever — used to simulate an unbounded
// stream and prove the reader actually limits before attempting to drain it.
type neverEOF struct{}

func (neverEOF) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	p[0] = 'x'
	return 1, nil
}
