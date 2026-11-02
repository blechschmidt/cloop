package boundedread

import (
	"errors"
	"io"
	"strings"
	"testing"
)

// endless is a reader that never ends: a peer streaming forever must still
// cost at most the cap plus one byte.
type endless struct{ served int64 }

func (e *endless) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'x'
	}
	e.served += int64(len(p))
	return len(p), nil
}

func TestReadAll_UnderAndAtTheLimit(t *testing.T) {
	for _, body := range []string{"", "hello", strings.Repeat("a", 64)} {
		got, err := ReadAll(strings.NewReader(body), "body", 64)
		if err != nil {
			t.Fatalf("ReadAll(%d bytes): %v", len(body), err)
		}
		if string(got) != body {
			t.Fatalf("ReadAll = %q, want %q", got, body)
		}
	}
}

func TestReadAll_RefusesALongerStreamWithoutReadingItAll(t *testing.T) {
	src := &endless{}
	_, err := ReadAll(src, "a remote page", 1024)
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("ReadAll on an endless stream = %v, want ErrTooLarge", err)
	}
	var se *SizeError
	if !errors.As(err, &se) || se.Path != "a remote page" || se.Max != 1024 {
		t.Fatalf("error = %#v, want a SizeError naming the stream and the cap", err)
	}
	// io.ReadAll grows its buffer, so the reader is asked for more than one
	// byte at a time; what matters is that the read stops near the cap rather
	// than following the stream.
	if src.served > 64<<10 {
		t.Fatalf("ReadAll pulled %d bytes from the stream for a 1 KiB cap", src.served)
	}
}

func TestReadAll_DefaultCap(t *testing.T) {
	_, err := ReadAll(io.LimitReader(&endless{}, DefaultMaxBytes+1), "body", 0)
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("ReadAll with maxBytes 0 on DefaultMaxBytes+1 = %v, want ErrTooLarge", err)
	}
}

func TestReadTruncated_KeepsThePrefixAndSaysSo(t *testing.T) {
	got, truncated, err := ReadTruncated(strings.NewReader("abcdef"), 4)
	if err != nil || !truncated || string(got) != "abcd" {
		t.Fatalf("ReadTruncated = %q, %v, %v; want \"abcd\", true, nil", got, truncated, err)
	}
	got, truncated, err = ReadTruncated(strings.NewReader("abcd"), 4)
	if err != nil || truncated || string(got) != "abcd" {
		t.Fatalf("ReadTruncated at the cap = %q, %v, %v; want \"abcd\", false, nil", got, truncated, err)
	}
	src := &endless{}
	got, truncated, err = ReadTruncated(src, 100)
	if err != nil || !truncated || len(got) != 100 {
		t.Fatalf("ReadTruncated on an endless stream = %d bytes, %v, %v", len(got), truncated, err)
	}
}

type failing struct{}

func (failing) Read([]byte) (int, error) { return 0, errors.New("connection reset") }

func TestStreamReadErrorsAreWrapped(t *testing.T) {
	if _, err := ReadAll(failing{}, "body", 10); err == nil || !strings.Contains(err.Error(), "connection reset") {
		t.Fatalf("ReadAll error = %v, want the reader's error wrapped", err)
	}
	if _, _, err := ReadTruncated(failing{}, 10); err == nil || !strings.Contains(err.Error(), "connection reset") {
		t.Fatalf("ReadTruncated error = %v, want the reader's error wrapped", err)
	}
}
