package reqid_test

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/reqid"
)

func TestGenerateProducesUniqueHexIDs(t *testing.T) {
	t.Parallel()
	seen := make(map[string]struct{}, 1024)
	for i := 0; i < 1024; i++ {
		id := reqid.Generate()
		if id == "" {
			t.Fatalf("Generate returned empty id")
		}
		if !reqid.IsValid(id) {
			t.Fatalf("Generate returned id %q that fails IsValid", id)
		}
		if _, dup := seen[id]; dup {
			t.Fatalf("Generate produced duplicate id %q after %d iterations", id, i)
		}
		seen[id] = struct{}{}
	}
}

func TestGenerateLengthIsHexEncodedOfLength(t *testing.T) {
	t.Parallel()
	id := reqid.Generate()
	if len(id) != reqid.Length*2 {
		t.Fatalf("Generate returned id of length %d, want %d", len(id), reqid.Length*2)
	}
}

func TestWithAndFromContextRoundTrip(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	if got := reqid.FromContext(ctx); got != "" {
		t.Fatalf("expected empty id from bare context, got %q", got)
	}
	ctx = reqid.WithContext(ctx, "abc-123")
	if got := reqid.FromContext(ctx); got != "abc-123" {
		t.Fatalf("FromContext = %q, want %q", got, "abc-123")
	}
}

func TestWithContextIgnoresEmpty(t *testing.T) {
	t.Parallel()
	ctx := reqid.WithContext(context.Background(), "abc")
	out := reqid.WithContext(ctx, "")
	if got := reqid.FromContext(out); got != "abc" {
		t.Fatalf("WithContext(\"\") should be a no-op; got %q", got)
	}
}

func TestWithContextHandlesNil(t *testing.T) {
	t.Parallel()
	//nolint:staticcheck // intentionally passing nil context to verify safety
	ctx := reqid.WithContext(nil, "abc")
	if got := reqid.FromContext(ctx); got != "abc" {
		t.Fatalf("expected nil context to be promoted to background; got %q", got)
	}
}

func TestIsValidAcceptsTypicalIDs(t *testing.T) {
	t.Parallel()
	good := []string{
		"abc",
		"x",
		"req-123",
		strings.Repeat("a", reqid.MaxLength),
		"6c4f8a3d2e1b9c7f8a3d2e1b",
	}
	for _, id := range good {
		if !reqid.IsValid(id) {
			t.Errorf("IsValid(%q) = false, want true", id)
		}
	}
}

func TestIsValidRejectsBadIDs(t *testing.T) {
	t.Parallel()
	bad := []string{
		"",
		"with space",
		"with\ttab",
		"with\nnewline",
		"with\x00null",
		strings.Repeat("a", reqid.MaxLength+1),
		"non-ascii-\xff",
	}
	for _, id := range bad {
		if reqid.IsValid(id) {
			t.Errorf("IsValid(%q) = true, want false", id)
		}
	}
}

func TestFromRequestParsesHeader(t *testing.T) {
	t.Parallel()
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set(reqid.HeaderName, "incoming-id")
	got, ok := reqid.FromRequest(r)
	if !ok {
		t.Fatalf("FromRequest ok=false for valid header")
	}
	if got != "incoming-id" {
		t.Fatalf("FromRequest = %q, want %q", got, "incoming-id")
	}
}

func TestFromRequestRejectsInvalidHeader(t *testing.T) {
	t.Parallel()
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set(reqid.HeaderName, strings.Repeat("a", reqid.MaxLength+1))
	if _, ok := reqid.FromRequest(r); ok {
		t.Fatalf("FromRequest accepted oversize header")
	}
}

func TestFromRequestEmptyWhenAbsent(t *testing.T) {
	t.Parallel()
	r := httptest.NewRequest("GET", "/", nil)
	if _, ok := reqid.FromRequest(r); ok {
		t.Fatalf("FromRequest ok=true for missing header")
	}
}

func TestFromRequestNilSafe(t *testing.T) {
	t.Parallel()
	if _, ok := reqid.FromRequest(nil); ok {
		t.Fatalf("FromRequest(nil) ok=true")
	}
}

func TestEnsureContextGeneratesWhenAbsent(t *testing.T) {
	t.Parallel()
	ctx, id := reqid.EnsureContext(context.Background())
	if id == "" {
		t.Fatalf("EnsureContext returned empty id")
	}
	if got := reqid.FromContext(ctx); got != id {
		t.Fatalf("EnsureContext: ctx id %q != returned id %q", got, id)
	}
}

func TestEnsureContextPreservesExisting(t *testing.T) {
	t.Parallel()
	ctx := reqid.WithContext(context.Background(), "preset")
	out, id := reqid.EnsureContext(ctx)
	if id != "preset" {
		t.Fatalf("EnsureContext lost existing id: got %q", id)
	}
	if reqid.FromContext(out) != "preset" {
		t.Fatalf("EnsureContext returned context without preset id")
	}
}
