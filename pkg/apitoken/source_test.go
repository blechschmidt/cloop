package apitoken

// Source-reading helpers for the assertions that are about *how* the code is
// written rather than what it returns — see
// TestVerifyHashUsesConstantTimeComparison for why a timing property is pinned
// this way instead of measured.

import (
	"os"
	"strings"
	"testing"
)

func readPackageSource(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(name)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(b)
}

// functionBody returns the text from the declaration starting with decl up to
// the closing brace at column 0, which is where gofmt always puts it.
func functionBody(t *testing.T, src, decl string) string {
	t.Helper()
	start := strings.Index(src, decl)
	if start < 0 {
		t.Fatalf("declaration %q not found — did the function get renamed?", decl)
	}
	rest := src[start:]
	if end := strings.Index(rest, "\n}\n"); end > 0 {
		return rest[:end]
	}
	return rest
}
