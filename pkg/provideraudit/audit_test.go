package provideraudit

import (
	"context"
	"errors"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/internal/hometest"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/redact/redacttest"
	"github.com/blechschmidt/cloop/pkg/state"
)

func TestMain(m *testing.M) {
	os.Exit(hometest.Isolate(m))
}

// TestRedactErrorMessageKeepsTheKindAndDropsTheValue pins this package's
// replacement style, which is what stays its own now that the shapes come
// from pkg/redact: the public lead of the credential survives so a reader can
// tell which key the provider rejected, and nothing of the value does.
func TestRedactErrorMessageKeepsTheKindAndDropsTheValue(t *testing.T) {
	r := rand.New(rand.NewPCG(20368, 9))
	ghs := redacttest.GitHubLongFormToken(r, "ghs_", 0)
	key := "sk-ant-api03-" + strings.Repeat("aB3-", 23) + "AA"

	for _, tc := range []struct{ name, in, want string }{
		{"anthropic key",
			"anthropic: 401 invalid x-api-key " + key,
			"anthropic: 401 invalid x-api-key sk-ant-api03-[REDACTED]"},
		{"bearer value keeps its scheme",
			"Authorization: Bearer abcdef0123456789 rejected",
			"Authorization: Bearer [REDACTED] rejected"},
		{"long-form GitHub token from a tool error",
			"tool: gh api failed with " + ghs + " (403)",
			"tool: gh api failed with ghs_[REDACTED] (403)"},
		{"credentials in a URL",
			"git push https://x-access-token:" + ghs + "@github.com/acme/w.git: 403",
			"git push https://[REDACTED]@github.com/acme/w.git: 403"},
		// The old bearer pattern rewrote any word after "bearer", so this
		// became "invalid Bearer [REDACTED]" — losing the one word of the
		// diagnostic that said what was wrong.
		{"prose is not a credential",
			"invalid bearer token",
			"invalid bearer token"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := RedactErrorMessage(tc.in); got != tc.want {
				t.Errorf("RedactErrorMessage:\n  got %q\n want %q", got, tc.want)
			}
		})
	}
}

type failingProvider struct{ err error }

func (p failingProvider) Name() string         { return "failing" }
func (p failingProvider) DefaultModel() string { return "test" }
func (p failingProvider) Complete(context.Context, string, provider.Options) (*provider.Result, error) {
	return nil, p.err
}

// TestWithAuditStoresOnlyTheRedactedError drives the real wrapper into a real
// project database and reads the row back, because the property is about what
// is stored: the caller still gets the original error — redaction is for the
// copy that outlives the call.
func TestWithAuditStoresOnlyTheRedactedError(t *testing.T) {
	workDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(workDir, ".cloop"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := state.Init(workDir, "provider audit redaction", 0); err != nil {
		t.Fatalf("state.Init: %v", err)
	}

	r := rand.New(rand.NewPCG(20368, 10))
	ghs := redacttest.GitHubLongFormToken(r, "ghs_", 0)
	cause := errors.New("tool call failed: git push https://x-access-token:" + ghs + "@github.com/acme/widgets.git: 403")

	_, err := WithAudit(failingProvider{err: cause}).Complete(context.Background(), "push it",
		provider.Options{WorkDir: workDir})
	if !errors.Is(err, cause) {
		t.Fatalf("the caller must get the provider's own error back, got %v", err)
	}

	rows, _, lerr := state.ListProviderCalls(workDir, 0, 10, 0, "")
	if lerr != nil {
		t.Fatalf("ListProviderCalls: %v", lerr)
	}
	if len(rows) != 1 {
		t.Fatalf("got %d stored calls, want 1; the assertion below would be vacuous", len(rows))
	}
	stored := rows[0].ErrorMessage
	if strings.Contains(stored, ghs) {
		t.Fatalf("the stored error carries the installation token:\n%s", stored)
	}
	if want := "git push https://[REDACTED]@github.com/acme/widgets.git: 403"; !strings.Contains(stored, want) {
		t.Errorf("stored error %q lost its diagnostic; want it to contain %q", stored, want)
	}
}
