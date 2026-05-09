package testgen

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
)

// stubProvider returns a fixed Go test code block and captures the prompt it
// received so the test can assert what artifact content was injected.
type stubProvider struct {
	lastPrompt string
}

func (s *stubProvider) Complete(_ context.Context, prompt string, _ provider.Options) (*provider.Result, error) {
	s.lastPrompt = prompt
	return &provider.Result{
		Output: "```go\npackage foo\n\nfunc TestStub(t *testing.T) {}\n```",
	}, nil
}

func (s *stubProvider) Name() string         { return "stub" }
func (s *stubProvider) DefaultModel() string { return "stub-1" }

// TestGenerate_OversizeArtifactDoesNotOOM verifies that a multi-MiB artifact
// file does not get fully read into memory and inflated into the AI prompt.
// Uses os.Truncate to create a 100 MiB sparse file in constant time — the
// previous os.ReadFile path would have allocated 100 MiB just to feed the AI.
func TestGenerate_OversizeArtifactDoesNotOOM(t *testing.T) {
	dir := t.TempDir()
	artifactRel := "artifact.md"
	artifactAbs := filepath.Join(dir, artifactRel)
	f, err := os.Create(artifactAbs)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	f.Close()
	if err := os.Truncate(artifactAbs, 100<<20); err != nil {
		t.Fatalf("truncate: %v", err)
	}

	task := &pm.Task{
		ID:           7,
		Title:        "do thing",
		Description:  "do the thing",
		ArtifactPath: artifactRel,
	}

	prov := &stubProvider{}
	res, err := Generate(context.Background(), prov, provider.Options{}, dir, task, LangGo)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if res == nil || res.Code == "" {
		t.Fatalf("unexpected empty result")
	}
	// The prompt must NOT contain a giant artifact body. The skip path treats
	// oversize artifacts as missing, so the prompt should reflect that.
	if len(prov.lastPrompt) > 1<<20 {
		t.Fatalf("prompt unexpectedly large (%d bytes) — oversize artifact slipped through cap", len(prov.lastPrompt))
	}
}

// TestGenerate_MissingArtifactStillSucceeds verifies that the prior contract
// (missing artifact = silent skip, generation still proceeds) is preserved.
func TestGenerate_MissingArtifactStillSucceeds(t *testing.T) {
	dir := t.TempDir()
	task := &pm.Task{
		ID:           7,
		Title:        "do thing",
		Description:  "do the thing",
		ArtifactPath: "does-not-exist.md",
	}
	res, err := Generate(context.Background(), &stubProvider{}, provider.Options{}, dir, task, LangGo)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if res == nil || !strings.Contains(res.Code, "TestStub") {
		t.Fatalf("expected stub code in result, got %+v", res)
	}
}

// TestGenerate_SmallArtifactInjected verifies the happy path: a small
// artifact's bytes show up in the AI prompt.
func TestGenerate_SmallArtifactInjected(t *testing.T) {
	dir := t.TempDir()
	artifactRel := "artifact.md"
	body := "the answer is 42"
	if err := os.WriteFile(filepath.Join(dir, artifactRel), []byte(body), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	task := &pm.Task{
		ID:           7,
		Title:        "do thing",
		Description:  "do the thing",
		ArtifactPath: artifactRel,
	}
	prov := &stubProvider{}
	if _, err := Generate(context.Background(), prov, provider.Options{}, dir, task, LangGo); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if !strings.Contains(prov.lastPrompt, body) {
		t.Fatalf("prompt missing artifact body")
	}
}
