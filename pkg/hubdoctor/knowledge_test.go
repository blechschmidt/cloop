package hubdoctor

// The knowledge embeddings check (Task 20471).

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

func embeddingFindings(t *testing.T, dir string, cfg *config.Config) map[string][]Finding {
	t.Helper()
	out := map[string][]Finding{}
	checkKnowledgeEmbeddings(dir, cfg, func(f Finding) {
		if f.Severity != SeverityPass && f.Remediation == "" {
			t.Errorf("%s is %s without a remediation: %s", f.Check, f.Severity, f.Message)
		}
		out[f.Check] = append(out[f.Check], f)
	})
	return out
}

func embeddingsOn(endpoint string) *config.Config {
	cfg := config.Default()
	cfg.Knowledge.Embeddings = config.EmbeddingsConfig{Enabled: true, Provider: "openai", Endpoint: endpoint,
		Model: "text-embedding-3-small", Dimensions: 1536}
	return cfg
}

// TestKnowledgeEmbeddingsFindings: off is a pass saying nothing leaves the
// hub; on is always a finding naming the endpoint the text is sent to; plain
// http beyond loopback is a warning; a section refused at load and a key the
// store cannot provide fail; and the syncs whose last pass could not embed are
// listed.
func TestKnowledgeEmbeddingsFindings(t *testing.T) {
	dir := t.TempDir()
	dbPath := mustInitStateDB(t, dir)

	t.Run("off", func(t *testing.T) {
		f := embeddingFindings(t, dir, config.Default())["knowledge.embeddings"]
		if len(f) != 1 || f[0].Severity != SeverityPass || !strings.Contains(f[0].Message, "no chunk text") {
			t.Fatalf("off: %+v", f)
		}
	})

	t.Run("on names the endpoint", func(t *testing.T) {
		got := embeddingFindings(t, dir, embeddingsOn("https://api.openai.com/v1"))
		f := got["knowledge.embeddings"]
		if len(f) != 1 || f[0].Severity != SeverityPass {
			t.Fatalf("on: %+v", got)
		}
		for _, want := range []string{"https://api.openai.com/v1", "every search query", "text-embedding-3-small", "1536",
			"0 of the 0 chunks"} {
			if !strings.Contains(f[0].Message, want) {
				t.Errorf("the finding %q does not say %q", f[0].Message, want)
			}
		}
		if f[0].Details["endpoint"] != "https://api.openai.com/v1" {
			t.Errorf("details = %v", f[0].Details)
		}
	})

	t.Run("the endpoint's query is not shown", func(t *testing.T) {
		f := embeddingFindings(t, dir, embeddingsOn("https://corp.openai.azure.com/openai/deployments/emb?api-version=2024-10-21"))["knowledge.embeddings"]
		if len(f) != 1 || strings.Contains(f[0].Message, "api-version") ||
			!strings.Contains(f[0].Message, "https://corp.openai.azure.com/openai/deployments/emb") {
			t.Fatalf("azure: %+v", f)
		}
	})

	t.Run("plaintext beyond loopback", func(t *testing.T) {
		f := embeddingFindings(t, dir, embeddingsOn("http://vllm.ml.svc:8000/v1"))["knowledge.embeddings"]
		if len(f) != 1 || f[0].Severity != SeverityWarn || !strings.Contains(f[0].Message, "unencrypted") ||
			!strings.Contains(f[0].Message, "http://vllm.ml.svc:8000/v1") {
			t.Fatalf("plain http: %+v", f)
		}
		for _, local := range []string{"http://localhost:11434/v1", "http://127.0.0.1:11434/v1", "http://[::1]:8000/v1"} {
			if f := embeddingFindings(t, dir, embeddingsOn(local))["knowledge.embeddings"]; len(f) != 1 || f[0].Severity != SeverityPass {
				t.Fatalf("%s: %+v", local, f)
			}
		}
	})

	t.Run("refused at load", func(t *testing.T) {
		cdir := t.TempDir()
		if err := os.MkdirAll(filepath.Join(cdir, ".cloop"), 0o755); err != nil {
			t.Fatal(err)
		}
		yaml := "knowledge:\n  embeddings:\n    enabled: true\n    provider: openai\n    model: m\n    dimensions: 8\n"
		if err := os.WriteFile(config.ConfigPath(cdir), []byte(yaml), 0o600); err != nil {
			t.Fatal(err)
		}
		cfg, err := config.Load(cdir)
		if err != nil {
			t.Fatal(err)
		}
		if cfg.Knowledge.Embeddings.Enabled {
			t.Fatal("a section without an endpoint loaded enabled")
		}
		f := embeddingFindings(t, cdir, cfg)["knowledge.embeddings"]
		if len(f) != 1 || f[0].Severity != SeverityFail || !strings.Contains(f[0].Message, "endpoint is required") {
			t.Fatalf("refused: %+v", f)
		}
		var repaired []Finding
		checkLoadRepairs(cfg, func(f Finding) { repaired = append(repaired, f) })
		if len(repaired) != 0 {
			t.Errorf("the switch-off was reported twice: %+v", repaired)
		}
	})

	t.Run("a key the store does not hold", func(t *testing.T) {
		t.Setenv("CLOOP_SECRET_KEY", "hubdoctor-embeddings-test-key-0123456789abcdef")
		cfg := embeddingsOn("https://api.openai.com/v1")
		cfg.Knowledge.Embeddings.SecretRef = "openai-embeddings"
		f := embeddingFindings(t, dir, cfg)["knowledge.embeddings.secret"]
		if len(f) != 1 || f[0].Severity != SeverityFail || !strings.Contains(f[0].Message, "openai-embeddings") {
			t.Fatalf("a missing key: %+v", f)
		}
	})

	t.Run("syncs that could not embed", func(t *testing.T) {
		db, err := statedb.Open(dbPath)
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()
		src, err := db.CreateKnowledgeSource(statedb.KnowledgeSourceRow{Kind: "confluence", Name: "Wiki", Scope: "org",
			Config: `{}`, Enabled: true}, "admin@corp.example")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.IndexKnowledgeDocument(statedb.KnowledgeDocumentRow{SourceID: src.ID, ExternalID: "p1", Title: "Page",
			ContentHash: "h1"}, func() ([]statedb.KnowledgeChunk, bool) {
			return []statedb.KnowledgeChunk{{Text: "one"}, {Text: "two"}}, false
		}); err != nil {
			t.Fatal(err)
		}
		if err := db.RecordKnowledgeSyncOutcome(src.ID, statedb.KnowledgeSyncOutcome{Status: "ok",
			Report: `{"warning":"embeddings: https://api.openai.com/v1 failed: HTTP 503"}`}); err != nil {
			t.Fatal(err)
		}
		got := embeddingFindings(t, dir, embeddingsOn("https://api.openai.com/v1"))
		if f := got["knowledge.embeddings.sync"]; len(f) != 1 || f[0].Severity != SeverityWarn ||
			!strings.Contains(f[0].Message, "Wiki") || !strings.Contains(f[0].Message, "HTTP 503") {
			t.Fatalf("a sync that could not embed: %+v", got)
		}
		if f := got["knowledge.embeddings"]; len(f) != 1 || !strings.Contains(f[0].Message, "0 of the 2 chunks") {
			t.Fatalf("coverage: %+v", f)
		}
	})

	// And it is one of the doctor's steps, under its own id.
	found := false
	for _, s := range steps(dir, config.Default(), Options{}, walSample{}, &Report{}, stepSet{}) {
		if s.id == "knowledge.embeddings" {
			found = true
			s.run(context.Background(), func(Finding) {})
		}
	}
	if !found {
		t.Fatal("the knowledge.embeddings step is not in the doctor's list")
	}
}
