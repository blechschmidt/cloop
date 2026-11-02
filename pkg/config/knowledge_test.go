package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestEmbeddingsConfig is the rule knowledge.embeddings is held to at load and
// by `cloop config validate` (Task 20471): off by default and checked only for
// a key written into it; on, a named endpoint, a model and its dimensions, no
// credential in the file, never a metadata service; and a section that fails
// is switched off at load, recorded, with the key dropped.
func TestEmbeddingsConfig(t *testing.T) {
	if Default().Knowledge.Embeddings.Enabled {
		t.Fatal("embeddings are on by default")
	}
	on := func(mod func(*EmbeddingsConfig)) EmbeddingsConfig {
		e := EmbeddingsConfig{Enabled: true, Provider: "openai", Endpoint: "https://api.openai.com/v1",
			Model: "text-embedding-3-small", Dimensions: 1536}
		if mod != nil {
			mod(&e)
		}
		return e
	}
	for name, e := range map[string]EmbeddingsConfig{
		"openai": on(nil),
		"azure": on(func(e *EmbeddingsConfig) {
			e.Endpoint = "https://corp.openai.azure.com/openai/deployments/emb?api-version=2024-10-21"
		}),
		"ollama": on(func(e *EmbeddingsConfig) {
			e.Endpoint, e.Model, e.Dimensions = "http://localhost:11434/v1", "nomic-embed-text:latest", 768
		}),
		"vllm": on(func(e *EmbeddingsConfig) { e.Endpoint, e.Model = "http://vllm.ml.svc:8000/v1", "BAAI/bge-m3" }),
		"voyage": on(func(e *EmbeddingsConfig) {
			e.Provider, e.Endpoint, e.Model, e.Dimensions = "Voyage", "", "voyage-3.5", 1024
		}),
		"knobs": on(func(e *EmbeddingsConfig) {
			e.SecretRef, e.Auth, e.BatchSize, e.Timeout, e.MaxCandidates = "openai#KEY", "bearer", 128, "45s", 200000
		}),
		"off garbage": {Provider: "nonsense", Dimensions: -1},
	} {
		if err := ValidateEmbeddings(e); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, tc := range map[string]struct {
		e    EmbeddingsConfig
		want string
	}{
		"no provider":      {on(func(e *EmbeddingsConfig) { e.Provider = "" }), "provider is required"},
		"other provider":   {on(func(e *EmbeddingsConfig) { e.Provider = "cohere" }), "is not openai"},
		"no endpoint":      {on(func(e *EmbeddingsConfig) { e.Endpoint = "" }), "endpoint is required"},
		"not http":         {on(func(e *EmbeddingsConfig) { e.Endpoint = "ftp://example.com/v1" }), "not an http(s) URL"},
		"userinfo":         {on(func(e *EmbeddingsConfig) { e.Endpoint = "https://u:sk-x@api.openai.com/v1" }), "user name or password"},
		"key in the query": {on(func(e *EmbeddingsConfig) { e.Endpoint = "https://corp.openai.azure.com/x?api-key=abc" }), "reads as a credential"},
		"metadata":         {on(func(e *EmbeddingsConfig) { e.Endpoint = "http://169.254.169.254/v1" }), "metadata service"},
		"no model":         {on(func(e *EmbeddingsConfig) { e.Model = "" }), "model is required"},
		"spaced model":     {on(func(e *EmbeddingsConfig) { e.Model = "text embedding" }), "space or control"},
		"no dimensions":    {on(func(e *EmbeddingsConfig) { e.Dimensions = 0 }), "dimensions is 0"},
		"huge dimensions":  {on(func(e *EmbeddingsConfig) { e.Dimensions = 100000 }), "from 1 to 8192"},
		"secret ref":       {on(func(e *EmbeddingsConfig) { e.SecretRef = "bad name!" }), "secret_ref"},
		"auth":             {on(func(e *EmbeddingsConfig) { e.Auth = "basic" }), "not bearer or api-key"},
		"batch":            {on(func(e *EmbeddingsConfig) { e.BatchSize = 10000 }), "batch_size"},
		"timeout":          {on(func(e *EmbeddingsConfig) { e.Timeout = "1h" }), "timeout"},
		"candidates":       {on(func(e *EmbeddingsConfig) { e.MaxCandidates = 10 }), "max_candidates"},
		"inline key":       {on(func(e *EmbeddingsConfig) { e.APIKey = "sk-abc" }), "never belongs in the configuration"},
		"inline key, off":  {EmbeddingsConfig{APIKey: "sk-abc"}, "secret_ref"},
	} {
		err := ValidateEmbeddings(tc.e)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want an error saying %q", name, err, tc.want)
		}
		if err != nil && strings.Contains(err.Error(), "sk-abc") {
			t.Errorf("%s: the error repeats the key: %v", name, err)
		}
	}

	// What the effective values are.
	e := on(nil)
	if e.EffectiveAuth() != EmbeddingsAuthBearer || e.EffectiveBatchSize() != EmbeddingsBatchSizeDefault ||
		e.EffectiveTimeout() != EmbeddingsTimeoutDefault || e.EffectiveMaxCandidates() != EmbeddingsMaxCandidatesDefault {
		t.Fatalf("defaults: %s %d %s %d", e.EffectiveAuth(), e.EffectiveBatchSize(), e.EffectiveTimeout(), e.EffectiveMaxCandidates())
	}
	e = on(func(e *EmbeddingsConfig) { e.Timeout, e.BatchSize = "2m", 16 })
	if e.EffectiveTimeout() != 2*time.Minute || e.EffectiveBatchSize() != 16 {
		t.Fatalf("set: %s %d", e.EffectiveTimeout(), e.EffectiveBatchSize())
	}
	azure := on(func(e *EmbeddingsConfig) {
		e.Endpoint = "https://corp.openai.azure.com/openai/deployments/emb?api-version=2024-10-21"
	})
	if azure.EffectiveAuth() != EmbeddingsAuthAPIKey || azure.EndpointDisplay() != "https://corp.openai.azure.com/openai/deployments/emb" {
		t.Fatalf("azure: %s %s", azure.EffectiveAuth(), azure.EndpointDisplay())
	}
	if v := on(func(e *EmbeddingsConfig) { e.Provider, e.Endpoint = "voyage", "" }); v.EffectiveEndpoint() != EmbeddingsVoyageEndpoint {
		t.Fatalf("voyage endpoint = %q", v.EffectiveEndpoint())
	}
	for endpoint, plain := range map[string]bool{
		"https://api.openai.com/v1": false, "http://localhost:11434/v1": false, "http://127.0.0.1:8000/v1": false,
		"http://[::1]:8000/v1": false, "http://vllm.ml.svc:8000/v1": true, "http://10.0.0.7:8000/v1": true,
	} {
		if got := on(func(e *EmbeddingsConfig) { e.Endpoint = endpoint }).PlaintextBeyondLoopback(); got != plain {
			t.Errorf("PlaintextBeyondLoopback(%s) = %v", endpoint, got)
		}
	}

	// Load: a section that fails is switched off and recorded; one that
	// loads stays on.
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".cloop"), 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(yaml string) *Config {
		t.Helper()
		if err := os.WriteFile(ConfigPath(dir), []byte(yaml), 0o600); err != nil {
			t.Fatal(err)
		}
		cfg, err := Load(dir)
		if err != nil {
			t.Fatal(err)
		}
		return cfg
	}
	cfg := write("knowledge:\n  embeddings:\n    enabled: true\n    provider: openai\n    endpoint: http://localhost:11434/v1\n" +
		"    model: nomic-embed-text\n    dimensions: 768\n")
	if !cfg.Knowledge.Embeddings.Enabled || cfg.Knowledge.Embeddings.Dimensions != 768 || len(cfg.LoadRepairs()) != 0 {
		t.Fatalf("a valid section: %+v, repairs %+v", cfg.Knowledge.Embeddings, cfg.LoadRepairs())
	}
	cfg = write("knowledge:\n  embeddings:\n    enabled: true\n    provider: openai\n    endpoint: https://api.openai.com/v1\n" +
		"    model: text-embedding-3-small\n    dimensions: 1536\n    api_key: sk-proj-0123456789abcdef0123\n")
	if cfg.Knowledge.Embeddings.Enabled || cfg.Knowledge.Embeddings.APIKey != "" {
		t.Fatalf("a section with a key loaded as %+v", cfg.Knowledge.Embeddings)
	}
	var off LoadRepair
	for _, r := range cfg.LoadRepairs() {
		if r.SwitchedOff == "knowledge.embeddings" {
			off = r
		}
	}
	if !strings.Contains(off.Detail, "api_key") || strings.Contains(off.Detail, "sk-proj") {
		t.Fatalf("the switch-off = %+v", off)
	}
	if err := cfg.ValidateNumeric(); err != nil {
		t.Fatalf("the repaired config does not validate: %v", err)
	}
}
