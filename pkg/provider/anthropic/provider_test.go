package anthropic

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/provider"
)

func makeServer(t *testing.T, handler http.HandlerFunc) (*httptest.Server, *Provider) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	p := New("test-api-key", srv.URL)
	return srv, p
}

func successHandler(output string, inputTokens, outputTokens int) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		resp := map[string]any{
			"content": []map[string]any{
				{"type": "text", "text": output},
			},
			"usage": map[string]int{
				"input_tokens":  inputTokens,
				"output_tokens": outputTokens,
			},
		}
		json.NewEncoder(w).Encode(resp)
	}
}

func TestComplete_Success(t *testing.T) {
	_, p := makeServer(t, successHandler("hello world", 10, 5))

	result, err := p.Complete(context.Background(), "say hello", provider.Options{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Output != "hello world" {
		t.Errorf("expected %q, got %q", "hello world", result.Output)
	}
	if result.InputTokens != 10 {
		t.Errorf("expected 10 input tokens, got %d", result.InputTokens)
	}
	if result.OutputTokens != 5 {
		t.Errorf("expected 5 output tokens, got %d", result.OutputTokens)
	}
	if result.Provider != ProviderName {
		t.Errorf("expected provider %q, got %q", ProviderName, result.Provider)
	}
	if result.Duration <= 0 {
		t.Error("expected positive duration")
	}
}

func TestComplete_UsesDefaultModel(t *testing.T) {
	var capturedModel string
	_, p := makeServer(t, func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		if m, ok := body["model"].(string); ok {
			capturedModel = m
		}
		successHandler("ok", 1, 1)(w, r)
	})

	p.Complete(context.Background(), "prompt", provider.Options{})
	if capturedModel != DefaultModel {
		t.Errorf("expected default model %q, got %q", DefaultModel, capturedModel)
	}
}

func TestComplete_UsesSpecifiedModel(t *testing.T) {
	var capturedModel string
	_, p := makeServer(t, func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		capturedModel, _ = body["model"].(string)
		successHandler("ok", 1, 1)(w, r)
	})

	p.Complete(context.Background(), "prompt", provider.Options{Model: "claude-haiku-4-5"})
	if capturedModel != "claude-haiku-4-5" {
		t.Errorf("expected model %q, got %q", "claude-haiku-4-5", capturedModel)
	}
}

func TestComplete_SendsSystemPrompt(t *testing.T) {
	var capturedSystem string
	_, p := makeServer(t, func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		capturedSystem, _ = body["system"].(string)
		successHandler("ok", 1, 1)(w, r)
	})

	p.Complete(context.Background(), "prompt", provider.Options{SystemPrompt: "be helpful"})
	if capturedSystem != "be helpful" {
		t.Errorf("expected system prompt %q, got %q", "be helpful", capturedSystem)
	}
}

func TestComplete_NoSystemPromptOmitted(t *testing.T) {
	var bodyRaw map[string]any
	_, p := makeServer(t, func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&bodyRaw)
		successHandler("ok", 1, 1)(w, r)
	})

	p.Complete(context.Background(), "prompt", provider.Options{})
	if _, ok := bodyRaw["system"]; ok {
		t.Error("expected system field to be omitted when SystemPrompt is empty")
	}
}

func TestComplete_APIError(t *testing.T) {
	_, p := makeServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]any{
			"error": map[string]string{
				"type":    "invalid_request_error",
				"message": "bad request",
			},
		})
	})

	_, err := p.Complete(context.Background(), "prompt", provider.Options{})
	if err == nil {
		t.Error("expected error for API error response")
	}
}

func TestComplete_HTTP500_NoRetry(t *testing.T) {
	calls := 0
	_, p := makeServer(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error":{"type":"server_error","message":"internal error"}}`))
	})

	// Use short timeout to avoid long retry waits
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err := p.Complete(ctx, "prompt", provider.Options{})
	if err == nil {
		t.Error("expected error for 500 response")
	}
	// Should retry on 500 (up to RetryConfig defaults: 3 attempts)
	if calls < 1 {
		t.Errorf("expected at least 1 call, got %d", calls)
	}
}

func TestComplete_NoAPIKey(t *testing.T) {
	p := New("", "http://localhost:99999")
	p.APIKey = "" // ensure empty

	_, err := p.Complete(context.Background(), "prompt", provider.Options{})
	if err == nil {
		t.Error("expected error when API key is empty")
	}
}

func TestComplete_AuthHeader(t *testing.T) {
	var capturedKey string
	_, p := makeServer(t, func(w http.ResponseWriter, r *http.Request) {
		capturedKey = r.Header.Get("x-api-key")
		successHandler("ok", 1, 1)(w, r)
	})

	p.Complete(context.Background(), "prompt", provider.Options{})
	if capturedKey != "test-api-key" {
		t.Errorf("expected x-api-key %q, got %q", "test-api-key", capturedKey)
	}
}

func TestComplete_AnthropicVersionHeader(t *testing.T) {
	var capturedVersion string
	_, p := makeServer(t, func(w http.ResponseWriter, r *http.Request) {
		capturedVersion = r.Header.Get("anthropic-version")
		successHandler("ok", 1, 1)(w, r)
	})

	p.Complete(context.Background(), "prompt", provider.Options{})
	if capturedVersion != apiVersion {
		t.Errorf("expected anthropic-version %q, got %q", apiVersion, capturedVersion)
	}
}

func TestComplete_ContextCancelled(t *testing.T) {
	_, p := makeServer(t, func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		successHandler("ok", 1, 1)(w, r)
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	_, err := p.Complete(ctx, "prompt", provider.Options{})
	if err == nil {
		t.Error("expected error for cancelled context")
	}
}

func TestName(t *testing.T) {
	p := New("key", "")
	if p.Name() != ProviderName {
		t.Errorf("expected %q, got %q", ProviderName, p.Name())
	}
}

func TestDefaultModel(t *testing.T) {
	p := New("key", "")
	if p.DefaultModel() != DefaultModel {
		t.Errorf("expected %q, got %q", DefaultModel, p.DefaultModel())
	}
}

func TestNew_DefaultBaseURL(t *testing.T) {
	p := New("key", "")
	if p.BaseURL != defaultBaseURL {
		t.Errorf("expected default base URL %q, got %q", defaultBaseURL, p.BaseURL)
	}
}

func TestComplete_MultipleContentBlocks(t *testing.T) {
	_, p := makeServer(t, func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]any{
			"content": []map[string]any{
				{"type": "text", "text": "hello "},
				{"type": "text", "text": "world"},
				{"type": "tool_use", "text": "ignored"},
			},
			"usage": map[string]int{"input_tokens": 5, "output_tokens": 3},
		}
		json.NewEncoder(w).Encode(resp)
	})

	result, err := p.Complete(context.Background(), "prompt", provider.Options{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Output != "hello world" {
		t.Errorf("expected concatenated text blocks, got %q", result.Output)
	}
}
