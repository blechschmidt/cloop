package openai

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
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

func successHandler(content string, promptTokens, completionTokens int) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		resp := map[string]any{
			"choices": []map[string]any{
				{"message": map[string]string{"content": content}},
			},
			"usage": map[string]int{
				"prompt_tokens":     promptTokens,
				"completion_tokens": completionTokens,
			},
		}
		json.NewEncoder(w).Encode(resp)
	}
}

func TestComplete_Success(t *testing.T) {
	_, p := makeServer(t, successHandler("hi there", 12, 8))

	result, err := p.Complete(context.Background(), "say hi", provider.Options{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Output != "hi there" {
		t.Errorf("expected %q, got %q", "hi there", result.Output)
	}
	if result.InputTokens != 12 {
		t.Errorf("expected 12 input tokens, got %d", result.InputTokens)
	}
	if result.OutputTokens != 8 {
		t.Errorf("expected 8 output tokens, got %d", result.OutputTokens)
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
		capturedModel, _ = body["model"].(string)
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

	p.Complete(context.Background(), "prompt", provider.Options{Model: "gpt-4-turbo"})
	if capturedModel != "gpt-4-turbo" {
		t.Errorf("expected model %q, got %q", "gpt-4-turbo", capturedModel)
	}
}

func TestComplete_SendsSystemPromptAsSystemMessage(t *testing.T) {
	var capturedMessages []map[string]any
	_, p := makeServer(t, func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		if msgs, ok := body["messages"].([]any); ok {
			for _, m := range msgs {
				if msg, ok := m.(map[string]any); ok {
					capturedMessages = append(capturedMessages, msg)
				}
			}
		}
		successHandler("ok", 1, 1)(w, r)
	})

	p.Complete(context.Background(), "user prompt", provider.Options{SystemPrompt: "be concise"})
	if len(capturedMessages) < 2 {
		t.Fatalf("expected at least 2 messages (system + user), got %d", len(capturedMessages))
	}
	if capturedMessages[0]["role"] != "system" {
		t.Errorf("expected first message role %q, got %q", "system", capturedMessages[0]["role"])
	}
	if capturedMessages[0]["content"] != "be concise" {
		t.Errorf("expected system content %q, got %q", "be concise", capturedMessages[0]["content"])
	}
	if capturedMessages[1]["role"] != "user" {
		t.Errorf("expected second message role %q, got %q", "user", capturedMessages[1]["role"])
	}
}

func TestComplete_BearerAuthHeader(t *testing.T) {
	var capturedAuth string
	_, p := makeServer(t, func(w http.ResponseWriter, r *http.Request) {
		capturedAuth = r.Header.Get("Authorization")
		successHandler("ok", 1, 1)(w, r)
	})

	p.Complete(context.Background(), "prompt", provider.Options{})
	if capturedAuth != "Bearer test-api-key" {
		t.Errorf("expected auth header %q, got %q", "Bearer test-api-key", capturedAuth)
	}
}

func TestComplete_NoAPIKey(t *testing.T) {
	p := New("", "http://localhost:99999")
	p.APIKey = ""

	_, err := p.Complete(context.Background(), "prompt", provider.Options{})
	if err == nil {
		t.Error("expected error when API key is empty")
	}
}

func TestComplete_APIError(t *testing.T) {
	_, p := makeServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]any{
			"error": map[string]string{
				"type":    "invalid_api_key",
				"message": "Incorrect API key",
			},
		})
	})

	_, err := p.Complete(context.Background(), "prompt", provider.Options{})
	if err == nil {
		t.Error("expected error for API error response")
	}
	if !strings.Contains(err.Error(), "Incorrect API key") {
		t.Errorf("expected error message to contain %q, got %q", "Incorrect API key", err.Error())
	}
}

func TestComplete_EmptyChoices(t *testing.T) {
	_, p := makeServer(t, func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"choices": []any{},
		})
	})

	_, err := p.Complete(context.Background(), "prompt", provider.Options{})
	if err == nil {
		t.Error("expected error for empty choices")
	}
}

func TestComplete_ContextCancelled(t *testing.T) {
	_, p := makeServer(t, func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		successHandler("ok", 1, 1)(w, r)
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := p.Complete(ctx, "prompt", provider.Options{})
	if err == nil {
		t.Error("expected error for cancelled context")
	}
}

func TestComplete_MaxTokensPassedThrough(t *testing.T) {
	var capturedMaxTokens float64
	_, p := makeServer(t, func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		capturedMaxTokens, _ = body["max_tokens"].(float64)
		successHandler("ok", 1, 1)(w, r)
	})

	p.Complete(context.Background(), "prompt", provider.Options{MaxTokens: 512})
	if int(capturedMaxTokens) != 512 {
		t.Errorf("expected max_tokens 512, got %v", capturedMaxTokens)
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
