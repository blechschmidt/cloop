package ollama

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
	p := New(srv.URL)
	return srv, p
}

func successHandler(content string, promptEval, eval int) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		resp := map[string]any{
			"message": map[string]string{
				"role":    "assistant",
				"content": content,
			},
			"done":              true,
			"prompt_eval_count": promptEval,
			"eval_count":        eval,
		}
		json.NewEncoder(w).Encode(resp)
	}
}

func TestComplete_Success(t *testing.T) {
	_, p := makeServer(t, successHandler("great response", 20, 15))

	result, err := p.Complete(context.Background(), "hello", provider.Options{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Output != "great response" {
		t.Errorf("expected %q, got %q", "great response", result.Output)
	}
	if result.InputTokens != 20 {
		t.Errorf("expected 20 input tokens, got %d", result.InputTokens)
	}
	if result.OutputTokens != 15 {
		t.Errorf("expected 15 output tokens, got %d", result.OutputTokens)
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

	p.Complete(context.Background(), "prompt", provider.Options{Model: "mistral"})
	if capturedModel != "mistral" {
		t.Errorf("expected model %q, got %q", "mistral", capturedModel)
	}
}

func TestComplete_StreamFalse(t *testing.T) {
	var capturedStream any
	_, p := makeServer(t, func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		capturedStream = body["stream"]
		successHandler("ok", 1, 1)(w, r)
	})

	p.Complete(context.Background(), "prompt", provider.Options{})
	if capturedStream != false {
		t.Errorf("expected stream=false, got %v", capturedStream)
	}
}

func TestComplete_SendsSystemPrompt(t *testing.T) {
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

	p.Complete(context.Background(), "user prompt", provider.Options{SystemPrompt: "be brief"})
	if len(capturedMessages) < 2 {
		t.Fatalf("expected at least 2 messages, got %d", len(capturedMessages))
	}
	if capturedMessages[0]["role"] != "system" {
		t.Errorf("expected system role, got %q", capturedMessages[0]["role"])
	}
	if capturedMessages[0]["content"] != "be brief" {
		t.Errorf("expected system content %q, got %q", "be brief", capturedMessages[0]["content"])
	}
}

func TestComplete_MaxTokens(t *testing.T) {
	var capturedOptions map[string]any
	_, p := makeServer(t, func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		if opts, ok := body["options"].(map[string]any); ok {
			capturedOptions = opts
		}
		successHandler("ok", 1, 1)(w, r)
	})

	p.Complete(context.Background(), "prompt", provider.Options{MaxTokens: 256})
	if capturedOptions == nil {
		t.Fatal("expected options to be set for max_tokens")
	}
	if int(capturedOptions["num_predict"].(float64)) != 256 {
		t.Errorf("expected num_predict=256, got %v", capturedOptions["num_predict"])
	}
}

func TestComplete_NoMaxTokens_NoOptions(t *testing.T) {
	var bodyRaw map[string]any
	_, p := makeServer(t, func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&bodyRaw)
		successHandler("ok", 1, 1)(w, r)
	})

	p.Complete(context.Background(), "prompt", provider.Options{})
	if _, ok := bodyRaw["options"]; ok {
		t.Error("expected options to be omitted when MaxTokens is 0")
	}
}

func TestComplete_ErrorResponse(t *testing.T) {
	_, p := makeServer(t, func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"error": "model not found",
		})
	})

	_, err := p.Complete(context.Background(), "prompt", provider.Options{})
	if err == nil {
		t.Error("expected error for error response")
	}
	if !strings.Contains(err.Error(), "model not found") {
		t.Errorf("expected error to contain %q, got %q", "model not found", err.Error())
	}
}

func TestComplete_HTTP500(t *testing.T) {
	_, p := makeServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]any{"error": ""})
	})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err := p.Complete(ctx, "prompt", provider.Options{})
	if err == nil {
		t.Error("expected error for 500 response")
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

func TestName(t *testing.T) {
	p := New("")
	if p.Name() != ProviderName {
		t.Errorf("expected %q, got %q", ProviderName, p.Name())
	}
}

func TestDefaultModel(t *testing.T) {
	p := New("")
	if p.DefaultModel() != DefaultModel {
		t.Errorf("expected %q, got %q", DefaultModel, p.DefaultModel())
	}
}

func TestNew_DefaultBaseURL(t *testing.T) {
	p := New("")
	if p.BaseURL != defaultBaseURL {
		t.Errorf("expected default base URL %q, got %q", defaultBaseURL, p.BaseURL)
	}
}

func TestNew_CustomBaseURL(t *testing.T) {
	p := New("http://custom:11434")
	if p.BaseURL != "http://custom:11434" {
		t.Errorf("expected custom base URL, got %q", p.BaseURL)
	}
}
