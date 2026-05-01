// Package ollama provides access to locally running Ollama models.
package ollama

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/blechschmidt/cloop/pkg/provider"
)

const (
	ProviderName   = "ollama"
	DefaultModel   = "llama3.2"
	defaultBaseURL = "http://localhost:11434"
)

type Provider struct {
	BaseURL string
	client  *http.Client
}

func New(baseURL string) *Provider {
	if baseURL == "" {
		baseURL = defaultBaseURL
	}
	return &Provider{
		BaseURL: baseURL,
		client:  &http.Client{},
	}
}

func (p *Provider) Name() string         { return ProviderName }
func (p *Provider) DefaultModel() string { return DefaultModel }

type ollamaMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type requestBody struct {
	Model    string          `json:"model"`
	Messages []ollamaMessage `json:"messages"`
	Stream   bool            `json:"stream"`
	Options  *ollamaOptions  `json:"options,omitempty"`
}

type ollamaOptions struct {
	NumPredict int `json:"num_predict,omitempty"`
}

type responseBody struct {
	Message struct {
		Role    string `json:"role"`
		Content string `json:"content"`
	} `json:"message"`
	Error           string `json:"error"`
	Done            bool   `json:"done"`
	PromptEvalCount int    `json:"prompt_eval_count"`
	EvalCount       int    `json:"eval_count"`
}

func (p *Provider) Complete(ctx context.Context, prompt string, opts provider.Options) (*provider.Result, error) {
	model := opts.Model
	if model == "" {
		model = DefaultModel
	}

	timeout := opts.Timeout
	if timeout == 0 {
		timeout = 10 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	messages := []ollamaMessage{}
	if opts.SystemPrompt != "" {
		messages = append(messages, ollamaMessage{Role: "system", Content: opts.SystemPrompt})
	}
	messages = append(messages, ollamaMessage{Role: "user", Content: prompt})

	reqBody := requestBody{
		Model:    model,
		Messages: messages,
		Stream:   false,
	}
	if opts.MaxTokens > 0 {
		reqBody.Options = &ollamaOptions{NumPredict: opts.MaxTokens}
	}

	data, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}

	url := p.BaseURL + "/api/chat"
	var result *provider.Result
	start := time.Now()

	retryErr := provider.DoWithRetry(ctx, provider.RetryConfig{}, func() (int, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(data))
		if err != nil {
			return 0, err
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := p.client.Do(req)
		if err != nil {
			return 0, fmt.Errorf("ollama: request failed (is ollama running at %s?): %w", p.BaseURL, err)
		}
		defer resp.Body.Close()

		respData, err := io.ReadAll(resp.Body)
		if err != nil {
			return resp.StatusCode, fmt.Errorf("ollama: reading response: %w", err)
		}

		var body responseBody
		if err := json.Unmarshal(respData, &body); err != nil {
			return resp.StatusCode, fmt.Errorf("ollama: parsing response: %w", err)
		}

		if body.Error != "" {
			return resp.StatusCode, fmt.Errorf("ollama error: %s", body.Error)
		}

		if resp.StatusCode != http.StatusOK {
			return resp.StatusCode, fmt.Errorf("ollama: HTTP %d: %s", resp.StatusCode, string(respData))
		}

		result = &provider.Result{
			Output:        body.Message.Content,
			Duration:      time.Since(start),
			Provider:      ProviderName,
			Model:         model,
			InputTokens:   body.PromptEvalCount,
			OutputTokens:  body.EvalCount,
		}
		return resp.StatusCode, nil
	})
	return result, retryErr
}
