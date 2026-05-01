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
	Error string `json:"error"`
	Done  bool   `json:"done"`
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

	body := requestBody{
		Model:    model,
		Messages: messages,
		Stream:   false,
	}
	if opts.MaxTokens > 0 {
		body.Options = &ollamaOptions{NumPredict: opts.MaxTokens}
	}

	data, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.BaseURL+"/api/chat", bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	start := time.Now()
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ollama: request failed (is ollama running at %s?): %w", p.BaseURL, err)
	}
	defer resp.Body.Close()
	duration := time.Since(start)

	respData, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("ollama: reading response: %w", err)
	}

	var result responseBody
	if err := json.Unmarshal(respData, &result); err != nil {
		return nil, fmt.Errorf("ollama: parsing response: %w", err)
	}

	if result.Error != "" {
		return nil, fmt.Errorf("ollama error: %s", result.Error)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ollama: HTTP %d: %s", resp.StatusCode, string(respData))
	}

	return &provider.Result{
		Output:   result.Message.Content,
		Duration: duration,
		Provider: ProviderName,
		Model:    model,
	}, nil
}
