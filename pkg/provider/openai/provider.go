// Package openai provides access to the OpenAI Chat Completions API
// and any OpenAI-compatible API (e.g. local models via llama.cpp server).
package openai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/blechschmidt/cloop/pkg/provider"
)

const (
	ProviderName   = "openai"
	DefaultModel   = "gpt-4o"
	defaultBaseURL = "https://api.openai.com/v1"
)

type Provider struct {
	APIKey  string
	BaseURL string
	client  *http.Client
}

func New(apiKey, baseURL string) *Provider {
	if apiKey == "" {
		apiKey = os.Getenv("OPENAI_API_KEY")
	}
	if baseURL == "" {
		baseURL = defaultBaseURL
	}
	return &Provider{
		APIKey:  apiKey,
		BaseURL: baseURL,
		client:  &http.Client{},
	}
}

func (p *Provider) Name() string         { return ProviderName }
func (p *Provider) DefaultModel() string { return DefaultModel }

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type requestBody struct {
	Model     string        `json:"model"`
	MaxTokens int           `json:"max_tokens,omitempty"`
	Messages  []chatMessage `json:"messages"`
}

type responseBody struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
	Usage *struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
	} `json:"usage"`
	Error *struct {
		Message string `json:"message"`
		Type    string `json:"type"`
	} `json:"error"`
}

func (p *Provider) Complete(ctx context.Context, prompt string, opts provider.Options) (*provider.Result, error) {
	if p.APIKey == "" {
		return nil, fmt.Errorf("openai: OPENAI_API_KEY not set")
	}

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

	messages := []chatMessage{}
	if opts.SystemPrompt != "" {
		messages = append(messages, chatMessage{Role: "system", Content: opts.SystemPrompt})
	}
	messages = append(messages, chatMessage{Role: "user", Content: prompt})

	reqBody := requestBody{
		Model:     model,
		MaxTokens: opts.MaxTokens,
		Messages:  messages,
	}

	data, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}

	url := p.BaseURL + "/chat/completions"
	var result *provider.Result
	start := time.Now()

	retryErr := provider.DoWithRetry(ctx, provider.RetryConfig{}, func() (int, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(data))
		if err != nil {
			return 0, err
		}
		req.Header.Set("Authorization", "Bearer "+p.APIKey)
		req.Header.Set("Content-Type", "application/json")

		resp, err := p.client.Do(req)
		if err != nil {
			return 0, fmt.Errorf("openai: request failed: %w", err)
		}
		defer resp.Body.Close()

		respData, err := io.ReadAll(resp.Body)
		if err != nil {
			return resp.StatusCode, fmt.Errorf("openai: reading response: %w", err)
		}

		var body responseBody
		if err := json.Unmarshal(respData, &body); err != nil {
			return resp.StatusCode, fmt.Errorf("openai: parsing response: %w", err)
		}

		if body.Error != nil {
			return resp.StatusCode, fmt.Errorf("openai API error (%s): %s", body.Error.Type, body.Error.Message)
		}

		if resp.StatusCode != http.StatusOK {
			return resp.StatusCode, fmt.Errorf("openai: HTTP %d: %s", resp.StatusCode, string(respData))
		}

		if len(body.Choices) == 0 {
			return resp.StatusCode, fmt.Errorf("openai: no choices in response")
		}

		result = &provider.Result{
			Output:   body.Choices[0].Message.Content,
			Duration: time.Since(start),
			Provider: ProviderName,
			Model:    model,
		}
		if body.Usage != nil {
			result.InputTokens = body.Usage.PromptTokens
			result.OutputTokens = body.Usage.CompletionTokens
		}
		return resp.StatusCode, nil
	})
	return result, retryErr
}
