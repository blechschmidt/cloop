// Package anthropic provides direct access to the Anthropic Messages API.
package anthropic

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
	ProviderName   = "anthropic"
	DefaultModel   = "claude-opus-4-6"
	defaultBaseURL = "https://api.anthropic.com/v1"
	apiVersion     = "2023-06-01"
)

type Provider struct {
	APIKey  string
	BaseURL string
	client  *http.Client
}

func New(apiKey, baseURL string) *Provider {
	if apiKey == "" {
		apiKey = os.Getenv("ANTHROPIC_API_KEY")
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

type message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type requestBody struct {
	Model     string    `json:"model"`
	MaxTokens int       `json:"max_tokens"`
	System    string    `json:"system,omitempty"`
	Messages  []message `json:"messages"`
}

type responseBody struct {
	Content []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content"`
	Usage *struct {
		InputTokens  int `json:"input_tokens"`
		OutputTokens int `json:"output_tokens"`
	} `json:"usage"`
	Error *struct {
		Type    string `json:"type"`
		Message string `json:"message"`
	} `json:"error"`
}

func (p *Provider) Complete(ctx context.Context, prompt string, opts provider.Options) (*provider.Result, error) {
	if p.APIKey == "" {
		return nil, fmt.Errorf("anthropic: ANTHROPIC_API_KEY not set")
	}

	model := opts.Model
	if model == "" {
		model = DefaultModel
	}

	maxTokens := opts.MaxTokens
	if maxTokens == 0 {
		maxTokens = 8192
	}

	timeout := opts.Timeout
	if timeout == 0 {
		timeout = 10 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	body := requestBody{
		Model:     model,
		MaxTokens: maxTokens,
		Messages:  []message{{Role: "user", Content: prompt}},
	}
	if opts.SystemPrompt != "" {
		body.System = opts.SystemPrompt
	}

	data, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}

	url := p.BaseURL + "/messages"
	var result *provider.Result
	start := time.Now()

	retryErr := provider.DoWithRetry(ctx, provider.RetryConfig{}, func() (int, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(data))
		if err != nil {
			return 0, err
		}
		req.Header.Set("x-api-key", p.APIKey)
		req.Header.Set("anthropic-version", apiVersion)
		req.Header.Set("content-type", "application/json")

		resp, err := p.client.Do(req)
		if err != nil {
			return 0, fmt.Errorf("anthropic: request failed: %w", err)
		}
		defer resp.Body.Close()

		respData, err := io.ReadAll(resp.Body)
		if err != nil {
			return resp.StatusCode, fmt.Errorf("anthropic: reading response: %w", err)
		}

		var body responseBody
		if err := json.Unmarshal(respData, &body); err != nil {
			return resp.StatusCode, fmt.Errorf("anthropic: parsing response: %w", err)
		}

		if body.Error != nil {
			return resp.StatusCode, fmt.Errorf("anthropic API error (%s): %s", body.Error.Type, body.Error.Message)
		}

		if resp.StatusCode != http.StatusOK {
			return resp.StatusCode, fmt.Errorf("anthropic: HTTP %d: %s", resp.StatusCode, string(respData))
		}

		var output string
		for _, c := range body.Content {
			if c.Type == "text" {
				output += c.Text
			}
		}
		result = &provider.Result{
			Output:   output,
			Duration: time.Since(start),
			Provider: ProviderName,
			Model:    model,
		}
		if body.Usage != nil {
			result.InputTokens = body.Usage.InputTokens
			result.OutputTokens = body.Usage.OutputTokens
		}
		return resp.StatusCode, nil
	})
	return result, retryErr
}
