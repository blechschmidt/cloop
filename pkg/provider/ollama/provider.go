// Package ollama provides access to locally running Ollama models.
package ollama

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
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
	NumPredict  int      `json:"num_predict,omitempty"`
	Temperature *float64 `json:"temperature,omitempty"`
	TopP        *float64 `json:"top_p,omitempty"`
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

	useStream := opts.OnToken != nil

	reqBody := requestBody{
		Model:    model,
		Messages: messages,
		Stream:   useStream,
	}
	if opts.MaxTokens > 0 || opts.Temperature != nil || opts.TopP != nil {
		reqBody.Options = &ollamaOptions{
			NumPredict:  opts.MaxTokens,
			Temperature: opts.Temperature,
			TopP:        opts.TopP,
		}
	}

	data, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}

	url := p.BaseURL + "/api/chat"
	start := time.Now()

	if useStream {
		return p.completeStreaming(ctx, url, data, model, start, opts.OnToken)
	}

	var result *provider.Result

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
			Output:       body.Message.Content,
			Duration:     time.Since(start),
			Provider:     ProviderName,
			Model:        model,
			InputTokens:  body.PromptEvalCount,
			OutputTokens: body.EvalCount,
		}
		return resp.StatusCode, nil
	})
	return result, retryErr
}

// completeStreaming uses Ollama's newline-delimited JSON streaming.
func (p *Provider) completeStreaming(ctx context.Context, url string, data []byte, model string, start time.Time, onToken func(string)) (*provider.Result, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ollama: request failed (is ollama running at %s?): %w", p.BaseURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("ollama: HTTP %d: %s", resp.StatusCode, string(body))
	}

	var sb strings.Builder
	var inputTokens, outputTokens int

	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var chunk responseBody
		if err := json.Unmarshal(line, &chunk); err != nil {
			continue
		}

		if chunk.Error != "" {
			return nil, fmt.Errorf("ollama error: %s", chunk.Error)
		}

		token := chunk.Message.Content
		if token != "" {
			sb.WriteString(token)
			onToken(token)
		}

		if chunk.Done {
			inputTokens = chunk.PromptEvalCount
			outputTokens = chunk.EvalCount
			break
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("ollama: reading stream: %w", err)
	}

	return &provider.Result{
		Output:       sb.String(),
		Duration:     time.Since(start),
		Provider:     ProviderName,
		Model:        model,
		InputTokens:  inputTokens,
		OutputTokens: outputTokens,
	}, nil
}
