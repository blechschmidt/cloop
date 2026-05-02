// Package anthropic provides direct access to the Anthropic Messages API.
package anthropic

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
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

type thinkingConfig struct {
	Type         string `json:"type"`
	BudgetTokens int    `json:"budget_tokens"`
}

type requestBody struct {
	Model       string          `json:"model"`
	MaxTokens   int             `json:"max_tokens"`
	System      string          `json:"system,omitempty"`
	Messages    []message       `json:"messages"`
	Stream      bool            `json:"stream,omitempty"`
	Temperature *float64        `json:"temperature,omitempty"`
	TopP        *float64        `json:"top_p,omitempty"`
	Thinking    *thinkingConfig `json:"thinking,omitempty"`
}

type contentBlock struct {
	Type     string `json:"type"`
	Text     string `json:"text"`
	Thinking string `json:"thinking"`
}

type responseBody struct {
	Content []contentBlock `json:"content"`
	Usage   *struct {
		InputTokens  int `json:"input_tokens"`
		OutputTokens int `json:"output_tokens"`
	} `json:"usage"`
	Error *struct {
		Type    string `json:"type"`
		Message string `json:"message"`
	} `json:"error"`
}

// SSE event types for streaming
type sseEvent struct {
	Type    string    `json:"type"`
	Index   int       `json:"index"`
	Delta   *sseDelta `json:"delta"`
	Usage   *sseUsage `json:"usage"`
	Message *struct {
		Usage *sseUsage `json:"usage"`
	} `json:"message"`
	// ContentBlock is present in content_block_start events and reveals the block type.
	ContentBlock *struct {
		Type string `json:"type"`
	} `json:"content_block"`
	Error *struct {
		Type    string `json:"type"`
		Message string `json:"message"`
	} `json:"error"`
}

type sseDelta struct {
	Type     string `json:"type"`
	Text     string `json:"text"`
	Thinking string `json:"thinking"`
}

type sseUsage struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
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

	useStream := opts.OnToken != nil

	body := requestBody{
		Model:     model,
		MaxTokens: maxTokens,
		Messages:  []message{{Role: "user", Content: prompt}},
		Stream:    useStream,
	}
	if opts.SystemPrompt != "" {
		body.System = opts.SystemPrompt
	}
	// Extended thinking: omit temperature/top_p (incompatible with thinking mode).
	if opts.ExtendedThinking {
		budget := opts.ThinkingBudget
		if budget <= 0 {
			budget = 8000
		}
		body.Thinking = &thinkingConfig{Type: "enabled", BudgetTokens: budget}
	} else {
		body.Temperature = opts.Temperature
		body.TopP = opts.TopP
	}

	data, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}

	url := p.BaseURL + "/messages"
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
		var thinkingText string
		for _, c := range body.Content {
			switch c.Type {
			case "text":
				output += c.Text
			case "thinking":
				thinkingText += c.Thinking
			}
		}
		result = &provider.Result{
			Output:         output,
			Duration:       time.Since(start),
			Provider:       ProviderName,
			Model:          model,
			ThinkingTokens: len([]rune(thinkingText)) / 4,
		}
		if body.Usage != nil {
			result.InputTokens = body.Usage.InputTokens
			result.OutputTokens = body.Usage.OutputTokens
		}
		return resp.StatusCode, nil
	})
	return result, retryErr
}

func (p *Provider) completeStreaming(ctx context.Context, url string, data []byte, model string, start time.Time, onToken func(string)) (*provider.Result, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	req.Header.Set("x-api-key", p.APIKey)
	req.Header.Set("anthropic-version", apiVersion)
	req.Header.Set("content-type", "application/json")
	req.Header.Set("accept", "text/event-stream")

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("anthropic: request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		var errResp responseBody
		if jsonErr := json.Unmarshal(body, &errResp); jsonErr == nil && errResp.Error != nil {
			return nil, fmt.Errorf("anthropic API error (%s): %s", errResp.Error.Type, errResp.Error.Message)
		}
		return nil, fmt.Errorf("anthropic: HTTP %d: %s", resp.StatusCode, string(body))
	}

	var sb strings.Builder
	var thinkingSb strings.Builder
	var inputTokens, outputTokens int
	// Track which content block type is currently streaming.
	// Blocks are indexed; we detect type from content_block_start events.
	currentBlockIsThinking := false

	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		payload := strings.TrimPrefix(line, "data: ")
		if payload == "[DONE]" {
			break
		}

		var event sseEvent
		if err := json.Unmarshal([]byte(payload), &event); err != nil {
			continue
		}

		if event.Error != nil {
			return nil, fmt.Errorf("anthropic stream error (%s): %s", event.Error.Type, event.Error.Message)
		}

		switch event.Type {
		case "message_start":
			if event.Message != nil && event.Message.Usage != nil {
				inputTokens = event.Message.Usage.InputTokens
			}
		case "content_block_start":
			// Detect block type from the content_block field in the event.
			currentBlockIsThinking = event.ContentBlock != nil && event.ContentBlock.Type == "thinking"
		case "content_block_delta":
			if event.Delta != nil {
				switch event.Delta.Type {
				case "text_delta":
					token := event.Delta.Text
					sb.WriteString(token)
					onToken(token)
				case "thinking_delta":
					thinkingSb.WriteString(event.Delta.Thinking)
				default:
					if currentBlockIsThinking && event.Delta.Thinking != "" {
						thinkingSb.WriteString(event.Delta.Thinking)
					} else if !currentBlockIsThinking && event.Delta.Text != "" {
						token := event.Delta.Text
						sb.WriteString(token)
						onToken(token)
					}
				}
			}
		case "message_delta":
			if event.Usage != nil {
				outputTokens = event.Usage.OutputTokens
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("anthropic: reading stream: %w", err)
	}

	thinkingText := thinkingSb.String()
	return &provider.Result{
		Output:         sb.String(),
		Duration:       time.Since(start),
		Provider:       ProviderName,
		Model:          model,
		InputTokens:    inputTokens,
		OutputTokens:   outputTokens,
		ThinkingTokens: len([]rune(thinkingText)) / 4,
	}, nil
}
