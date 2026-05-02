// Package openai provides access to the OpenAI Chat Completions API
// and any OpenAI-compatible API (e.g. local models via llama.cpp server).
package openai

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

// isReasoningModel returns true for OpenAI o-series models that do not support
// temperature or system messages but do support reasoning_effort.
func isReasoningModel(model string) bool {
	m := strings.ToLower(model)
	return strings.HasPrefix(m, "o1") || strings.HasPrefix(m, "o3") || strings.HasPrefix(m, "o4-mini")
}

// reasoningEffort maps a thinking budget (token count) to an OpenAI reasoning_effort value.
func reasoningEffort(budget int) string {
	if budget <= 0 || budget >= 12000 {
		return "high"
	}
	if budget >= 4000 {
		return "medium"
	}
	return "low"
}

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
	Model            string        `json:"model"`
	MaxTokens        int           `json:"max_tokens,omitempty"`
	MaxCompletionTokens int        `json:"max_completion_tokens,omitempty"`
	Messages         []chatMessage `json:"messages"`
	Stream           bool          `json:"stream,omitempty"`
	Temperature      *float64      `json:"temperature,omitempty"`
	TopP             *float64      `json:"top_p,omitempty"`
	FrequencyPenalty *float64      `json:"frequency_penalty,omitempty"`
	ReasoningEffort  string        `json:"reasoning_effort,omitempty"`
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
		CompletionTokensDetails *struct {
			ReasoningTokens int `json:"reasoning_tokens"`
		} `json:"completion_tokens_details"`
	} `json:"usage"`
	Error *struct {
		Message string `json:"message"`
		Type    string `json:"type"`
	} `json:"error"`
}

// streamChunk is a single SSE data chunk from OpenAI's streaming API.
type streamChunk struct {
	Choices []struct {
		Delta struct {
			Content string `json:"content"`
		} `json:"delta"`
		FinishReason string `json:"finish_reason"`
	} `json:"choices"`
	Usage *struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
		CompletionTokensDetails *struct {
			ReasoningTokens int `json:"reasoning_tokens"`
		} `json:"completion_tokens_details"`
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

	reasoning := isReasoningModel(model)

	messages := []chatMessage{}
	// o-series models do not support the system role — omit the system prompt.
	if opts.SystemPrompt != "" && !reasoning {
		messages = append(messages, chatMessage{Role: "system", Content: opts.SystemPrompt})
	}
	messages = append(messages, chatMessage{Role: "user", Content: prompt})

	useStream := opts.OnToken != nil

	reqBody := requestBody{
		Model:    model,
		Messages: messages,
		Stream:   useStream,
	}
	if reasoning {
		// o-series: use max_completion_tokens, omit temperature/top_p/freq_penalty.
		if opts.MaxTokens > 0 {
			reqBody.MaxCompletionTokens = opts.MaxTokens
		}
		if opts.ExtendedThinking {
			reqBody.ReasoningEffort = reasoningEffort(opts.ThinkingBudget)
		}
	} else {
		reqBody.MaxTokens = opts.MaxTokens
		reqBody.Temperature = opts.Temperature
		reqBody.TopP = opts.TopP
		reqBody.FrequencyPenalty = opts.FrequencyPenalty
	}

	data, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}

	url := p.BaseURL + "/chat/completions"
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
			if body.Usage.CompletionTokensDetails != nil {
				result.ThinkingTokens = body.Usage.CompletionTokensDetails.ReasoningTokens
			}
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
	req.Header.Set("Authorization", "Bearer "+p.APIKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "text/event-stream")

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("openai: request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		var errResp responseBody
		if jsonErr := json.Unmarshal(body, &errResp); jsonErr == nil && errResp.Error != nil {
			return nil, fmt.Errorf("openai API error (%s): %s", errResp.Error.Type, errResp.Error.Message)
		}
		return nil, fmt.Errorf("openai: HTTP %d: %s", resp.StatusCode, string(body))
	}

	var sb strings.Builder
	var inputTokens, outputTokens, reasoningTokens int

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

		var chunk streamChunk
		if err := json.Unmarshal([]byte(payload), &chunk); err != nil {
			continue
		}

		if chunk.Error != nil {
			return nil, fmt.Errorf("openai stream error (%s): %s", chunk.Error.Type, chunk.Error.Message)
		}

		for _, choice := range chunk.Choices {
			if token := choice.Delta.Content; token != "" {
				sb.WriteString(token)
				onToken(token)
			}
		}

		// OpenAI can include usage in the final chunk when stream_options.include_usage is set,
		// but by default it's not included. We capture it if present.
		if chunk.Usage != nil {
			inputTokens = chunk.Usage.PromptTokens
			outputTokens = chunk.Usage.CompletionTokens
			if chunk.Usage.CompletionTokensDetails != nil {
				reasoningTokens = chunk.Usage.CompletionTokensDetails.ReasoningTokens
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("openai: reading stream: %w", err)
	}

	return &provider.Result{
		Output:         sb.String(),
		Duration:       time.Since(start),
		Provider:       ProviderName,
		Model:          model,
		InputTokens:    inputTokens,
		OutputTokens:   outputTokens,
		ThinkingTokens: reasoningTokens,
	}, nil
}
