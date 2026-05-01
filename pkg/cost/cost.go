// Package cost provides token-cost estimation for common AI model providers.
// Prices are per 1M tokens and are approximate — they may lag behind
// official pricing changes. Always verify with your provider's pricing page.
package cost

import "fmt"

// ModelPricing holds the input and output cost in USD per 1M tokens.
type ModelPricing struct {
	InputPerM  float64
	OutputPerM float64
}

// prices is a lookup table of known model pricing (USD / 1M tokens).
// Keys are lowercase model IDs. Partial prefix matches are tried on miss.
var prices = map[string]ModelPricing{
	// Anthropic Claude 4.x
	"claude-opus-4-6":          {InputPerM: 15.00, OutputPerM: 75.00},
	"claude-opus-4-5":          {InputPerM: 15.00, OutputPerM: 75.00},
	"claude-sonnet-4-6":        {InputPerM: 3.00, OutputPerM: 15.00},
	"claude-sonnet-4-5":        {InputPerM: 3.00, OutputPerM: 15.00},
	"claude-haiku-4-5":         {InputPerM: 0.80, OutputPerM: 4.00},
	// Anthropic Claude 3.x
	"claude-3-opus-20240229":   {InputPerM: 15.00, OutputPerM: 75.00},
	"claude-3-5-sonnet-20241022": {InputPerM: 3.00, OutputPerM: 15.00},
	"claude-3-5-haiku-20241022": {InputPerM: 0.80, OutputPerM: 4.00},
	"claude-3-haiku-20240307":  {InputPerM: 0.25, OutputPerM: 1.25},
	// OpenAI GPT-4o
	"gpt-4o":                   {InputPerM: 2.50, OutputPerM: 10.00},
	"gpt-4o-mini":              {InputPerM: 0.15, OutputPerM: 0.60},
	"gpt-4-turbo":              {InputPerM: 10.00, OutputPerM: 30.00},
	"gpt-4":                    {InputPerM: 30.00, OutputPerM: 60.00},
	"gpt-3.5-turbo":            {InputPerM: 0.50, OutputPerM: 1.50},
	// OpenAI o-series
	"o1":                       {InputPerM: 15.00, OutputPerM: 60.00},
	"o1-mini":                  {InputPerM: 3.00, OutputPerM: 12.00},
	"o3-mini":                  {InputPerM: 1.10, OutputPerM: 4.40},
	// Google (via OpenAI-compat)
	"gemini-1.5-pro":           {InputPerM: 1.25, OutputPerM: 5.00},
	"gemini-1.5-flash":         {InputPerM: 0.075, OutputPerM: 0.30},
	// Ollama / local models — zero cost
	"llama3.2":                 {InputPerM: 0, OutputPerM: 0},
	"llama3.1":                 {InputPerM: 0, OutputPerM: 0},
	"mistral":                  {InputPerM: 0, OutputPerM: 0},
	"mixtral":                  {InputPerM: 0, OutputPerM: 0},
	"phi3":                     {InputPerM: 0, OutputPerM: 0},
	"qwen":                     {InputPerM: 0, OutputPerM: 0},
	"deepseek":                 {InputPerM: 0, OutputPerM: 0},
}

// Estimate returns the estimated cost in USD for the given token counts.
// model is matched case-insensitively; unrecognised models return (0, false).
func Estimate(model string, inputTokens, outputTokens int) (usd float64, ok bool) {
	p, ok := lookup(model)
	if !ok {
		return 0, false
	}
	return (float64(inputTokens)/1_000_000)*p.InputPerM +
		(float64(outputTokens)/1_000_000)*p.OutputPerM, true
}

// FormatCost returns a human-readable cost string, e.g. "$0.0042" or "$1.23".
func FormatCost(usd float64) string {
	if usd == 0 {
		return "$0.00 (local)"
	}
	if usd < 0.0001 {
		return fmt.Sprintf("$%.6f", usd)
	}
	if usd < 0.01 {
		return fmt.Sprintf("$%.4f", usd)
	}
	return fmt.Sprintf("$%.2f", usd)
}

// lookup performs an exact then prefix-based match.
func lookup(model string) (ModelPricing, bool) {
	// Exact match
	if p, ok := prices[model]; ok {
		return p, true
	}
	// Prefix match — find longest key that is a prefix of the model name
	var best string
	for k := range prices {
		if len(k) > len(best) && len(model) >= len(k) && model[:len(k)] == k {
			best = k
		}
	}
	if best != "" {
		return prices[best], true
	}
	return ModelPricing{}, false
}
