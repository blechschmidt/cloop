package anthropic

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/blechschmidt/cloop/pkg/provider"
)

// requestRules is what the Messages API accepts from each model cloop offers
// (Anthropic's model pages and thinking guide, checked 2026-11-10): whether
// thinking is turned on with {type: "adaptive"}, and whether temperature and
// top_p are accepted. A model added to provider.ClaudeModels needs a row, so
// whoever adds it checks the rules instead of trusting the generation guess.
var requestRules = map[string]struct{ adaptive, sampling bool }{
	"claude-fable-5-2":  {adaptive: true, sampling: false},
	"claude-fable-5-1":  {adaptive: true, sampling: false},
	"claude-fable-5":    {adaptive: true, sampling: false},
	"claude-opus-5-5":   {adaptive: true, sampling: false},
	"claude-opus-5":     {adaptive: true, sampling: false},
	"claude-opus-4-8":   {adaptive: true, sampling: false},
	"claude-opus-4-7":   {adaptive: true, sampling: false},
	"claude-opus-4-6":   {adaptive: true, sampling: true},
	"claude-opus-4-5":   {adaptive: false, sampling: true},
	"claude-sonnet-5-5": {adaptive: true, sampling: false},
	"claude-sonnet-5":   {adaptive: true, sampling: false},
	"claude-sonnet-4-6": {adaptive: true, sampling: true},
	"claude-sonnet-4-5": {adaptive: false, sampling: true},
	"claude-haiku-5-5":  {adaptive: true, sampling: false},
	"claude-haiku-4-5":  {adaptive: false, sampling: true},
}

func TestEveryOfferedModelGetsTheRequestShapeItAccepts(t *testing.T) {
	for _, m := range provider.ClaudeModels {
		want, ok := requestRules[m.ID]
		if !ok {
			t.Errorf("%s is offered (provider.ClaudeModels) but has no row in requestRules: "+
				"check whether it takes adaptive thinking and temperature/top_p, and add one", m.ID)
			continue
		}
		if _, _, _, parsed := claudeGeneration(m.ID); !parsed {
			t.Errorf("claudeGeneration(%q) did not parse an offered model's ID", m.ID)
		}
		if got := adaptiveThinking(m.ID); got != want.adaptive {
			t.Errorf("adaptiveThinking(%q) = %v, want %v", m.ID, got, want.adaptive)
		}
		if got := acceptsSampling(m.ID); got != want.sampling {
			t.Errorf("acceptsSampling(%q) = %v, want %v", m.ID, got, want.sampling)
		}
	}
}

func TestClaudeGenerationParsesTheIDShapes(t *testing.T) {
	cases := []struct {
		id           string
		line         string
		major, minor int
		ok           bool
	}{
		{"claude-fable-5-2", "fable", 5, 2, true},
		{"claude-fable-5", "fable", 5, 0, true},
		{"claude-opus-4-5-20251101", "opus", 4, 5, true},
		{"claude-sonnet-4-20250514", "sonnet", 4, 0, true},
		{"Claude-Opus-5-5", "opus", 5, 5, true},
		{"claude-sonnet-5[1m]", "sonnet", 5, 0, true},
		{"anthropic.claude-haiku-5-5", "haiku", 5, 5, true},
		{"claude-opus-4-5@20251101", "opus", 4, 5, true},
		{"claude-3-5-sonnet-20241022", "", 0, 0, false},
		{"claude-opus", "", 0, 0, false},
		{"gpt-4o", "", 0, 0, false},
		{"", "", 0, 0, false},
	}
	for _, c := range cases {
		line, major, minor, ok := claudeGeneration(c.id)
		if line != c.line || major != c.major || minor != c.minor || ok != c.ok {
			t.Errorf("claudeGeneration(%q) = %q, %d, %d, %v; want %q, %d, %d, %v",
				c.id, line, major, minor, ok, c.line, c.major, c.minor, c.ok)
		}
	}
	// A later release gets the newer rules without a code change; an ID that
	// does not parse keeps the older ones.
	for _, id := range []string{"claude-fable-5-3", "claude-opus-6", "claude-mythos-5-2", "claude-haiku-6-1"} {
		if !adaptiveThinking(id) || acceptsSampling(id) {
			t.Errorf("%s: adaptive=%v sampling=%v; want adaptive thinking and no sampling parameters",
				id, adaptiveThinking(id), acceptsSampling(id))
		}
	}
	for _, id := range []string{"claude-3-5-sonnet-20241022", "my-gateway-model"} {
		if adaptiveThinking(id) || !acceptsSampling(id) {
			t.Errorf("%s: adaptive=%v sampling=%v; want the older request shape",
				id, adaptiveThinking(id), acceptsSampling(id))
		}
	}
}

// captureBody runs one Complete and returns the JSON body the API received.
func captureBody(t *testing.T, opts provider.Options) map[string]json.RawMessage {
	t.Helper()
	var body map[string]json.RawMessage
	_, p := makeServer(t, func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("decode request: %v", err)
		}
		successHandler("ok", 1, 1)(w, r)
	})
	if _, err := p.Complete(context.Background(), "prompt", opts); err != nil {
		t.Fatalf("Complete: %v", err)
	}
	return body
}

func TestCompleteSendsAdaptiveThinkingToNewerModels(t *testing.T) {
	for _, model := range []string{"claude-fable-5-2", "claude-opus-4-6"} {
		body := captureBody(t, provider.Options{Model: model, ExtendedThinking: true, ThinkingBudget: 12000})
		var th map[string]any
		if err := json.Unmarshal(body["thinking"], &th); err != nil {
			t.Fatalf("%s: thinking = %s: %v", model, body["thinking"], err)
		}
		if th["type"] != "adaptive" {
			t.Errorf("%s: thinking.type = %v, want adaptive", model, th["type"])
		}
		if _, has := th["budget_tokens"]; has {
			t.Errorf("%s: thinking carries budget_tokens (%v), which the model refuses", model, th["budget_tokens"])
		}
	}
}

func TestCompleteKeepsTheThinkingBudgetForOlderModels(t *testing.T) {
	body := captureBody(t, provider.Options{Model: "claude-haiku-4-5", ExtendedThinking: true, ThinkingBudget: 12000})
	var th struct {
		Type         string `json:"type"`
		BudgetTokens int    `json:"budget_tokens"`
	}
	if err := json.Unmarshal(body["thinking"], &th); err != nil {
		t.Fatalf("thinking = %s: %v", body["thinking"], err)
	}
	if th.Type != "enabled" || th.BudgetTokens != 12000 {
		t.Errorf("thinking = %+v, want enabled with budget_tokens 12000", th)
	}
}

func TestCompleteDropsSamplingParametersTheModelRefuses(t *testing.T) {
	temp, topP := 0.2, 0.9
	for _, model := range []string{"claude-fable-5-2", "claude-opus-5-5", "claude-sonnet-5-5", "claude-haiku-5-5", "claude-opus-4-7"} {
		body := captureBody(t, provider.Options{Model: model, Temperature: &temp, TopP: &topP})
		if _, has := body["temperature"]; has {
			t.Errorf("%s: temperature sent (%s); the model answers it with a 400", model, body["temperature"])
		}
		if _, has := body["top_p"]; has {
			t.Errorf("%s: top_p sent (%s); the model answers it with a 400", model, body["top_p"])
		}
		if _, has := body["thinking"]; has {
			t.Errorf("%s: thinking sent without --think: %s", model, body["thinking"])
		}
	}
	for _, model := range []string{"claude-sonnet-4-6", "claude-haiku-4-5", "claude-3-5-sonnet-20241022"} {
		body := captureBody(t, provider.Options{Model: model, Temperature: &temp, TopP: &topP})
		if string(body["temperature"]) != "0.2" || string(body["top_p"]) != "0.9" {
			t.Errorf("%s: temperature=%s top_p=%s, want 0.2 and 0.9 passed through",
				model, body["temperature"], body["top_p"])
		}
	}
}
