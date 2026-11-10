package provider

// ClaudeModel is one Claude model that cloop offers for the claudecode and
// anthropic providers.
type ClaudeModel struct {
	// ID is the model ID a request names. For the 4.5 models it is the alias
	// that resolves to their dated snapshot (claude-opus-4-5 for
	// claude-opus-4-5-20251101); every later model's ID has no date.
	ID string
	// Name is the display name Anthropic's Models API gives the model.
	Name string
}

// ClaudeModels is every Claude model the Anthropic Models API listed on
// 2026-11-10, grouped by line (Fable, Opus, Sonnet, Haiku) and newest first
// within each line.
//
// The setup wizard offers this list. The dashboard's model pickers and its
// price table are JavaScript, so pkg/ui's tests compare them with this list
// and with pkg/cost: a model added here and not there fails a test instead of
// going missing from a picker or being booked as free by a spend cap.
//
// Claude Mythos is left out on purpose. Anthropic serves it only to
// organizations in its verification programs, so for everyone else choosing
// it would fail every task. pkg/cost still prices it.
var ClaudeModels = []ClaudeModel{
	{ID: "claude-fable-5-2", Name: "Claude Fable 5.2"},
	{ID: "claude-fable-5-1", Name: "Claude Fable 5.1"},
	{ID: "claude-fable-5", Name: "Claude Fable 5"},
	{ID: "claude-opus-5-5", Name: "Claude Opus 5.5"},
	{ID: "claude-opus-5", Name: "Claude Opus 5"},
	{ID: "claude-opus-4-8", Name: "Claude Opus 4.8"},
	{ID: "claude-opus-4-7", Name: "Claude Opus 4.7"},
	{ID: "claude-opus-4-6", Name: "Claude Opus 4.6"},
	{ID: "claude-opus-4-5", Name: "Claude Opus 4.5"},
	{ID: "claude-sonnet-5-5", Name: "Claude Sonnet 5.5"},
	{ID: "claude-sonnet-5", Name: "Claude Sonnet 5"},
	{ID: "claude-sonnet-4-6", Name: "Claude Sonnet 4.6"},
	{ID: "claude-sonnet-4-5", Name: "Claude Sonnet 4.5"},
	{ID: "claude-haiku-5-5", Name: "Claude Haiku 5.5"},
	{ID: "claude-haiku-4-5", Name: "Claude Haiku 4.5"},
}

// ClaudeModelIDs returns the IDs of ClaudeModels in order.
func ClaudeModelIDs() []string {
	ids := make([]string, len(ClaudeModels))
	for i, m := range ClaudeModels {
		ids[i] = m.ID
	}
	return ids
}
