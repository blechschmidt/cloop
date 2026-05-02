package suggest

import (
	"strings"
	"testing"
)

// --- BuildPrompt ---

func TestBuildPrompt_ContainsRequiredSections(t *testing.T) {
	prompt := BuildPrompt(
		"Build an AI assistant",
		"Use Go only",
		"cmd/\npkg/",
		"recent commit: fix bug",
		"memory context",
		"task 1: existing feature",
		5,
	)

	required := []string{
		"PROJECT GOAL",
		"Build an AI assistant",
		"CONSTRAINTS",
		"Use Go only",
		"EXISTING TASKS",
		"task 1: existing feature",
		"PROJECT STRUCTURE",
		"cmd/",
		"RECENT ACTIVITY",
		"recent commit: fix bug",
		"PROJECT MEMORY",
		"memory context",
		"Generate exactly 5",
		"feature, ux, performance, security, dx, integration, docs",
		"xs (<1h)",
	}

	for _, want := range required {
		if !strings.Contains(prompt, want) {
			t.Errorf("prompt missing expected section/content: %q", want)
		}
	}
}

func TestBuildPrompt_OmitsEmptySections(t *testing.T) {
	prompt := BuildPrompt("my goal", "", "", "", "", "", 3)

	if strings.Contains(prompt, "CONSTRAINTS") {
		t.Error("CONSTRAINTS section should be omitted when instructions is empty")
	}
	if strings.Contains(prompt, "EXISTING TASKS") {
		t.Error("EXISTING TASKS section should be omitted when existingTasks is empty")
	}
	if strings.Contains(prompt, "PROJECT STRUCTURE") {
		t.Error("PROJECT STRUCTURE section should be omitted when fileTree is empty")
	}
	if strings.Contains(prompt, "RECENT ACTIVITY") {
		t.Error("RECENT ACTIVITY section should be omitted when recentLog is empty")
	}
	if strings.Contains(prompt, "PROJECT MEMORY") {
		t.Error("PROJECT MEMORY section should be omitted when memCtx is empty")
	}
	if !strings.Contains(prompt, "my goal") {
		t.Error("goal should always be present")
	}
	if !strings.Contains(prompt, "Generate exactly 3") {
		t.Error("count should be in prompt")
	}
}

func TestBuildPrompt_OutputIsJSON(t *testing.T) {
	prompt := BuildPrompt("goal", "", "", "", "", "", 2)
	// Prompt should end with a JSON skeleton to guide the model
	if !strings.Contains(prompt, `{"summary"`) {
		t.Error("prompt should contain JSON output example")
	}
	if !strings.Contains(prompt, `"suggestions"`) {
		t.Error("prompt should contain suggestions key in example")
	}
}

// --- Parse ---

func TestParse_ValidJSON(t *testing.T) {
	input := `{"summary":"test summary","suggestions":[{"id":1,"title":"Dark mode","description":"Add dark mode","rationale":"UX improvement","category":"ux","effort":"s"},{"id":2,"title":"Caching","description":"Add Redis cache","rationale":"Performance","category":"performance","effort":"m"}]}`
	result, err := Parse(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Summary != "test summary" {
		t.Errorf("summary = %q, want %q", result.Summary, "test summary")
	}
	if len(result.Suggestions) != 2 {
		t.Fatalf("expected 2 suggestions, got %d", len(result.Suggestions))
	}
	if result.Suggestions[0].Title != "Dark mode" {
		t.Errorf("suggestion 0 title = %q", result.Suggestions[0].Title)
	}
	if result.Suggestions[1].Category != CategoryPerformance {
		t.Errorf("suggestion 1 category = %q", result.Suggestions[1].Category)
	}
	if result.Suggestions[1].Effort != EffortM {
		t.Errorf("suggestion 1 effort = %q", result.Suggestions[1].Effort)
	}
}

func TestParse_JSONWithLeadingText(t *testing.T) {
	// Model sometimes wraps JSON in markdown or preamble
	input := "Here are my suggestions:\n\n```json\n" +
		`{"summary":"wrapped","suggestions":[{"id":1,"title":"T","description":"D","rationale":"R","category":"feature","effort":"xs"}]}` +
		"\n```"
	result, err := Parse(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Summary != "wrapped" {
		t.Errorf("summary = %q", result.Summary)
	}
}

func TestParse_AssignsIDsWhenMissing(t *testing.T) {
	input := `{"summary":"ids","suggestions":[{"title":"A","description":"","rationale":"","category":"feature","effort":"xs"},{"title":"B","description":"","rationale":"","category":"dx","effort":"s"}]}`
	result, err := Parse(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Suggestions[0].ID != 1 {
		t.Errorf("first suggestion ID = %d, want 1", result.Suggestions[0].ID)
	}
	if result.Suggestions[1].ID != 2 {
		t.Errorf("second suggestion ID = %d, want 2", result.Suggestions[1].ID)
	}
}

func TestParse_PreservesExistingIDs(t *testing.T) {
	input := `{"summary":"ids","suggestions":[{"id":10,"title":"A","description":"","rationale":"","category":"feature","effort":"xs"}]}`
	result, err := Parse(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Suggestions[0].ID != 10 {
		t.Errorf("ID should be preserved, got %d", result.Suggestions[0].ID)
	}
}

func TestParse_NoJSONReturnsError(t *testing.T) {
	_, err := Parse("no json here at all")
	if err == nil {
		t.Error("expected error for input with no JSON")
	}
}

func TestParse_InvalidJSONReturnsError(t *testing.T) {
	_, err := Parse("{invalid json}")
	if err == nil {
		t.Error("expected error for malformed JSON")
	}
}

func TestParse_EmptySuggestions(t *testing.T) {
	input := `{"summary":"none","suggestions":[]}`
	result, err := Parse(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Suggestions) != 0 {
		t.Errorf("expected 0 suggestions, got %d", len(result.Suggestions))
	}
}

// --- Result struct ---

func TestResult_Fields(t *testing.T) {
	r := &Result{
		Summary: "good ideas",
		Suggestions: []*Suggestion{
			{ID: 1, Title: "Feature A", Description: "Desc", Rationale: "Because", Category: CategoryFeature, Effort: EffortL},
		},
	}
	if r.Summary != "good ideas" {
		t.Errorf("summary wrong: %q", r.Summary)
	}
	if r.Suggestions[0].Effort != EffortL {
		t.Errorf("effort wrong: %q", r.Suggestions[0].Effort)
	}
}

// --- EffortLabel ---

func TestEffortLabel(t *testing.T) {
	tests := []struct {
		effort Effort
		want   string
	}{
		{EffortXS, "XS  <1h"},
		{EffortS, "S   1–4h"},
		{EffortM, "M   4–16h"},
		{EffortL, "L   1–5d"},
		{EffortXL, "XL  >1wk"},
		{"unknown", "unknown"},
	}
	for _, tt := range tests {
		got := EffortLabel(tt.effort)
		if got != tt.want {
			t.Errorf("EffortLabel(%q) = %q, want %q", tt.effort, got, tt.want)
		}
	}
}

// --- CategoryLabel ---

func TestCategoryLabel(t *testing.T) {
	tests := []struct {
		cat  Category
		want string
	}{
		{CategoryFeature, "feature"},
		{CategoryUX, "ux"},
		{CategoryPerformance, "perf"},
		{CategorySecurity, "security"},
		{CategoryDX, "dx"},
		{CategoryIntegration, "integration"},
		{CategoryDocs, "docs"},
		{"custom", "custom"},
	}
	for _, tt := range tests {
		got := CategoryLabel(tt.cat)
		if got != tt.want {
			t.Errorf("CategoryLabel(%q) = %q, want %q", tt.cat, got, tt.want)
		}
	}
}

// --- Suggestion struct round-trip ---

func TestSuggestion_JSONRoundTrip(t *testing.T) {
	s := &Suggestion{
		ID:          7,
		Title:       "Rate limiting",
		Description: "Add rate limiting middleware",
		Rationale:   "Prevent abuse",
		Category:    CategorySecurity,
		Effort:      EffortS,
	}
	input := `{"summary":"s","suggestions":[{"id":7,"title":"Rate limiting","description":"Add rate limiting middleware","rationale":"Prevent abuse","category":"security","effort":"s"}]}`
	result, err := Parse(input)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	got := result.Suggestions[0]
	if got.ID != s.ID || got.Title != s.Title || got.Category != s.Category || got.Effort != s.Effort {
		t.Errorf("round-trip mismatch: got %+v, want %+v", got, s)
	}
}
