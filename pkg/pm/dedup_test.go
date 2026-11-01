package pm

import (
	"context"
	"testing"

	"github.com/blechschmidt/cloop/pkg/provider"
)

func TestParseDedupResponse(t *testing.T) {
	tests := []struct {
		name        string
		output      string
		wantIndices []int
		wantReason  string
		wantErr     bool
	}{
		{
			name:        "all novel",
			output:      `{"novel":[0,1,2],"reason":"All tasks are new"}`,
			wantIndices: []int{0, 1, 2},
			wantReason:  "All tasks are new",
		},
		{
			name:        "some novel",
			output:      `{"novel":[0,2],"reason":"Task 1 duplicates existing #5"}`,
			wantIndices: []int{0, 2},
			wantReason:  "Task 1 duplicates existing #5",
		},
		{
			name:        "none novel",
			output:      `{"novel":[],"reason":"All tasks already covered"}`,
			wantIndices: []int{},
			wantReason:  "All tasks already covered",
		},
		{
			name:        "json embedded in text",
			output:      "Here is my analysis:\n{\"novel\":[1],\"reason\":\"Task 0 is a dup\"}\nDone.",
			wantIndices: []int{1},
			wantReason:  "Task 0 is a dup",
		},
		{
			name:    "no json",
			output:  "No JSON here",
			wantErr: true,
		},
		{
			name:    "malformed json",
			output:  `{"novel":[`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			indices, reason, err := parseDedupResponse(tt.output)
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(indices) != len(tt.wantIndices) {
				t.Errorf("indices: got %v, want %v", indices, tt.wantIndices)
			} else {
				for i := range indices {
					if indices[i] != tt.wantIndices[i] {
						t.Errorf("indices[%d]: got %d, want %d", i, indices[i], tt.wantIndices[i])
					}
				}
			}
			if reason != tt.wantReason {
				t.Errorf("reason: got %q, want %q", reason, tt.wantReason)
			}
		})
	}
}

// TestDeduplicateTasks_ShortCircuits verifies DeduplicateTasks short-circuits
// (no provider call) when candidates or existing tasks are empty.
func TestDeduplicateTasks_ShortCircuits(t *testing.T) {
	candidates := []*Task{
		{ID: 1, Title: "New feature", Description: "Add a cool feature"},
	}

	emptyOpts := provider.Options{}

	// No candidates → return empty, no provider call.
	result, err := DeduplicateTasks(context.Background(), nil, emptyOpts, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error with no candidates: %v", err)
	}
	if len(result) != 0 {
		t.Errorf("expected empty result, got %d", len(result))
	}

	// No existing tasks → return all candidates, no provider call.
	result, err = DeduplicateTasks(context.Background(), nil, emptyOpts, nil, candidates)
	if err != nil {
		t.Fatalf("unexpected error with no existing: %v", err)
	}
	if len(result) != 1 {
		t.Errorf("expected 1 result, got %d", len(result))
	}
}

func TestDedupPrompt_ContainsTitles(t *testing.T) {
	existing := []*Task{
		{ID: 1, Title: "Existing feature", Description: "Already done"},
	}
	candidates := []*Task{
		{ID: 0, Title: "Brand new feature", Description: "Something novel"},
	}
	prompt := dedupPrompt(existing, candidates)
	for _, want := range []string{"Existing feature", "Brand new feature", "novel", "duplicate"} {
		found := false
		for _, line := range splitLines(prompt) {
			if containsStr(line, want) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("prompt missing expected text %q", want)
		}
	}
}

func splitLines(s string) []string {
	var lines []string
	start := 0
	for i, c := range s {
		if c == '\n' {
			lines = append(lines, s[start:i])
			start = i + 1
		}
	}
	lines = append(lines, s[start:])
	return lines
}

func containsStr(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		func() bool {
			for i := 0; i <= len(s)-len(substr); i++ {
				if s[i:i+len(substr)] == substr {
					return true
				}
			}
			return false
		}())
}

// answerProvider answers every prompt with out, or fails with err, and keeps
// the prompts it was given.
type answerProvider struct {
	out     string
	err     error
	prompts []string
}

func (p *answerProvider) Name() string { return "answer" }

func (p *answerProvider) DefaultModel() string { return "" }

func (p *answerProvider) Complete(_ context.Context, prompt string, _ provider.Options) (*provider.Result, error) {
	p.prompts = append(p.prompts, prompt)
	if p.err != nil {
		return nil, p.err
	}
	return &provider.Result{Output: p.out}, nil
}

// JudgeDuplicates asks the question DeduplicateTasks asks, in its words, and
// answers with the duplicates rather than dropping them — and, unlike it, an
// answer it cannot read is an error, never "nothing is a duplicate" (Task 20462).
func TestJudgeDuplicates(t *testing.T) {
	existing := []*Task{{ID: 3, Title: "The CLI shall exit 2 on a malformed config"}}
	candidates := []*Task{{ID: 7, Title: "Malformed configs make the CLI exit 2"}, {ID: 8, Title: "Logs are kept 30 days"}}

	p := &answerProvider{out: `{"novel":[1],"reason":"candidate 0 restates existing #3"}`}
	v, err := JudgeDuplicates(context.Background(), p, provider.Options{}, existing, candidates)
	if err != nil {
		t.Fatal(err)
	}
	if len(v.Duplicates) != 1 || v.Duplicates[0] != 0 || v.Reason != "candidate 0 restates existing #3" {
		t.Fatalf("verdict = %+v", v)
	}
	if len(p.prompts) != 1 || p.prompts[0] != dedupPrompt(existing, candidates) {
		t.Errorf("JudgeDuplicates did not ask the dedup question:\n%v", p.prompts)
	}

	if _, err := JudgeDuplicates(context.Background(), &answerProvider{out: "I could not decide."}, provider.Options{},
		existing, candidates); err == nil {
		t.Error("an unreadable answer was taken for one")
	}
	if _, err := JudgeDuplicates(context.Background(), &answerProvider{err: context.DeadlineExceeded}, provider.Options{},
		existing, candidates); err == nil {
		t.Error("a failed call was taken for an answer")
	}
	// Nothing to compare with: nothing is asked.
	none := &answerProvider{}
	if v, err := JudgeDuplicates(context.Background(), none, provider.Options{}, nil, candidates); err != nil ||
		len(v.Duplicates) != 0 || len(none.prompts) != 0 {
		t.Errorf("with nothing existing: %+v, %v, %d prompts", v, err, len(none.prompts))
	}
}
