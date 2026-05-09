package orchestrator

import "testing"

// TestLooksLikeClarificationQuestion locks in the contract of the heuristic
// that decides whether a TaskInProgress output (no TASK_* signal) should be
// rerouted to TaskFailed instead of the default-arm "silently DONE" path.
//
// This function is load-bearing in three sites added in commit be4d52b:
//   - sequential runPM (after the auto-resolve clarification loop)
//   - parallel runPMParallel (no auto-resolve loop)
//   - runEvolve (no auto-resolve loop)
//
// A regression here would silently re-open the fail-open class of bug those
// sites exist to close, so the cases below are deliberately exhaustive.
func TestLooksLikeClarificationQuestion(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		expect bool
	}{
		// --- Positive cases: real clarification patterns LLMs emit ---
		{
			name:   "before-i-proceed phrasing",
			input:  "Before I proceed, should I use option A or option B?",
			expect: true,
		},
		{
			name:   "would-you-like-me-to phrasing",
			input:  "Would you like me to write tests for this change?",
			expect: true,
		},
		{
			name:   "could-you-clarify phrasing",
			input:  "Could you clarify which migration strategy you prefer?",
			expect: true,
		},
		{
			name:   "do-you-want-me-to phrasing",
			input:  "Do you want me to also update the README?",
			expect: true,
		},
		{
			name:   "which-approach phrasing",
			input:  "Which approach would you prefer for the rollback path?",
			expect: true,
		},
		{
			name:   "please-confirm phrasing",
			input:  "Please confirm: should the cache be invalidated on shutdown?",
			expect: true,
		},
		{
			name:   "let-me-know-if phrasing",
			input:  "Let me know if you'd like a different format?",
			expect: true,
		},
		{
			name:   "would-you-prefer phrasing",
			input:  "Would you prefer the synchronous or asynchronous variant?",
			expect: true,
		},
		{
			name:   "i-have-a-few-questions phrasing",
			input:  "I have a few questions before I can implement this. Where is the schema defined?",
			expect: true,
		},
		{
			name:   "couple-of-questions phrasing",
			input:  "I have a couple of questions about the requirements. Should X behave like Y?",
			expect: true,
		},
		{
			name:   "how-should-i phrasing",
			input:  "How should I handle the case where the file doesn't exist?",
			expect: true,
		},
		{
			name:   "what-would-you phrasing",
			input:  "What would you like the timeout default to be?",
			expect: true,
		},
		{
			name:   "awaiting-your phrasing",
			input:  "Awaiting your guidance on this. Should I proceed with option A?",
			expect: true,
		},
		{
			name:   "need-your-input phrasing",
			input:  "I need your input on the schema. Are nullable columns acceptable?",
			expect: true,
		},
		{
			name:   "how-do-you-want phrasing",
			input:  "How do you want errors logged — JSON or plain text?",
			expect: true,
		},
		{
			name:   "case insensitive — uppercase",
			input:  "BEFORE I PROCEED, SHOULD I USE OPTION A?",
			expect: true,
		},
		{
			name:   "case insensitive — title case",
			input:  "Before I Proceed, Should I Use Option A?",
			expect: true,
		},
		{
			name:   "multi-line clarification",
			input:  "I started working on this but ran into a question.\n\nBefore I proceed, should I assume the input is sorted?",
			expect: true,
		},
		{
			name:   "multiple question marks",
			input:  "Before I proceed: A or B? Or maybe C? Or do you want both?",
			expect: true,
		},

		// --- Negative cases: must NOT trip the heuristic ---
		{
			name:   "empty string",
			input:  "",
			expect: false,
		},
		{
			name:   "whitespace only",
			input:  "   \n\t  \n",
			expect: false,
		},
		{
			name:   "pattern but no question mark",
			input:  "I have a couple of questions answered already in the spec.",
			expect: false,
		},
		{
			name:   "question mark but no pattern",
			input:  "Done. Is this what you wanted? TASK_DONE",
			expect: false,
		},
		{
			name:   "completion summary with rhetorical question — no pattern",
			input:  "Implemented the migration. Want a follow-up PR? Sure thing.",
			expect: false,
		},
		{
			name:   "code-block style question marks but no pattern",
			input:  "Updated the regex to `^foo\\?bar$` and added tests for `?` escaping.",
			expect: false,
		},
		{
			name:   "no questions, no patterns",
			input:  "Implemented and tested. All checks pass.",
			expect: false,
		},
		{
			name:   "trailing-space-sensitive: 'should i' without trailing space and no other pattern",
			// "Should I?" has no trailing space after "i", and no other pattern.
			// The pattern list uses "should i " (with trailing space) precisely
			// to require a word boundary, so this must be a negative.
			input:  "Should I?",
			expect: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := looksLikeClarificationQuestion(tt.input)
			if got != tt.expect {
				t.Errorf("looksLikeClarificationQuestion(%q) = %v, want %v", tt.input, got, tt.expect)
			}
		})
	}
}
