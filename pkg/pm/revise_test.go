package pm

// Tests for the prompt and the answer cleanup behind revising a task's details
// from a spoken instruction (Task 20302). They are pure functions tested
// directly, because they are the whole contract with the model, and a test that
// can only reach them through HTTP and a live API key is a test nobody runs.
// The hub's handler and `cloop task revise` are tested where they live.

import (
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// the prompt
// ---------------------------------------------------------------------------

// TestRevisePrompt_CarriesBothInputsAndTheRules pins what the model
// is actually told. Each assertion below is a way the feature silently becomes
// something else: without the current details it writes a new description from
// scratch (which is the Replace button, not this one); without the delimiters a
// description quoting an instruction is read as one; without the "reply with
// only" rule the answer arrives wrapped in "Sure! Here is the revised…" and
// that lands verbatim in somebody's plan.
func TestRevisePrompt_CarriesBothInputsAndTheRules(t *testing.T) {
	const (
		title   = "Bound the artifact reads"
		current = "Cap each read at 1 MiB and log the truncation."
		instr   = "also make sure it works on the glasses page"
	)
	p := RevisePrompt(title, current, instr)

	for _, want := range []string{title, current, instr} {
		if !strings.Contains(p, want) {
			t.Errorf("prompt omits %q:\n%s", want, p)
		}
	}
	for _, tag := range []string{"<details>", "</details>", "<instruction>", "</instruction>"} {
		if !strings.Contains(p, tag) {
			t.Errorf("prompt omits the %s delimiter — free text the user dictated would "+
				"read to the model as part of this prompt:\n%s", tag, p)
		}
	}
	// The instruction has to be framed as being *about* the details, not as a
	// message to the assistant, or "ignore the above" in a description becomes
	// an instruction rather than a quotation.
	if !strings.Contains(p, "strictly as an instruction about the details above") {
		t.Errorf("prompt does not confine the instruction to the details:\n%s", p)
	}
	if !strings.Contains(p, "no code fences") {
		t.Errorf("prompt does not forbid code fences, which is the formatting the "+
			"cleaner then has to guess at:\n%s", p)
	}
	// Two things it must not do. Rewriting the title is invisible here (the
	// title field is not what this writes to) but produces details that open by
	// restating their own heading; inventing scope is how a dictated "and add a
	// test" comes back as four new requirements.
	if !strings.Contains(p, "Do not restate or rewrite the task title.") {
		t.Errorf("prompt does not exclude the title:\n%s", p)
	}
	if !strings.Contains(p, "Do not invent scope") {
		t.Errorf("prompt does not forbid inventing scope:\n%s", p)
	}
}

// ---------------------------------------------------------------------------
// the reply cleaner
// ---------------------------------------------------------------------------

func TestCleanRevisedDescription(t *testing.T) {
	long := strings.Repeat("é", MaxReviseDescriptionRunes+500)

	cases := []struct {
		name string
		in   string
		want string
	}{
		{"plain text survives untouched",
			"Cap each read at 1 MiB.", "Cap each read at 1 MiB."},
		{"surrounding whitespace goes",
			"\n\n  Cap each read.  \n", "Cap each read."},
		{"a fence wrapping the whole answer is unwrapped",
			"```\nCap each read.\n```", "Cap each read."},
		{"a language-tagged fence is unwrapped too",
			"```markdown\nCap each read.\n```", "Cap each read."},
		// The case that makes the "whole answer" qualifier load-bearing: a
		// description legitimately containing a code block must keep it, or
		// this cleaner silently eats the example somebody dictated.
		{"an inner code block is preserved",
			"Do this:\n\n```go\nx := 1\n```\n\nThen that.",
			"Do this:\n\n```go\nx := 1\n```\n\nThen that."},
		// Opens with a fence but does not close at the end — unwrapping would
		// drop the trailing prose.
		{"an unbalanced leading fence is left alone",
			"```go\nx := 1\n```\nand then some prose",
			"```go\nx := 1\n```\nand then some prose"},
		{"nothing at all stays nothing", "   \n ", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := CleanRevisedDescription(c.in); got != c.want {
				t.Errorf("CleanRevisedDescription(%q)\n got %q\nwant %q", c.in, got, c.want)
			}
		})
	}

	t.Run("an enormous answer is capped without splitting a rune", func(t *testing.T) {
		got := CleanRevisedDescription(long)
		if n := len([]rune(got)); n != MaxReviseDescriptionRunes {
			t.Fatalf("capped to %d runes, want %d", n, MaxReviseDescriptionRunes)
		}
		if strings.ContainsRune(got, '�') {
			t.Error("the cap split a multi-byte rune — counting bytes rather than runes " +
				"mangles the non-ASCII prose a dictated description is often made of")
		}
	})
}

func TestTruncateRunes_CountsRunesNotBytes(t *testing.T) {
	const s = "ünïcödé"
	if got := TruncateRunes(s, 3); got != "ünï" {
		t.Errorf("TruncateRunes(%q, 3) = %q, want %q", s, got, "ünï")
	}
	if got := TruncateRunes(s, 100); got != s {
		t.Errorf("TruncateRunes past the end changed the string: %q", got)
	}
	if got := TruncateRunes(s, 0); got != "" {
		t.Errorf("TruncateRunes(_, 0) = %q, want empty", got)
	}
}
