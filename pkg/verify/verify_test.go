package verify

import (
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/pm"
)

// makeTask is a helper to build a *pm.Task for tests.
func makeTask(id int, title, description string) *pm.Task {
	return &pm.Task{
		ID:          id,
		Title:       title,
		Description: description,
	}
}

// -----------------------------------------------------------------
// GenerateScriptPrompt
// -----------------------------------------------------------------

func TestGenerateScriptPrompt_ContainsTaskDetails(t *testing.T) {
	task := makeTask(7, "Add Prometheus metrics endpoint", "Expose /metrics via HTTP")
	output := "I created pkg/metrics/metrics.go and registered the handler."

	prompt := GenerateScriptPrompt(task, output)

	if !strings.Contains(prompt, "7") {
		t.Error("prompt should contain task ID")
	}
	if !strings.Contains(prompt, "Add Prometheus metrics endpoint") {
		t.Error("prompt should contain task title")
	}
	if !strings.Contains(prompt, "Expose /metrics via HTTP") {
		t.Error("prompt should contain task description")
	}
	if !strings.Contains(prompt, output) {
		t.Error("prompt should contain task output")
	}
}

func TestGenerateScriptPrompt_ContainsInstructions(t *testing.T) {
	task := makeTask(1, "Test task", "")
	prompt := GenerateScriptPrompt(task, "done")

	for _, keyword := range []string{
		"bash",
		"exit",
		"```bash",
		"5-15 lines",
	} {
		if !strings.Contains(prompt, keyword) {
			t.Errorf("prompt should contain %q", keyword)
		}
	}
}

func TestGenerateScriptPrompt_NoDescriptionOmitted(t *testing.T) {
	task := makeTask(3, "No-desc task", "")
	prompt := GenerateScriptPrompt(task, "output here")
	// Should not have a "Description:" line when description is empty.
	if strings.Contains(prompt, "Description:") {
		t.Error("prompt should not include Description line when description is empty")
	}
}

func TestGenerateScriptPrompt_LongOutputTruncated(t *testing.T) {
	task := makeTask(2, "Long output task", "desc")
	// Build output longer than 2000 chars.
	longOutput := strings.Repeat("x", 2500)
	prompt := GenerateScriptPrompt(task, longOutput)

	if strings.Contains(prompt, longOutput) {
		t.Error("long output should be truncated in the prompt")
	}
	if !strings.Contains(prompt, "truncated") {
		t.Error("prompt should indicate truncation occurred")
	}
}

func TestGenerateScriptPrompt_ShortOutputNotTruncated(t *testing.T) {
	task := makeTask(4, "Short output task", "desc")
	output := "short output"
	prompt := GenerateScriptPrompt(task, output)

	if !strings.Contains(prompt, output) {
		t.Error("short output should appear verbatim in the prompt")
	}
	if strings.Contains(prompt, "truncated") {
		t.Error("short output should not be truncated")
	}
}

// -----------------------------------------------------------------
// ParseScript
// -----------------------------------------------------------------

func TestParseScript_BashCodeBlock(t *testing.T) {
	input := "Here is your script:\n```bash\nls -la\necho done\n```\nEnd."
	got := ParseScript(input)
	want := "ls -la\necho done"
	if got != want {
		t.Errorf("ParseScript() = %q, want %q", got, want)
	}
}

func TestParseScript_GenericCodeBlock(t *testing.T) {
	input := "```\ngrep foo bar.txt\n```"
	got := ParseScript(input)
	want := "grep foo bar.txt"
	if got != want {
		t.Errorf("ParseScript() = %q, want %q", got, want)
	}
}

func TestParseScript_NoCodeBlock_ReturnsTrimmed(t *testing.T) {
	input := "  ls -la\necho done  "
	got := ParseScript(input)
	want := "ls -la\necho done"
	if got != want {
		t.Errorf("ParseScript() = %q, want %q", got, want)
	}
}

func TestParseScript_EmptyResponse(t *testing.T) {
	got := ParseScript("")
	if got != "" {
		t.Errorf("ParseScript(\"\") = %q, want empty string", got)
	}
}

func TestParseScript_BashBlockPreferredOverGeneric(t *testing.T) {
	// If both ```bash and ``` blocks are present, ```bash should win.
	input := "```\ngeneric\n```\n\n```bash\nspecific\n```"
	got := ParseScript(input)
	// The function finds ```bash first (it appears later in the string, but the
	// search tries ```bash before generic ```).
	if !strings.Contains(got, "specific") {
		t.Errorf("ParseScript should prefer ```bash block, got %q", got)
	}
}

func TestParseScript_MultilineScript(t *testing.T) {
	script := "#!/usr/bin/env bash\nset -e\ntest -f go.mod\necho 'go.mod exists'\ngo build ./...\necho 'build ok'"
	input := "```bash\n" + script + "\n```"
	got := ParseScript(input)
	if got != script {
		t.Errorf("ParseScript() = %q, want %q", got, script)
	}
}

func TestParseScript_TrailingWhitespace(t *testing.T) {
	input := "```bash\n  ls -la  \n```"
	got := ParseScript(input)
	// TrimSpace on the extracted block.
	if got != "ls -la" {
		t.Errorf("ParseScript() = %q, want %q", got, "ls -la")
	}
}
