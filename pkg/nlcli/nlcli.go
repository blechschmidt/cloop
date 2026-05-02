// Package nlcli implements natural language CLI dispatch: it sends a free-text
// user instruction plus the list of available cloop commands to an AI provider
// and receives back a concrete CLI invocation that can be re-executed.
package nlcli

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/provider"
)

// InterpretResult is the structured response returned by the AI.
type InterpretResult struct {
	// Command is the cloop sub-command (e.g. "run", "task", "pivot").
	Command string `json:"command"`
	// Args are the positional and flag arguments for the sub-command.
	Args []string `json:"args"`
	// Explanation is a short human-readable description of what the resolved
	// command will do.
	Explanation string `json:"explanation"`
}

// buildPrompt constructs the prompt sent to the AI.
func buildPrompt(input string, availableCommands []string) string {
	var b strings.Builder

	b.WriteString("You are a cloop CLI assistant. Your job is to translate a free-text user instruction into a concrete cloop CLI invocation.\n\n")

	b.WriteString("## AVAILABLE COMMANDS\n")
	for _, c := range availableCommands {
		b.WriteString("  ")
		b.WriteString(c)
		b.WriteString("\n")
	}
	b.WriteString("\n")

	b.WriteString("## USER INSTRUCTION\n")
	b.WriteString(input)
	b.WriteString("\n\n")

	b.WriteString("## RULES\n")
	b.WriteString("1. Choose the single most appropriate command from the list above.\n")
	b.WriteString("2. Include any necessary flags or positional arguments.\n")
	b.WriteString("3. Do NOT invent commands that are not in the list.\n")
	b.WriteString("4. Keep args as a flat list of strings (each flag or value is a separate element).\n")
	b.WriteString("5. Provide a concise explanation (1-2 sentences) of what the resolved command will do.\n\n")

	b.WriteString("## OUTPUT FORMAT\n")
	b.WriteString("Respond with ONLY a single JSON object — no markdown fences, no prose:\n\n")
	b.WriteString(`{
  "command": "<sub-command>",
  "args": ["<arg1>", "<arg2>", ...],
  "explanation": "<what this command will do>"
}`)
	b.WriteString("\n")

	return b.String()
}

// stripFences removes optional ```json ... ``` wrapping that some models add.
func stripFences(s string) string {
	if strings.HasPrefix(s, "```") {
		idx := strings.Index(s, "\n")
		if idx >= 0 {
			s = s[idx+1:]
		}
		if end := strings.LastIndex(s, "```"); end >= 0 {
			s = s[:end]
		}
		s = strings.TrimSpace(s)
	}
	return s
}

// Interpret sends the user instruction plus the available command list to the
// AI provider and returns the resolved sub-command, its arguments, and a plain
// English explanation of what will be run.
//
//   - ctx       — request context (use for timeout/cancellation)
//   - p         — AI provider to use for the call
//   - model     — model override; empty string uses the provider default
//   - input     — free-text user instruction (e.g. "show me what tasks are left")
//   - availableCommands — slice of command name strings (e.g. "run", "status", ...)
func Interpret(
	ctx context.Context,
	p provider.Provider,
	model string,
	input string,
	availableCommands []string,
) (*InterpretResult, error) {
	if strings.TrimSpace(input) == "" {
		return nil, fmt.Errorf("input cannot be empty")
	}

	prompt := buildPrompt(input, availableCommands)

	result, err := p.Complete(ctx, prompt, provider.Options{
		Model:   model,
		Timeout: 30 * time.Second,
	})
	if err != nil {
		return nil, fmt.Errorf("nlcli: AI call: %w", err)
	}

	raw := strings.TrimSpace(result.Output)
	raw = stripFences(raw)

	var ir InterpretResult
	if err := json.Unmarshal([]byte(raw), &ir); err != nil {
		return nil, fmt.Errorf("nlcli: parse AI response: %w\nraw:\n%s", err, raw)
	}

	ir.Command = strings.TrimSpace(ir.Command)
	if ir.Command == "" {
		return nil, fmt.Errorf("nlcli: AI returned empty command")
	}

	return &ir, nil
}
