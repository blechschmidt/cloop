// Package voice provides NLP intent parsing for voice-based task management.
// It takes a transcribed text string, calls an AI provider to extract the
// user's intent, and returns a structured IntentResult ready for execution.
package voice

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/blechschmidt/cloop/pkg/provider"
)

// Action is the type of operation the user wants to perform.
type Action string

const (
	ActionAddTask       Action = "add_task"
	ActionListTasks     Action = "list_tasks"
	ActionMarkDone      Action = "mark_done"
	ActionMarkFailed    Action = "mark_failed"
	ActionSetPriority   Action = "set_priority"
	ActionStartRun      Action = "start_run"
	ActionStopRun       Action = "stop_run"
	ActionShowStatus    Action = "show_status"
	ActionShowGoal      Action = "show_goal"
	ActionReorderTasks  Action = "reorder_tasks"
	ActionGenerateRetro Action = "generate_retro"
	ActionUnknown       Action = "unknown"
)

// IntentResult holds the parsed user intent and parameters.
type IntentResult struct {
	// Transcription is the raw text from speech-to-text.
	Transcription string `json:"transcription"`

	// Action is the detected operation.
	Action Action `json:"action"`

	// TaskTitle is populated for add_task.
	TaskTitle string `json:"task_title,omitempty"`

	// TaskDescription is populated for add_task.
	TaskDescription string `json:"task_description,omitempty"`

	// TaskID is populated for mark_done, mark_failed, set_priority.
	TaskID int `json:"task_id,omitempty"`

	// Priority (1=highest) for add_task / set_priority.
	Priority int `json:"priority,omitempty"`

	// CloopArgs holds the resolved cloop command arguments for execution.
	// e.g. ["task", "add", "Fix the login bug"]
	CloopArgs []string `json:"cloop_args,omitempty"`

	// Explanation is a human-friendly description of the resolved action.
	Explanation string `json:"explanation,omitempty"`
}

// intentJSON is the schema the AI must return.
type intentJSON struct {
	Action          string   `json:"action"`
	TaskTitle       string   `json:"task_title,omitempty"`
	TaskDescription string   `json:"task_description,omitempty"`
	TaskID          int      `json:"task_id,omitempty"`
	Priority        int      `json:"priority,omitempty"`
	CloopArgs       []string `json:"cloop_args"`
	Explanation     string   `json:"explanation"`
}

// systemPrompt describes the available actions to the AI.
const systemPrompt = `You are a voice command parser for cloop, an AI product manager CLI.

Given a transcribed voice command, extract the user's intent and return ONLY valid JSON
matching this schema (no markdown fences, no prose):

{
  "action": "<one of: add_task|list_tasks|mark_done|mark_failed|set_priority|start_run|stop_run|show_status|show_goal|reorder_tasks|generate_retro|unknown>",
  "task_title": "<title if add_task>",
  "task_description": "<description if add_task>",
  "task_id": <integer task ID if targeting a specific task, else 0>,
  "priority": <1-5 integer; 1=critical, 5=lowest; 0 if not specified>,
  "cloop_args": ["<command>", "<sub>", "<arg1>", ...],
  "explanation": "<one sentence summary of what will be executed>"
}

cloop command mapping:
- add_task       → ["task", "add", "<title>"]
- list_tasks     → ["task", "list"]
- mark_done      → ["task", "status", "<id>", "done"]
- mark_failed    → ["task", "status", "<id>", "failed"]
- set_priority   → ["task", "edit", "<id>", "--priority", "<p>"]
- start_run      → ["run", "--pm"]
- stop_run       → ["stop"]  (placeholder; actual stop is via the daemon)
- show_status    → ["status"]
- show_goal      → ["status"]
- reorder_tasks  → ["task", "reorder"]
- generate_retro → ["retro"]
- unknown        → []

If the intent is unclear, use action "unknown" with empty cloop_args.`

// Parse calls the AI provider to interpret a transcribed voice command.
func Parse(ctx context.Context, p provider.Provider, model, transcription string) (*IntentResult, error) {
	if strings.TrimSpace(transcription) == "" {
		return &IntentResult{
			Transcription: transcription,
			Action:        ActionUnknown,
			Explanation:   "empty transcription",
		}, nil
	}

	prompt := fmt.Sprintf(`%s

Voice command: %q

Return JSON only.`, systemPrompt, transcription)

	opts := provider.Options{
		Model: model,
	}
	result, err := p.Complete(ctx, prompt, opts)
	if err != nil {
		return nil, fmt.Errorf("AI parse: %w", err)
	}

	// Strip potential markdown fences.
	raw := strings.TrimSpace(result.Output)
	raw = strings.TrimPrefix(raw, "```json")
	raw = strings.TrimPrefix(raw, "```")
	raw = strings.TrimSuffix(raw, "```")
	raw = strings.TrimSpace(raw)

	var parsed intentJSON
	if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
		// Fallback: return unknown with the raw text.
		return &IntentResult{
			Transcription: transcription,
			Action:        ActionUnknown,
			Explanation:   "could not parse AI response: " + raw,
		}, nil
	}

	intent := &IntentResult{
		Transcription:   transcription,
		Action:          Action(parsed.Action),
		TaskTitle:       parsed.TaskTitle,
		TaskDescription: parsed.TaskDescription,
		TaskID:          parsed.TaskID,
		Priority:        parsed.Priority,
		CloopArgs:       parsed.CloopArgs,
		Explanation:     parsed.Explanation,
	}
	return intent, nil
}
