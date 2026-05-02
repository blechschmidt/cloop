// Package coach provides per-task AI coaching tips before task execution.
// Unlike explain (which narrates what will happen), coaching is prescriptive:
// it gives the executor concrete advice on how to approach the task well,
// what to watch out for, and common pitfalls to avoid.
package coach

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
)

// Tip is a single coaching tip with a category label.
type Tip struct {
	// Category is one of: approach, pitfall, quality, speed, security, testing
	Category string `json:"category"`
	// Advice is the actionable coaching advice (1-3 sentences).
	Advice string `json:"advice"`
}

// CoachingSession holds the full coaching output for a task.
type CoachingSession struct {
	TaskID          int      `json:"task_id"`
	TaskTitle       string   `json:"task_title"`
	Tips            []Tip    `json:"tips"`
	KeyQuestion     string   `json:"key_question"`
	SuccessCriteria []string `json:"success_criteria"`
}

// Coach generates a coaching session for the given task.
// model may be empty (the provider will use its default).
// workDir is used for future context injection but is currently informational.
func Coach(ctx context.Context, p provider.Provider, model string, task *pm.Task, plan *pm.Plan, workDir string) (*CoachingSession, error) {
	if task == nil {
		return nil, fmt.Errorf("task is nil")
	}

	prompt := buildPrompt(task, plan)

	result, err := p.Complete(ctx, prompt, provider.Options{
		Model:   model,
		Timeout: 3 * time.Minute,
	})
	if err != nil {
		return nil, fmt.Errorf("coach: %w", err)
	}

	session, err := parseResponse(result.Output, task)
	if err != nil {
		return nil, fmt.Errorf("coach: parsing response: %w", err)
	}
	return session, nil
}

// buildPrompt constructs the AI prompt for the coaching call.
func buildPrompt(task *pm.Task, plan *pm.Plan) string {
	var b strings.Builder

	b.WriteString("You are a senior engineer who has completed hundreds of software tasks like this one. ")
	b.WriteString("A developer is about to start the task below. Your job is to give them expert coaching BEFORE they begin: ")
	b.WriteString("concrete, actionable tips on how to approach it well, what pitfalls to avoid, and what good execution looks like.\n\n")

	b.WriteString("## PROJECT GOAL\n")
	if plan != nil {
		b.WriteString(plan.Goal)
	} else {
		b.WriteString("(no plan context)")
	}
	b.WriteString("\n\n")

	// Plan progress context
	if plan != nil {
		total := len(plan.Tasks)
		done := 0
		for _, t := range plan.Tasks {
			if t.Status == pm.TaskDone || t.Status == pm.TaskSkipped {
				done++
			}
		}
		b.WriteString(fmt.Sprintf("## PLAN PROGRESS\n%d/%d tasks complete\n\n", done, total))

		// Show recently completed tasks as context
		var recent []string
		for _, t := range plan.Tasks {
			if t.Status == pm.TaskDone && t.ID != task.ID {
				recent = append(recent, fmt.Sprintf("#%d %s", t.ID, t.Title))
				if len(recent) >= 3 {
					break
				}
			}
		}
		if len(recent) > 0 {
			b.WriteString("## RECENTLY COMPLETED\n")
			for _, r := range recent {
				b.WriteString(fmt.Sprintf("- %s\n", r))
			}
			b.WriteString("\n")
		}
	}

	b.WriteString("## TASK TO COACH\n")
	b.WriteString(fmt.Sprintf("ID: #%d\n", task.ID))
	b.WriteString(fmt.Sprintf("Title: %s\n", task.Title))
	if task.Description != "" {
		b.WriteString(fmt.Sprintf("Description: %s\n", task.Description))
	}
	if task.Role != "" {
		b.WriteString(fmt.Sprintf("Role: %s\n", task.Role))
	}
	if task.EstimatedMinutes > 0 {
		b.WriteString(fmt.Sprintf("Estimated time: %d minutes\n", task.EstimatedMinutes))
	}
	if len(task.DependsOn) > 0 {
		deps := make([]string, len(task.DependsOn))
		for i, d := range task.DependsOn {
			deps[i] = fmt.Sprintf("#%d", d)
		}
		b.WriteString(fmt.Sprintf("Depends on: %s\n", strings.Join(deps, ", ")))
	}
	if len(task.Tags) > 0 {
		b.WriteString(fmt.Sprintf("Tags: %s\n", strings.Join(task.Tags, ", ")))
	}
	b.WriteString("\n")

	b.WriteString("## INSTRUCTIONS\n")
	b.WriteString("Respond with ONLY a JSON object (no markdown fences, no extra text) in this exact schema:\n\n")
	b.WriteString(`{
  "tips": [
    {
      "category": "<one of: approach, pitfall, quality, speed, security, testing>",
      "advice": "<1-3 sentence actionable tip>"
    }
  ],
  "key_question": "<the single most important thing to clarify or decide before starting>",
  "success_criteria": [
    "<observable, concrete signal that this task is done correctly>",
    "..."
  ]
}`)
	b.WriteString("\n\n")
	b.WriteString("Rules:\n")
	b.WriteString("- Include 3 to 5 tips (mix categories appropriately for this task)\n")
	b.WriteString("- Each tip must be specific to THIS task — no generic advice\n")
	b.WriteString("- success_criteria: 2-4 items, each one concrete and observable\n")
	b.WriteString("- key_question: exactly one question, not a list\n")
	b.WriteString("- Output valid JSON only — no markdown, no explanations outside the JSON\n")

	return b.String()
}

// parseResponse parses the AI JSON response into a CoachingSession.
// Falls back gracefully if the JSON is wrapped in markdown fences.
func parseResponse(raw string, task *pm.Task) (*CoachingSession, error) {
	raw = strings.TrimSpace(raw)

	// Strip markdown code fences if present
	if strings.HasPrefix(raw, "```") {
		lines := strings.Split(raw, "\n")
		// Drop first line (```json or ```) and last line (```)
		if len(lines) >= 2 {
			end := len(lines) - 1
			for end > 0 && strings.TrimSpace(lines[end]) == "```" {
				end--
			}
			raw = strings.Join(lines[1:end+1], "\n")
		}
	}

	// Find the JSON object boundaries
	start := strings.Index(raw, "{")
	end := strings.LastIndex(raw, "}")
	if start < 0 || end < 0 || end <= start {
		return nil, fmt.Errorf("no JSON object found in response")
	}
	raw = raw[start : end+1]

	var payload struct {
		Tips            []Tip    `json:"tips"`
		KeyQuestion     string   `json:"key_question"`
		SuccessCriteria []string `json:"success_criteria"`
	}
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		return nil, fmt.Errorf("JSON parse error: %w", err)
	}

	if len(payload.Tips) == 0 {
		return nil, fmt.Errorf("response contained no tips")
	}

	return &CoachingSession{
		TaskID:          task.ID,
		TaskTitle:       task.Title,
		Tips:            payload.Tips,
		KeyQuestion:     payload.KeyQuestion,
		SuccessCriteria: payload.SuccessCriteria,
	}, nil
}
