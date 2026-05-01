// Package ask provides AI Q&A with full project context.
package ask

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/memory"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/state"
)

// BuildPrompt constructs an AI Q&A prompt with full project context.
func BuildPrompt(question string, s *state.ProjectState, mem *memory.Memory, recentSteps int) string {
	var b strings.Builder

	b.WriteString("You are an AI product manager assistant with full knowledge of this project.\n")
	b.WriteString("Answer the user's question accurately, concisely, and helpfully.\n\n")

	b.WriteString("## PROJECT STATE\n")
	b.WriteString(fmt.Sprintf("Goal:     %s\n", s.Goal))
	b.WriteString(fmt.Sprintf("Status:   %s\n", s.Status))
	if s.Provider != "" {
		b.WriteString(fmt.Sprintf("Provider: %s\n", s.Provider))
	}
	if s.Model != "" {
		b.WriteString(fmt.Sprintf("Model:    %s\n", s.Model))
	}
	if s.Instructions != "" {
		b.WriteString(fmt.Sprintf("Instructions: %s\n", s.Instructions))
	}
	elapsed := time.Since(s.CreatedAt).Round(time.Second)
	b.WriteString(fmt.Sprintf("Elapsed:  %s\n", elapsed))
	if s.TotalInputTokens > 0 || s.TotalOutputTokens > 0 {
		b.WriteString(fmt.Sprintf("Tokens:   %d in / %d out\n", s.TotalInputTokens, s.TotalOutputTokens))
	}
	b.WriteString("\n")

	if s.PMMode && s.Plan != nil && len(s.Plan.Tasks) > 0 {
		done, failed := s.Plan.CountByStatus()
		pending := 0
		inprog := 0
		for _, t := range s.Plan.Tasks {
			if t.Status == pm.TaskPending {
				pending++
			} else if t.Status == pm.TaskInProgress {
				inprog++
			}
		}

		b.WriteString("## TASK PLAN\n")
		b.WriteString(fmt.Sprintf("Total: %d tasks — %d done, %d failed, %d pending, %d in-progress\n\n",
			len(s.Plan.Tasks), done, failed, pending, inprog))

		sorted := make([]*pm.Task, len(s.Plan.Tasks))
		copy(sorted, s.Plan.Tasks)
		sort.SliceStable(sorted, func(i, j int) bool {
			return sorted[i].Priority < sorted[j].Priority
		})

		for _, t := range sorted {
			marker := taskMarker(t.Status)
			rolePart := ""
			if t.Role != "" {
				rolePart = fmt.Sprintf(" [%s]", t.Role)
			}
			b.WriteString(fmt.Sprintf("  %s #%d [P%d]%s %s\n", marker, t.ID, t.Priority, rolePart, t.Title))
			if t.Description != "" && len(t.Description) < 200 {
				b.WriteString(fmt.Sprintf("       %s\n", t.Description))
			}
			if len(t.DependsOn) > 0 {
				deps := make([]string, len(t.DependsOn))
				for i, d := range t.DependsOn {
					deps[i] = fmt.Sprintf("#%d", d)
				}
				b.WriteString(fmt.Sprintf("       depends on: %s\n", strings.Join(deps, ", ")))
			}
			if t.Result != "" {
				b.WriteString(fmt.Sprintf("       result: %s\n", truncate(t.Result, 150)))
			}
		}
		b.WriteString("\n")
	} else if !s.PMMode {
		b.WriteString(fmt.Sprintf("## STEPS\nCompleted: %d", s.CurrentStep))
		if s.MaxSteps > 0 {
			b.WriteString(fmt.Sprintf(" / %d max", s.MaxSteps))
		}
		b.WriteString("\n\n")
	}

	// Recent step outputs
	if recentSteps > 0 && len(s.Steps) > 0 {
		recent := s.LastNSteps(recentSteps)
		b.WriteString("## RECENT ACTIVITY\n")
		for _, step := range recent {
			b.WriteString(fmt.Sprintf("### %s (%s)\n", step.Task, step.Duration))
			out := step.Output
			if len(out) > 800 {
				out = out[:400] + "\n...(truncated)...\n" + out[len(out)-400:]
			}
			b.WriteString(out)
			b.WriteString("\n\n")
		}
	}

	// Memory
	if mem != nil {
		if memStr := mem.FormatForPrompt(15); memStr != "" {
			b.WriteString(memStr)
		}
	}

	b.WriteString("## QUESTION\n")
	b.WriteString(question)
	b.WriteString("\n\n")
	b.WriteString("Provide a clear, helpful answer. Be specific and reference actual project state where relevant.")

	return b.String()
}

// Ask calls the provider with a question prompt and returns the answer.
func Ask(ctx context.Context, p provider.Provider, question string, s *state.ProjectState, mem *memory.Memory, model string, timeout time.Duration, recentSteps int) (string, error) {
	prompt := BuildPrompt(question, s, mem, recentSteps)
	result, err := p.Complete(ctx, prompt, provider.Options{
		Model:   model,
		Timeout: timeout,
	})
	if err != nil {
		return "", fmt.Errorf("ask: %w", err)
	}
	return result.Output, nil
}

func taskMarker(status pm.TaskStatus) string {
	switch status {
	case pm.TaskDone:
		return "[x]"
	case pm.TaskSkipped:
		return "[-]"
	case pm.TaskFailed:
		return "[!]"
	case pm.TaskInProgress:
		return "[~]"
	default:
		return "[ ]"
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
