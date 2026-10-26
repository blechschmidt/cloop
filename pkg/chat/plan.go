package chat

// The dashboard's plan assistant (Task 200): one question about the plan,
// answered with the whole plan as context. Since Task 20442 the model call is
// made by `cloop plan chat` on the project's executor rather than inside the
// hub, so the prompt lives here, where the subcommand builds it from the state
// it runs against.

import (
	"fmt"
	"strings"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
)

// PlanMessage is one earlier turn of a plan-assistant conversation, as the
// dashboard keeps it.
type PlanMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// PlanSystemPrompt describes the project to the plan assistant: its goal,
// progress, and every task with its status, priority, dependencies and
// annotations. A nil state, or one without a plan, says so.
func PlanSystemPrompt(ps *state.ProjectState) string {
	var b strings.Builder
	b.WriteString("You are a plan-aware AI assistant for the cloop AI product manager.\n")
	b.WriteString("You help the user understand, analyse, and improve their project plan.\n")
	b.WriteString("Be concise, practical, and reference specific task IDs when relevant.\n\n")

	if ps == nil || ps.Plan == nil {
		b.WriteString("No plan is currently initialised for this project.\n")
		return b.String()
	}
	b.WriteString("## Current Plan\n")
	b.WriteString("**Goal:** " + ps.Goal + "\n\n")
	total := len(ps.Plan.Tasks)
	done, inProg, failed, pending := 0, 0, 0, 0
	for _, t := range ps.Plan.Tasks {
		switch t.Status {
		case pm.TaskDone:
			done++
		case pm.TaskInProgress:
			inProg++
		case pm.TaskFailed:
			failed++
		default:
			pending++
		}
	}
	fmt.Fprintf(&b, "**Progress:** %d/%d done, %d in-progress, %d pending, %d failed\n\n",
		done, total, inProg, pending, failed)
	b.WriteString("### Tasks\n")
	for _, t := range ps.Plan.Tasks {
		fmt.Fprintf(&b, "- [#%d] **%s** — status: `%s`, priority: %d", t.ID, t.Title, t.Status, t.Priority)
		if t.Assignee != "" {
			fmt.Fprintf(&b, ", assignee: %s", t.Assignee)
		}
		if t.EstimatedMinutes > 0 {
			fmt.Fprintf(&b, ", est: %dm", t.EstimatedMinutes)
		}
		if t.ActualMinutes > 0 {
			fmt.Fprintf(&b, ", actual: %dm", t.ActualMinutes)
		}
		if len(t.DependsOn) > 0 {
			fmt.Fprintf(&b, ", depends on: %v", t.DependsOn)
		}
		if t.Pinned {
			b.WriteString(", pinned")
		}
		b.WriteString("\n")
		if t.Description != "" {
			fmt.Fprintf(&b, "  %s\n", t.Description)
		}
		if len(t.Annotations) > 0 {
			b.WriteString("  annotations:\n")
			for _, a := range t.Annotations {
				fmt.Fprintf(&b, "    • [%s] %s\n", a.Author, a.Text)
			}
		}
	}
	return b.String()
}

// PlanConversation renders the earlier turns and the new message as the
// prompt. Turns in any role but user and assistant are dropped.
func PlanConversation(history []PlanMessage, msg string) string {
	var b strings.Builder
	for _, h := range history {
		switch h.Role {
		case "user":
			fmt.Fprintf(&b, "Human: %s\n\n", h.Content)
		case "assistant":
			fmt.Fprintf(&b, "Assistant: %s\n\n", h.Content)
		}
	}
	fmt.Fprintf(&b, "Human: %s\n\nAssistant: ", msg)
	return b.String()
}

// RecentPlanHistory keeps the latest turns whose contents together fit in
// maxBytes, in their order. The conversation travels to the executor as an
// argument, which the kernel bounds, so a long one is cut from its start: the
// assistant sees the most recent exchange, which is what the question is
// about. A turn that alone exceeds the budget ends the window.
func RecentPlanHistory(history []PlanMessage, maxBytes int) []PlanMessage {
	used := 0
	start := len(history)
	for i := len(history) - 1; i >= 0; i-- {
		n := len(history[i].Role) + len(history[i].Content)
		if used+n > maxBytes {
			break
		}
		used += n
		start = i
	}
	return history[start:]
}
