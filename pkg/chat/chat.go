// Package chat provides an interactive conversational PM interface.
package chat

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/memory"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/state"
)

// Turn represents a single conversation turn.
type Turn struct {
	Role    string // "user" or "assistant"
	Content string
}

// Session holds the state of an interactive chat session.
type Session struct {
	State    *state.ProjectState
	Memory   *memory.Memory
	History  []Turn
	Provider provider.Provider
	Model    string
	Timeout  time.Duration

	// Action callbacks — called when AI emits a PM directive.
	OnTaskUpdate func(taskID int, status pm.TaskStatus) error
	OnTaskCreate func(title, description string, priority int) (*pm.Task, error)
	OnNote       func(text string) error
}

// NewSession creates a new chat session.
func NewSession(s *state.ProjectState, mem *memory.Memory, prov provider.Provider, model string) *Session {
	return &Session{
		State:    s,
		Memory:   mem,
		Provider: prov,
		Model:    model,
		Timeout:  120 * time.Second,
		History:  []Turn{},
	}
}

// Send sends a user message and returns the AI response.
// It also parses and applies any PM actions found in the response.
func (sess *Session) Send(ctx context.Context, userMsg string) (string, []ActionResult, error) {
	// Build the full prompt: system context + history + new message
	prompt := sess.buildPrompt(userMsg)

	ctx, cancel := context.WithTimeout(ctx, sess.Timeout)
	defer cancel()

	result, err := sess.Provider.Complete(ctx, prompt, provider.Options{
		Model:   sess.Model,
		Timeout: sess.Timeout,
	})
	if err != nil {
		return "", nil, fmt.Errorf("chat: %w", err)
	}

	// Record in history
	sess.History = append(sess.History, Turn{Role: "user", Content: userMsg})
	sess.History = append(sess.History, Turn{Role: "assistant", Content: result.Output})

	// Trim history to last 20 turns (10 exchanges) to avoid prompt blowup
	if len(sess.History) > 20 {
		sess.History = sess.History[len(sess.History)-20:]
	}

	// Parse and apply actions
	actions := ParseActions(result.Output)
	results := sess.applyActions(actions)

	return result.Output, results, nil
}

// ActionType identifies the kind of PM action the AI wants to take.
type ActionType string

const (
	ActionTaskDone    ActionType = "TASK_DONE"
	ActionTaskFail    ActionType = "TASK_FAIL"
	ActionTaskSkip    ActionType = "TASK_SKIP"
	ActionTaskStart   ActionType = "TASK_START"
	ActionTaskCreate  ActionType = "TASK_CREATE"
	ActionNote        ActionType = "NOTE"
	ActionGoalDone    ActionType = "GOAL_COMPLETE"
)

// Action represents a PM directive embedded in an AI response.
type Action struct {
	Type   ActionType
	Args   []string // parsed arguments
	Raw    string   // original directive line
}

// ActionResult records what happened when an action was applied.
type ActionResult struct {
	Action  Action
	Success bool
	Message string
}

// ParseActions scans AI output for embedded PM directives.
// Directives look like: ACTION:TASK_DONE:3 or ACTION:TASK_CREATE:Title:Description:2
func ParseActions(text string) []Action {
	var actions []Action
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "ACTION:") {
			continue
		}
		raw := line
		parts := strings.SplitN(strings.TrimPrefix(line, "ACTION:"), ":", -1)
		if len(parts) == 0 {
			continue
		}
		a := Action{
			Type: ActionType(strings.ToUpper(parts[0])),
			Args: parts[1:],
			Raw:  raw,
		}
		actions = append(actions, a)
	}
	return actions
}

func (sess *Session) applyActions(actions []Action) []ActionResult {
	var results []ActionResult
	for _, a := range actions {
		r := ActionResult{Action: a}
		switch a.Type {
		case ActionTaskDone:
			r = sess.applyTaskStatus(a, pm.TaskDone)
		case ActionTaskFail:
			r = sess.applyTaskStatus(a, pm.TaskFailed)
		case ActionTaskSkip:
			r = sess.applyTaskStatus(a, pm.TaskSkipped)
		case ActionTaskStart:
			r = sess.applyTaskStatus(a, pm.TaskInProgress)
		case ActionTaskCreate:
			r = sess.applyTaskCreate(a)
		case ActionNote:
			r = sess.applyNote(a)
		case ActionGoalDone:
			r = ActionResult{Action: a, Success: true, Message: "Goal marked as complete"}
		default:
			r = ActionResult{Action: a, Success: false, Message: fmt.Sprintf("unknown action type: %s", a.Type)}
		}
		results = append(results, r)
	}
	return results
}

func (sess *Session) applyTaskStatus(a Action, status pm.TaskStatus) ActionResult {
	if len(a.Args) == 0 {
		return ActionResult{Action: a, Success: false, Message: "missing task ID"}
	}
	id, err := strconv.Atoi(a.Args[0])
	if err != nil {
		return ActionResult{Action: a, Success: false, Message: "invalid task ID: " + a.Args[0]}
	}
	if sess.State.Plan == nil {
		return ActionResult{Action: a, Success: false, Message: "no task plan"}
	}
	for _, t := range sess.State.Plan.Tasks {
		if t.ID == id {
			old := t.Status
			t.Status = status
			if sess.OnTaskUpdate != nil {
				if err := sess.OnTaskUpdate(id, status); err != nil {
					t.Status = old
					return ActionResult{Action: a, Success: false, Message: err.Error()}
				}
			}
			return ActionResult{Action: a, Success: true, Message: fmt.Sprintf("Task #%d status → %s", id, status)}
		}
	}
	return ActionResult{Action: a, Success: false, Message: fmt.Sprintf("task #%d not found", id)}
}

func (sess *Session) applyTaskCreate(a Action) ActionResult {
	title := ""
	description := ""
	priority := 3
	if len(a.Args) > 0 {
		title = a.Args[0]
	}
	if len(a.Args) > 1 {
		description = a.Args[1]
	}
	if len(a.Args) > 2 {
		if p, err := strconv.Atoi(a.Args[2]); err == nil {
			priority = p
		}
	}
	if title == "" {
		return ActionResult{Action: a, Success: false, Message: "task title required"}
	}
	if sess.State.Plan == nil {
		sess.State.Plan = &pm.Plan{}
	}
	if sess.OnTaskCreate != nil {
		t, err := sess.OnTaskCreate(title, description, priority)
		if err != nil {
			return ActionResult{Action: a, Success: false, Message: err.Error()}
		}
		return ActionResult{Action: a, Success: true, Message: fmt.Sprintf("Created task #%d: %s", t.ID, t.Title)}
	}
	// Fallback: create directly on plan
	maxID := 0
	for _, t := range sess.State.Plan.Tasks {
		if t.ID > maxID {
			maxID = t.ID
		}
	}
	t := &pm.Task{
		ID:          maxID + 1,
		Title:       title,
		Description: description,
		Priority:    priority,
		Status:      pm.TaskPending,
	}
	sess.State.Plan.Tasks = append(sess.State.Plan.Tasks, t)
	return ActionResult{Action: a, Success: true, Message: fmt.Sprintf("Created task #%d: %s", t.ID, t.Title)}
}

func (sess *Session) applyNote(a Action) ActionResult {
	text := strings.Join(a.Args, ":")
	if text == "" {
		return ActionResult{Action: a, Success: false, Message: "note text required"}
	}
	if sess.OnNote != nil {
		if err := sess.OnNote(text); err != nil {
			return ActionResult{Action: a, Success: false, Message: err.Error()}
		}
	} else if sess.Memory != nil {
		sess.Memory.Add(text, "chat", sess.State.Goal, []string{"chat", "note"})
	}
	return ActionResult{Action: a, Success: true, Message: "Note saved"}
}

// buildPrompt assembles the full prompt: system context + conversation history + new message.
func (sess *Session) buildPrompt(userMsg string) string {
	var b strings.Builder

	b.WriteString(sess.buildSystemContext())
	b.WriteString("\n\n---\n\n")

	// Conversation history
	if len(sess.History) > 0 {
		b.WriteString("## CONVERSATION HISTORY\n\n")
		for _, turn := range sess.History {
			if turn.Role == "user" {
				b.WriteString("User: ")
			} else {
				b.WriteString("Assistant: ")
			}
			b.WriteString(turn.Content)
			b.WriteString("\n\n")
		}
	}

	b.WriteString("## CURRENT MESSAGE\n\n")
	b.WriteString("User: ")
	b.WriteString(userMsg)
	b.WriteString("\n\n")

	b.WriteString("## INSTRUCTIONS\n\n")
	b.WriteString("You are an expert AI product manager assistant. Respond helpfully and concisely to the user's message.\n")
	b.WriteString("You have full knowledge of this project's state, tasks, and history.\n\n")
	b.WriteString("To take PM actions, emit directives on their own lines using this format:\n")
	b.WriteString("  ACTION:TASK_DONE:3         (mark task #3 as done)\n")
	b.WriteString("  ACTION:TASK_FAIL:5         (mark task #5 as failed)\n")
	b.WriteString("  ACTION:TASK_SKIP:2         (mark task #2 as skipped)\n")
	b.WriteString("  ACTION:TASK_START:4        (mark task #4 as in progress)\n")
	b.WriteString("  ACTION:TASK_CREATE:Title:Description:Priority  (create new task)\n")
	b.WriteString("  ACTION:NOTE:text           (save a note to project memory)\n\n")
	b.WriteString("Only emit ACTION directives when the user explicitly asks you to update or create tasks.\n")
	b.WriteString("Keep your response focused. Reference specific task IDs and project data when relevant.\n")

	return b.String()
}

func (sess *Session) buildSystemContext() string {
	var b strings.Builder
	s := sess.State

	b.WriteString("## PROJECT CONTEXT\n\n")
	b.WriteString(fmt.Sprintf("Goal:    %s\n", s.Goal))
	b.WriteString(fmt.Sprintf("Status:  %s\n", s.Status))
	if s.Provider != "" {
		b.WriteString(fmt.Sprintf("Provider: %s", s.Provider))
		if s.Model != "" {
			b.WriteString(fmt.Sprintf(" / %s", s.Model))
		}
		b.WriteString("\n")
	}
	elapsed := time.Since(s.CreatedAt).Round(time.Second)
	b.WriteString(fmt.Sprintf("Age:     %s\n", elapsed))
	if s.TotalInputTokens > 0 || s.TotalOutputTokens > 0 {
		b.WriteString(fmt.Sprintf("Tokens:  %d in / %d out\n", s.TotalInputTokens, s.TotalOutputTokens))
	}

	// Task plan
	if s.PMMode && s.Plan != nil && len(s.Plan.Tasks) > 0 {
		b.WriteString("\n## TASKS\n\n")
		done, failed := s.Plan.CountByStatus()
		pending, inprog := 0, 0
		for _, t := range s.Plan.Tasks {
			switch t.Status {
			case pm.TaskPending:
				pending++
			case pm.TaskInProgress:
				inprog++
			}
		}
		b.WriteString(fmt.Sprintf("Total: %d  |  Done: %d  |  Failed: %d  |  In-progress: %d  |  Pending: %d\n\n",
			len(s.Plan.Tasks), done, failed, inprog, pending))

		sorted := make([]*pm.Task, len(s.Plan.Tasks))
		copy(sorted, s.Plan.Tasks)
		sort.SliceStable(sorted, func(i, j int) bool {
			return sorted[i].Priority < sorted[j].Priority
		})

		for _, t := range sorted {
			marker := taskMarker(t.Status)
			b.WriteString(fmt.Sprintf("%s #%d [P%d]", marker, t.ID, t.Priority))
			if t.Role != "" {
				b.WriteString(fmt.Sprintf(" [%s]", t.Role))
			}
			b.WriteString(fmt.Sprintf(" %s\n", t.Title))
			if t.Description != "" {
				b.WriteString(fmt.Sprintf("     %s\n", truncate(t.Description, 150)))
			}
			if len(t.DependsOn) > 0 {
				deps := make([]string, len(t.DependsOn))
				for i, d := range t.DependsOn {
					deps[i] = fmt.Sprintf("#%d", d)
				}
				b.WriteString(fmt.Sprintf("     depends: %s\n", strings.Join(deps, ", ")))
			}
			if t.Result != "" {
				b.WriteString(fmt.Sprintf("     result: %s\n", truncate(t.Result, 120)))
			}
		}
	} else {
		b.WriteString(fmt.Sprintf("\n## STEPS\nCompleted: %d", s.CurrentStep))
		if s.MaxSteps > 0 {
			b.WriteString(fmt.Sprintf(" / %d max", s.MaxSteps))
		}
		b.WriteString("\n")
	}

	// Recent step activity
	recent := s.LastNSteps(5)
	if len(recent) > 0 {
		b.WriteString("\n## RECENT ACTIVITY\n\n")
		for _, step := range recent {
			b.WriteString(fmt.Sprintf("Step %d: %s (%s)\n", step.Step, step.Task, step.Duration))
			if step.Output != "" {
				out := step.Output
				if len(out) > 300 {
					out = out[:300] + "...(truncated)"
				}
				b.WriteString(out)
				b.WriteString("\n")
			}
			b.WriteString("\n")
		}
	}

	// Memory
	if sess.Memory != nil {
		if memStr := sess.Memory.FormatForPrompt(10); memStr != "" {
			b.WriteString("\n")
			b.WriteString(memStr)
		}
	}

	return b.String()
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
