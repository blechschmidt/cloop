// Package shell implements an interactive REPL session combining conversational
// AI with plan awareness. It is the backend for the `cloop shell` command.
package shell

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/state"
)

// Message is a single turn in the conversation history.
type Message struct {
	Role    string // "user" or "assistant"
	Content string
}

// Shell holds all state for a running cloop shell session.
type Shell struct {
	State    *state.ProjectState
	Provider provider.Provider
	Model    string
	Timeout  time.Duration
	History  []Message

	// OnToken, if set, enables streaming. Each token chunk is passed to this
	// callback as the AI generates its response.
	OnToken func(token string)

	// OnSave is called after any action that mutates state so that the caller
	// can persist the change to disk.
	OnSave func() error
}

// New creates a Shell with sensible defaults.
func New(s *state.ProjectState, prov provider.Provider, model string) *Shell {
	return &Shell{
		State:    s,
		Provider: prov,
		Model:    model,
		Timeout:  120 * time.Second,
		History:  []Message{},
	}
}

// Run starts the interactive REPL, reading from in and writing to out.
// It returns when the user types /quit or in reaches EOF.
func (sh *Shell) Run(ctx context.Context, in io.Reader, out io.Writer) error {
	fmt.Fprintf(out, "\ncloop shell  [%s]\n", sh.Provider.Name())
	fmt.Fprintf(out, "Project: %s\n", sh.State.Goal)
	fmt.Fprintf(out, "Type /help for commands, /quit to exit\n\n")

	scanner := bufio.NewScanner(in)

	for {
		fmt.Fprintf(out, "cloop> ")

		if !scanner.Scan() {
			fmt.Fprintln(out)
			break
		}

		input := strings.TrimSpace(scanner.Text())
		if input == "" {
			continue
		}

		if strings.HasPrefix(input, "/") {
			done, err := sh.handleCommand(ctx, input, out)
			if err != nil {
				fmt.Fprintf(out, "error: %v\n\n", err)
			}
			if done {
				break
			}
			continue
		}

		// Regular conversational input → send to provider.
		if err := sh.chat(ctx, input, out); err != nil {
			fmt.Fprintf(out, "error: %v\n\n", err)
		}
	}

	return nil
}

// handleCommand processes a slash command and reports whether the REPL should exit.
func (sh *Shell) handleCommand(ctx context.Context, input string, out io.Writer) (exit bool, err error) {
	fields := strings.Fields(input)
	cmd := strings.ToLower(fields[0])

	switch cmd {
	case "/quit", "/exit", "/q":
		fmt.Fprintln(out, "Goodbye!")
		return true, nil

	case "/help", "/h", "/?":
		sh.printHelp(out)
		return false, nil

	case "/status":
		sh.printStatus(out)
		return false, nil

	case "/clear":
		sh.History = nil
		fmt.Fprintln(out, "Conversation history cleared.")
		fmt.Fprintln(out)
		return false, nil

	case "/run":
		if len(fields) < 2 {
			fmt.Fprintln(out, "Usage: /run <task-id>")
			fmt.Fprintln(out)
			return false, nil
		}
		id, parseErr := strconv.Atoi(fields[1])
		if parseErr != nil {
			fmt.Fprintf(out, "Invalid task ID: %s\n\n", fields[1])
			return false, nil
		}
		return false, sh.runTask(ctx, id, out)

	case "/add":
		if len(fields) < 2 {
			fmt.Fprintln(out, "Usage: /add <task title>")
			fmt.Fprintln(out)
			return false, nil
		}
		title := strings.Join(fields[1:], " ")
		return false, sh.addTask(title, out)

	case "/done":
		if len(fields) < 2 {
			fmt.Fprintln(out, "Usage: /done <task-id>")
			fmt.Fprintln(out)
			return false, nil
		}
		id, parseErr := strconv.Atoi(fields[1])
		if parseErr != nil {
			fmt.Fprintf(out, "Invalid task ID: %s\n\n", fields[1])
			return false, nil
		}
		return false, sh.markDone(id, out)

	default:
		fmt.Fprintf(out, "Unknown command: %s  (type /help)\n\n", fields[0])
		return false, nil
	}
}

// chat sends a user message to the provider with plan context injected, streams
// the reply, and appends both turns to History.
func (sh *Shell) chat(ctx context.Context, userMsg string, out io.Writer) error {
	prompt := sh.buildPrompt(userMsg)

	callCtx, cancel := context.WithTimeout(ctx, sh.Timeout)
	defer cancel()

	opts := provider.Options{
		Model:     sh.Model,
		Timeout:   sh.Timeout,
	}

	var streamBuf strings.Builder
	if sh.OnToken != nil {
		opts.OnToken = func(token string) {
			sh.OnToken(token)
			streamBuf.WriteString(token)
		}
		fmt.Fprintf(out, "ai> ")
	}

	result, err := sh.Provider.Complete(callCtx, prompt, opts)
	if err != nil {
		return fmt.Errorf("provider: %w", err)
	}

	response := result.Output
	if sh.OnToken != nil {
		// Streaming was active: response may already have been printed by OnToken.
		// Use whatever was buffered (it equals result.Output for conforming providers).
		fmt.Fprintln(out)
	} else {
		fmt.Fprintf(out, "ai> %s\n", response)
	}
	fmt.Fprintln(out)

	// Append to history.
	sh.History = append(sh.History,
		Message{Role: "user", Content: userMsg},
		Message{Role: "assistant", Content: response},
	)

	return nil
}

// buildPrompt constructs the full prompt: plan context + conversation history + new message.
func (sh *Shell) buildPrompt(userMsg string) string {
	var b strings.Builder

	// System context: who we are.
	b.WriteString("You are an AI product manager assistant embedded in cloop, a project management CLI.\n")
	b.WriteString("You help users manage their project plan through natural conversation.\n\n")

	// Current plan state.
	b.WriteString("## CURRENT PROJECT STATE\n")
	b.WriteString(fmt.Sprintf("Goal: %s\n", sh.State.Goal))
	b.WriteString(fmt.Sprintf("Status: %s\n", sh.State.Status))

	if sh.State.PMMode && sh.State.Plan != nil && len(sh.State.Plan.Tasks) > 0 {
		b.WriteString(fmt.Sprintf("Tasks (%d total):\n", len(sh.State.Plan.Tasks)))
		statusSymbol := map[pm.TaskStatus]string{
			pm.TaskPending:    "[ ]",
			pm.TaskInProgress: "[~]",
			pm.TaskDone:       "[x]",
			pm.TaskSkipped:    "[-]",
			pm.TaskFailed:     "[!]",
		}
		for _, t := range sh.State.Plan.Tasks {
			sym := statusSymbol[t.Status]
			b.WriteString(fmt.Sprintf("  %s #%d (P%d) %s\n", sym, t.ID, t.Priority, t.Title))
		}
	} else {
		b.WriteString("No PM task plan loaded (run `cloop run --pm` to create one).\n")
	}
	b.WriteString("\n")

	// Conversation history.
	if len(sh.History) > 0 {
		b.WriteString("## CONVERSATION HISTORY\n")
		for _, m := range sh.History {
			switch m.Role {
			case "user":
				b.WriteString(fmt.Sprintf("User: %s\n", m.Content))
			case "assistant":
				b.WriteString(fmt.Sprintf("Assistant: %s\n", m.Content))
			}
		}
		b.WriteString("\n")
	}

	// New user message.
	b.WriteString("## USER MESSAGE\n")
	b.WriteString(userMsg)
	b.WriteString("\n\nProvide a helpful, concise response.\n")

	return b.String()
}

// runTask executes a specific task by ID using the provider.
func (sh *Shell) runTask(ctx context.Context, taskID int, out io.Writer) error {
	if sh.State.Plan == nil {
		return fmt.Errorf("no plan loaded — run `cloop run --pm` first")
	}

	var task *pm.Task
	for _, t := range sh.State.Plan.Tasks {
		if t.ID == taskID {
			task = t
			break
		}
	}
	if task == nil {
		return fmt.Errorf("task #%d not found", taskID)
	}

	fmt.Fprintf(out, "Running task #%d: %s\n", task.ID, task.Title)
	fmt.Fprintln(out, strings.Repeat("-", 60))

	prompt := pm.ExecuteTaskPrompt(sh.State.Goal, sh.State.Instructions, sh.State.Plan, task)

	callCtx, cancel := context.WithTimeout(ctx, sh.Timeout)
	defer cancel()

	opts := provider.Options{
		Model:   sh.Model,
		Timeout: sh.Timeout,
	}

	var outputBuf strings.Builder
	if sh.OnToken != nil {
		opts.OnToken = func(token string) {
			sh.OnToken(token)
			outputBuf.WriteString(token)
		}
	}

	start := time.Now()
	result, err := sh.Provider.Complete(callCtx, prompt, opts)
	elapsed := time.Since(start).Round(100 * time.Millisecond)

	if err != nil {
		task.Status = pm.TaskFailed
		if sh.OnSave != nil {
			_ = sh.OnSave()
		}
		return fmt.Errorf("task execution failed: %w", err)
	}

	output := result.Output
	if sh.OnToken == nil {
		fmt.Fprintln(out, output)
	} else {
		fmt.Fprintln(out)
	}

	// Check for completion signals in the last 10 lines.
	lines := strings.Split(strings.TrimSpace(output), "\n")
	last := lines
	if len(last) > 10 {
		last = last[len(last)-10:]
	}
	tail := strings.Join(last, "\n")

	switch {
	case strings.Contains(tail, "TASK_DONE"):
		now := time.Now()
		task.Status = pm.TaskDone
		task.CompletedAt = &now
		task.ActualMinutes = int(elapsed.Minutes())
		fmt.Fprintf(out, "\n  task #%d marked done (%s)\n\n", task.ID, elapsed)
	case strings.Contains(tail, "TASK_SKIPPED"):
		task.Status = pm.TaskSkipped
		fmt.Fprintf(out, "\n  task #%d skipped\n\n", task.ID)
	case strings.Contains(tail, "TASK_FAILED"):
		task.Status = pm.TaskFailed
		fmt.Fprintf(out, "\n  task #%d marked failed\n\n", task.ID)
	default:
		fmt.Fprintf(out, "\n  task #%d finished (%s) — no completion signal detected\n\n", task.ID, elapsed)
	}

	if sh.OnSave != nil {
		_ = sh.OnSave()
	}

	return nil
}

// addTask adds a new pending task to the plan.
func (sh *Shell) addTask(title string, out io.Writer) error {
	if sh.State.Plan == nil {
		sh.State.Plan = pm.NewPlan(sh.State.Goal)
		sh.State.PMMode = true
	}

	maxID := 0
	maxPriority := 0
	for _, t := range sh.State.Plan.Tasks {
		if t.ID > maxID {
			maxID = t.ID
		}
		if t.Priority > maxPriority {
			maxPriority = t.Priority
		}
	}

	task := &pm.Task{
		ID:       maxID + 1,
		Title:    title,
		Priority: maxPriority + 1,
		Status:   pm.TaskPending,
	}
	sh.State.Plan.Tasks = append(sh.State.Plan.Tasks, task)

	fmt.Fprintf(out, "Added task #%d: %s\n\n", task.ID, task.Title)

	if sh.OnSave != nil {
		return sh.OnSave()
	}
	return nil
}

// markDone marks a task as done by ID.
func (sh *Shell) markDone(taskID int, out io.Writer) error {
	if sh.State.Plan == nil {
		return fmt.Errorf("no plan loaded")
	}

	for _, t := range sh.State.Plan.Tasks {
		if t.ID == taskID {
			now := time.Now()
			t.Status = pm.TaskDone
			t.CompletedAt = &now
			fmt.Fprintf(out, "Task #%d marked as done: %s\n\n", t.ID, t.Title)
			if sh.OnSave != nil {
				return sh.OnSave()
			}
			return nil
		}
	}

	return fmt.Errorf("task #%d not found", taskID)
}

// printStatus prints the current plan state to out.
func (sh *Shell) printStatus(out io.Writer) {
	s := sh.State
	fmt.Fprintf(out, "Goal:   %s\n", s.Goal)
	fmt.Fprintf(out, "Status: %s\n", s.Status)
	fmt.Fprintf(out, "Steps:  %d", s.CurrentStep)
	if s.MaxSteps > 0 {
		fmt.Fprintf(out, " / %d", s.MaxSteps)
	}
	fmt.Fprintln(out)

	if s.PMMode && s.Plan != nil && len(s.Plan.Tasks) > 0 {
		statusIcon := map[pm.TaskStatus]string{
			pm.TaskPending:    "○",
			pm.TaskInProgress: "◐",
			pm.TaskDone:       "●",
			pm.TaskSkipped:    "—",
			pm.TaskFailed:     "✗",
		}
		fmt.Fprintln(out, "Tasks:")
		for _, t := range s.Plan.Tasks {
			icon := statusIcon[t.Status]
			role := ""
			if t.Role != "" {
				role = fmt.Sprintf(" [%s]", t.Role)
			}
			fmt.Fprintf(out, "  %s #%d (P%d)%s %s  [%s]\n", icon, t.ID, t.Priority, role, t.Title, t.Status)
		}
		done, failed := s.Plan.CountByStatus()
		fmt.Fprintf(out, "  %d done, %d failed, %d remaining\n",
			done, failed, len(s.Plan.Tasks)-done-failed)
	} else {
		fmt.Fprintln(out, "No PM task plan. Run `cloop run --pm` to create one.")
	}
	fmt.Fprintln(out)
}

// printHelp prints available commands to out.
func (sh *Shell) printHelp(out io.Writer) {
	fmt.Fprintln(out, "cloop shell commands:")
	fmt.Fprintln(out, "  /status              Show project and plan status")
	fmt.Fprintln(out, "  /run <task-id>       Execute a specific task via the AI provider")
	fmt.Fprintln(out, "  /add <title>         Add a new pending task to the plan")
	fmt.Fprintln(out, "  /done <task-id>      Mark a task as done")
	fmt.Fprintln(out, "  /clear               Clear conversation history")
	fmt.Fprintln(out, "  /quit                Exit the shell (also: /exit)")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Any other input is sent to the AI as a conversational message.")
	fmt.Fprintln(out, "The AI has full knowledge of your project goal and task plan.")
	fmt.Fprintln(out)
}
