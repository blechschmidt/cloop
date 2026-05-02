// Package aipair implements an interactive streaming AI coding assistant REPL
// scoped to a specific task. It is the backend for the `cloop ai-pair` command.
package aipair

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/artifact"
	"github.com/blechschmidt/cloop/pkg/kb"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/state"
)

const (
	// contextTokenBudget is the max tokens allocated to file context injection.
	contextTokenBudget = 4000

	// historyMaxTurns is the maximum number of conversation turns (user+assistant
	// pairs) kept in the prompt. Older turns are pruned to stay within limits.
	historyMaxTurns = 20

	// pairSessionsDir is the directory where pair session logs are saved.
	pairSessionsDir = ".cloop/pair-sessions"
)

// Message is a single turn in the conversation history.
type Message struct {
	Role    string // "user" or "assistant"
	Content string
}

// Session holds all state for a running ai-pair session.
type Session struct {
	State   *state.ProjectState
	Plan    *pm.Plan
	Prov    provider.Provider
	Model   string
	Timeout time.Duration
	WorkDir string

	// activeTask is the task currently being worked on.
	activeTask *pm.Task

	// fileContext is the cached file context injected into the system prompt.
	fileContext string

	// history is the rolling conversation history (user + assistant pairs).
	history []Message

	// OnSave is called after mutations that change the plan state.
	OnSave func() error
}

// New creates a Session scoped to the given task ID.
// If taskID is 0 the first pending/in-progress task is used.
func New(s *state.ProjectState, prov provider.Provider, model, workDir string, taskID int) (*Session, error) {
	if s.Plan == nil || len(s.Plan.Tasks) == 0 {
		return nil, fmt.Errorf("no task plan found — run 'cloop run --pm' first")
	}

	sess := &Session{
		State:   s,
		Plan:    s.Plan,
		Prov:    prov,
		Model:   model,
		Timeout: 120 * time.Second,
		WorkDir: workDir,
	}

	if err := sess.switchTask(taskID); err != nil {
		return nil, err
	}

	return sess, nil
}

// switchTask changes the active task to the one with the given ID.
// If id is 0, the first non-done task is chosen.
func (sess *Session) switchTask(id int) error {
	if id == 0 {
		for _, t := range sess.Plan.Tasks {
			if t.Status != pm.TaskDone && t.Status != pm.TaskSkipped {
				sess.activeTask = t
				return nil
			}
		}
		return fmt.Errorf("no pending or in-progress tasks found")
	}
	for _, t := range sess.Plan.Tasks {
		if t.ID == id {
			sess.activeTask = t
			return nil
		}
	}
	return fmt.Errorf("task #%d not found", id)
}

// Run starts the interactive REPL, reading from in and writing to out.
// It returns when the user types /quit or in reaches EOF.
func (sess *Session) Run(ctx context.Context, in io.Reader, out io.Writer) error {
	// Collect initial file context.
	sess.fileContext = pm.CollectRelevantContext(sess.WorkDir, sess.activeTask, contextTokenBudget)

	sess.printWelcome(out)

	scanner := bufio.NewScanner(in)
	// Increase scanner buffer for large pastes.
	scanner.Buffer(make([]byte, 256*1024), 256*1024)

	for {
		fmt.Fprintf(out, "\npair(%d)> ", sess.activeTask.ID)

		if !scanner.Scan() {
			fmt.Fprintln(out)
			break
		}

		input := strings.TrimSpace(scanner.Text())
		if input == "" {
			continue
		}

		if strings.HasPrefix(input, "/") {
			done, err := sess.handleCommand(ctx, input, out)
			if err != nil {
				fmt.Fprintf(out, "error: %v\n", err)
			}
			if done {
				break
			}
			continue
		}

		if err := sess.chat(ctx, input, out); err != nil {
			fmt.Fprintf(out, "error: %v\n", err)
		}
	}

	// Save the session log.
	if err := sess.saveSession(); err != nil {
		fmt.Fprintf(out, "warning: could not save session log: %v\n", err)
	}

	return nil
}

// handleCommand processes a /slash command.
// Returns (exit=true) when the REPL should terminate.
func (sess *Session) handleCommand(ctx context.Context, input string, out io.Writer) (exit bool, err error) {
	fields := strings.Fields(input)
	cmd := strings.ToLower(fields[0])

	switch cmd {
	case "/quit", "/exit", "/q":
		fmt.Fprintln(out, "Goodbye!")
		return true, nil

	case "/help", "/h", "/?":
		sess.printHelp(out)
		return false, nil

	case "/task":
		sess.printTask(out)
		return false, nil

	case "/files":
		fmt.Fprintln(out, "Re-scanning relevant files…")
		sess.fileContext = pm.CollectRelevantContext(sess.WorkDir, sess.activeTask, contextTokenBudget)
		if sess.fileContext == "" {
			fmt.Fprintln(out, "No relevant files found.")
		} else {
			lines := strings.Count(sess.fileContext, "\n")
			tokens := pm.EstimateTokens(sess.fileContext)
			fmt.Fprintf(out, "Context updated: ~%d tokens across %d lines.\n", tokens, lines)
		}
		return false, nil

	case "/done":
		return true, sess.markDone(out)

	case "/switch":
		if len(fields) < 2 {
			fmt.Fprintln(out, "Usage: /switch <task-id>")
			return false, nil
		}
		id, parseErr := strconv.Atoi(fields[1])
		if parseErr != nil {
			fmt.Fprintf(out, "Invalid task ID: %s\n", fields[1])
			return false, nil
		}
		if switchErr := sess.switchTask(id); switchErr != nil {
			return false, switchErr
		}
		sess.history = nil
		sess.fileContext = pm.CollectRelevantContext(sess.WorkDir, sess.activeTask, contextTokenBudget)
		fmt.Fprintf(out, "Switched to task #%d: %s\n", sess.activeTask.ID, sess.activeTask.Title)
		return false, nil

	case "/clear":
		sess.history = nil
		fmt.Fprintln(out, "Conversation history cleared.")
		return false, nil

	default:
		fmt.Fprintf(out, "Unknown command: %s  (type /help)\n", fields[0])
		return false, nil
	}
}

// chat sends a user message to the provider with full context, streams the
// reply, and appends both turns to the history.
func (sess *Session) chat(ctx context.Context, userMsg string, out io.Writer) error {
	prompt := sess.buildPrompt(userMsg)

	callCtx, cancel := context.WithTimeout(ctx, sess.Timeout)
	defer cancel()

	opts := provider.Options{
		Model:   sess.Model,
		Timeout: sess.Timeout,
	}

	var streamBuf strings.Builder
	opts.OnToken = func(token string) {
		fmt.Print(token)
		streamBuf.WriteString(token)
	}
	fmt.Fprintf(out, "\nai-pair> ")

	result, err := sess.Prov.Complete(callCtx, prompt, opts)
	fmt.Fprintln(out)

	if err != nil {
		return fmt.Errorf("provider: %w", err)
	}

	response := result.Output
	if streamBuf.Len() == 0 {
		// Non-streaming provider: print the full response.
		fmt.Fprintf(out, "%s\n", response)
	}

	// Append to rolling history.
	sess.history = append(sess.history,
		Message{Role: "user", Content: userMsg},
		Message{Role: "assistant", Content: response},
	)
	// Prune oldest turns beyond the limit.
	if len(sess.history) > historyMaxTurns*2 {
		sess.history = sess.history[len(sess.history)-historyMaxTurns*2:]
	}

	return nil
}

// buildPrompt constructs the full prompt: system context + file context +
// conversation history + new user message.
func (sess *Session) buildPrompt(userMsg string) string {
	var b strings.Builder

	// — System role / persona —
	b.WriteString("You are an expert AI coding assistant paired with a developer working on a specific task.\n")
	b.WriteString("You have full context of the task, relevant source files, recent outputs, and project knowledge.\n")
	b.WriteString("Provide concrete, actionable coding guidance. Prefer short focused answers with code examples.\n\n")

	// — Current task context —
	t := sess.activeTask
	b.WriteString("## Active Task\n")
	b.WriteString(fmt.Sprintf("ID:          #%d\n", t.ID))
	b.WriteString(fmt.Sprintf("Title:       %s\n", t.Title))
	b.WriteString(fmt.Sprintf("Status:      %s\n", t.Status))
	if t.Description != "" {
		b.WriteString(fmt.Sprintf("Description: %s\n", t.Description))
	}
	if t.Role != "" {
		b.WriteString(fmt.Sprintf("Role:        %s\n", t.Role))
	}
	if t.Priority > 0 {
		b.WriteString(fmt.Sprintf("Priority:    P%d\n", t.Priority))
	}
	if len(t.Tags) > 0 {
		b.WriteString(fmt.Sprintf("Tags:        %s\n", strings.Join(t.Tags, ", ")))
	}
	b.WriteString("\n")

	// — Plan summary (brief) —
	if sess.Plan != nil && len(sess.Plan.Tasks) > 0 {
		b.WriteString("## Plan Summary\n")
		b.WriteString(fmt.Sprintf("Goal: %s\n", sess.Plan.Goal))
		for _, pt := range sess.Plan.Tasks {
			sym := taskSymbol(pt.Status)
			b.WriteString(fmt.Sprintf("  %s #%d %s\n", sym, pt.ID, pt.Title))
		}
		b.WriteString("\n")
	}

	// — Recent task output artifact —
	if artifact := sess.readTaskArtifact(t); artifact != "" {
		b.WriteString("## Recent Task Output\n\n")
		// Limit artifact to ~1000 tokens to avoid prompt bloat.
		trimmed := pm.PruneToTokenBudget([]string{artifact}, 1000)
		if len(trimmed) > 0 {
			b.WriteString(trimmed[0])
		}
		b.WriteString("\n\n")
	}

	// — KB entries —
	if kbSection := sess.buildKBSection(); kbSection != "" {
		b.WriteString(kbSection)
	}

	// — Relevant file context —
	if sess.fileContext != "" {
		b.WriteString(sess.fileContext)
		b.WriteString("\n")
	}

	// — Conversation history —
	if len(sess.history) > 0 {
		b.WriteString("## Conversation History\n")
		for _, m := range sess.history {
			switch m.Role {
			case "user":
				b.WriteString(fmt.Sprintf("Developer: %s\n", m.Content))
			case "assistant":
				b.WriteString(fmt.Sprintf("AI: %s\n", m.Content))
			}
		}
		b.WriteString("\n")
	}

	// — New message —
	b.WriteString("## Developer Message\n")
	b.WriteString(userMsg)
	b.WriteString("\n\nRespond concisely and directly.\n")

	return b.String()
}

// readTaskArtifact reads the most recent task output artifact from disk.
// Returns empty string if none found.
func (sess *Session) readTaskArtifact(t *pm.Task) string {
	// Check task.ArtifactPath first.
	if t.ArtifactPath != "" {
		absPath := t.ArtifactPath
		if !filepath.IsAbs(absPath) {
			absPath = filepath.Join(sess.WorkDir, absPath)
		}
		data, err := os.ReadFile(absPath)
		if err == nil {
			return string(data)
		}
	}

	// Try the live artifact file.
	livePath := artifact.LiveArtifactPath(sess.WorkDir, t.ID)
	data, err := os.ReadFile(livePath)
	if err == nil && len(data) > 0 {
		return string(data)
	}

	// Scan .cloop/tasks/ for the most recent matching artifact.
	dir := filepath.Join(sess.WorkDir, ".cloop", "tasks")
	prefix := fmt.Sprintf("%d-", t.ID)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	// ReadDir returns entries in alphabetical order; take the last matching file.
	var best string
	for _, e := range entries {
		if !e.IsDir() && strings.HasPrefix(e.Name(), prefix) && strings.HasSuffix(e.Name(), ".md") {
			best = filepath.Join(dir, e.Name())
		}
	}
	if best == "" {
		return ""
	}
	data, err = os.ReadFile(best)
	if err != nil {
		return ""
	}
	return string(data)
}

// buildKBSection returns relevant KB entries as a markdown section.
func (sess *Session) buildKBSection() string {
	kbStore, err := kb.Load(sess.WorkDir)
	if err != nil || len(kbStore.Entries) == 0 {
		return ""
	}

	// Score entries by keyword overlap with the active task.
	keywords := extractKBKeywords(sess.activeTask.Title + " " + sess.activeTask.Description)

	type scored struct {
		entry *kb.Entry
		score int
	}
	var results []scored
	for _, e := range kbStore.Entries {
		score := 0
		text := strings.ToLower(e.Title + " " + e.Content)
		for _, kw := range keywords {
			if strings.Contains(text, kw) {
				score++
			}
		}
		if score > 0 {
			results = append(results, scored{e, score})
		}
	}
	if len(results) == 0 {
		return ""
	}

	// Sort by score descending; take top 3.
	for i := 1; i < len(results); i++ {
		for j := i; j > 0 && results[j].score > results[j-1].score; j-- {
			results[j], results[j-1] = results[j-1], results[j]
		}
	}
	if len(results) > 3 {
		results = results[:3]
	}

	var b strings.Builder
	b.WriteString("## Knowledge Base\n\n")
	for _, r := range results {
		b.WriteString(fmt.Sprintf("**%s**\n%s\n\n", r.entry.Title, r.entry.Content))
	}
	return b.String()
}

// extractKBKeywords splits text into lowercase keywords filtering stop words.
func extractKBKeywords(text string) []string {
	stop := map[string]bool{
		"the": true, "a": true, "an": true, "and": true, "or": true,
		"for": true, "to": true, "of": true, "in": true, "on": true,
		"at": true, "by": true, "is": true, "it": true, "be": true,
		"as": true, "if": true, "do": true, "no": true, "so": true,
		"add": true, "use": true, "new": true, "get": true, "set": true,
		"run": true, "all": true, "any": true, "not": true, "can": true,
	}
	words := strings.FieldsFunc(strings.ToLower(text), func(r rune) bool {
		return !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9'))
	})
	seen := make(map[string]bool)
	var result []string
	for _, w := range words {
		if len(w) >= 3 && !stop[w] && !seen[w] {
			seen[w] = true
			result = append(result, w)
		}
	}
	return result
}

// markDone marks the active task as done and triggers a save.
func (sess *Session) markDone(out io.Writer) error {
	now := time.Now()
	sess.activeTask.Status = pm.TaskDone
	sess.activeTask.CompletedAt = &now
	fmt.Fprintf(out, "Task #%d marked as done: %s\n", sess.activeTask.ID, sess.activeTask.Title)
	if sess.OnSave != nil {
		return sess.OnSave()
	}
	return nil
}

// saveSession persists the conversation to .cloop/pair-sessions/<id>-<ts>.md.
func (sess *Session) saveSession() error {
	if len(sess.history) == 0 {
		return nil // Nothing to save.
	}

	dir := filepath.Join(sess.WorkDir, pairSessionsDir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create pair-sessions dir: %w", err)
	}

	ts := time.Now().UTC().Format("20060102-150405")
	filename := fmt.Sprintf("%d-%s.md", sess.activeTask.ID, ts)
	path := filepath.Join(dir, filename)

	var b strings.Builder
	b.WriteString("---\n")
	b.WriteString(fmt.Sprintf("task_id: %d\n", sess.activeTask.ID))
	b.WriteString(fmt.Sprintf("task_title: %q\n", sess.activeTask.Title))
	b.WriteString(fmt.Sprintf("task_status: %s\n", sess.activeTask.Status))
	b.WriteString(fmt.Sprintf("provider: %s\n", sess.Prov.Name()))
	b.WriteString(fmt.Sprintf("recorded_at: %s\n", ts))
	b.WriteString("---\n\n")

	b.WriteString(fmt.Sprintf("# AI Pair Session — Task #%d: %s\n\n", sess.activeTask.ID, sess.activeTask.Title))

	for _, m := range sess.history {
		switch m.Role {
		case "user":
			b.WriteString(fmt.Sprintf("**Developer:** %s\n\n", m.Content))
		case "assistant":
			b.WriteString(fmt.Sprintf("**AI:** %s\n\n", m.Content))
		}
	}

	return os.WriteFile(path, []byte(b.String()), 0o644)
}

// printWelcome prints the startup banner.
func (sess *Session) printWelcome(out io.Writer) {
	t := sess.activeTask
	fmt.Fprintln(out)
	fmt.Fprintf(out, "cloop ai-pair  [%s]\n", sess.Prov.Name())
	fmt.Fprintf(out, "Task #%d (P%d) [%s]: %s\n", t.ID, t.Priority, t.Status, t.Title)
	if t.Description != "" {
		desc := t.Description
		if len(desc) > 120 {
			desc = desc[:117] + "…"
		}
		fmt.Fprintf(out, "Desc: %s\n", desc)
	}
	if sess.fileContext != "" {
		tokens := pm.EstimateTokens(sess.fileContext)
		fmt.Fprintf(out, "Context: ~%d tokens of relevant file context injected.\n", tokens)
	}
	fmt.Fprintln(out, "Type /help for commands, /quit to exit.")
}

// printHelp prints available commands.
func (sess *Session) printHelp(out io.Writer) {
	fmt.Fprintln(out, "\nai-pair commands:")
	fmt.Fprintln(out, "  /task              Show current task details")
	fmt.Fprintln(out, "  /files             Re-scan and refresh file context")
	fmt.Fprintln(out, "  /done              Mark active task done and exit")
	fmt.Fprintln(out, "  /switch <id>       Switch to a different task")
	fmt.Fprintln(out, "  /clear             Clear conversation history")
	fmt.Fprintln(out, "  /quit              Exit the session (also: /exit)")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Any other input is sent to the AI as a coding question.")
}

// printTask prints the current task details.
func (sess *Session) printTask(out io.Writer) {
	t := sess.activeTask
	fmt.Fprintf(out, "\nTask #%d  [%s]\n", t.ID, t.Status)
	fmt.Fprintf(out, "  Title:    %s\n", t.Title)
	if t.Description != "" {
		fmt.Fprintf(out, "  Desc:     %s\n", t.Description)
	}
	fmt.Fprintf(out, "  Priority: P%d\n", t.Priority)
	if t.Role != "" {
		fmt.Fprintf(out, "  Role:     %s\n", t.Role)
	}
	if len(t.Tags) > 0 {
		fmt.Fprintf(out, "  Tags:     %s\n", strings.Join(t.Tags, ", "))
	}
	if len(t.DependsOn) > 0 {
		deps := make([]string, len(t.DependsOn))
		for i, d := range t.DependsOn {
			deps[i] = fmt.Sprintf("#%d", d)
		}
		fmt.Fprintf(out, "  Deps:     %s\n", strings.Join(deps, ", "))
	}
	if t.ArtifactPath != "" {
		fmt.Fprintf(out, "  Artifact: %s\n", t.ArtifactPath)
	}
	fmt.Fprintln(out)
}

// taskSymbol returns a single-character status indicator.
func taskSymbol(s pm.TaskStatus) string {
	switch s {
	case pm.TaskPending:
		return "○"
	case pm.TaskInProgress:
		return "◐"
	case pm.TaskDone:
		return "●"
	case pm.TaskSkipped:
		return "—"
	case pm.TaskFailed:
		return "✗"
	default:
		return "?"
	}
}
