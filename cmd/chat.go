package cmd

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
	"time"
	"github.com/blechschmidt/cloop/pkg/chat"
	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/memory"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	chatProvider string
	chatModel    string
	chatTimeout  string
	chatSave     bool
)

var chatCmd = &cobra.Command{
	Use:   "chat",
	Short: "Interactive conversational AI product manager",
	Long: `Start an interactive chat session with your AI product manager.

The AI has full knowledge of your project: goals, tasks, milestones, recent
activity, and project memory. Ask questions, get suggestions, or let the AI
update your task plan — all through natural conversation.

Slash commands:
  /status    Show current project status
  /tasks     List all tasks
  /help      Show available commands
  /clear     Clear conversation history
  /save      Save conversation to file
  /quit      Exit the chat (also: /exit, Ctrl+D)

The AI can also take PM actions on your behalf:
  "Mark task 3 as done"
  "Create a new task for writing API documentation"
  "What should we work on next?"
  "Why is the project behind schedule?"

Examples:
  cloop chat
  cloop chat --provider anthropic
  cloop chat --save`,
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()

		s, err := state.Load(workdir)
		if err != nil {
			return fmt.Errorf("no project found — run 'cloop init' first: %w", err)
		}
		if s.Goal == "" {
			return fmt.Errorf("no goal set — run 'cloop init <goal>'")
		}

		cfg, err := config.Load(workdir)
		if err != nil {
			return fmt.Errorf("loading config: %w", err)
		}
		applyEnvOverrides(cfg)

		// Resolve provider
		pName := chatProvider
		if pName == "" {
			pName = cfg.Provider
		}
		if pName == "" {
			pName = s.Provider
		}
		if pName == "" {
			pName = autoSelectProvider()
		}

		// Resolve model
		model := chatModel
		if model == "" {
			switch pName {
			case "anthropic":
				model = cfg.Anthropic.Model
			case "openai":
				model = cfg.OpenAI.Model
			case "ollama":
				model = cfg.Ollama.Model
			case "claudecode":
				model = cfg.ClaudeCode.Model
			}
		}
		if model == "" {
			model = s.Model
		}

		provCfg := provider.ProviderConfig{
			Name:             pName,
			AnthropicAPIKey:  cfg.Anthropic.APIKey,
			AnthropicBaseURL: cfg.Anthropic.BaseURL,
			OpenAIAPIKey:     cfg.OpenAI.APIKey,
			OpenAIBaseURL:    cfg.OpenAI.BaseURL,
			OllamaBaseURL:    cfg.Ollama.BaseURL,
		}
		prov, err := provider.Build(provCfg)
		if err != nil {
			return fmt.Errorf("provider: %w", err)
		}

		timeout := 120 * time.Second
		if chatTimeout != "" {
			timeout, err = time.ParseDuration(chatTimeout)
			if err != nil {
				return fmt.Errorf("invalid --timeout: %w", err)
			}
		}

		mem, _ := memory.Load(workdir)
		if mem == nil {
			mem = &memory.Memory{}
		}

		sess := chat.NewSession(s, mem, prov, model)
		sess.Timeout = timeout

		// Wire up action callbacks so they persist to disk
		sess.OnTaskUpdate = func(taskID int, status pm.TaskStatus) error {
			return s.Save()
		}
		sess.OnTaskCreate = func(title, desc string, priority int) (*pm.Task, error) {
			if s.Plan == nil {
				s.Plan = &pm.Plan{}
			}
			maxID := 0
			for _, t := range s.Plan.Tasks {
				if t.ID > maxID {
					maxID = t.ID
				}
			}
			t := &pm.Task{
				ID:          maxID + 1,
				Title:       title,
				Description: desc,
				Priority:    priority,
				Status:      pm.TaskPending,
			}
			s.Plan.Tasks = append(s.Plan.Tasks, t)
			if err := s.Save(); err != nil {
				return nil, err
			}
			return t, nil
		}
		sess.OnNote = func(text string) error {
			mem.Add(text, "chat", s.Goal, []string{"chat", "note"})
			return mem.Save(workdir)
		}

		return runChatLoop(sess, prov, s, mem, workdir)
	},
}

func runChatLoop(sess *chat.Session, prov provider.Provider, s *state.ProjectState, mem *memory.Memory, workdir string) error {
	// Colors
	headerColor := color.New(color.FgCyan, color.Bold)
	promptColor := color.New(color.FgGreen, color.Bold)
	aiColor := color.New(color.FgWhite)
	dimColor := color.New(color.Faint)
	actionColor := color.New(color.FgYellow)
	errorColor := color.New(color.FgRed)
	successColor := color.New(color.FgGreen)

	// Print header
	headerColor.Printf("\ncloop chat")
	dimColor.Printf(" — %s\n", prov.Name())
	dimColor.Printf("Project: %s\n", s.Goal)
	dimColor.Printf("Type /help for commands, /quit to exit\n\n")

	scanner := bufio.NewScanner(os.Stdin)
	var transcript []string

	for {
		// Prompt
		promptColor.Printf("you> ")

		if !scanner.Scan() {
			// EOF (Ctrl+D)
			fmt.Println()
			break
		}

		input := strings.TrimSpace(scanner.Text())
		if input == "" {
			continue
		}

		// Handle slash commands
		if strings.HasPrefix(input, "/") {
			switch strings.ToLower(strings.Fields(input)[0]) {
			case "/quit", "/exit", "/q":
				dimColor.Printf("Goodbye!\n")
				if chatSave && len(transcript) > 0 {
					saveTranscript(transcript, workdir)
				}
				return nil

			case "/help", "/h", "/?":
				printChatHelp(dimColor)
				continue

			case "/status":
				printChatStatus(s, dimColor, successColor, errorColor)
				continue

			case "/tasks":
				printChatTasks(s, successColor, errorColor, dimColor)
				continue

			case "/clear":
				sess.History = nil
				dimColor.Printf("Conversation history cleared.\n\n")
				continue

			case "/save":
				if len(transcript) > 0 {
					path := saveTranscript(transcript, workdir)
					successColor.Printf("Transcript saved to %s\n\n", path)
				} else {
					dimColor.Printf("Nothing to save yet.\n\n")
				}
				continue

			default:
				errorColor.Printf("Unknown command: %s (type /help for commands)\n\n", input)
				continue
			}
		}

		// Record user message in transcript
		transcript = append(transcript, "you: "+input)

		// Spinner / thinking indicator
		dimColor.Printf("thinking...")

		ctx := context.Background()
		start := time.Now()
		response, actions, err := sess.Send(ctx, input)
		elapsed := time.Since(start).Round(100 * time.Millisecond)

		// Clear "thinking..."
		fmt.Printf("\r%s\r", strings.Repeat(" ", 20))

		if err != nil {
			errorColor.Printf("Error: %v\n\n", err)
			continue
		}

		// Print AI response (filter out ACTION: lines from display)
		displayResponse := filterActionLines(response)
		aiColor.Printf("ai> ")
		fmt.Printf("%s\n", displayResponse)
		dimColor.Printf("(%s)\n\n", elapsed)

		transcript = append(transcript, "ai: "+displayResponse)

		// Print action results
		for _, ar := range actions {
			if ar.Success {
				actionColor.Printf("  ✓ %s\n", ar.Message)
			} else {
				errorColor.Printf("  ✗ Action failed: %s\n", ar.Message)
			}
		}
		if len(actions) > 0 {
			fmt.Println()
		}
	}

	if chatSave && len(transcript) > 0 {
		path := saveTranscript(transcript, workdir)
		dimColor.Printf("Transcript saved to %s\n", path)
	}

	return nil
}

func filterActionLines(text string) string {
	var lines []string
	for _, line := range strings.Split(text, "\n") {
		if !strings.HasPrefix(strings.TrimSpace(line), "ACTION:") {
			lines = append(lines, line)
		}
	}
	// Trim trailing blank lines
	for len(lines) > 0 && strings.TrimSpace(lines[len(lines)-1]) == "" {
		lines = lines[:len(lines)-1]
	}
	return strings.Join(lines, "\n")
}

func printChatHelp(dim *color.Color) {
	fmt.Println("Available commands:")
	fmt.Println("  /status     Current project status")
	fmt.Println("  /tasks      List all PM tasks")
	fmt.Println("  /clear      Clear conversation history")
	fmt.Println("  /save       Save transcript to .cloop/chat-<timestamp>.txt")
	fmt.Println("  /help       Show this help")
	fmt.Println("  /quit       Exit chat")
	fmt.Println()
	dim.Println("Ask anything about your project, e.g.:")
	dim.Println("  \"What should we prioritize next?\"")
	dim.Println("  \"Mark task 3 as done\"")
	dim.Println("  \"Create a task for writing tests\"")
	dim.Println("  \"Why are we behind schedule?\"")
	fmt.Println()
}

func printChatStatus(s *state.ProjectState, dim, success, fail *color.Color) {
	fmt.Printf("Goal:   %s\n", s.Goal)
	fmt.Printf("Status: %s\n", s.Status)
	fmt.Printf("Steps:  %d", s.CurrentStep)
	if s.MaxSteps > 0 {
		fmt.Printf(" / %d", s.MaxSteps)
	}
	fmt.Println()
	if s.PMMode && s.Plan != nil {
		done, failed := s.Plan.CountByStatus()
		total := len(s.Plan.Tasks)
		fmt.Printf("Tasks:  %d total — ", total)
		success.Printf("%d done", done)
		fmt.Printf(", ")
		fail.Printf("%d failed", failed)
		fmt.Printf(", %d remaining\n", total-done-failed)
	}
	elapsed := time.Since(s.CreatedAt).Round(time.Second)
	dim.Printf("Age:    %s\n", elapsed)
	fmt.Println()
}

func printChatTasks(s *state.ProjectState, success, fail, dim *color.Color) {
	if !s.PMMode || s.Plan == nil || len(s.Plan.Tasks) == 0 {
		dim.Printf("No tasks defined. Run 'cloop run --pm' to start PM mode.\n\n")
		return
	}

	statusIcon := map[pm.TaskStatus]string{
		pm.TaskPending:    "○",
		pm.TaskInProgress: "◐",
		pm.TaskDone:       "●",
		pm.TaskSkipped:    "—",
		pm.TaskFailed:     "✗",
	}

	for _, t := range s.Plan.Tasks {
		icon := statusIcon[t.Status]
		switch t.Status {
		case pm.TaskDone:
			success.Printf("  %s", icon)
		case pm.TaskFailed:
			fail.Printf("  %s", icon)
		default:
			dim.Printf("  %s", icon)
		}
		fmt.Printf(" #%d [P%d]", t.ID, t.Priority)
		if t.Role != "" {
			dim.Printf(" [%s]", t.Role)
		}
		fmt.Printf(" %s", t.Title)
		if t.Status == pm.TaskInProgress {
			color.New(color.FgYellow).Printf(" ← in progress")
		}
		fmt.Println()
	}
	fmt.Println()
}

func saveTranscript(lines []string, workdir string) string {
	ts := time.Now().Format("20060102-150405")
	path := fmt.Sprintf("%s/.cloop/chat-%s.txt", workdir, ts)
	content := strings.Join(lines, "\n") + "\n"
	_ = os.WriteFile(path, []byte(content), 0o644)
	return path
}

func init() {
	chatCmd.Flags().StringVar(&chatProvider, "provider", "", "AI provider to use")
	chatCmd.Flags().StringVar(&chatModel, "model", "", "Model to use")
	chatCmd.Flags().StringVar(&chatTimeout, "timeout", "", "Response timeout (e.g. 60s, 2m)")
	chatCmd.Flags().BoolVar(&chatSave, "save", false, "Auto-save transcript on exit")
	rootCmd.AddCommand(chatCmd)
}
