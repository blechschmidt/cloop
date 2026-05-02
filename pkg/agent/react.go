package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/fatih/color"
)

// Tool is a capability the agent can invoke during its ReAct loop.
type Tool interface {
	Name() string
	Description() string
	// Run executes the tool with the given arguments and returns its output.
	Run(args map[string]string) (string, error)
}

// StepLog records one completed ReAct step.
type StepLog struct {
	Step        int
	Thought     string
	Action      string
	ActionInput map[string]string
	Observation string
}

// Agent drives a ReAct (Reason + Act) loop to accomplish a goal using tools.
type Agent struct {
	provider provider.Provider
	model    string
	timeout  time.Duration
	tools    map[string]Tool
	steps    []StepLog
	dryRun   bool
	workDir  string
}

// reactAction is the JSON structure the LLM must emit on each step.
type reactAction struct {
	Thought     string            `json:"thought"`
	Action      string            `json:"action"`
	ActionInput map[string]string `json:"action_input"`
}

// Config holds configuration for creating a new Agent.
type AgentConfig struct {
	Provider provider.Provider
	Model    string
	Timeout  time.Duration
	DryRun   bool
	WorkDir  string
}

// New creates a new Agent with the built-in tool set registered.
func New(cfg AgentConfig) *Agent {
	a := &Agent{
		provider: cfg.Provider,
		model:    cfg.Model,
		timeout:  cfg.Timeout,
		dryRun:   cfg.DryRun,
		workDir:  cfg.WorkDir,
		tools:    make(map[string]Tool),
	}
	if a.timeout == 0 {
		a.timeout = 2 * time.Minute
	}

	a.Register(&readFileTool{})
	a.Register(&writeFileTool{dryRun: cfg.DryRun})
	a.Register(&runShellTool{dryRun: cfg.DryRun, workDir: cfg.WorkDir})
	a.Register(&searchFilesTool{workDir: cfg.WorkDir})
	a.Register(&webFetchTool{})

	return a
}

// Register adds a tool to the agent's registry.
func (a *Agent) Register(t Tool) {
	a.tools[t.Name()] = t
}

// Steps returns the recorded step log.
func (a *Agent) Steps() []StepLog { return a.steps }

// Run drives the ReAct loop until the goal is achieved or maxSteps is reached.
// Returns the final result string (from the "finish" action) or an error.
func (a *Agent) Run(ctx context.Context, goal string, maxSteps int) (string, error) {
	if maxSteps <= 0 {
		maxSteps = 20
	}

	bold := color.New(color.Bold)
	cyan := color.New(color.FgCyan, color.Bold)
	green := color.New(color.FgGreen, color.Bold)
	yellow := color.New(color.FgYellow, color.Bold)
	red := color.New(color.FgRed, color.Bold)
	dim := color.New(color.Faint)

	cyan.Printf("\n━━━ cloop agent ━━━\n")
	bold.Printf("Goal: ")
	fmt.Printf("%s\n", goal)
	if a.dryRun {
		yellow.Printf("[dry-run mode — shell/write actions will not execute]\n")
	}
	fmt.Println()

	systemPrompt := a.buildSystemPrompt()
	transcript := fmt.Sprintf("Goal: %s\n", goal)

	for step := 1; step <= maxSteps; step++ {
		cyan.Printf("── Step %d/%d ──\n", step, maxSteps)

		prompt := transcript + fmt.Sprintf("\nStep %d:\n", step)

		reqCtx, cancel := context.WithTimeout(ctx, a.timeout)
		result, err := a.provider.Complete(reqCtx, prompt, provider.Options{
			Model:        a.model,
			SystemPrompt: systemPrompt,
			MaxTokens:    2048,
		})
		cancel()
		if err != nil {
			return "", fmt.Errorf("step %d: provider error: %w", step, err)
		}

		raw := strings.TrimSpace(result.Output)

		// Extract JSON from the response (handle markdown code fences)
		jsonStr := extractJSON(raw)
		if jsonStr == "" {
			return "", fmt.Errorf("step %d: no JSON found in response:\n%s", step, raw)
		}

		var act reactAction
		if err := json.Unmarshal([]byte(jsonStr), &act); err != nil {
			return "", fmt.Errorf("step %d: failed to parse action JSON: %w\nRaw: %s", step, err, jsonStr)
		}

		// Print thought
		bold.Printf("Thought: ")
		fmt.Printf("%s\n", act.Thought)

		// Print action
		argsJSON, _ := json.Marshal(act.ActionInput)
		bold.Printf("Action:  ")
		green.Printf("%s", act.Action)
		dim.Printf("(%s)\n", string(argsJSON))

		// Handle finish
		if act.Action == "finish" {
			finalResult := act.ActionInput["result"]
			fmt.Println()
			green.Printf("━━━ Agent finished ━━━\n")
			bold.Printf("Result: ")
			fmt.Printf("%s\n", finalResult)
			return finalResult, nil
		}

		// Dispatch to tool
		tool, ok := a.tools[act.Action]
		var observation string
		if !ok {
			observation = fmt.Sprintf("ERROR: unknown tool %q. Available tools: %s",
				act.Action, a.toolNames())
			red.Printf("Observation: %s\n\n", observation)
		} else {
			var toolErr error
			observation, toolErr = tool.Run(act.ActionInput)
			if toolErr != nil {
				observation = fmt.Sprintf("ERROR: %s", toolErr.Error())
				red.Printf("Observation: %s\n\n", observation)
			} else {
				bold.Printf("Observation: ")
				// Truncate long observations for display
				display := observation
				if len(display) > 500 {
					display = display[:500] + "…"
				}
				fmt.Printf("%s\n\n", display)
			}
		}

		// Record step
		log := StepLog{
			Step:        step,
			Thought:     act.Thought,
			Action:      act.Action,
			ActionInput: act.ActionInput,
			Observation: observation,
		}
		a.steps = append(a.steps, log)

		// Append to transcript
		transcript += fmt.Sprintf(
			"Step %d:\nThought: %s\nAction: %s(%s)\nObservation: %s\n\n",
			step, act.Thought, act.Action, string(argsJSON), observation,
		)

		if ctx.Err() != nil {
			return "", ctx.Err()
		}
	}

	return "", fmt.Errorf("agent stopped: reached max steps (%d) without finishing", maxSteps)
}

// buildSystemPrompt constructs the system prompt describing the ReAct protocol and tools.
func (a *Agent) buildSystemPrompt() string {
	var sb strings.Builder
	sb.WriteString(`You are an autonomous agent operating in a ReAct (Reason + Act) loop.
At each step you will receive a transcript of the goal and all prior steps.
You must respond with ONLY a single JSON object — no other text, no markdown fences:

{
  "thought": "your reasoning about what to do next",
  "action": "tool_name",
  "action_input": { "arg1": "value1", ... }
}

When the goal is accomplished, use action "finish":
{
  "thought": "The goal is complete.",
  "action": "finish",
  "action_input": { "result": "concise summary of what was accomplished" }
}

Available tools:
`)
	for _, t := range a.tools {
		sb.WriteString(fmt.Sprintf("- %s: %s\n", t.Name(), t.Description()))
	}
	sb.WriteString(`
Rules:
- Always emit exactly one JSON object per step.
- Never emit explanatory text outside the JSON.
- Keep action_input values as strings.
- If a tool returns an error, adapt your approach.
- For run_shell, use simple non-interactive commands.
- Be efficient: finish as soon as the goal is met.
`)
	return sb.String()
}

func (a *Agent) toolNames() string {
	names := make([]string, 0, len(a.tools))
	for n := range a.tools {
		names = append(names, n)
	}
	return strings.Join(names, ", ")
}

// extractJSON finds the first complete JSON object in s.
// It handles responses wrapped in markdown code fences.
func extractJSON(s string) string {
	// Strip markdown code fence if present
	if idx := strings.Index(s, "```json"); idx >= 0 {
		s = s[idx+7:]
		if end := strings.Index(s, "```"); end >= 0 {
			s = s[:end]
		}
	} else if idx := strings.Index(s, "```"); idx >= 0 {
		s = s[idx+3:]
		if end := strings.Index(s, "```"); end >= 0 {
			s = s[:end]
		}
	}

	s = strings.TrimSpace(s)

	// Find the first '{' and match closing '}'
	start := strings.Index(s, "{")
	if start < 0 {
		return ""
	}
	depth := 0
	inStr := false
	escaped := false
	for i := start; i < len(s); i++ {
		c := s[i]
		if escaped {
			escaped = false
			continue
		}
		if c == '\\' && inStr {
			escaped = true
			continue
		}
		if c == '"' {
			inStr = !inStr
			continue
		}
		if inStr {
			continue
		}
		if c == '{' {
			depth++
		} else if c == '}' {
			depth--
			if depth == 0 {
				return s[start : i+1]
			}
		}
	}
	return ""
}

// ─────────────────────────── built-in tools ───────────────────────────

type readFileTool struct{}

func (t *readFileTool) Name() string { return "read_file" }
func (t *readFileTool) Description() string {
	return `Read the contents of a file. Args: {"path": "<file path>"}`
}
func (t *readFileTool) Run(args map[string]string) (string, error) {
	path := args["path"]
	if path == "" {
		return "", fmt.Errorf("missing required arg: path")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// ─────────────────────────────────────────────────────────────────────

type writeFileTool struct{ dryRun bool }

func (t *writeFileTool) Name() string { return "write_file" }
func (t *writeFileTool) Description() string {
	return `Write content to a file (creates parent dirs if needed). Args: {"path": "<file path>", "content": "<text>"}`
}
func (t *writeFileTool) Run(args map[string]string) (string, error) {
	path := args["path"]
	content := args["content"]
	if path == "" {
		return "", fmt.Errorf("missing required arg: path")
	}
	if t.dryRun {
		return fmt.Sprintf("[dry-run] would write %d bytes to %s", len(content), path), nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", err
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		return "", err
	}
	return fmt.Sprintf("wrote %d bytes to %s", len(content), path), nil
}

// ─────────────────────────────────────────────────────────────────────

type runShellTool struct {
	dryRun  bool
	workDir string
}

func (t *runShellTool) Name() string { return "run_shell" }
func (t *runShellTool) Description() string {
	return `Run a shell command and return its output. Args: {"command": "<shell command>"}`
}
func (t *runShellTool) Run(args map[string]string) (string, error) {
	command := args["command"]
	if command == "" {
		return "", fmt.Errorf("missing required arg: command")
	}
	if t.dryRun {
		return fmt.Sprintf("[dry-run] would run: %s", command), nil
	}
	cmd := exec.Command("sh", "-c", command)
	if t.workDir != "" {
		cmd.Dir = t.workDir
	}
	out, err := cmd.CombinedOutput()
	output := string(out)
	if err != nil {
		// Return output + error; agent can decide how to react.
		if output == "" {
			return "", fmt.Errorf("command failed: %w", err)
		}
		return output, fmt.Errorf("command exited with error: %w", err)
	}
	if output == "" {
		return "(no output)", nil
	}
	return output, nil
}

// ─────────────────────────────────────────────────────────────────────

type searchFilesTool struct{ workDir string }

func (t *searchFilesTool) Name() string { return "search_files" }
func (t *searchFilesTool) Description() string {
	return `Search for files matching a glob pattern. Args: {"pattern": "<glob>", "directory": "<dir (optional, defaults to .)>"}`
}
func (t *searchFilesTool) Run(args map[string]string) (string, error) {
	pattern := args["pattern"]
	if pattern == "" {
		return "", fmt.Errorf("missing required arg: pattern")
	}
	dir := args["directory"]
	if dir == "" {
		if t.workDir != "" {
			dir = t.workDir
		} else {
			dir = "."
		}
	}

	// If pattern doesn't contain a path separator, prepend the dir.
	fullPattern := pattern
	if !filepath.IsAbs(pattern) && !strings.Contains(pattern, string(filepath.Separator)) {
		fullPattern = filepath.Join(dir, "**", pattern)
	}

	matches, err := filepath.Glob(fullPattern)
	if err != nil {
		return "", fmt.Errorf("invalid pattern: %w", err)
	}

	// Fallback: walk the directory if Glob returns nothing (** isn't supported natively)
	if len(matches) == 0 {
		// Try simple pattern in the directory
		directMatches, err2 := filepath.Glob(filepath.Join(dir, pattern))
		if err2 == nil {
			matches = directMatches
		}
	}

	if len(matches) == 0 {
		return "no files found", nil
	}
	return strings.Join(matches, "\n"), nil
}

// ─────────────────────────────────────────────────────────────────────

type webFetchTool struct{}

func (t *webFetchTool) Name() string { return "web_fetch" }
func (t *webFetchTool) Description() string {
	return `Fetch the body of a URL (text/HTML only). Args: {"url": "<url>"}`
}
func (t *webFetchTool) Run(args map[string]string) (string, error) {
	url := args["url"]
	if url == "" {
		return "", fmt.Errorf("missing required arg: url")
	}
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		return "", fmt.Errorf("url must start with http:// or https://")
	}
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(url) //nolint:noctx
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	const maxBytes = 32 * 1024 // 32 KB limit
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes))
	if err != nil {
		return "", err
	}
	result := string(body)
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("HTTP %d: %s", resp.StatusCode, result)
	}
	return result, nil
}
