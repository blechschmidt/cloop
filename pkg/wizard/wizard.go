// Package wizard implements a step-by-step terminal setup wizard for cloop init.
// It uses bufio.Scanner and ANSI escape codes; no external dependencies required.
package wizard

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// Result holds the values collected by the wizard.
type Result struct {
	Goal         string
	Provider     string
	APIKey       string
	Model        string
	MaxSteps     int
	MaxParallel  int
	PMMode       bool
	Instructions string
}

// Run launches the interactive wizard and returns the collected Result.
// It writes prompts to stdout and reads answers from stdin.
func Run() (*Result, error) {
	scanner := bufio.NewScanner(os.Stdin)
	res := &Result{}

	clearScreen()
	printBanner()

	// ── Step 1: Goal ─────────────────────────────────────────────────────────
	printStep(1, 6, "Project Goal")
	fmt.Println("  Describe what you want cloop to build or accomplish.")
	fmt.Println("  (Press Enter twice to finish)")
	fmt.Println()
	var goalLines []string
	for {
		fmt.Print(bold("  > "))
		if !scanner.Scan() {
			break
		}
		line := scanner.Text()
		if line == "" && len(goalLines) > 0 {
			break
		}
		if line != "" {
			goalLines = append(goalLines, line)
		}
	}
	if len(goalLines) == 0 {
		return nil, fmt.Errorf("goal cannot be empty")
	}
	res.Goal = strings.Join(goalLines, " ")
	printConfirm("Goal", truncate(res.Goal, 60))

	// ── Step 2: Provider ─────────────────────────────────────────────────────
	printStep(2, 6, "AI Provider")
	providers := []string{"claudecode", "anthropic", "openai", "ollama", "mock"}
	providerDesc := []string{
		"Claude Code CLI (local, no API key needed)",
		"Anthropic API (claude-sonnet-4-6 etc.)",
		"OpenAI API (gpt-4o etc.)",
		"Ollama (local models, no API key needed)",
		"Mock (offline deterministic, for CI/testing)",
	}
	selectedIdx := chooseFromList(scanner, providers, providerDesc, 0)
	res.Provider = providers[selectedIdx]
	printConfirm("Provider", res.Provider)

	// ── Step 3: API Key (if needed) ─────────────────────────────────────────
	printStep(3, 6, "API Key")
	needsKey := res.Provider == "anthropic" || res.Provider == "openai"
	if needsKey {
		envVar := "ANTHROPIC_API_KEY"
		if res.Provider == "openai" {
			envVar = "OPENAI_API_KEY"
		}
		envVal := os.Getenv(envVar)
		if envVal != "" {
			fmt.Printf("  %s is already set in environment — leave blank to use it.\n", green(envVar))
		} else {
			fmt.Printf("  Enter your %s API key (input hidden):\n", res.Provider)
		}
		fmt.Println()
		fmt.Print(bold("  > "))
		key := readMasked(scanner)
		if key != "" {
			res.APIKey = key
		}
		if res.APIKey == "" && envVal == "" {
			fmt.Println("  " + yellow("Warning: no API key provided — set "+envVar+" before running."))
		} else if res.APIKey != "" {
			printConfirm("API Key", strings.Repeat("*", len(res.APIKey)))
		} else {
			printConfirm("API Key", "(from "+envVar+" env var)")
		}
	} else {
		fmt.Println("  " + green("No API key needed for "+res.Provider+"."))
		printConfirm("API Key", "n/a")
	}

	// ── Step 4: Model ────────────────────────────────────────────────────────
	printStep(4, 6, "Model")
	defaultModels := map[string][]string{
		"claudecode": {"(provider default)", "claude-opus-4-6", "claude-sonnet-4-6", "claude-haiku-4-5-20251001"},
		"anthropic":  {"claude-sonnet-4-6", "claude-opus-4-6", "claude-haiku-4-5-20251001"},
		"openai":     {"gpt-4o", "gpt-4o-mini", "gpt-4-turbo", "o1"},
		"ollama":     {"llama3.2", "mistral", "qwen2.5", "deepseek-r1"},
		"mock":       {"(provider default)"},
	}
	models := defaultModels[res.Provider]
	if len(models) == 0 {
		models = []string{"(provider default)"}
	}
	fmt.Println("  Choose a model or type a custom model name:")
	fmt.Println()
	selectedModel := chooseFromListWithCustom(scanner, models, 0)
	if selectedModel == "(provider default)" {
		selectedModel = ""
	}
	res.Model = selectedModel
	if res.Model != "" {
		printConfirm("Model", res.Model)
	} else {
		printConfirm("Model", "(provider default)")
	}

	// ── Step 5: Max Steps & Parallelism ──────────────────────────────────────
	printStep(5, 6, "Execution Settings")
	fmt.Println("  Max steps per run (0 = unlimited, default 0):")
	fmt.Print(bold("  > "))
	if scanner.Scan() {
		val := strings.TrimSpace(scanner.Text())
		if val != "" {
			if n, err := strconv.Atoi(val); err == nil && n >= 0 {
				res.MaxSteps = n
			}
		}
	}
	fmt.Println()
	fmt.Println("  Max parallel tasks (0 = sequential, default 0):")
	fmt.Print(bold("  > "))
	if scanner.Scan() {
		val := strings.TrimSpace(scanner.Text())
		if val != "" {
			if n, err := strconv.Atoi(val); err == nil && n >= 0 {
				res.MaxParallel = n
			}
		}
	}
	fmt.Println()
	fmt.Println("  Enable Product Manager mode (AI decomposes goal into tasks)? [Y/n]:")
	fmt.Print(bold("  > "))
	if scanner.Scan() {
		ans := strings.TrimSpace(strings.ToLower(scanner.Text()))
		res.PMMode = ans == "" || ans == "y" || ans == "yes"
	}
	printConfirm("Max Steps", strconv.Itoa(res.MaxSteps))
	printConfirm("Max Parallel", strconv.Itoa(res.MaxParallel))
	if res.PMMode {
		printConfirm("PM Mode", "enabled")
	} else {
		printConfirm("PM Mode", "disabled")
	}

	// ── Step 6: Confirm ──────────────────────────────────────────────────────
	printStep(6, 6, "Confirm & Write Config")
	fmt.Println()
	fmt.Println("  Summary:")
	fmt.Printf("    %-14s %s\n", "Goal:", truncate(res.Goal, 60))
	fmt.Printf("    %-14s %s\n", "Provider:", res.Provider)
	if res.Model != "" {
		fmt.Printf("    %-14s %s\n", "Model:", res.Model)
	}
	if res.APIKey != "" {
		fmt.Printf("    %-14s %s\n", "API Key:", strings.Repeat("*", len(res.APIKey)))
	}
	fmt.Printf("    %-14s %d\n", "Max Steps:", res.MaxSteps)
	fmt.Printf("    %-14s %d\n", "Max Parallel:", res.MaxParallel)
	fmt.Printf("    %-14s %v\n", "PM Mode:", res.PMMode)
	fmt.Println()
	fmt.Print("  Proceed? [Y/n]: ")
	if scanner.Scan() {
		ans := strings.TrimSpace(strings.ToLower(scanner.Text()))
		if ans != "" && ans != "y" && ans != "yes" {
			return nil, fmt.Errorf("setup cancelled")
		}
	}
	fmt.Println()
	return res, nil
}

// ── UI helpers ────────────────────────────────────────────────────────────────

const (
	ansiReset  = "\033[0m"
	ansiBold   = "\033[1m"
	ansiGreen  = "\033[32m"
	ansiYellow = "\033[33m"
	ansiCyan   = "\033[36m"
)

func bold(s string) string   { return ansiBold + s + ansiReset }
func green(s string) string  { return ansiGreen + s + ansiReset }
func yellow(s string) string { return ansiYellow + s + ansiReset }
func cyan(s string) string   { return ansiCyan + s + ansiReset }

func clearScreen() {
	fmt.Print("\033[2J\033[H")
}

func printBanner() {
	fmt.Println(cyan(ansiBold + "  ╔═══════════════════════════════════╗"))
	fmt.Println(cyan("  ║       cloop  Setup  Wizard        ║"))
	fmt.Println(cyan("  ╚═══════════════════════════════════╝" + ansiReset))
	fmt.Println()
}

func printStep(n, total int, title string) {
	fmt.Print("\n" + bold(cyan(fmt.Sprintf("  Step %d/%d — %s", n, total, title))) + "\n")
	fmt.Println(strings.Repeat("─", 42))
}

func printConfirm(label, value string) {
	fmt.Printf("  "+green("✓")+" %-14s %s\n", label+":", bold(value))
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}

// chooseFromList renders a numbered list and reads a 1-based selection.
func chooseFromList(scanner *bufio.Scanner, items, descs []string, defaultIdx int) int {
	for i, item := range items {
		marker := "  "
		if i == defaultIdx {
			marker = green("→ ")
		}
		desc := ""
		if i < len(descs) {
			desc = "  " + descs[i]
		}
		fmt.Printf("  %s[%d] %s%s\n", marker, i+1, bold(item), desc)
	}
	fmt.Printf("\n  Select [1-%d] (default %d): ", len(items), defaultIdx+1)
	if scanner.Scan() {
		val := strings.TrimSpace(scanner.Text())
		if val == "" {
			return defaultIdx
		}
		if n, err := strconv.Atoi(val); err == nil && n >= 1 && n <= len(items) {
			return n - 1
		}
	}
	return defaultIdx
}

// chooseFromListWithCustom is like chooseFromList but allows typing a custom value.
func chooseFromListWithCustom(scanner *bufio.Scanner, items []string, defaultIdx int) string {
	for i, item := range items {
		marker := "  "
		if i == defaultIdx {
			marker = green("→ ")
		}
		fmt.Printf("  %s[%d] %s\n", marker, i+1, item)
	}
	fmt.Printf("  [c] Enter custom model name\n")
	fmt.Printf("\n  Select [1-%d/c] (default %d): ", len(items), defaultIdx+1)
	if scanner.Scan() {
		val := strings.TrimSpace(scanner.Text())
		if val == "" {
			return items[defaultIdx]
		}
		if val == "c" || val == "C" {
			fmt.Print("  Custom model name: ")
			if scanner.Scan() {
				custom := strings.TrimSpace(scanner.Text())
				if custom != "" {
					return custom
				}
			}
			return items[defaultIdx]
		}
		if n, err := strconv.Atoi(val); err == nil && n >= 1 && n <= len(items) {
			return items[n-1]
		}
	}
	return items[defaultIdx]
}
