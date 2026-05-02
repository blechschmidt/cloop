package cmd

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/testgen"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	genTestsProvider string
	genTestsModel    string
	genTestsTimeout  string
	genTestsLang     string
	genTestsRun      bool
)

var taskGenerateTestsCmd = &cobra.Command{
	Use:   "generate-tests <task-id>",
	Short: "AI-generated test suite from completed task output",
	Long: `Ask the AI provider to generate a test suite for a completed task.

The command reads the task description and artifact output, detects the
project language (Go, Python, Node.js, or shell), and writes the generated
tests to .cloop/tests/<task-id>_test.<ext>.

Use --run to execute the generated tests immediately after writing them.

Language is auto-detected from project files (go.mod, package.json, *.py).
Override with --lang go|python|node|shell.

Examples:
  cloop task generate-tests 5
  cloop task generate-tests 5 --run
  cloop task generate-tests 5 --lang go --provider anthropic
  cloop task generate-tests 5 --run --timeout 3m`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()

		s, err := state.Load(workdir)
		if err != nil {
			return err
		}
		if !s.PMMode || s.Plan == nil || len(s.Plan.Tasks) == 0 {
			return fmt.Errorf("no task plan found — run 'cloop run --pm' to create one")
		}

		taskID, err := strconv.Atoi(args[0])
		if err != nil {
			return fmt.Errorf("invalid task ID %q: must be a number", args[0])
		}

		var task = s.Plan.TaskByID(taskID)
		if task == nil {
			return fmt.Errorf("task %d not found", taskID)
		}

		// Build provider
		cfg, err := config.Load(workdir)
		if err != nil {
			return fmt.Errorf("loading config: %w", err)
		}
		applyEnvOverrides(cfg)

		pName := genTestsProvider
		if pName == "" {
			pName = cfg.Provider
		}
		if pName == "" && s.Provider != "" {
			pName = s.Provider
		}
		if pName == "" {
			pName = autoSelectProvider()
		}

		model := genTestsModel
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

		timeout := 5 * time.Minute
		if genTestsTimeout != "" {
			timeout, err = time.ParseDuration(genTestsTimeout)
			if err != nil {
				return fmt.Errorf("invalid timeout: %w", err)
			}
		}

		// Detect language
		var lang testgen.Lang
		if genTestsLang != "" {
			switch genTestsLang {
			case "go":
				lang = testgen.LangGo
			case "python":
				lang = testgen.LangPython
			case "node", "js", "javascript":
				lang = testgen.LangNode
			case "shell", "bash", "sh":
				lang = testgen.LangShell
			default:
				return fmt.Errorf("unknown language %q: use go, python, node, or shell", genTestsLang)
			}
		} else {
			lang = testgen.DetectLang(workdir)
		}

		headerColor := color.New(color.FgCyan, color.Bold)
		dimColor := color.New(color.Faint)
		successColor := color.New(color.FgGreen)
		failColor := color.New(color.FgRed)

		headerColor.Printf("Generating tests for task %d: %s\n", task.ID, task.Title)
		dimColor.Printf("Language: %s  |  Provider: %s\n\n", lang, pName)

		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		opts := provider.Options{
			Model:   model,
			Timeout: timeout,
		}

		result, err := testgen.Generate(ctx, prov, opts, workdir, task, lang)
		if err != nil {
			return fmt.Errorf("test generation failed: %w", err)
		}

		// Show relative path for readability
		rel, relErr := filepath.Rel(workdir, result.FilePath)
		if relErr != nil {
			rel = result.FilePath
		}

		successColor.Printf("Tests written to: %s\n\n", rel)
		dimColor.Printf("--- preview (first 20 lines) ---\n")
		printFirstLines(result.Code, 20)
		fmt.Println()

		if !genTestsRun {
			dimColor.Printf("Tip: run 'cloop task generate-tests %d --run' to execute the tests immediately.\n", taskID)
			return nil
		}

		// Execute tests
		headerColor.Printf("Running tests...\n\n")

		runCmd, runArgs := buildRunCommand(lang, result.FilePath, workdir)
		execCmd := exec.CommandContext(ctx, runCmd, runArgs...)
		execCmd.Dir = workdir

		var outBuf bytes.Buffer
		execCmd.Stdout = &outBuf
		execCmd.Stderr = &outBuf

		runErr := execCmd.Run()
		output := outBuf.String()
		fmt.Print(output)

		if runErr != nil {
			failColor.Printf("\nTests FAILED (exit code %d)\n", execCmd.ProcessState.ExitCode())
			return fmt.Errorf("tests failed")
		}

		successColor.Printf("\nTests PASSED\n")
		return nil
	},
}

// buildRunCommand returns the executable and args needed to run the generated
// test file for the given language.
func buildRunCommand(lang testgen.Lang, filePath, workDir string) (string, []string) {
	switch lang {
	case testgen.LangGo:
		// Run all tests in the .cloop/tests/ directory as a standalone package.
		// Since the generated file may not be part of the module tree, we compile
		// and run it directly with `go run`.
		return "go", []string{"run", filePath}
	case testgen.LangPython:
		return "python3", []string{filePath}
	case testgen.LangNode:
		return "node", []string{"--test", filePath}
	default: // shell
		return "bash", []string{filePath}
	}
}

// printFirstLines prints at most n lines of text.
func printFirstLines(text string, n int) {
	dimColor := color.New(color.Faint)
	lines := splitLines(text)
	count := n
	if len(lines) < count {
		count = len(lines)
	}
	for _, line := range lines[:count] {
		dimColor.Printf("  %s\n", line)
	}
	if len(lines) > n {
		dimColor.Printf("  ... (%d more lines)\n", len(lines)-n)
	}
}

func splitLines(s string) []string {
	var lines []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			lines = append(lines, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}

func init() {
	taskGenerateTestsCmd.Flags().StringVar(&genTestsProvider, "provider", "", "AI provider to use (anthropic, openai, ollama, claudecode)")
	taskGenerateTestsCmd.Flags().StringVar(&genTestsModel, "model", "", "Model override for the AI provider")
	taskGenerateTestsCmd.Flags().StringVar(&genTestsTimeout, "timeout", "5m", "Timeout for the AI call (e.g. 2m, 300s)")
	taskGenerateTestsCmd.Flags().StringVar(&genTestsLang, "lang", "", "Language for generated tests: go, python, node, shell (auto-detected if omitted)")
	taskGenerateTestsCmd.Flags().BoolVar(&genTestsRun, "run", false, "Execute the generated tests immediately after writing them")

	taskCmd.AddCommand(taskGenerateTestsCmd)
}
