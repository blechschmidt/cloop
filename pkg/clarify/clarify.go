// Package clarify implements an interactive goal clarification dialog.
// Before plan decomposition, the AI generates 3-5 clarifying questions about
// the goal (ambiguities, constraints, success criteria, tech stack preferences).
// Answers are collected from stdin and injected as structured context into
// the decomposition prompt, producing a better-scoped plan.
package clarify

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/fatih/color"
	"github.com/mattn/go-isatty"
)

const clarificationFile = "clarification.json"

// QA holds a single clarifying question and the user's answer.
type QA struct {
	Question string `json:"question"`
	Answer   string `json:"answer"`
}

// IsTTY returns true when os.Stdin is an interactive terminal.
func IsTTY() bool {
	return isatty.IsTerminal(os.Stdin.Fd()) || isatty.IsCygwinTerminal(os.Stdin.Fd())
}

// ClarificationPath returns the path to the Q&A audit file.
func ClarificationPath(workDir string) string {
	return filepath.Join(workDir, ".cloop", clarificationFile)
}

// Load reads previously saved clarification Q&A from disk.
// Returns nil, nil when the file does not exist.
func Load(workDir string) ([]QA, error) {
	data, err := os.ReadFile(ClarificationPath(workDir))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var qas []QA
	if err := json.Unmarshal(data, &qas); err != nil {
		return nil, fmt.Errorf("clarification: parse: %w", err)
	}
	return qas, nil
}

// save writes Q&A pairs to .cloop/clarification.json.
func save(workDir string, qas []QA) error {
	path := ClarificationPath(workDir)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(qas, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

// QuestionsPrompt builds the prompt asking the AI to generate clarifying questions.
func QuestionsPrompt(goal, instructions string) string {
	var b strings.Builder
	b.WriteString("You are an AI product manager helping to clarify a project goal before breaking it into tasks.\n\n")
	b.WriteString(fmt.Sprintf("## PROJECT GOAL\n%s\n\n", goal))
	if instructions != "" {
		b.WriteString(fmt.Sprintf("## CONSTRAINTS\n%s\n\n", instructions))
	}
	b.WriteString("## YOUR TASK\n")
	b.WriteString("Generate 3-5 clarifying questions that will help produce a more precise and actionable task plan.\n")
	b.WriteString("Focus on:\n")
	b.WriteString("- Ambiguities in the goal description\n")
	b.WriteString("- Key constraints (tech stack, timeline, budget, team size)\n")
	b.WriteString("- Success criteria and acceptance conditions\n")
	b.WriteString("- Non-obvious scope boundaries (what's in vs out)\n")
	b.WriteString("- Specific preferences that would change the approach\n\n")
	b.WriteString("Output ONLY a JSON array of question strings — no explanation, no markdown:\n")
	b.WriteString(`["question 1","question 2","question 3"]`)
	b.WriteString("\n\nKeep each question concise (one sentence). 3-5 questions total.")
	return b.String()
}

// parseQuestions extracts the JSON array of questions from the AI response.
func parseQuestions(output string) ([]string, error) {
	// Strip any markdown fences
	output = strings.TrimSpace(output)
	if idx := strings.Index(output, "```"); idx != -1 {
		output = output[idx:]
		output = strings.TrimPrefix(output, "```json")
		output = strings.TrimPrefix(output, "```")
		if end := strings.Index(output, "```"); end != -1 {
			output = output[:end]
		}
		output = strings.TrimSpace(output)
	}
	// Find the JSON array
	start := strings.Index(output, "[")
	end := strings.LastIndex(output, "]")
	if start == -1 || end == -1 || end <= start {
		return nil, fmt.Errorf("no JSON array found in response")
	}
	output = output[start : end+1]

	var questions []string
	if err := json.Unmarshal([]byte(output), &questions); err != nil {
		return nil, fmt.Errorf("parse questions: %w", err)
	}
	return questions, nil
}

// Run executes the full clarification dialog:
//  1. Calls the AI provider to generate 3-5 questions about the goal.
//  2. Presents each question to the user interactively on the terminal.
//  3. Collects answers via scanner.
//  4. Saves Q&A pairs to .cloop/clarification.json.
//  5. Returns the Q&A slice for injection into the decomposition prompt.
//
// Returns nil, nil when stdin is not a TTY (non-interactive mode).
// The caller must ensure skip=true in automation contexts.
func Run(
	ctx context.Context,
	p provider.Provider,
	model string,
	timeout time.Duration,
	goal, instructions, workDir string,
	scanner *bufio.Scanner,
) ([]QA, error) {
	promptColor := color.New(color.FgCyan, color.Bold)
	questionColor := color.New(color.FgYellow)
	dimColor := color.New(color.Faint)

	promptColor.Printf("\nGoal clarification\n")
	dimColor.Printf("Generating clarifying questions to refine your plan...\n\n")

	// Ask the AI for clarifying questions.
	prompt := QuestionsPrompt(goal, instructions)
	result, err := p.Complete(ctx, prompt, provider.Options{
		Model:   model,
		Timeout: timeout,
	})
	if err != nil {
		return nil, fmt.Errorf("clarify: generate questions: %w", err)
	}

	questions, err := parseQuestions(result.Output)
	if err != nil {
		// Non-fatal: if we can't parse questions, skip clarification gracefully.
		dimColor.Printf("(Could not parse clarifying questions — skipping)\n\n")
		return nil, nil
	}
	if len(questions) == 0 {
		dimColor.Printf("(No clarifying questions generated — skipping)\n\n")
		return nil, nil
	}

	// Cap at 5 questions.
	if len(questions) > 5 {
		questions = questions[:5]
	}

	promptColor.Printf("Please answer these questions to help scope your plan better.\n")
	dimColor.Printf("Press Enter to skip any question.\n\n")

	var qas []QA
	for i, q := range questions {
		questionColor.Printf("Q%d: %s\n", i+1, q)
		fmt.Print("    > ")
		if !scanner.Scan() {
			break
		}
		answer := strings.TrimSpace(scanner.Text())
		qas = append(qas, QA{Question: q, Answer: answer})
		fmt.Println()
	}

	// Save for auditability.
	if err := save(workDir, qas); err != nil {
		// Non-fatal.
		dimColor.Printf("(Warning: could not save clarification.json: %v)\n", err)
	}

	promptColor.Printf("Clarification complete. Decomposing goal with your answers...\n\n")
	return qas, nil
}

// BuildContext formats Q&A pairs into a structured context block
// suitable for injection into the decomposition prompt.
func BuildContext(qas []QA) string {
	if len(qas) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("## GOAL CLARIFICATION (user-provided context)\n")
	b.WriteString("The following Q&A captures important context provided by the project owner.\n")
	b.WriteString("Use these answers to scope the task plan precisely:\n\n")
	for i, qa := range qas {
		b.WriteString(fmt.Sprintf("**Q%d: %s**\n", i+1, qa.Question))
		if qa.Answer == "" {
			b.WriteString("  Answer: (no answer provided)\n")
		} else {
			b.WriteString(fmt.Sprintf("  Answer: %s\n", qa.Answer))
		}
		b.WriteString("\n")
	}
	return b.String()
}
