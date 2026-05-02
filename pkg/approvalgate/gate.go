// Package approvalgate implements human-in-the-loop approval gates for PM task execution.
// When a task requires approval (RequiresApproval:true or high-priority with RequireApproval config),
// the gate pauses execution and prompts the user interactively before the task runs.
package approvalgate

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/fatih/color"
)

// Result is the outcome of an approval gate check.
type Result struct {
	Approved   bool
	Skipped    bool
	Paused     bool
	EditedDesc string // non-empty when user edited the description
}

// Gate is the interface for approval gate implementations.
type Gate interface {
	Approve(task *pm.Task) Result
}

// InteractiveGate prompts the user interactively to approve, skip, or edit a task.
type InteractiveGate struct {
	scanner *bufio.Scanner
}

// New returns a new InteractiveGate reading from os.Stdin.
func New() Gate {
	return &InteractiveGate{scanner: bufio.NewScanner(os.Stdin)}
}

// Approve prompts the user for [y/n/skip/edit] and returns the result.
// Pre-approved tasks (task.Approved == true) bypass the prompt immediately.
func (g *InteractiveGate) Approve(task *pm.Task) Result {
	if task.Approved {
		color.New(color.FgGreen).Printf("  Task %d pre-approved.\n", task.ID)
		return Result{Approved: true}
	}

	approveColor := color.New(color.FgYellow, color.Bold)
	dimColor := color.New(color.Faint)

	approveColor.Printf("\n⚠  Approval required: Task %d [P%d] — %s\n", task.ID, task.Priority, task.Title)
	if task.Description != "" {
		dimColor.Printf("   %s\n", task.Description)
	}

	for {
		fmt.Printf("Approve? [y]es / [n]o (pause) / [s]kip / [e]dit description: ")
		if !g.scanner.Scan() {
			// EOF — treat as pause
			return Result{Paused: true}
		}
		answer := strings.ToLower(strings.TrimSpace(g.scanner.Text()))
		switch answer {
		case "y", "yes", "":
			return Result{Approved: true}
		case "n", "no":
			return Result{Paused: true}
		case "s", "skip":
			return Result{Skipped: true}
		case "e", "edit":
			edited := openEditor(task.Description)
			return Result{Approved: true, EditedDesc: edited}
		}
		fmt.Printf("   Please enter y, n, s, or e: ")
	}
}

// openEditor opens $EDITOR (fallback: vi) on a temp file pre-filled with content.
// Returns the edited content, or the original content if the editor fails.
func openEditor(content string) string {
	editor := os.Getenv("EDITOR")
	if editor == "" {
		editor = os.Getenv("VISUAL")
	}
	if editor == "" {
		editor = "vi"
	}

	tmpFile, err := os.CreateTemp("", "cloop-task-*.txt")
	if err != nil {
		fmt.Fprintf(os.Stderr, "  could not create temp file: %v\n", err)
		return content
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(content); err != nil {
		tmpFile.Close()
		fmt.Fprintf(os.Stderr, "  could not write temp file: %v\n", err)
		return content
	}
	tmpFile.Close()

	cmd := exec.Command(editor, tmpFile.Name())
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "  editor exited with error: %v\n", err)
		return content
	}

	data, err := os.ReadFile(tmpFile.Name())
	if err != nil {
		return content
	}
	result := strings.TrimSpace(string(data))
	if result == "" {
		return content
	}
	return result
}
