// Package learning implements cross-session AI learning memory for cloop.
// After each PM run the AI distills key outcomes, failure patterns, and project
// conventions into .cloop/memory.md. On subsequent runs this memory is injected
// into every task execution prompt so the AI improves over time.
package learning

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
)

const memoryFile = ".cloop/memory.md"

// saveMu serialises the read-modify-write inside SaveMemory. Two concurrent
// callers without this lock would each load the same baseline, each append
// their own session, and the second writer would silently overwrite the first
// — losing accumulated history. Atomic writes guard against torn reads but
// not against lost updates.
var saveMu sync.Mutex

// Distill asks the AI to summarise what worked, what failed, and any recurring
// patterns from the just-completed PM plan. Returns a markdown document.
func Distill(ctx context.Context, p provider.Provider, model string, plan *pm.Plan) (string, error) {
	if plan == nil || len(plan.Tasks) == 0 {
		return "", nil
	}

	prompt := buildDistillPrompt(plan)
	result, err := p.Complete(ctx, prompt, provider.Options{
		Model:   model,
		Timeout: 90 * time.Second,
	})
	if err != nil {
		return "", fmt.Errorf("distill: %w", err)
	}
	output := strings.TrimSpace(result.Output)
	if output == "" {
		return "", nil
	}
	return output, nil
}

// SaveMemory writes the distilled summary to .cloop/memory.md.
// Each call appends a dated section so history accumulates over runs.
//
// The whole read-modify-write is serialised by saveMu — concurrent callers
// would otherwise each load the same baseline and the second writer would
// silently drop the first writer's session. The final write is atomic
// (tmp → fsync → rename), so a crash mid-write can never leave a truncated
// memory.md that destroys all accumulated history.
func SaveMemory(workDir, summary string) error {
	if strings.TrimSpace(summary) == "" {
		return nil
	}
	saveMu.Lock()
	defer saveMu.Unlock()

	path := filepath.Join(workDir, memoryFile)
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("save memory: %w", err)
	}

	// Load existing content to append.
	existing, _ := os.ReadFile(path)

	var b strings.Builder
	if len(existing) == 0 {
		b.WriteString("# cloop Project Memory\n\n")
		b.WriteString("This file contains accumulated learnings from past PM runs.\n")
		b.WriteString("It is automatically updated after each run and injected into future task prompts.\n\n")
	} else {
		b.Write(existing)
		if !strings.HasSuffix(string(existing), "\n") {
			b.WriteString("\n")
		}
		b.WriteString("\n")
	}

	b.WriteString(fmt.Sprintf("## Session — %s\n\n", time.Now().Format("2006-01-02 15:04")))
	b.WriteString(summary)
	b.WriteString("\n")

	return writeAtomic(path, []byte(b.String()), 0o644)
}

// writeAtomic stages data to a sibling .tmp file in the same directory, fsyncs
// it, then renames it over path. Rename within a directory is atomic on
// POSIX/Linux, so any concurrent reader either sees the old file or the new
// file — never a half-written one.
func writeAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return fmt.Errorf("learning: create tmp: %w", err)
	}
	tmpPath := tmp.Name()
	defer func() {
		if _, statErr := os.Stat(tmpPath); statErr == nil {
			_ = os.Remove(tmpPath)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("learning: write tmp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("learning: sync tmp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("learning: close tmp: %w", err)
	}
	if err := os.Chmod(tmpPath, mode); err != nil {
		return fmt.Errorf("learning: chmod tmp: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("learning: rename tmp: %w", err)
	}
	return nil
}

// LoadMemory reads the project memory from .cloop/memory.md.
// Returns empty string if no memory file exists yet.
func LoadMemory(workDir string) string {
	path := filepath.Join(workDir, memoryFile)
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	content := strings.TrimSpace(string(data))
	if content == "" {
		return ""
	}
	return content
}

// FormatForPrompt wraps the memory content for injection into a task prompt.
// Returns empty string if memory is empty.
func FormatForPrompt(workDir string) string {
	mem := LoadMemory(workDir)
	if mem == "" {
		return ""
	}
	var b strings.Builder
	b.WriteString("## PROJECT MEMORY (learnings from previous PM runs)\n")
	b.WriteString("Use this accumulated knowledge to avoid repeating mistakes and build on past work:\n\n")
	b.WriteString(mem)
	b.WriteString("\n\n---\n\n")
	return b.String()
}

// buildDistillPrompt constructs the AI prompt for plan distillation.
func buildDistillPrompt(plan *pm.Plan) string {
	var b strings.Builder
	b.WriteString("You are reviewing a completed AI product-manager run. Distill the key learnings.\n\n")
	b.WriteString(fmt.Sprintf("## GOAL\n%s\n\n", plan.Goal))
	b.WriteString("## TASK OUTCOMES\n")

	for _, t := range plan.Tasks {
		status := string(t.Status)
		b.WriteString(fmt.Sprintf("- [%s] Task %d (P%d): %s\n", status, t.ID, t.Priority, t.Title))
		if t.Description != "" {
			b.WriteString(fmt.Sprintf("  Description: %s\n", truncate(t.Description, 200)))
		}
		if t.Result != "" {
			b.WriteString(fmt.Sprintf("  Result: %s\n", truncate(t.Result, 300)))
		}
		if t.HealAttempts > 0 {
			b.WriteString(fmt.Sprintf("  Heal attempts: %d\n", t.HealAttempts))
		}
	}

	b.WriteString("\n## INSTRUCTIONS\n")
	b.WriteString("Write a concise markdown document (200–500 words) for future runs. Structure it as:\n\n")
	b.WriteString("### What Worked\n")
	b.WriteString("Approaches, patterns, or tools that produced successful outcomes.\n\n")
	b.WriteString("### What Failed or Caused Problems\n")
	b.WriteString("Patterns to avoid. Include specific failure reasons if informative.\n\n")
	b.WriteString("### Project Conventions Discovered\n")
	b.WriteString("Architecture decisions, coding conventions, constraints, or important facts about the codebase.\n\n")
	b.WriteString("### Recommendations for Next Run\n")
	b.WriteString("Concrete, actionable advice the AI should follow in the next session.\n\n")
	b.WriteString("Be specific and concise. Omit sections that have nothing meaningful to say. ")
	b.WriteString("Output ONLY the markdown content (no outer code fence, no preamble).\n")
	return b.String()
}

func truncate(s string, max int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}
