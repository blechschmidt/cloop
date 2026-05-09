// Package learning implements cross-session AI learning memory for cloop.
// After each PM run the AI distills key outcomes, failure patterns, and project
// conventions into .cloop/memory.md. On subsequent runs this memory is injected
// into every task execution prompt so the AI improves over time.
package learning

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/blechschmidt/cloop/pkg/atomicfile"
	"github.com/blechschmidt/cloop/pkg/boundedread"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
)

const memoryFile = ".cloop/memory.md"

// memoryFileMaxBytes caps how much of memory.md the load and read-modify-write
// paths will pull into RAM. Memory is plain prose distilled by the AI at the
// end of each PM run; in steady state the file stays well under 100 KiB. A cap
// of 1 MiB tolerates many sessions of accumulation while preventing two
// pathologies if the file ever bloats unexpectedly (provider hallucination,
// disk-corruption replay, deliberate tampering): (1) FormatForPrompt would
// inject the full bytes into every task prompt, blowing token budgets and
// potentially triggering provider errors; (2) SaveMemory's read-modify-write
// would slurp the bloated file into RAM, append, and write it back — so each
// run would amplify the bloat instead of self-healing. With the cap, an
// oversize file causes LoadMemory to return empty and SaveMemory to drop the
// stale content (recreating a fresh memory.md with just the new session), so
// the system recovers automatically on the next run instead of staying broken.
const memoryFileMaxBytes int64 = 1 << 20

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

	// Load existing content to append. A bounded read prevents this
	// read-modify-write from amplifying a bloated memory.md every run — if
	// the file ever exceeds memoryFileMaxBytes, treat existing as empty so
	// the next write recreates the file cleanly with just the new session.
	// errors.Is(err, fs.ErrNotExist) is the expected first-write path; any
	// other error (perms, I/O) also degrades to empty so we don't lose the
	// new session because of a transient read failure.
	existing, readErr := boundedread.ReadFile(path, memoryFileMaxBytes)
	if readErr != nil {
		existing = nil
		if errors.Is(readErr, boundedread.ErrTooLarge) {
			fmt.Fprintf(os.Stderr, "[learning] memory.md exceeds %d bytes; resetting and starting fresh: %v\n", memoryFileMaxBytes, readErr)
		}
	}

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

	return atomicfile.Write(path, []byte(b.String()), 0o644)
}

// LoadMemory reads the project memory from .cloop/memory.md.
// Returns empty string if no memory file exists yet, or if the file exceeds
// the in-prompt size cap (memoryFileMaxBytes) — in which case prompts run
// without injected memory until the next SaveMemory call rewrites the file
// at a healthy size, rather than risk blowing token budgets by injecting an
// arbitrarily large blob into every task prompt.
func LoadMemory(workDir string) string {
	path := filepath.Join(workDir, memoryFile)
	data, err := boundedread.ReadFile(path, memoryFileMaxBytes)
	if err != nil {
		if errors.Is(err, boundedread.ErrTooLarge) {
			fmt.Fprintf(os.Stderr, "[learning] memory.md exceeds %d bytes; skipping prompt injection until next SaveMemory: %v\n", memoryFileMaxBytes, err)
		}
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
