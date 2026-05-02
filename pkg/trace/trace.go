// Package trace correlates recent git commits with PM plan tasks using an AI provider.
// It walks git log, sends commit messages + task list to the provider, and returns
// a structured mapping of commit→task with confidence levels.
package trace

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
)

// Commit holds a parsed git log entry.
type Commit struct {
	Hash    string `json:"hash"`
	Subject string `json:"subject"`
}

// Confidence is the AI-rated match quality for a commit→task pairing.
type Confidence string

const (
	ConfidenceHigh   Confidence = "high"
	ConfidenceMedium Confidence = "medium"
	ConfidenceLow    Confidence = "low"
	ConfidenceNone   Confidence = "none"
)

// TraceEntry links a single commit to a task (or indicates no match).
type TraceEntry struct {
	Hash              string     `json:"hash"`
	Subject           string     `json:"subject"`
	MatchedTaskID     int        `json:"matched_task_id"`     // 0 = no match
	MatchedTaskTitle  string     `json:"matched_task_title"`  // empty = no match
	Confidence        Confidence `json:"confidence"`
}

// TraceMap is the complete mapping for a run.
type TraceMap struct {
	GeneratedAt time.Time    `json:"generated_at"`
	Entries     []TraceEntry `json:"entries"`
}

// GitLog returns the most recent commits (up to limit) from workDir.
// If since is non-empty it is passed as --since to git log.
func GitLog(workDir string, limit int, since string) ([]Commit, error) {
	args := []string{"log", fmt.Sprintf("--max-count=%d", limit), "--oneline", "--no-merges"}
	if since != "" {
		args = append(args, "--since="+since)
	}
	cmd := exec.Command("git", args...)
	cmd.Dir = workDir
	out, err := cmd.Output()
	if err != nil {
		// If not a git repo or no commits, return empty gracefully.
		return nil, fmt.Errorf("git log: %w", err)
	}

	var commits []Commit
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// Format: "<short-hash> <subject>"
		parts := strings.SplitN(line, " ", 2)
		if len(parts) != 2 {
			continue
		}
		commits = append(commits, Commit{
			Hash:    parts[0],
			Subject: parts[1],
		})
	}
	return commits, nil
}

// BuildPrompt constructs the AI prompt for commit→task mapping.
func BuildPrompt(commits []Commit, tasks []*pm.Task) string {
	var sb strings.Builder
	sb.WriteString("You are a commit traceability assistant. Your job is to map git commits to project tasks.\n\n")
	sb.WriteString("## Tasks\n")
	for _, t := range tasks {
		sb.WriteString(fmt.Sprintf("- ID %d: %s (%s)\n", t.ID, t.Title, t.Status))
		if t.Description != "" {
			desc := t.Description
			if len(desc) > 120 {
				desc = desc[:120] + "..."
			}
			sb.WriteString(fmt.Sprintf("  Description: %s\n", desc))
		}
	}

	sb.WriteString("\n## Commits\n")
	for _, c := range commits {
		sb.WriteString(fmt.Sprintf("- %s: %s\n", c.Hash, c.Subject))
	}

	sb.WriteString(`
## Instructions

For each commit, determine the most likely task it belongs to.
Return a JSON array with one object per commit in this exact format:

[
  {
    "hash": "<short hash>",
    "matched_task_id": <task ID or 0 if no match>,
    "confidence": "<high|medium|low|none>"
  }
]

Rules:
- Use "high" when the commit message clearly references the task title or ID
- Use "medium" when the commit is likely related but not explicitly mentioned
- Use "low" when it's a weak guess
- Use "none" and matched_task_id=0 when no task matches
- Only output the JSON array, no other text
`)
	return sb.String()
}

// aiEntry is used to decode the AI JSON response.
type aiEntry struct {
	Hash          string `json:"hash"`
	MatchedTaskID int    `json:"matched_task_id"`
	Confidence    string `json:"confidence"`
}

// Run orchestrates the full trace pipeline: collect commits, call AI, parse, return.
func Run(ctx context.Context, prov provider.Provider, model string, workDir string, limit int, since string) (*TraceMap, error) {
	// Load state for tasks (non-fatal if not in PM mode)
	var tasks []*pm.Task
	statePath := filepath.Join(workDir, ".cloop", "state.json")
	if data, err := os.ReadFile(statePath); err == nil {
		var raw struct {
			Plan *pm.Plan `json:"plan"`
		}
		if err := json.Unmarshal(data, &raw); err == nil && raw.Plan != nil {
			tasks = raw.Plan.Tasks
		}
	}

	commits, err := GitLog(workDir, limit, since)
	if err != nil {
		return nil, err
	}
	if len(commits) == 0 {
		return &TraceMap{GeneratedAt: time.Now()}, nil
	}

	// Build a lookup for tasks by ID.
	taskByID := make(map[int]*pm.Task, len(tasks))
	for _, t := range tasks {
		taskByID[t.ID] = t
	}

	prompt := BuildPrompt(commits, tasks)

	resp, err := prov.Complete(ctx, prompt, provider.Options{
		Model:   model,
		Timeout: 2 * time.Minute,
	})
	if err != nil {
		return nil, fmt.Errorf("AI completion: %w", err)
	}

	// Extract JSON from the response (may be wrapped in markdown fences).
	jsonText := extractJSON(resp.Output)

	var aiEntries []aiEntry
	if err := json.Unmarshal([]byte(jsonText), &aiEntries); err != nil {
		return nil, fmt.Errorf("parsing AI response: %w\nRaw: %s", err, resp.Output)
	}

	// Index AI entries by hash for O(1) lookup.
	aiByHash := make(map[string]aiEntry, len(aiEntries))
	for _, e := range aiEntries {
		aiByHash[e.Hash] = e
	}

	entries := make([]TraceEntry, 0, len(commits))
	for _, c := range commits {
		entry := TraceEntry{
			Hash:       c.Hash,
			Subject:    c.Subject,
			Confidence: ConfidenceNone,
		}
		if ai, ok := aiByHash[c.Hash]; ok {
			entry.MatchedTaskID = ai.MatchedTaskID
			entry.Confidence = Confidence(ai.Confidence)
			if ai.MatchedTaskID > 0 {
				if t, ok := taskByID[ai.MatchedTaskID]; ok {
					entry.MatchedTaskTitle = t.Title
				}
			}
		}
		entries = append(entries, entry)
	}

	tm := &TraceMap{
		GeneratedAt: time.Now(),
		Entries:     entries,
	}
	return tm, nil
}

// WriteTraceJSON persists the trace map to .cloop/trace.json.
func WriteTraceJSON(workDir string, tm *TraceMap) error {
	dir := filepath.Join(workDir, ".cloop")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(tm, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "trace.json"), data, 0o644)
}

// LoadTraceJSON reads the persisted trace map from .cloop/trace.json.
// Returns nil without error when the file does not exist.
func LoadTraceJSON(workDir string) (*TraceMap, error) {
	data, err := os.ReadFile(filepath.Join(workDir, ".cloop", "trace.json"))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var tm TraceMap
	if err := json.Unmarshal(data, &tm); err != nil {
		return nil, err
	}
	return &tm, nil
}

// LastLinkedCommit returns the most recent commit entry that was matched to a task,
// or nil if none found. Used by `cloop status`.
func LastLinkedCommit(workDir string) *TraceEntry {
	tm, err := LoadTraceJSON(workDir)
	if err != nil || tm == nil {
		return nil
	}
	for _, e := range tm.Entries {
		if e.MatchedTaskID > 0 && e.Confidence != ConfidenceNone {
			return &e
		}
	}
	return nil
}

// extractJSON pulls a JSON array from an AI response that may contain markdown fences.
func extractJSON(s string) string {
	s = strings.TrimSpace(s)
	// Strip markdown code fences if present.
	for _, fence := range []string{"```json", "```"} {
		if idx := strings.Index(s, fence); idx != -1 {
			s = s[idx+len(fence):]
			if end := strings.Index(s, "```"); end != -1 {
				s = s[:end]
			}
		}
	}
	s = strings.TrimSpace(s)
	// Find the outer array.
	start := strings.Index(s, "[")
	end := strings.LastIndex(s, "]")
	if start != -1 && end != -1 && end > start {
		return s[start : end+1]
	}
	return s
}
