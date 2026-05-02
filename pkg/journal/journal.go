// Package journal provides a per-task decision log with AI summarization.
// Entries are stored as JSONL (one JSON object per line) in
// .cloop/journal/<task-id>.jsonl for efficient append-only writes.
package journal

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
)

// EntryType classifies a journal entry.
type EntryType string

const (
	TypeDecision    EntryType = "decision"
	TypeObservation EntryType = "observation"
	TypeBlocker     EntryType = "blocker"
	TypeInsight     EntryType = "insight"
)

// ValidTypes lists the accepted entry type values.
var ValidTypes = []EntryType{TypeDecision, TypeObservation, TypeBlocker, TypeInsight}

// IsValidType reports whether t is a recognised entry type.
func IsValidType(t EntryType) bool {
	for _, v := range ValidTypes {
		if v == t {
			return true
		}
	}
	return false
}

// Entry is a single journal record for a task.
type Entry struct {
	Timestamp time.Time `json:"timestamp"`
	TaskID    string    `json:"task_id"`
	Author    string    `json:"author"`
	Type      EntryType `json:"type"`
	Body      string    `json:"body"`
}

// journalDir returns the absolute path to the journal directory.
func journalDir(workDir string) string {
	return filepath.Join(workDir, ".cloop", "journal")
}

// journalFile returns the path to the JSONL file for a given task ID.
func journalFile(workDir, taskID string) string {
	return filepath.Join(journalDir(workDir), taskID+".jsonl")
}

// Append writes a single entry to the task's journal file.
// The file is created if it does not exist. The directory is created on demand.
func Append(workDir string, entry Entry) error {
	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now()
	}
	if err := os.MkdirAll(journalDir(workDir), 0o755); err != nil {
		return fmt.Errorf("journal: creating directory: %w", err)
	}

	data, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("journal: marshaling entry: %w", err)
	}

	f, err := os.OpenFile(journalFile(workDir, entry.TaskID), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("journal: opening file: %w", err)
	}
	defer f.Close()

	_, err = fmt.Fprintf(f, "%s\n", data)
	if err != nil {
		return fmt.Errorf("journal: writing entry: %w", err)
	}
	return nil
}

// List reads all journal entries for the given task ID.
// Returns an empty slice (not an error) when the file does not exist.
func List(workDir, taskID string) ([]Entry, error) {
	path := journalFile(workDir, taskID)
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("journal: opening %s: %w", path, err)
	}
	defer f.Close()

	var entries []Entry
	scanner := bufio.NewScanner(f)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var e Entry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			return nil, fmt.Errorf("journal: parsing line %d of %s: %w", lineNum, path, err)
		}
		entries = append(entries, e)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("journal: reading %s: %w", path, err)
	}
	return entries, nil
}

// SummarizePrompt builds the AI prompt used by Summarize.
func SummarizePrompt(taskID string, entries []Entry) string {
	var b strings.Builder
	b.WriteString("You are a technical project manager. Below are journal entries for a specific task.\n")
	b.WriteString("Write a concise narrative summary (3-6 sentences) covering:\n")
	b.WriteString("- Key decisions made and the rationale behind them\n")
	b.WriteString("- Blockers encountered and how they were resolved\n")
	b.WriteString("- Important observations and insights\n")
	b.WriteString("- Overall trajectory of the task\n\n")
	b.WriteString(fmt.Sprintf("## Task ID: %s\n\n", taskID))
	b.WriteString("## Journal Entries\n\n")
	for i, e := range entries {
		b.WriteString(fmt.Sprintf("### Entry %d — %s [%s] by %s\n",
			i+1, e.Timestamp.Format("2006-01-02 15:04"), string(e.Type), e.Author))
		b.WriteString(e.Body)
		b.WriteString("\n\n")
	}
	b.WriteString("## Instructions\n")
	b.WriteString("Write only the narrative summary. Do not repeat the entries verbatim.\n")
	b.WriteString("Be specific and factual. Use past tense. Maximum 200 words.\n")
	return b.String()
}

// Summarize calls the AI provider to generate a narrative summary of a task's journal.
func Summarize(ctx context.Context, p provider.Provider, model string, entries []Entry) (string, error) {
	if len(entries) == 0 {
		return "(no journal entries)", nil
	}

	taskID := entries[0].TaskID
	prompt := SummarizePrompt(taskID, entries)

	result, err := p.Complete(ctx, prompt, provider.Options{
		Model:   model,
		Timeout: 60 * time.Second,
	})
	if err != nil {
		return "", fmt.Errorf("journal summarize: %w", err)
	}
	return strings.TrimSpace(result.Output), nil
}

// ListAll returns all task IDs that have journal files in the given workDir.
func ListAll(workDir string) ([]string, error) {
	dir := journalDir(workDir)
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("journal: reading directory: %w", err)
	}
	var ids []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if strings.HasSuffix(name, ".jsonl") {
			ids = append(ids, strings.TrimSuffix(name, ".jsonl"))
		}
	}
	return ids, nil
}
