// Package memory implements persistent session learning for cloop.
// After each session the AI can extract key learnings (what worked, what failed,
// important project facts) which are stored in .cloop/memory.json and injected
// into future session prompts so the AI builds institutional knowledge over time.
package memory

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/provider"
)

const memoryFile = ".cloop/memory.json"

// Entry is a single learned fact stored across sessions.
type Entry struct {
	ID        int       `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	Goal      string    `json:"goal,omitempty"`   // project goal when memory was recorded
	Content   string    `json:"content"`           // the learning / fact
	Source    string    `json:"source"`            // "ai" or "user"
	Tags      []string  `json:"tags,omitempty"`
}

// Memory is the persistent knowledge base for a project.
type Memory struct {
	Entries []*Entry `json:"entries"`
	NextID  int      `json:"next_id"`
}

// Load reads memory from disk. Returns empty memory if file doesn't exist.
func Load(workDir string) (*Memory, error) {
	path := filepath.Join(workDir, memoryFile)
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return &Memory{NextID: 1}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read memory: %w", err)
	}
	var m Memory
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parse memory: %w", err)
	}
	if m.NextID == 0 {
		m.NextID = len(m.Entries) + 1
	}
	return &m, nil
}

// Save persists memory to disk.
func (m *Memory) Save(workDir string) error {
	path := filepath.Join(workDir, memoryFile)
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

// Add appends a new entry to memory.
func (m *Memory) Add(content, source, goal string, tags []string) *Entry {
	e := &Entry{
		ID:        m.NextID,
		Timestamp: time.Now(),
		Goal:      goal,
		Content:   content,
		Source:    source,
		Tags:      tags,
	}
	m.NextID++
	m.Entries = append(m.Entries, e)
	return e
}

// Delete removes an entry by ID. Returns false if not found.
func (m *Memory) Delete(id int) bool {
	for i, e := range m.Entries {
		if e.ID == id {
			m.Entries = append(m.Entries[:i], m.Entries[i+1:]...)
			return true
		}
	}
	return false
}

// Clear removes all entries.
func (m *Memory) Clear() {
	m.Entries = nil
	m.NextID = 1
}

// FormatForPrompt returns a prompt-ready summary of stored memories.
// It returns at most limit entries (most recent first). 0 = all.
func (m *Memory) FormatForPrompt(limit int) string {
	if len(m.Entries) == 0 {
		return ""
	}
	entries := m.Entries
	// Most recent first
	reversed := make([]*Entry, len(entries))
	for i, e := range entries {
		reversed[len(entries)-1-i] = e
	}
	if limit > 0 && len(reversed) > limit {
		reversed = reversed[:limit]
	}
	var b strings.Builder
	b.WriteString("## PROJECT MEMORY (learnings from previous sessions)\n")
	b.WriteString("Use this accumulated knowledge to avoid repeating mistakes and build on past work:\n\n")
	for _, e := range reversed {
		age := formatAge(e.Timestamp)
		b.WriteString(fmt.Sprintf("- [%s ago] %s\n", age, e.Content))
	}
	b.WriteString("\n")
	return b.String()
}

// ExtractLearningsPrompt builds a prompt asking the AI to extract key learnings
// from the just-completed session.
func ExtractLearningsPrompt(goal string, sessionSummary string) string {
	var b strings.Builder
	b.WriteString("You are reviewing a completed AI work session to extract useful learnings for future sessions.\n\n")
	b.WriteString(fmt.Sprintf("## PROJECT GOAL\n%s\n\n", goal))
	b.WriteString("## SESSION SUMMARY\n")
	b.WriteString(sessionSummary)
	b.WriteString("\n\n## INSTRUCTIONS\n")
	b.WriteString("Extract 1-5 concise, actionable learnings from this session. Focus on:\n")
	b.WriteString("- What worked well (approaches, tools, patterns)\n")
	b.WriteString("- What failed or caused problems (avoid in future)\n")
	b.WriteString("- Important project facts discovered (architecture, conventions, constraints)\n")
	b.WriteString("- Dependencies or blockers that were resolved\n\n")
	b.WriteString("Output ONLY a JSON array of learning strings (no explanation, no markdown):\n")
	b.WriteString(`["Learning 1: what we discovered", "Learning 2: what to avoid", ...]`)
	b.WriteString("\n\nKeep each learning under 150 characters. Be specific. If the session had no learnings worth recording, output: []")
	return b.String()
}

// ExtractLearnings calls the AI to extract learnings from a session and stores them.
func ExtractLearnings(ctx context.Context, p provider.Provider, model string, goal string, sessionSummary string, mem *Memory) ([]string, error) {
	if strings.TrimSpace(sessionSummary) == "" {
		return nil, nil
	}
	prompt := ExtractLearningsPrompt(goal, sessionSummary)
	result, err := p.Complete(ctx, prompt, provider.Options{
		Model:   model,
		Timeout: 60 * time.Second,
	})
	if err != nil {
		return nil, fmt.Errorf("extract learnings: %w", err)
	}

	learnings, err := parseLearnings(result.Output)
	if err != nil {
		return nil, fmt.Errorf("parse learnings: %w", err)
	}

	for _, l := range learnings {
		mem.Add(l, "ai", goal, nil)
	}
	return learnings, nil
}

// parseLearnings extracts a JSON string array from the AI response.
func parseLearnings(output string) ([]string, error) {
	// Find the JSON array
	start := strings.Index(output, "[")
	end := strings.LastIndex(output, "]")
	if start == -1 || end == -1 || end <= start {
		return nil, nil // No array found — treat as no learnings
	}
	jsonStr := output[start : end+1]
	var learnings []string
	if err := json.Unmarshal([]byte(jsonStr), &learnings); err != nil {
		return nil, fmt.Errorf("unmarshal learnings: %w", err)
	}
	// Filter empty strings
	var result []string
	for _, l := range learnings {
		if strings.TrimSpace(l) != "" {
			result = append(result, strings.TrimSpace(l))
		}
	}
	return result, nil
}

// FormatAge returns a human-readable age string for a timestamp.
func FormatAge(t time.Time) string {
	return formatAge(t)
}

func formatAge(t time.Time) string {
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	case d < 7*24*time.Hour:
		return fmt.Sprintf("%dd", int(d.Hours()/24))
	default:
		return fmt.Sprintf("%dw", int(d.Hours()/(24*7)))
	}
}
