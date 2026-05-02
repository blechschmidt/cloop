// Package kb implements a persistent project-scoped knowledge base stored in .cloop/kb.json.
// Each entry has an ID, title, content, tags, and creation timestamp.
// The KB is used to inject relevant context into task execution prompts.
package kb

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/provider"
)

const kbFile = ".cloop/kb.json"

// Entry is a single knowledge base record.
type Entry struct {
	ID        int       `json:"id"`
	Title     string    `json:"title"`
	Content   string    `json:"content"`
	Tags      []string  `json:"tags,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// KB is the in-memory representation of the knowledge base.
type KB struct {
	Entries []*Entry `json:"entries"`
}

func path(workDir string) string {
	return filepath.Join(workDir, kbFile)
}

// Load reads the knowledge base from disk. Returns an empty KB if the file does not exist.
func Load(workDir string) (*KB, error) {
	data, err := os.ReadFile(path(workDir))
	if os.IsNotExist(err) {
		return &KB{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("kb: read: %w", err)
	}
	var kb KB
	if err := json.Unmarshal(data, &kb); err != nil {
		return nil, fmt.Errorf("kb: parse: %w", err)
	}
	return &kb, nil
}

// Save writes the knowledge base to disk, creating the .cloop directory if needed.
func Save(workDir string, kb *KB) error {
	dir := filepath.Join(workDir, ".cloop")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("kb: mkdir: %w", err)
	}
	data, err := json.MarshalIndent(kb, "", "  ")
	if err != nil {
		return fmt.Errorf("kb: marshal: %w", err)
	}
	return os.WriteFile(path(workDir), data, 0o644)
}

// nextID returns 1 + the maximum existing entry ID (or 1 if the KB is empty).
func nextID(kb *KB) int {
	max := 0
	for _, e := range kb.Entries {
		if e.ID > max {
			max = e.ID
		}
	}
	return max + 1
}

// Add creates a new entry and appends it to the KB. Returns the new entry.
func Add(workDir, title, content string, tags []string) (*Entry, error) {
	kb, err := Load(workDir)
	if err != nil {
		return nil, err
	}
	entry := &Entry{
		ID:        nextID(kb),
		Title:     title,
		Content:   content,
		Tags:      tags,
		CreatedAt: time.Now(),
	}
	kb.Entries = append(kb.Entries, entry)
	if err := Save(workDir, kb); err != nil {
		return nil, err
	}
	return entry, nil
}

// Get returns the entry with the given ID, or an error if not found.
func Get(workDir string, id int) (*Entry, error) {
	kb, err := Load(workDir)
	if err != nil {
		return nil, err
	}
	for _, e := range kb.Entries {
		if e.ID == id {
			return e, nil
		}
	}
	return nil, fmt.Errorf("kb: entry %d not found", id)
}

// Remove deletes the entry with the given ID. Returns an error if not found.
func Remove(workDir string, id int) error {
	kb, err := Load(workDir)
	if err != nil {
		return err
	}
	newEntries := make([]*Entry, 0, len(kb.Entries))
	found := false
	for _, e := range kb.Entries {
		if e.ID == id {
			found = true
			continue
		}
		newEntries = append(newEntries, e)
	}
	if !found {
		return fmt.Errorf("kb: entry %d not found", id)
	}
	kb.Entries = newEntries
	return Save(workDir, kb)
}

// KeywordScore returns a relevance score for an entry against a query string.
// It counts normalized word overlaps between the query and the entry title+content.
func KeywordScore(entry *Entry, query string) int {
	normalize := func(s string) map[string]bool {
		words := strings.FieldsFunc(strings.ToLower(s), func(r rune) bool {
			return !('a' <= r && r <= 'z') && !('0' <= r && r <= '9')
		})
		m := make(map[string]bool, len(words))
		for _, w := range words {
			if len(w) > 2 { // skip very short words
				m[w] = true
			}
		}
		return m
	}

	qWords := normalize(query)
	haystack := normalize(entry.Title + " " + entry.Content)

	score := 0
	for w := range qWords {
		if haystack[w] {
			score++
		}
	}
	// Title matches count double
	titleWords := normalize(entry.Title)
	for w := range qWords {
		if titleWords[w] {
			score++
		}
	}
	return score
}

// TopRelevant returns up to n entries most relevant to the query using keyword overlap.
// Entries with zero score are excluded.
func TopRelevant(workDir, query string, n int) ([]*Entry, error) {
	kb, err := Load(workDir)
	if err != nil {
		return nil, err
	}
	type scored struct {
		entry *Entry
		score int
	}
	var candidates []scored
	for _, e := range kb.Entries {
		s := KeywordScore(e, query)
		if s > 0 {
			candidates = append(candidates, scored{e, s})
		}
	}
	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].score > candidates[j].score
	})
	if len(candidates) > n {
		candidates = candidates[:n]
	}
	result := make([]*Entry, len(candidates))
	for i, c := range candidates {
		result[i] = c.entry
	}
	return result, nil
}

// SearchPrompt builds a prompt for AI-powered semantic search over KB entries.
func SearchPrompt(query string, entries []*Entry) string {
	var b strings.Builder
	b.WriteString("You are a knowledge base search engine. Given a search query and a list of knowledge base entries, return the IDs of the most relevant entries.\n\n")
	b.WriteString(fmt.Sprintf("## QUERY\n%s\n\n", query))
	b.WriteString("## KNOWLEDGE BASE ENTRIES\n")
	for _, e := range entries {
		tags := ""
		if len(e.Tags) > 0 {
			tags = fmt.Sprintf(" [tags: %s]", strings.Join(e.Tags, ", "))
		}
		b.WriteString(fmt.Sprintf("ID %d: %s%s\n%s\n\n", e.ID, e.Title, tags, e.Content))
	}
	b.WriteString("## INSTRUCTIONS\nReturn ONLY a JSON array of entry IDs sorted by relevance (most relevant first), e.g. [3,1,5]. ")
	b.WriteString("Return an empty array [] if nothing is relevant. No explanation.")
	return b.String()
}

// AISearch performs semantic search using the provider and returns relevant entries.
func AISearch(ctx context.Context, p provider.Provider, model, workDir, query string) ([]*Entry, error) {
	kb, err := Load(workDir)
	if err != nil {
		return nil, err
	}
	if len(kb.Entries) == 0 {
		return nil, nil
	}

	prompt := SearchPrompt(query, kb.Entries)
	opts := provider.Options{Model: model}
	var buf strings.Builder
	opts.OnToken = func(t string) { buf.WriteString(t) }
	if _, err := p.Complete(ctx, prompt, opts); err != nil {
		return nil, fmt.Errorf("kb: AI search: %w", err)
	}
	raw := buf.String()
	// Extract JSON array from response
	start := strings.Index(raw, "[")
	end := strings.LastIndex(raw, "]")
	if start == -1 || end <= start {
		return nil, nil
	}
	var ids []int
	if err := json.Unmarshal([]byte(raw[start:end+1]), &ids); err != nil {
		return nil, fmt.Errorf("kb: parse search result: %w", err)
	}
	// Build id→entry map
	idMap := make(map[int]*Entry, len(kb.Entries))
	for _, e := range kb.Entries {
		idMap[e.ID] = e
	}
	var result []*Entry
	for _, id := range ids {
		if e, ok := idMap[id]; ok {
			result = append(result, e)
		}
	}
	return result, nil
}

// FormatKBSection formats a slice of entries as a "## Project Knowledge" markdown section
// suitable for injection into AI prompts.
func FormatKBSection(entries []*Entry) string {
	if len(entries) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("## Project Knowledge\n")
	for _, e := range entries {
		b.WriteString(fmt.Sprintf("### %s\n", e.Title))
		b.WriteString(e.Content)
		b.WriteString("\n\n")
	}
	return b.String()
}
