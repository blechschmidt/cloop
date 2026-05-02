// Package search implements unified full-text search across all cloop project artifacts.
// It can search tasks, KB entries, journal entries, step logs, task artifacts,
// changelog, retro reports, and plan snapshots.
package search

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/archive"
	"github.com/blechschmidt/cloop/pkg/journal"
	"github.com/blechschmidt/cloop/pkg/kb"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/replay"
	"github.com/blechschmidt/cloop/pkg/state"
)

// SourceType identifies the artifact type a result came from.
type SourceType string

const (
	SourceTask      SourceType = "task"
	SourceKB        SourceType = "kb"
	SourceJournal   SourceType = "journal"
	SourceStepLog   SourceType = "steplog"
	SourceArtifact  SourceType = "artifact"
	SourceChangelog SourceType = "changelog"
	SourceRetro     SourceType = "retro"
	SourceSnapshot  SourceType = "snapshot"
	SourceArchive   SourceType = "archive"
)

// AllSources is the full set of source types.
var AllSources = []SourceType{
	SourceTask, SourceKB, SourceJournal, SourceStepLog,
	SourceArtifact, SourceChangelog, SourceRetro, SourceSnapshot,
	SourceArchive,
}

// Result is one match returned by a search.
type Result struct {
	Source    SourceType `json:"source"`
	ID        string     `json:"id,omitempty"`         // task ID, KB entry ID, etc.
	Title     string     `json:"title,omitempty"`      // human-readable label
	Excerpt   string     `json:"excerpt"`              // matched text snippet (≤200 chars)
	FilePath  string     `json:"file_path,omitempty"` // relative path to file
	Timestamp time.Time  `json:"timestamp,omitempty"` // when the artifact was created/updated
	Score     int        `json:"score"`               // relevance score (higher = more relevant)
}

// Options controls the search behaviour.
type Options struct {
	// Types filters which source types to search. Empty = all.
	Types []SourceType
	// Semantic uses the AI provider to re-rank results by relevance.
	Semantic bool
	// Provider and Model for semantic re-ranking.
	Provider provider.Provider
	Model    string
	// Timeout for AI calls.
	Timeout time.Duration
}

// excerptAround returns a ≤maxLen character snippet centred on the first
// case-insensitive occurrence of query in text.
func excerptAround(text, query string, maxLen int) string {
	lower := strings.ToLower(text)
	lq := strings.ToLower(query)
	idx := strings.Index(lower, lq)
	if idx == -1 {
		// No direct match; return beginning of text.
		if len(text) > maxLen {
			return strings.TrimSpace(text[:maxLen]) + "…"
		}
		return strings.TrimSpace(text)
	}
	start := idx - maxLen/4
	if start < 0 {
		start = 0
	}
	end := start + maxLen
	if end > len(text) {
		end = len(text)
	}
	excerpt := strings.TrimSpace(text[start:end])
	if start > 0 {
		excerpt = "…" + excerpt
	}
	if end < len(text) {
		excerpt = excerpt + "…"
	}
	// Collapse newlines.
	return strings.Join(strings.Fields(excerpt), " ")
}

// substringScore counts non-overlapping case-insensitive occurrences of query in text.
func substringScore(text, query string) int {
	if query == "" || text == "" {
		return 0
	}
	lower := strings.ToLower(text)
	lq := strings.ToLower(query)
	count := 0
	for {
		i := strings.Index(lower, lq)
		if i == -1 {
			break
		}
		count++
		lower = lower[i+len(lq):]
	}
	return count
}

// matchesAny returns true if text contains any of the query words case-insensitively.
func matchesAny(text, query string) bool {
	if query == "" {
		return true
	}
	lower := strings.ToLower(text)
	// Try full query first.
	if strings.Contains(lower, strings.ToLower(query)) {
		return true
	}
	// Fall back to any word match (words > 3 chars).
	for _, w := range strings.Fields(query) {
		if len(w) > 3 && strings.Contains(lower, strings.ToLower(w)) {
			return true
		}
	}
	return false
}

// enabled returns true if the given source type is included in the filter list.
func enabled(typ SourceType, types []SourceType) bool {
	if len(types) == 0 {
		return true
	}
	for _, t := range types {
		if t == typ {
			return true
		}
	}
	return false
}

// Run executes the search and returns matching results sorted by score descending.
func Run(ctx context.Context, workDir, query string, opts Options) ([]Result, error) {
	var results []Result

	if enabled(SourceTask, opts.Types) {
		r, err := searchTasks(workDir, query)
		if err == nil {
			results = append(results, r...)
		}
	}

	if enabled(SourceKB, opts.Types) {
		r, err := searchKB(workDir, query)
		if err == nil {
			results = append(results, r...)
		}
	}

	if enabled(SourceJournal, opts.Types) {
		r, err := searchJournal(workDir, query)
		if err == nil {
			results = append(results, r...)
		}
	}

	if enabled(SourceStepLog, opts.Types) {
		r, err := searchStepLog(workDir, query)
		if err == nil {
			results = append(results, r...)
		}
	}

	if enabled(SourceArtifact, opts.Types) {
		r, err := searchArtifacts(workDir, query)
		if err == nil {
			results = append(results, r...)
		}
	}

	if enabled(SourceChangelog, opts.Types) {
		r, err := searchFile(workDir, query, ".cloop/CHANGELOG.md", SourceChangelog, "Changelog")
		if err == nil {
			results = append(results, r...)
		}
	}

	if enabled(SourceRetro, opts.Types) {
		r, err := searchGlob(workDir, query, ".cloop/retro-*.md", SourceRetro)
		if err == nil {
			results = append(results, r...)
		}
	}

	if enabled(SourceSnapshot, opts.Types) {
		r, err := searchSnapshots(workDir, query)
		if err == nil {
			results = append(results, r...)
		}
	}

	if enabled(SourceArchive, opts.Types) {
		r, err := searchArchive(workDir, query)
		if err == nil {
			results = append(results, r...)
		}
	}

	// Remove zero-score results.
	filtered := results[:0]
	for _, r := range results {
		if r.Score > 0 {
			filtered = append(filtered, r)
		}
	}
	results = filtered

	// Sort by score descending.
	sort.Slice(results, func(i, j int) bool {
		if results[i].Score != results[j].Score {
			return results[i].Score > results[j].Score
		}
		return results[i].Timestamp.After(results[j].Timestamp)
	})

	if opts.Semantic && opts.Provider != nil && len(results) > 0 {
		results = semanticRank(ctx, opts.Provider, opts.Model, query, results, opts.Timeout)
	}

	return results, nil
}

// searchTasks searches task titles, descriptions, and annotations.
func searchTasks(workDir, query string) ([]Result, error) {
	s, err := state.Load(workDir)
	if err != nil || s.Plan == nil {
		return nil, nil
	}
	var results []Result
	for _, t := range s.Plan.Tasks {
		haystack := t.Title + " " + t.Description
		for _, a := range t.Annotations {
			haystack += " " + a.Text
		}
		score := substringScore(haystack, query)
		if score == 0 {
			continue
		}
		excerpt := excerptAround(haystack, query, 200)
		results = append(results, Result{
			Source:  SourceTask,
			ID:      fmt.Sprintf("%d", t.ID),
			Title:   fmt.Sprintf("Task %d: %s", t.ID, t.Title),
			Excerpt: excerpt,
			Score:   score * 3, // tasks weighted higher
		})
	}
	return results, nil
}

// searchArchive searches tasks in .cloop/archive.json.
func searchArchive(workDir, query string) ([]Result, error) {
	tasks, err := archive.Load(workDir)
	if err != nil || len(tasks) == 0 {
		return nil, nil
	}
	var results []Result
	for _, a := range tasks {
		t := a.Task
		haystack := t.Title + " " + t.Description
		for _, ann := range t.Annotations {
			haystack += " " + ann.Text
		}
		score := substringScore(haystack, query)
		if score == 0 {
			continue
		}
		excerpt := excerptAround(haystack, query, 200)
		results = append(results, Result{
			Source:    SourceArchive,
			ID:        fmt.Sprintf("%d", t.ID),
			Title:     fmt.Sprintf("Archived Task %d: %s [%s]", t.ID, t.Title, t.Status),
			Excerpt:   excerpt,
			FilePath:  ".cloop/archive.json",
			Timestamp: a.ArchivedAt,
			Score:     score * 2,
		})
	}
	return results, nil
}

// searchKB searches knowledge base entries.
func searchKB(workDir, query string) ([]Result, error) {
	base, err := kb.Load(workDir)
	if err != nil {
		return nil, err
	}
	var results []Result
	for _, e := range base.Entries {
		haystack := e.Title + " " + e.Content + " " + strings.Join(e.Tags, " ")
		score := substringScore(haystack, query)
		if score == 0 {
			continue
		}
		excerpt := excerptAround(e.Title+" — "+e.Content, query, 200)
		results = append(results, Result{
			Source:    SourceKB,
			ID:        fmt.Sprintf("%d", e.ID),
			Title:     fmt.Sprintf("KB #%d: %s", e.ID, e.Title),
			Excerpt:   excerpt,
			FilePath:  ".cloop/kb.json",
			Timestamp: e.CreatedAt,
			Score:     score * 2,
		})
	}
	return results, nil
}

// searchJournal searches all per-task journal JSONL files.
func searchJournal(workDir, query string) ([]Result, error) {
	dir := filepath.Join(workDir, ".cloop", "journal")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, nil // directory may not exist
	}
	var results []Result
	for _, de := range entries {
		if de.IsDir() || !strings.HasSuffix(de.Name(), ".jsonl") {
			continue
		}
		relPath := filepath.Join(".cloop", "journal", de.Name())
		absPath := filepath.Join(workDir, relPath)
		f, err := os.Open(absPath)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		lineNum := 0
		for sc.Scan() {
			lineNum++
			var e journal.Entry
			if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
				continue
			}
			score := substringScore(e.Body, query)
			if score == 0 {
				continue
			}
			excerpt := excerptAround(e.Body, query, 200)
			results = append(results, Result{
				Source:    SourceJournal,
				ID:        fmt.Sprintf("%s:%d", e.TaskID, lineNum),
				Title:     fmt.Sprintf("Journal [task %s] %s", e.TaskID, e.Type),
				Excerpt:   excerpt,
				FilePath:  relPath,
				Timestamp: e.Timestamp,
				Score:     score,
			})
		}
		f.Close()
	}
	return results, nil
}

// searchStepLog searches the replay.jsonl step log.
func searchStepLog(workDir, query string) ([]Result, error) {
	relPath := ".cloop/replay.jsonl"
	absPath := filepath.Join(workDir, relPath)
	f, err := os.Open(absPath)
	if err != nil {
		return nil, nil
	}
	defer f.Close()

	var results []Result
	sc := bufio.NewScanner(f)
	// replay entries can be large; increase buffer.
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		var e replay.Entry
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			continue
		}
		haystack := e.TaskTitle + " " + e.Content
		score := substringScore(haystack, query)
		if score == 0 {
			continue
		}
		excerpt := excerptAround(e.Content, query, 200)
		results = append(results, Result{
			Source:    SourceStepLog,
			ID:        fmt.Sprintf("task%d:step%d", e.TaskID, e.Step),
			Title:     fmt.Sprintf("Step log [task %d \"%s\" step %d]", e.TaskID, e.TaskTitle, e.Step),
			Excerpt:   excerpt,
			FilePath:  relPath,
			Timestamp: e.Ts,
			Score:     score,
		})
	}
	return results, nil
}

// searchArtifacts searches task artifact markdown files in .cloop/tasks/.
func searchArtifacts(workDir, query string) ([]Result, error) {
	dir := filepath.Join(workDir, ".cloop", "tasks")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, nil
	}
	var results []Result
	for _, de := range entries {
		if de.IsDir() || !strings.HasSuffix(de.Name(), ".md") {
			continue
		}
		relPath := filepath.Join(".cloop", "tasks", de.Name())
		absPath := filepath.Join(workDir, relPath)
		data, err := os.ReadFile(absPath)
		if err != nil {
			continue
		}
		text := string(data)
		score := substringScore(text, query)
		if score == 0 {
			continue
		}
		info, _ := de.Info()
		var ts time.Time
		if info != nil {
			ts = info.ModTime()
		}
		// Use filename as title (strip .md).
		title := strings.TrimSuffix(de.Name(), ".md")
		excerpt := excerptAround(text, query, 200)
		results = append(results, Result{
			Source:    SourceArtifact,
			ID:        de.Name(),
			Title:     fmt.Sprintf("Artifact: %s", title),
			Excerpt:   excerpt,
			FilePath:  relPath,
			Timestamp: ts,
			Score:     score,
		})
	}
	return results, nil
}

// searchFile searches a single file, returning one result per match block.
func searchFile(workDir, query, relPath string, src SourceType, label string) ([]Result, error) {
	absPath := filepath.Join(workDir, relPath)
	data, err := os.ReadFile(absPath)
	if err != nil {
		return nil, nil
	}
	text := string(data)
	score := substringScore(text, query)
	if score == 0 {
		return nil, nil
	}
	info, _ := os.Stat(absPath)
	var ts time.Time
	if info != nil {
		ts = info.ModTime()
	}
	excerpt := excerptAround(text, query, 200)
	return []Result{{
		Source:    src,
		ID:        filepath.Base(relPath),
		Title:     label,
		Excerpt:   excerpt,
		FilePath:  relPath,
		Timestamp: ts,
		Score:     score,
	}}, nil
}

// searchGlob searches a set of files matching a glob pattern.
func searchGlob(workDir, query, globPattern string, src SourceType) ([]Result, error) {
	absGlob := filepath.Join(workDir, globPattern)
	matches, err := filepath.Glob(absGlob)
	if err != nil {
		return nil, err
	}
	var results []Result
	for _, absPath := range matches {
		data, err := os.ReadFile(absPath)
		if err != nil {
			continue
		}
		text := string(data)
		score := substringScore(text, query)
		if score == 0 {
			continue
		}
		rel, _ := filepath.Rel(workDir, absPath)
		info, _ := os.Stat(absPath)
		var ts time.Time
		if info != nil {
			ts = info.ModTime()
		}
		label := strings.TrimSuffix(filepath.Base(absPath), ".md")
		excerpt := excerptAround(text, query, 200)
		results = append(results, Result{
			Source:    src,
			ID:        filepath.Base(absPath),
			Title:     fmt.Sprintf("%s: %s", strings.Title(string(src)), label),
			Excerpt:   excerpt,
			FilePath:  rel,
			Timestamp: ts,
			Score:     score,
		})
	}
	return results, nil
}

// searchSnapshots searches plan snapshot JSON files.
func searchSnapshots(workDir, query string) ([]Result, error) {
	dir := filepath.Join(workDir, ".cloop", "plan-history")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, nil
	}
	var results []Result
	for _, de := range entries {
		if de.IsDir() || !strings.HasSuffix(de.Name(), ".json") {
			continue
		}
		relPath := filepath.Join(".cloop", "plan-history", de.Name())
		absPath := filepath.Join(workDir, relPath)
		data, err := os.ReadFile(absPath)
		if err != nil {
			continue
		}
		var snap pm.Snapshot
		if err := json.Unmarshal(data, &snap); err != nil {
			continue
		}
		// Build searchable text from all task titles + descriptions in the snapshot.
		var sb strings.Builder
		if snap.Plan != nil {
			sb.WriteString(snap.Plan.Goal)
			sb.WriteString(" ")
			for _, t := range snap.Plan.Tasks {
				sb.WriteString(t.Title)
				sb.WriteString(" ")
				sb.WriteString(t.Description)
				sb.WriteString(" ")
			}
		}
		text := sb.String()
		score := substringScore(text, query)
		if score == 0 {
			continue
		}
		excerpt := excerptAround(text, query, 200)
		results = append(results, Result{
			Source:    SourceSnapshot,
			ID:        de.Name(),
			Title:     fmt.Sprintf("Snapshot v%d (%s)", snap.Version, snap.Timestamp.Format("2006-01-02")),
			Excerpt:   excerpt,
			FilePath:  relPath,
			Timestamp: snap.Timestamp,
			Score:     score,
		})
	}
	return results, nil
}

// SemanticRankPrompt builds the AI prompt used to re-rank results.
func SemanticRankPrompt(query string, results []Result) string {
	var b strings.Builder
	b.WriteString("You are a search relevance engine. Given a user query and a list of search results, ")
	b.WriteString("return the indices of the results re-ranked from most to least relevant.\n\n")
	b.WriteString(fmt.Sprintf("## QUERY\n%s\n\n", query))
	b.WriteString("## RESULTS\n")
	for i, r := range results {
		b.WriteString(fmt.Sprintf("[%d] source=%s title=%q\n    %s\n\n", i, r.Source, r.Title, r.Excerpt))
	}
	b.WriteString("## INSTRUCTIONS\n")
	b.WriteString("Return ONLY a JSON array of 0-based indices in relevance order, e.g. [2,0,1,3]. ")
	b.WriteString("Include ALL indices. No explanation.")
	return b.String()
}

// semanticRank uses the AI provider to re-order results by semantic relevance.
// Falls back to the original order on any error.
func semanticRank(ctx context.Context, p provider.Provider, model, query string, results []Result, timeout time.Duration) []Result {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	prompt := SemanticRankPrompt(query, results)
	opts := provider.Options{Model: model}
	var buf strings.Builder
	opts.OnToken = func(t string) { buf.WriteString(t) }
	if _, err := p.Complete(ctx, prompt, opts); err != nil {
		return results
	}
	raw := buf.String()
	start := strings.Index(raw, "[")
	end := strings.LastIndex(raw, "]")
	if start == -1 || end <= start {
		return results
	}
	var indices []int
	if err := json.Unmarshal([]byte(raw[start:end+1]), &indices); err != nil {
		return results
	}

	// Build re-ordered slice; include any missing indices at the end.
	seen := make(map[int]bool, len(results))
	ranked := make([]Result, 0, len(results))
	for _, idx := range indices {
		if idx < 0 || idx >= len(results) || seen[idx] {
			continue
		}
		seen[idx] = true
		r := results[idx]
		r.Score = len(results) - len(ranked) // descending synthetic score
		ranked = append(ranked, r)
	}
	// Append any results the AI missed.
	for i, r := range results {
		if !seen[i] {
			ranked = append(ranked, r)
		}
	}
	return ranked
}

// ParseTypes parses a comma-separated type filter string into SourceType slice.
// "all" or empty returns nil (= all types).
func ParseTypes(s string) ([]SourceType, error) {
	if s == "" || s == "all" {
		return nil, nil
	}
	var types []SourceType
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		switch SourceType(part) {
		case SourceTask, SourceKB, SourceJournal, SourceStepLog,
			SourceArtifact, SourceChangelog, SourceRetro, SourceSnapshot:
			types = append(types, SourceType(part))
		default:
			return nil, fmt.Errorf("unknown type %q — valid values: tasks, kb, journal, steplog, artifact, changelog, retro, snapshot, all", part)
		}
	}
	return types, nil
}
