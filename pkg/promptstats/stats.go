// Package promptstats tracks per-task prompt outcomes to learn which prompt
// patterns correlate with success vs failure. Records are appended to
// .cloop/prompt-stats.jsonl as JSONL entries.
package promptstats

import (
	"bufio"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const statsFile = ".cloop/prompt-stats.jsonl"

// Record is a single prompt outcome entry written after a task completes.
type Record struct {
	TaskTitle  string `json:"task_title"`
	PromptHash string `json:"prompt_hash"`
	Outcome    string `json:"outcome"`    // "done", "failed", "skipped"
	DurationMs int64  `json:"duration_ms"` // wall-clock ms for the task
}

// HashPrompt returns a 12-char hex prefix of the SHA-256 of the prompt.
// This is used as a compact fingerprint for matching similar prompts.
func HashPrompt(prompt string) string {
	h := sha256.Sum256([]byte(prompt))
	return fmt.Sprintf("%x", h)[:12]
}

// Append writes a single record to the JSONL stats file, creating the file
// and parent directory as needed.
func Append(workDir string, rec Record) error {
	path := filepath.Join(workDir, statsFile)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("promptstats mkdir: %w", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("promptstats open: %w", err)
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(rec); err != nil {
		return fmt.Errorf("promptstats encode: %w", err)
	}
	return nil
}

// Load reads all records from the stats file. Returns nil, nil when the file
// does not exist yet.
func Load(workDir string) ([]Record, error) {
	path := filepath.Join(workDir, statsFile)
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("promptstats open: %w", err)
	}
	defer f.Close()

	var records []Record
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var rec Record
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			continue // skip malformed lines
		}
		records = append(records, rec)
	}
	return records, scanner.Err()
}

// HashStats aggregates outcomes for a single prompt hash.
type HashStats struct {
	Hash     string
	Total    int
	Done     int
	Failed   int
	Skipped  int
	TotalMs  int64
}

// FailureRate returns the fraction of executions that failed (0.0 – 1.0).
func (h HashStats) FailureRate() float64 {
	if h.Total == 0 {
		return 0
	}
	return float64(h.Failed) / float64(h.Total)
}

// SuccessRate returns the fraction of executions that succeeded (0.0 – 1.0).
func (h HashStats) SuccessRate() float64 {
	if h.Total == 0 {
		return 0
	}
	return float64(h.Done) / float64(h.Total)
}

// AvgDurMs returns the average duration in milliseconds.
func (h HashStats) AvgDurMs() int64 {
	if h.Total == 0 {
		return 0
	}
	return h.TotalMs / int64(h.Total)
}

// Summary aggregates all records into per-hash statistics.
type Summary struct {
	Total   int
	Done    int
	Failed  int
	Skipped int
	ByHash  map[string]*HashStats
}

// Summarize aggregates records into a Summary.
func Summarize(records []Record) Summary {
	s := Summary{ByHash: make(map[string]*HashStats)}
	for _, r := range records {
		s.Total++
		switch r.Outcome {
		case "done":
			s.Done++
		case "failed":
			s.Failed++
		case "skipped":
			s.Skipped++
		}
		hs, ok := s.ByHash[r.PromptHash]
		if !ok {
			hs = &HashStats{Hash: r.PromptHash}
			s.ByHash[r.PromptHash] = hs
		}
		hs.Total++
		hs.TotalMs += r.DurationMs
		switch r.Outcome {
		case "done":
			hs.Done++
		case "failed":
			hs.Failed++
		case "skipped":
			hs.Skipped++
		}
	}
	return s
}

// TopPerforming returns HashStats sorted by success rate descending, limited
// to hashes with at least minTotal executions.
func TopPerforming(s Summary, minTotal int) []*HashStats {
	var result []*HashStats
	for _, hs := range s.ByHash {
		if hs.Total >= minTotal {
			result = append(result, hs)
		}
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].SuccessRate() > result[j].SuccessRate()
	})
	return result
}

// AdaptiveHint returns a short advisory string to prepend to a prompt based
// on historical outcomes for tasks with similar titles. Returns "" when
// there is no relevant history (< 2 matching records).
func AdaptiveHint(records []Record, taskTitle string) string {
	if len(records) < 2 {
		return ""
	}
	titleWords := tokenize(taskTitle)

	var successTitles []string
	var failedTitles []string

	for _, r := range records {
		if similarity(titleWords, tokenize(r.TaskTitle)) < 0.25 {
			continue
		}
		switch r.Outcome {
		case "done":
			successTitles = append(successTitles, r.TaskTitle)
		case "failed":
			failedTitles = append(failedTitles, r.TaskTitle)
		}
	}

	if len(successTitles) == 0 && len(failedTitles) == 0 {
		return ""
	}

	var b strings.Builder
	b.WriteString("## ADAPTIVE HINT (from historical task outcomes)\n")

	if len(successTitles) > 0 {
		ex := successTitles
		if len(ex) > 2 {
			ex = ex[len(ex)-2:]
		}
		b.WriteString(fmt.Sprintf(
			"Previous similar tasks succeeded: %s\n",
			strings.Join(ex, "; "),
		))
		b.WriteString("Apply the same approach: implement fully, verify with build/tests, confirm the feature works end-to-end.\n")
	}
	if len(failedTitles) > 0 {
		ex := failedTitles
		if len(ex) > 2 {
			ex = ex[len(ex)-2:]
		}
		b.WriteString(fmt.Sprintf(
			"Previous similar tasks failed: %s — review dependencies and edge cases carefully before proceeding.\n",
			strings.Join(ex, "; "),
		))
	}
	b.WriteString("\n")
	return b.String()
}

// FeedbackRecord is a minimal view of pkg/feedback.Record used here to avoid
// an import cycle. Callers should pass feedback records cast to this type.
type FeedbackRecord struct {
	TaskID    int
	TaskTitle string
	Rating    int // 1-5
	Comment   string
}

// FeedbackHint returns a short advisory string derived from human ratings of
// similar tasks. Returns "" when there are fewer than 2 matching records.
// High-rated tasks (4-5) indicate an approach that worked well; low-rated
// ones (1-2) flag patterns to avoid.
func FeedbackHint(records []FeedbackRecord, taskTitle string) string {
	if len(records) < 2 {
		return ""
	}
	titleWords := tokenize(taskTitle)

	var highRated []string
	var lowRated []string
	for _, r := range records {
		if similarity(titleWords, tokenize(r.TaskTitle)) < 0.25 {
			continue
		}
		switch {
		case r.Rating >= 4:
			label := r.TaskTitle
			if r.Comment != "" {
				label += fmt.Sprintf(" (%s)", r.Comment)
			}
			highRated = append(highRated, label)
		case r.Rating <= 2:
			label := r.TaskTitle
			if r.Comment != "" {
				label += fmt.Sprintf(" (%s)", r.Comment)
			}
			lowRated = append(lowRated, label)
		}
	}

	if len(highRated) == 0 && len(lowRated) == 0 {
		return ""
	}

	var b strings.Builder
	b.WriteString("## HUMAN FEEDBACK HINT (from rated task outputs)\n")
	if len(highRated) > 0 {
		ex := highRated
		if len(ex) > 2 {
			ex = ex[len(ex)-2:]
		}
		b.WriteString(fmt.Sprintf(
			"Highly-rated similar tasks: %s\n",
			strings.Join(ex, "; "),
		))
		b.WriteString("Maintain this quality: be thorough, address edge cases, and verify the output works end-to-end.\n")
	}
	if len(lowRated) > 0 {
		ex := lowRated
		if len(ex) > 2 {
			ex = ex[len(ex)-2:]
		}
		b.WriteString(fmt.Sprintf(
			"Poorly-rated similar tasks: %s — avoid the same mistakes, pay extra attention to completeness and clarity.\n",
			strings.Join(ex, "; "),
		))
	}
	b.WriteString("\n")
	return b.String()
}

// tokenize splits a string into lowercase words of length >= 3.
func tokenize(s string) []string {
	words := strings.FieldsFunc(strings.ToLower(s), func(r rune) bool {
		return !('a' <= r && r <= 'z') && !('0' <= r && r <= '9')
	})
	result := words[:0]
	for _, w := range words {
		if len(w) >= 3 {
			result = append(result, w)
		}
	}
	return result
}

// similarity returns the Jaccard similarity coefficient between two word sets.
func similarity(a, b []string) float64 {
	if len(a) == 0 || len(b) == 0 {
		return 0
	}
	setA := make(map[string]bool, len(a))
	for _, w := range a {
		setA[w] = true
	}
	intersect := 0
	union := len(setA)
	for _, w := range b {
		if setA[w] {
			intersect++
		} else {
			union++
		}
	}
	return float64(intersect) / float64(union)
}
