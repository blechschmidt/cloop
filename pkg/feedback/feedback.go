// Package feedback stores human ratings on AI task outputs.
// Records are appended to .cloop/feedback.jsonl as an append-only JSONL log.
package feedback

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const feedbackFile = ".cloop/feedback.jsonl"

// Record is a single human-rating entry for a task output.
type Record struct {
	TaskID    int       `json:"task_id"`
	TaskTitle string    `json:"task_title"`
	Rating    int       `json:"rating"`    // 1-5
	Comment   string    `json:"comment,omitempty"`
	Provider  string    `json:"provider,omitempty"`
	Model     string    `json:"model,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}

// Append writes a single feedback record to the JSONL log, creating the
// file and parent directory as needed.
func Append(workDir string, rec Record) error {
	if rec.Rating < 1 || rec.Rating > 5 {
		return fmt.Errorf("rating must be between 1 and 5, got %d", rec.Rating)
	}
	if rec.Timestamp.IsZero() {
		rec.Timestamp = time.Now().UTC()
	}

	path := filepath.Join(workDir, feedbackFile)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("feedback mkdir: %w", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("feedback open: %w", err)
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(rec); err != nil {
		return fmt.Errorf("feedback encode: %w", err)
	}
	return nil
}

// List reads all feedback records from the JSONL log. When taskID > 0 only
// records matching that task ID are returned. Returns nil, nil when the file
// does not exist yet.
func List(workDir string, taskID int) ([]Record, error) {
	path := filepath.Join(workDir, feedbackFile)
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("feedback open: %w", err)
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
		if taskID > 0 && rec.TaskID != taskID {
			continue
		}
		records = append(records, rec)
	}
	return records, scanner.Err()
}

// AvgRating returns the average rating across the supplied records, and the
// count of records included. Returns 0, 0 when the slice is empty.
func AvgRating(records []Record) (avg float64, count int) {
	if len(records) == 0 {
		return 0, 0
	}
	sum := 0
	for _, r := range records {
		sum += r.Rating
	}
	return float64(sum) / float64(len(records)), len(records)
}

// Stars returns a star-string representation of a 1-5 rating, e.g. "★★★☆☆".
func Stars(rating int) string {
	if rating < 1 {
		rating = 1
	}
	if rating > 5 {
		rating = 5
	}
	return strings.Repeat("★", rating) + strings.Repeat("☆", 5-rating)
}
