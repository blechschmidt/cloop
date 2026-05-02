// Package importer parses CSV exports from Jira, Linear, and GitHub Issues
// and converts them into cloop pm.Task slices ready for appending to a plan.
package importer

import (
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/blechschmidt/cloop/pkg/pm"
)

// Format identifies the source CSV schema.
type Format string

const (
	FormatAuto   Format = "auto"
	FormatJira   Format = "jira"
	FormatLinear Format = "linear"
	FormatGitHub Format = "github"
)

// Import reads a CSV file at path, detects or uses the given format, and
// returns a slice of Tasks ready to be appended to an existing plan.
// startID is the ID to assign to the first imported task; subsequent tasks
// get startID+1, startID+2, etc.
func Import(path string, format Format, startID int) ([]*pm.Task, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()

	r := csv.NewReader(f)
	r.LazyQuotes = true
	r.TrimLeadingSpace = true

	headers, err := r.Read()
	if err != nil {
		return nil, fmt.Errorf("read headers: %w", err)
	}

	// Normalise header names for comparison.
	idx := buildIndex(headers)

	if format == FormatAuto {
		format = detect(idx)
	}

	var tasks []*pm.Task
	id := startID

	for {
		row, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read row: %w", err)
		}

		var t *pm.Task
		switch format {
		case FormatJira:
			t = parseJira(row, idx, id)
		case FormatLinear:
			t = parseLinear(row, idx, id)
		case FormatGitHub:
			t = parseGitHub(row, idx, id)
		default:
			return nil, fmt.Errorf("unknown format %q", format)
		}

		if t != nil {
			tasks = append(tasks, t)
			id++
		}
	}

	return tasks, nil
}

// detect sniffs the header index to choose a format.
func detect(idx map[string]int) Format {
	if has(idx, "summary") && has(idx, "labels") {
		return FormatJira
	}
	if has(idx, "identifier") {
		return FormatLinear
	}
	if has(idx, "body") || (has(idx, "title") && has(idx, "state")) {
		return FormatGitHub
	}
	// Default fallback.
	return FormatJira
}

// buildIndex returns a map of lowercase header name → column index.
func buildIndex(headers []string) map[string]int {
	m := make(map[string]int, len(headers))
	for i, h := range headers {
		m[strings.ToLower(strings.TrimSpace(h))] = i
	}
	return m
}

func has(idx map[string]int, key string) bool {
	_, ok := idx[key]
	return ok
}

func col(row []string, idx map[string]int, key string) string {
	i, ok := idx[key]
	if !ok || i >= len(row) {
		return ""
	}
	return strings.TrimSpace(row[i])
}

// mapStatus converts external status strings to cloop TaskStatus.
func mapStatus(s string) pm.TaskStatus {
	lower := strings.ToLower(strings.TrimSpace(s))
	switch lower {
	case "done", "closed", "complete", "completed", "resolved", "merged":
		return pm.TaskDone
	case "in_progress", "in progress", "in-progress", "doing", "started", "active":
		return pm.TaskInProgress
	default:
		return pm.TaskPending
	}
}

// mapPriority converts external priority strings to cloop integers (1=highest).
func mapPriority(s string) int {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "highest", "critical", "blocker", "urgent", "p0", "1":
		return 1
	case "high", "major", "p1", "2":
		return 2
	case "medium", "normal", "moderate", "p2", "3":
		return 3
	case "low", "minor", "p3", "4":
		return 4
	case "lowest", "trivial", "p4", "5":
		return 5
	default:
		return 3 // default medium
	}
}

// parseTags splits a comma- or semicolon-separated label string into a slice.
func parseTags(raw string) []string {
	if raw == "" {
		return nil
	}
	raw = strings.ReplaceAll(raw, ";", ",")
	parts := strings.Split(raw, ",")
	var out []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// parseJira handles exports with: Summary, Description, Priority, Status, Labels
func parseJira(row []string, idx map[string]int, id int) *pm.Task {
	title := col(row, idx, "summary")
	if title == "" {
		return nil
	}
	return &pm.Task{
		ID:          id,
		Title:       title,
		Description: col(row, idx, "description"),
		Priority:    mapPriority(col(row, idx, "priority")),
		Status:      mapStatus(col(row, idx, "status")),
		Tags:        parseTags(col(row, idx, "labels")),
	}
}

// parseLinear handles exports with: Title, Description, Priority, State, Identifier
func parseLinear(row []string, idx map[string]int, id int) *pm.Task {
	title := col(row, idx, "title")
	if title == "" {
		return nil
	}
	tags := parseTags(col(row, idx, "labels"))
	// Linear identifier (e.g. ENG-42) becomes a tag so it's traceable.
	if ident := col(row, idx, "identifier"); ident != "" {
		tags = append([]string{ident}, tags...)
	}
	return &pm.Task{
		ID:          id,
		Title:       title,
		Description: col(row, idx, "description"),
		Priority:    mapPriority(col(row, idx, "priority")),
		Status:      mapStatus(col(row, idx, "state")),
		Tags:        tags,
	}
}

// parseGitHub handles exports with: title, body, labels, state
func parseGitHub(row []string, idx map[string]int, id int) *pm.Task {
	title := col(row, idx, "title")
	if title == "" {
		return nil
	}
	return &pm.Task{
		ID:          id,
		Title:       title,
		Description: col(row, idx, "body"),
		Priority:    3, // GitHub Issues have no built-in priority
		Status:      mapStatus(col(row, idx, "state")),
		Tags:        parseTags(col(row, idx, "labels")),
	}
}
