// Package planio implements portable plan export and import for sharing
// cloop plans between teams without requiring git access.
// Supported formats: yaml, json, toml.
package planio

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/blechschmidt/cloop/pkg/pm"
	"gopkg.in/yaml.v3"
)

const schemaVersion = "1"

// PlanFile is the portable interchange representation of a plan.
// It uses string tags across all three serialization formats so that
// exported files are human-readable and round-trip cleanly.
type PlanFile struct {
	SchemaVersion string     `json:"schema_version" yaml:"schema_version" toml:"schema_version"`
	ExportedAt    string     `json:"exported_at"    yaml:"exported_at"    toml:"exported_at"`
	Goal          string     `json:"goal"           yaml:"goal"           toml:"goal"`
	Tasks         []TaskFile `json:"tasks"          yaml:"tasks"          toml:"tasks"`
}

// TaskFile is the portable representation of a single task.
// Only fields that are meaningful for interchange are included.
// Runtime-only fields (artifact paths, heal counters, internal state) are omitted.
type TaskFile struct {
	ID               int      `json:"id"                          yaml:"id"                          toml:"id"`
	Title            string   `json:"title"                       yaml:"title"                       toml:"title"`
	Description      string   `json:"description,omitempty"       yaml:"description,omitempty"       toml:"description,omitempty"`
	Priority         int      `json:"priority"                    yaml:"priority"                    toml:"priority"`
	Status           string   `json:"status"                      yaml:"status"                      toml:"status"`
	Role             string   `json:"role,omitempty"              yaml:"role,omitempty"              toml:"role,omitempty"`
	DependsOn        []int    `json:"depends_on,omitempty"        yaml:"depends_on,omitempty"        toml:"depends_on,omitempty"`
	Tags             []string `json:"tags,omitempty"              yaml:"tags,omitempty"              toml:"tags,omitempty"`
	EstimatedMinutes int      `json:"estimated_minutes,omitempty" yaml:"estimated_minutes,omitempty" toml:"estimated_minutes,omitempty"`
	Assignee         string   `json:"assignee,omitempty"          yaml:"assignee,omitempty"          toml:"assignee,omitempty"`
	Deadline         string   `json:"deadline,omitempty"          yaml:"deadline,omitempty"          toml:"deadline,omitempty"`
	Condition        string   `json:"condition,omitempty"         yaml:"condition,omitempty"         toml:"condition,omitempty"`
	Recurrence       string   `json:"recurrence,omitempty"        yaml:"recurrence,omitempty"        toml:"recurrence,omitempty"`
	RequiresApproval bool     `json:"requires_approval,omitempty" yaml:"requires_approval,omitempty" toml:"requires_approval,omitempty"`
	MaxMinutes       int      `json:"max_minutes,omitempty"       yaml:"max_minutes,omitempty"       toml:"max_minutes,omitempty"`
	ExternalURL      string   `json:"external_url,omitempty"      yaml:"external_url,omitempty"      toml:"external_url,omitempty"`
	Result           string   `json:"result,omitempty"            yaml:"result,omitempty"            toml:"result,omitempty"`
}

// DetectFormat infers the serialization format from the file extension.
// Returns "yaml", "json", or "toml". Returns "" when the extension is unknown.
func DetectFormat(path string) string {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".yaml", ".yml":
		return "yaml"
	case ".json":
		return "json"
	case ".toml":
		return "toml"
	default:
		return ""
	}
}

// Export serialises plan to the given format and writes to outputPath.
// If outputPath is "-" or empty the result is written to stdout.
// format must be "yaml", "json", or "toml".
func Export(plan *pm.Plan, format, outputPath string) error {
	if plan == nil {
		return fmt.Errorf("no plan to export")
	}

	pf := planToFile(plan)

	var data []byte
	var err error

	switch format {
	case "yaml":
		data, err = yaml.Marshal(pf)
	case "json":
		data, err = json.MarshalIndent(pf, "", "  ")
		if err == nil {
			data = append(data, '\n')
		}
	case "toml":
		var sb strings.Builder
		enc := toml.NewEncoder(&sb)
		err = enc.Encode(pf)
		if err == nil {
			data = []byte(sb.String())
		}
	default:
		return fmt.Errorf("unsupported format %q: must be yaml, json, or toml", format)
	}

	if err != nil {
		return fmt.Errorf("encoding plan as %s: %w", format, err)
	}

	if outputPath == "" || outputPath == "-" {
		_, err = os.Stdout.Write(data)
		return err
	}

	// Ensure parent directory exists.
	if dir := filepath.Dir(outputPath); dir != "." && dir != "" {
		if mkErr := os.MkdirAll(dir, 0o755); mkErr != nil {
			return fmt.Errorf("creating output directory: %w", mkErr)
		}
	}

	return os.WriteFile(outputPath, data, 0o644)
}

// MergeMode controls how Import handles an existing plan.
type MergeMode string

const (
	// MergeReplace discards the existing plan and replaces it with the imported one.
	MergeReplace MergeMode = "replace"
	// MergeMerge appends new tasks (by title) to the existing plan; existing tasks are kept.
	MergeMerge MergeMode = "merge"
)

// ImportResult carries the imported plan along with diagnostic counters.
type ImportResult struct {
	Plan       *pm.Plan
	Added      int // tasks appended (merge mode only)
	Skipped    int // tasks skipped because they already existed (merge mode only)
	Replaced   int // tasks in the new plan (replace mode only)
}

// Import reads a plan file from filePath, validates it, and merges or replaces
// the existing plan according to mode.
// existing may be nil when there is no current plan (replace always succeeds;
// merge with a nil existing plan treats every imported task as new).
func Import(filePath string, format string, existing *pm.Plan, mode MergeMode) (*ImportResult, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", filePath, err)
	}

	if format == "" {
		format = DetectFormat(filePath)
	}
	if format == "" {
		return nil, fmt.Errorf("cannot determine format from file extension %q — use --format", filepath.Ext(filePath))
	}

	var pf PlanFile

	switch format {
	case "yaml":
		if err := yaml.Unmarshal(data, &pf); err != nil {
			return nil, fmt.Errorf("parsing YAML: %w", err)
		}
	case "json":
		if err := json.Unmarshal(data, &pf); err != nil {
			return nil, fmt.Errorf("parsing JSON: %w", err)
		}
	case "toml":
		if _, err := toml.Decode(string(data), &pf); err != nil {
			return nil, fmt.Errorf("parsing TOML: %w", err)
		}
	default:
		return nil, fmt.Errorf("unsupported format %q: must be yaml, json, or toml", format)
	}

	if err := validate(&pf); err != nil {
		return nil, fmt.Errorf("invalid plan file: %w", err)
	}

	switch mode {
	case MergeReplace:
		return doReplace(&pf), nil
	case MergeMerge:
		return doMerge(&pf, existing), nil
	default:
		return nil, fmt.Errorf("unknown merge mode %q: must be replace or merge", mode)
	}
}

// ---- internal helpers -------------------------------------------------------

// planToFile converts the live pm.Plan into the portable PlanFile.
func planToFile(plan *pm.Plan) PlanFile {
	pf := PlanFile{
		SchemaVersion: schemaVersion,
		ExportedAt:    time.Now().UTC().Format(time.RFC3339),
		Goal:          plan.Goal,
	}

	for _, t := range plan.Tasks {
		tf := TaskFile{
			ID:               t.ID,
			Title:            t.Title,
			Description:      t.Description,
			Priority:         t.Priority,
			Status:           string(t.Status),
			Role:             string(t.Role),
			DependsOn:        t.DependsOn,
			Tags:             t.Tags,
			EstimatedMinutes: t.EstimatedMinutes,
			Assignee:         t.Assignee,
			Condition:        t.Condition,
			Recurrence:       t.Recurrence,
			RequiresApproval: t.RequiresApproval,
			MaxMinutes:       t.MaxMinutes,
			ExternalURL:      t.ExternalURL,
			Result:           t.Result,
		}
		if t.Deadline != nil {
			tf.Deadline = t.Deadline.UTC().Format(time.RFC3339)
		}
		pf.Tasks = append(pf.Tasks, tf)
	}

	return pf
}

// fileToTask converts a TaskFile into a live *pm.Task.
func fileToTask(tf TaskFile) *pm.Task {
	t := &pm.Task{
		ID:               tf.ID,
		Title:            tf.Title,
		Description:      tf.Description,
		Priority:         tf.Priority,
		Status:           pm.TaskStatus(tf.Status),
		Role:             pm.AgentRole(tf.Role),
		DependsOn:        tf.DependsOn,
		Tags:             tf.Tags,
		EstimatedMinutes: tf.EstimatedMinutes,
		Assignee:         tf.Assignee,
		Condition:        tf.Condition,
		Recurrence:       tf.Recurrence,
		RequiresApproval: tf.RequiresApproval,
		MaxMinutes:       tf.MaxMinutes,
		ExternalURL:      tf.ExternalURL,
		Result:           tf.Result,
	}
	if tf.Deadline != "" {
		if parsed, err := time.Parse(time.RFC3339, tf.Deadline); err == nil {
			t.Deadline = &parsed
		}
	}
	// Default missing status to pending so imported tasks can be executed.
	if t.Status == "" {
		t.Status = pm.TaskPending
	}
	return t
}

// validate checks required fields in the PlanFile.
func validate(pf *PlanFile) error {
	if strings.TrimSpace(pf.Goal) == "" {
		return fmt.Errorf("goal is required")
	}
	if len(pf.Tasks) == 0 {
		return fmt.Errorf("plan must contain at least one task")
	}
	seenIDs := make(map[int]bool, len(pf.Tasks))
	for i, tf := range pf.Tasks {
		if strings.TrimSpace(tf.Title) == "" {
			return fmt.Errorf("task[%d]: title is required", i)
		}
		if tf.Priority < 0 {
			return fmt.Errorf("task[%d] %q: priority must be >= 0", i, tf.Title)
		}
		if seenIDs[tf.ID] {
			return fmt.Errorf("task[%d] %q: duplicate id %d", i, tf.Title, tf.ID)
		}
		seenIDs[tf.ID] = true
	}
	return nil
}

// doReplace converts the PlanFile into a fresh pm.Plan (preserving all imported IDs).
func doReplace(pf *PlanFile) *ImportResult {
	plan := pm.NewPlan(pf.Goal)
	for _, tf := range pf.Tasks {
		plan.Tasks = append(plan.Tasks, fileToTask(tf))
	}
	return &ImportResult{Plan: plan, Replaced: len(pf.Tasks)}
}

// doMerge appends tasks from pf that are not already present in existing (matched by title).
// New tasks get IDs reassigned to avoid collision with existing ones.
func doMerge(pf *PlanFile, existing *pm.Plan) *ImportResult {
	if existing == nil {
		// No existing plan — behave like replace but keep the goal from the file.
		return doReplace(pf)
	}

	result := &ImportResult{Plan: existing}

	// Build title lookup for fast duplicate detection.
	existingTitles := make(map[string]bool, len(existing.Tasks))
	for _, t := range existing.Tasks {
		existingTitles[strings.ToLower(strings.TrimSpace(t.Title))] = true
	}

	// Find the highest existing ID so we can assign collision-free IDs.
	maxID := 0
	for _, t := range existing.Tasks {
		if t.ID > maxID {
			maxID = t.ID
		}
	}

	for _, tf := range pf.Tasks {
		key := strings.ToLower(strings.TrimSpace(tf.Title))
		if existingTitles[key] {
			result.Skipped++
			continue
		}

		maxID++
		tf.ID = maxID
		newTask := fileToTask(tf)

		// Remap depends_on IDs — they refer to the source plan so we clear them
		// rather than import potentially broken references into the merged plan.
		newTask.DependsOn = nil

		existing.Tasks = append(existing.Tasks, newTask)
		existingTitles[key] = true
		result.Added++
	}

	return result
}
