// Package scaffold implements AI-powered project scaffolding from a cloop plan.
// It reads the active plan's goal and task list, asks the AI to generate a
// complete project skeleton (directory tree, stub files, config templates, README),
// and writes the result to the target output directory.
package scaffold

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
)

// ScaffoldFile represents a single file to be written.
type ScaffoldFile struct {
	Path    string `json:"path"`
	Content string `json:"content"`
}

// ScaffoldPlan is the manifest returned by the AI describing the project skeleton.
type ScaffoldPlan struct {
	Dirs  []string       `json:"dirs"`
	Files []ScaffoldFile `json:"files"`
}

// scaffoldPrompt builds the AI prompt from the active plan.
func scaffoldPrompt(plan *pm.Plan) string {
	var sb strings.Builder

	sb.WriteString("You are a project scaffolding assistant. Based on the project goal and task list below, generate a complete project skeleton.\n\n")
	sb.WriteString("PROJECT GOAL:\n")
	sb.WriteString(plan.Goal)
	sb.WriteString("\n\n")

	sb.WriteString("TASKS:\n")
	for _, t := range plan.Tasks {
		sb.WriteString(fmt.Sprintf("- [%d] %s\n", t.ID, t.Title))
		if t.Description != "" {
			sb.WriteString(fmt.Sprintf("      %s\n", t.Description))
		}
	}
	sb.WriteString("\n")

	sb.WriteString(`Generate a JSON scaffold manifest with the following structure:
{
  "dirs": ["list", "of", "directories", "to", "create"],
  "files": [
    {"path": "relative/path/to/file.ext", "content": "full file content as string"}
  ]
}

Requirements:
- Include all necessary directories (e.g. src/, tests/, docs/, config/)
- Include stub source files with minimal but working placeholder code
- Include a README.md at the root with project overview, setup instructions, and task summary
- Include relevant config templates (e.g. .gitignore, Makefile, docker-compose.yml, CI workflow) as appropriate
- File paths must be relative (no leading slash)
- Paths in "dirs" should also appear as prefixes to files in "files" where applicable
- Do NOT include binary files
- Respond with ONLY the JSON object, no markdown fences, no explanation

`)

	return sb.String()
}

// extractJSON attempts to find and extract the JSON object from raw AI output,
// handling cases where the model wraps it in markdown code fences.
func extractJSON(raw string) string {
	raw = strings.TrimSpace(raw)

	// Strip markdown code fences if present
	if idx := strings.Index(raw, "```json"); idx >= 0 {
		raw = raw[idx+7:]
	} else if idx := strings.Index(raw, "```"); idx >= 0 {
		raw = raw[idx+3:]
	}
	if idx := strings.Index(raw, "```"); idx >= 0 {
		raw = raw[:idx]
	}

	raw = strings.TrimSpace(raw)

	// Find the outermost JSON object bounds
	start := strings.Index(raw, "{")
	end := strings.LastIndex(raw, "}")
	if start >= 0 && end > start {
		return raw[start : end+1]
	}
	return raw
}

// Generate calls the AI provider to produce a ScaffoldPlan, then writes all
// directories and files to outputDir (unless dryRun is true, in which case it
// only returns the plan without writing anything).
func Generate(ctx context.Context, prov provider.Provider, model string, plan *pm.Plan, outputDir string, dryRun bool) (*ScaffoldPlan, error) {
	prompt := scaffoldPrompt(plan)

	opts := provider.Options{
		Model:   model,
		Timeout: 3 * time.Minute,
	}

	result, err := prov.Complete(ctx, prompt, opts)
	if err != nil {
		return nil, fmt.Errorf("AI completion failed: %w", err)
	}

	jsonStr := extractJSON(result.Output)

	var sp ScaffoldPlan
	if err := json.Unmarshal([]byte(jsonStr), &sp); err != nil {
		return nil, fmt.Errorf("parsing scaffold manifest: %w\n\nRaw output:\n%s", err, result.Output)
	}

	if dryRun {
		return &sp, nil
	}

	// Write directories
	for _, dir := range sp.Dirs {
		fullPath := filepath.Join(outputDir, filepath.FromSlash(dir))
		if err := os.MkdirAll(fullPath, 0o755); err != nil {
			return nil, fmt.Errorf("creating directory %s: %w", dir, err)
		}
	}

	// Write files
	for _, f := range sp.Files {
		fullPath := filepath.Join(outputDir, filepath.FromSlash(f.Path))
		// Ensure parent directory exists
		if err := os.MkdirAll(filepath.Dir(fullPath), 0o755); err != nil {
			return nil, fmt.Errorf("creating parent dir for %s: %w", f.Path, err)
		}
		if err := os.WriteFile(fullPath, []byte(f.Content), 0o644); err != nil {
			return nil, fmt.Errorf("writing file %s: %w", f.Path, err)
		}
	}

	return &sp, nil
}
