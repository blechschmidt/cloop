// Package filewatch monitors file/directory patterns and triggers plan re-evaluation
// when watched files change. Designed for TDD-style AI loops where code changes
// should drive plan updates.
package filewatch

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/fatih/color"
	"github.com/fsnotify/fsnotify"
)

// Config holds file-watch configuration.
type Config struct {
	// WorkDir is the project root.
	WorkDir string
	// Globs are file patterns to watch (e.g. "**/*.go", "src/**/*.ts").
	Globs []string
	// Debounce is the duration to wait after the last change before triggering.
	Debounce time.Duration
}

// ChangeEvent describes a batch of file changes that triggered re-evaluation.
type ChangeEvent struct {
	// Files is the list of changed file paths (relative to WorkDir).
	Files []string
	// ResetTaskIDs are the task IDs that were reset to pending.
	ResetTaskIDs []int
	// Context is a human-readable description of what changed.
	Context string
}

// Run starts the file watcher. It blocks until ctx is cancelled.
// onTrigger is called after each debounced batch of changes once the state
// has been updated (relevant tasks reset to pending).
func Run(ctx context.Context, cfg Config, onTrigger func(ChangeEvent)) error {
	if len(cfg.Globs) == 0 {
		return fmt.Errorf("no glob patterns specified")
	}
	if cfg.Debounce <= 0 {
		cfg.Debounce = 2 * time.Second
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("creating watcher: %w", err)
	}
	defer watcher.Close()

	dirs, err := resolveWatchDirs(cfg.WorkDir, cfg.Globs)
	if err != nil {
		return fmt.Errorf("resolving watch paths: %w", err)
	}
	if len(dirs) == 0 {
		return fmt.Errorf("no directories found matching the given patterns")
	}

	for dir := range dirs {
		if err := watcher.Add(dir); err != nil {
			return fmt.Errorf("watching %s: %w", dir, err)
		}
	}

	dim := color.New(color.Faint)
	cyan := color.New(color.FgCyan)
	cyan.Printf("cloop watch: monitoring %d director(ies) for patterns: %s\n",
		len(dirs), strings.Join(cfg.Globs, ", "))
	dim.Printf("  debounce: %s — press Ctrl+C to stop\n\n", cfg.Debounce)

	// pending accumulates changed files until the debounce timer fires.
	pending := map[string]struct{}{}
	var debounceTimer *time.Timer

	fireTrigger := func() {
		if len(pending) == 0 {
			return
		}
		files := make([]string, 0, len(pending))
		for f := range pending {
			files = append(files, f)
		}
		for k := range pending {
			delete(pending, k)
		}

		evt, err := applyReEvaluation(cfg.WorkDir, files)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[watch] state update failed: %v\n", err)
			return
		}
		onTrigger(evt)
	}

	for {
		select {
		case <-ctx.Done():
			if debounceTimer != nil {
				debounceTimer.Stop()
			}
			return nil

		case err, ok := <-watcher.Errors:
			if !ok {
				return nil
			}
			fmt.Fprintf(os.Stderr, "[watch] watcher error: %v\n", err)

		case event, ok := <-watcher.Events:
			if !ok {
				return nil
			}
			if event.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Rename) == 0 {
				continue
			}
			rel, err := filepath.Rel(cfg.WorkDir, event.Name)
			if err != nil {
				rel = event.Name
			}
			// Skip .cloop internals to avoid feedback loops.
			if strings.HasPrefix(rel, ".cloop") {
				continue
			}
			if !matchesAnyGlob(rel, cfg.Globs) {
				continue
			}

			pending[rel] = struct{}{}

			if debounceTimer != nil {
				debounceTimer.Stop()
			}
			debounceTimer = time.AfterFunc(cfg.Debounce, fireTrigger)
		}
	}
}

// applyReEvaluation loads the current state, resets relevant tasks to pending,
// adds a watch-trigger context note, and saves state.
func applyReEvaluation(workDir string, changedFiles []string) (ChangeEvent, error) {
	evt := ChangeEvent{Files: changedFiles}

	s, err := state.Load(workDir)
	if err != nil {
		return evt, fmt.Errorf("loading state: %w", err)
	}

	if !s.PMMode || s.Plan == nil {
		evt.Context = fmt.Sprintf("files changed: %s (no active PM plan — run with --pm to enable)", strings.Join(changedFiles, ", "))
		return evt, nil
	}

	resetIDs := resetRelevantTasks(s.Plan, changedFiles)
	evt.ResetTaskIDs = resetIDs
	evt.Context = buildChangeContext(changedFiles, resetIDs, s.Plan)

	// Annotate each reset task with the change context so the AI has it on re-run.
	if len(resetIDs) > 0 {
		for _, t := range s.Plan.Tasks {
			for _, id := range resetIDs {
				if t.ID == id {
					note := fmt.Sprintf("[watch trigger] %s", evt.Context)
					if t.FailureDiagnosis != "" {
						t.FailureDiagnosis = note + "\n\nPrevious context:\n" + t.FailureDiagnosis
					} else {
						t.FailureDiagnosis = note
					}
				}
			}
		}
	}

	if err := s.Save(); err != nil {
		return evt, fmt.Errorf("saving state: %w", err)
	}

	return evt, nil
}

// resetRelevantTasks resets tasks to pending based on relevance to changed files.
// Relevance rules:
//  1. Status is failed or in_progress → always reset.
//  2. A changed file's stem (basename without extension) appears in the task title/description.
func resetRelevantTasks(plan *pm.Plan, changedFiles []string) []int {
	stems := make([]string, 0, len(changedFiles))
	for _, f := range changedFiles {
		base := strings.ToLower(filepath.Base(f))
		if idx := strings.LastIndex(base, "."); idx > 0 {
			base = base[:idx]
		}
		stems = append(stems, base)
	}

	var resetIDs []int
	for _, t := range plan.Tasks {
		switch t.Status {
		case pm.TaskFailed, pm.TaskInProgress:
			t.Status = pm.TaskPending
			t.StartedAt = nil
			resetIDs = append(resetIDs, t.ID)
		case pm.TaskDone, pm.TaskSkipped:
			if taskRelatedToFiles(t, stems, changedFiles) {
				t.Status = pm.TaskPending
				t.StartedAt = nil
				resetIDs = append(resetIDs, t.ID)
			}
		}
	}
	return resetIDs
}

// taskRelatedToFiles returns true if any file stem or path component appears
// in the task's title or description (case-insensitive).
func taskRelatedToFiles(t *pm.Task, stems []string, changedFiles []string) bool {
	haystack := strings.ToLower(t.Title + " " + t.Description)
	for _, stem := range stems {
		if len(stem) > 2 && strings.Contains(haystack, stem) {
			return true
		}
	}
	for _, f := range changedFiles {
		parts := strings.FieldsFunc(strings.ToLower(f), func(r rune) bool {
			return r == '/' || r == '\\'
		})
		for _, part := range parts {
			p := strings.TrimSuffix(part, filepath.Ext(part))
			if len(p) > 2 && strings.Contains(haystack, p) {
				return true
			}
		}
	}
	return false
}

// buildChangeContext returns a human-readable summary of what changed and which tasks were reset.
func buildChangeContext(changedFiles []string, resetIDs []int, plan *pm.Plan) string {
	sb := &strings.Builder{}
	fmt.Fprintf(sb, "File change: %s", strings.Join(changedFiles, ", "))
	if len(resetIDs) > 0 {
		titles := make([]string, 0, len(resetIDs))
		for _, id := range resetIDs {
			for _, t := range plan.Tasks {
				if t.ID == id {
					titles = append(titles, fmt.Sprintf("#%d %s", t.ID, t.Title))
					break
				}
			}
		}
		fmt.Fprintf(sb, " → reset tasks: %s", strings.Join(titles, "; "))
	}
	return sb.String()
}

// PrintEvent prints a colored summary of a ChangeEvent to stdout.
func PrintEvent(evt ChangeEvent) {
	cyan := color.New(color.FgCyan, color.Bold)
	bold := color.New(color.Bold)
	yellow := color.New(color.FgYellow)
	dim := color.New(color.Faint)

	now := time.Now().Format("15:04:05")
	cyan.Printf("[%s] File change detected\n", now)

	bold.Printf("Changed:\n")
	for _, f := range evt.Files {
		dim.Printf("  • %s\n", f)
	}

	if len(evt.ResetTaskIDs) > 0 {
		yellow.Printf("Reset %d task(s) to pending: IDs %v\n", len(evt.ResetTaskIDs), evt.ResetTaskIDs)
	} else {
		dim.Printf("No tasks reset (no relevant tasks found or no active plan)\n")
	}

	if evt.Context != "" {
		dim.Printf("Context: %s\n", evt.Context)
	}
}

// resolveWatchDirs finds all directories under workDir containing files that
// match any glob. Returns a set of absolute directory paths.
func resolveWatchDirs(workDir string, globs []string) (map[string]struct{}, error) {
	dirs := map[string]struct{}{
		workDir: {},
	}

	err := filepath.WalkDir(workDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			name := d.Name()
			if name != "." && (strings.HasPrefix(name, ".") || name == "vendor" || name == "node_modules") {
				return filepath.SkipDir
			}
			return nil
		}

		rel, err := filepath.Rel(workDir, path)
		if err != nil {
			return nil
		}
		if matchesAnyGlob(rel, globs) {
			dirs[filepath.Dir(path)] = struct{}{}
		}
		return nil
	})
	return dirs, err
}

// matchesAnyGlob reports whether relPath matches any of the provided glob patterns.
func matchesAnyGlob(relPath string, globs []string) bool {
	for _, g := range globs {
		if matchGlob(g, relPath) {
			return true
		}
	}
	return false
}

// matchGlob implements double-star glob matching.
// Patterns without "**" are delegated to filepath.Match.
// "**/*.go" matches any .go file at any depth.
// "src/**/*.go" matches any .go file under src/ at any depth.
func matchGlob(pattern, path string) bool {
	path = filepath.ToSlash(path)

	if !strings.Contains(pattern, "**") {
		ok, _ := filepath.Match(pattern, path)
		if !ok {
			ok, _ = filepath.Match(pattern, filepath.Base(path))
		}
		return ok
	}

	// Double-star: split on "**/" and check:
	//   prefix — must match the start of the path (if non-empty)
	//   suffix — must match a suffix of the path
	parts := strings.SplitN(pattern, "**/", 2)
	if len(parts) != 2 {
		return false
	}
	prefix := parts[0] // e.g. "src/" or ""
	suffix := parts[1] // e.g. "*.go"

	segments := strings.Split(path, "/")
	for i := range segments {
		sub := strings.Join(segments[i:], "/")
		ok, _ := filepath.Match(suffix, sub)
		if !ok {
			continue
		}
		// If there is a required prefix, verify it matches the path up to this point.
		if prefix == "" {
			return true
		}
		pathPrefix := strings.Join(segments[:i], "/")
		if pathPrefix != "" {
			pathPrefix += "/"
		}
		if prefixOK, _ := filepath.Match(prefix, pathPrefix); prefixOK {
			return true
		}
		// Also check if the path starts with the literal prefix.
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}
