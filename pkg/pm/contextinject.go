package pm

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"
)

// sourceExtensions is the set of file extensions considered source files for
// codebase context injection. Files outside this set are skipped.
var sourceExtensions = map[string]bool{
	".go":    true,
	".ts":    true,
	".tsx":   true,
	".js":    true,
	".jsx":   true,
	".py":    true,
	".rb":    true,
	".java":  true,
	".kt":    true,
	".rs":    true,
	".c":     true,
	".cpp":   true,
	".h":     true,
	".hpp":   true,
	".cs":    true,
	".sh":    true,
	".yaml":  true,
	".yml":   true,
	".json":  true,
	".toml":  true,
	".md":    true,
	".sql":   true,
	".proto": true,
}

// ignoredDirs are directories skipped during source file collection.
var ignoredDirs = map[string]bool{
	".git":        true,
	"node_modules": true,
	"vendor":      true,
	".cloop":      true,
	"dist":        true,
	"build":       true,
	"target":      true,
	"__pycache__": true,
	".next":       true,
	".nuxt":       true,
	"coverage":    true,
}

// ciScoredFile pairs a file path with its relevance score for a given task.
type ciScoredFile struct {
	path  string
	score int
}

// CollectRelevantContext scans the working directory for files relevant to the
// given task, collects up to maxTokens worth of the most relevant snippets, and
// formats them as a fenced code block section for inclusion in a task prompt.
//
// Relevance is determined by keyword overlap between the task title/description
// and file paths, with git diff --stat used to boost recently-modified files.
// The top-N files are read and truncated to fit within the token budget.
//
// Returns an empty string when workDir is empty, no relevant files are found,
// or maxTokens is zero.
func CollectRelevantContext(workDir string, task *Task, maxTokens int) string {
	if workDir == "" || task == nil || maxTokens <= 0 {
		return ""
	}

	// Build keyword set from task title and description.
	keywords := ciExtractKeywords(task.Title + " " + task.Description)
	if len(keywords) == 0 {
		return ""
	}

	// Collect all source files under workDir.
	files := ciCollectSourceFiles(workDir)
	if len(files) == 0 {
		return ""
	}

	// Score each file by keyword overlap with its relative path.
	scored := ciScoreFiles(workDir, files, keywords)

	// Boost files touched in recent git diff --stat (best-effort).
	ciBoostFromGitDiff(workDir, scored)

	// Sort descending by score, then alphabetically for determinism.
	sort.Slice(scored, func(i, j int) bool {
		if scored[i].score != scored[j].score {
			return scored[i].score > scored[j].score
		}
		return scored[i].path < scored[j].path
	})

	// Keep only files with a positive score.
	relevant := make([]ciScoredFile, 0, len(scored))
	for _, sf := range scored {
		if sf.score > 0 {
			relevant = append(relevant, sf)
		}
	}
	if len(relevant) == 0 {
		return ""
	}

	// Reserve tokens for the section header.
	headerTokens := EstimateTokens("## Relevant codebase context\n\n")
	remaining := maxTokens - headerTokens
	if remaining <= 0 {
		return ""
	}

	var sections []string
	for _, sf := range relevant {
		if remaining <= 0 {
			break
		}
		snippet := ciReadFileSnippet(sf.path, remaining)
		if snippet == "" {
			continue
		}
		rel, err := filepath.Rel(workDir, sf.path)
		if err != nil {
			rel = sf.path
		}
		block := fmt.Sprintf("```%s\n%s\n```\n", rel, snippet)
		blockTokens := EstimateTokens(block)
		if blockTokens > remaining && len(sections) > 0 {
			// Skip files that won't fit once we already have some context.
			break
		}
		sections = append(sections, block)
		remaining -= blockTokens
	}

	if len(sections) == 0 {
		return ""
	}

	var b strings.Builder
	b.WriteString("## Relevant codebase context\n\n")
	for _, s := range sections {
		b.WriteString(s)
		b.WriteString("\n")
	}
	return b.String()
}

// ciExtractKeywords splits text into lowercase, deduplicated keywords,
// filtering out very short or common stop words.
func ciExtractKeywords(text string) []string {
	stopWords := map[string]bool{
		"the": true, "a": true, "an": true, "and": true, "or": true,
		"for": true, "to": true, "of": true, "in": true, "on": true,
		"at": true, "by": true, "is": true, "it": true, "be": true,
		"as": true, "if": true, "do": true, "no": true, "so": true,
		"we": true, "he": true, "she": true, "they": true, "this": true,
		"that": true, "with": true, "from": true, "into": true, "via": true,
		"add": true, "use": true, "new": true, "get": true, "set": true,
		"run": true, "all": true, "any": true, "not": true, "can": true,
		"task": true, "each": true, "also": true, "when": true, "will": true,
		"its": true, "has": true, "are": true, "was": true, "per": true,
	}

	// Split on non-alphanumeric characters.
	words := strings.FieldsFunc(strings.ToLower(text), func(r rune) bool {
		return !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9'))
	})

	seen := make(map[string]bool)
	result := make([]string, 0, len(words))
	for _, w := range words {
		if len(w) < 3 || stopWords[w] || seen[w] {
			continue
		}
		seen[w] = true
		result = append(result, w)
	}
	return result
}

// ciCollectSourceFiles lists source files under root using git ls-files,
// falling back to filepath.WalkDir. Skips ignoredDirs and non-source files.
func ciCollectSourceFiles(root string) []string {
	var files []string

	// Use git ls-files for speed in git repos.
	out, err := exec.Command("git", "-C", root, "ls-files", "--cached", "--others", "--exclude-standard").Output()
	if err == nil {
		for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			// Skip files inside ignored dirs.
			parts := strings.Split(line, "/")
			skip := false
			for _, p := range parts[:len(parts)-1] {
				if ignoredDirs[p] {
					skip = true
					break
				}
			}
			if skip {
				continue
			}
			ext := strings.ToLower(filepath.Ext(line))
			if !sourceExtensions[ext] {
				continue
			}
			files = append(files, filepath.Join(root, line))
		}
		return files
	}

	// Fallback: manual walk.
	filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if ignoredDirs[filepath.Base(path)] {
				return filepath.SkipDir
			}
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if sourceExtensions[ext] {
			files = append(files, path)
		}
		return nil
	})
	return files
}

// ciScoreFiles scores each file by keyword overlap with its relative path.
func ciScoreFiles(workDir string, files []string, keywords []string) []ciScoredFile {
	scored := make([]ciScoredFile, 0, len(files))
	for _, f := range files {
		rel, err := filepath.Rel(workDir, f)
		if err != nil {
			rel = f
		}
		normalized := strings.ToLower(filepath.ToSlash(rel))
		score := 0
		for _, kw := range keywords {
			if strings.Contains(normalized, kw) {
				score++
			}
		}
		scored = append(scored, ciScoredFile{path: f, score: score})
	}
	return scored
}

// ciBoostFromGitDiff runs git diff --stat HEAD and increments scores for files
// appearing in the diff output. Errors are silently ignored.
func ciBoostFromGitDiff(workDir string, scored []ciScoredFile) {
	out, err := exec.Command("git", "-C", workDir, "diff", "--stat", "HEAD").Output()
	if err != nil {
		return
	}
	diffFiles := make(map[string]bool)
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// Lines look like: "pkg/foo/bar.go | 12 ++-"
		parts := strings.Split(line, "|")
		if len(parts) < 2 {
			continue
		}
		diffFiles[strings.TrimSpace(parts[0])] = true
	}
	if len(diffFiles) == 0 {
		return
	}
	for i := range scored {
		rel, err := filepath.Rel(workDir, scored[i].path)
		if err != nil {
			continue
		}
		if diffFiles[filepath.ToSlash(rel)] {
			scored[i].score += 2
		}
	}
}

// ciReadFileSnippet reads up to budgetTokens tokens from path,
// truncating at a clean newline boundary.
func ciReadFileSnippet(path string, budgetTokens int) string {
	// Limit raw bytes to budgetTokens*4 (conservative token estimate).
	maxBytes := budgetTokens * 4
	if maxBytes > 64*1024 {
		maxBytes = 64 * 1024
	}

	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()

	data := make([]byte, maxBytes)
	n, _ := f.Read(data)
	if n == 0 {
		return ""
	}
	content := data[:n]

	// Ensure valid UTF-8 by trimming trailing incomplete rune.
	for !utf8.Valid(content) && len(content) > 0 {
		content = content[:len(content)-1]
	}

	text := string(content)

	// Trim to token budget by dropping trailing lines.
	for EstimateTokens(text) > budgetTokens && len(text) > 0 {
		idx := strings.LastIndexByte(text[:len(text)-1], '\n')
		if idx < 0 {
			break
		}
		text = text[:idx]
	}

	return strings.TrimRight(text, "\n")
}
