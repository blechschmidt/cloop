// Package mergeresolve provides AI-driven automatic resolution of git merge
// conflicts produced by the mergequeue when two parallel task branches both
// touch the same lines of a file.
//
// The resolver implements the mergequeue.Resolver interface and is wired in
// from the orchestrator when worktree-parallel mode is enabled and a provider
// is available. When the merge queue encounters a conflict it hands the
// resolver the list of conflicted files (with conflict markers intact) and
// expects back the resolved content for each. The queue then writes the files,
// stages them, and finishes the merge commit — fully automating what would
// otherwise be a manual operation.
//
// The resolver is intentionally conservative:
//
//   - It only resolves files git reports as "both modified" (status code UU).
//     "Add/add", "delete/modify", and rename conflicts are left for human
//     attention because they involve structural decisions an LLM should not
//     silently make.
//   - It refuses to "resolve" a file if the AI's output still contains
//     conflict markers (<<<<<<<, =======, >>>>>>>) — that's a sign the model
//     gave up and we'd commit broken code.
//   - Each file is bounded by MaxFileBytes so a single huge generated file
//     can't blow up the prompt or the merge commit.
//   - On any error the caller (mergequeue) falls back to `git merge --abort`,
//     so the existing manual-resolution path is preserved.
package mergeresolve

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/mergequeue"
	"github.com/blechschmidt/cloop/pkg/provider"
)

// MaxFileBytes bounds the size of any single conflicted file the resolver will
// hand to the AI. Larger files are skipped (the merge is aborted as if no
// resolver were configured) because they would dominate the prompt and the
// LLM's chance of producing a correct unified resolution falls sharply.
const MaxFileBytes = 64 * 1024

// DefaultTimeout is the per-file timeout for the provider call when the
// caller does not specify one explicitly. Each conflicted file is resolved in
// its own provider call so this bounds the slowest file, not the whole merge.
const DefaultTimeout = 90 * time.Second

// Resolver uses an AI provider to resolve git merge conflicts.
//
// Construct with New(provider, model) and pass into mergequeue.Queue via
// SetResolver. Safe for concurrent calls.
type Resolver struct {
	provider provider.Provider
	model    string
	timeout  time.Duration
}

// New returns a Resolver that delegates to the given provider/model. model
// may be empty in which case the provider's DefaultModel is used by the
// callee. timeout may be zero in which case DefaultTimeout is used per file.
func New(p provider.Provider, model string, timeout time.Duration) *Resolver {
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	return &Resolver{provider: p, model: model, timeout: timeout}
}

// Resolve handles a batch of conflicted files. For every file it returns a
// ResolvedFile whose Content is free of conflict markers. Implements the
// mergequeue.Resolver interface.
//
// Files that exceed MaxFileBytes or that the AI cannot resolve cleanly are
// omitted from the result so the caller (mergequeue.Queue) sees a partial
// answer and falls back to `git merge --abort`. This conservative behaviour
// preserves the existing manual-resolution path whenever auto-resolve isn't
// confident.
func (r *Resolver) Resolve(ctx context.Context, info mergequeue.ResolveInfo, files []mergequeue.ConflictFile) ([]mergequeue.ResolvedFile, error) {
	if r == nil {
		return nil, errors.New("mergeresolve: nil resolver")
	}
	if r.provider == nil {
		return nil, errors.New("mergeresolve: nil provider")
	}
	if len(files) == 0 {
		return nil, nil
	}
	out := make([]mergequeue.ResolvedFile, 0, len(files))
	var lastErr error
	for _, f := range files {
		if len(f.Content) > MaxFileBytes {
			lastErr = fmt.Errorf("file %q exceeds %d bytes — skipped", f.Path, MaxFileBytes)
			continue
		}
		resolved, err := r.resolveOne(ctx, info, f)
		if err != nil {
			lastErr = err
			continue
		}
		out = append(out, mergequeue.ResolvedFile{Path: f.Path, Content: resolved})
	}
	if len(out) == 0 && lastErr != nil {
		return nil, lastErr
	}
	return out, nil
}

// resolveOne builds a focused prompt for a single file and asks the provider
// for a fully-merged version. It rejects an answer that still contains
// conflict markers, since that would propagate a broken state into the
// commit.
func (r *Resolver) resolveOne(ctx context.Context, c mergequeue.ResolveInfo, f mergequeue.ConflictFile) (string, error) {
	prompt := buildPrompt(c, f)
	opts := provider.Options{
		Model:        r.model,
		Timeout:      r.timeout,
		SystemPrompt: systemPrompt,
		MaxTokens:    8000,
	}
	res, err := r.provider.Complete(ctx, prompt, opts)
	if err != nil {
		return "", fmt.Errorf("mergeresolve %q: provider: %w", f.Path, err)
	}
	resolved := extractCodeBlock(res.Output)
	if resolved == "" {
		return "", fmt.Errorf("mergeresolve %q: empty AI output", f.Path)
	}
	if hasConflictMarkers(resolved) {
		return "", fmt.Errorf("mergeresolve %q: AI output still contains conflict markers", f.Path)
	}
	return resolved, nil
}

const systemPrompt = `You are an expert software engineer resolving a git merge conflict.
The user will show you a single source file containing conflict markers
(<<<<<<<, =======, >>>>>>>) plus context about which branches are merging.

Your task: produce the fully-merged version of the file. Rules:

1. Output ONLY the resolved file content, with no commentary, no diff, no
   explanation, and absolutely no remaining conflict markers.
2. Wrap the resolved content in a single fenced code block (triple
   backticks). The language hint is optional.
3. Preserve the file's existing style, indentation, and trailing newline.
4. When both sides made compatible changes, combine them. When they made
   incompatible changes, prefer the change that fulfils the incoming task's
   intent unless that would obviously break the base branch.
5. Never delete code that wasn't part of the conflict region.
6. If you genuinely cannot resolve the conflict, output an empty code block.`

func buildPrompt(c mergequeue.ResolveInfo, f mergequeue.ConflictFile) string {
	var b strings.Builder
	b.WriteString("Merge conflict to resolve.\n\n")
	if c.BaseBranch != "" {
		fmt.Fprintf(&b, "Base branch: %s\n", c.BaseBranch)
	}
	if c.SourceBranch != "" {
		fmt.Fprintf(&b, "Source branch (being merged in): %s\n", c.SourceBranch)
	}
	if c.TaskID != 0 {
		fmt.Fprintf(&b, "cloop task ID: %d\n", c.TaskID)
	}
	if strings.TrimSpace(c.TaskTitle) != "" {
		fmt.Fprintf(&b, "Task title: %s\n", strings.TrimSpace(c.TaskTitle))
	}
	fmt.Fprintf(&b, "\nFile: %s\n", f.Path)
	b.WriteString("Current contents (with conflict markers):\n\n")
	b.WriteString("```\n")
	b.WriteString(f.Content)
	if !strings.HasSuffix(f.Content, "\n") {
		b.WriteString("\n")
	}
	b.WriteString("```\n\n")
	b.WriteString("Return the fully-merged file inside a single fenced code block.")
	return b.String()
}

// extractCodeBlock returns the content of the first fenced code block in s.
// When no fenced block is found it returns s trimmed of whitespace — some
// smaller models occasionally omit the fence even when asked. An empty fenced
// block (the model's way to say "I can't resolve") returns "".
func extractCodeBlock(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	start := strings.Index(s, "```")
	if start < 0 {
		// No fence — treat the whole response as code. This is best-effort;
		// hasConflictMarkers will catch obvious garbage downstream.
		return s
	}
	// Skip the opening fence line (which may include a language hint).
	rest := s[start+3:]
	nl := strings.IndexByte(rest, '\n')
	if nl < 0 {
		return ""
	}
	rest = rest[nl+1:]
	end := strings.Index(rest, "```")
	if end < 0 {
		// Unterminated fence; take what we have.
		return strings.TrimRight(rest, "\n") + "\n"
	}
	body := rest[:end]
	if strings.TrimSpace(body) == "" {
		// Empty fence — explicit "give up" signal from the prompt rules.
		return ""
	}
	// Ensure a trailing newline so the merged file matches POSIX text-file
	// convention git's index expects.
	if !strings.HasSuffix(body, "\n") {
		body += "\n"
	}
	return body
}

// hasConflictMarkers reports whether s still contains any of the standard git
// conflict markers. We check at start-of-line because the strings can legally
// appear elsewhere (e.g. in documentation about merge conflicts).
func hasConflictMarkers(s string) bool {
	for _, line := range strings.Split(s, "\n") {
		switch {
		case strings.HasPrefix(line, "<<<<<<< "),
			line == "=======",
			strings.HasPrefix(line, ">>>>>>> "):
			return true
		}
	}
	return false
}
