// Package artifact persists the full AI response for each PM task as a
// human-readable Markdown file with YAML frontmatter under .cloop/tasks/.
// It also stores shell verification scripts and their results.
package artifact

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/atomicfile"
	"github.com/blechschmidt/cloop/pkg/boundedread"
	"github.com/blechschmidt/cloop/pkg/pm"
)

// WriteExecArtifact persists the output of a 'cloop task exec' run under
// .cloop/tasks/<id>-<slug>-exec-<ts>.md.
// Returns the relative path (relative to workDir) of the artifact file.
func WriteExecArtifact(workDir string, task *pm.Task, cmdArgs []string, exitCode int, elapsed time.Duration, output string) (string, error) {
	dir := filepath.Join(workDir, ".cloop", "tasks")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("create artifact dir: %w", err)
	}

	s := slug(task.Title, 40)
	ts := time.Now().UTC().Format("20060102-150405")
	filename := fmt.Sprintf("%d-%s-exec-%s.md", task.ID, s, ts)
	absPath := filepath.Join(dir, filename)

	var b strings.Builder

	b.WriteString("---\n")
	b.WriteString(fmt.Sprintf("id: %d\n", task.ID))
	b.WriteString(fmt.Sprintf("title: %q\n", task.Title))
	b.WriteString(fmt.Sprintf("status: %s\n", task.Status))
	b.WriteString(fmt.Sprintf("event: exec\n"))
	b.WriteString(fmt.Sprintf("command: %q\n", strings.Join(cmdArgs, " ")))
	b.WriteString(fmt.Sprintf("exit_code: %d\n", exitCode))
	b.WriteString(fmt.Sprintf("elapsed: %s\n", elapsed.Round(time.Millisecond)))
	b.WriteString(fmt.Sprintf("recorded_at: %s\n", ts))
	b.WriteString("---\n\n")

	b.WriteString(fmt.Sprintf("## Command\n\n```\n%s\n```\n\n", strings.Join(cmdArgs, " ")))
	b.WriteString(fmt.Sprintf("**Exit code:** %d | **Elapsed:** %s\n\n", exitCode, elapsed.Round(time.Millisecond)))

	b.WriteString("## Output\n\n```\n")
	if output != "" {
		b.WriteString(output)
		if !strings.HasSuffix(output, "\n") {
			b.WriteByte('\n')
		}
	} else {
		b.WriteString("(no output)\n")
	}
	b.WriteString("```\n")

	if err := atomicfile.Write(absPath, []byte(b.String()), 0o644); err != nil {
		return "", fmt.Errorf("write exec artifact: %w", err)
	}

	rel, err := filepath.Rel(workDir, absPath)
	if err != nil {
		rel = absPath
	}
	return rel, nil
}

var nonSlugRe = regexp.MustCompile(`[^a-z0-9-]+`)

// MaxReadBytes is the cap applied to every read of a task artifact. It is the
// shared constant described in boundedread; see there for why artifacts need
// one despite not being attacker-controlled.
const MaxReadBytes = boundedread.ArtifactMaxBytes

// resolveArtifactPath makes an artifact path absolute. Paths are stored
// relative to the project directory (see WriteTaskArtifact), but callers
// occasionally hold an absolute one already.
func resolveArtifactPath(workDir, artifactPath string) string {
	if filepath.IsAbs(artifactPath) {
		return artifactPath
	}
	return filepath.Join(workDir, artifactPath)
}

// ReadArtifactTail reads at most MaxReadBytes from the end of a task artifact.
//
// This is the right default for anything that wants to know how a task turned
// out — context injection into the next task, evaluation, summarization —
// because an agent's conclusion, its completion signal and any failure it hit
// are all at the end of its transcript. total is the artifact's full size on
// disk, so callers can say how much they did not read.
func ReadArtifactTail(workDir, artifactPath string) (data []byte, truncated bool, total int64, err error) {
	abs := resolveArtifactPath(workDir, artifactPath)
	info, err := os.Stat(abs)
	if err != nil {
		return nil, false, 0, err
	}
	data, truncated, err = boundedread.ReadFileTail(abs, MaxReadBytes)
	if err != nil {
		return nil, false, 0, err
	}
	return data, truncated, info.Size(), nil
}

// ReadArtifactHead reads at most MaxReadBytes from the start of a task
// artifact. Prefer ReadArtifactTail unless the caller genuinely wants the
// beginning — a browsable detail pane that renders the first N lines, for
// instance, where the reader scrolls from the top.
func ReadArtifactHead(workDir, artifactPath string) (data []byte, truncated bool, total int64, err error) {
	abs := resolveArtifactPath(workDir, artifactPath)
	info, err := os.Stat(abs)
	if err != nil {
		return nil, false, 0, err
	}
	data, truncated, err = boundedread.ReadFileTruncated(abs, MaxReadBytes)
	if err != nil {
		return nil, false, 0, err
	}
	return data, truncated, info.Size(), nil
}

// ReadLiveArtifactTail reads at most MaxReadBytes from the end of a task's
// live streaming output file.
//
// Live artifacts are the riskiest of the lot: they are the log of a task that
// is running right now, so they are the ones actually growing while something
// reads them. Always tail-biased — a live log is read to find out where the
// task has got to, which is by definition its last line.
func ReadLiveArtifactTail(workDir string, taskID int) (data []byte, truncated bool, total int64, err error) {
	return ReadArtifactTail(workDir, LiveArtifactPath(workDir, taskID))
}

// TailTruncationNotice is the marker to prepend to a tail-biased read that hit
// the cap. It goes at the top because that is where the omission is: the
// reader is about to see the end of a much longer log.
//
// Truncation must always be stated. A summarizer that silently receives 16 MiB
// of a 2 GB log reports confidently on a fraction of the work; one that is
// told the log was cut can qualify what it says.
func TailTruncationNotice(total int64) string {
	return fmt.Sprintf("[truncated: artifact is %s; only the final %s is shown — earlier output was not read]\n\n",
		HumanBytes(total), HumanBytes(MaxReadBytes))
}

// HeadTruncationNotice is the marker to append to a head-biased read that hit
// the cap. It goes at the bottom, where the content stops.
func HeadTruncationNotice(total int64) string {
	return fmt.Sprintf("[truncated: artifact is %s; only the first %s was read — later output, including the task outcome, is not shown]",
		HumanBytes(total), HumanBytes(MaxReadBytes))
}

// HumanBytes renders a byte count for a human reading a log line or a prompt.
// Exported so callers that impose their own, tighter budget on top of the read
// cap can describe it in the same units.
func HumanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for v := n / unit; v >= unit && exp < 4; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTP"[exp])
}

// ReadTaskOutput reads the AI output for a completed task.
// If task.ArtifactPath is set and readable, it returns the artifact body with
// YAML frontmatter stripped.  Falls back to task.Result if the file is missing.
// Returns empty string when neither source is available.
//
// The read is bounded at MaxReadBytes and biased to the tail, because every
// caller of this function wants the outcome: chained task input, acceptance
// checks, post-task evaluation, replay comparison and the task detail panel.
// When the cap is hit the returned string opens with TailTruncationNotice so
// no consumer mistakes the surviving tail for the whole transcript.
func ReadTaskOutput(workDir string, task *pm.Task) string {
	if task.ArtifactPath != "" {
		data, truncated, total, err := ReadArtifactTail(workDir, task.ArtifactPath)
		if err == nil {
			if truncated {
				// Frontmatter lives at the head, which by definition was not
				// read, so there is nothing to strip off a truncated tail.
				return TailTruncationNotice(total) + string(data)
			}
			return stripFrontmatter(string(data))
		}
	}
	return task.Result
}

// stripFrontmatter removes YAML frontmatter (--- ... ---\n) from the start of s.
func stripFrontmatter(s string) string {
	if len(s) < 4 || s[:3] != "---" {
		return s
	}
	rest := s[3:]
	idx := strings.Index(rest, "\n---")
	if idx < 0 {
		return s
	}
	body := rest[idx+4:]
	body = strings.TrimLeft(body, "\n")
	return body
}

// LiveArtifactDir returns the directory where live streaming artifacts are written.
func LiveArtifactDir(workDir string) string {
	return filepath.Join(workDir, ".cloop", "artifacts")
}

// LiveArtifactPath returns the canonical path for the live streaming output file
// for the given task ID. The file is written incrementally during execution.
func LiveArtifactPath(workDir string, taskID int) string {
	return filepath.Join(LiveArtifactDir(workDir), fmt.Sprintf("%d_output.txt", taskID))
}

// OpenLiveArtifact creates (or truncates) the live streaming output file for a
// task and returns the open file handle. The caller is responsible for closing it.
// Errors are non-fatal; the caller should treat nil as "no live artifact".
func OpenLiveArtifact(workDir string, taskID int) (*os.File, error) {
	dir := LiveArtifactDir(workDir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("create artifact dir: %w", err)
	}
	return os.OpenFile(LiveArtifactPath(workDir, taskID), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
}

// slug converts a task title into a URL-safe, lowercase, hyphen-separated
// string truncated to maxLen characters.
func slug(title string, maxLen int) string {
	s := strings.ToLower(title)
	s = strings.ReplaceAll(s, " ", "-")
	s = nonSlugRe.ReplaceAllString(s, "")
	// Collapse consecutive hyphens.
	for strings.Contains(s, "--") {
		s = strings.ReplaceAll(s, "--", "-")
	}
	s = strings.Trim(s, "-")
	if len(s) > maxLen {
		s = s[:maxLen]
		s = strings.TrimRight(s, "-")
	}
	return s
}

// WriteTaskArtifact writes the full AI response for a completed task to
// .cloop/tasks/<id>-<slug>.md with YAML frontmatter.
// Returns the relative path (relative to workDir) of the artifact file.
func WriteTaskArtifact(workDir string, task *pm.Task, fullOutput string) (string, error) {
	dir := filepath.Join(workDir, ".cloop", "tasks")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("create artifact dir: %w", err)
	}

	s := slug(task.Title, 40)
	filename := fmt.Sprintf("%d-%s.md", task.ID, s)
	absPath := filepath.Join(dir, filename)

	var b strings.Builder

	// YAML frontmatter
	b.WriteString("---\n")
	b.WriteString(fmt.Sprintf("id: %d\n", task.ID))
	b.WriteString(fmt.Sprintf("title: %q\n", task.Title))
	b.WriteString(fmt.Sprintf("status: %s\n", task.Status))
	if task.Role != "" {
		b.WriteString(fmt.Sprintf("role: %s\n", task.Role))
	}
	if task.StartedAt != nil {
		b.WriteString(fmt.Sprintf("started_at: %s\n", task.StartedAt.UTC().Format(time.RFC3339)))
	}
	if task.CompletedAt != nil {
		b.WriteString(fmt.Sprintf("finished_at: %s\n", task.CompletedAt.UTC().Format(time.RFC3339)))
	}
	if task.EstimatedMinutes > 0 {
		b.WriteString(fmt.Sprintf("estimated_minutes: %d\n", task.EstimatedMinutes))
	}
	if task.ActualMinutes > 0 {
		b.WriteString(fmt.Sprintf("actual_minutes: %d\n", task.ActualMinutes))
	}
	// The sandbox this run executed in, when the control plane recorded one.
	// See sandbox.go for why it arrives via a file: the project directory is
	// the only thing the control plane (which resolved the image digest) and
	// this code (which runs inside the sandbox) both see.
	if rec, ok := LoadSandboxRun(workDir); ok {
		b.WriteString(rec.frontmatter())
	}
	b.WriteString("---\n\n")

	// Full AI response body
	b.WriteString(fullOutput)
	if !strings.HasSuffix(fullOutput, "\n") {
		b.WriteByte('\n')
	}

	if err := atomicfile.Write(absPath, []byte(b.String()), 0o644); err != nil {
		return "", fmt.Errorf("write artifact: %w", err)
	}

	// Return path relative to workDir for storage in task.ArtifactPath.
	rel, err := filepath.Rel(workDir, absPath)
	if err != nil {
		rel = absPath
	}
	return rel, nil
}

// WriteVerificationArtifact persists a shell verification script and its
// execution result under .cloop/tasks/<id>-<slug>-verify.md.
// Returns the relative path (relative to workDir) of the artifact file.
func WriteVerificationArtifact(workDir string, task *pm.Task, script, scriptOutput string, passed bool) (string, error) {
	dir := filepath.Join(workDir, ".cloop", "tasks")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("create artifact dir: %w", err)
	}

	s := slug(task.Title, 40)
	filename := fmt.Sprintf("%d-%s-verify.md", task.ID, s)
	absPath := filepath.Join(dir, filename)

	verdict := "PASS"
	if !passed {
		verdict = "FAIL"
	}

	var b strings.Builder

	// YAML frontmatter
	b.WriteString("---\n")
	b.WriteString(fmt.Sprintf("id: %d\n", task.ID))
	b.WriteString(fmt.Sprintf("title: %q\n", task.Title))
	b.WriteString(fmt.Sprintf("verification: %s\n", verdict))
	b.WriteString(fmt.Sprintf("generated_at: %s\n", time.Now().UTC().Format(time.RFC3339)))
	b.WriteString("---\n\n")

	// Script
	b.WriteString("## Verification Script\n\n")
	b.WriteString("```bash\n")
	b.WriteString(script)
	if !strings.HasSuffix(script, "\n") {
		b.WriteByte('\n')
	}
	b.WriteString("```\n\n")

	// Output
	b.WriteString("## Script Output\n\n")
	b.WriteString("```\n")
	if scriptOutput != "" {
		b.WriteString(scriptOutput)
		if !strings.HasSuffix(scriptOutput, "\n") {
			b.WriteByte('\n')
		}
	} else {
		b.WriteString("(no output)\n")
	}
	b.WriteString("```\n\n")

	b.WriteString(fmt.Sprintf("**Verdict: %s**\n", verdict))

	if err := atomicfile.Write(absPath, []byte(b.String()), 0o644); err != nil {
		return "", fmt.Errorf("write verification artifact: %w", err)
	}

	rel, err := filepath.Rel(workDir, absPath)
	if err != nil {
		rel = absPath
	}
	return rel, nil
}
