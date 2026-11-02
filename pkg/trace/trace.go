// Package trace correlates recent git commits with PM plan tasks using an AI provider.
// It walks git log, sends commit messages + task list to the provider, and returns
// a structured mapping of commit→task with confidence levels.
package trace

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/atomicfile"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/requirements"
)

// Commit holds a parsed git log entry.
type Commit struct {
	Hash    string `json:"hash"`
	Subject string `json:"subject"`
}

// Confidence is the AI-rated match quality for a commit→task pairing.
type Confidence string

const (
	ConfidenceHigh   Confidence = "high"
	ConfidenceMedium Confidence = "medium"
	ConfidenceLow    Confidence = "low"
	ConfidenceNone   Confidence = "none"
)

// TraceEntry links a single commit to a task (or indicates no match).
type TraceEntry struct {
	Hash             string     `json:"hash"`
	Subject          string     `json:"subject"`
	MatchedTaskID    int        `json:"matched_task_id"`    // 0 = no match
	MatchedTaskTitle string     `json:"matched_task_title"` // empty = no match
	Confidence       Confidence `json:"confidence"`
	// Tasks are every task the commit's subject names, MatchedTaskID first,
	// when it names more than one: "(Tasks 12, 13)" (Task 20465).
	Tasks []int `json:"tasks,omitempty"`
}

// subjectTaskList and subjectCloopTask find the tasks a commit subject names:
// "(Task 12)" and "(Tasks 12, 13 and 14)", as cloop's own history writes them,
// and "cloop(task-12): …", as its git workflow commits (pkg/git).
var (
	subjectTaskList  = regexp.MustCompile(`\(Tasks? #?(\d{1,9}(?:(?:,\s*|\s+and\s+)#?\d{1,9})*)\)`)
	subjectCloopTask = regexp.MustCompile(`^cloop\(task-(\d{1,9})\):`)
	subjectNumber    = regexp.MustCompile(`\d{1,9}`)
)

// SubjectTasks returns the ids of the tasks subject names, in the order it
// names them, each once (Task 20465). A commit that names its task is linked
// to it without asking a model.
func SubjectTasks(subject string) []int {
	var out []int
	add := func(raw string) {
		id, err := strconv.Atoi(raw)
		if err == nil && id > 0 && !slices.Contains(out, id) {
			out = append(out, id)
		}
	}
	if m := subjectCloopTask.FindStringSubmatch(subject); m != nil {
		add(m[1])
	}
	for _, m := range subjectTaskList.FindAllStringSubmatch(subject, -1) {
		for _, n := range subjectNumber.FindAllString(m[1], -1) {
			add(n)
		}
	}
	return out
}

// TraceMap is the complete mapping for a run.
type TraceMap struct {
	GeneratedAt time.Time    `json:"generated_at"`
	Entries     []TraceEntry `json:"entries"`
}

// GitLog returns the most recent commits (up to limit) from workDir.
// If since is non-empty it is passed as --since to git log.
func GitLog(workDir string, limit int, since string) ([]Commit, error) {
	args := []string{"log", fmt.Sprintf("--max-count=%d", limit), "--oneline", "--no-merges"}
	if since != "" {
		args = append(args, "--since="+since)
	}
	cmd := exec.Command("git", args...)
	cmd.Dir = workDir
	out, err := cmd.Output()
	if err != nil {
		// If not a git repo or no commits, return empty gracefully.
		return nil, fmt.Errorf("git log: %w", err)
	}

	var commits []Commit
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// Format: "<short-hash> <subject>"
		parts := strings.SplitN(line, " ", 2)
		if len(parts) != 2 {
			continue
		}
		commits = append(commits, Commit{
			Hash:    parts[0],
			Subject: parts[1],
		})
	}
	return commits, nil
}

// BuildPrompt constructs the AI prompt for commit→task mapping.
func BuildPrompt(commits []Commit, tasks []*pm.Task) string {
	var sb strings.Builder
	sb.WriteString("You are a commit traceability assistant. Your job is to map git commits to project tasks.\n\n")
	sb.WriteString("## Tasks\n")
	for _, t := range tasks {
		sb.WriteString(fmt.Sprintf("- ID %d: %s (%s)\n", t.ID, t.Title, t.Status))
		if t.Description != "" {
			desc := t.Description
			if len(desc) > 120 {
				desc = desc[:120] + "..."
			}
			sb.WriteString(fmt.Sprintf("  Description: %s\n", desc))
		}
	}

	sb.WriteString("\n## Commits\n")
	for _, c := range commits {
		sb.WriteString(fmt.Sprintf("- %s: %s\n", c.Hash, c.Subject))
	}

	sb.WriteString(`
## Instructions

For each commit, determine the most likely task it belongs to.
Return a JSON array with one object per commit in this exact format:

[
  {
    "hash": "<short hash>",
    "matched_task_id": <task ID or 0 if no match>,
    "confidence": "<high|medium|low|none>"
  }
]

Rules:
- Use "high" when the commit message clearly references the task title or ID
- Use "medium" when the commit is likely related but not explicitly mentioned
- Use "low" when it's a weak guess
- Use "none" and matched_task_id=0 when no task matches
- Only output the JSON array, no other text
`)
	return sb.String()
}

// aiEntry is used to decode the AI JSON response.
type aiEntry struct {
	Hash          string `json:"hash"`
	MatchedTaskID int    `json:"matched_task_id"`
	Confidence    string `json:"confidence"`
}

// Run orchestrates the full trace pipeline: collect commits, link the ones
// whose subject names their task, ask the model about the rest, and return
// the mapping. tasks are the plan's (state.Load reads them from the project's
// database). A nil prov asks no model: the commits no subject links stay
// unmatched (Task 20465).
func Run(ctx context.Context, prov provider.Provider, model string, workDir string, tasks []*pm.Task, limit int, since string) (*TraceMap, error) {
	commits, err := GitLog(workDir, limit, since)
	if err != nil {
		return nil, err
	}
	if len(commits) == 0 {
		return &TraceMap{GeneratedAt: time.Now()}, nil
	}

	// Build a lookup for tasks by ID.
	taskByID := make(map[int]*pm.Task, len(tasks))
	for _, t := range tasks {
		if t != nil {
			taskByID[t.ID] = t
		}
	}

	// A commit whose subject names its task needs no model: the link is the
	// author's own. Only the rest are asked about.
	entries := make([]TraceEntry, 0, len(commits))
	var unmatched []Commit
	for _, c := range commits {
		entry := TraceEntry{Hash: c.Hash, Subject: c.Subject, Confidence: ConfidenceNone}
		if ids := SubjectTasks(c.Subject); len(ids) > 0 {
			entry.MatchedTaskID, entry.Confidence = ids[0], ConfidenceHigh
			if t, ok := taskByID[ids[0]]; ok {
				entry.MatchedTaskTitle = t.Title
			}
			if len(ids) > 1 {
				entry.Tasks = ids
			}
		} else {
			unmatched = append(unmatched, c)
		}
		entries = append(entries, entry)
	}
	if len(unmatched) == 0 || prov == nil {
		return &TraceMap{GeneratedAt: time.Now(), Entries: entries}, nil
	}

	prompt := BuildPrompt(unmatched, tasks)

	resp, err := prov.Complete(ctx, prompt, provider.Options{
		Model:   model,
		Timeout: 2 * time.Minute,
	})
	if err != nil {
		return nil, fmt.Errorf("AI completion: %w", err)
	}

	// Extract JSON from the response (may be wrapped in markdown fences).
	jsonText := extractJSON(resp.Output)

	var aiEntries []aiEntry
	if err := json.Unmarshal([]byte(jsonText), &aiEntries); err != nil {
		return nil, fmt.Errorf("parsing AI response: %w\nRaw: %s", err, resp.Output)
	}

	// Index AI entries by hash for O(1) lookup.
	aiByHash := make(map[string]aiEntry, len(aiEntries))
	for _, e := range aiEntries {
		aiByHash[e.Hash] = e
	}

	for i := range entries {
		entry := &entries[i]
		if entry.MatchedTaskID != 0 {
			continue
		}
		if ai, ok := aiByHash[entry.Hash]; ok {
			entry.MatchedTaskID = ai.MatchedTaskID
			entry.Confidence = Confidence(ai.Confidence)
			if ai.MatchedTaskID > 0 {
				if t, ok := taskByID[ai.MatchedTaskID]; ok {
					entry.MatchedTaskTitle = t.Title
				}
			}
		}
	}

	tm := &TraceMap{
		GeneratedAt: time.Now(),
		Entries:     entries,
	}
	return tm, nil
}

// WriteTraceJSON persists the trace map to .cloop/trace.json.
//
// The write is atomic: data is staged in a sibling .tmp file, fsynced, chmod'd,
// then renamed into place. Without this, a crash mid-write or ENOSPC would
// leave trace.json corrupted, which would silently break `cloop status` (which
// calls LastLinkedCommit on every invocation) and any tooling that loads the
// commit→task mapping.
func WriteTraceJSON(workDir string, tm *TraceMap) error {
	dir := filepath.Join(workDir, ".cloop")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(tm, "", "  ")
	if err != nil {
		return err
	}
	return atomicfile.Write(filepath.Join(dir, "trace.json"), data, 0o644)
}

// LoadTraceJSON reads the persisted trace map from .cloop/trace.json.
// Returns nil without error when the file does not exist.
//
// On parse failure (zero-byte file from a torn pre-atomicfile write, schema
// drift, manual edit gone wrong) the corrupt trace.json is quarantined
// aside as trace.json.corrupt-<unix> and (nil, nil) is returned. The trace
// map is a derived index of commit→task links; `cloop status`,
// LastLinkedCommit, and similar callers all already handle the "no trace
// data yet" case, so returning empty is strictly better than refusing every
// status query until the user manually deletes the corrupt file.
func LoadTraceJSON(workDir string) (*TraceMap, error) {
	path := filepath.Join(workDir, ".cloop", "trace.json")
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var tm TraceMap
	if err := json.Unmarshal(data, &tm); err != nil {
		qpath := atomicfile.QuarantineCorrupt(path)
		if qpath != "" {
			fmt.Fprintf(os.Stderr, "warning: commit→task trace at %s was corrupt (%v); quarantined to %s, starting fresh\n", path, err, qpath)
		} else {
			fmt.Fprintf(os.Stderr, "warning: commit→task trace at %s was corrupt (%v) and could not be quarantined; ignoring\n", path, err)
		}
		return nil, nil
	}
	return &tm, nil
}

// MaxTraceFileBytes bounds what Peek reads of .cloop/trace.json. `cloop
// trace` writes one entry per commit it was asked about — 50 unless told
// otherwise — and a file far larger than that was not written by it.
const MaxTraceFileBytes = 4 << 20

// maxTaskCommitEntries bounds the entries TaskCommits reads.
const maxTaskCommitEntries = 5000

// Peek reads .cloop/trace.json for a reader that must change nothing and
// trust nothing — the hub, and `cloop requirements trace` (Task 20465). Unlike
// LoadTraceJSON it never quarantines a file it cannot parse (that is `cloop
// status`'s to do, in its own checkout); it reads at most MaxTraceFileBytes;
// and it opens the file inside .cloop only, as a regular file, so that a
// symbolic link planted in a project's directory cannot have the hub read
// another project's trace to this one's viewers. A missing, oversized or
// unparsable file is no trace: (nil, nil).
func Peek(workDir string) (*TraceMap, error) {
	root, err := os.OpenRoot(filepath.Join(workDir, ".cloop"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer root.Close()
	f, err := root.Open("trace.json")
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() || fi.Size() > MaxTraceFileBytes {
		return nil, nil
	}
	data, err := io.ReadAll(io.LimitReader(f, MaxTraceFileBytes+1))
	if err != nil {
		return nil, err
	}
	var tm TraceMap
	if len(data) > MaxTraceFileBytes || json.Unmarshal(data, &tm) != nil {
		return nil, nil
	}
	return &tm, nil
}

// TaskCommits are the commits tm links to a task, by task id, each task's in
// the trace's order — newest first, as git log lists them: what the
// traceability matrix shows of the trace (Task 20465). A link the trace rated
// none, or at a confidence it does not name, is no link; a hash that is not
// one is dropped. The subjects are the repository's words: whoever shows them
// escapes them.
func (tm *TraceMap) TaskCommits() map[int][]requirements.TraceCommit {
	out := map[int][]requirements.TraceCommit{}
	if tm == nil {
		return out
	}
	for i, e := range tm.Entries {
		if i == maxTaskCommitEntries {
			break
		}
		switch e.Confidence {
		case ConfidenceHigh, ConfidenceMedium, ConfidenceLow:
		default:
			continue
		}
		hash := requirements.CleanCommit(e.Hash)
		if e.MatchedTaskID <= 0 || hash == "" {
			continue
		}
		// A commit whose subject names several tasks is each one's.
		ids := []int{e.MatchedTaskID}
		for _, id := range e.Tasks {
			if id > 0 && !slices.Contains(ids, id) && len(ids) < 16 {
				ids = append(ids, id)
			}
		}
		for _, id := range ids {
			out[id] = append(out[id], requirements.TraceCommit{Hash: hash, Subject: e.Subject,
				TaskID: id, Source: requirements.CommitFromTrace, Confidence: string(e.Confidence)})
		}
	}
	return out
}

// MatrixPlan is plan as the traceability matrix reads it (Task 20465): its
// tasks, each with the commits it records of its own work, and the commits
// the project's trace links to them, read through Peek. A trace that cannot be
// read is no trace: the matrix without it still has every other column. The
// hub and `cloop requirements trace` both build theirs here.
func MatrixPlan(workDir string, plan *pm.Plan) requirements.TracePlan {
	tp := requirements.TracePlan{Tasks: pm.TracePlanTasks(plan)}
	if tm, err := Peek(workDir); err == nil {
		tp.Traced = tm.TaskCommits()
	}
	return tp
}

// LastLinkedCommit returns the most recent commit entry that was matched to a task,
// or nil if none found. Used by `cloop status`.
func LastLinkedCommit(workDir string) *TraceEntry {
	tm, err := LoadTraceJSON(workDir)
	if err != nil || tm == nil {
		return nil
	}
	for _, e := range tm.Entries {
		if e.MatchedTaskID > 0 && e.Confidence != ConfidenceNone {
			return &e
		}
	}
	return nil
}

// extractJSON pulls a JSON array from an AI response that may contain markdown fences.
func extractJSON(s string) string {
	s = strings.TrimSpace(s)
	// Strip markdown code fences if present.
	for _, fence := range []string{"```json", "```"} {
		if idx := strings.Index(s, fence); idx != -1 {
			s = s[idx+len(fence):]
			if end := strings.Index(s, "```"); end != -1 {
				s = s[:end]
			}
		}
	}
	s = strings.TrimSpace(s)
	// Find the outer array.
	start := strings.Index(s, "[")
	end := strings.LastIndex(s, "]")
	if start != -1 && end != -1 && end > start {
		return s[start : end+1]
	}
	return s
}
