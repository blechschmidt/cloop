package multiagent

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/blechschmidt/cloop/pkg/atomicfile"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
)

// Result holds the outputs of all three sub-agent passes plus the final signal.
type Result struct {
	ArchitectOutput string
	CoderOutput     string
	ReviewerOutput  string
	// Signal is the final task signal extracted from the reviewer's output,
	// falling back to the coder's signal. One of TASK_DONE, TASK_FAILED, TASK_SKIPPED.
	Signal      pm.TaskStatus
	ArtifactDir string // relative path of the per-task artifact directory

	// InputTokens, OutputTokens and ThinkingTokens are summed over the passes.
	InputTokens    int
	OutputTokens   int
	ThinkingTokens int
	// Background is the background work the passes left behind (Task 20205):
	// the first pass whose work did not drain, else the last that left any.
	// The orchestrator judges the task by it exactly as it judges a single
	// agent's — otherwise a coder that started a job and walked away would
	// have its "waiting" record cleared and its result accepted.
	Background *provider.BackgroundActivity
	// SessionID is the coder's conversation, where a provider reports one.
	// The coder made the changes, so a review gate that sends the task back
	// with findings resumes that conversation.
	SessionID string
}

// Brief is what every pass is told about the task.
type Brief struct {
	Task           *pm.Task
	Goal           string
	Instructions   string
	ProjectContext string
	// Notice is a prompt section every pass carries — the review gate's,
	// while the project's gate is on (Task 20365), so a sub-agent that pushes
	// knows the push is held and must not be routed around.
	Notice string
}

var nonSlugRe = regexp.MustCompile(`[^a-z0-9-]+`)

func slug(title string, maxLen int) string {
	s := strings.ToLower(title)
	s = strings.ReplaceAll(s, " ", "-")
	s = nonSlugRe.ReplaceAllString(s, "")
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

// RunTask executes a single PM task through the three-pass multi-agent pipeline
// (architect → coder → reviewer) and returns the combined result.
//
// Each pass uses its own system prompt from roles.go. The coder receives the
// architect's output as context, and the reviewer receives both prior outputs.
// Sub-agent responses are stored as artifact files under
// .cloop/tasks/<id>-<slug>-multiagent/{architect,coder,reviewer}.txt.
//
// opts are the options a single-agent run of the task would get — model,
// effort, thinking settings, working directory, the environment that holds
// pushes for the review gate, the background-wait notice — and every pass
// runs with them, setting only its own system prompt (Task 20365). Before
// that, the pipeline built options of its own from a model and a timeout, so a
// gated project's sub-agents pushed straight past the gate, ran in the
// process's working directory rather than the task's, and were cut off at ten
// minutes when no step timeout was set, against Task 20148's rule that
// a task has no time limit unless one is configured. A zero opts.Timeout
// still means none.
//
// Two stability bounds protect the pipeline:
//   - ctx.Err() is checked between passes so a cancelled parent (Ctrl+C
//     translated to cancel, or the orchestrator's per-task watchdog firing)
//     bails before the next pass instead of running the full architect→coder
//     →reviewer chain — each pass can run for many minutes, so an unbounded
//     pipeline ignores cancellation for tens of minutes after the user asked
//     it to stop.
//   - Each prov.Complete call is wrapped in panic recovery so a panic inside
//     a provider implementation (e.g. nil-pointer in a third-party SDK,
//     malformed JSON deref) becomes a returned error instead of taking down
//     the orchestrator and losing every other queued task.
func RunTask(ctx context.Context, prov provider.Provider, opts provider.Options, brief Brief) (*Result, error) {
	task := brief.Task
	if task == nil {
		return nil, fmt.Errorf("multiagent: no task")
	}
	res := &Result{}

	// Build the base task description block used by all passes.
	var header strings.Builder
	if brief.ProjectContext != "" {
		header.WriteString("## Project Context\n\n")
		header.WriteString(brief.ProjectContext)
		header.WriteString("\n\n")
	}
	header.WriteString("## Goal\n\n")
	header.WriteString(brief.Goal)
	header.WriteString("\n\n")
	if brief.Instructions != "" {
		header.WriteString("## Instructions\n\n")
		header.WriteString(brief.Instructions)
		header.WriteString("\n\n")
	}
	header.WriteString(fmt.Sprintf("## Task %d: %s\n\n", task.ID, task.Title))
	header.WriteString(task.Description)
	header.WriteString("\n")
	if brief.Notice != "" {
		header.WriteString("\n")
		header.WriteString(strings.TrimRight(brief.Notice, "\n"))
		header.WriteString("\n")
	}
	baseContext := header.String()

	// pass runs one sub-agent with the shared options and its role's system
	// prompt, and folds what it spent and left behind into res.
	pass := func(name, systemPrompt, prompt string) (*provider.Result, error) {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("multiagent cancelled before %s pass: %w", name, err)
		}
		passOpts := opts
		passOpts.SystemPrompt = systemPrompt
		r, err := safeComplete(ctx, prov, prompt, passOpts)
		if err != nil {
			return nil, fmt.Errorf("%s pass: %w", name, err)
		}
		res.InputTokens += r.InputTokens
		res.OutputTokens += r.OutputTokens
		res.ThinkingTokens += r.ThinkingTokens
		if bg := r.Background; bg != nil && bg.Detected > 0 && !res.Background.Incomplete() {
			res.Background = bg
		}
		return r, nil
	}

	// ── Pass 1: Architect ──────────────────────────────────────────────────
	archResult, err := pass("architect", ArchitectSystemPrompt, baseContext+"\nDesign the technical approach for this task.")
	if err != nil {
		return nil, err
	}
	res.ArchitectOutput = archResult.Output

	// ── Pass 2: Coder ──────────────────────────────────────────────────────
	var coderPrompt strings.Builder
	coderPrompt.WriteString(baseContext)
	coderPrompt.WriteString("\n## Architect's Design\n\n")
	coderPrompt.WriteString(res.ArchitectOutput)
	coderPrompt.WriteString("\n\nImplement the task following the architect's design above.")
	coderResult, err := pass("coder", CoderSystemPrompt, coderPrompt.String())
	if err != nil {
		return nil, err
	}
	res.CoderOutput = coderResult.Output
	res.SessionID = coderResult.SessionID

	// ── Pass 3: Reviewer ───────────────────────────────────────────────────
	var reviewerPrompt strings.Builder
	reviewerPrompt.WriteString(baseContext)
	reviewerPrompt.WriteString("\n## Architect's Design\n\n")
	reviewerPrompt.WriteString(res.ArchitectOutput)
	reviewerPrompt.WriteString("\n\n## Coder's Implementation\n\n")
	reviewerPrompt.WriteString(res.CoderOutput)
	reviewerPrompt.WriteString("\n\nReview the implementation and emit your verdict.")
	reviewerResult, err := pass("reviewer", ReviewerSystemPrompt, reviewerPrompt.String())
	if err != nil {
		return nil, err
	}
	res.ReviewerOutput = reviewerResult.Output

	// ── Signal resolution ─────────────────────────────────────────────────
	// Reviewer's verdict takes precedence; fall back to coder's signal.
	reviewerSignal := pm.CheckTaskSignal(res.ReviewerOutput)
	coderSignal := pm.CheckTaskSignal(res.CoderOutput)

	switch {
	case reviewerSignal == pm.TaskDone || reviewerSignal == pm.TaskFailed || reviewerSignal == pm.TaskSkipped:
		res.Signal = reviewerSignal
	case coderSignal == pm.TaskDone || coderSignal == pm.TaskFailed || coderSignal == pm.TaskSkipped:
		res.Signal = coderSignal
	default:
		// Neither emitted a recognizable signal — treat as done (matches single-agent behaviour).
		res.Signal = pm.TaskDone
	}

	return res, nil
}

// WriteArtifacts persists the three sub-agent outputs as text files under
// .cloop/tasks/<id>-<slug>-multiagent/ and returns the relative directory path.
func WriteArtifacts(workDir string, task *pm.Task, res *Result) (string, error) {
	s := slug(task.Title, 40)
	dirName := fmt.Sprintf("%d-%s-multiagent", task.ID, s)
	absDir := filepath.Join(workDir, ".cloop", "tasks", dirName)
	if err := os.MkdirAll(absDir, 0o755); err != nil {
		return "", fmt.Errorf("create multiagent artifact dir: %w", err)
	}

	files := map[string]string{
		"architect.txt": res.ArchitectOutput,
		"coder.txt":     res.CoderOutput,
		"reviewer.txt":  res.ReviewerOutput,
	}
	for name, content := range files {
		absPath := filepath.Join(absDir, name)
		if err := atomicfile.Write(absPath, []byte(content), 0o644); err != nil {
			return "", fmt.Errorf("write %s: %w", name, err)
		}
	}

	rel, err := filepath.Rel(workDir, absDir)
	if err != nil {
		rel = absDir
	}
	return rel, nil
}
