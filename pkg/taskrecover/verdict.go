package taskrecover

// verdict.go is the orchestrator's half of recovery (Task 20365).
//
// Reconcile used to adopt whatever terminal signal the tail of the live
// artifact carried. That is the agent's word, and the orchestrator does not
// always take it: the review gate fails a task the agent called done, --verify
// and --script-verify fail one, work left running in the background fails one,
// an unanswered clarification question fails one, an unfinished turn returns
// one to pending. When the run then died — or, since Task 20362, stopped
// because the outcome write failed — before that decision reached the database,
// the agent's TASK_DONE was all that was left, recovery recorded it, and the
// task's dependents ran on work the orchestrator had rejected.
//
// So the orchestrator writes its decision down where recovery looks first: a
// sidecar next to the live artifact, .cloop/artifacts/<id>_verdict.json. It is
// written before the outcome write and before anything announces the outcome,
// atomically, so it is either the previous decision or the new one and never a
// torn mix. Reconcile applies a fresh verdict instead of the agent's signal and
// falls back to the signal only when there is none.
//
// # Freshness
//
// A verdict is held to the rule the live artifact is held to: one written
// before the execution being recovered started belongs to an earlier attempt
// and is ignored. A verdict also names the start of the execution it decided,
// and when the task names one too they must agree. That second check is what
// keeps a verdict from one machine's attempt from being read against another
// machine's clock — a remote device and its hub do not share one.
//
// The orchestrator removes a task's sidecar when an attempt starts, so a stale
// one only survives a removal that failed; the freshness rule is what makes
// that harmless.
//
// # What a verdict is not
//
// It is not the task's record. The database is, and once the outcome write has
// landed the sidecar is redundant: nothing reads it for a task that is not in
// progress, and PruneVerdicts removes it in time. It is also not a security
// boundary. Like the live artifact, it sits in a directory the agent can write
// to, and an agent that forges one gains nothing it could not get by printing
// TASK_DONE — which is precisely the claim recovery used to accept unchecked.

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/blechschmidt/cloop/pkg/artifact"
	"github.com/blechschmidt/cloop/pkg/atomicfile"
	"github.com/blechschmidt/cloop/pkg/pm"
)

// VerdictFormat is the version of the sidecar this build writes. Readers accept
// any format at or above 1 and read the fields they know: every field but the
// status is optional, so a later format that adds one is still a valid format-1
// document.
const VerdictFormat = 1

// Sources name what decided a task's outcome. They are recorded in the verdict
// and repeated in the recovered task's annotation and journal row, so an
// operator can tell "the review gate failed this" from "the agent gave up".
const (
	// SourceAgent: the agent's own signal, accepted as it stood.
	SourceAgent = "agent"
	// SourceReviewGate: the review gate (Task 20357) — a block, a publish
	// that failed, an approval, or a review still pending.
	SourceReviewGate = "review_gate"
	// SourceVerify and SourceScriptVerify: --verify and --script-verify.
	SourceVerify       = "verify"
	SourceScriptVerify = "script_verify"
	// SourceBackground: work the agent left running (Task 20205).
	SourceBackground = "background"
	// SourceClarification: the agent asked questions instead of working.
	SourceClarification = "clarification"
	// SourceAbort: the execution produced no finished work — an unfinished
	// turn, a refusal, empty output. The task goes back to pending.
	SourceAbort = "abort"
	// SourceInterrupted: the run stopped under the task (Task 20348).
	SourceInterrupted = "interrupted"
	// SourceBudget: the token budget or cost limit ran out after the task.
	SourceBudget = "budget"
	// SourceTimeout: the task's time budget expired.
	SourceTimeout = "timeout"
	// SourceProvider: the provider failed the call.
	SourceProvider = "provider_error"
	// SourceOperator: a person chose the outcome.
	SourceOperator = "operator"
	// SourceFailover: the hub's executor failover (Task 20391) — the run's
	// node went unreachable after executors.failover.max_attempts was used
	// up, or the task is a suspected node killer.
	SourceFailover = "failover"
	// SourceOrchestrator: anything else the orchestrator decides on its own —
	// a risk check, a pre-task hook, a dry run, an implicit completion.
	SourceOrchestrator = "orchestrator"
)

// ReasonReviewPending marks the verdict written while a task's outcome waits
// on the review gate: from the start of a gated execution until the gate
// decides. Such a verdict decides nothing itself, but it stops recovery from
// adopting a TASK_DONE the reviewer never approved — the work behind it was
// never published, since held pushes die with the run.
const ReasonReviewPending = "review_pending"

// ErrNoVerdict reports that a task has no verdict sidecar.
var ErrNoVerdict = errors.New("taskrecover: no verdict")

// Field bounds. A verdict carries text an agent or a reviewer wrote, and is
// read back into memory by recovery, so every field has a ceiling.
const (
	maxVerdictBytes     = 256 << 10
	maxVerdictDetail    = 2 << 10
	maxVerdictSummary   = 600
	maxVerdictDiagnosis = 16 << 10
	maxVerdictCode      = 64
)

// Verdict is the orchestrator's decision about one execution of one task.
type Verdict struct {
	// Format is the document version; see VerdictFormat.
	Format int `json:"format"`
	// TaskID names the task. A sidecar whose ID does not match its file name
	// is refused as corrupt.
	TaskID int `json:"task_id"`
	// Status is what was decided: done, failed, skipped or timed_out is the
	// outcome; pending means the task runs again; in_progress means nothing
	// was decided yet (see ReasonReviewPending).
	Status pm.TaskStatus `json:"status"`
	// Reason is a machine-readable code for why — "review_blocked",
	// "background_abandoned", "verify_failed", an abort class.
	Reason string `json:"reason,omitempty"`
	// Source is what decided; one of the Source constants.
	Source string `json:"source,omitempty"`
	// Detail is one sentence for the operator.
	Detail string `json:"detail,omitempty"`
	// Summary is the task's result summary when the decision was made, so a
	// recovery that cannot read the live artifact still has one.
	Summary string `json:"summary,omitempty"`
	// Diagnosis is the task's failure diagnosis when the decision was made:
	// the reviewer's findings, the background work that never finished.
	Diagnosis string `json:"diagnosis,omitempty"`
	// Review is the review gate's record, when the gate took part.
	Review *pm.TaskReview `json:"review,omitempty"`
	// Background is the background-work record the decision was made on.
	Background *pm.BackgroundWork `json:"background,omitempty"`
	// StartedAt is the start of the execution this verdict decided.
	StartedAt *time.Time `json:"started_at,omitempty"`
	// WrittenAt is when the decision was written down.
	WrittenAt time.Time `json:"written_at"`
}

// Decided reports whether the verdict settles the task: an outcome, or a
// return to pending. A verdict that is still waiting on something does not.
func (v *Verdict) Decided() bool {
	if v == nil {
		return false
	}
	switch v.Status {
	case pm.TaskDone, pm.TaskFailed, pm.TaskSkipped, pm.TaskTimedOut, pm.TaskPending:
		return true
	}
	return false
}

// AwaitingReview reports whether the verdict records an execution whose
// outcome was waiting on the review gate.
func (v *Verdict) AwaitingReview() bool {
	return v != nil && v.Status == pm.TaskInProgress && v.Reason == ReasonReviewPending
}

// For reports whether v belongs to t's current execution: written no earlier
// than that execution started — the rule the live artifact's mtime is held to —
// and, when both name a start, for the same one.
func (v *Verdict) For(t *pm.Task) bool {
	if v == nil || t == nil {
		return false
	}
	if t.StartedAt == nil {
		return true
	}
	if v.WrittenAt.Before(*t.StartedAt) {
		return false
	}
	return v.StartedAt == nil || sameStart(*v.StartedAt, *t.StartedAt)
}

// sameStart compares two recordings of one start instant. Every store cloop
// writes StartedAt through keeps nanoseconds, so this is equality; the
// millisecond tolerance only keeps a store that rounds from turning a
// verdict into a stale one.
func sameStart(a, b time.Time) bool {
	d := a.Sub(b)
	if d < 0 {
		d = -d
	}
	return d < time.Millisecond
}

// Describe renders who decided and why, for annotations and the journal:
// "review gate (review_blocked): Review gate: changes requested …".
func (v *Verdict) Describe() string {
	if v == nil {
		return ""
	}
	who := strings.ReplaceAll(v.Source, "_", " ")
	if who == "" {
		who = "cloop"
	}
	if v.Reason != "" {
		who += " (" + v.Reason + ")"
	}
	if v.Detail != "" {
		return who + ": " + strings.TrimRight(v.Detail, ". ")
	}
	return who
}

// VerdictPath is where a task's verdict sidecar lives: next to its live
// artifact.
func VerdictPath(workDir string, taskID int) string {
	return filepath.Join(artifact.LiveArtifactDir(workDir), fmt.Sprintf("%d_verdict.json", taskID))
}

// WriteVerdict writes v as taskID's sidecar, atomically. WrittenAt is set to
// now unless the caller set it; every free-text field is bounded.
func WriteVerdict(workDir string, v Verdict) error {
	if workDir == "" {
		return errors.New("taskrecover: write verdict: no project directory")
	}
	if v.TaskID <= 0 {
		return fmt.Errorf("taskrecover: write verdict: invalid task id %d", v.TaskID)
	}
	if !validVerdictStatus(v.Status) {
		return fmt.Errorf("taskrecover: write verdict for task #%d: invalid status %q", v.TaskID, v.Status)
	}
	v.Format = VerdictFormat
	if v.WrittenAt.IsZero() {
		v.WrittenAt = time.Now()
	}
	bound(&v)
	data, err := json.MarshalIndent(&v, "", "  ")
	if err != nil {
		return fmt.Errorf("taskrecover: encode verdict for task #%d: %w", v.TaskID, err)
	}
	if len(data) > maxVerdictBytes {
		// Only the review record can get this large. The decision and its
		// headline matter more than the findings, which the task's own
		// record keeps once its outcome is stored.
		v.Review = nil
		if data, err = json.MarshalIndent(&v, "", "  "); err != nil {
			return fmt.Errorf("taskrecover: encode verdict for task #%d: %w", v.TaskID, err)
		}
	}
	dir := artifact.LiveArtifactDir(workDir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("taskrecover: create %s: %w", dir, err)
	}
	// 0644 like the live artifact beside it: on a remote device the agent
	// that reads it back may not be the user the workload ran as.
	if err := atomicfile.Write(VerdictPath(workDir, v.TaskID), append(data, '\n'), 0o644); err != nil {
		return fmt.Errorf("taskrecover: write verdict for task #%d: %w", v.TaskID, err)
	}
	return nil
}

// ClearVerdict removes taskID's sidecar. A sidecar that is not there is not an
// error.
func ClearVerdict(workDir string, taskID int) error {
	if workDir == "" || taskID <= 0 {
		return nil
	}
	err := os.Remove(VerdictPath(workDir, taskID))
	if err == nil || errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return fmt.Errorf("taskrecover: remove the verdict of task #%d: %w", taskID, err)
}

// ReadVerdict reads taskID's sidecar. It returns ErrNoVerdict when there is
// none, and any other error when there is one that cannot be used — which the
// caller reports, because a sidecar that exists says a decision was made.
//
// Symbolic links are refused, in the file and in the directory holding it. On
// a remote device the reader is the agent, which may be able to read files the
// workload that wrote this directory cannot, and a link is how the workload
// would ask it to.
func ReadVerdict(workDir string, taskID int) (*Verdict, error) {
	dir := artifact.LiveArtifactDir(workDir)
	info, err := os.Lstat(dir)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return nil, ErrNoVerdict
	case err != nil:
		return nil, fmt.Errorf("inspect %s: %w", dir, err)
	case info.Mode()&os.ModeSymlink != 0:
		return nil, fmt.Errorf("%s is a symbolic link; not following it", dir)
	case !info.IsDir():
		return nil, fmt.Errorf("%s is not a directory", dir)
	}

	path := VerdictPath(workDir, taskID)
	f, err := openNoFollow(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNoVerdict
	}
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()
	if fi, err := f.Stat(); err != nil {
		return nil, fmt.Errorf("inspect %s: %w", path, err)
	} else if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxVerdictBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	if len(data) > maxVerdictBytes {
		return nil, fmt.Errorf("%s is larger than %d bytes", path, maxVerdictBytes)
	}
	var v Verdict
	if err := json.Unmarshal(data, &v); err != nil {
		return nil, fmt.Errorf("%s is not a verdict: %w", path, err)
	}
	switch {
	case v.Format < 1:
		return nil, fmt.Errorf("%s has no recognisable format", path)
	case v.TaskID != taskID:
		return nil, fmt.Errorf("%s names task #%d", path, v.TaskID)
	case !validVerdictStatus(v.Status):
		return nil, fmt.Errorf("%s records an unknown status %q", path, clip(string(v.Status), 32))
	case v.WrittenAt.IsZero():
		return nil, fmt.Errorf("%s does not say when it was written", path)
	}
	bound(&v)
	return &v, nil
}

func validVerdictStatus(s pm.TaskStatus) bool {
	switch s {
	case pm.TaskDone, pm.TaskFailed, pm.TaskSkipped, pm.TaskTimedOut, pm.TaskPending, pm.TaskInProgress:
		return true
	}
	return false
}

// bound applies the field ceilings in place.
func bound(v *Verdict) {
	v.Reason = clip(v.Reason, maxVerdictCode)
	v.Source = clip(v.Source, maxVerdictCode)
	v.Detail = clip(v.Detail, maxVerdictDetail)
	v.Summary = clip(v.Summary, maxVerdictSummary)
	v.Diagnosis = clip(v.Diagnosis, maxVerdictDiagnosis)
	if v.Review != nil {
		v.Review = v.Review.Clone()
		v.Review.Bound()
	}
	if v.Background != nil {
		bg := *v.Background
		if len(bg.Commands) > 20 {
			bg.Commands = bg.Commands[:20]
		}
		bg.Commands = append([]string(nil), bg.Commands...)
		for i := range bg.Commands {
			bg.Commands[i] = clip(bg.Commands[i], 512)
		}
		v.Background = &bg
	}
}

// clip keeps the first n bytes of s, cut at a UTF-8 boundary.
func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// verdictName matches a sidecar, and verdictTemp a staging file a crash left
// between atomicfile's create and its rename.
var (
	verdictName = regexp.MustCompile(`^([1-9][0-9]{0,9})_verdict\.json$`)
	verdictTemp = regexp.MustCompile(`^\.([1-9][0-9]{0,9})_verdict\.json\..+\.tmp$`)
)

// PruneResult is what PruneVerdicts removed, or would have.
type PruneResult struct {
	Deleted int
	Bytes   int64
	// Kept counts sidecars left in place: their task is in progress, or they
	// are newer than the cutoff.
	Kept int
}

// PruneVerdicts removes the sidecars nothing will read again: those older than
// cutoff whose task is not in progress, including tasks no longer in the plan.
//
// A sidecar is read only to recover a task left in progress, so one whose task
// is in any other state is redundant — the outcome it decided is stored. The
// cutoff keeps the pass away from a run that is writing one right now: a task
// that a concurrent run has just started would read as not in progress to a
// caller holding an older plan.
//
// inProgress reports whether a task is in progress. Nothing outside
// .cloop/artifacts is touched, and a symbolic link there is never followed.
func PruneVerdicts(workDir string, inProgress func(taskID int) bool, cutoff time.Time, dryRun bool) (PruneResult, error) {
	var res PruneResult
	dir := artifact.LiveArtifactDir(workDir)
	if info, err := os.Lstat(dir); errors.Is(err, os.ErrNotExist) {
		return res, nil
	} else if err != nil {
		return res, fmt.Errorf("taskrecover: inspect %s: %w", dir, err)
	} else if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return res, fmt.Errorf("taskrecover: %s is not a directory; not pruning through it", dir)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return res, fmt.Errorf("taskrecover: read %s: %w", dir, err)
	}
	var errs []error
	for _, e := range entries {
		m := verdictName.FindStringSubmatch(e.Name())
		temp := false
		if m == nil {
			if m = verdictTemp.FindStringSubmatch(e.Name()); m == nil {
				continue
			}
			temp = true
		}
		info, err := e.Info() // lstat: a link is reported as one
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		id, _ := strconv.Atoi(m[1])
		if !info.ModTime().Before(cutoff) || (!temp && inProgress != nil && inProgress(id)) {
			res.Kept++
			continue
		}
		if !dryRun {
			if err := os.Remove(filepath.Join(dir, e.Name())); err != nil && !errors.Is(err, os.ErrNotExist) {
				errs = append(errs, err)
				continue
			}
		}
		res.Deleted++
		res.Bytes += info.Size()
	}
	if len(errs) > 0 {
		return res, fmt.Errorf("taskrecover: prune verdicts: %w", errors.Join(errs...))
	}
	return res, nil
}
