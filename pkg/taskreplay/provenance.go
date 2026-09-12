package taskreplay

// provenance.go reconstructs the input state of one past task execution.
//
// # Why this is not a new package
//
// The question it answers — "what exactly went in, so it can go in again?" — is
// the input half of the question this package already asks. ReplayTask
// reconstructs a prompt and sends it to a provider; Reproduce reconstructs the
// same prompt *plus* the commit, the model settings and the sandbox, and sends
// it to an executor. Splitting the input reconstruction into its own package
// would give two places that decide what "the same task, again" means, and they
// would drift — the failure mode gitwriteback's package comment names, for the
// same reason: a drifted copy is silent, because a reproduction that replayed
// slightly different inputs still returns a verdict, just a worthless one.
//
// # Where the record actually lives
//
// There is no single provenance row to read. The custody chain was recorded
// where each link was formed, by the subsystem that formed it:
//
//   - the model settings, goal and instructions in the project state;
//   - the prompt, reconstructible from the plan by pm.ExecuteTaskPrompt — the
//     same call the orchestrator made;
//   - the sandbox in the artifact frontmatter stamp (pkg/artifact/sandbox.go),
//     which is the durable per-task copy; .cloop/sandbox-run.json describes
//     whatever ran most recently and is the wrong file to read here;
//   - the returned commit on the task record, put there by pkg/writeback;
//   - the commit it was based on in the write_back event's detail blob, which
//     is the only place BaseSHA survives.
//
// Reading five sources means five chances to find nothing. Every one of them
// degrades to a warning rather than an error, except the returned commit: with
// no commit there is nothing to compare a reproduction against, and a harness
// that proceeded anyway would be scoring a diff against an absence.

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"github.com/blechschmidt/cloop/pkg/artifact"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/sandbox"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// ErrNoRecordedCommit is returned for a task that has no write-back commit.
//
// It is the ordinary outcome for a task that ran on the host: its changes went
// straight into the working tree, so there is no commit that is *this task's*
// and nothing to reproduce against. Callers should present it as "this task
// cannot be reproduced", not as a failure.
var ErrNoRecordedCommit = errors.New("task has no recorded write-back commit, so there is nothing to reproduce against")

// BaseSource says how the parent commit was determined, because the two ways
// are not equally trustworthy and a verdict computed on a guessed base is worth
// less than one computed on a recorded base.
type BaseSource string

const (
	// BaseRecorded: read from the write_back event the original run wrote.
	// This is the commit the executor actually provisioned its workspace at.
	BaseRecorded BaseSource = "recorded"

	// BaseForkPoint: computed as the merge base of the project's HEAD and the
	// returned commit — the point the write-back branch forked from mainline.
	//
	// Trustworthy, and the reason the ordinary case still gets a strong
	// verdict: it is correct for a write-back of any length, because it asks
	// where the branch diverged rather than assuming how far back that was.
	// It only fails to produce an answer when the write-back has since been
	// merged into HEAD, in which case the merge base is the commit itself and
	// there is no range left to measure.
	BaseForkPoint BaseSource = "fork-point"

	// BaseFirstParent: inferred as the first parent of the returned commit.
	//
	// The last resort, and never trusted. It is correct only when the
	// write-back was a single commit: a three-commit write-back has its base
	// three commits back, so reproducing from the first parent starts from a
	// tree that already contains two thirds of the work — which would then
	// reproduce "identically" for the wrong reason. Nothing here can tell the
	// two apart, so Comparison.BaseConfirmed is false for this source and
	// verdictFor refuses to rule. See TestCompareBundleMultiCommitInferredBase.
	BaseFirstParent BaseSource = "first-parent"
)

// Trusted reports whether a verdict computed against this base is worth
// anything. See BaseFirstParent for the case that is not.
func (b BaseSource) Trusted() bool {
	return b == BaseRecorded || b == BaseForkPoint
}

// Provenance is the reconstructed input state of one past task execution:
// everything a reproduction needs to set up the same run again.
type Provenance struct {
	TaskID    int           `json:"task_id"`
	TaskTitle string        `json:"task_title"`
	Status    pm.TaskStatus `json:"status"`

	// The plan side of the input.
	Goal         string `json:"goal,omitempty"`
	Instructions string `json:"instructions,omitempty"`
	Prompt       string `json:"prompt,omitempty"`
	PromptSHA256 string `json:"prompt_sha256,omitempty"`

	// The model side. Effort is the reasoning-effort level (Task 20149).
	Provider string `json:"provider,omitempty"`
	Model    string `json:"model,omitempty"`
	Effort   string `json:"effort,omitempty"`

	// The sandbox side: the stamp the original run left, plus whether the
	// project's .cloop/sandbox.yaml still hashes to what that run used.
	Sandbox        artifact.SandboxRecord `json:"sandbox"`
	SandboxHashNow string                 `json:"sandbox_hash_now,omitempty"`
	SandboxDrift   bool                   `json:"sandbox_drift"`

	// The git side.
	BaseSHA        string     `json:"base_sha,omitempty"`
	BaseSource     BaseSource `json:"base_source,omitempty"`
	OriginalCommit string     `json:"original_commit,omitempty"`
	OriginalBranch string     `json:"original_branch,omitempty"`

	// Warnings name each link of the chain that could not be recovered. They
	// are the caller's evidence for how much a verdict is worth.
	Warnings []string `json:"warnings,omitempty"`
}

// PinnedImage reports whether the original run's filesystem can be reproduced
// byte-for-byte — that is, whether the image was digest-pinned.
//
// A reproduction against a floating tag is still worth running, but a
// DIVERGENT verdict from one is not evidence of orchestrator nondeterminism:
// the image moved underneath it. Callers surface this next to the verdict.
func (p *Provenance) PinnedImage() bool { return p.Sandbox.Pinned() }

// Reproducible reports whether enough of the chain survived to place a run.
func (p *Provenance) Reproducible() bool {
	return strings.TrimSpace(p.OriginalCommit) != "" && strings.TrimSpace(p.BaseSHA) != ""
}

// ReadProvenance reconstructs the input state of taskID's original execution.
func ReadProvenance(workDir string, taskID int) (*Provenance, error) {
	s, err := state.Load(workDir)
	if err != nil {
		return nil, fmt.Errorf("load state: %w", err)
	}
	if s.Plan == nil || len(s.Plan.Tasks) == 0 {
		return nil, fmt.Errorf("no plan found in %s: %w", workDir, ErrTaskNotReplayable)
	}
	task := s.Plan.TaskByID(taskID)
	if task == nil {
		return nil, fmt.Errorf("task %d not found: %w", taskID, statedb.ErrTaskNotFound)
	}

	p := &Provenance{
		TaskID:       task.ID,
		TaskTitle:    task.Title,
		Status:       task.Status,
		Goal:         s.Plan.Goal,
		Instructions: s.Instructions,
		Provider:     s.Provider,
		Model:        s.Model,
		Effort:       s.Effort,

		OriginalCommit: strings.TrimSpace(task.WriteBackCommit),
		OriginalBranch: strings.TrimSpace(task.WriteBackBranch),
	}

	// The same call the orchestrator made. It renders today's plan, not the
	// plan as it stood during the original run — see the note on Prompt drift
	// in ReplayTask. For a reproduction that difference is the point of the
	// hash: two runs of the same task whose prompts hash differently were not
	// given the same input, and the verdict says so rather than blaming the
	// model.
	p.Prompt = pm.ExecuteTaskPrompt(s.Plan.Goal, s.Instructions, "", s.Plan, task, true)
	sum := sha256.Sum256([]byte(p.Prompt))
	p.PromptSHA256 = hex.EncodeToString(sum[:])

	if rec, ok := artifact.ReadTaskSandbox(workDir, task); ok {
		p.Sandbox = rec
	} else {
		p.warn("no sandbox stamp on the task artifact: the executor and image this task ran on are unknown")
	}

	// Drift between the spec that ran and the spec at HEAD. Recorded rather
	// than corrected: reproducing against today's sandbox.yaml is the useful
	// thing to do (it is what a re-run would get), but a divergence explained
	// by a changed sandbox is not a divergence in the orchestrator.
	if resolved, rerr := sandbox.Resolve(workDir); rerr == nil && resolved.Present() {
		p.SandboxHashNow = resolved.Spec.Hash()
		if p.Sandbox.SpecHash != "" && p.SandboxHashNow != p.Sandbox.SpecHash {
			p.SandboxDrift = true
			p.warn(".cloop/sandbox.yaml has changed since this task ran: the reproduction runs in a different sandbox than the original")
		}
	} else if p.Sandbox.SpecHash != "" {
		p.SandboxDrift = true
		p.warn(".cloop/sandbox.yaml is gone but this task ran with one: the reproduction runs on the executor's defaults")
	}

	if p.OriginalCommit == "" {
		return p, fmt.Errorf("task %d: %w", taskID, ErrNoRecordedCommit)
	}

	if base, ok := writeBackBase(workDir, taskID); ok {
		p.BaseSHA, p.BaseSource = base, BaseRecorded
	}
	// A missing base is not filled in here: recovering it means reading the
	// repository, which this file does not open. ResolveBase does it, and
	// Reproduce calls that before dispatching — the sandbox needs a commit to
	// check out, so the base has to exist before the run, not at comparison
	// time.
	return p, nil
}

// warn appends a warning, ignoring duplicates so a repeated diagnosis does not
// make the chain look worse than it is.
func (p *Provenance) warn(msg string) {
	for _, existing := range p.Warnings {
		if existing == msg {
			return
		}
	}
	p.Warnings = append(p.Warnings, msg)
}

// writeBackBase recovers the base commit from the task's write_back event.
//
// pkg/writeback records BaseSHA in the event's detail blob and nowhere else —
// the task row deliberately carries only "a branch that exists at a commit that
// exists". Reading it here rather than adding a column means every task that
// already ran is reproducible, instead of only tasks that run after this ships.
//
// The newest matching event wins: a task retried after a failed write-back has
// more than one, and the last one is the one whose commit is on the task.
func writeBackBase(workDir string, taskID int) (string, bool) {
	conn, err := openStateDB(workDir)
	if err != nil {
		return "", false
	}
	defer conn.Close()

	rows, err := conn.Query(`
		SELECT details FROM events
		WHERE task_id = ? AND type = ?
		ORDER BY id DESC
		LIMIT 20`, taskID, string(statedb.EventWriteBack))
	if err != nil {
		return "", false
	}
	defer rows.Close()

	for rows.Next() {
		var details string
		if err := rows.Scan(&details); err != nil {
			return "", false
		}
		var blob struct {
			Base string `json:"base"`
		}
		if err := json.Unmarshal([]byte(details), &blob); err != nil {
			continue
		}
		if base := strings.TrimSpace(blob.Base); base != "" {
			return base, true
		}
	}
	return "", false
}

// openStateDB opens a single-connection reader/writer on the project's state.db
// with the schema migrated.
//
// Every query in this package goes through it. The two-step — open through
// statedb so migrations run, then open a raw conn for the query — is the idiom
// store.go established, and the reason is that statedb.DB exposes no general
// query surface: the alternative is adding a method there for each one-off
// question a verification tool asks, which would grow the shared type for the
// benefit of a single caller.
func openStateDB(workDir string) (*sql.DB, error) {
	dbPath := state.StateDBPath(state.ActiveDir(workDir))
	db, err := statedb.Open(dbPath)
	if err != nil {
		return nil, fmt.Errorf("open state db: %w", err)
	}
	db.Close()

	conn, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("open state db conn: %w", err)
	}
	conn.SetMaxOpenConns(1)
	if _, err := conn.Exec(`PRAGMA busy_timeout=5000`); err != nil {
		conn.Close()
		return nil, fmt.Errorf("busy_timeout: %w", err)
	}
	return conn, nil
}

// ProvenanceAge is how long ago the original run started, when the stamp
// recorded it. Zero when unknown.
func (p *Provenance) ProvenanceAge(now time.Time) time.Duration {
	if p.Sandbox.StartedAt.IsZero() {
		return 0
	}
	return now.Sub(p.Sandbox.StartedAt)
}
