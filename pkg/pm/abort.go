package pm

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"
)

// This file carries the record of a task whose stored outcome is a refusal
// rather than work (Task 20224).
//
// Task 20211 taught the orchestrator to recognise a provider refusal *live* and
// reset the task to pending instead of closing it as done. That fixed the
// future and left the past alone: fourteen tasks in this project's own ledger
// are still recorded as done whose entire summary is "You've hit your limit",
// "You've hit your org's monthly usage limit", or the harness declining to run
// under root. `cloop task audit-ledger` could list them, but nothing consulted
// it — so the plan counted them complete, auto-evolve planned new work on top,
// and three features (watch-deps, ai-pr-review, vision) stayed missing for
// roughly a hundred iterations with nobody the wiser.
//
// A TaskAbort is that finding made durable. It exists on the task rather than
// being recomputed from prose on every read for two reasons. The obvious one is
// cost. The load-bearing one is that a *verdict* has to survive: several of
// those fourteen were quietly re-implemented by later tasks, so the refusal
// summary is real but the work exists anyway. Without somewhere to record
// "checked, the work is there, here is who did it", the only way to stop an
// audit re-flagging them forever is to stop running it — which is how the
// previous ledger ended up consulted by nothing.

// TaskAbort records that a task's stored summary is a provider or harness
// refusal rather than a description of work done.
type TaskAbort struct {
	// Class is the orchestrator's AbortClass as a string ("usage_limit",
	// "quota_exceeded", "harness_refused", ...). It is kept as a plain string
	// because the classifier lives in pkg/orchestrator, which imports this
	// package; holding the typed value here would invert that dependency.
	Class string `json:"class"`
	// Reason is operator-facing prose naming what the provider said.
	Reason string `json:"reason"`
	// Evidence is the matched excerpt of the stored summary, so the record
	// shows what was actually seen rather than our paraphrase of it.
	Evidence string `json:"evidence,omitempty"`
	// DetectedAt is when the sweep first recognised this outcome.
	DetectedAt time.Time `json:"detected_at,omitempty"`
	// SummaryFingerprint binds this record to the exact summary it describes.
	// When the task runs again its summary changes, the fingerprint stops
	// matching, and the whole record — including any clearance below — ceases
	// to apply. It is what makes reusing the stored classification safe rather
	// than merely cheap: a stale verdict can never mask a fresh refusal.
	//
	// Not a credential despite being a hash: it digests the task's own summary,
	// which is already visible to anyone who can read the task, and it gates a
	// cache decision rather than access to anything.
	SummaryFingerprint string `json:"summary_fingerprint,omitempty"`

	// Cleared records a verdict that the work exists despite the refusal
	// summary — typically because a later task re-landed it. A cleared abort
	// stops blocking plan completion but stays visible, because the ledger
	// entry is still wrong and a reader of project history deserves to know
	// why it was allowed to stand.
	Cleared bool `json:"cleared,omitempty"`
	// ClearedBy names who made that call ("cli", "triage", a username).
	ClearedBy string `json:"cleared_by,omitempty"`
	// ClearedNote is the evidence for the clearance. Required in practice:
	// a clearance without a reason is indistinguishable from giving up.
	ClearedNote string     `json:"cleared_note,omitempty"`
	ClearedAt   *time.Time `json:"cleared_at,omitempty"`
}

// Blocks reports whether this abort should stop a plan counting as complete.
// A nil receiver does not block, so callers can ask the question of any task.
func (a *TaskAbort) Blocks() bool {
	return a != nil && !a.Cleared
}

// Clear records the verdict that the work exists despite the refusal summary.
func (a *TaskAbort) Clear(by, note string) {
	if a == nil {
		return
	}
	now := time.Now().UTC()
	a.Cleared = true
	a.ClearedBy = by
	a.ClearedNote = note
	a.ClearedAt = &now
}

// FingerprintSummary fingerprints a task summary so a TaskAbort can be tied
// to the exact text it was derived from. Whitespace is normalised away because a
// summary that differs only in trailing newlines is the same summary; anything
// else counts as a new outcome that must be classified afresh.
func FingerprintSummary(result string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(result)))
	return hex.EncodeToString(sum[:8])
}

// AbortAppliesTo reports whether a stored record still describes this task's
// current summary. A record that does not is stale and must be re-derived.
func AbortAppliesTo(a *TaskAbort, result string) bool {
	return a != nil && a.SummaryFingerprint != "" && a.SummaryFingerprint == FingerprintSummary(result)
}

// UnverifiedAborts returns the tasks recorded as done whose stored outcome is
// an uncleared refusal — work the plan believes shipped and which demonstrably
// never ran.
func (p *Plan) UnverifiedAborts() []*Task {
	var out []*Task
	for _, t := range p.Tasks {
		if t == nil {
			continue
		}
		if t.Status == TaskDone && t.Abort.Blocks() {
			out = append(out, t)
		}
	}
	return out
}

// AbortedOutcomes returns every task carrying an abort record, cleared or not,
// in plan order. This is the reporting view: the UI shows cleared entries too,
// annotated with why they were allowed to stand.
func (p *Plan) AbortedOutcomes() []*Task {
	var out []*Task
	for _, t := range p.Tasks {
		if t != nil && t.Abort != nil {
			out = append(out, t)
		}
	}
	return out
}
