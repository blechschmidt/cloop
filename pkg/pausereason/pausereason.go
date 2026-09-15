// Package pausereason gives a paused run a machine-readable explanation.
//
// Before this existed, every one of the ~26 sites that paused a run wrote the
// same opaque string into ProjectState.Status: "paused". An approval gate
// waiting on a human, a budget that had run out, an operator's Ctrl-C and an
// exhausted subscription window were indistinguishable in the API, in the
// dashboard and in the audit trail. An autonomous fleet could stall for a week
// and the only way to learn why was to read the terminal scrollback of a
// process that had already exited.
//
// The package is deliberately a leaf: pkg/state imports pkg/statedb, so the
// type cannot live in either of them if both are to name it. It depends on
// nothing but the standard library.
package pausereason

import (
	"fmt"
	"strings"
	"time"
)

// Code names why a run paused. It is the field a caller switches on, so the
// set is closed — an unrecognised code is a bug, not an extension point.
type Code string

const (
	// CodeUsageCap is a Claude Code subscription window whose configured
	// per-project cap has been reached. This is the one pause that reliably
	// ends on its own, which is why it carries ResumesAt.
	CodeUsageCap Code = "usage_cap"
	// CodeBudget is a configured spend limit: the daily/global budget in
	// pkg/budget, or a per-task cost ceiling.
	CodeBudget Code = "budget"
	// CodeTokenBudget is the --token-budget cumulative token ceiling.
	CodeTokenBudget Code = "token_budget"
	// CodeStepLimit is the --steps or per-project max-steps ceiling.
	CodeStepLimit Code = "step_limit"
	// CodeApproval is a human-in-the-loop gate: an approval declined, or an
	// interactive review the operator quit.
	CodeApproval Code = "approval"
	// CodeAbort is a provider or harness refusal that waiting will not fix —
	// a hard quota, a rejected credential, a harness that would not start.
	CodeAbort Code = "abort"
	// CodeCancelled is a context cancellation: Ctrl-C, a deadline, or the
	// hub stopping the run.
	CodeCancelled Code = "cancelled"
	// CodePlanOnly is --plan-only: the plan was decomposed and shown, and
	// execution was never intended.
	CodePlanOnly Code = "plan_only"
	// CodeIdle is the ordinary end of a run — every runnable task is done and
	// auto-evolve is off, so there is nothing left to do until someone adds
	// work. It is a pause rather than a completion because the plan may still
	// grow.
	CodeIdle Code = "idle"
	// CodeOperator is a stop the operator asked for through the hub or CLI.
	CodeOperator Code = "operator"
	// CodeStale is a run that died without saying so — the process vanished
	// and the hub reconciled its status on the way back up.
	CodeStale Code = "stale"
)

// codeLabels is the operator-facing noun for each code, used when a Reason
// carries no detail of its own.
var codeLabels = map[Code]string{
	CodeUsageCap:    "subscription usage cap reached",
	CodeBudget:      "budget limit reached",
	CodeTokenBudget: "token budget reached",
	CodeStepLimit:   "step limit reached",
	CodeApproval:    "waiting for approval",
	CodeAbort:       "run aborted",
	CodeCancelled:   "run interrupted",
	CodePlanOnly:    "plan-only mode",
	CodeIdle:        "no runnable tasks",
	CodeOperator:    "stopped by operator",
	CodeStale:       "previous run ended unexpectedly",
}

// Known reports whether c is a code this package defines. The persistence
// layer uses it to drop garbage rather than surface a code the UI cannot
// render.
func Known(c Code) bool {
	_, ok := codeLabels[c]
	return ok
}

// Codes returns every defined code. Order is stable so tests and generated
// documentation do not churn.
func Codes() []Code {
	return []Code{
		CodeUsageCap, CodeBudget, CodeTokenBudget, CodeStepLimit,
		CodeApproval, CodeAbort, CodeCancelled, CodePlanOnly,
		CodeIdle, CodeOperator, CodeStale,
	}
}

// Reason is the structured explanation persisted alongside Status.
type Reason struct {
	// Code is the machine-readable category. Always set.
	Code Code `json:"code"`
	// Detail is one operator-facing sentence fragment naming the specific
	// cause — "5-hour cap reached", "daily budget of $20 spent". It is
	// prose for a human; never switch on it.
	Detail string `json:"detail,omitempty"`
	// ResumesAt is when the condition lifts on its own, for the pauses where
	// that instant is actually known. Only CodeUsageCap sets it today: the
	// OAuth usage API reports each window's reset, so the hub can resume
	// without a human. Nil means "nobody knows; a human decides".
	ResumesAt *time.Time `json:"resumes_at,omitempty"`
}

// New builds a Reason with no known resume time.
func New(code Code, detail string) Reason {
	return Reason{Code: code, Detail: strings.TrimSpace(detail)}
}

// NewUntil builds a Reason that lifts by itself at resumesAt. A zero time is
// treated as unknown, so callers may pass a reset time straight through
// without first checking whether the provider supplied one.
func NewUntil(code Code, detail string, resumesAt time.Time) Reason {
	r := New(code, detail)
	if !resumesAt.IsZero() {
		t := resumesAt.UTC()
		r.ResumesAt = &t
	}
	return r
}

// Label is the human detail, falling back to the code's own noun when the
// caller supplied none.
func (r *Reason) Label() string {
	if r == nil {
		return ""
	}
	if d := strings.TrimSpace(r.Detail); d != "" {
		return d
	}
	if l, ok := codeLabels[r.Code]; ok {
		return l
	}
	return string(r.Code)
}

// Summary renders the one-line form the CLI and logs use:
//
//	5-hour cap reached, resumes 14:50
//
// The clock is rendered in loc so a terminal shows the operator's own wall
// time. The Web UI does its own formatting from ResumesAt instead, because
// only the browser knows the reader's timezone.
func (r *Reason) Summary(loc *time.Location) string {
	if r == nil {
		return ""
	}
	label := r.Label()
	if r.ResumesAt == nil {
		return label
	}
	if loc == nil {
		loc = time.UTC
	}
	return fmt.Sprintf("%s, resumes %s", label, r.ResumesAt.In(loc).Format("15:04"))
}

// AutoResumable reports whether this pause has cleared by now and can be
// restarted without asking a human.
//
// Only CodeUsageCap qualifies. Every other code either needs a decision (a
// declined approval, a raised budget) or describes a run that was not meant
// to continue at all (plan-only, operator stop) — resuming those on a timer
// would override the very intent that stopped them.
func (r *Reason) AutoResumable(now time.Time) bool {
	if r == nil || r.Code != CodeUsageCap || r.ResumesAt == nil {
		return false
	}
	return !now.Before(*r.ResumesAt)
}

// Normalize returns the reason that should be stored against a run in the
// given status, or nil when none should be.
//
// It enforces the invariant that a pause reason exists only for a paused run.
// Persisting it at exactly one funnel — rather than expecting ~26 call sites
// to clear the field on the way out of "paused" — is what keeps a resumed run
// from still claiming it is waiting on a cap that lifted hours ago.
func Normalize(status string, r *Reason) *Reason {
	if r == nil || status != "paused" || !Known(r.Code) {
		return nil
	}
	out := *r
	out.Detail = strings.TrimSpace(out.Detail)
	if out.ResumesAt != nil {
		t := out.ResumesAt.UTC()
		out.ResumesAt = &t
	}
	return &out
}
