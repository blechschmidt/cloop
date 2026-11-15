package projectmove

// move.go is the move itself (Task 20494): a durable state machine, journalled
// one row per move in the control plane's project_moves table, that takes a
// project from the executor it is bound to onto another without losing what
// the old side holds.
//
//	preflight → quiesce → capture → switch → seed → verify → done
//	                                         └──────┴──→ rolled_back
//	(any phase before switch) ──→ failed
//
//   - preflight: Preflight with the move's own options. A blocked report ends
//     the move as failed, its blockers named.
//   - quiesce: the project's run (and its features') is stopped the way Stop
//     stops it — the task it was on goes back to pending, so the next run picks
//     it up — and a run waiting in a pool's queue leaves it. While the move is
//     open, no run of the project may start: the hub refuses every dispatch.
//   - capture: the source's repository into a bundle (movegit), its .cloop
//     files into a tar, both in the hub's move store, bounded in size and
//     checked against the disk floor before anything is written.
//   - switch: the binding, and the path-keyed rows a binding change writes,
//     in one transaction with the move's own phase.
//   - seed: the target is given the bundle — through the branch-bundle
//     workspace an isolating executor receives a feature with — and rebuilds
//     the working copy from it, the uncommitted state put back as uncommitted
//     changes on the original branch. A target working in the hub's own tree
//     needs nothing; one that builds its tree from the forge needs everything
//     to be there already, which capture checked.
//   - verify: the target is read back and compared with what was captured:
//     each branch's commit and tree, the snapshot, the index and the working
//     tree, and every delivered file's digest. Only a verified move is done.
//
// A failure before switch leaves the binding as it was, and the move failed.
// A failure after it rolls the binding back — in one transaction with the
// move's phase again — and keeps the bundle. The source is never deleted: a
// done move records it as retained, with the command that cleans up what the
// move kept.
//
// Every write is a compare-and-swap on the move's (phase, version), and every
// phase can be run again: a hub that stops anywhere leaves the row naming the
// phase to run next, and the member that takes the move's lease next (pkg/ui
// holds one per move, through pkg/hublease) runs it from there.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor/movegit"
)

// Phase is where a move is.
type Phase string

// The phases, in order, and the three a move ends in.
const (
	PhasePreflight  Phase = "preflight"
	PhaseQuiesce    Phase = "quiesce"
	PhaseCapture    Phase = "capture"
	PhaseSwitch     Phase = "switch"
	PhaseSeed       Phase = "seed"
	PhaseVerify     Phase = "verify"
	PhaseDone       Phase = "done"
	PhaseFailed     Phase = "failed"
	PhaseRolledBack Phase = "rolled_back"
)

// Phases lists the open phases in order.
var Phases = []Phase{PhasePreflight, PhaseQuiesce, PhaseCapture, PhaseSwitch, PhaseSeed, PhaseVerify}

// Open reports whether a move at p is still in progress.
func (p Phase) Open() bool {
	switch p {
	case PhaseDone, PhaseFailed, PhaseRolledBack:
		return false
	}
	return true
}

// Switched reports whether a move at p has switched the binding: a failure
// from here on rolls it back.
func (p Phase) Switched() bool { return p == PhaseSeed || p == PhaseVerify }

// next is the phase after p on the way to done.
func (p Phase) next() Phase {
	for i, q := range Phases {
		if q == p {
			if i+1 < len(Phases) {
				return Phases[i+1]
			}
			return PhaseDone
		}
	}
	return PhaseDone
}

// valid reports whether p is a phase at all.
func (p Phase) valid() bool {
	if !p.Open() {
		return true
	}
	for _, q := range Phases {
		if q == p {
			return true
		}
	}
	return false
}

// Move is one move, as journalled.
type Move struct {
	ID      string  `json:"id"`
	Project Project `json:"project"`
	// Source and Target are bindings: where the project was bound when the
	// move started ("" for the hub's default executor), and where it goes.
	Source        string    `json:"source"`
	Target        string    `json:"target"`
	Phase         Phase     `json:"phase"`
	FailedPhase   Phase     `json:"failed_phase,omitempty"`
	Error         string    `json:"error,omitempty"`
	AbandonSource bool      `json:"abandon_source,omitempty"`
	StartedBy     string    `json:"started_by,omitempty"`
	Version       int64     `json:"version"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
	FinishedAt    time.Time `json:"finished_at,omitempty"`
	Detail        Detail    `json:"detail"`
}

// Open reports whether the move is still in progress.
func (m Move) Open() bool { return m.Phase.Open() }

// Detail is what the move's phases recorded.
type Detail struct {
	Preflight *PreflightSummary `json:"preflight,omitempty"`
	Quiesce   *QuiesceRecord    `json:"quiesce,omitempty"`
	Capture   *CaptureRecord    `json:"capture,omitempty"`
	Switch    *SwitchRecord     `json:"switch,omitempty"`
	Seed      *SeedRecord       `json:"seed,omitempty"`
	Verify    *VerifyRecord     `json:"verify,omitempty"`
	// Retained is what the move keeps of the source and in its store, and
	// the command that cleans it up.
	Retained *Retained `json:"retained,omitempty"`
	// Rollback is set while a failed switched move is being rolled back.
	Rollback *RollbackRecord `json:"rollback,omitempty"`
	// Timeline is one entry per phase run, in order: a phase run twice — a
	// hub stopped in it — appears twice.
	Timeline []Step `json:"timeline,omitempty"`
	// Starter is the owner key of whoever started the move: a pool hands a
	// runner holding the project's volume only to work started by someone
	// who may read the project (Task 20495).
	Starter string `json:"starter,omitempty"`
}

// PreflightSummary is the preflight the move ran.
type PreflightSummary struct {
	Source   Endpoint         `json:"source"`
	Target   Endpoint         `json:"target"`
	Counts   Counts           `json:"counts"`
	Findings []FindingSummary `json:"findings"`
}

// FindingSummary is one finding, without its particulars.
type FindingSummary struct {
	Kind     Kind     `json:"kind"`
	Severity Severity `json:"severity"`
	Title    string   `json:"title"`
}

// QuiesceRecord is what quiescing did.
type QuiesceRecord struct {
	// Stopped names the runs that were stopped: "the project", "feature x".
	Stopped []string `json:"stopped,omitempty"`
	// Unqueued names the runs taken out of a pool's queue.
	Unqueued []string `json:"unqueued,omitempty"`
	// Requeued are the tasks put back to pending, by who: "the project #12".
	Requeued []string `json:"requeued,omitempty"`
}

// Delivery modes: how the target receives what was captured.
const (
	// DeliverSameTree: the target works in the hub's own tree, the source's.
	DeliverSameTree = "same_tree"
	// DeliverDevice: the target keeps a working copy the seed builds.
	DeliverDevice = "device"
	// DeliverForge: the target builds every run's tree from the forge.
	DeliverForge = "forge"
	// DeliverNothing: the source was abandoned, or holds nothing to carry.
	DeliverNothing = "nothing"
	// DeliverHubTree: the source was a device's working copy, or a pool
	// runner's volume, and the target works in the hub's own directory for
	// the project, which the seed builds from the capture (Task 20495).
	DeliverHubTree = "hub_tree"
	// DeliverSameDevice: the source and the target are one device — a device
	// and its virtual executors keep one working copy — so nothing moves.
	DeliverSameDevice = "same_device"
)

// CaptureRecord is what capture wrote.
type CaptureRecord struct {
	// Store is the move's directory in the hub's move store.
	Store string `json:"store"`
	// Delivery is how the target receives it; see the Deliver constants.
	Delivery string `json:"delivery"`
	// Git is the repository's manifest; Repository false for a project
	// with no repository, or when nothing was captured.
	Git movegit.Manifest `json:"git"`
	// Bundle is the bundle's file name in Store ("" when none was written).
	Bundle string `json:"bundle,omitempty"`
	// Files are the .cloop files the move delivers, and FilesTar the tar in
	// Store that holds them.
	Files    []File          `json:"files,omitempty"`
	FilesTar string          `json:"files_tar,omitempty"`
	TarSum   *movegit.Digest `json:"files_tar_digest,omitempty"`
	// KeptOnHub are the .cloop files that stay in the hub's copy of the
	// project and are not delivered: its configuration (which can hold
	// credentials), the attachment store, anything else.
	KeptOnHub []Item `json:"kept_on_hub,omitempty"`
	// Bytes is what the store holds for the move.
	Bytes int64 `json:"bytes"`
	// Abandoned reports that nothing was captured: the move abandons its
	// source.
	Abandoned bool `json:"abandoned,omitempty"`
	// Notes say what the capture could not keep exactly.
	Notes []string `json:"notes,omitempty"`
	// From says where the capture was taken: "hub" for the hub's own tree,
	// "device <id>", or "runner <id> of pool <id>" (Task 20495).
	From string `json:"from,omitempty"`
	// WorkDir is where the source's working copy is, when it is not the
	// hub's tree: on the device, or on the runner's volume.
	WorkDir string `json:"work_dir,omitempty"`
	// Scan is what the capture taken from a device was scanned for, and what
	// the scan found.
	Scan *ScanRecord `json:"scan,omitempty"`
}

// ScanRecord is how a capture from a device was scanned for the credentials
// the project's runs are given (Task 20495). It names no value.
type ScanRecord struct {
	// Grants is how many of the project's grants reach the source; Values
	// how many values they deliver, each matched in its common encodings.
	Grants int `json:"grants"`
	Values int `json:"values"`
	// Mode is the scan's mode: values, or shapes as well.
	Mode string `json:"mode"`
	// Result is the bundle's and the files' scan result: clean, secret,
	// limit or unreadable.
	Result string `json:"result"`
}

// SwitchRecord is what the switch changed, for a rollback to change back.
type SwitchRecord struct {
	// PreviousBinding is the binding the switch replaced ("" for none).
	PreviousBinding string `json:"previous_binding"`
	// PreviousFirewall is the project's stored firewall rule set before the
	// switch — which narrows it to fit the target, as a bind does — so a
	// rollback can put it back; nil when the project had none.
	PreviousFirewall json.RawMessage `json:"previous_firewall,omitempty"`
	At               time.Time       `json:"at"`
}

// SeedRecord is how the target was seeded.
type SeedRecord struct {
	Delivery string `json:"delivery"`
	// Executor is the executor the seed ran on; WorkDir the working copy it
	// built there.
	Executor string `json:"executor,omitempty"`
	WorkDir  string `json:"work_dir,omitempty"`
	// Bytes is what was shipped.
	Bytes int64  `json:"bytes,omitempty"`
	Note  string `json:"note,omitempty"`
}

// VerifyRecord is what verification compared.
type VerifyRecord struct {
	Delivery string `json:"delivery"`
	// Checked counts the refs, trees and files compared.
	Checked int `json:"checked"`
	// Mismatches are what differed; a verified move has none.
	Mismatches []string `json:"mismatches,omitempty"`
}

// Retained is what a move keeps after it.
type Retained struct {
	// Source says where the source's copy is and what it still holds.
	Source string `json:"source"`
	// Store is the move's directory in the hub's move store: the bundle and
	// the files, kept until cleanup.
	Store string `json:"store,omitempty"`
	// Refs are the hidden refs the capture wrote into the source repository.
	Refs []string `json:"refs,omitempty"`
	// Command cleans up what the move kept.
	Command   string    `json:"command"`
	CleanedAt time.Time `json:"cleaned_at,omitempty"`
	CleanedBy string    `json:"cleaned_by,omitempty"`
	// SourceRemovedAt is when cleanup removed the copy of the project the
	// source kept apart from the hub — a device's working copy — which it
	// does only for a verified move, and only once the person cleaning up
	// confirmed it (Task 20496). Zero while that copy is kept.
	SourceRemovedAt time.Time `json:"source_removed_at,omitempty"`
	// SourceRemoved names where that copy was: "<executor> at <dir>".
	SourceRemoved string `json:"source_removed,omitempty"`
	// SourceKept reports a cleanup asked to leave that copy where it is.
	SourceKept bool `json:"source_kept,omitempty"`
}

// RollbackRecord is a rollback in progress, or done.
type RollbackRecord struct {
	Pending     bool      `json:"pending"`
	FailedPhase Phase     `json:"failed_phase"`
	Reason      string    `json:"reason"`
	At          time.Time `json:"at"`
}

// Step is one run of one phase.
type Step struct {
	Phase   Phase     `json:"phase"`
	Started time.Time `json:"started"`
	Ended   time.Time `json:"ended,omitempty"`
	Member  string    `json:"member,omitempty"`
	Error   string    `json:"error,omitempty"`
}

// File is one .cloop file a move delivers.
type File struct {
	// Path is relative to .cloop, slash-separated.
	Path   string `json:"path"`
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
	Mode   uint32 `json:"mode"`
}

// NewMoveID mints a move's identifier: 16 hex digits, which also names its
// hidden ref and its store directory.
func NewMoveID() (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("projectmove: mint a move id: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

// Errors a move's callers distinguish.
var (
	// ErrMoveOpen refuses a second move of a project with one in progress.
	ErrMoveOpen = errors.New("projectmove: the project already has a move in progress")
	// ErrChanged reports the move changed under a write: another hub process
	// owns it now, and this one stops driving it.
	ErrChanged = errors.New("projectmove: the move changed under this process")
	// ErrNotFound is a move id with no move.
	ErrNotFound = errors.New("projectmove: no such move")
	// ErrStillOpen refuses to clean up after a move that has not ended.
	ErrStillOpen = errors.New("projectmove: the move has not ended")
)

// BlockedError is a move refused by its preflight.
type BlockedError struct {
	Report *Report
}

func (e *BlockedError) Error() string {
	var titles []string
	for _, f := range e.Report.Findings {
		if f.Severity == SeverityBlocker {
			titles = append(titles, f.Title)
		}
	}
	return "projectmove: the preflight blocks the move: " + strings.Join(titles, "; ")
}

// summarize keeps what a move records of its preflight.
func summarize(r *Report) *PreflightSummary {
	s := &PreflightSummary{Source: r.Source, Target: r.Target, Counts: r.Counts, Findings: []FindingSummary{}}
	for _, f := range r.Findings {
		s.Findings = append(s.Findings, FindingSummary{Kind: f.Kind, Severity: f.Severity, Title: f.Title})
	}
	return s
}

// clone deep-copies a move through JSON, so a phase handler can change its
// copy without touching the one the engine compares against.
func (m Move) clone() Move {
	b, err := json.Marshal(m)
	if err != nil {
		return m
	}
	var out Move
	if err := json.Unmarshal(b, &out); err != nil {
		return m
	}
	return out
}

// DescribeTarget renders a binding for a sentence.
func DescribeTarget(binding string) string {
	switch {
	case binding == "":
		return "the hub's default executor"
	case strings.HasPrefix(binding, "pool:"):
		return "executor pool " + strings.TrimPrefix(binding, "pool:")
	default:
		return "executor " + binding
	}
}

// contextErr distinguishes the engine being told to stop from a phase that
// failed.
func contextErr(ctx context.Context) error { return ctx.Err() }
