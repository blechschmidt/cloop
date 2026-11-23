package projectseed

// result.go is the return half of a seeded dispatch (Task 20339).
//
// A seed carries the project to an executor that cannot read the hub's
// filesystem. Until this file nothing carried it back. `cloop run` on the
// device executed the plan, recorded each outcome in the database the seed had
// just become, and exited — and the hub, whose own database is the one the
// dashboard renders, still had every task pending. From the operator's side a
// run started, streamed a transcript ending "All tasks complete", and stopped
// with the task it had just finished still waiting in the queue. Starting it
// again ran the task again; the second time the agent found its own work
// already pushed and skipped it, and the hub still showed it pending.
//
// So once the workload has exited, the device reads back what the run changed
// (Harvest) and the hub folds it into its own copy of the project (merge.go).
//
// # What travels
//
// Only what the run changed, measured against the seed the device was sent:
// every task whose record differs from the seed, with both versions; every task
// the run created; and the run's steps, journal events and cost rows. Those
// last three are new by construction — a seed carries none of them and the
// previous dispatch's database is removed before the run begins (see
// staleDatabaseFiles) — so the device sends all it finds. A 500-task plan in
// which one task finished returns one task.
//
// # Why read the database rather than have `cloop run` report
//
// The agent reads what the run left behind instead of trusting the run to say
// what it did, for two reasons. A run killed half way — the OOM killer, a stop
// from the dashboard — reports nothing, but the tasks it finished before dying
// are in its database and are exactly the work that would otherwise be lost.
// And the harness is not necessarily this build: in container mode it is
// whatever `cloop` the image carries, and the protocol should not depend on it.
//
// # Trust
//
// The document is written on a device the hub does not control, by code reading
// a directory a model-driven workload could write to. The device may not name
// the fields that matter: the hub merges a fixed list of outcome fields and
// ignores the rest, sanitises tasks the run created, and stamps attribution
// from its own dispatch record (see merge.go). This side's job is narrower —
// read nothing outside the workspace, bound everything, and scrub credentials
// before they cross the wire.

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"time"
	"unicode/utf8"

	"github.com/blechschmidt/cloop/pkg/attachments"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/pausereason"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
	"github.com/blechschmidt/cloop/pkg/taskrecover"
)

// ResultFormat is the version of the Result document this build writes.
//
// Readers accept any version at or above 1 and read the fields they know: every
// field is optional, so a later format that adds one is still a valid format-1
// document to an older hub. Changing the meaning of an existing field needs a
// new name, not a new number.
const ResultFormat = 1

// MaxResultInflatedBytes bounds a result after decompression, for the same
// reason MaxDecompressedBytes bounds a seed: a compressed ceiling alone is not
// a bound on what gzip will expand to.
const MaxResultInflatedBytes = 16 << 20 // 16 MiB

// Collection ceilings. A well-behaved run is far below every one of them; they
// exist so that a runaway one — or a device that is lying — produces a refused
// document instead of an unbounded allocation on the hub.
const (
	maxResultTasks  = 10000
	maxResultSteps  = 2000
	maxResultEvents = 2000
	maxResultCosts  = 5000

	// maxStepOutputBytes is how much of one step's output travels. The tail
	// is kept, because that is where a harness prints its verdict and where a
	// failure explains itself.
	maxStepOutputBytes = 32 << 10
	// shrunkStepOutputBytes is the tail kept when a result has to shrink to fit.
	shrunkStepOutputBytes = 2 << 10
	// maxEventMessageBytes and maxEventDetailBytes bound one journal row.
	maxEventMessageBytes = 8 << 10
	maxEventDetailBytes  = 16 << 10

	// maxResultAttachments bounds the files one result describes (Task 20428).
	maxResultAttachments = 200
	// attachmentCarryBytes is the room a result always keeps for the files a
	// run attached, measured by their own bytes, whatever the rest of the
	// result takes: the rest gives way to make it (encodeResult cuts step
	// output and event details before it drops a file). It is the whole of
	// what a result carried until Task 20515.
	//
	// A result also has the room the rest of it leaves free in its frame
	// (executor.MaxProjectResultBytes), and there files are measured as they
	// cost it: base64 in the document, compressed with it (carryCost). Files
	// are carried while they fit either one, so a run's logs and reports —
	// 726 KiB of them, a fifth of which this room alone used to leave in the
	// executor's workspace with the frame half empty — come back whole, and
	// no file pushes out more of the rest than one did before.
	attachmentCarryBytes = 384 << 10
	// resultFrameSlack is left free of files when they take the room the rest
	// of the result leaves: each file's cost is measured on its own, and the
	// document they are compressed into together comes out a little
	// differently.
	resultFrameSlack = 16 << 10
	// maxAttachmentTextBytes bounds an attachment's name, task title and
	// reason as they travel.
	maxAttachmentTextBytes = 4 << 10
)

// maxWastedCarryBytes bounds the bytes carryAttachments reads, scrubs and
// compresses of files that then do not fit. Past it, a file that could fit the
// room left for files only by shrinking more than likelyBestRatio-fold is
// described without being read: a run that attached a hundred logs too large
// for its result does not hold its outcome back while each is compressed to
// find out. A variable so a test need not read megabytes to reach it.
var maxWastedCarryBytes int64 = 24 << 20

// likelyBestRatio is how far, past maxWastedCarryBytes, a file is still
// assumed to shrink in the frame: logs and text rarely do better than this,
// so a file it rules out would very likely not have fit.
const likelyBestRatio = 8

// attachmentCarryRawBytes bounds the files a result carries by their own
// bytes. The hub inflates a result under MaxResultInflatedBytes, where base64
// makes each byte a third larger, and a log that compresses a hundredfold costs
// the frame almost nothing; this keeps such files from filling the inflated
// document, and bounds what the device reads. A variable so a test need not
// compress megabytes to reach it.
var attachmentCarryRawBytes int64 = 8 << 20

// resultInflatedLimit is what encodeResult keeps a result under once
// inflated: MaxResultInflatedBytes, which the hub refuses a document past.
// A variable for the same reason.
var resultInflatedLimit int64 = MaxResultInflatedBytes

// ErrNoSeed reports that a workload was started without a seed. Such a
// workload read its project from somewhere the hub can see (a bind mount), or
// had none; either way there is no dispatch-time copy to measure a change
// against, and nothing to send back.
var ErrNoSeed = errors.New("projectseed: the workload was not sent a project, so there is none to read back")

// Result is what a seeded run changed, as the device reports it.
type Result struct {
	// Format is the document version; see ResultFormat.
	Format int `json:"format"`
	// BaseStep is the step counter the run started from — the seed's
	// CurrentStep. Informational: the hub numbers the run's steps after its
	// own history whatever this says, because its history may have grown
	// while the run was out.
	BaseStep int `json:"base_step"`
	// Status is the project status the run left behind ("complete",
	// "paused", "failed", ...).
	Status string `json:"status,omitempty"`
	// PauseReason explains a "paused" Status, including when a usage cap
	// lifts — which is what lets the hub's auto-resume pick the run back up.
	PauseReason *pausereason.Reason `json:"pause_reason,omitempty"`
	// InputTokens, OutputTokens and EvolveSteps are what the run *added*,
	// rather than the device's totals: the hub's own totals may have moved
	// while the run was out, and adding a delta is correct either way.
	InputTokens  int `json:"input_tokens,omitempty"`
	OutputTokens int `json:"output_tokens,omitempty"`
	EvolveSteps  int `json:"evolve_steps,omitempty"`
	// Tasks are the tasks the run changed or created.
	Tasks []TaskChange `json:"tasks,omitempty"`
	// Steps are the steps the run recorded, in order.
	Steps []state.StepResult `json:"steps,omitempty"`
	// Events are the journal rows the run wrote, oldest first.
	Events []Event `json:"events,omitempty"`
	// Costs are the cost rows the run recorded.
	Costs []Cost `json:"costs,omitempty"`
	// Attachments are the files the run attached to tasks (Task 20428), with
	// their bytes when the result had room for them.
	Attachments []Attachment `json:"attachments,omitempty"`
	// Omitted says what the device left out to fit the transport, one
	// sentence each, so the hub can say so instead of presenting a partial
	// history as a whole one.
	Omitted []string `json:"omitted,omitempty"`
	// Interim marks a progress report — the plan as it stood while the run
	// was still going (Task 50) — rather than the run's outcome. It carries
	// Tasks and the token deltas and nothing else: no steps, no journal, no
	// spend rows, no attachments, no status. The hub renders one
	// live and merges one only if the run ends without an outcome, so a
	// document that may be superseded a few seconds later stays cheap to
	// produce and cheap to send.
	Interim bool `json:"interim,omitempty"`
}

// TaskChange is one task the run touched.
type TaskChange struct {
	// Before is the task as the seed had it; nil when the run created it.
	//
	// It travels so the hub can tell its own edits from the run's: a field
	// the hub changed while the run was out no longer matches Before, and the
	// hub's value is kept. It is the device's claim, and the hub treats it as
	// one — see merge.go.
	Before *pm.Task `json:"before,omitempty"`
	// After is the task as the run left it.
	After *pm.Task `json:"after"`
}

// Event is one journal row, in a form that survives JSON: statedb.EventRow has
// no tags and an ID that means nothing on another database.
type Event struct {
	Timestamp time.Time `json:"timestamp"`
	Type      string    `json:"type"`
	TaskID    int       `json:"task_id,omitempty"`
	TaskTitle string    `json:"task_title,omitempty"`
	Step      int       `json:"step"`
	Message   string    `json:"message,omitempty"`
	Details   string    `json:"details,omitempty"`
}

// Attachment is one file the run attached to a task (Task 20428).
//
// Data is the file — scrubbed like every other field — when the result had
// room for it, and empty otherwise, with Left saying why: the hub records the
// attachment either way, so a person looking at the task learns the file
// exists and where it is. Size and SHA256 describe Data when it travels, and
// are the device's account of the file when it does not; the hub checks the
// one and only reports the other.
type Attachment struct {
	// ID is the id the run gave the attachment in its own copy of the
	// project (Task 20513), and the id the hub records it under: a file the
	// run also sent the hub while it ran is then one attachment, however
	// many ways it arrived. Empty from a device whose cloop predates it,
	// which the hub gives a fresh id.
	ID     string `json:"id,omitempty"`
	TaskID int    `json:"task_id"`
	// TaskTitle is the title the task had in the seed — or, for a task the
	// run created, as it left it. The hub attaches the file only to the task
	// the run worked on: one the hub deleted or retitled while the run was
	// out, and whose id now belongs to another, does not get it.
	TaskTitle string    `json:"task_title,omitempty"`
	Name      string    `json:"name"`
	Size      int64     `json:"size"`
	SHA256    string    `json:"sha256,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	Data      []byte    `json:"data,omitempty"`
	Left      string    `json:"left,omitempty"`
	// Sent says the run sent the file to the hub while it ran (Task 20513),
	// so its bytes do not travel here: the hub attached it, or holds it for
	// this merge. It is the run's word, and the hub believes it only as far
	// as finding the file under ID.
	Sent bool `json:"sent,omitempty"`

	// cost is what Data takes in the compressed result, as carryCost
	// measured it: what encodeResult frees by dropping the file. Never
	// encoded.
	cost int64
}

// Cost is one cost-ledger row. It carries no identity: who pays for a run is
// decided by the hub that dispatched it, never by the device that ran it.
type Cost struct {
	Timestamp      time.Time `json:"timestamp"`
	TaskID         int       `json:"task_id,omitempty"`
	TaskTitle      string    `json:"task_title,omitempty"`
	Provider       string    `json:"provider,omitempty"`
	Model          string    `json:"model,omitempty"`
	InputTokens    int       `json:"input_tokens,omitempty"`
	OutputTokens   int       `json:"output_tokens,omitempty"`
	ThinkingTokens int       `json:"thinking_tokens,omitempty"`
	EstimatedUSD   float64   `json:"estimated_usd,omitempty"`
}

// Harvest reads back what a seeded run left in dir and returns it as the
// compressed bytes of a Result.
//
// dir is the workload's working directory — the one Write placed the seed in —
// and seed is the exact payload the workload was started with; the change is
// measured against it. scrub, when non-nil, is applied to every free-text field
// before anything is encoded, so a credential the workload printed does not
// cross the wire.
//
// Nothing outside dir/.cloop is read. A `.cloop` or database file that the
// workload replaced with a symbolic link is refused rather than followed: the
// agent may be able to read files the workload cannot, and a link is how a
// workload would ask it to.
func Harvest(dir string, seed []byte, scrub func(string) string) ([]byte, error) {
	return harvest(dir, seed, scrub, false)
}

// HarvestProgress reads back the plan of a seeded run that is *still running*
// (Task 50) and returns a document marked Interim.
//
// The hub renders it over its own copy of the project, so the operator sees
// the work a run on another machine is going through — which for a project
// whose tasks the run plans itself is the only way those tasks can be seen
// before the run ends — and merges it if the run ends without ever sending
// its outcome, which is how a lost run's plan survives the loss.
//
// It is deliberately much less than Harvest. Only the tasks and the token
// deltas travel: a progress report is produced every few seconds while the
// harness holds the database, so it reads the plan and nothing else — no
// journal, no steps, no spend rows, no attachments, no verdict sidecars. And
// it claims nothing about how the run ended, because it has not.
func HarvestProgress(dir string, seed []byte, scrub func(string) string) ([]byte, error) {
	return harvest(dir, seed, scrub, true)
}

func harvest(dir string, seed []byte, scrub func(string) string, interim bool) ([]byte, error) {
	if len(seed) == 0 {
		return nil, ErrNoSeed
	}
	if scrub == nil {
		scrub = func(s string) string { return s }
	}
	base, err := decodeSeed(seed)
	if err != nil {
		return nil, err
	}
	r, err := collect(dir, base, scrub, interim)
	if err != nil {
		return nil, err
	}
	return encodeResult(r)
}

// decodeSeed turns a seed back into the project it was built from.
func decodeSeed(seed []byte) (*state.ProjectState, error) {
	if err := executor.ValidateProjectSeed(seed); err != nil {
		return nil, err
	}
	raw, err := inflate(seed)
	if err != nil {
		return nil, err
	}
	var st state.ProjectState
	if err := json.Unmarshal(raw, &st); err != nil {
		return nil, fmt.Errorf("projectseed: the seed this workload was started with is not a project: %w", err)
	}
	return &st, nil
}

// collect builds the Result for the project the run left in dir. With interim
// set it builds a progress report instead: the plan, and nothing that costs a
// second read of the database the run is still writing. See HarvestProgress.
func collect(dir string, base *state.ProjectState, scrub func(string) string, interim bool) (*Result, error) {
	dbPath, err := workspaceDB(dir)
	if err != nil {
		return nil, err
	}

	r := &Result{Format: ResultFormat, BaseStep: base.CurrentStep, Interim: interim}

	after, err := state.LoadDatabase(dbPath)
	if errors.Is(err, statedb.ErrProjectNotFound) {
		// The run never opened its project — it failed before that, or it
		// was not `cloop run` at all. Nothing changed, and saying so is a
		// result: the hub learns the run came back empty rather than that it
		// did not come back.
		return r, nil
	}
	if err != nil {
		return nil, fmt.Errorf("projectseed: read the project the run left in %s: %w", dbPath, err)
	}

	r.InputTokens = nonNegative(after.TotalInputTokens - base.TotalInputTokens)
	r.OutputTokens = nonNegative(after.TotalOutputTokens - base.TotalOutputTokens)
	r.EvolveSteps = nonNegative(after.EvolveStep - base.EvolveStep)

	if interim {
		// A progress report stops here (Task 50). Everything below is an
		// account of a run that has ended — the verdict of a task the
		// orchestrator decided but could not store, the status the run left
		// the project in, its journal, its spend, its attached files — and a
		// run still going will give all of it when it does end.
		r.Tasks = diffTasks(base.Plan, after.Plan, scrub)
		if len(r.Tasks) > maxResultTasks {
			return nil, fmt.Errorf("projectseed: the run has %d changed tasks, more than the %d a result may carry",
				len(r.Tasks), maxResultTasks)
		}
		return r, nil
	}

	// A run that died — or stopped because its own outcome write failed —
	// after the orchestrator had decided a task leaves that decision in the
	// task's verdict sidecar, not in the database (Task 20365). Apply it here,
	// so the hub hears the decision rather than "still in progress"; without
	// the device's live artifact, the hub's own recovery could only re-queue
	// the task, and a rejected one would run again as if nothing had been
	// decided. Only verdicts are read: what the orchestrator had not decided
	// stays in progress for the hub to settle, as before.
	settled := taskrecover.SettleFromVerdicts(dir, after.Plan)

	r.Status = after.Status
	if after.PauseReason != nil {
		pr := *after.PauseReason
		pr.Detail = scrub(pr.Detail)
		r.PauseReason = &pr
	}
	r.Tasks = diffTasks(base.Plan, after.Plan, scrub)
	if len(r.Tasks) > maxResultTasks {
		return nil, fmt.Errorf("projectseed: the run left %d changed tasks, more than the %d a result may carry",
			len(r.Tasks), maxResultTasks)
	}
	r.Steps, r.Omitted = runSteps(after.Steps, base.CurrentStep, scrub, r.Omitted)

	events, costs, notes, err := journal(dbPath, scrub)
	if err != nil {
		return nil, err
	}
	r.Events, r.Costs = append(events, settledEvents(settled, scrub)...), costs
	if n := len(r.Events) - maxResultEvents; n > 0 {
		r.Events = r.Events[n:]
		notes = append(notes, fmt.Sprintf("%d more of the run's oldest journal events were left on the "+
			"executor to make room for its recoveries", n))
	}
	r.Omitted = append(r.Omitted, notes...)
	free, err := freeRoom(r)
	if err != nil {
		return nil, err
	}
	r.Attachments, notes, err = carryAttachments(dbPath, base.Plan, after.Plan, scrub, free)
	if err != nil {
		return nil, err
	}
	r.Omitted = append(r.Omitted, notes...)
	return r, nil
}

// workspaceDB returns the path of the database the run left in dir, once dir's
// .cloop is a real directory and none of the database's files is a link: the
// workload could have replaced any of them, and whoever reads them here may be
// able to read what the workload cannot.
func workspaceDB(dir string) (string, error) {
	cloopDir := filepath.Join(dir, seedDir)
	info, err := os.Lstat(cloopDir)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return "", fmt.Errorf("projectseed: %s is gone — the workload removed the project it was sent, "+
			"so there is nothing to read back", cloopDir)
	case err != nil:
		return "", fmt.Errorf("projectseed: inspect %s: %w", cloopDir, err)
	case info.Mode()&os.ModeSymlink != 0:
		return "", fmt.Errorf("projectseed: %s was replaced by a symbolic link; refusing to follow it "+
			"out of the workspace", cloopDir)
	case !info.IsDir():
		return "", fmt.Errorf("projectseed: %s is not a directory", cloopDir)
	}
	for _, name := range staleDatabaseFiles {
		p := filepath.Join(cloopDir, name)
		if li, err := os.Lstat(p); err == nil && li.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("projectseed: %s is a symbolic link; refusing to read the project through it", p)
		}
	}
	return filepath.Join(cloopDir, "state.db"), nil
}

// freeRoom is the room r's frame has left for files once the rest of the
// result is in it, compressed: what files may take without anything else
// giving way.
func freeRoom(r *Result) (int64, error) {
	out, _, err := encode(r)
	if err != nil {
		return 0, err
	}
	return max(int64(executor.MaxProjectResultBytes-len(out)-resultFrameSlack), 0), nil
}

// carryAttachments reads the files the run attached, in the order they were
// attached, and carries each one while the files carried so far, it included,
// fit either room a result has for them: free, the room the rest of the result
// leaves, measured as each file costs the compressed frame (carryCost); or
// attachmentCarryBytes of their own bytes, which the rest gives way to.
// attachmentCarryRawBytes bounds them all by their own bytes. The rest travel
// as a description.
//
// Every file is read through attachments.Open, rooted at the store beside
// dbPath: one the workload replaced with a link, or with anything but a plain
// file, is described as such rather than read. The agent reading this runs
// outside the workload's sandbox and may be able to read what the workload
// cannot.
func carryAttachments(dbPath string, base, after *pm.Plan, scrub func(string) string, free int64) ([]Attachment, []string, error) {
	db, err := statedb.Open(dbPath)
	if err != nil {
		return nil, nil, fmt.Errorf("projectseed: open %s to read the run's attachments: %w", dbPath, err)
	}
	rows, err := db.AllTaskAttachments()
	db.Close()
	if err != nil {
		return nil, nil, fmt.Errorf("projectseed: read the run's attachments: %w", err)
	}
	// Only what the run attached as results. A task's input files are the
	// hub's to begin with (Task 20511): the run fetched its copies from there,
	// and a row of one in the sandbox's database — none is written there, but
	// the workload can write that database — is not something to send back.
	kept := rows[:0]
	for _, row := range rows {
		if row.Role == statedb.AttachmentRoleResult {
			kept = append(kept, row)
		}
	}
	rows = kept
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].CreatedAt.Before(rows[j].CreatedAt) })
	var notes []string
	if n := len(rows) - maxResultAttachments; n > 0 {
		notes = append(notes, fmt.Sprintf("the run attached %d files; the newest %d were left in the executor's workspace",
			len(rows), n))
		rows = rows[:maxResultAttachments]
	}
	title := func(id int) string {
		for _, p := range []*pm.Plan{base, after} {
			if p == nil {
				continue
			}
			if t := p.TaskByID(id); t != nil {
				return t.Title
			}
		}
		return ""
	}
	// Each room is charged for every file carried, so whichever is still
	// not overdrawn is one the files carried so far fit.
	floor, raw := int64(attachmentCarryBytes), attachmentCarryRawBytes
	var wasted int64
	out := make([]Attachment, 0, len(rows))
	for _, row := range rows {
		a := Attachment{ID: row.ID, TaskID: row.TaskID, TaskTitle: scrub(title(row.TaskID)), Name: scrub(row.Name),
			Size: min(max(row.Size, 0), attachments.MaxFileBytes), SHA256: row.SHA256, CreatedAt: row.CreatedAt}
		switch {
		case attachments.WasSent(dbPath, row.ID):
			// On the hub already (Task 20513): described, so the hub can
			// tell it from a file it never got, and not carried.
			a.Sent = true
		case row.Unavailable != "":
			a.Left = scrub(row.Unavailable)
		case row.Size > raw:
			a.Left = rawLeft(row.Size)
		case row.Size > floor && free <= 0:
			// Past the room kept for files, with none left in the frame.
			a.Left = noRoomLeft(row.Size)
		case row.Size > floor && wasted >= maxWastedCarryBytes && row.Size > free*likelyBestRatio:
			// Too much read already of files that did not fit, and this one
			// would fit only by shrinking more than files do.
			a.Left = fmt.Sprintf("left in the executor's workspace: at %s it is too large for the room the run's "+
				"result had left for files", attachments.HumanBytes(row.Size))
		default:
			data, err := readAttachment(dbPath, row)
			if err != nil {
				a.Left = "left in the executor's workspace: " + scrub(err.Error())
				break
			}
			// Scrubbed like any text the run produced; the size, digest and
			// cost are of what is sent.
			data = []byte(scrub(string(data)))
			size := int64(len(data))
			var cost int64
			fits := false
			if free > 0 {
				cost, fits = carryCost(data, free)
			}
			switch {
			case size > raw:
				a.Left = rawLeft(size)
			case fits:
			case size <= floor:
				cost, _ = carryCost(data, math.MaxInt64)
				fits = true
			default:
				a.Left = noRoomLeft(size)
			}
			if !fits || size > raw {
				wasted += size
				break
			}
			sum := sha256.Sum256(data)
			a.Data, a.Size, a.SHA256, a.cost = data, size, hex.EncodeToString(sum[:]), cost
			free -= cost
			floor -= size
			raw -= size
		}
		out = append(out, a)
	}
	return out, notes, nil
}

// noRoomLeft is the reason a file of size bytes is not carried: neither room
// a result has for files had enough of it left.
func noRoomLeft(size int64) string {
	return fmt.Sprintf("left in the executor's workspace: at %s it did not fit in what the run's result had "+
		"left for files", attachments.HumanBytes(size))
}

// rawLeft is the reason a file of size bytes is not carried: the files a
// result already carries leave less than that of attachmentCarryRawBytes.
func rawLeft(size int64) string {
	return fmt.Sprintf("left in the executor's workspace: at %s it did not fit in what is left of the %s "+
		"of files a run's result carries", attachments.HumanBytes(size), attachments.HumanBytes(attachmentCarryRawBytes))
}

// carryCost reports what data costs a result's frame — its base64, as the
// document holds it, compressed as encodeResult compresses the document — and
// whether that is within limit. It stops once the cost passes limit, so a
// large file that cannot fit costs little to find out about.
func carryCost(data []byte, limit int64) (int64, bool) {
	cw := &countingWriter{limit: limit}
	zw, err := gzip.NewWriterLevel(cw, gzip.BestCompression)
	if err != nil {
		return 0, false
	}
	enc := base64.NewEncoder(base64.StdEncoding, zw)
	_, err = enc.Write(data)
	if err == nil {
		err = enc.Close()
	}
	if err == nil {
		err = zw.Close()
	}
	if err != nil || cw.n > limit {
		return cw.n, false
	}
	return cw.n, true
}

// errPastLimit stops carryCost's compressor once the cost is known to be too
// high.
var errPastLimit = errors.New("past the limit")

// countingWriter counts what is written to it, keeps none of it, and fails
// once the count passes limit.
type countingWriter struct{ n, limit int64 }

func (w *countingWriter) Write(p []byte) (int, error) {
	w.n += int64(len(p))
	if w.n > w.limit {
		return 0, errPastLimit
	}
	return len(p), nil
}

// readAttachment reads one stored attachment of the run, refusing what is not
// a plain file inside dir.
func readAttachment(dbPath string, row statedb.AttachmentRow) ([]byte, error) {
	f, _, err := attachments.Open(dbPath, row)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, row.Size+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) != row.Size {
		return nil, fmt.Errorf("it changed while it was read")
	}
	return data, nil
}

// settledEvents renders the recoveries SettleFromVerdicts made as the journal
// rows a recovery on the hub would have written, newest last.
func settledEvents(settled []taskrecover.Outcome, scrub func(string) string) []Event {
	var out []Event
	for _, oc := range settled {
		row, details, ok := taskrecover.EventFor(oc)
		if !ok {
			continue
		}
		e := Event{
			Timestamp: row.Timestamp,
			Type:      string(row.Type),
			TaskID:    row.TaskID,
			TaskTitle: scrub(row.TaskTitle),
			Step:      row.Step,
			Message:   truncate(scrub(row.Message), maxEventMessageBytes),
		}
		if e.Timestamp.IsZero() {
			e.Timestamp = time.Now()
		}
		if details != nil {
			if b, err := json.Marshal(details); err == nil {
				e.Details = boundDetails(scrub(string(b)))
			}
		}
		out = append(out, e)
	}
	return out
}

// diffTasks returns every task in after that is new or differs from base.
func diffTasks(base, after *pm.Plan, scrub func(string) string) []TaskChange {
	if after == nil {
		return nil
	}
	seeded := make(map[int]*pm.Task)
	if base != nil {
		for _, t := range base.Tasks {
			if t != nil {
				seeded[t.ID] = t
			}
		}
	}
	var out []TaskChange
	for _, t := range after.Tasks {
		if t == nil {
			continue
		}
		b, known := seeded[t.ID]
		if !known {
			out = append(out, TaskChange{After: scrubTask(t, scrub)})
			continue
		}
		if fingerprint(b) == fingerprint(t) {
			continue
		}
		out = append(out, TaskChange{
			Before: forTransit(cloneTask(b)),
			After:  forTransit(scrubTask(t, scrub)),
		})
	}
	return out
}

// forTransit drops what the hub never merges for a task it already has, which
// is also what is large: the description is the operator's text and the hub
// keeps its own, and an artifact path names a file on this device.
func forTransit(t *pm.Task) *pm.Task {
	t.Description = ""
	t.ArtifactPath = ""
	return t
}

// fingerprint renders a task canonically enough that a seed task and the same
// task read back from SQLite compare equal: every timestamp in UTC. The two
// sides otherwise disagree about nothing but the zone a time is printed in.
func fingerprint(t *pm.Task) string {
	c := cloneTask(t)
	utc := func(p *time.Time) *time.Time {
		if p == nil {
			return nil
		}
		v := p.UTC()
		return &v
	}
	c.StartedAt, c.CompletedAt = utc(c.StartedAt), utc(c.CompletedAt)
	c.Deadline, c.NextRunAt = utc(c.Deadline), utc(c.NextRunAt)
	for i := range c.Annotations {
		c.Annotations[i].Timestamp = c.Annotations[i].Timestamp.UTC()
	}
	if c.Background != nil {
		c.Background.DetectedAt = c.Background.DetectedAt.UTC()
	}
	if c.Abort != nil {
		c.Abort.DetectedAt = c.Abort.DetectedAt.UTC()
		c.Abort.ClearedAt = utc(c.Abort.ClearedAt)
	}
	if c.Review != nil {
		c.Review.ReviewedAt = c.Review.ReviewedAt.UTC()
	}
	// Counted by whichever database loads the task: the seed carries the
	// hub's count and the device's database counts its own files, so the two
	// differ without the task having changed. A run's attachments travel as
	// Result.Attachments (Task 20428).
	c.AttachmentCount = 0
	// Joined in by whichever database loads the task from the pool placements
	// the hub records (Task 20486): the seed carries the hub's, and a device's
	// database has none, so a task that ever ran on a pool would read as
	// changed after every remote run without the task having changed.
	c.ExecutorPool, c.ExecutorRunner = "", ""
	b, err := json.Marshal(c)
	if err != nil {
		// Unreachable for a pm.Task; treat as changed, which costs only bytes.
		return fmt.Sprintf("unmarshalable-%p", t)
	}
	return string(b)
}

// cloneTask copies a task deeply enough that editing the copy's slices and
// pointed-to records cannot reach the original.
func cloneTask(t *pm.Task) *pm.Task {
	c := *t
	c.DependsOn = append([]int(nil), t.DependsOn...)
	c.Tags = append([]string(nil), t.Tags...)
	c.Annotations = append([]pm.Annotation(nil), t.Annotations...)
	c.Links = append([]pm.Link(nil), t.Links...)
	c.OnSuccess = append([]string(nil), t.OnSuccess...)
	c.OnFailure = append([]string(nil), t.OnFailure...)
	if t.Background != nil {
		bg := *t.Background
		bg.Commands = append([]string(nil), t.Background.Commands...)
		c.Background = &bg
	}
	if t.Abort != nil {
		ab := *t.Abort
		c.Abort = &ab
	}
	c.Review = t.Review.Clone()
	return &c
}

// scrubTask returns a copy of t with every free-text field passed through scrub.
func scrubTask(t *pm.Task, scrub func(string) string) *pm.Task {
	c := cloneTask(t)
	c.Title = scrub(c.Title)
	c.Description = scrub(c.Description)
	c.Result = scrub(c.Result)
	c.FailureDiagnosis = scrub(c.FailureDiagnosis)
	c.Condition = scrub(c.Condition)
	for i := range c.Annotations {
		c.Annotations[i].Text = scrub(c.Annotations[i].Text)
	}
	for i := range c.Tags {
		c.Tags[i] = scrub(c.Tags[i])
	}
	for i := range c.Links {
		c.Links[i].URL = scrub(c.Links[i].URL)
		c.Links[i].Label = scrub(c.Links[i].Label)
	}
	if c.Background != nil {
		for i := range c.Background.Commands {
			c.Background.Commands[i] = scrub(c.Background.Commands[i])
		}
	}
	if c.Abort != nil {
		c.Abort.Reason = scrub(c.Abort.Reason)
		c.Abort.Evidence = scrub(c.Abort.Evidence)
		c.Abort.ClearedNote = scrub(c.Abort.ClearedNote)
	}
	if c.Review != nil {
		scrubReview(c.Review, scrub)
	}
	return c
}

// scrubReview passes a review record's free text through scrub in place. The
// reviewer quotes the diff it read, and the diff is exactly where a credential
// the agent mishandled would appear.
func scrubReview(r *pm.TaskReview, scrub func(string) string) {
	r.Summary = scrub(r.Summary)
	r.Error = scrub(r.Error)
	for i := range r.Findings {
		f := &r.Findings[i]
		f.File, f.Title, f.Detail = scrub(f.File), scrub(f.Title), scrub(f.Detail)
	}
	for i := range r.Published {
		r.Published[i].Detail = scrub(r.Published[i].Detail)
	}
}

// runSteps returns the steps this run recorded, scrubbed and bounded.
func runSteps(all []state.StepResult, from int, scrub func(string) string, notes []string) ([]state.StepResult, []string) {
	var out []state.StepResult
	for _, st := range all {
		if st.Step < from {
			// A seed carries no steps and the old database was removed, so
			// this is unreachable today. Kept so a future seed that does carry
			// history cannot send it back as though the run had made it.
			continue
		}
		st.Task = scrub(st.Task)
		st.Output = tail(scrub(st.Output), maxStepOutputBytes)
		out = append(out, st)
	}
	if len(out) > maxResultSteps {
		notes = append(notes, fmt.Sprintf("the run recorded %d steps; the first %d were left on the executor",
			len(out), len(out)-maxResultSteps))
		out = out[len(out)-maxResultSteps:]
	}
	return out, notes
}

// journal reads the run's events and cost rows from the database it left.
func journal(dbPath string, scrub func(string) string) ([]Event, []Cost, []string, error) {
	db, err := statedb.Open(dbPath)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("projectseed: open %s to read the run's journal: %w", dbPath, err)
	}
	defer db.Close()

	var notes []string
	rows, total, err := db.ListEvents(0, maxResultEvents)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("projectseed: read the run's events: %w", err)
	}
	if total > len(rows) {
		notes = append(notes, fmt.Sprintf("the run wrote %d journal events; the oldest %d were left on the executor",
			total, total-len(rows)))
	}
	events := make([]Event, 0, len(rows))
	// ListEvents is newest first; a journal replays oldest first.
	for i := len(rows) - 1; i >= 0; i-- {
		row := rows[i]
		events = append(events, Event{
			Timestamp: row.Timestamp,
			Type:      string(row.Type),
			TaskID:    row.TaskID,
			TaskTitle: scrub(row.TaskTitle),
			Step:      row.Step,
			Message:   truncate(scrub(row.Message), maxEventMessageBytes),
			Details:   boundDetails(scrub(row.Details)),
		})
	}

	// Read straight from the table, not through cost.ReadLedger: that also
	// imports .cloop/costs.jsonl, which is not removed between dispatches and
	// so still holds every earlier run's rows. They were reported when those
	// runs came back; reporting them again would bill them twice.
	entries, err := db.ReadCosts()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("projectseed: read the run's cost rows: %w", err)
	}
	if len(entries) > maxResultCosts {
		notes = append(notes, fmt.Sprintf("the run recorded %d cost rows; the oldest %d were left on the executor",
			len(entries), len(entries)-maxResultCosts))
		entries = entries[len(entries)-maxResultCosts:]
	}
	costs := make([]Cost, 0, len(entries))
	for _, e := range entries {
		costs = append(costs, Cost{
			Timestamp:      e.Timestamp,
			TaskID:         e.TaskID,
			TaskTitle:      scrub(e.TaskTitle),
			Provider:       e.Provider,
			Model:          e.Model,
			InputTokens:    e.InputTokens,
			OutputTokens:   e.OutputTokens,
			ThinkingTokens: e.ThinkingTokens,
			EstimatedUSD:   e.EstimatedUSD,
		})
	}
	return events, costs, notes, nil
}

// boundDetails keeps an event's JSON details only while they are small enough
// to be worth carrying. Truncating JSON would produce something that no longer
// parses, so an oversized blob is dropped whole.
func boundDetails(d string) string {
	if len(d) > maxEventDetailBytes {
		return ""
	}
	return d
}

// encodeResult compresses r, shrinking it in stages until it fits the
// transport: executor.MaxProjectResultBytes compressed, and
// MaxResultInflatedBytes once the hub inflates it — a document past either is
// refused whole, the run's outcomes with it. Each stage gives up something
// less important than the one after it, and says what it gave up.
func encodeResult(r *Result) ([]byte, error) {
	stages := []func(*Result) string{
		func(*Result) string { return "" },
		func(r *Result) string {
			if len(r.Steps) == 0 {
				return ""
			}
			for i := range r.Steps {
				r.Steps[i].Output = tail(r.Steps[i].Output, shrunkStepOutputBytes)
			}
			return fmt.Sprintf("step output was cut to its last %d bytes to fit the transport", shrunkStepOutputBytes)
		},
		func(r *Result) string {
			if len(r.Events) == 0 {
				return ""
			}
			for i := range r.Events {
				r.Events[i].Details = ""
			}
			return "journal event details were dropped to fit the transport"
		},
		// The files the result carries go next: one at a time, by
		// dropCarriedFiles, rather than all of them for the last few bytes.
		nil,
		func(r *Result) string {
			if len(r.Steps) == 0 {
				return ""
			}
			for i := range r.Steps {
				r.Steps[i].Output = ""
			}
			return "step output was dropped to fit the transport; it remains in the executor's workspace"
		},
		func(r *Result) string {
			if len(r.Events) == 0 {
				return ""
			}
			n := len(r.Events)
			r.Events = nil
			return fmt.Sprintf("%d journal events were dropped to fit the transport", n)
		},
	}
	for _, shrink := range stages {
		if shrink == nil {
			out, ok, err := dropCarriedFiles(r)
			if err != nil || ok {
				return out, err
			}
			continue
		}
		if note := shrink(r); note != "" {
			r.Omitted = append(r.Omitted, note)
		}
		out, inflated, err := encode(r)
		if err != nil {
			return nil, err
		}
		if fitsTransport(out, inflated) {
			return out, nil
		}
	}
	return nil, fmt.Errorf("projectseed: the run changed %d task(s), which do not fit in a %d-byte result "+
		"even without its step output and journal", len(r.Tasks), executor.MaxProjectResultBytes)
}

// leftForRoom is what a carried file that encodeResult had to drop says.
const leftForRoom = "left in the executor's workspace: the run's result had no room for it"

// dropCarriedFiles leaves files r carries in the executor's workspace until r
// fits the transport or carries none — as few, and as little, as it takes: see
// pickFile — and says in r.Omitted how many it left. It returns r encoded, and
// whether that fits.
func dropCarriedFiles(r *Result) ([]byte, bool, error) {
	var carried []int
	for i := range r.Attachments {
		if len(r.Attachments[i].Data) > 0 {
			carried = append(carried, i)
		}
	}
	if len(carried) == 0 {
		return nil, false, nil
	}
	out, inflated, err := encode(r)
	if err != nil {
		return nil, false, err
	}
	note, dropped := len(r.Omitted), 0
	r.Omitted = append(r.Omitted, "")
	for least := 1; len(carried) > 0; least *= 2 {
		// Files enough to cover what the document is over by, as each costs
		// it. The costs are estimates — files alike cost less together than
		// each on its own — so the document is encoded again to see, and each
		// round that falls short drops twice as many as the one before, so a
		// handful of encodes settle it whatever the estimates missed.
		over := int64(len(out)-executor.MaxProjectResultBytes) + dropSlack
		overInflated := int64(inflated) - resultInflatedLimit
		if overInflated > 0 {
			overInflated += dropSlack
		}
		var freed, freedInflated int64
		for n := 0; len(carried) > 0 && (n < least ||
			(len(out) > executor.MaxProjectResultBytes && freed < over) ||
			(overInflated > 0 && freedInflated < overInflated)); n++ {
			i := pickFile(r, carried, over-freed, overInflated-freedInflated)
			a := &r.Attachments[carried[i]]
			carried = append(carried[:i], carried[i+1:]...)
			freed += fileCost(a)
			freedInflated += inflatedCost(a)
			a.Data, a.cost, a.Left = nil, 0, leftForRoom
			dropped++
		}
		r.Omitted[note] = fmt.Sprintf("%s attached by the run %s left in the executor's workspace to fit the transport",
			plural(dropped, "file", "files"), map[bool]string{true: "was", false: "were"}[dropped == 1])
		if out, inflated, err = encode(r); err != nil {
			return nil, false, err
		}
		if fitsTransport(out, inflated) {
			return out, true, nil
		}
	}
	return out, false, nil
}

// dropSlack is added to what a result is over by when files are chosen to
// cover it, for what their estimated costs miss.
const dropSlack = 1 << 10

// pickFile chooses which of the carried files — indexes into r.Attachments —
// to leave behind next, given what the result is still over by, compressed and
// inflated: the cheapest one that covers it alone, so a result a little too
// large loses a little; or, when none does, the most costly by the measure the
// result is over by.
func pickFile(r *Result, carried []int, over, overInflated int64) int {
	cost := func(i int) int64 { return fileCost(&r.Attachments[carried[i]]) }
	inflated := func(i int) int64 { return inflatedCost(&r.Attachments[carried[i]]) }
	best := -1
	for i := range carried {
		if (over <= 0 || cost(i) >= over) && (overInflated <= 0 || inflated(i) >= overInflated) &&
			(best < 0 || cost(i) < cost(best)) {
			best = i
		}
	}
	if best >= 0 {
		return best
	}
	best = 0
	for i := range carried {
		if (overInflated > 0 && inflated(i) > inflated(best)) || (overInflated <= 0 && cost(i) > cost(best)) {
			best = i
		}
	}
	return best
}

// inflatedCost is what dropping a carried file frees in the inflated result:
// its base64.
func inflatedCost(a *Attachment) int64 {
	return int64(base64.StdEncoding.EncodedLen(len(a.Data)))
}

// fileCost is what dropping a carried file frees in the compressed result:
// its measured cost, or — for a document not built by carryAttachments — its
// size.
func fileCost(a *Attachment) int64 {
	if a.cost > 0 {
		return a.cost
	}
	return int64(len(a.Data))
}

// fitsTransport reports whether a document encoded to out, inflating to
// inflated bytes, is one the hub accepts.
func fitsTransport(out []byte, inflated int) bool {
	return len(out) <= executor.MaxProjectResultBytes && int64(inflated) <= resultInflatedLimit
}

func compress(r *Result) ([]byte, error) {
	out, _, err := encode(r)
	return out, err
}

// encode compresses r, and reports how large it is before compression: what
// the hub inflates it to.
func encode(r *Result) ([]byte, int, error) {
	raw, err := json.Marshal(r)
	if err != nil {
		return nil, 0, fmt.Errorf("projectseed: marshal result: %w", err)
	}
	var buf bytes.Buffer
	zw, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		return nil, 0, fmt.Errorf("projectseed: open compressor: %w", err)
	}
	if _, err := zw.Write(raw); err != nil {
		return nil, 0, fmt.Errorf("projectseed: compress result: %w", err)
	}
	if err := zw.Close(); err != nil {
		return nil, 0, fmt.Errorf("projectseed: finish compressing result: %w", err)
	}
	return buf.Bytes(), len(raw), nil
}

// DecodeResult parses the bytes a device sent back, refusing anything a
// well-behaved device could not have produced. It checks shape and bounds only;
// what the hub accepts *from* a valid document is decided by Merge.
func DecodeResult(data []byte) (*Result, error) {
	switch {
	case len(data) == 0:
		return nil, errors.New("projectseed: the result is empty")
	case len(data) > executor.MaxProjectResultBytes:
		return nil, fmt.Errorf("projectseed: the result is %d bytes, over the %d-byte ceiling",
			len(data), executor.MaxProjectResultBytes)
	case len(data) < 2 || data[0] != 0x1f || data[1] != 0x8b:
		return nil, errors.New("projectseed: the result is not gzip-compressed")
	}
	raw, err := inflateBounded(data, MaxResultInflatedBytes)
	if err != nil {
		return nil, err
	}
	var r Result
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, fmt.Errorf("projectseed: the result is not a result document: %w", err)
	}
	if r.Format < 1 {
		return nil, fmt.Errorf("projectseed: the result has no recognisable format (format %d)", r.Format)
	}
	switch {
	case len(r.Tasks) > maxResultTasks:
		return nil, fmt.Errorf("projectseed: the result carries %d tasks, more than %d", len(r.Tasks), maxResultTasks)
	case len(r.Steps) > maxResultSteps:
		return nil, fmt.Errorf("projectseed: the result carries %d steps, more than %d", len(r.Steps), maxResultSteps)
	case len(r.Events) > maxResultEvents:
		return nil, fmt.Errorf("projectseed: the result carries %d events, more than %d", len(r.Events), maxResultEvents)
	case len(r.Costs) > maxResultCosts:
		return nil, fmt.Errorf("projectseed: the result carries %d cost rows, more than %d", len(r.Costs), maxResultCosts)
	case len(r.Attachments) > maxResultAttachments:
		return nil, fmt.Errorf("projectseed: the result carries %d attachments, more than %d",
			len(r.Attachments), maxResultAttachments)
	}
	for i, a := range r.Attachments {
		switch {
		case a.TaskID <= 0:
			return nil, fmt.Errorf("projectseed: attachment %d names no task", i)
		case a.Size < 0 || a.Size > attachments.MaxFileBytes:
			// No device attaches a file this size, and a size nobody bounded
			// is what the hub's accounting would then add up.
			return nil, fmt.Errorf("projectseed: attachment %d claims %d bytes, outside 0..%d",
				i, a.Size, attachments.MaxFileBytes)
		case len(a.Data) > 0 && int64(len(a.Data)) != a.Size:
			return nil, fmt.Errorf("projectseed: attachment %d carries %d bytes but claims %d", i, len(a.Data), a.Size)
		case a.ID != "" && !statedb.ValidAttachmentID(a.ID):
			return nil, fmt.Errorf("projectseed: attachment %d has an id that is not an attachment's", i)
		case a.Sent && len(a.Data) > 0:
			return nil, fmt.Errorf("projectseed: attachment %d is marked sent and carries its bytes too", i)
		case len(a.Name) > maxAttachmentTextBytes || len(a.TaskTitle) > maxAttachmentTextBytes ||
			len(a.Left) > maxAttachmentTextBytes || len(a.SHA256) > 64:
			return nil, fmt.Errorf("projectseed: attachment %d carries an oversized field", i)
		}
	}
	for i, tc := range r.Tasks {
		if tc.After == nil || tc.After.ID <= 0 {
			return nil, fmt.Errorf("projectseed: task change %d names no task", i)
		}
		if tc.Before != nil && tc.Before.ID != tc.After.ID {
			return nil, fmt.Errorf("projectseed: task change %d pairs task #%d with task #%d",
				i, tc.Before.ID, tc.After.ID)
		}
	}
	return &r, nil
}

// inflateBounded decompresses data under ceiling bytes; one byte more is an
// error rather than a silent truncation.
func inflateBounded(data []byte, ceiling int64) ([]byte, error) {
	zr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("projectseed: read result: %w", err)
	}
	defer zr.Close()
	raw, err := io.ReadAll(io.LimitReader(zr, ceiling+1))
	if err != nil {
		return nil, fmt.Errorf("projectseed: decompress result: %w", err)
	}
	if int64(len(raw)) > ceiling {
		return nil, fmt.Errorf("projectseed: result inflates past the %d-byte ceiling", ceiling)
	}
	return raw, nil
}

// tail keeps the last n bytes of s, cut at a UTF-8 boundary.
func tail(s string, n int) string {
	if len(s) <= n {
		return s
	}
	i := len(s) - n
	for i < len(s) && !utf8.RuneStart(s[i]) {
		i++
	}
	return s[i:]
}

// truncate keeps the first n bytes of s, cut at a UTF-8 boundary.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

func nonNegative(n int) int {
	if n < 0 {
		return 0
	}
	return n
}
