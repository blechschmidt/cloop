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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
	"unicode/utf8"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/pausereason"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
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
)

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
	// Omitted says what the device left out to fit the transport, one
	// sentence each, so the hub can say so instead of presenting a partial
	// history as a whole one.
	Omitted []string `json:"omitted,omitempty"`
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
	r, err := collect(dir, base, scrub)
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

// collect builds the Result for the project the run left in dir.
func collect(dir string, base *state.ProjectState, scrub func(string) string) (*Result, error) {
	cloopDir := filepath.Join(dir, seedDir)
	info, err := os.Lstat(cloopDir)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return nil, fmt.Errorf("projectseed: %s is gone — the workload removed the project it was sent, "+
			"so there is nothing to read back", cloopDir)
	case err != nil:
		return nil, fmt.Errorf("projectseed: inspect %s: %w", cloopDir, err)
	case info.Mode()&os.ModeSymlink != 0:
		return nil, fmt.Errorf("projectseed: %s was replaced by a symbolic link; refusing to follow it "+
			"out of the workspace", cloopDir)
	case !info.IsDir():
		return nil, fmt.Errorf("projectseed: %s is not a directory", cloopDir)
	}
	for _, name := range staleDatabaseFiles {
		p := filepath.Join(cloopDir, name)
		if li, err := os.Lstat(p); err == nil && li.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("projectseed: %s is a symbolic link; refusing to read the project through it", p)
		}
	}

	r := &Result{Format: ResultFormat, BaseStep: base.CurrentStep}

	dbPath := filepath.Join(cloopDir, "state.db")
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

	r.Status = after.Status
	if after.PauseReason != nil {
		pr := *after.PauseReason
		pr.Detail = scrub(pr.Detail)
		r.PauseReason = &pr
	}
	r.InputTokens = nonNegative(after.TotalInputTokens - base.TotalInputTokens)
	r.OutputTokens = nonNegative(after.TotalOutputTokens - base.TotalOutputTokens)
	r.EvolveSteps = nonNegative(after.EvolveStep - base.EvolveStep)
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
	r.Events, r.Costs = events, costs
	r.Omitted = append(r.Omitted, notes...)
	return r, nil
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
	return c
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

// encodeResult compresses r, shrinking it in stages until it fits
// executor.MaxProjectResultBytes. Each stage gives up something less important
// than the one after it, and says what it gave up.
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
		if note := shrink(r); note != "" {
			r.Omitted = append(r.Omitted, note)
		}
		out, err := compress(r)
		if err != nil {
			return nil, err
		}
		if len(out) <= executor.MaxProjectResultBytes {
			return out, nil
		}
	}
	return nil, fmt.Errorf("projectseed: the run changed %d task(s), which do not fit in a %d-byte result "+
		"even without its step output and journal", len(r.Tasks), executor.MaxProjectResultBytes)
}

func compress(r *Result) ([]byte, error) {
	raw, err := json.Marshal(r)
	if err != nil {
		return nil, fmt.Errorf("projectseed: marshal result: %w", err)
	}
	var buf bytes.Buffer
	zw, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		return nil, fmt.Errorf("projectseed: open compressor: %w", err)
	}
	if _, err := zw.Write(raw); err != nil {
		return nil, fmt.Errorf("projectseed: compress result: %w", err)
	}
	if err := zw.Close(); err != nil {
		return nil, fmt.Errorf("projectseed: finish compressing result: %w", err)
	}
	return buf.Bytes(), nil
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
