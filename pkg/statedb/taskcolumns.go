// Package statedb — rehydration of the JSON-encoded task columns.
//
// plan_tasks stores six list fields as JSON text: depends_on, tags and
// annotations since the first schema, and links, on_success and on_failure
// since 0054 (Task 20361). Decoding them used to be a discarded error per
// column per row, which made a damaged column indistinguishable from an empty
// one: the field came back nil, and the load reported success.
//
// For some of them that is a visibility loss. For depends_on it is a
// correctness bug, because an empty dependency list is not "no information" —
// it is a positive assertion that the task has no prerequisites, and
// pm.DepsReady reads it as permission to run. A task whose dependencies were
// dropped on load is admitted ahead of the work it depends on, defeating the
// gate silently (Task 20297). on_success and on_failure are the same kind of
// field: pm.ResolveBranch skips the branch not taken, so an empty list lets
// both branches of a branched plan run. That asymmetry is why the columns are
// decoded under different rules rather than one.
package statedb

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log"
	"sync"

	"github.com/blechschmidt/cloop/pkg/pm"
)

// maxCorruptValueInError bounds how much of an undecodable column is echoed
// back in the error: enough to recognise a truncation or a value written into
// the wrong column, short enough that the message stays one log line.
const maxCorruptValueInError = 64

// taskListColumns holds one row's JSON-encoded list columns as stored.
type taskListColumns struct {
	DependsOn, Tags, Annotations, Links, OnSuccess, OnFailure string
}

// decodeTaskColumns rehydrates the JSON-encoded columns of a freshly scanned
// task row. It is the only decoder for both read paths — LoadTask and
// loadTasks — so the two cannot disagree about what a damaged row means.
//
// The per-field rule, and why it differs:
//
//   - depends_on, on_success and on_failure are fatal. Degrading them would
//     convert "the plan's ordering is unreadable" into "there is no ordering",
//     which is not a smaller truth but the opposite one: it releases a task to
//     run early, against prerequisites that have not been built, or runs the
//     branch a task's outcome was meant to skip. That damage is unrecoverable,
//     while refusing the load is not — the error names the row to repair.
//
//   - tags, annotations and links degrade to empty, and report. Their failure
//     mode is "shows less": a label-filtered run skips the task, its decision
//     log is missing, a ticket link is gone. Refusing to open a whole project
//     because one task's note field is damaged would trade a partial loss for
//     a total one — the same trade decodeBackground and decodeAbort decline to
//     make.
//
// On any failure the destination field is left empty rather than partially
// filled; see decodeList for why that matters.
func decodeTaskColumns(t *pm.Task, raw taskListColumns) error {
	deps, err := decodeList[int](raw.DependsOn)
	if err != nil {
		t.DependsOn = nil
		return corruptColumn(t.ID, "depends_on", raw.DependsOn, err)
	}
	onSuccess, err := decodeList[string](raw.OnSuccess)
	if err != nil {
		t.OnSuccess = nil
		return corruptColumn(t.ID, "on_success", raw.OnSuccess, err)
	}
	onFailure, err := decodeList[string](raw.OnFailure)
	if err != nil {
		t.OnFailure = nil
		return corruptColumn(t.ID, "on_failure", raw.OnFailure, err)
	}
	t.DependsOn, t.OnSuccess, t.OnFailure = deps, onSuccess, onFailure

	t.Tags = degradableList[string](t.ID, "tags", raw.Tags)
	t.Annotations = degradableList[pm.Annotation](t.ID, "annotations", raw.Annotations)
	t.Links = degradableList[pm.Link](t.ID, "links", raw.Links)
	return nil
}

// decodeList decodes a JSON array, returning nothing at all unless the decode
// was clean.
//
// A type error inside an otherwise well-formed array does not abort the
// decode: encoding/json records it and keeps going, having already written the
// elements it did parse plus a zero for the one it could not. `[1,2,"x"]`
// lands as {1,2,0} — a subset of the real prerequisites, plus a dependency on
// task 0, which does not exist and so is vacuously satisfied. That is a worse
// outcome than an empty list, and it is reachable from a single mistyped
// element, so a caller is only ever handed the result of a clean decode.
// (Truncation, by contrast, does discard — but relying on the difference is
// not worth the reasoning.)
//
// The two spellings of an empty list — null, which the writer stores for a nil
// list, and [], the columns' default — skip the decoder and come back exactly
// as it would return them: nil and empty. Nearly every list column of nearly
// every row is one of the two, and the plan is read on every dashboard request.
func decodeList[T any](raw string) ([]T, error) {
	switch raw {
	case "null":
		return nil, nil
	case "[]":
		return []T{}, nil
	}
	var out []T
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return nil, err
	}
	return out, nil
}

// degradableList decodes a column whose loss only hides information, reporting
// rather than failing when it cannot.
func degradableList[T any](taskID int, column, raw string) []T {
	out, err := decodeList[T](raw)
	if err != nil {
		reportDegradedColumn(taskID, column, raw, err)
		return nil
	}
	return out
}

// corruptColumn is the error for a column decodeTaskColumns refuses to drop.
func corruptColumn(taskID int, column, raw string, err error) error {
	return fmt.Errorf("task %d: column %s is not decodable JSON (%s): %w",
		taskID, column, clipColumnValue(raw), wrap(ErrCorruptTaskColumn, err))
}

// clipColumnValue renders a column value for an error message, bounded and
// quoted. The raw bytes are worth showing for the fatal columns specifically:
// they hold lists of task ids, never free text, so echoing one cannot leak
// prompt or annotation content, and it is the information an operator needs to
// repair the row.
func clipColumnValue(raw string) string {
	if len(raw) > maxCorruptValueInError {
		return fmt.Sprintf("%q…", raw[:maxCorruptValueInError])
	}
	return fmt.Sprintf("%q", raw)
}

// Degraded-column reporting.
//
// This package deliberately has no logger dependency — it is the data layer,
// and every other diagnostic it produces travels back as an error. A dropped
// tags or annotations field has nowhere to travel to, because the load it
// belongs to succeeds. So it goes to a package-level sink instead, which
// defaults to the standard logger and is swappable for tests and for a host
// that would rather route it into structured logging.
var (
	degradedMu sync.RWMutex
	degradedFn = logDegradedColumn
)

// degradedLogged remembers which damaged values the default sink has already
// logged, so a dashboard that reloads a project on every request logs a
// damaged row once rather than once per request. Bounded: past the cap the
// sink logs every report again, which is noisy but never silent.
var (
	degradedLoggedMu sync.Mutex
	degradedLogged   = map[[sha256.Size]byte]struct{}{}
)

const maxDegradedLogged = 1024

func logDegradedColumn(taskID int, column, raw string, err error) {
	key := sha256.Sum256([]byte(fmt.Sprintf("%d\x00%s\x00%s", taskID, column, raw)))
	degradedLoggedMu.Lock()
	_, seen := degradedLogged[key]
	if !seen && len(degradedLogged) < maxDegradedLogged {
		degradedLogged[key] = struct{}{}
	}
	degradedLoggedMu.Unlock()
	if seen {
		return
	}
	log.Printf("statedb: task %d: column %s is not decodable JSON, field dropped: %v",
		taskID, column, err)
}

// setDegradedColumnReporter installs fn as the sink for degraded-column
// reports and returns a function that restores the previous one. Passing nil
// restores the default logger.
func setDegradedColumnReporter(fn func(taskID int, column, raw string, err error)) (restore func()) {
	degradedMu.Lock()
	defer degradedMu.Unlock()
	prev := degradedFn
	if fn == nil {
		fn = logDegradedColumn
	}
	degradedFn = fn
	return func() {
		degradedMu.Lock()
		degradedFn = prev
		degradedMu.Unlock()
	}
}

func reportDegradedColumn(taskID int, column, raw string, err error) {
	degradedMu.RLock()
	fn := degradedFn
	degradedMu.RUnlock()
	fn(taskID, column, raw, err)
}
