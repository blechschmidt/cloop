// Event-based broadcast (Task 20132): instead of fanning out the entire
// ProjectState on every change — multi-hundred-KB payloads for projects with
// thousands of tasks — the server computes a diff against the previously
// broadcast snapshot and ships only the delta. The wire format is a
// state_diff envelope with three buckets (tasks_added / tasks_removed /
// tasks_changed) plus a state_changed map for top-level scalar fields.
//
// Clients apply the diff to their local appState mirror and only re-render
// what touched the changed rows. The first broadcast (no previous snapshot)
// still ships the full state so a fresh tab has something to render against.

package ui

import (
	"bytes"
	"encoding/json"
	"sync"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
)

// stateDiff is the wire payload for the "state_diff" WebSocket event.
//
// The shape mirrors the three change kinds that matter to the frontend:
//   - Tasks the client doesn't yet have (full task object).
//   - Tasks the client should drop (just the ID).
//   - Tasks whose fields changed (id + only the changed fields, encoded as
//     a marshalled JSON object so the client can shallow-merge without
//     knowing the full pm.Task schema).
//
// state_changed carries top-level ProjectState scalar/struct fields that
// changed since the last snapshot (goal, status, model, etc.). Plan-level
// fields (Goal, Version) are surfaced here too under "plan_goal" and
// "plan_version" so the client doesn't need plan-specific diff logic.
type stateDiff struct {
	TasksAdded   []*pm.Task         `json:"tasks_added,omitempty"`
	TasksRemoved []int              `json:"tasks_removed,omitempty"`
	TasksChanged []taskChange       `json:"tasks_changed,omitempty"`
	StateChanged map[string]any     `json:"state_changed,omitempty"`
	// HasChanges is set false only when there is literally nothing to ship
	// (all four buckets are empty). Callers use this to skip the broadcast
	// entirely instead of fanning out an empty envelope.
	HasChanges bool `json:"-"`
}

// taskChange carries the changed fields of a task. The fields are flattened
// into the parent JSON object at marshal time (e.g. {"id":7,"status":"done"})
// so the client can `Object.assign(local, change)` without unwrapping.
type taskChange struct {
	ID     int
	Fields map[string]any
}

// MarshalJSON flattens taskChange so it shows up as {"id":N, ...changed fields}
// on the wire. The ID is always present; Fields' keys are merged in alongside
// (last-write-wins if a caller put "id" in Fields, which it shouldn't).
func (c taskChange) MarshalJSON() ([]byte, error) {
	out := make(map[string]any, len(c.Fields)+1)
	for k, v := range c.Fields {
		out[k] = v
	}
	out["id"] = c.ID
	return json.Marshal(out)
}

// computeStateDiff returns the delta between prev and curr. If prev is nil
// (first broadcast for a project, or the cache was evicted), every task is
// reported in TasksAdded and every persisted top-level field is reported in
// StateChanged — i.e. the diff degenerates into a "full state" payload, which
// gives the client a complete picture without needing a separate code path.
//
// The function never mutates either argument. Tasks are matched by ID; tasks
// present in both prev and curr produce a taskChange only when at least one
// JSON field differs (compared by re-marshalling each side and walking the
// resulting maps — handles all *time.Time and []string fields correctly
// without bespoke per-field comparisons).
func computeStateDiff(prev, curr *state.ProjectState) stateDiff {
	var d stateDiff
	d.StateChanged = make(map[string]any)

	if curr == nil {
		return d
	}

	prevTasks := indexTasks(prev)
	currTasks := indexTasks(curr)

	// Removed tasks: in prev, not in curr.
	for id := range prevTasks {
		if _, ok := currTasks[id]; !ok {
			d.TasksRemoved = append(d.TasksRemoved, id)
		}
	}
	// Added + changed.
	for id, currT := range currTasks {
		prevT, existed := prevTasks[id]
		if !existed {
			d.TasksAdded = append(d.TasksAdded, currT)
			continue
		}
		if changes := taskFieldDiff(prevT, currT); len(changes) > 0 {
			d.TasksChanged = append(d.TasksChanged, taskChange{ID: id, Fields: changes})
		}
	}

	// Top-level scalar diff. Both sides are marshalled with Steps nilled out
	// (same wire shape as marshalStateForWire) and Plan.Tasks dropped so the
	// per-field comparison doesn't double-report task changes.
	d.StateChanged = topLevelFieldDiff(prev, curr)

	d.HasChanges = len(d.TasksAdded) > 0 ||
		len(d.TasksRemoved) > 0 ||
		len(d.TasksChanged) > 0 ||
		len(d.StateChanged) > 0
	if !d.HasChanges {
		d.StateChanged = nil
	}
	return d
}

// indexTasks returns a map keyed by task ID. Nil-safe.
func indexTasks(ps *state.ProjectState) map[int]*pm.Task {
	out := make(map[int]*pm.Task)
	if ps == nil || ps.Plan == nil {
		return out
	}
	for _, t := range ps.Plan.Tasks {
		if t == nil {
			continue
		}
		out[t.ID] = t
	}
	return out
}

// taskFieldDiff returns a map of every JSON-visible field that differs
// between prev and curr. Comparison is done by re-marshalling each side and
// walking the resulting JSON objects — robust against *time.Time, []string,
// nested structs, etc. without needing a hand-maintained field list.
//
// Returns nil (not an empty map) when nothing changed.
func taskFieldDiff(prev, curr *pm.Task) map[string]any {
	if prev == nil || curr == nil {
		// Caller guarantees both non-nil; degenerate guard.
		return nil
	}
	prevRaw, err := json.Marshal(prev)
	if err != nil {
		return nil
	}
	currRaw, err := json.Marshal(curr)
	if err != nil {
		return nil
	}
	if bytes.Equal(prevRaw, currRaw) {
		return nil
	}

	var prevMap, currMap map[string]json.RawMessage
	if err := json.Unmarshal(prevRaw, &prevMap); err != nil {
		return nil
	}
	if err := json.Unmarshal(currRaw, &currMap); err != nil {
		return nil
	}

	out := make(map[string]any)
	for k, currV := range currMap {
		prevV, existed := prevMap[k]
		if !existed || !bytes.Equal(prevV, currV) {
			var v any
			if err := json.Unmarshal(currV, &v); err == nil {
				out[k] = v
			} else {
				out[k] = json.RawMessage(currV)
			}
		}
	}
	// Fields that existed in prev but are absent / zero in curr (omitempty
	// dropped them). Report them as explicit nulls so the client can clear
	// the field instead of silently keeping the stale value.
	for k := range prevMap {
		if _, ok := currMap[k]; !ok {
			out[k] = nil
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// topLevelFieldDiff returns top-level ProjectState fields whose marshalled
// JSON differs. Plan.Tasks are excluded (handled by the per-task diff);
// Steps are excluded (always nilled on the wire by marshalStateForWire).
//
// Returns an empty map (not nil) when nothing changed at the top level.
func topLevelFieldDiff(prev, curr *state.ProjectState) map[string]any {
	out := make(map[string]any)
	prevRaw, err := marshalTopLevel(prev)
	if err != nil {
		return out
	}
	currRaw, err := marshalTopLevel(curr)
	if err != nil {
		return out
	}
	if bytes.Equal(prevRaw, currRaw) {
		return out
	}

	var prevMap, currMap map[string]json.RawMessage
	if err := json.Unmarshal(prevRaw, &prevMap); err != nil {
		return out
	}
	if err := json.Unmarshal(currRaw, &currMap); err != nil {
		return out
	}
	for k, currV := range currMap {
		prevV, existed := prevMap[k]
		if !existed || !bytes.Equal(prevV, currV) {
			var v any
			if err := json.Unmarshal(currV, &v); err == nil {
				out[k] = v
			} else {
				out[k] = json.RawMessage(currV)
			}
		}
	}
	for k := range prevMap {
		if _, ok := currMap[k]; !ok {
			out[k] = nil
		}
	}
	return out
}

// marshalTopLevel serialises ps as marshalStateForWire would, but with
// Plan.Tasks nilled too so per-task changes don't appear in the top-level
// diff. Returns the empty JSON object for nil.
func marshalTopLevel(ps *state.ProjectState) ([]byte, error) {
	if ps == nil {
		return []byte(`{}`), nil
	}
	clone := *ps
	clone.Steps = nil
	if ps.Plan != nil {
		planClone := *ps.Plan
		planClone.Tasks = nil
		clone.Plan = &planClone
	}
	return json.Marshal(&clone)
}

// ensureDiffCache lazily initialises s.diffCache so Server values constructed
// directly (not via New) still work. The constructor wires it up; this guard
// is just a belt-and-braces for tests.
func (s *Server) ensureDiffCache() *stateCache {
	if s.diffCache == nil {
		s.diffCache = newStateCache()
	}
	return s.diffCache
}

// stateCache is the per-project snapshot cache used by the diff broadcaster.
// Each entry holds the most recently broadcast ProjectState (deep-copied via
// JSON round-trip on insert so callers can mutate the original without
// invalidating the cache). Bounded only by the number of distinct projects
// the daemon has broadcasted for — same lifetime as hubClients.
type stateCache struct {
	mu    sync.Mutex
	prev  map[string]*state.ProjectState
}

func newStateCache() *stateCache {
	return &stateCache{prev: make(map[string]*state.ProjectState)}
}

// swap installs curr as the cached snapshot for workDir and returns the
// previous one. The stored snapshot is a deep copy so subsequent mutations
// in the caller never affect future diffs.
func (c *stateCache) swap(workDir string, curr *state.ProjectState) *state.ProjectState {
	c.mu.Lock()
	defer c.mu.Unlock()
	prev := c.prev[workDir]
	if curr != nil {
		c.prev[workDir] = deepCopyState(curr)
	} else {
		delete(c.prev, workDir)
	}
	return prev
}

// drop forgets the cached snapshot for workDir. Called when the project is
// removed from the multi-project registry or when an explicit resync is
// requested so the next broadcast ships a full diff.
func (c *stateCache) drop(workDir string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.prev, workDir)
}

// deepCopyState returns an independent copy of ps via JSON round-trip.
// Returns nil for nil input. JSON failures fall back to a shallow copy
// (with Steps nilled) — the diff will conservatively report more changes
// rather than miss any. Steps are always nilled in the cache since they
// are not part of the diff.
func deepCopyState(ps *state.ProjectState) *state.ProjectState {
	if ps == nil {
		return nil
	}
	raw, err := json.Marshal(ps)
	if err != nil {
		clone := *ps
		clone.Steps = nil
		return &clone
	}
	var out state.ProjectState
	if err := json.Unmarshal(raw, &out); err != nil {
		clone := *ps
		clone.Steps = nil
		return &clone
	}
	out.Steps = nil
	return &out
}
