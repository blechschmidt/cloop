package ui

import (
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/blechschmidt/cloop/pkg/pm"
)

// Input-validation helpers for HTTP query parameters.
//
// The UI runs as a long-lived daemon, so unbounded query params let an
// authenticated client (or a malicious one if auth is misconfigured) waste
// memory and CPU: a 10 MiB ?q=… string forces every comparison loop to scan
// the whole buffer; a ?tags=a,a,a,…,a list with millions of entries blows up
// when split. These helpers cap inputs early so the server cost of any single
// request stays bounded regardless of what the client sends.

const (
	// maxQueryStringLen caps free-text search and filter inputs (?q=, ?assignee=,
	// presence ?name=, etc.) at 256 chars. Inputs longer than this are clamped
	// to empty so the handler treats them as "filter not specified" rather than
	// 400-ing — clients that send oversized strings get no results, not crashes.
	maxQueryStringLen = 256

	// maxCSVItems caps the number of comma-separated entries accepted on a
	// list query param (?status=, ?tags=). 64 is well above any realistic
	// human-driven UI but small enough that the resulting set fits in cache.
	maxCSVItems = 64

	// maxCSVItemLen caps each individual CSV entry at 64 chars.
	maxCSVItemLen = 64

	// maxPresenceFieldLen caps WebSocket presence ?name= and ?color= at 64
	// chars. These get echoed to every other connected client, so a single
	// malicious connector with a multi-megabyte name would amplify into the
	// per-client outgoing buffer of every peer.
	maxPresenceFieldLen = 64
)

// boundedQueryString returns the trimmed query value, or "" if it exceeds
// maxLen. Treating oversized inputs as "absent" keeps the calling handler's
// existing zero-value path correct — no special-casing required at the call
// site beyond replacing `r.URL.Query().Get(key)` with this helper.
func boundedQueryString(raw string, maxLen int) string {
	v := strings.TrimSpace(raw)
	if len(v) > maxLen {
		return ""
	}
	return v
}

// validateDependsOn checks a caller-supplied dependency list against the plan
// it will be stored in, returning a human-readable reason when it is invalid.
//
// This is not cosmetic validation (Task 20188). A task that depends on itself
// — or on an id that does not exist — is never `ready` and never
// `PermanentlyBlocked`, so the orchestrator's NextTask() returns nil, the run
// loop breaks, and the run ends early with tasks still pending and nothing
// anywhere saying why. The three write paths (/api/task/add, /api/task/edit,
// PUT /api/tasks/{id}) all assigned the []int verbatim, so the plan could be
// put into that state through the UI in one click.
//
// selfID is the task being edited, or 0 when adding a new one. existing is
// the current plan; a dependency must name a task already in it.
func validateDependsOn(deps []int, selfID int, existing []*pm.Task) error {
	if len(deps) == 0 {
		return nil
	}
	known := make(map[int]struct{}, len(existing))
	for _, t := range existing {
		if t != nil {
			known[t.ID] = struct{}{}
		}
	}
	seen := make(map[int]struct{}, len(deps))
	for _, d := range deps {
		if d <= 0 {
			return fmt.Errorf("dependency id %d is not a valid task id", d)
		}
		if selfID != 0 && d == selfID {
			return fmt.Errorf("task %d cannot depend on itself", selfID)
		}
		if _, ok := known[d]; !ok {
			return fmt.Errorf("dependency task %d does not exist", d)
		}
		if _, dup := seen[d]; dup {
			return fmt.Errorf("dependency task %d is listed more than once", d)
		}
		seen[d] = struct{}{}
	}
	return nil
}

// boundedDisplayName caps a human-readable label at maxLen, truncating rather
// than dropping.
//
// This is the counterpart to boundedQueryString, and the distinction matters
// (Task 20188). For a *filter*, "too long" should mean "absent" so the
// handler's zero-value path stays correct. For a *label* — a presence name
// broadcast to every peer — returning "" throws away the caller's fallback
// and shows a blank entry in the collaborator list. Truncation preserves
// something recognisable while keeping the same amplification bound.
//
// Truncation is rune-aware so a multi-byte name is never cut mid-rune, and
// an ellipsis marks the cut. maxLen is a byte budget, matching the sibling
// helper and the buffer bound it exists to protect.
func boundedDisplayName(raw string, maxLen int) string {
	v := strings.TrimSpace(raw)
	if len(v) <= maxLen {
		return v
	}
	const ellipsis = "…"
	budget := maxLen - len(ellipsis)
	if budget <= 0 {
		return ""
	}
	// Walk back to a rune boundary at or below the byte budget.
	cut := budget
	for cut > 0 && !utf8.RuneStart(v[cut]) {
		cut--
	}
	return v[:cut] + ellipsis
}

// parseCSVList splits raw on commas and returns the trimmed, non-empty items,
// capped at maxItems entries with each item capped at maxItemLen chars. Items
// longer than maxItemLen are dropped (not truncated) so a client cannot smuggle
// a partial token past validation. Returns nil when the input is empty.
func parseCSVList(raw string, maxItems, maxItemLen int) []string {
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	if len(parts) > maxItems {
		parts = parts[:maxItems]
	}
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		v := strings.TrimSpace(p)
		if v == "" || len(v) > maxItemLen {
			continue
		}
		out = append(out, v)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// parsePriorityFilter parses a 1-4 task priority filter. Returns 0 (meaning
// "no priority filter") for empty input, anything unparseable, or any value
// outside the 1-4 range used throughout pkg/pm. Bug fix: the previous
// `strconv.Atoi(s); _ = err` pattern silently let -1 or 99999 through.
func parsePriorityFilter(raw string) int {
	if raw == "" {
		return 0
	}
	v, err := strconv.Atoi(raw)
	if err != nil || v < 1 || v > 4 {
		return 0
	}
	return v
}

// parsePositiveID parses a path/query value as a strictly positive integer ID.
// Returns (0, false) for empty, non-numeric, zero, or negative values so call
// sites can return a single 400 instead of repeating the err/<=0 pair.
func parsePositiveID(raw string) (int, bool) {
	if raw == "" {
		return 0, false
	}
	v, err := strconv.Atoi(raw)
	if err != nil || v <= 0 {
		return 0, false
	}
	return v, true
}
