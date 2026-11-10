// Package ratelimit - claude_usage_models.go reads the weekly windows a
// Claude plan meters for one model alone out of the usage API's limits[]
// list (Task 20490).
//
// The usage API names its older per-model windows with keys of their own,
// seven_day_opus and seven_day_sonnet. Fable's weekly window has no such key:
// it is only a row of limits[], the list of meters claude.ai's usage page and
// Claude Code's /usage screen draw, as kind "weekly_scoped" with the model in
// scope.model.display_name:
//
//	{"kind":"weekly_scoped","group":"weekly","percent":7,"severity":"normal",
//	 "resets_at":"2026-11-13T22:00:00.283105+00:00",
//	 "scope":{"model":{"id":null,"display_name":"Fable"},"surface":null},
//	 "is_active":false}
//
// Rows are classified on kind and scope, never on a label, the way Claude
// Code reads them.
package ratelimit

import (
	"encoding/json"
	"strings"
	"unicode"
)

// ModelWindow is a weekly window the plan meters for one model alone.
type ModelWindow struct {
	// Model is the server's display name for the model, e.g. "Fable".
	Model string `json:"model"`
	UsageDetail
}

const (
	// maxModelWindows bounds the model windows one snapshot keeps. A plan
	// meters a handful; the bound is for a server that sends thousands.
	maxModelWindows = 16
	// maxModelNameRunes bounds a model's display name.
	maxModelNameRunes = 64
)

// usageLimitRow is the part of one limits[] row this package reads.
type usageLimitRow struct {
	Kind     string   `json:"kind"`
	Percent  *float64 `json:"percent"`
	ResetsAt *string  `json:"resets_at"`
	Scope    *struct {
		Model *struct {
			DisplayName string `json:"display_name"`
		} `json:"model"`
	} `json:"scope"`
}

// modelWindows returns the model-scoped weekly windows in a limits[] list,
// in the server's order.
//
// Each row is decoded on its own and a row this cannot read is skipped, so a
// change to the list's shape loses rows rather than the whole snapshot. A row
// with no percentage is skipped the way a window with no utilization is.
func modelWindows(raw json.RawMessage) []ModelWindow {
	if len(raw) == 0 {
		return nil
	}
	var rows []json.RawMessage
	if err := json.Unmarshal(raw, &rows); err != nil {
		return nil
	}
	var out []ModelWindow
	for _, r := range rows {
		if len(out) == maxModelWindows {
			break
		}
		var row usageLimitRow
		if err := json.Unmarshal(r, &row); err != nil {
			continue
		}
		if row.Kind != "weekly_scoped" || row.Percent == nil ||
			row.Scope == nil || row.Scope.Model == nil {
			continue
		}
		name := cleanModelName(row.Scope.Model.DisplayName)
		if name == "" {
			continue
		}
		w := &UsageWindow{Utilization: row.Percent}
		if row.ResetsAt != nil {
			w.ResetsAt = *row.ResetsAt
		}
		out = append(out, ModelWindow{Model: name, UsageDetail: *parseWindow(w)})
	}
	return out
}

// addModelWindows files model windows into a snapshot.
//
// Opus and Sonnet have fields of their own, so a window scoped to either is
// the meter those fields already describe: it fills the field when the server
// left the key out, and is not listed a second time when it did not. Every
// other model, Fable among them, goes to SevenDayModels.
func addModelWindows(u *ClaudeUsage, windows []ModelWindow) {
	for _, w := range windows {
		var field **UsageDetail
		switch strings.ToLower(w.Model) {
		case "opus":
			field = &u.SevenDayOpus
		case "sonnet":
			field = &u.SevenDaySonnet
		default:
			u.SevenDayModels = append(u.SevenDayModels, w)
			continue
		}
		if *field == nil {
			d := w.UsageDetail
			*field = &d
		}
	}
}

// cleanModelName makes a display name safe to show and to log: valid UTF-8,
// no control or format characters (a bidi override among them), whitespace
// collapsed, and at most maxModelNameRunes long. The dashboard escapes it as
// well; this is so that what it escapes is a name.
func cleanModelName(s string) string {
	s = strings.ToValidUTF8(s, "")
	s = strings.Map(func(r rune) rune {
		switch {
		case unicode.IsSpace(r):
			return ' ' // a tab or newline still separates words
		case unicode.IsControl(r) || unicode.Is(unicode.Cf, r):
			return -1
		}
		return r
	}, s)
	s = strings.Join(strings.Fields(s), " ")
	if r := []rune(s); len(r) > maxModelNameRunes {
		s = strings.TrimSpace(string(r[:maxModelNameRunes]))
	}
	return s
}
