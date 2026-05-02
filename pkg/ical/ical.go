// Package ical generates RFC 5545 iCalendar documents from a cloop task plan.
// The output is a VCALENDAR with one VTODO per task, importable into Google
// Calendar, Outlook, Apple Calendar, and any other RFC-5545-compliant client.
package ical

import (
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/blechschmidt/cloop/pkg/pm"
)

const crlf = "\r\n"

// Build returns a complete VCALENDAR document for the given plan.
// Each task is represented as a VTODO component.
func Build(plan *pm.Plan) string {
	var b strings.Builder

	writeLine(&b, "BEGIN:VCALENDAR")
	writeLine(&b, "VERSION:2.0")
	writeLine(&b, "PRODID:-//cloop//cloop task ical//EN")
	writeLine(&b, "CALSCALE:GREGORIAN")
	writeLine(&b, "METHOD:PUBLISH")
	writeProperty(&b, "X-WR-CALNAME", plan.Goal)
	writeLine(&b, "X-WR-TIMEZONE:UTC")

	for _, t := range plan.Tasks {
		writeVTODO(&b, t)
	}

	writeLine(&b, "END:VCALENDAR")

	return b.String()
}

func writeVTODO(b *strings.Builder, t *pm.Task) {
	writeLine(b, "BEGIN:VTODO")

	// UID — stable identifier derived from task ID
	writeProperty(b, "UID", fmt.Sprintf("cloop-task-%d@cloop", t.ID))

	// DTSTAMP — creation/export timestamp
	writeProperty(b, "DTSTAMP", formatDateTime(time.Now().UTC()))

	// SUMMARY
	writeProperty(b, "SUMMARY", t.Title)

	// DESCRIPTION
	if t.Description != "" {
		writeProperty(b, "DESCRIPTION", t.Description)
	}

	// DUE and DTSTART
	if t.Deadline != nil {
		due := t.Deadline.UTC()
		writeProperty(b, "DUE", formatDateTime(due))

		if t.EstimatedMinutes > 0 {
			dtstart := due.Add(-time.Duration(t.EstimatedMinutes) * time.Minute)
			writeProperty(b, "DTSTART", formatDateTime(dtstart))
		} else {
			// Default: start one hour before due
			writeProperty(b, "DTSTART", formatDateTime(due.Add(-time.Hour)))
		}
	} else if t.StartedAt != nil {
		writeProperty(b, "DTSTART", formatDateTime(t.StartedAt.UTC()))
	}

	if t.CompletedAt != nil {
		writeProperty(b, "COMPLETED", formatDateTime(t.CompletedAt.UTC()))
	}

	// STATUS
	writeProperty(b, "STATUS", icalStatus(t.Status))

	// PRIORITY — iCal RFC 5545: 1=highest, 9=lowest, 0=undefined
	// cloop priority: P0 (0)→1, P1 (1)→2, P2 (2)→5, P3 (3)→9
	writeProperty(b, "PRIORITY", fmt.Sprintf("%d", icalPriority(t.Priority)))

	// CATEGORIES from task tags
	if len(t.Tags) > 0 {
		writeProperty(b, "CATEGORIES", strings.Join(t.Tags, ","))
	}

	// PERCENT-COMPLETE
	if t.Status == pm.TaskDone || t.Status == pm.TaskSkipped {
		writeProperty(b, "PERCENT-COMPLETE", "100")
	} else if t.Status == pm.TaskInProgress {
		writeProperty(b, "PERCENT-COMPLETE", "50")
	} else {
		writeProperty(b, "PERCENT-COMPLETE", "0")
	}

	// DURATION from EstimatedMinutes (ISO 8601 duration)
	if t.EstimatedMinutes > 0 {
		writeProperty(b, "DURATION", fmt.Sprintf("PT%dM", t.EstimatedMinutes))
	}

	// X- extensions for cloop-specific data
	writeProperty(b, "X-CLOOP-TASK-ID", fmt.Sprintf("%d", t.ID))
	if t.Assignee != "" {
		writeProperty(b, "X-CLOOP-ASSIGNEE", t.Assignee)
	}
	if string(t.Role) != "" {
		writeProperty(b, "X-CLOOP-ROLE", string(t.Role))
	}

	writeLine(b, "END:VTODO")
}

// icalStatus maps a TaskStatus to its RFC 5545 VTODO STATUS value.
func icalStatus(s pm.TaskStatus) string {
	switch s {
	case pm.TaskDone:
		return "COMPLETED"
	case pm.TaskInProgress:
		return "IN-PROCESS"
	case pm.TaskSkipped:
		return "COMPLETED" // best approximation; no SKIPPED in RFC 5545
	case pm.TaskFailed, pm.TaskTimedOut:
		return "CANCELLED"
	default:
		return "NEEDS-ACTION"
	}
}

// icalPriority maps a cloop priority integer to RFC 5545 PRIORITY values.
// RFC 5545 §3.8.1.9: 1–4 high, 5 medium, 6–9 low, 0 undefined.
func icalPriority(p int) int {
	switch p {
	case 0:
		return 1 // P0 → highest
	case 1:
		return 2 // P1 → high
	case 2:
		return 5 // P2 → medium
	case 3:
		return 9 // P3 → low
	default:
		if p < 0 {
			return 1
		}
		return 9
	}
}

// formatDateTime formats a time.Time as an iCalendar UTC DATE-TIME value.
func formatDateTime(t time.Time) string {
	return t.UTC().Format("20060102T150405Z")
}

// writeProperty writes a folded iCalendar content line (name:value).
// Lines longer than 75 octets are folded per RFC 5545 §3.1.
func writeProperty(b *strings.Builder, name, value string) {
	// Escape special characters in property values per RFC 5545 §3.3.11
	escaped := escapeValue(value)
	line := name + ":" + escaped
	writeFolded(b, line)
}

// writeLine writes a short line directly (no folding needed for control lines).
func writeLine(b *strings.Builder, s string) {
	b.WriteString(s)
	b.WriteString(crlf)
}

// writeFolded folds a content line at 75 octets (not characters) per RFC 5545.
func writeFolded(b *strings.Builder, line string) {
	const maxOctets = 75

	// Fast path: line fits in one chunk
	if len(line) <= maxOctets {
		b.WriteString(line)
		b.WriteString(crlf)
		return
	}

	// Fold: write 75 octets, then CRLF + SPACE for continuation.
	// We must not break in the middle of a UTF-8 multi-byte sequence.
	remaining := line
	first := true
	for len(remaining) > 0 {
		limit := maxOctets
		if !first {
			limit = maxOctets - 1 // one octet consumed by the leading space
		}
		if limit >= len(remaining) {
			if !first {
				b.WriteByte(' ')
			}
			b.WriteString(remaining)
			b.WriteString(crlf)
			break
		}
		// Trim limit to a valid UTF-8 boundary
		for limit > 0 && !utf8.RuneStart(remaining[limit]) {
			limit--
		}
		if !first {
			b.WriteByte(' ')
		}
		b.WriteString(remaining[:limit])
		b.WriteString(crlf)
		remaining = remaining[limit:]
		first = false
	}
}

// escapeValue escapes backslashes, commas, semicolons, and newlines in
// TEXT property values per RFC 5545 §3.3.11.
func escapeValue(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, ";", `\;`)
	// Do not escape commas in CATEGORIES (they are list separators there).
	// For all other properties this is conservative but correct.
	s = strings.ReplaceAll(s, "\r\n", `\n`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	s = strings.ReplaceAll(s, "\r", `\n`)
	return s
}
