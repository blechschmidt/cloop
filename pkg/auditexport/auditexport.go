// Package auditexport serialises the tamper-evident audit trail into the
// formats a compliance pipeline consumes (Task 20167).
//
// Three writers, one interface:
//
//	jsonl  one JSON object per line — lossless, the format to keep
//	csv    a flat table — the format a human opens in a spreadsheet
//	cef    ArcSight Common Event Format — the format a SIEM ingests
//
// The package deliberately holds no database handle and no file handle: it
// writes events from a slice to an io.Writer. That keeps the format rules
// (which are fiddly, especially CEF's two-level escaping) testable against
// golden fixtures without a SQLite dependency, and lets the same code serve
// both the CLI's `--output file` and a future HTTP download.
//
// Hashes are carried through every format. An export that dropped prev_hash
// and row_hash would be a list of claims about the past with no way to check
// them; carrying them means a recipient can re-run the chain verification
// against the export itself.
package auditexport

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/statedb"
)

// Event is the row shape being exported, re-exported so callers need not
// import pkg/statedb just to name the type.
type Event = statedb.AuditEvent

// Format selects the serialisation.
type Format string

const (
	// FormatJSONL writes one JSON object per line. Lossless.
	FormatJSONL Format = "jsonl"

	// FormatCSV writes a header row followed by one row per event.
	FormatCSV Format = "csv"

	// FormatCEF writes ArcSight Common Event Format records.
	FormatCEF Format = "cef"
)

// AllFormats lists the supported formats in the order help text shows them.
var AllFormats = []Format{FormatJSONL, FormatCSV, FormatCEF}

// ParseFormat resolves a user-supplied format name, case-insensitively.
// "json" is accepted as an alias for jsonl: it is the name people reach for,
// and refusing it teaches nothing.
func ParseFormat(s string) (Format, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "jsonl", "json", "ndjson":
		return FormatJSONL, nil
	case "csv":
		return FormatCSV, nil
	case "cef":
		return FormatCEF, nil
	case "":
		return FormatJSONL, nil
	}
	names := make([]string, len(AllFormats))
	for i, f := range AllFormats {
		names[i] = string(f)
	}
	return "", fmt.Errorf("unknown format %q (valid: %s)", s, strings.Join(names, ", "))
}

// Options tunes an export run.
type Options struct {
	// Format selects the serialisation. Zero value is FormatJSONL.
	Format Format

	// ProductVersion is stamped into the CEF header so a SIEM can attribute
	// a record to the binary that produced it. Ignored by the other formats.
	// Defaults to "dev" when empty.
	ProductVersion string

	// MaxPayloadBytes truncates the payload field in CEF output. CEF has no
	// formal size cap but collectors routinely drop records past a few
	// kilobytes, and a step payload can be large. 0 selects the default;
	// negative disables truncation.
	MaxPayloadBytes int
}

// defaultCEFPayloadBytes keeps a record comfortably inside the ~8 KiB most
// syslog collectors accept, leaving room for the header and the other
// extension fields.
const defaultCEFPayloadBytes = 4096

// Write serialises events to w in the requested format.
func Write(w io.Writer, events []Event, opts Options) error {
	switch opts.Format {
	case FormatCSV:
		return writeCSV(w, events)
	case FormatCEF:
		return writeCEF(w, events, opts)
	case FormatJSONL, "":
		return writeJSONL(w, events)
	}
	return fmt.Errorf("auditexport: unknown format %q", opts.Format)
}

// ── JSONL ───────────────────────────────────────────────────────────────────

// jsonlRecord is the wire shape. It is declared explicitly rather than
// marshalling statedb.AuditEvent directly so the exported field names are a
// stable contract with whatever consumes the file — renaming a Go field must
// not silently change an export format someone's pipeline parses.
//
// Payload is emitted as raw JSON when it parses as JSON (which it does for
// every emitter in pkg/statedb) so a consumer can index into it, and as a
// string otherwise so a malformed row still round-trips.
type jsonlRecord struct {
	ID         int64           `json:"id"`
	Timestamp  string          `json:"timestamp"`
	Actor      string          `json:"actor"`
	EventType  string          `json:"event_type"`
	EntityType string          `json:"entity_type"`
	EntityID   string          `json:"entity_id"`
	Payload    json.RawMessage `json:"payload,omitempty"`
	PrevHash   string          `json:"prev_hash"`
	RowHash    string          `json:"row_hash"`
}

func writeJSONL(w io.Writer, events []Event) error {
	enc := json.NewEncoder(w)
	for _, ev := range events {
		rec := jsonlRecord{
			ID:         ev.ID,
			Timestamp:  ev.Timestamp.UTC().Format(time.RFC3339Nano),
			Actor:      ev.Actor,
			EventType:  ev.EventType,
			EntityType: ev.EntityType,
			EntityID:   ev.EntityID,
			PrevHash:   ev.PrevHash,
			RowHash:    ev.RowHash,
		}
		rec.Payload = payloadAsRawJSON(ev.Payload)
		if err := enc.Encode(rec); err != nil {
			return fmt.Errorf("auditexport: encode event %d: %w", ev.ID, err)
		}
	}
	return nil
}

// payloadAsRawJSON returns the payload as embeddable JSON: verbatim when it
// is valid JSON, otherwise wrapped as a JSON string.
func payloadAsRawJSON(payload string) json.RawMessage {
	if strings.TrimSpace(payload) == "" {
		return nil
	}
	if json.Valid([]byte(payload)) {
		return json.RawMessage(payload)
	}
	quoted, err := json.Marshal(payload)
	if err != nil {
		return nil
	}
	return json.RawMessage(quoted)
}

// ── CSV ─────────────────────────────────────────────────────────────────────

// csvHeader is the column order. Appending is safe for consumers that read by
// name; reordering is not, so new columns go on the end.
var csvHeader = []string{
	"id", "timestamp", "actor", "event_type",
	"entity_type", "entity_id", "payload", "prev_hash", "row_hash",
}

func writeCSV(w io.Writer, events []Event) error {
	cw := csv.NewWriter(w)
	if err := cw.Write(csvHeader); err != nil {
		return fmt.Errorf("auditexport: write csv header: %w", err)
	}
	for _, ev := range events {
		row := []string{
			strconv.FormatInt(ev.ID, 10),
			ev.Timestamp.UTC().Format(time.RFC3339Nano),
			ev.Actor,
			ev.EventType,
			ev.EntityType,
			ev.EntityID,
			ev.Payload,
			ev.PrevHash,
			ev.RowHash,
		}
		if err := cw.Write(row); err != nil {
			return fmt.Errorf("auditexport: write csv row %d: %w", ev.ID, err)
		}
	}
	cw.Flush()
	if err := cw.Error(); err != nil {
		return fmt.Errorf("auditexport: flush csv: %w", err)
	}
	return nil
}

// ── CEF ─────────────────────────────────────────────────────────────────────

// CEF record layout:
//
//	CEF:0|Vendor|Product|Version|SignatureID|Name|Severity|Extension
//
// The seven header fields are pipe-delimited and escape `|` and `\`. The
// extension is a space-separated run of key=value pairs with a *different*
// escaping rule — `=`, `\`, and newlines — which is the part implementations
// usually get wrong, so the two escapers below are kept deliberately separate
// rather than shared.
const (
	cefVersion = "0"
	cefVendor  = "cloop"
	cefProduct = "cloop"
)

func writeCEF(w io.Writer, events []Event, opts Options) error {
	product := strings.TrimSpace(opts.ProductVersion)
	if product == "" {
		product = "dev"
	}
	maxPayload := opts.MaxPayloadBytes
	if maxPayload == 0 {
		maxPayload = defaultCEFPayloadBytes
	}

	for _, ev := range events {
		header := strings.Join([]string{
			"CEF:" + cefVersion,
			cefEscapeHeader(cefVendor),
			cefEscapeHeader(cefProduct),
			cefEscapeHeader(product),
			cefEscapeHeader(signatureID(ev)),
			cefEscapeHeader(eventName(ev)),
			strconv.Itoa(severityFor(ev)),
		}, "|")

		ext := cefExtension(ev, maxPayload)
		if _, err := fmt.Fprintf(w, "%s|%s\n", header, ext); err != nil {
			return fmt.Errorf("auditexport: write cef record %d: %w", ev.ID, err)
		}
	}
	return nil
}

// signatureID is the Device Event Class ID: the stable machine key a SIEM
// correlation rule matches on. The event type is exactly that, so it is used
// unchanged rather than inventing a numbering scheme that would have to be
// kept in sync with the emitters.
func signatureID(ev Event) string {
	if ev.EventType == "" {
		return "audit.unknown"
	}
	return ev.EventType
}

// eventName is the human-readable Name field an analyst reads in a console.
func eventName(ev Event) string {
	entity := ev.EntityType
	if entity == "" {
		entity = "record"
	}
	if ev.EntityID != "" {
		return fmt.Sprintf("%s %s %s", ev.EventType, entity, ev.EntityID)
	}
	return fmt.Sprintf("%s %s", ev.EventType, entity)
}

// severityFor maps an event onto CEF's 0–10 scale.
//
// The ranking answers "what would an analyst want paged about": an
// authorization denial and a credential grant outrank a task edit, which
// outranks the step-append firehose. Everything unrecognised lands at 3 —
// visible but not alarming — so a new emitter is never silently invisible.
func severityFor(ev Event) int {
	t := ev.EventType
	switch {
	case strings.HasPrefix(t, "authz.denied"):
		return 8
	case strings.HasSuffix(t, ".deny"), strings.HasSuffix(t, ".denied"):
		return 8
	case strings.HasPrefix(t, "secret."), strings.HasPrefix(t, "egress."):
		return 7
	case strings.HasPrefix(t, "executor."):
		return 6
	case strings.HasPrefix(t, "config."):
		return 5
	case strings.HasPrefix(t, "authz."):
		return 4
	case t == "task.delete":
		return 4
	case strings.HasPrefix(t, "step."):
		return 1
	case strings.HasPrefix(t, "task."), strings.HasPrefix(t, "state."), strings.HasPrefix(t, "plan."):
		return 2
	}
	return 3
}

// cefExtension builds the key=value tail.
//
// Keys are the CEF standard ones where a standard one means the right thing
// (rt, suser, act, cat, externalId, outcome) and custom-string slots
// otherwise, each paired with its Label as the specification requires — an
// unlabelled cs1 is meaningless to a collector.
func cefExtension(ev Event, maxPayload int) string {
	pairs := [][2]string{
		{"rt", strconv.FormatInt(ev.Timestamp.UTC().UnixMilli(), 10)},
		{"externalId", strconv.FormatInt(ev.ID, 10)},
		{"suser", ev.Actor},
		{"act", ev.EventType},
		{"cat", ev.EntityType},
	}
	if outcome := outcomeFor(ev); outcome != "" {
		pairs = append(pairs, [2]string{"outcome", outcome})
	}
	if ev.EntityID != "" {
		pairs = append(pairs,
			[2]string{"cs1Label", "entityId"},
			[2]string{"cs1", ev.EntityID},
		)
	}
	pairs = append(pairs,
		[2]string{"cs2Label", "rowHash"},
		[2]string{"cs2", ev.RowHash},
		[2]string{"cs3Label", "prevHash"},
		[2]string{"cs3", ev.PrevHash},
	)
	if payload := truncate(ev.Payload, maxPayload); payload != "" {
		pairs = append(pairs,
			[2]string{"cs4Label", "payload"},
			[2]string{"cs4", payload},
		)
	}

	var b strings.Builder
	for i, kv := range pairs {
		if kv[1] == "" {
			continue
		}
		if i > 0 && b.Len() > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(kv[0])
		b.WriteByte('=')
		b.WriteString(cefEscapeExtension(kv[1]))
	}
	return b.String()
}

// outcomeFor maps an event onto CEF's success/failure outcome field where the
// event type carries that meaning. Returns "" when it does not, rather than
// guessing: a wrong outcome is worse than an absent one.
func outcomeFor(ev Event) string {
	switch {
	case strings.HasSuffix(ev.EventType, ".denied"), strings.HasSuffix(ev.EventType, ".deny"):
		return "failure"
	case strings.HasSuffix(ev.EventType, ".granted"):
		return "success"
	}
	return ""
}

// truncate clips s to at most n bytes on a rune boundary, appending an
// explicit marker. A silently clipped payload would read as a complete one.
func truncate(s string, n int) string {
	if n < 0 || len(s) <= n {
		return s
	}
	const marker = "…[truncated]"
	if n <= len(marker) {
		return marker
	}
	cut := n - len(marker)
	for cut > 0 && !utf8Boundary(s, cut) {
		cut--
	}
	return s[:cut] + marker
}

// utf8Boundary reports whether index i starts a rune (i.e. is not a
// continuation byte).
func utf8Boundary(s string, i int) bool {
	if i <= 0 || i >= len(s) {
		return true
	}
	return s[i]&0xC0 != 0x80
}

// cefEscapeHeader escapes the two characters that are special in a CEF
// header field: the pipe delimiter and the escape character itself.
func cefEscapeHeader(s string) string {
	r := strings.NewReplacer(
		`\`, `\\`,
		`|`, `\|`,
	)
	return collapseNewlines(r.Replace(s))
}

// cefEscapeExtension escapes an extension *value*. The rules differ from the
// header: `=` is the delimiter here and must be escaped, `|` must not be, and
// literal newlines are represented as the two-character sequence \n so a
// record stays on one line.
func cefEscapeExtension(s string) string {
	r := strings.NewReplacer(
		`\`, `\\`,
		`=`, `\=`,
		"\n", `\n`,
		"\r", `\r`,
	)
	return r.Replace(s)
}

// collapseNewlines flattens embedded newlines in header fields, which have no
// escape for them.
func collapseNewlines(s string) string {
	return strings.NewReplacer("\n", " ", "\r", " ").Replace(s)
}

// ── Summary ─────────────────────────────────────────────────────────────────

// Summary describes an export run, for the CLI to report on stderr without
// polluting the exported stream on stdout.
type Summary struct {
	Format     Format
	Events     int
	FirstID    int64
	LastID     int64
	Actors     []string
	EventTypes []string
}

// Summarize describes a set of events without serialising them.
func Summarize(events []Event, format Format) Summary {
	s := Summary{Format: format, Events: len(events)}
	if len(events) == 0 {
		return s
	}
	actors := map[string]struct{}{}
	types := map[string]struct{}{}
	s.FirstID, s.LastID = events[0].ID, events[0].ID
	for _, ev := range events {
		if ev.ID < s.FirstID {
			s.FirstID = ev.ID
		}
		if ev.ID > s.LastID {
			s.LastID = ev.ID
		}
		if ev.Actor != "" {
			actors[ev.Actor] = struct{}{}
		}
		if ev.EventType != "" {
			types[ev.EventType] = struct{}{}
		}
	}
	s.Actors = sortedKeys(actors)
	s.EventTypes = sortedKeys(types)
	return s
}

func sortedKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
