package statedb

// Browser telemetry storage (Task 20251). See migrations/0034_telemetry.sql for
// the column-by-column rationale. This file is the accessor layer: what an
// event *means*, how it is normalized and how credentials are stripped all
// live in pkg/telemetry, which this package imports for the model only.

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/telemetry"
)

// TelemetryMaxRows is the hard ceiling on stored events.
//
// Enforced on the write path rather than by the hourly retention janitor,
// because the writer here is an endpoint that accepts unauthenticated POSTs:
// a bound that only holds once an hour is not a bound against the traffic this
// table is actually exposed to. At the field budgets pkg/telemetry enforces,
// the worst case is a few hundred megabytes, and the realistic case — the
// trails of a handful of sessions — is a few megabytes.
const TelemetryMaxRows = 50000

// telemetryTrimSlack is how far over the ceiling the table is allowed to drift
// before a trim runs, and how much headroom a trim leaves behind.
//
// Trimming to exactly TelemetryMaxRows on every insert would run a DELETE for
// every batch once the table is full — the steady state for a busy hub. This
// makes the trim amortised: it fires roughly once per slack events, and each
// firing does bounded work.
const telemetryTrimSlack = 2000

// TelemetryFilter selects events for reading. The zero value means "the most
// recent page of everything", which is the query a reader opening the panel
// wants before they know what they are looking for.
type TelemetryFilter struct {
	Source  string
	Kind    string
	Session string
	// Search matches message, url, view and detail. Applied in SQL rather than
	// in the caller because the table is bounded but large, and a reader
	// filtering client-side would page through thousands of rows to find one.
	Search string
	Since  time.Time
	Limit  int
	Offset int
}

const telemetryDefaultLimit = 200

// TelemetryMaxLimit bounds one page. Chosen so that a page of worst-case rows
// still marshals to a response a browser will render rather than choke on.
const TelemetryMaxLimit = 1000

// AppendTelemetry stores a normalized batch and enforces the row ceiling.
//
// Takes the whole batch in one transaction: a trail's value is its ordering,
// and a partially-written batch would show a reader a gap that never happened.
func (d *DB) AppendTelemetry(events []telemetry.Event) error {
	if len(events) == 0 {
		return nil
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	tx, err := d.conn.Begin()
	if err != nil {
		return fmt.Errorf("statedb: begin telemetry append: %w", classifyDriverErr(err))
	}
	defer func() { _ = tx.Rollback() }()

	stmt, err := tx.Prepare(
		`INSERT INTO telemetry_events
		     (received_at, client_millis, source, kind, session, seq,
		      message, stack, url, view, detail, user_agent, client_ip, actor, release)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("statedb: prepare telemetry insert: %w", classifyDriverErr(err))
	}
	defer stmt.Close()

	for _, e := range events {
		if _, err := stmt.Exec(
			formatOptionalTime(e.At), e.ClientMillis, string(e.Source), string(e.Kind),
			e.Session, e.Seq, e.Message, e.Stack, e.URL, e.View, e.Detail,
			e.UserAgent, e.ClientIP, e.Actor, e.Release,
		); err != nil {
			return fmt.Errorf("statedb: insert telemetry event: %w", classifyDriverErr(err))
		}
	}

	if err := trimTelemetryTx(tx); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("statedb: commit telemetry append: %w", classifyDriverErr(err))
	}
	return nil
}

// trimTelemetryTx drops the oldest rows once the table has drifted past the
// ceiling by more than the slack. Runs inside the append transaction so the
// bound cannot be observed as violated even briefly.
func trimTelemetryTx(tx *sql.Tx) error {
	var count int64
	if err := tx.QueryRow(`SELECT COUNT(*) FROM telemetry_events`).Scan(&count); err != nil {
		return fmt.Errorf("statedb: count telemetry events: %w", classifyDriverErr(err))
	}
	if count <= TelemetryMaxRows+telemetryTrimSlack {
		return nil
	}
	// Delete by id, which is monotonic with arrival: keep the newest
	// TelemetryMaxRows-telemetryTrimSlack and drop everything below.
	keep := TelemetryMaxRows - telemetryTrimSlack
	if _, err := tx.Exec(
		`DELETE FROM telemetry_events
		  WHERE id <= (SELECT id FROM telemetry_events ORDER BY id DESC LIMIT 1 OFFSET ?)`,
		keep,
	); err != nil {
		return fmt.Errorf("statedb: trim telemetry events: %w", classifyDriverErr(err))
	}
	return nil
}

// QueryTelemetry returns one page of events, newest first, and the total number
// of rows matching the filter so a caller can render "showing 200 of 4,812".
func (d *DB) QueryTelemetry(f TelemetryFilter) ([]telemetry.Event, int, error) {
	where, args := telemetryWhere(f)

	limit := f.Limit
	if limit <= 0 {
		limit = telemetryDefaultLimit
	}
	if limit > TelemetryMaxLimit {
		limit = TelemetryMaxLimit
	}
	offset := f.Offset
	if offset < 0 {
		offset = 0
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	var total int
	if err := d.conn.QueryRow(`SELECT COUNT(*) FROM telemetry_events`+where, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("statedb: count telemetry: %w", classifyDriverErr(err))
	}

	rows, err := d.conn.Query(
		`SELECT id, received_at, client_millis, source, kind, session, seq,
		        message, stack, url, view, detail, user_agent, client_ip, actor, release
		   FROM telemetry_events`+where+`
		  ORDER BY id DESC
		  LIMIT ? OFFSET ?`,
		append(append([]interface{}{}, args...), limit, offset)...,
	)
	if err != nil {
		return nil, 0, fmt.Errorf("statedb: query telemetry: %w", classifyDriverErr(err))
	}
	defer rows.Close()

	var out []telemetry.Event
	for rows.Next() {
		var (
			e        telemetry.Event
			received string
			source   string
			kind     string
		)
		if err := rows.Scan(&e.ID, &received, &e.ClientMillis, &source, &kind, &e.Session,
			&e.Seq, &e.Message, &e.Stack, &e.URL, &e.View, &e.Detail,
			&e.UserAgent, &e.ClientIP, &e.Actor, &e.Release); err != nil {
			return nil, 0, fmt.Errorf("statedb: scan telemetry: %w", classifyDriverErr(err))
		}
		e.At = parseOptionalTime(received)
		e.Source = telemetry.Source(source)
		e.Kind = telemetry.Kind(kind)
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("statedb: iterate telemetry: %w", classifyDriverErr(err))
	}
	return out, total, nil
}

// TelemetrySession is one page load, rolled up.
//
// The index of the panel: a reader arrives knowing "a wearer reported a problem
// around ten past four" and needs to turn that into a session id before any
// per-event view is useful.
type TelemetrySession struct {
	Session   string    `json:"session"`
	Source    string    `json:"source"`
	Events    int       `json:"events"`
	Errors    int       `json:"errors"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	UserAgent string    `json:"user_agent,omitempty"`
	Actor     string    `json:"actor,omitempty"`
	Release   string    `json:"release,omitempty"`
}

// ListTelemetrySessions rolls events up by session, most recently active first.
func (d *DB) ListTelemetrySessions(source string, limit int) ([]TelemetrySession, error) {
	if limit <= 0 {
		limit = 100
	}
	if limit > TelemetryMaxLimit {
		limit = TelemetryMaxLimit
	}

	where := ""
	var args []interface{}
	if s := strings.TrimSpace(source); s != "" {
		where = ` WHERE source = ?`
		args = append(args, s)
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	// MAX(...) on the correlated columns rather than an arbitrary pick: within
	// one session the user agent and release are constant by construction, so
	// any aggregate returns the true value while keeping this a single scan.
	rows, err := d.conn.Query(
		`SELECT session,
		        MAX(source)      AS source,
		        COUNT(*)         AS events,
		        SUM(CASE WHEN kind IN ('error','rejection') THEN 1 ELSE 0 END) AS errors,
		        MIN(received_at) AS first_seen,
		        MAX(received_at) AS last_seen,
		        MAX(user_agent)  AS user_agent,
		        MAX(actor)       AS actor,
		        MAX(release)     AS release
		   FROM telemetry_events`+where+`
		  GROUP BY session
		  ORDER BY MAX(id) DESC
		  LIMIT ?`,
		append(args, limit)...,
	)
	if err != nil {
		return nil, fmt.Errorf("statedb: list telemetry sessions: %w", classifyDriverErr(err))
	}
	defer rows.Close()

	var out []TelemetrySession
	for rows.Next() {
		var (
			s           TelemetrySession
			first, last string
		)
		if err := rows.Scan(&s.Session, &s.Source, &s.Events, &s.Errors,
			&first, &last, &s.UserAgent, &s.Actor, &s.Release); err != nil {
			return nil, fmt.Errorf("statedb: scan telemetry session: %w", classifyDriverErr(err))
		}
		s.FirstSeen = parseOptionalTime(first)
		s.LastSeen = parseOptionalTime(last)
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("statedb: iterate telemetry sessions: %w", classifyDriverErr(err))
	}
	return out, nil
}

// PruneTelemetry deletes events older than cutoff and returns how many went.
// The operator-invoked companion to the automatic row ceiling: `cloop hub
// telemetry prune` for when a trail should go now rather than when it ages out.
//
// The age half of the same policy now also runs unattended — see
// PruneTelemetryRows and the janitor's telemetry step (Task 20291). Both go
// through rowretention.go's id-bounded path rather than comparing the
// RFC3339Nano text column directly, because a string comparison on that column
// is only an ordering if every writer used identical UTC formatting, and a row
// whose timestamp will not parse must stop the prune rather than be swept into
// it.
func (d *DB) PruneTelemetry(cutoff time.Time) (int64, error) {
	cutID, ok, err := d.ageCutoffID(tableTelemetryEvents, cutoff)
	if err != nil || !ok {
		return 0, err
	}
	return d.deleteUpToID(tableTelemetryEvents, cutID)
}

// telemetryWhere builds the shared filter clause. Every value is bound as a
// parameter — the fields are browser-supplied, and the search term in
// particular is whatever a reader typed.
func telemetryWhere(f TelemetryFilter) (string, []interface{}) {
	var (
		clauses []string
		args    []interface{}
	)
	if s := strings.TrimSpace(f.Source); s != "" {
		clauses = append(clauses, "source = ?")
		args = append(args, s)
	}
	if k := strings.TrimSpace(f.Kind); k != "" {
		clauses = append(clauses, "kind = ?")
		args = append(args, k)
	}
	if s := strings.TrimSpace(f.Session); s != "" {
		clauses = append(clauses, "session = ?")
		args = append(args, s)
	}
	if !f.Since.IsZero() {
		clauses = append(clauses, "received_at >= ?")
		args = append(args, formatOptionalTime(f.Since.UTC()))
	}
	if q := strings.TrimSpace(f.Search); q != "" {
		// ESCAPE so that a reader searching for a literal % or _ — plausible
		// in a URL or a percent-encoded message — matches those characters
		// rather than turning into a wildcard.
		like := "%" + escapeLike(q) + "%"
		clauses = append(clauses,
			`(message LIKE ? ESCAPE '\' OR url LIKE ? ESCAPE '\' OR view LIKE ? ESCAPE '\' OR detail LIKE ? ESCAPE '\')`)
		args = append(args, like, like, like, like)
	}
	if len(clauses) == 0 {
		return "", nil
	}
	return " WHERE " + strings.Join(clauses, " AND "), args
}

// escapeLike neutralises LIKE metacharacters in a user-supplied search term.
func escapeLike(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return r.Replace(s)
}
