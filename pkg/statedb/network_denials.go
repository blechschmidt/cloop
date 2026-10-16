package statedb

// network_denials.go records what a run's sandbox firewall refused (Task
// 20437; migration 0080). See the migration for the columns.
//
// Writes come from one place — the hub, as each report arrives from the
// packet log a container executor or a device's agent reads — and every one is
// bounded twice. A run holds at most MaxDenialRowsPerRun itemised rows: what
// arrives for a new destination past that is added to the run's unitemised
// row, so a workload spraying addresses costs a counter, not a row each. And
// the table holds at most denialMaxRows rows and none older than
// denialMaxAge, trimmed by the write that adds a row, so it is bounded without
// a janitor step to forget.

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/auditaction"
)

const (
	// MaxDenialRowsPerRun bounds a run's itemised rows, across its tasks.
	MaxDenialRowsPerRun = 64
	// DenialUnitemised is the rule of a run's row that counts what was not
	// itemised.
	DenialUnitemised = "unitemised"
	// DenialTimeFormat is how first_seen and last_seen are stored: fixed
	// width, so they order and compare as text.
	DenialTimeFormat = "2006-01-02T15:04:05.000000Z"

	denialMaxRows = 20000
	denialMaxAge  = 30 * 24 * time.Hour
)

// DenialRow is one row: a run's refusals of one destination by one deny path.
type DenialRow struct {
	RunID       string
	TaskID      int
	Rule        string
	Dst         string
	Port        int
	Proto       string
	ExecutorID  string
	Fingerprint string
	Why         string
	Count       int64
	FirstSeen   time.Time
	LastSeen    time.Time
}

// DenialWrite is one report to record.
type DenialWrite struct {
	RunID       string
	TaskID      int
	ExecutorID  string
	Fingerprint string
	// Entries are the report's itemised refusals. Count is a delta.
	Entries []DenialRow
	// Unitemised is the report's refusals no entry holds.
	Unitemised int64
	// At stamps the unitemised row.
	At time.Time
}

// DenialWriteResult says what a write changed.
type DenialWriteResult struct {
	// New are the rows this write created: the destinations the run had not
	// been refused before — under that task.
	New []DenialRow
	// Unitemised is what this write added to the run's unitemised row: the
	// report's own, and the entries past the run's cap.
	Unitemised int64
	// FirstUnitemised says this write created the unitemised row: the first
	// time the run went past what is itemised.
	FirstUnitemised bool
}

func formatDenialTime(t time.Time) string { return t.UTC().Format(DenialTimeFormat) }

func parseDenialTime(s string) time.Time {
	t, err := time.Parse(DenialTimeFormat, s)
	if err != nil {
		return time.Time{}
	}
	return t
}

// RecordDenials adds one report to its run's rows, in one transaction.
func (d *DB) RecordDenials(w DenialWrite) (DenialWriteResult, error) {
	var res DenialWriteResult
	if strings.TrimSpace(w.RunID) == "" {
		return res, fmt.Errorf("statedb network denials: a report needs a run id")
	}
	if len(w.Entries) == 0 && w.Unitemised <= 0 {
		return res, nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	tx, err := d.conn.Begin()
	if err != nil {
		return res, fmt.Errorf("statedb network denials: begin: %w", classifyDriverErr(err))
	}
	defer tx.Rollback() //nolint:errcheck // a no-op after a commit

	var rows int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM network_denials WHERE run_id = ? AND rule != ?`,
		w.RunID, DenialUnitemised).Scan(&rows); err != nil {
		return res, fmt.Errorf("statedb network denials: count run %s: %w", w.RunID, classifyDriverErr(err))
	}
	unitemised := w.Unitemised
	if unitemised < 0 {
		unitemised = 0
	}
	inserted := false
	for _, e := range w.Entries {
		if e.Count <= 0 {
			continue
		}
		first, last := formatDenialTime(e.FirstSeen), formatDenialTime(e.LastSeen)
		r, err := tx.Exec(`UPDATE network_denials
			SET count = count + ?,
			    first_seen = MIN(first_seen, ?),
			    last_seen = MAX(last_seen, ?),
			    why = CASE WHEN ? != '' THEN ? ELSE why END
			WHERE run_id = ? AND task_id = ? AND rule = ? AND dst = ? AND port = ? AND proto = ?`,
			e.Count, first, last, e.Why, e.Why, w.RunID, w.TaskID, e.Rule, e.Dst, e.Port, e.Proto)
		if err != nil {
			return res, fmt.Errorf("statedb network denials: update: %w", classifyDriverErr(err))
		}
		if n, _ := r.RowsAffected(); n > 0 {
			continue
		}
		if rows >= MaxDenialRowsPerRun {
			unitemised += e.Count
			continue
		}
		if _, err := tx.Exec(`INSERT INTO network_denials
			(run_id, task_id, rule, dst, port, proto, executor_id, fingerprint, why, count, first_seen, last_seen)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			w.RunID, w.TaskID, e.Rule, e.Dst, e.Port, e.Proto, w.ExecutorID, w.Fingerprint, e.Why,
			e.Count, first, last); err != nil {
			return res, fmt.Errorf("statedb network denials: insert: %w", classifyDriverErr(err))
		}
		rows++
		inserted = true
		row := e
		row.RunID, row.TaskID, row.ExecutorID, row.Fingerprint = w.RunID, w.TaskID, w.ExecutorID, w.Fingerprint
		res.New = append(res.New, row)
	}
	if unitemised > 0 {
		at := w.At
		if at.IsZero() {
			at = time.Now()
		}
		ts := formatDenialTime(at)
		r, err := tx.Exec(`UPDATE network_denials SET count = count + ?, last_seen = MAX(last_seen, ?)
			WHERE run_id = ? AND task_id = 0 AND rule = ? AND dst = '' AND port = 0 AND proto = ''`,
			unitemised, ts, w.RunID, DenialUnitemised)
		if err != nil {
			return res, fmt.Errorf("statedb network denials: update unitemised: %w", classifyDriverErr(err))
		}
		if n, _ := r.RowsAffected(); n == 0 {
			if _, err := tx.Exec(`INSERT INTO network_denials
				(run_id, task_id, rule, executor_id, fingerprint, count, first_seen, last_seen)
				VALUES (?, 0, ?, ?, ?, ?, ?, ?)`,
				w.RunID, DenialUnitemised, w.ExecutorID, w.Fingerprint, unitemised, ts, ts); err != nil {
				return res, fmt.Errorf("statedb network denials: insert unitemised: %w", classifyDriverErr(err))
			}
			inserted = true
			res.FirstUnitemised = true
		}
		res.Unitemised = unitemised
	}
	if inserted {
		if err := trimDenialsTx(tx, time.Now()); err != nil {
			return res, err
		}
	}
	if err := tx.Commit(); err != nil {
		return res, fmt.Errorf("statedb network denials: commit: %w", classifyDriverErr(err))
	}
	return res, nil
}

// trimDenialsTx keeps the table inside its bounds: no row older than
// denialMaxAge, and only the newest denialMaxRows. Run by the write that
// added rows, so a quiet table costs nothing.
func trimDenialsTx(tx *sql.Tx, now time.Time) error {
	if _, err := tx.Exec(`DELETE FROM network_denials WHERE last_seen < ?`,
		formatDenialTime(now.Add(-denialMaxAge))); err != nil {
		return fmt.Errorf("statedb network denials: trim by age: %w", classifyDriverErr(err))
	}
	if _, err := tx.Exec(`DELETE FROM network_denials WHERE id <= (
		SELECT id FROM network_denials ORDER BY id DESC LIMIT 1 OFFSET ?)`, denialMaxRows); err != nil {
		return fmt.Errorf("statedb network denials: trim by count: %w", classifyDriverErr(err))
	}
	return nil
}

const denialColumns = `run_id, task_id, rule, dst, port, proto, executor_id, fingerprint, why, count, first_seen, last_seen`

func scanDenials(rows *sql.Rows) ([]DenialRow, error) {
	defer rows.Close()
	var out []DenialRow
	for rows.Next() {
		var r DenialRow
		var first, last string
		if err := rows.Scan(&r.RunID, &r.TaskID, &r.Rule, &r.Dst, &r.Port, &r.Proto, &r.ExecutorID,
			&r.Fingerprint, &r.Why, &r.Count, &first, &last); err != nil {
			return nil, classifyDriverErr(err)
		}
		r.FirstSeen, r.LastSeen = parseDenialTime(first), parseDenialTime(last)
		out = append(out, r)
	}
	return out, classifyDriverErr(rows.Err())
}

// RunDenials returns a run's rows, most refused first.
func (d *DB) RunDenials(runID string) ([]DenialRow, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	rows, err := d.conn.Query(`SELECT `+denialColumns+` FROM network_denials WHERE run_id = ?
		ORDER BY count DESC, id LIMIT ?`, runID, MaxDenialRowsPerRun*4+1)
	if err != nil {
		return nil, fmt.Errorf("statedb network denials: run %s: %w", runID, classifyDriverErr(err))
	}
	return scanDenials(rows)
}

// TaskDenials returns the rows recorded under a task, and — for runIDs, the
// executions it was dispatched into — the rows no task was named for whose
// refusals fall inside [from, to] (a device's seeded run reports refusals
// before the hub knows which task is running) and those runs' unitemised rows.
func (d *DB) TaskDenials(taskID int, runIDs []string, from, to time.Time) ([]DenialRow, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	q := `SELECT ` + denialColumns + ` FROM network_denials WHERE task_id = ?`
	args := []any{taskID}
	if len(runIDs) > 0 && !from.IsZero() {
		if to.IsZero() {
			to = time.Now()
		}
		// The runs' unitemised rows too, whatever their times: they are the
		// "and this many more" of what the task shows.
		q += ` OR (task_id = 0 AND run_id IN (?` + strings.Repeat(",?", len(runIDs)-1) +
			`) AND (rule = ? OR (last_seen >= ? AND first_seen <= ?)))`
		for _, r := range runIDs {
			args = append(args, r)
		}
		args = append(args, DenialUnitemised, formatDenialTime(from), formatDenialTime(to))
	}
	q += ` ORDER BY count DESC, id LIMIT ?`
	args = append(args, MaxDenialRowsPerRun*4)
	rows, err := d.conn.Query(q, args...)
	if err != nil {
		return nil, fmt.Errorf("statedb network denials: task %d: %w", taskID, classifyDriverErr(err))
	}
	return scanDenials(rows)
}

// DenialSummary is one destination's refusals across the project's runs.
type DenialSummary struct {
	Rule       string
	Dst        string
	Port       int
	Proto      string
	Why        string
	Count      int64
	Runs       int
	FirstSeen  time.Time
	LastSeen   time.Time
	LastRunID  string
	ExecutorID string
}

// RecentDenials summarises the project's refusals since since, by
// destination and rule, most recent first.
func (d *DB) RecentDenials(since time.Time, limit int) ([]DenialSummary, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	rows, err := d.conn.Query(`SELECT rule, dst, port, proto, SUM(count), COUNT(DISTINCT run_id),
			MIN(first_seen), MAX(last_seen),
			(SELECT n2.why FROM network_denials n2 WHERE n2.rule = n.rule AND n2.dst = n.dst AND
				n2.port = n.port AND n2.proto = n.proto ORDER BY n2.last_seen DESC LIMIT 1),
			(SELECT n2.run_id FROM network_denials n2 WHERE n2.rule = n.rule AND n2.dst = n.dst AND
				n2.port = n.port AND n2.proto = n.proto ORDER BY n2.last_seen DESC LIMIT 1),
			(SELECT n2.executor_id FROM network_denials n2 WHERE n2.rule = n.rule AND n2.dst = n.dst AND
				n2.port = n.port AND n2.proto = n.proto ORDER BY n2.last_seen DESC LIMIT 1)
		FROM network_denials n
		WHERE last_seen >= ? AND rule != ?
		GROUP BY rule, dst, port, proto
		ORDER BY MAX(last_seen) DESC
		LIMIT ?`, formatDenialTime(since), DenialUnitemised, limit)
	if err != nil {
		return nil, fmt.Errorf("statedb network denials: recent: %w", classifyDriverErr(err))
	}
	defer rows.Close()
	var out []DenialSummary
	for rows.Next() {
		var s DenialSummary
		var first, last string
		var why, run, ex sql.NullString
		if err := rows.Scan(&s.Rule, &s.Dst, &s.Port, &s.Proto, &s.Count, &s.Runs, &first, &last,
			&why, &run, &ex); err != nil {
			return nil, classifyDriverErr(err)
		}
		s.FirstSeen, s.LastSeen = parseDenialTime(first), parseDenialTime(last)
		s.Why, s.LastRunID, s.ExecutorID = why.String, run.String, ex.String
		out = append(out, s)
	}
	return out, classifyDriverErr(rows.Err())
}

// DenialRuleTotal is one deny path's refusals in a run, for its audit row.
type DenialRuleTotal struct {
	Rule         string
	Count        int64
	Destinations int
	FirstSeen    time.Time
	LastSeen     time.Time
	Why          string
	// Top are its most refused destinations, as "dst:port/proto".
	Top []string
}

// RunDenialTotals sums a run's rows by deny path.
func (d *DB) RunDenialTotals(runID string) ([]DenialRuleTotal, error) {
	rows, err := d.RunDenials(runID)
	if err != nil {
		return nil, err
	}
	by := map[string]*DenialRuleTotal{}
	var order []string
	for _, r := range rows {
		t := by[r.Rule]
		if t == nil {
			t = &DenialRuleTotal{Rule: r.Rule, FirstSeen: r.FirstSeen, LastSeen: r.LastSeen, Why: r.Why}
			by[r.Rule] = t
			order = append(order, r.Rule)
		}
		t.Count += r.Count
		if r.Rule != DenialUnitemised {
			t.Destinations++
			if len(t.Top) < 8 {
				t.Top = append(t.Top, DenialDestination(r.Dst, r.Port, r.Proto))
			}
		}
		if !r.FirstSeen.IsZero() && (t.FirstSeen.IsZero() || r.FirstSeen.Before(t.FirstSeen)) {
			t.FirstSeen = r.FirstSeen
		}
		if r.LastSeen.After(t.LastSeen) {
			t.LastSeen = r.LastSeen
		}
	}
	out := make([]DenialRuleTotal, 0, len(order))
	for _, k := range order {
		out = append(out, *by[k])
	}
	return out, nil
}

// DenialDestination renders a row's destination: 203.0.113.7:443/tcp,
// [2001:db8::7]:443/tcp, 203.0.113.7/icmp.
func DenialDestination(dst string, port int, proto string) string {
	if port == 0 {
		return dst + "/" + proto
	}
	if strings.Contains(dst, ":") {
		return fmt.Sprintf("[%s]:%d/%s", dst, port, proto)
	}
	return fmt.Sprintf("%s:%d/%s", dst, port, proto)
}

// EgressRefusal is one refusal of the egress proxy, read from the audit trail
// (egress.connect and egress.request rows whose decision is deny): what a run
// asked the hub's proxy for and was refused, shown beside what its firewall
// refused.
type EgressRefusal struct {
	At     time.Time
	Action string
	Host   string
	Port   int
	Reason string
	RunID  string
}

// EgressRefusals returns the newest proxy refusals of runIDs, newest first.
// The control plane's audit trail is where they are, so this is called on the
// control plane's handle.
func (d *DB) EgressRefusals(runIDs []string, limit int) ([]EgressRefusal, error) {
	if len(runIDs) == 0 {
		return nil, nil
	}
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	args := []any{string(auditaction.ActionEgressConnect), string(auditaction.ActionEgressRequest)}
	for _, r := range runIDs {
		args = append(args, r)
	}
	args = append(args, limit)
	d.mu.Lock()
	defer d.mu.Unlock()
	rows, err := d.conn.Query(`SELECT timestamp, event_type,
			COALESCE(json_extract(payload, '$.host'), ''), COALESCE(json_extract(payload, '$.port'), 0),
			COALESCE(json_extract(payload, '$.reason'), ''), COALESCE(json_extract(payload, '$.run_id'), '')
		FROM audit_events
		WHERE event_type IN (?, ?) AND json_valid(payload)
		  AND json_extract(payload, '$.decision') = 'deny'
		  AND json_extract(payload, '$.run_id') IN (?`+strings.Repeat(",?", len(runIDs)-1)+`)
		ORDER BY id DESC LIMIT ?`, args...)
	if err != nil {
		return nil, fmt.Errorf("statedb: egress refusals: %w", classifyDriverErr(err))
	}
	defer rows.Close()
	var out []EgressRefusal
	for rows.Next() {
		var e EgressRefusal
		var ts string
		if err := rows.Scan(&ts, &e.Action, &e.Host, &e.Port, &e.Reason, &e.RunID); err != nil {
			return nil, classifyDriverErr(err)
		}
		if t, err := time.Parse(time.RFC3339Nano, ts); err == nil {
			e.At = t
		}
		out = append(out, e)
	}
	return out, classifyDriverErr(rows.Err())
}
