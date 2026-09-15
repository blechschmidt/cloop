package statedb

// Retention for the per-run row tables (Task 20291).
//
// Task 20229 gave the hub a janitor, and the janitor prunes files: plan
// snapshots, sealed audit exports, and then a VACUUM. Not one row table was in
// its reach, which made the VACUUM largely ceremonial — it reclaims free pages,
// and nothing was creating free pages in the tables that actually grow.
//
// Measured on this repository's own control plane (2.4 GB state.db) before this
// file existed:
//
//	audit_events      270 MB   bounded by pkg/auditretention (opt-in)
//	provider_calls     47.5 MB 265 rows, of which 46.8 MB is prompt text
//	steps               3.2 MB 5,152 rows
//	telemetry_events    0.9 MB bounded at write time by trimTelemetryTx
//	events              0.5 MB 1,760 rows
//	costs                 tiny 258 rows
//
// Live data in that file totalled 338 MB, so provider_calls alone was 14% of
// everything real in the database — held in 265 rows, at roughly 178 KB each.
// The shape of the problem is therefore not "too many rows" but "a few rows
// carrying whole LLM prompts", and the fix is shaped to match: bodies are
// dropped on an age bound long before rows are, because the row's metadata is
// what the inspector list and the cost reports read, and it costs ~200 bytes.
//
// # Why bodies are stripped rather than rows deleted
//
// pkg/ui's provider inspector has two readers. The list
// (statedb.ListProviderCalls, feeding GET /api/provider-calls) already selects
// literal '' for prompt, system_prompt, response and headers — it never reads a
// body. Only the per-call modal and the replay flow (LoadProviderCall) do.
// Deleting the row would take the timestamp, provider, model, token counts and
// latency that the list and every cost-shaped report depend on; clearing the
// four text columns takes 99% of the bytes and none of that.
//
// A stripped row records that it was stripped, in its own headers JSON under
// ProviderCallBodiesPrunedKey. Without that marker an aged call would render as
// a call with an empty prompt — indistinguishable from a bug — and the replay
// endpoint would cheerfully send "" to the provider. The marker goes in headers
// rather than in a new column because the schema-compat classifier treats any
// ALTER as breaking (see schema_compat.go), and a migration that locks older
// hubs out of every project database is a far worse defect than the one this
// file fixes.
//
// # Concurrency
//
// Every prune here is id-bounded: it computes the highest id it may touch, then
// works strictly at or below it. Ids are monotonic with insertion in all five
// tables, so a concurrent writer is always appending *above* the cut and cannot
// be affected by, or affect, the work in progress. That is what makes it safe
// to compute the cut in one statement and apply it in another without holding a
// transaction across both.
//
// The apply loop deletes in batches of rowPruneBatch, each its own transaction,
// releasing the process mutex between them. Under WAL a writer in another
// process is blocked for the duration of each transaction and no longer, so
// bounding the transaction bounds the stall — which matters on the first pass
// after an upgrade, where the backlog can be the whole table.

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// rowPruneBatch is how many rows one delete transaction removes.
//
// Sized for the stall it imposes rather than for throughput: 2,000 rows of even
// the heaviest table is a few milliseconds of write lock, so a concurrent
// writer in another process waits well inside the busy timeout. A single
// unbounded DELETE would be faster in wall-clock terms and would hold the lock
// for the whole backlog, which on a first pass is exactly the case where
// somebody is watching.
const rowPruneBatch = 2000

// ageScanChunk bounds how many (id, timestamp) pairs the age scan holds at
// once. The scan stops at the first row that is not older than the cutoff, so
// in steady state it reads a handful; the chunk only bounds the first pass on a
// table that has never been pruned.
const ageScanChunk = 5000

// ProviderCallBodiesPrunedKey is the key under which a stripped provider-call
// row records when its bodies went, inside the headers JSON object.
//
// Exported because pkg/ui reads it: the detail endpoint surfaces it so the
// panel can say "bodies pruned" instead of showing an empty prompt, and the
// replay endpoint refuses a call whose prompt no longer exists rather than
// sending an empty one to a provider.
const ProviderCallBodiesPrunedKey = "bodies_pruned_at"

// RowRetention bounds one row table. The zero value bounds nothing.
type RowRetention struct {
	// MaxRows is the hard ceiling: the newest MaxRows rows survive and the
	// rest are deleted. Zero or less keeps every row.
	MaxRows int

	// MaxAge deletes rows older than this. Zero or less keeps every row
	// regardless of age.
	//
	// An age bound alone does not make a table bounded — an unbounded write
	// rate still produces an unbounded table within any fixed window — which is
	// why hubdoctor reports boundedness off MaxRows and not off this.
	MaxAge time.Duration
}

// Active reports whether this policy would delete anything at all.
func (r RowRetention) Active() bool { return r.MaxRows > 0 || r.MaxAge > 0 }

// Bounded reports whether this policy puts a ceiling on the table's size.
func (r RowRetention) Bounded() bool { return r.MaxRows > 0 }

// RowPruneResult is what one table's prune did, or would have done in a dry
// run.
type RowPruneResult struct {
	// Deleted is the number of rows removed.
	Deleted int64 `json:"deleted"`

	// BytesReleased is the variable-width column content those rows held. It
	// is returned to the database freelist, not to the filesystem — only the
	// subsequent VACUUM shrinks the file — so callers must not add it to a
	// "bytes reclaimed" total that also counts the VACUUM.
	//
	// Measured across the rows the prune set out to remove, so when the call
	// also returns an error it describes the intent rather than the outcome.
	// Read it together with the error, never instead of it.
	BytesReleased int64 `json:"bytes_released"`

	// Remaining is the row count after the prune (before it, in a dry run).
	Remaining int64 `json:"remaining"`
}

// ProviderCallRetention bounds provider_calls, which needs two limits rather
// than one because its rows are cheap and its bodies are not.
type ProviderCallRetention struct {
	// BodyMaxAge clears prompt, system_prompt and response on rows older than
	// this, keeping the row itself. Zero or less keeps every body.
	BodyMaxAge time.Duration

	// Rows bounds the rows themselves, applied after the strip.
	Rows RowRetention
}

// Active reports whether this policy would change anything.
func (p ProviderCallRetention) Active() bool { return p.BodyMaxAge > 0 || p.Rows.Active() }

// ProviderCallPruneResult reports both halves of a provider_calls pass.
type ProviderCallPruneResult struct {
	// Stripped is the number of rows whose bodies were cleared, and
	// StrippedBytes the text those bodies held.
	Stripped      int64 `json:"stripped"`
	StrippedBytes int64 `json:"stripped_bytes"`

	RowPruneResult
}

// growthTable describes one append-only table to the generic prune.
type growthTable struct {
	// name is the table, idCol its monotonic key, timeCol the insertion
	// timestamp as RFC3339Nano text.
	name    string
	idCol   string
	timeCol string

	// bytesExpr sums the variable-width columns of one row. An estimate of
	// content, not of pages: it ignores per-row and per-page overhead and the
	// index entries that go with the row, so it under-reports what a VACUUM
	// will actually reclaim. Under-reporting is the right direction for a
	// number an operator uses to decide whether a prune was worth it.
	bytesExpr string
}

var (
	tableProviderCalls = growthTable{
		name: "provider_calls", idCol: "id", timeCol: "timestamp",
		bytesExpr: "LENGTH(prompt)+LENGTH(system_prompt)+LENGTH(response)+LENGTH(headers)" +
			"+LENGTH(task_title)+LENGTH(provider)+LENGTH(model)+LENGTH(timestamp)" +
			"+LENGTH(request_id)+LENGTH(error_message)+LENGTH(status)",
	}
	tableSteps = growthTable{
		name: "steps", idCol: "step", timeCol: "time",
		bytesExpr: "LENGTH(output)+LENGTH(task)+LENGTH(duration)+LENGTH(time)",
	}
	tableEvents = growthTable{
		name: "events", idCol: "id", timeCol: "timestamp",
		bytesExpr: "LENGTH(message)+LENGTH(details)+LENGTH(task_title)+LENGTH(type)+LENGTH(timestamp)",
	}
	tableCosts = growthTable{
		name: "costs", idCol: "id", timeCol: "timestamp",
		bytesExpr: "LENGTH(task_title)+LENGTH(provider)+LENGTH(model)+LENGTH(timestamp)",
	}
	tableTelemetryEvents = growthTable{
		name: "telemetry_events", idCol: "id", timeCol: "received_at",
		bytesExpr: "LENGTH(message)+LENGTH(stack)+LENGTH(url)+LENGTH(view)+LENGTH(detail)" +
			"+LENGTH(user_agent)+LENGTH(session)+LENGTH(received_at)",
	}
)

// GrowthTables names the row tables retention covers, in the order a report
// should list them. Exported so hubdoctor can enumerate them without
// duplicating the list and drifting from it.
func GrowthTables() []string {
	return []string{
		tableProviderCalls.name,
		tableSteps.name,
		tableEvents.name,
		tableCosts.name,
		tableTelemetryEvents.name,
	}
}

// PruneSteps bounds the steps table.
//
// Callers must not run this while an orchestrator is executing against the same
// project. steps is the one table here that is not purely append-only: a run
// holds the whole step history in memory (state.Load reads every row) and
// saveStateLocked upserts all of it on each save, so rows deleted underneath a
// live run come straight back on its next write. The janitor skips this step
// for a running project for that reason.
func (d *DB) PruneSteps(p RowRetention, now time.Time, dryRun bool) (RowPruneResult, error) {
	return d.pruneGrowthTable(tableSteps, p, now, dryRun)
}

// PruneEvents bounds the unified event history.
func (d *DB) PruneEvents(p RowRetention, now time.Time, dryRun bool) (RowPruneResult, error) {
	return d.pruneGrowthTable(tableEvents, p, now, dryRun)
}

// PruneCosts bounds the cost ledger.
//
// The ledger is mirrored to .cloop/costs.jsonl, so a pruned row is not the last
// record of the spend — which is why bounding it at all is defensible. Two
// readers still argue for a generous ceiling. `cloop cost report` aggregates
// over the whole table, so pruning shortens the history it can show; and the
// hub's spend enforcement tracks its booking position in
// project_spend_cursor.last_cost_row_id, reading forward from it with
// ReadCostsAfterID. Deleting the oldest rows cannot strand that cursor unless
// the hub has fallen more than MaxRows behind, which is a broken hub rather
// than a busy one — but it is the reason this prune takes the oldest rows and
// never the newest.
func (d *DB) PruneCosts(p RowRetention, now time.Time, dryRun bool) (RowPruneResult, error) {
	return d.pruneGrowthTable(tableCosts, p, now, dryRun)
}

// PruneTelemetryRows applies age and count retention to the browser telemetry
// trail.
//
// trimTelemetryTx already caps the table at TelemetryMaxRows on the write path,
// because a public ingest endpoint must not be able to fill a disk between two
// janitor passes. This is the age half of the policy, which no write-time cap
// can express: a debugging trail that has gone quiet should still age out.
func (d *DB) PruneTelemetryRows(p RowRetention, now time.Time, dryRun bool) (RowPruneResult, error) {
	return d.pruneGrowthTable(tableTelemetryEvents, p, now, dryRun)
}

// PruneProviderCalls strips aged bodies and then bounds the rows.
//
// The two limits are applied in that order and both are honoured: a row that is
// old enough to lose its bodies and also falls outside the row ceiling is
// deleted, and the bytes are reported once — the strip empties the columns
// before the delete measures what the row still held.
func (d *DB) PruneProviderCalls(p ProviderCallRetention, now time.Time, dryRun bool) (ProviderCallPruneResult, error) {
	var out ProviderCallPruneResult

	if p.BodyMaxAge > 0 {
		stripped, bytes, err := d.stripProviderCallBodies(p.BodyMaxAge, now, dryRun)
		if err != nil {
			return out, err
		}
		out.Stripped, out.StrippedBytes = stripped, bytes
	}

	rows, err := d.pruneGrowthTable(tableProviderCalls, p.Rows, now, dryRun)
	if err != nil {
		return out, err
	}
	out.RowPruneResult = rows
	if !p.Rows.Active() {
		// pruneGrowthTable short-circuits on an inactive policy and leaves
		// Remaining unset. The caller still wants the count.
		n, cerr := d.countRows(tableProviderCalls)
		if cerr != nil {
			return out, cerr
		}
		out.Remaining = n
	}
	return out, nil
}

// stripProviderCallBodies clears prompt, system_prompt and response on rows
// older than maxAge, stamping the headers JSON so the row says what happened to
// it.
func (d *DB) stripProviderCallBodies(maxAge time.Duration, now time.Time, dryRun bool) (stripped, bytes int64, err error) {
	cutID, ok, err := d.cutoffID(tableProviderCalls, RowRetention{MaxAge: maxAge}, now)
	if err != nil || !ok {
		return 0, 0, err
	}

	// Only rows that still hold something; re-stamping an already-stripped row
	// would move its marker forward every pass and make the record a lie.
	const hasBody = "(LENGTH(prompt)+LENGTH(system_prompt)+LENGTH(response)) > 0"

	d.mu.Lock()
	err = d.conn.QueryRow(
		`SELECT COUNT(*), IFNULL(SUM(LENGTH(prompt)+LENGTH(system_prompt)+LENGTH(response)), 0)
		   FROM provider_calls WHERE id <= ? AND `+hasBody, cutID,
	).Scan(&stripped, &bytes)
	d.mu.Unlock()
	if err != nil {
		return 0, 0, fmt.Errorf("statedb: measure provider_call bodies: %w", classifyDriverErr(err))
	}
	if dryRun || stripped == 0 {
		return stripped, bytes, nil
	}

	stamp := formatOptionalTime(now)
	// json_set on a CASE guard rather than on headers directly: the column is
	// TEXT with a '' default, and json_set of invalid JSON returns NULL, which
	// would silently blank the metadata it is supposed to annotate.
	const strip = `
		UPDATE provider_calls
		   SET prompt = '', system_prompt = '', response = '',
		       headers = json_set(
		           CASE WHEN json_valid(headers) THEN headers ELSE '{}' END,
		           '$.` + ProviderCallBodiesPrunedKey + `', ?)
		 WHERE id IN (SELECT id FROM provider_calls
		               WHERE id <= ? AND ` + hasBody + `
		               ORDER BY id LIMIT ?)`

	var done int64
	for done < stripped {
		n, err := d.execBatch(strip, stamp, cutID, rowPruneBatch)
		if err != nil {
			return done, bytes, fmt.Errorf("statedb: strip provider_call bodies: %w", err)
		}
		if n == 0 {
			break
		}
		done += n
	}
	return done, bytes, nil
}

// pruneGrowthTable applies a RowRetention to one table.
func (d *DB) pruneGrowthTable(t growthTable, p RowRetention, now time.Time, dryRun bool) (RowPruneResult, error) {
	var out RowPruneResult
	if !p.Active() {
		return out, nil
	}

	cutID, ok, err := d.cutoffID(t, p, now)
	if err != nil {
		return out, err
	}
	if !ok {
		n, err := d.countRows(t)
		if err != nil {
			return out, err
		}
		out.Remaining = n
		return out, nil
	}

	d.mu.Lock()
	err = d.conn.QueryRow(
		fmt.Sprintf(`SELECT COUNT(*), IFNULL(SUM(%s), 0) FROM %s WHERE %s <= ?`,
			t.bytesExpr, t.name, t.idCol), cutID,
	).Scan(&out.Deleted, &out.BytesReleased)
	d.mu.Unlock()
	if err != nil {
		return out, fmt.Errorf("statedb: measure %s: %w", t.name, classifyDriverErr(err))
	}

	if dryRun {
		total, err := d.countRows(t)
		if err != nil {
			return out, err
		}
		// What *would* remain, not what currently does. A preview that reported
		// the pre-prune count alongside the rows it plans to delete reads as
		// "deleted 25, 30 remain", which is nonsense on either reading.
		out.Remaining = total - out.Deleted
		return out, nil
	}

	// Deleted is reassigned from what the loop achieved, not left at what the
	// measurement planned. A batch that fails partway through — a locked
	// database, a full disk — leaves rows behind, and reporting the plan as
	// though it were the outcome would tell an operator the table is bounded
	// when it is not.
	done, err := d.deleteUpToID(t, cutID)
	out.Deleted = done
	if err != nil {
		return out, err
	}

	total, err := d.countRows(t)
	if err != nil {
		return out, err
	}
	out.Remaining = total
	return out, nil
}

// deleteUpToID removes every row at or below cutID, in bounded batches.
//
// Terminates on a batch that deletes nothing rather than on a precomputed
// count: another process may have removed some of the same rows in between, and
// a loop that insists on its own arithmetic would spin.
func (d *DB) deleteUpToID(t growthTable, cutID int64) (int64, error) {
	del := fmt.Sprintf(
		`DELETE FROM %s WHERE %s IN (SELECT %s FROM %s WHERE %s <= ? ORDER BY %s LIMIT ?)`,
		t.name, t.idCol, t.idCol, t.name, t.idCol, t.idCol)

	var done int64
	for {
		n, err := d.execBatch(del, cutID, rowPruneBatch)
		if err != nil {
			return done, fmt.Errorf("statedb: prune %s: %w", t.name, err)
		}
		if n == 0 {
			return done, nil
		}
		done += n
	}
}

// execBatch runs one bounded write in its own transaction and reports how many
// rows it touched. Takes and releases the process mutex so a batch loop does
// not lock out the rest of the process for the whole backlog.
func (d *DB) execBatch(query string, args ...any) (int64, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	tx, err := d.conn.Begin()
	if err != nil {
		return 0, classifyDriverErr(err)
	}
	defer func() { _ = tx.Rollback() }()

	res, err := tx.Exec(query, args...)
	if err != nil {
		return 0, classifyDriverErr(err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		// The statement ran; only the count is unavailable. Report zero and let
		// the caller's loop terminate rather than spin on an unknown.
		n = 0
	}
	if err := tx.Commit(); err != nil {
		return 0, classifyDriverErr(err)
	}
	return n, nil
}

// cutoffID returns the highest id the policy permits deleting, and whether
// there is one at all.
func (d *DB) cutoffID(t growthTable, p RowRetention, now time.Time) (int64, bool, error) {
	var (
		cut   int64
		found bool
	)
	if p.MaxRows > 0 {
		id, ok, err := d.countCutoffID(t, p.MaxRows)
		if err != nil {
			return 0, false, err
		}
		if ok {
			cut, found = id, true
		}
	}
	if p.MaxAge > 0 {
		id, ok, err := d.ageCutoffID(t, now.Add(-p.MaxAge))
		if err != nil {
			return 0, false, err
		}
		if ok && (!found || id > cut) {
			cut, found = id, true
		}
	}
	return cut, found, nil
}

// countCutoffID returns the highest id outside the newest maxRows rows.
func (d *DB) countCutoffID(t growthTable, maxRows int) (int64, bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	var id int64
	err := d.conn.QueryRow(fmt.Sprintf(
		`SELECT %s FROM %s ORDER BY %s DESC LIMIT 1 OFFSET ?`,
		t.idCol, t.name, t.idCol), maxRows).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, false, nil // fewer rows than the ceiling
	}
	if err != nil {
		return 0, false, fmt.Errorf("statedb: %s count cutoff: %w", t.name, classifyDriverErr(err))
	}
	return id, true, nil
}

// ageCutoffID returns the highest id in the leading run of rows older than
// cutoff.
//
// It walks forward and stops at the first row that is not older, rather than
// asking SQL for MAX(id) WHERE timestamp < ?. Two reasons, both learned from
// this schema. The timestamps are TEXT, so a string comparison is only an
// ordering if every writer formatted UTC with the same fractional precision —
// LoadStateLite already carries a comment about that assumption not holding.
// And a row whose timestamp does not parse has no age, so the safe reading is
// "not old enough", which stops the scan rather than deleting into the unknown.
func (d *DB) ageCutoffID(t growthTable, cutoff time.Time) (int64, bool, error) {
	var (
		last  int64
		found bool
	)
	scan := fmt.Sprintf(`SELECT %s, %s FROM %s WHERE %s > ? ORDER BY %s LIMIT ?`,
		t.idCol, t.timeCol, t.name, t.idCol, t.idCol)

	for {
		d.mu.Lock()
		rows, err := d.conn.Query(scan, last, ageScanChunk)
		if err != nil {
			d.mu.Unlock()
			return 0, false, fmt.Errorf("statedb: %s age scan: %w", t.name, classifyDriverErr(err))
		}
		var (
			seen    int
			stopped bool
		)
		for rows.Next() {
			var (
				id int64
				ts string
			)
			if err := rows.Scan(&id, &ts); err != nil {
				_ = rows.Close()
				d.mu.Unlock()
				return 0, false, fmt.Errorf("statedb: %s age scan: %w", t.name, classifyDriverErr(err))
			}
			seen++
			at := parseOptionalTime(ts)
			if at.IsZero() || !at.Before(cutoff) {
				stopped = true
				break
			}
			last, found = id, true
		}
		iterErr := rows.Err()
		_ = rows.Close()
		d.mu.Unlock()
		if iterErr != nil && !stopped {
			return 0, false, fmt.Errorf("statedb: %s age scan: %w", t.name, classifyDriverErr(iterErr))
		}
		if stopped || seen < ageScanChunk {
			break
		}
	}
	return last, found, nil
}

func (d *DB) countRows(t growthTable) (int64, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	var n int64
	if err := d.conn.QueryRow(fmt.Sprintf(`SELECT COUNT(*) FROM %s`, t.name)).Scan(&n); err != nil {
		return 0, fmt.Errorf("statedb: count %s: %w", t.name, classifyDriverErr(err))
	}
	return n, nil
}

// TableStat is one row table's current size, for reporting.
type TableStat struct {
	Name string `json:"name"`
	Rows int64  `json:"rows"`
	// Bytes is the variable-width column content across all rows. See
	// growthTable.bytesExpr: an under-estimate of what the table costs on disk,
	// deliberately.
	Bytes int64 `json:"bytes"`
	// Oldest is the insertion timestamp of the lowest-id row, or the zero time
	// when the table is empty or that row's timestamp will not parse.
	Oldest time.Time `json:"oldest,omitempty"`
}

// GrowthTableStats measures every table retention covers.
//
// One full scan per table: `cloop hub doctor` is an on-demand command and the
// whole point of the finding is to be accurate about a table nobody has looked
// at. Not for a request path.
func (d *DB) GrowthTableStats() ([]TableStat, error) {
	tables := []growthTable{
		tableProviderCalls, tableSteps, tableEvents, tableCosts, tableTelemetryEvents,
	}
	out := make([]TableStat, 0, len(tables))
	for _, t := range tables {
		st, err := d.growthTableStat(t)
		if err != nil {
			return nil, err
		}
		out = append(out, st)
	}
	return out, nil
}

func (d *DB) growthTableStat(t growthTable) (TableStat, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	st := TableStat{Name: t.name}
	if err := d.conn.QueryRow(fmt.Sprintf(
		`SELECT COUNT(*), IFNULL(SUM(%s), 0) FROM %s`, t.bytesExpr, t.name),
	).Scan(&st.Rows, &st.Bytes); err != nil {
		return st, fmt.Errorf("statedb: measure %s: %w", t.name, classifyDriverErr(err))
	}
	if st.Rows == 0 {
		return st, nil
	}
	var ts string
	if err := d.conn.QueryRow(fmt.Sprintf(
		`SELECT %s FROM %s ORDER BY %s LIMIT 1`, t.timeCol, t.name, t.idCol),
	).Scan(&ts); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return st, nil
		}
		return st, fmt.Errorf("statedb: oldest %s: %w", t.name, classifyDriverErr(err))
	}
	st.Oldest = parseOptionalTime(ts)
	return st, nil
}

// ProviderCallBodiesPruned reports when a provider-call row's bodies were
// dropped by retention, reading the marker out of its headers JSON.
//
// ok is false for a row that still has its bodies, which is every row on a hub
// where the strip has not run. Callers that render or replay a prompt should
// check this before treating an empty prompt as the truth.
func ProviderCallBodiesPruned(headersJSON string) (time.Time, bool) {
	if headersJSON == "" {
		return time.Time{}, false
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal([]byte(headersJSON), &m); err != nil {
		return time.Time{}, false
	}
	raw, ok := m[ProviderCallBodiesPrunedKey]
	if !ok {
		return time.Time{}, false
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return time.Time{}, false
	}
	at := parseOptionalTime(s)
	if at.IsZero() {
		// The marker is present but unreadable. Still a positive statement that
		// the bodies went — losing the "when" must not resurrect the "whether".
		return time.Time{}, true
	}
	return at, true
}
