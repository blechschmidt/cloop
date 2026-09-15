package statedb

// Tests for the row-table retention added in Task 20291.
//
// Each table is seeded past its limit and the prune is asserted to bound it;
// the dry-run path is asserted to change nothing. The provider-call tests also
// pin the property the whole design rests on — that stripping a body leaves the
// row's metadata intact, because the inspector list and the cost reports read
// the metadata and never the body.

import (
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/telemetry"
)

// ─── fixtures ────────────────────────────────────────────────────────────────

// seedProviderCalls inserts n rows, the oldest first, spaced one day apart and
// ending `newestAge` before now. Each carries a body of bodyKB.
func seedProviderCalls(t *testing.T, db *DB, n int, newestAge time.Duration, bodyKB int) {
	t.Helper()
	body := strings.Repeat("p", bodyKB*1024)
	for i := 0; i < n; i++ {
		age := newestAge + time.Duration(n-1-i)*24*time.Hour
		if _, err := db.AppendProviderCall(ProviderCallRow{
			Timestamp: time.Now().Add(-age).UTC(),
			Provider:  "anthropic", Model: "claude-opus-4-8",
			TaskID: i + 1, TaskTitle: fmt.Sprintf("task %d", i+1),
			Prompt: body, SystemPrompt: "sys", Response: "ok", Status: "ok",
			Headers:      `{"max_tokens":4096}`,
			InputTokens:  100 + i,
			OutputTokens: 7,
			LatencyMs:    1234,
		}); err != nil {
			t.Fatalf("AppendProviderCall %d: %v", i, err)
		}
	}
}

func seedSteps(t *testing.T, db *DB, n int, newestAge time.Duration) {
	t.Helper()
	for i := 0; i < n; i++ {
		age := newestAge + time.Duration(n-1-i)*time.Hour
		if err := db.AppendStep(StepRow{
			Step: i + 1, Task: "fixture", Output: strings.Repeat("o", 256),
			Duration: "1s", Time: time.Now().Add(-age).UTC(),
		}); err != nil {
			t.Fatalf("AppendStep %d: %v", i, err)
		}
	}
}

func seedEvents(t *testing.T, db *DB, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		if err := db.RecordEvent(EventRow{
			Timestamp: time.Now().Add(-time.Duration(n-i) * time.Minute).UTC(),
			Type:      "task_started", TaskID: i + 1, Message: "seeded", Step: -1,
		}); err != nil {
			t.Fatalf("RecordEvent %d: %v", i, err)
		}
	}
}

func seedCosts(t *testing.T, db *DB, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		if err := db.AppendCost(CostEntry{
			Timestamp: time.Now().Add(-time.Duration(n-i) * time.Minute).UTC(),
			TaskID:    i + 1, TaskTitle: "seeded", Provider: "anthropic",
			Model: "claude-opus-4-8", InputTokens: 10, OutputTokens: 5, EstimatedUSD: 0.01,
		}); err != nil {
			t.Fatalf("AppendCost %d: %v", i, err)
		}
	}
}

func rowCount(t *testing.T, db *DB, table string) int64 {
	t.Helper()
	var n int64
	if err := db.conn.QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&n); err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	return n
}

// ─── count bounds ────────────────────────────────────────────────────────────

func TestPruneBoundsEachTableByRowCount(t *testing.T) {
	const (
		seeded = 40
		keep   = 10
	)
	cases := []struct {
		table string
		seed  func(*DB)
		prune func(*DB) (RowPruneResult, error)
	}{
		{
			table: "steps",
			seed:  func(db *DB) { seedSteps(t, db, seeded, time.Hour) },
			prune: func(db *DB) (RowPruneResult, error) {
				return db.PruneSteps(RowRetention{MaxRows: keep}, time.Now(), false)
			},
		},
		{
			table: "events",
			seed:  func(db *DB) { seedEvents(t, db, seeded) },
			prune: func(db *DB) (RowPruneResult, error) {
				return db.PruneEvents(RowRetention{MaxRows: keep}, time.Now(), false)
			},
		},
		{
			table: "costs",
			seed:  func(db *DB) { seedCosts(t, db, seeded) },
			prune: func(db *DB) (RowPruneResult, error) {
				return db.PruneCosts(RowRetention{MaxRows: keep}, time.Now(), false)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.table, func(t *testing.T) {
			db := openTestDB(t)
			tc.seed(db)
			if got := rowCount(t, db, tc.table); got != seeded {
				t.Fatalf("seed: %s has %d rows, want %d", tc.table, got, seeded)
			}

			res, err := tc.prune(db)
			if err != nil {
				t.Fatalf("prune %s: %v", tc.table, err)
			}
			if res.Deleted != seeded-keep {
				t.Errorf("Deleted = %d, want %d", res.Deleted, seeded-keep)
			}
			if res.Remaining != keep {
				t.Errorf("Remaining = %d, want %d", res.Remaining, keep)
			}
			if res.BytesReleased <= 0 {
				t.Errorf("BytesReleased = %d, want > 0", res.BytesReleased)
			}
			if got := rowCount(t, db, tc.table); got != keep {
				t.Errorf("%s has %d rows after prune, want %d", tc.table, got, keep)
			}

			// Idempotent: a second pass over a table already at its ceiling
			// must not delete anything.
			again, err := tc.prune(db)
			if err != nil {
				t.Fatalf("second prune: %v", err)
			}
			if again.Deleted != 0 {
				t.Errorf("second prune deleted %d rows, want 0", again.Deleted)
			}
		})
	}
}

// TestPruneKeepsTheNewestRows pins *which* rows survive. A ceiling that kept an
// arbitrary subset would satisfy a row count and be useless.
func TestPruneKeepsTheNewestRows(t *testing.T) {
	db := openTestDB(t)
	seedEvents(t, db, 30)

	if _, err := db.PruneEvents(RowRetention{MaxRows: 5}, time.Now(), false); err != nil {
		t.Fatalf("PruneEvents: %v", err)
	}

	var lo, hi int64
	if err := db.conn.QueryRow(`SELECT MIN(id), MAX(id) FROM events`).Scan(&lo, &hi); err != nil {
		t.Fatalf("range: %v", err)
	}
	if hi != 30 {
		t.Errorf("newest surviving id = %d, want 30", hi)
	}
	if lo != 26 {
		t.Errorf("oldest surviving id = %d, want 26 (the newest five)", lo)
	}
}

// ─── age bounds ──────────────────────────────────────────────────────────────

func TestPruneTelemetryRowsBoundsByAge(t *testing.T) {
	db := openTestDB(t)
	// Ten events an hour apart; the oldest six are more than four hours old.
	for i := 0; i < 10; i++ {
		ev := telEvent("s1", int64(i), telemetry.KindNote, "seeded")
		ev.At = time.Now().Add(-time.Duration(10-i) * time.Hour).UTC()
		if err := db.AppendTelemetry([]telemetry.Event{ev}); err != nil {
			t.Fatalf("AppendTelemetry %d: %v", i, err)
		}
	}

	// A cutoff of 4h30m rather than 4h: the seeded rows sit on exact hours, and
	// a cutoff on one of them would make the outcome depend on how long the
	// seeding took.
	res, err := db.PruneTelemetryRows(RowRetention{MaxAge: 4*time.Hour + 30*time.Minute}, time.Now(), false)
	if err != nil {
		t.Fatalf("PruneTelemetryRows: %v", err)
	}
	if res.Deleted != 6 {
		t.Errorf("Deleted = %d, want 6", res.Deleted)
	}
	if res.Remaining != 4 {
		t.Errorf("Remaining = %d, want 4", res.Remaining)
	}
}

// TestAgeScanStopsAtAnUndatableRow pins the conservative direction: a row whose
// timestamp will not parse has no age, so it stops the scan rather than being
// swept into the delete along with everything around it.
func TestAgeScanStopsAtAnUndatableRow(t *testing.T) {
	db := openTestDB(t)
	seedEvents(t, db, 10) // all within the last ten minutes

	// Age rows 1-6 well past any cutoff, then corrupt row 3's timestamp.
	old := time.Now().Add(-90 * 24 * time.Hour).UTC().Format(time.RFC3339Nano)
	if _, err := db.conn.Exec(`UPDATE events SET timestamp = ? WHERE id <= 6`, old); err != nil {
		t.Fatalf("age rows: %v", err)
	}
	if _, err := db.conn.Exec(`UPDATE events SET timestamp = 'not a timestamp' WHERE id = 3`); err != nil {
		t.Fatalf("corrupt row: %v", err)
	}

	res, err := db.PruneEvents(RowRetention{MaxAge: 24 * time.Hour}, time.Now(), false)
	if err != nil {
		t.Fatalf("PruneEvents: %v", err)
	}
	// Rows 1 and 2 go; row 3 stops the scan, so 4-6 survive despite being old.
	if res.Deleted != 2 {
		t.Errorf("Deleted = %d, want 2 (the scan must stop at the undatable row)", res.Deleted)
	}
	if got := rowCount(t, db, "events"); got != 8 {
		t.Errorf("events has %d rows, want 8", got)
	}
}

// ─── dry run ─────────────────────────────────────────────────────────────────

func TestPruneDryRunDeletesNothing(t *testing.T) {
	db := openTestDB(t)
	seedSteps(t, db, 30, time.Hour)
	seedEvents(t, db, 30)
	seedCosts(t, db, 30)
	seedProviderCalls(t, db, 10, 60*24*time.Hour, 4)

	before := map[string]int64{}
	for _, tbl := range GrowthTables() {
		before[tbl] = rowCount(t, db, tbl)
	}
	var bodyBytesBefore int64
	if err := db.conn.QueryRow(
		`SELECT IFNULL(SUM(LENGTH(prompt)+LENGTH(response)), 0) FROM provider_calls`,
	).Scan(&bodyBytesBefore); err != nil {
		t.Fatalf("measure bodies: %v", err)
	}

	steps, err := db.PruneSteps(RowRetention{MaxRows: 5}, time.Now(), true)
	if err != nil {
		t.Fatalf("PruneSteps: %v", err)
	}
	events, err := db.PruneEvents(RowRetention{MaxRows: 5}, time.Now(), true)
	if err != nil {
		t.Fatalf("PruneEvents: %v", err)
	}
	costs, err := db.PruneCosts(RowRetention{MaxRows: 5}, time.Now(), true)
	if err != nil {
		t.Fatalf("PruneCosts: %v", err)
	}
	calls, err := db.PruneProviderCalls(ProviderCallRetention{
		BodyMaxAge: 24 * time.Hour,
		Rows:       RowRetention{MaxRows: 5},
	}, time.Now(), true)
	if err != nil {
		t.Fatalf("PruneProviderCalls: %v", err)
	}

	// A dry run still reports what it would have done — a report of zero would
	// make the flag useless for previewing a policy.
	if steps.Deleted != 25 || events.Deleted != 25 || costs.Deleted != 25 {
		t.Errorf("dry run reported %d/%d/%d deletions, want 25 each",
			steps.Deleted, events.Deleted, costs.Deleted)
	}
	// Remaining is what *would* be left, not what currently is — otherwise the
	// preview reads "deleted 25, 30 remain".
	if steps.Remaining != 5 || events.Remaining != 5 || costs.Remaining != 5 {
		t.Errorf("dry run reported %d/%d/%d remaining, want 5 each",
			steps.Remaining, events.Remaining, costs.Remaining)
	}
	if calls.Stripped != 10 {
		t.Errorf("dry run reported %d strips, want 10", calls.Stripped)
	}
	if calls.StrippedBytes <= 0 {
		t.Errorf("dry run reported %d stripped bytes, want > 0", calls.StrippedBytes)
	}

	for _, tbl := range GrowthTables() {
		if got := rowCount(t, db, tbl); got != before[tbl] {
			t.Errorf("dry run changed %s: %d rows, want %d", tbl, got, before[tbl])
		}
	}
	var bodyBytesAfter int64
	if err := db.conn.QueryRow(
		`SELECT IFNULL(SUM(LENGTH(prompt)+LENGTH(response)), 0) FROM provider_calls`,
	).Scan(&bodyBytesAfter); err != nil {
		t.Fatalf("measure bodies: %v", err)
	}
	if bodyBytesAfter != bodyBytesBefore {
		t.Errorf("dry run stripped bodies: %d bytes remain, want %d", bodyBytesAfter, bodyBytesBefore)
	}
}

// ─── provider calls ──────────────────────────────────────────────────────────

// TestStripProviderCallBodiesKeepsMetadata is the central claim of the design:
// the bytes go and everything the inspector list and the cost reports read
// stays.
func TestStripProviderCallBodiesKeepsMetadata(t *testing.T) {
	db := openTestDB(t)
	// Five rows 40+ days old, five within the last five days.
	seedProviderCalls(t, db, 5, 40*24*time.Hour, 8)
	seedProviderCalls(t, db, 5, 24*time.Hour, 8)

	res, err := db.PruneProviderCalls(ProviderCallRetention{
		BodyMaxAge: 30 * 24 * time.Hour,
	}, time.Now(), false)
	if err != nil {
		t.Fatalf("PruneProviderCalls: %v", err)
	}
	if res.Stripped != 5 {
		t.Fatalf("Stripped = %d, want 5", res.Stripped)
	}
	if res.StrippedBytes < 5*8*1024 {
		t.Errorf("StrippedBytes = %d, want at least %d", res.StrippedBytes, 5*8*1024)
	}
	if res.Deleted != 0 {
		t.Errorf("Deleted = %d, want 0 — no row limit was set", res.Deleted)
	}
	if res.Remaining != 10 {
		t.Errorf("Remaining = %d, want 10", res.Remaining)
	}

	// The list endpoint's fields must be untouched on a stripped row.
	old, err := db.LoadProviderCall(1)
	if err != nil {
		t.Fatalf("LoadProviderCall(1): %v", err)
	}
	if old.Prompt != "" || old.Response != "" || old.SystemPrompt != "" {
		t.Errorf("row 1 kept a body: prompt=%d response=%d system=%d bytes",
			len(old.Prompt), len(old.Response), len(old.SystemPrompt))
	}
	if old.Provider != "anthropic" || old.Model != "claude-opus-4-8" {
		t.Errorf("row 1 lost its provider/model: %q/%q", old.Provider, old.Model)
	}
	if old.InputTokens != 100 || old.OutputTokens != 7 || old.LatencyMs != 1234 {
		t.Errorf("row 1 lost its metrics: in=%d out=%d latency=%d",
			old.InputTokens, old.OutputTokens, old.LatencyMs)
	}
	if old.TaskID != 1 || old.TaskTitle != "task 1" {
		t.Errorf("row 1 lost its task binding: %d/%q", old.TaskID, old.TaskTitle)
	}
	if old.Timestamp.IsZero() {
		t.Error("row 1 lost its timestamp")
	}

	// And it says it was stripped, rather than looking like an empty call.
	at, pruned := ProviderCallBodiesPruned(old.Headers)
	if !pruned {
		t.Fatalf("row 1 carries no pruned marker; headers = %q", old.Headers)
	}
	if at.IsZero() {
		t.Error("pruned marker has no timestamp")
	}
	// The pre-existing header keys survive the stamp.
	if !strings.Contains(old.Headers, "max_tokens") {
		t.Errorf("stamping the marker dropped the original headers: %q", old.Headers)
	}

	// The recent rows are untouched, marker included.
	recent, err := db.LoadProviderCall(10)
	if err != nil {
		t.Fatalf("LoadProviderCall(10): %v", err)
	}
	if len(recent.Prompt) != 8*1024 {
		t.Errorf("recent row lost its prompt: %d bytes", len(recent.Prompt))
	}
	if _, pruned := ProviderCallBodiesPruned(recent.Headers); pruned {
		t.Error("recent row was marked as pruned")
	}
}

// TestStripProviderCallBodiesIsIdempotent pins that a second pass neither
// re-counts the bytes nor moves the marker forward — a marker that advanced
// every night would stop being a record of when the bodies went.
func TestStripProviderCallBodiesIsIdempotent(t *testing.T) {
	db := openTestDB(t)
	seedProviderCalls(t, db, 3, 40*24*time.Hour, 4)

	first, err := db.PruneProviderCalls(ProviderCallRetention{BodyMaxAge: 24 * time.Hour}, time.Now(), false)
	if err != nil {
		t.Fatalf("first prune: %v", err)
	}
	if first.Stripped != 3 {
		t.Fatalf("first prune stripped %d, want 3", first.Stripped)
	}
	row, err := db.LoadProviderCall(1)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	markedAt, _ := ProviderCallBodiesPruned(row.Headers)

	second, err := db.PruneProviderCalls(ProviderCallRetention{BodyMaxAge: 24 * time.Hour},
		time.Now().Add(time.Hour), false)
	if err != nil {
		t.Fatalf("second prune: %v", err)
	}
	if second.Stripped != 0 || second.StrippedBytes != 0 {
		t.Errorf("second prune stripped %d rows / %d bytes, want 0/0",
			second.Stripped, second.StrippedBytes)
	}
	row, err = db.LoadProviderCall(1)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	againAt, _ := ProviderCallBodiesPruned(row.Headers)
	if !againAt.Equal(markedAt) {
		t.Errorf("marker moved from %s to %s", markedAt, againAt)
	}
}

// TestPruneProviderCallsAppliesBothLimits covers the interaction: the strip
// runs first, so the rows the ceiling then deletes are already empty and their
// bytes are reported once rather than twice.
func TestPruneProviderCallsAppliesBothLimits(t *testing.T) {
	db := openTestDB(t)
	seedProviderCalls(t, db, 12, 40*24*time.Hour, 4)

	res, err := db.PruneProviderCalls(ProviderCallRetention{
		BodyMaxAge: 24 * time.Hour,
		Rows:       RowRetention{MaxRows: 4},
	}, time.Now(), false)
	if err != nil {
		t.Fatalf("PruneProviderCalls: %v", err)
	}
	if res.Stripped != 12 {
		t.Errorf("Stripped = %d, want 12", res.Stripped)
	}
	if res.Deleted != 8 {
		t.Errorf("Deleted = %d, want 8", res.Deleted)
	}
	if res.Remaining != 4 {
		t.Errorf("Remaining = %d, want 4", res.Remaining)
	}
	// The deleted rows had already lost their bodies, so the delete's byte
	// count must be small — if it still counted the prompts, the caller would
	// be told the same bytes were freed twice.
	if res.BytesReleased > res.StrippedBytes/10 {
		t.Errorf("delete reported %d bytes against %d stripped: bodies were counted twice",
			res.BytesReleased, res.StrippedBytes)
	}
}

// TestBodiesPrunedMarkerParsing covers the marker reader's edge cases, since it
// gates whether the UI offers to replay a call.
func TestBodiesPrunedMarkerParsing(t *testing.T) {
	cases := []struct {
		name    string
		headers string
		want    bool
	}{
		{"empty", "", false},
		{"no marker", `{"max_tokens":4096}`, false},
		{"not json", `max_tokens=4096`, false},
		{"marker present", `{"` + ProviderCallBodiesPrunedKey + `":"2026-09-15T12:00:00Z"}`, true},
		// An unreadable "when" must not resurrect the "whether": the bodies are
		// still gone, and offering to replay them would be wrong.
		{"marker unparseable", `{"` + ProviderCallBodiesPrunedKey + `":"yesterday"}`, true},
		{"marker wrong type", `{"` + ProviderCallBodiesPrunedKey + `":42}`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, got := ProviderCallBodiesPruned(tc.headers); got != tc.want {
				t.Errorf("ProviderCallBodiesPruned(%q) = %v, want %v", tc.headers, got, tc.want)
			}
		})
	}
}

// ─── policy plumbing ─────────────────────────────────────────────────────────

func TestInactiveRetentionIsANoOp(t *testing.T) {
	db := openTestDB(t)
	seedEvents(t, db, 20)

	res, err := db.PruneEvents(RowRetention{}, time.Now(), false)
	if err != nil {
		t.Fatalf("PruneEvents: %v", err)
	}
	if res.Deleted != 0 {
		t.Errorf("Deleted = %d, want 0", res.Deleted)
	}
	if got := rowCount(t, db, "events"); got != 20 {
		t.Errorf("events has %d rows, want 20", got)
	}
}

// ─── concurrency ─────────────────────────────────────────────────────────────

// TestPruneIsSafeAgainstAConcurrentWriter pins the property the whole design
// rests on, and the one a comment cannot establish: a prune running while
// another connection appends must never take a row that writer just added.
//
// This is the real deployment shape rather than a synthetic race. The janitor
// runs inside the hub while an orchestrator subprocess writes to the same file
// over its own connection, so the test uses a second *DB — two connections, one
// file, WAL — instead of two goroutines sharing one handle, which would prove
// only that the process mutex works.
//
// The invariant is asserted by identity, not by count. Every id the writer
// produced must still be present; counting rows would pass just as well if the
// prune had deleted a fresh row and the writer had happened to add another.
func TestPruneIsSafeAgainstAConcurrentWriter(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	db, err := Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close() //nolint:errcheck // test cleanup

	// A backlog worth batching: rowPruneBatch is 2000, so this forces the
	// delete loop through several transactions and gives the writer real
	// opportunity to interleave rather than racing one atomic statement.
	const (
		seeded = 5000
		keep   = 100
		writes = 200
	)
	seedEvents(t, db, seeded)

	writer, err := Open(path)
	if err != nil {
		t.Fatalf("open second connection: %v", err)
	}
	defer writer.Close() //nolint:errcheck // test cleanup

	var (
		wg        sync.WaitGroup
		writeErr  error
		writtenAt = make([]string, 0, writes)
		mu        sync.Mutex
	)
	start := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		for i := 0; i < writes; i++ {
			// A marker unique to this writer, so the survivors can be identified
			// without depending on ids the prune is concurrently reasoning about.
			msg := fmt.Sprintf("concurrent-%d", i)
			if err := writer.RecordEvent(EventRow{
				Timestamp: time.Now().UTC(), Type: "task_started",
				TaskID: i + 1, Message: msg, Step: -1,
			}); err != nil {
				mu.Lock()
				writeErr = fmt.Errorf("write %d: %w", i, err)
				mu.Unlock()
				return
			}
			mu.Lock()
			writtenAt = append(writtenAt, msg)
			mu.Unlock()
		}
	}()

	close(start)
	res, pruneErr := db.PruneEvents(RowRetention{MaxRows: keep}, time.Now(), false)
	wg.Wait()

	if pruneErr != nil {
		t.Fatalf("PruneEvents under a concurrent writer: %v", pruneErr)
	}
	if writeErr != nil {
		t.Fatalf("concurrent writer failed while the prune ran: %v", writeErr)
	}
	if len(writtenAt) != writes {
		t.Fatalf("writer recorded %d rows, want %d", len(writtenAt), writes)
	}

	// Not one of the writer's rows may have been swept up. They were all
	// inserted above the cut, so an id-bounded prune cannot reach them.
	for _, msg := range writtenAt {
		var n int
		if err := db.conn.QueryRow(
			`SELECT COUNT(*) FROM events WHERE message = ?`, msg).Scan(&n); err != nil {
			t.Fatalf("look up %s: %v", msg, err)
		}
		if n != 1 {
			t.Fatalf("row %q written during the prune is gone (found %d)", msg, n)
		}
	}

	// And the prune still did its job: everything at or below the cut went.
	if res.Deleted < seeded-keep {
		t.Errorf("deleted %d rows, want at least %d", res.Deleted, seeded-keep)
	}
	total := rowCount(t, db, "events")
	if total > keep+writes {
		t.Errorf("events has %d rows, want no more than %d", total, keep+writes)
	}
}

// TestStripIsSafeAgainstAConcurrentWriter is the same property for the UPDATE
// path. A strip that reached a row inserted after its cut would blank a live
// call's prompt — the write path's data, destroyed by a maintenance pass.
func TestStripIsSafeAgainstAConcurrentWriter(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	db, err := Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close() //nolint:errcheck // test cleanup

	// All old enough to be stripped, so the cut covers the whole seeded set and
	// only ordering keeps the writer's rows out of it.
	seedProviderCalls(t, db, 300, 60*24*time.Hour, 2)

	writer, err := Open(path)
	if err != nil {
		t.Fatalf("open second connection: %v", err)
	}
	defer writer.Close() //nolint:errcheck // test cleanup

	const writes = 50
	var (
		wg       sync.WaitGroup
		writeErr error
		ids      []int64
		mu       sync.Mutex
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < writes; i++ {
			id, err := writer.AppendProviderCall(ProviderCallRow{
				Timestamp: time.Now().UTC(), Provider: "anthropic",
				Model: "claude-opus-4-8", TaskID: i + 1,
				Prompt: "live prompt", Response: "live response", Status: "ok",
			})
			if err != nil {
				mu.Lock()
				writeErr = fmt.Errorf("write %d: %w", i, err)
				mu.Unlock()
				return
			}
			mu.Lock()
			ids = append(ids, id)
			mu.Unlock()
		}
	}()

	_, _, stripErr := db.stripProviderCallBodies(24*time.Hour, time.Now(), false)
	wg.Wait()

	if stripErr != nil {
		t.Fatalf("strip under a concurrent writer: %v", stripErr)
	}
	if writeErr != nil {
		t.Fatalf("concurrent writer failed while the strip ran: %v", writeErr)
	}

	for _, id := range ids {
		var prompt, response string
		if err := db.conn.QueryRow(
			`SELECT prompt, response FROM provider_calls WHERE id = ?`, id,
		).Scan(&prompt, &response); err != nil {
			t.Fatalf("read row %d: %v", id, err)
		}
		if prompt != "live prompt" || response != "live response" {
			t.Fatalf("row %d written during the strip was blanked: prompt=%q response=%q",
				id, prompt, response)
		}
	}
}

func TestGrowthTableStats(t *testing.T) {
	db := openTestDB(t)
	seedEvents(t, db, 7)
	seedProviderCalls(t, db, 2, time.Hour, 1)

	stats, err := db.GrowthTableStats()
	if err != nil {
		t.Fatalf("GrowthTableStats: %v", err)
	}
	if len(stats) != len(GrowthTables()) {
		t.Fatalf("got %d stats, want %d", len(stats), len(GrowthTables()))
	}
	byName := map[string]TableStat{}
	for _, s := range stats {
		byName[s.Name] = s
	}
	if got := byName["events"].Rows; got != 7 {
		t.Errorf("events rows = %d, want 7", got)
	}
	if byName["events"].Oldest.IsZero() {
		t.Error("events has no oldest timestamp")
	}
	if got := byName["provider_calls"].Rows; got != 2 {
		t.Errorf("provider_calls rows = %d, want 2", got)
	}
	if byName["provider_calls"].Bytes < 2*1024 {
		t.Errorf("provider_calls bytes = %d, want at least 2 KiB", byName["provider_calls"].Bytes)
	}
	// An empty table is reported, not omitted: "costs: 0 rows" is the answer
	// the hub doctor needs, and a missing entry would read as a broken probe.
	if _, ok := byName["costs"]; !ok {
		t.Error("costs missing from the stats")
	}
}
