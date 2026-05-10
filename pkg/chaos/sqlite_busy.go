package chaos

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync"
	"time"

	_ "modernc.org/sqlite" // pure-Go SQLite driver, no CGo
)

// BusyHolder injects sqlite-busy contention by opening a sibling connection
// to the project's state database and parking a write transaction inside it.
// While the transaction is open, every other writer that exceeds the project's
// busy_timeout returns SQLITE_BUSY — the realistic SQLITE_BUSY scenario the
// rest of cloop's code is designed to survive.
//
// The holder uses an *exclusive* transaction (BEGIN IMMEDIATE) so reads from
// other connections still proceed under WAL — only writers contend, which
// matches the production failure mode we want to reproduce.
//
// Concurrency: a holder is single-shot. Start opens the transaction, Stop
// rolls it back. Stop is safe to call multiple times and returns the wall-
// clock duration the transaction was actually held.
type BusyHolder struct {
	dbPath string

	mu      sync.Mutex
	conn    *sql.DB
	tx      *sql.Tx
	startAt time.Time
	stopped bool
}

// NewBusyHolder creates a holder targeting the given database file.
func NewBusyHolder(dbPath string) *BusyHolder {
	return &BusyHolder{dbPath: dbPath}
}

// Start opens the auxiliary connection and begins the immediate transaction.
// Must be paired with Stop. Returns an error if the database file is missing
// or the BEGIN IMMEDIATE itself cannot acquire the write lock within
// busyTimeout.
//
// The transaction is held by writing to a chaos-private throwaway table so we
// never mutate any production row. The table is created lazily and keeps a
// single dummy row whose value we increment on each Start invocation.
func (h *BusyHolder) Start(ctx context.Context) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.tx != nil {
		return errors.New("chaos: BusyHolder already started")
	}

	// Use a generous busy_timeout so the BEGIN IMMEDIATE itself does not
	// surface SQLITE_BUSY when the database is genuinely contended at start.
	dsn := fmt.Sprintf("file:%s?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)", h.dbPath)
	conn, err := sql.Open("sqlite", dsn)
	if err != nil {
		return fmt.Errorf("chaos: open sqlite-busy holder: %w", err)
	}
	conn.SetMaxOpenConns(1)
	if err := conn.PingContext(ctx); err != nil {
		conn.Close()
		return fmt.Errorf("chaos: ping sqlite-busy holder: %w", err)
	}

	if _, err := conn.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS _chaos_busy(
		id INTEGER PRIMARY KEY,
		ticks INTEGER NOT NULL DEFAULT 0,
		updated_at TEXT NOT NULL DEFAULT ''
	)`); err != nil {
		conn.Close()
		return fmt.Errorf("chaos: create _chaos_busy: %w", err)
	}

	tx, err := conn.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelDefault})
	if err != nil {
		conn.Close()
		return fmt.Errorf("chaos: begin sqlite-busy tx: %w", err)
	}
	// Force the transaction into write-lock state by issuing an UPDATE that
	// guarantees we hold an EXCLUSIVE write reservation under WAL.
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO _chaos_busy(id, ticks, updated_at) VALUES(1, 1, ?)
		 ON CONFLICT(id) DO UPDATE SET ticks = ticks + 1, updated_at = excluded.updated_at`,
		time.Now().UTC().Format(time.RFC3339Nano),
	); err != nil {
		_ = tx.Rollback()
		conn.Close()
		return fmt.Errorf("chaos: claim write lock: %w", err)
	}

	h.conn = conn
	h.tx = tx
	h.startAt = time.Now()
	return nil
}

// Stop rolls back the transaction (releasing the write lock) and closes the
// auxiliary connection. Returns the wall-clock time the lock was held. Safe
// to call multiple times; subsequent calls return the same duration.
func (h *BusyHolder) Stop() time.Duration {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.stopped {
		return time.Since(h.startAt)
	}
	h.stopped = true
	if h.tx != nil {
		_ = h.tx.Rollback()
		h.tx = nil
	}
	if h.conn != nil {
		_ = h.conn.Close()
		h.conn = nil
	}
	return time.Since(h.startAt)
}
