// Provider call audit log (Task 20105 / Task 20123).
//
// Persists one row per Provider.Complete invocation. Writers are best-effort:
// observability code MUST NOT fail the originating call if the DB is locked or
// the disk fills up. Readers paginate latest-first to feed the Web UI's
// "Provider Calls" panel.

package statedb

import (
	"database/sql"
	"fmt"
	"strings"
	"time"
)

// ProviderCallRow is one row in the provider_calls table. Headers is a
// JSON-encoded string by the time it reaches this layer (the redaction step
// runs in pkg/provideraudit before the row is built).
type ProviderCallRow struct {
	ID             int64
	Timestamp      time.Time
	Provider       string
	Model          string
	TaskID         int
	TaskTitle      string
	RequestID      string
	Prompt         string
	SystemPrompt   string
	Response       string
	ErrorMessage   string
	Status         string // "ok" | "error" | "timeout" | "context_canceled"
	Headers        string // JSON object, secrets already redacted
	InputTokens    int
	OutputTokens   int
	ThinkingTokens int
	LatencyMs      int
}

// AppendProviderCall inserts one provider-call row and returns the assigned
// id. Best-effort: errors are wrapped through classifyDriverErr so callers can
// distinguish ErrDBLocked from real corruption, but production code paths
// typically log-and-discard.
func (d *DB) AppendProviderCall(row ProviderCallRow) (int64, error) {
	if row.Timestamp.IsZero() {
		row.Timestamp = time.Now().UTC()
	}
	d.mu.Lock()
	defer d.mu.Unlock()

	res, err := d.conn.Exec(`
		INSERT INTO provider_calls(
			timestamp, provider, model, task_id, task_title, request_id,
			prompt, system_prompt, response, error_message, status, headers,
			input_tokens, output_tokens, thinking_tokens, latency_ms
		) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		row.Timestamp.UTC().Format(time.RFC3339Nano),
		row.Provider, row.Model, row.TaskID, row.TaskTitle, row.RequestID,
		row.Prompt, row.SystemPrompt, row.Response, row.ErrorMessage, row.Status, row.Headers,
		row.InputTokens, row.OutputTokens, row.ThinkingTokens, row.LatencyMs,
	)
	if err != nil {
		return 0, fmt.Errorf("statedb: append provider_call: %w", classifyDriverErr(err))
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("statedb: append provider_call: %w", classifyDriverErr(err))
	}
	return id, nil
}

// ListProviderCalls returns up to limit rows ordered most-recent-first,
// optionally filtered. The summary form omits the heavy prompt/response/headers
// columns so the list endpoint stays cheap even when the table grows large.
//
// Filters:
//   - taskID > 0: only calls bound to that task
//   - provider != "": only calls from that provider
//
// Returns total = count of all matching rows (regardless of limit/offset) so
// the UI can render pagination controls.
func (d *DB) ListProviderCalls(offset, limit, taskID int, provider string) (rows []ProviderCallRow, total int, err error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if limit <= 0 || limit > 500 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}

	var (
		where  []string
		args   []any
	)
	if taskID > 0 {
		where = append(where, "task_id = ?")
		args = append(args, taskID)
	}
	if provider != "" {
		where = append(where, "provider = ?")
		args = append(args, provider)
	}
	whereSQL := ""
	if len(where) > 0 {
		whereSQL = " WHERE " + strings.Join(where, " AND ")
	}

	if err := d.conn.QueryRow(`SELECT COUNT(*) FROM provider_calls`+whereSQL, args...).Scan(&total); err != nil {
		return nil, 0, classifyDriverErr(err)
	}

	args2 := append(append([]any{}, args...), limit, offset)
	q, err := d.conn.Query(`
		SELECT id, timestamp, provider, model, task_id, task_title, request_id,
			'', '', '', error_message, status, '',
			input_tokens, output_tokens, thinking_tokens, latency_ms
		FROM provider_calls`+whereSQL+`
		ORDER BY id DESC
		LIMIT ? OFFSET ?`, args2...)
	if err != nil {
		return nil, total, classifyDriverErr(err)
	}
	defer q.Close()

	for q.Next() {
		var r ProviderCallRow
		var ts string
		if err := q.Scan(
			&r.ID, &ts, &r.Provider, &r.Model, &r.TaskID, &r.TaskTitle, &r.RequestID,
			&r.Prompt, &r.SystemPrompt, &r.Response, &r.ErrorMessage, &r.Status, &r.Headers,
			&r.InputTokens, &r.OutputTokens, &r.ThinkingTokens, &r.LatencyMs,
		); err != nil {
			return nil, total, classifyDriverErr(err)
		}
		if t, perr := time.Parse(time.RFC3339Nano, ts); perr == nil {
			r.Timestamp = t
		}
		rows = append(rows, r)
	}
	if err := q.Err(); err != nil {
		return nil, total, classifyDriverErr(err)
	}
	return rows, total, nil
}

// LoadProviderCall returns the full row (including prompt, response, headers)
// for a single audit-log id. Returns sql.ErrNoRows-wrapped error when missing.
func (d *DB) LoadProviderCall(id int64) (*ProviderCallRow, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	row := d.conn.QueryRow(`
		SELECT id, timestamp, provider, model, task_id, task_title, request_id,
			prompt, system_prompt, response, error_message, status, headers,
			input_tokens, output_tokens, thinking_tokens, latency_ms
		FROM provider_calls WHERE id = ? LIMIT 1`, id)

	var r ProviderCallRow
	var ts string
	if err := row.Scan(
		&r.ID, &ts, &r.Provider, &r.Model, &r.TaskID, &r.TaskTitle, &r.RequestID,
		&r.Prompt, &r.SystemPrompt, &r.Response, &r.ErrorMessage, &r.Status, &r.Headers,
		&r.InputTokens, &r.OutputTokens, &r.ThinkingTokens, &r.LatencyMs,
	); err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("provider_call %d: not found", id)
		}
		return nil, classifyDriverErr(err)
	}
	if t, perr := time.Parse(time.RFC3339Nano, ts); perr == nil {
		r.Timestamp = t
	}
	return &r, nil
}
