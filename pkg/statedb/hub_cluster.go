// Hub cluster tables (Task 20354).
//
// Rows for migrations/0052_hub_cluster.sql: who is serving this control plane
// (hub_members), what one member produced that the others must deliver
// (hub_bus), and which member holds a thing that cannot be shared (hub_owners).
// See the migration for why each exists and why their timestamps are integers.
//
// This file owns the SQL only. Whether a member is alive, who may adopt an
// orphan, and how an event is routed are policy, and live in pkg/hubcluster.
//
// Every ownership mutation is a compare-and-swap against the row the caller
// read, for the reason hub_instances.go gives: two members racing to adopt the
// same orphaned run must not both conclude it was free, because the loser
// would stream, settle and bill a run the winner is also streaming.

package statedb

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ErrHubOwnerNotFound is returned when no member owns (kind, key).
var ErrHubOwnerNotFound = errors.New("statedb: hub owner not found")

// HubMemberRow is one hub process serving this control plane.
type HubMemberRow struct {
	InstanceID string
	Hostname   string
	PID        int
	// BootID disambiguates a pid across reboots, exactly as on HubLeaseRow.
	BootID       string
	Address      string
	AdvertiseURL string
	Version      string
	// Meta is a JSON object of further endpoints; "{}" when there are none.
	Meta        string
	StartedAt   time.Time
	HeartbeatAt time.Time
	// LeftAt is a graceful leave; the zero time while the member serves.
	LeftAt time.Time
}

// HubEventRow is one event on the cluster bus.
type HubEventRow struct {
	Seq       int64
	Origin    string
	Target    string
	Topic     string
	Key       string
	Payload   string
	CreatedAt time.Time
}

// HubOwnerRow records which member holds (Kind, Key).
type HubOwnerRow struct {
	Kind       string
	Key        string
	InstanceID string
	Meta       string
	ClaimedAt  time.Time
	UpdatedAt  time.Time
}

// unixMillis renders t for an integer millisecond column; the zero time is 0.
func unixMillis(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixMilli()
}

// fromUnixMillis is the inverse of unixMillis.
func fromUnixMillis(ms int64) time.Time {
	if ms == 0 {
		return time.Time{}
	}
	return time.UnixMilli(ms).UTC()
}

func normalizeMeta(meta string) string {
	if strings.TrimSpace(meta) == "" {
		return "{}"
	}
	return meta
}

// ── hub_members ─────────────────────────────────────────────────────────────

// JoinHubMember records row as a serving member, replacing any previous row
// for the same instance id. Instance ids are minted per process, so a replace
// only ever happens to a process re-joining after it left.
func (d *DB) JoinHubMember(row HubMemberRow) error {
	if strings.TrimSpace(row.InstanceID) == "" {
		return errors.New("statedb: hub member instance id is required")
	}
	now := time.Now().UTC()
	if row.StartedAt.IsZero() {
		row.StartedAt = now
	}
	if row.HeartbeatAt.IsZero() {
		row.HeartbeatAt = now
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	if _, err := d.conn.Exec(
		`INSERT INTO hub_members(instance_id, hostname, pid, boot_id, address,
		                         advertise_url, version, meta, started_ms,
		                         heartbeat_ms, left_ms)
		 VALUES(?,?,?,?,?,?,?,?,?,?,0)
		 ON CONFLICT(instance_id) DO UPDATE SET
		   hostname      = excluded.hostname,
		   pid           = excluded.pid,
		   boot_id       = excluded.boot_id,
		   address       = excluded.address,
		   advertise_url = excluded.advertise_url,
		   version       = excluded.version,
		   meta          = excluded.meta,
		   started_ms    = excluded.started_ms,
		   heartbeat_ms  = excluded.heartbeat_ms,
		   left_ms       = 0`,
		row.InstanceID, row.Hostname, row.PID, row.BootID, row.Address,
		row.AdvertiseURL, row.Version, normalizeMeta(row.Meta),
		unixMillis(row.StartedAt), unixMillis(row.HeartbeatAt),
	); err != nil {
		return fmt.Errorf("statedb: join hub member %s: %w", row.InstanceID, classifyDriverErr(err))
	}
	return nil
}

// HeartbeatHubMember advances a member's heartbeat.
//
// false means the row is gone or marked left: a peer or an operator decided
// this process is no longer a member, and it must stop acting as one rather
// than quietly re-inserting itself.
func (d *DB) HeartbeatHubMember(instanceID string, at time.Time) (bool, error) {
	if strings.TrimSpace(instanceID) == "" {
		return false, errors.New("statedb: hub member instance id is required")
	}
	if at.IsZero() {
		at = time.Now().UTC()
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	res, err := d.conn.Exec(
		`UPDATE hub_members SET heartbeat_ms = ? WHERE instance_id = ? AND left_ms = 0`,
		unixMillis(at), instanceID)
	if err != nil {
		return false, fmt.Errorf("statedb: heartbeat hub member %s: %w", instanceID, classifyDriverErr(err))
	}
	return rowsChanged(res)
}

// LeaveHubMember marks a member as having left gracefully. Idempotent.
func (d *DB) LeaveHubMember(instanceID string, at time.Time) error {
	if strings.TrimSpace(instanceID) == "" {
		return errors.New("statedb: hub member instance id is required")
	}
	if at.IsZero() {
		at = time.Now().UTC()
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, err := d.conn.Exec(
		`UPDATE hub_members SET left_ms = ? WHERE instance_id = ? AND left_ms = 0`,
		unixMillis(at), instanceID); err != nil {
		return fmt.Errorf("statedb: leave hub member %s: %w", instanceID, classifyDriverErr(err))
	}
	return nil
}

// ListHubMembers returns every member row, serving or not, oldest first.
func (d *DB) ListHubMembers() ([]HubMemberRow, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	rows, err := d.conn.Query(
		`SELECT instance_id, hostname, pid, boot_id, address, advertise_url,
		        version, meta, started_ms, heartbeat_ms, left_ms
		 FROM hub_members ORDER BY started_ms, instance_id`)
	if err != nil {
		return nil, fmt.Errorf("statedb: list hub members: %w", classifyDriverErr(err))
	}
	defer rows.Close()
	var out []HubMemberRow
	for rows.Next() {
		var (
			r                          HubMemberRow
			started, heartbeat, leftAt int64
		)
		if err := rows.Scan(&r.InstanceID, &r.Hostname, &r.PID, &r.BootID,
			&r.Address, &r.AdvertiseURL, &r.Version, &r.Meta,
			&started, &heartbeat, &leftAt); err != nil {
			return nil, fmt.Errorf("statedb: scan hub member: %w", classifyDriverErr(err))
		}
		r.StartedAt = fromUnixMillis(started)
		r.HeartbeatAt = fromUnixMillis(heartbeat)
		r.LeftAt = fromUnixMillis(leftAt)
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("statedb: list hub members: %w", classifyDriverErr(err))
	}
	return out, nil
}

// PruneHubMembers deletes the rows of members that stopped heartbeating
// before cutoff, whether they left gracefully or not. The row of a member
// that is gone serves forensics for a while and then only clutters `cloop hub
// cluster status`, so the leader trims it.
func (d *DB) PruneHubMembers(cutoff time.Time) (int64, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	res, err := d.conn.Exec(`DELETE FROM hub_members WHERE heartbeat_ms < ?`, unixMillis(cutoff))
	if err != nil {
		return 0, fmt.Errorf("statedb: prune hub members: %w", classifyDriverErr(err))
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// ── hub_bus ─────────────────────────────────────────────────────────────────

// AppendHubEvents publishes events in one transaction and returns the
// sequence number of the last one. Batching is what keeps a chatty run's live
// output from costing one write transaction per line.
func (d *DB) AppendHubEvents(events []HubEventRow) (int64, error) {
	if len(events) == 0 {
		return 0, nil
	}
	now := time.Now().UTC()

	d.mu.Lock()
	defer d.mu.Unlock()
	tx, err := d.conn.Begin()
	if err != nil {
		return 0, fmt.Errorf("statedb: publish hub events: %w", classifyDriverErr(err))
	}
	defer func() { _ = tx.Rollback() }()
	stmt, err := tx.Prepare(
		`INSERT INTO hub_bus(origin, target, topic, key, payload, created_ms)
		 VALUES(?,?,?,?,?,?)`)
	if err != nil {
		return 0, fmt.Errorf("statedb: publish hub events: %w", classifyDriverErr(err))
	}
	defer stmt.Close()
	var last int64
	for _, ev := range events {
		created := ev.CreatedAt
		if created.IsZero() {
			created = now
		}
		res, err := stmt.Exec(ev.Origin, ev.Target, ev.Topic, ev.Key, ev.Payload, unixMillis(created))
		if err != nil {
			return 0, fmt.Errorf("statedb: publish hub event %q: %w", ev.Topic, classifyDriverErr(err))
		}
		if id, err := res.LastInsertId(); err == nil {
			last = id
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("statedb: publish hub events: %w", classifyDriverErr(err))
	}
	return last, nil
}

// HubEventsAfter returns up to limit events with seq > after, in order.
//
// Reading by seq is only lossless because SQLite has one writer at a time: a
// row with a higher seq can never become visible before one with a lower seq,
// so a reader that has seen seq N has seen everything at or below it. A
// database with concurrent writers would need a different cursor.
func (d *DB) HubEventsAfter(after int64, limit int) ([]HubEventRow, error) {
	if limit <= 0 {
		limit = 256
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	rows, err := d.conn.Query(
		`SELECT seq, origin, target, topic, key, payload, created_ms
		 FROM hub_bus WHERE seq > ? ORDER BY seq LIMIT ?`, after, limit)
	if err != nil {
		return nil, fmt.Errorf("statedb: read hub events: %w", classifyDriverErr(err))
	}
	defer rows.Close()
	var out []HubEventRow
	for rows.Next() {
		var (
			ev      HubEventRow
			created int64
		)
		if err := rows.Scan(&ev.Seq, &ev.Origin, &ev.Target, &ev.Topic, &ev.Key,
			&ev.Payload, &created); err != nil {
			return nil, fmt.Errorf("statedb: scan hub event: %w", classifyDriverErr(err))
		}
		ev.CreatedAt = fromUnixMillis(created)
		out = append(out, ev)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("statedb: read hub events: %w", classifyDriverErr(err))
	}
	return out, nil
}

// HubEventBounds returns the lowest and highest seq still on the bus, and the
// highest seq ever issued. A reader starts at the high-water mark so it does not
// replay history, and compares its cursor with the lowest seq to learn that it
// fell so far behind that pruning took events it never read.
//
// The high-water mark comes from sqlite_sequence, not MAX(seq): after the
// leader prunes every row the table is empty, and a reader that restarted then
// must still begin past the numbers already handed out.
func (d *DB) HubEventBounds() (lowest, highest, issued int64, err error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	var lo, hi sql.NullInt64
	if err := d.conn.QueryRow(`SELECT MIN(seq), MAX(seq) FROM hub_bus`).Scan(&lo, &hi); err != nil {
		return 0, 0, 0, fmt.Errorf("statedb: hub bus bounds: %w", classifyDriverErr(err))
	}
	var seq sql.NullInt64
	err = d.conn.QueryRow(`SELECT seq FROM sqlite_sequence WHERE name = 'hub_bus'`).Scan(&seq)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return 0, 0, 0, fmt.Errorf("statedb: hub bus sequence: %w", classifyDriverErr(err))
	}
	issued = seq.Int64
	if hi.Int64 > issued {
		issued = hi.Int64
	}
	return lo.Int64, hi.Int64, issued, nil
}

// PruneHubEvents deletes events published before cutoff.
func (d *DB) PruneHubEvents(cutoff time.Time) (int64, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	res, err := d.conn.Exec(`DELETE FROM hub_bus WHERE created_ms < ?`, unixMillis(cutoff))
	if err != nil {
		return 0, fmt.Errorf("statedb: prune hub events: %w", classifyDriverErr(err))
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// ── hub_owners ──────────────────────────────────────────────────────────────

// GetHubOwner returns the owner row for (kind, key), or ErrHubOwnerNotFound.
func (d *DB) GetHubOwner(kind, key string) (HubOwnerRow, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	row := d.conn.QueryRow(
		`SELECT kind, key, instance_id, meta, claimed_ms, updated_ms
		 FROM hub_owners WHERE kind = ? AND key = ?`, kind, key)
	out, err := scanHubOwnerRow(row)
	if errors.Is(err, sql.ErrNoRows) {
		return HubOwnerRow{}, fmt.Errorf("%w: %s %q", ErrHubOwnerNotFound, kind, key)
	}
	if err != nil {
		return HubOwnerRow{}, fmt.Errorf("statedb: get hub owner %s %q: %w", kind, key, classifyDriverErr(err))
	}
	return out, nil
}

// ListHubOwners returns every row of one kind, or of every kind when kind is
// empty, ordered by kind then key.
func (d *DB) ListHubOwners(kind string) ([]HubOwnerRow, error) {
	query := `SELECT kind, key, instance_id, meta, claimed_ms, updated_ms FROM hub_owners`
	var args []any
	if kind != "" {
		query += ` WHERE kind = ?`
		args = append(args, kind)
	}
	query += ` ORDER BY kind, key`

	d.mu.Lock()
	defer d.mu.Unlock()
	rows, err := d.conn.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("statedb: list hub owners: %w", classifyDriverErr(err))
	}
	defer rows.Close()
	var out []HubOwnerRow
	for rows.Next() {
		r, err := scanHubOwnerRow(rows)
		if err != nil {
			return nil, fmt.Errorf("statedb: scan hub owner: %w", classifyDriverErr(err))
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("statedb: list hub owners: %w", classifyDriverErr(err))
	}
	return out, nil
}

// ClaimHubOwner takes (row.Kind, row.Key) for row.InstanceID, conditioned on
// the current row still matching expect — the compare-and-swap AcquireHubLease
// documents. A zero expect means "I saw no owner"; a populated one means "I saw
// this owner and judged it gone". It reports whether the claim was taken.
func (d *DB) ClaimHubOwner(row, expect HubOwnerRow) (bool, error) {
	if strings.TrimSpace(row.Kind) == "" || strings.TrimSpace(row.Key) == "" {
		return false, errors.New("statedb: hub owner kind and key are required")
	}
	if strings.TrimSpace(row.InstanceID) == "" {
		return false, errors.New("statedb: hub owner instance id is required")
	}
	now := time.Now().UTC()
	if row.ClaimedAt.IsZero() {
		row.ClaimedAt = now
	}
	if row.UpdatedAt.IsZero() {
		row.UpdatedAt = row.ClaimedAt
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	res, err := d.conn.Exec(
		`INSERT INTO hub_owners(kind, key, instance_id, meta, claimed_ms, updated_ms)
		 VALUES(?,?,?,?,?,?)
		 ON CONFLICT(kind, key) DO UPDATE SET
		   instance_id = excluded.instance_id,
		   meta        = excluded.meta,
		   claimed_ms  = excluded.claimed_ms,
		   updated_ms  = excluded.updated_ms
		 WHERE hub_owners.instance_id = ? AND hub_owners.claimed_ms = ?`,
		row.Kind, row.Key, row.InstanceID, normalizeMeta(row.Meta),
		unixMillis(row.ClaimedAt), unixMillis(row.UpdatedAt),
		expect.InstanceID, unixMillis(expect.ClaimedAt),
	)
	if err != nil {
		return false, fmt.Errorf("statedb: claim hub owner %s %q: %w", row.Kind, row.Key, classifyDriverErr(err))
	}
	return rowsChanged(res)
}

// PutHubOwner records row unconditionally: the latest writer wins.
//
// For facts rather than claims. An agent's socket is wherever the agent last
// connected — the member it left may not have noticed yet, and must not be
// able to keep the row by virtue of having written it first.
func (d *DB) PutHubOwner(row HubOwnerRow) error {
	if strings.TrimSpace(row.Kind) == "" || strings.TrimSpace(row.Key) == "" {
		return errors.New("statedb: hub owner kind and key are required")
	}
	if strings.TrimSpace(row.InstanceID) == "" {
		return errors.New("statedb: hub owner instance id is required")
	}
	now := time.Now().UTC()
	if row.ClaimedAt.IsZero() {
		row.ClaimedAt = now
	}
	if row.UpdatedAt.IsZero() {
		row.UpdatedAt = row.ClaimedAt
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, err := d.conn.Exec(
		`INSERT INTO hub_owners(kind, key, instance_id, meta, claimed_ms, updated_ms)
		 VALUES(?,?,?,?,?,?)
		 ON CONFLICT(kind, key) DO UPDATE SET
		   instance_id = excluded.instance_id,
		   meta        = excluded.meta,
		   claimed_ms  = excluded.claimed_ms,
		   updated_ms  = excluded.updated_ms`,
		row.Kind, row.Key, row.InstanceID, normalizeMeta(row.Meta),
		unixMillis(row.ClaimedAt), unixMillis(row.UpdatedAt),
	); err != nil {
		return fmt.Errorf("statedb: put hub owner %s %q: %w", row.Kind, row.Key, classifyDriverErr(err))
	}
	return nil
}

// UpdateHubOwnerMeta rewrites the meta of a row instanceID still owns. false
// means it no longer does.
func (d *DB) UpdateHubOwnerMeta(kind, key, instanceID, meta string, at time.Time) (bool, error) {
	if at.IsZero() {
		at = time.Now().UTC()
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	res, err := d.conn.Exec(
		`UPDATE hub_owners SET meta = ?, updated_ms = ?
		 WHERE kind = ? AND key = ? AND instance_id = ?`,
		normalizeMeta(meta), unixMillis(at), kind, key, instanceID)
	if err != nil {
		return false, fmt.Errorf("statedb: update hub owner %s %q: %w", kind, key, classifyDriverErr(err))
	}
	return rowsChanged(res)
}

// ReleaseHubOwner deletes (kind, key) if instanceID still owns it. A member
// releasing something another member has since taken over releases nothing.
func (d *DB) ReleaseHubOwner(kind, key, instanceID string) (bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	res, err := d.conn.Exec(
		`DELETE FROM hub_owners WHERE kind = ? AND key = ? AND instance_id = ?`,
		kind, key, instanceID)
	if err != nil {
		return false, fmt.Errorf("statedb: release hub owner %s %q: %w", kind, key, classifyDriverErr(err))
	}
	return rowsChanged(res)
}

// ReleaseHubOwnerIfClaim deletes (kind, key) if it is still exactly the claim
// the caller read — owner and claim instant. It is how a member removes an
// orphan it judged dead without racing a member that adopted it meanwhile.
func (d *DB) ReleaseHubOwnerIfClaim(expect HubOwnerRow) (bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	res, err := d.conn.Exec(
		`DELETE FROM hub_owners WHERE kind = ? AND key = ? AND instance_id = ? AND claimed_ms = ?`,
		expect.Kind, expect.Key, expect.InstanceID, unixMillis(expect.ClaimedAt))
	if err != nil {
		return false, fmt.Errorf("statedb: release hub owner %s %q: %w", expect.Kind, expect.Key, classifyDriverErr(err))
	}
	return rowsChanged(res)
}

func scanHubOwnerRow(sc rowScanner) (HubOwnerRow, error) {
	var (
		r                HubOwnerRow
		claimed, updated int64
	)
	if err := sc.Scan(&r.Kind, &r.Key, &r.InstanceID, &r.Meta, &claimed, &updated); err != nil {
		return HubOwnerRow{}, err
	}
	r.ClaimedAt = fromUnixMillis(claimed)
	r.UpdatedAt = fromUnixMillis(updated)
	return r, nil
}

// ── hub_seen ────────────────────────────────────────────────────────────────

// MarkHubSeen records (kind, key) as seen until expires and reports whether it
// was fresh — not already recorded with an expiry still ahead of now. Check and
// record share one write transaction, so of two members presenting the same
// value at once exactly one is told it was fresh.
func (d *DB) MarkHubSeen(kind, key string, expires, now time.Time) (bool, error) {
	if strings.TrimSpace(kind) == "" || strings.TrimSpace(key) == "" {
		return false, errors.New("statedb: hub seen kind and key are required")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	tx, err := d.conn.Begin()
	if err != nil {
		return false, fmt.Errorf("statedb: mark hub seen: %w", classifyDriverErr(err))
	}
	defer func() { _ = tx.Rollback() }()
	var until int64
	err = tx.QueryRow(`SELECT expires_ms FROM hub_seen WHERE kind = ? AND key = ?`, kind, key).Scan(&until)
	switch {
	case err == nil && until > unixMillis(now):
		return false, nil
	case err != nil && !errors.Is(err, sql.ErrNoRows):
		return false, fmt.Errorf("statedb: read hub seen: %w", classifyDriverErr(err))
	}
	if _, err := tx.Exec(
		`INSERT INTO hub_seen(kind, key, expires_ms) VALUES(?,?,?)
		 ON CONFLICT(kind, key) DO UPDATE SET expires_ms = excluded.expires_ms`,
		kind, key, unixMillis(expires)); err != nil {
		return false, fmt.Errorf("statedb: mark hub seen: %w", classifyDriverErr(err))
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("statedb: mark hub seen: %w", classifyDriverErr(err))
	}
	return true, nil
}

// PruneHubSeen deletes rows whose expiry has passed.
func (d *DB) PruneHubSeen(now time.Time) (int64, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	res, err := d.conn.Exec(`DELETE FROM hub_seen WHERE expires_ms <= ?`, unixMillis(now))
	if err != nil {
		return 0, fmt.Errorf("statedb: prune hub seen: %w", classifyDriverErr(err))
	}
	n, _ := res.RowsAffected()
	return n, nil
}
