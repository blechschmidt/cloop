package statedb

// Replacing the hub's certificate authority online (Task 20438). See
// migrations/0081_hub_ca_rotation.sql for the tables, and hub_tls.go for the
// CA rows a rotation moves between.
//
// Each step that changes which CAs exist is one transaction over both the
// hub_tls rows and the rotation's journal row, so no reader ever sees a staged
// CA without its rotation or an activation half done; and each runs on a
// secure-delete connection, because each one deletes or rewrites a row that
// held a sealed key. pkg/hubca decides whether a step may run — no run left
// that would break, every member caught up — and this file only does it.

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Hub CA row ids (hub_tls.id).
const (
	// HubCAActive is the CA leaves are issued from.
	HubCAActive = "ca"
	// HubCANext is a CA staged to replace it.
	HubCANext = "ca:next"
	// HubCAPrevious is the CA an activation replaced, still trusted until it
	// is retired.
	HubCAPrevious = "ca:previous"
)

// Rotation states (hub_ca_rotations.state).
const (
	HubCARotationStaged    = "staged"
	HubCARotationActive    = "active"
	HubCARotationRetired   = "retired"
	HubCARotationAbandoned = "abandoned"
)

// ErrHubCARotationConflict is returned when a step finds the CA rows or the
// rotation in a state other than the one it was asked to move from: another
// operator, or another hub process, moved it first.
var ErrHubCARotationConflict = errors.New("statedb: the hub CA rotation moved under this step")

// HubCARotationRow is one rotation's journal.
type HubCARotationRow struct {
	ID          string
	State       string
	FromSerial  string
	ToSerial    string
	Names       []string
	Emergency   bool
	StagedAt    time.Time
	StagedBy    string
	ActivatedAt time.Time
	ActivatedBy string
	EndedAt     time.Time
	EndedBy     string
	Forced      []string
	CutRuns     []string
	Detail      string
}

// Current reports whether the rotation is still under way: staged, or
// activated with its previous CA not yet retired.
func (r HubCARotationRow) Current() bool {
	return r.State == HubCARotationStaged || r.State == HubCARotationActive
}

const hubCARotationColumns = `id, state, from_serial, to_serial, names, emergency, staged_at, staged_by,
	activated_at, activated_by, ended_at, ended_by, forced, cut_runs, detail`

// StageHubCA stores next as the staged CA (HubCANext) and opens rot for it, in
// one transaction. False, with nothing written, when a CA is already staged:
// two operators staging at once leave one staged CA and one refusal.
func (d *DB) StageHubCA(next HubTLSRow, rot HubCARotationRow) (bool, error) {
	if next.ID != HubCANext || next.Kind != "ca" {
		return false, fmt.Errorf("statedb: a staged hub CA is row %s of kind ca, not %s/%s", HubCANext, next.ID, next.Kind)
	}
	if err := next.check(); err != nil {
		return false, err
	}
	if strings.TrimSpace(rot.ID) == "" || rot.State != HubCARotationStaged || rot.ToSerial != next.Serial {
		return false, fmt.Errorf("statedb: staging hub CA %s needs a staged rotation naming it", next.Serial)
	}
	sans, err := encodeHubTLSSANs(next.SANs)
	if err != nil {
		return false, err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	tx, done, err := d.shreddingTx()
	if err != nil {
		return false, fmt.Errorf("statedb: stage hub CA: %w", classifyDriverErr(err))
	}
	defer done()
	defer tx.Rollback()

	res, err := tx.Exec(`INSERT INTO hub_tls(`+hubTLSColumns+`)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO NOTHING`,
		next.ID, next.Kind, next.Serial, next.Issuer, next.CertPEM, next.KeyID, next.WrappedDEK, next.KeySealed,
		sans, formatTimeRFC(next.NotBefore), formatTimeRFC(next.NotAfter), formatTimeRFC(next.IssuedAt), next.IssuedBy)
	if err != nil {
		return false, fmt.Errorf("statedb: stage hub CA %s: %w", next.Serial, classifyDriverErr(err))
	}
	if n, err := res.RowsAffected(); err != nil || n == 0 {
		if err != nil {
			return false, fmt.Errorf("statedb: stage hub CA %s: %w", next.Serial, classifyDriverErr(err))
		}
		return false, nil
	}
	if err := insertHubCARotation(tx, rot); err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("statedb: stage hub CA %s: %w", next.Serial, classifyDriverErr(err))
	}
	return true, nil
}

// ActivateHubCA makes the staged CA the one leaves are issued from: HubCAActive
// moves to HubCAPrevious and HubCANext to HubCAActive, and the rotation is
// recorded active — one transaction, compare-and-swap on both serials, so a
// reader sees the old pair or the new one and never neither. forced names the
// runs the activation was told to break.
//
// The sealed keys move with their rows untouched: pkg/hubca binds a CA's
// envelope to the CA's serial rather than to the row it sits in.
func (d *DB) ActivateHubCA(fromSerial, toSerial, rotationID string, at time.Time, by string, forced []string) error {
	if fromSerial == "" || toSerial == "" || rotationID == "" {
		return errors.New("statedb: activating a hub CA needs both serials and the rotation")
	}
	forcedJSON, err := encodeStringList(forced)
	if err != nil {
		return err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	tx, done, err := d.shreddingTx()
	if err != nil {
		return fmt.Errorf("statedb: activate hub CA: %w", classifyDriverErr(err))
	}
	defer done()
	defer tx.Rollback()

	rows, err := queryHubTLS(tx, `WHERE id IN (?, ?, ?)`, HubCAActive, HubCANext, HubCAPrevious)
	if err != nil {
		return err
	}
	byID := map[string]HubTLSRow{}
	for _, r := range rows {
		byID[r.ID] = r
	}
	cur, ok := byID[HubCAActive]
	if !ok || cur.Serial != fromSerial {
		return fmt.Errorf("%w: the active hub CA is not %s", ErrHubCARotationConflict, fromSerial)
	}
	next, ok := byID[HubCANext]
	if !ok || next.Serial != toSerial {
		return fmt.Errorf("%w: the staged hub CA is not %s", ErrHubCARotationConflict, toSerial)
	}
	if prev, ok := byID[HubCAPrevious]; ok {
		return fmt.Errorf("%w: hub CA %s is still trusted as the previous one; retire it first",
			ErrHubCARotationConflict, prev.Serial)
	}
	curSANs, err := encodeHubTLSSANs(cur.SANs)
	if err != nil {
		return err
	}
	nextSANs, err := encodeHubTLSSANs(next.SANs)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT INTO hub_tls(`+hubTLSColumns+`)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		HubCAPrevious, cur.Kind, cur.Serial, cur.Issuer, cur.CertPEM, cur.KeyID, cur.WrappedDEK, cur.KeySealed,
		curSANs, formatTimeRFC(cur.NotBefore), formatTimeRFC(cur.NotAfter), formatTimeRFC(cur.IssuedAt),
		cur.IssuedBy); err != nil {
		return fmt.Errorf("statedb: keep hub CA %s as the previous one: %w", cur.Serial, classifyDriverErr(err))
	}
	res, err := tx.Exec(`UPDATE hub_tls SET kind = ?, serial = ?, issuer = ?, cert_pem = ?,
		key_id = ?, wrapped_dek = ?, key_sealed = ?, sans = ?, not_before = ?, not_after = ?,
		issued_at = ?, issued_by = ?
		WHERE id = ? AND serial = ?`,
		next.Kind, next.Serial, next.Issuer, next.CertPEM, next.KeyID, next.WrappedDEK, next.KeySealed,
		nextSANs, formatTimeRFC(next.NotBefore), formatTimeRFC(next.NotAfter), formatTimeRFC(next.IssuedAt),
		next.IssuedBy, HubCAActive, fromSerial)
	if err != nil {
		return fmt.Errorf("statedb: activate hub CA %s: %w", toSerial, classifyDriverErr(err))
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return fmt.Errorf("%w: the active hub CA changed while activating %s", ErrHubCARotationConflict, toSerial)
	}
	if _, err := tx.Exec(`DELETE FROM hub_tls WHERE id = ? AND serial = ?`, HubCANext, toSerial); err != nil {
		return fmt.Errorf("statedb: clear the staged hub CA %s: %w", toSerial, classifyDriverErr(err))
	}
	res, err = tx.Exec(`UPDATE hub_ca_rotations SET state = ?, activated_at = ?, activated_by = ?, forced = ?
		WHERE id = ? AND state = ?`,
		HubCARotationActive, formatTimeRFC(at), by, forcedJSON, rotationID, HubCARotationStaged)
	if err != nil {
		return fmt.Errorf("statedb: record the activation of hub CA %s: %w", toSerial, classifyDriverErr(err))
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return fmt.Errorf("%w: rotation %s is not staged", ErrHubCARotationConflict, rotationID)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("statedb: activate hub CA %s: %w", toSerial, classifyDriverErr(err))
	}
	return nil
}

// RetireHubCAPrevious deletes the previous CA, sealed key and all, and records
// the rotation retired, in one transaction on a secure-delete connection: the
// record and the row it held go together. cutRuns names the runs whose proxy
// sessions an emergency rotation ended; nil for an ordinary retirement.
func (d *DB) RetireHubCAPrevious(serial, rotationID string, at time.Time, by string, cutRuns []string) error {
	if serial == "" || rotationID == "" {
		return errors.New("statedb: retiring a hub CA needs its serial and the rotation")
	}
	cut, err := encodeStringList(cutRuns)
	if err != nil {
		return err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	tx, done, err := d.shreddingTx()
	if err != nil {
		return fmt.Errorf("statedb: retire hub CA: %w", classifyDriverErr(err))
	}
	defer done()
	defer tx.Rollback()

	res, err := tx.Exec(`DELETE FROM hub_tls WHERE id = ? AND serial = ?`, HubCAPrevious, serial)
	if err != nil {
		return fmt.Errorf("statedb: retire hub CA %s: %w", serial, classifyDriverErr(err))
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return fmt.Errorf("%w: hub CA %s is not the previous one", ErrHubCARotationConflict, serial)
	}
	res, err = tx.Exec(`UPDATE hub_ca_rotations SET state = ?, ended_at = ?, ended_by = ?, cut_runs = ?
		WHERE id = ? AND state = ?`,
		HubCARotationRetired, formatTimeRFC(at), by, cut, rotationID, HubCARotationActive)
	if err != nil {
		return fmt.Errorf("statedb: record the retirement of hub CA %s: %w", serial, classifyDriverErr(err))
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return fmt.Errorf("%w: rotation %s is not active", ErrHubCARotationConflict, rotationID)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("statedb: retire hub CA %s: %w", serial, classifyDriverErr(err))
	}
	return nil
}

// AbandonHubCANext deletes the staged CA, sealed key and all, and records its
// rotation abandoned with detail. A rotation with no row (staged by a process
// that died between the two writes of an older build) is not required.
func (d *DB) AbandonHubCANext(serial, rotationID string, at time.Time, by, detail string) error {
	if serial == "" {
		return errors.New("statedb: abandoning a staged hub CA needs its serial")
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	tx, done, err := d.shreddingTx()
	if err != nil {
		return fmt.Errorf("statedb: abandon the staged hub CA: %w", classifyDriverErr(err))
	}
	defer done()
	defer tx.Rollback()

	res, err := tx.Exec(`DELETE FROM hub_tls WHERE id = ? AND serial = ?`, HubCANext, serial)
	if err != nil {
		return fmt.Errorf("statedb: abandon the staged hub CA %s: %w", serial, classifyDriverErr(err))
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return fmt.Errorf("%w: hub CA %s is not the staged one", ErrHubCARotationConflict, serial)
	}
	if rotationID != "" {
		res, err = tx.Exec(`UPDATE hub_ca_rotations SET state = ?, ended_at = ?, ended_by = ?, detail = ?
			WHERE id = ? AND state = ?`,
			HubCARotationAbandoned, formatTimeRFC(at), by, detail, rotationID, HubCARotationStaged)
		if err != nil {
			return fmt.Errorf("statedb: record abandoning hub CA %s: %w", serial, classifyDriverErr(err))
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return fmt.Errorf("%w: rotation %s is not staged", ErrHubCARotationConflict, rotationID)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("statedb: abandon the staged hub CA %s: %w", serial, classifyDriverErr(err))
	}
	return nil
}

// SetHubCARotationEmergency marks a rotation as one `--now` drove.
func (d *DB) SetHubCARotationEmergency(rotationID string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, err := d.conn.Exec(`UPDATE hub_ca_rotations SET emergency = 1 WHERE id = ?`, rotationID); err != nil {
		return fmt.Errorf("statedb: mark rotation %s an emergency: %w", rotationID, classifyDriverErr(err))
	}
	return nil
}

// GetHubCARotation returns the rotation by id; ErrHubTLSNotFound when there is
// none.
func (d *DB) GetHubCARotation(id string) (HubCARotationRow, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	rows, err := queryHubCARotations(d.conn, `WHERE id = ?`, id)
	if err != nil {
		return HubCARotationRow{}, err
	}
	if len(rows) == 0 {
		return HubCARotationRow{}, fmt.Errorf("%w: rotation %s", ErrHubTLSNotFound, id)
	}
	return rows[0], nil
}

// ListHubCARotations returns the most recent rotations first, at most limit.
func (d *DB) ListHubCARotations(limit int) ([]HubCARotationRow, error) {
	if limit <= 0 {
		limit = 20
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	return queryHubCARotations(d.conn, `ORDER BY staged_at DESC, id DESC LIMIT ?`, limit)
}

// CurrentHubCARotation returns the rotation under way — staged, or active
// with its previous CA not retired — and whether there is one.
func (d *DB) CurrentHubCARotation() (HubCARotationRow, bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	rows, err := queryHubCARotations(d.conn, `WHERE state IN (?, ?) ORDER BY staged_at DESC, id DESC LIMIT 1`,
		HubCARotationStaged, HubCARotationActive)
	if err != nil || len(rows) == 0 {
		return HubCARotationRow{}, false, err
	}
	return rows[0], true, nil
}

func insertHubCARotation(tx *sql.Tx, r HubCARotationRow) error {
	names, err := encodeStringList(r.Names)
	if err != nil {
		return err
	}
	forced, err := encodeStringList(r.Forced)
	if err != nil {
		return err
	}
	cut, err := encodeStringList(r.CutRuns)
	if err != nil {
		return err
	}
	emergency := 0
	if r.Emergency {
		emergency = 1
	}
	if _, err := tx.Exec(`INSERT INTO hub_ca_rotations(`+hubCARotationColumns+`)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.ID, r.State, r.FromSerial, r.ToSerial, names, emergency, formatTimeRFC(r.StagedAt), r.StagedBy,
		formatTimeRFC(r.ActivatedAt), r.ActivatedBy, formatTimeRFC(r.EndedAt), r.EndedBy, forced, cut,
		r.Detail); err != nil {
		return fmt.Errorf("statedb: record hub CA rotation %s: %w", r.ID, classifyDriverErr(err))
	}
	return nil
}

func queryHubCARotations(q hubTLSQuerier, where string, args ...any) ([]HubCARotationRow, error) {
	rows, err := q.Query(`SELECT `+hubCARotationColumns+` FROM hub_ca_rotations `+where, args...)
	if err != nil {
		return nil, fmt.Errorf("statedb: read hub CA rotations: %w", classifyDriverErr(err))
	}
	defer rows.Close()
	var out []HubCARotationRow
	for rows.Next() {
		var r HubCARotationRow
		var names, forced, cut, stagedAt, activatedAt, endedAt string
		var emergency int
		if err := rows.Scan(&r.ID, &r.State, &r.FromSerial, &r.ToSerial, &names, &emergency, &stagedAt,
			&r.StagedBy, &activatedAt, &r.ActivatedBy, &endedAt, &r.EndedBy, &forced, &cut, &r.Detail); err != nil {
			return nil, fmt.Errorf("statedb: scan hub CA rotation: %w", classifyDriverErr(err))
		}
		r.Emergency = emergency != 0
		r.Names = decodeStringList(names)
		r.Forced = decodeStringList(forced)
		r.CutRuns = decodeStringList(cut)
		r.StagedAt = parseStaticTokenTime(stagedAt)
		r.ActivatedAt = parseStaticTokenTime(activatedAt)
		r.EndedAt = parseStaticTokenTime(endedAt)
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("statedb: read hub CA rotations: %w", classifyDriverErr(err))
	}
	return out, nil
}

// HubCALeafAck is what a member reports of one monitor's leaf.
type HubCALeafAck struct {
	Serial   string    `json:"serial"`
	Issuer   string    `json:"issuer"`
	NotAfter time.Time `json:"not_after,omitzero"`
}

// HubCAMemberRow is what one hub process serves and hands out.
type HubCAMemberRow struct {
	InstanceID string
	// Active is the serial of the CA the member issues leaves from.
	Active string
	// Trusts are the CA serials the member tells new dispatches to trust.
	Trusts []string
	// Leaves are, per monitor, the leaf the member serves.
	Leaves map[string]HubCALeafAck
	// AdoptedAt is when the member adopted the trust it reports.
	AdoptedAt time.Time
	SeenAt    time.Time
}

// PutHubCAMember records what a member serves, updating its row in place.
func (d *DB) PutHubCAMember(row HubCAMemberRow) error {
	if strings.TrimSpace(row.InstanceID) == "" {
		return errors.New("statedb: a hub CA member row needs the member's id")
	}
	trusts, err := encodeStringList(row.Trusts)
	if err != nil {
		return err
	}
	leaves := row.Leaves
	if leaves == nil {
		leaves = map[string]HubCALeafAck{}
	}
	lb, err := json.Marshal(leaves)
	if err != nil {
		return fmt.Errorf("statedb: encode the leaves of member %s: %w", row.InstanceID, err)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, err := d.conn.Exec(`INSERT INTO hub_ca_members(instance_id, active, trusts, leaves, adopted_at, seen_at)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(instance_id) DO UPDATE SET active = excluded.active, trusts = excluded.trusts,
			leaves = excluded.leaves, adopted_at = excluded.adopted_at, seen_at = excluded.seen_at`,
		row.InstanceID, row.Active, trusts, string(lb), formatTimeRFC(row.AdoptedAt), formatTimeRFC(row.SeenAt)); err != nil {
		return fmt.Errorf("statedb: record hub CA member %s: %w", row.InstanceID, classifyDriverErr(err))
	}
	return nil
}

// ListHubCAMembers returns every member row, by id.
func (d *DB) ListHubCAMembers() ([]HubCAMemberRow, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	rows, err := d.conn.Query(`SELECT instance_id, active, trusts, leaves, adopted_at, seen_at
		FROM hub_ca_members ORDER BY instance_id`)
	if err != nil {
		return nil, fmt.Errorf("statedb: read hub CA members: %w", classifyDriverErr(err))
	}
	defer rows.Close()
	var out []HubCAMemberRow
	for rows.Next() {
		var r HubCAMemberRow
		var trusts, leaves, adopted, seen string
		if err := rows.Scan(&r.InstanceID, &r.Active, &trusts, &leaves, &adopted, &seen); err != nil {
			return nil, fmt.Errorf("statedb: scan hub CA member: %w", classifyDriverErr(err))
		}
		r.Trusts = decodeStringList(trusts)
		r.Leaves = map[string]HubCALeafAck{}
		if strings.TrimSpace(leaves) != "" {
			// A row this build cannot read reports no leaves rather than
			// failing the whole list: it is one member's report.
			_ = json.Unmarshal([]byte(leaves), &r.Leaves)
		}
		r.AdoptedAt = parseStaticTokenTime(adopted)
		r.SeenAt = parseStaticTokenTime(seen)
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("statedb: read hub CA members: %w", classifyDriverErr(err))
	}
	return out, nil
}

// DeleteHubCAMember removes a member's report: it no longer runs a monitor
// under tls: auto, so it serves nothing a rotation waits for.
func (d *DB) DeleteHubCAMember(instanceID string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, err := d.conn.Exec(`DELETE FROM hub_ca_members WHERE instance_id = ?`, instanceID); err != nil {
		return fmt.Errorf("statedb: forget hub CA member %s: %w", instanceID, classifyDriverErr(err))
	}
	return nil
}

// PruneHubCAMembers deletes the rows of members not heard from since cutoff,
// and reports how many: a member that stopped leaves its row, and the table
// would otherwise keep one per process that ever served. Compared in Go: the
// column holds RFC 3339 text whose fraction varies in length, which does not
// sort as text.
func (d *DB) PruneHubCAMembers(cutoff time.Time) (int64, error) {
	rows, err := d.ListHubCAMembers()
	if err != nil {
		return 0, err
	}
	var n int64
	for _, r := range rows {
		if !r.SeenAt.Before(cutoff) {
			continue
		}
		d.mu.Lock()
		res, err := d.conn.Exec(`DELETE FROM hub_ca_members WHERE instance_id = ? AND seen_at = ?`,
			r.InstanceID, formatTimeRFC(r.SeenAt))
		d.mu.Unlock()
		if err != nil {
			return n, fmt.Errorf("statedb: prune hub CA member %s: %w", r.InstanceID, classifyDriverErr(err))
		}
		k, _ := res.RowsAffected()
		n += k
	}
	return n, nil
}

func encodeStringList(in []string) (string, error) {
	if in == nil {
		in = []string{}
	}
	b, err := json.Marshal(in)
	if err != nil {
		return "", fmt.Errorf("statedb: encode a list: %w", err)
	}
	return string(b), nil
}

// decodeStringList reads a JSON list column; nil for an empty column or one
// that does not parse, which no writer here produces.
func decodeStringList(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	var out []string
	if err := json.Unmarshal([]byte(s), &out); err != nil {
		return nil
	}
	return out
}
