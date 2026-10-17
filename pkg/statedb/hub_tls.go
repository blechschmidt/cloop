package statedb

// The hub's own certificate authority and the leaves it issues its credential
// monitors (Task 20409). See migrations/0065_hub_tls.sql for the shape.
//
// Mechanical accessors. pkg/hubca owns the certificates, the sealing and the
// rule for when a leaf is replaced; this file only stores rows. Nothing here
// sees a private key in the clear: the key columns hold an envelope sealed
// under the hub's KEK registry, and a row that would store an empty one is
// refused so a caller that forgot to seal fails instead of writing nothing.
//
// Since Task 20438 the CA is replaced online, through three CA rows: 'ca', the
// one leaves are issued from; 'ca:next', a CA staged to replace it; and
// 'ca:previous', the one it replaced, still trusted until it is retired (see
// migrations/0081_hub_ca_rotation.sql and hub_ca_rotation.go). Retiring a CA
// deletes its row, and its sealed key is meant to be gone from the file with
// it. A delete alone does not do that — SQLite leaves the record in the page's
// free space — and neither does any earlier write: replacing a row, or
// rewrapping its key under a new KEK, frees an image of it with the envelope
// in it. So, as for the KEK registry (Task 20433), every write to hub_tls runs
// on a secure-delete connection (shreddingTx), which zeroes what it frees.

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ErrHubTLSNotFound is returned when the hub has no row by that id: no CA
// minted yet, or no leaf issued for that monitor.
var ErrHubTLSNotFound = errors.New("statedb: no hub certificate by that id")

// HubTLSRow is one row of hub_tls.
type HubTLSRow struct {
	// ID is "ca" or "leaf:<monitor>".
	ID string
	// Kind is "ca" or "leaf".
	Kind string
	// Serial is the certificate's serial in lowercase hex.
	Serial string
	// Issuer is, for a leaf, the serial of the CA that signed it.
	Issuer string
	// CertPEM is the certificate. Public.
	CertPEM string
	// KeyID, WrappedDEK and KeySealed are the private key's envelope.
	KeyID      string
	WrappedDEK []byte
	KeySealed  []byte
	// SANs are a leaf's names and addresses.
	SANs []string
	// NotBefore and NotAfter bound the certificate's validity.
	NotBefore time.Time
	NotAfter  time.Time
	// IssuedAt and IssuedBy say when and by which hub process.
	IssuedAt time.Time
	IssuedBy string
}

func (r HubTLSRow) check() error {
	switch {
	case strings.TrimSpace(r.ID) == "":
		return errors.New("statedb: a hub certificate row needs an id")
	case r.Kind != "ca" && r.Kind != "leaf":
		return fmt.Errorf("statedb: hub certificate %s: kind %q is neither ca nor leaf", r.ID, r.Kind)
	case strings.TrimSpace(r.Serial) == "":
		return fmt.Errorf("statedb: hub certificate %s has no serial", r.ID)
	case strings.TrimSpace(r.CertPEM) == "":
		return fmt.Errorf("statedb: hub certificate %s has no certificate", r.ID)
	case len(r.KeySealed) == 0 || len(r.WrappedDEK) == 0 || strings.TrimSpace(r.KeyID) == "":
		// The one refusal that matters: a row with no sealed key is either a
		// caller that forgot to seal — about to write nothing, and then fail at
		// the next start — or one about to write the key some other way.
		return fmt.Errorf("statedb: refusing to store hub certificate %s without a sealed private key", r.ID)
	}
	return nil
}

const hubTLSColumns = `id, kind, serial, issuer, cert_pem, key_id, wrapped_dek, key_sealed,
	sans, not_before, not_after, issued_at, issued_by`

// GetHubTLS returns the row by id, or ErrHubTLSNotFound.
func (d *DB) GetHubTLS(id string) (HubTLSRow, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	rows, err := queryHubTLS(d.conn, `WHERE id = ?`, id)
	if err != nil {
		return HubTLSRow{}, err
	}
	if len(rows) == 0 {
		return HubTLSRow{}, fmt.Errorf("%w: %s", ErrHubTLSNotFound, id)
	}
	return rows[0], nil
}

// ListHubTLS returns every row, by id.
func (d *DB) ListHubTLS() ([]HubTLSRow, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return queryHubTLS(d.conn, `ORDER BY id`)
}

// InsertHubTLS writes a row that does not exist yet, and reports whether it
// was written. An existing row is left exactly as it is and inserted is
// false: the CA is minted once, and of two hub processes minting it at the
// same moment the one that loses must adopt the winner's rather than replace
// it — a replaced CA is one every sandbox already given the old one refuses.
func (d *DB) InsertHubTLS(row HubTLSRow) (inserted bool, err error) {
	if err := row.check(); err != nil {
		return false, err
	}
	sans, err := encodeHubTLSSANs(row.SANs)
	if err != nil {
		return false, err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	res, err := d.secureExec(`INSERT INTO hub_tls(`+hubTLSColumns+`)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO NOTHING`,
		row.ID, row.Kind, row.Serial, row.Issuer, row.CertPEM, row.KeyID, row.WrappedDEK, row.KeySealed,
		sans, formatTimeRFC(row.NotBefore), formatTimeRFC(row.NotAfter), formatTimeRFC(row.IssuedAt), row.IssuedBy)
	if err != nil {
		return false, fmt.Errorf("statedb: insert hub certificate %s: %w", row.ID, classifyDriverErr(err))
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("statedb: insert hub certificate %s: %w", row.ID, classifyDriverErr(err))
	}
	return n > 0, nil
}

// ReplaceHubTLS swaps the row by id for next if, and only if, its serial is
// still expectSerial, and reports whether it did. False is an ordinary outcome:
// another hub process replaced it first, and the caller re-reads the winner.
//
// Updated in place, never deleted and re-inserted, for the reason SaveState is
// (tests/arch/rowreplace_test.go): a binary that knows fewer columns must not
// reset the ones it does not know.
func (d *DB) ReplaceHubTLS(next HubTLSRow, expectSerial string) (bool, error) {
	if err := next.check(); err != nil {
		return false, err
	}
	if strings.TrimSpace(expectSerial) == "" {
		return false, fmt.Errorf("statedb: replacing hub certificate %s needs the serial it replaces", next.ID)
	}
	sans, err := encodeHubTLSSANs(next.SANs)
	if err != nil {
		return false, err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	res, err := d.secureExec(`UPDATE hub_tls SET kind = ?, serial = ?, issuer = ?, cert_pem = ?,
		key_id = ?, wrapped_dek = ?, key_sealed = ?, sans = ?, not_before = ?, not_after = ?,
		issued_at = ?, issued_by = ?
		WHERE id = ? AND serial = ?`,
		next.Kind, next.Serial, next.Issuer, next.CertPEM, next.KeyID, next.WrappedDEK, next.KeySealed,
		sans, formatTimeRFC(next.NotBefore), formatTimeRFC(next.NotAfter), formatTimeRFC(next.IssuedAt),
		next.IssuedBy, next.ID, expectSerial)
	if err != nil {
		return false, fmt.Errorf("statedb: replace hub certificate %s: %w", next.ID, classifyDriverErr(err))
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("statedb: replace hub certificate %s: %w", next.ID, classifyDriverErr(err))
	}
	return n > 0, nil
}

// CountHubTLSByKey groups the rows by the key sealing their private keys.
func (d *DB) CountHubTLSByKey() (map[string]int, error) {
	return d.countByKey(
		`SELECT key_id, COUNT(*) FROM hub_tls
		 WHERE key_sealed IS NOT NULL AND length(key_sealed) > 0
		 GROUP BY key_id`, "hub certificates")
}

// ListHubTLSNotUnderKey returns up to limit rows whose private key is sealed
// under some other key, by id.
func (d *DB) ListHubTLSNotUnderKey(keyID string, limit int) ([]HubTLSRow, error) {
	if limit <= 0 {
		limit = 128
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	return queryHubTLS(d.conn, `WHERE key_id <> ? AND key_sealed IS NOT NULL AND length(key_sealed) > 0
		ORDER BY id LIMIT ?`, keyID, limit)
}

// ReplaceHubTLSSealed swaps a row's key envelope under compare-and-swap on the
// key id and the exact ciphertext, for the reason ReplaceBrokerSecretSealed
// gives: a leaf renewed while a rotation was reading it must not have the
// previous key restored under a fresh wrap. On a secure-delete connection,
// because the image of the row the rewrap frees carries the old envelope.
func (d *DB) ReplaceHubTLSSealed(id string, expect, next SealedRow) (bool, error) {
	if id == "" {
		return false, fmt.Errorf("statedb: hub certificate id is empty")
	}
	if len(next.Ciphertext) == 0 || len(expect.Ciphertext) == 0 {
		// An empty expectation binds as NULL and would match nothing: a swap
		// that silently cannot happen reads as a rotation that converged.
		return false, fmt.Errorf("statedb: refusing to rewrap hub certificate %s against or onto an empty ciphertext", id)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	res, err := d.secureExec(`UPDATE hub_tls SET key_id = ?, wrapped_dek = ?, key_sealed = ?
		 WHERE id = ? AND key_id = ? AND key_sealed = ?`,
		next.KeyID, next.WrappedDEK, next.Ciphertext, id, expect.KeyID, expect.Ciphertext)
	if err != nil {
		return false, fmt.Errorf("statedb: rewrap hub certificate %s: %w", id, classifyDriverErr(err))
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("statedb: rewrap hub certificate %s: %w", id, classifyDriverErr(err))
	}
	return n > 0, nil
}

// DeleteHubTLS removes the row by id if, and only if, its serial is still
// serial, and reports whether it did — on a secure-delete connection, so the
// row's sealed key is zeroed in the page it leaves rather than left in its
// free space. pkg/hubca deletes a CA it retires or abandons; nothing deletes a
// leaf, which is only ever replaced.
func (d *DB) DeleteHubTLS(id, serial string) (bool, error) {
	if strings.TrimSpace(id) == "" || strings.TrimSpace(serial) == "" {
		return false, errors.New("statedb: deleting a hub certificate needs its id and serial")
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	res, err := d.secureExec(`DELETE FROM hub_tls WHERE id = ? AND serial = ?`, id, serial)
	if err != nil {
		return false, fmt.Errorf("statedb: delete hub certificate %s: %w", id, classifyDriverErr(err))
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("statedb: delete hub certificate %s: %w", id, classifyDriverErr(err))
	}
	return n > 0, nil
}

// hubTLSQuerier is what the readers here read through.
type hubTLSQuerier interface {
	Query(query string, args ...any) (*sql.Rows, error)
}

func queryHubTLS(q hubTLSQuerier, where string, args ...any) ([]HubTLSRow, error) {
	rows, err := q.Query(`SELECT `+hubTLSColumns+` FROM hub_tls `+where, args...)
	if err != nil {
		return nil, fmt.Errorf("statedb: read hub certificates: %w", classifyDriverErr(err))
	}
	defer rows.Close()
	var out []HubTLSRow
	for rows.Next() {
		var r HubTLSRow
		var sans, notBefore, notAfter, issuedAt string
		if err := rows.Scan(&r.ID, &r.Kind, &r.Serial, &r.Issuer, &r.CertPEM, &r.KeyID, &r.WrappedDEK,
			&r.KeySealed, &sans, &notBefore, &notAfter, &issuedAt, &r.IssuedBy); err != nil {
			return nil, fmt.Errorf("statedb: scan hub certificate: %w", classifyDriverErr(err))
		}
		if strings.TrimSpace(sans) != "" {
			if err := json.Unmarshal([]byte(sans), &r.SANs); err != nil {
				return nil, fmt.Errorf("statedb: hub certificate %s: names are not a JSON list: %w", r.ID, err)
			}
		}
		r.NotBefore = parseStaticTokenTime(notBefore)
		r.NotAfter = parseStaticTokenTime(notAfter)
		r.IssuedAt = parseStaticTokenTime(issuedAt)
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("statedb: read hub certificates: %w", classifyDriverErr(err))
	}
	return out, nil
}

func encodeHubTLSSANs(sans []string) (string, error) {
	if sans == nil {
		sans = []string{}
	}
	b, err := json.Marshal(sans)
	if err != nil {
		return "", fmt.Errorf("statedb: encode hub certificate names: %w", err)
	}
	return string(b), nil
}
