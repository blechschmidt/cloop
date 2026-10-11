package statedb

// Static admin token retirement and use (Task 20406). See
// migrations/0064_static_tokens.sql for why both tables exist.
//
// Mechanical accessors. pkg/statictoken owns the fingerprint and the rule for
// when a retirement would leave a hub with no way in; pkg/ui decides what a
// request presenting a retired token is told. Nothing here sees a token's
// value: rows are keyed by its fingerprint, and a malformed one is refused so
// a caller that passed the value by mistake fails instead of storing it.

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ErrStaticTokenFingerprint is returned for a fingerprint that is not 64
// lowercase hex characters.
var ErrStaticTokenFingerprint = errors.New("statedb: a static token fingerprint is 64 lowercase hex characters")

// validStaticTokenFingerprint reports whether fp has the shape
// statictoken.Fingerprint produces. Checked here rather than trusted, because
// the mistake it catches — passing the token instead of its fingerprint —
// would put a credential in a table built to hold none.
func validStaticTokenFingerprint(fp string) bool {
	if len(fp) != 64 {
		return false
	}
	for _, c := range fp {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// RetiredStaticTokenRow is one row of retired_static_tokens.
type RetiredStaticTokenRow struct {
	Fingerprint string
	RetiredAt   time.Time
	RetiredBy   string
	Reason      string
}

// RetireStaticToken records a retirement and, in the same commit, the audit
// event saying so, so the two cannot disagree: a retirement with no record is
// an authority change nobody can review, and a record with no retirement
// claims a containment that did not happen.
//
// Retiring a fingerprint that is already retired writes nothing and returns
// the stored row with written=false. The first retirement is the one an
// auditor reads, and re-stamping it would move the date a caller is told the
// token stopped working. ev may be nil, for a caller that records elsewhere.
func (d *DB) RetireStaticToken(row RetiredStaticTokenRow, ev *AuditEvent) (stored RetiredStaticTokenRow, written bool, err error) {
	row.Fingerprint = strings.TrimSpace(row.Fingerprint)
	if !validStaticTokenFingerprint(row.Fingerprint) {
		return RetiredStaticTokenRow{}, false, ErrStaticTokenFingerprint
	}
	if strings.TrimSpace(row.RetiredBy) == "" {
		return RetiredStaticTokenRow{}, false, errors.New("statedb: a static token retirement names who retired it")
	}
	if row.RetiredAt.IsZero() {
		row.RetiredAt = time.Now()
	}
	row.RetiredAt = row.RetiredAt.UTC()

	d.mu.Lock()
	defer d.mu.Unlock()
	tx, err := d.conn.Begin()
	if err != nil {
		return RetiredStaticTokenRow{}, false, fmt.Errorf("statedb: retire static token: begin: %w", classifyDriverErr(err))
	}
	defer tx.Rollback() //nolint:errcheck

	existing, err := queryRetiredStaticTokens(tx, `WHERE fingerprint = ?`, row.Fingerprint)
	if err != nil {
		return RetiredStaticTokenRow{}, false, err
	}
	if len(existing) > 0 {
		return existing[0], false, nil
	}
	if _, err := tx.Exec(
		`INSERT INTO retired_static_tokens(fingerprint, retired_at, retired_by, reason) VALUES (?, ?, ?, ?)`,
		row.Fingerprint, row.RetiredAt.Format(time.RFC3339Nano), row.RetiredBy, row.Reason); err != nil {
		return RetiredStaticTokenRow{}, false, fmt.Errorf("statedb: retire static token: %w", classifyDriverErr(err))
	}
	if ev != nil {
		evs := []*AuditEvent{ev}
		// Checked like every other append (audit_home.go); a mis-route is
		// reported, not dropped.
		d.assertAuditHome(evs)
		if err := appendAuditEventsTx(tx, evs); err != nil {
			return RetiredStaticTokenRow{}, false, err
		}
	}
	if err := tx.Commit(); err != nil {
		return RetiredStaticTokenRow{}, false, fmt.Errorf("statedb: retire static token: commit: %w", classifyDriverErr(err))
	}
	return row, true, nil
}

// ListRetiredStaticTokens returns every retirement, newest first. The whole
// table, because a hub refuses every fingerprint in it and the table holds one
// row per token ever retired.
func (d *DB) ListRetiredStaticTokens() ([]RetiredStaticTokenRow, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return queryRetiredStaticTokens(d.conn, `ORDER BY retired_at DESC, fingerprint`)
}

// staticTokenQuerier is what the readers here read through: the connection,
// or a transaction already holding the write lock.
type staticTokenQuerier interface {
	Query(query string, args ...any) (*sql.Rows, error)
}

func queryRetiredStaticTokens(q staticTokenQuerier, where string, args ...any) ([]RetiredStaticTokenRow, error) {
	rows, err := q.Query(`SELECT fingerprint, retired_at, retired_by, reason FROM retired_static_tokens `+where, args...)
	if err != nil {
		return nil, fmt.Errorf("statedb: list retired static tokens: %w", classifyDriverErr(err))
	}
	defer rows.Close()
	var out []RetiredStaticTokenRow
	for rows.Next() {
		var r RetiredStaticTokenRow
		var at string
		if err := rows.Scan(&r.Fingerprint, &at, &r.RetiredBy, &r.Reason); err != nil {
			return nil, fmt.Errorf("statedb: scan retired static token: %w", classifyDriverErr(err))
		}
		r.RetiredAt = parseStaticTokenTime(at)
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("statedb: list retired static tokens: %w", classifyDriverErr(err))
	}
	return out, nil
}

// StaticTokenUseRow is one row of static_token_use.
type StaticTokenUseRow struct {
	Fingerprint   string
	FirstSeenAt   time.Time
	HeldAt        time.Time
	HeldBy        string
	SSO           bool
	LastUsedAt    time.Time
	LastUsedIP    string
	RefusedCount  int64
	LastRefusedAt time.Time
	LastRefusedIP string
}

// StaticTokenUseReport is what one hub process flushes about one fingerprint:
// what it saw since its previous flush.
type StaticTokenUseReport struct {
	Fingerprint string
	// At is when the report was made.
	At time.Time
	// Held says the reporting process holds this token — it is its configured
	// static token — and stamps held_at, held_by and sso.
	Held   bool
	HeldBy string
	SSO    bool
	// UsedAt and UsedIP are the latest request admitted with the token since
	// the previous flush; zero when none was.
	UsedAt time.Time
	UsedIP string
	// Refused counts the requests refused because the token is retired since
	// the previous flush, the latest at RefusedAt from RefusedIP.
	Refused   int64
	RefusedAt time.Time
	RefusedIP string
}

// ReportStaticTokenUse merges reports into static_token_use in one
// transaction.
//
// Merged rather than overwritten, because several hub processes may hold one
// token and each flushes only what it saw: the latest use and the latest
// refusal win whichever process reported them, the refusal count adds up, and
// a report that saw no use leaves the recorded one alone. Compared as times
// in Go rather than as text in SQL, since RFC 3339 with trimmed fractions does
// not sort as a string.
func (d *DB) ReportStaticTokenUse(reports []StaticTokenUseReport) error {
	if len(reports) == 0 {
		return nil
	}
	for _, rep := range reports {
		if !validStaticTokenFingerprint(rep.Fingerprint) {
			return ErrStaticTokenFingerprint
		}
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	tx, err := d.conn.Begin()
	if err != nil {
		return fmt.Errorf("statedb: report static token use: begin: %w", classifyDriverErr(err))
	}
	defer tx.Rollback() //nolint:errcheck

	for _, rep := range reports {
		at := rep.At
		if at.IsZero() {
			at = time.Now()
		}
		rows, err := queryStaticTokenUse(tx, `WHERE fingerprint = ?`, rep.Fingerprint)
		if err != nil {
			return err
		}
		row := StaticTokenUseRow{Fingerprint: rep.Fingerprint}
		if len(rows) > 0 {
			row = rows[0]
		}
		if rep.Held {
			if row.FirstSeenAt.IsZero() {
				row.FirstSeenAt = at
			}
			row.HeldAt, row.HeldBy, row.SSO = at, rep.HeldBy, rep.SSO
		}
		if !rep.UsedAt.IsZero() && rep.UsedAt.After(row.LastUsedAt) {
			row.LastUsedAt, row.LastUsedIP = rep.UsedAt, rep.UsedIP
		}
		if rep.Refused > 0 {
			row.RefusedCount += rep.Refused
			if rep.RefusedAt.After(row.LastRefusedAt) {
				row.LastRefusedAt, row.LastRefusedIP = rep.RefusedAt, rep.RefusedIP
			}
		}
		sso := 0
		if row.SSO {
			sso = 1
		}
		if _, err := tx.Exec(`INSERT INTO static_token_use(fingerprint, first_seen_at, held_at, held_by, sso,
				last_used_at, last_used_ip, refused_count, last_refused_at, last_refused_ip)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(fingerprint) DO UPDATE SET
				first_seen_at = excluded.first_seen_at, held_at = excluded.held_at,
				held_by = excluded.held_by, sso = excluded.sso,
				last_used_at = excluded.last_used_at, last_used_ip = excluded.last_used_ip,
				refused_count = excluded.refused_count, last_refused_at = excluded.last_refused_at,
				last_refused_ip = excluded.last_refused_ip`,
			row.Fingerprint, formatStaticTokenTime(row.FirstSeenAt), formatStaticTokenTime(row.HeldAt),
			row.HeldBy, sso, formatStaticTokenTime(row.LastUsedAt), row.LastUsedIP, row.RefusedCount,
			formatStaticTokenTime(row.LastRefusedAt), row.LastRefusedIP); err != nil {
			return fmt.Errorf("statedb: report static token use: %w", classifyDriverErr(err))
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("statedb: report static token use: commit: %w", classifyDriverErr(err))
	}
	return nil
}

// ListStaticTokenUse returns every row, the most recently held first.
func (d *DB) ListStaticTokenUse() ([]StaticTokenUseRow, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return queryStaticTokenUse(d.conn, `ORDER BY held_at DESC, fingerprint`)
}

func queryStaticTokenUse(q staticTokenQuerier, where string, args ...any) ([]StaticTokenUseRow, error) {
	rows, err := q.Query(`SELECT fingerprint, first_seen_at, held_at, held_by, sso, last_used_at,
		last_used_ip, refused_count, last_refused_at, last_refused_ip FROM static_token_use `+where, args...)
	if err != nil {
		return nil, fmt.Errorf("statedb: list static token use: %w", classifyDriverErr(err))
	}
	defer rows.Close()
	var out []StaticTokenUseRow
	for rows.Next() {
		var (
			r                          StaticTokenUseRow
			first, held, used, refused string
			sso                        int
		)
		if err := rows.Scan(&r.Fingerprint, &first, &held, &r.HeldBy, &sso, &used, &r.LastUsedIP,
			&r.RefusedCount, &refused, &r.LastRefusedIP); err != nil {
			return nil, fmt.Errorf("statedb: scan static token use: %w", classifyDriverErr(err))
		}
		r.FirstSeenAt = parseStaticTokenTime(first)
		r.HeldAt = parseStaticTokenTime(held)
		r.LastUsedAt = parseStaticTokenTime(used)
		r.LastRefusedAt = parseStaticTokenTime(refused)
		r.SSO = sso != 0
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("statedb: list static token use: %w", classifyDriverErr(err))
	}
	return out, nil
}

// formatStaticTokenTime renders t for a column, ” for the zero time.
func formatStaticTokenTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}

// parseStaticTokenTime reads a column back, the zero time for ” or anything
// that does not parse.
func parseStaticTokenTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}
	}
	return t.UTC()
}
