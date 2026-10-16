package statedb

// What a database's sealed material depends on, read without migrating it
// (Task 20410).
//
// `cloop db backup` writes these into its sidecar, and `cloop db restore`
// reads them again from the backup before swapping it in: which sealing keys
// the backup's secrets, sessions and hub CA keys are sealed under. Both read a
// file nothing may write — the copy VACUUM INTO just produced, and a backup the
// operator has not yet decided to restore — so everything here goes through a
// connection OpenConn opened, never through Open, which would migrate it. A
// table the database predates reads as empty, and a sealed set that predates
// its key column reads as sealed the pre-envelope way, which is what migration
// 0019 stamps such rows when it adds the column.

import (
	"database/sql"
	"errors"
	"fmt"
	"sort"
)

// LegacyKeyID is the key id pre-envelope material reads as (secretbroker's
// LegacyKeyID, which migration 0019 stamps).
const LegacyKeyID = "legacy"

// SealedFacts is what a database's sealed material depends on.
type SealedFacts struct {
	// KEKs is the sealing-key registry, retired keys included.
	KEKs []KEKRow
	// Rows counts sealed rows by set ("secrets", "sessions", "hub_tls"),
	// then by the key id each is sealed under.
	Rows map[string]map[string]int
	// LegacySalt is the pre-envelope cipher's salt, hex; "" when the
	// database has none.
	LegacySalt string
	// LegacySample is one ciphertext sealed the pre-envelope way, so a
	// passphrase can be checked against the legacy key, which has no check
	// value; nil when no row is sealed that way.
	LegacySample []byte
}

// ByKey totals Rows per key id, across sets.
func (f SealedFacts) ByKey() map[string]int {
	out := map[string]int{}
	for _, byKey := range f.Rows {
		for id, n := range byKey {
			out[id] += n
		}
	}
	return out
}

// Sets lists the sets with sealed rows, sorted.
func (f SealedFacts) Sets() []string {
	out := make([]string, 0, len(f.Rows))
	for set := range f.Rows {
		out = append(out, set)
	}
	sort.Strings(out)
	return out
}

// ReadSealedFacts reads the facts through conn. legacySaltKey names the
// legacy salt's row in broker_meta (secretbroker.LegacySaltMetaKey).
func ReadSealedFacts(conn *sql.DB, legacySaltKey string) (SealedFacts, error) {
	f := SealedFacts{Rows: map[string]map[string]int{}}

	if ok, err := tableExists(conn, "broker_keks"); err != nil {
		return f, err
	} else if ok {
		var cols kekColumns
		var err error
		if cols.root, err = hasColumn(conn, "broker_keks", "root"); err != nil {
			return f, fmt.Errorf("statedb: %w", err)
		}
		if cols.kms, err = hasColumn(conn, "broker_keks", "wrap"); err != nil {
			return f, fmt.Errorf("statedb: %w", err)
		}
		if f.KEKs, err = listKEKs(conn, cols); err != nil {
			return f, err
		}
	}

	for _, p := range sealedPopulations {
		counts, sample, err := readSealedPopulation(conn, p, f.LegacySample == nil)
		if err != nil {
			return f, err
		}
		if len(counts) > 0 {
			f.Rows[p.set] = counts
		}
		if f.LegacySample == nil {
			f.LegacySample = sample
		}
	}

	if ok, err := tableExists(conn, "broker_meta"); err != nil {
		return f, err
	} else if ok {
		err := conn.QueryRow(`SELECT value FROM broker_meta WHERE key = ?`, legacySaltKey).Scan(&f.LegacySalt)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return f, fmt.Errorf("statedb: read the legacy salt: %w", classifyDriverErr(err))
		}
	}
	return f, nil
}

// readSealedPopulation counts p's sealed rows by key id and, when wantSample
// is set, returns one pre-envelope ciphertext from it. The identifiers come
// from sealedPopulations, never from input, so building the SQL from them is
// safe.
func readSealedPopulation(conn *sql.DB, p sealedPopulation, wantSample bool) (map[string]int, []byte, error) {
	if ok, err := tableExists(conn, p.table); err != nil || !ok {
		return nil, nil, err
	}
	hasValue, err := hasColumn(conn, p.table, p.valueColumn)
	if err != nil {
		return nil, nil, fmt.Errorf("statedb: %w", err)
	}
	if !hasValue {
		return nil, nil, nil // nothing is sealed in a set that predates its sealed column
	}
	hasKey, err := hasColumn(conn, p.table, p.keyColumn)
	if err != nil {
		return nil, nil, fmt.Errorf("statedb: %w", err)
	}

	sealed := "1=1"
	if !p.everyRow {
		sealed = p.valueColumn + " IS NOT NULL AND length(" + p.valueColumn + ") > 0"
	}
	keyExpr, legacy := "'"+LegacyKeyID+"'", sealed
	if hasKey {
		keyExpr = p.keyColumn
		legacy = sealed + " AND " + p.keyColumn + " IN ('', '" + LegacyKeyID + "')"
	}

	rows, err := conn.Query(`SELECT ` + keyExpr + `, COUNT(*) FROM ` + p.table +
		` WHERE ` + sealed + ` GROUP BY 1`)
	if err != nil {
		return nil, nil, fmt.Errorf("statedb: count %s by key: %w", p.set, classifyDriverErr(err))
	}
	defer rows.Close()
	counts := map[string]int{}
	for rows.Next() {
		var (
			id string
			n  int
		)
		if err := rows.Scan(&id, &n); err != nil {
			return nil, nil, fmt.Errorf("statedb: count %s by key: %w", p.set, classifyDriverErr(err))
		}
		if id == "" {
			id = LegacyKeyID
		}
		counts[id] += n
	}
	if err := rows.Err(); err != nil {
		return nil, nil, fmt.Errorf("statedb: count %s by key: %w", p.set, classifyDriverErr(err))
	}

	var sample []byte
	if wantSample && counts[LegacyKeyID] > 0 {
		err := conn.QueryRow(`SELECT ` + p.valueColumn + ` FROM ` + p.table + ` WHERE ` + legacy +
			` AND ` + p.valueColumn + ` IS NOT NULL LIMIT 1`).Scan(&sample)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return nil, nil, fmt.Errorf("statedb: read a pre-envelope %s row: %w", p.set, classifyDriverErr(err))
		}
	}
	return counts, sample, nil
}
