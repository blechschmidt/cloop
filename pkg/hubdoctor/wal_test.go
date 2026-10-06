package hubdoctor

// statedb.wal (Task 20392): the write-ahead log against the larger of 64 MiB
// and a quarter of the database.

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/statedb"
)

func TestWALFinding(t *testing.T) {
	const mib = int64(1) << 20
	cases := []struct {
		name     string
		sample   walSample
		want     Severity
		inText   string
		findings int
	}{
		{"no database", walSample{}, "", "", 0},
		{"no log", walSample{present: true, dbBytes: 400 * mib}, SeverityPass, "state.db-wal is 0 B", 1},
		{"a working log", walSample{present: true, dbBytes: 400 * mib, walBytes: 4 * mib}, SeverityPass, "warned about above 100.0 MB", 1},
		{"at the limit", walSample{present: true, dbBytes: 10 * mib, walBytes: 64 * mib}, SeverityPass, "warned about above 64.0 MB", 1},
		{"past 64 MiB beside a small database", walSample{present: true, dbBytes: 10 * mib, walBytes: 65 * mib}, SeverityWarn, "over the 64.0 MB", 1},
		// A quarter of a large database is the larger allowance.
		{"a large database's burst", walSample{present: true, dbBytes: 1024 * mib, walBytes: 200 * mib}, SeverityPass, "warned about above 256.0 MB", 1},
		{"past a quarter of a large database", walSample{present: true, dbBytes: 1024 * mib, walBytes: 300 * mib}, SeverityWarn, "over the 256.0 MB", 1},
		// The hub this was written on, 2026-10-06.
		{"the live hub", walSample{present: true, dbBytes: 411619328, walBytes: 339949472}, SeverityWarn, "state.db-wal is 324.2 MB", 1},
		{"unmeasurable", walSample{present: true, dbBytes: mib, err: errors.New("stat: permission denied")}, SeverityWarn, "could not measure", 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got []Finding
			checkWAL(tc.sample, func(f Finding) { got = append(got, f) })
			if len(got) != tc.findings {
				t.Fatalf("findings = %+v, want %d", got, tc.findings)
			}
			if tc.findings == 0 {
				return
			}
			f := got[0]
			if f.Check != "statedb.wal" {
				t.Errorf("Check = %q, want statedb.wal", f.Check)
			}
			if f.Severity != tc.want {
				t.Errorf("Severity = %s, want %s (%s)", f.Severity, tc.want, f.Message)
			}
			if !strings.Contains(f.Message, tc.inText) {
				t.Errorf("Message = %q, want it to contain %q", f.Message, tc.inText)
			}
			if f.Severity != SeverityPass && f.Remediation == "" {
				t.Error("a warning carries no remediation")
			}
		})
	}
}

func TestWALWarnAbove(t *testing.T) {
	for _, tc := range []struct{ db, want int64 }{
		{0, statedb.JournalSizeLimitBytes},
		{256 << 20, statedb.JournalSizeLimitBytes},
		{257 << 20, (257 << 20) / 4},
		{4 << 30, 1 << 30},
	} {
		if got := walWarnAbove(tc.db); got != tc.want {
			t.Errorf("walWarnAbove(%d) = %d, want %d", tc.db, got, tc.want)
		}
	}
}

// The log is measured before any check opens the database. Against a hub that
// is not running, the doctor's own connections are the only ones, and the
// last of them to close deletes the log — so a check that looked when its
// turn came would report a log the doctor itself had just removed.
func TestDoctorMeasuresTheLogItFoundNotTheOneItLeft(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, ".cloop", "state.db")
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o700); err != nil {
		t.Fatal(err)
	}
	db, err := statedb.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	// What a hub that stopped without a clean close leaves: a log, past the
	// limit, that nothing holds open.
	const size = 100 << 20
	if err := os.WriteFile(statedb.WALPath(dbPath), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(statedb.WALPath(dbPath), size); err != nil {
		t.Fatal(err)
	}

	f := only(t, findingsFor(t, dir, hubCfg(), Options{Offline: true}), "statedb.wal")
	wantSeverity(t, f, SeverityWarn)
	if got, _ := f.Details["wal_bytes"].(int64); got != size {
		t.Errorf("wal_bytes = %v, want the %d bytes the log held when the doctor started", f.Details["wal_bytes"], size)
	}
}
