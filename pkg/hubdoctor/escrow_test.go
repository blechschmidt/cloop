package hubdoctor

// The sealing key escrow, as the doctor reports it (Task 20410).

import (
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/keyescrow"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// No escrow on record warns; one holding another key fails; one holding the
// key in use passes. The doctor compares fingerprints and opens nothing.
func TestTheEscrowOnRecordIsComparedWithTheKeyInUse(t *testing.T) {
	dir := t.TempDir()
	dbPath := mustInitStateDB(t, dir)
	const key = "Zq4pV9mW2xT7rL0yH3nB8kD5sF1gJ6cA-uE_oI4tR7w"
	t.Setenv("CLOOP_SECRET_KEY", key)

	f := only(t, findingsFor(t, dir, hubCfg(), Options{Offline: true}), "secret_key.escrow")
	wantSeverity(t, f, SeverityWarn)
	if !strings.Contains(f.Message, "no escrow") || !strings.Contains(f.Remediation, "escrow export") {
		t.Errorf("no escrow: %+v", f)
	}

	record := func(escrowed string) {
		t.Helper()
		ef, err := keyescrow.Wrap([]byte(escrowed), []byte("a long enough escrow passphrase"), keyescrow.WrapOptions{CreatedBy: "cli:test"})
		if err != nil {
			t.Fatal(err)
		}
		db, err := statedb.Open(dbPath)
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()
		if err := keyescrow.SaveRecord(db, ef.Record("cli:test", time.Now())); err != nil {
			t.Fatal(err)
		}
	}

	record("an-older-key-the-hub-no-longer-runs-on-0123456789")
	f = only(t, findingsFor(t, dir, hubCfg(), Options{Offline: true}), "secret_key.escrow")
	wantSeverity(t, f, SeverityFail)
	if !strings.Contains(f.Message, "opens nothing sealed now") {
		t.Errorf("a stale escrow: %+v", f)
	}

	record(key)
	f = only(t, findingsFor(t, dir, hubCfg(), Options{Offline: true}), "secret_key.escrow")
	wantSeverity(t, f, SeverityPass)
	fp, _ := keyescrow.Fingerprint([]byte(key))
	if !strings.Contains(f.Message, fp) {
		t.Errorf("the escrow of the key in use: %+v", f)
	}
}
