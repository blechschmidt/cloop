package hubdoctor

// The sealing key check.
//
// CLOOP_SECRET_KEY is the root of the secret broker: every GitHub PAT,
// kubeconfig and egress credential in the database is sealed under a key
// derived from it. That makes it the one value in a cloop deployment with two
// opposite failure modes, both silent:
//
//   - Absent. The hub boots, serves the dashboard, and fails only when
//     something tries to open a sealed secret — which on a fresh deployment is
//     the first real run, long after the operator concluded it worked.
//   - Weak. Everything works perfectly, forever, and the sealed material is
//     recoverable by anyone who obtains the database. Nothing will ever report
//     this at runtime, because from the code's point of view there is no
//     failure.
//
// So this file checks presence *and* quality, and it is the only place in cloop
// that judges the second. The bar is deliberately empirical rather than
// cryptographic: a real generated key is 32 bytes of crypto/rand rendered as
// base64url, and the values that show up instead are recognisable — a
// passphrase somebody typed, a placeholder copied out of a compose file, a
// short hex string. Distinguishing those from a real key does not require
// estimating entropy precisely; it requires noticing they are short, or made of
// a handful of distinct characters, or literally the string in the docs.

import (
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/secretstore"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

const (
	// minKeyLength is below what `cloop hub bootstrap` generates (43
	// characters for 32 random bytes in base64url). Anything shorter was
	// typed by a human or truncated.
	minKeyLength = 32

	// minKeyEntropyBits is the Shannon estimate below which a value is
	// treated as a passphrase rather than a key. A 32-byte random key in
	// base64url scores ~180 bits by this measure; "correct-horse-battery"
	// scores under 80.
	minKeyEntropyBits = 96
)

// placeholderKeys are values shipped in cloop's own documentation and eval
// stack. Finding one in a deployment means the operator copied an example and
// did not replace it, which is worth naming explicitly rather than describing
// as "low entropy".
var placeholderKeys = []string{
	"eval-only-not-a-real-key-change-me",
	"change-me",
	"changeme",
	"secret",
	"cloop",
}

func checkSecretKey(dir string, cfg *config.Config, add addFn) {
	key := os.Getenv(secretbroker.EnvPassphraseKey)
	sealed := hasSealedMaterial(dir) || brokerSecretsStored(dir)

	// Unset exactly when the keyring says so (secretbroker.OpenKeyring tests
	// for ""): a value of spaces is a passphrase to it, and is judged below
	// as one — a very short one.
	if key == "" {
		// Severity turns on whether anything is already sealed. With sealed
		// material and no key the hub cannot open its own secrets, which is
		// an outage; without, it is a hub that will fail the first time
		// somebody grants a credential.
		sev := SeverityWarn
		msg := secretbroker.EnvPassphraseKey + " is not set, so no secret can be sealed or opened; " +
			"granting a credential will fail"
		if sealed {
			sev = SeverityFail
			msg = secretbroker.EnvPassphraseKey + " is not set but this hub has sealed secrets — " +
				"they cannot be opened without it"
		}
		add(Finding{
			Check: "secret_key.present", Title: "Sealing key", Severity: sev,
			Message:     msg,
			Remediation: "Export " + secretbroker.EnvPassphraseKey + " from .cloop/hub.env (`cloop hub bootstrap` writes it)",
		})
		return
	}

	for _, p := range placeholderKeys {
		if strings.EqualFold(strings.TrimSpace(key), p) {
			add(Finding{
				Check: "secret_key.entropy", Title: "Sealing key strength", Severity: SeverityFail,
				Message: "the sealing key is a placeholder value from cloop's own documentation; " +
					"every sealed credential is recoverable by anyone with the database",
				Remediation: "Generate a real one: `cloop hub key rotate` (or re-run `cloop hub bootstrap`), " +
					"then re-seal existing secrets",
			})
			return
		}
	}

	bits := shannonBits(key)
	switch {
	case len(key) < minKeyLength:
		add(Finding{
			Check: "secret_key.entropy", Title: "Sealing key strength", Severity: SeverityFail,
			Message: fmt.Sprintf("the sealing key is %d characters; `cloop hub bootstrap` generates 43 "+
				"(32 bytes of crypto/rand)", len(key)),
			Remediation: "Replace it with a generated key: `cloop hub key rotate`",
		})
	case bits < minKeyEntropyBits:
		add(Finding{
			Check: "secret_key.entropy", Title: "Sealing key strength", Severity: SeverityWarn,
			Message: fmt.Sprintf("the sealing key looks like a passphrase (~%.0f bits by character "+
				"distribution) rather than generated key material", bits),
			Remediation: "Replace it with a generated key: `cloop hub key rotate`",
		})
	default:
		add(Finding{
			Check: "secret_key.entropy", Title: "Sealing key strength", Severity: SeverityPass,
			Message: fmt.Sprintf("%d characters of high-entropy key material", len(key)),
		})
	}

	checkKeyOpensKeyring(dir, add)
	_ = cfg
}

// checkKeyOpensKeyring asks the hub's own keyring whether the key opens this
// control plane's sealing keys: secretbroker.OpenKeyring, which the broker
// runs before every lease, opened read-only (WithoutKeyCreation) so that a
// diagnostic never mints or promotes a key. Strength says nothing about this:
// a perfectly random key that is not the one the secrets were sealed under
// passed here, on a hub whose broker refused every lease (Task 20387).
func checkKeyOpensKeyring(dir string, add addFn) {
	dbPath := state.DBPath(dir)
	if _, err := os.Stat(dbPath); err != nil {
		return
	}
	db, err := statedb.Open(dbPath)
	if err != nil {
		return // checkStorage reports a database that will not open
	}
	defer func() { _ = db.Close() }()
	store, err := secretstore.New(db)
	if err != nil {
		return
	}
	kr, err := secretbroker.OpenKeyring(store, secretbroker.WithoutKeyCreation())
	switch {
	case errors.Is(err, secretbroker.ErrKeyUnavailable):
		add(Finding{
			Check: "secret_key.matches", Title: "Sealing key matches", Severity: SeverityFail,
			Message: "the key does not open this hub's sealing keys, so the broker refuses every lease " +
				"and no sealed secret can be read: " + err.Error(),
			Remediation: "Set " + secretbroker.EnvPassphraseKey + " to the key these secrets were sealed " +
				"under (the hub's own environment file has it); `cloop hub key list` names the keys it cannot open",
		})
	case err != nil:
		add(Finding{
			Check: "secret_key.matches", Title: "Sealing key matches", Severity: SeverityWarn,
			Message:     "the hub's sealing keys could not be checked against the key: " + err.Error(),
			Remediation: "Run `cloop hub key list` in this directory for the keyring's own report",
		})
	case kr.PrimaryID() == "":
		add(Finding{
			Check: "secret_key.matches", Title: "Sealing key matches", Severity: SeverityPass,
			Message: "no sealing key is recorded yet; the hub creates its first from this key when it " +
				"first needs one",
		})
	default:
		add(Finding{
			Check: "secret_key.matches", Title: "Sealing key matches", Severity: SeverityPass,
			Message: "the key derives this hub's primary sealing key, " + kr.PrimaryID(),
		})
	}
}

// hasSealedMaterial reports whether this control plane has a project secret
// file sealed under the key. The broker's own sealed rows are judged by
// brokerSecretsStored.
//
// It reads the filesystem rather than the database deliberately, and it is
// deliberately conservative: a state.db exists on every hub, so treating its
// presence as evidence of sealed material would turn "no key configured yet"
// into a failure on every fresh deployment.
func hasSealedMaterial(dir string) bool {
	if dir == "" {
		return false
	}
	_, err := os.Stat(filepath.Join(dir, ".cloop", "secrets.enc"))
	return err == nil
}

// brokerSecretsStored reports whether the broker holds any secret in the hub's
// database: a PAT, a kubeconfig, an App key — each sealed under the key, and
// unreadable without it. Not the key registry: the hub records a sealing key
// whenever it starts with one set, sealed secret or not, so a recorded key
// says only that the hub once had one. Read from the store's own listing;
// false when there is no database to read.
func brokerSecretsStored(dir string) bool {
	dbPath := state.DBPath(dir)
	if _, err := os.Stat(dbPath); err != nil {
		return false
	}
	db, err := statedb.Open(dbPath)
	if err != nil {
		return false
	}
	defer func() { _ = db.Close() }()
	store, err := secretstore.New(db)
	if err != nil {
		return false
	}
	secrets, err := store.ListSecrets()
	return err == nil && len(secrets) > 0
}

// shannonBits estimates total entropy as (per-character Shannon entropy of the
// observed distribution) × length.
//
// This measure is generous to random strings and harsh to repetitive ones,
// which is exactly the discrimination wanted: it cannot tell a real key from a
// cleverly-chosen one, and it reliably separates 43 base64 characters from
// "hunter2hunter2hunter2hunter2hunter2".
func shannonBits(s string) float64 {
	if s == "" {
		return 0
	}
	counts := map[rune]int{}
	n := 0
	for _, r := range s {
		counts[r]++
		n++
	}
	var perChar float64
	for _, c := range counts {
		p := float64(c) / float64(n)
		perChar -= p * math.Log2(p)
	}
	return perChar * float64(n)
}
