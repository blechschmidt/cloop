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
	"github.com/blechschmidt/cloop/pkg/keyescrow"
	"github.com/blechschmidt/cloop/pkg/rootkey"
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

// changeRootHint is the remedy for a key that has to be replaced: the
// procedure, not `cloop hub key rotate` alone, which mints every new
// key-encryption key from the same root and so replaces nothing that matters
// about a weak one (Task 20425).
const changeRootHint = "Change the root key online: generate one (`openssl rand -base64 32`), restart every hub " +
	"member with it as " + rootkey.EnvKey + " and the old one as " + rootkey.EnvPrevious + ", escrow it " +
	"(`cloop hub key escrow export`), then `cloop hub key rotate --retire-previous` and drop " +
	rootkey.EnvPrevious + " — the runbook's \"Changing CLOOP_SECRET_KEY itself\". `cloop hub key rotate` " +
	"alone derives every new key from the same weak value"

func checkSecretKey(dir string, cfg *config.Config, add addFn) {
	roots, rerr := rootkey.Resolve()
	if rerr != nil {
		// Configured and refused: the hub would not start, and nothing else
		// about the key can be judged until it does.
		add(Finding{
			Check: "secret_key.source", Title: "Sealing key source", Severity: SeverityFail,
			Message:     "the hub's root key is configured and refused, so the hub will not start: " + rerr.Error(),
			Remediation: "Fix the source the message names; `cloop hub key` commands and the hub read it the same way",
		})
		return
	}
	key := roots.Current.Value
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
			Message: msg,
			Remediation: "Give the hub its key: a file named by " + rootkey.EnvKeyFile + " (mode 0400, outside .cloop/), " +
				"the systemd credential " + rootkey.Credential + ", or " + rootkey.EnvKey + " — `cloop hub bootstrap` writes one",
		})
		return
	}
	checkKeySource(roots, add)

	weak := false
	for _, p := range placeholderKeys {
		if strings.EqualFold(strings.TrimSpace(key), p) {
			add(Finding{
				Check: "secret_key.entropy", Title: "Sealing key strength", Severity: SeverityFail,
				Message: "the sealing key is a placeholder value from cloop's own documentation; " +
					"every sealed credential is recoverable by anyone with the database",
				Remediation: changeRootHint,
			})
			weak = true
			break
		}
	}

	bits := shannonBits(key)
	switch {
	case weak:
	case len(key) < minKeyLength:
		add(Finding{
			Check: "secret_key.entropy", Title: "Sealing key strength", Severity: SeverityFail,
			Message: fmt.Sprintf("the sealing key is %d characters; `cloop hub bootstrap` generates 43 "+
				"(32 bytes of crypto/rand)", len(key)),
			Remediation: changeRootHint,
		})
	case bits < minKeyEntropyBits:
		add(Finding{
			Check: "secret_key.entropy", Title: "Sealing key strength", Severity: SeverityWarn,
			Message: fmt.Sprintf("the sealing key looks like a passphrase (~%.0f bits by character "+
				"distribution) rather than generated key material", bits),
			Remediation: changeRootHint,
		})
	default:
		add(Finding{
			Check: "secret_key.entropy", Title: "Sealing key strength", Severity: SeverityPass,
			Message: fmt.Sprintf("%d characters of high-entropy key material", len(key)),
		})
	}

	checkKeyOpensKeyring(dir, roots, add)
	checkKeyEscrow(dir, roots, add)
	_ = cfg
}

// checkKeySource reports where the root key comes from (Task 20425). An
// environment variable is in /proc/<pid>/environ, `systemctl show` and the
// environment of every child not scrubbed of it; on a host where systemd
// starts the hub, a credential costs one line of the unit and ends all three.
func checkKeySource(roots rootkey.Roots, add addFn) {
	cur := roots.Current
	envCopy := false
	for _, also := range cur.Also {
		envCopy = envCopy || also == rootkey.SourceEnvironment
	}
	switch {
	case cur.Source == rootkey.SourceEnvironment && systemdHost():
		add(Finding{
			Check: "secret_key.source", Title: "Sealing key source", Severity: SeverityWarn,
			Message: "the root key is read from the environment variable " + rootkey.EnvKey + " on a host run by " +
				"systemd: it is readable in /proc/<pid>/environ and `systemctl show`, and inherited by every " +
				"child process that is not scrubbed of it",
			Remediation: "Load it as a credential instead: `systemd-creds encrypt --name=" + rootkey.Credential +
				" <key file> /etc/credstore.encrypted/" + rootkey.Credential + "` and " +
				"`LoadCredentialEncrypted=" + rootkey.Credential + "` in the unit (or LoadCredential= from a 0400 " +
				"file outside .cloop/), then remove " + rootkey.EnvKey + " from its EnvironmentFile",
		})
	case envCopy:
		add(Finding{
			Check: "secret_key.source", Title: "Sealing key source", Severity: SeverityWarn,
			Message: "the root key is read from " + cur.Describe() + ", and the same key is also set in the " +
				"environment variable " + rootkey.EnvKey + " — which keeps every exposure the file was meant to end",
			Remediation: "Remove " + rootkey.EnvKey + " from the hub's environment (its EnvironmentFile, " +
				"hub.env, the Pod's env)",
		})
	default:
		add(Finding{
			Check: "secret_key.source", Title: "Sealing key source", Severity: SeverityPass,
			Message: "the root key is read from " + cur.Describe(),
		})
	}

	if prev := roots.Previous; prev.Set() {
		add(Finding{
			Check: "secret_key.previous", Title: "Previous root key", Severity: SeverityWarn,
			Message: "a change of root is in progress: " + rootkey.EnvPrevious + " is set (" + prev.Describe() +
				"), so everything the old key sealed is still openable with it",
			Remediation: "Once every hub member runs on the new key, escrow it and run `cloop hub key rotate " +
				"--retire-previous`; then remove " + rootkey.EnvPrevious + " from every member",
		})
	}
}

// systemdHost reports whether systemd is this host's init (sd_booted(3)).
var systemdHost = func() bool {
	fi, err := os.Stat("/run/systemd/system")
	return err == nil && fi.IsDir()
}

// checkKeyEscrow reports whether the key is escrowed, and whether the escrow
// on record still holds it (Task 20410).
//
// Every sealing key derives from CLOOP_SECRET_KEY, so losing .cloop/hub.env
// loses everything sealed, however often the keys were rotated — unless the
// key itself was escrowed. And an escrow of a key the hub no longer runs on is
// worse than none: it recovers nothing sealed now, while looking like a
// recovery plan. The hub records only the escrow's id and the key's
// fingerprint, which is all this compares.
func checkKeyEscrow(dir string, roots rootkey.Roots, add addFn) {
	key := roots.Current.Value
	dbPath := state.DBPath(dir)
	if _, err := os.Stat(dbPath); err != nil {
		return
	}
	db, err := statedb.Open(dbPath)
	if err != nil {
		return // checkStorage reports a database that will not open
	}
	defer func() { _ = db.Close() }()

	const exportHint = "`cloop hub key escrow export --output <file off this host>`, and keep the passphrase " +
		"apart from the file"
	rec, ok, err := keyescrow.LoadRecord(db)
	switch {
	case err != nil:
		add(Finding{
			Check: "secret_key.escrow", Title: "Sealing key escrow", Severity: SeverityWarn,
			Message:     "the hub's escrow record could not be read: " + err.Error(),
			Remediation: "Escrow the key again: " + exportHint,
		})
		return
	case !ok:
		add(Finding{
			Check: "secret_key.escrow", Title: "Sealing key escrow", Severity: SeverityWarn,
			Message: "no escrow of " + secretbroker.EnvPassphraseKey + " is recorded: lose the key and every " +
				"sealed secret, session and hub CA key is lost with it — no rotation can help, since every key derives from it",
			Remediation: exportHint + ". After restoring a backup taken before an existing escrow, record it again: " +
				"`cloop hub key escrow verify <file> --record`",
		})
		return
	}
	fingerprint, err := keyescrow.Fingerprint([]byte(key))
	if err != nil {
		add(Finding{
			Check: "secret_key.escrow", Title: "Sealing key escrow", Severity: SeverityWarn,
			Message:     "the key's fingerprint could not be computed to compare with the escrow on record: " + err.Error(),
			Remediation: "Run `cloop hub key escrow verify <file>` against the escrow file",
		})
		return
	}
	who := rec.CreatedAt
	if rec.CreatedBy != "" {
		who += " by " + rec.CreatedBy
	}
	if prev := roots.Previous; fingerprint != rec.KeyFingerprint && prev.Set() {
		// Mid-way through a change of root the escrow on record may well hold
		// the old key, which still opens everything until the retire step —
		// and that step refuses until the new one is escrowed.
		if pfp, perr := keyescrow.Fingerprint([]byte(prev.Value)); perr == nil && pfp == rec.KeyFingerprint {
			add(Finding{
				Check: "secret_key.escrow", Title: "Sealing key escrow", Severity: SeverityWarn,
				Message: fmt.Sprintf("the escrow on record (%s, made %s) holds the previous root key, %s; the "+
					"new one, %s, is not escrowed, and `cloop hub key rotate --retire-previous` refuses until it is",
					rec.ID, who, rec.KeyFingerprint, fingerprint),
				Remediation: "Escrow the new key: " + exportHint,
				Details:     map[string]any{"escrow_id": rec.ID, "escrowed_key": rec.KeyFingerprint, "active_key": fingerprint},
			})
			return
		}
	}
	if fingerprint != rec.KeyFingerprint {
		add(Finding{
			Check: "secret_key.escrow", Title: "Sealing key escrow", Severity: SeverityFail,
			Message: fmt.Sprintf("the escrow on record (%s, made %s) holds key %s, and the %s in use is %s: "+
				"recovering from it would restore a key that opens nothing sealed now",
				rec.ID, who, rec.KeyFingerprint, secretbroker.EnvPassphraseKey, fingerprint),
			Remediation: "Escrow the key in use: " + exportHint,
			Details:     map[string]any{"escrow_id": rec.ID, "escrowed_key": rec.KeyFingerprint, "active_key": fingerprint},
		})
		return
	}
	add(Finding{
		Check: "secret_key.escrow", Title: "Sealing key escrow", Severity: SeverityPass,
		Message: fmt.Sprintf("escrowed as %s (%s), made %s; it holds the key in use, %s — rehearse recovery "+
			"with `cloop hub key escrow verify <file>`", rec.ID, rec.KDF, who, fingerprint),
		Details: map[string]any{"escrow_id": rec.ID, "key_fingerprint": fingerprint},
	})
}

// checkKeyOpensKeyring asks the hub's own keyring whether the key opens this
// control plane's sealing keys: secretbroker.OpenKeyring, which the broker
// runs before every lease, opened read-only (WithoutKeyCreation) so that a
// diagnostic never mints or promotes a key. Strength says nothing about this:
// a perfectly random key that is not the one the secrets were sealed under
// passed here, on a hub whose broker refused every lease (Task 20387).
func checkKeyOpensKeyring(dir string, roots rootkey.Roots, add addFn) {
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
	kr, err := secretbroker.OpenKeyring(store, secretbroker.WithoutKeyCreation(),
		secretbroker.WithKeyringRoots(roots.Current.Value, roots.Previous.Value))
	var underivable []string
	if err == nil {
		underivable = kr.Underivable()
	}
	switch {
	case errors.Is(err, secretbroker.ErrKeyUnavailable) || len(underivable) > 0:
		// The rule the hub starts by (Task 20425): every live key-encryption
		// key derives from a configured root, or the hub does not start.
		msg := "live sealing key(s) " + strings.Join(underivable, ", ") + " derive from no configured root key, " +
			"so the hub refuses to start, the broker refuses every lease and no sealed secret can be read"
		if err != nil {
			msg = "the key does not open this hub's sealing keys, so the broker refuses every lease " +
				"and no sealed secret can be read: " + err.Error()
		}
		add(Finding{
			Check: "secret_key.matches", Title: "Sealing key matches", Severity: SeverityFail,
			Message: msg,
			Remediation: "Give the hub the key these secrets were sealed under — and, mid-way through a change of " +
				"root, the old one as " + rootkey.EnvPrevious + "; `cloop hub key list` names the keys it cannot open",
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
	case roots.Previous.Set() && len(kr.PreviousRootKeys()) == 0:
		add(Finding{
			Check: "secret_key.matches", Title: "Sealing key matches", Severity: SeverityPass,
			Message: "the key derives this hub's primary sealing key, " + kr.PrimaryID() + ", and every other " +
				"live one; " + rootkey.EnvPrevious + " derives none and can be removed",
		})
	default:
		msg := "the key derives this hub's primary sealing key, " + kr.PrimaryID()
		if !kr.PrimaryFromCurrent() && roots.Previous.Set() {
			msg = "every live sealing key derives from the configured roots; the primary, " + kr.PrimaryID() +
				", derives from " + rootkey.EnvPrevious + " until `cloop hub key rotate --retire-previous`"
		}
		add(Finding{
			Check: "secret_key.matches", Title: "Sealing key matches", Severity: SeverityPass,
			Message: msg,
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
