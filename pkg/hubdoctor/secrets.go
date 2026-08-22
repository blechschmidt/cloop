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
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
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
	sealed := hasSealedMaterial(dir)

	if strings.TrimSpace(key) == "" {
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

	_ = cfg
}

// hasSealedMaterial reports whether this control plane has a project secret
// file sealed under the key.
//
// It reads the filesystem rather than the database deliberately, and it is
// deliberately conservative: a state.db exists on every hub, so treating its
// presence as evidence of sealed material would turn "no key configured yet"
// into a failure on every fresh deployment. The broker's own sealed rows live
// inside that database and are reported by checkStorage; what this answers is
// the narrower question that can be answered without opening it.
func hasSealedMaterial(dir string) bool {
	if dir == "" {
		return false
	}
	_, err := os.Stat(filepath.Join(dir, ".cloop", "secrets.enc"))
	return err == nil
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
