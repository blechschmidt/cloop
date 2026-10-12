package rootkey_test

import (
	"testing"

	"github.com/blechschmidt/cloop/pkg/auditcheckpoint"
	"github.com/blechschmidt/cloop/pkg/keyescrow"
	"github.com/blechschmidt/cloop/pkg/rootkey"
)

// One key, one name: the fingerprint a sealing key records for its root, a hub
// member advertises, an escrow carries and an audit checkpoint is stamped with
// are the same string, or `cloop hub key rotate --retire-previous` could never
// match an escrow to the root every member runs on.
func TestOneKeyHasOneName(t *testing.T) {
	const key = "Zq4pV9mW2xT7rL0yH3nB8kD5sF1gJ6cA-uE_oI4tR7w"
	fp, err := rootkey.Fingerprint(key)
	if err != nil || len(fp) != 16 {
		t.Fatalf("Fingerprint = %q, %v", fp, err)
	}
	cp, err := auditcheckpoint.DeriveKey(key)
	if err != nil {
		t.Fatal(err)
	}
	escrow, err := keyescrow.Fingerprint([]byte(key))
	if err != nil {
		t.Fatal(err)
	}
	if cp.Fingerprint() != fp || escrow != fp {
		t.Errorf("rootkey %s, audit checkpoint %s, escrow %s: one key, three names", fp, cp.Fingerprint(), escrow)
	}
	other, _ := rootkey.Fingerprint(key + "x")
	if other == fp {
		t.Error("two keys share a fingerprint")
	}
	if _, err := rootkey.Fingerprint(""); err == nil {
		t.Error("an empty key has a fingerprint")
	}
	cur, prev, err := rootkey.Roots{Current: rootkey.Root{Value: key}}.Fingerprints()
	if err != nil || cur != fp || prev != "" {
		t.Errorf("Roots.Fingerprints = %q, %q, %v", cur, prev, err)
	}
}
