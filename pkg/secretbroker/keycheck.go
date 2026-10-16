package secretbroker

// Judging sealing keys against a passphrase without a store (Task 20410).
//
// OpenKeyring answers "does this passphrase open this registry?" for the hub
// that is about to serve from it, and refuses to start when the answer is no
// (keyring.go). Restoring a backup used to find that out the same way — after
// the backup had been swapped in, when the hub would not start. CheckKeys asks
// the identical question of key records read from somewhere that is not a
// live store, so `cloop db restore` can ask it of the backup before swapping
// anything, and `cloop hub key escrow` can ask it of a key recovered from
// escrow before installing it.

import (
	"context"
	"errors"
	"sort"
	"strings"
)

// LegacySaltMetaKey is where the pre-envelope cipher's salt lives in the
// broker's metadata table, for callers reading a database without a Store.
const LegacySaltMetaKey = metaKeySalt

// KeyCheck is one sealing key judged against a set of roots.
type KeyCheck struct {
	ID    string `json:"id"`
	State string `json:"state"`
	// Opens: one of the roots derives the key, or unwraps it, and it passes
	// its check value.
	Opens bool `json:"opens"`
	// Root is the index in the roots checked of the one that opens it — 0
	// for the first, the current root — or -1 when none does.
	Root int `json:"root"`
	// Retired: the key's salt was destroyed, so nothing derives it — whatever
	// is still sealed under it was lost before anybody asked.
	Retired bool `json:"retired,omitempty"`
	// KMS names the KMS a key is held by (Task 20433); "" for a key derived
	// from a passphrase. Such a key opens only through that KMS: no escrowed
	// passphrase recovers it, and a restore of it needs access to the KMS.
	KMS string `json:"kms,omitempty"`
	// Why says why the key does not open, when it does not: no root of its
	// kind was checked, the KMS cannot be reached, or it refused.
	Why string `json:"why,omitempty"`
	// KMSUnreachable: the KMS holding the key did not answer — the key may be
	// perfectly good.
	KMSUnreachable bool `json:"kms_unreachable,omitempty"`
}

// CheckKeys reports, for every record, whether one of roots opens it: the
// check-value test OpenKeyring runs before it will serve, asked of every root a
// hub could hold — the current one and, during a change of root, the previous
// (Task 20425). A key derived from a passphrase is tried against the
// passphrase roots, about 60 ms per root tried; a key held by a KMS against
// the KMS roots, one call each (Task 20433). Every live record is opened,
// because a registry with one corrupt row is exactly the case where "the first
// one opened" says nothing about the rest. Results are ordered by ID. Zero
// roots are skipped; no roots open nothing.
func CheckKeys(roots []Root, records []KEKRecord) []KeyCheck {
	return CheckKeysContext(context.Background(), roots, records)
}

// CheckKeysContext is CheckKeys with the KMS calls bounded by ctx.
func CheckKeysContext(ctx context.Context, roots []Root, records []KEKRecord) []KeyCheck {
	out := make([]KeyCheck, 0, len(records))
	for _, rec := range records {
		c := KeyCheck{ID: rec.ID, State: rec.State, Retired: rec.Retired(), Root: -1}
		if rec.Wrap == WrapKMS {
			c.KMS = orUnnamed(rec.Root)
		}
		if !c.Retired {
			tried := false
			var lastErr error
			for i, root := range roots {
				if root.IsZero() || !root.opens(rec) {
					continue
				}
				tried = true
				key, err := cachedOpenKEK(ctx, root, rec)
				if err == nil {
					zero(key)
					c.Opens, c.Root = true, i
					break
				}
				lastErr = err
			}
			switch {
			case c.Opens:
			case !tried && rec.Wrap == WrapKMS:
				c.Why = "held by the KMS " + c.KMS + ", and no KMS was checked"
			case !tried:
				c.Why = "derived from a passphrase, and no passphrase was checked"
			case lastErr != nil:
				c.Why = strings.TrimPrefix(reasonForRec(rec, lastErr), " ")
				c.KMSUnreachable = errors.Is(lastErr, ErrKMSUnavailable)
			}
		}
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// LegacyKeyOpens reports whether one of roots opens sample, a ciphertext the
// pre-envelope construction sealed under the store-wide salt saltHex.
//
// That construction has no check value, so the only way to answer is to open
// something it sealed. The plaintext is wiped before this returns and never
// leaves it; the answer is all a caller gets.
func LegacyKeyOpens(roots []Root, saltHex string, sample []byte) bool {
	if len(sample) == 0 {
		return false
	}
	salt, err := decodeHex(saltHex)
	if err != nil || len(salt) != saltSize {
		return false
	}
	for _, root := range roots {
		if root.Passphrase == "" {
			continue
		}
		c := &Cipher{key: deriveKey(root.Passphrase, salt)}
		plain, err := c.Unseal(sample)
		zero(plain)
		zero(c.key)
		if err == nil {
			return true
		}
	}
	return false
}
