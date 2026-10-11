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

import "sort"

// LegacySaltMetaKey is where the pre-envelope cipher's salt lives in the
// broker's metadata table, for callers reading a database without a Store.
const LegacySaltMetaKey = metaKeySalt

// KeyCheck is one sealing key judged against a passphrase.
type KeyCheck struct {
	ID    string `json:"id"`
	State string `json:"state"`
	// Opens: the passphrase derives the key and it passes its check value.
	Opens bool `json:"opens"`
	// Retired: the key's salt was destroyed, so nothing derives it — whatever
	// is still sealed under it was lost before anybody asked.
	Retired bool `json:"retired,omitempty"`
}

// CheckKeys reports, for every record, whether passphrase derives it: the
// check-value test OpenKeyring runs before it will serve. Every live record is
// derived — about 60 ms each — because a registry with one corrupt row is
// exactly the case where "the first one opened" says nothing about the rest.
// Results are ordered by ID. An empty passphrase opens nothing.
func CheckKeys(passphrase string, records []KEKRecord) []KeyCheck {
	out := make([]KeyCheck, 0, len(records))
	for _, rec := range records {
		c := KeyCheck{ID: rec.ID, State: rec.State, Retired: rec.Retired()}
		if !c.Retired && passphrase != "" {
			if key, err := deriveKEK(passphrase, rec); err == nil {
				zero(key)
				c.Opens = true
			}
		}
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// LegacyKeyOpens reports whether passphrase opens sample, a ciphertext the
// pre-envelope construction sealed under the store-wide salt saltHex.
//
// That construction has no check value, so the only way to answer is to open
// something it sealed. The plaintext is wiped before this returns and never
// leaves it; the answer is all a caller gets.
func LegacyKeyOpens(passphrase, saltHex string, sample []byte) bool {
	if passphrase == "" || len(sample) == 0 {
		return false
	}
	salt, err := decodeHex(saltHex)
	if err != nil || len(salt) != saltSize {
		return false
	}
	c := &Cipher{key: deriveKey(passphrase, salt)}
	defer zero(c.key)
	plain, err := c.Unseal(sample)
	zero(plain)
	return err == nil
}
