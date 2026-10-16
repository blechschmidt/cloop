package secretbroker

import "testing"

// CheckKeys gives the answer OpenKeyring would, from records alone: the
// question a restore has to ask of a backup before it swaps the backup in.
func TestCheckKeysAnswersWhatOpenKeyringWould(t *testing.T) {
	const pass = "check-keys-passphrase-0123456789abcdef"
	store := newMemKeyStore()
	kr, err := OpenKeyring(store, WithKeyringPassphrase(pass))
	if err != nil {
		t.Fatal(err)
	}
	first := kr.PrimaryID()
	if _, err := kr.AddKey("test"); err != nil {
		t.Fatal(err)
	}
	if err := kr.RetireKey(first); err != nil {
		t.Fatal(err)
	}
	if _, err := kr.AddKey("test"); err != nil {
		t.Fatal(err)
	}
	records, _ := store.ListKEKs()

	got := CheckKeys(passRoots(pass), records)
	if len(got) != 3 {
		t.Fatalf("%d verdicts for 3 records", len(got))
	}
	for i, c := range got {
		if i > 0 && got[i-1].ID >= c.ID {
			t.Errorf("not ordered by id: %v", got)
		}
		switch {
		case c.ID == first && (!c.Retired || c.Opens):
			t.Errorf("the retired key: %+v", c)
		case c.ID != first && (c.Retired || !c.Opens):
			t.Errorf("a live key the passphrase derives: %+v", c)
		}
	}

	for _, c := range CheckKeys(passRoots("another-passphrase-entirely-0123456789"), records) {
		if c.Opens {
			t.Errorf("another passphrase opens %s", c.ID)
		}
	}
	for _, c := range CheckKeys(passRoots(""), records) {
		if c.Opens {
			t.Errorf("no passphrase opens %s", c.ID)
		}
	}

	// A record whose check value was tampered with does not open, exactly as
	// OpenKeyring would not derive it.
	tampered := append([]KEKRecord(nil), records...)
	for i := range tampered {
		if !tampered[i].Retired() {
			tampered[i].CheckValue = append([]byte(nil), tampered[i].CheckValue...)
			tampered[i].CheckValue[len(tampered[i].CheckValue)-1] ^= 1
			break
		}
	}
	opened := 0
	for _, c := range CheckKeys(passRoots(pass), tampered) {
		if c.Opens {
			opened++
		}
	}
	if opened != 1 {
		t.Errorf("with one live key's check value tampered, %d of 2 open; want 1", opened)
	}
}

func TestLegacyKeyOpensASampleOnly(t *testing.T) {
	const pass = "legacy-passphrase-0123456789abcdefgh"
	salt := make([]byte, saltSize)
	for i := range salt {
		salt[i] = byte(i)
	}
	c, err := NewLegacyCipher(pass, salt)
	if err != nil {
		t.Fatal(err)
	}
	sample, err := c.Seal([]byte("a pre-envelope credential"))
	if err != nil {
		t.Fatal(err)
	}
	saltHex := encodeHex(salt)
	if !LegacyKeyOpens(passRoots(pass), saltHex, sample) {
		t.Fatal("the passphrase that sealed it does not open it")
	}
	for name, ok := range map[string]bool{
		"another passphrase": LegacyKeyOpens(passRoots("not-the-legacy-passphrase-012345"), saltHex, sample),
		"no passphrase":      LegacyKeyOpens(passRoots(""), saltHex, sample),
		"a corrupt salt":     LegacyKeyOpens(passRoots(pass), "zz", sample),
		"no sample":          LegacyKeyOpens(passRoots(pass), saltHex, nil),
	} {
		if ok {
			t.Errorf("%s opens it", name)
		}
	}
}

// passRoots is positional: an empty passphrase is a zero Root, skipped, so
// KeyCheck.Root indexes the slice the test wrote.
func passRoots(ps ...string) []Root {
	out := make([]Root, 0, len(ps))
	for _, p := range ps {
		out = append(out, PassphraseRoot(p))
	}
	return out
}
