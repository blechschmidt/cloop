package statedb

// Storage-level tests for the sealing-key registry (Task 20181).
//
// These sit below pkg/secretbroker: they check the properties the SQL is
// solely responsible for, where a Go-side check would be a race or a lie.

import (
	"bytes"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

func openKeysDB(t *testing.T) *DB {
	t.Helper()
	return openFresh(t)
}

func putTestKEK(t *testing.T, db *DB, id, state string) {
	t.Helper()
	if err := db.PutKEK(KEKRow{
		ID: id, Salt: "aa", State: state, CheckValue: []byte("cv"),
		CreatedAt: "2026-01-01T00:00:00Z", CreatedBy: "test",
	}); err != nil {
		t.Fatalf("put kek %s: %v", id, err)
	}
}

// TestOnlyOnePrimaryKEKCanExist. The invariant is enforced by a partial unique
// index rather than by application code, because two processes promoting
// concurrently is exactly the case application code cannot cover: both would
// read "there is one primary", both would demote it, and both would promote
// their own.
func TestOnlyOnePrimaryKEKCanExist(t *testing.T) {
	db := openKeysDB(t)
	putTestKEK(t, db, "kek_a", "active")
	putTestKEK(t, db, "kek_b", "active")

	if err := db.PromoteKEK("kek_a", time.Now()); err != nil {
		t.Fatalf("promote a: %v", err)
	}
	if err := db.PromoteKEK("kek_b", time.Now()); err != nil {
		t.Fatalf("promote b: %v", err)
	}

	primaries := 0
	keks, err := db.ListKEKs()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	for _, k := range keks {
		if k.State == "primary" {
			primaries++
		}
	}
	if primaries != 1 {
		t.Fatalf("%d primaries after two promotions, want 1", primaries)
	}
	row, ok, err := db.PrimaryKEK()
	if err != nil || !ok {
		t.Fatalf("PrimaryKEK: %v ok=%v", err, ok)
	}
	if row.ID != "kek_b" {
		t.Errorf("primary = %s, want kek_b", row.ID)
	}
}

// TestRetirementIsTerminal. A crypto-shred that an ordinary upsert can undo is
// not a shred — it is a flag, and the whole point of blanking the salt is that
// the guarantee should survive code that does not know about it.
func TestRetirementIsTerminal(t *testing.T) {
	db := openKeysDB(t)
	putTestKEK(t, db, "kek_doomed", "active")

	if err := db.RetireKEK("kek_doomed", time.Now()); err != nil {
		t.Fatalf("retire: %v", err)
	}

	// The obvious resurrection: write the record again with a live salt.
	if err := db.PutKEK(KEKRow{
		ID: "kek_doomed", Salt: "bb", State: "active", CheckValue: []byte("cv"),
	}); err != nil {
		t.Fatalf("put: %v", err)
	}

	keks, _ := db.ListKEKs()
	for _, k := range keks {
		if k.ID != "kek_doomed" {
			continue
		}
		if k.Salt != "" {
			t.Errorf("a retired key's salt was restored by an upsert: %q", k.Salt)
		}
		if k.State != "retired" {
			t.Errorf("a retired key's state was restored to %q", k.State)
		}
	}
	// And it cannot be promoted back into service.
	if err := db.PromoteKEK("kek_doomed", time.Now()); !errors.Is(err, ErrKEKNotFound) {
		t.Errorf("promoting a retired key: err = %v, want ErrKEKNotFound", err)
	}
}

// TestRetirementRefusesWhileEitherPopulationReferencesTheKey exercises both
// arms of the reference check, including the sessions arm's "only rows that
// actually hold sealed material count" filter — without it, a logged-out
// session that never had a refresh token would block retirement forever.
func TestRetirementRefusesWhileEitherPopulationReferencesTheKey(t *testing.T) {
	db := openKeysDB(t)
	putTestKEK(t, db, "kek_held", "active")
	putTestKEK(t, db, "kek_primary", "active")
	if err := db.PromoteKEK("kek_primary", time.Now()); err != nil {
		t.Fatalf("promote: %v", err)
	}

	if err := db.PutBrokerSecret(BrokerSecretRow{
		ID: "sec_1", Kind: "env", Name: "held", Payload: []byte("ct"),
		KeyID: "kek_held", WrappedDEK: []byte("wrapped"),
	}); err != nil {
		t.Fatalf("put secret: %v", err)
	}
	if err := db.RetireKEK("kek_held", time.Now()); !errors.Is(err, ErrKEKInUse) {
		t.Fatalf("with a secret referencing it: err = %v, want ErrKEKInUse", err)
	}

	if err := db.DeleteBrokerSecret("sec_1"); err != nil {
		t.Fatalf("delete secret: %v", err)
	}
	if err := db.PutSession(SessionRow{
		ID: "sess_1", Subject: "u", IssuedAt: time.Now(), LastSeen: time.Now(),
		RefreshSealed: []byte("ct"), RefreshKeyID: "kek_held",
		RefreshWrappedDEK: []byte("wrapped"),
	}); err != nil {
		t.Fatalf("put session: %v", err)
	}
	if err := db.RetireKEK("kek_held", time.Now()); !errors.Is(err, ErrKEKInUse) {
		t.Fatalf("with a session referencing it: err = %v, want ErrKEKInUse", err)
	}

	// Clearing the token also clears the key id, so the row stops blocking.
	if err := db.UpdateSessionRefresh("sess_1", SessionRefreshUpdate{CheckedAt: time.Now()}); err != nil {
		t.Fatalf("clear refresh: %v", err)
	}
	if err := db.RetireKEK("kek_held", time.Now()); err != nil {
		t.Fatalf("retire after clearing: %v", err)
	}
	if err := db.RetireKEK("kek_primary", time.Now()); !errors.Is(err, ErrKEKInUse) {
		t.Errorf("retiring the primary: err = %v, want ErrKEKInUse", err)
	}
}

// TestSealedCompareAndSwapComparesBytes. SQLite's `payload = ?` on a BLOB is
// the entire concurrency guarantee of rotation, so it is checked directly
// rather than inferred from the layer above — including with embedded NULs and
// high bytes, which is what ciphertext looks like.
func TestSealedCompareAndSwapComparesBytes(t *testing.T) {
	db := openKeysDB(t)
	original := []byte{0x00, 0xff, 'a', 0x00, 0x7f, 0xc3, 0xa9}
	if err := db.PutBrokerSecret(BrokerSecretRow{
		ID: "sec_cas", Kind: "env", Name: "cas", Payload: original,
		KeyID: "kek_old", WrappedDEK: []byte("w1"),
	}); err != nil {
		t.Fatalf("put: %v", err)
	}

	next := SealedRow{KeyID: "kek_new", WrappedDEK: []byte("w2"), Ciphertext: original}

	// One byte off must not match.
	wrong := append([]byte(nil), original...)
	wrong[3] ^= 0x01
	ok, err := db.ReplaceBrokerSecretSealed("sec_cas",
		SealedRow{KeyID: "kek_old", Ciphertext: wrong}, next)
	if err != nil {
		t.Fatalf("cas (wrong bytes): %v", err)
	}
	if ok {
		t.Fatal("the swap matched a different ciphertext")
	}

	// The right key with the wrong ciphertext must not match either — this is
	// the lost-update case, and matching on key id alone is the bug.
	ok, _ = db.ReplaceBrokerSecretSealed("sec_cas",
		SealedRow{KeyID: "kek_old", Ciphertext: []byte("totally different")}, next)
	if ok {
		t.Fatal("the swap matched on key id alone")
	}

	// An empty expectation binds as NULL and would silently match nothing;
	// that has to be an error rather than a "skipped" row.
	if _, err := db.ReplaceBrokerSecretSealed("sec_cas",
		SealedRow{KeyID: "kek_old"}, next); err == nil {
		t.Error("an empty compare-and-swap expectation was accepted")
	}

	// The exact bytes swap.
	ok, err = db.ReplaceBrokerSecretSealed("sec_cas",
		SealedRow{KeyID: "kek_old", Ciphertext: original}, next)
	if err != nil {
		t.Fatalf("cas: %v", err)
	}
	if !ok {
		t.Fatal("the swap did not match the exact ciphertext it was given")
	}
	row, err := db.GetBrokerSecret("sec_cas")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if row.KeyID != "kek_new" || string(row.WrappedDEK) != "w2" {
		t.Errorf("row after swap = %+v", row)
	}
}

// TestRetirementLeavesNothingOfTheKeyInTheFile. Blanking a column leaves the
// bytes it held in the page's free space unless secure_delete zeroes them, and
// a copy of the file would still give up a retired key's salt — or the KMS
// ciphertext the KMS would still unwrap (Task 20433). After retiring, and the
// last handle closing (which checkpoints and removes the log), neither is
// anywhere in the file; the KMS wrapping of a live key, which retirement does
// not touch, still is — the positive control.
func TestRetirementLeavesNothingOfTheKeyInTheFile(t *testing.T) {
	path := freshPath(t)
	db, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	const (
		retiredSalt = "5a17c0ffee5a17c0ffee5a17c0ffee5a17c0ffee5a17c0ffee5a17c0ffee5a17"
		liveSalt    = "11ve11ve11ve11ve"
	)
	retiredCT := []byte("vault:v1:retired-kms-ciphertext-that-must-not-survive")
	liveCT := []byte("vault:v1:live-kms-ciphertext-that-stays")
	for _, row := range []KEKRow{
		{ID: "kek_retired", Salt: retiredSalt, State: "active", CheckValue: []byte("check-of-the-retired-key"),
			CreatedAt: "2026-01-01T00:00:00Z", Wrap: "kms", KMSKeyID: "transit/cloop:v1", KMSCiphertext: retiredCT},
		{ID: "kek_live", Salt: liveSalt, State: "primary", CheckValue: []byte("check-of-the-live-key"),
			CreatedAt: "2026-01-02T00:00:00Z", Wrap: "kms", KMSKeyID: "transit/cloop:v1", KMSCiphertext: liveCT},
	} {
		if err := db.PutKEK(row); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.RetireKEK("kek_retired", time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for what, b := range map[string][]byte{"the retired salt": []byte(retiredSalt),
		"the retired KMS ciphertext": retiredCT, "the retired check value": []byte("check-of-the-retired-key")} {
		if bytes.Contains(data, b) {
			t.Errorf("%s is still in the file after retirement", what)
		}
	}
	if !bytes.Contains(data, liveCT) {
		t.Error("the live key's KMS ciphertext is not in the file: the scan is not reading what it should")
	}
}

// Retirement reaches the images of the row its key's earlier writes freed,
// too: they ran with secure_delete, so none of them was left in a page's free
// space with the salt, the check value or a KMS ciphertext in it — of which a
// rewrap after a rotation of the KMS key leaves one the KMS would still unwrap
// under the old key version. The sequences are a key's ordinary life: minted
// primary, attributed, demoted when another is promoted, rewrapped, retired
// (Task 20433).
func TestNoEarlierImageOfARetiredKeyStaysInTheFile(t *testing.T) {
	scan := func(t *testing.T, path string, gone map[string][]byte) {
		t.Helper()
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for what, b := range gone {
			if bytes.Contains(data, b) {
				t.Errorf("%s is still in the file after retirement", what)
			}
		}
	}
	must := func(t *testing.T, err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}

	t.Run("held by a KMS", func(t *testing.T) {
		path := freshPath(t)
		db, err := Open(path)
		must(t, err)
		salt := "dec0ydec0ydec0ydec0ydec0ydec0ydec0ydec0ydec0ydec0ydec0ydec0yzz"
		check := []byte("check-value-of-the-kms-held-key")
		first := []byte("vault:v1:the-first-ciphertext-under-kms-key-version-1")
		second := []byte("vault:v2:the-second-ciphertext-under-kms-key-version-22xx")
		must(t, db.PutKEK(KEKRow{ID: "kek_a", Salt: salt, State: "primary", CheckValue: check,
			CreatedAt: "2026-01-01T00:00:00Z", Root: "vault", Wrap: "kms", KMSKeyID: "transit/cloop:v1",
			KMSCiphertext: first}))
		must(t, db.PutKEK(KEKRow{ID: "kek_b", Salt: "bbbb", State: "active", CheckValue: []byte("cv-b"),
			CreatedAt: "2026-01-02T00:00:00Z"}))
		must(t, db.PromoteKEK("kek_b", time.Now()))
		if ok, err := db.RewrapKEK("kek_a", first, KEKRow{KMSKeyID: "transit/cloop:v2", KMSCiphertext: second}); err != nil || !ok {
			t.Fatalf("rewrap: %v, %v", ok, err)
		}
		must(t, db.RetireKEK("kek_a", time.Now()))
		must(t, db.Close())
		scan(t, path, map[string][]byte{"the salt": []byte(salt), "the check value": check,
			"the ciphertext under the old KMS key version": first, "the current ciphertext": second})
	})

	t.Run("derived from a passphrase", func(t *testing.T) {
		path := freshPath(t)
		db, err := Open(path)
		must(t, err)
		salt := "5a175a175a175a175a175a175a175a175a175a175a175a175a175a175a175a17"
		check := []byte("check-value-of-the-derived-key")
		// Minted by a build before Task 20425, so unattributed; demoted; then
		// attributed by the first newer process to derive it.
		must(t, db.PutKEK(KEKRow{ID: "kek_p", Salt: salt, State: "primary", CheckValue: check,
			CreatedAt: "2026-01-01T00:00:00Z"}))
		must(t, db.PutKEK(KEKRow{ID: "kek_q", Salt: "qqqq", State: "active", CheckValue: []byte("cv-q"),
			CreatedAt: "2026-01-02T00:00:00Z"}))
		must(t, db.PromoteKEK("kek_q", time.Now()))
		if ok, err := db.SetKEKRoot("kek_p", "fp:0123456789ab"); err != nil || !ok {
			t.Fatalf("attribute: %v, %v", ok, err)
		}
		must(t, db.RetireKEK("kek_p", time.Now()))
		must(t, db.Close())
		scan(t, path, map[string][]byte{"the salt": []byte(salt), "the check value": check})
	})
}

// Every write to the key registry runs on a secure-delete connection: a
// statement given to secureExec, or one on the transaction shreddingTx began.
// A writer that goes to the pool, or to a transaction of its own, frees images
// of a key's row unzeroed, and the file keeps them past the key's retirement
// (Task 20433).
func TestEveryKeyRegistryWriteIsSecureDelete(t *testing.T) {
	fset := token.NewFileSet()
	names, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	var files []*ast.File
	for _, name := range names {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, f)
	}
	write := regexp.MustCompile(`(?is)\b(update|insert\s+(or\s+\w+\s+)?into|delete\s+from|replace\s+into)\s+broker_keks\b`)
	callsTo := func(fn *ast.FuncDecl, name string) bool {
		found := false
		ast.Inspect(fn, func(n ast.Node) bool {
			if c, ok := n.(*ast.CallExpr); ok {
				switch f := c.Fun.(type) {
				case *ast.SelectorExpr:
					found = found || f.Sel.Name == name
				case *ast.Ident:
					found = found || f.Name == name
				}
			}
			return !found
		})
		return found
	}
	writes := 0
	for _, file := range files {
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				c, ok := n.(*ast.CallExpr)
				if !ok || len(c.Args) == 0 {
					return true
				}
				lit, ok := c.Args[0].(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING || !write.MatchString(lit.Value) {
					return true
				}
				writes++
				at := fset.Position(lit.Pos())
				sel, _ := c.Fun.(*ast.SelectorExpr)
				switch {
				case sel != nil && sel.Sel.Name == "secureExec":
				case fn.Name.Name == "takeWriteLock":
					// Takes the caller's transaction: checked at its call sites.
				case sel != nil && isIdent(sel.X, "tx") && callsTo(fn, "shreddingTx"):
				default:
					t.Errorf("%s: %s writes broker_keks off a secure-delete connection", at, fn.Name.Name)
				}
				return true
			})
			if fn.Name.Name != "takeWriteLock" && callsTo(fn, "takeWriteLock") && !callsTo(fn, "shreddingTx") {
				t.Errorf("%s takes the registry's write lock on a transaction shreddingTx did not begin", fn.Name.Name)
			}
		}
	}
	if writes < 8 {
		t.Fatalf("found %d writes to broker_keks; the scan is not reading what it should", writes)
	}
}

func isIdent(e ast.Expr, name string) bool {
	id, ok := e.(*ast.Ident)
	return ok && id.Name == name
}

// A build from before migration 0079 retires a key by blanking the columns it
// knows (the statement below is its RetireKEK's), so a KMS-held key it retires
// keeps the KMS's ciphertext of it — what the KMS would still unwrap.
// ScrubRetiredKEKs destroys that, in the row and in the file, and leaves a
// live key's ciphertext alone (Task 20433).
func TestScrubDestroysWhatAnOlderBuildsRetirementLeft(t *testing.T) {
	path := freshPath(t)
	db, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	leftCT := []byte("vault:v1:kms-ciphertext-an-older-build-retired-and-left")
	liveCT := []byte("vault:v1:live-kms-ciphertext-that-stays")
	for _, row := range []KEKRow{
		{ID: "kek_old", Salt: "dec0ydec0ydec0ydec0ydec0ydec0ydec0ydec0y", State: "active",
			CheckValue: []byte("check-of-the-old-key"), CreatedAt: "2026-01-01T00:00:00Z", Wrap: "kms",
			KMSKeyID: "transit/cloop:v1", KMSCiphertext: leftCT, KMSAnnotations: `{"a.example.com":"dg=="}`},
		{ID: "kek_live", Salt: "11ve11ve11ve11ve", State: "primary", CheckValue: []byte("check-of-the-live-key"),
			CreatedAt: "2026-01-02T00:00:00Z", Wrap: "kms", KMSKeyID: "transit/cloop:v1", KMSCiphertext: liveCT},
	} {
		if err := db.PutKEK(row); err != nil {
			t.Fatal(err)
		}
	}
	if n, err := db.ScrubRetiredKEKs(); err != nil || n != 0 {
		t.Fatalf("with nothing retired the sweep scrubbed %d: %v", n, err)
	}

	if _, err := db.conn.Exec(`UPDATE broker_keks SET state='retired', salt='', check_value=NULL, retired_at=?
		WHERE id = ?`, "2026-10-16T00:00:00Z", "kek_old"); err != nil {
		t.Fatal(err)
	}
	if n, err := db.ScrubRetiredKEKs(); err != nil || n != 1 {
		t.Fatalf("the sweep scrubbed %d key(s), want 1: %v", n, err)
	}
	rows, err := db.ListKEKs()
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		switch {
		case r.ID == "kek_old" && (len(r.KMSCiphertext) != 0 || r.KMSAnnotations != ""):
			t.Errorf("the retired key still carries ciphertext %q and annotations %q", r.KMSCiphertext, r.KMSAnnotations)
		case r.ID == "kek_live" && !bytes.Equal(r.KMSCiphertext, liveCT):
			t.Errorf("the sweep touched the live key: %q", r.KMSCiphertext)
		}
	}
	if n, err := db.ScrubRetiredKEKs(); err != nil || n != 0 {
		t.Fatalf("a second sweep scrubbed %d: %v", n, err)
	}

	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, leftCT) {
		t.Error("the KMS ciphertext the older build left is still in the file after the sweep")
	}
	if !bytes.Contains(data, liveCT) {
		t.Error("the live key's KMS ciphertext is not in the file: the scan is not reading what it should")
	}
}
