package keyescrow

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/internal/statedbtest"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

const (
	testKey        = "Zq4pV9mW2xT7rL0yH3nB8kD5sF1gJ6cA-uE_oI4tR7w"
	testPassphrase = "correct horse battery staple escrow"
)

func wrap(t *testing.T) *File {
	t.Helper()
	f, err := Wrap([]byte(testKey), []byte(testPassphrase), WrapOptions{
		CreatedBy: "cli:test", Hub: "/srv/hub", Now: time.Date(2026, 10, 11, 9, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestWrapOpensWithItsPassphraseOnly(t *testing.T) {
	f := wrap(t)
	got, err := f.Open([]byte(testPassphrase))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != testKey {
		t.Fatalf("opened %q", got)
	}
	if fp, _ := Fingerprint([]byte(testKey)); f.KeyFingerprint != fp {
		t.Errorf("file names fingerprint %s, the key's is %s", f.KeyFingerprint, fp)
	}
	if f.KDF.Params != DefaultParams || f.KDF.Alg != KDFArgon2id || f.AEAD.Alg != AEADAESGCM {
		t.Errorf("kdf %+v aead %+v", f.KDF, f.AEAD)
	}
	if _, err := f.Open([]byte(testPassphrase + "!")); !errors.Is(err, ErrOpen) {
		t.Fatalf("a wrong passphrase: %v", err)
	}
}

// The plaintext key must appear nowhere in what is written to disk.
func TestTheFileHoldsNoPlaintext(t *testing.T) {
	f := wrap(t)
	data, err := f.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte(testKey)) || bytes.Contains(data, []byte(testPassphrase)) {
		t.Fatal("the escrow file holds the key or the passphrase in the clear")
	}
}

// Every header field is bound into the AEAD: editing any of them — a cheaper
// KDF, another fingerprint, a different id — makes the file refuse to open
// rather than open to the same key under a description that is no longer true.
func TestEveryHeaderFieldIsAuthenticated(t *testing.T) {
	edits := map[string]func(*File){
		"escrow_id":       func(f *File) { f.ID = "esc_0000000000000000" },
		"created_at":      func(f *File) { f.CreatedAt = "2020-01-01T00:00:00Z" },
		"created_by":      func(f *File) { f.CreatedBy = "cli:mallory" },
		"hub":             func(f *File) { f.Hub = "/elsewhere" },
		"key_fingerprint": func(f *File) { f.KeyFingerprint = "0123456789abcdef" },
		"kdf.time":        func(f *File) { f.KDF.Time = 2 },
		"kdf.memory_kib":  func(f *File) { f.KDF.MemoryKiB = 32 << 10 },
		"kdf.threads":     func(f *File) { f.KDF.Threads = 2 },
		"kdf.salt":        func(f *File) { f.KDF.Salt = b64.EncodeToString(bytes.Repeat([]byte{7}, saltSize)) },
		"aead.nonce":      func(f *File) { f.AEAD.Nonce = b64.EncodeToString(bytes.Repeat([]byte{7}, nonceSize)) },
		"ciphertext": func(f *File) {
			ct, _ := b64.DecodeString(f.Ciphertext)
			ct[0] ^= 1
			f.Ciphertext = b64.EncodeToString(ct)
		},
	}
	for name, edit := range edits {
		t.Run(name, func(t *testing.T) {
			f := wrap(t)
			edit(f)
			if _, err := f.Open([]byte(testPassphrase)); !errors.Is(err, ErrOpen) {
				t.Fatalf("an edited %s: %v", name, err)
			}
		})
	}
}

// The KDF and cipher fields fail above because the derived key or the nonce
// changes; that would happen even if they were not authenticated. So the
// binding itself is asserted: every header field is in the associated data,
// and no two fields can trade bytes.
func TestEveryHeaderFieldIsInTheAssociatedData(t *testing.T) {
	base := wrap(t)
	edits := map[string]func(*File){
		"kind":            func(f *File) { f.Kind += "x" },
		"v":               func(f *File) { f.Version++ },
		"escrow_id":       func(f *File) { f.ID += "x" },
		"created_at":      func(f *File) { f.CreatedAt += "x" },
		"created_by":      func(f *File) { f.CreatedBy += "x" },
		"hub":             func(f *File) { f.Hub += "x" },
		"key_fingerprint": func(f *File) { f.KeyFingerprint += "x" },
		"kdf.alg":         func(f *File) { f.KDF.Alg += "x" },
		"kdf.time":        func(f *File) { f.KDF.Time++ },
		"kdf.memory_kib":  func(f *File) { f.KDF.MemoryKiB++ },
		"kdf.threads":     func(f *File) { f.KDF.Threads++ },
		"kdf.salt":        func(f *File) { f.KDF.Salt += "x" },
		"aead.alg":        func(f *File) { f.AEAD.Alg += "x" },
		"aead.nonce":      func(f *File) { f.AEAD.Nonce += "x" },
	}
	for name, edit := range edits {
		f := *base
		edit(&f)
		if string(f.aad()) == string(base.aad()) {
			t.Errorf("%s is not in the associated data", name)
		}
	}
	// Moving bytes from one string field to its neighbour changes the AAD.
	a, b := *base, *base
	a.CreatedBy, a.Hub = "ab", "c"
	b.CreatedBy, b.Hub = "a", "bc"
	if string(a.aad()) == string(b.aad()) {
		t.Error("two fields can trade bytes without changing the associated data")
	}
	if !strings.Contains(string(base.aad()), base.KeyFingerprint) {
		t.Error("the fingerprint is not in the associated data")
	}
}

// A crafted file must not make whoever opens it allocate the machine, and a
// file with less work than anything this package writes is not one of ours.
func TestParametersAreBoundedOnRead(t *testing.T) {
	cases := map[string]Params{
		"memory over the ceiling":  {Time: 3, MemoryKiB: maxMemoryKiB + 1, Threads: 4},
		"time over the ceiling":    {Time: maxTime + 1, MemoryKiB: 64 << 10, Threads: 4},
		"no threads":               {Time: 3, MemoryKiB: 64 << 10, Threads: 0},
		"memory under the floor":   {Time: 4, MemoryKiB: 8 << 10, Threads: 1},
		"threads over the ceiling": {Time: 3, MemoryKiB: 64 << 10, Threads: maxThreads + 1},
		"too little work":          {Time: 1, MemoryKiB: 20 << 10, Threads: 1},
	}
	for name, p := range cases {
		t.Run(name, func(t *testing.T) {
			f := wrap(t)
			f.KDF.Params = p
			if _, err := f.Open([]byte(testPassphrase)); !errors.Is(err, ErrParams) {
				t.Fatalf("Open: %v", err)
			}
			data, _ := json.Marshal(f)
			if _, err := Parse(data); !errors.Is(err, ErrParams) {
				t.Fatalf("Parse: %v", err)
			}
			if _, err := Wrap([]byte(testKey), []byte(testPassphrase), WrapOptions{Params: p}); !errors.Is(err, ErrParams) {
				t.Fatalf("Wrap: %v", err)
			}
		})
	}
	// OWASP's other floor, 46 MiB over one pass, is enough work.
	if err := (Params{Time: 1, MemoryKiB: 46 << 10, Threads: 1}).validate(); err != nil {
		t.Errorf("46 MiB × 1: %v", err)
	}
}

func TestPassphrasePolicy(t *testing.T) {
	for _, weak := range []string{"", "short", "fourteen chars", "aaaaaaaaaaaaaaaaaaaa", "abababababababab", "abcdabcdabcdabcd"} {
		if err := CheckPassphrase([]byte(weak)); !errors.Is(err, ErrWeakPassphrase) {
			t.Errorf("%q accepted: %v", weak, err)
		}
	}
	if err := CheckPassphrase([]byte("fifteen chars!!")); err != nil {
		t.Errorf("15 characters refused: %v", err)
	}
	if err := CheckPassphrase([]byte("zwölf äpfel säuerlich")); err != nil {
		t.Errorf("non-ASCII refused: %v", err)
	}
	if err := CheckPassphrase([]byte{0xff, 0xfe, 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n'}); err == nil {
		t.Error("invalid UTF-8 accepted")
	}
	if _, err := Wrap([]byte(testKey), []byte(testKey), WrapOptions{}); !errors.Is(err, ErrWeakPassphrase) {
		t.Errorf("the key as its own passphrase: %v", err)
	}
	if _, err := Wrap(nil, []byte(testPassphrase), WrapOptions{}); !errors.Is(err, ErrNoKey) {
		t.Errorf("no key: %v", err)
	}
}

func TestParseRefusesWhatIsNotAnEscrow(t *testing.T) {
	f := wrap(t)
	good, err := f.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Parse(good); err != nil {
		t.Fatalf("a good file: %v", err)
	}
	for name, data := range map[string]string{
		"empty":          "",
		"not json":       "CLOOP_SECRET_KEY=abc",
		"another kind":   strings.Replace(string(good), Kind, "cloop.audit.checkpoint", 1),
		"newer version":  strings.Replace(string(good), `"v": 1`, `"v": 2`, 1),
		"unknown field":  strings.Replace(string(good), `"kind"`, `"extra": 1, "kind"`, 1),
		"another cipher": strings.Replace(string(good), AEADAESGCM, "chacha20", 1),
	} {
		if _, err := Parse([]byte(data)); err == nil {
			t.Errorf("%s: parsed", name)
		}
	}
	if _, err := Parse(bytes.Repeat([]byte(" "), maxFileSize+1)); err == nil {
		t.Error("an oversized file parsed")
	}
}

func TestWriteFileRefusesDotCloopAndOverwrites(t *testing.T) {
	f := wrap(t)
	dir := t.TempDir()
	if err := WriteFile(filepath.Join(dir, ".cloop", "escrow.json"), f, false); err == nil ||
		!strings.Contains(err.Error(), ".cloop") {
		t.Fatalf("inside .cloop/: %v", err)
	}
	// Through a symlinked directory too.
	if err := os.MkdirAll(filepath.Join(dir, "hub", ".cloop"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "hub", ".cloop"), filepath.Join(dir, "innocent")); err != nil {
		t.Fatal(err)
	}
	if err := WriteFile(filepath.Join(dir, "innocent", "escrow.json"), f, false); err == nil {
		t.Fatal("a symlink into .cloop/ was followed")
	}

	path := filepath.Join(dir, "escrow.json")
	if err := WriteFile(path, f, false); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("mode %s", fi.Mode().Perm())
	}
	if err := WriteFile(path, wrap(t), false); err == nil {
		t.Fatal("an existing escrow was replaced without --force")
	}
	back, err := ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if back.ID != f.ID {
		t.Fatalf("read back %s, wrote %s", back.ID, f.ID)
	}
	if err := WriteFile(path, wrap(t), true); err != nil {
		t.Fatalf("with replace: %v", err)
	}
	if left, _ := filepath.Glob(filepath.Join(dir, ".escrow.json.tmp-*")); len(left) != 0 {
		t.Errorf("temporaries left behind: %v", left)
	}
}

func TestRecordRoundTripsThroughTheHub(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	statedbtest.Template().Seed(t, path)
	db, err := statedb.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	if _, ok, err := LoadRecord(db); err != nil || ok {
		t.Fatalf("a fresh hub records an escrow: %v %v", ok, err)
	}
	f := wrap(t)
	want := f.Record("cli:test", time.Date(2026, 10, 11, 10, 0, 0, 0, time.UTC))
	if err := SaveRecord(db, want); err != nil {
		t.Fatal(err)
	}
	got, ok, err := LoadRecord(db)
	if err != nil || !ok || got != want {
		t.Fatalf("got %+v %v %v, want %+v", got, ok, err, want)
	}
	raw, _, _ := db.HubMeta(recordKey)
	if strings.Contains(raw, testKey) || strings.Contains(raw, f.Ciphertext) {
		t.Fatal("the hub's record holds key material")
	}

	// Read through a read-only connection, as verify does.
	conn, err := statedb.OpenConn(path, statedb.ReadOnly)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if got, ok, err := ReadRecord(conn); err != nil || !ok || got != want {
		t.Fatalf("read-only: %+v %v %v", got, ok, err)
	}
	bare, err := statedb.OpenConn(filepath.Join(t.TempDir(), "bare.db"), statedb.ReadWrite)
	if err != nil {
		t.Fatal(err)
	}
	defer bare.Close()
	if _, ok, err := ReadRecord(bare); err != nil || ok {
		t.Fatalf("a database with no metadata table: %v %v", ok, err)
	}
}

func TestWriteEnvFile(t *testing.T) {
	now := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)

	t.Run("created", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), ".cloop", "hub.env")
		res, err := WriteEnvFile(path, []byte(testKey), false, now)
		if err != nil || !res.Created {
			t.Fatalf("%+v %v", res, err)
		}
		assertEnv(t, path, testKey)
		if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
			t.Errorf("mode %s", fi.Mode().Perm())
		}
	})

	t.Run("other lines kept, key replaced in place", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "hub.env")
		writeFile(t, path, "# comment\nCLOOP_UI_TOKEN=tok\n#CLOOP_SECRET_KEY=old-comment\nexport CLOOP_SECRET_KEY=\nOTHER=1\n")
		if _, err := WriteEnvFile(path, []byte(testKey), false, now); err != nil {
			t.Fatal(err)
		}
		got := readFile(t, path)
		for _, line := range []string{"# comment", "CLOOP_UI_TOKEN=tok", "#CLOOP_SECRET_KEY=old-comment", "OTHER=1"} {
			if !strings.Contains(got, line+"\n") {
				t.Errorf("lost %q:\n%s", line, got)
			}
		}
		assertEnv(t, path, testKey)
	})

	t.Run("the same key is left alone", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "hub.env")
		writeFile(t, path, "CLOOP_SECRET_KEY="+testKey+"\n")
		before, _ := os.Stat(path)
		res, err := WriteEnvFile(path, []byte(testKey), false, now)
		if err != nil || !res.Unchanged {
			t.Fatalf("%+v %v", res, err)
		}
		if after, _ := os.Stat(path); !os.SameFile(before, after) {
			t.Error("the file was rewritten")
		}
	})

	t.Run("a different key needs force, and is kept aside", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "hub.env")
		writeFile(t, path, "CLOOP_SECRET_KEY='another-key-entirely'\nCLOOP_UI_TOKEN=tok\n")
		if _, err := WriteEnvFile(path, []byte(testKey), false, now); err == nil {
			t.Fatal("a different key was replaced without force")
		}
		assertEnv(t, path, "'another-key-entirely'")
		res, err := WriteEnvFile(path, []byte(testKey), true, now)
		if err != nil {
			t.Fatal(err)
		}
		assertEnv(t, path, testKey)
		if res.Previous == "" || !strings.Contains(readFile(t, res.Previous), "another-key-entirely") {
			t.Fatalf("the previous file was not kept: %+v", res)
		}
		if !strings.Contains(readFile(t, path), "CLOOP_UI_TOKEN=tok") {
			t.Error("the other lines were lost")
		}
	})

	t.Run("a symlinked env file is written through", func(t *testing.T) {
		dir := t.TempDir()
		target := filepath.Join(dir, "etc-cloop-hub.env")
		writeFile(t, target, "CLOOP_UI_TOKEN=tok\n")
		link := filepath.Join(dir, "hub.env")
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		res, err := WriteEnvFile(link, []byte(testKey), false, now)
		if err != nil {
			t.Fatal(err)
		}
		if fi, err := os.Lstat(link); err != nil || fi.Mode()&os.ModeSymlink == 0 {
			t.Fatalf("the link was replaced: %v", err)
		}
		assertEnv(t, target, testKey)
		if res.Path != target {
			t.Errorf("reported %s", res.Path)
		}
	})

	t.Run("a key the file cannot hold unquoted", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "hub.env")
		for _, k := range []string{`has "quotes" and $vars`, "~/a:~/b", "a:~b", "with space"} {
			if _, err := WriteEnvFile(path, []byte(k), false, now); err == nil {
				t.Errorf("%q written", k)
			}
		}
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Error("a file was left behind")
		}
	})

	// The last assignment is what a shell sourcing the file ends up with, so
	// a file whose first line holds this key and a later one another key does
	// not "already hold" it.
	t.Run("a later assignment of another key counts", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "hub.env")
		writeFile(t, path, "CLOOP_SECRET_KEY="+testKey+"\nX=1\nCLOOP_SECRET_KEY=a-stale-key-that-wins\n")
		if res, err := WriteEnvFile(path, []byte(testKey), false, now); err == nil || res.Unchanged {
			t.Fatalf("reported %+v, %v", res, err)
		}
		if _, err := WriteEnvFile(path, []byte(testKey), true, now); err != nil {
			t.Fatal(err)
		}
		assertEnv(t, path, testKey)
		if !strings.Contains(readFile(t, path), "X=1") {
			t.Error("the other line was lost")
		}
	})

	t.Run("the key assigned twice is written once", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "hub.env")
		writeFile(t, path, "CLOOP_SECRET_KEY="+testKey+"\nCLOOP_SECRET_KEY="+testKey+"\n")
		res, err := WriteEnvFile(path, []byte(testKey), false, now)
		if err != nil || res.Unchanged || res.Previous != "" {
			t.Fatalf("%+v %v", res, err)
		}
		assertEnv(t, path, testKey)
	})
}

func assertEnv(t *testing.T, path, want string) {
	t.Helper()
	var got []string
	for _, line := range strings.Split(readFile(t, path), "\n") {
		if v, ok := isKeyLine(line); ok {
			got = append(got, v)
		}
	}
	want = strings.Trim(want, "'")
	if len(got) != 1 || got[0] != want {
		t.Fatalf("CLOOP_SECRET_KEY assignments %q, want exactly %q", got, want)
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// A recovered key goes back into the hub's key file the way the hub reads it
// (Task 20425): the key and a newline, 0600; the same key leaves the file
// alone; a different one is refused without replace and kept aside with it;
// and a path the hub would refuse to read — inside .cloop/, relative — is
// refused here first.
func TestWriteKeyFile(t *testing.T) {
	now := time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)
	dir := t.TempDir()
	path := filepath.Join(dir, "cloop-secret-key")

	res, err := WriteKeyFile(path, []byte(testKey), false, now)
	if err != nil || !res.Created {
		t.Fatalf("%+v %v", res, err)
	}
	if b, _ := os.ReadFile(path); string(b) != testKey+"\n" {
		t.Fatalf("the key file holds %q", b)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Errorf("mode %s", fi.Mode().Perm())
	}

	if res, err := WriteKeyFile(path, []byte(testKey), false, now); err != nil || !res.Unchanged {
		t.Fatalf("the same key again: %+v %v", res, err)
	}

	const other = "a-different-key-0123456789abcdefghijklmnopq"
	if _, err := WriteKeyFile(path, []byte(other), false, now); err == nil || !strings.Contains(err.Error(), "--force") {
		t.Fatalf("a different key without replace: %v", err)
	}
	res, err = WriteKeyFile(path, []byte(other), true, now)
	if err != nil || res.Previous == "" {
		t.Fatalf("a different key with replace: %+v %v", res, err)
	}
	if b, _ := os.ReadFile(res.Previous); string(b) != testKey+"\n" {
		t.Errorf("the replaced key was not kept aside: %q", b)
	}
	if b, _ := os.ReadFile(path); string(b) != other+"\n" {
		t.Errorf("the key file holds %q", b)
	}

	for name, p := range map[string]string{
		"inside .cloop/": filepath.Join(dir, ".cloop", "cloop-secret-key"),
		"relative":       "cloop-secret-key",
	} {
		if _, err := WriteKeyFile(p, []byte(testKey), true, now); err == nil {
			t.Errorf("%s: written", name)
		}
	}
	if _, err := WriteKeyFile(filepath.Join(dir, "k2"), []byte("two\nlines"), true, now); err == nil {
		t.Error("a key with a newline in it was written to a file that would read back as another key")
	}
}
