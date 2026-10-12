package rootkey

// The resolver every reader of the root key goes through (Task 20425). Each
// refusal here is a configuration the hub would otherwise start on with a key
// someone else could read, replace, or that is not the key the operator meant.

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	keyA = "Zq4pV9mW2xT7rL0yH3nB8kD5sF1gJ6cA-uE_oI4tR7w"
	keyB = "pL0yH3nB8kD5sF1gJ6cA-uE_oI4tR7wZq4pV9mW2xT"
)

// env is a getenv over a map, so a test says exactly what is set.
func env(vars map[string]string) func(string) string {
	return func(k string) string { return vars[k] }
}

// self is a resolver for this process with the given environment.
func self(vars map[string]string) resolver {
	rv := defaultResolver()
	rv.getenv = env(vars)
	return rv
}

// keyFile writes value to a 0600 file this process owns, in a fresh
// directory, and returns its path.
func keyFile(t *testing.T, value string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "cloop-secret-key")
	if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestNothingConfiguredIsNoKeyAndNoError(t *testing.T) {
	r, err := self(nil).resolve()
	if err != nil || r.Current.Set() || r.Previous.Set() || r.Changing() {
		t.Fatalf("resolve with nothing set: %+v, %v", r, err)
	}
}

func TestEachSourceAlone(t *testing.T) {
	path := keyFile(t, keyA+"\n")
	creds := filepath.Dir(keyFile(t, keyA))
	for name, tc := range map[string]struct {
		vars   map[string]string
		source Source
	}{
		"file":        {map[string]string{EnvKeyFile: path}, SourceFile},
		"credential":  {map[string]string{EnvCredentialsDirectory: creds}, SourceCredential},
		"environment": {map[string]string{EnvKey: keyA}, SourceEnvironment},
	} {
		t.Run(name, func(t *testing.T) {
			r, err := self(tc.vars).resolve()
			if err != nil {
				t.Fatal(err)
			}
			if r.Current.Value != keyA || r.Current.Source != tc.source {
				t.Fatalf("resolved %q from %s, want the key from %s", r.Current.Value, r.Current.Source, tc.source)
			}
			if strings.Contains(r.Current.Describe(), keyA) {
				t.Error("Describe names the key itself")
			}
		})
	}
}

// One trailing newline is what `echo` adds; nothing else is stripped, because
// the environment variable a file replaces never had it.
func TestAKeyFileLosesOneNewlineAndNothingElse(t *testing.T) {
	for raw, want := range map[string]string{
		keyA + "\n":   keyA,
		keyA + "\r\n": keyA,
		keyA:          keyA,
		" " + keyA:    " " + keyA,
		keyA + " \n":  keyA + " ",
	} {
		r, err := self(map[string]string{EnvKeyFile: keyFile(t, raw)}).resolve()
		if err != nil || r.Current.Value != want {
			t.Errorf("file %q read as %q (%v), want %q", raw, r.Current.Value, err, want)
		}
	}
}

// Sources that agree resolve to the first, and say which others hold the
// same key — the doctor warns about a copy left in the environment.
func TestAgreeingSourcesResolveToTheFileAndNameTheOthers(t *testing.T) {
	path := keyFile(t, keyA)
	creds := filepath.Dir(keyFile(t, keyA))
	r, err := self(map[string]string{EnvKeyFile: path, EnvCredentialsDirectory: creds, EnvKey: keyA}).resolve()
	if err != nil {
		t.Fatal(err)
	}
	if r.Current.Source != SourceFile || r.Current.Path != path {
		t.Errorf("resolved from %s, want the file", r.Current.Describe())
	}
	if len(r.Current.Also) != 2 || r.Current.Also[0] != SourceCredential || r.Current.Also[1] != SourceEnvironment {
		t.Errorf("Also = %v, want the credential and the environment", r.Current.Also)
	}
}

// Two sources holding different keys are refused, never ranked: which one the
// hub picked would decide whether it opens anything.
func TestDisagreeingSourcesAreRefused(t *testing.T) {
	path := keyFile(t, keyA)
	creds := filepath.Dir(keyFile(t, keyB))
	for name, vars := range map[string]map[string]string{
		"file and environment":       {EnvKeyFile: path, EnvKey: keyB},
		"file and credential":        {EnvKeyFile: path, EnvCredentialsDirectory: creds},
		"credential and environment": {EnvCredentialsDirectory: creds, EnvKey: keyA},
		"previous file and variable": {EnvKey: keyB, EnvPreviousFile: path, EnvPrevious: "something else entirely"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := self(vars).resolve()
			if !errors.Is(err, ErrConflict) {
				t.Fatalf("err = %v, want ErrConflict", err)
			}
			for _, k := range []string{keyA, keyB} {
				if strings.Contains(err.Error(), k) {
					t.Fatal("the refusal names a key")
				}
			}
		})
	}
}

func TestAPreviousKeyNeedsACurrentOneAndIsNotIt(t *testing.T) {
	if _, err := self(map[string]string{EnvPrevious: keyA}).resolve(); !errors.Is(err, ErrPreviousAlone) {
		t.Errorf("a previous key alone: %v, want ErrPreviousAlone", err)
	}
	if _, err := self(map[string]string{EnvKey: keyA, EnvPrevious: keyA}).resolve(); !errors.Is(err, ErrSameKey) {
		t.Errorf("the same key twice: %v, want ErrSameKey", err)
	}
	r, err := self(map[string]string{EnvKey: keyB, EnvPreviousFile: keyFile(t, keyA)}).resolve()
	if err != nil {
		t.Fatal(err)
	}
	if !r.Changing() || r.Previous.Value != keyA || r.Previous.Source != SourceFile {
		t.Errorf("previous = %+v", r.Previous)
	}
	if got := r.Values(); len(got) != 2 || got[0] != keyB || got[1] != keyA {
		t.Errorf("Values() = %v, want current then previous", got)
	}
}

// The file rules: a regular file this process owns, readable by nobody else,
// outside every .cloop/ directory.
func TestKeyFileRefusals(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, mode os.FileMode, body string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		return path
	}
	inCloop := filepath.Join(dir, "hub", ".cloop", "cloop-secret-key")
	if err := os.MkdirAll(filepath.Dir(inCloop), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(inCloop, []byte(keyA), 0o600); err != nil {
		t.Fatal(err)
	}
	linkToCloop := filepath.Join(dir, "link-into-cloop")
	if err := os.Symlink(inCloop, linkToCloop); err != nil {
		t.Fatal(err)
	}

	for name, tc := range map[string]struct {
		path string
		want error
	}{
		"readable by everyone":  {write("world", 0o644, keyA), ErrRefused},
		"readable by its group": {write("group", 0o640, keyA), ErrRefused},
		"writable by its group": {write("gwrite", 0o620, keyA), ErrRefused},
		"executable":            {write("exec", 0o700, keyA), ErrRefused},
		"inside .cloop/":        {inCloop, ErrRefused},
		"a link into .cloop/":   {linkToCloop, ErrRefused},
		"a directory":           {dir, ErrRefused},
		"relative":              {"cloop-secret-key", ErrRefused},
		"missing":               {filepath.Join(dir, "nope"), ErrUnreadable},
		"empty":                 {write("empty", 0o600, "\n"), ErrRefused},
		"a NUL byte":            {write("nul", 0o600, "abc\x00def"), ErrRefused},
		"too large":             {write("large", 0o600, strings.Repeat("k", maxFileSize+1)), ErrRefused},
	} {
		t.Run(name, func(t *testing.T) {
			for _, slot := range []string{EnvKeyFile, EnvPreviousFile} {
				vars := map[string]string{slot: tc.path}
				if slot == EnvPreviousFile {
					vars[EnvKey] = keyB
				}
				_, err := self(vars).resolve()
				if !errors.Is(err, tc.want) {
					t.Fatalf("%s=%s: err = %v, want %v", slot, tc.path, err, tc.want)
				}
			}
		})
	}

	// 0400 and 0600 are both fine.
	for _, mode := range []os.FileMode{0o400, 0o600} {
		path := write("ok-"+mode.String(), mode, keyA)
		if r, err := self(map[string]string{EnvKeyFile: path}).resolve(); err != nil || r.Current.Value != keyA {
			t.Errorf("mode %04o: %v", mode, err)
		}
	}
	// A credentials directory that is not absolute is refused rather than
	// read relative to wherever the hub was started.
	if _, err := self(map[string]string{EnvCredentialsDirectory: "creds"}).resolve(); !errors.Is(err, ErrRefused) {
		t.Errorf("a relative credentials directory: %v", err)
	}
}

// The owner rule, against the process's identity rather than the file's: a
// file owned by another user is refused, and a root-owned one only in the
// shape Kubernetes gives a Secret volume — readable through a group this
// process is in, by nobody else.
func TestKeyFileOwnerRule(t *testing.T) {
	rv := resolver{euid: 1000, gid: 1000, groups: []int{65532}}
	for name, tc := range map[string]struct {
		uid, gid int
		perm     os.FileMode
		ok       bool
	}{
		"its own, 0400":                     {1000, 1000, 0o400, true},
		"its own, 0600":                     {1000, 1000, 0o600, true},
		"its own, group-readable":           {1000, 1000, 0o440, false},
		"another user's":                    {1001, 1000, 0o400, false},
		"root's, through its primary group": {0, 1000, 0o440, true},
		"root's, through its fsGroup":       {0, 65532, 0o440, true},
		"root's, through another group":     {0, 4242, 0o440, false},
		"root's, group-writable":            {0, 65532, 0o460, false},
		"root's, unreadable to the group":   {0, 65532, 0o400, false},
	} {
		err := rv.checkAccess("/k", tc.uid, tc.gid, tc.perm)
		if (err == nil) != tc.ok {
			t.Errorf("%s: err = %v, want ok=%v", name, err, tc.ok)
		}
	}
}

// A serving hub pins what it resolved at startup: a key file changing under it
// takes effect at the next restart, not mid-flight.
func TestPinHoldsUntilUnpinned(t *testing.T) {
	path := keyFile(t, keyA)
	t.Setenv(EnvKey, "")
	t.Setenv(EnvKeyFile, path)
	t.Setenv(EnvPrevious, "")
	t.Setenv(EnvPreviousFile, "")
	t.Setenv(EnvCredentialsDirectory, "")
	r, err := Resolve()
	if err != nil || r.Current.Value != keyA {
		t.Fatalf("resolve: %+v, %v", r, err)
	}
	unpin := Pin(r)
	if err := os.WriteFile(path, []byte(keyB), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, _ := Current(); got != keyA || !Pinned() {
		t.Errorf("pinned: Current() = %q", got)
	}
	unpin()
	if got, _ := Current(); got != keyB || Pinned() {
		t.Errorf("unpinned: Current() = %q", got)
	}
}

func TestInsideCloopDir(t *testing.T) {
	for path, want := range map[string]bool{
		"/srv/hub/.cloop/key":     true,
		"/srv/hub/.cloop":         true,
		"/srv/hub/cloop/key":      false,
		"/etc/cloop/root-key/key": false,
		"/srv/hub/.cloopx/key":    false,
		"/srv/hub/x/../.cloop/k":  true,
	} {
		if got := InsideCloopDir(path); got != want {
			t.Errorf("InsideCloopDir(%q) = %v, want %v", path, got, want)
		}
	}
}
