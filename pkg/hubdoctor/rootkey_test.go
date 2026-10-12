package hubdoctor

// The root key as the doctor reports it (Task 20425): where it came from, a
// source the hub would refuse, a change of root in progress, and a live key no
// configured root derives.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/keyescrow"
	"github.com/blechschmidt/cloop/pkg/rootkey"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

const (
	doctorOldRoot = "hubdoctor-branch-grants" // what seedBranchGrants seals under
	doctorNewRoot = "Zq4pV9mW2xT7rL0yH3nB8kD5sF1gJ6cA-uE_oI4tR7w"
)

// noRootSources clears every source of the root key, so a test sets exactly
// the ones it means.
func noRootSources(t *testing.T) {
	t.Helper()
	for _, v := range []string{rootkey.EnvKey, rootkey.EnvKeyFile, rootkey.EnvPrevious, rootkey.EnvPreviousFile,
		rootkey.EnvCredentialsDirectory} {
		t.Setenv(v, "")
	}
}

func onSystemd(t *testing.T, yes bool) {
	t.Helper()
	prev := systemdHost
	systemdHost = func() bool { return yes }
	t.Cleanup(func() { systemdHost = prev })
}

func writeKey(t *testing.T, value string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "cloop-secret-key")
	if err := os.WriteFile(path, []byte(value+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestTheDoctorSaysWhereTheRootKeyComesFrom(t *testing.T) {
	dir := t.TempDir()
	noRootSources(t)

	// An environment variable, on a host systemd runs: readable in
	// /proc/<pid>/environ and `systemctl show`, so a credential is named.
	onSystemd(t, true)
	t.Setenv(rootkey.EnvKey, doctorNewRoot)
	f := only(t, findingsFor(t, dir, hubCfg(), Options{Offline: true}), "secret_key.source")
	wantSeverity(t, f, SeverityWarn)
	if !strings.Contains(f.Remediation, "LoadCredentialEncrypted="+rootkey.Credential) {
		t.Errorf("remediation %q", f.Remediation)
	}

	// The same variable where systemd does not run the host: said, not warned.
	onSystemd(t, false)
	f = only(t, findingsFor(t, dir, hubCfg(), Options{Offline: true}), "secret_key.source")
	wantSeverity(t, f, SeverityPass)

	// A key file, with a copy of the key left in the environment: the copy
	// keeps every exposure the file was meant to end.
	path := writeKey(t, doctorNewRoot, 0o400)
	t.Setenv(rootkey.EnvKeyFile, path)
	f = only(t, findingsFor(t, dir, hubCfg(), Options{Offline: true}), "secret_key.source")
	wantSeverity(t, f, SeverityWarn)
	if !strings.Contains(f.Message, "also set in the environment") {
		t.Errorf("message %q", f.Message)
	}

	// The key file alone, on a systemd host or not.
	onSystemd(t, true)
	t.Setenv(rootkey.EnvKey, "")
	f = only(t, findingsFor(t, dir, hubCfg(), Options{Offline: true}), "secret_key.source")
	wantSeverity(t, f, SeverityPass)
	if !strings.Contains(f.Message, path) {
		t.Errorf("message %q does not name the file", f.Message)
	}
}

// A source the hub would refuse fails the doctor, with the reason — before
// anything else about the key is judged, because the hub will not start.
func TestTheDoctorFailsARootSourceTheHubRefuses(t *testing.T) {
	dir := t.TempDir()
	for name, set := range map[string]func(t *testing.T){
		"a world-readable key file": func(t *testing.T) {
			t.Setenv(rootkey.EnvKeyFile, writeKey(t, doctorNewRoot, 0o644))
		},
		"a file and a variable that disagree": func(t *testing.T) {
			t.Setenv(rootkey.EnvKeyFile, writeKey(t, doctorNewRoot, 0o600))
			t.Setenv(rootkey.EnvKey, doctorOldRoot)
		},
	} {
		t.Run(name, func(t *testing.T) {
			noRootSources(t)
			set(t)
			got := findingsFor(t, dir, hubCfg(), Options{Offline: true})
			wantSeverity(t, only(t, got, "secret_key.source"), SeverityFail)
			if len(got["secret_key.entropy"]) != 0 {
				t.Error("the key's strength was judged although the hub would not start on it")
			}
		})
	}
}

// Mid-way through a change of root: the previous root is warned about for as
// long as it is set; the keys it derives satisfy the rule the hub starts by,
// and without it they fail it.
func TestTheDoctorFollowsAChangeOfRoot(t *testing.T) {
	dir := t.TempDir()
	seedBranchGrants(t, dir) // keys and a secret of the old root
	noRootSources(t)

	t.Setenv(rootkey.EnvKey, doctorNewRoot)
	t.Setenv(rootkey.EnvPrevious, doctorOldRoot)
	got := findingsFor(t, dir, hubCfg(), Options{Offline: true})
	wantSeverity(t, only(t, got, "secret_key.previous"), SeverityWarn)
	f := only(t, got, "secret_key.matches")
	wantSeverity(t, f, SeverityPass)
	if !strings.Contains(f.Message, "--retire-previous") {
		t.Errorf("matches: %q", f.Message)
	}

	// The new key alone: every live key derives from no configured root.
	t.Setenv(rootkey.EnvPrevious, "")
	got = findingsFor(t, dir, hubCfg(), Options{Offline: true})
	f = only(t, got, "secret_key.matches")
	wantSeverity(t, f, SeverityFail)
	if !strings.Contains(f.Message, "no configured root") || !strings.Contains(f.Remediation, rootkey.EnvPrevious) {
		t.Errorf("a key no root derives: %+v", f)
	}
	if len(got["secret_key.previous"]) != 0 {
		t.Error("a previous root is reported where none is set")
	}
}

// The escrow on record holding the previous root, mid-change, is a warning
// that the retire step is waiting for an escrow of the new one — not the
// failure an escrow of an unrelated key is.
func TestAnEscrowOfThePreviousRootWarnsDuringAChange(t *testing.T) {
	dir := t.TempDir()
	dbPath := mustInitStateDB(t, dir)
	noRootSources(t)
	t.Setenv(rootkey.EnvKey, doctorNewRoot)
	t.Setenv(rootkey.EnvPrevious, doctorOldRoot)
	ef, err := keyescrow.Wrap([]byte(doctorOldRoot), []byte("a long enough escrow passphrase"), keyescrow.WrapOptions{})
	if err != nil {
		t.Fatal(err)
	}
	db, err := statedb.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := keyescrow.SaveRecord(db, ef.Record("cli:test", time.Now())); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
	f := only(t, findingsFor(t, dir, hubCfg(), Options{Offline: true}), "secret_key.escrow")
	wantSeverity(t, f, SeverityWarn)
	if !strings.Contains(f.Message, "previous root") || !strings.Contains(f.Message, "--retire-previous") {
		t.Errorf("message %q", f.Message)
	}
}

// A weak key is not fixed by `cloop hub key rotate`, which mints every new key
// from it: the remediation names the change of root instead.
func TestAWeakKeyIsToldToChangeTheRootNotToRotate(t *testing.T) {
	noRootSources(t)
	for _, weak := range []string{"hunter2", "eval-only-not-a-real-key-change-me", strings.Repeat("a", 40)} {
		t.Setenv(rootkey.EnvKey, weak)
		f := only(t, findingsFor(t, t.TempDir(), hubCfg(), Options{Offline: true}), "secret_key.entropy")
		if f.Severity == SeverityPass {
			t.Fatalf("%q passes", weak)
		}
		if !strings.Contains(f.Remediation, "--retire-previous") || !strings.Contains(f.Remediation, rootkey.EnvPrevious) {
			t.Errorf("%q: remediation %q does not name the change of root", weak, f.Remediation)
		}
	}
}
