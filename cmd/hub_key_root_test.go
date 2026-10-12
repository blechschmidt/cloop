package cmd

// `cloop hub key rotate --retire-previous`, and the escrow commands during a
// change of root (Task 20425).

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/keyescrow"
	"github.com/blechschmidt/cloop/pkg/rootkey"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

const (
	rootChangeOld        = "root-change-cli-old-key-0123456789abcdefgh"
	rootChangeNew        = "root-change-cli-new-key-IJKLMNOPQRSTUVWXYZ98"
	rootChangePassphrase = "five random words make a fine escrow passphrase"
)

// clearRoots unsets every source of the root key, so a test sets exactly the
// ones it means whatever the machine running it exports.
func clearRoots(t *testing.T) {
	t.Helper()
	for _, v := range []string{rootkey.EnvKey, rootkey.EnvKeyFile, rootkey.EnvPrevious, rootkey.EnvPreviousFile,
		rootkey.EnvCredentialsDirectory} {
		t.Setenv(v, "")
	}
}

// rootChangeHub is a hub whose secret is sealed under the old root, with this
// shell holding the new root and the old one beside it — the configuration
// --retire-previous runs in.
func rootChangeHub(t *testing.T) string {
	t.Helper()
	clearRoots(t)
	t.Setenv(rootkey.EnvKey, rootChangeOld)
	dir := auditDir(t)
	drillMint(t, dir, "drill-token", "the value before the change")
	t.Setenv(rootkey.EnvKey, rootChangeNew)
	t.Setenv(rootkey.EnvPrevious, rootChangeOld)
	return dir
}

// putMember records a live hub member advertising the given roots; "" for
// none.
func putMember(t *testing.T, dir, id, current, previous string) {
	t.Helper()
	meta := map[string]string{}
	if current != "" {
		meta[rootkey.EndpointCurrent] = current
	}
	if previous != "" {
		meta[rootkey.EndpointPrevious] = previous
	}
	b, _ := json.Marshal(meta)
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.JoinHubMember(statedb.HubMemberRow{InstanceID: id, Hostname: "hub-" + id + ".example",
		PID: 4242, Meta: string(b), HeartbeatAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
}

func retirePrevious(t *testing.T, dir string, dryRun bool) (string, error) {
	t.Helper()
	h, err := openHubKeyring(dir, false)
	if err != nil {
		t.Fatalf("open the hub's keyring: %v", err)
	}
	defer h.close()
	var out bytes.Buffer
	err = runRetirePrevious(&out, dir, h, dryRun, false)
	return out.String(), err
}

// keyStates is every key's state, by id.
func keyStates(t *testing.T, dir string) map[string]string {
	t.Helper()
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows, err := db.ListKEKs()
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, r := range rows {
		out[r.ID] = r.State
	}
	return out
}

func escrowNew(t *testing.T, dir string) {
	t.Helper()
	pass := filepath.Join(t.TempDir(), "passphrase")
	if err := os.WriteFile(pass, []byte(rootChangePassphrase+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := runEscrowExport(&out, escrowOptions{Workdir: dir, File: filepath.Join(t.TempDir(), "hub.escrow"),
		PassphraseFile: pass, Key: rootChangeNew, Previous: rootChangeOld, Now: time.Now}); err != nil {
		t.Fatalf("escrow the new key mid-change: %v\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "still derive from "+rootkey.EnvPrevious) {
		t.Errorf("the export does not say the old root's keys are still live:\n%s", out.String())
	}
}

// The precondition is about the deployment, not the registry: every live hub
// member must advertise the new root as its current one, and an escrow of it
// must be on record. Until then nothing is minted, rewrapped or retired; once
// it holds, the old root's keys are retired and the new root alone opens
// everything.
func TestRetirePreviousWaitsForEveryMemberAndAnEscrow(t *testing.T) {
	dir := rootChangeHub(t)
	oldFP, _ := rootkey.Fingerprint(rootChangeOld)
	newFP, _ := rootkey.Fingerprint(rootChangeNew)
	putMember(t, dir, "restarted", newFP, oldFP)
	putMember(t, dir, "not-yet", oldFP, "")
	putMember(t, dir, "older-build", "", "")
	before := keyStates(t, dir)

	out, err := retirePrevious(t, dir, false)
	if !errors.Is(err, errRootChangeNotReady) {
		t.Fatalf("with members on the old root: %v\n%s", err, out)
	}
	for _, want := range []string{"not-yet", "runs on root key " + oldFP, "older-build", "advertises no root key",
		"no escrow is on record", "nothing was minted, rewrapped or retired"} {
		if !strings.Contains(out, want) && !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not say %q:\n%s", want, out)
		}
	}
	if got := keyStates(t, dir); len(got) != len(before) {
		t.Fatalf("a refused run changed the registry: %v, was %v", got, before)
	}

	// Every member restarted onto the new root; still no escrow of it.
	putMember(t, dir, "not-yet", newFP, oldFP)
	putMember(t, dir, "older-build", newFP, oldFP)
	if out, err := retirePrevious(t, dir, false); !errors.Is(err, errRootChangeNotReady) ||
		!strings.Contains(out, "no escrow is on record") {
		t.Fatalf("without an escrow: %v\n%s", err, out)
	}

	// A dry run with everything ready says what would happen and does it not.
	escrowNew(t, dir)
	out, err = retirePrevious(t, dir, true)
	if err != nil || !strings.Contains(out, "Dry run: 1 row(s) would be rewrapped") {
		t.Fatalf("dry run: %v\n%s", err, out)
	}
	if got := keyStates(t, dir); len(got) != len(before) {
		t.Fatal("a dry run changed the registry")
	}

	out, err = retirePrevious(t, dir, false)
	if err != nil {
		t.Fatalf("with every member ready and the new key escrowed: %v\n%s", err, out)
	}
	after := keyStates(t, dir)
	for id := range before {
		if after[id] != secretbroker.KEKStateRetired {
			t.Errorf("the old root's key %s is %s", id, after[id])
		}
	}
	if len(after) != len(before)+1 {
		t.Errorf("%d keys after, want the old ones and one minted from the new root", len(after))
	}

	// Restart without the previous root: the secret leases.
	t.Setenv(rootkey.EnvPrevious, "")
	if got := drillLease(t, dir); got != "the value before the change" {
		t.Fatalf("after the change the secret leases as %q", got)
	}
	// And the old root alone no longer opens the hub.
	t.Setenv(rootkey.EnvKey, rootChangeOld)
	if _, err := openHubKeyring(dir, false); !errors.Is(err, secretbroker.ErrKeyUnavailable) {
		t.Errorf("the old root after the change: %v", err)
	}

	// The audit trail names the change, by fingerprint.
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	events, _, err := db.ListAuditEvents(statedb.AuditFilter{EventType: string(auditaction.ActionSealingKeyRootChanged)})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || !strings.Contains(events[0].Payload, newFP) || !strings.Contains(events[0].Payload, oldFP) ||
		strings.Contains(events[0].Payload, rootChangeNew) {
		t.Errorf("audit rows %+v", events)
	}
}

// A hub serving under ui.cluster.exclusive holds the lease and no member row,
// so it advertises no root: the change waits for it to stop.
func TestRetirePreviousRefusesBesideAnExclusiveHub(t *testing.T) {
	dir := rootChangeHub(t)
	escrowNew(t, dir)
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := db.AcquireHubLease(statedb.HubLeaseRow{InstanceID: "exclusive-hub", Hostname: "elsewhere.example",
		PID: 4242}, statedb.HubLeaseRow{}); err != nil || !ok {
		t.Fatalf("take the lease: %v %v", ok, err)
	}
	_ = db.Close()
	out, err := retirePrevious(t, dir, false)
	if !errors.Is(err, errRootChangeNotReady) || !strings.Contains(out, "exclusively") {
		t.Fatalf("beside an exclusive hub: %v\n%s", err, out)
	}
}

// Without the previous root there is nothing to retire, and the command says
// which variable it needs rather than rotating anyway.
func TestRetirePreviousNeedsThePreviousRootInThisShell(t *testing.T) {
	dir := rootChangeHub(t)
	t.Setenv(rootkey.EnvKey, rootChangeOld)
	t.Setenv(rootkey.EnvPrevious, "")
	_, err := retirePrevious(t, dir, false)
	if !errors.Is(err, secretbroker.ErrNoPreviousRoot) || !strings.Contains(err.Error(), rootkey.EnvPrevious) {
		t.Fatalf("err = %v", err)
	}
}

// A plain rotation mid-change would mint from the new root with no member
// check; it is refused and pointed at --retire-previous. Resuming onto the
// current primary, a dry run, and a rotation once the change is finished are
// not.
func TestAPlainRotationIsRefusedMidChange(t *testing.T) {
	dir := rootChangeHub(t)
	h, err := openHubKeyring(dir, false)
	if err != nil {
		t.Fatal(err)
	}
	defer h.close()
	if err := refuseRotationMidChange(h.keyring, false, false); err == nil ||
		!strings.Contains(err.Error(), "--retire-previous") {
		t.Fatalf("a plain rotation mid-change: %v", err)
	}
	for name, ok := range map[string]bool{
		"--continue": refuseRotationMidChange(h.keyring, true, false) == nil,
		"--dry-run":  refuseRotationMidChange(h.keyring, false, true) == nil,
	} {
		if !ok {
			t.Errorf("%s was refused", name)
		}
	}
}

// The escrow of the new key, checked mid-change, opens the hub together with
// the previous root; recovered, it goes back into the hub's key file.
func TestTheNewKeysEscrowVerifiesMidChangeAndImportsIntoTheKeyFile(t *testing.T) {
	dir := rootChangeHub(t)
	pass := filepath.Join(t.TempDir(), "passphrase")
	if err := os.WriteFile(pass, []byte(rootChangePassphrase), 0o600); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "hub.escrow")
	var out bytes.Buffer
	if err := runEscrowExport(&out, escrowOptions{Workdir: dir, File: file, PassphraseFile: pass,
		Key: rootChangeNew, Previous: rootChangeOld, Now: time.Now}); err != nil {
		t.Fatalf("export: %v\n%s", err, out.String())
	}
	// Exporting the old key alone on this hub is refused nowhere: it opens
	// every live key. Exporting a key that opens none is.
	if err := runEscrowExport(&out, escrowOptions{Workdir: dir, File: filepath.Join(t.TempDir(), "x.escrow"),
		PassphraseFile: pass, Key: "a-key-this-hub-never-had-0123456789", Now: time.Now}); err == nil {
		t.Fatal("an escrow of a key that opens nothing here was made")
	}

	out.Reset()
	code := runEscrowVerify(&out, escrowOptions{Workdir: dir, File: file, PassphraseFile: pass,
		Key: rootChangeNew, Previous: rootChangeOld, Now: time.Now})
	if code != 0 || !strings.Contains(out.String(), "OPENS THE HUB") || !strings.Contains(out.String(), rootkey.EnvPrevious) {
		t.Fatalf("verify mid-change: exit %d\n%s", code, out.String())
	}

	// Recovered into the bootstrap's key file, not into an environment.
	clearRoots(t)
	out.Reset()
	if code := runEscrowImport(&out, escrowOptions{Workdir: dir, File: file, PassphraseFile: pass, Now: time.Now}); code != 0 {
		t.Fatalf("import: exit %d\n%s", code, out.String())
	}
	keyPath := filepath.Join(dir, hubKeyFile)
	got, err := os.ReadFile(keyPath)
	if err != nil || strings.TrimSpace(string(got)) != rootChangeNew {
		t.Fatalf("the key file holds %q (%v)", got, err)
	}
	if !strings.Contains(out.String(), rootkey.EnvKeyFile+"="+keyPath) {
		t.Errorf("import does not say how to point the hub at it:\n%s", out.String())
	}
	t.Setenv(rootkey.EnvKeyFile, keyPath)
	if r, err := rootkey.Resolve(); err != nil || r.Current.Value != rootChangeNew {
		t.Fatalf("the hub would not read the key file import wrote: %v", err)
	}

	// A hub that keeps its key in hub.env, as before Task 20425, gets it back
	// there instead.
	legacyDir := t.TempDir()
	envPath := filepath.Join(legacyDir, ".cloop", hubEnvFile)
	if err := os.MkdirAll(filepath.Dir(envPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(envPath, []byte("CLOOP_SECRET_KEY=a-key-lost-with-the-old-host-0123456\nCLOOP_UI_TOKEN=tok\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(rootkey.EnvKeyFile, "")
	out.Reset()
	if code := runEscrowImport(&out, escrowOptions{Workdir: legacyDir, File: file, PassphraseFile: pass,
		Force: true, Now: time.Now}); code != 0 {
		t.Fatalf("import into hub.env: exit %d\n%s", code, out.String())
	}
	if _, err := os.Stat(filepath.Join(legacyDir, hubKeyFile)); err == nil {
		t.Error("a key file was written for a hub that keeps its key in hub.env")
	}
	if !keyescrow.EnvFileHoldsKey(envPath) {
		t.Error("hub.env holds no key after the import")
	}
}
