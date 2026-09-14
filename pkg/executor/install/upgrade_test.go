package install

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// upgradeFixture stages an "installed" agent under a temp directory and returns
// an Installer whose commands are recorded rather than run.
//
// Root is deliberately left empty and every path made absolute under the temp
// dir instead. A non-empty Root suppresses command execution entirely (see
// Installer.Root), which would make the restart assertions vacuous — the tests
// would pass without a restart ever being attempted. Recording through Run is
// what lets them check the supervisor was actually asked.
type upgradeFixture struct {
	dir      string
	spec     Spec
	inst     *Installer
	commands *[]string
}

func newUpgradeFixture(t *testing.T, out Output, installedBinary string) *upgradeFixture {
	t.Helper()
	dir := t.TempDir()

	spec := Spec{
		ServiceName: "cloop-executor",
		BinaryPath:  filepath.Join(dir, "usr", "local", "bin", "cloop"),
		StateDir:    filepath.Join(dir, "var", "lib", "cloop-executor"),
		UnitDir:     filepath.Join(dir, "etc", "systemd", "system"),
		// Without this the OutputShell cases write to the real /etc/init.d:
		// as root they overwrite the host's own service script, and as the
		// unprivileged user CI runs as they fail with permission denied.
		InitDir: filepath.Join(dir, "etc", "init.d"),
		Server:  "wss://hub.example:8888/api/executors/connect",
	}
	norm, err := spec.Normalize()
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}

	// The binary, at the path an install would have put it. Wrapped into
	// something that actually runs and answers `version`, because Upgrade now
	// executes both binaries before it replaces anything — see fakeCloop.
	mustWrite(t, norm.BinaryPath, fakeCloop(fixtureVersion, installedBinary), BinaryMode)
	// The supervision artifact, which is what Upgrade checks to decide whether
	// anything is installed at all.
	switch out {
	case OutputSystemd:
		mustWrite(t, norm.UnitPath(), SystemdUnit(norm), UnitFileMode)
	case OutputShell:
		mustWrite(t, norm.InitScriptPath(), InitScript(norm), ScriptFileMode)
	}

	var commands []string
	return &upgradeFixture{
		dir:      dir,
		spec:     norm,
		commands: &commands,
		inst: &Installer{
			Run: func(name string, args ...string) error {
				commands = append(commands, strings.TrimSpace(name+" "+strings.Join(args, " ")))
				return nil
			},
			Logf: func(string, ...any) {},
		},
	}
}

func mustWrite(t *testing.T, path, body string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(body), mode); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// fixtureVersion is the build both the installed and the staged binary claim in
// the tests that do not care about versions.
//
// The *same* version on both sides deliberately: it keeps two binaries with the
// same marker byte-identical, which is what the idempotence and same-file cases
// depend on, and an equal version is not a downgrade so the safety check lets
// every other case through. Tests about version ordering build their binaries
// explicitly instead.
const fixtureVersion = "v1.0.0"

// fakeCloop renders a stand-in for the cloop binary: a shell script that answers
// `version` and `version --json` the way a real build does, and carries a marker
// so a test can tell which one ended up installed.
//
// A script rather than a copy of the real binary, because these tests need to
// vary the version and the protocol freely, and because the property under test
// is "Upgrade ran it and believed what it said" — not "the real cloop prints a
// version", which cmd/version_test.go covers.
func fakeCloop(version, marker string) string {
	return "#!/bin/sh\n" +
		"# cloop-test-marker: " + marker + "\n" +
		"if [ \"$1\" = \"version\" ] && [ \"$2\" = \"--json\" ]; then\n" +
		"  printf '{\"version\":\"" + version + "\",\"protocol\":6,\"min_protocol\":1}\\n'\n" +
		"  exit 0\n" +
		"fi\n" +
		"if [ \"$1\" = \"version\" ]; then echo \"cloop " + version + "\"; exit 0; fi\n" +
		"exit 0\n"
}

// markerOf recovers what fakeCloop embedded, so the existing assertions can keep
// comparing short names instead of whole scripts.
func markerOf(body string) string {
	for _, line := range strings.Split(body, "\n") {
		if rest, ok := strings.CutPrefix(strings.TrimSpace(line), "# cloop-test-marker:"); ok {
			return strings.TrimSpace(rest)
		}
	}
	return body
}

// newBinary writes a "new build" to the temp dir and returns its path.
func (f *upgradeFixture) newBinary(t *testing.T, body string) string {
	t.Helper()
	return f.stageBinary(t, fakeCloop(fixtureVersion, body))
}

// stageBinary writes an arbitrary body as the staged binary. The escape hatch
// for the tests that need something other than a well-behaved cloop.
func (f *upgradeFixture) stageBinary(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(f.dir, "tmp", "cloop-new")
	mustWrite(t, path, body, BinaryMode)
	return path
}

func (f *upgradeFixture) installed(t *testing.T) string {
	t.Helper()
	body, err := os.ReadFile(f.spec.BinaryPath)
	if err != nil {
		t.Fatalf("read installed binary: %v", err)
	}
	return markerOf(string(body))
}

// TestUpgradeReplacesBinaryAndRestarts is the happy path: the whole point of
// the flag that the UI had been recommending before it existed.
func TestUpgradeReplacesBinaryAndRestarts(t *testing.T) {
	f := newUpgradeFixture(t, OutputSystemd, "OLD BUILD")
	src := f.newBinary(t, "NEW BUILD")

	res, err := f.inst.Upgrade(f.spec, OutputSystemd, UpgradeOptions{Source: src})
	if err != nil {
		t.Fatalf("Upgrade: %v", err)
	}

	if !res.BinaryReplaced {
		t.Error("BinaryReplaced = false, want true")
	}
	if res.AlreadyCurrent {
		t.Error("AlreadyCurrent = true on a genuine upgrade")
	}
	if !res.Restarted {
		t.Error("Restarted = false, want true")
	}
	if got := f.installed(t); got != "NEW BUILD" {
		t.Errorf("installed binary = %q, want %q", got, "NEW BUILD")
	}
	if res.PreviousChecksum == res.NewChecksum || res.PreviousChecksum == "" || res.NewChecksum == "" {
		t.Errorf("checksums not reported distinctly: %q -> %q", res.PreviousChecksum, res.NewChecksum)
	}

	// try-restart, not restart: a service an operator deliberately stopped
	// must stay stopped through an upgrade.
	joined := strings.Join(*f.commands, "\n")
	if !strings.Contains(joined, "systemctl try-restart cloop-executor.service") {
		t.Errorf("expected a try-restart of the unit, got commands:\n%s", joined)
	}
	if strings.Contains(joined, "systemctl restart ") {
		t.Errorf("used plain `systemctl restart`, which would start a deliberately stopped "+
			"service; commands:\n%s", joined)
	}
	// An upgrade must not re-enable, re-provision credentials, or create users.
	for _, forbidden := range []string{"enable", "useradd"} {
		if strings.Contains(joined, forbidden) {
			t.Errorf("upgrade ran %q, which is install's job not upgrade's; commands:\n%s",
				forbidden, joined)
		}
	}
}

// TestUpgradeIsIdempotent is the property the CLI help promises and the reason
// an operator can re-run it without thinking. A second run must not bounce a
// healthy agent.
func TestUpgradeIsIdempotent(t *testing.T) {
	f := newUpgradeFixture(t, OutputSystemd, "OLD BUILD")
	src := f.newBinary(t, "NEW BUILD")

	if _, err := f.inst.Upgrade(f.spec, OutputSystemd, UpgradeOptions{Source: src}); err != nil {
		t.Fatalf("first Upgrade: %v", err)
	}
	*f.commands = nil

	res, err := f.inst.Upgrade(f.spec, OutputSystemd, UpgradeOptions{Source: src})
	if err != nil {
		t.Fatalf("second Upgrade: %v", err)
	}
	if !res.AlreadyCurrent {
		t.Error("AlreadyCurrent = false on a repeat upgrade")
	}
	if res.BinaryReplaced {
		t.Error("re-copied an identical binary")
	}
	if res.Restarted {
		t.Error("restarted the service for an identical binary; a re-run must not bounce a healthy agent")
	}
	if len(*f.commands) != 0 {
		t.Errorf("repeat upgrade ran commands: %v", *f.commands)
	}
	if got := f.installed(t); got != "NEW BUILD" {
		t.Errorf("installed binary changed on the no-op run: %q", got)
	}
}

// TestUpgradeForceReplacesIdenticalBinary covers the recovery case: the bytes
// match but the install is somehow broken, so the operator wants it redone.
func TestUpgradeForceReplacesIdenticalBinary(t *testing.T) {
	f := newUpgradeFixture(t, OutputSystemd, "SAME BUILD")
	src := f.newBinary(t, "SAME BUILD")

	res, err := f.inst.Upgrade(f.spec, OutputSystemd, UpgradeOptions{Source: src, Force: true})
	if err != nil {
		t.Fatalf("Upgrade --force: %v", err)
	}
	if res.AlreadyCurrent {
		t.Error("--force still reported AlreadyCurrent")
	}
	if !res.BinaryReplaced || !res.Restarted {
		t.Errorf("--force did not replace and restart: %+v", res)
	}
}

// TestUpgradeRefusesWhenNotInstalled is the "do not half-install" property. An
// upgrade must not be a back door to creating a supervised service with no unit
// and no credential.
func TestUpgradeRefusesWhenNotInstalled(t *testing.T) {
	f := newUpgradeFixture(t, OutputSystemd, "OLD BUILD")
	if err := os.Remove(f.spec.UnitPath()); err != nil {
		t.Fatalf("remove unit: %v", err)
	}
	src := f.newBinary(t, "NEW BUILD")

	res, err := f.inst.Upgrade(f.spec, OutputSystemd, UpgradeOptions{Source: src})
	if err == nil {
		t.Fatal("Upgrade succeeded with no unit file present")
	}
	if !errors.Is(err, ErrNotInstalled) {
		t.Errorf("error does not wrap ErrNotInstalled: %v", err)
	}
	// The message must point at the command that would work, which is the
	// entire lesson of the flag this replaces.
	if !strings.Contains(err.Error(), "--bundle") {
		t.Errorf("refusal does not name the install path: %v", err)
	}
	if res.BinaryReplaced {
		t.Error("refused upgrade still replaced the binary")
	}
	if got := f.installed(t); got != "OLD BUILD" {
		t.Errorf("installed binary was touched by a refused upgrade: %q", got)
	}
	if len(*f.commands) != 0 {
		t.Errorf("refused upgrade ran commands: %v", *f.commands)
	}
}

// TestUpgradeRefusesDockerWithARealProcedure pins the other half of the fix:
// where an in-place binary replace is meaningless, the command must say so and
// name what does work — not silently succeed having changed nothing.
func TestUpgradeRefusesDockerWithARealProcedure(t *testing.T) {
	f := newUpgradeFixture(t, OutputDocker, "OLD BUILD")
	src := f.newBinary(t, "NEW BUILD")

	_, err := f.inst.Upgrade(f.spec, OutputDocker, UpgradeOptions{Source: src})
	if err == nil {
		t.Fatal("Upgrade succeeded for --output docker, where there is no binary to replace")
	}
	for _, want := range []string{"podman pull", "podman rm"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("docker refusal does not name %q: %v", want, err)
		}
	}
	if got := f.installed(t); got != "OLD BUILD" {
		t.Errorf("docker refusal still replaced the binary: %q", got)
	}
}

// TestUpgradeShellOutputRestartsInitScript covers the devices without systemd,
// which are exactly the constrained edge devices this subsystem targets.
func TestUpgradeShellOutputRestartsInitScript(t *testing.T) {
	f := newUpgradeFixture(t, OutputShell, "OLD BUILD")
	src := f.newBinary(t, "NEW BUILD")

	res, err := f.inst.Upgrade(f.spec, OutputShell, UpgradeOptions{Source: src})
	if err != nil {
		t.Fatalf("Upgrade: %v", err)
	}
	if !res.BinaryReplaced || !res.Restarted {
		t.Errorf("shell upgrade incomplete: %+v", res)
	}
	want := f.spec.InitScriptPath() + " restart"
	if joined := strings.Join(*f.commands, "\n"); !strings.Contains(joined, want) {
		t.Errorf("expected %q, got commands:\n%s", want, joined)
	}
}

// TestUpgradeReportsUnrestartedService covers the outcome an operator must not
// miss: the binary landed but the supervisor refused, so the device is still
// running the old build even though the command mostly succeeded.
//
// The service is *not* running in this scenario — an unloaded unit cannot be —
// and that is what distinguishes it from the rollback case below. Nothing was
// taken down by the upgrade, so there is nothing to restore, and the right
// outcome is the honest partial success rather than a revert.
func TestUpgradeReportsUnrestartedService(t *testing.T) {
	f := newUpgradeFixture(t, OutputSystemd, "OLD BUILD")
	src := f.newBinary(t, "NEW BUILD")
	f.inst.Run = func(name string, args ...string) error {
		if len(args) > 0 && (args[0] == "try-restart" || args[0] == "is-active") {
			return errors.New("Unit cloop-executor.service not loaded")
		}
		return nil
	}

	_, err := f.inst.Upgrade(f.spec, OutputSystemd, UpgradeOptions{Source: src})
	if err == nil {
		t.Fatal("Upgrade reported success despite a failed restart")
	}
	// The copy already happened, so the error must say so rather than reading
	// as a clean failure an operator would retry blind.
	if !strings.Contains(err.Error(), "in place") {
		t.Errorf("restart failure does not say the binary was already replaced: %v", err)
	}
	if got := f.installed(t); got != "NEW BUILD" {
		t.Errorf("binary not replaced before the restart attempt: %q", got)
	}
}

// TestUpgradeSetsExecutableMode is the regression guard on the staging file's
// mode. CreateTemp makes 0600; a binary left at 0600 is a service that fails to
// start as its own unprivileged user, which an upgrade must never introduce.
func TestUpgradeSetsExecutableMode(t *testing.T) {
	f := newUpgradeFixture(t, OutputSystemd, "OLD BUILD")
	src := f.newBinary(t, "NEW BUILD")

	if _, err := f.inst.Upgrade(f.spec, OutputSystemd, UpgradeOptions{Source: src}); err != nil {
		t.Fatalf("Upgrade: %v", err)
	}
	st, err := os.Stat(f.spec.BinaryPath)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if got := st.Mode().Perm(); got != BinaryMode {
		t.Errorf("binary mode = %04o, want %04o", got, BinaryMode)
	}
}

// TestUpgradeLeavesUnitAndCredentialAlone pins the documented scope. Silently
// re-rendering the unit would be the dangerous version of this feature: the unit
// carries the hub URL and certificate pin, and an operator upgrading months
// later has neither to hand.
func TestUpgradeLeavesUnitAndCredentialAlone(t *testing.T) {
	f := newUpgradeFixture(t, OutputSystemd, "OLD BUILD")
	credential := f.spec.CredentialsFile
	mustWrite(t, credential, "cloopenroll1.secret-token\n", CredentialFileMode)

	unitBefore, err := os.ReadFile(f.spec.UnitPath())
	if err != nil {
		t.Fatalf("read unit: %v", err)
	}
	src := f.newBinary(t, "NEW BUILD")

	// Deliberately a spec with no Server, which is what an operator upgrading
	// without the original bundle actually has. If Upgrade re-rendered the
	// unit from this, the device would lose its hub URL.
	bare := Spec{
		ServiceName: f.spec.ServiceName,
		BinaryPath:  f.spec.BinaryPath,
		StateDir:    f.spec.StateDir,
		UnitDir:     f.spec.UnitDir,
	}
	if _, err := f.inst.Upgrade(bare, OutputSystemd, UpgradeOptions{Source: src}); err != nil {
		t.Fatalf("Upgrade without a bundle: %v", err)
	}

	unitAfter, err := os.ReadFile(f.spec.UnitPath())
	if err != nil {
		t.Fatalf("read unit after: %v", err)
	}
	if string(unitAfter) != string(unitBefore) {
		t.Error("upgrade rewrote the unit file; it must leave supervision config alone")
	}
	if !strings.Contains(string(unitAfter), f.spec.Server) {
		t.Errorf("the unit lost its control-plane URL %q — the device no longer knows its hub",
			f.spec.Server)
	}
	body, err := os.ReadFile(credential)
	if err != nil {
		t.Fatalf("credential was removed by an upgrade: %v", err)
	}
	if !strings.Contains(string(body), "secret-token") {
		t.Errorf("credential was rewritten by an upgrade: %q", body)
	}
}

// TestUpgradeMissingSourceNamesTheFlag: the most likely operator mistake is
// pointing --from at nothing, and the error has to say which flag to fix.
func TestUpgradeMissingSourceNamesTheFlag(t *testing.T) {
	f := newUpgradeFixture(t, OutputSystemd, "OLD BUILD")

	_, err := f.inst.Upgrade(f.spec, OutputSystemd, UpgradeOptions{
		Source: filepath.Join(f.dir, "does-not-exist"),
	})
	if err == nil {
		t.Fatal("Upgrade succeeded with a nonexistent source binary")
	}
	if !strings.Contains(err.Error(), "--binary") && !strings.Contains(err.Error(), "--from") {
		t.Errorf("error does not name a flag to fix: %v", err)
	}
	if got := f.installed(t); got != "OLD BUILD" {
		t.Errorf("installed binary was touched: %q", got)
	}
}

// TestUpgradeSameFileIsANoOp guards the case that would otherwise delete the
// binary: renaming a file over itself. Reachable when --force is combined with
// running the already-installed binary.
func TestUpgradeSameFileIsANoOp(t *testing.T) {
	f := newUpgradeFixture(t, OutputSystemd, "SAME BUILD")

	res, err := f.inst.Upgrade(f.spec, OutputSystemd, UpgradeOptions{
		Source: f.spec.BinaryPath,
		Force:  true,
	})
	if err != nil {
		t.Fatalf("Upgrade: %v", err)
	}
	if !res.AlreadyCurrent {
		t.Errorf("upgrading a binary from itself was not treated as a no-op: %+v", res)
	}
	if got := f.installed(t); got != "SAME BUILD" {
		t.Errorf("binary corrupted by an upgrade from itself: %q", got)
	}
}
