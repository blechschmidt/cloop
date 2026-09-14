package install

// upgrade_verify_test.go covers the two failures that used to take a device off
// the fleet: installing a binary that cannot run, and installing one that runs
// here but will not stay up there.
//
// The binaries are real files that really get executed. A test that stubbed the
// probe would assert that Upgrade calls a function, which is not the property in
// question — the property is that a truncated download and a wrong-architecture
// copy are *refused*, and the only thing that knows whether a file is either of
// those is the kernel. So the corrupt case is genuinely corrupt bytes, and the
// ancient case is a program that genuinely answers like an old cloop.

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/provenance"
)

// corruptBinary is what a truncated or interrupted download looks like: an ELF
// header with nothing usable behind it. Every kernel this runs on refuses it
// with ENOEXEC, which is the same error a wrong-architecture binary produces —
// so this one file covers both of the task's hardware failure modes.
const corruptBinary = "\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
	"\x02\x00\x3e\x00\x01\x00\x00\x00\xde\xad\xbe\xef"

// ancientCloop renders a build old enough to predate the machine-readable
// version report: it answers plain `version` and fails the --json flag the way
// cobra does for a flag it has never heard of.
func ancientCloop(version string) string {
	return "#!/bin/sh\n" +
		"# cloop-test-marker: ANCIENT\n" +
		"if [ \"$2\" = \"--json\" ]; then echo 'unknown flag: --json' >&2; exit 1; fi\n" +
		"if [ \"$1\" = \"version\" ]; then echo \"cloop " + version + "\"; exit 0; fi\n" +
		"exit 0\n"
}

// TestUpgradeRefusesACorruptBinary is the headline of the second half of Task
// 20252. Hashing a file only ever answered "are these the same bytes"; a
// truncated download passes that and was renamed over a working agent's binary,
// which on a host an operator cannot reach again means a site visit.
func TestUpgradeRefusesACorruptBinary(t *testing.T) {
	f := newUpgradeFixture(t, OutputSystemd, "OLD BUILD")
	src := f.stageBinary(t, corruptBinary)

	res, err := f.inst.Upgrade(f.spec, OutputSystemd, UpgradeOptions{Source: src})
	if err == nil {
		t.Fatal("a binary that cannot execute was installed over a working agent")
	}
	if !errors.Is(err, ErrBinaryUnusable) {
		t.Errorf("error does not wrap ErrBinaryUnusable: %v", err)
	}
	// The raw kernel error is "exec format error", which only means something
	// to a reader who already knows it means "wrong machine".
	if !strings.Contains(err.Error(), "truncated") && !strings.Contains(err.Error(), "architecture") {
		t.Errorf("refusal does not explain what an exec-format failure means: %v", err)
	}

	if got := f.installed(t); got != "OLD BUILD" {
		t.Errorf("the working binary was replaced by an unusable one: %q", got)
	}
	if res.BinaryReplaced || res.Restarted {
		t.Errorf("refused upgrade still mutated the device: %+v", res)
	}
	if len(*f.commands) != 0 {
		t.Errorf("refused upgrade bounced the service: %v", *f.commands)
	}
}

// TestUpgradeRefusesACorruptBinaryEvenWithForce draws the line --force does not
// cross. --force has always meant "replace even though the bytes are
// identical"; letting it also mean "install something proven broken" would
// delete the only check standing between a bad download and an offline device.
func TestUpgradeRefusesACorruptBinaryEvenWithForce(t *testing.T) {
	f := newUpgradeFixture(t, OutputSystemd, "OLD BUILD")
	src := f.stageBinary(t, corruptBinary)

	_, err := f.inst.Upgrade(f.spec, OutputSystemd, UpgradeOptions{Source: src, Force: true})
	if !errors.Is(err, ErrBinaryUnusable) {
		t.Fatalf("--force installed an unusable binary: %v", err)
	}
	if got := f.installed(t); got != "OLD BUILD" {
		t.Errorf("--force replaced the working binary with an unusable one: %q", got)
	}
}

// TestUpgradeRefusesANonCloopBinary: a file that runs perfectly well and is not
// cloop. The likely real cause is a path typo pointing at another tool, and the
// refusal has to say that rather than reporting a successful upgrade.
func TestUpgradeRefusesANonCloopBinary(t *testing.T) {
	f := newUpgradeFixture(t, OutputSystemd, "OLD BUILD")
	src := f.stageBinary(t, "#!/bin/sh\necho 'GNU tar 1.35'\n")

	_, err := f.inst.Upgrade(f.spec, OutputSystemd, UpgradeOptions{Source: src})
	if !errors.Is(err, ErrBinaryUnusable) {
		t.Fatalf("a binary that is not cloop was installed: %v", err)
	}
	if !strings.Contains(err.Error(), "did not identify itself as cloop") {
		t.Errorf("refusal does not say what was wrong with it: %v", err)
	}
	if got := f.installed(t); got != "OLD BUILD" {
		t.Errorf("installed binary was replaced: %q", got)
	}
}

// TestUpgradeRefusesAnAncientBinary is the other half of the task's brief. An
// "upgrade" that silently moves a device backwards is how a fleet ends up
// running builds nobody chose — and the operator has no reason to look, because
// the command reported success.
func TestUpgradeRefusesAnAncientBinary(t *testing.T) {
	f := newUpgradeFixture(t, OutputSystemd, "OLD BUILD") // installed: fixtureVersion, v1.0.0
	src := f.stageBinary(t, ancientCloop("v0.0.1"))

	_, err := f.inst.Upgrade(f.spec, OutputSystemd, UpgradeOptions{Source: src})
	if err == nil {
		t.Fatal("an upgrade silently moved the device backwards to v0.0.1")
	}
	if !errors.Is(err, ErrDowngrade) {
		t.Errorf("error does not wrap ErrDowngrade: %v", err)
	}
	for _, want := range []string{"v0.0.1", fixtureVersion, "--force"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal does not mention %q: %v", want, err)
		}
	}
	if got := f.installed(t); got != "OLD BUILD" {
		t.Errorf("the newer installed binary was replaced by an ancient one: %q", got)
	}
	if len(*f.commands) != 0 {
		t.Errorf("refused downgrade bounced the service: %v", *f.commands)
	}
}

// TestUpgradeForceAllowsADeliberateRollback: refusing outright would send an
// operator backing out a bad release to `cp` and `systemctl`, which bypasses
// every other check in this file. The escape hatch has to exist and has to be in
// the command.
func TestUpgradeForceAllowsADeliberateRollback(t *testing.T) {
	f := newUpgradeFixture(t, OutputSystemd, "OLD BUILD")
	src := f.stageBinary(t, ancientCloop("v0.0.1"))

	res, err := f.inst.Upgrade(f.spec, OutputSystemd, UpgradeOptions{Source: src, Force: true})
	if err != nil {
		t.Fatalf("--force refused a deliberate rollback: %v", err)
	}
	if got := f.installed(t); got != "ANCIENT" {
		t.Errorf("--force did not install the older build: %q", got)
	}
	// The old binary predates `version --json`, so the protocol numbers are
	// unknown — and must be reported as unknown rather than invented.
	if res.StagedBuild.Structured {
		t.Error("claimed a machine-readable report from a build that has none")
	}
	if res.StagedBuild.Version != "v0.0.1" {
		t.Errorf("fell back to the text form but read the wrong version: %q", res.StagedBuild.Version)
	}
}

// TestUpgradeRefusesAProtocolBelowTheControlPlaneFloor covers the refusal that
// the current constants cannot reach: MinProtocolVersion is 1, so no binary can
// report a positive protocol below it.
//
// Tested at checkUpgradeSafety, which takes the floor as a parameter for exactly
// this reason. The check is not dead code — it becomes live the moment the hub
// drops support for an old protocol, which is the scenario in which installing a
// too-old agent silently removes a device from the fleet — and a rule nobody has
// ever executed is a rule that does not work.
func TestUpgradeRefusesAProtocolBelowTheControlPlaneFloor(t *testing.T) {
	staged := BinaryIdentity{Version: "v2.0.0", Protocol: 2, MinProtocol: 1, Structured: true}
	installed := BinaryIdentity{Version: "v1.0.0", Structured: true}

	err := checkUpgradeSafety(staged, installed, 4)
	if err == nil {
		t.Fatal("accepted a binary speaking a protocol the control plane no longer accepts")
	}
	if !errors.Is(err, ErrDowngrade) {
		t.Errorf("error does not wrap ErrDowngrade: %v", err)
	}
	// The consequence, not just the mismatch: the operator has to understand
	// that this takes the device out of the fleet rather than merely warning.
	if !strings.Contains(err.Error(), "hello") && !strings.Contains(err.Error(), "out of the fleet") {
		t.Errorf("refusal does not say what installing it would do: %v", err)
	}

	// A binary that did not report a protocol is not assumed to speak v0. That
	// would refuse every pre-report build on a technicality rather than on the
	// version comparison, which is the check that understands the question.
	silent := BinaryIdentity{Version: "v2.0.0"}
	if err := checkUpgradeSafety(silent, installed, 4); err != nil {
		t.Errorf("a build that reported no protocol was treated as speaking v0: %v", err)
	}
}

// TestUpgradeAllowsAnUnreleasedBuild: a developer testing a fix on a device is
// legitimate and common. "dev+g4f7b5bc" cannot be ordered against a release, and
// refusing what cannot be ordered here would block that — the binary has already
// been shown to run, which is the check that matters.
func TestUpgradeAllowsAnUnreleasedBuild(t *testing.T) {
	f := newUpgradeFixture(t, OutputSystemd, "OLD BUILD")
	src := f.stageBinary(t, fakeCloop("dev+g4f7b5bc.dirty", "DEV BUILD"))

	if _, err := f.inst.Upgrade(f.spec, OutputSystemd, UpgradeOptions{Source: src}); err != nil {
		t.Fatalf("refused an unreleased build: %v", err)
	}
	if got := f.installed(t); got != "DEV BUILD" {
		t.Errorf("installed = %q, want the dev build", got)
	}
}

// TestUpgradeVerifiesDuringADryRun. The stated purpose of --dry-run is to answer
// "will this do what I think" before bouncing a service on a device that may be
// hard to reach. A dry run that skipped the one check capable of saying "no"
// would answer a question nobody asked.
func TestUpgradeVerifiesDuringADryRun(t *testing.T) {
	f := newUpgradeFixture(t, OutputSystemd, "OLD BUILD")
	src := f.stageBinary(t, corruptBinary)

	if _, err := f.inst.Upgrade(f.spec, OutputSystemd, UpgradeOptions{
		Source: src,
		DryRun: true,
	}); !errors.Is(err, ErrBinaryUnusable) {
		t.Fatalf("a dry run reported a corrupt binary as installable: %v", err)
	}

	// And a good one still reports what it found, without changing anything.
	good := f.stageBinary(t, fakeCloop("v1.1.0", "NEW BUILD"))
	res, err := f.inst.Upgrade(f.spec, OutputSystemd, UpgradeOptions{Source: good, DryRun: true})
	if err != nil {
		t.Fatalf("dry run of a good binary: %v", err)
	}
	if !res.Verified || res.StagedBuild.Version != "v1.1.0" {
		t.Errorf("dry run did not report what it verified: %+v", res.StagedBuild)
	}
	if res.BinaryReplaced || len(*f.commands) != 0 {
		t.Errorf("dry run mutated the device: replaced=%v commands=%v",
			res.BinaryReplaced, *f.commands)
	}
	if got := f.installed(t); got != "OLD BUILD" {
		t.Errorf("dry run replaced the binary: %q", got)
	}
}

// TestUpgradeRollsBackWhenTheServiceDoesNotComeBack is the property verification
// cannot deliver on its own. A binary can run here and still fail there — a
// newer libc than the device has, a startup panic on its hardware — and the only
// evidence is a service that will not stay up, by which point the binary that
// worked is gone.
func TestUpgradeRollsBackWhenTheServiceDoesNotComeBack(t *testing.T) {
	f := newUpgradeFixture(t, OutputSystemd, "OLD BUILD")
	src := f.stageBinary(t, fakeCloop("v1.1.0", "BAD BUILD"))

	// Running before the upgrade, dead ever after: the new build starts and
	// immediately exits.
	var restarts, statusChecks int
	f.inst.Run = func(name string, args ...string) error {
		*f.commands = append(*f.commands, strings.TrimSpace(name+" "+strings.Join(args, " ")))
		if len(args) == 0 {
			return nil
		}
		switch args[0] {
		case "is-active":
			statusChecks++
			if statusChecks == 1 {
				return nil // healthy before the upgrade
			}
			return errors.New("inactive")
		case "try-restart", "restart":
			// Both verbs count: the upgrade uses try-restart and the rollback
			// uses restart, and what this counter is asserting is that the
			// service was brought up twice.
			restarts++
		}
		return nil
	}

	res, err := f.inst.Upgrade(f.spec, OutputSystemd, UpgradeOptions{
		Source:        src,
		SettleTimeout: 50 * time.Millisecond,
	})
	if err == nil {
		t.Fatal("the upgrade reported success with the service down")
	}
	if !res.RolledBack {
		t.Errorf("RolledBack = false; the device was left on a build that will not run: %+v", res)
	}
	if got := f.installed(t); got != "OLD BUILD" {
		t.Errorf("installed = %q, want the previous build restored", got)
	}
	// Restored *and* started: leaving the good binary on disk with the service
	// down is not a rollback, it is a different outage.
	if restarts < 2 {
		t.Errorf("the restored binary was never started (restarts=%d)", restarts)
	}
	// And started with `restart`, not the `try-restart` the upgrade uses.
	// try-restart only acts on a unit that is currently running, and the unit
	// being rolled back is by definition one that just failed to stay up — so
	// try-restart would return success having done nothing, leaving the device
	// with the good binary and a stopped agent.
	joined := strings.Join(*f.commands, "\n")
	if !strings.Contains(joined, "systemctl restart cloop-executor.service") {
		t.Errorf("the rollback used try-restart, which is a no-op on a failed unit; commands:\n%s",
			joined)
	}
	if !strings.Contains(err.Error(), "rolled back") ||
		!strings.Contains(err.Error(), "still in the fleet") {
		t.Errorf("the error does not tell the operator the device is safe: %v", err)
	}
	// The backup is consumed by the restore rather than left beside a binary it
	// is now identical to.
	if _, statErr := os.Stat(backupPath(f.spec.BinaryPath)); !os.IsNotExist(statErr) {
		t.Errorf("the backup survived a completed rollback: %v", statErr)
	}
}

// TestUpgradeDoesNotRollBackAServiceThatWasAlreadyStopped. systemd's try-restart
// succeeds whether or not it restarted anything, so after the fact a
// deliberately stopped service is indistinguishable from one that crashed on the
// new build. Rolling back on that would revert a good upgrade every time it
// landed on a stopped agent — including every device installed with --no-start.
func TestUpgradeDoesNotRollBackAServiceThatWasAlreadyStopped(t *testing.T) {
	f := newUpgradeFixture(t, OutputSystemd, "OLD BUILD")
	src := f.stageBinary(t, fakeCloop("v1.1.0", "NEW BUILD"))

	f.inst.Run = func(name string, args ...string) error {
		*f.commands = append(*f.commands, strings.TrimSpace(name+" "+strings.Join(args, " ")))
		if len(args) > 0 && args[0] == "is-active" {
			return errors.New("inactive") // stopped before and after
		}
		return nil
	}

	start := time.Now()
	res, err := f.inst.Upgrade(f.spec, OutputSystemd, UpgradeOptions{
		Source:        src,
		SettleTimeout: 10 * time.Second,
	})
	if err != nil {
		t.Fatalf("Upgrade on a stopped service: %v", err)
	}
	if res.RolledBack {
		t.Error("rolled back an upgrade on a service that was never running")
	}
	if got := f.installed(t); got != "NEW BUILD" {
		t.Errorf("installed = %q, want the new build in place for the next start", got)
	}
	// And it did not sit out the settle budget to discover that.
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("waited %s for a service that was not running", elapsed)
	}
}

// TestUpgradeKeepsThePreviousBinary. The kept copy is the operator's manual
// escape hatch after the command has already returned, so it has to be at a
// predictable path and named in the result.
func TestUpgradeKeepsThePreviousBinary(t *testing.T) {
	f := newUpgradeFixture(t, OutputSystemd, "OLD BUILD")
	src := f.stageBinary(t, fakeCloop("v1.1.0", "NEW BUILD"))

	res, err := f.inst.Upgrade(f.spec, OutputSystemd, UpgradeOptions{Source: src})
	if err != nil {
		t.Fatalf("Upgrade: %v", err)
	}
	if res.BackupPath == "" {
		t.Fatal("the upgrade reported no backup path")
	}
	body, err := os.ReadFile(res.BackupPath)
	if err != nil {
		t.Fatalf("read the kept binary: %v", err)
	}
	if got := markerOf(string(body)); got != "OLD BUILD" {
		t.Errorf("the kept binary is %q, not the one that was replaced", got)
	}
	// Executable, or a manual rollback by an operator who copies it back would
	// produce a service that cannot start.
	st, err := os.Stat(res.BackupPath)
	if err != nil {
		t.Fatalf("stat backup: %v", err)
	}
	if got := st.Mode().Perm(); got != BinaryMode {
		t.Errorf("backup mode = %04o, want %04o", got, BinaryMode)
	}
	// One generation, not one per upgrade: a device with a small root
	// filesystem must not fill up from routine rollouts.
	if dir, base := filepath.Split(res.BackupPath); base != filepath.Base(f.spec.BinaryPath)+backupSuffix {
		t.Errorf("backup landed at an unpredictable name %q in %s", base, dir)
	}
}

// TestUpgradeReportsAFailedRollback is the outcome that needs a human on the
// device. It must not be reported in the same register as an ordinary failure,
// because the operator's response is different: go there.
func TestUpgradeReportsAFailedRollback(t *testing.T) {
	f := newUpgradeFixture(t, OutputSystemd, "OLD BUILD")
	src := f.stageBinary(t, fakeCloop("v1.1.0", "BAD BUILD"))

	var restarts, statusChecks int
	f.inst.Run = func(name string, args ...string) error {
		if len(args) == 0 {
			return nil
		}
		switch args[0] {
		case "is-active":
			statusChecks++
			if statusChecks == 1 {
				return nil
			}
			return errors.New("inactive")
		case "try-restart", "restart":
			restarts++
			if restarts > 1 {
				// The restore's own start fails too.
				return errors.New("Job for cloop-executor.service failed")
			}
		}
		return nil
	}

	_, err := f.inst.Upgrade(f.spec, OutputSystemd, UpgradeOptions{
		Source:        src,
		SettleTimeout: 50 * time.Millisecond,
	})
	if err == nil {
		t.Fatal("a failed rollback was reported as success")
	}
	if !strings.Contains(err.Error(), "manual recovery") {
		t.Errorf("the error does not say a human is needed: %v", err)
	}
	// Both causes, because the second without the first is unactionable.
	if !strings.Contains(err.Error(), "The upgrade failed") ||
		!strings.Contains(err.Error(), "The rollback also failed") {
		t.Errorf("the error does not carry both failures: %v", err)
	}
}

// TestStagedInstallSkipsVerificationRatherThanFailing. A staged install builds a
// tree for a different machine, whose binary may legitimately not run on this
// one — the same rule that stops Installer.run touching this host's systemd.
// Skipped, and reported as skipped: silence would read as "checked and good".
func TestStagedInstallSkipsVerificationRatherThanFailing(t *testing.T) {
	// Provenance is a separate question, and a staged install gets no pass on
	// it — see TestStagedInstallStillVerifiesProvenance. Stubbed to accept so
	// this test stays about the executability check it was written for.
	stubProvenance(t, 0, "")
	root := t.TempDir()
	spec := Spec{
		ServiceName: "cloop-executor",
		BinaryPath:  "/usr/local/bin/cloop",
		StateDir:    "/var/lib/cloop-executor",
		UnitDir:     "/etc/systemd/system",
		Server:      "wss://hub.example:8888/api/executors/connect",
	}
	norm, err := spec.Normalize()
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	inst := &Installer{Root: root, Logf: func(string, ...any) {}}
	mustWrite(t, filepath.Join(root, norm.BinaryPath), "OLD ARM BINARY", BinaryMode)
	mustWrite(t, filepath.Join(root, norm.UnitPath()), SystemdUnit(norm), UnitFileMode)

	// Bytes no local kernel would execute — exactly the legitimate case.
	src := filepath.Join(t.TempDir(), "cloop-arm64")
	mustWrite(t, src, corruptBinary, BinaryMode)
	mustWrite(t, provenance.BundleNameFor(src), "{}", 0o644)

	res, err := inst.Upgrade(norm, OutputSystemd, UpgradeOptions{Source: src})
	if err != nil {
		t.Fatalf("a staged install refused a binary for another architecture: %v", err)
	}
	if res.Verified {
		t.Error("Verified = true, but a staged install cannot execute the candidate")
	}
	if !res.BinaryReplaced {
		t.Error("the staged tree did not receive the new binary")
	}
}

// TestIdentifyPrefersTheStructuredReport. The fallback exists for old builds; if
// it were taken for current ones the protocol numbers would be silently absent
// and the control-plane floor check would never fire.
func TestIdentifyPrefersTheStructuredReport(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cloop")
	mustWrite(t, path, fakeCloop("v1.4.2", "X"), BinaryMode)

	inst := &Installer{Logf: func(string, ...any) {}}
	id, err := inst.identify(path)
	if err != nil {
		t.Fatalf("identify: %v", err)
	}
	if !id.Structured {
		t.Error("fell back to text parsing for a binary that offers --json")
	}
	if id.Version != "v1.4.2" || id.Protocol != 6 || id.MinProtocol != 1 {
		t.Errorf("identity = %+v, want v1.4.2 / protocol 6 / min 1", id)
	}
}
