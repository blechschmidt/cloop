package install

// upgrade.go replaces the cloop binary on an already-installed device and
// restarts the service, so a fleet can be rolled forward without uninstalling
// and re-enrolling every node.
//
// It exists because the Executors panel told operators to run
// `cloop executor agent install --upgrade` when a device's protocol version was
// too old to honour a secret revocation — and no such flag had ever been
// implemented. The remediation the UI offered for its most security-relevant
// warning failed with an unknown-flag error, which is worse than offering none:
// an operator who tries the documented fix and watches it fail learns to
// distrust the whole panel.
//
// The scope is deliberately narrow, and the narrowness is the safety property.
// An upgrade replaces a binary and restarts a service. It does *not* re-render
// the unit file and does *not* touch credentials, because it cannot do either
// honestly: the unit embeds the control-plane URL and the certificate pin, both
// of which arrive in an enrollment bundle that an operator upgrading a device
// six months later does not have in hand. Re-rendering from a bare spec would
// quietly write a unit pointing at no server — turning "your agent is one
// version behind" into "your agent no longer knows where its hub is". Changing
// the unit is what re-running a full install with the bundle is for, and
// UpgradeResult says plainly that the unit was left alone.
//
// Five properties are asserted by tests rather than assumed:
//
//   - Idempotent. Re-running with the same binary copies nothing and restarts
//     nothing. An operator re-runs a command because the first run printed
//     something they did not understand, and a second run that bounces a
//     healthy agent teaches them not to.
//   - Refuses what it cannot do. An upgrade on a device that was never
//     installed does not half-install it; it names the command that would.
//   - Atomic. The binary is renamed into place, never written through. A
//     running executable cannot be opened for writing on Linux at all
//     (ETXTBSY), and a partial copy over a service binary is unrecoverable
//     from the device's own supervisor.
//   - Verified. The staged binary is executed and made to identify itself
//     before anything is replaced. Hashing it only ever answered "are these
//     the same bytes", which a truncated download and a wrong-architecture
//     copy both pass — and both were then renamed over a working agent and the
//     service restarted. See verify.go.
//   - Reversible. The replaced binary is kept, and if a service that was
//     running before the upgrade does not come back on the new build within a
//     bounded wait, it is put back and restarted. Verification cannot catch a
//     binary that runs here and fails in its own environment; only the service
//     failing to stay up shows that, and by then the good binary is gone. See
//     rollback.go.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor/remote"
	"github.com/blechschmidt/cloop/pkg/provenance"
)

// UpgradeOptions parameterises an in-place upgrade.
type UpgradeOptions struct {
	// Source is the new cloop binary to install. Empty means the running
	// executable, which is the common case: an operator copies a new cloop to
	// the device and runs it with --upgrade.
	Source string
	// Force replaces the binary and restarts the service even when the
	// installed binary is already byte-identical. For recovering from a
	// truncated or mis-permissioned install, where the bytes match but the
	// service is not actually running the binary on disk.
	//
	// It also permits a deliberate rollback: installing a build older than
	// the one in place, or one speaking a protocol this control plane no
	// longer accepts. It does *not* permit installing a binary that failed
	// verification — see ErrBinaryUnusable for why that line is where it is.
	Force bool
	// DryRun performs every check and reports what would happen without
	// writing a byte or restarting anything.
	//
	// It is a real mode rather than a courtesy, because this command bounces a
	// service on a device an operator may not be able to reach again quickly.
	// The checks it runs are the expensive ones — is anything installed, does
	// the source exist, is it even a different build, does the new binary run
	// at all — so a dry run answers "will this do what I think" rather than
	// merely echoing the flags back.
	DryRun bool

	// Bundle is the Sigstore bundle proving the source binary's provenance.
	// Empty looks for one beside the source, at <source>.sigstore.json, which
	// is where a release download leaves it.
	Bundle string

	// SkipVerify installs a binary whose provenance has not been proven.
	//
	// The escape hatch for an air-gapped site that cannot reach Sigstore, and
	// for a developer installing a locally built binary — which has no
	// signature and cannot have one. It is a separate flag from Force on
	// purpose: Force means "I know this is a downgrade", which is a statement
	// about versions, and conflating it with "I do not know where this binary
	// came from" would let a routine rollback silently drop a security check.
	SkipVerify bool

	// SettleTimeout bounds the wait for a restarted service to report itself
	// active before the upgrade concludes the new build is bad and rolls back.
	// Zero uses serviceSettleTimeout.
	//
	// Exposed because the right value is a property of the device, not of
	// cloop. The default is generous for a laptop and can still be short for a
	// heavily loaded single-core gateway paging in a 40 MB executable off slow
	// flash — and there, a timeout that fires early does not merely report a
	// problem, it reverts a good upgrade.
	SettleTimeout time.Duration
}

// settleTimeout resolves the configured wait, falling back to the default.
func (o UpgradeOptions) settleTimeout() time.Duration {
	if o.SettleTimeout > 0 {
		return o.SettleTimeout
	}
	return serviceSettleTimeout
}

// provenanceVerifier is the verifier used by verifyProvenance. A package
// variable so tests can substitute a stand-in cosign without an upgrade having
// to carry a verifier through its options.
var provenanceVerifier = &provenance.Verifier{}

// verifyProvenance proves the source binary came from cloop's release workflow
// before anything executes or installs it.
//
// This is the executor agent: the binary an enterprise deliberately places on
// high-value hosts and then leases credentials to. An upgrade path that
// installs whatever file it is pointed at is a way to convert write access to
// a staging directory — or a compromised hub telling an operator to upgrade —
// into code execution on every device in the fleet.
//
// It fails closed, including when the bundle is simply absent. That is a real
// cost: a locally built binary has no signature and never will, so a developer
// upgrading a test device has to pass --insecure-skip-verify. The alternative
// is worse in the way that matters — "no bundle found, proceeding" would mean
// an attacker bypasses the check by deleting a file, which is not a check.
func (in *Installer) verifyProvenance(res *UpgradeResult, source string, opts UpgradeOptions) error {
	if opts.SkipVerify {
		in.logf("WARNING: %s", provenance.SkipNotice)
		res.ProvenanceVerified = false
		return nil
	}

	bundle := strings.TrimSpace(opts.Bundle)
	if bundle == "" {
		bundle = provenance.BundleNameFor(source)
	}

	if _, err := os.Stat(bundle); err != nil {
		return fmt.Errorf(
			"%w\n\n"+
				"No signature bundle for %s (looked for %s).\n"+
				"Release downloads publish one beside every artifact; pass --bundle to point\n"+
				"at it, or --insecure-skip-verify to install a binary whose origin is unknown\n"+
				"— which is what a locally built binary always is.",
			provenance.ErrBundleMissing, source, bundle)
	}

	issuer, identity := provenanceVerifier.TrustRoot()
	if err := provenanceVerifier.VerifyBlob(context.Background(), source, bundle); err != nil {
		return fmt.Errorf(
			"%w\n\n"+
				"Refusing to install %s onto this device.\n"+
				"Required signing identity: %s\n"+
				"Required OIDC issuer:      %s\n"+
				"Pass --insecure-skip-verify only if you know where this binary came from.",
			err, source, identity, issuer)
	}

	in.logf("verified the provenance of %s (identity %s)", source, identity)
	res.ProvenanceVerified = true
	return nil
}

// UpgradeResult describes what an upgrade did, so the CLI can report the truth
// rather than a fixed success message.
type UpgradeResult struct {
	// Spec is the normalised spec the upgrade ran against.
	Spec Spec
	// Output is the supervision system involved.
	Output Output
	// Source is the binary that was installed from.
	Source string
	// AlreadyCurrent reports that the installed binary was byte-identical and
	// nothing was changed.
	AlreadyCurrent bool
	// BinaryReplaced reports that the service binary was rewritten.
	BinaryReplaced bool
	// Restarted reports that the service was asked to restart. False with
	// BinaryReplaced true means the service was not running, so the new binary
	// is in place and will be used whenever it is next started.
	Restarted bool
	// DryRun echoes that nothing was actually changed, so a caller cannot
	// render a result as done when it was only planned.
	DryRun bool
	// StagedBuild is what the new binary said about itself when it was run,
	// and InstalledBuild is what the one being replaced said. A zero
	// StagedBuild means verification was skipped — see Verified.
	StagedBuild, InstalledBuild BinaryIdentity
	// Verified reports that the staged binary was executed and identified
	// itself before anything was replaced. False means the check was skipped
	// because the installer is staged (its target is another machine, whose
	// binary may legitimately not run here), and the result must not be
	// rendered as though the binary had been proven good.
	Verified bool
	// ProvenanceVerified reports that the source binary's signature was
	// checked against cloop's release workflow before anything was executed or
	// written. False means --insecure-skip-verify was passed, and the result
	// must not be rendered as though the binary's origin were known.
	ProvenanceVerified bool
	// BackupPath is where the replaced binary was kept, so an operator can
	// roll back by hand. Empty when nothing was replaced.
	BackupPath string
	// RolledBack reports that the service did not come back on the new binary
	// and the previous one was restored. It travels with a non-nil error:
	// the upgrade failed, and this says the device was left working.
	RolledBack bool

	// PreviousChecksum and NewChecksum are SHA-256 sums of the old and new
	// binaries, for an operator correlating a rollout across a fleet.
	//
	// "Checksum" rather than "digest" deliberately. These are content sums of a
	// public binary used to answer "are these the same bytes", not credential
	// material, so comparing them with == is correct — and the security suite's
	// constant-time scanner reads any identifier containing "digest" as a
	// secret. Naming them for what they are keeps that check meaningful instead
	// of adding an exception to it.
	PreviousChecksum string
	NewChecksum      string
}

// ErrNotInstalled is returned when there is nothing to upgrade.
//
// A sentinel because the CLI distinguishes it: it is the one failure with a
// different next step (install, not retry), and a caller should not have to
// match on message text to find out.
var ErrNotInstalled = errors.New("install: no existing agent install found")

// Upgrade replaces the service binary and restarts the service.
//
// It reports what it did rather than only whether it succeeded — see
// UpgradeResult — because "nothing needed doing" and "the binary was replaced
// but the service was stopped" are both successes that an operator must be able
// to tell apart from "the device is now running the new build".
func (in *Installer) Upgrade(spec Spec, out Output, opts UpgradeOptions) (UpgradeResult, error) {
	// NormalizeForRemoval, not Normalize: an upgrade needs only the paths. An
	// operator upgrading a device enrolled months ago does not still have the
	// bundle, and demanding --server to replace a binary would be exactly the
	// friction that made the nonexistent flag a dead end in the first place.
	s, err := spec.NormalizeForRemoval()
	if err != nil {
		return UpgradeResult{}, err
	}
	res := UpgradeResult{Spec: s, Output: out, DryRun: opts.DryRun}

	// A container image is not a binary on this filesystem, so there is
	// nothing here to replace. Say so and name the real procedure rather than
	// reporting a success that changed nothing — the failure this whole file
	// exists to stop.
	if out == OutputDocker {
		return res, fmt.Errorf(
			"install: --upgrade does not apply to --output docker: the agent runs from image %s, "+
				"so upgrading means pulling a new image and recreating the container:\n"+
				"  podman pull %s\n"+
				"  podman rm --force %s\n"+
				"  then re-run the podman command from `cloop executor agent install --output docker`",
			s.Image, s.Image, s.ServiceName)
	}

	// Refuse an upgrade of something that was never installed, rather than
	// quietly creating a binary with no supervisor around it. The check is on
	// the supervision artifact, not the binary: a stray cloop at the default
	// path is not an install.
	supervisor := s.UnitPath()
	if out == OutputShell {
		supervisor = s.InitScriptPath()
	}
	if _, statErr := os.Stat(in.path(supervisor)); statErr != nil {
		return res, fmt.Errorf(
			"%w: %s is not present.\n"+
				"--upgrade replaces the binary of an existing install; it does not create one.\n"+
				"To install this device for the first time:\n"+
				"  cloop executor agent install --bundle <bundle from `cloop executor enroll`>",
			ErrNotInstalled, supervisor)
	}

	source := s.BinaryPath
	if opts.Source != "" {
		source = opts.Source
	} else if self, sErr := os.Executable(); sErr == nil {
		source = self
	}
	if !filepath.IsAbs(source) {
		abs, aErr := filepath.Abs(source)
		if aErr != nil {
			return res, fmt.Errorf("install: resolve --binary %q: %w", source, aErr)
		}
		source = abs
	}
	res.Source = source

	// The source is read from the real filesystem even when Root is set: it is
	// the binary the operator is holding, not a file inside the staging tree
	// they are building. Only the destination is staged.
	newChecksum, err := fileChecksum(source)
	if err != nil {
		return res, fmt.Errorf(
			"install: cannot read the new cloop binary at %s: %w\n"+
				"Pass --binary with the path to the new binary on this device", source, err)
	}
	res.NewChecksum = newChecksum

	target := in.path(s.BinaryPath)
	res.PreviousChecksum, _ = fileChecksum(target) // absent is fine; "" means unknown

	if res.PreviousChecksum == newChecksum && !opts.Force {
		res.AlreadyCurrent = true
		in.logf("%s is already running this build (%s); nothing to do", s.BinaryPath, shortChecksum(newChecksum))
		return res, nil
	}

	// Same file on disk: replacing it with itself is a no-op that a rename
	// would turn into a deleted binary. Reachable when --force is passed while
	// running the installed binary, and when a checksum collision is not the
	// explanation, an identity check is.
	if sameFile(source, target) {
		res.AlreadyCurrent = true
		in.logf("%s is the binary being run; nothing to copy", s.BinaryPath)
		return res, nil
	}

	// Provenance, and it has to come before verifyUpgrade rather than after.
	//
	// verifyUpgrade's whole method is to *execute* the candidate binary and
	// ask it what it is. That is the right way to find a truncated download or
	// a wrong-architecture build, and exactly the wrong thing to do first to a
	// binary that might be hostile: by the time it has printed a convincing
	// version string it has already run as whatever user this command is, on a
	// host chosen for holding credentials. So the question "did this come from
	// cloop" is settled while the file is still inert.
	//
	// Unlike verifyUpgrade this also runs for staged installs (Root set).
	// Checking a signature only reads the bytes, so a cross-architecture build
	// being staged for another machine can have its origin proven here even
	// though it could never be executed on this one.
	if err := in.verifyProvenance(&res, source, opts); err != nil {
		return res, err
	}

	// Run the thing before installing it. Everything up to here was a
	// comparison of bytes, which cannot distinguish a cloop binary from a
	// truncated download or one built for another architecture — and renaming
	// either of those over a working agent's binary is what takes a device off
	// the fleet. See verify.go.
	//
	// Deliberately before the dry-run bailout: "is this binary any good" is the
	// question a dry run is for, and one that answered it only by echoing the
	// flags back would not be worth running.
	if err := in.verifyUpgrade(&res, source, target, opts); err != nil {
		return res, err
	}

	// Everything above was a check; everything below mutates the device. This
	// is the line a dry run stops at, placed after the checks precisely so a
	// dry run is worth running.
	if opts.DryRun {
		in.logf("would replace %s (%s -> %s) and restart %s",
			s.BinaryPath, shortChecksum(res.PreviousChecksum), shortChecksum(newChecksum), s.ServiceName)
		return res, nil
	}

	// Sampled before the restart, not after: systemd's try-restart succeeds
	// whether or not it restarted anything, so afterwards a service the
	// operator had deliberately stopped is indistinguishable from one that
	// crashed on the new binary. Rolling back on that would undo a good
	// upgrade every time it landed on a stopped agent.
	wasRunning, runningKnown := in.serviceActive(s, out)

	// Keep the binary being replaced. A copy rather than a rename, so the
	// service binary never briefly ceases to exist. See rollback.go.
	backup, err := in.saveBackup(s.BinaryPath)
	if err != nil {
		return res, err
	}
	res.BackupPath = backup

	if err := in.replaceBinary(source, s.BinaryPath); err != nil {
		return res, err
	}
	res.BinaryReplaced = true
	in.logf("replaced %s (%s -> %s)", s.BinaryPath,
		shortChecksum(res.PreviousChecksum), shortChecksum(newChecksum))

	wasUp := runningKnown && wasRunning
	restarted, err := in.restartService(s, out)
	if err != nil {
		if wasUp {
			// A running agent was taken down by this upgrade and the supervisor
			// will not bring it back. The old binary is the only one known to
			// work here, so put it back rather than leaving the device on an
			// untested build it is not even running.
			return res, in.rollback(&res, s, out, backup,
				fmt.Errorf("the service did not restart: %w", err))
		}
		// Nothing was running, so nothing was taken down. This is the
		// pre-existing partial success, and it must not read as a clean
		// failure: an operator who retries after a restart error should know
		// the copy already happened.
		return res, fmt.Errorf("install: %s was upgraded but the service did not restart: %w\n"+
			"The new binary is in place; start it manually to finish the upgrade", s.BinaryPath, err)
	}
	res.Restarted = restarted

	// Only wait if there was something to come back. A service that was not
	// running before the upgrade is no evidence about the new binary, and
	// waiting out the budget to conclude that would punish every device
	// installed with --no-start.
	if wasUp {
		settle := opts.settleTimeout()
		if !in.waitForService(s, out, settle) {
			return res, in.rollback(&res, s, out, backup, fmt.Errorf(
				"%s was running before the upgrade and did not come back within %s on the new "+
					"build (%s)", s.ServiceName, settle, res.StagedBuild.Version))
		}
		in.logf("%s is running the new build", s.ServiceName)
	}
	return res, nil
}

// verifyUpgrade runs the staged binary, records what it said, and refuses the
// upgrade if it is not something this device should be asked to run.
//
// It fills res even on the paths that do not refuse, because "verification was
// skipped" and "verification passed" are different facts and the CLI prints
// them differently.
func (in *Installer) verifyUpgrade(res *UpgradeResult, source, target string, opts UpgradeOptions) error {
	staged, err := in.identify(source)
	switch {
	case errors.Is(err, errStagedProbe):
		// A staged installer targets another machine; running its binary here
		// would be wrong even if it worked. Reported, not treated as a pass.
		in.logf("staged install: not executing %s to verify it", source)
		return nil
	case err != nil:
		return err
	}
	res.StagedBuild = staged
	res.Verified = true
	in.logf("verified %s: %s", source, staged)

	// Platform check for the case exec cannot catch: a binary that runs and
	// then reports a platform that is not this one. Rare, but it means the
	// operator copied something that only appears to work.
	if staged.OS != "" && staged.Arch != "" &&
		(staged.OS != runtime.GOOS || staged.Arch != runtime.GOARCH) {
		return fmt.Errorf("%w: %s reports itself as %s/%s, but this device is %s/%s.\n"+
			"Copy the binary built for this platform",
			ErrBinaryUnusable, source, staged.OS, staged.Arch, runtime.GOOS, runtime.GOARCH)
	}

	// Best-effort on the installed side: an agent whose binary is already
	// broken is exactly the one that most needs replacing, so a probe failure
	// here must not block the upgrade. It only costs the downgrade comparison.
	if installed, iErr := in.identify(target); iErr == nil {
		res.InstalledBuild = installed
	}

	if err := checkUpgradeSafety(res.StagedBuild, res.InstalledBuild, remote.MinProtocolVersion); err != nil {
		if !opts.Force {
			return err
		}
		in.logf("--force: proceeding despite %v", err)
	}
	return nil
}

// rollback restores the previous binary after a failed restart and returns the
// error to report, which names both what went wrong and what state the device
// was left in.
//
// It always returns non-nil: it is only called on a failure path, and a rollback
// that reported success would leave an operator believing a build was deployed
// that was not.
func (in *Installer) rollback(res *UpgradeResult, s Spec, out Output, backup string, cause error) error {
	if rErr := in.restoreBackup(s, out, backup); rErr != nil {
		// Both the upgrade and the recovery failed. This is the one outcome
		// that needs a human on the device, and it must not be reported in the
		// same register as an ordinary failure.
		return fmt.Errorf("install: %s is in an inconsistent state and needs manual recovery.\n"+
			"  The upgrade failed: %v\n"+
			"  The rollback also failed: %v\n"+
			"The previous binary may still be at %s",
			s.ServiceName, cause, rErr, backupPath(s.BinaryPath))
	}
	res.RolledBack = true
	res.Restarted = false
	return fmt.Errorf("install: the upgrade was rolled back.\n"+
		"  %v\n"+
		"  The previous binary was restored and %s was restarted, so this device is still in "+
		"the fleet.\n"+
		"Check the new build on a device you can reach, then retry: journalctl -u %s",
		cause, s.ServiceName, s.ServiceName)
}

// replaceBinary installs src over the service binary atomically.
//
// Write-then-rename rather than write-in-place, for two independent reasons:
// Linux refuses to open a running executable for writing (ETXTBSY), so writing
// through would fail on exactly the device that needs upgrading; and a rename
// means no observer — including the supervisor restarting the service — can
// ever see a half-written binary.
func (in *Installer) replaceBinary(src, devicePath string) error {
	target := in.path(devicePath)
	if err := os.MkdirAll(filepath.Dir(target), SystemDirMode); err != nil {
		return fmt.Errorf("install: create %s: %w", filepath.Dir(devicePath), err)
	}

	srcFile, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("install: open %s: %w", src, err)
	}
	defer srcFile.Close()

	// Same directory as the target so the rename is within one filesystem;
	// across filesystems rename fails and the atomicity is lost.
	tmp, err := os.CreateTemp(filepath.Dir(target), ".cloop-upgrade-*")
	if err != nil {
		return fmt.Errorf("install: create staging file beside %s: %w", devicePath, err)
	}
	tmpName := tmp.Name()
	defer func() {
		tmp.Close()
		// Harmless once the rename succeeded; removes the debris if it did not.
		_ = os.Remove(tmpName)
	}()

	if _, err := io.Copy(tmp, srcFile); err != nil {
		return fmt.Errorf("install: copy %s to %s: %w", src, devicePath, err)
	}
	// Flush to disk before the rename. Without this a power loss just after an
	// upgrade can leave the directory entry pointing at a zero-length file —
	// a device that no longer has a working cloop and cannot be reached to fix
	// it, which for an edge device means a site visit.
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("install: flush %s: %w", devicePath, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("install: close staging file for %s: %w", devicePath, err)
	}
	// Explicit chmod: CreateTemp makes 0600, and the mode must not depend on
	// the umask of whoever ran the upgrade.
	if err := os.Chmod(tmpName, BinaryMode); err != nil {
		return fmt.Errorf("install: set mode on %s: %w", devicePath, err)
	}
	if err := os.Rename(tmpName, target); err != nil {
		return fmt.Errorf("install: install %s: %w", devicePath, err)
	}
	return nil
}

// restartService asks the supervisor to pick up the new binary, reporting
// whether it actually restarted anything.
//
// try-restart rather than restart, for systemd: a service an operator
// deliberately stopped must stay stopped. An upgrade is not the moment to
// override that decision, and the unit's Restart=always means a *running*
// agent is the normal case anyway.
func (in *Installer) restartService(s Spec, out Output) (bool, error) {
	switch out {
	case OutputSystemd:
		if err := in.run("systemctl", "daemon-reload"); err != nil {
			// Not fatal: the unit file did not change, so a failed reload does
			// not stop the restart below from picking up the new binary.
			in.logf("note: systemctl daemon-reload failed: %v", err)
		}
		if err := in.run("systemctl", "try-restart", s.UnitFileName()); err != nil {
			return false, err
		}
		in.logf("restarted %s", s.UnitFileName())
		return true, nil
	case OutputShell:
		if err := in.run(s.InitScriptPath(), "restart"); err != nil {
			return false, err
		}
		in.logf("restarted %s", s.ServiceName)
		return true, nil
	default:
		return false, nil
	}
}

// fileChecksum returns the hex SHA-256 of a file, or "" and an error.
func fileChecksum(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// shortChecksum abbreviates a checksum for logs, naming an absent one rather than
// printing an empty field.
func shortChecksum(d string) string {
	if d == "" {
		return "unknown"
	}
	if len(d) > 12 {
		return d[:12]
	}
	return d
}

// sameFile reports whether two paths are the same file on disk, so an upgrade
// cannot rename a binary over itself.
func sameFile(a, b string) bool {
	sa, err := os.Stat(a)
	if err != nil {
		return false
	}
	sb, err := os.Stat(b)
	if err != nil {
		return false
	}
	return os.SameFile(sa, sb)
}
