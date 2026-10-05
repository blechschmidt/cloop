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
// UpgradeResult says plainly that the unit was left alone. The firewall grant
// is the one exception, and only when asked for: it is a drop-in beside the
// unit precisely so an upgrade can add or remove it (see packetfilter.go).
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
	"github.com/blechschmidt/cloop/pkg/version"
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
	// verification — see ErrBinaryUnusable for why that line is where it is —
	// nor one earlier on main than the installed binary, which takes
	// AllowRollback.
	Force bool

	// AllowRollback permits installing a build whose sequence is lower than
	// the installed binary's, or one carrying none when the installed binary
	// does (ErrRollback, Task 20380).
	//
	// It is not Force, because Force arrives from places that must not be able
	// to do this: the upgrade request the agent files for the root helper, and
	// the upgrade frame the hub sends an agent running as root, both carry a
	// force flag, and a compromised agent or hub could set either. Only the
	// CLI sets this, from --force on an `install --upgrade` run by root on the
	// device — never from --apply-request, whose target the request names.
	AllowRollback bool
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

	// ProvenanceEstablished states that the caller has already proven this
	// binary's provenance against a signed artifact, and that there is
	// therefore no bundle to find beside it (Task 20331).
	//
	// It exists for exactly one caller: a remote agent upgrading itself. The
	// release signs the *archive*, not the executable inside it, so by the time
	// pkg/upgrade has verified the signature and extracted the binary there is
	// no bundle that would match the extracted file — the check has already
	// happened, one layer up, and cannot be repeated here.
	//
	// It is deliberately not spelled as SkipVerify. Reusing that flag would
	// work and would be a lie in two directions: it would print a warning
	// saying provenance was not checked when it was, and it would record
	// ProvenanceVerified=false in the result an operator reads afterwards.
	// Distinguishing "verified elsewhere" from "not verified" is the difference
	// between an audit trail and a plausible one.
	//
	// Like SkipVerify, this is settable only in-process. Nothing an agent
	// receives from the control plane reaches it; see the security argument in
	// pkg/executor/remote/upgradeproto.go.
	ProvenanceEstablished bool

	// PacketFilter grants or withdraws the packet-filter drop-in (Task 20352)
	// as part of the upgrade. The zero value leaves it as the device has it.
	//
	// It is how a device installed before the installer granted CAP_NET_ADMIN
	// gets the grant without the enrollment bundle a full install needs, and it
	// applies even when the binary is already current: the drop-in is written,
	// systemd reloaded, and the agent restarted, with the same rollback as a
	// binary swap if it does not come back.
	PacketFilter PacketFilterChange

	// Channel moves the device to another update channel (Task 20376): edge
	// writes the channel drop-in, stable removes it, empty keeps it. Like the
	// packet filter it applies even when the binary is current, and it is
	// decided here, on the device — the hub has no way to set it.
	Channel provenance.Channel

	// RemoteUpgrade installs or removes the root helper that carries out an
	// upgrade the hub asks for (remoteupgrade.go). The zero value keeps it.
	RemoteUpgrade RemoteUpgradeChange

	// ExpectVersion, when set, is the version the staged binary must report
	// when it is run. An edge build's signed manifest names it (Task 20376):
	// the signature proves edge.yml built *a* commit, the manifest says which,
	// and this is what proves the bytes being installed are that build rather
	// than another genuine one renamed. Unlike a downgrade, a mismatch is not
	// overridable by Force.
	ExpectVersion string

	// ExpectCommit and ExpectSequence are the rest of what the signed manifest
	// says about the build (Task 20380): the full commit it was made from and
	// that commit's place on main. Checked whenever ExpectVersion is set,
	// against what the binary reports when it is run, and not overridable: a
	// validly signed manifest for one commit paired with a binary of another
	// is refused even when the versions happen to agree. ExpectSequence zero
	// means the manifest names none (schema 1), and then the binary must carry
	// none either.
	ExpectCommit   string
	ExpectSequence int

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

	// Checked after SkipVerify so the two cannot disagree: if a caller somehow
	// set both, the honest answer is the weaker one, and reporting "verified"
	// because the stronger-sounding field won would be the one outcome this
	// flag exists to prevent.
	if opts.ProvenanceEstablished {
		res.ProvenanceVerified = true
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
	// BinaryCurrent reports that the installed binary was already this build,
	// so none was copied — whether or not something else, the packet-filter
	// drop-in, changed.
	BinaryCurrent bool
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

	// PacketFilterChanged reports that the upgrade wrote or removed the
	// packet-filter drop-in, and PacketFilterChange says how, for the log.
	PacketFilterChanged bool
	PacketFilterChange  string
	// PacketFilterGranted reports whether the device's unit grants the agent
	// what installing a sandbox firewall takes, once the upgrade is done. Only
	// meaningful for OutputSystemd.
	PacketFilterGranted bool

	// ChannelChanged reports that the upgrade moved the device to another
	// update channel, and Channel is the channel it follows afterwards.
	ChannelChanged bool
	Channel        provenance.Channel
	// RemoteUpgradeChanged reports that the upgrade installed or removed the
	// remote-upgrade helper, and RemoteUpgradeInstalled whether the device has
	// it afterwards.
	RemoteUpgradeChanged   bool
	RemoteUpgradeInstalled bool
	// UnitChanges says, one line each, what the upgrade changed beside the
	// binary — or, for a dry run, would change.
	UnitChanges []string

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

	// The unit changes are decided before the binary, because either one
	// alone is reason to restart the service and neither alone makes an
	// upgrade a no-op.
	units, err := in.planUnitChanges(s, out, opts)
	if err != nil {
		return res, err
	}
	res.PacketFilterGranted = units.packetFilterGranted
	res.Channel = units.channelAfter
	res.RemoteUpgradeInstalled = units.helperAfter

	// Same file on disk: replacing it with itself is a no-op that a rename
	// would turn into a deleted binary. Reachable when --force is passed while
	// running the installed binary, and when a checksum collision is not the
	// explanation, an identity check is.
	swapBinary := true
	switch {
	case res.PreviousChecksum == newChecksum && !opts.Force:
		swapBinary = false
		in.logf("%s is already running this build (%s)", s.BinaryPath, shortChecksum(newChecksum))
	case sameFile(source, target):
		swapBinary = false
		in.logf("%s is the binary being run; nothing to copy", s.BinaryPath)
	}
	res.BinaryCurrent = !swapBinary
	if !swapBinary && units.empty() {
		res.AlreadyCurrent = true
		return res, nil
	}
	if !swapBinary {
		return in.changeUnitsOnly(res, s, out, units, opts)
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
		in.noteUnitChanges(&res, units, true)
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

	// The unit changes first: of the two, they are what can fail for a
	// reason of their own (a read-only /etc), and failing before the binary
	// is touched leaves nothing to undo.
	if err := in.applyUnitChanges(s, units); err != nil {
		return res, err
	}
	in.noteUnitChanges(&res, units, false)

	if err := in.replaceBinary(source, s.BinaryPath); err != nil {
		if rErr := in.restoreUnitChanges(s, units); rErr != nil {
			return res, fmt.Errorf("%w\n(and %v also failed)", err, rErr)
		}
		in.forgetUnitChanges(&res, units)
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
			return res, in.rollback(&res, s, out, backup, units,
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
			return res, in.rollback(&res, s, out, backup, units, fmt.Errorf(
				"%s was running before the upgrade and did not come back within %s on the new "+
					"build (%s)", s.ServiceName, settle, res.StagedBuild.Version))
		}
		in.logf("%s is running the new build", s.ServiceName)
	}
	return res, nil
}

// changeUnitsOnly is an upgrade whose binary is already current but whose
// unit changes — the packet-filter grant, the channel, the remote-upgrade
// helper — are to be made: write them, restart, and put the old files back if
// the service does not come back.
//
// It restarts even though no binary changed — systemd applies a unit's
// capabilities and environment at exec, so a grant or a channel the running
// agent was not started with does nothing until it is — and with the same
// try-restart as a binary upgrade: a service an operator stopped stays
// stopped, and picks the change up when it is next started.
func (in *Installer) changeUnitsOnly(res UpgradeResult, s Spec, out Output, units *unitChanges,
	opts UpgradeOptions) (UpgradeResult, error) {
	if opts.DryRun {
		in.noteUnitChanges(&res, units, true)
		in.logf("then restart %s", s.ServiceName)
		return res, nil
	}
	wasRunning, runningKnown := in.serviceActive(s, out)
	if err := in.applyUnitChanges(s, units); err != nil {
		return res, err
	}
	in.noteUnitChanges(&res, units, false)

	wasUp := runningKnown && wasRunning
	restarted, err := in.restartService(s, out)
	if err != nil {
		if wasUp {
			return res, in.rollback(&res, s, out, "", units, fmt.Errorf("the service did not restart: %w", err))
		}
		return res, fmt.Errorf("install: %s was changed but the service did not restart: %w\n"+
			"The new configuration is in place; start the service to apply it", s.DropInDir(), err)
	}
	res.Restarted = restarted
	if wasUp {
		settle := opts.settleTimeout()
		if !in.waitForService(s, out, settle) {
			return res, in.rollback(&res, s, out, "", units, fmt.Errorf(
				"%s was running before the change and did not come back within %s", s.ServiceName, settle))
		}
		in.logf("%s is running with the new configuration", s.ServiceName)
	}
	return res, nil
}

// noteUnitChanges records in res what the unit changes did (or, for a dry
// run, would do), and logs each.
func (in *Installer) noteUnitChanges(res *UpgradeResult, units *unitChanges, dryRun bool) {
	if units.empty() {
		return
	}
	res.UnitChanges = units.describe(dryRun)
	for _, line := range res.UnitChanges {
		in.logf("%s", line)
	}
	if pf := units.packetFilter; pf != nil {
		res.PacketFilterChange = pf.describe(dryRun)
		if !dryRun {
			res.PacketFilterChanged = true
			res.PacketFilterGranted = pf.grantedAfter
		}
	}
	if dryRun {
		return
	}
	res.ChannelChanged = units.channelChanged
	res.RemoteUpgradeChanged = units.helperGrant || units.helperWithdraw
}

// forgetUnitChanges undoes noteUnitChanges after the files were put back.
func (in *Installer) forgetUnitChanges(res *UpgradeResult, units *unitChanges) {
	if units.empty() {
		return
	}
	res.UnitChanges = nil
	if pf := units.packetFilter; pf != nil {
		res.PacketFilterChanged, res.PacketFilterChange = false, ""
		res.PacketFilterGranted = pf.grantedBefore
	}
	if units.channelChanged {
		res.ChannelChanged = false
		res.Channel = units.channelBefore
	}
	if units.helperGrant || units.helperWithdraw {
		res.RemoteUpgradeChanged = false
		res.RemoteUpgradeInstalled = units.helperBefore
	}
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

	// The build the caller proved it was fetching (an edge build's signed
	// manifest names it) must be the build that runs. Not overridable: a
	// mismatch means these are not the bytes that were verified for.
	if want := strings.TrimSpace(opts.ExpectVersion); want != "" {
		if staged.Version != want {
			return fmt.Errorf("%w: %s reports version %q, but the build being installed is %q — these are not "+
				"the bytes its signature was checked for", ErrBinaryUnusable, source, staged.Version, want)
		}
		if err := checkManifestStamp(source, staged, opts); err != nil {
			return err
		}
	}

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
	if installed, ok := in.installedIdentity(target); ok {
		res.InstalledBuild = installed
	}

	err = checkUpgradeSafety(res.StagedBuild, res.InstalledBuild, remote.MinProtocolVersion)
	if errors.Is(err, ErrRollback) {
		if !opts.AllowRollback {
			// The journal line: on a device this runs in the root helper,
			// whose output is the unit's journal, and an operator reading why
			// the hub's Upgrade did nothing finds it there.
			in.logf("refused: %s would move this device back on main from %s to %s; only root on the "+
				"device can do that (install --upgrade --force), not the hub or the agent",
				source, describeSequence(res.InstalledBuild), describeSequence(res.StagedBuild))
			return err
		}
		in.logf("--force, as root on this device: rolling back from %s to %s",
			describeSequence(res.InstalledBuild), describeSequence(res.StagedBuild))
		// The rest of the rules still apply to the rollback, under the same
		// --force that allowed it.
		installed := res.InstalledBuild
		installed.Sequence = 0
		err = checkUpgradeSafety(res.StagedBuild, installed, remote.MinProtocolVersion)
	}
	if err != nil {
		if !opts.Force {
			return err
		}
		in.logf("--force: proceeding despite %v", err)
	}
	switch installed, staged := res.InstalledBuild, res.StagedBuild; {
	case installed.Sequence <= 0 && staged.Sequence > 0:
		// The bootstrap case: nothing to order against yet. From the next
		// upgrade on, this device refuses anything earlier than staged.
		in.logf("the installed binary (%s) carries no sequence, so this move cannot be ordered and is allowed; "+
			"from now on this device refuses builds earlier on main than %s", installedLabel(installed),
			version.SequenceLabel(staged.Sequence))
	case installed.Sequence <= 0:
		in.logf("neither the installed binary (%s) nor the staged one (%s) carries a sequence, so this move "+
			"cannot be ordered and is allowed", installedLabel(installed), installedLabel(staged))
	case staged.Sequence > installed.Sequence:
		in.logf("moving forward on main, %s -> %s", version.SequenceLabel(installed.Sequence),
			version.SequenceLabel(staged.Sequence))
	}
	return nil
}

// installedIdentity is what the installed binary says it is, and whether it
// could be asked.
//
// Probed by running it, like the staged binary. When the probe cannot answer
// and this process is itself the installed binary — the root helper always
// is: its unit runs `<binary> executor agent install --upgrade --apply-request`
// — the answer is this process's own identity. A probe that a hostile agent
// could make fail must not be a way to make the installed build look
// sequence-less, which is the one case the rollback rule lets through.
func (in *Installer) installedIdentity(target string) (BinaryIdentity, bool) {
	id, err := in.identify(target)
	if err == nil && id.Structured {
		return id, true
	}
	if in.Exec == nil && !in.staged() && runningBinaryIs(target) {
		self := selfIdentity()
		if err != nil {
			in.logf("note: %s did not identify itself (%v); it is the binary running this upgrade, so its "+
				"identity is read from this process", target, err)
		}
		return self, true
	}
	return id, err == nil
}

// runningBinaryIs reports whether this process runs the binary at path.
// Indirected so tests can claim either answer.
var runningBinaryIs = func(path string) bool {
	self, err := os.Executable()
	return err == nil && sameFile(self, path)
}

// checkManifestStamp holds the staged binary's own stamp against what the
// signed manifest says about the build: the same commit, the same sequence
// (Task 20380). A manifest of schema 1 names no sequence, so the binary must
// carry none either; one that names a sequence also names its commit, and the
// binary must report that commit.
func checkManifestStamp(source string, staged BinaryIdentity, opts UpgradeOptions) error {
	wantCommit := strings.ToLower(strings.TrimSpace(opts.ExpectCommit))
	wantSeq := opts.ExpectSequence
	if staged.Sequence != wantSeq {
		return fmt.Errorf("%w: %s reports %s, but its signed manifest names %s — these are not the bytes "+
			"the manifest describes", ErrBinaryUnusable, source, version.SequenceLabel(staged.Sequence),
			version.SequenceLabel(wantSeq))
	}
	if wantCommit == "" {
		return nil
	}
	if staged.Commit == "" && wantSeq <= 0 {
		// A build from before the stamp reports no commit; its version, which
		// names the commit's prefix, was checked above.
		return nil
	}
	if staged.Commit != wantCommit {
		reported := staged.Commit
		if reported == "" {
			reported = "no commit"
		}
		return fmt.Errorf("%w: %s reports %s, but its signed manifest describes commit %s — a manifest "+
			"for one commit paired with a binary of another", ErrBinaryUnusable, source, reported, wantCommit)
	}
	return nil
}

// describeSequence names a build and its place on main for a journal line.
func describeSequence(id BinaryIdentity) string {
	return installedLabel(id) + " (" + version.SequenceLabel(id.Sequence) + ")"
}

// installedLabel names a build, or says that it could not be identified.
func installedLabel(id BinaryIdentity) string {
	if strings.TrimSpace(id.Version) == "" {
		return "an unidentified build"
	}
	return id.Version
}

// rollback restores the previous binary after a failed restart and returns the
// error to report, which names both what went wrong and what state the device
// was left in.
//
// It always returns non-nil: it is only called on a failure path, and a rollback
// that reported success would leave an operator believing a build was deployed
// that was not.
func (in *Installer) rollback(res *UpgradeResult, s Spec, out Output, backup string, units *unitChanges,
	cause error) error {
	// The unit changes go back first, so that whichever binary starts below
	// starts with the unit configuration it last ran under.
	if !units.empty() && units.applied {
		if dErr := in.restoreUnitChanges(s, units); dErr != nil {
			return fmt.Errorf("install: %s is in an inconsistent state and needs manual recovery.\n"+
				"  The upgrade failed: %v\n"+
				"  %v",
				s.ServiceName, cause, dErr)
		}
		in.forgetUnitChanges(res, units)
	}
	if !res.BinaryReplaced {
		// Only the drop-in changed, and it is back; start the service on it.
		if sErr := in.startService(s, out); sErr != nil {
			return fmt.Errorf("install: %s is in an inconsistent state and needs manual recovery.\n"+
				"  The change failed: %v\n"+
				"  The previous configuration was restored, but the service did not restart: %v",
				s.ServiceName, cause, sErr)
		}
		res.RolledBack = true
		res.Restarted = false
		return fmt.Errorf("install: the change was rolled back.\n"+
			"  %v\n"+
			"  The previous configuration was restored and %s was restarted, so this device is still "+
			"in the fleet.\n"+
			"Check the device's logs: journalctl -u %s",
			cause, s.ServiceName, s.ServiceName)
	}
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
