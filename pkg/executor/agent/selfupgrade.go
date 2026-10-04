package agent

// selfupgrade.go is the one path every device-side upgrade takes (Task 20376):
// resolve a target through the pinned repository, verify it against the
// signing identity of its channel, and install it with install.Upgrade.
//
// Three callers share it, and sharing is the point — a check that lived in only
// one of them would be a check the other two bypass:
//
//   - the root helper (<service>-upgrade.service) carrying out a request the
//     agent filed when the hub asked it to upgrade;
//   - an agent that runs as root, which can do the work itself;
//   - `cloop executor agent install --upgrade --to <target>`, run by an
//     operator on the device.
//
// What may be installed is decided here and nowhere else: a published release
// (verified against release.yml on a tag), or — only when the device follows
// the edge channel — an edge build of a commit on main (verified against
// edge.yml on main, bound to its commit by the signed manifest, and required to
// report the manifest's version when it is run). The caller supplies the
// device's channel, and must take it from configuration only root can write:
// the request file, which the agent's user can write, never carries it.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor/install"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
	"github.com/blechschmidt/cloop/pkg/provenance"
	"github.com/blechschmidt/cloop/pkg/upgrade"
	"github.com/blechschmidt/cloop/pkg/version"
)

// ErrNotOnEdgeChannel reports an edge target on a device that does not follow
// the edge channel.
var ErrNotOnEdgeChannel = errors.New("agent: this device does not follow the edge channel")

// ErrNotATarget reports a target that is neither a release, "latest" nor an
// edge build.
var ErrNotATarget = errors.New("agent: not something this device installs")

// EdgeOptInCommand is what an operator runs on a device to put it on the edge
// channel.
const EdgeOptInCommand = "sudo cloop executor agent install --upgrade --channel edge"

// RemoteUpgradeCommand is what an operator runs on a device to let the hub
// upgrade it.
const RemoteUpgradeCommand = "sudo cloop executor agent install --upgrade --remote-upgrade"

// CheckTarget refuses a target this device does not install, before anything
// is downloaded. channel is the device's own.
func CheckTarget(target string, channel provenance.Channel) error {
	target = strings.TrimSpace(target)
	switch {
	case target == "":
		return fmt.Errorf("%w: no version was named", ErrNotATarget)
	case strings.EqualFold(target, remote.LatestVersion), version.IsRelease(target):
		return nil
	case upgrade.IsEdgeTarget(target):
		if _, err := upgrade.ParseEdgeTarget(target); err != nil {
			return err
		}
		if channel != provenance.ChannelEdge {
			return fmt.Errorf("%w: %s is a build of main, and this device installs published releases only. "+
				"Only an operator on the device can change that — the hub cannot: `%s` puts it on the edge "+
				"channel, after which it installs signed builds of main as well", ErrNotOnEdgeChannel, target,
				EdgeOptInCommand)
		}
		return nil
	}
	return fmt.Errorf("%w: %q is neither a release tag, %q, nor an edge build (edge:<commit>)",
		ErrNotATarget, target, remote.LatestVersion)
}

// UpgradeTarget is one device-side upgrade.
type UpgradeTarget struct {
	// Target is a release tag, "latest", or "edge:<commit>".
	Target string
	// Channel is the device's update channel, from root-owned configuration.
	Channel provenance.Channel
	// Install carries everything else install.Upgrade takes — Force, DryRun,
	// SettleTimeout, and any unit changes an operator asked for in the same
	// command. Source, the provenance fields and ExpectVersion are filled in
	// here from what was staged.
	Install install.UpgradeOptions
	// Fetch is the staging options: verification against the release
	// identity can be skipped for a release (an operator's --insecure-skip-
	// verify on the device), never for an edge build. Tests set the verifier
	// and the edge mirror.
	Fetch upgrade.Options
	// Installer applies the upgrade; nil uses the real one.
	Installer *install.Installer
	// Progress receives one line per step; nil discards them.
	Progress func(string)
}

// UpgradeTo stages t.Target, verifies it, and installs it over spec's binary.
func UpgradeTo(spec install.Spec, out install.Output, t UpgradeTarget) (install.UpgradeResult, upgrade.Staged, error) {
	var staged upgrade.Staged
	progress := t.Progress
	if progress == nil {
		progress = func(string) {}
	}
	if err := CheckTarget(t.Target, t.Channel); err != nil {
		return install.UpgradeResult{}, staged, err
	}

	// Staged into a private directory that is removed however this ends: a
	// verified binary left in /tmp is an executable with nobody watching it.
	dir, err := os.MkdirTemp("", "cloop-agent-upgrade-")
	if err != nil {
		return install.UpgradeResult{}, staged, fmt.Errorf("agent: staging directory: %w", err)
	}
	defer os.RemoveAll(dir)

	target := strings.TrimSpace(t.Target)
	if upgrade.IsEdgeTarget(target) {
		staged, err = upgrade.StageEdge(target, dir, t.Fetch, progress)
	} else {
		staged, err = upgrade.StageRelease(target, dir, t.Fetch, progress)
	}
	if err != nil {
		return install.UpgradeResult{}, staged, err
	}

	opts := t.Install
	opts.Source = staged.BinaryPath
	opts.Bundle = ""
	// The signature was checked against the archive before the binary was
	// extracted, so there is no bundle beside this file to find — see the
	// field's doc comment.
	opts.ProvenanceEstablished = staged.ProvenanceVerified
	opts.SkipVerify = !staged.ProvenanceVerified
	opts.ExpectVersion = staged.Version
	inst := t.Installer
	if inst == nil {
		inst = &install.Installer{}
	}
	res, err := inst.Upgrade(spec, out, opts)
	return res, staged, err
}

// remoteUpgradeMode is how this device carries out an upgrade the hub asks
// for.
type remoteUpgradeMode int

const (
	// remoteUpgradeUnavailable: it cannot; the issue says why and what fixes it.
	remoteUpgradeUnavailable remoteUpgradeMode = iota
	// remoteUpgradeHelper: it files a request for the root helper.
	remoteUpgradeHelper
	// remoteUpgradeInProcess: the agent runs as root and does it itself.
	remoteUpgradeInProcess
)

// Indirected for tests: the effective uid, and where cosign is looked up.
var (
	agentEUID    = os.Geteuid
	cosignOnPath = func() error {
		_, err := exec.LookPath(provenance.CosignBinary)
		return err
	}
)

// remoteUpgradeReadiness says how this device would carry out an upgrade the
// hub asked for, or why it cannot — in a sentence the Executors panel shows
// beside the device, so the remedy is an operator's next step rather than a
// line in a journal on the device.
func (a *Agent) remoteUpgradeReadiness() (remoteUpgradeMode, install.Spec, install.Output, string) {
	spec, out, err := a.installTarget()
	if err != nil {
		return remoteUpgradeUnavailable, spec, out, err.Error()
	}
	mode := remoteUpgradeUnavailable
	switch {
	case out == install.OutputSystemd && (&install.Installer{}).HelperInstalled(spec):
		// Installed is not armed: a path unit that was disabled, or stopped
		// by a withdrawal that failed half-way, would leave the request filed
		// and never carried out — the very failure the helper exists to end.
		unit := spec.UpgradeHelperPathUnitName()
		if active, known := a.unitActive(unit); known && !active {
			return remoteUpgradeUnavailable, spec, out, fmt.Sprintf(
				"the remote-upgrade helper is installed but %s is not active, so a request would never be "+
					"carried out. Run `sudo systemctl enable --now %s` on the device", unit, unit)
		}
		mode = remoteUpgradeHelper
	case agentEUID() == 0:
		mode = remoteUpgradeInProcess
	default:
		return remoteUpgradeUnavailable, spec, out, fmt.Sprintf(
			"this agent runs unprivileged and the device has no remote-upgrade helper (%s), so it cannot "+
				"replace its own binary or restart itself. Run `%s` on the device once", spec.UpgradeHelperPathUnitName(),
			RemoteUpgradeCommand)
	}
	if err := cosignOnPath(); err != nil {
		return remoteUpgradeUnavailable, spec, out, "cosign is not installed on this device, and every build is " +
			"verified with it before it is installed. Install it from https://github.com/sigstore/cosign/releases " +
			"(a single static binary, e.g. to /usr/local/bin/cosign)"
	}
	return mode, spec, out, ""
}

// unitActive asks systemd whether unit is active. Known is false when the
// answer is not a unit state — no systemctl, no bus — which callers treat as
// "cannot tell" rather than as a refusal.
func (a *Agent) unitActive(unit string) (active, known bool) {
	if a.cfg.UnitActive != nil {
		return a.cfg.UnitActive(unit)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// Read as the agent: the unit's sandbox allows it (AF_UNIX to the system
	// bus), and is-active needs no privilege.
	out, _ := exec.CommandContext(ctx, "systemctl", "is-active", unit).Output()
	switch state := strings.TrimSpace(string(out)); state {
	case "active", "reloading", "activating":
		return true, true
	case "inactive", "failed", "deactivating":
		return false, true
	}
	return false, false
}

// fileUpgradeRequest hands an upgrade to the root helper.
func (a *Agent) fileUpgradeRequest(spec install.Spec, p remote.UpgradePayload, reason string) error {
	return install.FileUpgradeRequest(spec, install.UpgradeRequest{
		TargetVersion: p.TargetVersion,
		Force:         p.Force,
		SettleSeconds: p.SettleSeconds,
		Reason:        reason,
		RequestedAt:   a.cfg.now().UTC().Format(time.RFC3339),
	})
}

// ApplyOptions parameterise ApplyUpgradeRequest.
type ApplyOptions struct {
	// Installer applies the upgrade, and answers which channel the device
	// follows; nil uses the real one.
	Installer *install.Installer
	// Fetch is the staging options. Tests set the verifier and the mirror.
	Fetch upgrade.Options
	// Now is the clock, for the request's age; nil uses time.Now.
	Now func() time.Time
	// Progress receives one line per step; nil discards them.
	Progress func(string)
}

// ApplyUpgradeRequest carries out the upgrade the agent filed, as the root
// helper does (`cloop executor agent install --upgrade --apply-request`).
//
// The request is taken — deleted — before anything else, so a request that is
// refused is not retried by the path unit. The channel it is checked against
// is the device's, from systemd's view of the agent's unit; a request cannot
// name one. It returns install.ErrNoRequest when nothing is waiting.
func ApplyUpgradeRequest(spec install.Spec, out install.Output, o ApplyOptions) (
	install.UpgradeRequest, install.UpgradeResult, upgrade.Staged, error,
) {
	inst := o.Installer
	if inst == nil {
		inst = &install.Installer{}
	}
	now := time.Now
	if o.Now != nil {
		now = o.Now
	}
	s, err := spec.NormalizeForRemoval()
	if err != nil {
		return install.UpgradeRequest{}, install.UpgradeResult{}, upgrade.Staged{}, err
	}
	req, err := install.TakeUpgradeRequest(s, now())
	if err != nil {
		return req, install.UpgradeResult{}, upgrade.Staged{}, err
	}
	channel, err := inst.DeviceChannel(s)
	if err != nil {
		return req, install.UpgradeResult{}, upgrade.Staged{}, err
	}
	t := UpgradeTarget{
		Target:    req.TargetVersion,
		Channel:   channel,
		Install:   install.UpgradeOptions{Force: req.Force},
		Fetch:     o.Fetch,
		Installer: inst,
		Progress:  o.Progress,
	}
	if req.SettleSeconds > 0 {
		t.Install.SettleTimeout = time.Duration(req.SettleSeconds) * time.Second
	}
	res, staged, err := UpgradeTo(s, out, t)
	return req, res, staged, err
}
