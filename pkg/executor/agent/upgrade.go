package agent

// Agent side of the upgrade frame: a device rolling its own binary forward on
// the control plane's request (Task 20331).
//
// Two properties shape everything here.
//
// The first is that the acknowledgement has to be sent *before* the work
// starts. A successful upgrade restarts this process, so any frame written
// after the installer takes over is a frame nobody will ever read. If the ack
// were sent at the end, the hub's request would time out on every upgrade that
// worked and return promptly only on the ones that failed — an outcome exactly
// inverted from what an operator would conclude. So validation happens up
// front, the device answers with whether it is going to try, and the upgrade
// then runs detached from the request that asked for it.
//
// The second is that the hub is not trusted to say where the bytes come from.
// The frame names a version; this code resolves it through pkg/upgrade, which
// fetches from cloop's release channel and proves the archive's signature
// against a pinned GitHub Actions identity before anything is written anywhere
// executable. The hub cannot supply a URL and cannot disable the check, because
// the wire format has no field for either — see pkg/executor/remote/
// upgradeproto.go for why that is the whole security model of this feature.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor/install"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
	"github.com/blechschmidt/cloop/pkg/upgrade"
	"github.com/blechschmidt/cloop/pkg/version"
)

// upgradeStager fetches and verifies a release, returning a path to the
// extracted binary. Indirected through a variable so tests can exercise the
// handler without reaching the network; production always uses the real one.
var upgradeStager = func(tag, destDir string) (upgrade.Staged, error) {
	return upgrade.StageRelease(tag, destDir, upgrade.Options{}, nil)
}

// upgradeInstaller applies a staged binary to this device's service install.
// Indirected for the same reason as upgradeStager.
var upgradeInstaller = func(
	spec install.Spec, output install.Output, opts install.UpgradeOptions,
) (install.UpgradeResult, error) {
	return (&install.Installer{}).Upgrade(spec, output, opts)
}

// handleUpgrade serves a TypeUpgrade frame.
func (a *Agent) handleUpgrade(ctx context.Context, sess *deviceSession, frame remote.Frame) {
	payload, err := remote.DecodeUpgrade(frame)
	if err != nil {
		a.replyError(ctx, sess, frame.ID, remote.CodeProtocol, err.Error())
		return
	}

	current := version.String()
	ack := remote.UpgradingPayload{
		FromVersion:   current,
		TargetVersion: payload.TargetVersion,
	}

	if reason, ok := a.upgradePreflight(payload, current); !ok {
		ack.Accepted = false
		ack.Reason = reason
		ack.AlreadyCurrent = strings.Contains(reason, "already running")
		a.reply(ctx, sess, remote.TypeUpgrading, frame.ID, "", ack)
		return
	}

	ack.Accepted = true
	a.reply(ctx, sess, remote.TypeUpgrading, frame.ID, "", ack)

	// Detached from ctx on purpose. ctx is scoped to this frame's handling and
	// to this session, and the session is precisely what the restart below
	// destroys — inheriting it would cancel the installer partway through
	// replacing a binary, which is the one moment in this flow where being
	// interrupted does real damage.
	go a.runUpgrade(payload, current)
}

// upgradePreflight decides whether this device can attempt the request, and
// explains itself when it cannot.
//
// Every refusal here is phrased as something an operator can act on, because
// these are the strings that surface in the UI beside the device's name. "Not
// installed as a service" and "no such release" have nothing in common as
// remedies, and a shared "upgrade failed" would make them indistinguishable.
func (a *Agent) upgradePreflight(p remote.UpgradePayload, current string) (string, bool) {
	// A device running the agent by hand — a developer's terminal, a container
	// started for a test — has no service to restart and no managed binary to
	// replace. Refusing with the reason is better than attempting it and
	// leaving a half-installed unit behind.
	if _, _, err := a.installTarget(); err != nil {
		return err.Error(), false
	}

	if !p.Force && p.TargetVersion != remote.LatestVersion {
		if cmp, ok := version.Compare(current, p.TargetVersion); ok {
			if cmp == 0 {
				return fmt.Sprintf("already running %s", current), false
			}
			if cmp > 0 {
				// A downgrade is a legitimate operation — it is how a fleet
				// gets off a bad release — but it is never what an operator
				// means by accident, so it takes Force.
				return fmt.Sprintf("running %s, which is newer than the requested %s; "+
					"re-run with force to downgrade", current, p.TargetVersion), false
			}
		}
	}
	return "", true
}

// runUpgrade performs the upgrade. It runs detached: by the time it succeeds,
// the process is being replaced, so it reports only to the local log.
func (a *Agent) runUpgrade(p remote.UpgradePayload, current string) {
	reason := strings.TrimSpace(p.Reason)
	if reason == "" {
		reason = "requested by the control plane"
	}
	a.logf("upgrade: moving from %s to %s (%s)", current, p.TargetVersion, reason)

	// Staged into a private directory that is removed however this ends. A
	// verified binary left in /tmp is an executable with nobody watching it.
	dir, err := os.MkdirTemp("", "cloop-agent-upgrade-")
	if err != nil {
		a.logf("upgrade: staging directory: %v", err)
		return
	}
	defer os.RemoveAll(dir)

	staged, err := upgradeStager(p.TargetVersion, dir)
	if err != nil {
		a.logf("upgrade: fetching %s: %v", p.TargetVersion, err)
		return
	}
	a.logf("upgrade: staged %s from %s (provenance verified: %t)",
		staged.Tag, staged.AssetName, staged.ProvenanceVerified)

	spec, output, err := a.installTarget()
	if err != nil {
		a.logf("upgrade: %v", err)
		return
	}

	opts := install.UpgradeOptions{
		Source: staged.BinaryPath,
		Force:  p.Force,
		// The signature was checked against the release archive before the
		// binary was extracted, so there is no bundle beside this file to find.
		// Never SkipVerify — see the field's doc comment.
		ProvenanceEstablished: staged.ProvenanceVerified,
		SkipVerify:            !staged.ProvenanceVerified,
	}
	if p.SettleSeconds > 0 {
		opts.SettleTimeout = time.Duration(p.SettleSeconds) * time.Second
	}

	res, err := upgradeInstaller(spec, output, opts)
	if err != nil {
		// Reaching here with the old binary still in place is the designed
		// outcome of a failed upgrade, not a second failure: the installer
		// backs up, verifies and rolls back. Saying so stops an operator
		// reading this line as "the device is now broken".
		if errors.Is(err, install.ErrNotInstalled) {
			a.logf("upgrade: no managed install found; the device is unchanged: %v", err)
			return
		}
		a.logf("upgrade: failed, device left on %s: %v", current, err)
		return
	}
	switch {
	case res.AlreadyCurrent:
		a.logf("upgrade: already running %s; nothing replaced", staged.Tag)
	case res.Restarted:
		a.logf("upgrade: installed %s and restarted", staged.Tag)
	default:
		a.logf("upgrade: installed %s; restart pending", staged.Tag)
	}
}

// installTarget describes this device's managed install, and which supervisor
// is running it.
//
// The directories are spelled out rather than left zero. Spec.UnitPath() joins
// UnitDir without defaulting it, so a spec carrying only a service name
// resolves to "/cloop-executor.service" — a path that never exists, which would
// make every device on the fleet refuse every upgrade with "not installed as a
// service". A feature that is uniformly and quietly inert is worse than one
// that fails loudly, so the values are stated here and asserted by
// TestInstallTargetResolvesRealSupervisionPaths.
//
// Both supervision shapes are probed because `cloop executor agent install`
// writes either, depending on --output: a systemd unit on most hosts, a POSIX
// init script on BusyBox and OpenRC devices. Those are exactly the small edge
// devices this feature is most useful for, and hardcoding systemd would have
// excluded them while appearing to work everywhere else.
func (a *Agent) installTarget() (install.Spec, install.Output, error) {
	spec := install.Spec{
		ServiceName: install.DefaultServiceName,
		BinaryPath:  install.DefaultBinaryPath,
		UnitDir:     install.DefaultUnitDir,
		InitDir:     install.DefaultInitDir,
	}
	if _, err := os.Stat(spec.UnitPath()); err == nil {
		return spec, install.OutputSystemd, nil
	}
	if _, err := os.Stat(spec.InitScriptPath()); err == nil {
		return spec, install.OutputShell, nil
	}
	return spec, install.OutputSystemd, fmt.Errorf(
		"this agent is not running from a managed service install (neither %s nor %s is "+
			"present), so there is no supervised binary to replace. Install it as a service "+
			"with `sudo cloop executor agent install` to make it upgradable from the hub",
		spec.UnitPath(), spec.InitScriptPath())
}

// logf writes one line to the agent's log.
func (a *Agent) logf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "agent: "+format+"\n", args...)
}
