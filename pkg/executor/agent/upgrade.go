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

	// What the device installs at all, decided on the device: a release, or
	// an edge build only if an operator here put it on the edge channel. The
	// hub cannot change the channel, so this refusal is the end of it.
	if err := CheckTarget(p.TargetVersion, a.channel()); err != nil {
		return err.Error(), false
	}

	// Whether it can carry the upgrade out (Task 20376). An unprivileged agent
	// with no root helper used to accept here and fail after the ack, where
	// nobody looked; the reason now reaches the hub instead.
	if mode, _, _, issue := a.remoteUpgradeReadiness(); mode == remoteUpgradeUnavailable {
		return issue, false
	}

	if upgrade.IsEdgeTarget(p.TargetVersion) {
		commit, _ := upgrade.ParseEdgeTarget(p.TargetVersion)
		if !p.Force && upgrade.SameCommit(current, commit) {
			return fmt.Sprintf("already running %s, the build of %s", current, p.TargetVersion), false
		}
		// Any other build moves to the hub's: "follow the hub" is what the
		// channel means. What may not happen is losing protocol, and the
		// installer refuses a staged binary that speaks less than this one.
		return "", true
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
//
// An unprivileged agent — every device installed with the defaults — hands the
// work to the root helper by filing a request, and the helper restarts this
// process when it is done. An agent running as root does it itself, through
// the same UpgradeTo the helper uses.
func (a *Agent) runUpgrade(p remote.UpgradePayload, current string) {
	reason := strings.TrimSpace(p.Reason)
	if reason == "" {
		reason = "requested by the control plane"
	}
	a.logf("upgrade: moving from %s to %s (%s)", current, p.TargetVersion, reason)

	mode, spec, output, issue := a.remoteUpgradeReadiness()
	switch mode {
	case remoteUpgradeHelper:
		if err := a.fileUpgradeRequest(spec, p, reason); err != nil {
			a.logf("upgrade: %v", err)
			return
		}
		a.logf("upgrade: filed the request for %s; %s carries it out and restarts this agent "+
			"(journalctl -u %s.service)", p.TargetVersion, spec.UpgradeHelperPathUnitName(), spec.UpgradeHelperName())
		return
	case remoteUpgradeUnavailable:
		a.logf("upgrade: %s", issue)
		return
	}

	t := UpgradeTarget{
		Target:   p.TargetVersion,
		Channel:  a.channel(),
		Install:  install.UpgradeOptions{Force: p.Force},
		Progress: func(line string) { a.logf("upgrade: %s", line) },
	}
	if p.SettleSeconds > 0 {
		t.Install.SettleTimeout = time.Duration(p.SettleSeconds) * time.Second
	}
	res, staged, err := UpgradeTo(spec, output, t)
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
	if a.cfg.InstallTarget != nil {
		return a.cfg.InstallTarget()
	}
	spec := install.Spec{
		ServiceName: install.DefaultServiceName,
		BinaryPath:  install.DefaultBinaryPath,
		UnitDir:     install.DefaultUnitDir,
		InitDir:     install.DefaultInitDir,
		// Stated, not left to Normalize, for the reason the comment above
		// gives for the rest: the upgrade request is filed here.
		StateDir: install.DefaultStateRoot + "/" + install.DefaultServiceName,
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
