package cmd

// executor_install_cmd.go is `cloop executor agent install`: the command that
// turns an enrollment bundle into a running, supervised, hardened agent.
//
// It exists because `cloop executor enroll` stopped one step short. It printed
// a command, and the operator was left to solve binary placement, service
// supervision, credential file modes and log handling by hand — on every
// device. The step that gets skipped under time pressure is always the file
// mode, and the thing it protects is a credential that attaches an arbitrary
// machine to the control plane.
//
// The rendering lives in pkg/executor/install so it can be tested without a
// systemd (and without root); this file is flag plumbing and the operator's
// view of what is about to happen.

import (
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/blechschmidt/cloop/pkg/executor/agent"
	"github.com/blechschmidt/cloop/pkg/executor/install"
	"github.com/blechschmidt/cloop/pkg/provenance"
	"github.com/blechschmidt/cloop/pkg/upgrade"
)

// enrollBundleEnv is where the bootstrap script passes the bundle.
//
// An environment variable rather than an argument: argv is world-readable
// through /proc for the lifetime of the process, and the whole point of this
// command is that the token stops being casually visible.
const enrollBundleEnv = "CLOOP_ENROLL_BUNDLE"

var executorAgentInstallCmd = &cobra.Command{
	Use:   "install",
	Short: "Install this device as a supervised, hardened cloop executor agent",
	Long: `Install the cloop executor agent as a service on this device.

Takes the bundle from ` + "`cloop executor enroll`" + ` and materialises everything a
device needs to stay enrolled across reboots:

  * a systemd unit with Restart=always and the hub's SPKI pin baked in
  * a dedicated non-login system user that owns nothing else on the box
  * NoNewPrivileges, ProtectSystem=strict, PrivateTmp, an empty capability
    bounding set, and a syscall filter
  * a StateDirectory holding the enrollment token at mode 0600
  * a drop-in granting CAP_NET_ADMIN and netlink sockets, so the agent can
    install the IP firewall of a sandbox that has one with nft(8). The agent
    keeps the capability to itself: nothing it starts receives it except nft,
    so a workload never holds it. --packet-filter=false withholds it, and the
    device then refuses every sandbox with a firewall
  * a root helper (<service>-upgrade.path and .service) that carries out an
    upgrade the hub asks for, which the unprivileged agent cannot do itself:
    it fetches the named build from cloop's repository, verifies its signature
    with cosign, and installs it with backup and rollback. --remote-upgrade=false
    withholds it, and the device then refuses the hub's Upgrade button

The token never appears in ExecStart. A unit file is world-readable and
` + "`systemctl show`" + ` prints the command line to anyone who asks, so the token is
written to a 0600 file that only the service user can read and the unit
carries its path. The agent deletes that file once the token is redeemed.

  --output docker   emit an equivalent podman run command and compose fragment
  --output shell    emit a POSIX init script for devices without systemd
  --dry-run         print what would be written, and write nothing
  --uninstall       reverse an install; idempotent, safe to re-run
  --upgrade         replace the binary of an existing install and restart it;
                    with --packet-filter, also grant (or with =false, withdraw)
                    the firewall capability on a device installed without it

--upgrade rolls a device forward without re-enrolling it. It replaces the binary
atomically and restarts the service, and it deliberately does nothing else: the
unit file and the credential are left exactly as they are, because re-rendering
the unit needs the control-plane URL and certificate pin from an enrollment
bundle that nobody still has months later. A unit change means re-running a full
install with the bundle. The exceptions are the firewall grant, the update
channel and the remote-upgrade helper, which are files beside the unit precisely
so that --upgrade with --packet-filter, --channel or --remote-upgrade can add them
(and take them away) without the bundle; a plain --upgrade leaves them as they are.

It is idempotent — an upgrade to the identical binary copies nothing and
restarts nothing — and it refuses rather than half-installing a device that was
never installed in the first place.

Before anything is replaced, the staged binary is executed and made to identify
itself. A truncated download, a copy built for another architecture and a file
that is not cloop all hash perfectly well, and all three used to be renamed over
a working agent's binary; now they are refused. A build older than the one
installed, or one speaking a protocol this control plane no longer accepts, is
refused too — pass --force for a deliberate rollback.

The replaced binary is kept beside the new one. If the service was running before
the upgrade and does not come back on the new build, the old one is restored and
restarted, so a bad rollout leaves the device in the fleet rather than offline.

Examples:

  # Everything from one blob (the bundle carries server, token and pin).
  sudo cloop executor agent install --bundle cloopenroll1.…

  # Keep the token out of this device's process list.
  CLOOP_ENROLL_BUNDLE='cloopenroll1.…' sudo -E cloop executor agent install

  # Review before committing.
  cloop executor agent install --bundle cloopenroll1.… --dry-run

  # Roll this device forward after copying a new cloop binary onto it.
  sudo /tmp/cloop executor agent install --upgrade

  # Upgrade from an explicit path instead of the running executable.
  sudo cloop executor agent install --upgrade --from /tmp/cloop-new

  # Let a device installed before the default changed install sandbox
  # firewalls. No bundle needed; restarts the agent even if its build is current.
  sudo cloop executor agent install --upgrade --packet-filter

  # Follow the hub's own build: the hub may then move this device to signed
  # builds of main as well as releases. Decided here; the hub cannot change it.
  sudo cloop executor agent install --upgrade --channel edge

  # Fetch a published build, verify it, and install it: a release, "latest",
  # or on the edge channel edge:<commit>.
  sudo cloop executor agent install --upgrade --to v0.0.4

  # Remove it, including the agent's identity and workspaces.
  sudo cloop executor agent install --uninstall --purge`,
	Args: cobra.NoArgs,
	// No SilenceErrors here: rootCmd sets it, and cmd.Execute prints the one
	// copy (Task 20294). A per-command "false" cannot re-enable cobra's print
	// — the check is on the root as well — so stating it only misled.
	RunE: func(cmd *cobra.Command, args []string) error {
		spec, out, err := specFromFlags(cmd)
		if err != nil {
			return err
		}

		dryRun, _ := cmd.Flags().GetBool("dry-run")
		uninstall, _ := cmd.Flags().GetBool("uninstall")
		purge, _ := cmd.Flags().GetBool("purge")
		root, _ := cmd.Flags().GetString("root")
		upgrade, _ := cmd.Flags().GetBool("upgrade")
		force, _ := cmd.Flags().GetBool("force")

		if upgrade && uninstall {
			return fmt.Errorf("--upgrade and --uninstall are opposites; pass one")
		}

		dim := color.New(color.Faint)
		inst := &install.Installer{
			Root: strings.TrimSpace(root),
			Logf: func(format string, a ...any) { dim.Fprintf(os.Stderr, "  "+format+"\n", a...) },
		}

		applyRequest, _ := cmd.Flags().GetBool("apply-request")
		to, _ := cmd.Flags().GetString("to")
		to = strings.TrimSpace(to)
		if (applyRequest || to != "") && !upgrade {
			return fmt.Errorf("--to and --apply-request are forms of --upgrade; pass --upgrade with them")
		}

		if upgrade {
			if err := requirePrivilege(inst, dryRun); err != nil {
				return err
			}
			// The two paths an upgrade involves are kept on separate flags,
			// because collapsing them is genuinely ambiguous: --binary has
			// always meant "where the binary lives on the device", and that is
			// the *destination*, already fixed by the existing install. The new
			// binary is a different path, so it gets --from.
			//
			// specFromFlags defaults --binary to this executable, which is right
			// for an install and wrong here — on an upgrade this executable is
			// the replacement, not the target. So the raw flag is re-read and an
			// unset one is left empty for Normalize to default.
			dest, _ := cmd.Flags().GetString("binary")
			spec.BinaryPath = strings.TrimSpace(dest)
			from, _ := cmd.Flags().GetString("from")

			settle, _ := cmd.Flags().GetDuration("settle-timeout")
			bundle, _ := cmd.Flags().GetString("bundle-sig")
			skipVerify, _ := cmd.Flags().GetBool("insecure-skip-verify")
			channel, err := upgradeChannel(cmd)
			if err != nil {
				return err
			}
			opts := install.UpgradeOptions{
				Source:        strings.TrimSpace(from), // empty: Upgrade uses this executable
				Bundle:        strings.TrimSpace(bundle),
				SkipVerify:    skipVerify,
				Force:         force,
				DryRun:        dryRun,
				SettleTimeout: settle,
				PacketFilter:  upgradePacketFilter(cmd),
				Channel:       channel,
				RemoteUpgrade: upgradeRemoteUpgrade(cmd, channel),
			}

			if applyRequest {
				// What the helper runs, as root, against the live install: a
				// dry run would still take (and so delete) the request, and a
				// staged tree has no request to take.
				if dryRun || inst.Root != "" {
					return fmt.Errorf("--apply-request carries out the request the agent filed and takes no " +
						"--dry-run or --root; use --to <target> --dry-run to see what an upgrade would do")
				}
				return applyUpgradeRequest(cmd, inst, spec, out)
			}
			if to != "" {
				if strings.TrimSpace(from) != "" {
					return fmt.Errorf("--to fetches a published build and --from names a local binary; pass one")
				}
				return upgradeToTarget(cmd, inst, spec, out, to, opts)
			}

			res, err := inst.Upgrade(spec, out, opts)
			if err != nil {
				return err
			}
			printUpgraded(cmd.OutOrStdout(), res)
			return nil
		}

		if uninstall {
			if err := requirePrivilege(inst, dryRun); err != nil {
				return err
			}
			if err := inst.Uninstall(spec, out, purge); err != nil {
				return err
			}
			color.New(color.FgGreen, color.Bold).Printf("Removed %s.\n", spec.ServiceName)
			if !purge {
				dim.Println("The agent's identity and workspaces were kept. Re-run with --purge to delete them.")
			}
			dim.Println("Revoke the credential on the control plane too: cloop executor revoke <agent-id>")
			return nil
		}

		// The grant is a systemd drop-in. Asked for explicitly on another
		// output, it is refused rather than silently not made; left at its
		// default there, it simply does not apply.
		if out != install.OutputSystemd && spec.PacketFilter {
			if cmd.Flags().Changed("packet-filter") {
				return fmt.Errorf("--packet-filter applies to --output systemd only: the grant is a systemd "+
					"drop-in, and the %s output has no equivalent that keeps the capability from the agent's "+
					"workloads", out)
			}
			spec.PacketFilter = false
		}
		// The channel and the upgrade helper the same way (Task 20376).
		if out != install.OutputSystemd {
			if spec.Channel == provenance.ChannelEdge {
				return fmt.Errorf("--channel applies to --output systemd only: it is a systemd drop-in")
			}
			if spec.RemoteUpgrade && cmd.Flags().Changed("remote-upgrade") {
				return fmt.Errorf("--remote-upgrade applies to --output systemd only: the helper is a root " +
					"systemd unit")
			}
			spec.RemoteUpgrade = false
		}

		plan, err := install.BuildPlan(spec, out)
		if err != nil {
			return err
		}

		if dryRun {
			printDryRun(cmd.OutOrStdout(), plan)
			return nil
		}
		if err := requirePrivilege(inst, dryRun); err != nil {
			return err
		}
		if err := preflight(plan); err != nil {
			return err
		}
		if err := inst.Apply(plan); err != nil {
			return err
		}
		printInstalled(plan)
		return nil
	},
}

// specFromFlags assembles the Spec, resolving the bundle from whichever of the
// three channels the caller used.
func specFromFlags(cmd *cobra.Command) (install.Spec, install.Output, error) {
	str := func(name string) string {
		v, _ := cmd.Flags().GetString(name)
		return strings.TrimSpace(v)
	}

	out, err := install.ParseOutput(str("output"))
	if err != nil {
		return install.Spec{}, "", err
	}

	bundle := str("bundle")
	if bundle == "" {
		bundle = strings.TrimSpace(os.Getenv(enrollBundleEnv))
	}
	if stdin, _ := cmd.Flags().GetBool("bundle-stdin"); stdin {
		// Reading from stdin is the bootstrap script's channel: it keeps the
		// bundle out of both argv and the environment, which is as private as
		// a value handed between two processes gets.
		raw, rerr := io.ReadAll(io.LimitReader(cmd.InOrStdin(), 64*1024))
		if rerr != nil {
			return install.Spec{}, "", fmt.Errorf("read enrollment bundle from stdin: %w", rerr)
		}
		if v := strings.TrimSpace(string(raw)); v != "" {
			bundle = v
		}
	}

	labelPairs, _ := cmd.Flags().GetStringSlice("label")
	labels, err := parseLabelPairs(labelPairs)
	if err != nil {
		return install.Spec{}, "", err
	}
	maxConc, _ := cmd.Flags().GetInt("max-concurrent")
	noStart, _ := cmd.Flags().GetBool("no-start")
	packetFilter, _ := cmd.Flags().GetBool("packet-filter")
	remoteUpgrade, _ := cmd.Flags().GetBool("remote-upgrade")
	channel, err := provenance.ParseChannel(str("channel"))
	if err != nil {
		return install.Spec{}, "", err
	}

	spec := install.Spec{
		ServiceName:     str("service-name"),
		User:            str("user"),
		Group:           str("group"),
		BinaryPath:      str("binary"),
		StateDir:        str("state-dir"),
		UnitDir:         str("unit-dir"),
		InitDir:         str("init-dir"),
		CredentialsFile: str("credentials-file"),
		WorkDirRoot:     str("workdir-root"),
		Server:          str("server"),
		Pin:             str("pin"),
		Bundle:          bundle,
		Token:           str("token"),
		RootCAFile:      str("ca-file"),
		MaxConcurrent:   maxConc,
		Labels:          labels,
		Image:           str("image"),
		NoStart:         noStart,
		PacketFilter:    packetFilter,
		RemoteUpgrade:   remoteUpgrade,
		Channel:         channel,
	}

	// Default the binary to the one being run, not to a path that may not
	// exist. An operator who copied cloop to /opt and ran it from there gets a
	// unit that points at /opt, which is what they meant.
	if spec.BinaryPath == "" {
		if self, serr := os.Executable(); serr == nil {
			spec.BinaryPath = self
		}
	}
	return spec, out, nil
}

// upgradePacketFilter maps --packet-filter onto an upgrade. Unlike an install,
// where it defaults to granting, an upgrade acts on it only when it was passed:
// what a fleet device may do is not something to change as a side effect of
// replacing its binary.
func upgradePacketFilter(cmd *cobra.Command) install.PacketFilterChange {
	if !cmd.Flags().Changed("packet-filter") {
		return install.PacketFilterKeep
	}
	if grant, _ := cmd.Flags().GetBool("packet-filter"); grant {
		return install.PacketFilterGrant
	}
	return install.PacketFilterWithdraw
}

// upgradeChannel maps --channel onto an upgrade: acted on only when passed,
// like --packet-filter, because which builds a device accepts is not something
// to change as a side effect of replacing its binary.
func upgradeChannel(cmd *cobra.Command) (provenance.Channel, error) {
	if !cmd.Flags().Changed("channel") {
		return "", nil
	}
	v, _ := cmd.Flags().GetString("channel")
	return provenance.ParseChannel(v)
}

// upgradeRemoteUpgrade maps --remote-upgrade onto an upgrade. Moving a device
// onto the edge channel installs the helper too unless told otherwise: the
// only point of the channel is that the hub can move the device along it.
func upgradeRemoteUpgrade(cmd *cobra.Command, channel provenance.Channel) install.RemoteUpgradeChange {
	if !cmd.Flags().Changed("remote-upgrade") {
		if channel == provenance.ChannelEdge {
			return install.RemoteUpgradeGrant
		}
		return install.RemoteUpgradeKeep
	}
	if grant, _ := cmd.Flags().GetBool("remote-upgrade"); grant {
		return install.RemoteUpgradeGrant
	}
	return install.RemoteUpgradeWithdraw
}

// deviceChannel is the channel the device follows as root sees it, for a
// command that is about to fetch a build: the one this same command moves it
// to, if it does, else what the unit says.
func deviceChannel(inst *install.Installer, spec install.Spec, requested provenance.Channel) (provenance.Channel, error) {
	if requested != "" {
		return requested, nil
	}
	s, err := spec.NormalizeForRemoval()
	if err != nil {
		return provenance.ChannelStable, err
	}
	return inst.DeviceChannel(s)
}

// upgradeToTarget is --upgrade --to: fetch a published build — a release,
// "latest", or on an edge-channel device edge:<commit> — verify it, and
// install it, through the same path the hub's Upgrade button ends in.
func upgradeToTarget(cmd *cobra.Command, inst *install.Installer, spec install.Spec, out install.Output,
	target string, opts install.UpgradeOptions) error {
	channel, err := deviceChannel(inst, spec, opts.Channel)
	if err != nil {
		return err
	}
	dim := color.New(color.Faint)
	res, staged, err := agent.UpgradeTo(spec, out, agent.UpgradeTarget{
		Target:    target,
		Channel:   channel,
		Install:   opts,
		Fetch:     upgrade.Options{SkipVerify: opts.SkipVerify},
		Installer: inst,
		Progress:  func(line string) { dim.Fprintf(os.Stderr, "  %s\n", line) },
	})
	if err != nil {
		return err
	}
	fmt.Fprintf(cmd.OutOrStdout(), "\nInstalled from %s (%s channel%s).\n", staged.Tag, staged.Channel,
		verifiedNote(staged.ProvenanceVerified))
	printUpgraded(cmd.OutOrStdout(), res)
	return nil
}

// parenthesised is " (s)", or "" for an empty s.
func parenthesised(s string) string {
	if s = strings.TrimSpace(s); s == "" {
		return ""
	}
	return " (" + s + ")"
}

func verifiedNote(verified bool) string {
	if verified {
		return ", signature verified"
	}
	return ", NOT verified"
}

// applyUpgradeRequest is --upgrade --apply-request, which the remote-upgrade
// helper runs as root when the agent files a request (Task 20376). It takes the
// request — deleting it whatever happens next — and carries it out under the
// device's own channel, never one the request names.
func applyUpgradeRequest(cmd *cobra.Command, inst *install.Installer, spec install.Spec, out install.Output) error {
	w := cmd.OutOrStdout()
	req, res, staged, err := agent.ApplyUpgradeRequest(spec, out, agent.ApplyOptions{
		Installer: inst,
		Progress:  func(line string) { fmt.Fprintf(w, "  %s\n", line) },
	})
	switch {
	case errors.Is(err, install.ErrNoRequest):
		fmt.Fprintln(w, "No upgrade request is waiting.")
		return nil
	case err != nil && req.TargetVersion == "":
		return err
	case err != nil:
		return fmt.Errorf("the request to move to %s%s was not carried out, and the device is on the build "+
			"it had: %w", req.TargetVersion, parenthesised(req.Reason), err)
	}
	fmt.Fprintf(w, "Carried out the request to move to %s%s.\n", req.TargetVersion, parenthesised(req.Reason))
	fmt.Fprintf(w, "Installed from %s (%s channel%s).\n", staged.Tag, staged.Channel, verifiedNote(staged.ProvenanceVerified))
	printUpgraded(w, res)
	return nil
}

// requirePrivilege refuses an install that cannot succeed, rather than failing
// half-way through with a permission error on the third file.
func requirePrivilege(inst *install.Installer, dryRun bool) error {
	if dryRun || inst.Root != "" || runtime.GOOS == "windows" {
		return nil
	}
	if os.Geteuid() == 0 {
		return nil
	}
	return fmt.Errorf(
		"this must run as root: it creates a system user, writes to /etc and /var/lib, and reloads systemd\n" +
			"Re-run with sudo, or use --dry-run to see what it would write, " +
			"or --root <dir> to stage the files for an image build")
}

// preflight catches the mismatches that produce a service which installs
// cleanly and then never starts.
func preflight(p install.Plan) error {
	if p.Output == install.OutputSystemd && runtime.GOOS != "linux" {
		return fmt.Errorf(
			"--output systemd targets Linux, but this is %s. Use --output shell, or --output docker",
			runtime.GOOS)
	}
	if p.Output == install.OutputSystemd || p.Output == install.OutputShell {
		if st, err := os.Stat(p.Spec.BinaryPath); err != nil {
			return fmt.Errorf(
				"the cloop binary is not at %s: %w\n"+
					"Copy it there first, or pass --binary with the path it actually has",
				p.Spec.BinaryPath, err)
		} else if st.IsDir() {
			return fmt.Errorf("--binary %s is a directory", p.Spec.BinaryPath)
		}
	}
	return nil
}

// printDryRun shows exactly what would be written, and deliberately shows the
// credential file only as a path and a mode.
func printDryRun(w io.Writer, p install.Plan) {
	header := color.New(color.FgCyan, color.Bold)
	dim := color.New(color.Faint)

	header.Fprintf(w, "Dry run — nothing was written.\n\n")
	for _, a := range p.Artifacts {
		if a.Secret {
			fmt.Fprintf(w, "  %s  (mode %04o, owner %s) — enrollment token, not shown\n",
				a.Path, a.Mode, p.Spec.User)
			continue
		}
		fmt.Fprintf(w, "  %s  (mode %04o)\n", a.Path, a.Mode)
	}
	for _, r := range p.Remove {
		fmt.Fprintf(w, "  %s  (removed if present)\n", r)
	}
	if len(p.Next) > 0 {
		fmt.Fprintln(w)
		for _, n := range p.Next {
			dim.Fprintf(w, "  then: %s\n", n)
		}
	}
	fmt.Fprintln(w)
	header.Fprintf(w, "── %s ", p.Output)
	dim.Fprintf(w, "%s\n", strings.Repeat("─", 56))
	fmt.Fprintln(w, p.Display)
	// Every other file the plan writes in full — the packet-filter drop-in —
	// so a review before committing sees the grant, not just its path.
	for _, a := range p.Artifacts {
		if a.Secret || a.Content == p.Display {
			continue
		}
		header.Fprintf(w, "── %s ", a.Path)
		dim.Fprintf(w, "%s\n", strings.Repeat("─", 8))
		fmt.Fprintln(w, a.Content)
	}
}

// printUpgraded reports what the upgrade actually did.
//
// Three outcomes are all successes and all mean different things, so they get
// different output rather than one "Upgraded." line: nothing needed doing; the
// binary was replaced and the service restarted; the binary was replaced but
// the service was not running, so the device is not yet on the new build. The
// third is the one an operator must not miss, because everything looks fine and
// the old build is still what would run.
func printUpgraded(w io.Writer, res install.UpgradeResult) {
	ok := color.New(color.FgGreen, color.Bold)
	warn := color.New(color.FgYellow, color.Bold)
	dim := color.New(color.Faint)

	if res.AlreadyCurrent {
		ok.Fprintf(w, "\nAlready up to date.\n")
		fmt.Fprintf(w, "  binary:  %s\n", res.Spec.BinaryPath)
		dim.Fprintf(w, "  build:   %s\n", shortChecksum(res.NewChecksum))
		printPacketFilter(w, res)
		dim.Fprintln(w, "  Nothing was replaced and the service was not restarted.")
		dim.Fprintln(w, "  Pass --force to replace and restart anyway.")
		return
	}

	// The binary was current and only the firewall grant changed.
	if res.BinaryCurrent {
		if res.DryRun {
			color.New(color.FgCyan, color.Bold).Fprintf(w, "\nDry run — nothing was changed.\n")
		} else {
			ok.Fprintf(w, "\nUpdated %s.\n", res.Spec.ServiceName)
		}
		fmt.Fprintf(w, "  binary:  %s (already this build: %s)\n", res.Spec.BinaryPath, shortChecksum(res.NewChecksum))
		printPacketFilter(w, res)
		if res.Restarted {
			fmt.Fprintf(w, "  service: restarted\n")
		}
		return
	}

	if res.DryRun {
		header := color.New(color.FgCyan, color.Bold)
		header.Fprintf(w, "\nDry run — nothing was changed.\n")
		fmt.Fprintf(w, "  binary:  %s\n", res.Spec.BinaryPath)
		fmt.Fprintf(w, "  from:    %s\n", res.Source)
		fmt.Fprintf(w, "  build:   %s -> %s\n",
			shortChecksum(res.PreviousChecksum), shortChecksum(res.NewChecksum))
		printVerification(w, res)
		printPacketFilter(w, res)
		dim.Fprintf(w, "\n  Would replace the binary and restart %s.\n", res.Spec.ServiceName)
		dim.Fprintln(w, "  The unit file and credential would be left unchanged.")
		return
	}

	ok.Fprintf(w, "\nUpgraded %s.\n", res.Spec.ServiceName)
	fmt.Fprintf(w, "  binary:  %s\n", res.Spec.BinaryPath)
	fmt.Fprintf(w, "  from:    %s\n", res.Source)
	fmt.Fprintf(w, "  build:   %s -> %s\n", shortChecksum(res.PreviousChecksum), shortChecksum(res.NewChecksum))
	printVerification(w, res)
	printPacketFilter(w, res)
	if res.BackupPath != "" {
		// Named because it is the operator's manual escape hatch, and because
		// a file silently appearing beside the service binary is the kind of
		// thing that gets deleted by whoever finds it next.
		dim.Fprintf(w, "  rollback: %s (the binary this replaced)\n", res.BackupPath)
	}

	if res.Restarted {
		fmt.Fprintf(w, "  service: restarted\n")
	} else {
		warn.Fprintf(w, "\nThe service was not running, so it was not started.\n")
		dim.Fprintf(w, "  The new binary is in place and will be used when it next starts.\n")
		switch res.Output {
		case install.OutputSystemd:
			dim.Fprintf(w, "  Start it with: systemctl start %s\n", res.Spec.UnitFileName())
		case install.OutputShell:
			dim.Fprintf(w, "  Start it with: %s start\n", res.Spec.InitScriptPath())
		}
	}

	fmt.Fprintln(w)
	// Named because an upgrade that silently left the unit alone would
	// otherwise look like one that refreshed everything.
	if res.PacketFilterChanged {
		dim.Fprintln(w, "  The unit file and credential were left unchanged; the firewall grant is the")
		dim.Fprintln(w, "  drop-in beside the unit.")
	} else {
		dim.Fprintln(w, "  The unit file and credential were left unchanged.")
	}
	dim.Fprintln(w, "  To change either, re-run a full install with the enrollment bundle.")
	if res.Output == install.OutputSystemd {
		dim.Fprintf(w, "  logs: journalctl -fu %s\n", res.Spec.UnitFileName())
	}
}

// printPacketFilter reports the firewall grant: what the upgrade did to it, or,
// on a device without it, the flag that adds it — and then the update channel
// and the remote-upgrade helper the same way (Task 20376). Silent for outputs
// that have none of them to report.
func printPacketFilter(w io.Writer, res install.UpgradeResult) {
	if res.Output != install.OutputSystemd {
		return
	}
	defer printUpdates(w, res)
	dim := color.New(color.Faint)
	switch {
	case res.PacketFilterChange != "":
		fmt.Fprintf(w, "  firewall: %s\n", res.PacketFilterChange)
	case res.PacketFilterGranted:
		dim.Fprintf(w, "  firewall: granted (the agent holds CAP_NET_ADMIN for nft(8))\n")
	default:
		color.New(color.FgYellow).Fprintf(w, "  firewall: not granted — %s\n", install.PacketFilterHint)
	}
}

// printUpdates reports which builds the device accepts and whether the hub can
// move it, naming what changed.
func printUpdates(w io.Writer, res install.UpgradeResult) {
	dim := color.New(color.Faint)
	for _, line := range res.UnitChanges {
		if line != res.PacketFilterChange {
			fmt.Fprintf(w, "  changed: %s\n", line)
		}
	}
	switch res.Channel {
	case provenance.ChannelEdge:
		dim.Fprintf(w, "  channel: edge — releases, and signed builds of main that passed CI\n")
	default:
		dim.Fprintf(w, "  channel: stable — published releases only\n")
	}
	if res.RemoteUpgradeInstalled {
		dim.Fprintf(w, "  remote upgrade: %s is armed\n", res.Spec.UpgradeHelperPathUnitName())
	} else {
		color.New(color.FgYellow).Fprintf(w, "  remote upgrade: not installed — the hub cannot upgrade this "+
			"device; re-run with --remote-upgrade\n")
	}
}

// printVerification reports what the staged binary said about itself.
//
// A skipped check is printed as skipped rather than omitted. An operator reading
// output with no verification line would reasonably conclude the binary was
// checked and found good, and the one mode where it is not checked — a staged
// install, whose target is another machine — is exactly the mode where that
// assumption is wrong.
func printVerification(w io.Writer, res install.UpgradeResult) {
	dim := color.New(color.Faint)
	if !res.Verified {
		dim.Fprintln(w, "  verified: skipped (staged install: the binary is for another machine)")
		return
	}
	fmt.Fprintf(w, "  verified: %s\n", res.StagedBuild)
	if prev := res.InstalledBuild.Version; prev != "" && prev != res.StagedBuild.Version {
		dim.Fprintf(w, "  replacing: %s\n", prev)
	}
}

// shortChecksum abbreviates a content checksum for display, naming an absent one
// rather than printing a blank field.
func shortChecksum(d string) string {
	if d == "" {
		return "unknown"
	}
	if len(d) > 12 {
		return d[:12]
	}
	return d
}

// printInstalled tells the operator what to do next, in the order they will
// want it: is it running, where are the logs, how do I undo this.
func printInstalled(p install.Plan) {
	ok := color.New(color.FgGreen, color.Bold)
	dim := color.New(color.Faint)

	switch p.Output {
	case install.OutputSystemd:
		ok.Printf("\nInstalled %s.\n", p.Spec.UnitFileName())
		fmt.Printf("  unit:    %s\n", p.Spec.UnitPath())
		fmt.Printf("  state:   %s\n", p.Spec.StateDir)
		fmt.Printf("  user:    %s (no login shell)\n", p.Spec.User)
		if p.Spec.PacketFilter {
			fmt.Printf("  firewall: CAP_NET_ADMIN for nft(8) only, in %s\n", p.Spec.PacketFilterDropInPath())
		} else {
			fmt.Printf("  firewall: withheld (--packet-filter=false); a sandbox with a firewall is refused here\n")
		}
		if p.Spec.Channel == provenance.ChannelEdge {
			fmt.Printf("  channel: edge — releases and signed builds of main, in %s\n", p.Spec.ChannelDropInPath())
		} else {
			fmt.Printf("  channel: stable — published releases only\n")
		}
		if p.Spec.RemoteUpgrade {
			fmt.Printf("  remote upgrade: %s carries out the hub's Upgrade, as root\n", p.Spec.UpgradeHelperPathUnitName())
		} else {
			fmt.Printf("  remote upgrade: withheld (--remote-upgrade=false); the hub's Upgrade is refused here\n")
		}
		fmt.Printf("  server:  %s\n", p.Spec.Server)
		if p.Spec.Pin != "" {
			fmt.Printf("  pin:     %s\n", p.Spec.Pin)
		}
		fmt.Println()
		dim.Printf("  logs:      journalctl -fu %s\n", p.Spec.UnitFileName())
		dim.Printf("  status:    systemctl status %s\n", p.Spec.UnitFileName())
		dim.Printf("  uninstall: cloop executor agent install --uninstall --purge\n")
	case install.OutputShell:
		ok.Printf("\nInstalled %s.\n", p.Spec.InitScriptPath())
		dim.Printf("  logs:      tail -f /var/log/%s.log\n", p.Spec.ServiceName)
		dim.Printf("  uninstall: cloop executor agent install --output shell --uninstall --purge\n")
	case install.OutputDocker:
		ok.Printf("\nWrote %s (mode 0600).\n", p.Spec.CredentialsFile)
		fmt.Println(p.Display)
	}
	if p.Spec.Pin == "" {
		color.New(color.FgYellow, color.Bold).Println(
			"\nNo certificate pin: this device will verify the hub against the system trust store only.")
		dim.Println("  Point the hub's ui.tls at a real certificate and re-enroll to pin it.")
	}
}

func init() {
	f := executorAgentInstallCmd.Flags()

	f.String("output", string(install.OutputSystemd), "systemd, docker, or shell")
	f.Bool("dry-run", false, "print what would be written without touching the filesystem")
	f.Bool("uninstall", false, "remove a previous install; idempotent")
	f.Bool("purge", false, "with --uninstall, also delete the agent's identity and workspaces")
	f.Bool("upgrade", false,
		"replace the binary of an existing install and restart it; idempotent, keeps the unit and credentials")
	f.String("from", "",
		"with --upgrade, the new cloop binary to install (default: this executable)")
	// --bundle-sig, not --bundle: --bundle already means the enrollment bundle
	// on this same command, and two flags a letter apart meaning entirely
	// different secrets is how an operator pastes an enrollment token into a
	// signature path.
	f.String("bundle-sig", "",
		"with --upgrade, the Sigstore bundle proving the new binary's provenance "+
			"(default: <binary>.sigstore.json beside it)")
	f.Bool("insecure-skip-verify", false,
		"with --upgrade, install without verifying the new binary's signature. Required "+
			"for a locally built binary, which has no signature; for a release, it gives up "+
			"the proof that the binary came from cloop's release workflow")
	f.Bool("force", false,
		"with --upgrade, replace and restart even when the installed binary is already identical, "+
			"or when the new one is a downgrade")
	f.Duration("settle-timeout", 0,
		"with --upgrade, how long to wait for the restarted service to come back before rolling "+
			"back to the previous binary (default 30s)")
	f.String("root", "",
		"stage the files beneath this directory instead of installing them, for image builds")
	f.String("to", "",
		"with --upgrade, fetch this published build from cloop's repository, verify its signature and "+
			"install it, instead of installing the running binary: a release tag, \"latest\", or — on a "+
			"device on the edge channel — edge:<commit>")
	f.String("channel", "",
		"the update channel this device follows: stable (published releases) or edge (signed builds of "+
			"main as well, so the hub can move it to its own build). A drop-in beside the unit that the "+
			"hub cannot change. With --upgrade it acts only when passed; edge also installs the "+
			"remote-upgrade helper. systemd output only")
	f.Bool("remote-upgrade", true,
		"install the root helper that carries out an upgrade the hub asks for (the agent itself runs "+
			"unprivileged and cannot replace its own binary). =false withholds it, and the hub's Upgrade "+
			"button is then refused by the device. With --upgrade it acts only when passed. systemd "+
			"output only")
	f.Bool("apply-request", false,
		"with --upgrade, carry out the upgrade request the agent filed; what the helper unit runs")
	_ = f.MarkHidden("apply-request")
	f.Bool("packet-filter", true,
		"grant the agent CAP_NET_ADMIN and netlink sockets, in a drop-in beside the unit, so it can "+
			"install sandboxes' IP firewalls with nft(8) — nothing the agent starts receives the "+
			"capability except nft. =false withholds it, and the device then refuses every sandbox with "+
			"a firewall. With --upgrade it acts only when passed: it grants or withdraws the drop-in on "+
			"an existing install. systemd output only")

	f.String("bundle", "",
		"enrollment bundle from `cloop executor enroll` (or set "+enrollBundleEnv+", "+
			"which keeps it out of this device's process list)")
	f.Bool("bundle-stdin", false, "read the enrollment bundle from stdin")
	f.String("token", "", "bare enrollment token, when you have one without a bundle")
	f.String("server", "", "control-plane WebSocket URL (default: from the bundle)")
	f.String("pin", "", "hub SPKI fingerprint to verify (default: from the bundle)")
	f.String("ca-file", "", "PEM bundle to trust in addition to the system store")

	f.String("service-name", install.DefaultServiceName, "unit, container and state directory name")
	f.String("user", "", "system user to run as (default: the service name)")
	f.String("group", "", "system group (default: the user)")
	f.String("binary", "", "path to the cloop binary on this device (default: this executable)")
	f.String("state-dir", "", "state directory (default: /var/lib/<service-name>)")
	f.String("unit-dir", install.DefaultUnitDir, "where to write the systemd unit")
	f.String("init-dir", install.DefaultInitDir, "where to write the --output shell init script")
	f.String("credentials-file", "",
		"0600 file holding the enrollment token (default: <state-dir>/enrollment)")
	f.String("workdir-root", "", "confine every workload beneath this directory (default: <state-dir>/work)")
	f.Int("max-concurrent", 0, "maximum simultaneous workloads (default: number of CPUs)")
	f.StringSlice("label", nil, "scheduler selector as key=value (repeatable)")
	f.String("image", install.DefaultImage, "container image, with --output docker")
	f.Bool("no-start", false, "install without enabling or starting, for golden images")

	executorAgentCmd.AddCommand(executorAgentInstallCmd)
}
