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
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/blechschmidt/cloop/pkg/executor/install"
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

The token never appears in ExecStart. A unit file is world-readable and
` + "`systemctl show`" + ` prints the command line to anyone who asks, so the token is
written to a 0600 file that only the service user can read and the unit
carries its path. The agent deletes that file once the token is redeemed.

  --output docker   emit an equivalent podman run command and compose fragment
  --output shell    emit a POSIX init script for devices without systemd
  --dry-run         print what would be written, and write nothing
  --uninstall       reverse an install; idempotent, safe to re-run
  --upgrade         replace the binary of an existing install and restart it

--upgrade rolls a device forward without re-enrolling it. It replaces the binary
atomically and restarts the service, and it deliberately does nothing else: the
unit file and the credential are left exactly as they are, because re-rendering
the unit needs the control-plane URL and certificate pin from an enrollment
bundle that nobody still has months later. A unit change means re-running a full
install with the bundle.

It is idempotent — an upgrade to the identical binary copies nothing and
restarts nothing — and it refuses rather than half-installing a device that was
never installed in the first place.

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

  # Remove it, including the agent's identity and workspaces.
  sudo cloop executor agent install --uninstall --purge`,
	Args:          cobra.NoArgs,
	SilenceErrors: false,
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

			res, err := inst.Upgrade(spec, out, install.UpgradeOptions{
				Source: strings.TrimSpace(from), // empty: Upgrade uses this executable
				Force:  force,
				DryRun: dryRun,
			})
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
		dim.Fprintln(w, "  Nothing was replaced and the service was not restarted.")
		dim.Fprintln(w, "  Pass --force to replace and restart anyway.")
		return
	}

	if res.DryRun {
		header := color.New(color.FgCyan, color.Bold)
		header.Fprintf(w, "\nDry run — nothing was changed.\n")
		fmt.Fprintf(w, "  binary:  %s\n", res.Spec.BinaryPath)
		fmt.Fprintf(w, "  from:    %s\n", res.Source)
		fmt.Fprintf(w, "  build:   %s -> %s\n",
			shortChecksum(res.PreviousChecksum), shortChecksum(res.NewChecksum))
		dim.Fprintf(w, "\n  Would replace the binary and restart %s.\n", res.Spec.ServiceName)
		dim.Fprintln(w, "  The unit file and credential would be left unchanged.")
		return
	}

	ok.Fprintf(w, "\nUpgraded %s.\n", res.Spec.ServiceName)
	fmt.Fprintf(w, "  binary:  %s\n", res.Spec.BinaryPath)
	fmt.Fprintf(w, "  from:    %s\n", res.Source)
	fmt.Fprintf(w, "  build:   %s -> %s\n", shortChecksum(res.PreviousChecksum), shortChecksum(res.NewChecksum))

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
	dim.Fprintln(w, "  The unit file and credential were left unchanged.")
	dim.Fprintln(w, "  To change either, re-run a full install with the enrollment bundle.")
	if res.Output == install.OutputSystemd {
		dim.Fprintf(w, "  logs: journalctl -fu %s\n", res.Spec.UnitFileName())
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
	f.Bool("force", false,
		"with --upgrade, replace and restart even when the installed binary is already identical")
	f.String("root", "",
		"stage the files beneath this directory instead of installing them, for image builds")

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
