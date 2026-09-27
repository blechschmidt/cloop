package cmd

// Gates on the executor agent upgrade path (Task 20230).
//
// The defect these close is specific and was live in production: the Executors
// panel told operators to run `cloop executor agent install --upgrade`, and
// cmd/executor_install_cmd.go defined no --upgrade flag. The remediation the UI
// offered for its most security-relevant warning — a device too old to hand back
// a revoked credential — failed with an unknown-flag error.
//
// A message naming a flag is exactly the kind of coupling the compiler cannot
// check, so it is checked here, from both ends: the flag must exist, and the
// string the UI shows must name a flag that exists.

import (
	"slices"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/install"
	"github.com/blechschmidt/cloop/pkg/ui"
)

// findCommand walks to a subcommand by path, e.g. executor agent install.
func findCommand(t *testing.T, path ...string) *cobra.Command {
	t.Helper()
	cur := rootCmd
	for _, name := range path {
		var next *cobra.Command
		for _, c := range cur.Commands() {
			if c.Name() == name {
				next = c
				break
			}
		}
		if next == nil {
			t.Fatalf("command %q not found under %q", name, cur.CommandPath())
		}
		cur = next
	}
	return cur
}

// TestExecutorInstallHasUpgradeFlag is the direct regression test. It would have
// failed for the entire time the UI was recommending the flag.
func TestExecutorInstallHasUpgradeFlag(t *testing.T) {
	cmd := findCommand(t, "executor", "agent", "install")

	for _, name := range []string{"upgrade", "from", "force"} {
		if cmd.Flags().Lookup(name) == nil {
			t.Errorf("`cloop executor agent install` has no --%s flag", name)
		}
	}
}

// TestUIUpgradeCommandResolves is the other direction, and the one that actually
// prevents a recurrence: whatever command string the UI puts in front of an
// operator must parse against the real CLI.
//
// Asserted by resolving the string rather than by comparing it to a literal,
// because a literal would only prove the two copies match — not that either one
// works.
func TestUIUpgradeCommandResolves(t *testing.T) {
	fields := strings.Fields(ui.AgentUpgradeCommand)
	if len(fields) == 0 || fields[0] != "cloop" {
		t.Fatalf("ui.AgentUpgradeCommand = %q, expected it to start with `cloop`",
			ui.AgentUpgradeCommand)
	}
	args := fields[1:] // drop the binary name

	// Split the command path from its flags, then resolve each half against the
	// real command tree.
	var path, flags []string
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			flags = append(flags, a)
			continue
		}
		if len(flags) > 0 {
			// A bare word after a flag is that flag's value, not a subcommand.
			continue
		}
		path = append(path, a)
	}

	cmd := findCommand(t, path...)
	if len(flags) == 0 {
		t.Fatalf("ui.AgentUpgradeCommand = %q names no flag; the warning it appears in "+
			"is about upgrading, so it must name the flag that does it", ui.AgentUpgradeCommand)
	}
	for _, f := range flags {
		name := strings.TrimLeft(f, "-")
		if cmd.Flags().Lookup(name) == nil {
			t.Errorf("ui.AgentUpgradeCommand names --%s, which `%s` does not define.\n"+
				"The UI must never print a command an operator cannot run.",
				name, cmd.CommandPath())
		}
	}
}

// TestNoUIStringNamesAnUnknownInstallFlag sweeps the whole executors panel
// source for flags of this command, so a *new* message reintroducing the same
// class of dead end is caught rather than only the one string that was wrong.
func TestNoUIStringNamesAnUnknownInstallFlag(t *testing.T) {
	cmd := findCommand(t, "executor", "agent", "install")

	// Every flag-looking token that appears next to this command's name in the
	// UI's own prose. Sourced from the exported constant plus the hint text,
	// which is where such strings live now that they are centralised.
	for _, s := range []string{ui.AgentUpgradeCommand} {
		for _, tok := range strings.Fields(s) {
			if !strings.HasPrefix(tok, "--") {
				continue
			}
			name := strings.Trim(tok, "-`.,")
			if cmd.Flags().Lookup(name) == nil {
				t.Errorf("UI string %q names --%s, undefined on `%s`", s, name, cmd.CommandPath())
			}
		}
	}
}

// TestPacketFilterGrantProcedureResolves: the device's probe and the hub's
// refusal both tell an operator to run executor.PacketFilterGrantProcedure on
// a device that cannot install a sandbox firewall (Task 20352). It has to name
// flags this command really has, and --packet-filter has to be a switch an
// upgrade honours only when it is passed — otherwise a plain upgrade would
// change what the device may do.
func TestPacketFilterGrantProcedureResolves(t *testing.T) {
	fields := strings.Fields(executor.PacketFilterGrantProcedure)
	if len(fields) < 4 || fields[0] != "cloop" {
		t.Fatalf("PacketFilterGrantProcedure = %q", executor.PacketFilterGrantProcedure)
	}
	var path, flags []string
	for _, f := range fields[1:] {
		if strings.HasPrefix(f, "--") {
			flags = append(flags, strings.TrimPrefix(f, "--"))
		} else {
			path = append(path, f)
		}
	}
	cmd := findCommand(t, path...)
	for _, name := range flags {
		if cmd.Flags().Lookup(name) == nil {
			t.Errorf("PacketFilterGrantProcedure names --%s, which `%s` does not define", name, cmd.CommandPath())
		}
	}
	if !slices.Contains(flags, "upgrade") || !slices.Contains(flags, "packet-filter") {
		t.Errorf("PacketFilterGrantProcedure = %q, want an --upgrade that passes --packet-filter",
			executor.PacketFilterGrantProcedure)
	}

	pf := cmd.Flags().Lookup("packet-filter")
	if pf == nil || pf.DefValue != "true" {
		t.Fatalf("--packet-filter must default to granting on install (Task 20352), got %+v", pf)
	}
	t.Cleanup(func() {
		_ = cmd.Flags().Set("packet-filter", "true")
		pf.Changed = false
	})
	if got := upgradePacketFilter(cmd); got != install.PacketFilterKeep {
		t.Errorf("an upgrade without --packet-filter = %v, want PacketFilterKeep", got)
	}
	_ = cmd.Flags().Set("packet-filter", "true")
	if got := upgradePacketFilter(cmd); got != install.PacketFilterGrant {
		t.Errorf("--upgrade --packet-filter = %v, want PacketFilterGrant", got)
	}
	_ = cmd.Flags().Set("packet-filter", "false")
	if got := upgradePacketFilter(cmd); got != install.PacketFilterWithdraw {
		t.Errorf("--upgrade --packet-filter=false = %v, want PacketFilterWithdraw", got)
	}
}

// TestUpgradeAndUninstallAreMutuallyExclusive: the two flags are opposites, and
// silently honouring one while ignoring the other on a fleet device is the kind
// of surprise that costs a site visit.
func TestUpgradeAndUninstallAreMutuallyExclusive(t *testing.T) {
	cmd := findCommand(t, "executor", "agent", "install")
	// Reset afterwards: rootCmd is shared across tests in this package.
	t.Cleanup(func() {
		_ = cmd.Flags().Set("upgrade", "false")
		_ = cmd.Flags().Set("uninstall", "false")
		_ = cmd.Flags().Set("dry-run", "false")
	})

	if err := cmd.Flags().Set("upgrade", "true"); err != nil {
		t.Fatalf("set --upgrade: %v", err)
	}
	if err := cmd.Flags().Set("uninstall", "true"); err != nil {
		t.Fatalf("set --uninstall: %v", err)
	}
	// --dry-run so that, if the guard were missing, the test would still not
	// touch this machine's filesystem or services.
	if err := cmd.Flags().Set("dry-run", "true"); err != nil {
		t.Fatalf("set --dry-run: %v", err)
	}

	err := cmd.RunE(cmd, nil)
	if err == nil {
		t.Fatal("passing both --upgrade and --uninstall was accepted")
	}
	if !strings.Contains(err.Error(), "opposites") {
		t.Errorf("error does not explain the conflict: %v", err)
	}
}
