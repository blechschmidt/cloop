package cmd

// forward_bind_cmd.go: `cloop forward bind | unbind | bindings` (Task 20430).
//
// A binding makes a forwarder's device available to one project's runs —
// optionally only those on one virtual executor — for a TTL. These commands
// act on the control plane in the current directory, like `cloop forward
// enroll`, and go through the same rules the dashboard does
// (ui.CreateForwarderBinding): the binding is validated and audited as
// forwarder.bind or forwarder.unbind. An unbind is announced to the running
// hubs, which detach the device from any run holding it at once; a hub that
// misses the announcement does so at its next re-check of the store, within
// seconds.

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/statedb"
	"github.com/blechschmidt/cloop/pkg/ui"
)

var forwardBindCmd = &cobra.Command{
	Use:   "bind <forwarder-id>",
	Short: "Make a forwarder's device available to a project's runs",
	Long: `Bind a device forwarder to a project.

While the binding is in force, every run of the project gets the forwarder's
device in its sandbox: the hub relays the forwarder's stream to the executor
that runs the sandbox, which attaches the device there — a USB device through
vhci_hcd, a network segment as a TAP — with no listener anywhere. A run whose
bound forwarder is offline is refused, naming it.

--virtual-executor narrows the binding to runs on one virtual executor. For a
network segment, --target names the interface inside the sandbox (default
fwd0) and --address/--gateway/--mtu configure it.

The binding lasts --ttl (default 24h, at most 90 days); revoke it earlier with
` + "`cloop forward unbind <binding-id>`" + `.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		project, _ := cmd.Flags().GetString("project")
		vx, _ := cmd.Flags().GetString("virtual-executor")
		ttl, _ := cmd.Flags().GetDuration("ttl")
		note, _ := cmd.Flags().GetString("note")
		target, _ := cmd.Flags().GetString("target")
		address, _ := cmd.Flags().GetString("address")
		gateway, _ := cmd.Flags().GetString("gateway")
		mtu, _ := cmd.Flags().GetInt("mtu")

		dir, err := bindingProjectDir(project)
		if err != nil {
			return err
		}
		_, db, err := openForwarderStore()
		if err != nil {
			return err
		}
		defer db.Close()
		row, err := ui.CreateForwarderBinding(db, ui.ForwarderBindingInput{
			ForwarderID:     args[0],
			Project:         dir,
			VirtualExecutor: vx,
			Interface:       ui.ForwarderBindingInterface(target, address, gateway, mtu),
			TTL:             ttl,
			Note:            note,
			Actor:           operatorActor(),
		}, time.Now())
		if err != nil {
			return err
		}
		color.New(color.FgCyan, color.Bold).Printf("Forwarder %s bound\n\n", row.ForwarderID)
		fmt.Printf("  binding:  %s\n", row.ID)
		fmt.Printf("  project:  %s\n", row.Project)
		if row.VirtualExecutor != "" {
			fmt.Printf("  only on:  virtual executor %s\n", row.VirtualExecutor)
		}
		fmt.Printf("  expires:  %s\n\n", row.ExpiresAt.Format(time.RFC3339))
		fmt.Printf("Revoke it with:\n  cloop forward unbind %s\n", row.ID)
		return nil
	},
}

var forwardUnbindCmd = &cobra.Command{
	Use:   "unbind <binding-id>",
	Short: "Revoke a forwarder binding, detaching the device from any run holding it",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		reason, _ := cmd.Flags().GetString("reason")
		_, db, err := openForwarderStore()
		if err != nil {
			return err
		}
		defer db.Close()
		actor := operatorActor()
		if strings.TrimSpace(reason) == "" {
			reason = "unbound by " + actor
		}
		b, changed, err := ui.RevokeForwarderBindingRecord(db, args[0], actor, reason, time.Now())
		if err != nil {
			return err
		}
		if !changed {
			fmt.Printf("Binding %s was already revoked.\n", b.ID)
			return nil
		}
		fmt.Printf("Unbound %s (forwarder %s from %s).\n", b.ID, b.ForwarderID, b.Project)
		announceForwarderRevocation(db, b.ForwarderID, b.ID, "its binding was revoked: "+reason)
		return nil
	},
}

var forwardBindingsCmd = &cobra.Command{
	Use:   "bindings",
	Short: "List forwarder bindings",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		project, _ := cmd.Flags().GetString("project")
		all, _ := cmd.Flags().GetBool("all")
		_, db, err := openForwarderStore()
		if err != nil {
			return err
		}
		defer db.Close()
		f := statedb.ForwarderBindingFilter{}
		if strings.TrimSpace(project) != "" {
			dir, err := filepath.Abs(project)
			if err != nil {
				return err
			}
			f.Project = dir
		}
		now := time.Now()
		if !all {
			f.ActiveAt = now
		}
		rows, err := db.ListForwarderBindings(f)
		if err != nil {
			return err
		}
		if len(rows) == 0 {
			fmt.Println("No forwarder bindings.")
			return nil
		}
		for _, b := range rows {
			state := "active until " + b.ExpiresAt.Format(time.RFC3339)
			switch {
			case b.Revoked():
				state = "revoked " + b.RevokedAt.Format(time.RFC3339)
			case b.Expired(now):
				state = "expired " + b.ExpiresAt.Format(time.RFC3339)
			}
			vx := ""
			if b.VirtualExecutor != "" {
				vx = " (only on " + b.VirtualExecutor + ")"
			}
			fmt.Printf("%-22s  %-18s  %s%s  %s\n", b.ID, b.ForwarderID, b.Project, vx, state)
		}
		return nil
	},
}

// bindingProjectDir resolves --project to the project directory a binding
// names: an existing directory holding a cloop project.
func bindingProjectDir(project string) (string, error) {
	if strings.TrimSpace(project) == "" {
		return "", fmt.Errorf("--project is required")
	}
	dir, err := filepath.Abs(project)
	if err != nil {
		return "", err
	}
	if fi, err := os.Stat(filepath.Join(dir, ".cloop")); err != nil || !fi.IsDir() {
		return "", fmt.Errorf("%s is not a cloop project (no .cloop directory)", dir)
	}
	return dir, nil
}

// announceForwarderRevocation tells the running hubs to cut what a revoked
// forwarder or binding had, and says so.
func announceForwarderRevocation(db *statedb.DB, forwarderID, bindingID, reason string) {
	faint := color.New(color.Faint)
	if err := ui.AnnounceForwarderRevocation(db, cliOrigin(), forwarderID, bindingID, reason); err != nil {
		color.New(color.FgYellow).Printf("  The running hubs could not be told: %v\n", err)
		faint.Println("  Each re-checks the store within seconds and detaches the device then.")
		return
	}
	faint.Println("  Running hubs were told, and detach the device from any run holding it at once.")
}

// auditForwarderCLI records a forwarder decision made from the CLI.
func auditForwarderCLI(db *statedb.DB, action auditaction.Action, forwarderID string, detail map[string]any) {
	statedb.AuditForwarderLifecycle(db.AsControlPlane(), statedb.ForwarderAuditInput{
		Action: action, ForwarderID: forwarderID, Actor: operatorActor(), Detail: detail,
	})
}

func init() {
	forwardBindCmd.Flags().String("project", "", "the project directory whose runs get the device")
	forwardBindCmd.Flags().String("virtual-executor", "", "only runs on this virtual executor get it")
	forwardBindCmd.Flags().Duration("ttl", ui.ForwarderBindingTTLDefault, "how long the binding lasts (at most 90 days)")
	forwardBindCmd.Flags().String("note", "", "why, for the audit trail")
	forwardBindCmd.Flags().String("target", "", "network segment only: the interface name inside the sandbox (default fwd0)")
	forwardBindCmd.Flags().String("address", "", "network segment only: a CIDR to configure on it in the sandbox")
	forwardBindCmd.Flags().String("gateway", "", "network segment only: a default route through it")
	forwardBindCmd.Flags().Int("mtu", 0, "network segment only: its MTU in the sandbox")
	forwardUnbindCmd.Flags().String("reason", "", "why, for the audit trail")
	forwardBindingsCmd.Flags().String("project", "", "only this project's bindings")
	forwardBindingsCmd.Flags().Bool("all", false, "include revoked and expired bindings")
	forwardCmd.AddCommand(forwardBindCmd, forwardUnbindCmd, forwardBindingsCmd)
}
