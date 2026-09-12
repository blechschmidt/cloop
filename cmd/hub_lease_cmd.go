package cmd

// hub_lease_cmd.go is the operator's view of the control-plane fence
// (Task 20214).
//
// The fence itself is automatic: `cloop ui` takes a lease at startup, renews it
// while it serves, releases it on a clean shutdown, and treats a lease nobody
// has renewed for a TTL as free. An operator never has to think about it in the
// ordinary case, including the crash case — that is the point of a lease rather
// than a lock file.
//
// What this command adds is the two things automation cannot do. `status`
// answers "why did my hub refuse to start, and how long until it can" without
// making someone read a SQLite table. `clear` releases a lapsed lease on
// purpose, for the case where the row should reflect reality before something
// else happens to the volume — a restore, a migration, a handover to another
// node — and no hub is going to be started to do it implicitly.
//
// `clear` refuses while the lease is live, and there is deliberately no --force.
// The failure mode of a forcing escape hatch is an operator evicting a hub that
// was working, which produces precisely the two-hub state the fence exists to
// prevent, except now with the newcomer believing it is sole owner. A lease that
// really is abandoned lapses on its own, so force would unblock nothing that
// waiting does not.

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/blechschmidt/cloop/pkg/hublease"
	"github.com/blechschmidt/cloop/pkg/state"
)

var hubLeaseCmd = &cobra.Command{
	Use:   "lease",
	Short: "Inspect or release the control-plane lease that fences this hub's state",
	Long: `Inspect or release the instance lease on this directory's control plane.

One cloop hub owns one .cloop/state.db. The hub keeps its project-status cache,
run registry and WebSocket clients in memory, so a second hub against the same
database does not share load — it diverges, silently, while both run the same
background sweeps. The lease makes that a startup error instead.

  cloop hub lease status    who holds it, and when it lapses
  cloop hub lease clear     release a lapsed lease explicitly`,
}

var hubLeaseStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show who holds this directory's control-plane lease",
	Long: `Show the control-plane lease for the current directory.

Exit code 0 whatever the state — this reports, it does not assert. Use it when a
hub refuses to start to see which process is holding the lease and, if that
process is already gone, how long remains before the lease lapses on its own.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()
		dbPath := state.DBPath(workdir)

		st, err := hublease.Inspect(hublease.Options{DBPath: dbPath})
		if err != nil {
			return err
		}

		bold := color.New(color.Bold)
		dim := color.New(color.Faint)
		bold.Printf("Control-plane lease\n")
		dim.Printf("  %s\n\n", dbPath)

		if !st.Present {
			fmt.Printf("  state      free — %s\n", st.Reason)
			return nil
		}

		row := st.Row
		if st.Live {
			color.New(color.FgGreen).Printf("  state      held\n")
		} else {
			color.New(color.FgYellow).Printf("  state      free — %s\n", st.Reason)
		}
		fmt.Printf("  instance   %s\n", row.InstanceID)
		if row.Hostname != "" {
			fmt.Printf("  host       %s", row.Hostname)
			if row.PID > 0 {
				fmt.Printf(" (pid %d)", row.PID)
			}
			fmt.Println()
		}
		if row.Address != "" {
			fmt.Printf("  serving    %s\n", row.Address)
		}
		if row.Version != "" {
			fmt.Printf("  version    %s\n", row.Version)
		}
		if !row.AcquiredAt.IsZero() {
			fmt.Printf("  acquired   %s\n", row.AcquiredAt.Format(time.RFC3339))
		}
		if !row.HeartbeatAt.IsZero() {
			fmt.Printf("  last beat  %s ago\n", st.Age.Round(time.Second))
		}
		if !row.ReleasedAt.IsZero() {
			fmt.Printf("  released   %s\n", row.ReleasedAt.Format(time.RFC3339))
		}
		if st.Live {
			fmt.Printf("  lapses in  %s if the holder stops renewing\n", st.Expires.Round(time.Second))
			fmt.Println()
			dim.Println("  Starting a second hub here will refuse while this lease is held.")
		}
		return nil
	},
}

var hubLeaseClearCmd = &cobra.Command{
	Use:   "clear",
	Short: "Release a lapsed control-plane lease",
	Long: `Release this directory's control-plane lease.

Refuses while the lease is live, and has no --force. A live lease means a hub is
renewing it right now, and evicting that hub would create the split-brain the
lease prevents — with the newcomer believing it is the only one. If the holder is
genuinely gone, the lease lapses by itself and the next ` + "`cloop ui`" + ` starts
without this command at all.

Use it when the row should reflect reality before something else touches the
volume — a restore, a move to another node — rather than as a way to start a
hub sooner.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()
		dbPath := state.DBPath(workdir)

		row, err := hublease.Clear(hublease.Options{DBPath: dbPath})
		if errors.Is(err, hublease.ErrLeaseLive) {
			// Not wrapped further: the message already names the holder and
			// says what to do, and a second layer of prefix would bury it.
			return err
		}
		if err != nil {
			return err
		}
		if row.InstanceID == "" {
			fmt.Println("No lease to clear — the control plane is free.")
			return nil
		}
		// Clear is a no-op on a lease whose holder already released it, and
		// says so rather than claiming a release it did not perform. An
		// operator running this after a clean shutdown should not be told
		// their command did something.
		if !row.ReleasedAt.IsZero() {
			fmt.Printf("Nothing to clear — %s released the lease at %s.\n",
				row.InstanceID, row.ReleasedAt.Format(time.RFC3339))
			return nil
		}
		color.New(color.FgGreen).Printf("Released the lease held by %s", row.InstanceID)
		if row.Hostname != "" {
			fmt.Printf(" (%s pid %d)", row.Hostname, row.PID)
		}
		fmt.Println(".")
		return nil
	},
}

func init() {
	hubLeaseCmd.AddCommand(hubLeaseStatusCmd)
	hubLeaseCmd.AddCommand(hubLeaseClearCmd)
	hubCmd.AddCommand(hubLeaseCmd)
}
