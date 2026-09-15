package cmd

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/diskusage"
	"github.com/blechschmidt/cloop/pkg/janitor"
	"github.com/blechschmidt/cloop/pkg/multiui"
)

// `cloop hub retention` is the manual face of the janitor the hub runs on a
// timer (Task 20229).
//
// It exists for two things the background pass cannot do. The first is a dry
// run: an operator about to enable retention on a hub holding real history
// wants to see what would go before it goes, and "trust the daily timer" is
// not an answer. The second is a hub that is not running — the disk fills
// whether or not the server is up, and the recovery path must not require
// starting the process whose database is the problem.

var (
	hubRetentionDryRun bool
	hubRetentionJSON   bool
)

var hubRetentionCmd = &cobra.Command{
	Use:   "retention",
	Short: "Report or apply .cloop disk retention",
	Long: `Report what .cloop costs and, optionally, reclaim it.

Runs the same retention pass the hub performs on its own schedule: bound
plan-history to the configured keep-count, apply size and age limits to the
sealed audit archive, bound the row tables that grow with every unit of work
(provider calls, steps, events, costs, telemetry), and VACUUM the database when
its freelist has grown large enough to be worth rewriting the file for.

With no flags this is a DRY RUN — nothing is deleted and nothing is vacuumed.
Pass --apply to actually reclaim.

Row pruning and the VACUUM report different numbers on purpose. Deleting a row
frees a page inside state.db; only the VACUUM hands pages back to the
filesystem. The row steps therefore run first, so the same pass can reclaim what
they released.

The VACUUM step is refused while another hub holds the control-plane lease,
because it rewrites the database file underneath that process's open
connections. The step-history prune is skipped while a run is executing here,
because a live run rewrites its own step history from memory. Everything else is
safe alongside a running hub and still applies.`,
	Example: `  cloop hub retention                # what would be reclaimed
  cloop hub retention --json         # the same, machine-readable
  cloop hub retention --apply        # reclaim it`,
	RunE: runHubRetention,
}

func runHubRetention(cmd *cobra.Command, _ []string) error {
	workDir, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("resolve working directory: %w", err)
	}

	cfg, err := config.Load(workDir)
	if err != nil {
		// The default policy prunes derived data only, so proceeding is safe
		// and is better than letting an unparseable config exempt a project
		// from retention. Say which policy is in force.
		fmt.Fprintf(os.Stderr, "warning: could not load config (%v); using default retention policy\n", err)
		cfg = nil
	}
	pol := janitor.PolicyFromConfig(cfg)

	// A `cloop run` executing in this directory keeps the whole step history in
	// memory and upserts all of it on every save, so pruning steps underneath
	// it is work that undoes itself. Probing the process table is how the
	// dashboard answers the same question, and it is the only signal available
	// to a command running outside the hub.
	running := multiui.IsCloopRunningInDir(workDir)

	rep, err := janitor.RunOnce(janitor.Options{
		WorkDir:         workDir,
		Policy:          pol,
		DryRun:          hubRetentionDryRun,
		RunActive:       running,
		RunActiveReason: "a cloop run is executing in this directory",
	})
	if err != nil {
		return err
	}

	if hubRetentionJSON {
		if err := printJSON(rep); err != nil {
			return err
		}
	} else {
		renderRetention(rep, pol)
	}

	// Checked after rendering, and for both formats. JSON is the mode a cron
	// wrapper uses, so returning early from it would hide exactly the failures
	// the wrapper exists to notice — and StepResult.Err marshals to an empty
	// object, so the payload alone cannot be relied on either.
	if errs := rep.Errs(); len(errs) > 0 {
		return fmt.Errorf("%d retention step(s) failed: %w", len(errs), errors.Join(errs...))
	}

	// A manual pass resets the hub's cadence. Without this the hub repeats the
	// work minutes later, which on a large database is the expensive half.
	if !hubRetentionDryRun {
		if err := janitor.MarkRun(workDir, time.Now()); err != nil {
			fmt.Fprintf(os.Stderr, "warning: %v\n", err)
		}
	}
	return nil
}

func renderRetention(rep *janitor.Report, pol janitor.Policy) {
	header := color.New(color.FgCyan, color.Bold)
	dim := color.New(color.Faint)
	warn := color.New(color.FgYellow)
	good := color.New(color.FgGreen)

	header.Printf("cloop hub retention — %s\n", rep.WorkDir)
	if rep.DryRun {
		dim.Println("dry run: nothing was deleted or vacuumed (pass --apply to reclaim)")
	}
	fmt.Println()

	if u := rep.Before; u != nil {
		fmt.Printf("%-22s %s\n", "Total .cloop", diskusage.HumanBytes(u.TotalBytes))
		for _, e := range u.Entries {
			if e.Bytes < 10<<20 {
				break // Entries is sorted largest-first
			}
			files := ""
			if e.IsDir {
				files = fmt.Sprintf("  (%d files)", e.Files)
			}
			dim.Printf("  %-20s %s%s\n", e.Name, diskusage.HumanBytes(e.Bytes), files)
		}
		if u.DBBytes > 0 && u.DBError == "" {
			fmt.Printf("%-22s %s of %s (%.0f%%)\n", "Reclaimable pages",
				diskusage.HumanBytes(u.ReclaimableBytes), diskusage.HumanBytes(u.DBBytes), u.FreeRatio*100)
		}
		fmt.Println()
	}

	steps := []struct {
		name string
		res  janitor.StepResult
		// unit names what Deleted counts, which differs by step: the
		// file-level steps delete files and the row steps delete rows.
		unit string
	}{
		{"plan-history", rep.PlanHistory, "file"},
		{"audit-archive", rep.Archive, "file"},
		{"provider-calls", rep.ProviderCalls, "row"},
		{"steps", rep.Steps, "row"},
		{"events", rep.Events, "row"},
		{"costs", rep.Costs, "row"},
		{"telemetry", rep.Telemetry, "row"},
		{"vacuum", rep.Vacuum, "file"},
	}
	for _, s := range steps {
		switch {
		case s.res.Err != nil:
			warn.Printf("  ✗ %-16s %v\n", s.name, s.res.Err)
		case s.res.Deleted > 0 || s.res.BytesFreed > 0 || s.res.BytesReleased > 0:
			good.Printf("  ✓ %-16s ", s.name)
			// Row steps free pages inside the file rather than disk, so they
			// report their own number; printing it as "reclaimed" would
			// promise a shrink only the VACUUM can deliver.
			fmt.Printf("%s", diskusage.HumanBytes(s.res.BytesFreed+s.res.BytesReleased))
			if s.res.Deleted > 0 {
				fmt.Printf(" in %d %s(s)", s.res.Deleted, s.unit)
			}
			fmt.Printf(" — %s\n", s.res.Reason)
		default:
			dim.Printf("  · %-16s %s\n", s.name, s.res.Reason)
		}
	}

	fmt.Println()
	verb := "Would reclaim"
	if !rep.DryRun {
		verb = "Reclaimed"
	}
	fmt.Printf("%s %s in %s\n", verb, diskusage.HumanBytes(rep.BytesFreed()), rep.Duration.Round(time.Millisecond))
	// Stated separately from the reclaim above, because these bytes are still
	// inside state.db: deleting a row frees a page, and only a VACUUM hands
	// pages back to the filesystem.
	if released := rep.BytesReleased(); released > 0 {
		note := "released to the database freelist"
		if !rep.Vacuum.Ran {
			note += "; a future VACUUM returns it to the filesystem"
		}
		fmt.Printf("%s %s %s\n", verb, diskusage.HumanBytes(released), note)
	}
	if !pol.Enabled {
		warn.Println("note: retention.enabled is false, so the hub will not do this on its own")
	}
}

func init() {
	// --apply rather than --dry-run defaulting to false: the destructive
	// direction should be the one you have to ask for, on a command whose
	// whole subject is deleting things.
	var apply bool
	hubRetentionCmd.Flags().BoolVar(&apply, "apply", false, "Actually delete and vacuum (default is a dry run)")
	hubRetentionCmd.Flags().BoolVar(&hubRetentionJSON, "json", false, "Emit the report as JSON")
	hubRetentionCmd.PreRun = func(_ *cobra.Command, _ []string) {
		hubRetentionDryRun = !apply
	}
	hubCmd.AddCommand(hubRetentionCmd)
}
