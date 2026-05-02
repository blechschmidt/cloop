package cmd

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var planCmd = &cobra.Command{
	Use:   "plan",
	Short: "Manage plan version history and diffs",
	Long: `Inspect the versioned history of your AI-managed task plan.

Subcommands:
  history          List all saved plan snapshots
  diff [v1] [v2]  Show a human-readable diff between two plan versions`,
}

var planHistoryCmd = &cobra.Command{
	Use:   "history",
	Short: "List all plan version snapshots",
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()
		if _, err := state.Load(workdir); err != nil {
			return err
		}

		metas, err := pm.ListSnapshots(workdir)
		if err != nil {
			return fmt.Errorf("listing snapshots: %w", err)
		}
		if len(metas) == 0 {
			fmt.Println("No plan snapshots found.")
			fmt.Println("Snapshots are created automatically when the plan changes in PM mode.")
			return nil
		}

		headerColor := color.New(color.FgCyan, color.Bold)
		dimColor := color.New(color.Faint)

		headerColor.Printf("%-6s  %-20s  %-8s  %s\n", "Ver", "Timestamp", "Tasks", "Summary")
		fmt.Println(strings.Repeat("─", 62))
		for _, m := range metas {
			ts := m.Timestamp.Local().Format("2006-01-02 15:04:05")
			fmt.Printf("v%-5d  %-20s  %-8d  ", m.Version, ts, m.TaskCount)
			dimColor.Printf("%s\n", m.Summary)
		}
		fmt.Println(strings.Repeat("─", 62))
		fmt.Printf("Total: %d snapshot(s)\n", len(metas))
		return nil
	},
}

var planDiffCmd = &cobra.Command{
	Use:   "diff [v1] [v2]",
	Short: "Show diff between two plan versions",
	Long: `Show a colorized diff between two plan versions.

  cloop plan diff          # diff between the last two snapshots
  cloop plan diff 3        # diff between v3 and the latest snapshot
  cloop plan diff 2 5      # diff between v2 and v5`,
	Args: cobra.MaximumNArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()
		if _, err := state.Load(workdir); err != nil {
			return err
		}

		metas, err := pm.ListSnapshots(workdir)
		if err != nil {
			return fmt.Errorf("listing snapshots: %w", err)
		}
		if len(metas) == 0 {
			return fmt.Errorf("no plan snapshots found — run 'cloop run --pm' to create a plan")
		}
		if len(metas) < 2 && len(args) < 2 {
			return fmt.Errorf("need at least 2 snapshots for a diff (have %d)", len(metas))
		}

		var v1, v2 int

		switch len(args) {
		case 0:
			// Default: last two snapshots.
			v1 = metas[len(metas)-2].Version
			v2 = metas[len(metas)-1].Version
		case 1:
			// One arg: compare it with the latest.
			parsed, err := parseVersion(args[0])
			if err != nil {
				return err
			}
			v1 = parsed
			v2 = metas[len(metas)-1].Version
		case 2:
			parsed1, err := parseVersion(args[0])
			if err != nil {
				return err
			}
			parsed2, err := parseVersion(args[1])
			if err != nil {
				return err
			}
			v1, v2 = parsed1, parsed2
		}

		if v1 == v2 {
			return fmt.Errorf("v%d and v%d are the same version", v1, v2)
		}

		snap1, err := pm.LoadSnapshot(workdir, v1)
		if err != nil {
			return fmt.Errorf("loading v%d: %w", v1, err)
		}
		snap2, err := pm.LoadSnapshot(workdir, v2)
		if err != nil {
			return fmt.Errorf("loading v%d: %w", v2, err)
		}

		diff := pm.DiffPlans(snap1.Plan, snap2.Plan)
		printPlanDiff(snap1, snap2, diff)
		return nil
	},
}

// parseVersion parses a version string like "3" or "v3" into an int.
func parseVersion(s string) (int, error) {
	s = strings.TrimPrefix(s, "v")
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("invalid version %q: must be a number (e.g. 3 or v3)", s)
	}
	return n, nil
}

// printPlanDiff prints a colorized human-readable plan diff.
func printPlanDiff(snap1, snap2 *pm.Snapshot, diff pm.PlanDiff) {
	addColor := color.New(color.FgGreen)
	removeColor := color.New(color.FgRed)
	changeColor := color.New(color.FgYellow)
	headerColor := color.New(color.FgCyan, color.Bold)
	dimColor := color.New(color.Faint)

	ts1 := snap1.Timestamp.Local().Format("2006-01-02 15:04:05")
	ts2 := snap2.Timestamp.Local().Format("2006-01-02 15:04:05")
	headerColor.Printf("Plan diff: v%d (%s)  →  v%d (%s)\n",
		snap1.Version, ts1, snap2.Version, ts2)
	fmt.Println(strings.Repeat("─", 72))

	if diff.IsEmpty() {
		dimColor.Println("No changes between these two versions.")
		return
	}

	// Added tasks.
	if len(diff.Added) > 0 {
		addColor.Printf("\n+ Added (%d task(s)):\n", len(diff.Added))
		for _, t := range diff.Added {
			rolePart := ""
			if t.Role != "" {
				rolePart = fmt.Sprintf(" [%s]", t.Role)
			}
			addColor.Printf("  + #%d [P%d]%s %s\n", t.ID, t.Priority, rolePart, t.Title)
			if t.Description != "" {
				dimColor.Printf("      %s\n", truncateStr(t.Description, 100))
			}
		}
	}

	// Removed tasks.
	if len(diff.Removed) > 0 {
		removeColor.Printf("\n- Removed (%d task(s)):\n", len(diff.Removed))
		for _, t := range diff.Removed {
			removeColor.Printf("  - #%d %s\n", t.ID, t.Title)
		}
	}

	// Changed tasks.
	if len(diff.Changed) > 0 {
		changeColor.Printf("\n~ Changed (%d task(s)):\n", len(diff.Changed))
		for _, td := range diff.Changed {
			changeColor.Printf("  ~ #%d %s\n", td.ID, td.Title)
			for _, fc := range td.Changes {
				dimColor.Printf("      %s: ", fc.Field)
				removeColor.Printf("%s", fc.OldValue)
				fmt.Printf(" → ")
				addColor.Printf("%s\n", fc.NewValue)
			}
		}
	}

	fmt.Println()
	fmt.Println(strings.Repeat("─", 72))
	total := len(diff.Added) + len(diff.Removed) + len(diff.Changed)
	fmt.Printf("Summary: ")
	if len(diff.Added) > 0 {
		addColor.Printf("+%d added  ", len(diff.Added))
	}
	if len(diff.Removed) > 0 {
		removeColor.Printf("-%d removed  ", len(diff.Removed))
	}
	if len(diff.Changed) > 0 {
		changeColor.Printf("~%d changed  ", len(diff.Changed))
	}
	dimColor.Printf("(%d total change(s))\n", total)
}

func init() {
	planCmd.AddCommand(planHistoryCmd)
	planCmd.AddCommand(planDiffCmd)
	rootCmd.AddCommand(planCmd)
}
