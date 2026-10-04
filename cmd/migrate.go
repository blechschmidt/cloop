package cmd

import (
	"fmt"
	"os"

	"github.com/blechschmidt/cloop/pkg/migrate"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var migrateCmd = &cobra.Command{
	Use:   "migrate",
	Short: "Upgrade and repair the .cloop project directory",
	Long: `Bring the project's state storage up to date, and repair what can be repaired
around it.

The project database (.cloop/state.db) is migrated automatically whenever any
cloop command opens it: its schema is the numbered migrations built into the
binary, recorded in the database's schema_migrations table. Two kinds of project
need this command, and cloop warns about them:

  legacy state.json   the project's state is still in .cloop/state.json —
                      it is converted into state.db
  pre-statedb         a state.db from before cloop versioned its schema —
                      it is adopted, and every migration since applied

For any other project, cloop migrate applies whatever migrations are pending —
the same thing the next command to open the database would do — and reports the
schema version before and after.

With --dry-run, nothing is written; the report says what would change.

Repairs are also performed: orphaned plan-history snapshot files are removed,
and config keys with invalid types are flagged.`,

	RunE: func(cmd *cobra.Command, args []string) error {
		workDir, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("resolve working directory: %w", err)
		}
		dryRun, _ := cmd.Flags().GetBool("dry-run")

		bold := color.New(color.Bold)
		cyan := color.New(color.FgCyan, color.Bold)
		green := color.New(color.FgGreen, color.Bold)
		yellow := color.New(color.FgYellow, color.Bold)
		red := color.New(color.FgRed, color.Bold)

		if dryRun {
			yellow.Println("dry-run mode — no changes will be written")
			fmt.Println()
		}

		report, repairs, err := migrate.Run(migrate.Options{WorkDir: workDir, DryRun: dryRun})
		if report != nil {
			printMigrateReport(report, bold, cyan, green, yellow)
		}
		if err != nil {
			return fmt.Errorf("migrate: %w", err)
		}

		// ── Repairs ──────────────────────────────────────────────────────────
		if len(repairs) > 0 {
			fmt.Println()
			cyan.Println("Repair report")
			for _, r := range repairs {
				if r.Fixed {
					fmt.Printf("  %s %-22s %s\n", green.Sprint("fixed"), r.Kind, r.Detail)
				} else if dryRun {
					fmt.Printf("  %s %-22s %s\n", yellow.Sprint("would fix"), r.Kind, r.Detail)
				} else {
					fmt.Printf("  %s %-22s %s\n", red.Sprint("unfixed"), r.Kind, r.Detail)
				}
			}
		}

		fmt.Println()
		after := report.After
		switch {
		case after.Kind == migrate.KindNone:
			fmt.Println("No project state here — nothing to migrate.")
		case after.Ahead():
			yellow.Printf("The database is at schema v%d, ahead of this binary (v%d).\n", after.SchemaVersion, after.LatestVersion)
		case dryRun && len(report.Steps) > 0:
			yellow.Println("Schema is not up to date; run 'cloop migrate' to apply the steps above.")
		case after.Kind == migrate.KindStatedb && after.Pending() == 0:
			green.Printf("Schema is up to date (statedb v%d).\n", after.SchemaVersion)
		default:
			yellow.Printf("Schema is not up to date: %s (this binary's latest: v%d).\n", after.Describe(), after.LatestVersion)
		}
		return nil
	},
}

func printMigrateReport(report *migrate.Report, bold, cyan, green, yellow *color.Color) {
	cyan.Println("Migration report")
	fmt.Printf("  Before : %s\n", report.Before.Describe())
	if !report.DryRun {
		fmt.Printf("  After  : %s\n", report.After.Describe())
	}
	fmt.Printf("  Latest : statedb v%d (this binary)\n", report.Before.LatestVersion)
	fmt.Println()

	if len(report.Steps) == 0 {
		green.Println("  Nothing to migrate.")
	} else {
		bold.Println("  Steps:")
		for _, s := range report.Steps {
			if s.Applied {
				fmt.Printf("%s%s\n", green.Sprint("  ✓ "), s.Note)
			} else {
				fmt.Printf("  - %s\n", s.Note)
			}
		}
	}

	if len(report.Warnings) > 0 {
		fmt.Println()
		yellow.Println("  Warnings:")
		for _, w := range report.Warnings {
			fmt.Printf("  ! %s\n", w)
		}
	}
}

func init() {
	migrateCmd.Flags().Bool("dry-run", false, "Print what would change without writing anything")
	// --from-version overrode the version pkg/migrate detected from its own
	// bookkeeping, which no longer exists (Task 20374): the schema version is
	// statedb's, read from the database. Accepted and ignored so a script that
	// passes it still runs.
	migrateCmd.Flags().Int("from-version", -1, "Ignored: the schema version is read from the database")
	_ = migrateCmd.Flags().MarkDeprecated("from-version",
		"the schema version is read from statedb's own bookkeeping and cannot be overridden")
	rootCmd.AddCommand(migrateCmd)
}
