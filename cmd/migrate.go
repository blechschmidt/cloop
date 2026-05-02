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
	Long: `Detect the current schema version of .cloop/state.db (or the absence of it,
indicating a legacy JSON-backed project) and run all pending versioned migration
steps to bring it up to the current schema version.

Migration steps are idempotent and transactional — they can be re-run safely.

With --dry-run, nothing is written; only a report of what would change is printed.

Repairs are also performed: orphaned plan-history snapshot files are removed,
and config keys with invalid types are flagged.

Schema versions:
  v0  Legacy: state stored in .cloop/state.json (JSON flat file)
  v1  SQLite: state.json converted to .cloop/state.db
  v2  Current: plan_tasks extended with assignee, external_url, links columns`,

	RunE: func(cmd *cobra.Command, args []string) error {
		workDir, _ := os.Getwd()
		dryRun, _ := cmd.Flags().GetBool("dry-run")
		fromVersion, _ := cmd.Flags().GetInt("from-version")

		opts := migrate.Options{
			WorkDir:     workDir,
			DryRun:      dryRun,
			FromVersion: fromVersion,
		}

		bold := color.New(color.Bold)
		cyan := color.New(color.FgCyan, color.Bold)
		green := color.New(color.FgGreen, color.Bold)
		yellow := color.New(color.FgYellow, color.Bold)
		red := color.New(color.FgRed, color.Bold)
		dim := color.New(color.Faint)

		if dryRun {
			yellow.Println("dry-run mode — no changes will be written")
			fmt.Println()
		}

		report, repairs, err := migrate.Run(opts)
		if err != nil {
			return fmt.Errorf("migrate: %w", err)
		}

		// ── Migration steps ──────────────────────────────────────────────────
		cyan.Println("Migration report")
		fmt.Printf("  From version : v%d\n", report.FromVersion)
		fmt.Printf("  To version   : v%d (current: v%d)\n", report.ToVersion, migrate.CurrentVersion)
		if report.FilesConverted > 0 {
			fmt.Printf("  Files converted  : %d\n", report.FilesConverted)
		}
		if report.RowsMigrated > 0 {
			fmt.Printf("  Rows migrated    : %d\n", report.RowsMigrated)
		}
		fmt.Println()

		if len(report.Steps) == 0 {
			green.Println("  Already at current version — no migration needed.")
		} else {
			bold.Println("  Steps:")
			for _, s := range report.Steps {
				prefix := "  "
				if s.Applied {
					prefix = green.Sprint("  ✓ ")
				} else {
					prefix = dim.Sprint("  - ")
				}
				fmt.Printf("%sv%d → v%d  %s\n", prefix, s.From, s.To, s.Note)
			}
		}

		if len(report.Warnings) > 0 {
			fmt.Println()
			yellow.Println("  Warnings:")
			for _, w := range report.Warnings {
				fmt.Printf("  ! %s\n", w)
			}
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
		if report.ToVersion == migrate.CurrentVersion {
			green.Println("Schema is up to date (v" + fmt.Sprintf("%d", migrate.CurrentVersion) + ").")
		} else {
			yellow.Printf("Schema is at v%d (target: v%d).\n", report.ToVersion, migrate.CurrentVersion)
		}

		return nil
	},
}

func init() {
	migrateCmd.Flags().Bool("dry-run", false, "Print what would change without writing anything")
	migrateCmd.Flags().Int("from-version", -1, "Override the detected schema version (useful for testing)")
	rootCmd.AddCommand(migrateCmd)
}
