package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/blechschmidt/cloop/pkg/dbverify"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var dbCmd = &cobra.Command{
	Use:   "db",
	Short: "Inspect and maintain the .cloop SQLite state database",
	Long: `Subcommands for inspecting and maintaining the project's SQLite state
database (.cloop/state.db). Use these to detect on-disk corruption after
crashes or disk errors before it cascades into confusing runtime failures.`,
}

var dbVerifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Run SQLite integrity and foreign-key checks against .cloop/state.db",
	Long: `Run PRAGMA integrity_check and PRAGMA foreign_key_check against
.cloop/state.db. Reports any corruption found and exits non-zero if
issues are detected.

By default the thorough integrity_check is used. Pass --quick to use
PRAGMA quick_check instead, which is several times faster but skips the
exhaustive UNIQUE/PK index verification.

Exit codes:
  0  database passed all checks
  1  one or more issues were detected
  2  the verification itself could not run (file missing, permission denied, etc.)`,
	RunE: func(cmd *cobra.Command, args []string) error {
		quick, _ := cmd.Flags().GetBool("quick")

		workdir, _ := os.Getwd()
		dbPath := filepath.Join(workdir, ".cloop", "state.db")

		header := color.New(color.FgCyan, color.Bold)
		pass := color.New(color.FgGreen, color.Bold)
		fail := color.New(color.FgRed, color.Bold)
		dim := color.New(color.Faint)

		mode := "integrity_check"
		if quick {
			mode = "quick_check"
		}

		header.Printf("cloop db verify — %s\n", mode)
		dim.Printf("  database: %s\n\n", dbPath)

		rep, err := dbverify.Verify(dbPath, quick)
		if err != nil {
			fail.Printf("Verification could not run: %v\n", err)
			// Distinguish "could not run" from "found issues" with a separate exit code.
			os.Exit(2)
		}

		if rep.OK() {
			pass.Println("PASS — no integrity or foreign-key issues found.")
			return nil
		}

		if len(rep.IntegrityIssues) > 0 {
			fail.Printf("FAIL — %s reported %d issue(s):\n", mode, len(rep.IntegrityIssues))
			for _, msg := range rep.IntegrityIssues {
				fmt.Printf("  • %s\n", msg)
			}
			fmt.Println()
		}

		if len(rep.ForeignKeyViolations) > 0 {
			fail.Printf("FAIL — foreign_key_check reported %d violation(s):\n", len(rep.ForeignKeyViolations))
			for _, v := range rep.ForeignKeyViolations {
				rowid := "<null>"
				if v.RowID.Valid {
					rowid = fmt.Sprintf("%d", v.RowID.Int64)
				}
				fmt.Printf("  • table=%s rowid=%s parent=%s fkid=%d\n",
					v.Table, rowid, v.Parent, v.FKID)
			}
			fmt.Println()
		}

		dim.Println("Hint: corruption is rarely repairable in place. Restore from a recent")
		dim.Println("      'cloop snapshot' or 'cloop migrate' the project after backing it up.")

		os.Exit(1)
		return nil
	},
}

func init() {
	dbVerifyCmd.Flags().Bool("quick", false, "Use PRAGMA quick_check instead of integrity_check (faster, less thorough)")
	dbCmd.AddCommand(dbVerifyCmd)
	rootCmd.AddCommand(dbCmd)
}
