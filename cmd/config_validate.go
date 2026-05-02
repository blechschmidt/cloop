package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/blechschmidt/cloop/pkg/configvalidate"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var configValidateCmd = &cobra.Command{
	Use:   "validate",
	Short: "Validate config.yaml and state.db for schema and semantic correctness",
	Long: `Validate .cloop/config.yaml and .cloop/state.db for schema and semantic correctness.

Checks performed:
  - Unknown top-level keys in config.yaml
  - Provider references that don't match registered providers
  - Model strings empty when provider is configured
  - URL fields that are malformed (must be http/https)
  - Budget values that are negative
  - Hooks referencing non-executable scripts
  - Task fields with invalid or stuck status values in state.db
  - (with --probe) HTTP reachability of notification webhook URLs

Findings are reported as ERROR, WARN, or INFO. Exit code 1 when any ERROR exists.

Use --fix to auto-correct safe issues:
  - Strip unknown keys from config.yaml
  - Reset invalid/stuck task statuses to "pending" in state.db`,
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()
		fix, _ := cmd.Flags().GetBool("fix")
		probe, _ := cmd.Flags().GetBool("probe")

		opts := configvalidate.ValidateOptions{Fix: fix, Probe: probe}

		ctx := context.Background()
		rep, err := configvalidate.Run(ctx, workdir, opts)
		if err != nil {
			return fmt.Errorf("validate: %w", err)
		}

		// ── color setup ───────────────────────────────────────────────────
		headerColor := color.New(color.FgCyan, color.Bold)
		errorColor := color.New(color.FgRed, color.Bold)
		warnColor := color.New(color.FgYellow, color.Bold)
		infoColor := color.New(color.FgBlue)
		dimColor := color.New(color.Faint)
		passColor := color.New(color.FgGreen, color.Bold)

		headerColor.Println("cloop config validate")
		fmt.Println()

		if len(rep.Findings) == 0 {
			passColor.Println("  No issues found — config and state look valid.")
		} else {
			// Header row
			fmt.Printf("  %-8s  %-44s  %s\n", "SEVERITY", "FIELD", "MESSAGE")
			fmt.Println("  " + strings.Repeat("─", 100))

			for _, f := range rep.Findings {
				var sevStr string
				switch f.Severity {
				case configvalidate.SeverityError:
					sevStr = errorColor.Sprint("ERROR   ")
				case configvalidate.SeverityWarn:
					sevStr = warnColor.Sprint("WARN    ")
				case configvalidate.SeverityInfo:
					sevStr = infoColor.Sprint("INFO    ")
				}
				fmt.Printf("  %s  %-44s  %s\n", sevStr, f.Field, f.Message)
				if f.FixNote != "" && !fix {
					dimColor.Printf("             fix: %s\n", f.FixNote)
				}
			}
		}

		// ── auto-fix summary ─────────────────────────────────────────────
		if len(rep.Fixed) > 0 {
			fmt.Println()
			passColor.Printf("  Auto-fixed %d issue(s):\n", len(rep.Fixed))
			for _, fix := range rep.Fixed {
				dimColor.Printf("    • %s\n", fix)
			}
		}

		// ── summary line ──────────────────────────────────────────────────
		fmt.Println()
		errs, warns, infos := rep.Counts()
		summary := fmt.Sprintf("%d error(s), %d warning(s), %d info", errs, warns, infos)
		switch {
		case errs > 0:
			errorColor.Printf("Result: %s\n", summary)
		case warns > 0:
			warnColor.Printf("Result: %s\n", summary)
		default:
			passColor.Printf("Result: %s\n", summary)
		}

		if !probe && len(rep.Findings) > 0 {
			fmt.Println()
			dimColor.Println("Tip: run 'cloop config validate --probe' to also check webhook URL reachability.")
		}
		if !fix && len(rep.Findings) > 0 {
			dimColor.Println("Tip: run 'cloop config validate --fix' to auto-correct fixable issues.")
		}

		if rep.HasErrors() {
			os.Exit(1)
		}
		return nil
	},
}

func init() {
	configValidateCmd.Flags().Bool("fix", false, "Auto-correct safe issues (strip unknown keys, reset stuck task statuses)")
	configValidateCmd.Flags().Bool("probe", false, "Probe notification webhook URLs for HTTP reachability")
	configCmd.AddCommand(configValidateCmd)
}
