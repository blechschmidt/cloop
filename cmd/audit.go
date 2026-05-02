package cmd

import (
	"fmt"
	"os"

	"github.com/blechschmidt/cloop/pkg/audit"
	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var auditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Security and compliance scan of config and state",
	Long: `Run a security and compliance audit on the cloop project.

Checks performed:
  • API keys present in config accidentally committed to git history
  • Webhook URLs using plain HTTP instead of HTTPS
  • Web UI configured to start without an authentication token
  • Env var secrets (.cloop/env.yaml) exposed in task output artifacts
  • Hook scripts with world-writable permissions or running as root
  • Snapshot directory size exceeding a configurable threshold

Each check reports PASS (green), WARN (yellow), or FAIL (red).`,
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()
		thresholdMB, _ := cmd.Flags().GetInt64("snapshot-threshold")

		cfg, err := config.Load(workdir)
		if err != nil {
			color.New(color.FgYellow).Fprintf(os.Stderr, "warning: could not load config: %v\n", err)
			cfg = config.Default()
		}

		opts := audit.DefaultOptions()
		if thresholdMB > 0 {
			opts.SnapshotSizeThresholdMB = thresholdMB
		}

		headerColor := color.New(color.FgCyan, color.Bold)
		passColor := color.New(color.FgGreen, color.Bold)
		warnColor := color.New(color.FgYellow, color.Bold)
		failColor := color.New(color.FgRed, color.Bold)
		dimColor := color.New(color.Faint)

		headerColor.Println("cloop audit — security and compliance scan")
		fmt.Println()

		findings, err := audit.Audit(workdir, cfg, opts)
		if err != nil {
			return fmt.Errorf("audit: %w", err)
		}

		for _, f := range findings {
			var levelStr string
			switch f.Level {
			case audit.Pass:
				levelStr = passColor.Sprint("PASS")
			case audit.Warn:
				levelStr = warnColor.Sprint("WARN")
			case audit.Fail:
				levelStr = failColor.Sprint("FAIL")
			}
			fmt.Printf("  [%s] %-42s %s\n", levelStr, f.Name, f.Message)
			if f.Fix != "" {
				dimColor.Printf("         fix: %s\n", f.Fix)
			}
		}

		fmt.Println()
		pass, warn, fail := audit.CountsByLevel(findings)
		summary := fmt.Sprintf("%d passed, %d warnings, %d failed", pass, warn, fail)
		switch {
		case fail > 0:
			failColor.Printf("Result: %s\n", summary)
		case warn > 0:
			warnColor.Printf("Result: %s\n", summary)
		default:
			passColor.Printf("Result: %s — all checks passed\n", summary)
		}

		if fail > 0 {
			os.Exit(1)
		}
		return nil
	},
}

func init() {
	auditCmd.Flags().Int64("snapshot-threshold", 50, "Warn when .cloop/plan-history/ exceeds this size in MiB")
	rootCmd.AddCommand(auditCmd)
}
