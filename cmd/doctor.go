package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/doctor"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var doctorCmd = &cobra.Command{
	Use:   "doctor",
	Short: "Check environment and configuration health",
	Long: `Run a series of diagnostic checks on the cloop environment and configuration.

Each check reports PASS, WARN, or FAIL with a short message and, where applicable,
a suggested fix. Use --providers to also test live provider connectivity.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()
		testProviders, _ := cmd.Flags().GetBool("providers")

		cfg, err := config.Load(workdir)
		if err != nil {
			// Config load failure is itself a finding; use defaults for other checks.
			color.New(color.FgYellow).Fprintf(os.Stderr, "warning: could not load config: %v\n", err)
			cfg = config.Default()
		}

		headerColor := color.New(color.FgCyan, color.Bold)
		passColor := color.New(color.FgGreen, color.Bold)
		warnColor := color.New(color.FgYellow, color.Bold)
		failColor := color.New(color.FgRed, color.Bold)
		dimColor := color.New(color.Faint)

		headerColor.Println("cloop doctor — environment health check")
		fmt.Println()

		ctx := context.Background()
		report := doctor.Run(ctx, workdir, cfg, testProviders)

		for _, r := range report.Results {
			var levelStr string
			switch r.Level {
			case doctor.Pass:
				levelStr = passColor.Sprint("PASS")
			case doctor.Warn:
				levelStr = warnColor.Sprint("WARN")
			case doctor.Fail:
				levelStr = failColor.Sprint("FAIL")
			}

			fmt.Printf("  [%s] %-36s %s\n", levelStr, r.Name, r.Message)
			if r.Fix != "" {
				dimColor.Printf("         fix: %s\n", r.Fix)
			}
		}

		fmt.Println()
		pass, warn, fail := report.Counts()
		summary := fmt.Sprintf("%d passed, %d warnings, %d failed", pass, warn, fail)
		switch {
		case fail > 0:
			failColor.Printf("Result: %s\n", summary)
		case warn > 0:
			warnColor.Printf("Result: %s\n", summary)
		default:
			passColor.Printf("Result: %s — all checks passed\n", summary)
		}

		if !testProviders {
			fmt.Println()
			dimColor.Println("Tip: run 'cloop doctor --providers' to also test live provider connectivity.")
		}

		// Exit non-zero if any checks failed.
		if fail > 0 {
			os.Exit(1)
		}
		return nil
	},
}

func init() {
	doctorCmd.Flags().Bool("providers", false, "Test live connectivity for each configured provider (slower)")
	rootCmd.AddCommand(doctorCmd)
}
