package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/integrations"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var integrationsCmd = &cobra.Command{
	Use:   "integrations",
	Short: "Show the health status of all configured integrations",
	Long: `Display a dashboard of all external integrations configured for this cloop project.

Checks include:
  - GitHub token validity and repository access
  - Slack and Discord webhook reachability
  - Generic webhook reachability
  - Prometheus metrics endpoint
  - MCP (Model Context Protocol) server readiness
  - Plugin health (discover and run describe)

Color coding:
  green  — configured and healthy
  yellow — configured but not testable (e.g. stdio-based integrations)
  red    — configured but unhealthy or unreachable
  dim    — not configured`,
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()
		asJSON, _ := cmd.Flags().GetBool("json")

		cfg, err := config.Load(workdir)
		if err != nil {
			color.New(color.FgYellow).Fprintf(os.Stderr, "warning: could not load config: %v\n", err)
			cfg = config.Default()
		}

		ctx := context.Background()
		statuses := integrations.Check(ctx, workdir, cfg)

		if asJSON {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(statuses)
		}

		return printIntegrationsDashboard(statuses)
	},
}

func printIntegrationsDashboard(statuses []integrations.IntegrationStatus) error {
	headerColor := color.New(color.FgCyan, color.Bold)
	greenColor := color.New(color.FgGreen, color.Bold)
	yellowColor := color.New(color.FgYellow, color.Bold)
	redColor := color.New(color.FgRed, color.Bold)
	dimColor := color.New(color.Faint)

	headerColor.Println("cloop integrations — external service health")
	fmt.Println()

	// Column widths.
	const nameWidth = 36
	const stateWidth = 14

	headerLine := fmt.Sprintf("  %-*s  %-*s  %s", nameWidth, "INTEGRATION", stateWidth, "STATUS", "DETAIL")
	dimColor.Println(headerLine)
	dimColor.Println("  " + strings.Repeat("─", nameWidth+stateWidth+30))

	healthy, configured, unconfigured, errored := 0, 0, 0, 0

	for _, s := range statuses {
		var stateStr string
		var stateColor *color.Color

		switch {
		case !s.Configured:
			stateStr = "not configured"
			stateColor = dimColor
			unconfigured++
		case s.Healthy:
			stateStr = "healthy"
			stateColor = greenColor
			healthy++
		case strings.HasPrefix(s.Detail, "not tested:"):
			stateStr = "not tested"
			stateColor = yellowColor
			configured++
		default:
			stateStr = "error"
			stateColor = redColor
			errored++
		}

		nameField := s.Name
		if len(nameField) > nameWidth {
			nameField = nameField[:nameWidth-1] + "…"
		}

		fmt.Printf("  %-*s  ", nameWidth, nameField)
		stateColor.Printf("%-*s", stateWidth, stateStr)
		fmt.Printf("  %s\n", s.Detail)
	}

	fmt.Println()

	summary := fmt.Sprintf("%d healthy, %d not tested, %d error(s), %d not configured",
		healthy, configured, errored, unconfigured)
	switch {
	case errored > 0:
		redColor.Printf("Summary: %s\n", summary)
	case configured > 0:
		yellowColor.Printf("Summary: %s\n", summary)
	default:
		greenColor.Printf("Summary: %s\n", summary)
	}

	return nil
}

func init() {
	integrationsCmd.Flags().Bool("json", false, "Output results as JSON")
	rootCmd.AddCommand(integrationsCmd)
}
