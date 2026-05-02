package cmd

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/blechschmidt/cloop/pkg/alert"
	"github.com/blechschmidt/cloop/pkg/notify"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

// ---------------------------------------------------------------------------
// cloop alert
// ---------------------------------------------------------------------------

var alertCmd = &cobra.Command{
	Use:   "alert",
	Short: "Threshold-based monitoring rules for plan metrics",
	Long: `Manage and evaluate threshold-based alert rules for cloop plan metrics.

Rules are persisted in .cloop/alerts.yaml and are evaluated automatically after
each task completes during 'cloop run --pm'. You can also run them manually
at any time with 'cloop alert check'.

Supported metrics:
  failure_rate            Percentage of failed tasks (0-100)
  task_duration_minutes   Actual duration of the last completed task in minutes
  pending_count           Number of tasks still in "pending" status
  cost_usd                Cumulative session cost from the cost ledger (USD)

Examples:
  cloop alert add high-failure --metric failure_rate --op gt --threshold 20 --notify desktop
  cloop alert add slow-task    --metric task_duration_minutes --op gt --threshold 60 --notify desktop
  cloop alert add over-budget  --metric cost_usd --op gt --threshold 5.00 --notify "webhook:https://hooks.slack.com/..."
  cloop alert list
  cloop alert check
  cloop alert rm high-failure`,
}

// ---------------------------------------------------------------------------
// cloop alert add
// ---------------------------------------------------------------------------

var (
	alertMetric    string
	alertOp        string
	alertThreshold float64
	alertNotify    string
)

var alertAddCmd = &cobra.Command{
	Use:   "add <name>",
	Short: "Add or replace a monitoring rule",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()
		rule := alert.Rule{
			Name:      args[0],
			Metric:    alert.Metric(alertMetric),
			Op:        alert.Op(alertOp),
			Threshold: alertThreshold,
			Notify:    alertNotify,
		}
		if err := alert.ValidateRule(rule); err != nil {
			return err
		}
		if err := alert.AddRule(workdir, rule); err != nil {
			return err
		}
		color.New(color.FgGreen).Printf("Alert rule %q saved.\n", rule.Name)
		return nil
	},
}

// ---------------------------------------------------------------------------
// cloop alert list
// ---------------------------------------------------------------------------

var alertListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all monitoring rules",
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()
		rules, err := alert.Load(workdir)
		if err != nil {
			return err
		}
		if len(rules) == 0 {
			fmt.Println("No alert rules configured. Use 'cloop alert add' to create one.")
			return nil
		}
		headerColor := color.New(color.FgCyan, color.Bold)
		sep := strings.Repeat("─", 72)
		fmt.Println(sep)
		headerColor.Printf("  %-20s  %-25s  %-4s  %-10s  %s\n", "NAME", "METRIC", "OP", "THRESHOLD", "NOTIFY")
		fmt.Println(sep)
		for _, r := range rules {
			fmt.Printf("  %-20s  %-25s  %-4s  %-10s  %s\n",
				r.Name, r.Metric, r.Op,
				strconv.FormatFloat(r.Threshold, 'f', -1, 64),
				r.Notify)
		}
		fmt.Println(sep)
		fmt.Printf("  %d rule(s)\n\n", len(rules))
		return nil
	},
}

// ---------------------------------------------------------------------------
// cloop alert rm
// ---------------------------------------------------------------------------

var alertRmCmd = &cobra.Command{
	Use:   "rm <name>",
	Short: "Remove a monitoring rule by name",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()
		if err := alert.RemoveRule(workdir, args[0]); err != nil {
			return err
		}
		color.New(color.FgYellow).Printf("Alert rule %q removed.\n", args[0])
		return nil
	},
}

// ---------------------------------------------------------------------------
// cloop alert check
// ---------------------------------------------------------------------------

var alertCheckCmd = &cobra.Command{
	Use:   "check",
	Short: "Evaluate all monitoring rules against current plan state",
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()

		rules, err := alert.Load(workdir)
		if err != nil {
			return err
		}
		if len(rules) == 0 {
			fmt.Println("No alert rules configured. Use 'cloop alert add' to create one.")
			return nil
		}

		// Load plan for task-based metrics.
		s, _ := state.Load(workdir)
		ctx := alert.EvalContext{
			TotalCostUSD: alert.SessionCostUSD(workdir),
		}
		if s != nil && s.PMMode && s.Plan != nil {
			ctx.Plan = s.Plan
		}

		violations := alert.Evaluate(workdir, rules, ctx)

		headerColor := color.New(color.FgCyan, color.Bold)
		headerColor.Printf("\ncloop alert check — %d rule(s) evaluated\n\n", len(rules))

		if len(violations) == 0 {
			color.New(color.FgGreen).Printf("All clear. No rules triggered.\n\n")
			return nil
		}

		alertColor := color.New(color.FgRed, color.Bold)
		for _, v := range violations {
			alertColor.Printf("  ALERT  %q\n", v.Rule.Name)
			fmt.Printf("         metric=%s  op=%s  threshold=%s  observed=%s\n",
				v.Rule.Metric, v.Rule.Op,
				strconv.FormatFloat(v.Rule.Threshold, 'f', -1, 64),
				strconv.FormatFloat(v.ObservedValue, 'f', 4, 64),
			)
			fmt.Printf("         notify=%s\n\n", v.Rule.Notify)
			// Fire notifications immediately for manually triggered checks.
			fireAlertNotification(v)
		}

		fmt.Printf("%d violation(s) found.\n\n", len(violations))
		return nil
	},
}

// ---------------------------------------------------------------------------
// fireAlertNotification dispatches the notification for a triggered violation.
// Supports: "desktop", "webhook:<url>", "slack:<url>".
// Errors are printed as warnings and do not abort execution.
// ---------------------------------------------------------------------------

func fireAlertNotification(v alert.Violation) {
	title := fmt.Sprintf("cloop alert: %s", v.Rule.Name)
	body := fmt.Sprintf("Metric %s %s %.4g (observed %.4g)",
		v.Rule.Metric, v.Rule.Op, v.Rule.Threshold, v.ObservedValue)

	ch := strings.TrimSpace(v.Rule.Notify)
	switch {
	case ch == "desktop":
		notify.Send(title, body)
	case strings.HasPrefix(ch, "webhook:"):
		url := strings.TrimPrefix(ch, "webhook:")
		if err := notify.SendWebhook(url, title, body); err != nil {
			fmt.Fprintf(os.Stderr, "  warning: webhook notify failed: %v\n", err)
		}
	case strings.HasPrefix(ch, "slack:"):
		url := strings.TrimPrefix(ch, "slack:")
		if err := notify.SendWebhook(url, title, body); err != nil {
			fmt.Fprintf(os.Stderr, "  warning: slack notify failed: %v\n", err)
		}
	default:
		// Unknown channel — best effort, ignore.
	}
}

// ---------------------------------------------------------------------------
// init
// ---------------------------------------------------------------------------

func init() {
	// alert add flags
	alertAddCmd.Flags().StringVar(&alertMetric, "metric", "", "Metric to monitor (failure_rate, task_duration_minutes, pending_count, cost_usd)")
	alertAddCmd.Flags().StringVar(&alertOp, "op", "", "Comparison operator: gt, lt, eq")
	alertAddCmd.Flags().Float64Var(&alertThreshold, "threshold", 0, "Numeric threshold value")
	alertAddCmd.Flags().StringVar(&alertNotify, "notify", "desktop", "Notification channel: desktop | webhook:<url> | slack:<url>")
	_ = alertAddCmd.MarkFlagRequired("metric")
	_ = alertAddCmd.MarkFlagRequired("op")
	_ = alertAddCmd.MarkFlagRequired("threshold")

	alertCmd.AddCommand(alertAddCmd)
	alertCmd.AddCommand(alertListCmd)
	alertCmd.AddCommand(alertRmCmd)
	alertCmd.AddCommand(alertCheckCmd)
	rootCmd.AddCommand(alertCmd)
}
