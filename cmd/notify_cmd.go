package cmd

import (
	"fmt"
	"os"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/notifywizard"
	"github.com/spf13/cobra"
)

var notifyCmd = &cobra.Command{
	Use:   "notify",
	Short: "Manage notification channels",
	Long: `Configure, test, and inspect cloop notification channels.

Supported channels:
  desktop  — OS desktop notifications (notify-send on Linux, osascript on macOS)
  slack    — Slack incoming webhook
  discord  — Discord webhook
  custom   — Generic HTTP webhook (POSTs JSON)

Sub-commands:
  cloop notify setup          # interactive wizard to configure all channels
  cloop notify test           # send a test ping to all configured channels
  cloop notify test slack     # send a test ping to a specific channel
  cloop notify status         # show which channels are configured`,
}

var notifySetupCmd = &cobra.Command{
	Use:   "setup",
	Short: "Interactive wizard to configure notification channels",
	Long: `Walk through each notification channel interactively.

For each channel you can enter a webhook URL (or toggle desktop notifications).
A connectivity test is performed immediately after you provide a URL so you know
whether the channel is reachable before saving.

Configuration is stored in .cloop/config.yaml under the notify section.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()
		cfg, err := config.Load(workdir)
		if err != nil {
			cfg = config.Default()
		}

		if err := notifywizard.Setup(cfg, os.Stdin, os.Stdout); err != nil {
			return err
		}

		if err := config.Save(workdir, cfg); err != nil {
			return fmt.Errorf("saving config: %w", err)
		}
		fmt.Println("\nConfiguration saved to .cloop/config.yaml")
		return nil
	},
}

var notifyTestCmd = &cobra.Command{
	Use:   "test [channel]",
	Short: "Send a test ping to notification channels",
	Long: `Send a test notification to verify channels are reachable.

Without an argument, tests all configured channels.
With a channel name (desktop, slack, discord, custom), tests only that channel.`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()
		cfg, err := config.Load(workdir)
		if err != nil {
			cfg = config.Default()
		}

		channel := ""
		if len(args) > 0 {
			channel = args[0]
		}

		fmt.Println("Sending test notifications…")
		fmt.Println()
		return notifywizard.Test(cfg, channel, os.Stdout)
	},
}

var notifyStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show configured notification channels",
	Long:  `Display which notification channels are configured in .cloop/config.yaml.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()
		cfg, err := config.Load(workdir)
		if err != nil {
			cfg = config.Default()
		}

		notifywizard.Status(cfg, os.Stdout)
		return nil
	},
}

func init() {
	notifyCmd.AddCommand(notifySetupCmd)
	notifyCmd.AddCommand(notifyTestCmd)
	notifyCmd.AddCommand(notifyStatusCmd)
	rootCmd.AddCommand(notifyCmd)
}
