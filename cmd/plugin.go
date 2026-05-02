package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/blechschmidt/cloop/pkg/plugin"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var pluginCmd = &cobra.Command{
	Use:   "plugin",
	Short: "Manage and run cloop plugins",
	Long: `Shell-script plugin system for cloop.

Plugins are executable scripts placed in .cloop/plugins/ (project-local)
or ~/.cloop/plugins/ (global). Each plugin must implement a "describe"
subcommand that prints a one-line description.

  cloop plugin list                     # show all discovered plugins
  cloop plugin run <name> [args...]     # execute a plugin by name`,
}

var pluginListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all discovered plugins with descriptions",
	RunE: func(cmd *cobra.Command, args []string) error {
		workDir, _ := os.Getwd()
		plugins, err := plugin.Discover(workDir)
		if err != nil {
			return fmt.Errorf("discovering plugins: %w", err)
		}
		if len(plugins) == 0 {
			color.New(color.Faint).Println("No plugins found.")
			color.New(color.Faint).Println("Add executable scripts to .cloop/plugins/ or ~/.cloop/plugins/")
			color.New(color.Faint).Println("Each script must implement a 'describe' subcommand.")
			return nil
		}

		bold := color.New(color.Bold)
		faint := color.New(color.Faint)

		// Compute column widths.
		maxName := len("NAME")
		maxScope := len("SCOPE")
		for _, p := range plugins {
			if len(p.Name) > maxName {
				maxName = len(p.Name)
			}
			if len(p.Scope) > maxScope {
				maxScope = len(p.Scope)
			}
		}

		header := fmt.Sprintf("%-*s  %-*s  %s", maxName, "NAME", maxScope, "SCOPE", "DESCRIPTION")
		bold.Println(header)
		faint.Println(strings.Repeat("-", len(header)+10))

		for _, p := range plugins {
			desc := p.Description
			if desc == "" {
				desc = faint.Sprint("(no description)")
			}
			fmt.Printf("%-*s  %-*s  %s\n", maxName, p.Name, maxScope, p.Scope, desc)
		}
		return nil
	},
}

var pluginRunCmd = &cobra.Command{
	Use:   "run <name> [args...]",
	Short: "Execute a plugin by name",
	Long: `Run a plugin by name, passing any extra arguments directly to the plugin script.

The plugin receives the following environment variables:
  CLOOP_WORK_DIR     - the current project working directory
  CLOOP_PLUGIN_NAME  - the plugin name being invoked

To pass flags to the plugin itself, use -- to terminate cloop flag parsing:
  cloop plugin run myplug -- --strict --verbose`,
	Args: cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]
		pluginArgs := args[1:]

		workDir, _ := os.Getwd()
		extraEnv := []string{
			"CLOOP_WORK_DIR=" + workDir,
			"CLOOP_PLUGIN_NAME=" + name,
		}
		if err := plugin.Run(workDir, name, pluginArgs, extraEnv); err != nil {
			return err
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(pluginCmd)
	pluginCmd.AddCommand(pluginListCmd, pluginRunCmd)
}
