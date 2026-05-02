package cmd

import (
	"fmt"
	"strings"

	"github.com/blechschmidt/cloop/pkg/plugin"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

const defaultRegistryURL = "https://raw.githubusercontent.com/blechschmidt/cloop/main/plugins/registry.json"

var pluginSearchRegistryURL string

var pluginSearchCmd = &cobra.Command{
	Use:   "search [query]",
	Short: "Search the remote plugin registry",
	Long: `Fetch the remote plugin registry and search for plugins matching the query.

The query is matched case-insensitively against plugin names, descriptions, and
tags. All words in the query must match (AND semantics). Omit the query to list
all available plugins.

Example:
  cloop plugin search
  cloop plugin search slack
  cloop plugin search "ci docker"`,
	RunE: func(cmd *cobra.Command, args []string) error {
		query := strings.Join(args, " ")

		faint := color.New(color.Faint)
		faint.Fprintf(cmd.OutOrStderr(), "Fetching registry from %s ...\n", pluginSearchRegistryURL)

		reg, err := plugin.FetchRegistry(pluginSearchRegistryURL)
		if err != nil {
			return fmt.Errorf("plugin registry: %w", err)
		}

		results := plugin.Search(reg, query)
		if len(results) == 0 {
			if query == "" {
				faint.Fprintln(cmd.OutOrStdout(), "No plugins found in registry.")
			} else {
				faint.Fprintf(cmd.OutOrStdout(), "No plugins matching %q.\n", query)
			}
			return nil
		}

		// Compute column widths.
		maxName := len("NAME")
		maxVer := len("VERSION")
		maxAuthor := len("AUTHOR")
		for _, p := range results {
			if len(p.Name) > maxName {
				maxName = len(p.Name)
			}
			if len(p.Version) > maxVer {
				maxVer = len(p.Version)
			}
			if len(p.Author) > maxAuthor {
				maxAuthor = len(p.Author)
			}
		}

		bold := color.New(color.Bold)
		header := fmt.Sprintf("%-*s  %-*s  %-*s  %s",
			maxName, "NAME",
			maxVer, "VERSION",
			maxAuthor, "AUTHOR",
			"DESCRIPTION")
		bold.Fprintln(cmd.OutOrStdout(), header)
		faint.Fprintln(cmd.OutOrStdout(), strings.Repeat("-", len(header)+10))

		for _, p := range results {
			tags := ""
			if len(p.Tags) > 0 {
				tags = " [" + strings.Join(p.Tags, ", ") + "]"
			}
			fmt.Fprintf(cmd.OutOrStdout(), "%-*s  %-*s  %-*s  %s%s\n",
				maxName, p.Name,
				maxVer, p.Version,
				maxAuthor, p.Author,
				p.Description,
				faint.Sprint(tags))
		}
		return nil
	},
}

func init() {
	pluginSearchCmd.Flags().StringVar(&pluginSearchRegistryURL, "registry", defaultRegistryURL, "URL of the plugin registry JSON")
	pluginCmd.AddCommand(pluginSearchCmd)
}
