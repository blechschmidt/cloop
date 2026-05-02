package cmd

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/blechschmidt/cloop/pkg/plugin"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var pluginInstallRegistryURL string

var pluginInstallCmd = &cobra.Command{
	Use:   "install <name>",
	Short: "Install a plugin from the remote registry",
	Long: `Look up a plugin by name in the remote registry, download its script, and
install it into .cloop/plugins/<name> with executable permissions.

Example:
  cloop plugin install cloop-notify-slack`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]
		faint := color.New(color.Faint)

		faint.Fprintf(cmd.OutOrStderr(), "Fetching registry from %s ...\n", pluginInstallRegistryURL)
		reg, err := plugin.FetchRegistry(pluginInstallRegistryURL)
		if err != nil {
			return fmt.Errorf("plugin registry: %w", err)
		}

		// Find the plugin by exact name match.
		var found *plugin.RegistryPlugin
		for i := range reg.Plugins {
			if reg.Plugins[i].Name == name {
				found = &reg.Plugins[i]
				break
		}
		}
		if found == nil {
			return fmt.Errorf("plugin %q not found in registry (try: cloop plugin search)", name)
		}

		faint.Fprintf(cmd.OutOrStderr(), "Downloading %s v%s from %s ...\n", found.Name, found.Version, found.URL)

		scriptBytes, err := downloadURL(found.URL)
		if err != nil {
			return fmt.Errorf("downloading plugin: %w", err)
		}

		workDir, _ := os.Getwd()
		pluginDir := filepath.Join(workDir, ".cloop", "plugins")
		if err := os.MkdirAll(pluginDir, 0o755); err != nil {
			return fmt.Errorf("creating plugin directory: %w", err)
		}

		destPath := filepath.Join(pluginDir, name)
		if err := os.WriteFile(destPath, scriptBytes, 0o755); err != nil {
			return fmt.Errorf("writing plugin file: %w", err)
		}

		color.New(color.FgGreen).Fprintf(cmd.OutOrStdout(),
			"Installed %s v%s to %s\n", found.Name, found.Version, destPath)
		fmt.Fprintf(cmd.OutOrStdout(), "  %s\n", found.Description)
		fmt.Fprintf(cmd.OutOrStdout(), "  Run with: cloop plugin run %s\n", name)
		return nil
	},
}

// downloadURL fetches the content at url and returns the raw bytes.
func downloadURL(url string) ([]byte, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(url) //nolint:noctx
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server returned HTTP %d for %s", resp.StatusCode, url)
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
	if err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}
	return data, nil
}

func init() {
	pluginInstallCmd.Flags().StringVar(&pluginInstallRegistryURL, "registry", defaultRegistryURL, "URL of the plugin registry JSON")
	pluginCmd.AddCommand(pluginInstallCmd)
}
