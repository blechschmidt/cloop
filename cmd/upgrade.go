package cmd

import (
	"fmt"

	"github.com/blechschmidt/cloop/pkg/upgrade"
	"github.com/blechschmidt/cloop/pkg/version"
	"github.com/spf13/cobra"
)

var upgradeCmd = &cobra.Command{
	Use:   "upgrade",
	Short: "Upgrade cloop to the latest GitHub release",
	Long: `upgrade checks the GitHub releases API for the latest cloop version.

Without flags it downloads the release asset for the current OS/arch,
verifies the SHA-256 checksum, and atomically replaces the running binary.

Use --check to only report whether an update is available.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		checkOnly, _ := cmd.Flags().GetBool("check")

		// version.Version, not Version(): the raw stamp. Check treats the
		// literal "dev" as "never self-upgrade", and the enriched form
		// ("dev+g4f7b5bc") would slip past that test and offer to replace a
		// developer's working binary with the latest release.
		result, err := upgrade.Check(version.Version)
		if err != nil {
			return fmt.Errorf("checking for updates: %w", err)
		}

		if !result.UpdateAvailable {
			fmt.Printf("cloop is up to date (%s)\n", result.Current)
			return nil
		}

		fmt.Printf("Update available: %s → %s\n", result.Current, result.Latest)

		if checkOnly {
			fmt.Println("Run `cloop upgrade` to install the update.")
			return nil
		}

		newVersion, err := upgrade.Upgrade(version.Version, func(msg string) {
			fmt.Println(msg)
		})
		if err != nil {
			return fmt.Errorf("upgrade failed: %w", err)
		}

		fmt.Printf("Successfully upgraded to %s\n", newVersion)
		return nil
	},
}

func init() {
	upgradeCmd.Flags().Bool("check", false, "check for updates without installing")
	rootCmd.AddCommand(upgradeCmd)
}
