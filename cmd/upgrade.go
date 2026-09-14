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

Without flags it downloads the release asset for the current OS/arch, verifies
its Sigstore signature against cloop's release workflow, verifies the SHA-256
checksum, and only then atomically replaces the running binary.

The signature is the check that matters. checksums.txt is served from the same
GitHub release as the archive it vouches for, so anyone who can replace the
archive can replace its checksum too; a signature cannot be forged without
being able to run cloop's release workflow. Verifying one requires cosign:
  https://github.com/sigstore/cosign/releases

Use --check to only report whether an update is available.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		checkOnly, _ := cmd.Flags().GetBool("check")
		skipVerify, _ := cmd.Flags().GetBool("insecure-skip-verify")

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

		newVersion, err := upgrade.UpgradeWithOptions(
			version.Version,
			upgrade.Options{SkipVerify: skipVerify},
			func(msg string) { fmt.Println(msg) },
		)
		if err != nil {
			return fmt.Errorf("upgrade failed: %w", err)
		}

		fmt.Printf("Successfully upgraded to %s\n", newVersion)
		return nil
	},
}

func init() {
	upgradeCmd.Flags().Bool("check", false, "check for updates without installing")
	upgradeCmd.Flags().Bool("insecure-skip-verify", false,
		"install without verifying the release signature. For air-gapped mirrors that "+
			"cannot reach Sigstore; gives up the proof that the binary came from cloop's "+
			"release workflow")
	rootCmd.AddCommand(upgradeCmd)
}
