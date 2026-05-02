package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/blechschmidt/cloop/pkg/secret"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var secretCmd = &cobra.Command{
	Use:   "secret",
	Short: "Manage AES-256-GCM encrypted project secrets",
	Long: `Store sensitive credentials as AES-256-GCM encrypted entries in .cloop/secrets.enc.

The encryption key is derived from the CLOOP_SECRET_KEY environment variable
(required for all subcommands). Secrets are automatically injected as environment
variables during task execution — alongside 'cloop env' variables.

  export CLOOP_SECRET_KEY="my-strong-passphrase"
  cloop secret set GITHUB_TOKEN ghp_abc123
  cloop secret get GITHUB_TOKEN
  cloop secret list
  cloop secret delete GITHUB_TOKEN
  cloop secret export   # KEY=value lines (decrypted)`,
}

var secretSetCmd = &cobra.Command{
	Use:   "set <KEY> <value>",
	Short: "Set (or update) an encrypted secret",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		workDir, _ := os.Getwd()
		key, value := args[0], args[1]

		store, err := secret.Open(workDir)
		if err != nil {
			return err
		}
		store.Set(key, value)
		if err := store.Save(); err != nil {
			return err
		}
		color.Green("✓ secret %s set (encrypted)", key)
		return nil
	},
}

var secretGetCmd = &cobra.Command{
	Use:   "get <KEY>",
	Short: "Print the decrypted value of a secret",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		workDir, _ := os.Getwd()
		key := args[0]

		store, err := secret.Open(workDir)
		if err != nil {
			return err
		}
		val, ok := store.Get(key)
		if !ok {
			return fmt.Errorf("secret: key %q not found", key)
		}
		fmt.Println(val)
		return nil
	},
}

var secretListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all secret keys (values masked)",
	RunE: func(cmd *cobra.Command, args []string) error {
		workDir, _ := os.Getwd()

		store, err := secret.Open(workDir)
		if err != nil {
			return err
		}
		keys := store.Keys()
		if len(keys) == 0 {
			color.New(color.Faint).Println("No secrets stored. Use 'cloop secret set KEY value' to add one.")
			return nil
		}

		headerColor := color.New(color.Bold)
		maskedColor := color.New(color.FgYellow)
		fmt.Printf("%-32s %s\n", headerColor.Sprint("KEY"), headerColor.Sprint("VALUE"))
		fmt.Println(strings.Repeat("─", 48))
		for _, k := range keys {
			fmt.Printf("%-32s %s\n", k, maskedColor.Sprint("****"))
		}
		fmt.Printf("\n%d secret(s) stored in .cloop/secrets.enc\n", store.Len())
		return nil
	},
}

var secretDeleteCmd = &cobra.Command{
	Use:     "delete <KEY>",
	Aliases: []string{"del", "rm"},
	Short:   "Delete a secret",
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		workDir, _ := os.Getwd()
		key := args[0]

		store, err := secret.Open(workDir)
		if err != nil {
			return err
		}
		if !store.Delete(key) {
			return fmt.Errorf("secret: key %q not found", key)
		}
		if err := store.Save(); err != nil {
			return err
		}
		color.Green("✓ secret %s deleted", key)
		return nil
	},
}

var secretExportCmd = &cobra.Command{
	Use:   "export",
	Short: "Print all secrets as KEY=value lines (decrypted)",
	Long: `Output KEY=value lines for all secrets in plain text.
Suitable for sourcing into a shell or piping to dotenv tools.

WARNING: this prints secrets in plain text to stdout.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		workDir, _ := os.Getwd()

		store, err := secret.Open(workDir)
		if err != nil {
			return err
		}
		for _, k := range store.Keys() {
			val, _ := store.Get(k)
			fmt.Printf("%s=%s\n", k, shellQuoteSecret(val))
		}
		return nil
	},
}

// shellQuoteSecret wraps val in single quotes, escaping embedded single quotes.
func shellQuoteSecret(val string) string {
	return "'" + strings.ReplaceAll(val, "'", "'\\''") + "'"
}

func init() {
	secretCmd.AddCommand(secretSetCmd)
	secretCmd.AddCommand(secretGetCmd)
	secretCmd.AddCommand(secretListCmd)
	secretCmd.AddCommand(secretDeleteCmd)
	secretCmd.AddCommand(secretExportCmd)

	rootCmd.AddCommand(secretCmd)
}
