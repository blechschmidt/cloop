package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var routerCmd = &cobra.Command{
	Use:   "router",
	Short: "Configure role-based provider routing for multi-agent execution",
	Long: `Router maps task roles to specific AI providers.
In PM mode, each task is routed to the best-suited provider based on its role.

Examples:
  cloop router set backend anthropic      # use Claude for backend tasks
  cloop router set frontend openai        # use GPT-4o for frontend tasks
  cloop router set testing ollama         # use Ollama for test writing
  cloop router set security anthropic     # use Claude for security tasks
  cloop router list                       # show current routing table
  cloop router clear backend              # remove a route
  cloop router clear --all                # remove all routes`,
}

var routerSetCmd = &cobra.Command{
	Use:   "set <role> <provider>",
	Short: "Map a task role to a specific provider",
	Long: `Set routes a task role to a specific provider.

Valid roles: backend, frontend, testing, security, devops, data, docs, review
Valid providers: anthropic, openai, ollama, claudecode

Example:
  cloop router set backend anthropic
  cloop router set frontend openai`,
	Args: cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		role := strings.ToLower(args[0])
		provName := strings.ToLower(args[1])
		workdir, _ := os.Getwd()

		// Validate role
		validRoles := pm.ValidRoles()
		roleValid := false
		for _, r := range validRoles {
			if r == role {
				roleValid = true
				break
			}
		}
		if !roleValid {
			return fmt.Errorf("unknown role %q (valid: %s)", role, strings.Join(validRoles, ", "))
		}

		// Validate provider
		validProviders := []string{"anthropic", "openai", "ollama", "claudecode"}
		provValid := false
		for _, p := range validProviders {
			if p == provName {
				provValid = true
				break
			}
		}
		if !provValid {
			return fmt.Errorf("unknown provider %q (valid: %s)", provName, strings.Join(validProviders, ", "))
		}

		cfg, err := config.Load(workdir)
		if err != nil {
			return fmt.Errorf("loading config: %w", err)
		}
		if cfg.Router.Routes == nil {
			cfg.Router.Routes = make(map[string]string)
		}
		cfg.Router.Routes[role] = provName
		if err := config.Save(workdir, cfg); err != nil {
			return fmt.Errorf("saving config: %w", err)
		}
		color.New(color.FgGreen).Printf("Router: %s → %s\n", role, provName)
		return nil
	},
}

var routerClearCmd = &cobra.Command{
	Use:   "clear [role]",
	Short: "Remove a role route (or all routes with --all)",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		all, _ := cmd.Flags().GetBool("all")
		workdir, _ := os.Getwd()
		cfg, err := config.Load(workdir)
		if err != nil {
			return fmt.Errorf("loading config: %w", err)
		}

		if all {
			cfg.Router.Routes = nil
			if err := config.Save(workdir, cfg); err != nil {
				return fmt.Errorf("saving config: %w", err)
			}
			color.New(color.FgYellow).Printf("Cleared all router routes.\n")
			return nil
		}
		if len(args) == 0 {
			return fmt.Errorf("specify a role or use --all")
		}
		role := strings.ToLower(args[0])
		if cfg.Router.Routes != nil {
			delete(cfg.Router.Routes, role)
			if err := config.Save(workdir, cfg); err != nil {
				return fmt.Errorf("saving config: %w", err)
			}
		}
		color.New(color.FgYellow).Printf("Cleared route for role: %s\n", role)
		return nil
	},
}

var routerListCmd = &cobra.Command{
	Use:   "list",
	Short: "Show the current routing table",
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()
		cfg, err := config.Load(workdir)
		if err != nil {
			return fmt.Errorf("loading config: %w", err)
		}

		headerColor := color.New(color.FgCyan, color.Bold)
		dimColor := color.New(color.Faint)
		roleColor := color.New(color.FgYellow)
		provColor := color.New(color.FgGreen)

		headerColor.Printf("\nProvider Routing Table\n")
		fmt.Printf("  Default provider: %s\n\n", cfg.Provider)

		if len(cfg.Router.Routes) == 0 {
			dimColor.Printf("  No role-specific routes configured.\n")
			dimColor.Printf("  All tasks use the default provider (%s).\n\n", cfg.Provider)
			dimColor.Printf("  Set routes with: cloop router set <role> <provider>\n")
			dimColor.Printf("  Roles: backend, frontend, testing, security, devops, data, docs, review\n")
			fmt.Println()
			return nil
		}

		fmt.Printf("  %-14s  %-12s\n", "ROLE", "PROVIDER")
		fmt.Printf("  %-14s  %-12s\n", strings.Repeat("-", 14), strings.Repeat("-", 12))
		// Show all valid roles, marking which have routes
		for _, role := range pm.ValidRoles() {
			if prov, ok := cfg.Router.Routes[role]; ok {
				roleColor.Printf("  %-14s", role)
				provColor.Printf("  %s\n", prov)
			} else {
				dimColor.Printf("  %-14s  %s (default)\n", role, cfg.Provider)
			}
		}
		fmt.Println()
		return nil
	},
}

func init() {
	routerClearCmd.Flags().Bool("all", false, "Clear all role routes")
	routerCmd.AddCommand(routerSetCmd)
	routerCmd.AddCommand(routerClearCmd)
	routerCmd.AddCommand(routerListCmd)
	rootCmd.AddCommand(routerCmd)
}
