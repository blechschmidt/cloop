package cmd

// zz_completion_register.go registers dynamic shell completions.
// The "zz_" prefix ensures this file's init() runs AFTER all other cmd/*.go
// init() functions (Go processes files in the same package alphabetically),
// so all cobra.Command vars are already populated when we traverse the tree.

import (
	"fmt"
	"os"
	"strconv"

	"github.com/blechschmidt/cloop/pkg/provider"
	clooptemplate "github.com/blechschmidt/cloop/pkg/template"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/spf13/cobra"
)

// completeProviders returns the list of registered provider names for flag completion.
func completeProviders(_ *cobra.Command, _ []string, _ string) ([]string, cobra.ShellCompDirective) {
	return provider.RegisteredNames(), cobra.ShellCompDirectiveNoFileComp
}

// completeTemplates returns the list of built-in template names for flag completion.
func completeTemplates(_ *cobra.Command, _ []string, _ string) ([]string, cobra.ShellCompDirective) {
	return clooptemplate.Names(), cobra.ShellCompDirectiveNoFileComp
}

// completeTaskIDs returns the task IDs from the current project state as completion candidates.
func completeTaskIDs(_ *cobra.Command, _ []string, _ string) ([]string, cobra.ShellCompDirective) {
	workdir, err := os.Getwd()
	if err != nil {
		return nil, cobra.ShellCompDirectiveError
	}
	s, err := state.Load(workdir)
	if err != nil || !s.PMMode || s.Plan == nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	ids := make([]string, 0, len(s.Plan.Tasks))
	for _, t := range s.Plan.Tasks {
		ids = append(ids, fmt.Sprintf("%d\t%s", t.ID, t.Title))
	}
	return ids, cobra.ShellCompDirectiveNoFileComp
}

// completeTaskIDsRaw returns plain task ID strings (without descriptions) for use
// when the shell doesn't render the tab-separated description.
func completeTaskIDsRaw(_ *cobra.Command, _ []string, _ string) ([]string, cobra.ShellCompDirective) {
	workdir, err := os.Getwd()
	if err != nil {
		return nil, cobra.ShellCompDirectiveError
	}
	s, err := state.Load(workdir)
	if err != nil || !s.PMMode || s.Plan == nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	ids := make([]string, 0, len(s.Plan.Tasks))
	for _, t := range s.Plan.Tasks {
		ids = append(ids, strconv.Itoa(t.ID))
	}
	return ids, cobra.ShellCompDirectiveNoFileComp
}

// registerProviderCompletions walks the entire command tree and registers
// --provider flag completion wherever the flag is defined.
func registerProviderCompletions(cmd *cobra.Command) {
	if f := cmd.Flags().Lookup("provider"); f != nil {
		_ = cmd.RegisterFlagCompletionFunc("provider", completeProviders)
	}
	for _, sub := range cmd.Commands() {
		registerProviderCompletions(sub)
	}
}

func init() {
	// Wire --provider completion across every command that defines the flag.
	registerProviderCompletions(rootCmd)

	// Wire --template completion on initCmd.
	_ = initCmd.RegisterFlagCompletionFunc("template", completeTemplates)

	// Wire task ID completion for task subcommands that take an ID argument.
	for _, sub := range []*cobra.Command{
		taskShowCmd,
		taskSkipCmd,
		taskDoneCmd,
		taskFailCmd,
		taskResetCmd,
		taskRemoveCmd,
		taskEditCmd,
		taskMoveCmd,
		taskSplitCmd,
		taskAnnotateCmd,
		taskNotesCmd,
	} {
		sub.ValidArgsFunction = completeTaskIDs
	}

	// taskTagCmd and taskUntagCmd take <id> <tag...> — complete only first arg as task ID.
	for _, sub := range []*cobra.Command{taskTagCmd, taskUntagCmd} {
		sub.ValidArgsFunction = func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			if len(args) == 0 {
				return completeTaskIDs(cmd, args, toComplete)
			}
			return nil, cobra.ShellCompDirectiveNoFileComp
		}
	}

	// taskMergeCmd takes multiple IDs — complete all positional args.
	taskMergeCmd.ValidArgsFunction = completeTaskIDsRaw
}
