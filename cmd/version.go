package cmd

import (
	"fmt"
	"runtime"

	"github.com/spf13/cobra"

	"github.com/blechschmidt/cloop/pkg/statedb"
)

// Version is set at build time via -ldflags "-X github.com/blechschmidt/cloop/cmd.Version=v1.2.3"
var Version = "dev"

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print cloop version information",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("cloop %s\n", Version)
		fmt.Printf("Go %s %s/%s\n", runtime.Version(), runtime.GOOS, runtime.GOARCH)
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)

	// Tell the storage layer which build it is, so every migration this
	// process applies is stamped into schema_migrations. That stamp is what
	// lets a later, older binary's refusal name the build that moved the
	// schema past it instead of only the version number it landed on
	// (Task 20226). Done here rather than in pkg/statedb because statedb sits
	// below the CLI in the import graph, and ldflags patch the variable
	// above before any init runs.
	statedb.SetBinaryVersion(Version)
}
