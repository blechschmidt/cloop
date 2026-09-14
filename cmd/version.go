package cmd

import (
	"encoding/json"
	"fmt"
	"runtime"

	"github.com/spf13/cobra"

	"github.com/blechschmidt/cloop/pkg/executor/remote"
	"github.com/blechschmidt/cloop/pkg/statedb"
	"github.com/blechschmidt/cloop/pkg/version"
)

// Version is this build's version.
//
// It is a function rather than the ldflags-patched variable it used to be. The
// variable now lives in pkg/version, because the CLI was the wrong owner: the
// executor agent has to report its build to the control plane and sits below
// cmd in the import graph, so it could not ask — and reported a frozen "1"
// instead. See pkg/version.
//
// Release builds stamp it with
//
//	-ldflags "-X github.com/blechschmidt/cloop/pkg/version.Version=v1.2.3"
//
// (scripts/build-release.sh). Patching cmd.Version has no effect any more.
func Version() string { return version.String() }

// versionReport is the --json form: everything needed to decide whether a cloop
// binary is safe to install on a device, in a shape a program can read.
//
// It exists for `cloop executor agent install --upgrade`, which execs the binary
// it is about to put in place and requires a parseable answer before it will
// replace a working agent (see pkg/executor/install/verify.go). Text scraping
// would have worked for the version line alone, but not for the protocol
// numbers, and those are the ones that decide whether the hub would still accept
// the device afterwards.
//
// Every field answers a question the installer has to ask:
//
//   - Version: is this a downgrade?
//   - Protocol / MinProtocol: would the control plane still talk to it?
//   - OS / Arch: is this even the right binary for this machine? An
//     exec-format error already catches the usual case, but a binary that runs
//     and then reports the wrong platform is worth naming rather than
//     installing.
type versionReport struct {
	Version string `json:"version"`
	Go      string `json:"go"`
	OS      string `json:"os"`
	Arch    string `json:"arch"`
	// Protocol is the newest executor-agent protocol version this build
	// speaks; MinProtocol is the oldest it accepts from the other end.
	Protocol    int `json:"protocol"`
	MinProtocol int `json:"min_protocol"`
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print cloop version information",
	Long: `Print cloop version information.

With --json, emit a machine-readable report carrying the build version, the Go
toolchain, the platform, and the executor-agent protocol versions this build
speaks. That form is what ` + "`cloop executor agent install --upgrade`" + ` execs to verify a
staged binary before it replaces a running agent.`,
	Args: cobra.NoArgs,
	// Deliberately overrides the root command's PersistentPreRunE, which loads
	// the project config, applies retention policy, reconciles executors and
	// may open a database. None of that is needed to print a version, and all
	// of it is actively wrong here: the installer execs this command to decide
	// whether a staged binary is safe to install, and a probe with side effects
	// on whatever directory it happens to run in is not a probe. It also has to
	// be fast and total — a version command that can block on reconciliation is
	// one that can hang an upgrade.
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		cmd.SilenceUsage = true
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		w := cmd.OutOrStdout()
		if asJSON, _ := cmd.Flags().GetBool("json"); asJSON {
			enc := json.NewEncoder(w)
			enc.SetIndent("", "  ")
			return enc.Encode(versionReport{
				Version:     Version(),
				Go:          runtime.Version(),
				OS:          runtime.GOOS,
				Arch:        runtime.GOARCH,
				Protocol:    remote.ProtocolVersion,
				MinProtocol: remote.MinProtocolVersion,
			})
		}
		fmt.Fprintf(w, "cloop %s\n", Version())
		fmt.Fprintf(w, "Go %s %s/%s\n", runtime.Version(), runtime.GOOS, runtime.GOARCH)
		fmt.Fprintf(w, "executor protocol v%d (accepts v%d and newer)\n",
			remote.ProtocolVersion, remote.MinProtocolVersion)
		return nil
	},
}

func init() {
	versionCmd.Flags().Bool("json", false, "emit a machine-readable report")
	rootCmd.AddCommand(versionCmd)

	// Tell the storage layer which build it is, so every migration this
	// process applies is stamped into schema_migrations. That stamp is what
	// lets a later, older binary's refusal name the build that moved the
	// schema past it instead of only the version number it landed on
	// (Task 20226). Done here rather than in pkg/statedb because statedb sits
	// below the CLI in the import graph, and ldflags patch the variable
	// above before any init runs.
	statedb.SetBinaryVersion(Version())
}
