package cmd

// executor_agent_cmd.go is the operator surface for remote executors: minting
// enrollment tokens on the control plane, running the agent on a device, and
// revoking either when something leaks.
//
// The design constraint that shapes all three commands is that the device is
// unreachable. Nothing here ever dials a device — enrollment produces a token
// the operator carries to the device, and the device dials back. That is why
// `enroll` prints a copy-pasteable command rather than doing anything itself.

import (
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/blechschmidt/cloop/pkg/executor/agent"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
	"github.com/blechschmidt/cloop/pkg/executorstore"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// openExecutorStore opens the control plane's enrollment storage for the
// current project directory.
//
// Enrollment lives in the control plane's own database rather than any managed
// project's, because an agent is not bound to a project: one device runs work
// for many, and most of them do not exist on it.
func openExecutorStore() (*executorstore.Store, *statedb.DB, error) {
	workdir, err := os.Getwd()
	if err != nil {
		return nil, nil, fmt.Errorf("determine working directory: %w", err)
	}
	db, err := statedb.Open(state.DBPath(workdir))
	if err != nil {
		return nil, nil, fmt.Errorf("open control-plane database: %w", err)
	}
	store, err := executorstore.New(db)
	if err != nil {
		_ = db.Close()
		return nil, nil, err
	}
	return store, db, nil
}

var executorEnrollCmd = &cobra.Command{
	Use:   "enroll",
	Short: "Mint a single-use token for enrolling a remote executor agent",
	Long: `Create a single-use, time-limited enrollment token for a remote device.

Remote agents run on machines this control plane cannot dial — edge devices
behind NAT, build boxes on an office network, laptops on hotel wifi. They
enroll by connecting OUTWARD, so this command does not contact anything: it
mints a token and prints the command to run on the device.

The token is single-use and expires (default 15m). It is shown exactly once —
only its hash is stored, so it cannot be recovered afterwards. If it leaks, run
` + "`cloop executor revoke <id>`" + `; if the leak was already redeemed, that
also revokes the credential it produced.

Once redeemed the device receives a long-lived credential, persists it 0600 at
~/.cloop/agent.json, and reconnects with it from then on.`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		name, _ := cmd.Flags().GetString("name")
		ttl, _ := cmd.Flags().GetDuration("ttl")
		root, _ := cmd.Flags().GetString("workdir-root")
		server, _ := cmd.Flags().GetString("server")
		labelPairs, _ := cmd.Flags().GetStringSlice("label")

		labels, err := parseLabelPairs(labelPairs)
		if err != nil {
			return err
		}

		store, db, err := openExecutorStore()
		if err != nil {
			return err
		}
		defer db.Close()

		token, rec, err := remote.Mint(store, remote.MintOptions{
			Name:        name,
			TTL:         ttl,
			WorkDirRoot: root,
			Labels:      labels,
		})
		if err != nil {
			return err
		}

		header := color.New(color.FgCyan, color.Bold)
		warn := color.New(color.FgYellow, color.Bold)
		dim := color.New(color.Faint)

		header.Printf("Enrollment token for %q\n\n", rec.Name)
		fmt.Printf("  id:      %s\n", rec.ID)
		fmt.Printf("  expires: %s (in %s)\n",
			rec.ExpiresAt.Format(time.RFC3339), time.Until(rec.ExpiresAt).Round(time.Second))
		if rec.WorkDirRoot != "" {
			fmt.Printf("  root:    %s\n", rec.WorkDirRoot)
		}
		fmt.Println()

		warn.Println("This token is shown once and cannot be recovered. Run on the device:")
		fmt.Printf("\n  cloop executor agent --server %s --token %s\n\n", displayServer(server), token)
		dim.Printf("Revoke with: cloop executor revoke %s\n", rec.ID)
		return nil
	},
}

// displayServer renders the --server value for the printed command, falling
// back to an obvious placeholder so a copied command fails loudly at the
// device rather than silently connecting somewhere unintended.
func displayServer(server string) string {
	if s := strings.TrimSpace(server); s != "" {
		return s
	}
	return "wss://YOUR-CONTROL-PLANE/api/executors/connect"
}

var executorAgentCmd = &cobra.Command{
	Use:   "agent",
	Short: "Run this machine as a remote executor for a cloop control plane",
	Long: `Run the cloop executor agent on this device.

The agent dials OUT to the control plane and holds one multiplexed WebSocket
open, so the device works behind NAT with no inbound firewall rule, no port
forwarding, and no VPN. Work arrives over that connection; output streams back
over it.

First run needs an enrollment token:

    cloop executor agent --server wss://host/api/executors/connect --token <tok>

The token is redeemed for a long-lived credential saved 0600 at
~/.cloop/agent.json. After that, plain ` + "`cloop executor agent`" + ` is enough — the
server URL and identity come from the saved credential.

Every workload is confined beneath --workdir-root (default ~/.cloop/work). A
workdir that escapes that root is refused, so a compromised control plane
cannot make this device read or write arbitrary paths.

The agent reconnects indefinitely with capped exponential backoff and resumes
log streaming where the control plane left off. It exits only when interrupted
or when the control plane revokes its credential.`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		server, _ := cmd.Flags().GetString("server")
		token, _ := cmd.Flags().GetString("token")
		credPath, _ := cmd.Flags().GetString("credential")
		root, _ := cmd.Flags().GetString("workdir-root")
		maxConc, _ := cmd.Flags().GetInt("max-concurrent")
		labelPairs, _ := cmd.Flags().GetStringSlice("label")

		labels, err := parseLabelPairs(labelPairs)
		if err != nil {
			return err
		}

		dim := color.New(color.Faint)
		a, err := agent.New(agent.Config{
			Server:         server,
			Token:          token,
			CredentialPath: credPath,
			WorkDirRoot:    root,
			MaxConcurrent:  maxConc,
			Labels:         labels,
			Logf: func(format string, args ...any) {
				dim.Fprintf(os.Stderr, "[agent] "+format+"\n", args...)
			},
		})
		if err != nil {
			return err
		}

		header := color.New(color.FgCyan, color.Bold)
		header.Printf("cloop executor agent\n")
		fmt.Printf("  root:    %s\n", a.WorkDirRoot())
		caps := a.Capabilities()
		fmt.Printf("  host:    %s/%s, %d CPU", caps.OS, caps.Arch, caps.CPUs)
		if caps.MemoryMB > 0 {
			fmt.Printf(", %d MB RAM", caps.MemoryMB)
		}
		fmt.Println()
		if len(caps.ContainerRuntimes) > 0 {
			fmt.Printf("  runtimes: %s\n", strings.Join(caps.ContainerRuntimes, ", "))
		}
		if len(caps.Harnesses) > 0 {
			fmt.Printf("  harnesses: %s\n", strings.Join(caps.Harnesses, ", "))
		}
		fmt.Println()

		// Ctrl-C and SIGTERM end the loop cleanly. Without this the agent's
		// reconnect loop would ignore a terminating signal until the process
		// was killed outright, orphaning any workload mid-write.
		ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
		defer stop()

		if err := a.Run(ctx); err != nil {
			if errors.Is(err, remote.ErrRevoked) || errors.Is(err, remote.ErrCredentialInvalid) {
				return fmt.Errorf("%w\n\nThis device's credential is no longer accepted. "+
					"Mint a new token on the control plane with `cloop executor enroll` "+
					"and re-run with --token", err)
			}
			return err
		}
		fmt.Println("agent stopped")
		return nil
	},
}

var executorRevokeCmd = &cobra.Command{
	Use:   "revoke <id>",
	Short: "Revoke an enrollment token or an enrolled agent's credential",
	Long: `Revoke a remote executor credential by ID.

The ID may be either an enrollment token ID (from ` + "`cloop executor enroll`" + `) or an
agent ID. Revoking an enrollment token ALSO revokes the agent it produced, if
it was already redeemed — a token that leaked before the real device used it
must not leave the attacker's credential live.

A revoked agent's live connection is dropped immediately where the control
plane is running; otherwise revocation takes effect on its next reconnect.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		store, db, err := openExecutorStore()
		if err != nil {
			return err
		}
		defer db.Close()

		kind, err := remote.Revoke(store, args[0], time.Now())
		if err != nil {
			return err
		}
		ok := color.New(color.FgGreen, color.Bold)
		switch kind {
		case "enrollment+agent":
			ok.Printf("Revoked enrollment token %s and the agent credential it minted.\n", args[0])
		case "enrollment":
			ok.Printf("Revoked enrollment token %s (it had not been redeemed).\n", args[0])
		default:
			ok.Printf("Revoked agent credential %s.\n", args[0])
		}
		color.New(color.Faint).Println(
			"A connected agent is disconnected by the control plane; others are refused on reconnect.")
		return nil
	},
}

var executorAgentsCmd = &cobra.Command{
	Use:   "agents",
	Short: "List enrolled remote agents and outstanding enrollment tokens",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		store, db, err := openExecutorStore()
		if err != nil {
			return err
		}
		defer db.Close()

		header := color.New(color.FgCyan, color.Bold)
		dim := color.New(color.Faint)

		agents, err := store.ListAgents()
		if err != nil {
			return err
		}
		header.Println("Enrolled agents")
		if len(agents) == 0 {
			dim.Println("  none — mint a token with `cloop executor enroll --name <name>`")
		} else {
			fmt.Printf("  %-20s %-16s %-10s %s\n", "AGENT ID", "NAME", "STATE", "LAST SEEN")
			for _, a := range agents {
				st := "active"
				if a.Revoked() {
					st = "revoked"
				}
				last := "never"
				if !a.LastSeen.IsZero() {
					last = a.LastSeen.Format(time.RFC3339)
				}
				fmt.Printf("  %-20s %-16s %-10s %s\n", a.AgentID, a.Name, st, last)
			}
		}

		tokens, err := store.ListEnrollments()
		if err != nil {
			return err
		}
		outstanding := make([]remote.EnrollmentRecord, 0, len(tokens))
		now := time.Now()
		for _, t := range tokens {
			// Only unusable-by-nobody tokens are worth showing: a redeemed,
			// revoked, or expired token is not something the operator can act
			// on, and listing them all buries the one that matters.
			if !t.Redeemed() && !t.Revoked() && !t.Expired(now) {
				outstanding = append(outstanding, t)
			}
		}
		fmt.Println()
		header.Println("Outstanding enrollment tokens")
		if len(outstanding) == 0 {
			dim.Println("  none")
			return nil
		}
		fmt.Printf("  %-20s %-16s %s\n", "TOKEN ID", "NAME", "EXPIRES IN")
		for _, t := range outstanding {
			fmt.Printf("  %-20s %-16s %s\n", t.ID, t.Name, time.Until(t.ExpiresAt).Round(time.Second))
		}
		return nil
	},
}

// parseLabelPairs converts repeated --label k=v flags into a map.
func parseLabelPairs(pairs []string) (map[string]string, error) {
	if len(pairs) == 0 {
		return nil, nil
	}
	out := make(map[string]string, len(pairs))
	for _, p := range pairs {
		k, v, ok := strings.Cut(p, "=")
		if !ok || strings.TrimSpace(k) == "" {
			return nil, fmt.Errorf("invalid --label %q: expected key=value", p)
		}
		out[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	return out, nil
}

func init() {
	executorEnrollCmd.Flags().String("name", "", "operator-facing name for the device (required)")
	_ = executorEnrollCmd.MarkFlagRequired("name")
	executorEnrollCmd.Flags().Duration("ttl", remote.DefaultEnrollTTL,
		"how long the token may be redeemed for (max 24h)")
	executorEnrollCmd.Flags().String("workdir-root", "",
		"filesystem root on the device that every workload is confined beneath")
	executorEnrollCmd.Flags().String("server", "",
		"control-plane WebSocket URL to print in the device command")
	executorEnrollCmd.Flags().StringSlice("label", nil,
		"scheduler selector as key=value (repeatable)")

	executorAgentCmd.Flags().String("server", "",
		"control-plane WebSocket URL (default: from the saved credential)")
	executorAgentCmd.Flags().String("token", "", "enrollment token (first run only)")
	executorAgentCmd.Flags().String("credential", "",
		"path to the agent credential file (default: ~/.cloop/agent.json)")
	executorAgentCmd.Flags().String("workdir-root", "",
		"confine every workload beneath this directory (default: ~/.cloop/work)")
	executorAgentCmd.Flags().Int("max-concurrent", 0,
		"maximum simultaneous workloads (default: number of CPUs)")
	executorAgentCmd.Flags().StringSlice("label", nil,
		"scheduler selector as key=value (repeatable)")

	executorCmd.AddCommand(executorEnrollCmd)
	executorCmd.AddCommand(executorAgentCmd)
	executorCmd.AddCommand(executorRevokeCmd)
	executorCmd.AddCommand(executorAgentsCmd)
}
