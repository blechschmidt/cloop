package cmd

// hub_cluster_cmd.go: the operator's view of the hub processes serving one
// control plane (Task 20354).
//
// Read straight from the database, so it answers with every hub process down
// — which is when "who was serving, and who led" matters most — and from any
// machine that can open the state file.

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/blechschmidt/cloop/pkg/egressbroker"
	"github.com/blechschmidt/cloop/pkg/hubcluster"
	"github.com/blechschmidt/cloop/pkg/hublease"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

var hubClusterJSON bool

var hubClusterCmd = &cobra.Command{
	Use:   "cluster",
	Short: "Show the hub processes serving this control plane",
	Long: `Show the hub processes serving this directory's control plane.

Every ` + "`cloop ui`" + ` joins the control plane at its working directory as a member.
Several may serve it at once behind a load balancer: they share the database,
forward to each other what only one of them can answer (a run's Stop, an edge
agent's operations, a login callback), relay live events between their
dashboards, and elect one leader for the work that must happen exactly once.

  cloop hub cluster status          members, the leader, and what each holds`,
}

var hubClusterStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "List the members serving this control plane and the leader",
	Long: `List the hub processes that serve, or recently served, this directory's
control plane: where each can be reached, whether it is alive, which one leads,
and what each holds that the others forward to it — edge agents' sockets, runs
in progress, in-flight logins.

A member is alive while it renews its row. One that stopped less than a day ago
is still listed, marked gone, so the member that was serving when something
went wrong can still be named.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()
		return printHubClusterStatus(state.DBPath(workdir), hubClusterJSON)
	},
}

// clusterStatusMember is one member as --json prints it: the field names
// GET /api/cluster uses, so a script can read either.
type clusterStatusMember struct {
	ID           string    `json:"id"`
	Hostname     string    `json:"hostname"`
	PID          int       `json:"pid"`
	Address      string    `json:"address"`
	AdvertiseURL string    `json:"advertise_url"`
	Version      string    `json:"version"`
	StartedAt    time.Time `json:"started_at"`
	HeartbeatAt  time.Time `json:"heartbeat_at"`
	LeftAt       time.Time `json:"left_at,omitzero"`
	Alive        bool      `json:"alive"`
	Leader       bool      `json:"leader"`
}

type clusterStatusOwner struct {
	Kind   string    `json:"kind"`
	Key    string    `json:"key"`
	Member string    `json:"member"`
	Since  time.Time `json:"since"`
}

func printHubClusterStatus(dbPath string, asJSON bool) error {
	if _, err := os.Stat(dbPath); err != nil {
		return fmt.Errorf("no control plane here (%s): %w", dbPath, err)
	}
	db, err := statedb.Open(dbPath)
	if err != nil {
		return err
	}
	defer db.Close()
	rows, err := db.ListHubMembers()
	if err != nil {
		return err
	}
	lease, err := hublease.Inspect(hublease.Options{Store: db})
	if err != nil {
		return err
	}
	leader := ""
	if lease.Live {
		leader = lease.Row.InstanceID
	}
	now := time.Now()
	members := make([]clusterStatusMember, 0, len(rows))
	for _, r := range rows {
		members = append(members, clusterStatusMember{
			ID: r.InstanceID, Hostname: r.Hostname, PID: r.PID, Address: r.Address,
			AdvertiseURL: r.AdvertiseURL, Version: r.Version,
			StartedAt: r.StartedAt, HeartbeatAt: r.HeartbeatAt, LeftAt: r.LeftAt,
			Alive: hubcluster.RowAlive(r, now), Leader: r.InstanceID == leader,
		})
	}
	owned, err := db.ListHubOwners("")
	if err != nil {
		return err
	}
	var owners []clusterStatusOwner
	for _, o := range owned {
		if o.Kind == "ccauth" || o.Kind == "session_refresh" || o.Kind == "lock" {
			continue // identities and transient locks: nothing an operator acts on here
		}
		if o.Kind == egressbroker.HostedStatusKind {
			continue // a member's report of its own egress proxy, not a thing it owns; see `cloop hub doctor`
		}
		owners = append(owners, clusterStatusOwner{Kind: o.Kind, Key: o.Key, Member: o.InstanceID, Since: o.ClaimedAt})
	}

	if asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(map[string]any{"leader": leader, "members": members, "owners": owners})
	}

	bold := color.New(color.Bold)
	dim := color.New(color.Faint)
	bold.Println("Hub cluster")
	dim.Printf("  %s\n\n", dbPath)
	if len(members) == 0 {
		fmt.Println("  No hub has served this control plane since clustering was introduced.")
		if lease.Live {
			fmt.Printf("  A hub that is not a member holds the lease: %s on %s (pid %d).\n",
				lease.Row.InstanceID, lease.Row.Hostname, lease.Row.PID)
		}
		return nil
	}
	sort.SliceStable(members, func(i, j int) bool {
		if members[i].Alive != members[j].Alive {
			return members[i].Alive
		}
		return members[i].StartedAt.Before(members[j].StartedAt)
	})
	live := 0
	for _, m := range members {
		state := color.New(color.FgGreen).Sprint("serving")
		switch {
		case !m.LeftAt.IsZero():
			state = color.New(color.Faint).Sprintf("left %s ago", now.Sub(m.LeftAt).Round(time.Second))
		case !m.Alive:
			state = color.New(color.FgYellow).Sprintf("gone (last beat %s ago)", now.Sub(m.HeartbeatAt).Round(time.Second))
		default:
			live++
		}
		role := ""
		if m.Leader {
			role = color.New(color.FgCyan).Sprint(" leader")
		}
		fmt.Printf("  %s%s  %s\n", m.ID, role, state)
		fmt.Printf("      host %s pid %d, listening %s, reachable at %s\n", m.Hostname, m.PID, m.Address, m.AdvertiseURL)
		if m.Version != "" {
			fmt.Printf("      version %s, started %s\n", m.Version, m.StartedAt.Format(time.RFC3339))
		}
	}
	fmt.Printf("\n  %d member(s) serving", live)
	if leader == "" {
		fmt.Print(", no leader at the moment")
	}
	fmt.Println()
	if len(owners) > 0 {
		fmt.Println()
		bold.Println("  Held by one member")
		for _, o := range owners {
			fmt.Printf("    %-10s %-40s %s\n", o.Kind, truncateMiddle(o.Key, 40), o.Member)
		}
	}
	return nil
}

func truncateMiddle(s string, max int) string {
	if len(s) <= max || max < 5 {
		return s
	}
	half := (max - 1) / 2
	return s[:half] + "…" + s[len(s)-half:]
}

func init() {
	hubClusterStatusCmd.Flags().BoolVar(&hubClusterJSON, "json", false, "Emit the status as JSON")
	hubClusterCmd.AddCommand(hubClusterStatusCmd)
	hubCmd.AddCommand(hubClusterCmd)
}
