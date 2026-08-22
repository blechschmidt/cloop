package cmd

// `cloop hub token` — the operator surface for scoped API tokens (Task 20175).
//
// The shell counterpart to the Tokens panel and the /api/tokens endpoints. It
// exists because the first token on a hub has to come from somewhere: a fresh
// deployment has no browser session and, once the deprecated `--token` is
// retired, no credential at all. Minting from the shell on the hub's own
// filesystem is the bootstrap that breaks that circle, and it is the reason
// this command deliberately does not go through the HTTP API.
//
// Which also means it has no HTTP identity to bound. Running it requires write
// access to the hub's state database, which on any sane deployment is the same
// authority as the service account — so the anti-escalation rule that governs
// the REST path (apitoken.CheckDelegation) has nothing to compare against here
// and is not applied. That is the standard root-shell caveat, stated in the
// help text rather than hidden: whoever can run this can already read the
// database it writes to.

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/blechschmidt/cloop/pkg/apitoken"
	"github.com/blechschmidt/cloop/pkg/eventlog"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

var hubTokenCmd = &cobra.Command{
	Use:   "token",
	Short: "Mint, list, and revoke scoped API tokens for non-interactive access",
	Long: `Scoped API tokens ("PATs") authenticate CI jobs, scripts, and edge
devices against the hub.

Unlike the deprecated static ` + "`--token`" + `, a PAT is not an authorization
bypass. It carries its own roles, so every RBAC check applies to it exactly as
it does to a signed-in user; it can be limited to specific projects; it can
expire; and it can be revoked individually without disturbing any other caller.

cloop stores a salted hash, never the token itself. The value is printed once
by ` + "`create`" + ` and cannot be recovered — if it is lost, revoke it and mint
another.

These subcommands write directly to the hub's state database and therefore
require filesystem access to it. That is the intended bootstrap path for a
hub that has no credential yet; day to day, prefer the Tokens panel or
POST /api/tokens, which additionally refuse to mint a token stronger than the
caller.`,
}

var hubTokenCreateCmd = &cobra.Command{
	Use:   "create <name>",
	Short: "Mint a new API token and print it once",
	Long: `Mint a token and print its value exactly once.

Examples:

  # A read-only token for a status dashboard, valid for 90 days
  cloop hub token create status-board --role viewer --expires-in 90d

  # A CI token that may drive one project and nothing else
  cloop hub token create ci-payments --role operator --project payments --expires-in 30d

  # An edge device that cannot be re-provisioned on a schedule
  cloop hub token create edge-berlin-1 --role operator --expires-in 0`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := cmd.Flags().GetString("workdir")
		roles, _ := cmd.Flags().GetStringSlice("role")
		projects, _ := cmd.Flags().GetStringSlice("project")
		expiresIn, _ := cmd.Flags().GetString("expires-in")
		quiet, _ := cmd.Flags().GetBool("quiet")

		expires, err := parseTokenLifetime(expiresIn, time.Now())
		if err != nil {
			return err
		}

		mgr, closer, err := openHubTokenManager(workdir)
		if err != nil {
			return err
		}
		defer closer()

		minted, err := mgr.Mint(apitoken.MintOptions{
			Name:         args[0],
			Roles:        roles,
			ProjectScope: projects,
			CreatedBy:    "cli:" + currentUser(),
			ExpiresAt:    expires,
		})
		if err != nil {
			return err
		}
		appendTokenAuditEvent(workdir, "api_token.created", minted.Token.Prefix, map[string]any{
			"name":          minted.Token.Name,
			"roles":         minted.Token.Roles,
			"project_scope": minted.Token.ProjectScope,
			"via":           "cli",
		})

		// --quiet prints the bare token and nothing else, so the command can
		// be used in a shell substitution or piped into a secret manager
		// without the caller having to strip decoration off it.
		if quiet {
			fmt.Println(minted.Plaintext)
			return nil
		}

		bold := color.New(color.Bold)
		warn := color.New(color.FgYellow)
		dim := color.New(color.Faint)

		bold.Println("\nToken created.")
		fmt.Printf("  %-14s %s\n", "name", minted.Token.Name)
		fmt.Printf("  %-14s %s\n", "roles", strings.Join(minted.Token.Roles, ", "))
		fmt.Printf("  %-14s %s\n", "projects", scopeLabel(minted.Token.ProjectScope))
		fmt.Printf("  %-14s %s\n", "expires", expiryLabel(minted.Token.ExpiresAt))
		fmt.Printf("  %-14s %s\n", "id", minted.Token.ID)

		bold.Print("\n  ")
		fmt.Println(minted.Plaintext)

		warn.Println("\nThis is the only time this value is shown.")
		dim.Println("cloop stores a salted hash, not the token — it cannot be recovered.")
		dim.Println("Store it in your secret manager now. If you lose it, revoke this")
		dim.Printf("token (`cloop hub token revoke %s`) and mint another.\n\n", minted.Token.ID)
		dim.Println("Use it as:  Authorization: Bearer <token>")
		return nil
	},
}

var hubTokenListCmd = &cobra.Command{
	Use:   "list",
	Short: "List API tokens and their scope, status, and last use",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := cmd.Flags().GetString("workdir")
		activeOnly, _ := cmd.Flags().GetBool("active")

		mgr, closer, err := openHubTokenManager(workdir)
		if err != nil {
			return err
		}
		defer closer()

		tokens, err := mgr.List()
		if err != nil {
			return err
		}
		now := time.Now()
		if activeOnly {
			live := tokens[:0:0]
			for _, t := range tokens {
				if t.Active(now) {
					live = append(live, t)
				}
			}
			tokens = live
		}
		if len(tokens) == 0 {
			fmt.Println("No API tokens. Create one with `cloop hub token create <name>`.")
			return nil
		}

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "ID\tNAME\tROLES\tPROJECTS\tSTATUS\tEXPIRES\tLAST USED")
		for i := range tokens {
			t := &tokens[i]
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
				t.ID, truncateField(t.Name, 28),
				strings.Join(t.Roles, ","),
				truncateField(scopeLabel(t.ProjectScope), 24),
				tokenStatusLabel(t, now),
				expiryLabel(t.ExpiresAt),
				lastUsedLabel(t.LastUsedAt))
		}
		return w.Flush()
	},
}

var hubTokenRevokeCmd = &cobra.Command{
	Use:   "revoke <id>",
	Short: "Revoke an API token immediately",
	Long: `Revoke a token. The next request presenting it is rejected.

The row is kept rather than deleted, so the audit trail can still answer what
this credential could reach and when it was withdrawn. Revoking an
already-revoked token is a no-op.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := cmd.Flags().GetString("workdir")

		mgr, closer, err := openHubTokenManager(workdir)
		if err != nil {
			return err
		}
		defer closer()

		// Read first so the confirmation names what was withdrawn, and so a
		// mistyped id is an error rather than a silent success.
		tok, err := mgr.Get(args[0])
		if err != nil {
			return err
		}
		if err := mgr.Revoke(args[0]); err != nil {
			return err
		}
		appendTokenAuditEvent(workdir, "api_token.revoked", tok.Prefix, map[string]any{
			"name":  tok.Name,
			"roles": tok.Roles,
			"via":   "cli",
		})
		color.New(color.FgGreen).Printf("Revoked token %s (%s).\n", tok.ID, tok.Name)
		return nil
	},
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// openHubTokenManager opens the hub's own state database and returns a manager
// plus its closer.
//
// The hub's database, not a project's: a token minted into a tenant-writable
// file would be a credential that tenant could forge.
func openHubTokenManager(workdir string) (*apitoken.Manager, func(), error) {
	if workdir == "" {
		wd, err := os.Getwd()
		if err != nil {
			return nil, nil, fmt.Errorf("resolve working directory: %w", err)
		}
		workdir = wd
	}
	dbPath := state.DBPath(workdir)
	if _, err := os.Stat(dbPath); err != nil {
		return nil, nil, fmt.Errorf(
			"no cloop state database at %s — run this from the hub's directory, "+
				"or pass --workdir", dbPath)
	}
	db, err := statedb.Open(dbPath)
	if err != nil {
		return nil, nil, fmt.Errorf("open %s: %w", dbPath, err)
	}
	store, err := apitoken.NewSQLStore(db)
	if err != nil {
		_ = db.Close()
		return nil, nil, err
	}
	mgr, err := apitoken.NewManager(store)
	if err != nil {
		_ = db.Close()
		return nil, nil, err
	}
	return mgr, func() { _ = db.Close() }, nil
}

// parseTokenLifetime accepts "90d", "12h", "0" (never expires), or an RFC3339
// timestamp.
//
// Days are spelled out rather than assumed because a bare number is ambiguous
// between seconds and days, and picking either silently produces a token with
// a lifetime nobody intended.
func parseTokenLifetime(raw string, now time.Time) (time.Time, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || raw == "0" {
		return time.Time{}, nil
	}
	if ts, err := time.Parse(time.RFC3339, raw); err == nil {
		if !ts.After(now) {
			return time.Time{}, fmt.Errorf("--expires-in %q is in the past", raw)
		}
		return ts, nil
	}
	if strings.HasSuffix(raw, "d") {
		var days int
		if _, err := fmt.Sscanf(raw, "%dd", &days); err != nil || days < 0 {
			return time.Time{}, fmt.Errorf("--expires-in %q is not a valid duration", raw)
		}
		if days == 0 {
			return time.Time{}, nil
		}
		return now.Add(time.Duration(days) * 24 * time.Hour), nil
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		return time.Time{}, fmt.Errorf(
			"--expires-in %q is not a valid duration — use 90d, 12h, an RFC3339 timestamp, or 0 for no expiry", raw)
	}
	if d <= 0 {
		return time.Time{}, nil
	}
	return now.Add(d), nil
}

func scopeLabel(scope []string) string {
	if len(scope) == 0 {
		return "(all)"
	}
	return strings.Join(scope, ",")
}

func expiryLabel(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	return t.UTC().Format("2006-01-02 15:04Z")
}

func lastUsedLabel(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	return t.UTC().Format("2006-01-02 15:04Z")
}

func tokenStatusLabel(t *apitoken.Token, now time.Time) string {
	switch {
	case t.Revoked():
		return "revoked"
	case t.Expired(now):
		return "expired"
	}
	return "active"
}

func truncateField(s string, max int) string {
	if len(s) <= max {
		return s
	}
	if max <= 1 {
		return s[:max]
	}
	return s[:max-1] + "…"
}

func currentUser() string {
	for _, key := range []string{"SUDO_USER", "USER", "LOGNAME"} {
		if v := strings.TrimSpace(os.Getenv(key)); v != "" {
			return v
		}
	}
	return "unknown"
}

// appendTokenAuditEvent records a lifecycle event in the hash-chained trail.
//
// Best-effort, matching the HTTP path: a wedged journal must not make minting
// a credential fail. The payload never contains the token value — only its
// public prefix, name, roles, and scope.
func appendTokenAuditEvent(workdir, eventType, prefix string, payload map[string]any) {
	if workdir == "" {
		wd, err := os.Getwd()
		if err != nil {
			return
		}
		workdir = wd
	}
	log, err := eventlog.Open(workdir)
	if err != nil {
		return
	}
	defer log.Close()
	blob, err := json.Marshal(payload)
	if err != nil {
		return
	}
	_ = log.Append(&eventlog.AuditEvent{
		Actor:      "cli:" + currentUser(),
		EventType:  eventType,
		EntityType: "api_token",
		EntityID:   prefix,
		Payload:    string(blob),
	})
}

func init() {
	for _, c := range []*cobra.Command{hubTokenCreateCmd, hubTokenListCmd, hubTokenRevokeCmd} {
		c.Flags().String("workdir", "", "hub directory holding .cloop/state.db (default: current directory)")
	}
	hubTokenCreateCmd.Flags().StringSlice("role", []string{"viewer"},
		"role the token acts with (repeatable): viewer, operator, maintainer, admin")
	hubTokenCreateCmd.Flags().StringSlice("project", nil,
		"limit the token to this project, by registry name or path (repeatable; default: all projects)")
	hubTokenCreateCmd.Flags().String("expires-in", "90d",
		"lifetime: 90d, 12h, an RFC3339 timestamp, or 0 for no expiry")
	hubTokenCreateCmd.Flags().Bool("quiet", false,
		"print only the token value, for piping into a secret manager")

	hubTokenListCmd.Flags().Bool("active", false, "hide revoked and expired tokens")

	hubTokenCmd.AddCommand(hubTokenCreateCmd)
	hubTokenCmd.AddCommand(hubTokenListCmd)
	hubTokenCmd.AddCommand(hubTokenRevokeCmd)
	hubCmd.AddCommand(hubTokenCmd)
}
