package cmd

// `cloop hub token static` — the deprecated static admin token, from a shell
// (Task 20406).
//
// --token / CLOOP_UI_TOKEN is an administrator credential outside RBAC that
// never expires. An operator who suspects it leaked used to have one remedy:
// edit the Secret and restart every hub member, while everything the token had
// already opened stayed open. `retire` writes the token's fingerprint into the
// retired set instead, and every member refuses it from then on — within about
// a second when it reads the hub bus, within 30 seconds when it does not — and
// closes the dashboard streams and sandbox terminals it opened.
//
// The token is found without its value. Every hub process holding one reports
// its fingerprint and last use to static_token_use, so `status` and `retire`
// read what the running hubs hold from the database; CLOOP_UI_TOKEN in this
// shell, as `cloop hub doctor` reads it, names one too.
//
// No lease: like sessions and role bindings (hub_admin.go), the retired set is
// re-read by a running hub, on the bus notice this command posts and every 30
// seconds, so a write behind a live hub takes effect rather than vanishing.

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/blechschmidt/cloop/pkg/apitoken"
	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/statedb"
	"github.com/blechschmidt/cloop/pkg/statictoken"
	"github.com/blechschmidt/cloop/pkg/ui"
)

// staticTokenReasonMax mirrors the Settings card's bound on a reason.
const staticTokenReasonMax = 1000

var hubTokenStaticCmd = &cobra.Command{
	Use:   "static",
	Short: "See whether the static admin token is still accepted, and retire it",
	Long: `The static --token / CLOOP_UI_TOKEN is an administrator credential that bypasses
RBAC and never expires. Once single sign-on works, retire it.

  cloop hub token static status                       what the running hubs hold
  cloop hub token static retire --reason "SSO is live" refuse it on every member

Retiring takes effect without a restart: every hub process refuses the token
from then on and closes the dashboard streams and sandbox terminals it opened —
within about a second on a hub that reads the hub bus (the default), within 30
seconds on one started with ui.cluster.exclusive. The token stays configured, so
a token-only hub stays closed and admits only API tokens.

Retirement is per value. Deploying a new CLOOP_UI_TOKEN and restarting is how a
new one is issued; the retired value is refused for good.`,
}

var hubTokenStaticStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show the static tokens hubs hold, whether each is retired, and their last use",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := cmd.Flags().GetString("workdir")
		asJSON, _ := cmd.Flags().GetBool("json")
		db, closer, err := openHubDB(workdir)
		if err != nil {
			return err
		}
		defer closer()
		now := time.Now()
		entries, err := gatherStaticTokens(db, now)
		if err != nil {
			return err
		}
		out := cmd.OutOrStdout()
		if asJSON {
			return json.NewEncoder(out).Encode(staticTokensJSON(entries, now))
		}
		if len(entries) == 0 {
			fmt.Fprintln(out, "No static token is known: no running hub reports holding one, none was ever retired,")
			fmt.Fprintln(out, "and CLOOP_UI_TOKEN is not set in this shell.")
			return nil
		}
		color.New(color.Bold).Fprintln(out, "Static admin tokens")
		accepted := false
		for _, e := range entries {
			printStaticToken(out, e, now)
			accepted = accepted || (e.Retired == nil && (e.Held || e.FromEnv))
		}
		if accepted {
			color.New(color.Faint).Fprintln(out,
				"\nAn accepted static token is an administrator outside RBAC that never expires. Retire it once\n"+
					"single sign-on works:  cloop hub token static retire --reason \"...\"")
		}
		return nil
	},
}

var hubTokenStaticRetireCmd = &cobra.Command{
	Use:   "retire",
	Short: "Retire the static admin token on every hub member, without a restart",
	Long: `Retire the static admin token.

The token to retire is the one running hubs report holding, or CLOOP_UI_TOKEN in
this shell; --fingerprint picks one when there are several (a rotation in
progress). A hub with no single sign-on and no active admin API token would be
left with nobody able to administer it, so that is refused unless --force is
given — mint one first with ` + "`cloop hub token create break-glass --role admin`" + `.

Examples:

  cloop hub token static retire --reason "SSO is live, INC-4471"
  cloop hub token static retire --fingerprint 3f9c1e7a --reason "leaked in a CI log"`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := cmd.Flags().GetString("workdir")
		rawReason, _ := cmd.Flags().GetString("reason")
		prefix, _ := cmd.Flags().GetString("fingerprint")
		force, _ := cmd.Flags().GetBool("force")

		reason, err := requireReason(rawReason)
		if err != nil {
			return err
		}
		if len(reason) > staticTokenReasonMax {
			return fmt.Errorf("--reason is too long: keep it to a sentence or two")
		}
		db, closer, err := openHubDB(workdir)
		if err != nil {
			return err
		}
		defer closer()
		warnIfNotAHub(workdir)

		now := time.Now()
		entries, err := gatherStaticTokens(db, now)
		if err != nil {
			return err
		}
		target, err := pickStaticToken(entries, strings.TrimSpace(prefix))
		if err != nil {
			return err
		}
		out := cmd.OutOrStdout()
		if target.Retired != nil {
			fmt.Fprintf(out, "Static token %s was already retired on %s by %s.\n", statictoken.Short(target.Fingerprint),
				target.Retired.RetiredAt.UTC().Format(time.RFC3339), target.Retired.RetiredBy)
			return nil
		}

		sso := staticTokenSSO(workdir, target, now)
		admins, err := activeAdminTokens(db, now)
		if err != nil {
			return err
		}
		if err := statictoken.CheckRetire(sso, admins, force); err != nil {
			return err
		}
		strands := statictoken.CheckRetire(sso, admins, false) != nil

		actor := operatorActor()
		payload, err := json.Marshal(map[string]any{
			"fingerprint": target.Fingerprint,
			"reason":      reason,
			"via":         "cli",
			"forced":      strands && force,
			"self":        false,
			"os_user":     actor,
		})
		if err != nil {
			return fmt.Errorf("encode audit payload: %w", err)
		}
		_, written, err := db.RetireStaticToken(statedb.RetiredStaticTokenRow{
			Fingerprint: target.Fingerprint, RetiredAt: now, RetiredBy: actor, Reason: reason,
		}, &statedb.AuditEvent{
			Actor:      actor,
			EventType:  string(auditaction.ActionStaticTokenRetired),
			EntityType: "static_token",
			EntityID:   target.Fingerprint,
			Payload:    string(payload),
		})
		if err != nil {
			return err
		}
		if !written {
			fmt.Fprintf(out, "Static token %s was retired meanwhile by someone else.\n", statictoken.Short(target.Fingerprint))
			return nil
		}

		// Tell running hubs, so they refuse it now and end what it opened,
		// rather than at their next 30-second re-read. The row is written,
		// so a failure here is reported, not fatal.
		announced := true
		if err := ui.AnnounceStaticTokenRetired(db, cliOrigin(), target.Fingerprint); err != nil {
			announced = false
			fmt.Fprintf(os.Stderr, "warning: could not notify running hubs of the retirement: %v\n", err)
		}
		color.New(color.FgGreen).Fprintf(out, "Retired static token %s.\n", statictoken.Short(target.Fingerprint))
		faint := color.New(color.Faint)
		if announced {
			faint.Fprintf(out, "\nRunning hubs were told: they refuse it and close the dashboards and sandbox\n"+
				"terminals it opened within about a second. A hub started with\n"+
				"ui.cluster.exclusive reads no announcements and refuses it within %s.\n", statictoken.ReportInterval)
		} else {
			faint.Fprintf(out, "\nRunning hubs refuse it within %s, at their next re-read.\n", statictoken.ReportInterval)
		}
		faint.Fprintln(out, "To issue another, deploy a new CLOOP_UI_TOKEN value and restart; this one is refused for good.")
		if strands {
			color.New(color.FgYellow).Fprintln(out, "\nThis hub has no single sign-on and no active admin API token: nobody can administer it\n"+
				"until someone here runs `cloop hub token create break-glass --role admin`.")
		}
		return nil
	},
}

// staticTokenEntry is one static token the control plane knows of.
type staticTokenEntry struct {
	Fingerprint string
	// Held: a running hub reported holding it within statictoken.HeldWithin.
	Held bool
	// FromEnv: it is CLOOP_UI_TOKEN in this shell.
	FromEnv bool
	Use     *statedb.StaticTokenUseRow
	Retired *statedb.RetiredStaticTokenRow
}

// gatherStaticTokens lists every static token the control plane knows of:
// reported by a hub process, retired, or exported in this shell. Held and
// exported tokens first, then the rest by fingerprint.
func gatherStaticTokens(db *statedb.DB, now time.Time) ([]staticTokenEntry, error) {
	uses, err := db.ListStaticTokenUse()
	if err != nil {
		return nil, err
	}
	retired, err := db.ListRetiredStaticTokens()
	if err != nil {
		return nil, err
	}
	byFP := map[string]*staticTokenEntry{}
	entry := func(fp string) *staticTokenEntry {
		if e := byFP[fp]; e != nil {
			return e
		}
		e := &staticTokenEntry{Fingerprint: fp}
		byFP[fp] = e
		return e
	}
	for i := range uses {
		e := entry(uses[i].Fingerprint)
		e.Use = &uses[i]
		e.Held = statictoken.Held(uses[i].HeldAt, now)
	}
	for i := range retired {
		entry(retired[i].Fingerprint).Retired = &retired[i]
	}
	if v := os.Getenv("CLOOP_UI_TOKEN"); v != "" {
		entry(statictoken.Fingerprint(v)).FromEnv = true
	}
	out := make([]staticTokenEntry, 0, len(byFP))
	for _, e := range byFP {
		out = append(out, *e)
	}
	sort.Slice(out, func(i, j int) bool {
		ci, cj := out[i].Held || out[i].FromEnv, out[j].Held || out[j].FromEnv
		if ci != cj {
			return ci
		}
		return out[i].Fingerprint < out[j].Fingerprint
	})
	return out, nil
}

// pickStaticToken chooses the token to retire: the one --fingerprint names, or
// else the only one a running hub holds or this shell exports.
func pickStaticToken(entries []staticTokenEntry, prefix string) (staticTokenEntry, error) {
	if prefix != "" {
		prefix = strings.ToLower(prefix)
		if len(prefix) < 8 {
			return staticTokenEntry{}, fmt.Errorf("--fingerprint needs at least 8 characters of the fingerprint `status` prints")
		}
		var match []staticTokenEntry
		for _, e := range entries {
			if strings.HasPrefix(e.Fingerprint, prefix) {
				match = append(match, e)
			}
		}
		switch len(match) {
		case 0:
			return staticTokenEntry{}, fmt.Errorf("no known static token has a fingerprint starting %q — see `cloop hub token static status`", prefix)
		case 1:
			return match[0], nil
		}
		return staticTokenEntry{}, fmt.Errorf("%d static tokens have a fingerprint starting %q: give more of it", len(match), prefix)
	}
	var live []staticTokenEntry
	for _, e := range entries {
		if e.Retired == nil && (e.Held || e.FromEnv) {
			live = append(live, e)
		}
	}
	switch len(live) {
	case 1:
		return live[0], nil
	case 0:
		return staticTokenEntry{}, fmt.Errorf("no running hub reports holding a static token that is not already retired, and " +
			"CLOOP_UI_TOKEN in this shell names none: nothing to retire. Export the hub's CLOOP_UI_TOKEN " +
			"(from hub.env), or pass --fingerprint")
	}
	fps := make([]string, 0, len(live))
	for _, e := range live {
		fps = append(fps, statictoken.Short(e.Fingerprint))
	}
	return staticTokenEntry{}, fmt.Errorf("running hubs hold %d static tokens (%s) — a rotation in progress? "+
		"Pass --fingerprint to choose", len(live), strings.Join(fps, ", "))
}

// staticTokenSSO reports whether retiring e leaves single sign-on as a way
// in: what the hubs holding it last reported when one has recently, the
// configuration they start from otherwise — config.yaml and every
// per-instance overlay.
func staticTokenSSO(workdir string, e staticTokenEntry, now time.Time) bool {
	if e.Use != nil && statictoken.Held(e.Use.HeldAt, now) {
		return e.Use.SSO
	}
	if workdir == "" {
		workdir, _ = os.Getwd()
	}
	if cfg, err := config.Load(workdir); err == nil && cfg != nil && cfg.UI.OIDC.Enabled {
		return true
	}
	ports, _ := config.UIInstancePorts(workdir)
	for _, port := range ports {
		if cfg, _, err := config.LoadUIInstance(workdir, port); err == nil && cfg != nil && cfg.UI.OIDC.Enabled {
			return true
		}
	}
	return false
}

// activeAdminTokens counts the API tokens that could administer the hub
// without the static token.
func activeAdminTokens(db *statedb.DB, now time.Time) (int, error) {
	store, err := apitoken.NewSQLStore(db)
	if err != nil {
		return 0, err
	}
	mgr, err := apitoken.NewManager(store)
	if err != nil {
		return 0, err
	}
	tokens, err := mgr.List()
	if err != nil {
		return 0, fmt.Errorf("list API tokens: %w", err)
	}
	return statictoken.ActiveAdminTokens(tokens, now), nil
}

func printStaticToken(out io.Writer, e staticTokenEntry, now time.Time) {
	status := color.New(color.FgRed).Sprint("accepted")
	switch {
	case e.Retired != nil:
		status = color.New(color.FgGreen).Sprintf("retired %s by %s", e.Retired.RetiredAt.UTC().Format("2006-01-02 15:04Z"),
			e.Retired.RetiredBy)
		if e.Retired.Reason != "" {
			status += fmt.Sprintf(" — %q", e.Retired.Reason)
		}
	case !e.Held && !e.FromEnv:
		status = "no running hub holds it"
	}
	fmt.Fprintf(out, "  %s  %s\n", statictoken.Short(e.Fingerprint), status)
	var where []string
	if e.Held {
		where = append(where, fmt.Sprintf("held by a running hub (reported %s ago)", durationLabel(now.Sub(e.Use.HeldAt))))
	}
	if e.FromEnv {
		where = append(where, "CLOOP_UI_TOKEN in this shell")
	}
	if len(where) > 0 {
		fmt.Fprintf(out, "                %s\n", strings.Join(where, "; "))
	}
	if e.Use != nil {
		if e.Use.LastUsedAt.IsZero() {
			fmt.Fprintf(out, "                never used since a hub first reported it %s ago\n",
				durationLabel(now.Sub(e.Use.FirstSeenAt)))
		} else {
			fmt.Fprintf(out, "                last used %s from %s (%s ago)\n",
				e.Use.LastUsedAt.UTC().Format("2006-01-02 15:04Z"), orDash(e.Use.LastUsedIP),
				durationLabel(now.Sub(e.Use.LastUsedAt)))
		}
		if e.Use.RefusedCount > 0 {
			fmt.Fprintf(out, "                refused %d time(s) since it was retired, last %s from %s\n",
				e.Use.RefusedCount, e.Use.LastRefusedAt.UTC().Format("2006-01-02 15:04Z"), orDash(e.Use.LastRefusedIP))
		}
	}
}

func staticTokensJSON(entries []staticTokenEntry, now time.Time) []map[string]any {
	out := make([]map[string]any, 0, len(entries))
	for _, e := range entries {
		m := map[string]any{
			"fingerprint": e.Fingerprint,
			"status":      "accepted",
			"held":        e.Held,
			"from_env":    e.FromEnv,
		}
		if !e.Held && !e.FromEnv {
			m["status"] = "not_held"
		}
		if e.Retired != nil {
			m["status"] = "retired"
			m["retired_at"] = e.Retired.RetiredAt.UTC()
			m["retired_by"] = e.Retired.RetiredBy
			m["reason"] = e.Retired.Reason
		}
		if e.Use != nil {
			m["first_seen_at"] = e.Use.FirstSeenAt.UTC()
			m["held_at"] = e.Use.HeldAt.UTC()
			m["sso"] = e.Use.SSO
			if !e.Use.LastUsedAt.IsZero() {
				m["last_used_at"] = e.Use.LastUsedAt.UTC()
				m["last_used_ip"] = e.Use.LastUsedIP
				m["unused_seconds"] = int64(now.Sub(e.Use.LastUsedAt).Seconds())
			}
			if e.Use.RefusedCount > 0 {
				m["refused_count"] = e.Use.RefusedCount
				m["last_refused_at"] = e.Use.LastRefusedAt.UTC()
				m["last_refused_ip"] = e.Use.LastRefusedIP
			}
		}
		out = append(out, m)
	}
	return out
}

// registerHubTokenStaticFlags declares the flags each subcommand reads. See
// registerHubRoleFlags for why this is not inline in init().
func registerHubTokenStaticFlags(c *cobra.Command, kind string) {
	c.Flags().String("workdir", "", "hub directory holding .cloop/state.db (default: current directory)")
	if kind == "status" {
		c.Flags().Bool("json", false, "emit JSON for scripting")
		return
	}
	c.Flags().String("reason", "", "why (required; recorded in the audit trail)")
	c.Flags().String("fingerprint", "", "the token to retire, by the fingerprint `status` prints (when hubs hold several)")
	c.Flags().Bool("force", false, "retire it although nothing else could administer a hub without single sign-on")
}

func init() {
	registerHubTokenStaticFlags(hubTokenStaticStatusCmd, "status")
	registerHubTokenStaticFlags(hubTokenStaticRetireCmd, "retire")
	hubTokenStaticCmd.AddCommand(hubTokenStaticStatusCmd)
	hubTokenStaticCmd.AddCommand(hubTokenStaticRetireCmd)
	hubTokenCmd.AddCommand(hubTokenStaticCmd)
}
