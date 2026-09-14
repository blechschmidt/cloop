package cmd

// `cloop hub quota` — capping a runaway tenant from a shell (Task 20248).
//
// The counterpart to /api/quotas. Unlike the session and role commands next to
// it, this one takes the control-plane lease and refuses when a hub holds it,
// because the enforcer loads overrides into memory once at startup and never
// re-reads them: a write behind a live hub would neither take effect nor
// survive the next edit made from the panel. See the lease rule in
// hub_admin.go.
//
// Limits are addressed by resource name rather than by a flag per resource
// (`--limit daily_cost_usd=25`). pkg/quota's resource list is data — it grew
// from four to seven — and a flag per entry would mean this file had to be
// edited every time somebody added one, with the failure mode being an
// operator who cannot cap the thing that is actually running away.

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/blechschmidt/cloop/pkg/quota"
	"github.com/blechschmidt/cloop/pkg/quotastore"
)

var hubQuotaCmd = &cobra.Command{
	Use:   "quota",
	Short: "Inspect and set per-identity quota overrides",
	Long: `Read and edit the per-identity ceilings that bound what one tenant may consume.

Most quota policy belongs in ui.quotas in .cloop/config.yaml, where it is
reviewed and deployed like the role mappings it sits beside. This command edits
the *override* table: the one-off cap applied to a single identity, usually
because something is running away right now.

  cloop hub quota list                    every identity with a limit or usage
  cloop hub quota set alice@x.io --limit daily_cost_usd=10 --reason "..."
  cloop hub quota clear alice@x.io --reason "..."

Available resources: ` + quotaResourceNames() + `.

These write state a running hub caches, so they refuse while a hub holds the
control-plane lease and point at PUT /api/quotas/{identity} instead.`,
}

var hubQuotaListCmd = &cobra.Command{
	Use:   "list",
	Short: "Show per-identity quota overrides and current usage",
	Long: `List quota overrides and the usage recorded against each identity.

Read-only, so it works while a hub is running. What it cannot show is the
ceiling an identity inherits from a group or role binding in ui.quotas: those
resolve against claims the identity provider releases at sign-in, which a shell
command has no way to obtain. Overrides and usage are exact; inherited limits
are visible in the Quotas panel or GET /api/quotas, which resolve against a
live session.`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := cmd.Flags().GetString("workdir")
		asJSON, _ := cmd.Flags().GetBool("json")

		db, closer, err := openHubDB(workdir)
		if err != nil {
			return err
		}
		defer closer()
		store, err := quotastore.New(db)
		if err != nil {
			return err
		}
		overrides, err := store.LoadOverrides()
		if err != nil {
			return fmt.Errorf("load quota overrides: %w", err)
		}
		counters, err := store.LoadCounters()
		if err != nil {
			return fmt.Errorf("load quota counters: %w", err)
		}

		rows := mergeQuotaRows(overrides, counters)
		if asJSON {
			return json.NewEncoder(os.Stdout).Encode(rows)
		}
		if len(rows) == 0 {
			fmt.Println("No quota overrides and no recorded usage.")
			fmt.Println("Set one with `cloop hub quota set <identity> --limit <resource>=<n> --reason \"...\"`.")
			return nil
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "IDENTITY\tRESOURCE\tOVERRIDE\tUSED\tUPDATED BY")
		for _, row := range rows {
			for _, res := range row.resources() {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
					truncateField(row.Identity, 32), res,
					quotaCellLabel(row.Limits, res),
					quotaCellLabel(row.Usage, res),
					truncateField(orDash(row.UpdatedBy), 24))
			}
		}
		return w.Flush()
	},
}

var hubQuotaSetCmd = &cobra.Command{
	Use:   "set <identity>",
	Short: "Set or raise one identity's quota ceilings",
	Long: `Write a quota override for one identity.

The override is sparse and merges with what is already stored: setting
daily_cost_usd leaves every other ceiling for that identity exactly as it was,
inherited or overridden. Use --unset to drop one back to whatever the
configured policy grants, and ` + "`cloop hub quota clear`" + ` to drop them all.

Identity is the key the enforcer accounts against — normally an email address,
matching what ` + "`cloop hub quota list`" + ` shows.

Examples:

  # Cap the account that is burning the org's budget, right now
  cloop hub quota set alice@example.com --limit daily_cost_usd=5 --reason "runaway plan INC-4413"

  # Two ceilings at once, then let one of them go back to policy
  cloop hub quota set ci@example.com --limit max_concurrent_tasks=2 --limit max_projects=3 --reason "noisy CI"
  cloop hub quota set ci@example.com --unset max_projects --reason "CI behaving; project cap back to policy"`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := cmd.Flags().GetString("workdir")
		rawLimits, _ := cmd.Flags().GetStringSlice("limit")
		unset, _ := cmd.Flags().GetStringSlice("unset")
		rawReason, _ := cmd.Flags().GetString("reason")

		identity := strings.TrimSpace(args[0])
		if identity == "" {
			return fmt.Errorf("identity is required")
		}
		if len(rawLimits) == 0 && len(unset) == 0 {
			return fmt.Errorf("give at least one --limit <resource>=<n> or --unset <resource>")
		}
		reason, err := requireReason(rawReason)
		if err != nil {
			return err
		}
		setLimits, err := parseQuotaLimits(rawLimits)
		if err != nil {
			return err
		}
		drop, err := parseQuotaResources(unset)
		if err != nil {
			return err
		}

		// Ahead of requireHubLease, which takes the lease and so writes a
		// hub_instances row of its own — checking after would always find one.
		warnIfNotAHub(workdir)

		release, err := requireHubLease(workdir, "PUT /api/quotas/{identity} or the Quotas panel")
		if err != nil {
			return err
		}
		defer release()

		db, closer, err := openHubDB(workdir)
		if err != nil {
			return err
		}
		defer closer()
		store, err := quotastore.New(db)
		if err != nil {
			return err
		}

		existing, err := loadQuotaOverride(store, identity)
		if err != nil {
			return err
		}
		merged := existing.Clone()
		if merged == nil {
			merged = quota.Limits{}
		}
		for res, v := range setLimits {
			merged[res] = v
		}
		for _, res := range drop {
			delete(merged, res)
		}
		// Normalize through pkg/quota so an unknown resource or an impossible
		// ceiling is rejected here rather than stored and then quietly ignored
		// by an enforcer that cannot make sense of it.
		normalized, err := merged.Normalize()
		if err != nil {
			return fmt.Errorf("invalid limits: %w", err)
		}

		if err := auditHubAdmin(db, "quota.override_set", "quota", identity, reason, map[string]any{
			"identity": identity,
			"limits":   quotaLimitsPayload(normalized),
			"unset":    resourceNames(drop),
		}); err != nil {
			return err
		}
		if len(normalized) == 0 {
			// Every ceiling was unset. Storing an empty override would leave a
			// row claiming to override nothing, which reads in the panel as "an
			// admin looked at this identity" and is not what happened.
			if _, err := store.DeleteOverride(identity); err != nil {
				return fmt.Errorf("clear quota override for %q: %w", identity, err)
			}
			color.New(color.FgGreen).Printf("Cleared every override for %s.\n", identity)
			printQuotaPropagationNote()
			return nil
		}
		if err := store.PutOverride(quota.Override{
			Identity:  identity,
			Limits:    normalized,
			UpdatedAt: time.Now().UTC(),
			UpdatedBy: operatorActor(),
		}); err != nil {
			return fmt.Errorf("write quota override for %q: %w", identity, err)
		}

		color.New(color.FgGreen).Printf("Quota override for %s:\n", identity)
		for _, res := range sortedResources(normalized) {
			fmt.Printf("  %-28s %s\n", res, quotaCellLabel(normalized, res))
		}
		printQuotaPropagationNote()
		return nil
	},
}

var hubQuotaClearCmd = &cobra.Command{
	Use:   "clear <identity>",
	Short: "Remove one identity's quota override entirely",
	Long: `Delete an identity's override so their ceilings come from ui.quotas again.

This does not remove their limits — it removes the *exception*. An identity
covered by a group binding in config returns to that binding's ceilings, and one
covered by nothing returns to ui.quotas.defaults.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := cmd.Flags().GetString("workdir")
		rawReason, _ := cmd.Flags().GetString("reason")

		identity := strings.TrimSpace(args[0])
		if identity == "" {
			return fmt.Errorf("identity is required")
		}
		reason, err := requireReason(rawReason)
		if err != nil {
			return err
		}

		warnIfNotAHub(workdir)

		release, err := requireHubLease(workdir, "DELETE /api/quotas/{identity} or the Quotas panel")
		if err != nil {
			return err
		}
		defer release()

		db, closer, err := openHubDB(workdir)
		if err != nil {
			return err
		}
		defer closer()
		store, err := quotastore.New(db)
		if err != nil {
			return err
		}

		// Read first so a mistyped identity is an error rather than a
		// confident "cleared" for somebody who never had an override.
		existing, err := loadQuotaOverride(store, identity)
		if err != nil {
			return err
		}
		if existing == nil {
			return fmt.Errorf("%q has no quota override — nothing to clear", identity)
		}
		if err := auditHubAdmin(db, "quota.override_cleared", "quota", identity, reason, map[string]any{
			"identity":       identity,
			"cleared_limits": quotaLimitsPayload(existing),
		}); err != nil {
			return err
		}
		if _, err := store.DeleteOverride(identity); err != nil {
			return fmt.Errorf("clear quota override for %q: %w", identity, err)
		}
		color.New(color.FgGreen).Printf("Cleared the quota override for %s.\n", identity)
		color.New(color.Faint).Println(
			"Their ceilings now come from ui.quotas. Takes effect when the hub next starts.")
		return nil
	},
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// printQuotaPropagationNote states when the write actually reaches enforcement.
// Printed on every path that changed something, including the one that only
// removes a ceiling: "my cap is gone" needs the same caveat as "my cap is in".
func printQuotaPropagationNote() {
	color.New(color.Faint).Println(
		"\nTakes effect when the hub next starts — it loads overrides once. Start it now,\n" +
			"or apply the same change through the Quotas panel on a running hub.")
}

// quotaRow is one identity's overrides and usage, joined for display.
type quotaRow struct {
	Identity  string                     `json:"identity"`
	Limits    map[quota.Resource]float64 `json:"limits,omitempty"`
	Usage     map[quota.Resource]float64 `json:"usage,omitempty"`
	UpdatedBy string                     `json:"updated_by,omitempty"`
	// A string rather than a time.Time: encoding/json's omitempty does not
	// apply to structs, so a zero time would render as "0001-01-01T00:00:00Z"
	// in --json output for every identity that only has usage.
	UpdatedAt string `json:"updated_at,omitempty"`
}

// resources returns every resource this row has something to say about, in the
// canonical order so repeated listings do not shuffle.
func (r quotaRow) resources() []quota.Resource {
	seen := map[quota.Resource]bool{}
	for res := range r.Limits {
		seen[res] = true
	}
	for res := range r.Usage {
		seen[res] = true
	}
	out := make([]quota.Resource, 0, len(seen))
	for _, res := range quota.AllResources {
		if seen[res] {
			out = append(out, res)
			delete(seen, res)
		}
	}
	// Anything left is a resource this binary does not know — a row written by
	// a newer build. Shown rather than hidden: an operator reading a cap they
	// cannot explain is better served than one shown a list that silently
	// omits the cap actually in force.
	rest := make([]quota.Resource, 0, len(seen))
	for res := range seen {
		rest = append(rest, res)
	}
	sort.Slice(rest, func(i, j int) bool { return rest[i] < rest[j] })
	return append(out, rest...)
}

// mergeQuotaRows joins overrides and counters by identity.
//
// Counters are folded across buckets: a daily resource has one row per UTC day
// and the sum over them is not meaningful, so the *current* bucket wins and
// older ones are dropped. LoadCounters returns them unordered, so "current" is
// the lexicographically greatest bucket, which for YYYY-MM-DD is the latest.
func mergeQuotaRows(overrides []quota.Override, counters []quota.CounterRow) []quotaRow {
	byIdentity := map[string]*quotaRow{}
	get := func(identity string) *quotaRow {
		if row, ok := byIdentity[identity]; ok {
			return row
		}
		row := &quotaRow{
			Identity: identity,
			Limits:   map[quota.Resource]float64{},
			Usage:    map[quota.Resource]float64{},
		}
		byIdentity[identity] = row
		return row
	}
	for _, o := range overrides {
		row := get(o.Identity)
		for res, v := range o.Limits {
			row.Limits[res] = v
		}
		row.UpdatedBy = o.UpdatedBy
		if !o.UpdatedAt.IsZero() {
			row.UpdatedAt = o.UpdatedAt.UTC().Format(time.RFC3339)
		}
	}
	latestBucket := map[string]string{}
	for _, c := range counters {
		row := get(c.Identity)
		key := c.Identity + "\x00" + string(c.Resource)
		if prev, ok := latestBucket[key]; ok && c.Bucket < prev {
			continue
		}
		latestBucket[key] = c.Bucket
		row.Usage[c.Resource] = c.Value
	}

	out := make([]quotaRow, 0, len(byIdentity))
	for _, row := range byIdentity {
		out = append(out, *row)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Identity < out[j].Identity })
	return out
}

func loadQuotaOverride(store *quotastore.Store, identity string) (quota.Limits, error) {
	overrides, err := store.LoadOverrides()
	if err != nil {
		return nil, fmt.Errorf("load quota overrides: %w", err)
	}
	for _, o := range overrides {
		if o.Identity == identity {
			return o.Limits, nil
		}
	}
	return nil, nil
}

// parseQuotaLimits reads repeated --limit resource=value pairs.
func parseQuotaLimits(raw []string) (quota.Limits, error) {
	out := quota.Limits{}
	for _, entry := range raw {
		name, value, ok := strings.Cut(entry, "=")
		if !ok {
			return nil, fmt.Errorf(
				"--limit %q is not resource=value — for example --limit daily_cost_usd=25", entry)
		}
		res, err := parseQuotaResource(name)
		if err != nil {
			return nil, err
		}
		n, err := strconv.ParseFloat(strings.TrimSpace(value), 64)
		if err != nil {
			return nil, fmt.Errorf("--limit %s: %q is not a number", res, value)
		}
		// Checked here as well as in Normalize because the message can name the
		// flag. A NaN ceiling compares false against everything, so it would not
		// be a cap at all — it would be a cap-shaped hole.
		if math.IsNaN(n) || math.IsInf(n, 0) {
			return nil, fmt.Errorf("--limit %s: %q is not a finite number", res, value)
		}
		if n < 0 {
			return nil, fmt.Errorf(
				"--limit %s: a negative ceiling is not a limit — use --unset %s to drop it", res, res)
		}
		out[res] = n
	}
	return out, nil
}

func parseQuotaResources(raw []string) ([]quota.Resource, error) {
	out := make([]quota.Resource, 0, len(raw))
	for _, name := range raw {
		res, err := parseQuotaResource(name)
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func parseQuotaResource(name string) (quota.Resource, error) {
	res := quota.Resource(strings.TrimSpace(strings.ToLower(name)))
	if !res.Valid() {
		return "", fmt.Errorf("%q is not a quota resource — valid: %s", name, quotaResourceNames())
	}
	return res, nil
}

func quotaResourceNames() string {
	names := make([]string, len(quota.AllResources))
	for i, r := range quota.AllResources {
		names[i] = string(r)
	}
	return strings.Join(names, ", ")
}

func resourceNames(resources []quota.Resource) []string {
	out := make([]string, len(resources))
	for i, r := range resources {
		out[i] = string(r)
	}
	return out
}

func sortedResources(limits quota.Limits) []quota.Resource {
	out := make([]quota.Resource, 0, len(limits))
	for _, res := range quota.AllResources {
		if _, ok := limits[res]; ok {
			out = append(out, res)
		}
	}
	return out
}

// quotaLimitsPayload converts limits for the audit record. Keys are strings
// because a JSON object's keys must be, and a map[quota.Resource]float64
// marshals to one anyway — being explicit keeps the recorded shape stable if
// the type ever changes.
func quotaLimitsPayload(limits quota.Limits) map[string]float64 {
	out := make(map[string]float64, len(limits))
	for res, v := range limits {
		out[string(res)] = v
	}
	return out
}

// quotaCellLabel renders one cell, distinguishing a resource the map does not
// mention from one explicitly set to zero.
//
// They are not the same thing and the difference is the whole cap: Normalize
// keeps a zero (only negatives are dropped) and the enforcer treats any
// requested amount above a zero ceiling as a breach, so `--limit
// daily_cost_usd=0` is a hard freeze. Printing it as "-" — the same as no
// override at all — would show the strictest possible cap as the absence of
// one, in the table an operator reads mid-incident.
func quotaCellLabel(m map[quota.Resource]float64, res quota.Resource) string {
	v, ok := m[res]
	if !ok {
		return "-"
	}
	return quotaValueLabel(v)
}

func quotaValueLabel(v float64) string {
	if v == math.Trunc(v) && math.Abs(v) < 1e15 {
		return strconv.FormatFloat(v, 'f', -1, 64)
	}
	return strconv.FormatFloat(v, 'f', 2, 64)
}

// registerHubQuotaFlags declares the flags each quota subcommand reads. See
// registerHubRoleFlags for why this is not inline in init().
func registerHubQuotaFlags(c *cobra.Command, kind string) {
	c.Flags().String("workdir", "", "hub directory holding .cloop/state.db (default: current directory)")
	switch kind {
	case "list":
		c.Flags().Bool("json", false, "emit JSON for scripting")
		return
	case "set":
		c.Flags().StringSlice("limit", nil,
			"ceiling to set as <resource>=<n> (repeatable): "+quotaResourceNames())
		c.Flags().StringSlice("unset", nil,
			"resource to drop back to configured policy (repeatable)")
	}
	c.Flags().String("reason", "", "why (required; recorded in the audit trail)")
}

func init() {
	registerHubQuotaFlags(hubQuotaListCmd, "list")
	registerHubQuotaFlags(hubQuotaSetCmd, "set")
	registerHubQuotaFlags(hubQuotaClearCmd, "clear")

	hubQuotaCmd.AddCommand(hubQuotaListCmd)
	hubQuotaCmd.AddCommand(hubQuotaSetCmd)
	hubQuotaCmd.AddCommand(hubQuotaClearCmd)
	hubCmd.AddCommand(hubQuotaCmd)
}
