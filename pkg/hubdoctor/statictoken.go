package hubdoctor

// ui.static_token: is the static admin token still accepted on a hub whose
// single sign-on enforces a role policy? (Task 20406)
//
// The static --token / CLOOP_UI_TOKEN is an administrator outside RBAC that
// never expires. Before SSO it is the hub's sign-in; once SSO works and a role
// policy is in force it is the one credential the policy does not reach — and
// the Helm chart's production path creates it beside the OIDC client secret,
// so a typical SSO install keeps it for ever unless somebody retires it. This
// check says so, and how long it has gone unused, which is the evidence an
// operator needs to retire it without breaking anything.
//
// Which tokens are accepted comes from two places, as `cloop hub token static`
// reads them: CLOOP_UI_TOKEN in the doctor's own shell (the ui.exposure
// convention), and the fingerprints running hubs report holding in
// static_token_use. Either is accepted unless retired_static_tokens names it.
//
// Only an SSO hub with an enforced policy is judged. Without SSO the token is
// the sign-in, and ui.exposure is the finding about it; with SSO and no policy
// every signed-in identity already holds nearly as much, and rbac.enforced is
// the finding to fix first.

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
	"github.com/blechschmidt/cloop/pkg/statictoken"
)

// staticTokenRetire is the remediation: the command, then the deployment.
const staticTokenRetire = "Retire it — `cloop hub token static retire --reason \"single sign-on is live\"`, " +
	"or Settings → Static admin token → Retire — and every member refuses it without a restart; " +
	"then remove CLOOP_UI_TOKEN / --token from the deployment (in Helm, secrets.uiToken or the key " +
	"in secrets.existingSecret)"

// acceptedStaticToken is one static token the doctor found, retired or not.
type acceptedStaticToken struct {
	fingerprint string
	fromEnv     bool
	use         *statedb.StaticTokenUseRow
	retired     *statedb.RetiredStaticTokenRow
}

func checkStaticToken(dir string, cfg *config.Config, opts Options, add addFn) {
	oc := cfg.UI.OIDC
	if !oc.Enabled {
		return
	}
	if enforced, err := oc.RBACEnforced(); err != nil || !enforced {
		return
	}
	now := opts.now()

	byFP := map[string]*acceptedStaticToken{}
	token := func(fp string) *acceptedStaticToken {
		if t := byFP[fp]; t != nil {
			return t
		}
		t := &acceptedStaticToken{fingerprint: fp}
		byFP[fp] = t
		return t
	}
	if v := os.Getenv(envUIToken); v != "" {
		token(statictoken.Fingerprint(v)).fromEnv = true
	}
	retired, uses, dbErr := readStaticTokenState(dir)
	for i := range uses {
		if statictoken.Held(uses[i].HeldAt, now) {
			token(uses[i].Fingerprint).use = &uses[i]
		}
	}
	for fp, t := range byFP {
		if t.use == nil {
			for i := range uses {
				if uses[i].Fingerprint == fp {
					t.use = &uses[i]
				}
			}
		}
		if rec, ok := retired[fp]; ok {
			rec := rec
			t.retired = &rec
		}
	}

	var accepted, gone []*acceptedStaticToken
	for _, t := range byFP {
		if t.retired != nil {
			gone = append(gone, t)
		} else {
			accepted = append(accepted, t)
		}
	}
	sort.Slice(accepted, func(i, j int) bool { return accepted[i].fingerprint < accepted[j].fingerprint })

	const title = "Static admin token"
	switch {
	case dbErr != nil && len(byFP) > 0:
		add(Finding{
			Check: "ui.static_token", Title: title, Severity: SeverityWarn,
			Message: "CLOOP_UI_TOKEN is set, and whether it is retired could not be read: " + dbErr.Error() +
				". While it is accepted it is an administrator outside the enforced role policy",
			Remediation: "Run `cloop db verify` and fix what it reports, then `cloop hub token static status`",
		})
	case len(accepted) > 0:
		parts := make([]string, 0, len(accepted))
		details := map[string]any{"accepted": len(accepted)}
		for i, t := range accepted {
			parts = append(parts, fmt.Sprintf("%s (%s; %s)", statictoken.Short(t.fingerprint), staticTokenWhere(t),
				staticTokenUnused(t, now)))
			if i == 0 {
				details["fingerprint"] = statictoken.Short(t.fingerprint)
				if t.use != nil && !t.use.LastUsedAt.IsZero() {
					details["last_used_at"] = t.use.LastUsedAt.UTC().Format(time.RFC3339)
					details["unused_seconds"] = int64(now.Sub(t.use.LastUsedAt).Seconds())
				}
			}
		}
		add(Finding{
			Check: "ui.static_token", Title: title, Severity: SeverityWarn,
			Message: "a static token is still accepted beside single sign-on with an enforced role policy: " +
				strings.Join(parts, ", ") + ". Whoever holds it is an administrator outside RBAC, and it never expires",
			Remediation: staticTokenRetire,
			Details:     details,
		})
	case len(gone) > 0:
		sort.Slice(gone, func(i, j int) bool { return gone[i].fingerprint < gone[j].fingerprint })
		t := gone[0]
		add(Finding{
			Check: "ui.static_token", Title: title, Severity: SeverityPass,
			Message: fmt.Sprintf("the static token %s was retired on %s by %s; every hub member refuses it",
				statictoken.Short(t.fingerprint), t.retired.RetiredAt.UTC().Format("2006-01-02 15:04Z"), t.retired.RetiredBy),
		})
	default:
		add(Finding{
			Check: "ui.static_token", Title: title, Severity: SeverityPass,
			Message: "no static token is accepted: CLOOP_UI_TOKEN is not set in this shell and no running hub reports holding one",
		})
	}
}

// readStaticTokenState reads the retired set and the reported use. A hub
// directory with no database has neither.
func readStaticTokenState(dir string) (map[string]statedb.RetiredStaticTokenRow, []statedb.StaticTokenUseRow, error) {
	path := state.DBPath(dir)
	if _, err := os.Stat(path); err != nil {
		return nil, nil, nil
	}
	db, err := statedb.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer db.Close()
	rows, err := db.ListRetiredStaticTokens()
	if err != nil {
		return nil, nil, err
	}
	retired := make(map[string]statedb.RetiredStaticTokenRow, len(rows))
	for _, r := range rows {
		retired[r.Fingerprint] = r
	}
	uses, err := db.ListStaticTokenUse()
	if err != nil {
		return nil, nil, err
	}
	return retired, uses, nil
}

// staticTokenWhere says how the doctor knows of t.
func staticTokenWhere(t *acceptedStaticToken) string {
	switch {
	case t.use != nil && t.fromEnv:
		return "held by a running hub, and CLOOP_UI_TOKEN in this shell"
	case t.fromEnv:
		return "CLOOP_UI_TOKEN in this shell"
	}
	return "held by a running hub"
}

// staticTokenUnused says how long t has gone unused, as far as the hubs
// holding it have reported.
func staticTokenUnused(t *acceptedStaticToken, now time.Time) string {
	switch {
	case t.use == nil:
		return "no hub has reported using it"
	case !t.use.LastUsedAt.IsZero():
		ip := ""
		if t.use.LastUsedIP != "" {
			ip = " from " + t.use.LastUsedIP
		}
		return fmt.Sprintf("unused for %s, last%s at %s", staticTokenAge(now.Sub(t.use.LastUsedAt)), ip,
			t.use.LastUsedAt.UTC().Format("2006-01-02 15:04Z"))
	case !t.use.FirstSeenAt.IsZero():
		return fmt.Sprintf("never used in the %s since a hub first reported holding it", staticTokenAge(now.Sub(t.use.FirstSeenAt)))
	}
	return "never used"
}

// staticTokenAge renders d coarsely: an operator deciding whether anything
// still depends on a token reads days, not seconds.
func staticTokenAge(d time.Duration) string {
	switch {
	case d < time.Minute:
		return "under a minute"
	case d < time.Hour:
		return fmt.Sprintf("%d minute(s)", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%d hour(s)", int(d.Hours()))
	}
	return fmt.Sprintf("%d days", int(d.Hours()/24))
}
