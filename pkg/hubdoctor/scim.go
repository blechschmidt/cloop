package hubdoctor

// SCIM provisioning (Task 20415): would the hub start with ui.oidc.scim, and
// can the directory the identity provider provisioned actually reach the
// people in it?
//
// A provisioned user is matched to a hub identity by ui.oidc.scim.match_claim.
// A user who carries no value for it is nobody the hub can refuse: the
// provider deactivates them and nothing here ends. Two users sharing a value
// are refused a guess — the hub acts on the claim alone and grants neither
// their groups. Both are the provider's attribute mappings telling the hub
// something other than what the operator chose to match on, and nothing on
// the request path says so.

import (
	"fmt"
	"os"
	"time"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/provision"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

func checkSCIM(dir string, cfg *config.Config, add addFn) {
	sc := cfg.UI.OIDC.SCIM
	claim, err := provision.ParseMatchClaim(sc.MatchClaim)
	if err != nil {
		add(Finding{
			Check: "scim.config", Title: "SCIM provisioning", Severity: SeverityFail,
			Message:     "the hub will not start: " + err.Error(),
			Remediation: "Set ui.oidc.scim.match_claim to email, preferred_username, oid or sub",
		})
		return
	}
	path := state.DBPath(dir)
	if _, err := os.Stat(path); err != nil {
		return // checkStorage reports a missing database
	}
	db, err := statedb.Open(path)
	if err != nil {
		return
	}
	defer db.Close()
	creds, err := db.ListSCIMCredentials()
	if err != nil {
		add(Finding{
			Check: "scim.config", Title: "SCIM provisioning", Severity: SeverityWarn,
			Message: "could not read the SCIM credentials: " + err.Error(),
		})
		return
	}
	live := 0
	var lastUsed time.Time
	for _, c := range creds {
		if c.Revoked() {
			continue
		}
		live++
		if c.LastUsedAt.After(lastUsed) {
			lastUsed = c.LastUsedAt
		}
	}
	if live == 0 {
		add(Finding{
			Check: "scim.config", Title: "SCIM provisioning", Severity: SeverityPass,
			Message: "not set up: no live SCIM credential, so the identity provider cannot provision this hub " +
				"and a deactivation there reaches nothing here until an administrator offboards the person",
			Remediation: "Optional: `cloop hub scim credential create <name>`, then point the identity " +
				"provider at <hub>/scim/v2 (docs/guides/scim-provisioning.md)",
		})
		return
	}
	if !cfg.UI.OIDC.Enabled {
		add(Finding{
			Check: "scim.config", Title: "SCIM provisioning", Severity: SeverityWarn,
			Message: fmt.Sprintf("%d live SCIM credential(s), but single sign-on is off: the hub serves "+
				"/scim/v2 only with ui.oidc enabled, so every provisioning request is refused", live),
			Remediation: "Enable ui.oidc, or revoke the credential with `cloop hub scim credential revoke`",
		})
		return
	}
	used := "never used"
	if !lastUsed.IsZero() {
		used = "last used " + lastUsed.UTC().Format(time.RFC3339)
	}
	add(Finding{
		Check: "scim.config", Title: "SCIM provisioning", Severity: SeverityPass,
		Message: fmt.Sprintf("%d live credential(s), %s; matching on %s, offboarding after %s", live, used, claim,
			offboardAfterText(sc.EffectiveOffboardAfterDays())),
	})

	d, err := provision.NewDirectory(db, claim)
	if err != nil {
		add(Finding{
			Check: "scim.directory", Title: "Provisioned directory", Severity: SeverityWarn,
			Message: "could not read the directory: " + err.Error(),
		})
		return
	}
	st := d.Stats()
	switch {
	case st.Ambiguous > 0 || st.Unmatchable > 0:
		carry := "carry no " + string(claim)
		if claim == provision.MatchOID {
			// Entra's default mapping sends mailNickname as externalId.
			carry = "carry no oid (an externalId that is not an Entra object ID: map objectId to externalId)"
		}
		add(Finding{
			Check: "scim.directory", Title: "Provisioned directory", Severity: SeverityWarn,
			Message: fmt.Sprintf("%d user(s) %s, so their deactivation reaches no hub identity; %d share "+
				"their %s with another, and are granted no provisioned group", st.Unmatchable, carry,
				st.Ambiguous, claim),
			Remediation: "Map the attribute the hub matches on in the identity provider's provisioning " +
				"settings — or choose the claim that attribute is (ui.oidc.scim.match_claim) — and let the " +
				"next cycle re-send the users; `cloop hub scim status` lists the counts",
		})
	default:
		add(Finding{
			Check: "scim.directory", Title: "Provisioned directory", Severity: SeverityPass,
			Message: fmt.Sprintf("%d user(s) — %d active, %d suspended — and %d group(s), every user matched by %s",
				st.Users, st.Active, st.Inactive, st.Groups, claim),
		})
	}
}

func offboardAfterText(days int) string {
	if days <= 0 {
		return "a DELETE only"
	}
	return fmt.Sprintf("%d day(s) suspended", days)
}
