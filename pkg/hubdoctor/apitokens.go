package hubdoctor

// api_tokens.unapproved: does a hub enforcing a role policy still hold API
// tokens minted when none was in force? (Task 20422)
//
// A token minted through the hub has no owner: its authority is its stamped
// roles, bounded at mint by the minter's own — and with single sign-on but no
// policy, every signed-in identity holds every role. So anybody signed in then
// could mint an admin token, which stayed admin once the policy was switched
// on. The hub now records what governed each mint and refuses an owner-less
// token not minted under a policy until an administrator approves it; this
// check fails while any such token is still live and unapproved, naming each,
// because a refused token is a CI job broken in a way its owner may not
// connect to a policy change — and a token nobody approves should be revoked
// rather than left suspended for its year.

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/blechschmidt/cloop/pkg/apitoken"
	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

func checkUnapprovedTokens(dir string, cfg *config.Config, opts Options, add addFn) {
	oc := cfg.UI.OIDC
	if !oc.Enabled {
		return
	}
	if enforced, err := oc.RBACEnforced(); err != nil || !enforced {
		// Without a policy no token is suspended, and rbac.enforced is the
		// finding to act on first.
		return
	}
	const title = "API tokens minted with no role policy in force"
	waiting, err := tokensAwaitingApproval(dir, opts)
	switch {
	case err != nil:
		add(Finding{
			Check: "api_tokens.unapproved", Title: title, Severity: SeverityWarn,
			Message:     "the API tokens could not be read, so whether any awaits approval is unknown: " + err.Error(),
			Remediation: "Run `cloop db verify` and fix what it reports, then `cloop hub token list`",
		})
	case len(waiting) == 0:
		add(Finding{
			Check: "api_tokens.unapproved", Title: title, Severity: SeverityPass,
			Message: "every live API token was minted under the role policy, at the control plane, or approved " +
				"since, or acts for an owner the policy decides",
		})
	default:
		names := make([]string, 0, len(waiting))
		ids := make([]string, 0, len(waiting))
		for _, t := range waiting {
			by := t.CreatedBy
			if by == "" {
				by = "unknown"
			}
			names = append(names, fmt.Sprintf("%s %q (%s; minted by %s on %s, %s)", t.ID, t.Name,
				strings.Join(t.Roles, ", "), by, t.CreatedAt.UTC().Format("2006-01-02"), mintedUnderLabel(t)))
			ids = append(ids, t.ID)
		}
		add(Finding{
			Check: "api_tokens.unapproved", Title: title, Severity: SeverityFail,
			Message: fmt.Sprintf("%d live API token(s) were minted while no role policy was in force — when anybody "+
				"signed in could mint any role — and are refused here until an administrator approves each: %s",
				len(waiting), strings.Join(names, "; ")),
			Remediation: "Approve each one you can vouch for — Secrets → API tokens → Approve, by an administrator " +
				"holding its roles, or `cloop hub token approve <id>` on the hub — and revoke the rest: " +
				"`cloop hub token revoke <id>`",
			Details: map[string]any{"tokens": ids},
		})
	}
}

// tokensAwaitingApproval lists the live tokens a role policy suspends until
// they are approved (apitoken.Token.AwaitsApproval), oldest first.
func tokensAwaitingApproval(dir string, opts Options) ([]apitoken.Token, error) {
	path := state.DBPath(dir)
	if _, err := os.Stat(path); err != nil {
		return nil, nil
	}
	db, err := statedb.Open(path)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	store, err := apitoken.NewSQLStore(db)
	if err != nil {
		return nil, err
	}
	tokens, err := store.List()
	if err != nil {
		return nil, err
	}
	now := opts.now()
	var out []apitoken.Token
	for i := range tokens {
		if t := &tokens[i]; t.Active(now) && t.AwaitsApproval() {
			out = append(out, *t)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}

// mintedUnderLabel says what governed a token's mint, as far as it is known.
func mintedUnderLabel(t apitoken.Token) string {
	if t.MintedUnder == apitoken.MintedUnderNoPolicy {
		return "no role policy in force"
	}
	return "minted before the hub recorded under what policy"
}
