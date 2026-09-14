package ui

// Per-identity spend, read back (Task 20264).
//
//	GET /api/cost/identities?window=today|7d|30d|all
//
// The question this answers is "who spent what". Before it, the hub could
// enforce a daily budget but not report against one — an operator asking why a
// tenant was refused had a denial and no arithmetic behind it.
//
// # Why this route is narrowed rather than simply gated
//
// Every other fleet-wide read here is admin-only: the Audit trail, the Quotas
// table, the executor inventory. Spend is different, because the person most
// entitled to see a spend figure is the person who spent it — a tenant refused
// at their daily cap needs to know how much of it they used, and having to ask
// an administrator to read their own number back is a bad enough experience
// that people work around it by not setting budgets at all.
//
// So the route is gated on a permission every signed-in role holds, and the
// *rows* are filtered: a caller holding user.manage (admin) sees the fleet, and
// everyone else sees exactly one row — their own — regardless of what they ask
// for. There is no identity parameter to tamper with, because the handler never
// reads one: the identity is taken from the request's own authenticated
// subject. That is what makes "a non-admin cannot read another identity's
// spend" a property of the shape of the code rather than of a check that could
// be forgotten.
//
// Deny-by-default still holds at the route: the permission is a real one, so an
// unmapped identity — authenticated by the IdP but bound to no role — is
// refused before the handler runs and sees nothing at all, not even its own row.

import (
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/authz"
	"github.com/blechschmidt/cloop/pkg/cost"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// identitySpendRow is one identity's spend over the requested window.
type identitySpendRow struct {
	Identity       string  `json:"identity"`
	InputTokens    int     `json:"input_tokens"`
	OutputTokens   int     `json:"output_tokens"`
	ThinkingTokens int     `json:"thinking_tokens"`
	TotalTokens    int     `json:"total_tokens"`
	EstimatedUSD   float64 `json:"estimated_usd"`
	Entries        int     `json:"entries"`
	Projects       int     `json:"projects"`
}

// spendWindow resolves the ?window= parameter to a UTC start instant.
//
// Anchored to UTC midnight rather than to "24 hours ago" because that is the
// boundary the quota enforcer's daily counters roll over on (see
// Enforcer.dayBucket). A report whose "today" differed from the budget's
// "today" would show a tenant under their cap while they were being refused,
// which is precisely the confusion this endpoint exists to end.
func spendWindow(param string, now time.Time) (from time.Time, label string) {
	utc := now.UTC()
	midnight := time.Date(utc.Year(), utc.Month(), utc.Day(), 0, 0, 0, 0, time.UTC)
	switch strings.TrimSpace(strings.ToLower(param)) {
	case "", "today":
		return midnight, "today"
	case "7d":
		return midnight.AddDate(0, 0, -6), "7d"
	case "30d":
		return midnight.AddDate(0, 0, -29), "30d"
	case "all":
		return time.Time{}, "all"
	default:
		// An unrecognised window reads as today rather than as everything.
		// Guessing wide would quietly hand back more history than the caller
		// asked for on nothing but a typo.
		return midnight, "today"
	}
}

// handleCostIdentities serves GET /api/cost/identities.
func (s *Server) handleCostIdentities(w http.ResponseWriter, r *http.Request) {
	from, label := spendWindow(r.URL.Query().Get("window"), time.Now())

	// Fleet-wide only for the role that already administers identities. Same
	// permission as the Quotas panel, so "can see everyone's limits" and "can
	// see everyone's spend" cannot drift apart into two different answers.
	fleet := s.grantFor(r).decide(authz.GlobalScope).Allows(authz.PermUserManage)

	// The caller's own identity, resolved exactly as the billing path resolves
	// it, so the row a tenant reads back is the row their budget is charged
	// against. An empty string here means the hub cannot name the caller at
	// all; combined with !fleet that yields an empty report rather than a
	// fallback to somebody else's data.
	var self string
	if subj := s.quotaSubject(r); subj != nil {
		if label := subj.Label(); label != "anonymous" {
			self = label
		}
	}
	if !fleet && self == "" {
		// A caller the hub cannot name, without fleet authority. There is no
		// row that is honestly theirs, and returning any would be attributing
		// somebody else's spend to them.
		jsonOK(w, map[string]interface{}{
			"window": label, "scope": "self", "identities": []identitySpendRow{},
		})
		return
	}

	rows := s.collectIdentitySpend(from, fleet, self)
	scope := "self"
	if fleet {
		scope = "fleet"
	}
	jsonOK(w, map[string]interface{}{
		"window":     label,
		"scope":      scope,
		"identities": rows,
	})
}

// collectIdentitySpend aggregates spend across every project the hub knows
// about, optionally narrowed to one identity.
//
// The narrowing is applied per row as they are merged rather than after, so a
// non-admin's response is never built holding other tenants' figures — there is
// no assembled fleet total for a later bug to leak.
func (s *Server) collectIdentitySpend(from time.Time, fleet bool, self string) []identitySpendRow {
	merged := make(map[string]*identitySpendRow)

	for _, entry := range s.allProjectEntries() {
		if entry.Path == "" {
			continue
		}
		db, err := statedb.Open(state.DBPath(entry.Path))
		if err != nil {
			// A project whose database cannot be opened contributes nothing.
			// Failing the whole report because one project of forty is mid
			// -migration would make the endpoint useless exactly when a fleet
			// is being upgraded.
			continue
		}
		spend, err := db.SpendByIdentity(from, time.Time{})
		_ = db.Close()
		if err != nil {
			continue
		}
		for _, sp := range spend {
			id := sp.Identity
			if id == "" {
				id = cost.IdentityUnattributed
			}
			if !fleet && id != self {
				continue
			}
			row, ok := merged[id]
			if !ok {
				row = &identitySpendRow{Identity: id}
				merged[id] = row
			}
			row.InputTokens += sp.InputTokens
			row.OutputTokens += sp.OutputTokens
			row.ThinkingTokens += sp.ThinkingTokens
			row.EstimatedUSD += sp.EstimatedUSD
			row.Entries += sp.Entries
			row.Projects++
		}
	}

	out := make([]identitySpendRow, 0, len(merged))
	for _, row := range merged {
		row.TotalTokens = row.InputTokens + row.OutputTokens + row.ThinkingTokens
		out = append(out, *row)
	}
	// Biggest spender first, name as the tiebreak so the order is stable
	// across requests rather than following Go's map iteration.
	sort.Slice(out, func(i, j int) bool {
		if out[i].EstimatedUSD != out[j].EstimatedUSD {
			return out[i].EstimatedUSD > out[j].EstimatedUSD
		}
		return out[i].Identity < out[j].Identity
	})
	return out
}
