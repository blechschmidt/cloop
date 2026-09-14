package ui

// GET /api/cost/identities (Task 20264).
//
// One property carries this file: a caller without user.manage sees exactly one
// row, their own, and no amount of asking changes that. Spend figures are a
// roster of who is worth compromising and a map of what each person is worth,
// so the narrow case is the default and the fleet view is the exception.

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/statedb"
)

// seedSpend writes cost rows into the fixture server's own project, which is
// the one collectIdentitySpend reads through allProjectEntries.
func seedSpend(t *testing.T, workDir string, rows map[string]float64) {
	t.Helper()
	db, err := statedb.Open(filepath.Join(workDir, ".cloop", "state.db"))
	if err != nil {
		t.Fatalf("open project db: %v", err)
	}
	defer func() { _ = db.Close() }()

	for identity, usd := range rows {
		if err := db.AppendCost(statedb.CostEntry{
			Timestamp: time.Now().UTC(), TaskID: 1, TaskTitle: "work",
			Provider: "anthropic", Model: "claude",
			InputTokens: 1000, OutputTokens: 200,
			EstimatedUSD: usd, Identity: identity,
		}); err != nil {
			t.Fatalf("append cost for %s: %v", identity, err)
		}
	}
}

// identitiesResponse is the wire shape the handler returns.
type identitiesResponse struct {
	Window     string             `json:"window"`
	Scope      string             `json:"scope"`
	Identities []identitySpendRow `json:"identities"`
}

func getIdentities(t *testing.T, c *http.Client, url string) (int, identitiesResponse, string) {
	t.Helper()
	code, body := do(t, c, http.MethodGet, url, "")
	var out identitiesResponse
	if code == http.StatusOK {
		if err := json.Unmarshal([]byte(body), &out); err != nil {
			t.Fatalf("decode %s: %v (body: %s)", url, err, body)
		}
	}
	return code, out, body
}

// TestNonAdminCannotReadAnotherIdentitysSpend is the access-control property.
//
// Every client in the RBAC fixture signs in as alice@example.com and differs
// only by group, so bob's row is present in the data and simply must not be
// returned to anyone who is not an administrator. That is the right shape for
// this test: the filtering is exercised against a row that genuinely exists,
// not against an empty table that would pass either way.
func TestNonAdminCannotReadAnotherIdentitysSpend(t *testing.T) {
	f := newRBACFixture(t)
	seedSpend(t, f.srv.WorkDir, map[string]float64{
		"alice@example.com": 1.25,
		"bob@example.com":   9.99,
	})

	url := f.ts.URL + "/api/cost/identities?window=today"

	// ── the admin sees the fleet
	code, adminView, body := getIdentities(t, f.admin, url)
	if code != http.StatusOK {
		t.Fatalf("admin GET = %d, want 200 (body: %s)", code, body)
	}
	if adminView.Scope != "fleet" {
		t.Errorf("admin scope = %q, want fleet", adminView.Scope)
	}
	seen := map[string]bool{}
	for _, row := range adminView.Identities {
		seen[row.Identity] = true
	}
	if !seen["alice@example.com"] || !seen["bob@example.com"] {
		t.Fatalf("admin view is missing a tenant: %+v", adminView.Identities)
	}

	// ── every non-admin role sees itself and nothing else
	for name, client := range map[string]*http.Client{
		"viewer":   f.viewer,
		"operator": f.operator,
	} {
		t.Run(name+" sees only its own row", func(t *testing.T) {
			code, view, body := getIdentities(t, client, url)
			if code != http.StatusOK {
				t.Fatalf("%s GET = %d, want 200 (body: %s)", name, code, body)
			}
			if view.Scope != "self" {
				t.Errorf("%s scope = %q, want self", name, view.Scope)
			}
			if len(view.Identities) != 1 {
				t.Fatalf("%s sees %d rows, want exactly its own: %+v",
					name, len(view.Identities), view.Identities)
			}
			if got := view.Identities[0].Identity; got != "alice@example.com" {
				t.Errorf("%s sees row for %q, want its own identity", name, got)
			}
			// The decisive assertion: bob's figures must not appear anywhere
			// in the response, not merely be absent from the row list.
			if strings.Contains(body, "bob@example.com") || strings.Contains(body, "9.99") {
				t.Errorf("%s response leaks another identity's spend: %s", name, body)
			}
		})
	}

	// ── deny-by-default: an authenticated identity bound to no role gets
	// nothing at all, not even its own figure.
	code, _, body = getIdentities(t, f.unmapped, url)
	if code == http.StatusOK {
		t.Errorf("an unmapped identity read spend and got 200: %s", body)
	}
}

// TestCostIdentitiesTakesNoIdentityParameter is the structural half of the
// property above.
//
// The handler must derive the caller's identity from the request's own
// authenticated subject. If it ever grew an `?identity=` parameter, the
// filtering would become a check somebody could forget rather than something
// the code cannot express — so a non-admin passing one must still see only
// itself.
func TestCostIdentitiesTakesNoIdentityParameter(t *testing.T) {
	f := newRBACFixture(t)
	seedSpend(t, f.srv.WorkDir, map[string]float64{
		"alice@example.com": 1.00,
		"bob@example.com":   42.00,
	})

	for _, probe := range []string{
		"?identity=bob@example.com",
		"?window=all&identity=bob@example.com",
		"?scope=fleet",
		"?window=all",
	} {
		code, view, body := getIdentities(t, f.operator, f.ts.URL+"/api/cost/identities"+probe)
		if code != http.StatusOK {
			t.Fatalf("operator GET %s = %d (body: %s)", probe, code, body)
		}
		if len(view.Identities) != 1 || view.Identities[0].Identity != "alice@example.com" {
			t.Fatalf("operator GET %s returned %+v — a query parameter widened the view",
				probe, view.Identities)
		}
	}
}

// TestSpendWindowAnchorsOnUTCMidnight: the report's "today" has to be the same
// day the quota enforcer buckets against, or a tenant reads a figure under
// their cap while being refused for exceeding it.
func TestSpendWindowAnchorsOnUTCMidnight(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 9, 14, 23, 30, 0, 0, time.UTC)
	from, label := spendWindow("today", now)
	want := time.Date(2026, 9, 14, 0, 0, 0, 0, time.UTC)
	if !from.Equal(want) {
		t.Errorf("today starts at %s, want %s", from, want)
	}
	if label != "today" {
		t.Errorf("label = %q, want today", label)
	}

	// Half an hour later it is a new day, and the window must move with it
	// rather than trailing 24 hours behind.
	from, _ = spendWindow("today", now.Add(time.Hour))
	if !from.Equal(want.AddDate(0, 0, 1)) {
		t.Errorf("after UTC midnight today starts at %s, want %s",
			from, want.AddDate(0, 0, 1))
	}

	// An unrecognised window narrows to today rather than widening to all
	// history: a typo must not hand back more than was asked for.
	if from, _ := spendWindow("everything-please", now); from.IsZero() {
		t.Error("an unrecognised window opened the full history")
	}
	if from, _ := spendWindow("all", now); !from.IsZero() {
		t.Error("window=all should leave the start open")
	}
}
