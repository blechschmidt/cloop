package hubdoctor

// api_tokens.unapproved (Task 20422): fail while a hub enforcing a role policy
// holds a live, owner-less API token minted with no policy in force — or
// before the hub recorded how — that nobody has approved; stay silent where no
// policy suspends anything.

import (
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/internal/rbactest"
	"github.com/blechschmidt/cloop/pkg/apitoken"
	"github.com/blechschmidt/cloop/pkg/config"
)

// unapprovedFindings runs the offline diagnosis of a hub with ui.oidc o over
// dir.
func unapprovedFindings(t *testing.T, dir string, o config.OIDCConfig, now time.Time) []Finding {
	t.Helper()
	cfg := hubCfg()
	cfg.UI.OIDC = o
	return findingsFor(t, dir, cfg, Options{Offline: true, Now: func() time.Time { return now }})["api_tokens.unapproved"]
}

// seedTokens mints one token of every kind the check tells apart, and returns
// the ids of the two a policy suspends.
func seedTokens(t *testing.T, dir string, now time.Time) []string {
	t.Helper()
	db := openDoctorDB(t, dir)
	store, err := apitoken.NewSQLStore(db)
	if err != nil {
		t.Fatal(err)
	}
	mgr, err := apitoken.NewManager(store)
	if err != nil {
		t.Fatal(err)
	}
	mgr.SetClock(func() time.Time { return now })
	mint := func(name string, opts apitoken.MintOptions) apitoken.Token {
		t.Helper()
		opts.Name, opts.CreatedBy = name, "someone@example.com"
		if opts.ExpiresAt.IsZero() {
			opts.ExpiresAt = now.Add(24 * time.Hour)
		}
		if opts.Roles == nil {
			opts.Roles = []string{"admin"}
		}
		m, err := mgr.Mint(opts)
		if err != nil {
			t.Fatal(err)
		}
		return m.Token
	}
	noPolicy := mint("no-policy", apitoken.MintOptions{MintedUnder: apitoken.MintedUnderNoPolicy})
	unknown := mint("unrecorded", apitoken.MintOptions{Roles: []string{"viewer"}})
	mint("under-policy", apitoken.MintOptions{MintedUnder: apitoken.MintedUnderPolicy})
	mint("operator", apitoken.MintOptions{MintedUnder: apitoken.MintedByOperator})
	mint("owned", apitoken.MintOptions{MintedUnder: apitoken.MintedUnderNoPolicy,
		Owner: &apitoken.Owner{Email: "alice@example.com"}})
	approved := mint("approved", apitoken.MintOptions{MintedUnder: apitoken.MintedUnderNoPolicy})
	if _, err := mgr.Approve(approved.ID, "admin@example.com"); err != nil {
		t.Fatal(err)
	}
	revoked := mint("revoked", apitoken.MintOptions{MintedUnder: apitoken.MintedUnderNoPolicy})
	if err := mgr.Revoke(revoked.ID); err != nil {
		t.Fatal(err)
	}
	mint("expired", apitoken.MintOptions{MintedUnder: apitoken.MintedUnderNoPolicy, ExpiresAt: now.Add(time.Minute)})
	return []string{noPolicy.ID, unknown.ID}
}

func TestUnapprovedTokensAcrossTheMatrix(t *testing.T) {
	now := time.Now()
	for _, tc := range rbactest.Matrix() {
		t.Run(tc.Name, func(t *testing.T) {
			empty := unapprovedFindings(t, t.TempDir(), tc.OIDC, now)
			dir := t.TempDir()
			ids := seedTokens(t, dir, now)
			// An hour on: the "expired" token has lapsed.
			got := unapprovedFindings(t, dir, tc.OIDC, now.Add(time.Hour))

			if !tc.OIDC.Enabled || !tc.Enforced {
				// No policy, no suspension: rbac.enforced is the finding.
				if len(empty) != 0 || len(got) != 0 {
					t.Fatalf("api_tokens.unapproved on a hub with no policy: %+v %+v", empty, got)
				}
				return
			}
			if len(empty) != 1 || empty[0].Severity != SeverityPass {
				t.Fatalf("no tokens: %+v, want one pass", empty)
			}
			if len(got) != 1 {
				t.Fatalf("%d findings, want one: %+v", len(got), got)
			}
			f := got[0]
			wantSeverity(t, f, SeverityFail)
			for _, want := range append([]string{"2 live API token(s)", `"no-policy"`, `"unrecorded"`,
				"no role policy in force", "minted before the hub recorded"}, ids...) {
				if !strings.Contains(f.Message, want) {
					t.Errorf("message does not say %q: %q", want, f.Message)
				}
			}
			for _, not := range []string{"under-policy", "operator", "owned", `"approved"`, "revoked", "expired"} {
				if strings.Contains(f.Message, not) {
					t.Errorf("message names %q, which no policy suspends: %q", not, f.Message)
				}
			}
			if !strings.Contains(f.Remediation, "cloop hub token approve") ||
				!strings.Contains(f.Remediation, "cloop hub token revoke") {
				t.Errorf("remediation does not name both commands: %q", f.Remediation)
			}
		})
	}
}
