package hubdoctor

import (
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/internal/statedbtest"
	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/provision"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

func scimFindings(t *testing.T, dir string, cfg *config.Config) map[string]Finding {
	t.Helper()
	out := map[string]Finding{}
	checkSCIM(dir, cfg, func(f Finding) { out[f.Check] = f })
	return out
}

func TestSCIMCheck(t *testing.T) {
	dir := statedbtest.Dir(t)
	cfg := &config.Config{}
	cfg.UI.OIDC.SCIM.MatchClaim = "upn"
	if f := scimFindings(t, dir, cfg)["scim.config"]; f.Severity != SeverityFail {
		t.Fatalf("an invalid match claim: %+v", f)
	}
	cfg.UI.OIDC.SCIM.MatchClaim = ""
	if f := scimFindings(t, dir, cfg)["scim.config"]; f.Severity != SeverityPass ||
		!strings.Contains(f.Message, "not set up") {
		t.Fatalf("no credential: %+v", f)
	}

	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := provision.MintCredential(db, "entra", provision.AdminContext{Actor: "test"}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if f := scimFindings(t, dir, cfg)["scim.config"]; f.Severity != SeverityWarn {
		t.Fatalf("a credential on a hub without single sign-on: %+v", f)
	}
	cfg.UI.OIDC.Enabled = true
	got := scimFindings(t, dir, cfg)
	if got["scim.config"].Severity != SeverityPass || got["scim.directory"].Severity != SeverityPass {
		t.Fatalf("a healthy directory: %+v", got)
	}
	// Two users the email match cannot tell apart cannot be written through
	// the service; one with no email at all can.
	if _, err := db.WriteSCIMUser(statedb.SCIMUserWrite{Create: true,
		Row: statedb.SCIMUserRow{ID: "u1", UserName: "no-address", Active: true}}); err != nil {
		t.Fatal(err)
	}
	if f := scimFindings(t, dir, cfg)["scim.directory"]; f.Severity != SeverityWarn ||
		!strings.Contains(f.Message, "1 user(s) carry no email") {
		t.Fatalf("an unmatchable user: %+v", f)
	}
}
