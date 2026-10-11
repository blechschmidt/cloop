package hubdoctor

// ui.static_token (Task 20406): warn while a static admin token is accepted
// beside single sign-on with an enforced role policy, saying how long it has
// gone unused; stay silent where the token is the sign-in or no policy exists
// for it to bypass.

import (
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/internal/rbactest"
	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/statedb"
	"github.com/blechschmidt/cloop/pkg/statictoken"
)

const doctorStaticToken = "doctor-static-token-20406"

// staticTokenFindings runs the offline diagnosis of a hub with ui.oidc o over
// dir, with CLOOP_UI_TOKEN set to env in the doctor's shell.
func staticTokenFindings(t *testing.T, dir string, o config.OIDCConfig, env string, now time.Time) []Finding {
	t.Helper()
	t.Setenv(envUIToken, env)
	cfg := hubCfg()
	cfg.UI.OIDC = o
	return findingsFor(t, dir, cfg, Options{Offline: true, Now: func() time.Time { return now }})["ui.static_token"]
}

func openDoctorDB(t *testing.T, dir string) *statedb.DB {
	t.Helper()
	db, err := statedb.Open(mustInitStateDB(t, dir))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestStaticTokenAcrossTheMatrix(t *testing.T) {
	now := time.Now()
	for _, tc := range rbactest.Matrix() {
		t.Run(tc.Name, func(t *testing.T) {
			// No token anywhere.
			got := staticTokenFindings(t, t.TempDir(), tc.OIDC, "", now)
			// The token in the doctor's shell, never reported by a hub.
			withEnv := staticTokenFindings(t, t.TempDir(), tc.OIDC, doctorStaticToken, now)

			if !tc.OIDC.Enabled || !tc.Enforced {
				// Without SSO the token is the sign-in (ui.exposure); with SSO
				// and no policy, rbac.enforced is the finding to fix first.
				if len(got) != 0 || len(withEnv) != 0 {
					t.Fatalf("ui.static_token on a hub with no policy for it to bypass: %+v %+v", got, withEnv)
				}
				return
			}
			if len(got) != 1 || got[0].Severity != SeverityPass || !strings.Contains(got[0].Message, "no static token is accepted") {
				t.Fatalf("no token: %+v, want one pass", got)
			}
			if len(withEnv) != 1 {
				t.Fatalf("token in the shell: %d findings", len(withEnv))
			}
			f := withEnv[0]
			wantSeverity(t, f, SeverityWarn)
			for _, want := range []string{"still accepted", statictoken.Short(statictoken.Fingerprint(doctorStaticToken)),
				"no hub has reported using it", "outside RBAC"} {
				if !strings.Contains(f.Message, want) {
					t.Errorf("message does not say %q: %q", want, f.Message)
				}
			}
			if !strings.Contains(f.Remediation, "cloop hub token static retire") {
				t.Errorf("remediation does not name the command: %q", f.Remediation)
			}
			if strings.Contains(f.Message, doctorStaticToken) {
				t.Fatal("the finding carries the token's value")
			}
		})
	}
}

// TestStaticTokenSaysHowLongItHasGoneUnused: a token a running hub reports,
// last used three days ago, and one it reports never having seen used.
func TestStaticTokenSaysHowLongItHasGoneUnused(t *testing.T) {
	now := time.Now()
	o := rbactest.Matrix()[4].OIDC // SSO + mappings

	dir := t.TempDir()
	db := openDoctorDB(t, dir)
	fp := statictoken.Fingerprint("held-by-a-running-hub")
	if err := db.ReportStaticTokenUse([]statedb.StaticTokenUseReport{{
		Fingerprint: fp, At: now.Add(-10 * time.Second), Held: true, HeldBy: "member-1", SSO: true,
		UsedAt: now.Add(-72 * time.Hour), UsedIP: "203.0.113.7",
	}}); err != nil {
		t.Fatal(err)
	}
	got := staticTokenFindings(t, dir, o, "", now)
	if len(got) != 1 {
		t.Fatalf("findings = %+v", got)
	}
	wantSeverity(t, got[0], SeverityWarn)
	for _, want := range []string{"held by a running hub", "unused for 3 days", "203.0.113.7"} {
		if !strings.Contains(got[0].Message, want) {
			t.Errorf("message does not say %q: %q", want, got[0].Message)
		}
	}
	if unused, _ := got[0].Details["unused_seconds"].(int64); unused < 71*3600 {
		t.Errorf("details = %v, want unused_seconds of about three days", got[0].Details)
	}

	quiet := t.TempDir()
	qdb := openDoctorDB(t, quiet)
	if err := qdb.ReportStaticTokenUse([]statedb.StaticTokenUseReport{{
		Fingerprint: statictoken.Fingerprint("never-used"), At: now.Add(-15 * 24 * time.Hour), Held: true,
	}, {
		Fingerprint: statictoken.Fingerprint("never-used"), At: now.Add(-time.Minute), Held: true,
	}}); err != nil {
		t.Fatal(err)
	}
	got = staticTokenFindings(t, quiet, o, "", now)
	if len(got) != 1 || !strings.Contains(got[0].Message, "never used in the 15 days") {
		t.Fatalf("a token never used: %+v", got)
	}

	// A token a hub last reported long ago is no running hub's.
	stale := t.TempDir()
	sdb := openDoctorDB(t, stale)
	if err := sdb.ReportStaticTokenUse([]statedb.StaticTokenUseReport{{
		Fingerprint: statictoken.Fingerprint("stopped-hub"), At: now.Add(-time.Hour), Held: true,
	}}); err != nil {
		t.Fatal(err)
	}
	got = staticTokenFindings(t, stale, o, "", now)
	if len(got) != 1 || got[0].Severity != SeverityPass {
		t.Fatalf("a token no running hub holds: %+v, want a pass", got)
	}
}

// TestStaticTokenRetiredIsAPass: the token in the shell was retired; every
// member refuses it.
func TestStaticTokenRetiredIsAPass(t *testing.T) {
	now := time.Now()
	dir := t.TempDir()
	db := openDoctorDB(t, dir)
	if _, _, err := db.RetireStaticToken(statedb.RetiredStaticTokenRow{
		Fingerprint: statictoken.Fingerprint(doctorStaticToken), RetiredBy: "cli:root", Reason: "SSO is live",
	}, nil); err != nil {
		t.Fatal(err)
	}
	got := staticTokenFindings(t, dir, rbactest.Matrix()[3].OIDC, doctorStaticToken, now)
	if len(got) != 1 || got[0].Severity != SeverityPass || !strings.Contains(got[0].Message, "retired") ||
		!strings.Contains(got[0].Message, "cli:root") {
		t.Fatalf("a retired token: %+v, want a pass naming the retirement", got)
	}
}
