package hubdoctor

// The doctor on a rotation of the hub CA (Task 20438): a stage that outlasts
// the longest monitor session, a previous CA kept past it, a member whose
// build predates rotation, a monitor configured at a name the active CA does
// not permit, and the CA's expiry naming the rotation as its remedy.

import (
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/hubca"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/secretstore"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// rotationRig is a control plane with a CA and the git proxy's leaf for
// hub.example.com, and the environment a rotation step works in.
func rotationRig(t *testing.T, at time.Time) (dir string, env hubca.Env, db *statedb.DB) {
	t.Helper()
	t.Setenv(secretbroker.EnvPassphraseKey, monitorTLSPassphrase)
	dir = t.TempDir()
	mustInitStateDB(t, dir)
	issueLeaf(t, dir, at, "hub.example.com")
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ks, err := secretstore.New(db)
	if err != nil {
		t.Fatal(err)
	}
	kr, err := secretbroker.OpenKeyring(ks, secretbroker.WithKeyringPassphrase(monitorTLSPassphrase))
	if err != nil {
		t.Fatal(err)
	}
	store, err := hubca.NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	return dir, hubca.Env{Store: store, Sealer: kr, Options: hubca.Options{Now: func() time.Time { return at }, Actor: "op"}}, db
}

func hubCAFindings(t *testing.T, dir string, cfg *config.Config, now time.Time) map[string][]Finding {
	t.Helper()
	out := map[string][]Finding{}
	checkHubCA(dir, cfg, Options{Now: func() time.Time { return now }}, func(f Finding) {
		out[f.Check] = append(out[f.Check], f)
	})
	return out
}

func TestHubCARotationAgeIsMeasuredAgainstTheLongestSession(t *testing.T) {
	staged := time.Now().UTC().Add(-time.Hour)
	dir, env, _ := rotationRig(t, staged)
	cfg := autoTLSConfig()
	cfg.Executors.GitProxy.SessionMinutes = 120

	steady := hubCAFindings(t, dir, cfg, staged)
	if f := onlyFinding(t, steady, "hubca.rotation"); f.Severity != SeverityPass ||
		!strings.Contains(f.Message, "no rotation under way") {
		t.Fatalf("steady: %+v", f)
	}
	if _, err := hubca.Stage(env, hubca.StageRequest{}); err != nil {
		t.Fatal(err)
	}
	// An hour into the stage, with two-hour sessions: fine.
	f := onlyFinding(t, hubCAFindings(t, dir, cfg, staged.Add(time.Hour)), "hubca.rotation")
	if f.Severity != SeverityPass || !strings.Contains(f.Message, "staged") {
		t.Fatalf("an hour into the stage: %+v", f)
	}
	// Three hours in, past the longest session: warned, with the way out.
	f = onlyFinding(t, hubCAFindings(t, dir, cfg, staged.Add(3*time.Hour)), "hubca.rotation")
	if f.Severity != SeverityWarn || !strings.Contains(f.Message, "longer than the longest session") ||
		!strings.Contains(f.Remediation, "--activate") || !strings.Contains(f.Remediation, "--abort") {
		t.Fatalf("three hours into the stage: %+v", f)
	}

	if _, err := hubca.Activate(env, hubca.ActivateRequest{}); err != nil {
		t.Fatal(err)
	}
	// Activated with the leaf still from the old CA, long after: the leader
	// has not reissued.
	f = onlyFinding(t, hubCAFindings(t, dir, cfg, staged.Add(time.Hour)), "hubca.rotation")
	if f.Severity != SeverityFail || !strings.Contains(f.Message, "has not reissued") {
		t.Fatalf("activated, leaf not reissued: %+v", f)
	}
	if _, err := hubca.ReissueLeaves(env.Store, env.Sealer, env.Options); err != nil {
		t.Fatal(err)
	}
	f = onlyFinding(t, hubCAFindings(t, dir, cfg, staged.Add(time.Hour)), "hubca.rotation")
	if f.Severity != SeverityPass || !strings.Contains(f.Remediation, "--retire-previous") {
		t.Fatalf("activated, leaf reissued: %+v", f)
	}
	f = onlyFinding(t, hubCAFindings(t, dir, cfg, staged.Add(4*time.Hour)), "hubca.rotation")
	if f.Severity != SeverityWarn || !strings.Contains(f.Message, "still trusted") {
		t.Fatalf("the previous CA kept past the longest session: %+v", f)
	}
}

func TestHubCAMembersThatPredateRotationAreNamed(t *testing.T) {
	now := time.Now().UTC()
	dir, env, db := rotationRig(t, now)
	for id, meta := range map[string]string{"hub_new": `{"` + hubca.EndpointRotation + `":"1"}`, "hub_old": "{}"} {
		if err := db.JoinHubMember(statedb.HubMemberRow{InstanceID: id, Hostname: "host", PID: 1, Version: "v0.0.6",
			Meta: meta, HeartbeatAt: now}); err != nil {
			t.Fatal(err)
		}
	}
	f := onlyFinding(t, hubCAFindings(t, dir, autoTLSConfig(), now), "hubca.members")
	if f.Severity != SeverityWarn || !strings.Contains(f.Message, "hub_old") || strings.Contains(f.Message, "hub_new") {
		t.Fatalf("steady, beside a member that predates rotation: %+v", f)
	}
	if _, err := hubca.Stage(env, hubca.StageRequest{}); err != nil {
		t.Fatal(err)
	}
	f = onlyFinding(t, hubCAFindings(t, dir, autoTLSConfig(), now), "hubca.members")
	if f.Severity != SeverityFail || !strings.Contains(f.Remediation, "Upgrade or stop") {
		t.Fatalf("staged, beside a member that predates rotation: %+v", f)
	}
}

func TestHubCANamesTheActiveCADoesNotPermitFail(t *testing.T) {
	now := time.Now().UTC()
	dir, env, _ := rotationRig(t, now)
	cfg := autoTLSConfig()
	f := onlyFinding(t, hubCAFindings(t, dir, cfg, now), "hubca.names")
	if f.Severity != SeverityPass || !strings.Contains(f.Message, "no name constraints") {
		t.Fatalf("an unconstrained CA: %+v", f)
	}
	if _, err := hubca.Stage(env, hubca.StageRequest{}); err != nil {
		t.Fatal(err)
	}
	if _, err := hubca.Activate(env, hubca.ActivateRequest{}); err != nil {
		t.Fatal(err)
	}
	f = onlyFinding(t, hubCAFindings(t, dir, cfg, now), "hubca.names")
	if f.Severity != SeverityPass {
		t.Fatalf("a CA permitting the configured name: %+v", f)
	}
	// The advertise URL moves to a host the CA was never told about.
	cfg.Executors.GitProxy.AdvertiseURL = "https://moved.example.org:8443"
	f = onlyFinding(t, hubCAFindings(t, dir, cfg, now), "hubca.names")
	if f.Severity != SeverityFail || !strings.Contains(f.Message, "moved.example.org") ||
		!strings.Contains(f.Remediation, "--stage --name moved.example.org") {
		t.Fatalf("a moved advertise URL: %+v", f)
	}
}

func TestHubCAExpiryNamesTheRotation(t *testing.T) {
	t.Setenv(secretbroker.EnvPassphraseKey, monitorTLSPassphrase)
	dir := t.TempDir()
	mustInitStateDB(t, dir)
	issueLeaf(t, dir, time.Now(), "hub.example.com")
	for _, tc := range []struct {
		left time.Duration
		sev  Severity
	}{{200 * 24 * time.Hour, SeverityWarn}, {10 * 24 * time.Hour, SeverityFail}} {
		db, err := statedb.Open(state.DBPath(dir))
		if err != nil {
			t.Fatal(err)
		}
		row, err := db.GetHubTLS(statedb.HubCAActive)
		_ = db.Close()
		if err != nil {
			t.Fatal(err)
		}
		at := row.NotAfter.Add(-tc.left)
		var got []Finding
		autoMonitorTLS(dir, hubca.GitProxy, "gitproxy.tls", "Git proxy TLS", proxyEndpoint{base: "https://hub.example.com:8443"},
			"0.0.0.0:8443", "nothing", at, func(f Finding) {
				if f.Check == "hubca.expiry" {
					got = append(got, f)
				}
			})
		if len(got) != 1 || got[0].Severity != tc.sev || !strings.Contains(got[0].Remediation, "cloop hub ca rotate --stage") {
			t.Fatalf("with %s left: %+v", tc.left, got)
		}
	}
}
