package cmd

// `cloop hub ca rotate` against a control plane whose CA a monitor minted
// (Task 20438): the steps in order, the refusals that name what they wait
// for, the confirmation the destructive ones need, and the trail and the
// cluster bus each step leaves.

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/hubca"
	"github.com/blechschmidt/cloop/pkg/rootkey"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/secretstore"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// runHubCA runs `cloop hub ca rotate` with args against dir, in-process.
func runHubCA(t *testing.T, dir string, args ...string) (string, error) {
	t.Helper()
	c := &cobra.Command{Use: "rotate", RunE: runHubCARotate, SilenceUsage: true, SilenceErrors: true}
	addHubCARotateFlags(c)
	c.Flags().Int("port", defaultUIPort, "")
	c.SetArgs(append([]string{"--workdir", dir}, args...))
	return captureStdout(t, c.Execute)
}

// caHub is a control plane with a minted CA and a git proxy leaf, as a hub
// running a monitor under tls: auto leaves it; srv stands in for the leader's
// monitor.
func caHub(t *testing.T) (dir string, srv *hubca.Server, db *statedb.DB) {
	t.Helper()
	clearRoots(t)
	t.Cleanup(secretbroker.ForgetOpenedKeys)
	t.Setenv(rootkey.EnvKey, rootChangeOld)
	dir = auditDir(t)
	var err error
	if db, err = statedb.Open(state.DBPath(dir)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ks, err := secretstore.New(db)
	if err != nil {
		t.Fatal(err)
	}
	kr, err := secretbroker.OpenKeyring(ks)
	if err != nil {
		t.Fatal(err)
	}
	store, err := hubca.NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	tr, err := hubca.OpenTrust(store, kr, hubca.Options{Actor: "hub_a"})
	if err != nil {
		t.Fatal(err)
	}
	srv, err = hubca.NewServer(hubca.ServerConfig{Monitor: hubca.GitProxy, Store: store, Sealer: kr, Trust: tr,
		Want: []string{"hub.internal"}, Options: hubca.Options{Actor: "hub_a"}})
	if err != nil {
		t.Fatal(err)
	}
	return dir, srv, db
}

func TestHubCARotateThroughTheCLI(t *testing.T) {
	dir, srv, db := caHub(t)
	ca1 := srv.Trust().State().Active.Serial
	// The hub serving the git proxy, as a live member reporting what it serves.
	if err := db.JoinHubMember(statedb.HubMemberRow{InstanceID: "hub_a", Hostname: "hub-a.example", PID: 4242,
		Version: "test", Meta: `{"` + hubca.EndpointRotation + `":"1"}`, HeartbeatAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	report := func() {
		t.Helper()
		if _, err := srv.Trust().Refresh(); err != nil {
			t.Fatal(err)
		}
		if err := srv.Trust().Report("hub_a", srv); err != nil {
			t.Fatal(err)
		}
	}
	report()

	out, err := runHubCA(t, dir)
	if err != nil || !strings.Contains(out, "Hub CA: steady") {
		t.Fatalf("status: %v\n%s", err, out)
	}

	// A run dispatched before the stage, told to trust CA1 for the git proxy.
	spec, _ := json.Marshal(executor.Spec{Argv: []string{"claude"}, Labels: map[string]string{
		executor.LabelRunID: "run_old", executor.LabelHubCATrust: ca1, executor.LabelHubCAUses: hubca.UseGitProxy}})
	if err := db.OpenExecutorSession(statedb.ExecutorSessionRow{ID: "sess_old", ExecutorID: "ex_1", HandleID: "h1",
		ProjectPath: "/srv/app", TaskID: 7, ClaimToken: "tok", StartedAt: time.Now().Add(-time.Hour),
		SpecJSON: string(spec)}); err != nil {
		t.Fatal(err)
	}

	out, err = runHubCA(t, dir, "--stage", "--name", "hub.example.com")
	if err != nil || !strings.Contains(out, "Staged hub CA") || !strings.Contains(out, "hub.example.com, hub.internal") {
		t.Fatalf("stage: %v\n%s", err, out)
	}
	if _, err := runHubCA(t, dir, "--stage"); err == nil || !strings.Contains(err.Error(), "already staged") {
		t.Fatalf("a second stage: %v", err)
	}
	if _, err := runHubCA(t, dir, "--stage", "--activate"); err == nil {
		t.Fatal("two steps at once were accepted")
	}
	// The member has not re-read its CAs yet: the activation waits for it.
	if _, err := runHubCA(t, dir, "--activate", "--force", "--yes", "--wait", "0"); err == nil ||
		!strings.Contains(err.Error(), "hub_a") {
		t.Fatalf("activate before the member adopted the stage: %v", err)
	}
	report()

	// The run dispatched before the stage holds the activation back, named.
	_, err = runHubCA(t, dir, "--activate")
	if err == nil || !strings.Contains(err.Error(), "run run_old of /srv/app (task 7) on executor ex_1") {
		t.Fatalf("activate with an older run: %v", err)
	}
	out, _ = runHubCA(t, dir, "--status")
	if !strings.Contains(out, "Runs the next step would break (1 of 1 running)") || !strings.Contains(out, "run_old") {
		t.Fatalf("status does not name the run:\n%s", out)
	}
	if _, err := runHubCA(t, dir, "--activate", "--force"); err == nil || !strings.Contains(err.Error(), "--yes") {
		t.Fatalf("a forced activation without --yes: %v", err)
	}
	out, err = runHubCA(t, dir, "--activate", "--force", "--yes", "--wait", "0")
	if err != nil || !strings.Contains(out, "Activated hub CA") || !strings.Contains(out, "run run_old") {
		t.Fatalf("forced activation: %v\n%s", err, out)
	}

	// Retirement waits for the leader to reissue the proxy's certificate.
	report()
	if _, err := runHubCA(t, dir, "--retire-previous", "--yes"); err == nil ||
		!strings.Contains(err.Error(), "still comes from the previous CA") {
		t.Fatalf("retire before the leader reissued: %v", err)
	}
	if issued, err := srv.Renew(); err != nil || !issued {
		t.Fatalf("leader renew: %v %v", issued, err)
	}
	report()
	out, err = runHubCA(t, dir, "--retire-previous", "--yes")
	if err != nil || !strings.Contains(out, "Retired hub CA "+ca1) {
		t.Fatalf("retire: %v\n%s", err, out)
	}

	// The emergency: everything at once, the old run named for its sessions.
	out, err = runHubCA(t, dir, "--now", "--yes", "--wait", "0")
	if err != nil || !strings.Contains(out, "Replaced hub CA(s)") || !strings.Contains(out, "run run_old") {
		t.Fatalf("now: %v\n%s", err, out)
	}

	// The trail names every step; the bus announced each.
	rows, _, err := db.ListAuditEvents(statedb.AuditFilter{EntityType: "hub_ca"})
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]int{}
	for _, r := range rows {
		seen[r.EventType]++
		if strings.Contains(r.Payload, "PRIVATE") {
			t.Errorf("an audit row carries a key: %s", r.Payload)
		}
	}
	for _, a := range []auditaction.Action{auditaction.ActionHubCARotationStaged, auditaction.ActionHubCARotationActivated,
		auditaction.ActionHubCAPreviousRetired, auditaction.ActionHubCAEmergencyRotated, auditaction.ActionHubCALeafIssued} {
		if seen[string(a)] == 0 {
			t.Errorf("no %s row on the trail (%v)", a, seen)
		}
	}
	evs, err := db.HubEventsAfter(0, 100)
	if err != nil {
		t.Fatal(err)
	}
	var steps []string
	for _, e := range evs {
		if e.Topic == hubca.BusTopic {
			steps = append(steps, e.Key)
		}
	}
	if got := strings.Join(steps, ","); got != "stage,activate,retire_previous,now" {
		t.Fatalf("bus announcements %s", got)
	}
	out, _ = runHubCA(t, dir, "--status", "--json")
	var st struct {
		Status  hubca.Status `json:"status"`
		History []struct {
			Emergency bool     `json:"Emergency"`
			CutRuns   []string `json:"CutRuns"`
		} `json:"history"`
	}
	if err := json.Unmarshal([]byte(out), &st); err != nil {
		t.Fatalf("--status --json: %v\n%s", err, out)
	}
	if st.Status.Phase != hubca.PhaseSteady || len(st.History) < 2 || !st.History[0].Emergency ||
		strings.Join(st.History[0].CutRuns, ",") != "run_old" {
		t.Fatalf("status after the emergency: %+v", st)
	}
}
