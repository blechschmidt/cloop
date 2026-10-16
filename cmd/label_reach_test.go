package cmd

import (
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/internal/statedbtest"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// TestCLILabelSubjectsUseTheHubsRecord (Task 20432): granting to a label
// selector says which executors it reaches now, and `cloop egress test --to
// executor:<id>` tests as that executor with the labels the hub records for
// it, while --to label:… says it is testing a hypothetical one.
func TestCLILabelSubjectsUseTheHubsRecord(t *testing.T) {
	dir := t.TempDir()
	statedbtest.SeedDir(t, dir)
	t.Chdir(dir)
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	if err := db.PutAgentCredential(statedb.AgentCredentialRow{AgentID: "edge-eu", Name: "edge-eu",
		SecretHash: "sha256-edge-eu", Labels: map[string]string{"region": "eu"}}); err != nil {
		t.Fatal(err)
	}
	if err := db.UpsertExecutor(statedb.ExecutorRow{ID: "edge-eu", Name: "edge-eu",
		Kind: executor.KindRemoteAgent}); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()

	reach := func(spec string) string {
		t.Helper()
		sub, err := secretbroker.ParseSubject(spec)
		if err != nil {
			t.Fatal(err)
		}
		out, err := captureStdout(t, func() error { printLabelReach(sub, "reaches: "); return nil })
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	if out := reach("label:region=eu"); !strings.Contains(out, "edge-eu") {
		t.Errorf("label:region=eu reach = %q, want edge-eu", out)
	}
	if out := reach("label:region=mars"); !strings.Contains(out, "no executor yet") {
		t.Errorf("label:region=mars reach = %q, want none", out)
	}
	if out := reach("project:" + dir); out != "" {
		t.Errorf("a project subject printed a reach: %q", out)
	}

	prev := egressTestToFlag
	t.Cleanup(func() { egressTestToFlag = prev })
	egressTestToFlag = "executor:edge-eu"
	r, hypothetical, err := egressTestRequester(dir)
	if err != nil || hypothetical || r.ExecutorID != "edge-eu" || r.Labels["region"] != "eu" {
		t.Errorf("--to executor:edge-eu = %+v (hypothetical %v), %v; want the recorded labels", r, hypothetical, err)
	}
	egressTestToFlag = "label:site=lab"
	r, hypothetical, err = egressTestRequester(dir)
	if err != nil || !hypothetical || r.ExecutorID != "cli" || r.Labels["site"] != "lab" {
		t.Errorf("--to label:site=lab = %+v (hypothetical %v), %v", r, hypothetical, err)
	}
}
