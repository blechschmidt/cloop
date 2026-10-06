package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fatih/color"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executorstore"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// TestPrintAgentInventoryShowsTheSequence: `cloop executor list --inventory`
// names each device's place on main (Task 20380) — the order its installer
// holds every upgrade to — and says nothing about one whose build carries none.
func TestPrintAgentInventoryShowsTheSequence(t *testing.T) {
	var buf bytes.Buffer
	prevOut, prevNoColor := color.Output, color.NoColor
	color.Output, color.NoColor = &buf, true
	t.Cleanup(func() { color.Output, color.NoColor = prevOut, prevNoColor })

	inv := statedb.ExecutorInventory{AgentVersion: "dev+g5facde4", OS: "linux", Arch: "amd64"}
	printAgentInventory(color.New(color.Faint), inv, 925)
	if !strings.Contains(buf.String(), "sequence:  925 on main") {
		t.Errorf("no sequence line:\n%s", buf.String())
	}
	buf.Reset()
	printAgentInventory(color.New(color.Faint), inv, 0)
	if strings.Contains(buf.String(), "sequence") {
		t.Errorf("a build without a sequence got a line:\n%s", buf.String())
	}
}

// TestExecutorListInventoryNamesSuspectedNodeKillers: `cloop executor list
// --inventory`, run in the hub's directory, finds a task quarantined in a
// project the hub failed a session over for (Task 20391) — the hub's records
// name the project, the project's own database holds the mark — and says which
// nodes it went down under and how to release it.
func TestExecutorListInventoryNamesSuspectedNodeKillers(t *testing.T) {
	hub := t.TempDir()
	project := t.TempDir()

	st, err := state.Init(project, "goal", 0)
	if err != nil {
		t.Fatal(err)
	}
	st.PMMode = true
	st.Plan = &pm.Plan{Goal: "goal", Tasks: []*pm.Task{
		{ID: 7, Title: "allocates until the kernel gives up", Status: pm.TaskFailed},
		{ID: 8, Title: "harmless", Status: pm.TaskPending},
	}}
	if err := st.Save(); err != nil {
		t.Fatal(err)
	}
	pdb, err := statedb.Open(state.DBPath(project))
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	if err := pdb.PutTaskQuarantine(7, pm.TaskQuarantine{Kind: pm.QuarantineNodeKiller, MarkedAt: at, Nodes: []pm.NodeLoss{
		{ExecutorID: "sgx", LostAt: at, SessionID: "s1"},
		{ExecutorID: "edge-2", LostAt: at.Add(3 * time.Minute), SessionID: "s2"},
	}}); err != nil {
		t.Fatal(err)
	}
	pdb.Close()

	// The hub's record of a session it failed over for that project.
	if err := os.MkdirAll(filepath.Join(hub, ".cloop"), 0o755); err != nil {
		t.Fatal(err)
	}
	hdb, err := statedb.Open(state.DBPath(hub))
	if err != nil {
		t.Fatal(err)
	}
	sched, err := executorstore.NewScheduler(hdb)
	if err != nil {
		t.Fatal(err)
	}
	if err := sched.OpenSession(executor.Session{
		ID: "s1", ExecutorID: "sgx", ClaimToken: "tok", Attempt: 1, ProjectPath: "work/project",
		Spec: executor.Spec{Argv: []string{"cloop", "run"}, Labels: map[string]string{"project": project}},
	}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := sched.ClaimRequeue("s1", "tok", 2, at); err != nil {
		t.Fatal(err)
	}
	hdb.Close()

	t.Chdir(hub)
	var buf bytes.Buffer
	prevOut, prevNoColor := color.Output, color.NoColor
	color.Output, color.NoColor = &buf, true
	t.Cleanup(func() { color.Output, color.NoColor = prevOut, prevNoColor })

	if err := printFleetInventory(color.New(color.Bold), color.New(color.Faint)); err != nil {
		t.Fatalf("printFleetInventory: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		"Suspected node killers", project, "task #7", "allocates until the kernel gives up",
		"sgx (unreachable 2026-10-06T12:00:00Z)", "edge-2 (unreachable 2026-10-06T12:03:00Z)",
		"cloop task reset 7",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the inventory does not mention %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "task #8") {
		t.Errorf("an unmarked task is listed:\n%s", out)
	}
}
