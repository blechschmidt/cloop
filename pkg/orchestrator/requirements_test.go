package orchestrator

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/requirements"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// TestTheAgentIsHeldToTheRequirementsItsTaskImplements: a task that
// implements requirements (Task 20460) is run with each one's title, details
// and test commands in its prompt as the acceptance contract, read from the
// project's database as they are when the task starts — on the sequential and
// the parallel path. A task that implements none is told nothing about them.
func TestTheAgentIsHeldToTheRequirementsItsTaskImplements(t *testing.T) {
	for _, parallel := range []bool{false, true} {
		t.Run(fmt.Sprintf("parallel=%v", parallel), func(t *testing.T) {
			dir := tempDir(t)
			planOf(t, dir, parallel, 1, 2)

			db, err := statedb.Open(state.DBPath(dir))
			if err != nil {
				t.Fatal(err)
			}
			kept, err := db.AddRequirement(requirements.Requirement{
				Title: "Config errors exit non-zero", Priority: requirements.PriorityMust,
				Description: "A malformed config makes every command exit 1.",
				Tests:       []requirements.Test{{Command: "go test ./pkg/config -run TestInvalid"}},
			}, "alice")
			if err != nil {
				t.Fatal(err)
			}
			old, err := db.AddRequirement(requirements.Requirement{Title: "Old rule", Status: requirements.StatusDeprecated}, "alice")
			db.Close()
			if err != nil {
				t.Fatal(err)
			}
			s, err := state.Load(dir)
			if err != nil {
				t.Fatal(err)
			}
			s.Plan.TaskByID(1).Requirements = []int{kept.ID, old.ID, 9}
			if err := s.Save(); err != nil {
				t.Fatal(err)
			}

			agent := newToolAgent(nil)
			o := newOrchestrator(t, dir, Config{WorkDir: dir, PMMode: true, NoHeal: true}, agent)
			if err := o.runPM(context.Background()); err != nil {
				t.Fatalf("runPM: %v", err)
			}

			p := agent.prompts[1]
			for _, want := range []string{
				"## ACCEPTANCE CONTRACT",
				fmt.Sprintf("### R-%d: Config errors exit non-zero [must]", kept.ID),
				"A malformed config makes every command exit 1.",
				"`go test ./pkg/config -run TestInvalid`",
				"The task is done only when every test listed here passes",
				"must not be weakened",
				fmt.Sprintf("R-%d (Old rule) is linked to this task but deprecated", old.ID),
				"R-9 is linked to this task, but its text is not available to this run.",
			} {
				if !strings.Contains(p, want) {
					t.Errorf("task 1's prompt lacks %q:\n%s", want, p)
				}
			}
			if i, j := strings.Index(p, "## ACCEPTANCE CONTRACT"), strings.LastIndex(p, "## INSTRUCTIONS"); i < 0 || j < i {
				t.Errorf("the contract must come before the closing instructions")
			}
			if strings.Contains(agent.prompts[2], "ACCEPTANCE CONTRACT") {
				t.Errorf("task 2 implements nothing, and its prompt has a contract:\n%s", agent.prompts[2])
			}
		})
	}
}
