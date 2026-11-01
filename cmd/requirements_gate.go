package cmd

// `cloop requirements gate` (Task 20461): show or set requirement-gated
// completion without starting a run. `cloop run --requirements-gate` sets it
// too, and so does a config.yaml that declares requirements.gate, at the start
// of every run. See pkg/orchestrator/reqgate.go for what the gate does.

import (
	"fmt"
	"os"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/blechschmidt/cloop/pkg/clijson"
	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
)

var requirementsGateCmd = &cobra.Command{
	Use:   "gate [off|linked|linked+must]",
	Short: "Show or set whether a task is done only once its requirements pass",
	Long: `With the requirements gate on, a task whose agent reports TASK_DONE is not
taken at its word: cloop runs the tests of the requirements the task implements
(cloop task edit --requirement) where the project runs — its executor, in the
directory the agent worked in — and the task is done only when they pass.

  linked        check the requirements the task implements
  linked+must   ... and every approved must requirement that has tests:
                a task may not leave one failing
  off           take the agent's word (the default)

A task whose requirements do not pass goes back to pending with the failing
commands and the end of their output in its next prompt — at most
--max-verify-retries times in a row (default 2) — and then fails with reason
requirements_unmet. A linked requirement without tests never blocks: it is
reported unverified, unless --assess asks the model about it.

Every check is recorded as the requirements' checks, tied to the task and the
commit, and shown on the Requirements tab; a requirement that passed before and
fails now is marked a regression on the task and in the event history.

The setting belongs to the project, travels with it to isolating executors,
and reaches a run that is already going at its next task. A config.yaml that
declares requirements.gate is applied at the start of every run, and this
command rewrites that declaration when it changes the setting.

  cloop requirements gate                 # show the setting
  cloop requirements gate linked
  cloop requirements gate linked+must --assess
  cloop requirements gate off`,
	Args: cobra.MaximumNArgs(1),
	RunE: runRequirementsGate,
}

func init() {
	f := requirementsGateCmd.Flags()
	f.Bool("assess", false, "Ask the model about the requirements in scope that have no tests")
	f.Bool("no-assess", false, "Stop asking the model about untested requirements")
	f.Bool("json", false, "Print the setting as JSON")
	requirementsCmd.AddCommand(requirementsGateCmd)
}

func runRequirementsGate(cmd *cobra.Command, args []string) error {
	workdir, err := os.Getwd()
	if err != nil {
		return err
	}
	s, err := state.LoadLite(workdir)
	if err != nil {
		return err
	}
	f := cmd.Flags()
	assess, _ := f.GetBool("assess")
	noAssess, _ := f.GetBool("no-assess")
	if assess && noAssess {
		return fmt.Errorf("give --assess or --no-assess, not both")
	}
	g := s.RequirementsGate.Clone()
	changing := len(args) == 1 || assess || noAssess
	if changing {
		next := g.Clone()
		if next == nil {
			next = &pm.RequirementsGate{Mode: pm.RequirementsGateOff}
		}
		if len(args) == 1 {
			mode, err := pm.ParseRequirementsGateMode(args[0])
			if err != nil {
				return err
			}
			next.Mode = mode
		}
		if assess {
			next.Assess = true
		}
		if noAssess {
			next.Assess = false
		}
		if err := state.SetRequirementsGate(workdir, next); err != nil {
			return err
		}
		if err := syncRequirementsGateDeclaration(workdir, next); err != nil {
			color.New(color.FgYellow).Fprintf(os.Stderr, "⚠ the project's setting changed, but config.yaml's requirements section could not be updated: %v\n", err)
		}
		g = next
	}
	if g == nil {
		g = &pm.RequirementsGate{Mode: pm.RequirementsGateOff}
	}
	if asJSON, _ := f.GetBool("json"); asJSON {
		return clijson.Emit(cmd.OutOrStdout(), g)
	}
	if changing {
		color.New(color.FgGreen).Println("Requirements gate updated.")
	}
	printRequirementsGate(g)
	return nil
}

// printRequirementsGate renders the setting for people.
func printRequirementsGate(g *pm.RequirementsGate) {
	color.New(color.Bold).Print("Requirements gate: ")
	if !g.Active() {
		fmt.Println("off")
		color.New(color.Faint).Println("  Turn it on with: cloop requirements gate [linked|linked+must]")
		return
	}
	color.New(color.FgGreen).Println(g.EffectiveMode())
	fmt.Printf("  A task is done only once %s.\n", g.Describe())
	if !g.Assess {
		color.New(color.Faint).Println("  Requirements without tests are reported unverified (--assess asks the model).")
	}
}

// syncRequirementsGateDeclaration rewrites config.yaml's requirements section
// to g when the file declares one, so the declaration and the project's
// setting never disagree and the next run does not put the old one back. A
// file that declares nothing is left alone.
func syncRequirementsGateDeclaration(workdir string, g *pm.RequirementsGate) error {
	cfg, err := config.Load(workdir)
	if err != nil {
		return err
	}
	if !cfg.Requirements.Declares() {
		return nil
	}
	cfg.Requirements.Gate = g.EffectiveMode()
	if cfg.Requirements.Assess != nil || g.Assess {
		assess := g.Assess
		cfg.Requirements.Assess = &assess
	}
	return config.Save(workdir, cfg)
}

// applyDeclaredRequirementsGate writes the gate config.yaml declares into the
// project before a run starts (Task 20461), and returns the setting the run
// holds its tasks to. A file that declares nothing leaves the project's own
// setting as it is.
func applyDeclaredRequirementsGate(workdir string, cfg *config.Config, current *pm.RequirementsGate) (*pm.RequirementsGate, error) {
	if cfg == nil || !cfg.Requirements.Declares() {
		return current, nil
	}
	mode, err := pm.ParseRequirementsGateMode(cfg.Requirements.Gate)
	if err != nil {
		return current, fmt.Errorf("config.yaml requirements.gate: %w", err)
	}
	next := current.Clone()
	if next == nil {
		next = &pm.RequirementsGate{}
	}
	next.Mode = mode
	if cfg.Requirements.Assess != nil {
		next.Assess = *cfg.Requirements.Assess
	}
	if current != nil && *current == *next {
		return current, nil
	}
	if err := state.SetRequirementsGate(workdir, next); err != nil {
		return current, err
	}
	return next, nil
}
