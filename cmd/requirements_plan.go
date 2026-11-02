package cmd

// `cloop requirements plan` (Task 20463): the tasks that close the gaps in
// the project's requirements — the approved ones that fail, that nothing
// shows to hold, that changed since they held, or that lack a test — planned
// by the model, held to the requirements (suggest.ApplyRequirements) and
// reviewed before any joins the plan.
//
// It is also what the dashboard's "Plan from requirements" dispatches to the
// project's executor: with --json (a framed plan the suggestions panel shows
// for review) and --requirements (the hub's requirement status summary, since
// a device's or a Pod's copy of the project holds no checks).

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/clijson"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/requirements"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
	"github.com/blechschmidt/cloop/pkg/suggest"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

// requirementsPlanTimeout is the model's time on a plan: one description per
// task, up to twenty.
const requirementsPlanTimeout = 5 * time.Minute

var requirementsPlanCmd = &cobra.Command{
	Use:   "plan",
	Short: "Plan the tasks that close the gaps in the requirements",
	Long: `Plan the work the project's requirements are waiting for. Every approved
requirement with an open gap that no open task closes is a target:

  fix        its latest check found it unfulfilled, or could not run its tests
  implement  nothing shows it holds yet — never checked, or no test and no
             verdict — or no task has ever implemented it
  verify     it was found to hold, but has changed since
  test       it holds by the model's or a person's word and lacks only a test:
             its task writes the test and nothing else

The model plans the tasks — must gaps first, then should, then could — and each
task links the requirements it closes, so its agent is given them as its
acceptance contract. What it proposes is held to the requirements: a link to a
draft, a deprecated requirement or one with no open gap is dropped, a task that
repeats an open task's work is left out, and a must gap the model left open gets
a task of its own. Review each task, or accept them all with --yes.

Drafts and deprecated requirements are never planned for. A requirement waiting
for a check — work on it finished since its verdict — or for a person is named,
not planned: run 'cloop requirements check' first.

  cloop requirements plan              # review the plan task by task
  cloop requirements plan --dry-run    # show it, add nothing
  cloop requirements plan --yes        # add every task
  cloop requirements plan --count 5    # at most five tasks`,
	Args: cobra.NoArgs,
	RunE: runRequirementsPlan,
}

func init() {
	requirementsCmd.AddCommand(requirementsPlanCmd)
	f := requirementsPlanCmd.Flags()
	f.Int("count", 0, fmt.Sprintf("Plan at most this many tasks (default: as many as the gaps need, up to %d)", suggest.MaxCount))
	f.Bool("yes", false, "Add every task without asking")
	f.Bool("dry-run", false, "Show the plan and add nothing")
	f.Bool("json", false, "Report the plan as framed JSON and add nothing, for the hub")
	f.String("requirements", "", "The requirement status summary, as JSON (the hub's; default: the project's own)")
	f.String("provider", "", "AI provider (default: the project's)")
	f.String("model", "", "Model")
	f.Duration("timeout", requirementsPlanTimeout, "How long the model may take")
	_ = f.MarkHidden("requirements")
}

// plannerRequirementStatus is the requirement status summary a planner
// command plans from: the hub's, given as JSON in raw, or else the project's
// own, assessed against plan (Task 20463).
func plannerRequirementStatus(workDir string, plan *pm.Plan, raw string, given bool) (requirements.StatusSummary, error) {
	if given {
		if strings.TrimSpace(raw) == "" {
			return requirements.StatusSummary{}, nil
		}
		return requirements.ParseStatusSummary([]byte(raw))
	}
	db, err := statedb.Open(state.DBPath(workDir))
	if err != nil {
		return requirements.StatusSummary{}, err
	}
	defer db.Close()
	facts, omitted, err := db.AsProject().RequirementFacts()
	if err != nil {
		return requirements.StatusSummary{}, err
	}
	sum := requirements.Summarize(facts, pm.TaskViews(plan))
	sum.Omitted = omitted
	return sum, nil
}

// openTasksList lists the plan's open tasks for a planner's prompt, with the
// requirements each implements.
func openTasksList(plan *pm.Plan) string {
	if plan == nil {
		return ""
	}
	var b strings.Builder
	for _, t := range plan.Tasks {
		if t == nil || (t.Status != pm.TaskPending && t.Status != pm.TaskInProgress) {
			continue
		}
		fmt.Fprintf(&b, "- [%s] Task %d: %s", t.Status, t.ID, t.Title)
		if len(t.Requirements) > 0 {
			keys := make([]string, len(t.Requirements))
			for i, id := range t.Requirements {
				keys[i] = requirements.Key(id)
			}
			fmt.Fprintf(&b, " (implements %s)", strings.Join(keys, ", "))
		}
		b.WriteString("\n")
	}
	return b.String()
}

func runRequirementsPlan(cmd *cobra.Command, args []string) error {
	f := cmd.Flags()
	asJSON, _ := f.GetBool("json")
	fail := func(err error) error {
		if asJSON {
			return failFramed(err)
		}
		return err
	}
	count, _ := f.GetInt("count")
	if count < 0 || count > suggest.MaxCount {
		return fail(fmt.Errorf("--count is between 1 and %d", suggest.MaxCount))
	}
	// The hub's summary names the hub's requirements; tasks are added here
	// only from the project's own.
	if f.Changed("requirements") && !asJSON {
		return fail(fmt.Errorf("--requirements is the hub's: give --json with it"))
	}
	workDir, err := os.Getwd()
	if err != nil {
		return fail(err)
	}
	s, err := state.Load(workDir)
	if err != nil {
		return fail(fmt.Errorf("no project found — run 'cloop init' first: %w", err))
	}
	raw, _ := f.GetString("requirements")
	sum, err := plannerRequirementStatus(workDir, s.Plan, raw, f.Changed("requirements"))
	if err != nil {
		return fail(fmt.Errorf("the requirement status: %w", err))
	}

	targets := sum.Targets()
	if len(targets) == 0 {
		result := &suggest.Result{Request: suggest.RequirementsRequest, Suggestions: []*suggest.Suggestion{},
			Summary: requirements.NothingToPlan(sum)}
		if asJSON {
			return clijson.Emit(os.Stdout, result)
		}
		color.New(color.FgGreen).Println(result.Summary)
		return nil
	}

	pflag, _ := f.GetString("provider")
	mflag, _ := f.GetString("model")
	prov, model, err := helperProvider(workDir, s, pflag, mflag)
	if err != nil {
		return fail(fmt.Errorf("provider: %w", err))
	}
	timeout, _ := f.GetDuration("timeout")
	projCtx := pm.BuildProjectContext(workDir)
	prompt := requirements.PlanPrompt(s.Goal, s.Instructions, projCtx.FileTree, openTasksList(s.Plan), sum, count)
	if !asJSON {
		color.New(color.FgCyan, color.Bold).Printf("\nPlanning %d open requirement gap(s) with %s...\n\n", len(targets), prov.Name())
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	result, err := suggest.GeneratePlan(ctx, prov, prompt, provider.Options{Model: model, WorkDir: workDir, Timeout: timeout},
		suggest.RequirementsRequest, count)
	if err != nil {
		return fail(fmt.Errorf("the model: %w", err))
	}
	suggest.ApplyRequirements(result, sum, suggest.ForGaps, count)
	if asJSON {
		return clijson.Emit(os.Stdout, result)
	}
	return reviewRequirementsPlan(cmd, s, sum, result)
}

// reviewRequirementsPlan shows the plan and adds the tasks a person accepts.
func reviewRequirementsPlan(cmd *cobra.Command, s *state.ProjectState, sum requirements.StatusSummary, result *suggest.Result) error {
	yes, _ := cmd.Flags().GetBool("yes")
	dryRun, _ := cmd.Flags().GetBool("dry-run")
	head := color.New(color.FgCyan, color.Bold)
	dim := color.New(color.Faint)
	bold := color.New(color.Bold)
	label := color.New(color.FgMagenta)
	warn := color.New(color.FgYellow)
	good := color.New(color.FgGreen, color.Bold)

	if len(result.Suggestions) == 0 {
		warn.Println("  The model proposed no task.")
		return nil
	}
	sep := strings.Repeat("─", 70)
	fmt.Println(sep)
	head.Printf("  A Plan of %d Tasks for the Requirements\n", len(result.Suggestions))
	if result.Summary != "" {
		dim.Printf("  %s\n", result.Summary)
	}
	fmt.Println(sep)
	fmt.Println()
	for _, n := range result.Notes {
		dim.Printf("  Note: %s\n", n)
	}
	if len(result.Notes) > 0 {
		fmt.Println()
	}

	reader := bufio.NewReader(os.Stdin)
	var accepted []*suggest.Suggestion
	for i, sg := range result.Suggestions {
		printSuggestion(i+1, sg, bold, dim, label)
		printLinks(sg, sum, dim)
		switch {
		case dryRun:
			continue
		case yes:
			accepted = append(accepted, sg)
			continue
		}
		fmt.Print("  Add this task? [y/n/q] ")
		line, err := reader.ReadString('\n')
		if err != nil {
			break
		}
		switch strings.ToLower(strings.TrimSpace(line)) {
		case "y", "yes":
			accepted = append(accepted, sg)
		case "q", "quit":
			goto done
		}
		fmt.Println()
	}
done:
	if dryRun {
		if open := suggest.Uncovered(result, sum); len(open) > 0 {
			warn.Printf("  Approved must requirements the plan leaves open: %s\n\n", standingKeys(open))
		}
		dim.Println("  (dry-run) Nothing was added.")
		return nil
	}
	if open := suggest.Uncovered(&suggest.Result{Suggestions: accepted}, sum); len(open) > 0 {
		warn.Printf("  Approved must requirements no accepted task closes: %s\n\n", standingKeys(open))
	}
	if len(accepted) == 0 {
		dim.Println("  No task accepted — nothing added to the plan.")
		return nil
	}
	if s.Plan == nil {
		s.Plan = pm.NewPlan(s.Goal)
	}
	s.PMMode = true
	added := suggest.NewLedger(result).Apply(s.Plan, accepted)
	if err := s.Save(); err != nil {
		return fmt.Errorf("saving state: %w", err)
	}
	good.Printf("  Added %d task(s), each linked to the requirements it closes.\n\n", len(added))
	for _, t := range added {
		dim.Printf("  + #%d [P%d] %s%s\n", t.ID, t.Priority, t.Title, taskLinkKeys(t))
	}
	fmt.Println()
	return nil
}

// printLinks says which requirements a proposed task closes, and how.
func printLinks(sg *suggest.Suggestion, sum requirements.StatusSummary, dim *color.Color) {
	if len(sg.Requirements) == 0 {
		dim.Printf("     Closes no requirement's gap.\n\n")
		return
	}
	parts := make([]string, 0, len(sg.Requirements))
	for _, id := range sg.Requirements {
		p := requirements.Key(id)
		if st, ok := sum.Lookup(id); ok && st.Priority != "" {
			p += " [" + st.Priority + "]"
		}
		parts = append(parts, p)
	}
	kind := ""
	if sg.Kind == requirements.ActionTest {
		kind = " — only adds a test"
	}
	dim.Printf("     Closes: %s%s\n\n", strings.Join(parts, ", "), kind)
}

func standingKeys(st []requirements.Standing) string {
	keys := make([]string, len(st))
	for i, s := range st {
		keys[i] = s.Key() + " (" + s.Title + ")"
	}
	return strings.Join(keys, ", ")
}

// taskLinkKeys names the requirements t implements: " (R-3, R-5)", or nothing.
func taskLinkKeys(t *pm.Task) string {
	if len(t.Requirements) == 0 {
		return ""
	}
	keys := make([]string, len(t.Requirements))
	for i, id := range t.Requirements {
		keys[i] = requirements.Key(id)
	}
	return " (" + strings.Join(keys, ", ") + ")"
}
