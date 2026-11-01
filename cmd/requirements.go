package cmd

// `cloop requirements` (Task 20458): what the project must keep doing, and
// whether it still does. See pkg/requirements.
//
// `check` is also what the hub dispatches to a project's executor when the
// dashboard's Requirements tab checks them: with --spec (the requirements as the
// hub has them), --json (a framed report) and --no-record (the hub records what
// it reads back). Run by hand it reads the project's own requirements, records
// what it finds, and exits 1 when one is not fulfilled — so it can gate CI.
// With --file it reads them from the spec file instead (Task 20459), and needs
// neither a hub nor a project database: requirements_spec.go has the spec
// file's other commands, export, import and validate.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/artifact"
	"github.com/blechschmidt/cloop/pkg/clijson"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/requirements"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

// errRequirementsFailing is check's exit for a requirement not fulfilled: the
// table already said which, so the error itself says nothing more.
var errRequirementsFailing = errors.New("not every requirement is fulfilled")

var requirementsCmd = &cobra.Command{
	Use:     "requirements",
	Aliases: []string{"requirement", "req", "reqs"},
	Short:   "What the project must keep doing, and whether it still does",
	Long: `Requirements are statements about the project that must stay true —
"the CLI exits non-zero on a malformed config", "every API route declares a
permission". A requirement may have tests: shell commands run in the project's
root that pass when they exit 0. One without tests can be assessed by the
model, or given a verdict by hand.

  cloop requirements add "Config errors exit non-zero" \
      --test "go test ./pkg/config -run TestInvalid"
  cloop requirements add "Every route declares a permission" -d "…" --priority must
  cloop requirements list
  cloop requirements check            # run every test; exit 1 if one fails
  cloop requirements check 3 --ai     # ask the model about R-3 if it has no tests
  cloop requirements verdict 4 fulfilled --note "checked by hand on staging"
  cloop requirements history 3

A requirement is a draft, approved or deprecated (--status); a check checks the
approved ones unless it is named or told otherwise.

They can also be kept as code, in .cloop/requirements.yaml beside the code they
govern, reviewed in pull requests:

  cloop requirements export           # write the spec file from the hub's requirements
  cloop requirements import           # merge the spec file's changes into the hub
  cloop requirements validate         # check the spec file, line by line
  cloop requirements check --file .cloop/requirements.yaml   # in CI, with no hub

The dashboard's Requirements tab runs the same check on the project's executor,
and shows when the spec file in the project's checkout has changed.`,
	RunE: func(cmd *cobra.Command, args []string) error { return runRequirementsList(cmd) },
}

var requirementsListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List the requirements and their latest verdicts",
	Args:    cobra.NoArgs,
	RunE:    func(cmd *cobra.Command, args []string) error { return runRequirementsList(cmd) },
}

var requirementsShowCmd = &cobra.Command{
	Use:   "show <id>",
	Short: "Show a requirement, its tests and its latest check",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		id, err := parseRequirementID(args[0])
		if err != nil {
			return err
		}
		p, err := openRequirementsProject()
		if err != nil {
			return err
		}
		defer p.db.Close()
		r, err := p.db.Requirement(id)
		if err != nil {
			return err
		}
		checks, err := p.db.RequirementChecks(id, 1)
		if err != nil {
			return err
		}
		if asJSON, _ := cmd.Flags().GetBool("json"); asJSON {
			out := map[string]any{"requirement": r}
			if len(checks) > 0 {
				out["last_check"] = checks[0]
			}
			return printJSON(out)
		}
		printRequirement(r)
		if len(checks) == 0 {
			color.New(color.Faint).Println("\nNever checked.")
			return nil
		}
		fmt.Println()
		printCheck(r, checks[0], true)
		return nil
	},
}

var requirementsAddCmd = &cobra.Command{
	Use:   "add <title>",
	Short: "Add a requirement",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		r := requirements.Requirement{Title: args[0]}
		r.Description, _ = cmd.Flags().GetString("description")
		r.Priority, _ = cmd.Flags().GetString("priority")
		r.Status, _ = cmd.Flags().GetString("status")
		r.Tags, _ = cmd.Flags().GetStringSlice("tag")
		tests, err := testsFromFlags(cmd)
		if err != nil {
			return err
		}
		r.Tests = tests
		p, err := openRequirementsProject()
		if err != nil {
			return err
		}
		defer p.db.Close()
		added, err := p.db.AddRequirement(r, operatorActor())
		if err != nil {
			return err
		}
		color.New(color.FgGreen, color.Bold).Printf("Added %s: %s\n", requirements.Key(added.ID), added.Title)
		if added.Status != requirements.StatusApproved {
			color.New(color.Faint).Printf("It is %s: a check passes it by unless it is named.\n", added.Status)
		}
		if !added.Tested() {
			color.New(color.Faint).Println("It has no tests: a check skips it unless the model is asked (--ai).")
		}
		return nil
	},
}

var requirementsEditCmd = &cobra.Command{
	Use:   "edit <id>",
	Short: "Change a requirement",
	Long: `Change a requirement's title, description, priority, tags, tests or status.
A flag not given leaves its field as it is; --test replaces the tests with the
ones given, and --clear-tests removes them all. Changing what a requirement says
or how it is tested makes its earlier verdicts stale; approving or deprecating
it does not.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		id, err := parseRequirementID(args[0])
		if err != nil {
			return err
		}
		p, err := openRequirementsProject()
		if err != nil {
			return err
		}
		defer p.db.Close()
		r, err := p.db.Requirement(id)
		if err != nil {
			return err
		}
		f := cmd.Flags()
		if f.Changed("title") {
			r.Title, _ = f.GetString("title")
		}
		if f.Changed("description") {
			r.Description, _ = f.GetString("description")
		}
		if f.Changed("priority") {
			r.Priority, _ = f.GetString("priority")
		}
		r.Status = ""
		if f.Changed("status") {
			r.Status, _ = f.GetString("status")
			if strings.TrimSpace(r.Status) == "" {
				return fmt.Errorf("--status is one of %s", strings.Join(requirements.Statuses, ", "))
			}
		}
		if f.Changed("tag") {
			r.Tags, _ = f.GetStringSlice("tag")
		}
		if clear, _ := f.GetBool("clear-tests"); clear {
			r.Tests = nil
		}
		if f.Changed("test") {
			tests, err := testsFromFlags(cmd)
			if err != nil {
				return err
			}
			r.Tests = tests
		}
		updated, err := p.db.UpdateRequirement(r, operatorActor())
		if err != nil {
			return err
		}
		color.New(color.FgGreen, color.Bold).Printf("Updated %s: %s\n", requirements.Key(updated.ID), updated.Title)
		return nil
	},
}

var requirementsRemoveCmd = &cobra.Command{
	Use:     "remove <id>",
	Aliases: []string{"rm"},
	Short:   "Delete a requirement and the history of its checks",
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		id, err := parseRequirementID(args[0])
		if err != nil {
			return err
		}
		p, err := openRequirementsProject()
		if err != nil {
			return err
		}
		defer p.db.Close()
		gone, err := p.db.DeleteRequirement(id, operatorActor())
		if err != nil {
			return err
		}
		fmt.Printf("Removed %s: %s\n", requirements.Key(gone.ID), gone.Title)
		return nil
	},
}

var requirementsVerdictCmd = &cobra.Command{
	Use:   "verdict <id> fulfilled|unfulfilled",
	Short: "Record a requirement's verdict by hand",
	Long: `Record what a person found: for a requirement nothing can test, or a test
that does not cover all of it. The verdict is about the requirement as it reads
now, and goes stale when it is changed.`,
	Args: cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		id, err := parseRequirementID(args[0])
		if err != nil {
			return err
		}
		verdict := strings.ToLower(strings.TrimSpace(args[1]))
		note, _ := cmd.Flags().GetString("note")
		p, err := openRequirementsProject()
		if err != nil {
			return err
		}
		defer p.db.Close()
		c, err := p.db.RecordRequirementVerdict(id, verdict, note, operatorActor())
		if err != nil {
			return err
		}
		fmt.Printf("Recorded %s as %s.\n", requirements.Key(c.RequirementID), c.Verdict)
		return nil
	},
}

var requirementsHistoryCmd = &cobra.Command{
	Use:   "history <id>",
	Short: "Show a requirement's recent checks, newest first",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		id, err := parseRequirementID(args[0])
		if err != nil {
			return err
		}
		limit, _ := cmd.Flags().GetInt("limit")
		p, err := openRequirementsProject()
		if err != nil {
			return err
		}
		defer p.db.Close()
		r, err := p.db.Requirement(id)
		if err != nil {
			return err
		}
		checks, err := p.db.RequirementChecks(id, limit)
		if err != nil {
			return err
		}
		if asJSON, _ := cmd.Flags().GetBool("json"); asJSON {
			return printJSON(map[string]any{"requirement": r, "checks": checks})
		}
		if len(checks) == 0 {
			fmt.Printf("%s has never been checked.\n", requirements.Key(id))
			return nil
		}
		for _, c := range checks {
			printCheck(r, c, false)
		}
		return nil
	},
}

var requirementsCheckCmd = &cobra.Command{
	Use:   "check [id...]",
	Short: "Check whether the requirements are still fulfilled",
	Long: `Run each requirement's tests in the project's root, in order, and report
what they found. A requirement with no tests is skipped — its last verdict,
a person's or the model's, stands — or, with --ai, assessed by the model
reading the code. With no ids, every approved requirement is checked (--status
picks others, --all every one); ids name requirements whatever their status.

With --file the requirements are read from a spec file rather than the
project's database, and nothing is recorded: a plain CI job with no hub and no
.cloop/state.db can run

  cloop requirements check --file .cloop/requirements.yaml

and a spec file that does not validate fails it, naming each problem's line.

Exits 1 when a requirement is unfulfilled or its check did not work (a test
timed out or could not start), so a CI job can run it as a gate. A test's
processes are all stopped when it ends, and what it printed is kept only in
part — its last 16 KiB — with credentials scrubbed.`,
	RunE: runRequirementsCheck,
}

func init() {
	rootCmd.AddCommand(requirementsCmd)
	requirementsCmd.AddCommand(requirementsListCmd, requirementsShowCmd, requirementsAddCmd, requirementsEditCmd,
		requirementsRemoveCmd, requirementsVerdictCmd, requirementsHistoryCmd, requirementsCheckCmd,
		requirementsExportCmd, requirementsImportCmd, requirementsValidateCmd)

	for _, c := range []*cobra.Command{requirementsCmd, requirementsListCmd, requirementsShowCmd, requirementsHistoryCmd} {
		c.Flags().Bool("json", false, "Print JSON")
	}
	for _, c := range []*cobra.Command{requirementsAddCmd, requirementsEditCmd} {
		c.Flags().StringP("description", "d", "", "What the requirement means, in detail")
		c.Flags().String("priority", "", "must, should or could")
		c.Flags().StringSlice("tag", nil, "A tag (repeatable, or comma-separated)")
		c.Flags().StringArray("test", nil, "A test's shell command, run in the project's root (repeatable)")
		c.Flags().Duration("test-timeout", 0, "How long each test given may run (default 10m)")
		c.Flags().String("status", "", "draft, approved or deprecated (a new requirement is approved)")
	}
	requirementsEditCmd.Flags().String("title", "", "A new title")
	requirementsEditCmd.Flags().Bool("clear-tests", false, "Remove every test")
	requirementsVerdictCmd.Flags().String("note", "", "What the verdict rests on")
	requirementsHistoryCmd.Flags().Int("limit", 10, "How many checks to show")

	f := requirementsCheckCmd.Flags()
	f.Bool("ai", false, "Ask the model about the requirements that have no tests")
	f.Bool("json", false, "Report as framed JSON, for the hub")
	f.Bool("no-record", false, "Record nothing in the project (the hub records what it reads back)")
	f.String("spec", "", "Check the requirements in this JSON spec instead of the project's own (the hub's)")
	f.String("provider", "", "AI provider for --ai (default: the project's)")
	f.String("model", "", "Model for --ai")
	f.Duration("ai-timeout", 5*time.Minute, "How long the model may take over one requirement")
	f.Duration("timeout", 0, "Stop the whole check after this long (default: no limit beyond each test's)")
	f.String("file", "", "Check the requirements in this spec file (e.g. "+requirements.SpecFileName+
		"); needs no hub and no project database, and records nothing")
	f.StringSlice("status", nil, "With no ids, check the requirements of these statuses (default approved)")
	f.Bool("all", false, "With no ids, check every requirement, whatever its status")
}

// requirementsProject is the project in the working directory, opened.
type requirementsProject struct {
	workDir string
	state   *state.ProjectState
	db      *statedb.DB
}

func openRequirementsProject() (*requirementsProject, error) {
	workDir, err := os.Getwd()
	if err != nil {
		return nil, err
	}
	s, err := state.LoadLite(workDir)
	if err != nil {
		return nil, err
	}
	db, err := statedb.Open(state.DBPath(workDir))
	if err != nil {
		return nil, err
	}
	db.AsProject()
	return &requirementsProject{workDir: workDir, state: s, db: db}, nil
}

func parseRequirementID(arg string) (int, error) {
	a := strings.TrimSpace(arg)
	a = strings.TrimPrefix(strings.TrimPrefix(a, "R-"), "r-")
	id, err := strconv.Atoi(strings.TrimPrefix(a, "#"))
	if err != nil || id <= 0 {
		return 0, fmt.Errorf("invalid requirement %q: give its number, or R-<number>", arg)
	}
	return id, nil
}

func testsFromFlags(cmd *cobra.Command) ([]requirements.Test, error) {
	commands, _ := cmd.Flags().GetStringArray("test")
	timeout, _ := cmd.Flags().GetDuration("test-timeout")
	if timeout < 0 || timeout > requirements.MaxTestTimeout {
		return nil, fmt.Errorf("--test-timeout must be between 0 and %s", requirements.MaxTestTimeout)
	}
	var tests []requirements.Test
	for _, c := range commands {
		tests = append(tests, requirements.Test{Command: c, TimeoutSeconds: int(timeout / time.Second)})
	}
	return tests, nil
}

func runRequirementsList(cmd *cobra.Command) error {
	p, err := openRequirementsProject()
	if err != nil {
		return err
	}
	defer p.db.Close()
	reqs, err := p.db.Requirements()
	if err != nil {
		return err
	}
	latest, err := p.db.LatestRequirementChecks()
	if err != nil {
		return err
	}
	if asJSON, _ := cmd.Flags().GetBool("json"); asJSON {
		type row struct {
			requirements.Requirement
			LastCheck *statedb.RequirementCheck `json:"last_check,omitempty"`
			Stale     bool                      `json:"stale,omitempty"`
		}
		out := make([]row, 0, len(reqs))
		for _, r := range reqs {
			x := row{Requirement: r}
			if c, ok := latest[r.ID]; ok {
				x.LastCheck, x.Stale = &c, c.Fingerprint != r.Fingerprint()
			}
			out = append(out, x)
		}
		return printJSON(map[string]any{"requirements": out})
	}
	if len(reqs) == 0 {
		fmt.Println("No requirements yet. Add one with: cloop requirements add \"<what must stay true>\" --test \"<command>\"")
		return nil
	}
	var counts requirements.Counts
	never := 0
	for _, r := range reqs {
		c, ok := latest[r.ID]
		verdict, note := "never", ""
		switch {
		case !ok:
			never++
		case c.Fingerprint != r.Fingerprint():
			verdict, note = c.Verdict, " (stale: changed since)"
			counts.Add(c.Verdict)
		default:
			verdict = c.Verdict
			counts.Add(c.Verdict)
		}
		tests := "no tests"
		if n := len(r.Tests); n == 1 {
			tests = "1 test"
		} else if n > 1 {
			tests = fmt.Sprintf("%d tests", n)
		}
		prio := r.Priority
		if prio == "" {
			prio = "-"
		}
		if r.CurrentStatus() != requirements.StatusApproved {
			note += " [" + r.CurrentStatus() + "]"
		}
		verdictColor(verdict).Printf("%-6s %-11s", requirements.Key(r.ID), verdict)
		fmt.Printf(" %-6s %-8s %s%s\n", prio, tests, r.Title, note)
	}
	fmt.Printf("\n%s, %d never checked\n", describeCounts(counts), never)
	return nil
}

func runRequirementsCheck(cmd *cobra.Command, args []string) error {
	f := cmd.Flags()
	asJSON, _ := f.GetBool("json")
	fail := func(err error) error {
		if asJSON {
			return failFramed(err)
		}
		return err
	}
	noRecord, _ := f.GetBool("no-record")
	specArg, _ := f.GetString("spec")
	fileArg, _ := f.GetString("file")
	assess, _ := f.GetBool("ai")
	total, _ := f.GetDuration("timeout")
	statuses, err := checkStatuses(f)
	if err != nil {
		return fail(err)
	}
	workDir, err := os.Getwd()
	if err != nil {
		return fail(err)
	}

	// What to check: the hub's spec, a spec file, or the project's own
	// requirements.
	var (
		reqs []requirements.Requirement
		goal string
		st   *state.ProjectState
		db   *statedb.DB
	)
	switch {
	case specArg != "" && fileArg != "":
		return fail(fmt.Errorf("give --spec or --file, not both"))
	case specArg != "":
		if len(args) > 0 {
			return fail(fmt.Errorf("give ids or --spec, not both"))
		}
		sp, err := requirements.ParseSpec([]byte(specArg))
		if err != nil {
			return fail(err)
		}
		reqs, goal = sp.Requirements, sp.Goal
	case fileArg != "":
		// The spec file alone: no hub, no project database, nothing
		// recorded — a CI job's checkout has neither.
		sf, _, err := requirements.LoadSpecFile(workDir, fileArg)
		if err != nil {
			return fail(specFileErr(fileArg, err))
		}
		if reqs, err = selectRequirements(sf.Requirements, args); err != nil {
			return fail(err)
		}
	default:
		p, err := openRequirementsProject()
		if err != nil {
			return fail(err)
		}
		defer p.db.Close()
		st, db = p.state, p.db
		if p.state.Plan != nil {
			goal = p.state.Plan.Goal
		}
		if goal == "" {
			goal = p.state.Goal
		}
		all, err := p.db.Requirements()
		if err != nil {
			return fail(err)
		}
		reqs, err = selectRequirements(all, args)
		if err != nil {
			return fail(err)
		}
	}
	if noRecord {
		db = nil
	}
	// Named requirements are checked whatever their status; otherwise only
	// the statuses asked for — approved, unless told — and the hub's spec
	// is checked as the hub sent it.
	var unasked []requirements.Requirement
	if len(args) == 0 && specArg == "" {
		reqs, unasked = byStatus(reqs, statuses)
	}
	// Without --ai a requirement nothing tests has nothing to run: it is
	// skipped, not recorded as unverified over a verdict reached before.
	var skipped []requirements.Requirement
	if !assess && specArg == "" {
		tested := reqs[:0:0]
		for _, r := range reqs {
			if r.Tested() {
				tested = append(tested, r)
			} else {
				skipped = append(skipped, r)
			}
		}
		reqs = tested
	}

	opts := requirements.Options{Dir: workDir}
	if assess && hasUntested(reqs) {
		if st == nil {
			// The hub's spec carries no provider: the executor's own copy of
			// the project says which one, as for every other helper.
			if s, err := state.LoadLite(workDir); err == nil {
				st = s
			}
		}
		pflag, _ := f.GetString("provider")
		mflag, _ := f.GetString("model")
		prov, model, err := helperProvider(workDir, st, pflag, mflag)
		if err != nil {
			return fail(fmt.Errorf("provider: %w", err))
		}
		aiTimeout, _ := f.GetDuration("ai-timeout")
		opts.Assess = assessWith(prov, model, workDir, goal, aiTimeout)
	}
	if !asJSON {
		opts.OnResult = func(r requirements.Result) {
			verdictColor(r.Verdict).Printf("%-6s %-11s", requirements.Key(r.RequirementID), r.Verdict)
			fmt.Printf(" %s\n", r.Summary)
		}
		for _, r := range skipped {
			color.New(color.Faint).Printf("%-6s %-11s no tests: ask the model (--ai), or record a verdict\n",
				requirements.Key(r.ID), "skipped")
		}
		if len(unasked) > 0 {
			color.New(color.Faint).Printf("Not checked: %s — name them, or pass --status or --all\n", describeUnasked(unasked))
		}
	}

	ctx := context.Background()
	if total > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, total)
		defer cancel()
	}
	started := time.Now()
	commit, dirty := requirements.WorkTree(ctx, workDir)
	report := requirements.Report{Commit: commit, Dirty: dirty, Results: requirements.Check(ctx, reqs, opts)}
	counts := requirements.Tally(report.Results)

	if db != nil && len(reqs) > 0 {
		run := statedb.RequirementRun{
			RunID: artifact.NewRunID(), State: statedb.RequirementRunDone, Source: "cli", StartedBy: operatorActor(),
			StartedAt: started, ExecutorID: "local", Assess: opts.Assess != nil, Counts: counts,
		}
		for _, r := range reqs {
			run.RequirementIDs = append(run.RequirementIDs, r.ID)
		}
		if _, err := db.RecordRequirementChecks(statedb.CheckRecord{
			RunID: run.RunID, Commit: commit, Dirty: dirty, ExecutorID: "local", CheckedBy: run.StartedBy,
		}, report.Results); err != nil {
			return fail(fmt.Errorf("record the checks: %w", err))
		}
		if err := db.RecordFinishedRequirementRun(run); err != nil {
			return fail(fmt.Errorf("record the check: %w", err))
		}
		statedb.AuditRequirementCheck(db, run, commit, dirty, run.StartedBy)
	}

	if asJSON {
		// The verdicts are in the report: a check that ran exits 0, and a
		// requirement it found unfulfilled is the hub's to say.
		return clijson.Emit(os.Stdout, report)
	}
	if len(reqs) == 0 {
		if len(skipped) == 0 && len(unasked) == 0 {
			fmt.Println("No requirements to check.")
		}
		return nil
	}
	where := ""
	if commit != "" {
		where = " at " + commit[:min(12, len(commit))]
		if dirty {
			where += " (with uncommitted changes)"
		}
	}
	fmt.Printf("\n%s%s\n", describeCounts(counts), where)
	if counts.Failing() {
		return errRequirementsFailing
	}
	return nil
}

func selectRequirements(all []requirements.Requirement, args []string) ([]requirements.Requirement, error) {
	if len(args) == 0 {
		return all, nil
	}
	byID := make(map[int]requirements.Requirement, len(all))
	for _, r := range all {
		byID[r.ID] = r
	}
	var out []requirements.Requirement
	seen := map[int]bool{}
	for _, a := range args {
		id, err := parseRequirementID(a)
		if err != nil {
			return nil, err
		}
		r, ok := byID[id]
		if !ok {
			return nil, fmt.Errorf("%w: %s", statedb.ErrRequirementNotFound, requirements.Key(id))
		}
		if !seen[id] {
			seen[id] = true
			out = append(out, r)
		}
	}
	return out, nil
}

// checkStatuses is the statuses a check without ids checks: --all, --status,
// or approved.
func checkStatuses(f interface {
	GetBool(string) (bool, error)
	GetStringSlice(string) ([]string, error)
}) ([]string, error) {
	if all, _ := f.GetBool("all"); all {
		return requirements.Statuses, nil
	}
	given, _ := f.GetStringSlice("status")
	if len(given) == 0 {
		return []string{requirements.StatusApproved}, nil
	}
	var out []string
	for _, s := range given {
		s, err := requirements.NormalizeStatus(s)
		if err != nil {
			return nil, err
		}
		if s != "" {
			out = append(out, s)
		}
	}
	return out, nil
}

// byStatus splits reqs into those of the statuses given and the rest.
func byStatus(reqs []requirements.Requirement, statuses []string) (in, out []requirements.Requirement) {
	for _, r := range reqs {
		if slices.Contains(statuses, r.CurrentStatus()) {
			in = append(in, r)
		} else {
			out = append(out, r)
		}
	}
	return in, out
}

// describeUnasked says which requirements a check passed by for their status:
// "2 drafts (R-4, R-5), 1 deprecated (R-9)".
func describeUnasked(reqs []requirements.Requirement) string {
	var parts []string
	for _, status := range requirements.Statuses {
		var keys []string
		for _, r := range reqs {
			if r.CurrentStatus() == status {
				keys = append(keys, requirements.Key(r.ID))
			}
		}
		if len(keys) == 0 {
			continue
		}
		n, what := len(keys), status
		if status == requirements.StatusDraft && n > 1 {
			what = "drafts"
		}
		if n > 6 {
			keys = append(keys[:6], "…")
		}
		parts = append(parts, fmt.Sprintf("%d %s (%s)", n, what, strings.Join(keys, ", ")))
	}
	return strings.Join(parts, ", ")
}

func hasUntested(reqs []requirements.Requirement) bool {
	for _, r := range reqs {
		if !r.Tested() {
			return true
		}
	}
	return false
}

// assessContextTokens bounds the code a model that cannot read the tree is
// shown instead.
const assessContextTokens = 6000

// assessWith asks prov about one untested requirement at a time. A provider
// that is an agent harness — Claude Code, Copilot — reads the tree itself; any
// other is shown the code most related to the requirement.
func assessWith(prov provider.Provider, model, workDir, goal string, timeout time.Duration) func(context.Context, requirements.Requirement) (requirements.Assessment, error) {
	agentic := prov.Name() == "claudecode" || prov.Name() == "copilot"
	return func(ctx context.Context, r requirements.Requirement) (requirements.Assessment, error) {
		code := ""
		if !agentic {
			code = pm.CollectRelevantContext(workDir, &pm.Task{Title: r.Title, Description: r.Description}, assessContextTokens)
		}
		cctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		res, err := prov.Complete(cctx, requirements.AssessPrompt(goal, r, code), provider.Options{
			Model: model, WorkDir: workDir, Timeout: timeout,
		})
		if err != nil {
			return requirements.Assessment{}, err
		}
		if res == nil {
			return requirements.Assessment{}, requirements.ErrNoAssessment
		}
		return requirements.ParseAssessment(res.Output)
	}
}

func printRequirement(r requirements.Requirement) {
	color.New(color.Bold).Printf("%s  %s\n", requirements.Key(r.ID), r.Title)
	if r.Priority != "" {
		fmt.Printf("Priority: %s\n", r.Priority)
	}
	if len(r.Tags) > 0 {
		fmt.Printf("Tags:     %s\n", strings.Join(r.Tags, ", "))
	}
	if r.Description != "" {
		fmt.Printf("\n%s\n", r.Description)
	}
	if len(r.Tests) == 0 {
		color.New(color.Faint).Println("\nNo tests.")
		return
	}
	fmt.Println("\nTests:")
	for i, t := range r.Tests {
		label := ""
		if t.Name != "" {
			label = t.Name + ": "
		}
		fmt.Printf("  %d. %s%s  (timeout %s)\n", i+1, label, t.Command, t.Timeout())
	}
}

func printCheck(r requirements.Requirement, c statedb.RequirementCheck, withOutput bool) {
	stale := ""
	if c.Fingerprint != r.Fingerprint() {
		stale = " — stale, the requirement changed since"
	}
	verdictColor(c.Verdict).Printf("%s", c.Verdict)
	fmt.Printf("  %s by %s via %s%s\n", c.CheckedAt.Local().Format("2006-01-02 15:04"), c.CheckedBy, c.Method, stale)
	if c.Summary != "" {
		fmt.Printf("  %s\n", c.Summary)
	}
	if c.Commit != "" {
		dirty := ""
		if c.Dirty {
			dirty = " (with uncommitted changes)"
		}
		fmt.Printf("  at %s%s on %s\n", c.Commit[:min(12, len(c.Commit))], dirty, c.ExecutorID)
	}
	for _, e := range c.Evidence {
		fmt.Printf("  - %s\n", e)
	}
	if !withOutput {
		return
	}
	for _, t := range c.Tests {
		fmt.Printf("  [%s] %s (%d ms)\n", t.Outcome, requirements.Test{Name: t.Name, Command: t.Command}.Label(), t.DurationMS)
		if t.Outcome != requirements.OutcomePass && strings.TrimSpace(t.Output) != "" {
			for _, line := range strings.Split(strings.TrimRight(t.Output, "\n"), "\n") {
				fmt.Printf("      %s\n", line)
			}
		}
	}
}

// describeCounts says what a set of verdicts adds up to.
func describeCounts(c requirements.Counts) string {
	errs := fmt.Sprintf("%d errors", c.Error)
	if c.Error == 1 {
		errs = "1 error"
	}
	return fmt.Sprintf("%d fulfilled, %d unfulfilled, %d unverified, %s", c.Fulfilled, c.Unfulfilled, c.Unverified, errs)
}

func verdictColor(v string) *color.Color {
	switch v {
	case requirements.VerdictFulfilled:
		return color.New(color.FgGreen)
	case requirements.VerdictUnfulfilled:
		return color.New(color.FgRed, color.Bold)
	case requirements.VerdictError:
		return color.New(color.FgYellow)
	}
	return color.New(color.Faint)
}
