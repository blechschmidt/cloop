package cmd

// `cloop requirements draft`, `lint` and `approve` (Task 20462): the model
// drafts testable requirements from the project's goal or a specification,
// lint says what is wrong with requirements as written, and a person approves
// the drafts — the only way one starts to count.
//
// draft and lint --ai are also what the hub dispatches to a project's
// executor for the Requirements tab's Draft dialog, with --json (a framed
// result) and their input as arguments — --text, --goal and --existing for a
// draft, --spec for a lint — so the model runs where the project's runs do,
// with the caller's account, and the executor needs no copy of the hub's
// requirements. The hub stores what comes back, through its own copy of the
// rules (requirements.CheckDraftResult, CheckModelFindings).

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/clijson"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/requirements"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
	"github.com/fatih/color"
	"github.com/mattn/go-isatty"
	"github.com/spf13/cobra"
)

// errLintFindings is lint's exit when it found something to settle: the
// report already said what.
var errLintFindings = errors.New("lint found requirements to fix")

// Model call budgets: drafting may read the repository for its tests; lint
// asks two short questions.
const (
	draftCallTimeout = 6 * time.Minute
	lintCallTimeout  = 3 * time.Minute
	// draftRepoTokens bounds the code a model that cannot read the tree is
	// shown to find a test command in.
	draftRepoTokens = 4000
	// closeEnough is how near a requirement's words must be to a duplicate's
	// for lint to name it as the one repeated.
	closeEnough = 0.25
)

var requirementsDraftCmd = &cobra.Command{
	Use:   "draft",
	Short: "Have the model draft testable requirements from the goal or a specification",
	Long: `Turn free text into requirements: atomic, testable statements in EARS form
("When <trigger>, the system shall <response>"), each with acceptance criteria,
a suggested priority, tags and — where the repository makes one obvious — a
test command.

  cloop requirements draft --from-goal          # the project's goal
  cloop requirements draft --from-file spec.md  # a specification
  cat notes.md | cloop requirements draft       # stdin

The drafts are stored with the status draft. A draft is checked by nothing —
not by a check, not by the requirements gate — and no agent is held to it,
until a person approves it: review each, edit what needs it, then

  cloop requirements approve 12 13             # or --all-drafts
  cloop requirements lint                      # what to fix first

The model's answer is read strictly and every proposal held to the bounds of a
requirement written by hand; one that does not fit, or that asks to be anything
but a draft, is refused and named. --dry-run shows the drafts and stores none.`,
	Args: cobra.NoArgs,
	RunE: runRequirementsDraft,
}

var requirementsLintCmd = &cobra.Command{
	Use:   "lint [id...]",
	Short: "Find ambiguous, compound, duplicate, contradictory and untested requirements",
	Long: `Lint reads the requirements as written and reports:

  ambiguous      wording a check cannot measure: "fast", "user-friendly",
                 "should handle", "etc."
  compound       two behaviours in one requirement: split it
  duplicate      a requirement that repeats another
  contradiction  two requirements that cannot both hold
  untested_must  an approved must requirement with no test

By rule it finds near-duplicates and contradictions by their words; with --ai
the model is asked as well — whether each draft repeats a requirement already
agreed (the semantic dedup auto-evolve uses for new tasks) and which pairs
contradict each other.

With no ids it lints every requirement but the deprecated ones (--all lints
those too). --file lints a spec file instead of the project's database. Exits 1
when it finds an error — a duplicate, a contradiction or an untested must — or,
with --strict, anything.`,
	RunE: runRequirementsLint,
}

var requirementsApproveCmd = &cobra.Command{
	Use:   "approve <id...>",
	Short: "Approve drafts, so that checks and the requirements gate count them",
	Long: `Approve drafted requirements: from now on a check runs their tests, the
requirements gate holds tasks to them, and an agent is given them as its
contract. Who approved each is recorded on it and in the audit trail
(requirement.approve). Read a draft — its test above all, which may be the
model's proposal — before approving it.

  cloop requirements approve 12 13
  cloop requirements approve --all-drafts`,
	RunE: runRequirementsApprove,
}

func init() {
	requirementsCmd.AddCommand(requirementsDraftCmd, requirementsLintCmd, requirementsApproveCmd)

	f := requirementsDraftCmd.Flags()
	f.Bool("from-goal", false, "Draft from the project's goal")
	f.String("from-file", "", "Draft from this file (- for stdin)")
	f.String("text", "", "Draft from this text")
	f.String("goal", "", "The project's goal, as context for a specification (default: the project's own)")
	f.String("existing", "", "The project's existing requirements, as JSON (the hub's; default: the project's own)")
	f.Bool("text-is-goal", false, "The text given is the project's goal (the hub's)")
	f.Int("max", requirements.DefaultDrafts, fmt.Sprintf("Draft at most this many (1-%d)", requirements.MaxDrafts))
	f.Bool("dry-run", false, "Show the drafts and store none")
	f.Bool("json", false, "Report as framed JSON, for the hub")
	f.String("provider", "", "AI provider (default: the project's)")
	f.String("model", "", "Model")
	f.Duration("timeout", draftCallTimeout, "How long the model may take")
	for _, name := range []string{"goal", "existing", "text-is-goal"} {
		_ = f.MarkHidden(name)
	}

	f = requirementsLintCmd.Flags()
	f.Bool("ai", false, "Ask the model about duplicates in other words, and contradictions")
	f.Bool("json", false, "Report as framed JSON, for the hub")
	f.Bool("strict", false, "Exit 1 on a warning too")
	f.Bool("all", false, "With no ids, lint the deprecated requirements too")
	f.String("file", "", "Lint the requirements in this spec file (e.g. "+requirements.SpecFileName+")")
	f.String("spec", "", "Lint the requirements in this JSON spec (the hub's)")
	f.String("provider", "", "AI provider for --ai (default: the project's)")
	f.String("model", "", "Model for --ai")
	f.Duration("timeout", lintCallTimeout, "How long the model may take over each question")

	requirementsApproveCmd.Flags().Bool("all-drafts", false, "Approve every draft")
	requirementsApproveCmd.Flags().Bool("json", false, "Print JSON")
}

// draftInput is the text a draft is made from, read from the one place the
// flags name.
func draftInput(cmd *cobra.Command, workDir string) (src requirements.DraftSource, origin string, st *state.ProjectState, err error) {
	f := cmd.Flags()
	fromGoal, _ := f.GetBool("from-goal")
	file, _ := f.GetString("from-file")
	text, _ := f.GetString("text")
	given := 0
	for _, set := range []bool{fromGoal, file != "", f.Changed("text")} {
		if set {
			given++
		}
	}
	if given > 1 {
		return src, "", nil, fmt.Errorf("give one of --from-goal, --from-file and --text")
	}
	// The project, when there is one: its goal is the source or the context.
	if s, lerr := state.LoadLite(workDir); lerr == nil {
		st = s
	}
	projectGoal := ""
	if st != nil {
		projectGoal = st.Goal
		if st.Plan != nil && st.Plan.Goal != "" {
			projectGoal = st.Plan.Goal
		}
	}
	switch {
	case fromGoal:
		if st == nil {
			return src, "", nil, fmt.Errorf("--from-goal: there is no cloop project here")
		}
		src.Text, src.Goal, origin = projectGoal, true, "goal"
	case file == "-":
		src.Text, err = readBounded(os.Stdin, "stdin")
		origin = "stdin"
	case file != "":
		var fh *os.File
		if fh, err = os.Open(file); err == nil {
			src.Text, err = readBounded(fh, file)
			fh.Close()
		}
		origin = "file"
	case f.Changed("text"):
		src.Text, origin = text, "text"
		// The hub sends the goal it holds as the text (Task 20462).
		if isGoal, _ := f.GetBool("text-is-goal"); isGoal {
			src.Goal, origin = true, "goal"
		}
	case !isatty.IsTerminal(os.Stdin.Fd()):
		src.Text, err = readBounded(os.Stdin, "stdin")
		origin = "stdin"
	default:
		return src, "", nil, fmt.Errorf("say what to draft from: --from-goal, --from-file <file>, or the text on stdin")
	}
	if err != nil {
		return src, "", nil, err
	}
	if src.Text, err = requirements.CheckDraftSource(src.Text); err != nil {
		return src, "", nil, err
	}
	if !src.Goal {
		src.Context, _ = f.GetString("goal")
		if !f.Changed("goal") {
			src.Context = projectGoal
		}
	}
	return src, origin, st, nil
}

// readBounded reads r, and no more than one byte past what a draft may be
// made from: CheckDraftSource refuses that.
func readBounded(r io.Reader, name string) (string, error) {
	b, err := io.ReadAll(io.LimitReader(r, requirements.MaxDraftSourceBytes+1))
	if err != nil {
		return "", fmt.Errorf("read %s: %w", name, err)
	}
	return string(b), nil
}

func runRequirementsDraft(cmd *cobra.Command, args []string) error {
	f := cmd.Flags()
	asJSON, _ := f.GetBool("json")
	fail := func(err error) error {
		if asJSON {
			return failFramed(err)
		}
		return err
	}
	dryRun, _ := f.GetBool("dry-run")
	limit, _ := f.GetInt("max")
	if limit < 1 || limit > requirements.MaxDrafts {
		return fail(fmt.Errorf("--max is between 1 and %d", requirements.MaxDrafts))
	}
	workDir, err := os.Getwd()
	if err != nil {
		return fail(err)
	}
	src, origin, st, err := draftInput(cmd, workDir)
	if err != nil {
		return fail(err)
	}

	// What the project already requires: the hub's, or the project's own.
	var (
		existing []requirements.Requirement
		db       *statedb.DB
	)
	if raw, _ := f.GetString("existing"); f.Changed("existing") {
		if existing, err = requirements.DecodeExisting([]byte(raw)); err != nil {
			return fail(fmt.Errorf("--existing: %w", err))
		}
	} else if !dryRun || st != nil {
		p, err := openRequirementsProject()
		if err != nil {
			return fail(err)
		}
		defer p.db.Close()
		db = p.db
		all, err := p.db.Requirements()
		if err != nil {
			return fail(err)
		}
		raw, _, err := requirements.EncodeExisting(all)
		if err != nil {
			return fail(err)
		}
		if existing, err = requirements.DecodeExisting(raw); err != nil {
			return fail(err)
		}
	}
	if dryRun {
		db = nil
	} else if db == nil {
		return fail(fmt.Errorf("--existing is the hub's: give --dry-run with it"))
	}

	pflag, _ := f.GetString("provider")
	mflag, _ := f.GetString("model")
	prov, model, err := helperProvider(workDir, st, pflag, mflag)
	if err != nil {
		return fail(fmt.Errorf("provider: %w", err))
	}
	agentic := prov.Name() == "claudecode" || prov.Name() == "copilot"
	repoContext := ""
	if !agentic {
		repoContext = pm.CollectRelevantContext(workDir, &pm.Task{Title: "tests", Description: firstRunes(src.Text, 2000)},
			draftRepoTokens)
	}
	timeout, _ := f.GetDuration("timeout")
	if !asJSON {
		color.New(color.Faint).Printf("Drafting requirements from %s with %s…\n", describeDraftOrigin(origin), prov.Name())
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	out, err := prov.Complete(ctx, requirements.DraftPrompt(src, existing, limit, agentic, repoContext),
		provider.Options{Model: model, WorkDir: workDir, Timeout: timeout})
	if err != nil {
		return fail(fmt.Errorf("the model: %w", err))
	}
	if out == nil {
		return fail(requirements.ErrNoDraftAnswer)
	}
	answer, err := requirements.ParseDraftAnswer(out.Output)
	if err != nil {
		return fail(err)
	}
	res := requirements.Drafts(answer, existing, limit)

	if db != nil && len(res.Drafts) > 0 {
		sum := sha256.Sum256([]byte(src.Text))
		stored, err := db.AddDraftRequirements(res.Drafts, operatorActor(), statedb.DraftOrigin{
			Source: origin, SHA256: hex.EncodeToString(sum[:]), Bytes: len(src.Text), ExecutorID: "local", Via: "cli",
			Refused: len(res.Refused),
		})
		if err != nil {
			return fail(fmt.Errorf("store the drafts: %w", err))
		}
		res.Drafts = stored
	}
	if asJSON {
		return clijson.Emit(os.Stdout, res)
	}
	printDrafts(res, db != nil)
	return nil
}

func describeDraftOrigin(origin string) string {
	switch origin {
	case "goal":
		return "the project's goal"
	case "stdin":
		return "stdin"
	case "text":
		return "the text given"
	}
	return "the file"
}

func firstRunes(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n])
	}
	return s
}

func printDrafts(res requirements.DraftResult, stored bool) {
	if len(res.Drafts) == 0 {
		fmt.Println("The model drafted no requirements.")
	}
	var ids []string
	for i, r := range res.Drafts {
		key := fmt.Sprintf("Draft %d", i+1)
		if r.ID > 0 {
			key = requirements.Key(r.ID)
			ids = append(ids, strconv.Itoa(r.ID))
		}
		color.New(color.Bold).Printf("\n%s  %s\n", key, r.Title)
		var meta []string
		if r.Priority != "" {
			meta = append(meta, r.Priority)
		}
		if len(r.Tags) > 0 {
			meta = append(meta, strings.Join(r.Tags, ", "))
		}
		if len(meta) > 0 {
			color.New(color.Faint).Printf("%s\n", strings.Join(meta, " · "))
		}
		if r.Description != "" {
			fmt.Println(r.Description)
		}
		for _, t := range r.Tests {
			fmt.Printf("Proposed test: %s\n", t.Command)
		}
	}
	if len(res.Refused) > 0 {
		color.New(color.FgYellow).Printf("\n%d proposal(s) refused:\n", len(res.Refused))
		for _, rf := range res.Refused {
			fmt.Printf("  %d. %s — %s\n", rf.Index, rf.Title, rf.Reason)
		}
	}
	if res.Notes != "" {
		color.New(color.Faint).Printf("\nThe model: %s\n", res.Notes)
	}
	if !stored {
		color.New(color.Faint).Println("\nNothing was stored (--dry-run).")
		return
	}
	if len(ids) > 0 {
		fmt.Printf("\nStored as drafts: nothing checks them until they are approved. Review each — its test above all —\n"+
			"edit what needs it (cloop requirements edit <id>), then: cloop requirements approve %s\n", strings.Join(ids, " "))
	}
}

func runRequirementsLint(cmd *cobra.Command, args []string) error {
	f := cmd.Flags()
	asJSON, _ := f.GetBool("json")
	fail := func(err error) error {
		if asJSON {
			return failFramed(err)
		}
		return err
	}
	strict, _ := f.GetBool("strict")
	assess, _ := f.GetBool("ai")
	all, _ := f.GetBool("all")
	specArg, _ := f.GetString("spec")
	fileArg, _ := f.GetString("file")
	workDir, err := os.Getwd()
	if err != nil {
		return fail(err)
	}

	var (
		reqs []requirements.Requirement
		goal string
		st   *state.ProjectState
	)
	switch {
	case specArg != "" && fileArg != "":
		return fail(fmt.Errorf("give --spec or --file, not both"))
	case specArg != "":
		sp, err := requirements.ParseSpec([]byte(specArg))
		if err != nil {
			return fail(err)
		}
		reqs, goal = sp.Requirements, sp.Goal
	case fileArg != "":
		sf, _, err := requirements.LoadSpecFile(workDir, fileArg)
		if err != nil {
			return fail(specFileErr(fileArg, err))
		}
		reqs = sf.Requirements
	default:
		p, err := openRequirementsProject()
		if err != nil {
			return fail(err)
		}
		defer p.db.Close()
		st = p.state
		if st.Plan != nil {
			goal = st.Plan.Goal
		}
		if goal == "" {
			goal = st.Goal
		}
		if reqs, err = p.db.Requirements(); err != nil {
			return fail(err)
		}
	}

	var subjects []int
	if len(args) > 0 {
		picked, err := selectRequirements(reqs, args)
		if err != nil {
			return fail(err)
		}
		for _, r := range picked {
			subjects = append(subjects, r.ID)
		}
	} else if all {
		for _, r := range reqs {
			subjects = append(subjects, r.ID)
		}
	}
	rep := requirements.LintReport{Findings: requirements.Lint(reqs, subjects)}
	rep.Checked = len(subjects)
	if subjects == nil {
		for _, r := range reqs {
			if r.CurrentStatus() != requirements.StatusDeprecated {
				rep.Checked++
			}
		}
	}

	if assess && len(reqs) > 0 {
		if st == nil {
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
		timeout, _ := f.GetDuration("timeout")
		if !asJSON {
			color.New(color.Faint).Printf("Asking %s about duplicates and contradictions…\n", prov.Name())
		}
		byModel, notes := modelLint(prov, provider.Options{Model: model, WorkDir: workDir, Timeout: timeout}, goal, reqs, subjects)
		rep.Findings = requirements.MergeFindings(rep.Findings, byModel)
		rep.Notes = append(rep.Notes, notes...)
	}

	if asJSON {
		return clijson.Emit(os.Stdout, rep)
	}
	printLint(rep)
	errs, warnings := rep.Counts()
	if errs > 0 || (strict && warnings > 0) {
		return errLintFindings
	}
	return nil
}

// modelLint asks the model what words alone cannot show: whether the drafts
// among the subjects (the subjects themselves, when none is a draft) repeat a
// requirement already there in other words — through the dedup auto-evolve
// asks before it injects a task (pm.JudgeDuplicates) — and which pairs
// contradict each other. It sees what LintSpec would send, so a project of a
// thousand requirements costs a bounded prompt. notes say what did not run.
func modelLint(prov provider.Provider, opts provider.Options, goal string, all []requirements.Requirement, subjects []int) ([]requirements.Finding, []string) {
	if subjects == nil {
		for _, r := range all {
			if r.CurrentStatus() != requirements.StatusDeprecated {
				subjects = append(subjects, r.ID)
			}
		}
	}
	raw, n, err := requirements.LintSpec(goal, all, subjects)
	var view []requirements.Requirement
	if err == nil {
		var sp requirements.Spec
		if sp, err = requirements.ParseSpec(raw); err == nil {
			view = sp.Requirements
		}
	}
	if err != nil {
		return nil, []string{"the model was not asked: " + err.Error()}
	}
	var notes []string
	if n < len(all) {
		notes = append(notes, fmt.Sprintf("the model was shown %d of the %d requirements: the rest did not fit one prompt", n, len(all)))
	}
	isSubject := map[int]bool{}
	for _, id := range subjects {
		isSubject[id] = true
	}
	var candidates, drafts, existing []requirements.Requirement
	for _, r := range view {
		if isSubject[r.ID] && r.CurrentStatus() == requirements.StatusDraft {
			drafts = append(drafts, r)
		}
	}
	candidates = drafts
	if len(candidates) == 0 {
		for _, r := range view {
			if isSubject[r.ID] {
				candidates = append(candidates, r)
			}
		}
	}
	for _, r := range view {
		if !slices.ContainsFunc(candidates, func(c requirements.Requirement) bool { return c.ID == r.ID }) &&
			r.CurrentStatus() != requirements.StatusDeprecated {
			existing = append(existing, r)
		}
	}

	var found []requirements.Finding
	ctx, cancel := context.WithTimeout(context.Background(), opts.Timeout)
	v, err := pm.JudgeDuplicates(ctx, prov, opts, asTasks(existing), asTasks(candidates))
	cancel()
	switch {
	case err != nil:
		notes = append(notes, "the model's duplicate check did not run: "+err.Error())
	case len(existing) == 0:
		notes = append(notes, "the model's duplicate check had nothing to compare the requirements with")
	default:
		for _, i := range v.Duplicates {
			if i < 0 || i >= len(candidates) {
				continue
			}
			c := candidates[i]
			var others []int
			if closest, sim, ok := requirements.Closest(c, existing); ok && sim >= closeEnough {
				others = []int{closest.ID}
			}
			found = append(found, requirements.ModelFinding(requirements.LintDuplicate, c.ID, others, v.Reason))
		}
	}

	ctx, cancel = context.WithTimeout(context.Background(), opts.Timeout)
	defer cancel()
	out, err := prov.Complete(ctx, requirements.ContradictionPrompt(goal, view), opts)
	if err == nil && out == nil {
		err = errors.New("the model gave no answer")
	}
	var contra []requirements.Finding
	if err == nil {
		contra, err = requirements.ParseContradictions(out.Output, view)
	}
	if err != nil {
		notes = append(notes, "the model's contradiction check did not run: "+err.Error())
	}
	for _, c := range contra {
		if isSubject[c.ID] || slices.ContainsFunc(c.Others, func(o int) bool { return isSubject[o] }) {
			found = append(found, c)
		}
	}
	return found, notes
}

// asTasks is reqs as the dedup reads them: an id, a title and what it means.
func asTasks(reqs []requirements.Requirement) []*pm.Task {
	out := make([]*pm.Task, len(reqs))
	for i, r := range reqs {
		out[i] = &pm.Task{ID: r.ID, Title: r.Title, Description: r.Description}
	}
	return out
}

func printLint(rep requirements.LintReport) {
	for _, f := range rep.Findings {
		c := color.New(color.FgYellow)
		if f.Severity == requirements.SeverityError {
			c = color.New(color.FgRed, color.Bold)
		}
		c.Printf("%-6s %-7s %-13s", requirements.Key(f.ID), f.Severity, f.Kind)
		fmt.Printf(" %s\n", f.Message)
		if f.Hint != "" {
			color.New(color.Faint).Printf("       %s\n", f.Hint)
		}
	}
	for _, n := range rep.Notes {
		color.New(color.FgYellow).Printf("Note: %s\n", n)
	}
	errs, warnings := rep.Counts()
	if len(rep.Findings) == 0 {
		fmt.Printf("%d requirement(s) linted: nothing to fix.\n", rep.Checked)
		return
	}
	fmt.Printf("\n%d requirement(s) linted: %d error(s), %d warning(s)\n", rep.Checked, errs, warnings)
}

func runRequirementsApprove(cmd *cobra.Command, args []string) error {
	allDrafts, _ := cmd.Flags().GetBool("all-drafts")
	asJSON, _ := cmd.Flags().GetBool("json")
	if allDrafts == (len(args) > 0) {
		return fmt.Errorf("name the drafts to approve, or give --all-drafts")
	}
	p, err := openRequirementsProject()
	if err != nil {
		return err
	}
	defer p.db.Close()
	var ids []int
	if allDrafts {
		reqs, err := p.db.Requirements()
		if err != nil {
			return err
		}
		for _, r := range reqs {
			if r.CurrentStatus() == requirements.StatusDraft {
				ids = append(ids, r.ID)
			}
		}
		if len(ids) == 0 {
			fmt.Println("There are no drafts to approve.")
			return nil
		}
	} else if ids, err = requirements.ParseRefs(args); err != nil {
		return err
	}
	approved, already, err := p.db.ApproveRequirements(ids, operatorActor())
	if err != nil {
		return err
	}
	if asJSON {
		if approved == nil {
			approved = []requirements.Requirement{}
		}
		if already == nil {
			already = []int{}
		}
		return printJSON(map[string]any{"approved": approved, "already": already})
	}
	for _, r := range approved {
		color.New(color.FgGreen, color.Bold).Printf("Approved %s: %s\n", requirements.Key(r.ID), r.Title)
	}
	if len(already) > 0 {
		keys := make([]string, len(already))
		for i, id := range already {
			keys[i] = requirements.Key(id)
		}
		color.New(color.Faint).Printf("Already approved: %s\n", strings.Join(keys, ", "))
	}
	return nil
}
