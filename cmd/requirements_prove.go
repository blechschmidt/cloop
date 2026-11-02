package cmd

// `cloop requirements prove` (Task 20464): show that a requirement's tests
// fail without its change and pass with it — a red-green proof (see
// pkg/requirements/proof.go and pkg/reqproof).
//
// Run by hand it proves the named requirements of the project in the working
// directory against the commit before each test's implementation (or --base),
// records what it finds, and exits 1 when a proof is vacuous, broken or could
// not run. The hub dispatches it to the project's executor with --spec, --json
// and --no-record, and records what it reads back; the requirements gate runs
// it beside a task's work with --base (where the task started), --only-changed
// and --before-only.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/blechschmidt/cloop/pkg/artifact"
	"github.com/blechschmidt/cloop/pkg/clijson"
	"github.com/blechschmidt/cloop/pkg/reqproof"
	"github.com/blechschmidt/cloop/pkg/requirements"
	"github.com/blechschmidt/cloop/pkg/statedb"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

// errRequirementsUnproven is prove's exit for a proof that is vacuous, broken
// or could not run: the table already said which.
var errRequirementsUnproven = errors.New("not every requirement's tests are proven")

var requirementsProveCmd = &cobra.Command{
	Use:   "prove <id>...",
	Short: "Show that a requirement's tests fail without its change and pass with it",
	Long: `A test that always passes makes a requirement look fulfilled when it is not.
prove runs each named requirement's tests twice: on the code before the change,
in a throwaway checkout of the base commit, and on the change — the project's
tree as it is. The project's own checkout is never touched, and the throwaway
checkout is removed however the proof ends.

  proven        red before, green after: the tests show the change
  vacuous       green before: they pass without the change too
  broken        red after: they fail on the change itself
  inconclusive  the test does not exist at the base, so the base run used the
                base code with the change's test files laid over it, and that
                could not settle it — or the change holds nothing but tests
  error         the proof itself did not run

The base is the commit before the test's implementation: the parent of the
newest commit that changed the test's files (or a test the command names, like
TestX in "go test -run TestX") — that commit itself when it changed nothing but
tests — or HEAD while the test is uncommitted. --base names another. Each run
is bounded by the tests' own timeouts.

  cloop requirements prove R-3
  cloop requirements prove 3 4 --base v1.2.0~1

Exits 1 when a proof is vacuous, broken or could not run.`,
	RunE: runRequirementsProve,
}

func init() {
	requirementsCmd.AddCommand(requirementsProveCmd)
	f := requirementsProveCmd.Flags()
	f.String("base", "", "The commit the tests run at before the change (default: the commit before each test's implementation)")
	f.Bool("json", false, "Report as framed JSON, for the hub")
	f.Bool("no-record", false, "Record nothing in the project (the hub records what it reads back)")
	f.String("spec", "", "Prove the requirements in this JSON spec instead of the project's own (the hub's)")
	f.Duration("timeout", 0, "Stop the whole proof after this long (default: no limit beyond each test's)")
	f.Bool("only-changed", false, "Prove only the requirements whose tests the change added or changed (the gate's)")
	f.IntSlice("changed", nil, "Requirements whose test commands the change added or changed (the gate's)")
	f.Bool("before-only", false, "Run only the base side: the caller has just run the tests on the change (the gate's)")
	f.String("base-from", "", "How --base was chosen: task or given (the gate's)")
	for _, name := range []string{"only-changed", "changed", "before-only", "base-from"} {
		_ = f.MarkHidden(name)
	}
}

func runRequirementsProve(cmd *cobra.Command, args []string) error {
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
	base, _ := f.GetString("base")
	baseFrom, _ := f.GetString("base-from")
	total, _ := f.GetDuration("timeout")
	onlyChanged, _ := f.GetBool("only-changed")
	beforeOnly, _ := f.GetBool("before-only")
	changedIDs, _ := f.GetIntSlice("changed")
	workDir, err := os.Getwd()
	if err != nil {
		return fail(err)
	}
	switch baseFrom {
	case "", requirements.BaseFromTask, requirements.BaseFromGiven:
	default:
		return fail(fmt.Errorf("--base-from is task or given, not %q", baseFrom))
	}
	if base != "" {
		// A person may name a base as git does — a tag, HEAD~3 — which is
		// resolved here, once, to the commit every proof uses.
		sha, err := resolveProofBase(workDir, base)
		if err != nil {
			return fail(err)
		}
		base = sha
	}

	var (
		reqs []requirements.Requirement
		db   *statedb.DB
	)
	switch {
	case specArg != "":
		if len(args) > 0 {
			return fail(fmt.Errorf("give ids or --spec, not both"))
		}
		sp, err := requirements.ParseSpec([]byte(specArg))
		if err != nil {
			return fail(err)
		}
		reqs = sp.Requirements
	case len(args) == 0:
		return fail(fmt.Errorf("name the requirements to prove: cloop requirements prove R-<n>"))
	default:
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
		if reqs, err = selectRequirements(all, args); err != nil {
			return fail(err)
		}
		// A draft's tests run nowhere until a person approves it (Task
		// 20462); a requirement with no tests has nothing to prove.
		if err := refuseDrafts(reqs); err != nil {
			return fail(err)
		}
		var untested []string
		for _, r := range reqs {
			if !r.Tested() {
				untested = append(untested, requirements.Key(r.ID))
			}
		}
		if len(untested) > 0 {
			return fail(fmt.Errorf("%s %s no tests, so there is nothing to prove: give %s a test first",
				strings.Join(untested, ", "), plural(len(untested), "has", "have"), plural(len(untested), "it", "them")))
		}
	}
	if noRecord {
		db = nil
	}

	// A proof stopped by a signal still removes its checkout: the context is
	// what tells it to.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if total > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, total)
		defer cancel()
	}
	changed := map[int]bool{}
	for _, id := range changedIDs {
		changed[id] = true
	}
	opts := reqproof.Options{Dir: workDir, Base: base, BaseFrom: baseFrom, OnlyChanged: onlyChanged, Changed: changed,
		BeforeOnly: beforeOnly}
	if !asJSON {
		opts.OnProof = func(p requirements.Proof) { printProofLine(p) }
		color.New(color.Faint).Printf("Proving %s: each test runs on the change, then at its base...\n", proofKeys(reqs))
	}
	started := time.Now()
	report, cleanupErr := reqproof.Prove(ctx, reqs, opts)
	if cleanupErr != nil {
		color.New(color.FgYellow).Fprintf(os.Stderr, "⚠ %v — the next proof removes what is left\n", cleanupErr)
	}

	if db != nil && len(report.Results) > 0 {
		run := statedb.RequirementRun{
			RunID: artifact.NewRunID(), State: statedb.RequirementRunDone, Source: "cli", StartedBy: operatorActor(),
			StartedAt: started, ExecutorID: "local", Kind: statedb.RequirementRunKindProve,
		}
		for _, p := range report.Results {
			run.RequirementIDs = append(run.RequirementIDs, p.RequirementID)
		}
		if _, err := db.RecordRequirementProofs(statedb.ProofRecord{RunID: run.RunID, ExecutorID: "local",
			ProvedBy: run.StartedBy}, report.Results); err != nil {
			return fail(fmt.Errorf("record the proofs: %w", err))
		}
		if err := db.RecordFinishedRequirementRun(run); err != nil {
			return fail(fmt.Errorf("record the proof: %w", err))
		}
		statedb.AuditRequirementProof(db, run, report.Results, run.StartedBy)
	}

	if asJSON {
		// The outcomes are in the report: a proof that ran exits 0.
		return clijson.Emit(os.Stdout, report)
	}
	failing := 0
	for _, p := range report.Results {
		switch p.Outcome {
		case requirements.ProofVacuous, requirements.ProofBroken, requirements.ProofError:
			failing++
		}
	}
	if ctx.Err() != nil {
		return errors.New("the proof was stopped")
	}
	if failing > 0 {
		return errRequirementsUnproven
	}
	return nil
}

// resolveProofBase is rev, as a person names a commit, resolved in the
// checkout at dir to the commit's full id.
func resolveProofBase(dir, rev string) (string, error) {
	rev = strings.TrimSpace(rev)
	if rev == "" || strings.HasPrefix(rev, "-") || strings.ContainsAny(rev, " \t\n") {
		return "", fmt.Errorf("--base %q is not a commit", rev)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := gitOutput(ctx, dir, "rev-parse", "--verify", "--quiet", "--end-of-options", rev+"^{commit}")
	sha := strings.TrimSpace(out)
	if err != nil || requirements.CleanCommit(sha) == "" {
		return "", fmt.Errorf("--base %q names no commit in this checkout", rev)
	}
	return sha, nil
}

func proofKeys(reqs []requirements.Requirement) string {
	keys := make([]string, 0, len(reqs))
	for _, r := range reqs {
		keys = append(keys, requirements.Key(r.ID))
	}
	return strings.Join(keys, ", ")
}

func printProofLine(p requirements.Proof) {
	proofColor(p.Outcome).Printf("%-6s %-13s", requirements.Key(p.RequirementID), p.Outcome)
	fmt.Printf(" %s\n", p.Summary)
	for _, side := range []struct {
		name string
		s    requirements.ProofSide
	}{{"base", p.Before}, {"change", p.After}} {
		for _, t := range side.s.Tests {
			if t.Outcome == requirements.OutcomePass {
				continue
			}
			fmt.Printf("       [%s on the %s] %s (exit %d)\n", t.Outcome, side.name,
				requirements.Test{Name: t.Name, Command: t.Command}.Label(), t.ExitCode)
		}
	}
}

func proofColor(outcome string) *color.Color {
	switch outcome {
	case requirements.ProofProven:
		return color.New(color.FgGreen)
	case requirements.ProofVacuous, requirements.ProofBroken:
		return color.New(color.FgRed, color.Bold)
	case requirements.ProofError:
		return color.New(color.FgYellow)
	}
	return color.New(color.Faint)
}
