package cmd

// `cloop requirements export`, `import` and `validate` (Task 20459): the
// project's requirements as code, in .cloop/requirements.yaml beside the code
// they govern. The format is pkg/requirements/specfile.go, the three-way merge
// pkg/requirements/merge.go, and the base it merges against statedb's
// requirement_spec_base.
//
// `validate --json` is also how the hub reads a project's spec file: it never
// opens the file on its own host, but dispatches this command to the project's
// executor and parses the bytes it prints. Like `check --file`, validate needs
// neither a hub nor a project database, so the root command does not reconcile
// executors for it (readsOnlyItsFiles).

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/blechschmidt/cloop/pkg/clijson"
	"github.com/blechschmidt/cloop/pkg/requirements"
	"github.com/blechschmidt/cloop/pkg/statedb"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var requirementsExportCmd = &cobra.Command{
	Use:   "export",
	Short: "Write the requirements to the spec file, " + requirements.SpecFileName,
	Long: `Write the project's requirements — drafts, approved and deprecated — to its spec
file, to be reviewed and committed beside the code. The file is written whole,
sorted by id, in one fixed layout, so a change to one requirement changes only
its own lines; comments in a file written by hand are not kept.

Export refuses to overwrite a file that holds changes the hub does not have — a
requirement changed, added or deleted in the file since the last import or
export — and names them: import them first, or pass --force to discard them.
--file - prints the file instead of writing it.`,
	Args: cobra.NoArgs,
	RunE: runRequirementsExport,
}

var requirementsImportCmd = &cobra.Command{
	Use:   "import",
	Short: "Merge the spec file's changes into the requirements",
	Long: `Merge the project's requirements spec file into its requirements three ways:
against what the file and the hub last agreed on, at the last import or export,
so a change made on one side only is that side's. A requirement changed in the
file is changed here, one added is added under its id, and one deleted is
deleted with the history of its checks; a change made here alone is left for
the next export.

A requirement both sides changed in the same field, or one side deleted while
the other changed it, is a conflict: it is listed, and nothing is imported
until every conflict is settled — with --resolve R-<n>=file|hub for one, or
--prefer file|hub for all. A requirement the file adds under the id of one that
was deleted is refused: an id names one requirement for good. --dry-run lists
what an import would do and does nothing.`,
	Args: cobra.NoArgs,
	RunE: runRequirementsImport,
}

var requirementsValidateCmd = &cobra.Command{
	Use:   "validate",
	Short: "Check the spec file, and say what is wrong on which line",
	Long: `Read the project's requirements spec file (` + requirements.SpecFileName + `, or --file) as
import and check --file read it, and report every problem with the line it is
on: an unknown key, a key or an id given twice, a field past its bounds. Exits 1
when the file is missing or invalid. Needs no hub and no project database.

With --json it prints the file itself, framed, with the commit of the checkout
and whether git has it changed or ignores it. That is how the hub reads a
project's spec file: on the project's executor, never on its own host.`,
	Args: cobra.NoArgs,
	RunE: runRequirementsValidate,
}

func init() {
	requirementsExportCmd.Flags().String("file", "", "Where to write it (default "+requirements.SpecFileName+"); - prints it")
	requirementsExportCmd.Flags().Bool("force", false, "Overwrite a file that has changes the hub does not")
	f := requirementsImportCmd.Flags()
	f.String("file", "", "The spec file to import (default "+requirements.SpecFileName+")")
	f.Bool("dry-run", false, "List what the import would do, and do nothing")
	f.StringArray("resolve", nil, "Settle a conflict: R-<n>=file takes the file's version, R-<n>=hub keeps the hub's (repeatable)")
	f.String("prefer", "", "Settle every conflict not named by --resolve: file or hub")
	f.Bool("json", false, "Print the plan and what was done as JSON")
	requirementsValidateCmd.Flags().String("file", "", "The spec file to check (default "+requirements.SpecFileName+")")
	requirementsValidateCmd.Flags().Bool("json", false, "Print the file and what was found, framed, for the hub")
}

// readsOnlyItsFiles reports whether cmd, as invoked, works from the files it
// is given alone: `cloop requirements validate`, and `check --file`. A plain
// CI job runs them in a checkout with no .cloop/state.db, and reconciling
// executors — which opens that database, creating it — would leave one behind.
func readsOnlyItsFiles(cmd *cobra.Command) bool {
	switch cmd {
	case requirementsValidateCmd:
		return true
	case requirementsCheckCmd:
		return cmd.Flags().Changed("file")
	}
	return false
}

// specPath is the spec file a command was pointed at.
func specPath(name string) string {
	if name == "" {
		return requirements.SpecFileName
	}
	return name
}

// specFileErrors is a spec file's problems, each named as an editor and a CI
// annotation read them: path:line:column: message.
type specFileErrors struct {
	path string
	errs requirements.SpecErrors
}

func (e *specFileErrors) Error() string {
	var b strings.Builder
	if len(e.errs) == 1 {
		fmt.Fprintf(&b, "%s is not a valid requirements spec:", e.path)
	} else {
		fmt.Fprintf(&b, "%s is not a valid requirements spec (%d problems):", e.path, len(e.errs))
	}
	for _, se := range e.errs {
		loc := e.path
		if se.Line > 0 {
			loc += ":" + strconv.Itoa(se.Line)
			if se.Column > 0 {
				loc += ":" + strconv.Itoa(se.Column)
			}
		}
		fmt.Fprintf(&b, "\n  %s: %s", loc, se.Message)
	}
	return b.String()
}

func (e *specFileErrors) Unwrap() error { return e.errs }

// specFileErr names path in what reading or parsing it found.
func specFileErr(name string, err error) error {
	path := specPath(name)
	var errs requirements.SpecErrors
	switch {
	case errors.As(err, &errs):
		return &specFileErrors{path: path, errs: errs}
	case errors.Is(err, requirements.ErrNoSpecFile):
		return fmt.Errorf("%w at %s: write one, or export the project's requirements to it with `cloop requirements export`",
			requirements.ErrNoSpecFile, path)
	}
	return fmt.Errorf("read %s: %w", path, err)
}

func runRequirementsValidate(cmd *cobra.Command, _ []string) error {
	name, _ := cmd.Flags().GetString("file")
	asJSON, _ := cmd.Flags().GetBool("json")
	workDir, err := os.Getwd()
	if err != nil {
		if asJSON {
			return failFramed(err)
		}
		return err
	}
	path := specPath(name)
	data, readErr := requirements.ReadSpecFile(workDir, name)

	if asJSON {
		rep := requirements.SpecFileReport{Path: path}
		var errs requirements.SpecErrors
		switch {
		case errors.Is(readErr, requirements.ErrNoSpecFile):
		case errors.As(readErr, &errs):
			// There, but not to be sent: a directory, or past the size bound.
			rep.Found, rep.Errors = true, errs
		case readErr != nil:
			return failFramed(fmt.Errorf("read %s: %w", path, readErr))
		default:
			rep.Found, rep.Content = true, data
			if f, err := requirements.ParseSpecFile(data); err != nil {
				var errs requirements.SpecErrors
				if errors.As(err, &errs) {
					rep.Errors = errs
				}
			} else {
				rep.Valid, rep.Count = true, len(f.Requirements)
			}
		}
		if rep.Found {
			rep.Commit, rep.Dirty, rep.Ignored = requirements.SpecFileGit(context.Background(), workDir, path)
		}
		return clijson.Emit(os.Stdout, rep)
	}

	if readErr != nil {
		return specFileErr(name, readErr)
	}
	f, err := requirements.ParseSpecFile(data)
	if err != nil {
		return specFileErr(name, err)
	}
	color.New(color.FgGreen).Printf("%s is valid: ", path)
	fmt.Println(describeSpecFile(f))
	if _, _, ignored := requirements.SpecFileGit(context.Background(), workDir, path); ignored {
		warnIgnored(path)
	}
	return nil
}

// describeSpecFile says what a spec file holds: "12 requirements — 9
// approved, 2 draft, 1 deprecated".
func describeSpecFile(f requirements.SpecFile) string {
	n := len(f.Requirements)
	what := fmt.Sprintf("%d requirements", n)
	if n == 1 {
		what = "1 requirement"
	}
	counts := f.Counts()
	var parts []string
	for _, s := range requirements.Statuses {
		if counts[s] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", counts[s], s))
		}
	}
	if len(parts) == 0 {
		return what
	}
	return what + " — " + strings.Join(parts, ", ")
}

// warnIgnored says that git will not carry the spec file anywhere.
func warnIgnored(path string) {
	color.New(color.FgYellow).Fprintf(os.Stderr, "warning: git ignores %s, so it reaches no other checkout. "+
		"If .gitignore names .cloop/, name .cloop/* instead and add !%s.\n", path, path)
}

func runRequirementsExport(cmd *cobra.Command, _ []string) error {
	name, _ := cmd.Flags().GetString("file")
	force, _ := cmd.Flags().GetBool("force")
	p, err := openRequirementsProject()
	if err != nil {
		return err
	}
	defer p.db.Close()
	reqs, err := p.db.Requirements()
	if err != nil {
		return err
	}
	out, err := requirements.RenderSpecFile(reqs)
	if err != nil {
		return fmt.Errorf("export: %w", err)
	}
	if name == "-" {
		_, err := os.Stdout.Write(out)
		return err
	}
	path := specPath(name)

	// The file may hold work the hub has not seen: overwriting it would lose
	// it without a word.
	existing, data, err := requirements.LoadSpecFile(p.workDir, name)
	switch {
	case errors.Is(err, requirements.ErrNoSpecFile):
	case err != nil && !force:
		return fmt.Errorf("%w\nFix it, or pass --force to overwrite it with the hub's requirements", specFileErr(name, err))
	case err == nil && !force:
		snap, err := p.db.RequirementSpecSnapshot()
		if err != nil {
			return err
		}
		plan := requirements.Merge(snap.Base, snap.Hub, existing.Requirements, snap.Assigned)
		if plan.Imports+plan.Conflicts+plan.Refused > 0 {
			fmt.Printf("%s has changes the hub does not:\n", path)
			for _, c := range plan.Changes {
				if c.Kind != requirements.ChangeExport {
					printSpecChange(c)
				}
			}
			return fmt.Errorf("nothing was exported: import those changes first (cloop requirements import), " +
				"or pass --force to overwrite them")
		}
	}

	if err := requirements.WriteSpecFile(p.workDir, name, out); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	commit, _, ignored := requirements.SpecFileGit(context.Background(), p.workDir, path)
	if err := p.db.RecordRequirementSpecExport(reqs, statedb.RequirementSpecSync{
		Actor: operatorActor(), Source: "cli", Path: path, SHA256: requirements.SpecSHA256(out), Commit: commit,
	}); err != nil {
		return fmt.Errorf("the file is written, but recording the export failed: %w", err)
	}
	f, _ := requirements.ParseSpecFile(out)
	if bytes.Equal(data, out) {
		fmt.Printf("%s already holds the requirements: %s.\n", path, describeSpecFile(f))
	} else {
		color.New(color.FgGreen, color.Bold).Printf("Wrote %s: ", path)
		fmt.Printf("%s. Commit it to keep them beside the code.\n", describeSpecFile(f))
	}
	if ignored {
		warnIgnored(path)
	}
	return nil
}

// parseResolutions reads --resolve R-<n>=file|hub settlements.
func parseResolutions(given []string) (map[int]string, error) {
	out := map[int]string{}
	for _, g := range given {
		key, how, ok := strings.Cut(g, "=")
		if !ok {
			return nil, fmt.Errorf("--resolve %q: write R-<n>=file or R-<n>=hub", g)
		}
		id, err := parseRequirementID(key)
		if err != nil {
			return nil, fmt.Errorf("--resolve %q: %w", g, err)
		}
		how = strings.ToLower(strings.TrimSpace(how))
		if how != requirements.TakeFile && how != requirements.KeepHub {
			return nil, fmt.Errorf("--resolve %q: settle it with file (the file's version) or hub (the hub's)", g)
		}
		out[id] = how
	}
	return out, nil
}

func runRequirementsImport(cmd *cobra.Command, _ []string) error {
	f := cmd.Flags()
	name, _ := f.GetString("file")
	dryRun, _ := f.GetBool("dry-run")
	asJSON, _ := f.GetBool("json")
	given, _ := f.GetStringArray("resolve")
	prefer, _ := f.GetString("prefer")
	prefer = strings.ToLower(strings.TrimSpace(prefer))
	if prefer != "" && prefer != requirements.TakeFile && prefer != requirements.KeepHub {
		return fmt.Errorf("--prefer is file or hub, not %q", prefer)
	}
	resolutions, err := parseResolutions(given)
	if err != nil {
		return err
	}
	p, err := openRequirementsProject()
	if err != nil {
		return err
	}
	defer p.db.Close()
	path := specPath(name)
	sf, data, err := requirements.LoadSpecFile(p.workDir, name)
	if err != nil {
		return specFileErr(name, err)
	}
	commit, _, _ := requirements.SpecFileGit(context.Background(), p.workDir, path)
	in := statedb.RequirementSpecImport{
		File: sf.Requirements, Resolutions: resolutions,
		Sync: statedb.RequirementSpecSync{
			Actor: operatorActor(), Source: "cli", Path: path, SHA256: requirements.SpecSHA256(data), Commit: commit,
		},
	}
	// --prefer settles what the plan finds in conflict; the import is then
	// held to that plan, should the hub change in between.
	if prefer != "" {
		plan, err := p.db.ImportRequirementSpec(statedb.RequirementSpecImport{File: sf.Requirements, DryRun: true,
			Resolutions: map[int]string{}})
		var cerr *requirements.ConflictError
		if err != nil && !errors.As(err, &cerr) {
			return err
		}
		for _, c := range plan.Plan.Changes {
			if _, named := resolutions[c.ID]; c.Kind == requirements.ChangeConflict && !named {
				resolutions[c.ID] = prefer
			}
		}
		in.Digest = plan.Plan.Digest
	}
	in.DryRun = dryRun
	res, err := p.db.ImportRequirementSpec(in)
	var cerr *requirements.ConflictError
	if err != nil && !errors.As(err, &cerr) {
		return err
	}
	if asJSON {
		if perr := printJSON(map[string]any{
			"path": path, "sha256": in.Sync.SHA256, "plan": res.Plan, "steps": res.Steps,
			"applied": err == nil && !dryRun,
		}); perr != nil {
			return perr
		}
		return err
	}

	plan := res.Plan
	fmt.Printf("%s: %s; %d in sync with the hub.\n", path, describeSpecFile(sf), plan.InSync)
	for _, c := range plan.Changes {
		printSpecChange(c)
	}
	if err != nil {
		if len(cerr.Unresolved) > 0 {
			color.New(color.Faint).Println("Settle each conflict with --resolve R-<n>=file|hub, or every one with --prefer file|hub.")
		}
		return err
	}
	counts := map[string]int{}
	for _, s := range res.Steps {
		counts[s.Action]++
	}
	var did []string
	for _, a := range []string{requirements.ActionAdd, requirements.ActionRestore, requirements.ActionUpdate, requirements.ActionDelete} {
		if counts[a] > 0 {
			did = append(did, fmt.Sprintf("%d %s", counts[a], pastTense(a)))
		}
	}
	switch {
	case dryRun && len(did) > 0:
		fmt.Printf("An import would leave %s. Nothing was imported (--dry-run).\n", strings.Join(did, ", "))
	case dryRun:
		fmt.Println("An import would change nothing. Nothing was imported (--dry-run).")
	case len(did) > 0:
		color.New(color.FgGreen, color.Bold).Printf("Imported: %s.\n", strings.Join(did, ", "))
	case plan.Exports > 0:
		fmt.Println("Nothing to import.")
	default:
		fmt.Println("Nothing to import: the file and the hub agree.")
	}
	if plan.Exports > 0 {
		fmt.Printf("The hub has %d change(s) the file does not: write them to it with `cloop requirements export`.\n", plan.Exports)
	}
	return nil
}

func pastTense(action string) string {
	switch action {
	case requirements.ActionAdd:
		return "added"
	case requirements.ActionRestore:
		return "restored"
	case requirements.ActionUpdate:
		return "updated"
	}
	return "deleted"
}

// printSpecChange prints one line of a merge plan.
func printSpecChange(c requirements.Change) {
	label, how := c.Kind, color.New(color.FgGreen)
	switch c.Kind {
	case requirements.ChangeExport:
		how = color.New(color.Faint)
	case requirements.ChangeConflict:
		label, how = "CONFLICT", color.New(color.FgRed, color.Bold)
	case requirements.ChangeRefused:
		label, how = "REFUSED", color.New(color.FgRed, color.Bold)
	}
	how.Printf("  %-6s %-9s %-8s", requirements.Key(c.ID), label, c.Action)
	reason := c.Reason
	if c.Stales {
		reason += " (its verdicts go stale)"
	}
	fmt.Printf(" %s\n", reason)
}
