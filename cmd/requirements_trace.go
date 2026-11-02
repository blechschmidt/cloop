package cmd

// `cloop requirements trace` (Task 20465): the traceability matrix — each
// approved requirement with the tasks that implement it and their states, the
// commits those tasks produced, its latest verdict and how old or stale it is,
// its latest red-green proof, and whether it is tested, assessed or unverified
// — and the spec coverage it adds up to. See pkg/requirements/trace.go.
//
// It reads what the project already records and changes nothing: the
// requirements, checks and proofs from the project's database, a page at a
// time; the plan; and the commit-to-task trace `cloop trace` writes. The
// dashboard's Traceability view and GET /api/requirements/trace read the same.

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/requirements"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
	"github.com/blechschmidt/cloop/pkg/trace"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var requirementsTraceCmd = &cobra.Command{
	Use:   "trace",
	Short: "The traceability matrix: each requirement's tasks, commits, verdict and proof, and the spec coverage",
	Long: `Show, for each approved requirement, the tasks that implement it and the state
each is in, the commits those tasks produced, its latest verdict with its age
and whether it is stale, its latest red-green proof, and whether it is tested,
assessed by the model or a person, or unverified — and the spec coverage they
add up to: how many musts are tested, proven, passing and linked to a task.

The commits are what each task records of its own work, and the ones
'cloop trace' links to it in .cloop/trace.json: run 'cloop trace' first to
link the recent history.

  cloop requirements trace                     # every row, and the coverage
  cloop requirements trace --priority must --gap unlinked
  cloop requirements trace --tag api --json    # for a script
  cloop requirements trace --markdown > TRACEABILITY.md
  cloop requirements trace --csv > trace.csv   # for a spreadsheet
  cloop requirements trace --limit 50 --after 120   # one page

--gap is one of unfulfilled, stale, untested, unlinked, unchecked — or none,
for the requirements with no gap; --priority must, should, could or none.`,
	Args: cobra.NoArgs,
	RunE: runRequirementsTrace,
}

func init() {
	requirementsCmd.AddCommand(requirementsTraceCmd)
	f := requirementsTraceCmd.Flags()
	f.Bool("json", false, "Print JSON: the rows, the coverage and the next page's cursor")
	f.Bool("markdown", false, "Print the coverage and a Markdown table")
	f.Bool("csv", false, "Print the rows as CSV")
	f.String("priority", "", "Only requirements of this priority: must, should, could, or none")
	f.String("tag", "", "Only requirements carrying this tag")
	f.String("gap", "", "Only requirements with this gap: unfulfilled, stale, untested, unlinked, unchecked, or none")
	f.Int("limit", 0, fmt.Sprintf("Rows per page, at most %d (default: every row)", requirements.MaxTracePage))
	f.Int("after", 0, "Start after this requirement id: the cursor a page printed")
}

// projectTrace reads a page of the project's matrix, or every row when limit
// is 0 — a keyset page at a time — with the coverage when after is 0.
func projectTrace(db *statedb.DB, plan requirements.TracePlan, filter requirements.TraceFilter, after, limit int,
	now time.Time) (requirements.TracePage, error) {
	if limit > 0 {
		return requirements.Trace(db, plan, requirements.TraceRequest{Filter: filter, After: after, Limit: limit,
			Coverage: after == 0}, now)
	}
	out, err := requirements.Trace(db, plan, requirements.TraceRequest{Filter: filter, After: after,
		Limit: requirements.MaxTracePage, Coverage: after == 0}, now)
	if err != nil {
		return out, err
	}
	// Bounded by the requirements there are: every page moves the cursor on.
	for next := out.Next; next != 0; {
		page, err := requirements.Trace(db, plan, requirements.TraceRequest{Filter: filter, After: next,
			Limit: requirements.MaxTracePage}, now)
		if err != nil {
			return out, err
		}
		out.Rows = append(out.Rows, page.Rows...)
		if page.Next <= next {
			break
		}
		next = page.Next
	}
	out.Next = 0
	return out, nil
}

// projectCoverage is the spec coverage of the project in workDir, for `cloop
// report`: nil when it has no database or no approved requirement.
func projectCoverage(workDir string, plan *pm.Plan) *requirements.Coverage {
	path := state.DBPath(workDir)
	if fi, err := os.Stat(path); err != nil || !fi.Mode().IsRegular() {
		return nil
	}
	db, err := statedb.Open(path)
	if err != nil {
		return nil
	}
	defer db.Close()
	page, err := requirements.Trace(db.AsProject(), trace.MatrixPlan(workDir, plan), requirements.TraceRequest{Coverage: true},
		time.Now().UTC())
	if err != nil || page.Coverage == nil || page.Coverage.Approved == 0 {
		return nil
	}
	return page.Coverage
}

func runRequirementsTrace(cmd *cobra.Command, _ []string) error {
	f := cmd.Flags()
	asJSON, _ := f.GetBool("json")
	asMarkdown, _ := f.GetBool("markdown")
	asCSV, _ := f.GetBool("csv")
	formats := 0
	for _, on := range []bool{asJSON, asMarkdown, asCSV} {
		if on {
			formats++
		}
	}
	if formats > 1 {
		return fmt.Errorf("--json, --markdown and --csv are alternatives: give one of them")
	}
	priority, _ := f.GetString("priority")
	tag, _ := f.GetString("tag")
	gap, _ := f.GetString("gap")
	filter, err := requirements.ParseTraceFilter(priority, tag, gap)
	if err != nil {
		return err
	}
	limit, _ := f.GetInt("limit")
	after, _ := f.GetInt("after")
	if limit < 0 || limit > requirements.MaxTracePage {
		return fmt.Errorf("--limit is a number of rows from 1 to %d, or 0 for every row", requirements.MaxTracePage)
	}
	if after < 0 {
		return fmt.Errorf("--after is a requirement id")
	}
	p, err := openRequirementsProject()
	if err != nil {
		return err
	}
	defer p.db.Close()
	var plan *pm.Plan
	if p.state != nil {
		plan = p.state.Plan
	}
	now := time.Now().UTC()
	page, err := projectTrace(p.db, trace.MatrixPlan(p.workDir, plan), filter, after, limit, now)
	if err != nil {
		return err
	}
	switch {
	case asJSON:
		return printJSON(struct {
			requirements.TracePage
			Filter      requirements.TraceFilter `json:"filter"`
			GeneratedAt time.Time                `json:"generated_at"`
		}{page, filter, now})
	case asCSV:
		return requirements.WriteTraceCSV(os.Stdout, page.Rows)
	case asMarkdown:
		if err := requirements.WriteTraceMarkdown(os.Stdout, page.Rows, page.Coverage); err != nil {
			return err
		}
		if page.Next != 0 {
			fmt.Printf("\nMore rows follow: cloop requirements trace --markdown --after %d\n", page.Next)
		}
		return nil
	}
	printTraceTerminal(page, filter)
	return nil
}

// printTraceTerminal draws the matrix for a person: the coverage, then a few
// lines per requirement.
func printTraceTerminal(page requirements.TracePage, filter requirements.TraceFilter) {
	bold, dim := color.New(color.Bold), color.New(color.Faint)
	yellow, red, green := color.New(color.FgYellow), color.New(color.FgRed), color.New(color.FgGreen)
	if c := page.Coverage; c != nil {
		bold.Println("Spec coverage")
		for _, l := range c.Lines() {
			fmt.Println("  " + l)
		}
		fmt.Println()
	}
	if len(page.Rows) == 0 {
		if filter != (requirements.TraceFilter{}) {
			fmt.Println("No approved requirement matches the filter.")
		} else {
			fmt.Println("No approved requirements. Add one with: cloop requirements add \"<what must stay true>\" --test \"<command>\"")
		}
		return
	}
	if page.Matched != nil && filter != (requirements.TraceFilter{}) {
		dim.Printf("%d of %d approved requirements match.\n\n", *page.Matched, page.Coverage.Approved)
	}
	for _, r := range page.Rows {
		prio := r.Priority
		if prio == "" {
			prio = "-"
		}
		verdict := r.VerdictLabel()
		paint := dim
		switch {
		case r.Verdict == nil:
		case r.Verdict.Stale != "":
			paint = yellow
		case r.Verdict.Verdict == requirements.VerdictFulfilled:
			paint = green
		case r.Verdict.Verdict == requirements.VerdictUnfulfilled || r.Verdict.Verdict == requirements.VerdictError:
			paint = red
		}
		fmt.Printf("%-6s %-7s %-16s ", r.Key(), prio, r.Verification)
		paint.Printf("%s", verdict)
		fmt.Printf("  proof: %s\n", r.ProofLabel())
		fmt.Printf("       %s\n", r.Title)
		tasks := make([]string, 0, len(r.Tasks))
		for _, t := range r.Tasks {
			tasks = append(tasks, t.Label())
		}
		if r.TasksOmitted > 0 {
			tasks = append(tasks, fmt.Sprintf("+%d more", r.TasksOmitted))
		}
		if len(tasks) == 0 {
			tasks = []string{"none"}
		}
		dim.Printf("       tasks: %s\n", strings.Join(tasks, "; "))
		if len(r.Commits) > 0 {
			commits := make([]string, 0, len(r.Commits))
			for _, c := range r.Commits {
				h := c.Hash
				if len(h) > 10 {
					h = h[:10]
				}
				commits = append(commits, fmt.Sprintf("%s #%d", h, c.TaskID))
			}
			if r.CommitsOmitted > 0 {
				commits = append(commits, fmt.Sprintf("+%d more", r.CommitsOmitted))
			}
			dim.Printf("       commits: %s\n", strings.Join(commits, "; "))
		}
		if v := r.Verdict; v != nil && v.Task != nil {
			dim.Printf("       checked for task %s\n", v.Task.Label())
		}
		if len(r.Gaps) > 0 {
			yellow.Printf("       open: %s\n", strings.Join(r.Gaps, ", "))
		}
	}
	if page.Next != 0 {
		dim.Printf("\nMore rows follow: cloop requirements trace --after %d\n", page.Next)
	}
}
