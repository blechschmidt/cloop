package cmd

// cloop adr — Architectural Decision Records.
//
// The decision journal in pkg/journal records why one *task* went the way it
// did; it is per-task, append-only, and scoped to a run. An ADR records why the
// *project* is shaped the way it is, outlives every task that motivated it, and
// carries a lifecycle — a decision can be accepted, later deprecated, or
// superseded by a better one, and the record has to say so. Neither replaces
// the other, and docs/ is where the result gets read.

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/blechschmidt/cloop/pkg/adr"
)

var (
	adrNewBody     string
	adrNewDeciders string
	adrNewTags     string
	adrNewStatus   string
	adrListStatus  string
	adrListJSON    bool
	adrShowJSON    bool
)

var adrCmd = &cobra.Command{
	Use:   "adr",
	Short: "Record architectural decisions",
	Long: `Manage Architectural Decision Records.

An ADR captures one significant design choice: the context that forced it, the
decision itself, and the consequences that follow. Records live as markdown
with YAML frontmatter in .cloop/adr/ so they review in a pull request and
travel with the repository.

A decision is never edited away. It is accepted, deprecated, or superseded by a
later record, and both sides of a supersession are linked so the history stays
readable.

  cloop adr new "Use SQLite for state" --deciders alice,bob
  cloop adr list --status Accepted
  cloop adr show 1
  cloop adr status 1 accepted
  cloop adr supersede 7 1`,
}

var adrNewCmd = &cobra.Command{
	Use:   "new <title>",
	Short: "Create a new decision record",
	Args:  cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()
		title := strings.Join(args, " ")

		body := adrNewBody
		if body == "-" {
			data, err := io.ReadAll(cmd.InOrStdin())
			if err != nil {
				return fmt.Errorf("reading body from stdin: %w", err)
			}
			body = string(data)
		}

		// Validate before writing anything, so a typo does not leave a
		// half-configured record on disk that the caller then has to clean up.
		status := ""
		if adrNewStatus != "" {
			var err error
			if status, err = adr.ParseStatus(adrNewStatus); err != nil {
				return err
			}
		}

		record, err := adr.Create(workdir, title, body)
		if err != nil {
			return fmt.Errorf("creating ADR: %w", err)
		}

		deciders := splitCommaList(adrNewDeciders)
		tags := splitCommaList(adrNewTags)
		if len(deciders) > 0 || len(tags) > 0 || status != "" {
			record.Deciders = deciders
			record.Tags = tags
			if status != "" {
				record.Status = status
			}
			if err := record.Save(); err != nil {
				return fmt.Errorf("saving ADR metadata: %w", err)
			}
		}

		color.New(color.FgGreen, color.Bold).Printf("Created ADR-%04d: %s\n", record.ID, record.Title)
		color.New(color.Faint).Println(record.Path)
		return nil
	},
}

var adrListCmd = &cobra.Command{
	Use:   "list",
	Short: "List decision records",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()

		records, err := adr.List(workdir)
		if err != nil {
			return fmt.Errorf("listing ADRs: %w", err)
		}

		if adrListStatus != "" {
			want, err := adr.ParseStatus(adrListStatus)
			if err != nil {
				return err
			}
			filtered := records[:0]
			for _, r := range records {
				if strings.EqualFold(r.Status, want) {
					filtered = append(filtered, r)
				}
			}
			records = filtered
		}

		if adrListJSON {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(records)
		}

		if len(records) == 0 {
			color.New(color.Faint).Println("No decision records. Create one with: cloop adr new \"<title>\"")
			return nil
		}

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "ID\tSTATUS\tDATE\tTITLE\t")
		for _, r := range records {
			date := ""
			if !r.Date.IsZero() {
				date = r.Date.Format("2006-01-02")
			}
			title := r.Title
			if len(r.SupersededBy) > 0 {
				title += fmt.Sprintf(" (superseded by %s)", joinIDs(r.SupersededBy))
			}
			fmt.Fprintf(w, "%04d\t%s\t%s\t%s\t\n", r.ID, colorStatus(r.Status), date, title)
		}
		return w.Flush()
	},
}

var adrShowCmd = &cobra.Command{
	Use:   "show <id>",
	Short: "Show one decision record",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()

		id, err := strconv.Atoi(args[0])
		if err != nil {
			return fmt.Errorf("invalid ADR id %q: %w", args[0], err)
		}
		record, err := adr.FindByID(workdir, id)
		if err != nil {
			return err
		}

		if adrShowJSON {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(record)
		}

		bold := color.New(color.Bold)
		faint := color.New(color.Faint)

		bold.Printf("ADR-%04d: %s\n", record.ID, record.Title)
		fmt.Printf("  status       %s\n", colorStatus(record.Status))
		if !record.Date.IsZero() {
			fmt.Printf("  date         %s\n", record.Date.Format("2006-01-02"))
		}
		if len(record.Deciders) > 0 {
			fmt.Printf("  deciders     %s\n", strings.Join(record.Deciders, ", "))
		}
		if len(record.Tags) > 0 {
			fmt.Printf("  tags         %s\n", strings.Join(record.Tags, ", "))
		}
		if len(record.Supersedes) > 0 {
			fmt.Printf("  supersedes   %s\n", joinIDs(record.Supersedes))
		}
		if len(record.SupersededBy) > 0 {
			fmt.Printf("  superseded   by %s\n", joinIDs(record.SupersededBy))
		}
		faint.Printf("  file         %s\n", record.Path)
		fmt.Println()
		fmt.Println(strings.TrimRight(record.Body, "\n"))
		return nil
	},
}

var adrStatusCmd = &cobra.Command{
	Use:   "status <id> <status>",
	Short: "Set the status of a decision record",
	Long: "Set the status of a decision record.\n\nValid statuses: " +
		strings.Join(adr.Statuses(), ", ") + ".\n\n" +
		"To mark a record superseded, prefer `cloop adr supersede`, which also\n" +
		"links the record that replaced it.",
	Args: cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()

		id, err := strconv.Atoi(args[0])
		if err != nil {
			return fmt.Errorf("invalid ADR id %q: %w", args[0], err)
		}
		status, err := adr.ParseStatus(args[1])
		if err != nil {
			return err
		}
		record, err := adr.FindByID(workdir, id)
		if err != nil {
			return err
		}
		if err := record.SetStatus(status); err != nil {
			return fmt.Errorf("setting status: %w", err)
		}

		color.New(color.FgGreen).Printf("ADR-%04d is now %s\n", record.ID, status)
		return nil
	},
}

var adrSupersedeCmd = &cobra.Command{
	Use:   "supersede <new-id> <old-id>",
	Short: "Record that one decision replaces another",
	Long: `Record that one decision replaces another.

Both files are updated: the new record gains a supersedes link, and the old one
gains the reverse link and moves to ` + adr.StatusSuperseded + `. The old record
is never deleted — the reason a decision was reversed is usually worth more
than the decision itself.`,
	Args: cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()

		newID, err := strconv.Atoi(args[0])
		if err != nil {
			return fmt.Errorf("invalid new ADR id %q: %w", args[0], err)
		}
		oldID, err := strconv.Atoi(args[1])
		if err != nil {
			return fmt.Errorf("invalid old ADR id %q: %w", args[1], err)
		}
		if err := adr.LinkSupersedes(workdir, newID, oldID); err != nil {
			return err
		}

		color.New(color.FgGreen).Printf("ADR-%04d supersedes ADR-%04d\n", newID, oldID)
		return nil
	},
}

// colorStatus renders a status for a tabwriter cell. Colour is applied with
// Sprint rather than Printf so the escape codes live inside the cell and do
// not throw off the column widths tabwriter computes.
func colorStatus(status string) string {
	switch status {
	case adr.StatusAccepted:
		return color.New(color.FgGreen).Sprint(status)
	case adr.StatusProposed:
		return color.New(color.FgYellow).Sprint(status)
	case adr.StatusRejected:
		return color.New(color.FgRed).Sprint(status)
	case adr.StatusSuperseded, adr.StatusDeprecated:
		return color.New(color.Faint).Sprint(status)
	default:
		return status
	}
}

func joinIDs(ids []int) string {
	parts := make([]string, len(ids))
	for i, id := range ids {
		parts[i] = fmt.Sprintf("ADR-%04d", id)
	}
	return strings.Join(parts, ", ")
}

func splitCommaList(v string) []string {
	if strings.TrimSpace(v) == "" {
		return nil
	}
	var out []string
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func init() {
	adrNewCmd.Flags().StringVar(&adrNewBody, "body", "", "Record body in markdown, or - to read stdin")
	adrNewCmd.Flags().StringVar(&adrNewDeciders, "deciders", "", "Comma-separated list of deciders")
	adrNewCmd.Flags().StringVar(&adrNewTags, "tags", "", "Comma-separated list of tags")
	adrNewCmd.Flags().StringVar(&adrNewStatus, "status", "", "Initial status (default "+adr.StatusProposed+")")

	adrListCmd.Flags().StringVar(&adrListStatus, "status", "", "Only show records with this status")
	adrListCmd.Flags().BoolVar(&adrListJSON, "json", false, "Output as JSON")

	adrShowCmd.Flags().BoolVar(&adrShowJSON, "json", false, "Output as JSON")

	adrCmd.AddCommand(adrNewCmd, adrListCmd, adrShowCmd, adrStatusCmd, adrSupersedeCmd)
	rootCmd.AddCommand(adrCmd)
}
