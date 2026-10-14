package cmd

// task_attachments.go is `cloop task attachments` (Task 20428): the files
// attached to a task — what a run left in its outbox, or what a person
// attached by hand — listed, added, saved out and removed.
//
// Not `cloop task attach`, which opens a shell in a running task's sandbox
// (Task 20265). The two are unrelated and the help text of each says so.

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"
	"unicode"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/blechschmidt/cloop/pkg/attachments"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

var (
	attachmentsJSON  bool
	attachmentsName  string
	attachmentsNote  string
	attachmentsOut   string
	attachmentsForce bool
)

var taskAttachmentsCmd = &cobra.Command{
	Use:     "attachments <task-id>",
	Aliases: []string{"attachment", "files"},
	Short:   "List, add, save and remove the files attached to a task",
	Long: `Files attached to a task: the reports, charts, screenshots, exports and logs a
run made for a person to look at, and files attached by hand.

A run attaches a file by copying it into its task's outbox, which the agent is
told about in its prompt and in $CLOOP_TASK_ATTACHMENTS:

  .cloop/attachments/outbox/<task-id>/

When the attempt ends, every regular file there is attached to the task and the
outbox is emptied. The dashboard shows a task's attachments in its details,
where images and text can be previewed and anything downloaded.

This is not ` + "`cloop task attach`" + `, which opens a shell inside a running task's
sandbox.

Limits: ` + attachments.HumanBytes(attachments.MaxFileBytes) + ` per file, ` +
		strconv.Itoa(attachments.MaxTaskFiles) + ` files and ` + attachments.HumanBytes(attachments.MaxTaskBytes) +
		` per task, ` + attachments.HumanBytes(attachments.MaxProjectBytes) + ` per project.`,
	Example: `  cloop task attachments 12                     # list task 12's attachments
  cloop task attachments add 12 report.html --note "Benchmark results"
  cloop task attachments get 12 report.html -o /tmp/report.html
  cloop task attachments remove 12 3f2a9c1b`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runAttachmentsList(cmd, args[0])
	},
}

var taskAttachmentsListCmd = &cobra.Command{
	Use:     "list <task-id>",
	Aliases: []string{"ls"},
	Short:   "List a task's attachments",
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runAttachmentsList(cmd, args[0])
	},
}

var taskAttachmentsAddCmd = &cobra.Command{
	Use:   "add <task-id> <file>...",
	Short: "Attach files to a task by hand",
	Args:  cobra.MinimumNArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		p, err := openAttachmentProject(args[0])
		if err != nil {
			return err
		}
		defer p.db.Close()
		if attachmentsName != "" && len(args) > 2 {
			return errors.New("--name names one file; attach several without it")
		}
		var added []statedb.AttachmentRow
		for _, path := range args[1:] {
			row, err := attachments.Add(p.db, p.dbPath, p.taskID, path, attachments.Meta{
				Name: attachmentsName, Source: statedb.AttachmentSourceCLI, Note: attachmentsNote,
				AddedBy: operatorActor(), CreatedAt: time.Now(),
			})
			if err != nil {
				return fmt.Errorf("attach %s to task %d: %w", path, p.taskID, err)
			}
			added = append(added, row)
			if !attachmentsJSON {
				color.New(color.FgGreen).Printf("Attached %s to task %d (%s, %s) — %s\n",
					row.Name, p.taskID, attachments.HumanBytes(row.Size), row.MediaType, row.ID)
			}
		}
		if attachmentsJSON {
			return printAttachmentsJSON(added)
		}
		return nil
	},
}

var taskAttachmentsGetCmd = &cobra.Command{
	Use:     "get <task-id> <attachment>",
	Aliases: []string{"save", "export"},
	Short:   "Save an attachment to a file, or print it with -o -",
	Long: `Save an attachment of a task to a file. <attachment> is its id, an id prefix of
at least six characters, or its name. Without -o it is saved under its own name
in the current directory, and an existing file is not overwritten without
--force.`,
	Args: cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		p, err := openAttachmentProject(args[0])
		if err != nil {
			return err
		}
		defer p.db.Close()
		row, err := p.resolve(args[1])
		if err != nil {
			return err
		}
		f, _, err := attachments.Open(p.dbPath, row)
		if err != nil {
			return fmt.Errorf("attachment %s of task %d: %w", row.Name, p.taskID, err)
		}
		defer f.Close()
		if attachmentsOut == "-" {
			_, err := io.Copy(cmd.OutOrStdout(), f)
			return err
		}
		dest := attachmentsOut
		if dest == "" {
			dest = attachments.BaseName(row.Name)
		}
		flags := os.O_WRONLY | os.O_CREATE | os.O_EXCL
		if attachmentsForce {
			flags = os.O_WRONLY | os.O_CREATE | os.O_TRUNC
		}
		out, err := os.OpenFile(dest, flags, 0o644)
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("%s exists — pass --force to overwrite it, or -o to save elsewhere", dest)
		}
		if err != nil {
			return err
		}
		if _, err := io.Copy(out, f); err != nil {
			out.Close()
			return fmt.Errorf("save %s: %w", dest, err)
		}
		if err := out.Close(); err != nil {
			return fmt.Errorf("save %s: %w", dest, err)
		}
		color.New(color.FgGreen).Printf("Saved %s (%s) to %s\n", printable(row.Name), attachments.HumanBytes(row.Size), dest)
		return nil
	},
}

var taskAttachmentsRemoveCmd = &cobra.Command{
	Use:     "remove <task-id> <attachment>",
	Aliases: []string{"rm", "delete"},
	Short:   "Delete an attachment of a task",
	Args:    cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		p, err := openAttachmentProject(args[0])
		if err != nil {
			return err
		}
		defer p.db.Close()
		row, err := p.resolve(args[1])
		if err != nil {
			return err
		}
		p.db.AsProject()
		if _, err := attachments.Delete(p.db, p.taskID, row.ID, operatorActor(), "cloop task attachments remove"); err != nil {
			return err
		}
		color.New(color.FgGreen).Printf("Deleted %s from task %d\n", printable(row.Name), p.taskID)
		return nil
	},
}

// attachmentProject is the project and task an attachments command works on.
type attachmentProject struct {
	workDir string
	dbPath  string
	taskID  int
	db      *statedb.DB
}

// openAttachmentProject opens the project in the working directory and checks
// the task exists.
func openAttachmentProject(taskArg string) (*attachmentProject, error) {
	id, err := strconv.Atoi(strings.TrimPrefix(strings.TrimSpace(taskArg), "#"))
	if err != nil || id <= 0 {
		return nil, fmt.Errorf("invalid task ID %q: must be a positive number", taskArg)
	}
	workDir, err := os.Getwd()
	if err != nil {
		return nil, err
	}
	s, err := state.LoadLite(workDir)
	if err != nil {
		return nil, err
	}
	if s.Plan == nil || s.Plan.TaskByID(id) == nil {
		return nil, fmt.Errorf("task %d not found: %w", id, statedb.ErrTaskNotFound)
	}
	dbPath := state.DBPath(workDir)
	db, err := statedb.Open(dbPath)
	if err != nil {
		return nil, err
	}
	return &attachmentProject{workDir: workDir, dbPath: dbPath, taskID: id, db: db}, nil
}

func (p *attachmentProject) resolve(ref string) (statedb.AttachmentRow, error) {
	rows, err := p.db.TaskAttachments(p.taskID)
	if err != nil {
		return statedb.AttachmentRow{}, err
	}
	row, err := attachments.Resolve(rows, ref)
	if err != nil {
		return row, fmt.Errorf("task %d: %w", p.taskID, err)
	}
	return row, nil
}

func runAttachmentsList(cmd *cobra.Command, taskArg string) error {
	p, err := openAttachmentProject(taskArg)
	if err != nil {
		return err
	}
	defer p.db.Close()
	rows, err := p.db.TaskAttachments(p.taskID)
	if err != nil {
		return err
	}
	if attachmentsJSON {
		return printAttachmentsJSON(rows)
	}
	if len(rows) == 0 {
		fmt.Printf("Task %d has no attachments.\n", p.taskID)
		return nil
	}
	w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tNAME\tSIZE\tTYPE\tADDED\tBY")
	for _, r := range rows {
		name := r.Name
		if r.Unavailable != "" {
			name += " (not on this machine: " + r.Unavailable + ")"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n", r.ID[:12], printable(name), attachments.HumanBytes(r.Size),
			printable(r.MediaType), r.CreatedAt.Local().Format("2006-01-02 15:04"), printable(attachmentAddedBy(r)))
	}
	return w.Flush()
}

// printable makes a value from the project's database safe to print: a row may
// have been written by a workload, and a terminal acts on escape sequences.
func printable(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return '?'
		}
		return r
	}, strings.ToValidUTF8(s, "?"))
}

// attachmentAddedBy says where an attachment came from, for the listing.
func attachmentAddedBy(r statedb.AttachmentRow) string {
	switch {
	case r.Source == statedb.AttachmentSourceRun && r.RunID != "":
		return "run " + r.RunID
	case r.AddedBy != "":
		return r.AddedBy
	}
	return r.Source
}

func printAttachmentsJSON(rows []statedb.AttachmentRow) error {
	if rows == nil {
		rows = []statedb.AttachmentRow{}
	}
	b, err := json.MarshalIndent(rows, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(b))
	return nil
}

func init() {
	taskAttachmentsCmd.PersistentFlags().BoolVar(&attachmentsJSON, "json", false, "Print machine-readable JSON")
	taskAttachmentsAddCmd.Flags().StringVar(&attachmentsName, "name", "", "Attach the file under this name (one file only)")
	taskAttachmentsAddCmd.Flags().StringVar(&attachmentsNote, "note", "", "A note shown with the attachment")
	taskAttachmentsGetCmd.Flags().StringVarP(&attachmentsOut, "output", "o", "", "Where to save it; - prints it to stdout")
	taskAttachmentsGetCmd.Flags().BoolVar(&attachmentsForce, "force", false, "Overwrite an existing file")
	taskAttachmentsCmd.AddCommand(taskAttachmentsListCmd, taskAttachmentsAddCmd, taskAttachmentsGetCmd, taskAttachmentsRemoveCmd)
	taskCmd.AddCommand(taskAttachmentsCmd)
}
