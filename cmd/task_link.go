package cmd

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	linkLabel string
	linkKind  string
)

var taskLinkCmd = &cobra.Command{
	Use:   "link",
	Short: "Manage external links for a task",
	Long: `Associate external URLs (tickets, PRs, docs, artifacts) with a task.

Subcommands:
  add  <task-id> <url>   Attach a URL to a task
  list <task-id>         Show all links for a task
  rm   <task-id> <index> Remove a link by its 1-based index`,
}

var taskLinkAddCmd = &cobra.Command{
	Use:   "add <task-id> <url>",
	Short: "Add an external link to a task",
	Long: `Attach an external URL to a task with an optional label and kind.

The kind is auto-detected from the URL when not specified:
  github.com/.../issues/... → ticket
  github.com/.../pull/...   → pr
  docs.*                    → doc
  anything else             → artifact

Examples:
  cloop task link add 3 https://github.com/org/repo/issues/42
  cloop task link add 3 https://github.com/org/repo/pull/99 --label "Implementation PR"
  cloop task link add 5 https://docs.example.com/guide --kind doc --label "API Guide"`,
	Args: cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()
		s, err := state.Load(workdir)
		if err != nil {
			return err
		}
		if !s.PMMode || s.Plan == nil {
			return fmt.Errorf("no task plan found — run 'cloop run --pm' to create one")
		}

		id, err := strconv.Atoi(args[0])
		if err != nil {
			return fmt.Errorf("invalid task ID %q: must be a number", args[0])
		}

		var task *pm.Task
		for _, t := range s.Plan.Tasks {
			if t.ID == id {
				task = t
				break
			}
		}
		if task == nil {
			return fmt.Errorf("task %d not found", id)
		}

		rawURL := strings.TrimSpace(args[1])
		if rawURL == "" {
			return fmt.Errorf("URL must not be empty")
		}

		kind := pm.DetectLinkKind(rawURL)
		if linkKind != "" {
			switch pm.LinkKind(linkKind) {
			case pm.LinkKindTicket, pm.LinkKindPR, pm.LinkKindDoc, pm.LinkKindArtifact:
				kind = pm.LinkKind(linkKind)
			default:
				return fmt.Errorf("invalid kind %q: must be one of ticket, pr, doc, artifact", linkKind)
			}
		}

		link := pm.Link{
			URL:   rawURL,
			Label: strings.TrimSpace(linkLabel),
			Kind:  kind,
		}
		task.Links = append(task.Links, link)

		if err := s.Save(); err != nil {
			return fmt.Errorf("saving state: %w", err)
		}

		display := rawURL
		if link.Label != "" {
			display = fmt.Sprintf("%s (%s)", link.Label, rawURL)
		}
		color.New(color.FgGreen).Printf("Link added to task %d [%s]: %s\n", id, kind, display)
		return nil
	},
}

var taskLinkListCmd = &cobra.Command{
	Use:   "list <task-id>",
	Short: "List all external links for a task",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()
		s, err := state.Load(workdir)
		if err != nil {
			return err
		}
		if !s.PMMode || s.Plan == nil {
			return fmt.Errorf("no task plan found — run 'cloop run --pm' to create one")
		}

		id, err := strconv.Atoi(args[0])
		if err != nil {
			return fmt.Errorf("invalid task ID %q: must be a number", args[0])
		}

		var task *pm.Task
		for _, t := range s.Plan.Tasks {
			if t.ID == id {
				task = t
				break
			}
		}
		if task == nil {
			return fmt.Errorf("task %d not found", id)
		}

		titleColor := color.New(color.FgWhite, color.Bold)
		dimColor := color.New(color.Faint)
		kindColor := color.New(color.FgCyan)

		titleColor.Printf("Task %d: %s — %d link(s)\n\n", task.ID, task.Title, len(task.Links))
		if len(task.Links) == 0 {
			dimColor.Printf("  No links yet. Use 'cloop task link add %d <url>' to add one.\n", id)
			return nil
		}

		for i, lnk := range task.Links {
			label := lnk.Label
			if label == "" {
				label = lnk.URL
			}
			kindColor.Printf("  %d. [%s] ", i+1, lnk.Kind)
			fmt.Printf("%s\n", label)
			if lnk.Label != "" {
				dimColor.Printf("       %s\n", lnk.URL)
			}
		}
		return nil
	},
}

var taskLinkRmCmd = &cobra.Command{
	Use:     "rm <task-id> <index>",
	Aliases: []string{"remove", "delete"},
	Short:   "Remove a link from a task by 1-based index",
	Args:    cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		workdir, _ := os.Getwd()
		s, err := state.Load(workdir)
		if err != nil {
			return err
		}
		if !s.PMMode || s.Plan == nil {
			return fmt.Errorf("no task plan found — run 'cloop run --pm' to create one")
		}

		taskID, err := strconv.Atoi(args[0])
		if err != nil {
			return fmt.Errorf("invalid task ID %q: must be a number", args[0])
		}
		idx, err := strconv.Atoi(args[1])
		if err != nil || idx < 1 {
			return fmt.Errorf("invalid index %q: must be a positive number", args[1])
		}

		var task *pm.Task
		for _, t := range s.Plan.Tasks {
			if t.ID == taskID {
				task = t
				break
			}
		}
		if task == nil {
			return fmt.Errorf("task %d not found", taskID)
		}

		if idx > len(task.Links) {
			return fmt.Errorf("index %d out of range: task %d has %d link(s)", idx, taskID, len(task.Links))
		}

		removed := task.Links[idx-1]
		task.Links = append(task.Links[:idx-1], task.Links[idx:]...)

		if err := s.Save(); err != nil {
			return fmt.Errorf("saving state: %w", err)
		}

		color.New(color.FgYellow).Printf("Removed link %d from task %d: %s\n", idx, taskID, removed.URL)
		return nil
	},
}

func init() {
	taskLinkAddCmd.Flags().StringVar(&linkLabel, "label", "", "Human-readable label for the link")
	taskLinkAddCmd.Flags().StringVar(&linkKind, "kind", "", "Link kind: ticket, pr, doc, artifact (auto-detected if omitted)")

	taskLinkCmd.AddCommand(taskLinkAddCmd)
	taskLinkCmd.AddCommand(taskLinkListCmd)
	taskLinkCmd.AddCommand(taskLinkRmCmd)

	// taskLinkCmd is registered to taskCmd in task_cmd.go init()
}
