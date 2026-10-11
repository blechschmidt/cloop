package cmd

// `cloop remote` (Task 20412): the projects on a hub, from a terminal signed
// in with `cloop login`.
//
// Every subcommand is one of the dashboard's own calls, made with the
// terminal's session — so each is authorised exactly as the dashboard's button
// would be for the same person: the hub decides, from the session's role on
// the project, and a viewer who presses `cloop remote run` is refused the same
// way their browser's Start button is. Nothing here reads a local .cloop.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/blechschmidt/cloop/pkg/hubclient"
)

var (
	remoteHub   string
	remoteToken string
	remoteJSON  bool

	remoteTaskStatus  string
	remoteDescription string
	remoteFollow      bool
)

var remoteCmd = &cobra.Command{
	Use:   "remote",
	Short: "Work with the projects on a hub from this terminal",
	Long: `Work with the projects on a cloop hub, as the identity this terminal signed in as
with ` + "`cloop login`" + `. Each command is authorised by the hub exactly as the dashboard
would authorise you.

A project is named by its name, its index or its path, as ` + "`cloop remote projects`" + `
lists them. The hub is the default one, or --hub.`,
}

var remoteProjectsCmd = &cobra.Command{
	Use:   "projects",
	Short: "List the projects you can see on the hub",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := remoteClient()
		if err != nil {
			return err
		}
		projects, err := c.Projects(remoteContext(cmd))
		if err != nil {
			return remoteErr(c, err)
		}
		if remoteJSON {
			return json.NewEncoder(os.Stdout).Encode(projects)
		}
		if len(projects) == 0 {
			fmt.Println("You can see no projects on this hub.")
			return nil
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "IDX\tNAME\tSTATUS\tTASKS\tPATH")
		for _, p := range projects {
			status := orDash(p.Status)
			if p.Running {
				status = "running"
			}
			fmt.Fprintf(w, "%d\t%s\t%s\t%d/%d\t%s\n", p.Idx, truncateField(p.Name, 32), status,
				p.DoneTasks, p.TotalTasks, p.Path)
		}
		return w.Flush()
	},
}

var remoteTasksCmd = &cobra.Command{
	Use:   "tasks <project>",
	Short: "List a project's tasks",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := remoteClient()
		if err != nil {
			return err
		}
		ctx := remoteContext(cmd)
		p, err := c.ResolveProject(ctx, args[0])
		if err != nil {
			return remoteErr(c, err)
		}
		tasks, err := c.Tasks(ctx, p.Idx)
		if err != nil {
			return remoteErr(c, err)
		}
		if want := strings.TrimSpace(remoteTaskStatus); want != "" {
			kept := tasks[:0]
			for _, t := range tasks {
				st := t.Status
				if st == "" {
					st = "pending"
				}
				if strings.EqualFold(st, want) {
					kept = append(kept, t)
				}
			}
			tasks = kept
		}
		if remoteJSON {
			return json.NewEncoder(os.Stdout).Encode(tasks)
		}
		if len(tasks) == 0 {
			fmt.Printf("%s has no tasks", p.Name)
			if remoteTaskStatus != "" {
				fmt.Printf(" with status %s", remoteTaskStatus)
			}
			fmt.Println(".")
			return nil
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "ID\tSTATUS\tPRI\tTITLE")
		for _, t := range tasks {
			st := t.Status
			if st == "" {
				st = "pending"
			}
			fmt.Fprintf(w, "%d\t%s\t%d\t%s\n", t.ID, st, t.Priority, truncateField(t.Title, 80))
		}
		return w.Flush()
	},
}

var remoteAddCmd = &cobra.Command{
	Use:   "add <project> <title>",
	Short: "Add a task to a project",
	Args:  cobra.MinimumNArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		title := strings.TrimSpace(strings.Join(args[1:], " "))
		if title == "" {
			return errors.New("a task needs a title")
		}
		c, err := remoteClient()
		if err != nil {
			return err
		}
		ctx := remoteContext(cmd)
		p, err := c.ResolveProject(ctx, args[0])
		if err != nil {
			return remoteErr(c, err)
		}
		t, err := c.AddTask(ctx, p.Idx, title, remoteDescription)
		if err != nil {
			return remoteErr(c, err)
		}
		if remoteJSON {
			return json.NewEncoder(os.Stdout).Encode(t)
		}
		fmt.Printf("Added task #%d to %s: %s\n", t.ID, p.Name, t.Title)
		return nil
	},
}

var remoteRunCmd = &cobra.Command{
	Use:   "run <project>",
	Short: "Start a project's run",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := remoteClient()
		if err != nil {
			return err
		}
		ctx := remoteContext(cmd)
		p, err := c.ResolveProject(ctx, args[0])
		if err != nil {
			return remoteErr(c, err)
		}
		if _, err := c.Run(ctx, p.Idx); err != nil {
			return remoteErr(c, err)
		}
		fmt.Printf("Started %s. Follow it with: cloop remote logs %s --follow\n", p.Name, quoteArg(p.Name))
		return nil
	},
}

var remoteStopCmd = &cobra.Command{
	Use:   "stop <project>",
	Short: "Stop a project's run",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := remoteClient()
		if err != nil {
			return err
		}
		ctx := remoteContext(cmd)
		p, err := c.ResolveProject(ctx, args[0])
		if err != nil {
			return remoteErr(c, err)
		}
		ok, msg, err := c.Stop(ctx, p.Idx)
		if err != nil {
			return remoteErr(c, err)
		}
		if !ok {
			return fmt.Errorf("%s: %s", p.Name, msg)
		}
		if msg == "" {
			msg = "stopping"
		}
		fmt.Printf("%s: %s\n", p.Name, msg)
		return nil
	},
}

var remoteLogsCmd = &cobra.Command{
	Use:   "logs <project>",
	Short: "Print a project's run output, or follow it with --follow",
	Long: `Print what the hub holds of a project's current run output. With --follow, keep
printing as the run produces it, over the dashboard's own live stream, until you
press Ctrl-C — or until the hub ends the stream because your session was revoked
or expired, or your access to the project was withdrawn, in which case the command
says so and exits non-zero.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := remoteClient()
		if err != nil {
			return err
		}
		ctx := remoteContext(cmd)
		p, err := c.ResolveProject(ctx, args[0])
		if err != nil {
			return remoteErr(c, err)
		}
		if !remoteFollow {
			lines, running, err := c.LiveLog(ctx, p.Idx)
			if err != nil {
				return remoteErr(c, err)
			}
			for _, l := range lines {
				fmt.Print(l)
			}
			if len(lines) == 0 {
				state := "not running"
				if running {
					state = "running"
				}
				fmt.Fprintf(os.Stderr, "(no output held for %s; it is %s)\n", p.Name, state)
			}
			return nil
		}
		ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
		defer stop()
		err = c.FollowLogs(ctx, p.Idx, os.Stdout, hubclient.LogEvents{
			RunState: func(running bool) {
				if running {
					fmt.Fprintf(os.Stderr, "[%s: run started]\n", p.Name)
				} else {
					fmt.Fprintf(os.Stderr, "[%s: run stopped]\n", p.Name)
				}
			},
		})
		if errors.Is(err, hubclient.ErrStreamEnded) {
			return fmt.Errorf("%v — if your session ended, run `cloop login %s` again", err, c.Base)
		}
		return remoteErr(c, err)
	},
}

// remoteClient builds the client for the hub the command acts on: --hub, else
// CLOOP_HUB_URL, else the default hub — with --token, or the session
// `cloop login` stored for it, or CLOOP_API_TOKEN where that is the hub's.
//
// CLOOP_API_TOKEN names no hub of its own. Set beside CLOOP_HUB_URL it is that
// hub's token and no other's; set alone it is used for a hub this terminal
// holds no session for, and never instead of one made for the hub — so a
// token exported for one hub does not travel to another named with --hub.
func remoteClient() (*hubclient.Client, error) {
	envHub := strings.TrimSpace(os.Getenv("CLOOP_HUB_URL"))
	hubURL := strings.TrimSpace(remoteHub)
	if hubURL == "" {
		hubURL = envHub
	}
	if token := strings.TrimSpace(remoteToken); token != "" {
		if hubURL == "" {
			return nil, errors.New("--token needs --hub (or CLOOP_HUB_URL) to say which hub it is for")
		}
		return hubclient.New(hubURL, "", token)
	}
	envToken := strings.TrimSpace(os.Getenv("CLOOP_API_TOKEN"))
	if envToken != "" && envHub != "" && sameHub(hubURL, envHub) {
		return hubclient.New(hubURL, "", envToken)
	}
	_, f, err := loadHubCredentials(true)
	if err != nil {
		return nil, err
	}
	if hubURL == "" {
		if hubURL, err = defaultHub(f); err != nil {
			return nil, err
		}
	}
	h, ok := f.Lookup(hubURL)
	if !ok {
		if envToken != "" && envHub == "" {
			return hubclient.New(hubURL, "", envToken)
		}
		norm, nerr := hubclient.NormalizeURL(hubURL)
		if nerr != nil {
			return nil, nerr
		}
		return nil, fmt.Errorf("this terminal is not signed in to %s: run `cloop login %s`", norm, norm)
	}
	return hubclient.New(h.URL, h.CAFile, h.Credential)
}

// remoteErr adds the one remedy a refused credential always has.
func remoteErr(c *hubclient.Client, err error) error {
	if err == nil {
		return nil
	}
	if hubclient.IsUnauthorized(err) {
		return fmt.Errorf("%w — the session has ended: run `cloop login %s` again", err, c.Base)
	}
	return err
}

func remoteContext(cmd *cobra.Command) context.Context {
	if ctx := cmd.Context(); ctx != nil {
		return ctx
	}
	return context.Background()
}

// quoteArg quotes a project name for a command line the user may paste.
func quoteArg(s string) string {
	if s != "" && !strings.ContainsAny(s, " \t'\"\\$`!*?[]{}()<>|&;#~") {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func init() {
	remoteCmd.PersistentFlags().StringVar(&remoteHub, "hub", "",
		"Hub URL (default: the default hub from `cloop login`, or CLOOP_HUB_URL)")
	remoteCmd.PersistentFlags().StringVar(&remoteToken, "token", "",
		"API token to use instead of the stored session (CLOOP_API_TOKEN: for CLOOP_HUB_URL's hub, or one with no stored session)")
	remoteProjectsCmd.Flags().BoolVar(&remoteJSON, "json", false, "Print JSON")
	remoteTasksCmd.Flags().BoolVar(&remoteJSON, "json", false, "Print JSON")
	remoteTasksCmd.Flags().StringVar(&remoteTaskStatus, "status", "",
		"Only tasks with this status (pending, in_progress, done, failed, skipped)")
	remoteAddCmd.Flags().StringVar(&remoteDescription, "description", "", "The task's description")
	remoteAddCmd.Flags().BoolVar(&remoteJSON, "json", false, "Print the new task as JSON")
	remoteLogsCmd.Flags().BoolVarP(&remoteFollow, "follow", "f", false,
		"Keep printing output as the run produces it")

	remoteCmd.AddCommand(remoteProjectsCmd, remoteTasksCmd, remoteAddCmd, remoteRunCmd, remoteStopCmd, remoteLogsCmd)
	rootCmd.AddCommand(remoteCmd)
}
