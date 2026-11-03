package cmd

// `cloop knowledge` (Task 20470): a hub's knowledge sources from a terminal
// signed in with `cloop login`, or holding an API token — the sources you can
// see and how their syncs are going, a sync of one now, and a search of what
// a project's sources hold.
//
// Every subcommand is one of the dashboard's own calls, made with the
// terminal's credential, so the hub decides exactly as it would for the
// dashboard: an administrator may sync any source and a person their own; a
// project's search reads only the sources bound to it. Nothing here reads a
// local .cloop.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/blechschmidt/cloop/pkg/hubclient"
	"github.com/blechschmidt/cloop/pkg/knowledgerun"
	"github.com/blechschmidt/cloop/pkg/pm"
)

var (
	knowledgeJSON     bool
	knowledgeWait     bool
	knowledgeK        int
	knowledgeMaxBytes int
)

// knowledgePoll is how often `cloop knowledge sync --wait` reads the source.
var knowledgePoll = 2 * time.Second

var knowledgeCmd = &cobra.Command{
	Use:   "knowledge",
	Short: "Work with a hub's knowledge sources from this terminal",
	Long: `Work with the knowledge sources a cloop hub indexes — Confluence spaces, Jira
projects — as the identity this terminal signed in as with ` + "`cloop login`" + `, or with
an API token. Each command is authorised by the hub exactly as the dashboard
would authorise you.

A source is named by its id or its name, as ` + "`cloop knowledge sources`" + ` lists them; a
project by its name, its index or its path, as ` + "`cloop remote projects`" + ` lists them.
The hub is the default one, or --hub.`,
}

var knowledgeSourcesCmd = &cobra.Command{
	Use:   "sources",
	Short: "List the knowledge sources you can see, and how their syncs are going",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := remoteClient()
		if err != nil {
			return err
		}
		list, err := c.KnowledgeSources(remoteContext(cmd))
		if err != nil {
			return remoteErr(c, err)
		}
		out := cmd.OutOrStdout()
		if knowledgeJSON {
			return json.NewEncoder(out).Encode(list)
		}
		if len(list.Sources) == 0 {
			fmt.Fprintln(out, "You can see no knowledge sources on this hub.")
			return nil
		}
		now := time.Now()
		w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "ID\tNAME\tKIND\tSCOPE\tSTATUS\tDOCS\tLAST SYNC\tNEXT")
		var failed []hubclient.KnowledgeSource
		for _, s := range list.Sources {
			fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\t%d\t%s\t%s\n", s.ID, truncateField(s.Name, 32), s.Kind,
				knowledgeScope(s), knowledgeStatus(s), s.Documents, knowledgeWhen(s.Sync.At, now),
				knowledgeNext(s, now))
			if s.Sync.Status == "error" && s.Sync.Error != "" {
				failed = append(failed, s)
			}
		}
		if err := w.Flush(); err != nil {
			return err
		}
		for _, s := range failed {
			fmt.Fprintf(out, "\n%s (%d): %s\n", s.Name, s.ID, s.Sync.Error)
		}
		return nil
	},
}

var knowledgeSyncCmd = &cobra.Command{
	Use:   "sync <source>",
	Short: "Sync a knowledge source now",
	Long: `Ask the hub to sync a knowledge source now, rather than at its next scheduled
sync. An administrator may sync any source; you may sync your own personal ones.
The sync runs on the hub; with --wait this command follows it to its end, says
what it did, and exits non-zero if it failed. A source already syncing — on any
hub member — is not synced twice: the command says which sync is running, and
with --wait follows that one.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := remoteClient()
		if err != nil {
			return err
		}
		ctx, stop := signal.NotifyContext(remoteContext(cmd), os.Interrupt, syscall.SIGTERM)
		defer stop()
		src, err := c.ResolveKnowledgeSource(ctx, args[0])
		if err != nil {
			return remoteErr(c, err)
		}
		out := cmd.OutOrStdout()
		_, running, err := c.SyncKnowledgeSource(ctx, src.ID)
		if ae, ok := hubclient.AsAPIError(err); ok && ae.Status == http.StatusConflict {
			r := runningFrom(ae.Details["running"])
			if r == nil || !knowledgeWait {
				return remoteErr(c, err)
			}
			running = r
			fmt.Fprintf(out, "A %s sync of %s is already running on %s; following it.\n", r.Origin, src.Name, r.Member)
		} else if err != nil {
			return remoteErr(c, err)
		} else if running == nil {
			return fmt.Errorf("the hub started a sync of %s but did not say which; see cloop knowledge sources", src.Name)
		} else {
			fmt.Fprintf(out, "Syncing %s on %s.\n", src.Name, orDash(running.Member))
		}
		if !knowledgeWait {
			fmt.Fprintln(out, "Follow it with: cloop knowledge sources")
			return nil
		}
		ended, err := waitForKnowledgeSync(ctx, c, src.ID, running)
		if err != nil {
			return remoteErr(c, err)
		}
		if knowledgeJSON {
			return json.NewEncoder(out).Encode(ended)
		}
		return reportKnowledgeSync(out, ended)
	},
}

var knowledgeSearchCmd = &cobra.Command{
	Use:   "search <project> <query...>",
	Short: "Search the knowledge sources bound to a project",
	Long: `Search what the knowledge sources bound to a project hold, best matches first.
The hub ranks by the query's words — a word ending in * matches a prefix — and,
with its knowledge.embeddings on, by their meaning too. A search that could not
use meaning says why on stderr.

Inside a run of a project with knowledge sources bound to it — the run's
sandbox holds CLOOP_KNOWLEDGE_URL and CLOOP_KNOWLEDGE_TOKEN — the project is the
run's own and is not named: ` + "`cloop knowledge search <query...>`" + ` searches it with
the run's knowledge session, and what it finds is cited on the task.`,
	Args: cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if rc, ok := runKnowledgeClient(); ok {
			return runKnowledgeSearch(cmd, rc, strings.Join(args, " "))
		}
		if len(args) < 2 {
			return fmt.Errorf("name a project and a query: cloop knowledge search <project> <query...>")
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
		query := strings.TrimSpace(strings.Join(args[1:], " "))
		hits, retrieval, err := c.SearchKnowledgeRetrieval(ctx, p.Idx, query, knowledgeK)
		if err != nil {
			return remoteErr(c, err)
		}
		if retrieval.Warning != "" {
			fmt.Fprintf(cmd.ErrOrStderr(), "note: %s\n", retrieval.Warning)
		}
		out := cmd.OutOrStdout()
		if knowledgeJSON {
			if hits == nil {
				hits = []hubclient.KnowledgeHit{}
			}
			return json.NewEncoder(out).Encode(hits)
		}
		if len(hits) == 0 {
			fmt.Fprintf(out, "Nothing bound to %s matches %q.\n", p.Name, query)
			return nil
		}
		for _, h := range hits {
			place := h.Title
			if len(h.Ancestors) > 0 {
				place = strings.Join(h.Ancestors, " › ") + " › " + h.Title
			}
			if h.Heading != "" {
				place += " § " + h.Heading
			}
			fmt.Fprintf(out, "%d. %s — %s (%s)\n", h.Rank, place, h.Source.Name, h.Source.Kind)
			if h.URL != "" {
				fmt.Fprintf(out, "   %s\n", h.URL)
			}
			fmt.Fprintf(out, "   %s\n", oneLineSnippet(h.Snippet))
		}
		return nil
	},
}

var knowledgeGetCmd = &cobra.Command{
	Use:   "get <id|url|ISSUE-KEY>",
	Short: "Read one document of the run's project's knowledge (inside a run)",
	Long: `Read one document of the knowledge sources bound to the project of the run
this command runs in, whole: by the document id a search printed, the URL a
person reads it at, or its issue key (ENG-42). It uses the run's knowledge
session — CLOOP_KNOWLEDGE_URL and CLOOP_KNOWLEDGE_TOKEN, which a run of a
project with knowledge sources bound to it is given — and what it reads is
cited on the task. What it prints is untrusted reference material.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		rc, ok := runKnowledgeClient()
		if !ok {
			return knowledgerun.ErrNotConfigured
		}
		ref := strings.TrimSpace(args[0])
		req := knowledgerun.GetRequest{MaxBytes: knowledgeMaxBytes, Task: knowledgerun.TaskFromEnv(os.Getenv)}
		what := ""
		if id, err := strconv.ParseInt(ref, 10, 64); err == nil && id > 0 {
			req.DocumentID, what = id, fmt.Sprintf("with id %d", id)
		} else if strings.HasPrefix(ref, "https://") || strings.HasPrefix(ref, "http://") {
			req.URL, what = ref, "at "+ref
		} else {
			req.Key, what = ref, "with key "+ref
		}
		resp, err := rc.Get(remoteContext(cmd), req)
		if err != nil {
			return err
		}
		if knowledgeJSON {
			return json.NewEncoder(cmd.OutOrStdout()).Encode(resp)
		}
		_, err = io.WriteString(cmd.OutOrStdout(), knowledgerun.FormatDocuments(what, resp))
		return err
	},
}

var (
	knowledgeRetrievalOn     bool
	knowledgeRetrievalOff    bool
	knowledgeRetrievalK      int
	knowledgeRetrievalBudget int
)

var knowledgeRetrievalCmd = &cobra.Command{
	Use:   "retrieval <project>",
	Short: "Show or set how a project's runs are given its knowledge",
	Long: `Show or set how the runs of a project with knowledge sources bound to it are
given what those sources hold. By default each task's prompt gets the ` + strconv.Itoa(pm.DefaultRetrievalK) + `
passages that best match the task — and the documents it names by issue key
or URL — within ` + strconv.Itoa(pm.DefaultRetrievalTokens) + ` tokens, fenced as untrusted reference material.

  --off         keep reference material out of the prompts (the agent can
                still search the project's knowledge itself)
  --on          put it back in
  --k N         passages per prompt (1-` + strconv.Itoa(pm.MaxRetrievalK) + `; 0 for the default)
  --budget N    tokens per prompt (` + strconv.Itoa(pm.MinRetrievalTokens) + `-` + strconv.Itoa(pm.MaxRetrievalTokens) + `; 0 for the default)

A running run picks a change up at its next task.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if knowledgeRetrievalOn && knowledgeRetrievalOff {
			return fmt.Errorf("--on and --off contradict each other")
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
		var change hubclient.KnowledgeRunSettingChange
		changed := false
		if knowledgeRetrievalOn || knowledgeRetrievalOff {
			on := knowledgeRetrievalOn
			change.Enabled, changed = &on, true
		}
		if cmd.Flags().Changed("k") {
			change.K, changed = &knowledgeRetrievalK, true
		}
		if cmd.Flags().Changed("budget") {
			change.TokenBudget, changed = &knowledgeRetrievalBudget, true
		}
		var st *hubclient.KnowledgeRunSetting
		if changed {
			st, err = c.SetKnowledgeRunSetting(ctx, p.Idx, change)
		} else {
			st, err = c.KnowledgeRunSetting(ctx, p.Idx)
		}
		if err != nil {
			return remoteErr(c, err)
		}
		out := cmd.OutOrStdout()
		if knowledgeJSON {
			return json.NewEncoder(out).Encode(st)
		}
		state := "on"
		if !st.Enabled {
			state = "off"
		}
		fmt.Fprintf(out, "Reference material for %s's tasks: %s — %d passages within %d tokens", p.Name, state, st.K, st.TokenBudget)
		if st.Default {
			fmt.Fprint(out, " (the defaults)")
		}
		fmt.Fprintln(out, ".")
		if st.Sources == 0 {
			fmt.Fprintln(out, "No knowledge source is bound to the project, so its runs get none.")
		}
		return nil
	},
}

// runKnowledgeClient is the run's knowledge session, when this command runs
// in a run that has one and names no hub or token of its own.
func runKnowledgeClient() (*knowledgerun.Client, bool) {
	if remoteHub != "" || remoteToken != "" {
		return nil, false
	}
	c, err := knowledgerun.FromEnv(os.Getenv)
	if err != nil {
		return nil, false
	}
	return c, true
}

// runKnowledgeSearch searches the run's project's knowledge.
func runKnowledgeSearch(cmd *cobra.Command, c *knowledgerun.Client, query string) error {
	query = strings.TrimSpace(query)
	resp, err := c.Search(remoteContext(cmd), knowledgerun.SearchRequest{
		Query: query, K: knowledgeK, Task: knowledgerun.TaskFromEnv(os.Getenv),
	})
	if err != nil {
		return err
	}
	if knowledgeJSON {
		return json.NewEncoder(cmd.OutOrStdout()).Encode(resp)
	}
	_, err = io.WriteString(cmd.OutOrStdout(), knowledgerun.FormatHits(query, resp))
	return err
}

// waitForKnowledgeSync reads source id until the sync running names has
// ended, and returns the source as it ended.
//
// The hub records a sync's outcome before it releases the sync's lease, so
// once the lease is gone the outcome is there to read: the source's last one,
// if it began no earlier than the sync did. When it is not — the hub process
// running it stopped, or the source was disabled or removed before it began —
// that is said, rather than waited for.
func waitForKnowledgeSync(ctx context.Context, c *hubclient.Client, id int64,
	running *hubclient.KnowledgeRunning) (*hubclient.KnowledgeSource, error) {
	since := running.Since
	ticker := time.NewTicker(knowledgePoll)
	defer ticker.Stop()
	for {
		src, err := c.KnowledgeSource(ctx, id)
		if err != nil {
			return nil, err
		}
		if src.Sync.Running == nil || src.Sync.Running.Since != since {
			if src.Sync.Status != "" && src.Sync.StartedAt >= since {
				return src, nil
			}
			return nil, fmt.Errorf("the sync of %s ended without recording how it went — the hub process running it "+
				"may have stopped, or the source was disabled or removed; see cloop knowledge sources", src.Name)
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("stopped following the sync of %s; it goes on on the hub: %w", src.Name, ctx.Err())
		case <-ticker.C:
		}
	}
}

// reportKnowledgeSync says how a sync ended, and fails when it did.
func reportKnowledgeSync(out io.Writer, src *hubclient.KnowledgeSource) error {
	st := src.Sync
	took := time.Duration(st.DurationMS) * time.Millisecond
	switch st.Status {
	case "ok":
		fmt.Fprintf(out, "Synced %s in %s", src.Name, took.Round(time.Millisecond))
		if c := st.Counts; c != nil {
			fmt.Fprintf(out, ": %d listed, %d new, %d updated, %d unchanged, %d deleted, %d removed",
				c.Listed, c.Created, c.Updated, c.Unchanged, c.Deleted, c.Removed)
			if c.Rejected > 0 {
				fmt.Fprintf(out, ", %d rejected", c.Rejected)
			}
		}
		fmt.Fprintf(out, ". It holds %d documents.\n", src.Documents)
		if st.More {
			fmt.Fprintln(out, "It has more to list; the next sync continues from where this one stopped, within a minute.")
		}
		return nil
	case "interrupted":
		fmt.Fprintf(out, "The sync of %s was interrupted (%s); the next continues from where it stopped.\n", src.Name, st.Error)
		return nil
	}
	return fmt.Errorf("the sync of %s failed: %s", src.Name, orDash(st.Error))
}

// runningFrom reads the running sync a 409's details carry.
func runningFrom(v any) *hubclient.KnowledgeRunning {
	blob, err := json.Marshal(v)
	if err != nil || v == nil {
		return nil
	}
	var r hubclient.KnowledgeRunning
	if json.Unmarshal(blob, &r) != nil || r.Since == "" {
		return nil
	}
	return &r
}

func knowledgeScope(s hubclient.KnowledgeSource) string {
	if s.Scope == "personal" {
		if s.Mine {
			return "mine"
		}
		return "personal:" + s.Owner
	}
	return s.Scope
}

func knowledgeStatus(s hubclient.KnowledgeSource) string {
	switch {
	case !s.Enabled:
		return "disabled"
	case s.Sync.Running != nil:
		return "syncing"
	case s.Sync.Status == "":
		return "never synced"
	}
	return s.Sync.Status
}

// knowledgeWhen renders an RFC 3339 time as how long ago it was.
func knowledgeWhen(ts string, now time.Time) string {
	t, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		return "-"
	}
	return roughDuration(now.Sub(t)) + " ago"
}

func knowledgeNext(s hubclient.KnowledgeSource, now time.Time) string {
	if !s.Enabled {
		return "-"
	}
	t, err := time.Parse(time.RFC3339, s.Sync.NextAt)
	if err != nil {
		return "-"
	}
	if !t.After(now) {
		return "due"
	}
	return "in " + roughDuration(t.Sub(now))
}

// roughDuration says a duration the way a person would read it at a glance.
func roughDuration(d time.Duration) string {
	if d < 0 {
		d = -d
	}
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	}
	return fmt.Sprintf("%dd", int(d.Hours()/24))
}

// oneLineSnippet is a snippet on one line.
func oneLineSnippet(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

func init() {
	// No backticks in a flag's usage: pflag would read the quoted words as
	// the flag's value name.
	knowledgeCmd.PersistentFlags().StringVar(&remoteHub, "hub", "",
		"Hub URL (default: the default hub from cloop login, or CLOOP_HUB_URL)")
	knowledgeCmd.PersistentFlags().StringVar(&remoteToken, "token", "",
		"API token to use instead of the stored session (CLOOP_API_TOKEN: for CLOOP_HUB_URL's hub, or one with no stored session)")
	knowledgeSourcesCmd.Flags().BoolVar(&knowledgeJSON, "json", false, "Print JSON")
	knowledgeSyncCmd.Flags().BoolVar(&knowledgeWait, "wait", false, "Follow the sync to its end")
	knowledgeSyncCmd.Flags().BoolVar(&knowledgeJSON, "json", false, "With --wait, print the source as the sync left it, as JSON")
	knowledgeSearchCmd.Flags().IntVarP(&knowledgeK, "limit", "k", 0, "How many results to print (the hub's default: 10; at most 50)")
	knowledgeSearchCmd.Flags().BoolVar(&knowledgeJSON, "json", false, "Print JSON")
	knowledgeGetCmd.Flags().IntVar(&knowledgeMaxBytes, "max-bytes", 0, "How much of the document's text to print (default 32768, at most 65536)")
	knowledgeGetCmd.Flags().BoolVar(&knowledgeJSON, "json", false, "Print JSON")
	knowledgeRetrievalCmd.Flags().BoolVar(&knowledgeRetrievalOn, "on", false, "Put reference material in the project's task prompts")
	knowledgeRetrievalCmd.Flags().BoolVar(&knowledgeRetrievalOff, "off", false, "Keep reference material out of the project's task prompts")
	knowledgeRetrievalCmd.Flags().IntVar(&knowledgeRetrievalK, "k", 0, "Passages per prompt (0 for the default)")
	knowledgeRetrievalCmd.Flags().IntVar(&knowledgeRetrievalBudget, "budget", 0, "Tokens of reference material per prompt (0 for the default)")
	knowledgeRetrievalCmd.Flags().BoolVar(&knowledgeJSON, "json", false, "Print JSON")
	knowledgeCmd.AddCommand(knowledgeSourcesCmd, knowledgeSyncCmd, knowledgeSearchCmd, knowledgeGetCmd, knowledgeRetrievalCmd)
	rootCmd.AddCommand(knowledgeCmd)
}
