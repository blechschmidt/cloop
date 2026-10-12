package cmd

// `cloop remote features` (Task 20417): a project's parallel features — a
// branch, a worktree and a task list of their own, run independently — from a
// terminal, through the Features panel's calls. Each is addressed through the
// parent project, and creating one or opening its pull request takes
// project.write there, as the panel's buttons do.

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/blechschmidt/cloop/pkg/hubclient"
)

var (
	featureDescription string
	featureBase        string
	featureTasks       []string
	featureAutoEvolve  bool
	featureInnovate    bool
	featureParallel    bool
	featureMaxParallel int
	featureAutoPR      bool

	featurePRTitle string
	featurePRBody  string
	featurePRDraft bool
)

var remoteFeaturesCmd = &cobra.Command{
	Use:   "features",
	Short: "Start, list and propose a project's parallel features",
	Long: `A feature is a branch of a project with its own worktree, task list and run
settings, so several lines of work run at once without touching each other.
Start one, run it like any project (` + "`cloop remote run <index>`" + `), and open its pull
request into the branch it was cut from when it is done.`,
}

var remoteFeaturesStartCmd = &cobra.Command{
	Use:   "start <project> <name>",
	Short: "Start a feature: a branch, its worktree and a task list of its own",
	Long: `Start a feature of a project.

    cloop remote features start api "Rate limiting" --task "Add a token bucket" \
        --task "Return 429 with Retry-After" --auto-pr

The feature is cut from --base (default: the repository's default branch) onto a
branch of its own, and gets an index of its own in ` + "`cloop remote projects`" + ` —
run, stop and follow it by that index.`,
	Args: cobra.MinimumNArgs(2),
	RunE: runRemoteFeaturesStart,
}

var remoteFeaturesListCmd = &cobra.Command{
	Use:   "list <project>",
	Short: "List a project's features",
	Args:  cobra.ExactArgs(1),
	RunE:  runRemoteFeaturesList,
}

var remoteFeaturesPRCmd = &cobra.Command{
	Use:   "pr <project> <feature>",
	Short: "Push a feature's branch and open its pull request",
	Long: `Push a feature's branch and open its pull request into the branch it was cut
from, with the project's own GitHub grant — or report the one already open. The
feature is named by its slug, as ` + "`cloop remote features list`" + ` shows it.`,
	Args: cobra.ExactArgs(2),
	RunE: runRemoteFeaturesPR,
}

func runRemoteFeaturesStart(cmd *cobra.Command, args []string) error {
	name := strings.TrimSpace(strings.Join(args[1:], " "))
	if name == "" {
		return errors.New("a feature needs a name")
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
	f, err := c.StartFeature(ctx, p.Idx, hubclient.StartFeatureRequest{
		Name: name, Description: featureDescription, Base: featureBase, Tasks: featureTasks,
		AutoEvolve: featureAutoEvolve, Innovate: featureInnovate, Parallel: featureParallel,
		MaxParallel: featureMaxParallel, AutoPR: featureAutoPR,
	})
	if err != nil {
		return remoteErr(c, err)
	}
	out := cmd.OutOrStdout()
	if remoteJSON {
		return json.NewEncoder(out).Encode(f)
	}
	fmt.Fprintf(out, "Started feature %s of %s on branch %s, cut from %s.\n", f.Slug, p.Name, f.Branch, orDash(f.Base))
	if f.Idx >= 0 {
		fmt.Fprintf(out, "It is project %d: run it with `cloop remote run %d`, follow it with `cloop remote logs %d --follow`.\n",
			f.Idx, f.Idx, f.Idx)
	}
	fmt.Fprintf(out, "Open its pull request when it is done: cloop remote features pr %s %s\n", quoteArg(p.Name), f.Slug)
	return nil
}

func runRemoteFeaturesList(cmd *cobra.Command, args []string) error {
	c, err := remoteClient()
	if err != nil {
		return err
	}
	ctx := remoteContext(cmd)
	p, err := c.ResolveProject(ctx, args[0])
	if err != nil {
		return remoteErr(c, err)
	}
	list, err := c.Features(ctx, p.Idx)
	if err != nil {
		return remoteErr(c, err)
	}
	out := cmd.OutOrStdout()
	if remoteJSON {
		return json.NewEncoder(out).Encode(list)
	}
	if len(list.Features) == 0 {
		fmt.Fprintf(out, "%s has no features. Start one with: cloop remote features start %s <name>\n", p.Name, quoteArg(p.Name))
		return nil
	}
	w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "IDX\tFEATURE\tBRANCH\tSTATUS\tTASKS\tPULL REQUEST")
	for _, f := range list.Features {
		slug, branch, pr := "-", "-", "-"
		if f.Feature != nil {
			slug, branch = f.Feature.Slug, f.Feature.Branch
			if f.Feature.PR != nil {
				pr = fmt.Sprintf("#%d %s %s", f.Feature.PR.Number, f.Feature.PR.State, f.Feature.PR.URL)
			}
		}
		status := orDash(f.Status)
		if f.Running {
			status = "running"
		}
		fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%d/%d\t%s\n", f.Idx, slug, branch, status, f.DoneTasks, f.TotalTasks, pr)
	}
	return w.Flush()
}

func runRemoteFeaturesPR(cmd *cobra.Command, args []string) error {
	c, err := remoteClient()
	if err != nil {
		return err
	}
	ctx := remoteContext(cmd)
	p, err := c.ResolveProject(ctx, args[0])
	if err != nil {
		return remoteErr(c, err)
	}
	res, err := c.OpenFeaturePR(ctx, p.Idx, strings.TrimSpace(args[1]), hubclient.FeaturePRRequest{
		Title: featurePRTitle, Body: featurePRBody, Draft: featurePRDraft,
	})
	if err != nil {
		return remoteErr(c, err)
	}
	out := cmd.OutOrStdout()
	if remoteJSON {
		return json.NewEncoder(out).Encode(res)
	}
	if res.PR == nil {
		fmt.Fprintln(out, "The hub reported no pull request.")
		return nil
	}
	verb := "Opened"
	if res.Existing {
		verb = "Already open:"
	}
	fmt.Fprintf(out, "%s pull request #%d (%s into %s): %s\n", verb, res.PR.Number, orDash(res.PR.Head), orDash(res.PR.Base), res.PR.URL)
	if len(res.Dirty) > 0 {
		fmt.Fprintf(out, "note: uncommitted changes are not in it: %s\n", strings.Join(res.Dirty, ", "))
	}
	return nil
}

func init() {
	f := remoteFeaturesStartCmd.Flags()
	f.StringVar(&featureDescription, "description", "", "What the feature is for")
	f.StringVar(&featureBase, "base", "", "Branch to cut from and propose into (default: the repository's default branch)")
	f.StringArrayVar(&featureTasks, "task", nil, "An initial task; repeatable")
	f.BoolVar(&featureAutoEvolve, "auto-evolve", false, "Let the feature's runs add tasks of their own")
	f.BoolVar(&featureInnovate, "innovate", false, "Let auto-evolve propose new ideas, not only follow-ups")
	f.BoolVar(&featureParallel, "parallel", false, "Run the feature's independent tasks in parallel")
	f.IntVar(&featureMaxParallel, "max-parallel", 0, "How many tasks may run at once with --parallel")
	f.BoolVar(&featureAutoPR, "auto-pr", false, "Open the pull request by itself once every task is done")
	f.BoolVar(&remoteJSON, "json", false, "Print the new feature as JSON")
	remoteFeaturesListCmd.Flags().BoolVar(&remoteJSON, "json", false, "Print JSON")
	pr := remoteFeaturesPRCmd.Flags()
	pr.StringVar(&featurePRTitle, "title", "", "The pull request's title (default: the feature's name)")
	pr.StringVar(&featurePRBody, "body", "", "The pull request's description (default: the feature's tasks)")
	pr.BoolVar(&featurePRDraft, "draft", false, "Open it as a draft")
	pr.BoolVar(&remoteJSON, "json", false, "Print the result as JSON")
	remoteFeaturesCmd.AddCommand(remoteFeaturesStartCmd, remoteFeaturesListCmd, remoteFeaturesPRCmd)
	remoteCmd.AddCommand(remoteFeaturesCmd)
}
