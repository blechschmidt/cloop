package cmd

// `cloop executor move` (Task 20496): move a project to another executor from
// a terminal — the dashboard's Move dialog, as calls to the same routes, made
// with this terminal's session (`cloop login`), an API token, or nothing at
// all for a hub on this machine without sign-in:
//
//	cloop executor move <project> --to <executor-id|pool:<id>|local>   preflight, confirm, move, follow it
//	cloop executor move status <move-id>                                where a move is, or how it ended
//	cloop executor move cleanup <move-id>                               remove what an ended move kept
//
// The move itself runs on the hub (pkg/projectmove's engine over pkg/ui): this
// command asks for the preflight, shows it, starts the move only when nothing
// blocks it and every warning was accepted (--yes, or a yes at the terminal),
// and then follows the hub's record of it until it ends. Interrupting the
// command does not stop the move.

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/blechschmidt/cloop/pkg/executor/movegit"
	"github.com/blechschmidt/cloop/pkg/hubclient"
	"github.com/blechschmidt/cloop/pkg/projectmove"
)

var (
	emoveHub   string
	emoveToken string
	emoveJSON  bool

	emoveTo             string
	emoveDryRun         bool
	emoveAbandon        bool
	emoveYes            bool
	emoveNoWait         bool
	emoveProject        string
	emoveKeepSource     bool
	emoveDiscardIgnored bool
)

// emovePollInterval is how often the command reads a move it follows.
var emovePollInterval = time.Second

var executorMoveCmd = &cobra.Command{
	Use:   "move <project> --to <executor-id|pool:<id>|local>",
	Short: "Move a project to another executor, taking its uncommitted and unpushed work along",
	Long: `Move a project to another executor or executor pool without losing what the old side holds:
its uncommitted changes and untracked files, commits no remote has, its features' branches,
and the files under .cloop that no database holds.

The command first shows the move's preflight: what would block it, what it carries, and what
it would lose or change. It stops there with --dry-run, or when anything blocks the move.
Warnings have to be accepted: at a terminal you are asked, otherwise pass --yes.

The hub then stops the project's runs (the task in progress goes back to pending), captures
the source, switches the project's binding, seeds the target and checks that it holds what
was captured. The command follows the move until it ends; interrupting it does not stop the
move, and ` + "`cloop executor move status <move-id>`" + ` picks it up again. No run of the project
starts while the move is open.

The source is never removed by a move: once it is verified, ` + "`cloop executor move cleanup`" + `
removes what the move kept.

Moving needs executor.manage on the project and a place on the target's access list; on a
hub with single sign-on, a recent sign-in as well (run ` + "`cloop login`" + ` again when asked).
The project is named by its name, its index or its path, as ` + "`cloop remote projects`" + ` lists them.`,
	Example: `  cloop executor move shop --to edge-01 --dry-run
  cloop executor move shop --to pool:gpu --yes
  cloop executor move status 3f9c2a7d10b4e865
  cloop executor move cleanup 3f9c2a7d10b4e865`,
	Args: cobra.ExactArgs(1),
	RunE: runExecutorMove,
}

var executorMoveStatusCmd = &cobra.Command{
	Use:   "status <move-id>",
	Short: "Show where a project move is, or how it ended",
	Long: `Show a project move: where it goes, the phase it is in or how it ended, each step it took,
and what it kept that cleanup would remove. The project is found among those this session
can see; --project names it outright.`,
	Args: cobra.ExactArgs(1),
	RunE: runExecutorMoveStatus,
}

var executorMoveCleanupCmd = &cobra.Command{
	Use:   "cleanup <move-id>",
	Short: "Remove what an ended move kept: its bundle, its hidden refs, and after a verified move the source's copy",
	Long: `Remove what an ended project move kept: its bundle and files in the hub's move store and the
hidden refs its capture wrote into the project's repository. After a verified move from a
device it also removes the working copy the device kept — and nothing at all unless that copy
is still exactly what the move captured. The project's directory on the hub is never removed.

The command lists what it removes and asks before it does (--yes answers for you). Pass
--keep-source to clean up the hub's half and leave the source's copy where it is: the way
past a device that is gone.`,
	Args: cobra.ExactArgs(1),
	RunE: runExecutorMoveCleanup,
}

// moveView is GET /api/projects/{idx}/move/{id}.
type moveView struct {
	Move    projectmove.Move `json:"move"`
	Cleanup *moveCleanup     `json:"cleanup,omitempty"`
}

// moveCleanup is the hub's cleanup plan for a move.
type moveCleanup struct {
	Allowed    bool        `json:"allowed"`
	Reason     string      `json:"reason,omitempty"`
	CleanedAt  *time.Time  `json:"cleaned_at,omitempty"`
	CleanedBy  string      `json:"cleaned_by,omitempty"`
	Verified   bool        `json:"verified"`
	Store      string      `json:"store,omitempty"`
	StoreBytes int64       `json:"store_bytes,omitempty"`
	Refs       []string    `json:"refs,omitempty"`
	Source     *moveSource `json:"source,omitempty"`
	Kept       []string    `json:"kept,omitempty"`
	Command    string      `json:"command"`
}

// moveSource is the source's own copy, as the plan describes it.
type moveSource struct {
	Executor  string     `json:"executor"`
	Name      string     `json:"name,omitempty"`
	WorkDir   string     `json:"work_dir"`
	Removable bool       `json:"removable"`
	Reason    string     `json:"reason,omitempty"`
	RemovedAt *time.Time `json:"removed_at,omitempty"`
}

// emoveHubClient is the hub this command talks to, resolved as `cloop task
// attach` resolves its own: --hub, CLOOP_HUB_URL, the default hub `cloop
// login` recorded, or else the hub on this machine — with --token, the
// session this terminal holds for that hub, or CLOOP_API_TOKEN where it is
// that hub's. A hub this terminal holds no session for is asked with no
// credential at all, which a hub without sign-in on this machine answers and
// any other refuses with what it wants presented.
func emoveHubClient() (*hubclient.Client, error) {
	envHub := strings.TrimSpace(os.Getenv("CLOOP_HUB_URL"))
	base := strings.TrimSpace(emoveHub)
	if base == "" {
		base = envHub
	}
	if tok := strings.TrimSpace(emoveToken); tok != "" {
		// Never guessed: a token sent to whichever hub answers on this
		// machine could act on another hub's project of the same name.
		if base == "" {
			return nil, errors.New("--token needs --hub (or CLOOP_HUB_URL) to say which hub it is for")
		}
		return hubclient.New(base, "", tok)
	}
	envToken := strings.TrimSpace(os.Getenv("CLOOP_API_TOKEN"))
	switch {
	case envToken == "":
	case envHub != "" && sameHub(base, envHub):
		return hubclient.New(base, "", envToken)
	case base == "":
		return hubclient.New(localHub, "", envToken)
	}
	path, err := hubclient.DefaultPath()
	if err != nil {
		return nil, err
	}
	f, err := hubclient.Load(path)
	if err != nil {
		return nil, err
	}
	if base == "" {
		base = f.Default
	}
	if base == "" {
		base = localHub
	}
	h, ok := f.Lookup(base)
	if !ok {
		if envToken != "" && envHub == "" {
			return hubclient.New(base, "", envToken)
		}
		return hubclient.New(base, "", "")
	}
	return hubclient.New(h.URL, h.CAFile, h.Credential)
}

// moveErr is remoteErr for this command, which may have asked a hub with no
// credential at all: that hub's 401 asks for a sign-in rather than reporting
// a session ended.
func moveErr(c *hubclient.Client, err error) error {
	if c != nil && c.Credential == "" && hubclient.IsUnauthorized(err) && !hubclient.IsReauthRequired(err) {
		return fmt.Errorf("%w — %s asks for a sign-in: run `cloop login %s`, or pass --token", err, c.Base, c.Base)
	}
	return remoteErr(c, err)
}

// moveConfirm asks question at the terminal, unless --yes answered it.
func moveConfirm(cmd *cobra.Command, question string) error {
	if emoveYes {
		return nil
	}
	if !interactive() {
		return errors.New("refusing without --yes: this is not a terminal to ask on")
	}
	fmt.Fprintf(cmd.ErrOrStderr(), "%s [y/N] ", question)
	answer, _ := bufio.NewReader(cmd.InOrStdin()).ReadString('\n')
	switch strings.ToLower(strings.TrimSpace(answer)) {
	case "y", "yes":
		return nil
	}
	return errors.New("not confirmed; nothing was changed")
}

func runExecutorMove(cmd *cobra.Command, args []string) error {
	target := strings.TrimSpace(emoveTo)
	if target == "" {
		return errors.New("--to names where the project moves: an executor id, pool:<id>, or local")
	}
	if _, err := projectmove.ParseTarget(target); err != nil {
		return errors.New(strings.TrimPrefix(err.Error(), "projectmove: "))
	}
	c, err := emoveHubClient()
	if err != nil {
		return err
	}
	ctx := remoteContext(cmd)
	p, err := c.ResolveProject(ctx, args[0])
	if err != nil {
		return moveErr(c, err)
	}
	out := cmd.OutOrStdout()

	q := url.Values{"target": {target}, "quiesce": {"1"}}
	if emoveAbandon {
		q.Set("abandon_source", "1")
	}
	var rep projectmove.Report
	if err := c.Do(ctx, http.MethodGet, fmt.Sprintf("/api/projects/%d/move/preflight", p.Idx), q, nil, &rep); err != nil {
		return moveErr(c, err)
	}
	if emoveJSON && emoveDryRun {
		if err := writeJSON(out, rep); err != nil {
			return err
		}
	} else if !emoveJSON {
		if err := rep.WriteText(out); err != nil {
			return err
		}
	}
	if rep.Blocked {
		return fmt.Errorf("the preflight blocks moving %s: resolve the %d blocker(s) it lists, then move it again", p.Name, rep.Counts.Blockers)
	}
	if emoveDryRun {
		return nil
	}
	if rep.Counts.Warnings > 0 && !emoveYes {
		if emoveJSON {
			return fmt.Errorf("the preflight reports %d warning(s): read them with --dry-run, then pass --yes to accept them", rep.Counts.Warnings)
		}
		if err := moveConfirm(cmd, fmt.Sprintf("Move %s to %s despite %d warning(s)?", p.Name, describeEndpointName(rep.Target), rep.Counts.Warnings)); err != nil {
			return err
		}
	}

	var started struct {
		Move projectmove.Move `json:"move"`
	}
	body := map[string]any{"target": target, "abandon_source": emoveAbandon}
	if err := c.DoLong(ctx, http.MethodPost, fmt.Sprintf("/api/projects/%d/move", p.Idx), nil, body, &started); err != nil {
		if ae, ok := hubclient.AsAPIError(err); ok && ae.Code == "move_blocked" && !emoveJSON {
			// The hub ran the preflight again as the move started, and the
			// project had changed since: show what it found.
			if raw, err := json.Marshal(ae.Details["report"]); err == nil {
				var again projectmove.Report
				if json.Unmarshal(raw, &again) == nil && len(again.Findings) > 0 {
					fmt.Fprintln(out, "\nThe hub's own preflight, as the move started:")
					_ = again.WriteText(out)
				}
			}
		}
		return moveErr(c, err)
	}
	m := started.Move
	if emoveNoWait {
		if emoveJSON {
			return writeJSON(out, moveView{Move: m})
		}
		fmt.Fprintf(out, "\nMove %s of %s to %s started. Follow it with: cloop executor move status %s\n",
			m.ID, p.Name, describeEndpointName(rep.Target), m.ID)
		return nil
	}
	if !emoveJSON {
		fmt.Fprintf(out, "\nMoving %s to %s (move %s):\n", p.Name, describeEndpointName(rep.Target), m.ID)
	}
	view, err := followMove(ctx, c, p.Idx, m.ID, out)
	if err != nil {
		return err
	}
	if emoveJSON {
		if err := writeJSON(out, view); err != nil {
			return err
		}
	} else {
		writeMoveOutcome(out, p.Name, view)
	}
	return moveOutcomeErr(view.Move)
}

// followMove reads the move until it ends, printing each step as it finishes
// unless --json asked for one answer at the end.
func followMove(ctx context.Context, c *hubclient.Client, idx int, id string, out io.Writer) (moveView, error) {
	printed := 0
	failures := 0
	progress := url.Values{"progress": {"1"}}
	for {
		var view moveView
		err := c.Do(ctx, http.MethodGet, fmt.Sprintf("/api/projects/%d/move/%s", idx, id), progress, nil, &view)
		if err == nil && !view.Move.Open() && view.Cleanup == nil {
			// It ended between two reads: once more, whole.
			err = c.Do(ctx, http.MethodGet, fmt.Sprintf("/api/projects/%d/move/%s", idx, id), nil, nil, &view)
		}
		switch {
		case err == nil:
			failures = 0
			if !emoveJSON {
				for _, st := range view.Move.Detail.Timeline[min(printed, len(view.Move.Detail.Timeline)):] {
					if st.Ended.IsZero() && st.Error == "" {
						break
					}
					writeMoveStep(out, st)
					printed++
				}
			}
			if !view.Move.Open() {
				return view, nil
			}
		case ctx.Err() != nil:
			return view, fmt.Errorf("stopped following move %s, which goes on on the hub: cloop executor move status %s", id, id)
		default:
			failures++
			if failures >= 5 {
				return view, fmt.Errorf("lost contact with the hub (%v); move %s goes on there: cloop executor move status %s",
					moveErr(c, err), id, id)
			}
		}
		select {
		case <-ctx.Done():
			return view, fmt.Errorf("stopped following move %s, which goes on on the hub: cloop executor move status %s", id, id)
		case <-time.After(emovePollInterval):
		}
	}
}

// writeMoveStep prints one finished step of a move.
func writeMoveStep(w io.Writer, st projectmove.Step) {
	took := ""
	if !st.Ended.IsZero() && !st.Started.IsZero() {
		took = " " + st.Ended.Sub(st.Started).Round(100*time.Millisecond).String()
	}
	mark := "✓"
	if st.Error != "" {
		mark = "✗"
	}
	if st.Phase == projectmove.PhaseRolledBack {
		mark = "↩"
	}
	line := fmt.Sprintf("  %s %-11s%s", mark, string(st.Phase), took)
	if st.Error != "" {
		line += " — " + st.Error
	}
	fmt.Fprintln(w, line)
}

// moveOutcomeErr is the command's error for a move that did not end done.
func moveOutcomeErr(m projectmove.Move) error {
	switch m.Phase {
	case projectmove.PhaseDone:
		return nil
	case projectmove.PhaseRolledBack:
		return fmt.Errorf("move %s was rolled back after %s failed: %s", m.ID, coalesce(string(m.FailedPhase), "a phase"), m.Error)
	default:
		return fmt.Errorf("move %s failed at %s: %s", m.ID, coalesce(string(m.FailedPhase), string(m.Phase)), m.Error)
	}
}

// writeMoveOutcome says how a followed move ended, and what it kept.
func writeMoveOutcome(w io.Writer, project string, v moveView) {
	m := v.Move
	switch m.Phase {
	case projectmove.PhaseDone:
		checked := ""
		if m.Detail.Verify != nil && m.Detail.Verify.Checked > 0 {
			checked = fmt.Sprintf(" (%d refs, trees and files checked)", m.Detail.Verify.Checked)
		}
		fmt.Fprintf(w, "\nDone: %s now runs on %s, and the hub verified it holds what was captured%s.\n",
			project, projectmove.DescribeTarget(m.Target), checked)
	case projectmove.PhaseRolledBack:
		fmt.Fprintf(w, "\nRolled back: %s failed (%s), so %s is bound to %s again.\n",
			m.FailedPhase, m.Error, project, projectmove.DescribeTarget(m.Source))
		return
	default:
		fmt.Fprintf(w, "\nFailed at %s: %s. %s stays on %s.\n", coalesce(string(m.FailedPhase), string(m.Phase)), m.Error,
			project, projectmove.DescribeTarget(m.Source))
		return
	}
	writeRetained(w, m)
	if v.Cleanup != nil && v.Cleanup.Allowed {
		fmt.Fprintf(w, "Remove what the move kept with: %s\n", v.Cleanup.Command)
	}
}

// writeRetained says what a move kept of its source, or that cleanup removed
// it.
func writeRetained(w io.Writer, m projectmove.Move) {
	r := m.Detail.Retained
	switch {
	case r == nil:
	case !r.SourceRemovedAt.IsZero():
		fmt.Fprintf(w, "Removed: the working copy on %s, %s.\n", r.SourceRemoved, r.SourceRemovedAt.Local().Format("2006-01-02 15:04:05"))
	case r.Source != "":
		fmt.Fprintf(w, "Kept: %s.\n", strings.TrimSuffix(r.Source, "."))
	}
}

// describeEndpointName names a move's end for a sentence.
func describeEndpointName(e projectmove.Endpoint) string {
	switch {
	case e.Name != "" && e.PoolID != "":
		return "pool " + e.Name
	case e.Name != "" && e.Name != e.ExecutorID:
		return e.Name + " (" + coalesce(e.ExecutorID, e.Binding) + ")"
	}
	return projectmove.DescribeTarget(e.Binding)
}

// findMove finds the move id names among the projects this session can see:
// the one --project names, else the projects moving under it first.
func findMove(ctx context.Context, c *hubclient.Client, id string) (hubclient.Project, moveView, error) {
	var view moveView
	if !movegit.ValidMoveID(id) {
		return hubclient.Project{}, view, fmt.Errorf("%q is not a move id: it is the 16 hex digits `cloop executor move` printed", id)
	}
	var candidates []hubclient.Project
	if ref := strings.TrimSpace(emoveProject); ref != "" {
		p, err := c.ResolveProject(ctx, ref)
		if err != nil {
			return p, view, moveErr(c, err)
		}
		candidates = []hubclient.Project{p}
	} else {
		all, err := c.Projects(ctx)
		if err != nil {
			return hubclient.Project{}, view, moveErr(c, err)
		}
		sort.SliceStable(all, func(i, j int) bool {
			return movingAs(all[i], id) && !movingAs(all[j], id)
		})
		candidates = all
	}
	for _, p := range candidates {
		err := c.Do(ctx, http.MethodGet, fmt.Sprintf("/api/projects/%d/move/%s", p.Idx, id), nil, nil, &view)
		if err == nil {
			return p, view, nil
		}
		if ae, ok := hubclient.AsAPIError(err); ok && (ae.Status == http.StatusNotFound || ae.Status == http.StatusConflict) {
			// Not this project's move, or a feature's entry, which has none.
			continue
		}
		return p, view, moveErr(c, err)
	}
	if strings.TrimSpace(emoveProject) != "" {
		return hubclient.Project{}, view, fmt.Errorf("%s has no move %s", emoveProject, id)
	}
	return hubclient.Project{}, view, fmt.Errorf("no project this session can see has a move %s", id)
}

func movingAs(p hubclient.Project, id string) bool { return p.Moving != nil && p.Moving.ID == id }

func runExecutorMoveStatus(cmd *cobra.Command, args []string) error {
	c, err := emoveHubClient()
	if err != nil {
		return err
	}
	p, view, err := findMove(remoteContext(cmd), c, strings.TrimSpace(args[0]))
	if err != nil {
		return err
	}
	out := cmd.OutOrStdout()
	if emoveJSON {
		return writeJSON(out, view)
	}
	writeMoveStatus(out, p, view)
	return nil
}

// writeMoveStatus renders a move for a terminal.
func writeMoveStatus(w io.Writer, p hubclient.Project, v moveView) {
	m := v.Move
	fmt.Fprintf(w, "Move %s of %s (%s)\n", m.ID, p.Name, m.Project.Path)
	fmt.Fprintf(w, "  from   %s\n  to     %s\n", projectmove.DescribeTarget(m.Source), projectmove.DescribeTarget(m.Target))
	state := string(m.Phase)
	switch {
	case m.Open():
		state += " (in progress)"
	case m.Phase == projectmove.PhaseFailed:
		state = fmt.Sprintf("failed at %s: %s", m.FailedPhase, m.Error)
	case m.Phase == projectmove.PhaseRolledBack:
		state = fmt.Sprintf("rolled back after %s failed: %s", m.FailedPhase, m.Error)
	case m.Detail.Verify != nil:
		state += fmt.Sprintf(" — verified, %d refs, trees and files checked", m.Detail.Verify.Checked)
	}
	fmt.Fprintf(w, "  phase  %s\n", state)
	started := m.CreatedAt.Local().Format("2006-01-02 15:04:05")
	if m.StartedBy != "" {
		started += " by " + m.StartedBy
	}
	fmt.Fprintf(w, "  began  %s\n", started)
	if m.AbandonSource {
		fmt.Fprintln(w, "  the source was abandoned: nothing was captured from it")
	}
	if len(m.Detail.Timeline) > 0 {
		fmt.Fprintln(w)
		for _, st := range m.Detail.Timeline {
			if st.Ended.IsZero() && st.Error == "" {
				fmt.Fprintf(w, "  … %s\n", st.Phase)
				continue
			}
			writeMoveStep(w, st)
		}
	}
	fmt.Fprintln(w)
	writeRetained(w, m)
	if cl := v.Cleanup; cl != nil {
		if cl.CleanedAt != nil {
			fmt.Fprintf(w, "Cleaned up %s by %s.\n", cl.CleanedAt.Local().Format("2006-01-02 15:04:05"), coalesce(cl.CleanedBy, "someone"))
		}
		if cl.Allowed {
			fmt.Fprintf(w, "Remove what the move kept with: %s\n", cl.Command)
		}
	}
}

func runExecutorMoveCleanup(cmd *cobra.Command, args []string) error {
	c, err := emoveHubClient()
	if err != nil {
		return err
	}
	ctx := remoteContext(cmd)
	p, view, err := findMove(ctx, c, strings.TrimSpace(args[0]))
	if err != nil {
		return err
	}
	m, plan := view.Move, view.Cleanup
	if plan == nil {
		return errors.New("this hub does not say what cleaning up after a move removes: upgrade it")
	}
	out := cmd.OutOrStdout()
	pendingCopy := plan.Source != nil && plan.Source.RemovedAt == nil
	if plan.CleanedAt != nil && (!pendingCopy || emoveKeepSource || !plan.Allowed) {
		if emoveJSON {
			return writeJSON(out, view)
		}
		fmt.Fprintf(out, "Move %s of %s was cleaned up already, %s.\n", m.ID, p.Name, plan.CleanedAt.Local().Format("2006-01-02 15:04:05"))
		if pendingCopy {
			fmt.Fprintf(out, "The working copy on %s at %s was kept: %s\n", coalesce(plan.Source.Name, plan.Source.Executor),
				plan.Source.WorkDir, coalesce(plan.Source.Reason, "cleanup was asked to keep it"))
		}
		return nil
	}
	if !plan.Allowed {
		return fmt.Errorf("cannot clean up after move %s yet: %s", m.ID, plan.Reason)
	}
	removeSource := plan.Source != nil && plan.Source.RemovedAt == nil && !emoveKeepSource
	if removeSource && !plan.Source.Removable {
		return fmt.Errorf("the copy on %s at %s cannot be removed now: %s — pass --keep-source to clean up the hub's half and leave it there",
			coalesce(plan.Source.Name, plan.Source.Executor), plan.Source.WorkDir, plan.Source.Reason)
	}
	w := cmd.ErrOrStderr()
	if !emoveJSON {
		w = out
	}
	fmt.Fprintf(w, "Cleaning up after move %s of %s removes:\n", m.ID, p.Name)
	if plan.Store != "" {
		fmt.Fprintf(w, "  - the move's bundle and files in the hub's move store, %s (%s)\n", plan.Store, humanSize(plan.StoreBytes))
	}
	if n := len(plan.Refs); n > 0 {
		fmt.Fprintf(w, "  - %d hidden ref(s) the capture wrote into the project's repository on the hub\n", n)
	}
	if removeSource {
		fmt.Fprintf(w, "  - the working copy on %s at %s, once the device has checked it holds nothing the move did not carry\n",
			coalesce(plan.Source.Name, plan.Source.Executor), plan.Source.WorkDir)
		if emoveDiscardIgnored {
			fmt.Fprintln(w, "    and the files in it git ignores, which no move carries (--discard-ignored)")
		}
	} else if plan.Source != nil && plan.Source.RemovedAt == nil {
		fmt.Fprintf(w, "It leaves the working copy on %s at %s, as --keep-source asks.\n", coalesce(plan.Source.Name, plan.Source.Executor), plan.Source.WorkDir)
	}
	for _, k := range plan.Kept {
		fmt.Fprintf(w, "It keeps %s.\n", strings.TrimSuffix(k, "."))
	}
	if err := moveConfirm(cmd, "Remove them? They cannot be brought back."); err != nil {
		return err
	}
	var done moveView
	body := map[string]any{"confirm": true, "keep_source": emoveKeepSource, "discard_ignored": emoveDiscardIgnored}
	if err := c.DoLong(ctx, http.MethodPost, fmt.Sprintf("/api/projects/%d/move/%s/cleanup", p.Idx, m.ID), nil, body, &done); err != nil {
		if ae, ok := hubclient.AsAPIError(err); ok && ae.Code == "source_copy_ignored" {
			if ex, _ := ae.Details["examples"].([]any); len(ex) > 0 {
				names := make([]string, 0, len(ex))
				for _, e := range ex {
					names = append(names, fmt.Sprint(e))
				}
				fmt.Fprintf(cmd.ErrOrStderr(), "Files git ignores in the copy, which no move carries: %s\n", strings.Join(names, ", "))
			}
			return fmt.Errorf("%w — copy any you need off the device, then run cleanup again with --discard-ignored, or with --keep-source to leave the copy", moveErr(c, err))
		}
		return moveErr(c, err)
	}
	if emoveJSON {
		return writeJSON(out, done)
	}
	fmt.Fprintf(out, "Cleaned up after move %s of %s.\n", m.ID, p.Name)
	if r := done.Move.Detail.Retained; r != nil && r.SourceRemoved != "" {
		fmt.Fprintf(out, "Removed the working copy on %s.\n", r.SourceRemoved)
	}
	return nil
}

func init() {
	// No backticks in a flag's usage: pflag reads quoted words as the value's name.
	executorMoveCmd.PersistentFlags().StringVar(&emoveHub, "hub", "",
		"Hub URL (default: the default hub from cloop login, CLOOP_HUB_URL, or the hub on this machine)")
	executorMoveCmd.PersistentFlags().StringVar(&emoveToken, "token", "",
		"API token to use instead of the stored session")
	executorMoveCmd.PersistentFlags().BoolVar(&emoveJSON, "json", false, "Print JSON")

	executorMoveCmd.Flags().StringVar(&emoveTo, "to", "", "Where the project moves: an executor id, pool:<id>, or local")
	executorMoveCmd.Flags().BoolVar(&emoveDryRun, "dry-run", false, "Show the preflight and stop")
	executorMoveCmd.Flags().BoolVar(&emoveAbandon, "abandon-source", false,
		"Move without capturing the source: for a source that is gone for good; what it holds is lost")
	executorMoveCmd.Flags().BoolVarP(&emoveYes, "yes", "y", false, "Accept the preflight's warnings without asking")
	executorMoveCmd.Flags().BoolVar(&emoveNoWait, "no-wait", false, "Start the move and return without following it")

	for _, c := range []*cobra.Command{executorMoveStatusCmd, executorMoveCleanupCmd} {
		c.Flags().StringVar(&emoveProject, "project", "", "The project the move is of: its name, index or path")
	}
	executorMoveCleanupCmd.Flags().BoolVarP(&emoveYes, "yes", "y", false, "Remove without asking")
	executorMoveCleanupCmd.Flags().BoolVar(&emoveKeepSource, "keep-source", false,
		"Leave the source's own copy where it is; remove only the move's bundle and refs")
	executorMoveCleanupCmd.Flags().BoolVar(&emoveDiscardIgnored, "discard-ignored", false,
		"Remove the files git ignores in the source's copy too, which no move carries")

	executorMoveCmd.AddCommand(executorMoveStatusCmd, executorMoveCleanupCmd)
	executorCmd.AddCommand(executorMoveCmd)
}
