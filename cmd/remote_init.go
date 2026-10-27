package cmd

// `cloop remote init` (Task 20417): from a checkout on a developer's machine
// to a project on the hub, bound to an executor, with its repositories and
// credentials, without opening the dashboard.
//
// Every step is one of the dashboard's own calls, made with the terminal's
// session, so each is allowed exactly when the dashboard's control would be:
//
//	create        POST /api/projects/new — with the executor binding and the
//	              grants the caller may make, applied together or not at all
//	repositories  GET/POST /api/projects/{idx}/repositories, /available
//	requests      POST /api/grant-requests, for what the caller may not grant
//	Claude        GET/POST /api/projects/{idx}/harness-credential
//	run           POST /api/run
//
// What can be checked before anything exists is checked first — the checkout's
// origin, the executor's access list, the secrets named — so a mistake costs
// nothing. Past the creation a failure leaves the project in place and says
// what is missing and the command that adds it.

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/blechschmidt/cloop/pkg/gitremote"
	"github.com/blechschmidt/cloop/pkg/hubclient"
)

var (
	rinitGoal          string
	rinitExecutor      string
	rinitRepos         []string
	rinitGrants        []string
	rinitRun           bool
	rinitName          string
	rinitDir           string
	rinitRepoSecret    string
	rinitAccess        string
	rinitBranches      []string
	rinitProvider      string
	rinitModel         string
	rinitEffortLevel   string
	rinitClaudeSecret  string
	rinitJustification string
)

var remoteInitCmd = &cobra.Command{
	Use:   "init",
	Short: "Create a hub project from this checkout, with its executor, repositories and credentials",
	Long: `Create a project on the hub from the git checkout you are in.

    cloop remote init --goal "Ship rate limiting for the public API"
    cloop remote init --goal "…" --executor edge-01 --access write --branch 'cloop/*' --run
    cloop remote init --goal "…" --repo acme/api-docs --grant staging-cluster,namespace=payments

The repository is the checkout's origin remote (https or ssh), plus any --repo.
The project is created under the hub's projects root as --name (default: the
repository's name), bound to --executor if you give one — one an administrator has
made available to you, see ` + "`cloop remote executors`" + ` — and granted the repositories
through a GitHub App installation the hub holds (yours first) or a GitHub token of
yours that the hub's git proxy guards (--repo-secret chooses). Access is read-only
unless --access write.

--grant attaches any other stored credential, narrowed as its kind needs:
--grant <secret>[,namespace=<ns>][,context=<ctx>][,host=<h>][,registry=<r>][,env=<KEY>][,ttl=<d>]
— repeat a key for several values. A credential you may not grant yourself is
requested from an approver instead, with --justification (default: the goal) as
the reason; the request id and who can approve it are printed.

On an executor that isolates, the project's sandbox needs a Claude credential of
its own: one of yours that is complete is granted for you, or name it with
--claude-secret. The project's dashboard link is printed; --run starts it.`,
	Args: cobra.NoArgs,
	RunE: runRemoteInit,
}

// initView is what `init --json` prints, and what the human output is read
// from.
type initView struct {
	Hub     string `json:"hub"`
	Project struct {
		Idx  int    `json:"idx"`
		Name string `json:"name"`
		Path string `json:"path"`
		URL  string `json:"url"`
	} `json:"project"`
	Repositories []string          `json:"repositories"`
	Executor     string            `json:"executor,omitempty"`
	Attached     *repoAttachResult `json:"attached,omitempty"`
	// Granted are the --grant credentials opened with the project.
	Granted []string `json:"granted,omitempty"`
	// Requested are the requests filed for credentials the caller may not
	// grant, repositories' included.
	Requested []hubclient.GrantRequest `json:"requested,omitempty"`
	Claude    *initClaude              `json:"claude,omitempty"`
	Run       *initRunView             `json:"run,omitempty"`
	Notes     []string                 `json:"notes,omitempty"`
	Problems  []string                 `json:"problems,omitempty"`
}

type initClaude struct {
	State   string `json:"state"`
	Granted string `json:"granted,omitempty"`
	Reason  string `json:"reason,omitempty"`
	Remedy  string `json:"remedy,omitempty"`
}

type initRunView struct {
	Started bool   `json:"started"`
	Message string `json:"message,omitempty"`
}

// checkout is what init reads from the directory it runs in.
type checkout struct {
	Top    string
	Origin *gitremote.Repo
}

func runRemoteInit(cmd *cobra.Command, _ []string) error {
	out := cmd.OutOrStdout()
	ctx := remoteContext(cmd)
	if rinitName != "" && rinitDir != "" {
		return errors.New("--name and --dir both say where the project goes: give one")
	}

	// ── what this checkout is ──
	co, err := readCheckout(ctx, ".", len(rinitRepos) > 0)
	if err != nil {
		return err
	}
	repos, err := initRepositories(co)
	if err != nil {
		return err
	}
	name := strings.TrimSpace(rinitName)
	if name == "" && rinitDir == "" {
		name = defaultProjectName(co, repos)
	}
	goal, err := initGoalText(cmd)
	if err != nil {
		return err
	}
	specs := make([]hubclient.ProjectGrant, 0, len(rinitGrants))
	for _, raw := range rinitGrants {
		g, err := parseGrantSpec(raw)
		if err != nil {
			return err
		}
		specs = append(specs, g)
	}
	if _, err := repoAccessPermissions(rinitAccess); err != nil {
		return err
	}
	if len(rinitBranches) > 0 && !strings.EqualFold(rinitAccess, "write") {
		return errors.New("--branch limits where pushes may go, so it needs --access write")
	}

	c, err := remoteClient()
	if err != nil {
		return err
	}
	view := &initView{Hub: c.Base}
	for _, r := range repos {
		view.Repositories = append(view.Repositories, r.FullName())
	}
	justification := strings.TrimSpace(rinitJustification)
	if justification == "" {
		justification = "cloop remote init for " + strings.Join(view.Repositories, ", ") + ": " + goal
	}

	// ── what can be checked before anything exists ──
	me, err := c.Me(ctx)
	if err != nil {
		return remoteErr(c, err)
	}
	perms := stringSet(me["global_permissions"])
	executorID, note, err := chooseInitExecutor(ctx, cmd, c, perms)
	if err != nil {
		return err
	}
	view.Executor = executorID
	if note != "" {
		view.Notes = append(view.Notes, note)
	}
	var direct, deferred []hubclient.ProjectGrant
	if perms["project.write"] {
		// Checked only for a caller the hub would let create a project at
		// all. Anyone else is refused by the hub itself, below, exactly as
		// the dashboard's New Project button would refuse them — not by a
		// guess made here about credentials they will never get to use.
		visible, catalog := secretsInView(ctx, c, perms)
		if direct, deferred, err = planGrants(specs, visible, catalog, perms, repos); err != nil {
			return err
		}
		if len(repos) > 0 {
			if err := checkRepoCredentialsExist(visible, catalog, rinitRepoSecret); err != nil {
				return err
			}
		}
	} else {
		direct = specs
	}

	// ── create ──
	req := hubclient.NewProjectRequest{
		Goal: goal, Provider: rinitProvider, Model: rinitModel, Effort: rinitEffortLevel,
		ExecutorID: executorID, Grants: direct,
	}
	if rinitDir != "" {
		req.Dir = rinitDir
	} else {
		req.Name = name
	}
	created, err := c.CreateProject(ctx, req)
	if err != nil {
		if ae, ok := hubclient.AsAPIError(err); ok && ae.Status == 400 && strings.HasPrefix(ae.Message, "dir is required") &&
			!strings.Contains(ae.Message, "name") {
			return fmt.Errorf("%s predates creating a project by name: say where on the hub it goes with --dir <path>", c.Base)
		}
		return remoteErr(c, err)
	}
	p, err := findCreatedProject(ctx, c, created)
	if err != nil {
		return err
	}
	view.Project.Idx, view.Project.Name, view.Project.Path = p.Idx, p.Name, p.Path
	view.Project.URL = c.DashboardURL(p.Path)
	for _, g := range direct {
		view.Granted = append(view.Granted, g.SecretRef)
	}
	if !remoteJSON {
		fmt.Fprintf(out, "Created %s on %s at %s", p.Name, c.Base, p.Path)
		if executorID != "" {
			fmt.Fprintf(out, ", bound to executor %s", executorID)
		}
		fmt.Fprintln(out, ".")
		for _, g := range direct {
			fmt.Fprintf(out, "Granted %s to it.\n", g.SecretRef)
		}
	}

	// ── its repositories ──
	if len(repos) > 0 {
		res, err := attachRepositories(ctx, c, p, repos, repoAttachOptions{
			Secret: rinitRepoSecret, Access: rinitAccess, Branches: rinitBranches, Justification: justification,
		})
		view.Attached = res
		if res != nil {
			view.Requested = append(view.Requested, res.Requested...)
			if !remoteJSON {
				printAttachResult(out, res)
			}
			for _, r := range res.Unreached {
				view.Problems = append(view.Problems, fmt.Sprintf("no credential you may use or ask for reaches %s", r))
			}
		}
		if err != nil {
			view.Problems = append(view.Problems, err.Error())
		}
	}

	// ── the credentials it needs an approver for ──
	for _, g := range deferred {
		r, err := c.RequestGrant(ctx, hubclient.FileGrantRequest{
			SecretRef: g.SecretRef, Subject: "project:" + p.Path, Scope: g.Scope, TTLMinutes: g.TTLMinutes,
			Justification: justification, Repos: g.Repos, Permissions: g.Permissions, Branches: g.Branches,
			Namespaces: g.Namespaces, Contexts: g.Contexts, Hosts: g.Hosts, Registries: g.Registries,
			EnvKeys: g.EnvKeys, Writable: g.Writable,
		})
		if err != nil {
			view.Problems = append(view.Problems, fmt.Sprintf("request %s: %v", g.SecretRef, remoteErr(c, err)))
			continue
		}
		view.Requested = append(view.Requested, r)
		if !remoteJSON {
			printRequestFiled(out, r)
		}
	}

	// ── the Claude credential its sandbox signs in with ──
	view.Claude = settleClaudeCredential(ctx, c, p, view)
	if !remoteJSON && view.Claude != nil {
		switch {
		case view.Claude.Granted != "":
			fmt.Fprintf(out, "Granted your Claude credential %s to its sandbox.\n", view.Claude.Granted)
		case view.Claude.State != "ok" && view.Claude.Reason != "":
			fmt.Fprintf(out, "Its sandbox has no Claude credential yet.\n  %s\n", view.Claude.Reason)
			if view.Claude.Remedy != "" {
				fmt.Fprintf(out, "  %s\n", view.Claude.Remedy)
			}
		}
	}

	if !remoteJSON {
		fmt.Fprintf(out, "Dashboard: %s\n", view.Project.URL)
	}

	// ── run ──
	if rinitRun {
		view.Run = &initRunView{}
		switch {
		case len(view.Problems) > 0:
			view.Run.Message = "not started: " + view.Problems[0]
		case pendingFor(view.Requested):
			view.Run.Message = "not started: it waits for the requests above — run it once they are approved: " +
				"cloop remote run " + quoteArg(p.Name)
		case view.Claude != nil && view.Claude.State != "ok" && view.Claude.State != "":
			view.Run.Message = "not started: its sandbox has no Claude credential — grant one from the project's " +
				"Overview in the dashboard, then start it with `cloop remote run " + quoteArg(p.Name) + "`"
		default:
			msg, err := c.Run(ctx, p.Idx)
			if err != nil {
				view.Run.Message = "not started: " + remoteErr(c, err).Error()
			} else {
				view.Run.Started, view.Run.Message = true, msg
			}
		}
		if !remoteJSON {
			if view.Run.Started {
				fmt.Fprintf(out, "Started %s. Follow it with: cloop remote logs %s --follow\n", p.Name, quoteArg(p.Name))
			} else {
				fmt.Fprintf(out, "Run %s\n", view.Run.Message)
			}
		}
	}

	if remoteJSON {
		if err := json.NewEncoder(out).Encode(view); err != nil {
			return err
		}
	} else {
		for _, n := range view.Notes {
			fmt.Fprintf(out, "note: %s\n", n)
		}
	}
	switch {
	case len(view.Problems) > 0:
		return fmt.Errorf("%s was created, but %s", p.Name, strings.Join(view.Problems, "; "))
	case view.Run != nil && !view.Run.Started:
		return fmt.Errorf("%s was created, but its run was %s", p.Name, view.Run.Message)
	}
	return nil
}

// readCheckout reads the git checkout dir is in: its top level and the
// repository its origin remote names. Outside a checkout, or without an
// origin, that is an error unless repositories were named some other way.
func readCheckout(ctx context.Context, dir string, haveRepos bool) (checkout, error) {
	var co checkout
	top, err := gitOutput(ctx, dir, "rev-parse", "--show-toplevel")
	if err != nil {
		if haveRepos {
			return co, nil
		}
		return co, errors.New("run `cloop remote init` inside a git checkout of the repository the project works on, " +
			"or name the repositories with --repo owner/name")
	}
	co.Top = top
	origin, err := gitOutput(ctx, top, "remote", "get-url", "origin")
	if err != nil || origin == "" {
		if haveRepos {
			return co, nil
		}
		return co, errors.New("this checkout has no origin remote: add one (git remote add origin " +
			"https://github.com/<owner>/<name>) or name the repositories with --repo owner/name")
	}
	repo, err := gitremote.ParseGitHub(origin)
	switch {
	case err == nil:
		co.Origin = &repo
	case errors.Is(err, gitremote.ErrCredential):
		return co, fmt.Errorf("the origin remote %w", err)
	case errors.Is(err, gitremote.ErrNotGitHub):
		if haveRepos {
			return co, nil
		}
		return co, fmt.Errorf("the origin remote %w — the hub reaches repositories through a GitHub App or a GitHub token, "+
			"so name the GitHub repositories the project works on with --repo owner/name", err)
	default:
		return co, fmt.Errorf("the origin remote %w — fix it, or name the repositories with --repo owner/name", err)
	}
	return co, nil
}

// gitOutput runs git in dir and returns its trimmed output.
func gitOutput(ctx context.Context, dir string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "git", append([]string{"-C", dir}, args...)...)
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0", "LC_ALL=C")
	raw, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(raw)), nil
}

// initRepositories is the origin's repository and every --repo, once each.
func initRepositories(co checkout) ([]gitremote.Repo, error) {
	var repos []gitremote.Repo
	seen := map[string]bool{}
	if co.Origin != nil {
		repos = append(repos, *co.Origin)
		seen[strings.ToLower(co.Origin.FullName())] = true
	}
	if len(rinitRepos) > 0 {
		extra, err := parseRepoArgs(rinitRepos)
		if err != nil {
			return nil, err
		}
		for _, r := range extra {
			if key := strings.ToLower(r.FullName()); !seen[key] {
				seen[key] = true
				repos = append(repos, r)
			}
		}
	}
	return repos, nil
}

// defaultProjectName is the name of the repository the checkout is of, else
// the first named, else the checkout's directory.
func defaultProjectName(co checkout, repos []gitremote.Repo) string {
	switch {
	case co.Origin != nil:
		return co.Origin.Name
	case len(repos) > 0:
		return repos[0].Name
	case co.Top != "":
		return filepath.Base(co.Top)
	}
	return ""
}

// initGoalText is --goal, or asked for at an interactive terminal.
func initGoalText(cmd *cobra.Command) (string, error) {
	if g := strings.TrimSpace(rinitGoal); g != "" {
		return g, nil
	}
	if !interactive() {
		return "", errors.New("a project needs a goal — what it should achieve, which cloop plans from: " +
			"--goal \"Ship rate limiting for the public API\"")
	}
	fmt.Fprint(cmd.ErrOrStderr(), "Goal (what the project should achieve): ")
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if g := strings.TrimSpace(line); g != "" {
		return g, nil
	}
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	return "", errors.New("a project needs a goal: --goal \"…\"")
}

// interactive reports whether both ends of this command are a terminal.
func interactive() bool {
	return term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stdout.Fd()))
}

// chooseInitExecutor resolves --executor among the executors open to the
// caller, or — at an interactive terminal, for a caller who may bind one —
// offers them. Empty means the hub's default, and the note then says when
// that default is one the caller's runs would be refused on.
func chooseInitExecutor(ctx context.Context, cmd *cobra.Command, c *hubclient.Client, perms map[string]bool) (string, string, error) {
	ref := strings.TrimSpace(rinitExecutor)
	if ref == "" && !perms["executor.read"] {
		return "", "", nil
	}
	list, err := c.Executors(ctx)
	if err != nil {
		if ref == "" {
			return "", "", nil // only a note was at stake
		}
		return "", "", remoteErr(c, err)
	}
	if ref != "" {
		e, err := resolveExecutor(list, ref)
		if err != nil {
			return "", "", err
		}
		return e.ID, "", nil
	}
	note := ""
	for _, e := range list.Executors {
		if e.ID == list.DefaultID && !e.Admitted {
			note = fmt.Sprintf("the hub's default executor %s is restricted and you are not on its access list, so its runs "+
				"would be refused: choose one with --executor (see `cloop remote executors`) or ask an administrator to admit you", e.ID)
		}
	}
	if !interactive() || !perms["executor.manage"] {
		return "", note, nil
	}
	var usable []hubclient.Executor
	for _, e := range availableExecutors(list) {
		if ok, _ := e.Usable(); ok {
			usable = append(usable, e)
		}
	}
	if len(usable) < 2 {
		return "", note, nil
	}
	errOut := cmd.ErrOrStderr()
	fmt.Fprintln(errOut, "Where should the project run?")
	for i, e := range usable {
		note := ""
		if e.ID == list.DefaultID {
			note = " (the hub's default)"
		}
		fmt.Fprintf(errOut, "  %d) %s — %s%s\n", i+1, e.ID, orDash(e.Kind), note)
	}
	fmt.Fprint(errOut, "Choose a number (Enter for the hub's default): ")
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	line = strings.TrimSpace(line)
	if line == "" {
		return "", note, nil
	}
	n, err := strconv.Atoi(line)
	if err != nil || n < 1 || n > len(usable) {
		return "", "", fmt.Errorf("%q is not one of the numbers offered", line)
	}
	return usable[n-1].ID, "", nil
}

// secretsInView reads the secrets the caller can see (to grant) and the ones
// they can ask for. Either is empty for a caller without the permission.
func secretsInView(ctx context.Context, c *hubclient.Client, perms map[string]bool) ([]hubclient.Secret, []hubclient.CatalogEntry) {
	var visible []hubclient.Secret
	var catalog []hubclient.CatalogEntry
	if perms["secret.own"] {
		if list, err := c.Secrets(ctx); err == nil {
			visible = list.Secrets
		}
	}
	if perms["secret.request"] {
		if cat, err := c.SecretCatalog(ctx); err == nil {
			catalog = cat
		}
	}
	return visible, catalog
}

// planGrants splits the --grant credentials into those the caller may grant
// with the creation — their own, or any with secret.grant hub-wide, which is
// what the hub checks — and those to ask an approver for afterwards. A secret
// they can neither see nor ask for is refused now, before anything exists.
func planGrants(specs []hubclient.ProjectGrant, visible []hubclient.Secret, catalog []hubclient.CatalogEntry,
	perms map[string]bool, repos []gitremote.Repo) (direct, deferred []hubclient.ProjectGrant, err error) {
	for _, g := range specs {
		kind := ""
		mine := false
		for _, s := range visible {
			if s.Name == g.SecretRef || s.ID == g.SecretRef {
				kind, mine = s.Kind, s.Mine && s.Personal
				break
			}
		}
		askable := false
		for _, e := range catalog {
			if e.Name == g.SecretRef || e.ID == g.SecretRef {
				askable = true
				if kind == "" {
					kind = e.Kind
				}
				break
			}
		}
		if kind == "" {
			return nil, nil, fmt.Errorf("--grant %s: there is no secret by that name that you can see or ask for "+
				"(an approver can tell you what is stored)", g.SecretRef)
		}
		if (kind == "github_app" || kind == "github_pat") && len(g.Repos) == 0 {
			for _, r := range repos {
				g.Repos = append(g.Repos, r.FullName())
			}
			if len(g.Permissions) == 0 {
				g.Permissions, _ = repoAccessPermissions(rinitAccess)
				g.Branches = rinitBranches
			}
		}
		switch {
		case mine || perms["secret.grant"]:
			direct = append(direct, g)
		case askable:
			deferred = append(deferred, g)
		default:
			return nil, nil, fmt.Errorf("--grant %s: you may not grant it and it is not offered for requests", g.SecretRef)
		}
	}
	return direct, deferred, nil
}

// checkRepoCredentialsExist refuses, before anything is created, a project
// whose repositories nothing could reach: no GitHub credential the caller can
// see, and none they could ask for.
func checkRepoCredentialsExist(visible []hubclient.Secret, catalog []hubclient.CatalogEntry, named string) error {
	named = strings.TrimSpace(named)
	found := false
	for _, s := range visible {
		if named != "" && (s.Name == named || s.ID == named) {
			return nil
		}
		if s.Kind == "github_app" || s.Kind == "github_pat" {
			found = true
		}
	}
	for _, e := range catalog {
		if named != "" && (e.Name == named || e.ID == named) {
			return nil
		}
		if e.Kind == "github_app" {
			found = true
		}
	}
	switch {
	case named != "":
		return fmt.Errorf("--repo-secret %s: there is no secret by that name that you can see or ask for", named)
	case !found:
		return errors.New("there is no GitHub credential on this hub that you could use or ask for: an administrator " +
			"connects the organisation's GitHub App (Settings → GitHub App), or you store a GitHub token of your own " +
			"(the Secrets panel) — then run this again")
	}
	return nil
}

// findCreatedProject is the project the hub just created, as the caller's
// project list addresses it.
func findCreatedProject(ctx context.Context, c *hubclient.Client, np hubclient.NewProject) (hubclient.Project, error) {
	projects, err := c.Projects(ctx)
	if err != nil {
		return hubclient.Project{}, remoteErr(c, err)
	}
	for _, p := range projects {
		if p.Path == np.Dir {
			return p, nil
		}
	}
	return hubclient.Project{}, fmt.Errorf("the hub created %s but does not list it for you: open the dashboard (%s)",
		np.Dir, c.DashboardURL(np.Dir))
}

// settleClaudeCredential makes sure the project's sandbox has a Claude
// credential when it needs one: --claude-secret, else the caller's own
// complete one when there is exactly one.
func settleClaudeCredential(ctx context.Context, c *hubclient.Client, p hubclient.Project, view *initView) *initClaude {
	hc, err := c.HarnessCredential(ctx, p.Idx)
	if err != nil {
		view.Notes = append(view.Notes, "could not check the Claude credential its sandbox would sign in with: "+
			firstLine(remoteErr(c, err).Error()))
		return nil
	}
	if !hc.Applies {
		return nil
	}
	res := &initClaude{State: hc.State}
	if hc.State == "ok" {
		return res
	}
	pick := strings.TrimSpace(rinitClaudeSecret)
	if pick == "" {
		var mine []hubclient.HarnessCandidate
		for _, cand := range hc.Candidates {
			if cand.Complete && cand.Mine {
				mine = append(mine, cand)
			}
		}
		if len(mine) == 1 {
			pick = mine[0].ID
		}
	}
	if pick == "" {
		// The hub words both for the project's provider; these stand in only
		// when it says nothing.
		noun := "Claude credential"
		if hc.Provider == "copilot" {
			noun = "Copilot credential"
		}
		res.Reason, res.Remedy = strings.TrimSpace(hc.Reason), strings.TrimSpace(hc.Remedy)
		if res.Reason == "" {
			res.Reason = "no grant gives the project's sandbox a " + noun
		}
		if res.Remedy == "" {
			res.Remedy = "Grant one from the project's Overview in the dashboard (" + noun + ")."
		}
		return res
	}
	granted, err := c.GrantHarnessCredential(ctx, p.Idx, pick)
	if err != nil {
		view.Problems = append(view.Problems, "grant the Claude credential: "+remoteErr(c, err).Error())
		res.Reason = "the grant was refused"
		return res
	}
	res.State = granted.State
	if granted.Granted != nil {
		res.Granted = granted.Granted.SecretName
	}
	if res.State != "ok" {
		res.Reason, res.Remedy = strings.TrimSpace(granted.Reason), strings.TrimSpace(granted.Remedy)
	}
	return res
}

// pendingFor reports whether any of the requests still waits.
func pendingFor(reqs []hubclient.GrantRequest) bool {
	for _, r := range reqs {
		if r.State == "pending" {
			return true
		}
	}
	return false
}

// stringSet reads a JSON array of strings into a set.
func stringSet(v any) map[string]bool {
	out := map[string]bool{}
	if list, ok := v.([]any); ok {
		for _, item := range list {
			if s, ok := item.(string); ok {
				out[s] = true
			}
		}
	}
	return out
}

// parseGrantSpec reads one --grant: a secret's name, then key=value pairs
// narrowing it, separated by commas. A key given twice adds a value.
func parseGrantSpec(raw string) (hubclient.ProjectGrant, error) {
	parts := strings.Split(raw, ",")
	g := hubclient.ProjectGrant{SecretRef: strings.TrimSpace(parts[0])}
	if g.SecretRef == "" || strings.Contains(g.SecretRef, "=") {
		return g, fmt.Errorf("--grant %q: start with the secret's name, then key=value pairs (--grant staging,namespace=payments)", raw)
	}
	for _, part := range parts[1:] {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		key, value, hasValue := strings.Cut(part, "=")
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.TrimSpace(value)
		if !hasValue && key != "writable" {
			return g, fmt.Errorf("--grant %s: %q is not key=value", g.SecretRef, part)
		}
		if hasValue && value == "" {
			return g, fmt.Errorf("--grant %s: %s has no value", g.SecretRef, key)
		}
		switch key {
		case "repo", "repos":
			r, err := gitremote.ParseRepo(value)
			if err != nil {
				return g, fmt.Errorf("--grant %s: %w", g.SecretRef, err)
			}
			g.Repos = append(g.Repos, r.FullName())
		case "access":
			perms, err := repoAccessPermissions(value)
			if err != nil {
				return g, fmt.Errorf("--grant %s: %w", g.SecretRef, err)
			}
			g.Permissions = append(g.Permissions, perms...)
		case "permission", "permissions":
			g.Permissions = append(g.Permissions, value)
		case "branch", "branches":
			g.Branches = append(g.Branches, value)
		case "namespace", "namespaces":
			g.Namespaces = append(g.Namespaces, value)
		case "context", "contexts":
			g.Contexts = append(g.Contexts, value)
		case "host", "hosts":
			g.Hosts = append(g.Hosts, value)
		case "registry", "registries":
			g.Registries = append(g.Registries, value)
		case "env", "env-key", "env_key", "env_keys":
			g.EnvKeys = append(g.EnvKeys, value)
		case "scope":
			g.Scope = value
		case "writable":
			b := true
			if hasValue {
				parsed, err := strconv.ParseBool(value)
				if err != nil {
					return g, fmt.Errorf("--grant %s: writable=%q is not true or false", g.SecretRef, value)
				}
				b = parsed
			}
			g.Writable = b
		case "ttl":
			d, err := time.ParseDuration(value)
			if err != nil || d < time.Minute {
				return g, fmt.Errorf("--grant %s: ttl=%q is not a duration of a minute or more (24h, 7d is 168h)", g.SecretRef, value)
			}
			g.TTLMinutes = int(d / time.Minute)
		default:
			return g, fmt.Errorf("--grant %s: unknown key %q (repo, access, permission, branch, namespace, context, "+
				"host, registry, env, scope, writable, ttl)", g.SecretRef, key)
		}
	}
	return g, nil
}

func init() {
	f := remoteInitCmd.Flags()
	f.StringVar(&rinitGoal, "goal", "", "What the project should achieve; cloop plans its tasks from it")
	f.StringVar(&rinitExecutor, "executor", "", "Bind the project to this executor, by id or name (see: cloop remote executors)")
	f.StringSliceVar(&rinitRepos, "repo", nil, "Another GitHub repository the project works on, as owner/name; repeatable")
	f.StringArrayVar(&rinitGrants, "grant", nil,
		"Another stored credential to give the project: <secret>[,key=value…]; repeatable")
	f.BoolVar(&rinitRun, "run", false, "Start the project's first run once it is set up")
	f.StringVar(&rinitName, "name", "", "The project's name, and its directory under the hub's projects root (default: the repository's name)")
	f.StringVar(&rinitDir, "dir", "", "The project's directory on the hub, instead of --name")
	f.StringVar(&rinitRepoSecret, "repo-secret", "", "The GitHub App or token to grant the repositories through (default: chosen for you)")
	f.StringVar(&rinitAccess, "access", "read", "Repository access: read, or write (push branches and open pull requests)")
	f.StringSliceVar(&rinitBranches, "branch", nil, "Limit pushes to these branches (with --access write); repeatable")
	f.StringVar(&rinitProvider, "provider", "", "AI provider (default: the hub's)")
	f.StringVar(&rinitModel, "model", "", "Model (default: the provider's)")
	f.StringVar(&rinitEffortLevel, "effort", "", "Model effort: low, medium, high, xhigh or max")
	f.StringVar(&rinitClaudeSecret, "claude-secret", "", "The env secret holding the credential its sandbox signs in with: Claude's, or COPILOT_GITHUB_TOKEN for a copilot project")
	f.StringVar(&rinitJustification, "justification", "", "Why, for any credential requested from an approver (default: the goal)")
	f.BoolVar(&remoteJSON, "json", false, "Print what was created, granted and requested as JSON")
	remoteCmd.AddCommand(remoteInitCmd)
}
