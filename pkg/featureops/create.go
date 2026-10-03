package featureops

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/boundedread"
	"github.com/blechschmidt/cloop/pkg/feature"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// ErrNested is returned when a feature is asked for inside a feature.
var ErrNested = errors.New("a feature cannot have features of its own — create it on the project instead")

// ErrExists is returned when the feature's directory or branch is taken.
var ErrExists = errors.New("feature already exists")

// maxTasks bounds the initial task list a feature can be created with. The
// list arrives from an HTTP request; the plan it seeds is for a person to
// have written, not for a script to fill.
const maxTasks = 200

// maxTaskTitle bounds one initial task's title.
const maxTaskTitle = 500

// CreateOptions describes a new feature.
type CreateOptions struct {
	// ProjectDir is the parent project: the top level of a git work tree
	// that is not itself a feature. Must be absolute.
	ProjectDir string
	// Name is the human name. The slug is derived from it unless Slug is set.
	Name string
	Slug string
	// Description is the feature's goal. Empty uses Name.
	Description string
	// Base is the branch to cut the feature from and to target with its pull
	// request. Empty picks DefaultBase.
	Base string

	// Run settings, independent of the parent's.
	AutoEvolve  bool
	Innovate    bool
	Parallel    bool
	MaxParallel int

	// Tasks seeds the feature's plan, one title per task, in order. Empty
	// leaves the plan empty, and the first run decomposes the goal.
	Tasks []string

	// AutoPR asks the hub to open the pull request when the plan completes.
	AutoPR bool

	CreatedBy string
	// Now is the clock; nil uses time.Now.
	Now func() time.Time
}

// Create makes a new feature: a worktree of the project's repository on a new
// branch, locked against pruning, with its own cloop state seeded from the
// parent's settings.
//
// On failure after the worktree exists, everything this call created is torn
// down again — the worktree, the branch, the exclude entry is left (it is
// harmless and shared) — so a failed create never leaves a half-feature that
// the next attempt trips over.
func Create(ctx context.Context, opts CreateOptions) (*feature.Info, error) {
	now := time.Now
	if opts.Now != nil {
		now = opts.Now
	}
	project := filepath.Clean(opts.ProjectDir)
	if !filepath.IsAbs(project) {
		return nil, fmt.Errorf("project directory %q is not absolute", opts.ProjectDir)
	}
	if _, _, nested := feature.ParentOf(project); nested {
		return nil, ErrNested
	}

	name := strings.TrimSpace(opts.Name)
	slug := strings.TrimSpace(opts.Slug)
	if slug == "" {
		slug = feature.Slugify(name)
	}
	if err := feature.ValidSlug(slug); err != nil {
		if name != "" {
			return nil, fmt.Errorf("%q cannot name a feature: %w", name, err)
		}
		return nil, err
	}
	if name == "" {
		name = slug
	}
	tasks, err := normaliseTasks(opts.Tasks)
	if err != nil {
		return nil, err
	}
	if opts.MaxParallel < 0 {
		return nil, fmt.Errorf("max parallel must not be negative, got %d", opts.MaxParallel)
	}

	existing, err := feature.List(project)
	if err != nil {
		return nil, fmt.Errorf("list existing features: %w", err)
	}
	if len(existing) >= feature.MaxPerProject {
		return nil, fmt.Errorf("this project already has %d features, the most one project may hold — remove one first", len(existing))
	}

	top, err := repoTopLevel(ctx, project)
	if err != nil {
		return nil, fmt.Errorf("%s is not a git repository, and a feature is a git worktree of one: %w", project, err)
	}
	if !sameDir(top, project) {
		return nil, fmt.Errorf("features need the project directory to be the top of its git repository; %s is inside %s", project, top)
	}

	dest := feature.Path(project, slug)
	if _, err := os.Lstat(dest); err == nil {
		return nil, fmt.Errorf("%w: %s is already present", ErrExists, dest)
	}
	branch := feature.BranchName(slug)
	if refExists(ctx, project, "refs/heads/"+branch) {
		return nil, fmt.Errorf("%w: branch %s is already present — pick another name, or delete the branch", ErrExists, branch)
	}

	base := strings.TrimSpace(opts.Base)
	if base == "" {
		if base, err = DefaultBase(ctx, project); err != nil {
			return nil, err
		}
	}
	if err := validBranchName(ctx, project, base); err != nil {
		return nil, fmt.Errorf("base: %w", err)
	}
	if strings.HasPrefix(base, feature.BranchPrefix) {
		return nil, fmt.Errorf("base %q is itself a feature branch; features are cut from the project's own branches", base)
	}
	baseRef, err := resolveBase(ctx, project, base)
	if err != nil {
		return nil, err
	}
	baseCommit, err := runGit(ctx, project, "rev-parse", "--verify", baseRef+"^{commit}")
	if err != nil {
		return nil, fmt.Errorf("resolve base %s: %w", base, err)
	}

	if err := ensureControlDirExcluded(ctx, project); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(feature.Dir(project), 0o755); err != nil {
		return nil, fmt.Errorf("create %s: %w", feature.Dir(project), err)
	}

	// --no-track: with a remote-tracking start point git would otherwise make
	// origin/<base> the feature's upstream, and a plain `git push` from the
	// worktree would then either be refused or — with push.default=upstream —
	// push the feature onto the base branch. The upstream is set below to the
	// feature's own name instead.
	if _, err := runGit(ctx, project, "worktree", "add", "--no-track", "-b", branch, dest, baseCommit); err != nil {
		return nil, fmt.Errorf("create the worktree: %w", err)
	}
	created := true
	defer func() {
		if created {
			rollbackCreate(project, dest, branch)
		}
	}()

	// Locked so that nothing collects it by accident: `git worktree prune`
	// (which cloop's task-worktree cleanup and `git gc` both run) removes
	// the bookkeeping of any worktree whose directory is briefly unreachable,
	// and a feature is long-lived work, not scratch.
	if _, err := runGit(ctx, project, "worktree", "lock", "--reason",
		"cloop feature "+slug+" - remove with: cloop feature remove "+slug, dest); err != nil {
		return nil, fmt.Errorf("lock the worktree: %w", err)
	}

	if hasRemote(ctx, project, "origin") {
		// A plain `git push` in the worktree now publishes the feature under
		// its own name and nowhere else. The harness is told to commit here;
		// harnesses also push by reflex, and this makes the reflex safe.
		if _, err := runGit(ctx, project, "config", "branch."+branch+".remote", "origin"); err != nil {
			return nil, fmt.Errorf("set the branch's remote: %w", err)
		}
		if _, err := runGit(ctx, project, "config", "branch."+branch+".merge", "refs/heads/"+branch); err != nil {
			return nil, fmt.Errorf("set the branch's upstream: %w", err)
		}
	}

	if err := hideTrackedControlFiles(ctx, dest); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Join(dest, feature.ControlDir), 0o755); err != nil {
		return nil, fmt.Errorf("create the feature's control directory: %w", err)
	}
	if err := removeCheckedOutState(dest); err != nil {
		return nil, err
	}
	if err := copyControlFiles(project, dest); err != nil {
		return nil, err
	}

	desc := strings.TrimSpace(opts.Description)
	meta := &feature.Meta{
		Slug:        slug,
		Title:       name,
		Description: desc,
		Branch:      branch,
		Base:        base,
		BaseCommit:  baseCommit,
		Parent:      project,
		CreatedAt:   now().UTC(),
		CreatedBy:   strings.TrimSpace(opts.CreatedBy),
		AutoPR:      opts.AutoPR,
	}
	if err := seedState(project, dest, meta, opts, tasks, now()); err != nil {
		return nil, err
	}
	// The record last: it is what makes the directory a feature to every
	// reader, so it must not exist before the state it describes does.
	if err := feature.SaveMeta(dest, meta); err != nil {
		return nil, fmt.Errorf("write the feature record: %w", err)
	}
	created = false
	return &feature.Info{Path: dest, Meta: meta}, nil
}

// rollbackCreate tears down a partially created feature. Best-effort, and on
// a fresh context: the caller's may be the one that expired.
func rollbackCreate(project, dest, branch string) {
	ctx, cancel := context.WithTimeout(context.Background(), gitTimeout)
	defer cancel()
	_, _ = runGit(ctx, project, "worktree", "unlock", dest)
	if _, err := runGit(ctx, project, "worktree", "remove", "--force", dest); err != nil {
		_ = os.RemoveAll(dest)
	}
	_, _ = runGit(ctx, project, "worktree", "prune")
	// -D, not -d: the branch was created by this call a moment ago and holds
	// nothing but the base commit, so there is no work on it to protect.
	_, _ = runGit(ctx, project, "branch", "-D", branch)
	_, _ = runGit(ctx, project, "config", "--remove-section", "branch."+branch)
}

// hasRemote reports whether the repository has a remote called name.
func hasRemote(ctx context.Context, dir, name string) bool {
	_, err := runGit(ctx, dir, "remote", "get-url", name)
	return err == nil
}

// excludeMarker introduces the exclude entry this package writes, so a human
// reading the file can tell where it came from.
const excludeMarker = "# cloop: project control state, including feature worktrees, is never committed"

// ensureControlDirExcluded makes sure git ignores every worktree's .cloop/.
//
// A feature worktree lives inside the parent's .cloop/, and has one of its own.
// In a repository that does not already ignore .cloop/ — `cloop init` only adds
// .cloop/env.yaml to .gitignore — two things go wrong: the parent's `git add -A`
// records each feature as an embedded repository, and the feature's commits
// sweep up its state database. Both are fixed by one line in the repository's
// shared exclude file, which unlike .gitignore is not itself committed and so
// changes nothing anyone else sees.
//
// Files already tracked under .cloop/ (a committed sandbox.yaml, say) stay
// tracked: exclude rules only apply to untracked paths.
func ensureControlDirExcluded(ctx context.Context, project string) error {
	probe := feature.ControlDir + "/state.db"
	_, err := runGit(ctx, project, "check-ignore", "-q", "--no-index", probe)
	if err == nil {
		return nil // already ignored
	}
	if exitCode(err) != 1 {
		return fmt.Errorf("check whether %s is ignored: %w", probe, err)
	}
	cd, err := commonDir(ctx, project)
	if err != nil {
		return fmt.Errorf("locate the repository's git directory: %w", err)
	}
	info := filepath.Join(cd, "info")
	if err := os.MkdirAll(info, 0o755); err != nil {
		return fmt.Errorf("create %s: %w", info, err)
	}
	path := filepath.Join(info, "exclude")
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	_, werr := fmt.Fprintf(f, "\n%s\n/%s/\n", excludeMarker, feature.ControlDir)
	cerr := f.Close()
	if werr != nil {
		return fmt.Errorf("write %s: %w", path, werr)
	}
	if cerr != nil {
		return fmt.Errorf("close %s: %w", path, cerr)
	}
	return nil
}

// hideTrackedControlFiles marks every file the repository tracks under .cloop/
// skip-worktree in the feature's worktree.
//
// Some repositories commit their .cloop/ — a sandbox.yaml, a shared config,
// sometimes a whole state.db. The exclude rule cannot help with those, because
// ignore rules only apply to untracked paths, so the feature's own state
// database, written over the committed one a moment later, would show as a
// modification and be swept into the feature's first `git add -A` — and from
// there into its pull request. skip-worktree tells git to treat the committed
// copies as authoritative in this worktree and to stop looking at what is on
// disk. It lives in the worktree's own index, so the project's checkout is not
// affected.
func hideTrackedControlFiles(ctx context.Context, dest string) error {
	out, err := runGit(ctx, dest, "ls-files", "-z", "--", feature.ControlDir)
	if err != nil {
		return fmt.Errorf("list tracked files under %s: %w", feature.ControlDir, err)
	}
	var paths []string
	for _, p := range strings.Split(out, "\x00") {
		if p != "" {
			paths = append(paths, p)
		}
	}
	if len(paths) == 0 {
		return nil
	}
	args := append([]string{"update-index", "--skip-worktree", "--"}, paths...)
	if _, err := runGit(ctx, dest, args...); err != nil {
		return fmt.Errorf("hide the repository's committed %s files from the feature's changes: %w", feature.ControlDir, err)
	}
	return nil
}

// checkedOutStateFiles are the project-state files a repository may have
// committed under .cloop/.
var checkedOutStateFiles = []string{"state.db", "state.db-wal", "state.db-shm", "state.db-journal", "state.json"}

// removeCheckedOutState deletes the project state the worktree's checkout put
// in the feature's .cloop/.
//
// A repository that commits its .cloop/ — some do, state database and all —
// checks the *parent's* state out into every feature. Seeding the feature's
// own state on top of it would merge into that database instead of starting
// one: the feature would inherit the parent's task list and, worse, its record
// of which directory it belongs to, so a run's results could never be merged
// back into it (Task 20367 found this). The files are skip-worktree by now
// (hideTrackedControlFiles), so removing them changes nothing git reports.
// A link is removed as a link.
func removeCheckedOutState(dest string) error {
	for _, name := range checkedOutStateFiles {
		p := filepath.Join(dest, feature.ControlDir, name)
		if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove the parent's state checked out at %s: %w", p, err)
		}
	}
	return nil
}

// controlFiles are the parent's per-project files a feature inherits, with
// the mode each is written with. Provider and hook configuration, the sandbox
// specification an isolating executor enforces, per-project environment, and
// the mock provider's script (which is how tests and demos drive a run).
//
// The state database is deliberately not here: the task list is the thing a
// feature has its own of.
var controlFiles = []struct {
	name string
	mode os.FileMode
}{
	{"config.yaml", 0o600},
	{"sandbox.yaml", 0o644},
	{"env.yaml", 0o600},
	{"mock_responses.yaml", 0o644},
}

// maxControlFile bounds a copied control file.
const maxControlFile = 4 << 20

// copyControlFiles copies the parent's control files into the feature,
// skipping any the worktree already has — a sandbox.yaml committed to the
// repository is the feature's own, and overwriting it would show up as a
// change in the feature's first commit.
func copyControlFiles(project, dest string) error {
	for _, cf := range controlFiles {
		src := filepath.Join(project, feature.ControlDir, cf.name)
		dst := filepath.Join(dest, feature.ControlDir, cf.name)
		if _, err := os.Lstat(dst); err == nil {
			continue
		}
		info, err := os.Lstat(src)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("inspect %s: %w", src, err)
		}
		if !info.Mode().IsRegular() {
			// A symlink here could point anywhere on the host; copying its
			// target into a directory a sandbox may see is not something to
			// do silently.
			continue
		}
		data, err := boundedread.ReadFile(src, maxControlFile)
		if err != nil {
			return fmt.Errorf("read %s: %w", src, err)
		}
		if err := os.WriteFile(dst, data, cf.mode); err != nil {
			return fmt.Errorf("write %s: %w", dst, err)
		}
	}
	return nil
}

// normaliseTasks trims and validates the initial task titles, dropping blank
// lines — the dashboard sends a textarea split on newlines.
func normaliseTasks(in []string) ([]string, error) {
	out := make([]string, 0, len(in))
	for _, t := range in {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		if len(t) > maxTaskTitle {
			return nil, fmt.Errorf("task %q is longer than %d characters", t[:40]+"…", maxTaskTitle)
		}
		out = append(out, t)
	}
	if len(out) > maxTasks {
		return nil, fmt.Errorf("%d initial tasks is more than the %d a feature may start with", len(out), maxTasks)
	}
	return out, nil
}

// seedState writes the feature's own project state: the parent's provider,
// model, effort and instructions, the feature's own run settings, and its
// initial plan.
func seedState(project, dest string, meta *feature.Meta, opts CreateOptions, tasks []string, now time.Time) error {
	parent, err := state.LoadLite(project)
	if err != nil && !errors.Is(err, statedb.ErrProjectNotFound) {
		return fmt.Errorf("read the parent project's settings: %w", err)
	}

	goal := meta.Description
	if goal == "" {
		goal = meta.Title
	}
	st := &state.ProjectState{
		Goal:      goal,
		WorkDir:   dest,
		Status:    "initialized",
		Steps:     []state.StepResult{},
		CreatedAt: now,
		PMMode:    true,
	}
	parentInstructions := ""
	parentName := filepath.Base(project)
	if parent != nil {
		st.Provider = parent.Provider
		st.Model = parent.Model
		st.Effort = parent.Effort
		st.MaxSteps = parent.MaxSteps
		st.SkipClarify = parent.SkipClarify
		st.DefaultMaxMinutes = parent.DefaultMaxMinutes
		st.WorktreeParallel = parent.WorktreeParallel
		parentInstructions = strings.TrimSpace(parent.Instructions)
	}
	st.Instructions = joinInstructions(parentInstructions, Instructions(meta, parentName))

	st.AutoEvolve = opts.AutoEvolve
	st.InnovateMode = opts.Innovate
	st.Parallel = opts.Parallel
	st.MaxParallel = opts.MaxParallel

	plan := &pm.Plan{Goal: goal, Tasks: make([]*pm.Task, 0, len(tasks))}
	for i, title := range tasks {
		plan.Tasks = append(plan.Tasks, &pm.Task{
			ID:       i + 1,
			Title:    title,
			Priority: i + 1,
			Status:   pm.TaskPending,
		})
	}
	st.Plan = plan
	if err := st.Save(); err != nil {
		return fmt.Errorf("initialise the feature's state: %w", err)
	}
	return nil
}

// joinInstructions appends the feature's note to the parent's instructions.
func joinInstructions(parent, note string) string {
	if parent == "" {
		return note
	}
	return parent + "\n\n" + note
}

// Instructions is the note every feature's harness is given about where it is
// working. It is part of the feature's instructions — visible and editable on
// its Overview — rather than injected invisibly, so a person reading what the
// agent was told sees the same thing the agent did.
func Instructions(m *feature.Meta, parentName string) string {
	return fmt.Sprintf(`## Feature branch
This project is the feature %q of %s. It is developed in its own git worktree on branch `+"`%s`"+`, cut from `+"`%s`"+`, while other features of the same project are developed in parallel in their own worktrees.
- Commit your work to this branch. Do not switch branches, and never merge into or push to `+"`%s`"+`.
- A plain `+"`git push`"+` publishes this branch only. When the feature is complete, a pull request into `+"`%s`"+` is opened from it.
- Change only files inside this worktree.`,
		m.Title, parentName, m.Branch, m.Base, m.Base, m.Base)
}
