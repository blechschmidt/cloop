package movegit

// restoreinto.go restores a capture into a repository that already holds an
// older copy of the same project (Task 20497): the copy a project left in the
// hub's own directory for it when it moved onto a device, which a move back
// from that device rebuilds. Replacing that repository wholesale would lose
// what only it holds — the worktrees of the project's features, registered in
// it, and their branches, which the hub moves on while the project is away (a
// feature's run on the device lands its work on the hub's branch) — so the
// capture is restored into it instead, each branch and tag settled three ways
// against the capture of the copy it left behind.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// ErrLeftBehindChanged refuses to restore into a repository whose working
// copy is no longer the one its earlier capture recorded: something changed
// it since, and restoring over it would lose that change.
var ErrLeftBehindChanged = errors.New("movegit: the copy the project left behind has changed since it was captured")

// ErrRefsDiverged refuses to restore into a repository where a branch or a
// tag moved both there and in the capture since the copy was left behind:
// neither side's commits may be dropped for the other's.
var ErrRefsDiverged = errors.New("movegit: branches moved both in the copy left behind and in the capture")

// LeftBehindProblems says how the repository at dir differs from the copy
// base recorded, where it matters for RestoreInto: HEAD, the index and the
// files on disk. None means it is the copy base captured. Branches are not
// compared: they are settled one by one when the capture is restored.
func LeftBehindProblems(ctx context.Context, dir string, base Manifest, opts InspectOptions) ([]string, error) {
	if !base.Repository || base.Snapshot == nil {
		return []string{"the earlier capture recorded no repository"}, nil
	}
	o, err := Inspect(ctx, dir, opts)
	if err != nil {
		return nil, err
	}
	if !o.Repository {
		return []string{"it holds no repository"}, nil
	}
	return leftBehindProblems(base, o), nil
}

func leftBehindProblems(base Manifest, o Observed) []string {
	var out []string
	if want, got := describeHead(base.Head), describeHead(o.Head); want != got {
		out = append(out, fmt.Sprintf("HEAD is %s, it was %s", orNone(got), orNone(want)))
	} else if base.Head.Commit != o.Head.Commit {
		out = append(out, fmt.Sprintf("HEAD is at %s, it was at %s", short(orNone(o.Head.Commit)), short(orNone(base.Head.Commit))))
	}
	if base.Snapshot.IndexTree != o.IndexTree {
		out = append(out, "the index changed")
	}
	if base.Snapshot.WorktreeTree != o.WorktreeTree {
		out = append(out, "files on disk changed")
	}
	return out
}

// RestoreInto restores the capture opts.Manifest describes into the
// repository already in opts.Dir, which holds the copy base recorded. The
// repository is kept, with the worktrees registered in it, and:
//
//   - the main worktree must still be as base recorded it — HEAD, the index,
//     the files on disk — unless resuming says this restore was checked
//     already and may have begun (ErrLeftBehindChanged otherwise);
//   - the capture's objects are read from the bundle file by `git bundle
//     unbundle`, with no transport: nothing in the repository's own
//     configuration (a URL rewrite, say) decides what is read;
//   - each branch and tag is settled before anything is written: one the
//     repository has not moved since base, or that the capture moved on
//     from where the repository has it, takes the capture's value (or goes,
//     if the capture has none); one the capture has not moved since base, or
//     that the repository is ahead of, keeps the repository's (and is
//     returned); anything else refuses the restore with ErrRefsDiverged. So
//     does a branch the capture moves that a worktree has checked out, and
//     a HEAD that would land on a branch the repository keeps or another
//     worktree has checked out;
//   - the files on disk become the capture's by a two-way merge from what
//     they are now, which refuses to write over a file or a directory git
//     does not track there (an ignored one included) rather than lose it.
//     Paths under opts.Reserve's directory that the target keeps for itself
//     are left out of that merge, whatever the repository tracks there;
//   - only then are the branches, the capture's hidden refs (its snapshots,
//     stash and carried trees), HEAD and the index written.
//
// It returns the refs the repository kept, at their values there: what a
// comparison with the capture must expect instead of the capture's own.
// Remotes are the repository's own and are left alone.
func RestoreInto(ctx context.Context, opts RestoreOptions, base Manifest, resuming bool) ([]Ref, error) {
	m := opts.Manifest
	if !m.Repository {
		return nil, fmt.Errorf("movegit: the capture holds no repository to restore into %s", opts.Dir)
	}
	if !base.Repository || base.Snapshot == nil {
		return nil, fmt.Errorf("%w: the earlier capture recorded no repository", ErrLeftBehindChanged)
	}
	if err := ValidateManifest(m, ""); err != nil {
		return nil, err
	}
	if !filepath.IsAbs(opts.BundlePath) {
		return nil, fmt.Errorf("movegit: the bundle %q is not an absolute path", opts.BundlePath)
	}
	if err := VerifyFile(opts.BundlePath, *m.Bundle); err != nil {
		return nil, err
	}
	dir, err := checkDir(opts.Dir)
	if err != nil {
		return nil, err
	}
	present, err := hasDotGit(dir)
	if err != nil {
		return nil, err
	}
	if !present {
		return nil, fmt.Errorf("%w: %s", ErrNotARepository, dir)
	}
	g, err := newRunner(ctx, dir, opts.CommandTimeout)
	if err != nil {
		return nil, err
	}
	if err := g.checkTop(ctx, dir); err != nil {
		return nil, err
	}

	o, err := Inspect(ctx, dir, InspectOptions{CommandTimeout: opts.CommandTimeout})
	if err != nil {
		return nil, err
	}
	if !resuming {
		if problems := leftBehindProblems(base, o); len(problems) > 0 {
			return nil, fmt.Errorf("%w: %s", ErrLeftBehindChanged, strings.Join(problems, "; "))
		}
	}

	// The capture's objects. unbundle writes objects and nothing else.
	if _, err := g.run(ctx, dir, nil, "bundle", "unbundle", opts.BundlePath); err != nil {
		return nil, fmt.Errorf("movegit: read the bundle into %s: %w", dir, err)
	}
	if err := g.reserved(ctx, dir, opts.Reserve, m.Snapshot.WorktreeTree, m.Snapshot.IndexTree, m.Snapshot.BaseTree); err != nil {
		return nil, err
	}

	// Settle the branches and tags before anything is written.
	theirs, baseRefs, ours := map[string]string{}, map[string]string{}, map[string]string{}
	for _, list := range [][]Ref{m.Branches, m.Tags} {
		for _, r := range list {
			theirs[r.Name] = r.Object
		}
	}
	for _, list := range [][]Ref{base.Branches, base.Tags} {
		for _, r := range list {
			baseRefs[r.Name] = r.Object
		}
	}
	for name, obj := range o.Refs {
		if strings.HasPrefix(name, "refs/heads/") || strings.HasPrefix(name, "refs/tags/") {
			ours[name] = obj
		}
	}
	checkedOut, err := g.checkedOutBranches(ctx, dir)
	if err != nil {
		return nil, err
	}
	names := map[string]bool{}
	for _, set := range []map[string]string{theirs, baseRefs, ours} {
		for name := range set {
			names[name] = true
		}
	}
	sorted := make([]string, 0, len(names))
	for name := range names {
		sorted = append(sorted, name)
	}
	sort.Strings(sorted)
	type update struct{ name, to, from string }
	var (
		updates  []update
		kept     []Ref
		keptName = map[string]bool{}
		diverged []string
	)
	branch := func(name string) bool { return strings.HasPrefix(name, "refs/heads/") }
	for _, name := range sorted {
		t, b, cur := theirs[name], baseRefs[name], ours[name]
		takeTheirs := cur == b || (branch(name) && cur != "" && t != "" && g.isAncestor(ctx, dir, cur, t))
		keepOurs := t == b || (branch(name) && cur != "" && t != "" && g.isAncestor(ctx, dir, t, cur))
		switch {
		case t == cur:
		case takeTheirs && checkedOut[name] != "":
			diverged = append(diverged, fmt.Sprintf("%s (checked out in %s)", quotePath(name), quotePath(checkedOut[name])))
		case takeTheirs:
			updates = append(updates, update{name: name, to: t, from: cur})
		case keepOurs:
			// Moved here since, and not in the capture: the repository's.
			kept = append(kept, Ref{Name: name, Object: cur, Commit: cur, Tree: o.Trees[name]})
			keptName[name] = true
		default:
			diverged = append(diverged, quotePath(name))
		}
	}
	if h := m.Head; !h.Detached && strings.HasPrefix(h.Branch, "refs/heads/") {
		switch {
		case keptName[h.Branch]:
			diverged = append(diverged, fmt.Sprintf("%s, where HEAD goes, which moved on here since", quotePath(h.Branch)))
		case checkedOut[h.Branch] != "":
			diverged = append(diverged, fmt.Sprintf("%s, where HEAD goes (checked out in %s)", quotePath(h.Branch), quotePath(checkedOut[h.Branch])))
		}
	}
	if len(diverged) > 0 {
		const most = 8
		if len(diverged) > most {
			diverged = append(diverged[:most], fmt.Sprintf("and %d more", len(diverged)-most))
		}
		return nil, fmt.Errorf("%w: %s", ErrRefsDiverged, strings.Join(diverged, ", "))
	}

	// The files first: a refusal here leaves the branches and HEAD as they
	// were. The index is made to name the files on disk as Inspect read them
	// (base's working-tree state, or, resuming, part base's and part the
	// capture's), without the paths the target keeps for itself, and the
	// merge then moves the disk to the capture's working tree.
	if _, err := g.run(ctx, dir, nil, "read-tree", o.WorktreeTree); err != nil {
		return nil, fmt.Errorf("movegit: read the copy left behind: %w", err)
	}
	if r := opts.Reserve; r != nil && r.Dir != "" {
		args := []string{"rm", "-r", "--cached", "-q", "--ignore-unmatch", "--", r.Dir}
		for _, a := range r.Allow {
			args = append(args, ":(exclude)"+r.Dir+"/"+a)
		}
		if _, err := g.run(ctx, dir, nil, args...); err != nil {
			return nil, fmt.Errorf("movegit: leave %s out of the restore: %w", r.Dir, err)
		}
	}
	from, err := g.run(ctx, dir, nil, "write-tree")
	if err != nil {
		return nil, fmt.Errorf("movegit: write the copy's tree: %w", err)
	}
	// Fresh stat data, so the merge reads the files as clean; it exits
	// non-zero only for files that differ, which none may.
	_, _ = g.run(ctx, dir, nil, "update-index", "-q", "--refresh")
	s := m.Snapshot
	// git treats ignored files as expendable: a merge that puts a file where
	// an ignored directory is removes the directory. Nothing the capture did
	// not record may be in the way of what it writes.
	if in, err := g.inTheWay(ctx, dir, strings.TrimSpace(from), s.WorktreeTree); err != nil {
		return nil, err
	} else if len(in) > 0 {
		const most = 8
		shown := make([]string, 0, most+1)
		for i, p := range in {
			if i == most {
				shown = append(shown, fmt.Sprintf("and %d more", len(in)-most))
				break
			}
			shown = append(shown, quotePath(p))
		}
		return nil, fmt.Errorf("%w: putting the capture's files in place would write over files git does not track here: %s",
			ErrLeftBehindChanged, strings.Join(shown, ", "))
	}
	if out, err := g.run(ctx, dir, nil, "read-tree", "-m", "-u", strings.TrimSpace(from), s.WorktreeTree); err != nil {
		return nil, fmt.Errorf("%w: putting the capture's files in place would write over files git does not track here: %v %s",
			ErrLeftBehindChanged, err, strings.TrimSpace(out))
	}

	// The branches, settled above, in one transaction that holds each to the
	// value it was settled against, and the capture's own hidden refs —
	// ValidateManifest held each to this move's namespaces.
	var script strings.Builder
	for _, u := range updates {
		if u.to == "" {
			fmt.Fprintf(&script, "delete %s %s\n", u.name, u.from)
			continue
		}
		from := u.from
		if from == "" {
			from = strings.Repeat("0", len(u.to))
		}
		fmt.Fprintf(&script, "update %s %s %s\n", u.name, u.to, from)
	}
	hidden := []Ref{{Name: s.Ref, Object: s.Commit}}
	for _, w := range m.Worktrees {
		if w.Ref != "" {
			hidden = append(hidden, Ref{Name: w.Ref, Object: w.Commit})
		}
	}
	hidden = append(append(hidden, m.Stash...), m.Carried...)
	for _, r := range hidden {
		if r.Name != "" && r.Object != "" {
			fmt.Fprintf(&script, "update %s %s\n", r.Name, r.Object)
		}
	}
	if script.Len() > 0 {
		if err := g.exec(ctx, dir, nil, strings.NewReader(script.String()), nil, "update-ref", "--stdin"); err != nil {
			return nil, fmt.Errorf("movegit: update the branches in %s: %w", dir, err)
		}
	}

	h := m.Head
	switch {
	case h.Detached:
		if _, err := g.run(ctx, dir, nil, "update-ref", "--no-deref", "HEAD", h.Commit); err != nil {
			return nil, fmt.Errorf("movegit: detach HEAD at %s: %w", short(h.Commit), err)
		}
	case strings.HasPrefix(h.Branch, "refs/heads/"):
		if _, err := g.run(ctx, dir, nil, "symbolic-ref", "HEAD", h.Branch); err != nil {
			return nil, fmt.Errorf("movegit: put HEAD on %s: %w", h.Branch, err)
		}
	default:
		return nil, fmt.Errorf("movegit: the manifest's HEAD names no branch and no commit")
	}
	if _, err := g.run(ctx, dir, nil, "read-tree", s.IndexTree); err != nil {
		return nil, fmt.Errorf("movegit: restore the index: %w", err)
	}
	return kept, nil
}

// inTheWay lists what moving the files in dir from tree a, which the index
// names, to tree b would write over that the index does not track: an
// untracked or ignored file where b writes one, a directory holding untracked
// or ignored content (a linked worktree's, say) where b puts a file, and an
// untracked file where b needs a directory.
func (g *runner) inTheWay(ctx context.Context, dir, a, b string) ([]string, error) {
	out, err := g.run(ctx, dir, nil, "ls-files", "-z")
	if err != nil {
		return nil, fmt.Errorf("movegit: list the files of the copy left behind: %w", err)
	}
	tracked := map[string]bool{}
	for _, p := range strings.Split(out, "\x00") {
		if p != "" {
			tracked[p] = true
		}
	}
	// Everything on disk the index does not name, ignored included, each
	// wholly untracked directory once as "dir/".
	out, err = g.run(ctx, dir, nil, "ls-files", "-z", "--others", "--directory")
	if err != nil {
		return nil, fmt.Errorf("movegit: list the files git does not track in %s: %w", dir, err)
	}
	var untracked []string
	for _, p := range strings.Split(out, "\x00") {
		if p != "" {
			untracked = append(untracked, p)
		}
	}
	holdsUntracked := func(d string) bool {
		for _, u := range untracked {
			if strings.HasPrefix(u, d+"/") {
				return true
			}
		}
		return false
	}
	out, err = g.run(ctx, dir, nil, "diff-tree", "-r", "-z", "--name-only", "--no-renames", a, b)
	if err != nil {
		return nil, fmt.Errorf("movegit: compare the copy with the capture: %w", err)
	}
	var in []string
	seen := map[string]bool{}
	add := func(p string) {
		if !seen[p] {
			seen[p] = true
			in = append(in, p)
		}
	}
	for _, p := range strings.Split(out, "\x00") {
		if p == "" {
			continue
		}
		if info, err := os.Lstat(filepath.Join(dir, filepath.FromSlash(p))); err == nil {
			switch {
			case info.IsDir() && holdsUntracked(p):
				add(p)
			case !info.IsDir() && !tracked[p]:
				add(p)
			}
		}
		for d := filepath.ToSlash(filepath.Dir(p)); d != "." && d != "/" && d != ""; d = filepath.ToSlash(filepath.Dir(d)) {
			if info, err := os.Lstat(filepath.Join(dir, filepath.FromSlash(d))); err == nil && !info.IsDir() && !tracked[d] {
				add(d)
			}
		}
	}
	sort.Strings(in)
	return in, nil
}

// isAncestor reports whether commit a is an ancestor of commit b (or b
// itself). Anything git cannot answer is a no.
func (g *runner) isAncestor(ctx context.Context, dir, a, b string) bool {
	_, err := g.run(ctx, dir, nil, "merge-base", "--is-ancestor", a, b)
	return err == nil
}

// checkedOutBranches maps each branch a linked worktree of the repository
// has checked out — inside the project or anywhere else — to that worktree's
// path.
func (g *runner) checkedOutBranches(ctx context.Context, dir string) (map[string]string, error) {
	out, err := g.run(ctx, dir, nil, "worktree", "list", "--porcelain", "-z")
	if err != nil {
		return nil, fmt.Errorf("movegit: list worktrees in %s: %w", dir, err)
	}
	branches := map[string]string{}
	var path string
	main := true
	for _, field := range strings.Split(out, "\x00") {
		key, value, _ := strings.Cut(field, " ")
		switch key {
		case "worktree":
			path = value
		case "branch":
			// The first entry is the main worktree, whose branch is HEAD's.
			if !main {
				branches[value] = path
			}
		case "":
			if path != "" {
				main = false
			}
		}
	}
	return branches, nil
}

// WithRefs returns m with each of refs in place of the branch or tag of the
// same name, added where m has none and left out where its Object is empty:
// what a copy RestoreInto restored holds, where it kept refs of its own.
func (m Manifest) WithRefs(refs []Ref) Manifest {
	if len(refs) == 0 {
		return m
	}
	byName := map[string]Ref{}
	for _, r := range refs {
		byName[r.Name] = r
	}
	apply := func(list []Ref, prefix string) []Ref {
		out := make([]Ref, 0, len(list))
		seen := map[string]bool{}
		for _, r := range list {
			if k, ok := byName[r.Name]; ok {
				seen[r.Name] = true
				if k.Object == "" {
					continue
				}
				r.Object, r.Commit, r.Tree = k.Object, k.Commit, k.Tree
			}
			out = append(out, r)
		}
		for _, k := range refs {
			if !seen[k.Name] && k.Object != "" && strings.HasPrefix(k.Name, prefix) {
				out = append(out, k)
			}
		}
		return out
	}
	m.Branches = apply(m.Branches, "refs/heads/")
	m.Tags = apply(m.Tags, "refs/tags/")
	return m
}
