package secretbroker

// localrepo.go delivers KindLocalRepo: a directory on the hub host holding git
// repositories, opened to one project as bind mounts.
//
// # Why this is a grant and not a mount
//
// pkg/executor.SpecMount already re-exposes paths inside a sandbox, and it is
// deliberately unable to express this: its sources are workspace-relative, so a
// spec can rearrange what it was given and never reach past it. That limit
// exists because a sandbox spec is repo-committed — .cloop/sandbox.yaml is
// whatever a pull request says it is — and a host path there would turn "merge
// this PR" into "bind /root and print it".
//
// The developer's actual need is the same capability with the trust inverted.
// They have three checkouts on the machine the hub runs on and want one project
// to build against them. Nobody in that story is untrusted: a human with
// secret.grant names the root, names the repositories, and names the project.
// That is a grant, and routing it through the broker means it arrives with the
// properties every other authority here already has — a subject that binds it
// to one project, a TTL, an audit row naming who opened it, and revocation that
// lands within a lease period rather than at the end of the run.
//
// # The shape
//
// The payload is a root directory, stored once ("the dev box's source tree" ->
// /home/dev/src). Grants name repositories under it:
//
//	secret:  local-src  ->  /home/dev/src
//	grant:   subject project:/srv/projects/api
//	         repos    api-service, shared-*
//	         writable false
//
// One secret, many grants, each opening a different slice to a different
// project — which is what "a number of particular Git repositories" means when
// there are five projects and twenty checkouts. A root that is itself a
// repository is accepted too, so the single-repo case does not need a wrapper
// directory.
//
// # Containment
//
// Every accepted path is resolved with filepath.EvalSymlinks and re-checked
// against the resolved root. This is the whole security argument for the
// package: the operator names a root, and a symlink planted inside it — by a
// dependency's postinstall script, by a tarball, by anything that has ever
// written to that tree — must not be able to redirect a bind to /. Because the
// check is on the resolved path, it holds regardless of who created the link.
//
// Names are checked separately from paths. A repository directory whose name
// contains a colon would append mount options to the container runtime's -v
// flag; one containing a slash or ".." would not be a direct child at all.

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

// SandboxRepoRoot is where granted repositories appear inside a sandbox.
//
// A fixed path rather than a configurable one so a harness, a setup script and
// a README can all name it without knowing which executor they landed on. It
// is outside /workspace on purpose: the workspace is bind-mounted whole by the
// container driver, so a target underneath it would be shadowed by that mount
// on some drivers and not others.
const SandboxRepoRoot = "/repos"

// MaxLocalRepos bounds how many repositories one grant may open.
//
// The limit is legibility, not resource use. A grant matching forty checkouts
// has stopped describing "these repositories" and started describing "the
// machine", which is the thing the allowlist exists to prevent someone doing by
// accident with a broad glob.
const MaxLocalRepos = 32

// localRepoMaterial resolves a granted root to the repositories a project may
// see, and returns them as mounts.
func (b *Broker) localRepoMaterial(mat Material, plaintext []byte) (Material, error) {
	root, err := ParseLocalRepoRoot(plaintext)
	if err != nil {
		return Material{}, err
	}

	repos, err := selectRepos(root, mat.Constraints)
	if err != nil {
		return Material{}, err
	}
	if len(repos) == 0 {
		// An empty result is an error rather than an empty mount list. The
		// grant asserts these repositories exist; delivering nothing would
		// start the harness in a sandbox with an empty /repos and let it
		// discover the problem as a missing directory several minutes in.
		return Material{}, wrapf(ErrInvalidConstraint,
			"local_repo grant on %s matched no git repository under the granted root (allowlist: %s)",
			mat.SecretName, strings.Join(mat.Constraints.Repos, ", "))
	}

	readOnly := !mat.Constraints.Writable
	names := make([]string, 0, len(repos))
	for _, r := range repos {
		mat.Mounts = append(mat.Mounts, RepoMount{
			Name:     r.name,
			Source:   r.path,
			Target:   path.Join(SandboxRepoRoot, r.name),
			ReadOnly: readOnly,
		})
		names = append(names, r.name)
	}

	// The env names the repositories and nothing else. Where they *are* is
	// deliberately not decided here: a driver that binds sees them at their
	// targets, one that already shares the hub's filesystem sees them at their
	// sources, and only the caller holding both the lease and the executor
	// knows which. That caller adds the path variables (see
	// pkg/ui.applyRepoGrants); this list is what stays true either way, and is
	// safe to carry into an audit row.
	mat.Env["CLOOP_LOCAL_REPOS"] = strings.Join(names, ",")

	access := "read-only"
	if mat.Constraints.Writable {
		access = "read-write"
	}
	mat.Summary = fmt.Sprintf("local repos (%s): %s", access, strings.Join(names, ","))
	return mat, nil
}

// ParseLocalRepoRoot validates a local_repo payload.
//
// Exported because storing one of these secrets should fail at the API with a
// usable message — "that path does not exist on the hub" is a typo the operator
// can fix in the dialog, and finding out at lease time instead means finding
// out during someone else's run.
func ParseLocalRepoRoot(payload []byte) (string, error) {
	raw := strings.TrimSpace(string(payload))
	switch {
	case raw == "":
		return "", wrapf(ErrMalformedPayload, "local_repo payload is empty; it must be an absolute path to a directory of git repositories")
	case strings.ContainsAny(raw, ":\x00\n\r\\"):
		// The colon has to be caught *here*, not only in RepoMount.validate.
		// A failure at materialisation time fails the whole lease, and
		// acquireSecretLease treats a failed lease as "no credentials" — so a
		// root at /home/dev/my:src would silently strip this project's GitHub
		// token and kubeconfig too, on every run, with one line on stderr.
		// Rejecting it in the mint dialog is what this function is for.
		return "", wrapf(ErrMalformedPayload,
			"local_repo path contains a colon, backslash, NUL or newline; "+
				"a colon cannot be expressed as a bind mount source")
	case !filepath.IsAbs(raw):
		return "", wrapf(ErrMalformedPayload, "local_repo path %q is not absolute", raw)
	}

	// Resolve before checking anything about it. A root that is itself a
	// symlink is fine — /home/dev/src -> /mnt/big/src is ordinary — but every
	// containment check below compares against the resolved form, so it has to
	// be established first.
	resolved, err := filepath.EvalSymlinks(filepath.Clean(raw))
	if err != nil {
		if os.IsNotExist(err) {
			return "", wrapf(ErrMalformedPayload, "local_repo path %q does not exist on the hub", raw)
		}
		return "", wrapf(ErrMalformedPayload, "local_repo path %q cannot be resolved: %v", raw, err)
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return "", wrapf(ErrMalformedPayload, "local_repo path %q cannot be read: %v", raw, err)
	}
	if !info.IsDir() {
		return "", wrapf(ErrMalformedPayload, "local_repo path %q is not a directory", raw)
	}
	if resolved == string(filepath.Separator) {
		return "", wrapf(ErrMalformedPayload, "local_repo path may not be the filesystem root")
	}
	return resolved, nil
}

// foundRepo is one repository that survived the allowlist and the containment
// check.
type foundRepo struct {
	name string
	path string
}

// selectRepos lists the git repositories directly under root that the
// constraints allow.
//
// Only direct children are considered. Recursing would make a root of
// /home/dev match a repository at /home/dev/.cache/some-dependency/vendor/x,
// which no operator granting "the source tree" is picturing.
func selectRepos(root string, c Constraints) ([]foundRepo, error) {
	// A root that is itself a repository is the single-checkout case. It is
	// still subject to the allowlist, matched on its own directory name, so a
	// grant cannot become broader by pointing at a repo instead of a tree.
	if isGitRepo(root) {
		name := filepath.Base(root)
		if !matchesAny(c.Repos, name) {
			return nil, nil
		}
		if err := validRepoName(name); err != nil {
			return nil, err
		}
		return []foundRepo{{name: name, path: root}}, nil
	}

	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, wrapf(ErrMalformedPayload, "local_repo root cannot be listed: %v", err)
	}

	var found []foundRepo
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, ".") {
			continue
		}
		// Match before touching the filesystem: a root with a large number of
		// entries should not cost a stat and a symlink resolution each.
		if !matchesAny(c.Repos, name) {
			continue
		}
		if err := validRepoName(name); err != nil {
			// A name that cannot be safely bound is skipped rather than
			// fatal. It is a property of what happens to be in the directory,
			// not of the grant, so failing the whole lease would let anyone
			// who can write to the root break an unrelated project's runs.
			continue
		}
		// e.IsDir() is false for a symlink to a directory, so resolve first
		// and ask afterwards — otherwise a symlinked checkout, which is how
		// plenty of people arrange a source tree, would be invisible.
		abs, ok := resolveWithin(root, name)
		if !ok {
			continue
		}
		if !isGitRepo(abs) {
			continue
		}
		found = append(found, foundRepo{name: name, path: abs})
		if len(found) > MaxLocalRepos {
			return nil, wrapf(ErrInvalidConstraint,
				"local_repo grant matches more than %d repositories; narrow the allowlist", MaxLocalRepos)
		}
	}

	// Deterministic order: the mount list ends up in an audit row and in a
	// spec that executorstore persists, and readdir order is not stable.
	sort.Slice(found, func(i, j int) bool { return found[i].name < found[j].name })
	return found, nil
}

// resolveWithin resolves root/name and confirms the result is still under
// root.
//
// This is the containment check the package rests on. A symlink at
// <root>/evil -> / resolves to /, which is not under root, and is dropped. The
// comparison is on the resolved path of both sides, so it cannot be defeated by
// a link anywhere in either chain.
func resolveWithin(root, name string) (string, bool) {
	abs, err := filepath.EvalSymlinks(filepath.Join(root, name))
	if err != nil {
		return "", false
	}
	// filepath.Rel is the containment test rather than strings.HasPrefix,
	// which would accept /home/dev/src-other for a root of /home/dev/src.
	rel, err := filepath.Rel(root, abs)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", false
	}
	return abs, true
}

// isGitRepo reports whether dir is a git repository — either a working tree
// with a .git, or a bare repository.
func isGitRepo(dir string) bool {
	if info, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
		// .git is a directory in a normal clone and a file in a worktree or
		// submodule. Both are repositories.
		_ = info
		return true
	}
	// A bare repository has no .git but has these.
	for _, marker := range []string{"HEAD", "objects"} {
		if _, err := os.Stat(filepath.Join(dir, marker)); err != nil {
			return false
		}
	}
	return true
}

// validRepoName rejects directory names that cannot be safely bound.
//
// The colon is the sharp one: container runtimes take -v as a
// colon-separated triple, so a directory named "x:/etc:ro" would append mount
// options — or a third path — to a flag the operator believed they controlled.
// The rest keep a name from being anything but a direct child.
func validRepoName(name string) error {
	switch {
	case name == "", name == ".", name == "..":
		return wrapf(ErrInvalidConstraint, "repository name %q is not a directory name", name)
	case len(name) > 128:
		return wrapf(ErrInvalidConstraint, "repository name %q exceeds 128 characters", name)
	case strings.ContainsAny(name, ":\x00\n\r/\\"):
		return wrapf(ErrInvalidConstraint,
			"repository name %q contains a colon, slash, backslash, NUL or newline", name)
	}
	return nil
}

// matchesAny reports whether name matches any pattern in the allowlist.
//
// An empty allowlist matches nothing. ValidateFor already refuses to create
// such a grant, so this is the second of the two places that reading is
// unavailable — an allowlist that fell open when empty would turn a storage
// bug into full access to the root.
func matchesAny(patterns []string, name string) bool {
	for _, p := range patterns {
		if p == "*" {
			return true
		}
		// Case-sensitive, unlike the github repo matcher this sits next to.
		// GitHub repository names genuinely are case-insensitive, so folding
		// there is correct; POSIX directory names are not. Folding here would
		// make a grant on "api" also open "API" and "ApI", which on Linux are
		// three unrelated repositories the operator never named.
		if ok, err := path.Match(p, name); err == nil && ok {
			return true
		}
	}
	return false
}

// validate re-checks a mount immediately before a driver receives it.
//
// Materialize calls this rather than trusting the Material it was handed,
// because the two can be separated by a store round trip and this is the one
// material kind that carries a host path verbatim into a runtime flag.
func (m RepoMount) validate() error {
	if err := validRepoName(m.Name); err != nil {
		return err
	}
	// The target is derived, never supplied, so it must be exactly what
	// localRepoMaterial would have produced. Checking it here is what makes
	// this function a guard against a tampered Material rather than only a
	// re-check of the fields a caller happened to fill in.
	if want := path.Join(SandboxRepoRoot, m.Name); m.Target != want {
		return wrapf(ErrInvalidConstraint,
			"repo mount %q targets %q, want %q", m.Name, m.Target, want)
	}
	for _, f := range []struct{ field, val string }{{"source", m.Source}, {"target", m.Target}} {
		switch {
		case strings.TrimSpace(f.val) == "":
			return wrapf(ErrInvalidConstraint, "repo mount %s is empty for %q", f.field, m.Name)
		case !filepath.IsAbs(f.val):
			return wrapf(ErrInvalidConstraint, "repo mount %s %q is not absolute", f.field, f.val)
		case strings.ContainsAny(f.val, ":\x00\n\r"):
			return wrapf(ErrInvalidConstraint,
				"repo mount %s %q contains a colon, NUL or newline", f.field, f.val)
		}
	}
	return nil
}
