// Package feature models parallel feature development inside one cloop project
// (Task 20341).
//
// A project has one task list and one set of run settings, because it has one
// .cloop/ directory and one working tree. That is the right shape for a single
// line of work and the wrong one for three: two features developed in the same
// checkout edit the same files, their tasks interleave in one plan, and there is
// no way to say "evolve this one, but let that one finish and stop".
//
// A feature is the smallest unit that removes all three problems at once: a git
// worktree of the project's repository, on its own branch, with its own .cloop/
// directory. Everything cloop already knows how to do to a project — run it,
// stop it, evolve it, edit its tasks, toggle innovate mode — it can then do to
// the feature without learning anything new, because a feature *is* a project
// as far as the orchestrator is concerned. What this package adds is the part
// that is not: where features live, how one is recognised, and what is recorded
// about it.
//
// # Layout
//
//	<project>/.cloop/features/<slug>/            the worktree (branch cloop/feature/<slug>)
//	<project>/.cloop/features/<slug>/.cloop/     the feature's own state, config and task list
//	<project>/.cloop/features/<slug>/.cloop/feature.json   what this package records
//
// Inside the parent's .cloop/ rather than beside the project, for three reasons.
// A feature is then deleted with its project and never outlives it on disk; an
// executor that bind-mounts the project directory can reach it; and — the one
// that decides it — the parent is derivable from the path alone. Inheritance of
// the parent's executor binding, grants and authorization (see ParentOf) is a
// security property, and one that holds by construction is better than one that
// holds because a registry entry says so.
//
// The cost of that choice is that everything which treats "a directory below
// the project" as "the project" has to learn that a feature subtree is not. The
// process-scoping helpers in pkg/multiui and the .cloop/ walkers in
// pkg/snapshot, pkg/diskusage and `cloop clean` are the places that do.
//
// # What lives here and what does not
//
// This package is pure: it reads and writes files and never runs a process.
// That is deliberate, because pkg/ui — which may not spawn processes, see
// pkg/ui/no_direct_exec_test.go — lists features on every projects refresh.
// Creating, removing and publishing a feature means running git and talking to
// GitHub, and lives in pkg/featureops, which only the CLI imports.
package feature

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/atomicfile"
	"github.com/blechschmidt/cloop/pkg/boundedread"
)

const (
	// ControlDir is the name of a project's control directory.
	ControlDir = ".cloop"

	// DirName is the directory under ControlDir that holds feature worktrees.
	DirName = "features"

	// MetaFile is the feature's own record, inside the feature's ControlDir.
	MetaFile = "feature.json"

	// BranchPrefix names every feature branch. It sits inside the cloop/
	// namespace on purpose: that is the git interception proxy's default
	// write-back allowlist (gitproxy.DefaultAllowedRef), so a sandbox can push
	// a feature branch through the proxy without anyone widening a policy —
	// and can still not push main.
	BranchPrefix = "cloop/feature/"

	// MaxSlugLen bounds a slug. Slugs become directory names and branch
	// components; 40 keeps both readable and far from any path limit.
	MaxSlugLen = 40

	// MaxPerProject bounds how many features one project may hold. Each one is
	// a full checkout plus a harness that can run concurrently with the rest,
	// so an unbounded count is an unbounded amount of disk and parallelism
	// reachable by anyone who can create one. The figure is generous for
	// people and small for a loop.
	MaxPerProject = 32

	// metaVersion is the schema version written into feature.json.
	metaVersion = 1

	// maxMetaBytes bounds a feature.json read. The record is a few hundred
	// bytes; anything near this size is not one, and it is read on every
	// dashboard refresh.
	maxMetaBytes = 256 << 10
)

// slugRe is the shape of a valid slug: lowercase alphanumerics and single
// hyphens, starting with an alphanumeric. Checked, not merely produced by
// Slugify, because a slug also arrives from HTTP requests and CLI arguments
// and becomes a path component and a ref name.
var slugRe = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$`)

// slugInvalid matches runs of characters Slugify replaces with one hyphen.
var slugInvalid = regexp.MustCompile(`[^a-z0-9]+`)

// Slugify derives a slug from a human name: lowercase, runs of anything other
// than a letter or digit collapsed to one hyphen, trimmed, and cut to
// MaxSlugLen. It returns "" when nothing usable is left, which ValidSlug then
// rejects with a message naming the input.
func Slugify(name string) string {
	s := strings.ToLower(strings.TrimSpace(name))
	s = slugInvalid.ReplaceAllString(s, "-")
	s = strings.Trim(s, "-")
	if len(s) > MaxSlugLen {
		s = strings.TrimRight(s[:MaxSlugLen], "-")
	}
	return s
}

// ValidSlug reports whether slug can name a feature.
func ValidSlug(slug string) error {
	switch {
	case slug == "":
		return errors.New("feature name is empty after normalisation — use letters or digits")
	case len(slug) > MaxSlugLen:
		return fmt.Errorf("feature slug %q is longer than %d characters", slug, MaxSlugLen)
	case strings.Contains(slug, "--"):
		// Allowed by the regexp's character class but never produced by
		// Slugify; refusing it keeps one spelling per name.
		return fmt.Errorf("feature slug %q contains a double hyphen", slug)
	case !slugRe.MatchString(slug):
		return fmt.Errorf("feature slug %q must be lowercase letters, digits and single hyphens", slug)
	}
	return nil
}

// BranchName returns the branch a feature is developed on.
func BranchName(slug string) string { return BranchPrefix + slug }

// Dir returns the directory holding a project's feature worktrees.
func Dir(projectDir string) string {
	return filepath.Join(projectDir, ControlDir, DirName)
}

// Path returns where the feature named slug lives inside projectDir.
func Path(projectDir, slug string) string {
	return filepath.Join(Dir(projectDir), slug)
}

// MetaPath returns the path of a feature's record.
func MetaPath(featureDir string) string {
	return filepath.Join(featureDir, ControlDir, MetaFile)
}

// ParentOf reports whether path is, by its shape, the root of a feature
// worktree — <parent>/.cloop/features/<slug> with a valid slug — and if so
// returns the parent project directory and the slug.
//
// It is purely lexical. It does not check that anything exists, which is what
// makes it usable from hot paths (every executor dispatch consults it) and
// what makes it trustworthy: the answer cannot be changed by writing a file.
// Callers that need to know a feature is real rather than merely well-named
// use IsFeature.
//
// A nested feature — a feature of a feature — is not recognised: the parent of
// such a path would itself be a feature, and ParentOf reports false for it.
// Features are one level deep by design (see pkg/featureops.Create).
func ParentOf(path string) (parent, slug string, ok bool) {
	if path == "" {
		return "", "", false
	}
	clean := filepath.Clean(path)
	slug = filepath.Base(clean)
	featuresDir := filepath.Dir(clean)
	controlDir := filepath.Dir(featuresDir)
	if filepath.Base(featuresDir) != DirName || filepath.Base(controlDir) != ControlDir {
		return "", "", false
	}
	if ValidSlug(slug) != nil {
		return "", "", false
	}
	parent = filepath.Dir(controlDir)
	if parent == controlDir || parent == "" || parent == "." {
		return "", "", false
	}
	if _, _, nested := ParentOf(parent); nested {
		return "", "", false
	}
	return parent, slug, true
}

// IsFeature reports whether path is the root of a real feature: shaped like
// one (ParentOf) and carrying a readable record for the same slug.
//
// The record's Parent field is deliberately not compared with the parent the
// path implies. The path is authoritative — it is what inheritance follows —
// and a project directory that was moved or reached through a different
// mount would otherwise lose every feature it has to a string mismatch in a
// file nobody edits. The slug is compared because a record copied into the
// wrong directory is a record describing some other feature.
func IsFeature(path string) bool {
	parent, slug, ok := ParentOf(path)
	if !ok || !realFeatureDir(parent, path) {
		return false
	}
	m, err := LoadMeta(path)
	if err != nil {
		return false
	}
	return m.Slug == slug
}

// InsideFeature reports whether path is a feature root or anything below one,
// returning that feature's root. Used by the process-scoping helpers, which
// see working directories such as <feature>/.cloop/worktrees/task-3 and have
// to attribute them to the feature rather than to its parent.
func InsideFeature(path string) (featureRoot string, ok bool) {
	clean := filepath.Clean(path)
	marker := string(os.PathSeparator) + ControlDir + string(os.PathSeparator) + DirName + string(os.PathSeparator)
	i := strings.Index(clean, marker)
	if i < 0 {
		return "", false
	}
	rest := clean[i+len(marker):]
	slug, _, _ := strings.Cut(rest, string(os.PathSeparator))
	root := clean[:i+len(marker)] + slug
	if _, _, ok := ParentOf(root); !ok {
		return "", false
	}
	return root, true
}

// PR is what is recorded about a feature's pull request.
type PR struct {
	Number int    `json:"number"`
	URL    string `json:"url"`
	// State is GitHub's state as last seen: open, closed or merged.
	State string `json:"state"`
	// Repo is owner/name on the forge the PR was opened on.
	Repo string `json:"repo,omitempty"`
	Head string `json:"head,omitempty"`
	Base string `json:"base,omitempty"`
	// HeadSHA is the commit the branch pointed at when the PR was opened or
	// last refreshed, so the dashboard can tell "the PR shows this work" from
	// "there are commits the PR does not have yet".
	HeadSHA   string    `json:"head_sha,omitempty"`
	Draft     bool      `json:"draft,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// Return is what became of the work of a feature's last run on an executor
// that isolates from the hub (Task 20367): such a run works on a standalone
// checkout of the feature's branch, and its commits come back as a bundle the
// hub vets and applies to the worktree here — by fast-forward only.
type Return struct {
	At time.Time `json:"at"`
	// Outcome is fast_forwarded, conflict (the work was kept on KeptOn
	// rather than applied), nothing (the run made no commits), or failed
	// (the work did not come back; Message says why).
	Outcome string `json:"outcome"`
	// Commit is the returned tip, when there was one.
	Commit string `json:"commit,omitempty"`
	// KeptOn is the branch conflicting work was kept on.
	KeptOn string `json:"kept_on,omitempty"`
	// Message is the operator-facing account.
	Message string `json:"message,omitempty"`
	// Executor is where the run happened.
	Executor string `json:"executor,omitempty"`
}

// Meta is a feature's record, persisted as .cloop/feature.json inside the
// feature's worktree.
type Meta struct {
	Version int    `json:"version"`
	Slug    string `json:"slug"`
	Title   string `json:"title"`
	// Description is the feature's goal as the user wrote it.
	Description string `json:"description,omitempty"`
	Branch      string `json:"branch"`
	// Base is the branch the feature was cut from and the one its pull
	// request targets.
	Base string `json:"base"`
	// BaseCommit is the commit Base pointed at when the feature was created.
	BaseCommit string `json:"base_commit,omitempty"`
	// Parent is the project directory this feature belongs to, absolute.
	Parent    string    `json:"parent"`
	CreatedAt time.Time `json:"created_at"`
	CreatedBy string    `json:"created_by,omitempty"`
	// AutoPR asks the hub to open the pull request by itself once the
	// feature's plan completes.
	AutoPR bool `json:"auto_pr,omitempty"`
	PR     *PR  `json:"pr,omitempty"`
	// Return is the outcome of the last run's write-back, for a feature run
	// on an isolating executor; nil for one that ran on the hub.
	Return *Return `json:"return,omitempty"`
}

// Validate checks a record's invariants before it is written or trusted.
func (m *Meta) Validate() error {
	if m == nil {
		return errors.New("feature record is missing")
	}
	if err := ValidSlug(m.Slug); err != nil {
		return err
	}
	if m.Branch != BranchName(m.Slug) {
		return fmt.Errorf("feature %q records branch %q, want %q", m.Slug, m.Branch, BranchName(m.Slug))
	}
	if strings.TrimSpace(m.Base) == "" {
		return fmt.Errorf("feature %q records no base branch", m.Slug)
	}
	if !filepath.IsAbs(m.Parent) {
		return fmt.Errorf("feature %q records a parent that is not an absolute path: %q", m.Slug, m.Parent)
	}
	return nil
}

// LoadMeta reads a feature's record from its worktree. The record must be a
// regular file: see realFeatureDir for why a link is never followed here.
func LoadMeta(featureDir string) (*Meta, error) {
	if fi, err := os.Lstat(MetaPath(featureDir)); err != nil {
		return nil, err
	} else if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("feature record %s is not a regular file", MetaPath(featureDir))
	}
	data, err := boundedread.ReadFile(MetaPath(featureDir), maxMetaBytes)
	if err != nil {
		return nil, err
	}
	var m Meta
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("feature record %s is not valid JSON: %w", MetaPath(featureDir), err)
	}
	if err := m.Validate(); err != nil {
		return nil, fmt.Errorf("feature record %s: %w", MetaPath(featureDir), err)
	}
	return &m, nil
}

// SaveMeta writes a feature's record atomically. The control directory must
// exist — it is created with the feature's state.
func SaveMeta(featureDir string, m *Meta) error {
	if err := m.Validate(); err != nil {
		return err
	}
	if m.Version == 0 {
		m.Version = metaVersion
	}
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return atomicfile.Write(MetaPath(featureDir), append(data, '\n'), 0o644)
}

// Info is one discovered feature.
type Info struct {
	// Path is the feature's worktree, absolute.
	Path string
	Meta *Meta
}

// List returns the features of projectDir, oldest first.
//
// It only reads files. A directory under .cloop/features that has no valid
// record — a half-created feature, a worktree someone made by hand, the
// leftovers of a crash — is skipped rather than reported: listing is what the
// dashboard does every two seconds, and it must describe what is usable, not
// fail on what is not. `cloop feature list` reports the skipped ones.
//
// A project that is itself a feature has no features.
func List(projectDir string) ([]Info, error) {
	if _, _, isFeature := ParentOf(projectDir); isFeature {
		return nil, nil
	}
	if !realDir(filepath.Join(projectDir, ControlDir)) || !realDir(Dir(projectDir)) {
		return nil, nil
	}
	entries, err := os.ReadDir(Dir(projectDir))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	out := make([]Info, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() || ValidSlug(e.Name()) != nil {
			continue
		}
		dir := filepath.Join(Dir(projectDir), e.Name())
		if !realFeatureDir(projectDir, dir) {
			continue
		}
		m, err := LoadMeta(dir)
		if err != nil || m.Slug != e.Name() {
			continue
		}
		out = append(out, Info{Path: dir, Meta: m})
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i].Meta, out[j].Meta
		if !a.CreatedAt.Equal(b.CreatedAt) {
			return a.CreatedAt.Before(b.CreatedAt)
		}
		return a.Slug < b.Slug
	})
	return out, nil
}

// Orphans returns the directories under .cloop/features that List skipped,
// with the reason, so an operator can see what is taking up room.
func Orphans(projectDir string) (map[string]string, error) {
	entries, err := os.ReadDir(Dir(projectDir))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, e := range entries {
		dir := filepath.Join(Dir(projectDir), e.Name())
		switch {
		case !e.IsDir():
			out[dir] = "not a directory"
		case ValidSlug(e.Name()) != nil:
			out[dir] = "directory name is not a valid feature slug"
		default:
			m, err := LoadMeta(dir)
			switch {
			case err != nil:
				out[dir] = "no usable feature record: " + err.Error()
			case m.Slug != e.Name():
				out[dir] = fmt.Sprintf("record names slug %q", m.Slug)
			}
		}
	}
	return out, nil
}

// realFeatureDir reports whether every directory between a project and one of
// its features is a real directory rather than a link: the project's .cloop,
// its features directory, the feature and the feature's own .cloop.
//
// A feature is authorized, pinned and granted as the project whose path it is
// under (ParentOf). A link anywhere on that path would let whoever can write
// into one project — an agent in a container that bind-mounts it — make
// another project's features, state and task lists appear under it, and act
// on them with its own authority. Links are therefore never followed here.
func realFeatureDir(projectDir, featureDir string) bool {
	return realDir(filepath.Join(projectDir, ControlDir)) &&
		realDir(Dir(projectDir)) &&
		realDir(featureDir) &&
		realDir(filepath.Join(featureDir, ControlDir))
}

// realDir reports whether path is a directory and not a symbolic link.
func realDir(path string) bool {
	fi, err := os.Lstat(path)
	return err == nil && fi.IsDir()
}
