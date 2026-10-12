// Package projectconfine decides which directories may be a hub project
// (Task 20418).
//
// A project's directory is not a label. It is what the hub hands an executor:
// the container driver bind-mounts it read-write at /workspace, the host driver
// forks the harness in it, and DELETE /api/projects/{idx}?delete_root=true
// removes it recursively. So "which directory is this project" is the same
// question as "what may model-authored code read and write on this host", and
// before this package the hub answered it with a text denylist that let a
// maintainer register /var/lib on the packaged image — an ancestor of the
// control plane, its hub.env, its state.db and every tenant's project — and
// then delete /var/lib/postgresql.
//
// One predicate, Policy.Check, now answers it everywhere a directory becomes
// or acts as a project: the dashboard's and `cloop remote init`'s creation,
// the registry writes in pkg/multiui, a project's own state trying to relocate
// it (pkg/state), and every dispatch, which re-checks the row it is about to
// bind before any driver sees it. Backstop is the part a driver can apply
// knowing only the control plane's directory, for a caller that reaches a
// driver without going through the hub.
//
// The invariant, for a candidate directory P (canonical — see Canonical):
//
//   - P is a plausible project root at all: absolute, not /, not the hub
//     user's home or one of its ancestors, not inside a system tree, not a
//     bare top-level directory, and nothing inside a .cloop directory.
//   - P is neither ui.projects_root nor an ancestor of it: the root contains
//     every project created by name.
//   - For a caller who is not an administrator, P is strictly inside
//     ui.projects_root, and no component below the root is hidden.
//   - P is neither equal to, inside, nor an ancestor of the hub's control
//     plane. The hub's own entry is the exception — it is the operator's
//     directory, not something registered through the API — and so is a
//     directory inside ui.projects_root when the operator put the root inside
//     the control plane, as the packaged image does (HOME=/var/lib/cloop).
//   - P is neither equal to, inside, nor an ancestor of any other directory
//     that holds a hub's control plane (.cloop/hub.env, or a running hub's
//     working directory).
//   - P neither contains nor sits inside another registered project, and is
//     not one. Features live under their project's .cloop/features and are
//     never registry rows, so they are excepted by construction.
package projectconfine

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// Rule names the part of the invariant a directory breaks. The values are
// stable: the dashboard flags a project by its rule and `cloop hub doctor`
// reports it.
type Rule string

const (
	// RuleUnresolvable: the path could not be resolved (a dangling or looping
	// symlink), so nothing about where it points can be checked.
	RuleUnresolvable Rule = "unresolvable"
	// RuleUnsafe: never a project root wherever the hub stands.
	RuleUnsafe Rule = "unsafe"
	// RuleProjectsRoot: ui.projects_root itself, or a directory containing it.
	RuleProjectsRoot Rule = "projects_root"
	// RuleOutsideRoot: a caller who is not an administrator named a directory
	// outside ui.projects_root.
	RuleOutsideRoot Rule = "outside_projects_root"
	// RuleControlPlane: overlaps this hub's own directory.
	RuleControlPlane Rule = "control_plane"
	// RuleHub: overlaps a directory holding another hub's control plane.
	RuleHub Rule = "hub"
	// RuleProject: overlaps another registered project, or is one.
	RuleProject Rule = "project"
	// RuleUnverifiable: the search below the directory for a hub's control
	// plane ran out of budget before it finished.
	RuleUnverifiable Rule = "unverifiable"
	// RuleRelocated: the project's .cloop is a link out of its directory, so
	// the hub's reads and writes of its state would land somewhere else.
	RuleRelocated Rule = "relocated"
)

// Relation is how a directory sits relative to another.
type Relation string

const (
	// Same: the two are one directory.
	Same Relation = "same"
	// Inside: the directory is strictly inside the other.
	Inside Relation = "inside"
	// Contains: the directory is a strict ancestor of the other.
	Contains Relation = "contains"
)

// Violation is a refusal, naming the rule and the directory it collides with.
//
// Its Error names every path involved, which is right for an administrator and
// for the hub's own log. A handler answering someone who may not see the other
// directory must not hand them this text: see the identical answers in
// pkg/ui/project_confine.go.
type Violation struct {
	// Path is the candidate, canonical when it could be resolved.
	Path string
	Rule Rule
	// Other is the directory Path collides with: the projects root, the
	// control plane, a hub's directory, another project. Empty for
	// RuleUnsafe, RuleUnresolvable and RuleUnverifiable.
	Other string
	// Relation is how Path sits relative to Other.
	Relation Relation
	// Reason is the specific rule's wording, for the rules that have no Other.
	Reason string
}

func (v *Violation) Error() string {
	switch v.Rule {
	case RuleUnresolvable:
		return fmt.Sprintf("%s cannot be resolved to a directory: %s", v.Path, v.Reason)
	case RuleUnsafe:
		return fmt.Sprintf("%s cannot be a project directory: %s", v.Path, v.Reason)
	case RuleProjectsRoot:
		if v.Relation == Same {
			return fmt.Sprintf("%s is the hub's projects root (ui.projects_root): a project goes inside it, not at it", v.Path)
		}
		return fmt.Sprintf("%s contains the hub's projects root %s, and with it every project created by name", v.Path, v.Other)
	case RuleOutsideRoot:
		if v.Reason != "" {
			return fmt.Sprintf("%s is outside the hub's projects root %s: %s", v.Path, v.Other, v.Reason)
		}
		return fmt.Sprintf("%s is outside the hub's projects root %s: only an administrator places a project elsewhere", v.Path, v.Other)
	case RuleControlPlane:
		switch v.Relation {
		case Same:
			return fmt.Sprintf("%s is the hub's own directory, which holds its control plane", v.Path)
		case Contains:
			return fmt.Sprintf("%s contains the hub's control plane %s: a sandbox bound to it could read the hub's "+
				"secrets, its database and every project's state", v.Path, v.Other)
		}
		return fmt.Sprintf("%s is inside the hub's control plane %s and outside its projects root", v.Path, v.Other)
	case RuleHub:
		return fmt.Sprintf("%s %s %s, which holds a hub's control plane (.cloop/hub.env)", v.Path, describe(v.Relation), v.Other)
	case RuleProject:
		if v.Relation == Same {
			return fmt.Sprintf("a project is already registered at %s", v.Path)
		}
		return fmt.Sprintf("%s %s the project at %s: two projects may not share a tree", v.Path, describe(v.Relation), v.Other)
	case RuleUnverifiable:
		return fmt.Sprintf("could not verify that %s holds no hub's control plane: %s", v.Path, v.Reason)
	case RuleRelocated:
		return fmt.Sprintf("%s/.cloop is a link to %s, outside the project: the hub's reads and writes of its "+
			"state would land there", v.Path, v.Other)
	}
	return fmt.Sprintf("%s is not a valid project directory (%s)", v.Path, v.Rule)
}

func describe(r Relation) string {
	switch r {
	case Same:
		return "is"
	case Inside:
		return "is inside"
	case Contains:
		return "contains"
	}
	return "overlaps"
}

// IsViolation reports whether err is a refusal by this package, and returns it.
func IsViolation(err error) (*Violation, bool) {
	var v *Violation
	if errors.As(err, &v) {
		return v, true
	}
	return nil, false
}

// Canonical returns path as the directory the kernel would create for it:
// absolute and lexically cleaned (a trailing slash, "." and ".." are gone),
// with the symbolic links of its deepest existing ancestor resolved. The
// components below that ancestor do not exist yet, so nothing can resolve
// them; they are re-appended as written.
//
// Lexical cleaning first is deliberate rather than a shortcut. The hub creates
// and registers the cleaned path, so that is the directory every later rule
// has to be about; "/srv/link/../x" is "/srv/x" to MkdirAll whatever link
// points at.
func Canonical(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", errors.New("the path is empty")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	existing := abs
	var rest []string
	for {
		if _, err := os.Lstat(existing); err == nil {
			break
		}
		parent := filepath.Dir(existing)
		if parent == existing {
			break
		}
		rest = append(rest, filepath.Base(existing))
		existing = parent
	}
	resolved, err := filepath.EvalSymlinks(existing)
	if err != nil {
		return "", fmt.Errorf("%s does not resolve: %w", existing, err)
	}
	parts := make([]string, 0, len(rest)+1)
	parts = append(parts, resolved)
	for i := len(rest) - 1; i >= 0; i-- {
		parts = append(parts, rest[i])
	}
	return filepath.Join(parts...), nil
}

// Within reports whether child is strictly inside parent. Both must be clean
// absolute paths; the comparison is by path component, so /srv/p2 is not
// inside /srv/p.
func Within(child, parent string) bool {
	if parent == "/" {
		return child != "/" && strings.HasPrefix(child, "/")
	}
	return strings.HasPrefix(child, parent+"/")
}

// Relate says how path sits relative to other, or "" when the two are
// unrelated. Both must be clean absolute paths.
func Relate(path, other string) Relation {
	switch {
	case path == other:
		return Same
	case Within(path, other):
		return Inside
	case Within(other, path):
		return Contains
	}
	return ""
}

// systemTrees are directories that are never a project root, at any depth.
// Anything under them belongs to the operating system or the image.
var systemTrees = []string{
	"/bin", "/boot", "/dev", "/etc", "/lib", "/lib32", "/lib64", "/libx32",
	"/proc", "/run", "/sbin", "/sys", "/usr",
}

// UnsafeReason returns why path can never be a project root, or "" when it
// could be one. path should be canonical; home is the hub user's home
// directory, "" to skip the home rule.
//
// These are the rules that do not depend on anything the hub has registered:
// the directory is wrong wherever the hub stands.
func UnsafeReason(path, home string) string {
	if path == "" || !filepath.IsAbs(path) {
		return "it is not an absolute path"
	}
	clean := filepath.Clean(path)
	if clean == "/" {
		return "it is the filesystem root"
	}
	if home = strings.TrimSpace(home); home != "" && filepath.IsAbs(home) {
		h := filepath.Clean(home)
		if canon, err := Canonical(h); err == nil {
			h = canon
		}
		if clean == h {
			return "it is the hub user's home directory"
		}
		if Within(h, clean) {
			return "it contains the hub user's home directory, where its credentials live"
		}
	}
	for _, sub := range systemTrees {
		if clean == sub || Within(clean, sub) {
			return "it is inside " + sub + ", which belongs to the operating system"
		}
	}
	// A bare top-level directory (/var, /home, /tmp, /opt, …) is a shared
	// mount point, never one project's root.
	if !strings.Contains(strings.TrimPrefix(clean, "/"), "/") {
		return "a top-level directory is shared by everything on the host"
	}
	// Nothing inside a .cloop directory is a project root. Under a project's
	// .cloop/features it is a feature, which inherits its parent's executor,
	// grants and roles (Task 20341); anywhere else in .cloop it is a hub's or
	// a project's own state.
	for _, part := range strings.Split(clean, "/") {
		if part == ".cloop" {
			return "it is inside a .cloop directory, which holds a project's or a hub's own state"
		}
	}
	return ""
}

// relocatedState reports whether dir/.cloop is a symbolic link resolving
// outside dir, and where to. The hub opens a project's database, config and
// artifacts under that path on the project's behalf, and a workload can
// replace its own .cloop with a link — to another project's, or to the hub's.
func relocatedState(dir string) (string, bool) {
	state := filepath.Join(dir, ".cloop")
	info, err := os.Lstat(state)
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		return "", false
	}
	target, err := filepath.EvalSymlinks(state)
	if err != nil {
		return state, true // a dangling or looping link is not this project's state either
	}
	if Within(target, dir) {
		return "", false
	}
	return target, true
}

// HubEnvFile is the file `cloop hub bootstrap` writes a hub's secrets to,
// relative to the hub's directory. A directory holding it is a hub.
const HubEnvFile = ".cloop/hub.env"

// holdsHub reports whether dir is a hub's directory by its hub.env.
func holdsHub(dir string) bool {
	_, err := os.Lstat(filepath.Join(dir, HubEnvFile))
	return err == nil
}

// HubsAbove returns path and those of its ancestors that hold a hub's
// control plane, nearest first. path should be canonical.
func HubsAbove(path string) []string {
	var out []string
	for d := path; ; {
		if holdsHub(d) {
			out = append(out, d)
		}
		parent := filepath.Dir(d)
		if parent == d {
			return out
		}
		d = parent
	}
}

// ScanLimits bounds the search below a directory for a hub's control plane.
type ScanLimits struct {
	// MaxDepth is how many levels below the directory are searched.
	MaxDepth int
	// MaxDirs is how many directories are visited before giving up.
	MaxDirs int
}

// DefaultScan is the search a creation runs: deeper than any hub an operator
// keeps inside another tree, small enough to answer within a request (about a
// second on a cold cache at the limit).
//
// Running out of directories is a refusal (RuleUnverifiable); running out of
// depth is not. A source checkout is routinely more than eight levels deep and
// nothing about that makes it unsafe, while a tree too broad to search could be
// hiding anything. A stopped hub kept more than eight levels below a directory
// somebody registers is the residual case, and the threat model says so.
var DefaultScan = ScanLimits{MaxDepth: 8, MaxDirs: 100000}

// skippedScanDirs are not searched below. Hidden directories are skipped by
// rule, because none of them is where an operator keeps a hub; node_modules
// because it is where a tree keeps tens of thousands of directories that are
// not.
var skippedScanDirs = map[string]bool{"node_modules": true}

// HubsBelow searches the tree under path, breadth first and without following
// symbolic links, for directories holding a hub's control plane. path itself is
// not reported (HubsAbove covers it). truncated says the directory budget ran
// out before the search finished, so an empty answer is not a "no"; the depth
// limit ends the search quietly (see DefaultScan).
func HubsBelow(path string, limits ScanLimits) (found []string, truncated bool) {
	if limits.MaxDepth <= 0 || limits.MaxDirs <= 0 {
		return nil, false
	}
	type level struct {
		dir   string
		depth int
	}
	queue := []level{{path, 0}}
	visited := 0
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		entries, err := os.ReadDir(cur.dir)
		if err != nil {
			continue // unreadable: nothing the hub could bind there either
		}
		for _, e := range entries {
			// DirEntry.Type reports the link itself, so a symlinked directory
			// is never descended into — it is somewhere else's tree.
			if e.Type()&fs.ModeType != fs.ModeDir {
				continue
			}
			name := e.Name()
			if strings.HasPrefix(name, ".") || skippedScanDirs[name] {
				continue
			}
			child := filepath.Join(cur.dir, name)
			visited++
			if visited > limits.MaxDirs {
				return found, true
			}
			if holdsHub(child) {
				found = append(found, child)
			}
			if cur.depth+1 < limits.MaxDepth {
				queue = append(queue, level{child, cur.depth + 1})
			}
		}
	}
	return found, false
}

// Policy is everything the invariant is checked against. Every path in it must
// be canonical (Canonical); empty means "none".
type Policy struct {
	// ControlPlane is the hub's own directory.
	ControlPlane string
	// ProjectsRoot is ui.projects_root, or its default.
	ProjectsRoot string
	// ConfineToRoot is set for a caller who is not an administrator: the
	// directory must then be strictly inside ProjectsRoot.
	ConfineToRoot bool
	// Projects are the registered projects. The candidate may be among them
	// when an existing row is re-checked (Existing).
	Projects []string
	// HubDirs are the working directories of running hubs: control planes the
	// search may not find, because one need not keep a hub.env. A candidate
	// may not be one or contain one.
	HubDirs []string
	// Home is the hub user's home directory.
	Home string
	// Existing marks the re-check of a directory that is already a project:
	// at dispatch, in `cloop hub doctor`, on the Projects tab. Its own row is
	// not a collision, and the hub's own directory is allowed.
	Existing bool
	// Scan is the search below the candidate for another hub. Zero searches
	// nothing.
	Scan ScanLimits
}

// Check applies the invariant to path. It returns the canonical path — the one
// to create, register and bind — and a *Violation when the path is refused.
func (p Policy) Check(path string) (string, error) {
	canon, err := Canonical(path)
	if err != nil {
		clean := path
		if abs, aerr := filepath.Abs(path); aerr == nil {
			clean = abs
		}
		return clean, &Violation{Path: clean, Rule: RuleUnresolvable, Reason: err.Error()}
	}
	if p.Existing && p.ControlPlane != "" && canon == p.ControlPlane {
		// The hub's own entry: the operator's directory, never registered
		// through the API, and the project this hub was started in.
		return canon, nil
	}
	if reason := UnsafeReason(canon, p.Home); reason != "" {
		return canon, &Violation{Path: canon, Rule: RuleUnsafe, Reason: reason}
	}
	if target, ok := relocatedState(canon); ok {
		return canon, &Violation{Path: canon, Rule: RuleRelocated, Other: target}
	}
	root := p.ProjectsRoot
	if root != "" {
		if rel := Relate(canon, root); rel == Same || rel == Contains {
			return canon, &Violation{Path: canon, Rule: RuleProjectsRoot, Other: root, Relation: rel}
		}
	}
	if p.ConfineToRoot {
		if root == "" || !Within(canon, root) {
			return canon, &Violation{Path: canon, Rule: RuleOutsideRoot, Other: root}
		}
		for _, part := range strings.Split(strings.TrimPrefix(canon, root+"/"), "/") {
			if strings.HasPrefix(part, ".") {
				return canon, &Violation{Path: canon, Rule: RuleOutsideRoot, Other: root,
					Reason: "a hidden directory (" + part + ") is not a place for a project"}
			}
		}
	}
	if c := p.ControlPlane; c != "" {
		switch rel := Relate(canon, c); rel {
		case Same, Contains:
			return canon, &Violation{Path: canon, Rule: RuleControlPlane, Other: c, Relation: rel}
		case Inside:
			// Inside the hub's directory is allowed only inside a projects
			// root the operator placed there, which is the packaged image's
			// layout: HOME, the control plane and the default root are all
			// under /var/lib/cloop.
			if root == "" || !Within(root, c) || !Within(canon, root) {
				return canon, &Violation{Path: canon, Rule: RuleControlPlane, Other: c, Relation: rel}
			}
		}
	}
	// A directory holding .cloop/hub.env is a hub's control plane, and none of
	// the three relations is allowed with it. A running hub's working
	// directory is one too, but without a hub.env what binding a directory
	// beside it exposes is only what lies below: so for those, equal and
	// above are refused, and a project inside a hub someone started in their
	// home does not stop every project there from running.
	hubs := HubsAbove(canon)
	var truncated bool
	if p.Scan.MaxDepth > 0 && p.Scan.MaxDirs > 0 {
		below, cut := HubsBelow(canon, p.Scan)
		hubs = append(hubs, below...)
		truncated = cut
	}
	for _, h := range hubs {
		if h == "" || h == p.ControlPlane {
			continue // the control plane's own rule, with its carve-out, decided above
		}
		if rel := Relate(canon, h); rel != "" {
			return canon, &Violation{Path: canon, Rule: RuleHub, Other: h, Relation: rel}
		}
	}
	for _, h := range p.HubDirs {
		if h == "" || h == p.ControlPlane {
			continue
		}
		if rel := Relate(canon, h); rel == Same || rel == Contains {
			return canon, &Violation{Path: canon, Rule: RuleHub, Other: h, Relation: rel}
		}
	}
	for _, e := range p.Projects {
		if e == "" || e == p.ControlPlane {
			continue // the hub's own entry: the control plane's rule decided it
		}
		rel := Relate(canon, e)
		if rel == "" || (rel == Same && p.Existing) {
			continue
		}
		return canon, &Violation{Path: canon, Rule: RuleProject, Other: e, Relation: rel}
	}
	if truncated {
		return canon, &Violation{Path: canon, Rule: RuleUnverifiable,
			Reason: fmt.Sprintf("the tree under it is deeper than %d levels or larger than %d directories",
				p.Scan.MaxDepth, p.Scan.MaxDirs)}
	}
	return canon, nil
}

// Backstop is the part of the invariant a driver can enforce knowing only the
// hub's own directory: a work directory may be that directory, but may neither
// contain it nor sit inside its .cloop, and may not sit inside a directory
// holding another hub's control plane.
//
// A driver calls it immediately before it binds or forks in workDir. The hub
// applies the whole invariant before dispatch (pkg/ui/project_confine.go); this
// is what still holds for a caller that reaches a driver some other way.
// workDir is a project's directory: a feature's has already been mapped to its
// project's by the caller. An empty controlPlane checks nothing.
func Backstop(controlPlane, workDir string) error {
	if strings.TrimSpace(controlPlane) == "" || strings.TrimSpace(workDir) == "" {
		return nil
	}
	c, err := Canonical(controlPlane)
	if err != nil {
		return nil // no control plane to protect: it does not exist
	}
	w, err := Canonical(workDir)
	if err != nil {
		return &Violation{Path: workDir, Rule: RuleUnresolvable, Reason: err.Error()}
	}
	if w == c {
		return nil
	}
	if Within(c, w) {
		return &Violation{Path: w, Rule: RuleControlPlane, Other: c, Relation: Contains}
	}
	if state := filepath.Join(c, ".cloop"); w == state || Within(w, state) {
		return &Violation{Path: w, Rule: RuleControlPlane, Other: c, Relation: Inside}
	}
	for _, h := range HubsAbove(w) {
		if h != c {
			return &Violation{Path: w, Rule: RuleHub, Other: h, Relation: Relate(w, h)}
		}
	}
	return nil
}
