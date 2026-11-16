package executor

// readonly.go: other projects a run may read (Task 20501).
//
// A project's readers list (pkg/projectreaders) names the other projects whose
// runs may read it. When the list of project B names project A, every run of A
// is given B's source tree read-only, and only then. What "given" means depends
// on where the run is, so a Spec carries the decision (Spec.ReadOnly) and each
// driver delivers it the one way it can:
//
//   - a container on the hub's host (runc, Kata, gVisor alike) binds B's
//     directory read-only at /readonly/<slug>, with B's control directory,
//     its git directory and its credential files covered by empty read-only
//     binds (ReadOnlyHidden);
//   - a workload forked on the hub's host reads B where it is, and the host
//     sandbox adds B's entries — the hidden ones left out — to its Landlock
//     policy read-only;
//   - a Kubernetes Pod or a remote device, which share no filesystem with the
//     hub, receives a snapshot of B instead (pkg/executor/readonlysnap), placed
//     at /readonly/<slug> by something other than the workload and mounted or
//     made read-only so the workload cannot change it.
//
// The run is told which projects it may read, and where, through
// EnvReadOnlyProjects; its orchestrator puts that list in every task's prompt
// and asks the hub at each task boundary whether it still holds.

import (
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"unicode"
)

// ReadOnlyRoot is the directory other projects appear under inside a sandbox.
const ReadOnlyRoot = "/readonly"

// MaxReadOnlyProjects bounds how many other projects one run is given. A
// readers list can name more; the hub gives the first ones by path and says
// which it left out.
const MaxReadOnlyProjects = 16

// maxReadOnlySlug bounds a slug: a DNS label's length, which also keeps it a
// valid Kubernetes volume sub-path.
const maxReadOnlySlug = 63

// EnvReadOnlyProjects tells a run which other projects it may read and where
// it finds each: the JSON of a []ReadOnlyManifestEntry. It names paths, never
// a credential.
const EnvReadOnlyProjects = "CLOOP_READONLY_PROJECTS"

// ReadOnlyDelivery says how a driver gives a run another project.
type ReadOnlyDelivery string

const (
	// ReadOnlyNone: the driver gives a run no other project.
	ReadOnlyNone ReadOnlyDelivery = ""
	// ReadOnlyBind: a read-only bind of the project's directory on this host
	// at /readonly/<slug>, its hidden entries covered.
	ReadOnlyBind ReadOnlyDelivery = "bind"
	// ReadOnlyInPlace: the project at its own path on this host, which the
	// workload reads where it is. Read-only only when the workload runs in the
	// host sandbox, whose Landlock policy grants it so; without one the
	// workload already reaches everything the hub's user can.
	ReadOnlyInPlace ReadOnlyDelivery = "in_place"
	// ReadOnlySnapshot: a snapshot the executor fetches from the hub and
	// places at /readonly/<slug> where the workload cannot write it.
	ReadOnlySnapshot ReadOnlyDelivery = "snapshot"
)

// ReadOnlyProject is one other project a run may read.
type ReadOnlyProject struct {
	// Slug names the project's directory under ReadOnlyRoot, unique within
	// the run (see ValidReadOnlySlug).
	Slug string `json:"slug"`
	// Project is the project's path on the hub: its identity there, under
	// which its readers list is kept. It is a name to the run, not a path it
	// can open (except in place, where the two are the same).
	Project string `json:"project"`
	// Name is the project's name on the hub, for the run's prompt.
	Name string `json:"name,omitempty"`
	// Source is the project's directory on the executor's own host, for a
	// driver that binds it or grants it in place: the hub's directory for the
	// hub's own drivers, the unpacked snapshot for a device's. Never shipped:
	// it means nothing on another machine.
	Source string `json:"-"`
	// Snapshot says how a driver that shares no filesystem with the hub
	// fetches the project. Nil for a driver that reads Source.
	Snapshot *ReadOnlySnapshotRef `json:"snapshot,omitempty"`
	// Sealed says Source is a snapshot the executor placed, which holds no
	// hidden entry and which nobody but the executor writes: a driver may
	// grant it whole rather than entry by entry. Never shipped.
	Sealed bool `json:"-"`
}

// ReadOnlySnapshotRef says where an executor fetches a snapshot of another
// project: the hub's run-scoped endpoint, which builds it when asked and asks
// the readers list first, every time — so the hub stops serving it the moment
// the list stops naming the run's project.
type ReadOnlySnapshotRef struct {
	// URL is the endpoint the snapshot is fetched from, with a POST naming
	// the slug.
	URL string `json:"url"`
	// TokenEnv names the variable of the workload's environment whose value
	// authenticates the fetch: the run's own session token, never a
	// credential of the hub's.
	TokenEnv string `json:"token_env"`
}

// Target is where the project appears inside a sandbox.
func (p ReadOnlyProject) Target() string { return path.Join(ReadOnlyRoot, p.Slug) }

// ReadOnlyManifestEntry is what a run is told about one project it may read.
type ReadOnlyManifestEntry struct {
	// Slug is the project's slug, by which the run asks the hub about it.
	Slug string `json:"slug"`
	// Project is its path on the hub; Name its name there.
	Project string `json:"project"`
	Name    string `json:"name,omitempty"`
	// Path is where the run finds its files.
	Path string `json:"path"`
}

// EncodeReadOnlyManifest renders entries as EnvReadOnlyProjects' value.
func EncodeReadOnlyManifest(entries []ReadOnlyManifestEntry) string {
	if len(entries) == 0 {
		return ""
	}
	b, err := json.Marshal(entries)
	if err != nil {
		return ""
	}
	return string(b)
}

// DecodeReadOnlyManifest reads EnvReadOnlyProjects' value. An empty value is
// no projects; a value that does not parse, or names a path that is not
// absolute, is an error — a run must not guess what it was given.
func DecodeReadOnlyManifest(value string) ([]ReadOnlyManifestEntry, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, nil
	}
	var entries []ReadOnlyManifestEntry
	if err := json.Unmarshal([]byte(value), &entries); err != nil {
		return nil, fmt.Errorf("executor: %s is not a list of projects: %w", EnvReadOnlyProjects, err)
	}
	if len(entries) > MaxReadOnlyProjects {
		return nil, fmt.Errorf("executor: %s names %d projects, at most %d are allowed",
			EnvReadOnlyProjects, len(entries), MaxReadOnlyProjects)
	}
	seen := map[string]bool{}
	for _, e := range entries {
		if !ValidReadOnlySlug(e.Slug) || seen[e.Slug] {
			return nil, fmt.Errorf("executor: %s names the slug %q twice or invalidly", EnvReadOnlyProjects, e.Slug)
		}
		seen[e.Slug] = true
		if !filepath.IsAbs(e.Path) || strings.ContainsAny(e.Path, "\x00\n\r") {
			return nil, fmt.Errorf("executor: %s gives %q no absolute path", EnvReadOnlyProjects, e.Slug)
		}
	}
	return entries, nil
}

// ReadOnlyManifest is what the run is told about projects when each is at
// pathOf's answer.
func ReadOnlyManifest(projects []ReadOnlyProject, pathOf func(ReadOnlyProject) string) []ReadOnlyManifestEntry {
	out := make([]ReadOnlyManifestEntry, 0, len(projects))
	for _, p := range projects {
		out = append(out, ReadOnlyManifestEntry{Slug: p.Slug, Project: p.Project, Name: p.Name, Path: pathOf(p)})
	}
	return out
}

// WithReadOnlyManifest returns env with EnvReadOnlyProjects set to the
// manifest of projects, any earlier value replaced; with no projects it is
// removed. A nil env stays nil when there is nothing to set.
func WithReadOnlyManifest(env []string, entries []ReadOnlyManifestEntry) []string {
	out := make([]string, 0, len(env)+1)
	for _, kv := range env {
		if name, _, _ := strings.Cut(kv, "="); name == EnvReadOnlyProjects {
			continue
		}
		out = append(out, kv)
	}
	if v := EncodeReadOnlyManifest(entries); v != "" {
		out = append(out, EnvReadOnlyProjects+"="+v)
	}
	if env == nil && len(out) == 0 {
		return nil
	}
	return out
}

// ValidReadOnlySlug reports whether s may name a directory under ReadOnlyRoot:
// lowercase letters, digits, '.', '_' and '-', starting with a letter or a
// digit, at most 63 bytes. Nothing in it can climb out of ReadOnlyRoot or
// re-parse as a mount option.
func ValidReadOnlySlug(s string) bool {
	if s == "" || len(s) > maxReadOnlySlug {
		return false
	}
	for i, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
		case (r == '-' || r == '_' || r == '.') && i > 0:
		default:
			return false
		}
	}
	return true
}

// ReadOnlySlug derives a slug for a project named name (its base name when
// name is empty) that is not in taken, and records it there.
func ReadOnlySlug(name, projectPath string, taken map[string]bool) string {
	base := slugify(name)
	if base == "" {
		base = slugify(filepath.Base(projectPath))
	}
	if base == "" {
		base = "project"
	}
	slug := base
	for n := 2; taken[slug]; n++ {
		suffix := fmt.Sprintf("-%d", n)
		trimmed := base
		if len(trimmed)+len(suffix) > maxReadOnlySlug {
			trimmed = strings.TrimRight(trimmed[:maxReadOnlySlug-len(suffix)], "-_.")
		}
		slug = trimmed + suffix
	}
	if taken != nil {
		taken[slug] = true
	}
	return slug
}

// slugify lowercases s and keeps what ValidReadOnlySlug allows, folding every
// run of anything else into one '-'.
func slugify(s string) string {
	var b strings.Builder
	dash := false
	for _, r := range strings.ToLower(strings.TrimSpace(s)) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '_', r == '.':
			if (r == '_' || r == '.') && b.Len() == 0 {
				continue
			}
			b.WriteRune(r)
			dash = false
		case unicode.IsSpace(r) || r == '-' || r == '/' || unicode.IsPunct(r) || unicode.IsSymbol(r) || r > unicode.MaxASCII:
			if b.Len() > 0 && !dash {
				b.WriteByte('-')
				dash = true
			}
		}
	}
	out := strings.Trim(b.String(), "-_.")
	if len(out) > maxReadOnlySlug {
		out = strings.TrimRight(out[:maxReadOnlySlug], "-_.")
	}
	return out
}

// readOnlyHiddenNames are the entries of a project nobody else is given: its
// control directory, where cloop keeps the project's state, configuration and
// credentials; its git directory, whose configuration can hold a credential
// and whose history the run does not need to read the tree; and the files
// tools keep credentials in.
var readOnlyHiddenNames = map[string]bool{
	".cloop": true, ".git": true,
	".netrc": true, ".git-credentials": true, ".npmrc": true, ".pypirc": true, ".envrc": true,
	".ssh": true, ".aws": true, ".kube": true, ".docker": true, ".gnupg": true, ".azure": true, ".gcloud": true,
	".claude": true, ".mcp.json": true,
	"id_rsa": true, "id_dsa": true, "id_ecdsa": true, "id_ed25519": true,
}

// ReadOnlyHidden reports whether an entry named name is kept out of another
// project's tree: the control and git directories, and the files credentials
// live in by convention — .env and .env.*, private keys (*.key, *.p12, *.pfx,
// id_rsa and its kind) and the configuration files of git, npm, pip, SSH and
// the cloud CLIs.
func ReadOnlyHidden(name string) bool {
	if readOnlyHiddenNames[name] {
		return true
	}
	if name == ".env" || strings.HasPrefix(name, ".env.") {
		return true
	}
	switch strings.ToLower(path.Ext(name)) {
	case ".key", ".p12", ".pfx":
		return true
	}
	return false
}

// ReadOnlyHiddenPath reports whether a slash-separated path relative to a
// project's root is hidden: any of its components is.
func ReadOnlyHiddenPath(rel string) bool {
	for _, elem := range strings.Split(rel, "/") {
		if ReadOnlyHidden(elem) {
			return true
		}
	}
	return false
}

// MaxReadOnlyEntries bounds the top-level entries of a project a driver
// grants one by one, and MaxReadOnlyEntriesTotal those of every project one
// run is given. A project root holds tens; hundreds is not a source tree, and
// each one is a path in the host sandbox's policy, which travels in one
// environment string the kernel caps at 128 KiB.
const (
	MaxReadOnlyEntries      = 256
	MaxReadOnlyEntriesTotal = 512
)

// ReadOnlyEntries lists the top-level entries of a project directory on this
// host. visible are the absolute paths of the directories and regular files a
// run granted entries one by one is given: no symbolic link, which a grant
// would follow out of the project, and no device, socket or pipe. hidden are
// those of the hidden entries that are directories or regular files, which a
// driver binding the whole directory must cover. A hidden symbolic link is
// neither: what it names is resolved inside the sandbox, where the project's
// own hidden entries are covered too.
func ReadOnlyEntries(dir string) (visible, hidden []string, err error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, nil, fmt.Errorf("executor: read %s: %w", dir, err)
	}
	aliases := hiddenAliases(dir, entries)
	for _, e := range entries {
		full := filepath.Join(dir, e.Name())
		t := e.Type()
		if !t.IsDir() && !t.IsRegular() {
			continue
		}
		if ReadOnlyHidden(e.Name()) || aliases[e.Name()] {
			hidden = append(hidden, full)
			continue
		}
		visible = append(visible, full)
	}
	if len(visible) > MaxReadOnlyEntries {
		return nil, nil, fmt.Errorf("executor: %s has %d entries, more than the %d a project is given one by one",
			dir, len(visible), MaxReadOnlyEntries)
	}
	sort.Strings(visible)
	sort.Strings(hidden)
	return visible, hidden, nil
}

// ValidateReadOnly checks the projects a Spec gives its workload.
func ValidateReadOnly(projects []ReadOnlyProject) error {
	if len(projects) > MaxReadOnlyProjects {
		return fmt.Errorf("%w: %d read-only projects, at most %d are allowed",
			ErrInvalidSpec, len(projects), MaxReadOnlyProjects)
	}
	seen := make(map[string]bool, len(projects))
	for i, p := range projects {
		if !ValidReadOnlySlug(p.Slug) {
			return fmt.Errorf("%w: read_only[%d] slug %q is not a valid directory name", ErrInvalidSpec, i, p.Slug)
		}
		if seen[p.Slug] {
			return fmt.Errorf("%w: read_only slug %q is used twice", ErrInvalidSpec, p.Slug)
		}
		seen[p.Slug] = true
		// The project's path names it, and a driver that binds Source checks
		// that one for the characters its mount flag cannot carry.
		for _, f := range []struct{ name, val string }{{"project", p.Project}, {"source", p.Source}} {
			if f.val == "" && f.name == "source" {
				continue
			}
			if !filepath.IsAbs(f.val) || filepath.Clean(f.val) != f.val || strings.ContainsAny(f.val, "\x00\n\r") {
				return fmt.Errorf("%w: read_only[%d] %s %q is not a clean absolute path", ErrInvalidSpec, i, f.name, f.val)
			}
		}
		if s := p.Snapshot; s != nil {
			if strings.TrimSpace(s.URL) == "" || strings.ContainsAny(s.URL, " \x00\n\r") {
				return fmt.Errorf("%w: read_only[%d] snapshot has no URL", ErrInvalidSpec, i)
			}
			if strings.TrimSpace(s.TokenEnv) == "" {
				return fmt.Errorf("%w: read_only[%d] snapshot names no token variable", ErrInvalidSpec, i)
			}
		}
	}
	return nil
}

// ReadOnlyHiddenAliases returns the top-level entries of the project
// directory dir that a hidden top-level link points into: a project may keep
// its .cloop as a link to a directory of its own tree, which the hub's
// confinement allows, and that directory is the control directory under
// another name. Each is hidden as its hidden name is.
func ReadOnlyHiddenAliases(dir string) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	m := hiddenAliases(dir, entries)
	out := make([]string, 0, len(m))
	for name := range m {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

func hiddenAliases(dir string, entries []os.DirEntry) map[string]bool {
	out := map[string]bool{}
	root, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return out
	}
	for _, e := range entries {
		if e.Type()&os.ModeSymlink == 0 || !ReadOnlyHidden(e.Name()) {
			continue
		}
		target, err := filepath.EvalSymlinks(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		rel, err := filepath.Rel(root, target)
		if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			continue
		}
		out[strings.Split(filepath.ToSlash(rel), "/")[0]] = true
	}
	return out
}

// ReadOnlyBindable says why the project directory dir cannot be bound into a
// container with its hidden entries covered, or nil when it can: the
// runtimes' mount flag is colon-separated and takes comma-separated options,
// so neither the directory's path nor the name of a hidden entry it holds may
// carry either.
func ReadOnlyBindable(dir string) error {
	if strings.ContainsAny(dir, ":,") {
		return fmt.Errorf("its path %q holds a colon or a comma, which a container's mount flag cannot carry", dir)
	}
	_, hidden, err := ReadOnlyEntries(dir)
	if err != nil {
		return err
	}
	for _, h := range hidden {
		if name := filepath.Base(h); !ReadOnlyCoverable(name) {
			return fmt.Errorf("it holds %q, a hidden entry whose name a container's mount flag cannot carry", name)
		}
	}
	return nil
}

// ReadOnlyCoverable reports whether a hidden entry's name can be the last
// element of a mount target a container's -v flag carries.
func ReadOnlyCoverable(name string) bool {
	return name != "" && !strings.ContainsAny(name, ":,\x00\n\r\\")
}
