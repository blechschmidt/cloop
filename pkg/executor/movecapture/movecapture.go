// Package movecapture is the device's half of a project move's capture (Task
// 20495): what an executor agent runs when the hub asks it for a project's
// working copy, which the hub cannot read because it is on another machine.
//
// It produces what pkg/ui's capture produces from the hub's own tree — a
// snapshot of the uncommitted state on a hidden ref, one git bundle of every
// local branch and tag and of the features' working copies, and a tar of the
// .cloop files a move delivers — and, for a preflight, the read-only
// inspection the hub's own tree gets: git state and .cloop inventories.
//
// # Where it may look
//
// Only inside the trees root the agent keeps working copies under, and there
// only in the directories the request names: the project's working copy and
// each feature's, each one path element, opened through an os.Root. A working
// copy is a tree a workload wrote, and the agent is typically a more
// privileged user than any workload — root, on a device that attaches
// hardware — so nothing in it is trusted to point anywhere:
//
//   - the directories themselves must be directories, not links;
//   - a repository's .git must be a directory holding only directories and
//     regular files — no symbolic link, socket or device anywhere in it — with
//     no alternates (another repository's object store), no commondir, and a
//     configuration naming no core.worktree and including nothing, as git
//     itself reads it;
//   - every linked worktree git would read is checked the same way, its .git
//     a file naming a directory under the repository's own .git/worktrees;
//   - the .cloop files are walked and read through the os.Root, a link never
//     followed and each file checked, once open, to be the entry walked.
//
// Git then runs as pkg/executor/movegit runs it: no hook, filter, fsmonitor
// or signing program, no system or global configuration.
//
// # What it never takes
//
// The working-tree snapshot leaves out .cloop, which the tar accounts for, and
// any directory the request excludes — the agent excludes the run homes and
// lease directories should either ever lie inside a working copy, which by
// construction they do not. The tar carries only what a move delivers
// (pkg/projectmove: artifacts, task output, the attachment outbox,
// checkpoints and the two specs), never the project's config.yaml, its
// database, or anything else. Remote URLs lose their user information. What
// the snapshot holds of the files a workload wrote is scanned for credentials
// by the hub, which knows the values; the device does not.
//
// The capture runs while no workload of the project runs — the move stopped
// its runs first — so nothing changes the tree between the checks and git's
// reads. It writes into the working copy's repository only what a hub-tree
// capture writes into the hub's: the snapshot commits and their hidden refs.
package movecapture

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/blechschmidt/cloop/pkg/executor/gitstate"
	"github.com/blechschmidt/cloop/pkg/executor/movegit"
	"github.com/blechschmidt/cloop/pkg/projectmove"
)

// Modes a request asks for.
const (
	// ModeInspect reads what the working copy holds, for a preflight: git
	// state and .cloop inventories, nothing written.
	ModeInspect = "inspect"
	// ModeCapture captures it: snapshot refs, the bundle and the tar.
	ModeCapture = "capture"
)

// DocumentVersion is the version of the document this build writes and reads.
const DocumentVersion = 1

// Names of the files a capture writes into its scratch directory.
const (
	BundleName = "repo.bundle"
	FilesName  = "cloop-files.tar"
)

// Feature is one of the project's features, whose working copy a device keeps
// in a directory of its own beside the project's.
type Feature struct {
	Slug string `json:"slug"`
	// Dir is the working copy's directory: one path element under the
	// trees root.
	Dir string `json:"dir"`
}

// Request is what to read or capture.
type Request struct {
	// Root is the directory the agent keeps working copies under.
	Root string
	// WorkDir is the project's working copy: one path element under Root.
	WorkDir  string
	Features []Feature
	Mode     string
	// MoveID names the hidden refs a capture writes.
	MoveID string
	// Exclude are paths inside a working copy, relative to it, that are
	// never read: the agent names any run home or lease directory that lies
	// inside one.
	Exclude []string
	// Scratch is where a capture writes its bundle and tar: a directory of
	// the agent's own, outside Root.
	Scratch string
	// MaxBundleBytes and MaxFilesBytes bound what a capture writes; zero
	// means no bound.
	MaxBundleBytes int64
	MaxFilesBytes  int64
}

// Inspection is what an inspection read: pkg/projectmove's Tree, with the
// features' working copies folded into the project's git state.
type Inspection struct {
	Git          gitstate.State                       `json:"git"`
	Files        projectmove.FileInventory            `json:"files"`
	FeatureFiles map[string]projectmove.FileInventory `json:"feature_files,omitempty"`
}

// Document is what the device sends the hub ahead of the bundle and the tar.
type Document struct {
	Version int    `json:"version"`
	Mode    string `json:"mode"`
	// Present reports that the project's working copy exists on the device;
	// a device that never ran the project has none, and nothing else is set.
	Present bool `json:"present"`
	// WorkDir is where the working copy is on the device.
	WorkDir    string      `json:"work_dir"`
	Inspection *Inspection `json:"inspection,omitempty"`
	// Manifest, Files, Kept and FilesTar are a capture's: the repository's
	// manifest (Repository false when the working copy holds none), the
	// .cloop files the tar holds, the categories kept on the device, and the
	// tar's digest.
	Manifest *movegit.Manifest  `json:"manifest,omitempty"`
	Files    []projectmove.File `json:"files,omitempty"`
	Kept     []projectmove.Item `json:"kept,omitempty"`
	FilesTar *movegit.Digest    `json:"files_tar,omitempty"`
	Notes    []string           `json:"notes,omitempty"`
	// Features are the slugs of the features whose working copies were
	// found and read.
	Features []string `json:"features,omitempty"`
	// Excluded are the paths inside the working copy the capture left out.
	Excluded []string `json:"excluded,omitempty"`
}

// Result is a capture's document and the files it wrote.
type Result struct {
	Doc Document
	// BundlePath is the bundle; "" when the working copy holds no
	// repository.
	BundlePath string
	// TarPath is the tar of .cloop files; "" when the working copy is absent.
	TarPath string
}

// ErrInvalidRequest is a request this package refuses before touching
// anything.
var ErrInvalidRequest = errors.New("movecapture: invalid request")

// ErrConfinement is a working copy whose layout could lead git, or a read,
// outside it.
var ErrConfinement = errors.New("movecapture: the working copy reaches outside itself")

// ErrNoProjectRepository refuses a device whose features' working copies hold
// repositories while the project's own does not: the features travel inside
// the project's bundle, and there is none to carry them.
var ErrNoProjectRepository = errors.New("movecapture: the project's own working copy holds no repository, so its features' working copies cannot be carried; push their work, or move the project with abandon_source")

// validName reports whether s is one plain path element.
func validName(s string) bool {
	if s == "" || s == "." || s == ".." || len(s) > 255 || strings.ContainsAny(s, "/\\\x00") {
		return false
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

// validSlug reports whether s can name a feature.
func validSlug(s string) bool {
	if s == "" || len(s) > 128 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '_', c == '.':
		default:
			return false
		}
	}
	return s != "." && s != ".."
}

// maxFeatures bounds how many features one request names.
const maxFeatures = 256

// Check validates a request's shape.
func (r Request) Check() error {
	switch r.Mode {
	case ModeInspect, ModeCapture:
	default:
		return fmt.Errorf("%w: mode %q", ErrInvalidRequest, r.Mode)
	}
	if !filepath.IsAbs(r.Root) {
		return fmt.Errorf("%w: the trees root %q is not an absolute path", ErrInvalidRequest, r.Root)
	}
	if !validName(r.WorkDir) {
		return fmt.Errorf("%w: %q is not one directory name", ErrInvalidRequest, r.WorkDir)
	}
	if len(r.Features) > maxFeatures {
		return fmt.Errorf("%w: %d features, at most %d", ErrInvalidRequest, len(r.Features), maxFeatures)
	}
	seen := map[string]bool{r.WorkDir: true}
	for _, f := range r.Features {
		if !validSlug(f.Slug) || !validName(f.Dir) || seen[f.Dir] {
			return fmt.Errorf("%w: feature %q at %q", ErrInvalidRequest, f.Slug, f.Dir)
		}
		seen[f.Dir] = true
	}
	for _, ex := range r.Exclude {
		if !relativeClean(ex) {
			return fmt.Errorf("%w: exclude %q is not a plain relative path", ErrInvalidRequest, ex)
		}
	}
	if r.Mode == ModeCapture {
		if !movegit.ValidMoveID(r.MoveID) {
			return fmt.Errorf("%w: %q is not a move id", ErrInvalidRequest, r.MoveID)
		}
		if !filepath.IsAbs(r.Scratch) {
			return fmt.Errorf("%w: no scratch directory", ErrInvalidRequest)
		}
		// Beside the working copies is the agent's own; inside one is the
		// workload's.
		inside := filepath.Clean(r.Scratch) == filepath.Clean(r.Root) || within(filepath.Join(r.Root, r.WorkDir), r.Scratch)
		for _, f := range r.Features {
			inside = inside || within(filepath.Join(r.Root, f.Dir), r.Scratch)
		}
		if inside {
			return fmt.Errorf("%w: the scratch directory %s is inside a working copy", ErrInvalidRequest, r.Scratch)
		}
	}
	return nil
}

// relativeClean reports whether p is a plain relative slash path.
func relativeClean(p string) bool {
	if p == "" || strings.HasPrefix(p, "/") || strings.Contains(p, "\\") {
		return false
	}
	for _, part := range strings.Split(p, "/") {
		if part == "" || part == "." || part == ".." {
			return false
		}
	}
	return true
}

// within reports whether p is root or lies beneath it, lexically.
func within(root, p string) bool {
	root, p = filepath.Clean(root), filepath.Clean(p)
	return p == root || strings.HasPrefix(p, root+string(filepath.Separator))
}

// tree is one opened working copy.
type tree struct {
	name string
	path string
	root *os.Root
}

func (t *tree) close() {
	if t != nil && t.root != nil {
		_ = t.root.Close()
	}
}

// Inspect reads what the project's working copy and its features' hold.
func Inspect(ctx context.Context, req Request) (Document, error) {
	req.Mode = ModeInspect
	if err := req.Check(); err != nil {
		return Document{}, err
	}
	trees, err := openRoot(req.Root)
	if err != nil {
		return Document{}, err
	}
	defer trees.Close()
	doc := Document{Version: DocumentVersion, Mode: ModeInspect, WorkDir: filepath.Join(req.Root, req.WorkDir)}
	main, err := openTree(trees, req.Root, req.WorkDir)
	if errors.Is(err, os.ErrNotExist) {
		return doc, nil
	}
	if err != nil {
		return doc, err
	}
	defer main.close()
	doc.Present = true
	exclude := append([]string{".cloop"}, req.Exclude...)
	// A worktree the confinement refuses fails the inspection, as it fails a
	// capture: the preflight then blocks the move instead of reporting a
	// worktree it could not read.
	var refused error
	inner := confiner(trees, req.Root)
	confine := func(dir string) error {
		err := inner(dir)
		if err != nil && refused == nil {
			refused = err
		}
		return err
	}
	if err := checkRepository(ctx, main); err != nil {
		return doc, err
	}
	if err := checkNested(ctx, main); err != nil {
		return doc, err
	}
	g, err := gitstate.Inspect(ctx, main.path, gitstate.Options{Exclude: exclude, Confine: confine})
	if err == nil && refused != nil {
		err = refused
	}
	if err != nil {
		return doc, err
	}
	ins := &Inspection{Git: g, Files: projectmove.InventoryFilesIn(main.root, filepath.Join(main.path, ".cloop")),
		FeatureFiles: map[string]projectmove.FileInventory{}}
	for _, f := range req.Features {
		ft, err := openTree(trees, req.Root, f.Dir)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return doc, fmt.Errorf("feature %s: %w", f.Slug, err)
		}
		doc.Features = append(doc.Features, f.Slug)
		if err := checkRepository(ctx, ft); err != nil {
			ft.close()
			return doc, fmt.Errorf("feature %s: %w", f.Slug, err)
		}
		if err := checkNested(ctx, ft); err != nil {
			ft.close()
			return doc, fmt.Errorf("feature %s: %w", f.Slug, err)
		}
		if hasRepository(ft) && !hasRepository(main) {
			ft.close()
			return doc, fmt.Errorf("%w (feature %s)", ErrNoProjectRepository, f.Slug)
		}
		fg, err := gitstate.Inspect(ctx, ft.path, gitstate.Options{Exclude: exclude, Confine: confine})
		if err == nil && refused != nil {
			err = refused
		}
		if err != nil {
			ft.close()
			return doc, fmt.Errorf("feature %s: %w", f.Slug, err)
		}
		foldFeature(&ins.Git, fg, f.Slug)
		ins.FeatureFiles[f.Slug] = projectmove.InventoryFilesIn(ft.root, filepath.Join(ft.path, ".cloop"))
		ft.close()
	}
	doc.Inspection = ins
	return doc, nil
}

// foldFeature adds a feature's working copy, a repository of its own on a
// device, to the project's git state: its worktrees named as the feature is
// inside the project, its branches by the feature.
func foldFeature(st *gitstate.State, f gitstate.State, slug string) {
	if !f.Repository {
		return
	}
	if !st.Repository {
		// The project's own working copy holds no repository; the feature's
		// are still worth reporting.
		st.Repository = true
		st.NotARepository = ""
	}
	rel := ".cloop/features/" + slug
	for _, w := range f.Worktrees {
		if w.Rel == "" {
			w.Rel = rel
		} else {
			w.Rel = rel + "/" + w.Rel
		}
		st.Worktrees = append(st.Worktrees, w)
	}
	for _, b := range f.Branches {
		b.Name = "feature " + slug + ": " + b.Name
		st.Branches = append(st.Branches, b)
	}
	st.BranchesSkipped += f.BranchesSkipped
	st.WorktreesSkipped += f.WorktreesSkipped
	st.Stash += f.Stash
	for _, r := range f.Remotes {
		known := false
		for _, have := range st.Remotes {
			known = known || have == r
		}
		if !known {
			st.Remotes = append(st.Remotes, r)
		}
	}
}

// Capture captures the project's working copy and its features' into
// req.Scratch.
func Capture(ctx context.Context, req Request) (Result, error) {
	req.Mode = ModeCapture
	if err := req.Check(); err != nil {
		return Result{}, err
	}
	trees, err := openRoot(req.Root)
	if err != nil {
		return Result{}, err
	}
	defer trees.Close()
	res := Result{Doc: Document{Version: DocumentVersion, Mode: ModeCapture, WorkDir: filepath.Join(req.Root, req.WorkDir)}}
	main, err := openTree(trees, req.Root, req.WorkDir)
	if errors.Is(err, os.ErrNotExist) {
		return res, nil
	}
	if err != nil {
		return res, err
	}
	defer main.close()
	res.Doc.Present = true
	if err := checkRepository(ctx, main); err != nil {
		return res, err
	}
	if err := checkNested(ctx, main); err != nil {
		return res, err
	}
	cred, err := ownerOf(main)
	if err != nil {
		return res, err
	}
	var (
		externals []movegit.ExternalTree
		sets      = []projectmove.FileSet{{Root: main.root, Dir: filepath.Join(main.path, ".cloop")}}
	)
	for _, f := range req.Features {
		ft, err := openTree(trees, req.Root, f.Dir)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return res, fmt.Errorf("feature %s: %w", f.Slug, err)
		}
		defer ft.close()
		if err := checkRepository(ctx, ft); err != nil {
			return res, fmt.Errorf("feature %s: %w", f.Slug, err)
		}
		if err := checkNested(ctx, ft); err != nil {
			return res, fmt.Errorf("feature %s: %w", f.Slug, err)
		}
		if hasRepository(ft) && !hasRepository(main) {
			return res, fmt.Errorf("%w (feature %s)", ErrNoProjectRepository, f.Slug)
		}
		fcred, err := ownerOf(ft)
		if err != nil {
			return res, err
		}
		res.Doc.Features = append(res.Doc.Features, f.Slug)
		externals = append(externals, movegit.ExternalTree{Rel: ".cloop/features/" + f.Slug, Dir: ft.path, Credential: fcred})
		sets = append(sets, projectmove.FileSet{Root: ft.root, Dir: filepath.Join(ft.path, ".cloop"),
			Prefix: "features/" + f.Slug + "/.cloop/"})
	}
	if err := os.MkdirAll(req.Scratch, 0o700); err != nil {
		return res, fmt.Errorf("movecapture: %w", err)
	}
	if cred != nil {
		// git writes the bundle here as the working copy's owner.
		if err := os.Chown(req.Scratch, int(cred.Uid), int(cred.Gid)); err != nil {
			return res, fmt.Errorf("movecapture: %w", err)
		}
	}
	bundle := filepath.Join(req.Scratch, BundleName)
	man, err := movegit.Capture(ctx, movegit.CaptureOptions{
		MoveID: req.MoveID, Dir: main.path, BundlePath: bundle, MaxBundleBytes: req.MaxBundleBytes,
		Exclude: append([]string{".cloop"}, req.Exclude...), Confine: confiner(trees, req.Root), External: externals,
		Credential: cred,
	})
	if err != nil {
		return res, err
	}
	res.Doc.Manifest = &man
	if man.Repository {
		res.BundlePath = bundle
	}
	tarPath := filepath.Join(req.Scratch, FilesName)
	files, kept, sum, err := projectmove.PackFileSets(tarPath, req.MaxFilesBytes, sets...)
	if err != nil {
		return res, err
	}
	res.TarPath = tarPath
	res.Doc.Files, res.Doc.Kept, res.Doc.FilesTar = files, kept, &sum
	res.Doc.Notes = append(res.Doc.Notes, man.Notes...)
	res.Doc.Excluded = append(res.Doc.Excluded, req.Exclude...)
	return res, nil
}

// Encode renders a document for the wire.
func (d Document) Encode() ([]byte, error) {
	b, err := json.Marshal(d)
	if err != nil {
		return nil, fmt.Errorf("movecapture: %w", err)
	}
	return b, nil
}
