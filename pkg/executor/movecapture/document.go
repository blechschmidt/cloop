package movecapture

// document.go is the hub's reading of a device's document. The device is the
// least trusted party in a capture: everything it says is bounded and checked
// before the hub records it, renders it in a report, or hands it to git.

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/blechschmidt/cloop/pkg/executor/gitstate"
	"github.com/blechschmidt/cloop/pkg/executor/movegit"
	"github.com/blechschmidt/cloop/pkg/projectmove"
)

// ErrInvalidDocument is a device's document the hub refuses.
var ErrInvalidDocument = errors.New("movecapture: the device's answer is not one a capture writes")

// Bounds on what a document may hold.
const (
	maxDocText     = 4096
	maxDocPaths    = gitstate.DefaultMaxPaths * 4
	maxDocNotes    = 256
	maxDocBranches = gitstate.DefaultMaxBranches * (maxFeatures + 1)
	maxDocTrees    = (gitstate.DefaultMaxWorktrees + 1) * (maxFeatures + 1)
	maxDocFiles    = 200_000
	maxDocKept     = 16
)

// knownCategories are the .cloop file categories an inventory may name.
var knownCategories = map[string]bool{
	projectmove.FilesArtifacts: true, projectmove.FilesAttachmentOutbox: true, projectmove.FilesAttachments: true,
	projectmove.FilesCheckpoints: true, projectmove.FilesSandboxSpec: true, projectmove.FilesRequirementsSpec: true,
	projectmove.FilesConfig: true, projectmove.FilesOther: true,
}

// DecodeDocument reads a device's document and holds it to what was asked: an
// inspection or a capture of move moveID. Free text is bounded and stripped of
// control characters; a capture's manifest must pass
// movegit.ValidateManifest and its files projectmove.ValidateFiles.
func DecodeDocument(raw []byte, mode, moveID string) (Document, error) {
	var d Document
	bad := func(format string, a ...any) (Document, error) {
		return Document{}, fmt.Errorf("%w: "+format, append([]any{ErrInvalidDocument}, a...)...)
	}
	if err := json.Unmarshal(raw, &d); err != nil {
		return bad("%v", err)
	}
	if d.Version != DocumentVersion {
		return bad("version %d, this hub reads %d", d.Version, DocumentVersion)
	}
	if d.Mode != mode {
		return bad("it is an answer to %q, the hub asked for %q", d.Mode, mode)
	}
	d.WorkDir = cleanText(d.WorkDir)
	if len(d.Notes) > maxDocNotes || len(d.Features) > maxFeatures || len(d.Excluded) > maxFeatures {
		return bad("too many notes, features or exclusions")
	}
	for i := range d.Notes {
		d.Notes[i] = cleanText(d.Notes[i])
	}
	for _, f := range d.Features {
		if !validSlug(f) {
			return bad("feature %q", f)
		}
	}
	for i := range d.Excluded {
		d.Excluded[i] = cleanText(d.Excluded[i])
	}
	if !d.Present {
		if d.Inspection != nil || d.Manifest != nil || len(d.Files) > 0 || d.FilesTar != nil {
			return bad("it reports no working copy and still describes one")
		}
		return d, nil
	}
	switch mode {
	case ModeInspect:
		if d.Inspection == nil || d.Manifest != nil || len(d.Files) > 0 {
			return bad("an inspection carries no inspection, or a capture's parts")
		}
		if err := cleanInspection(d.Inspection); err != nil {
			return bad("%v", err)
		}
	case ModeCapture:
		if d.Manifest == nil || d.Inspection != nil {
			return bad("a capture carries no manifest")
		}
		if err := movegit.ValidateManifest(*d.Manifest, moveID); err != nil {
			return bad("%v", err)
		}
		// The manifest's prose is the device's, and the hub records and
		// shows it.
		man := d.Manifest
		for i := range man.Notes {
			man.Notes[i] = cleanText(man.Notes[i])
		}
		if man.Snapshot != nil {
			man.Snapshot.IndexNote = cleanText(man.Snapshot.IndexNote)
		}
		for i := range man.Worktrees {
			man.Worktrees[i].IndexNote = cleanText(man.Worktrees[i].IndexNote)
		}
		if len(d.Files) > maxDocFiles || len(d.Kept) > maxDocKept {
			return bad("%d files and %d kept categories", len(d.Files), len(d.Kept))
		}
		if err := projectmove.ValidateFiles(d.Files); err != nil {
			return bad("%v", err)
		}
		read := map[string]bool{}
		for _, f := range d.Features {
			read[f] = true
		}
		for _, f := range d.Files {
			if rest, ok := strings.CutPrefix(f.Path, "features/"); ok {
				slug, _, _ := strings.Cut(rest, "/")
				if !read[slug] {
					return bad(".cloop/%s belongs to a feature whose working copy the device did not read", f.Path)
				}
			}
		}
		if d.FilesTar == nil || d.FilesTar.Bytes < 0 || len(d.FilesTar.SHA256) != 64 {
			return bad("the tar's digest is missing")
		}
		for i := range d.Kept {
			if err := cleanItem(&d.Kept[i]); err != nil {
				return bad("%v", err)
			}
		}
	default:
		return bad("mode %q", mode)
	}
	return d, nil
}

// cleanText bounds s and replaces what a terminal or a log would act on.
func cleanText(s string) string {
	s = strings.ToValidUTF8(s, "?")
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) {
			return '?'
		}
		return r
	}, s)
	if len(s) > maxDocText {
		cut := maxDocText
		for cut > 0 && !utf8.RuneStart(s[cut]) {
			cut--
		}
		s = s[:cut] + "…"
	}
	return s
}

func cleanList(l []string, max int) ([]string, error) {
	if len(l) > max {
		return nil, fmt.Errorf("a list of %d, at most %d", len(l), max)
	}
	for i := range l {
		l[i] = cleanText(l[i])
	}
	return l, nil
}

// cleanInspection bounds an inspection's git state and inventories.
func cleanInspection(ins *Inspection) error {
	g := &ins.Git
	g.Dir, g.NotARepository = cleanText(g.Dir), cleanText(g.NotARepository)
	if len(g.Worktrees) > maxDocTrees || len(g.Branches) > maxDocBranches {
		return fmt.Errorf("%d worktrees and %d branches", len(g.Worktrees), len(g.Branches))
	}
	var err error
	if g.Remotes, err = cleanList(g.Remotes, 64); err != nil {
		return err
	}
	for i := range g.Worktrees {
		w := &g.Worktrees[i]
		w.Path, w.Rel, w.Branch, w.Head = cleanText(w.Path), cleanText(w.Rel), cleanText(w.Branch), cleanText(w.Head)
		w.Locked, w.Error = cleanText(w.Locked), cleanText(w.Error)
		if w.ChangedPaths, err = cleanList(w.ChangedPaths, maxDocPaths); err != nil {
			return err
		}
		if w.UntrackedPaths, err = cleanList(w.UntrackedPaths, maxDocPaths); err != nil {
			return err
		}
		if w.Changed < 0 || w.Untracked < 0 || w.Orphaned < 0 {
			return errors.New("a negative count")
		}
	}
	for i := range g.Branches {
		b := &g.Branches[i]
		b.Name, b.Head, b.Upstream, b.Error = cleanText(b.Name), cleanText(b.Head), cleanText(b.Upstream), cleanText(b.Error)
		if b.Unpushed < 0 {
			return errors.New("a negative count")
		}
	}
	if g.Stash < 0 || g.BranchesSkipped < 0 || g.WorktreesSkipped < 0 || g.WorktreesOutside < 0 {
		return errors.New("a negative count")
	}
	if err := cleanInventory(&ins.Files); err != nil {
		return err
	}
	if len(ins.FeatureFiles) > maxFeatures {
		return fmt.Errorf("%d feature inventories", len(ins.FeatureFiles))
	}
	for slug, inv := range ins.FeatureFiles {
		if !validSlug(slug) {
			return fmt.Errorf("an inventory for feature %q", slug)
		}
		if err := cleanInventory(&inv); err != nil {
			return err
		}
		ins.FeatureFiles[slug] = inv
	}
	return nil
}

func cleanInventory(inv *projectmove.FileInventory) error {
	inv.Dir, inv.Error = cleanText(inv.Dir), cleanText(inv.Error)
	if len(inv.Categories) > len(knownCategories) || inv.Links < 0 {
		return fmt.Errorf("an inventory of %d categories", len(inv.Categories))
	}
	for i := range inv.Categories {
		c := &inv.Categories[i]
		if !knownCategories[c.Name] || c.Files < 0 || c.Bytes < 0 {
			return fmt.Errorf("a file category %q", c.Name)
		}
		var err error
		if c.Examples, err = cleanList(c.Examples, 16); err != nil {
			return err
		}
	}
	return nil
}

func cleanItem(it *projectmove.Item) error {
	if !knownCategories[it.Name] || it.Count < 0 || it.Bytes < 0 {
		return fmt.Errorf("a kept category %q", it.Name)
	}
	it.Path, it.Detail = cleanText(it.Path), cleanText(it.Detail)
	var err error
	it.Examples, err = cleanList(it.Examples, 16)
	return err
}
