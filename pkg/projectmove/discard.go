package projectmove

// discard.go removes the copy of a project that a verified move left on a
// device (Task 20496).
//
// A move only ever reads its source: a done move records the device's working
// copy as retained, and nothing removes it until the person cleaning up after
// the move confirms. Then the hub runs `cloop workspace move-discard` on the
// device, in that working copy, and it removes nothing unless the copy still
// holds exactly what the move captured and nothing the move did not carry:
//
//   - the move's snapshot ref names the snapshot commit the hub recorded, so
//     the directory is the copy this move captured and not one a later move
//     seeded there, or another project's;
//   - HEAD is still the commit the snapshot stands on, and the index and the
//     files on disk are what it recorded;
//   - every branch, tag, note and the stash is where the capture found it,
//     checked against a digest of the capture's manifest (RefsDigest) — a
//     commit on another branch, or a new stash entry, would otherwise go with
//     the copy;
//   - the files under .cloop a move delivers are the ones it delivered
//     (FilesDigest);
//   - it has no linked worktrees, whose own changes the checks above do not
//     see;
//   - and it holds no file git ignores — an .env, a data directory, build
//     output — which no move carries, unless the person asked for those to go
//     too (DiscardIgnored).
//
// When one of those fails the copy is kept and the report says why; it is not
// an error. Otherwise a marker naming the move is written first, then every
// entry of the directory is removed — .git second to last, the marker last —
// and the directory itself is kept, empty: the agent addresses a project's
// working copy by it, and an empty one is what a later move onto the device
// seeds into. A discard that was cut off part-way finds its marker and
// finishes, rather than finding a half-removed repository it no longer
// recognises.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/blechschmidt/cloop/pkg/executor/movegit"
)

// Why a discard kept a working copy (WorkingCopyReport.Kept).
const (
	// KeptChanged: the copy is not, or no longer, what the move captured.
	KeptChanged = "changed"
	// KeptIgnored: the copy holds files git ignores, which no move carries.
	KeptIgnored = "ignored"
)

// discardMarker is the file a discard writes into the copy before it removes
// anything, naming the move and its snapshot.
const discardMarker = ".cloop-move-discard"

// maxIgnoredListed bounds how many ignored paths a discard reads before it
// stops counting.
const maxIgnoredListed = 10000

// DiscardOptions say which copy DiscardWorkingCopy may remove.
type DiscardOptions struct {
	// MoveID is the move; Snapshot the snapshot commit its capture recorded.
	MoveID   string
	Snapshot string
	// Refs is RefsDigest of the capture's manifest; Files is FilesDigest of
	// the files the move delivered.
	Refs  string
	Files string
	// DiscardIgnored removes the files git ignores along with the rest. Without
	// it a copy holding any is kept.
	DiscardIgnored bool
}

// RefsDigest is what a working copy's refs must come to for a discard to
// remove it: every branch and tag the capture recorded at its object, and the
// stash's newest entry. A working copy's own refs are read the same way by
// ObservedRefsDigest; remote-tracking refs and the moves' hidden refs are left
// out of both, and any other ref — a note, say — makes them differ.
func RefsDigest(m movegit.Manifest) string {
	lines := make([]string, 0, len(m.Branches)+len(m.Tags)+1)
	for _, r := range m.Branches {
		lines = append(lines, r.Name+" "+r.Object)
	}
	for _, r := range m.Tags {
		lines = append(lines, r.Name+" "+r.Object)
	}
	if len(m.Stash) > 0 {
		lines = append(lines, "refs/stash "+m.Stash[0].Object)
	}
	return digestLines(lines)
}

// ObservedRefsDigest is RefsDigest for a working copy as Inspect read it.
func ObservedRefsDigest(o movegit.Observed) string {
	lines := make([]string, 0, len(o.Refs))
	for name, obj := range o.Refs {
		if strings.HasPrefix(name, "refs/remotes/") || strings.HasPrefix(name, "refs/cloop/") {
			continue
		}
		lines = append(lines, name+" "+obj)
	}
	return digestLines(lines)
}

// FilesDigest is what the .cloop files a move delivers must come to: each
// one's path and content digest.
func FilesDigest(files []File) string {
	lines := make([]string, 0, len(files))
	for _, f := range files {
		lines = append(lines, f.Path+" "+f.SHA256)
	}
	return digestLines(lines)
}

func digestLines(lines []string) string {
	sort.Strings(lines)
	sum := sha256.Sum256([]byte(strings.Join(lines, "\n")))
	return hex.EncodeToString(sum[:])
}

func validDigest(s string) bool {
	if len(s) != 64 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil && strings.ToLower(s) == s
}

// DiscardWorkingCopy removes the working copy at dir that move opts.MoveID
// captured, when it still holds exactly that, and reports what it did. A
// directory that is already empty, or gone, is reported as such: cleanup run
// again finds nothing left to do. A copy it may not remove is reported kept,
// with the reason, and no error.
func DiscardWorkingCopy(ctx context.Context, dir string, opts DiscardOptions) (WorkingCopyReport, error) {
	r := WorkingCopyReport{MoveID: opts.MoveID}
	switch {
	case !movegit.ValidMoveID(opts.MoveID):
		return r, fmt.Errorf("projectmove: %q is not a move id", opts.MoveID)
	case !movegit.ValidObject(opts.Snapshot):
		return r, fmt.Errorf("projectmove: %q is not a snapshot commit", opts.Snapshot)
	case !validDigest(opts.Refs) || !validDigest(opts.Files):
		return r, errors.New("projectmove: a discard needs the digests of the refs and the files the move captured")
	}
	dir = filepath.Clean(dir)
	info, err := os.Lstat(dir)
	if errors.Is(err, os.ErrNotExist) {
		r.Empty = true
		return r, nil
	}
	if err != nil {
		return r, fmt.Errorf("projectmove: %w", err)
	}
	if !info.IsDir() {
		return r, fmt.Errorf("projectmove: %s is not a directory, so it is not a working copy to remove", dir)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return r, fmt.Errorf("projectmove: %w", err)
	}
	if len(entries) == 0 {
		r.Empty = true
		return r, nil
	}
	marker := []byte(opts.MoveID + " " + opts.Snapshot + "\n")
	if b, err := os.ReadFile(filepath.Join(dir, discardMarker)); err == nil && bytes.Equal(b, marker) {
		// This move's discard began here and was cut off: what it checked
		// then still holds, and what is left of the copy goes.
		return removeCopy(dir, entries, r)
	}

	kept := func(why string, problems ...string) (WorkingCopyReport, error) {
		r.Kept, r.Problems = why, problems
		return r, nil
	}
	snap, err := movegit.ReadSnapshot(ctx, dir, opts.MoveID, opts.Snapshot)
	if err != nil {
		return kept(KeptChanged, fmt.Sprintf("it holds no snapshot %s of move %s (%v)", opts.Snapshot, opts.MoveID, err))
	}
	o, err := movegit.Inspect(ctx, dir, movegit.InspectOptions{})
	if err != nil {
		return r, fmt.Errorf("projectmove: read %s before removing it: %w", dir, err)
	}
	ref := movegit.SnapshotRefPrefix + opts.MoveID
	if got := o.Refs[ref]; got != opts.Snapshot {
		return kept(KeptChanged, fmt.Sprintf("%s names %s rather than the snapshot the move recorded, %s", ref, orNothing(got), opts.Snapshot))
	}
	var changed []string
	if o.Head.Commit != snap.Base {
		changed = append(changed, fmt.Sprintf("HEAD is at %s, not %s", orNothing(o.Head.Commit), orNothing(snap.Base)))
	}
	if o.IndexTree != snap.IndexTree {
		changed = append(changed, "the index differs")
	}
	if o.WorktreeTree != snap.WorktreeTree {
		changed = append(changed, "the files git tracks or would track differ")
	}
	if ObservedRefsDigest(o) != opts.Refs {
		changed = append(changed, "its branches, tags, notes or stash differ from what the move captured")
	}
	if wts, err := os.ReadDir(filepath.Join(dir, ".git", "worktrees")); err == nil && len(wts) > 0 {
		changed = append(changed, fmt.Sprintf("it has %d linked worktree(s), whose changes a move does not check", len(wts)))
	}
	scratch, err := os.MkdirTemp("", "cloop-move-discard-*")
	if err != nil {
		return r, fmt.Errorf("projectmove: %w", err)
	}
	defer os.RemoveAll(scratch)
	files, _, _, err := PackFiles(dir, filepath.Join(scratch, CarrierFiles), 0)
	if err != nil {
		return r, fmt.Errorf("projectmove: read %s/.cloop before removing it: %w", dir, err)
	}
	if FilesDigest(files) != opts.Files {
		changed = append(changed, "the files under .cloop a move carries differ from the ones it delivered")
	}
	if len(changed) > 0 {
		return kept(KeptChanged, changed...)
	}
	if !opts.DiscardIgnored {
		ignored, more, err := movegit.IgnoredPaths(ctx, dir, nil, maxIgnoredListed)
		if err != nil {
			return r, fmt.Errorf("projectmove: %w", err)
		}
		if len(ignored) > 0 {
			r.Ignored = len(ignored)
			r.Examples = ignored[:min(len(ignored), maxExamples)]
			plus := ""
			if more {
				plus = " or more"
			}
			return kept(KeptIgnored, fmt.Sprintf("it holds %d%s file(s) or director(ies) git ignores, which no move carries", len(ignored), plus))
		}
	}

	if err := writeFileAtomic(filepath.Join(dir, discardMarker), marker); err != nil {
		return r, err
	}
	entries, err = os.ReadDir(dir)
	if err != nil {
		return r, fmt.Errorf("projectmove: %w", err)
	}
	return removeCopy(dir, entries, r)
}

// removeCopy removes every entry of dir — the repository second to last and
// the discard's marker last, so a discard cut off part-way leaves its marker
// to be found — and reports the copy removed.
func removeCopy(dir string, entries []os.DirEntry, r WorkingCopyReport) (WorkingCopyReport, error) {
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	rank := func(n string) int {
		switch n {
		case discardMarker:
			return 2
		case ".git":
			return 1
		}
		return 0
	}
	sort.Slice(names, func(i, j int) bool {
		if a, b := rank(names[i]), rank(names[j]); a != b {
			return a < b
		}
		return names[i] < names[j]
	})
	for _, name := range names {
		// One path element each, read from the directory itself: RemoveAll
		// removes a symbolic link, never what it points at.
		if err := os.RemoveAll(filepath.Join(dir, name)); err != nil {
			return r, fmt.Errorf("projectmove: remove %s from %s: %w", name, dir, err)
		}
	}
	r.Empty = true
	r.Entries = 0
	for _, n := range names {
		if n != discardMarker {
			r.Entries++
		}
	}
	shown := make([]string, 0, maxExamples)
	for _, n := range names {
		if n != discardMarker && len(shown) < maxExamples {
			shown = append(shown, n)
		}
	}
	r.Examples = shown
	return r, nil
}

func orNothing(s string) string {
	if s == "" {
		return "nothing"
	}
	return s
}
