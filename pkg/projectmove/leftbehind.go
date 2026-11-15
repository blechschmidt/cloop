package projectmove

// leftbehind.go is the copy of a project the hub's own directory for it still
// holds after a move took the project onto a device (Task 20497). A verified
// move keeps its source, and the hub's directory is never removed — it holds
// the project's state and its features' worktrees — so a project that goes
// to a device and comes back finds its old copy where the move back wants to
// build the working copy. That copy is recognised by the capture of the move
// that left it: a directory still exactly as that capture recorded it holds
// nothing anyone made since, and the move back restores the device's working
// copy into its repository (movegit.RestoreInto) rather than refusing it.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/blechschmidt/cloop/pkg/executor/movegit"
)

// LeftBehindCopy is the copy of a project the hub's directory for it holds
// from before an earlier move took the project off the hub.
type LeftBehindCopy struct {
	// MoveID is the move that captured the copy and took the project away;
	// Target where it took it.
	MoveID string `json:"move_id"`
	Target string `json:"target"`
	// Problems say how the directory differs from what that move captured:
	// its HEAD, its index, its files. None means it is the copy the move
	// left, untouched.
	Problems []string `json:"problems,omitempty"`
}

// LeftBehindBy finds, among a project's moves listed newest first, the move
// whose capture the hub's directory for it still holds: the latest finished
// move that captured the hub's own tree with a repository in it, unless a
// later one built or kept the project's working copy in that directory.
func LeftBehindBy(moves []Move) (Move, bool) {
	for _, m := range moves {
		c := m.Detail.Capture
		if m.Phase != PhaseDone || c == nil {
			continue
		}
		if c.Delivery == DeliverHubTree || c.Delivery == DeliverSameTree {
			return Move{}, false
		}
		if c.From == "hub" && c.Git.Repository && c.Git.Snapshot != nil {
			return m, true
		}
	}
	return Move{}, false
}

// SeedLeftBehind is SeedHubTree for a hub directory that still holds the copy
// the move base captured when it took the project away: the capture is
// restored into that copy's repository (movegit.RestoreInto), so the worktrees
// of the project's features stay registered in it, and a branch the hub moved
// on while the project was away — a feature's written-back work — keeps the
// hub's commits. The .cloop files are delivered as SeedHubTree delivers them.
//
// It may be run again for the same move after the hub stopped part-way; it
// returns the refs the hub kept, which verification expects in place of the
// capture's.
func SeedLeftBehind(ctx context.Context, dir, moveID string, c *CaptureRecord, base Move) ([]movegit.Ref, error) {
	if c == nil {
		return nil, errors.New("projectmove: no capture to seed the hub's directory with")
	}
	bc := base.Detail.Capture
	if bc == nil || !bc.Git.Repository {
		return nil, fmt.Errorf("projectmove: move %s recorded no repository the hub's directory could still hold", base.ID)
	}
	if !c.Git.Repository {
		return nil, fmt.Errorf("projectmove: %s holds the repository move %s left there, and the capture holds none to put in its place",
			dir, base.ID)
	}
	resuming := false
	if rec, ok := readMovedIn(dir); ok && rec.MoveID == moveID {
		resuming = true
	}
	if seeding, _ := readMovingIn(dir); seeding == moveID {
		resuming = true
	}
	if !resuming {
		// Checked before the marker goes down: a seed that stopped before
		// the check finished must check again, not take itself for one that
		// began restoring.
		problems, err := movegit.LeftBehindProblems(ctx, dir, bc.Git, movegit.InspectOptions{})
		if err != nil {
			return nil, err
		}
		if len(problems) > 0 {
			return nil, fmt.Errorf("%w: %s holds the copy move %s left there, changed since (%s)",
				movegit.ErrLeftBehindChanged, dir, base.ID, strings.Join(problems, "; "))
		}
	}
	cloopDir := filepath.Join(dir, ".cloop")
	if err := ensureDir(cloopDir); err != nil {
		return nil, err
	}
	if err := writeFileAtomic(filepath.Join(cloopDir, MovingInFile), []byte(moveID)); err != nil {
		return nil, err
	}
	kept, err := movegit.RestoreInto(ctx, movegit.RestoreOptions{Dir: dir, BundlePath: filepath.Join(c.Store, c.Bundle),
		Manifest: c.Git, Reserve: &HubTreeReserved}, bc.Git, true)
	if err != nil {
		return nil, err
	}
	if err := excludeCloop(dir); err != nil {
		return nil, err
	}
	if c.FilesTar != "" {
		tarPath := filepath.Join(c.Store, c.FilesTar)
		if c.TarSum != nil {
			if err := movegit.VerifyFile(tarPath, *c.TarSum); err != nil {
				return nil, err
			}
		}
		if err := ExtractFiles(tarPath, cloopDir, c.Files); err != nil {
			return nil, err
		}
	}
	rec, err := json.Marshal(movedIn{MoveID: moveID, Files: c.Files})
	if err != nil {
		return nil, fmt.Errorf("projectmove: %w", err)
	}
	if err := writeFileAtomic(filepath.Join(cloopDir, MovedInFile), rec); err != nil {
		return nil, err
	}
	if err := os.Remove(filepath.Join(cloopDir, MovingInFile)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("projectmove: %w", err)
	}
	return kept, nil
}

// SeedMarker names the move whose seed last wrote dir, a project's directory
// on the hub: one that began and did not finish (MovingInFile), or else the
// one that finished (MovedInFile); "" when no seed wrote it.
func SeedMarker(dir string) string {
	if id, ok := readMovingIn(dir); ok && id != "" {
		return id
	}
	if rec, ok := readMovedIn(dir); ok {
		return rec.MoveID
	}
	return ""
}
