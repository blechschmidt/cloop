package agent

// branch.go receives a branch the control plane ships ahead of a start frame
// (protocol v16, Task 20367) — the device's half of how a feature reaches a
// remote sandbox. The hub's half is pkg/executor/remote/branch.go, and the tree
// is built from the result by pkg/executor/gitprovision.
//
// # Shape of a transfer
//
// The hub writes every branch_chunk for a handle before that handle's start
// frame, on the same connection. Chunks are handled inline on the frame loop,
// in order, and the start frame is dispatched to its own goroutine only after
// it has been read — so by the time handleStart asks for the bundle, every
// chunk the hub sent for it has been written to disk. A start that finds the
// transfer missing, short or failed refuses rather than provisioning from
// whatever arrived: a feature built from part of its branch is a run on code
// nobody wrote.
//
// # Bounds
//
// Everything here is written to this device's disk on the say-so of frames
// from the network, so it is bounded three ways: each transfer by its declared
// total and by executor.MaxBranchBundleBytes, the number in flight by
// maxBranchTransfers, and the lifetime of one that is never claimed by
// branchTransferTTL. A transfer is a file under the agent's root, 0600, removed
// when the start claims it and provisioning finishes, when the workload is
// forgotten, or when it goes stale.

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor/remote"
)

const (
	// branchIncomingDir is where transfers are written, under the agent's
	// root. Dot-named so it can never be mistaken for a workload directory.
	branchIncomingDir = ".cloop-branch-incoming"
	// maxBranchTransfers bounds how many transfers may be in flight at once.
	// A start claims its transfer immediately, so the real number is one or
	// two; this keeps a misbehaving control plane from filling the disk with
	// transfers no start will ever claim.
	maxBranchTransfers = 8
	// branchTransferTTL is how long an unclaimed transfer is kept. The start
	// frame follows its chunks on the same connection, so anything older than
	// this is a transfer whose start was lost with its session.
	branchTransferTTL = 15 * time.Minute
)

// branchTransfer is one bundle being received.
type branchTransfer struct {
	path    string
	f       *os.File
	total   int64
	written int64
	started time.Time
	// err is the first thing that went wrong; once set, further chunks are
	// discarded and the start that claims the transfer refuses with it.
	err error
}

// receiveBranchChunk writes one chunk of a shipped branch to its transfer.
//
// It never replies: a chunk has no correlation id to answer, and the start
// frame that follows is where a failed transfer is reported, naming what went
// wrong.
func (a *Agent) receiveBranchChunk(frame remote.Frame) {
	p, err := remote.DecodeBranchChunk(frame)
	handleID := frame.Handle
	if err != nil {
		a.cfg.logf("refusing a branch chunk for %s: %v", handleID, err)
		a.failBranchTransfer(handleID, err)
		return
	}

	a.branchMu.Lock()
	defer a.branchMu.Unlock()
	a.sweepBranchTransfersLocked()

	t := a.branches[handleID]
	if p.Offset == 0 {
		// The first chunk opens the transfer. One already open for the handle
		// is replaced — a fresh start of the same bundle — rather than appended
		// to, which would splice two transfers into one file.
		if t != nil {
			t.discard()
			delete(a.branches, handleID)
		}
		if len(a.branches) >= maxBranchTransfers {
			a.cfg.logf("refusing a branch for %s: %d transfers are already in flight", handleID, len(a.branches))
			a.branches[handleID] = &branchTransfer{started: a.cfg.now(), total: p.Total,
				err: fmt.Errorf("the device already has %d branch transfers in flight", len(a.branches))}
			return
		}
		t, err = a.openBranchTransfer(p.Total)
		if err != nil {
			a.cfg.logf("cannot receive the branch for %s: %v", handleID, err)
			a.branches[handleID] = &branchTransfer{started: a.cfg.now(), total: p.Total, err: err}
			return
		}
		a.branches[handleID] = t
	}
	if t == nil {
		a.cfg.logf("discarding a branch chunk for %s at offset %d: no transfer was started", handleID, p.Offset)
		return
	}
	if t.err != nil {
		return
	}
	switch {
	case p.Total != t.total:
		t.fail(fmt.Errorf("the chunk at offset %d says the bundle is %d bytes, the transfer said %d",
			p.Offset, p.Total, t.total))
		return
	case p.Offset != t.written:
		t.fail(fmt.Errorf("a chunk arrived at offset %d where %d was expected", p.Offset, t.written))
		return
	}
	if _, err := t.f.Write(p.Data); err != nil {
		t.fail(fmt.Errorf("writing the bundle to this device's disk: %w", err))
		return
	}
	t.written += int64(len(p.Data))
}

// openBranchTransfer creates the file a transfer is written to.
func (a *Agent) openBranchTransfer(total int64) (*branchTransfer, error) {
	dir := filepath.Join(a.root, branchIncomingDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("cannot create %s: %w", dir, err)
	}
	f, err := os.CreateTemp(dir, "branch-*.bundle")
	if err != nil {
		return nil, fmt.Errorf("cannot create a file in %s: %w", dir, err)
	}
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		_ = os.Remove(f.Name())
		return nil, err
	}
	return &branchTransfer{path: f.Name(), f: f, total: total, started: a.cfg.now()}, nil
}

// takeBranchBundle claims the transfer for handleID once its start frame has
// arrived, returning the path of the complete bundle. The caller owns the file
// from here and removes it once provisioning is done.
func (a *Agent) takeBranchBundle(handleID string) (string, error) {
	a.branchMu.Lock()
	t := a.branches[handleID]
	delete(a.branches, handleID)
	a.branchMu.Unlock()
	if t == nil {
		return "", errors.New("the control plane's copy of the feature's branch did not arrive before " +
			"its start; the connection may have dropped mid-transfer — start the run again")
	}
	if t.err != nil {
		t.discard()
		return "", fmt.Errorf("the feature's branch did not arrive intact: %w", t.err)
	}
	if err := t.f.Close(); err != nil {
		_ = os.Remove(t.path)
		return "", fmt.Errorf("the feature's branch could not be written to this device's disk: %w", err)
	}
	t.f = nil
	if t.written != t.total {
		_ = os.Remove(t.path)
		return "", fmt.Errorf("only %d of the feature's %d-byte branch arrived before its start", t.written, t.total)
	}
	return t.path, nil
}

// dropBranchTransfer discards whatever is held for handleID.
func (a *Agent) dropBranchTransfer(handleID string) {
	a.branchMu.Lock()
	t := a.branches[handleID]
	delete(a.branches, handleID)
	a.branchMu.Unlock()
	if t != nil {
		t.discard()
	}
}

// failBranchTransfer marks the transfer for handleID failed, if there is one.
func (a *Agent) failBranchTransfer(handleID string, err error) {
	a.branchMu.Lock()
	defer a.branchMu.Unlock()
	if t := a.branches[handleID]; t != nil {
		t.fail(err)
	}
}

// sweepBranchTransfersLocked removes transfers nobody claimed in time.
func (a *Agent) sweepBranchTransfersLocked() {
	now := a.cfg.now()
	for id, t := range a.branches {
		if now.Sub(t.started) > branchTransferTTL {
			a.cfg.logf("discarding the unclaimed branch transfer for %s", id)
			t.discard()
			delete(a.branches, id)
		}
	}
}

// clearBranchIncoming removes transfers a previous run of the agent left
// behind. Nothing can claim them: the handles they were for belonged to a
// session that no longer exists.
func (a *Agent) clearBranchIncoming() {
	dir := filepath.Join(a.root, branchIncomingDir)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		_ = os.Remove(filepath.Join(dir, e.Name()))
	}
}

func (t *branchTransfer) fail(err error) {
	if t.err == nil {
		t.err = err
	}
	if t.f != nil {
		_ = t.f.Close()
		t.f = nil
	}
	if t.path != "" {
		_ = os.Remove(t.path)
	}
}

func (t *branchTransfer) discard() {
	if t.f != nil {
		_ = t.f.Close()
		t.f = nil
	}
	if t.path != "" {
		_ = os.Remove(t.path)
	}
}
