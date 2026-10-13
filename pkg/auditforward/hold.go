package auditforward

// hold.go: what audit forwarding asks of retention.
//
// A sink's cursor is the newest row it has acknowledged, and a prune that
// passed it would remove rows the sink can now never receive — they would
// survive only in the prune's sealed archive. auditretention.Prune clamps its
// cutoff to the slowest live cursor on the chain it prunes; this file finds
// that cursor for it.
//
// The cursors live in the control plane's database. Pruning the control plane
// — or the hub's own project, the same file — finds them in the database being
// pruned. Pruning a project's database from the project's directory needs to
// know which control plane forwards it, and the forwarder says: it records the
// control plane's path in each project chain it forwards (markerKey). That
// record is advisory, as everything in a project's database is: whoever can
// rewrite it can also delete the rows a prune would have removed, which the
// forwarder reports as a discontinuity either way.
//
// A cursor names its chain by the path the hub reached it by, and a shell may
// reach the same file by another — a symlinked home, an automount — so a
// cursor is matched to the database being pruned by file identity, not by
// spelling.

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/blechschmidt/cloop/pkg/statedb"
)

// markerKey is the hub-meta key under which a forwarded project chain names
// the control plane holding its cursors.
const markerKey = "audit.forward.control_plane"

// markChain records which control plane forwards a project chain — once per
// process per database file, so a file restored or replaced under the hub is
// marked again.
func (f *Forwarder) markChain(db *statedb.DB, ch Chain) {
	if ch.Path == f.opts.ControlPlane {
		return
	}
	fi, err := os.Stat(ch.Path)
	if err != nil {
		return
	}
	if prev, done := f.marked.Load(ch.Path); done && os.SameFile(prev.(os.FileInfo), fi) {
		return
	}
	if v, ok, err := db.HubMeta(markerKey); err == nil && ok && v == f.opts.ControlPlane {
		f.marked.Store(ch.Path, fi)
		return
	}
	if err := db.SetHubMeta(markerKey, f.opts.ControlPlane); err != nil {
		f.logf("could not record in %s which control plane forwards it: %v", ch.Path, err)
		return
	}
	f.marked.Store(ch.Path, fi)
}

// ErrHoldUnreadable is returned when a control plane that may hold cursors on
// the chain could not be read: a prune must not guess that nothing holds it.
var ErrHoldUnreadable = errors.New("auditforward: the audit forwarding cursors could not be read")

// RetentionHold reports the hold live audit sinks put on the chain held by db
// at dbPath: the newest row every one of them has acknowledged. held is false
// when no live cursor names the chain.
//
// The cursors are looked for in db itself, in the control plane the chain's
// forwarded-by record names, and in controlPlane when it is set — a database
// the caller names that does not exist is an error, not "nothing holds it". A
// control plane other than db is opened read-only. consulted lists the
// databases read.
func RetentionHold(db *statedb.DB, dbPath, controlPlane string) (hold statedb.AuditForwardHold, held bool, consulted []string, err error) {
	path := absPath(dbPath)
	self, err := os.Stat(path)
	if err != nil {
		return statedb.AuditForwardHold{}, false, nil, fmt.Errorf("%w: %v", ErrHoldUnreadable, err)
	}

	var others []string
	if controlPlane != "" {
		cp := absPath(controlPlane)
		if _, err := os.Stat(cp); err != nil {
			return statedb.AuditForwardHold{}, false, nil,
				fmt.Errorf("%w: the control plane named, %s, cannot be read: %v", ErrHoldUnreadable, cp, err)
		}
		others = append(others, cp)
	}
	if v, ok, merr := db.HubMeta(markerKey); merr == nil && ok && v != "" {
		// A record naming a control plane that is gone holds nothing: that
		// hub forwards nothing any more.
		if _, err := os.Stat(v); err == nil {
			others = append(others, absPath(v))
		}
	}

	// db's own cursors: it may be the control plane.
	cursors, err := db.AuditForwardCursors()
	if err != nil {
		return statedb.AuditForwardHold{}, false, nil, fmt.Errorf("%w: %v", ErrHoldUnreadable, err)
	}
	consulted = append(consulted, path)
	seen := map[string]bool{path: true}
	for _, cp := range others {
		if seen[cp] || sameFile(cp, self) {
			continue
		}
		seen[cp] = true
		more, err := readCursors(cp)
		if err != nil {
			return statedb.AuditForwardHold{}, false, consulted, fmt.Errorf("%w: %s: %v", ErrHoldUnreadable, cp, err)
		}
		consulted = append(consulted, cp)
		cursors = append(cursors, more...)
	}

	for _, c := range cursors {
		if c.Retired() || (c.Chain != path && !sameFile(c.Chain, self)) {
			continue
		}
		if hold.Sinks == nil {
			hold.Sinks = map[string]int64{}
		}
		if at, ok := hold.Sinks[c.Sink]; !ok || c.AckedID < at {
			hold.Sinks[c.Sink] = c.AckedID
		}
		if !held || c.AckedID < hold.ThroughID || (c.AckedID == hold.ThroughID && c.Sink < hold.Sink) {
			hold.ThroughID, hold.Sink, held = c.AckedID, c.Sink, true
		}
	}
	return hold, held, consulted, nil
}

// readCursors reads every cursor of the control plane at path, read-only: a
// prune run beside a hub must neither migrate nor create its database.
func readCursors(path string) ([]statedb.AuditForwardCursor, error) {
	conn, err := statedb.OpenConn(path, statedb.ReadOnly)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	return statedb.ReadAuditForwardCursors(conn)
}

// sameFile reports whether path names the file fi describes.
func sameFile(path string, fi os.FileInfo) bool {
	other, err := os.Stat(path)
	return err == nil && os.SameFile(other, fi)
}

func absPath(p string) string {
	if abs, err := filepath.Abs(p); err == nil {
		return abs
	}
	return p
}
