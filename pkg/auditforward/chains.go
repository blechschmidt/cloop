package auditforward

// chains.go: the read handles the sink workers share, and the cheap check
// that lets a caught-up sink skip a chain nothing has written to.

import (
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/blechschmidt/cloop/pkg/statedb"
)

// handleIdle is how long a chain's handle stays open with nobody using it. A
// hub with a hundred quiet projects should not hold three hundred file
// descriptors for them, and one that is busy should not reopen a database —
// which re-checks its schema — every two seconds.
const handleIdle = 5 * time.Minute

// handleCache keeps one handle per chain database, shared by every sink's
// worker: statedb.DB is safe for concurrent use.
type handleCache struct {
	mu   sync.Mutex
	open map[string]*cachedHandle
}

type cachedHandle struct {
	db   *statedb.DB
	refs int
	used time.Time
	// file is the database file the handle opened, so a file replaced under
	// it — a project database restored while the hub runs — is noticed and
	// reopened rather than read from the old inode for as long as it is busy.
	file os.FileInfo
	// stale marks a handle replaced in the map, closed once its last user
	// gives it back.
	stale bool
}

func newHandleCache() *handleCache {
	return &handleCache{open: map[string]*cachedHandle{}}
}

// get returns the handle for path, and the function that gives it back. A
// database that does not exist is an error, never created: a project that has
// never run has no chain to forward.
func (c *handleCache) get(path string) (*statedb.DB, func(), error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	fi, err := os.Stat(path)
	if err != nil {
		return nil, nil, fmt.Errorf("chain database %s: %w", path, err)
	}
	h, ok := c.open[path]
	if ok && !os.SameFile(fi, h.file) {
		h.stale = true
		if h.refs == 0 {
			_ = h.db.Close()
		}
		delete(c.open, path)
		ok = false
	}
	if !ok {
		db, err := statedb.Open(path)
		if err != nil {
			return nil, nil, fmt.Errorf("open chain database %s: %w", path, err)
		}
		h = &cachedHandle{db: db, file: fi}
		c.open[path] = h
	}
	h.refs++
	h.used = time.Now()
	released := false
	return h.db, func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		if released {
			return
		}
		released = true
		h.refs--
		h.used = time.Now()
		if h.stale && h.refs == 0 {
			_ = h.db.Close()
		}
	}, nil
}

// sweep closes the handles nobody has used for handleIdle.
func (c *handleCache) sweep(now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for path, h := range c.open {
		if h.refs == 0 && now.Sub(h.used) > handleIdle {
			_ = h.db.Close()
			delete(c.open, path)
		}
	}
}

// closeAll closes every handle. Workers must have stopped.
func (c *handleCache) closeAll() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for path, h := range c.open {
		_ = h.db.Close()
		delete(c.open, path)
	}
}

// fileMark is what a stat says about a file.
type fileMark struct {
	size int64
	mod  time.Time
}

// chainMark is what a stat says about a chain's database: the file and its
// write-ahead log, where every commit lands until a checkpoint copies it back
// — a database that has been written to has a different mark.
type chainMark struct {
	db, wal fileMark
}

// markOf stats a chain's database, reporting false when it does not exist.
func markOf(path string) (chainMark, bool) {
	fi, err := os.Stat(path)
	if err != nil {
		return chainMark{}, false
	}
	m := chainMark{db: fileMark{size: fi.Size(), mod: fi.ModTime()}}
	if wi, err := os.Stat(statedb.WALPath(path)); err == nil {
		m.wal = fileMark{size: wi.Size(), mod: wi.ModTime()}
	}
	return m, true
}
