package redact

// live.go keeps a workload's own redaction current while the hub rewrites its
// lease directory (Task 20375).
//
// FromEnviron reads the lease directory once. That was enough while a lease's
// files never changed after dispatch; since the hub re-mints a GitHub App
// installation token before GitHub's hour ends and rewrites the token file in
// place, a run that printed its token after the refresh would print one the
// startup read never saw. Live re-reads the directory when a file in it
// changed, and keeps every value it has ever seen: a token printed before the
// refresh must stay scrubbed after it.

import (
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// liveCheckInterval bounds how often Current looks at the lease directory. A
// refresh happens once an hour per token; a second's delay before its value is
// scrubbed is the window this buys an output path that asks per token.
const liveCheckInterval = time.Second

// Live is a Set over a process's lease that follows rewrites of its files.
// The zero value is not usable; call NewLive. Safe for concurrent use.
type Live struct {
	dir string
	now func() time.Time

	mu        sync.Mutex
	set       *Set
	stamp     string
	nextCheck time.Time
}

// NewLive returns a Live seeded from environ exactly as FromEnviron would be.
func NewLive(environ []string) *Live {
	l := &Live{now: time.Now}
	for _, kv := range environ {
		if strings.HasPrefix(kv, LeaseDirKey+"=") {
			l.dir = strings.TrimPrefix(kv, LeaseDirKey+"=")
		}
	}
	l.set = FromEnviron(environ)
	l.stamp = dirStamp(l.dir)
	return l
}

// Active reports whether the process holds anything to scrub. A process with
// no lease — the control plane, a workload with no grants — gets false, and a
// caller can skip redaction entirely.
func (l *Live) Active() bool {
	if l == nil {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.set.Len() > 0
}

// Current returns the Set to scrub with now: everything the environment and the
// lease directory held at the start, plus every value the directory has held
// since. Nil when there is nothing to scrub.
func (l *Live) Current() *Set {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if l.dir == "" || now.Before(l.nextCheck) {
		return l.set
	}
	l.nextCheck = now.Add(liveCheckInterval)
	if stamp := dirStamp(l.dir); stamp != l.stamp {
		l.stamp = stamp
		l.set = l.set.With(leaseDirValues(l.dir)...)
	}
	return l.set
}

// dirStamp summarises the regular files in dir — name, size, modification time
// — so a rewrite of any of them changes it. Unreadable is "", which a later
// readable directory differs from.
func dirStamp(dir string) string {
	if strings.TrimSpace(dir) == "" {
		return ""
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	parts := make([]string, 0, len(entries))
	for _, ent := range entries {
		if ent.IsDir() {
			continue
		}
		info, err := ent.Info()
		if err != nil {
			continue
		}
		parts = append(parts, filepath.Base(ent.Name())+":"+strconv.FormatInt(info.Size(), 10)+":"+
			strconv.FormatInt(info.ModTime().UnixNano(), 10))
	}
	sort.Strings(parts)
	return strings.Join(parts, "|")
}
