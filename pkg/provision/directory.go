package provision

// The provisioned directory as the authorization path reads it.
//
// authz.Resolver asks it, at every decision, which provisioned groups the
// subject belongs to (authz.DirectorySource). That is what makes a removal at
// the identity provider demote the user on their next request rather than at
// the next claim refresh: the groups are never read off a token or a session,
// so there is nothing cached about the person for the removal to wait behind.
//
// What is cached is the directory itself, for one reason: a SQL read per
// decision is not affordable on a hub's hot path. The cache is exact on the
// member that applied a change — the change invalidates it before the request
// that made it returns — and on the others within one bus notice, or at worst
// one version check (DefaultCheckEvery), a one-row read of a counter every
// directory write bumps in its own transaction.
//
// A group grants nothing to an account the directory cannot vouch for: an
// inactive one, and one whose match value two provisioned users share. The
// write path refuses to create the second (scim 409 uniqueness); one can still
// arise when ui.oidc.scim.match_claim is changed under a populated directory,
// and then neither user's groups count until the provider repairs it.

import (
	"strings"
	"sync"
	"time"

	"github.com/blechschmidt/cloop/pkg/authz"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// DefaultCheckEvery is how often a cache asks the database whether the
// directory changed, when nothing told it so.
const DefaultCheckEvery = 2 * time.Second

// Directory is a cached, indexed copy of the provisioned directory.
type Directory struct {
	db    *statedb.DB
	claim MatchClaim
	every time.Duration
	now   func() time.Time
	onErr func(error)

	mu      sync.Mutex
	loaded  bool
	version int64
	checked time.Time
	byValue map[string][]*dirEntry
	stats   DirectoryStats
}

type dirEntry struct {
	id     string
	active bool
	// groups are the display names and external ids of the user's groups:
	// what a scim_group binding may name.
	groups []string
}

// DirectoryStats summarise the directory, for Settings and the doctor.
type DirectoryStats struct {
	Version     int64 `json:"version"`
	Users       int   `json:"users"`
	Active      int   `json:"active"`
	Inactive    int   `json:"inactive"`
	Groups      int   `json:"groups"`
	Memberships int   `json:"memberships"`
	// Unmatchable users carry no value for the match claim, and so are no
	// hub identity at all; Ambiguous users share their value with another.
	Unmatchable int `json:"unmatchable"`
	Ambiguous   int `json:"ambiguous"`
}

// DirectoryOption configures a Directory.
type DirectoryOption func(*Directory)

// WithCheckEvery sets how often the version is checked.
func WithCheckEvery(d time.Duration) DirectoryOption {
	return func(dir *Directory) {
		if d > 0 {
			dir.every = d
		}
	}
}

// WithDirectoryClock replaces the clock, for tests.
func WithDirectoryClock(now func() time.Time) DirectoryOption {
	return func(dir *Directory) {
		if now != nil {
			dir.now = now
		}
	}
}

// WithDirectoryErrors installs a sink for failed refreshes: the cache keeps
// serving its last good copy, and the hub logs why.
func WithDirectoryErrors(fn func(error)) DirectoryOption {
	return func(dir *Directory) { dir.onErr = fn }
}

// NewDirectory reads the directory once, eagerly: a hub that cannot read it
// at startup must not come up granting groups from nothing.
func NewDirectory(db *statedb.DB, claim MatchClaim, opts ...DirectoryOption) (*Directory, error) {
	d := &Directory{db: db, claim: claim, every: DefaultCheckEvery, now: time.Now}
	for _, o := range opts {
		o(d)
	}
	if err := d.load(); err != nil {
		return nil, err
	}
	return d, nil
}

// Claim reports the match claim the directory indexes by.
func (d *Directory) Claim() MatchClaim { return d.claim }

// Invalidate makes the next read check the version, and reload on a change.
func (d *Directory) Invalidate() {
	d.mu.Lock()
	d.checked = time.Time{}
	d.mu.Unlock()
}

// DirectoryGroups implements authz.DirectorySource.
func (d *Directory) DirectoryGroups(s *authz.Subject) []string {
	v := SubjectValue(d.claim, s)
	if v == "" {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.refreshLocked()
	es := d.byValue[v]
	if len(es) != 1 || !es[0].active {
		return nil
	}
	return es[0].groups
}

// UserFor reports the provisioned user a subject matches, and whether the
// match is unique and active.
func (d *Directory) UserFor(s *authz.Subject) (id string, active, unique bool) {
	v := SubjectValue(d.claim, s)
	if v == "" {
		return "", false, false
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.refreshLocked()
	es := d.byValue[v]
	if len(es) != 1 {
		return "", false, false
	}
	return es[0].id, es[0].active, true
}

// Stats reports the directory's summary.
func (d *Directory) Stats() DirectoryStats {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.refreshLocked()
	return d.stats
}

func (d *Directory) refreshLocked() {
	now := d.now()
	if d.loaded && now.Sub(d.checked) < d.every {
		return
	}
	// Stamped before the read, as rolestore does: on a wedged database every
	// decision would otherwise queue behind the same failing query.
	d.checked = now
	v, err := d.db.SCIMDirectoryVersion()
	if err != nil {
		if d.onErr != nil {
			d.onErr(err)
		}
		return
	}
	if d.loaded && v == d.version {
		return
	}
	if err := d.loadLocked(); err != nil && d.onErr != nil {
		d.onErr(err)
	}
}

func (d *Directory) load() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.checked = d.now()
	return d.loadLocked()
}

func (d *Directory) loadLocked() error {
	dir, err := d.db.LoadSCIMDirectory()
	if err != nil {
		return err
	}
	byValue := make(map[string][]*dirEntry, len(dir.Users))
	stats := DirectoryStats{Version: dir.Version, Users: len(dir.Users), Groups: len(dir.Groups)}
	for _, u := range dir.Users {
		row := statedb.SCIMUserRow{UserName: u.UserName, ExternalID: u.ExternalID, Email: u.Email}
		v := UserValue(d.claim, row)
		if u.Active {
			stats.Active++
		} else {
			stats.Inactive++
		}
		stats.Memberships += len(u.GroupIDs)
		if v == "" {
			stats.Unmatchable++
			continue
		}
		e := &dirEntry{id: u.ID, active: u.Active}
		seen := map[string]bool{}
		for _, gid := range u.GroupIDs {
			g, ok := dir.Groups[gid]
			if !ok {
				continue
			}
			for _, name := range []string{g.DisplayName, g.ExternalID} {
				name = strings.TrimSpace(name)
				if name == "" || seen[strings.ToLower(name)] {
					continue
				}
				seen[strings.ToLower(name)] = true
				e.groups = append(e.groups, name)
			}
		}
		byValue[v] = append(byValue[v], e)
	}
	for _, es := range byValue {
		if len(es) > 1 {
			stats.Ambiguous += len(es)
		}
	}
	d.byValue, d.stats, d.version, d.loaded = byValue, stats, dir.Version, true
	return nil
}

var _ authz.DirectorySource = (*Directory)(nil)
