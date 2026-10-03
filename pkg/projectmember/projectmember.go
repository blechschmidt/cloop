// Package projectmember is the durable per-project member list: who besides a
// project's owner may reach it, and at what role (Task 20366).
//
// It is the split pkg/rolestore and pkg/sessionstore already use: pkg/authz
// owns the role model and stays stdlib-only, pkg/statedb owns the table, and
// this package owns normalisation and the cache that makes reading the list on
// every authorization decision affordable.
//
// # What a membership is
//
// An additive grant scoped to one project: "this identity is also admitted to
// this path, at this role". The hub unions it with whatever the identity
// already holds (authz.Union), so sharing a project can never demote anybody.
// It is also never more than the granter's own authority on that project —
// the REST layer enforces that cap, because this package does not know who is
// asking.
//
// # Freshness
//
// Reads are served from an in-memory snapshot refreshed every TTL, so a write
// another process made (the CLI, another hub member) lands within one TTL.
// Writes through a Store land at once: the Store reloads — or, should the
// database refuse the read, patches its snapshot with the change it just
// committed — before returning, so "I removed them" holds on the very next
// request. Invalidate makes the next read reload; pkg/ui calls it when another
// hub member announces a change on the cluster bus. Every reload that finds
// the list changed is reported to the OnChange callback, which is how a hub
// closes the live streams of somebody who just lost access.
//
// # Failure policy
//
// A refresh that fails keeps serving the last good snapshot. The table only
// grants, so an empty answer would be the "safe" direction, but it would also
// revoke every collaborator for as long as a storage blip lasted. The first
// load happens in New and its failure is fatal to hub startup, so the degraded
// case is bounded by a snapshot that was known-good once. A row whose role
// this build cannot parse is skipped and reported, never fatal: one unreadable
// row must not un-share every project on the hub.
package projectmember

import (
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"

	"github.com/blechschmidt/cloop/pkg/authz"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// DefaultTTL bounds how long a membership written by another process takes to
// reach this one's authorization decisions.
const DefaultTTL = 10 * time.Second

// MaxKeyLen bounds an identity key. RFC 5321 caps an address at 254 octets;
// the rest is room for a "sub:" prefix on a long opaque subject.
const MaxKeyLen = 320

// MaxReasonLen bounds the free-text reason stored with a membership.
const MaxReasonLen = 500

// Member is one membership as the rest of the hub sees it.
type Member struct {
	// ProjectPath is the project's normalised absolute path.
	ProjectPath string `json:"project_path"`
	// IdentityKey is the grantee in oidcauth.Identity.OwnerKey's namespace.
	IdentityKey string `json:"identity"`
	// Role is what the grantee may do on the project.
	Role authz.Role `json:"role"`
	// Reason is why they were admitted; may be empty.
	Reason string `json:"reason,omitempty"`
	// GrantedAt and GrantedBy record the most recent write.
	GrantedAt time.Time `json:"granted_at"`
	GrantedBy string    `json:"granted_by,omitempty"`
}

// Change is what a reload found different from the snapshot before it.
type Change struct {
	// Projects are the paths whose roster changed.
	Projects []string
	// Identities are the keys whose memberships changed.
	Identities []string
}

// Empty reports whether nothing changed.
func (c Change) Empty() bool { return len(c.Projects) == 0 && len(c.Identities) == 0 }

// Audit builds the audit events committed together with a change; prev and
// next are nil when there was no membership before or after. See
// statedb.MemberAudit.
type Audit func(prev, next *Member) ([]*statedb.AuditEvent, error)

// Store reads memberships through a TTL cache.
type Store struct {
	db       *statedb.DB
	ttl      time.Duration
	now      func() time.Time
	onError  func(error)
	onChange func(Change)

	// refreshMu serialises loads and the snapshot swaps that follow a write,
	// so a load that read the table before a write committed can never swap
	// in after that write's own update and resurrect what it removed.
	refreshMu sync.Mutex
	snap      atomic.Pointer[snapshot]
	stale     atomic.Bool

	// afterWriteHook, when set, runs before the reload that follows a write
	// and fails it by returning an error. Tests only: it is how they reach
	// the patch path without a database that commits and then refuses reads.
	afterWriteHook func() error
}

type snapshot struct {
	at      time.Time
	members []Member // ordered by path, then identity
	byPair  map[pair]int
}

type pair struct{ path, key string }

// Option configures a Store.
type Option func(*Store)

// WithTTL overrides the refresh interval. A non-positive value is ignored: a
// zero TTL would put a query on every permission check of every request.
func WithTTL(d time.Duration) Option {
	return func(s *Store) {
		if d > 0 {
			s.ttl = d
		}
	}
}

// WithErrorHandler installs a sink for failed refreshes and skipped rows.
func WithErrorHandler(fn func(error)) Option {
	return func(s *Store) { s.onError = fn }
}

// WithOnChange installs the callback a reload calls, on its own goroutine,
// when the list changed.
func WithOnChange(fn func(Change)) Option {
	return func(s *Store) { s.onChange = fn }
}

// WithClock injects a clock, for tests.
func WithClock(now func() time.Time) Option {
	return func(s *Store) {
		if now != nil {
			s.now = now
		}
	}
}

// New adapts a control-plane database and performs the first load.
//
// The database must be the hub's own, never a managed project's: a tenant
// able to write the file holding this table could admit itself to every
// project on the hub with one INSERT.
func New(db *statedb.DB, opts ...Option) (*Store, error) {
	if db == nil {
		return nil, errors.New("projectmember: nil database")
	}
	s := &Store{db: db, ttl: DefaultTTL, now: time.Now}
	for _, opt := range opts {
		opt(s)
	}
	members, err := s.load()
	if err != nil {
		return nil, err
	}
	s.snap.Store(newSnapshot(members, s.now()))
	return s, nil
}

// Invalidate makes the next read reload from the database.
func (s *Store) Invalidate() { s.stale.Store(true) }

// Refresh reloads now, whatever the TTL says, and reports a failure. The
// change it finds, if any, goes to the OnChange callback.
func (s *Store) Refresh() error {
	s.refreshMu.Lock()
	defer s.refreshMu.Unlock()
	return s.reloadLocked()
}

// current returns a snapshot no older than the TTL, reloading if needed.
func (s *Store) current() *snapshot {
	if snap := s.snap.Load(); s.fresh(snap) {
		return snap
	}
	s.refreshMu.Lock()
	defer s.refreshMu.Unlock()
	if snap := s.snap.Load(); s.fresh(snap) {
		return snap // reloaded while this caller waited
	}
	_ = s.reloadLocked()
	return s.snap.Load()
}

func (s *Store) fresh(snap *snapshot) bool {
	return !s.stale.Load() && s.now().Sub(snap.at) < s.ttl
}

// reloadLocked replaces the snapshot with the table's current contents. On
// failure the old snapshot stays, re-stamped, so a wedged database is retried
// once per TTL rather than by every request. Callers hold refreshMu.
func (s *Store) reloadLocked() error {
	// Cleared before the read: an Invalidate that arrives while it runs is
	// about a write this read may have missed, and must survive it.
	s.stale.Store(false)
	members, err := s.load()
	old := s.snap.Load()
	if err != nil {
		stamped := *old
		stamped.at = s.now()
		s.snap.Store(&stamped)
		s.report(err)
		return err
	}
	s.swapLocked(old, newSnapshot(members, s.now()))
	return nil
}

// swapLocked installs next and reports what differs from old.
func (s *Store) swapLocked(old, next *snapshot) {
	s.snap.Store(next)
	if change := diff(old, next); !change.Empty() && s.onChange != nil {
		fn := s.onChange
		go func() {
			defer func() {
				if r := recover(); r != nil {
					s.report(fmt.Errorf("projectmember: change callback panicked: %v", r))
				}
			}()
			fn(change)
		}()
	}
}

func (s *Store) report(err error) {
	if s.onError != nil && err != nil {
		s.onError(err)
	}
}

// Any reports whether any project on the hub has been shared. Served from the
// cache, so a hub that never shared anything pays one slice length per check.
func (s *Store) Any() bool {
	return s != nil && len(s.current().members) > 0
}

// All returns every membership, ordered by project then identity.
func (s *Store) All() []Member {
	if s == nil {
		return nil
	}
	return append([]Member(nil), s.current().members...)
}

// Lookup returns identityKey's membership of projectPath.
func (s *Store) Lookup(projectPath, identityKey string) (Member, bool) {
	if s == nil {
		return Member{}, false
	}
	p := pair{NormalizePath(projectPath), NormalizeKey(identityKey)}
	if p.path == "" || p.key == "" {
		return Member{}, false
	}
	snap := s.current()
	i, ok := snap.byPair[p]
	if !ok {
		return Member{}, false
	}
	return snap.members[i], true
}

// RoleFor returns the role identityKey holds on projectPath by membership.
func (s *Store) RoleFor(projectPath, identityKey string) (authz.Role, bool) {
	m, ok := s.Lookup(projectPath, identityKey)
	if !ok {
		return authz.RoleNone, false
	}
	return m.Role, true
}

// MembersOf returns projectPath's members ordered by identity.
func (s *Store) MembersOf(projectPath string) []Member {
	if s == nil {
		return nil
	}
	path := NormalizePath(projectPath)
	var out []Member
	for _, m := range s.current().members {
		if m.ProjectPath == path {
			out = append(out, m)
		}
	}
	return out
}

// ProjectsOf returns identityKey's memberships ordered by project.
func (s *Store) ProjectsOf(identityKey string) []Member {
	if s == nil {
		return nil
	}
	key := NormalizeKey(identityKey)
	if key == "" {
		return nil
	}
	var out []Member
	for _, m := range s.current().members {
		if m.IdentityKey == key {
			out = append(out, m)
		}
	}
	return out
}

// Grant records or replaces a membership and returns it as stored, along with
// the membership it replaced (nil for a new member). audit builds the rows
// committed with it. The grant is in force for this process when Grant
// returns.
func (s *Store) Grant(m Member, audit Audit) (Member, *Member, error) {
	path := NormalizePath(m.ProjectPath)
	if path == "" {
		return Member{}, nil, errors.New("projectmember: a project path is required")
	}
	key, err := ParseKey(m.IdentityKey)
	if err != nil {
		return Member{}, nil, err
	}
	role, err := ParseGrantableRole(string(m.Role))
	if err != nil {
		return Member{}, nil, err
	}
	reason := strings.TrimSpace(m.Reason)
	if len(reason) > MaxReasonLen {
		return Member{}, nil, fmt.Errorf("projectmember: the reason is longer than %d characters", MaxReasonLen)
	}
	at := m.GrantedAt
	if at.IsZero() {
		at = s.now()
	}
	stored, prevRow, err := s.db.PutProjectMember(statedb.ProjectMemberRow{
		ProjectPath: path,
		IdentityKey: key,
		Role:        string(role),
		Reason:      reason,
		GrantedAt:   at,
		GrantedBy:   strings.TrimSpace(m.GrantedBy),
	}, rowAudit(audit))
	if err != nil {
		return Member{}, nil, fmt.Errorf("projectmember: grant: %w", err)
	}
	out := fromRowUnchecked(stored)
	var prev *Member
	if prevRow != nil {
		p := fromRowUnchecked(*prevRow)
		prev = &p
	}
	s.afterWrite(func(members []Member) []Member {
		members = removePair(members, pair{out.ProjectPath, out.IdentityKey})
		return append(members, out)
	})
	return out, prev, nil
}

// Revoke removes a membership and returns it, or nil when there was none. The
// removal is in force for this process when Revoke returns.
func (s *Store) Revoke(projectPath, identityKey string, audit Audit) (*Member, error) {
	path, key := NormalizePath(projectPath), NormalizeKey(identityKey)
	if path == "" || key == "" {
		return nil, errors.New("projectmember: a project path and an identity are required")
	}
	row, err := s.db.DeleteProjectMember(path, key, rowAudit(audit))
	if err != nil {
		return nil, fmt.Errorf("projectmember: revoke: %w", err)
	}
	// Even when nothing was removed: the caller's view was stale either way,
	// and a cache still listing someone the table no longer holds is the
	// most confusing outcome a revocation can have.
	s.afterWrite(func(members []Member) []Member { return removePair(members, pair{path, key}) })
	if row == nil {
		return nil, nil
	}
	m := fromRowUnchecked(*row)
	return &m, nil
}

// RevokeProject removes every membership on a project that is leaving the hub.
func (s *Store) RevokeProject(projectPath string, audit Audit) ([]Member, error) {
	path := NormalizePath(projectPath)
	if path == "" {
		return nil, errors.New("projectmember: a project path is required")
	}
	rows, err := s.db.DeleteProjectMembersOf(path, rowAudit(audit))
	if err != nil {
		return nil, fmt.Errorf("projectmember: revoke the members of %s: %w", path, err)
	}
	s.afterWrite(func(members []Member) []Member {
		out := members[:0:0]
		for _, m := range members {
			if m.ProjectPath != path {
				out = append(out, m)
			}
		}
		return out
	})
	out := make([]Member, 0, len(rows))
	for _, r := range rows {
		out = append(out, fromRowUnchecked(r))
	}
	return out, nil
}

// afterWrite brings the snapshot up to date with a write this process just
// committed: a reload, which also picks up other writers, or — should the
// database refuse the read — patch applied to the current snapshot, so the
// write is in force either way.
func (s *Store) afterWrite(patch func([]Member) []Member) {
	s.refreshMu.Lock()
	defer s.refreshMu.Unlock()
	var err error
	if s.afterWriteHook != nil {
		err = s.afterWriteHook()
	}
	if err == nil {
		err = s.reloadLocked()
	}
	if err == nil {
		return
	}
	old := s.snap.Load()
	s.swapLocked(old, newSnapshot(patch(append([]Member(nil), old.members...)), old.at))
	// And read the table again at the next opportunity, now that the
	// snapshot is a guess about what it holds.
	s.stale.Store(true)
}

func (s *Store) load() ([]Member, error) {
	rows, err := s.db.ListProjectMembers()
	if err != nil {
		return nil, fmt.Errorf("projectmember: load project members: %w", err)
	}
	out := make([]Member, 0, len(rows))
	for _, row := range rows {
		m, err := fromRow(row)
		if err != nil {
			s.report(fmt.Errorf("projectmember: skipping membership %s: %w", row.ID, err))
			continue
		}
		out = append(out, m)
	}
	return out, nil
}

// fromRow translates a stored row, refusing one that grants nothing this build
// understands. The single translation point for every reader, so what the
// Members card shows cannot differ from what is enforced.
func fromRow(row statedb.ProjectMemberRow) (Member, error) {
	role, err := ParseGrantableRole(row.Role)
	if err != nil {
		return Member{}, err
	}
	m := fromRowUnchecked(row)
	m.Role = role
	if m.ProjectPath == "" || m.IdentityKey == "" {
		return Member{}, errors.New("the row names no project or no identity")
	}
	return m, nil
}

func fromRowUnchecked(row statedb.ProjectMemberRow) Member {
	role, _ := authz.ParseRole(row.Role)
	return Member{
		ProjectPath: NormalizePath(row.ProjectPath),
		IdentityKey: NormalizeKey(row.IdentityKey),
		Role:        role,
		Reason:      row.Reason,
		GrantedAt:   row.GrantedAt,
		GrantedBy:   row.GrantedBy,
	}
}

func rowAudit(audit Audit) statedb.MemberAudit {
	if audit == nil {
		return nil
	}
	return func(prev, next *statedb.ProjectMemberRow) ([]*statedb.AuditEvent, error) {
		var p, n *Member
		if prev != nil {
			m := fromRowUnchecked(*prev)
			p = &m
		}
		if next != nil {
			m := fromRowUnchecked(*next)
			n = &m
		}
		return audit(p, n)
	}
}

func newSnapshot(members []Member, at time.Time) *snapshot {
	sort.Slice(members, func(i, j int) bool {
		if members[i].ProjectPath != members[j].ProjectPath {
			return members[i].ProjectPath < members[j].ProjectPath
		}
		return members[i].IdentityKey < members[j].IdentityKey
	})
	snap := &snapshot{at: at, members: members, byPair: make(map[pair]int, len(members))}
	for i, m := range members {
		snap.byPair[pair{m.ProjectPath, m.IdentityKey}] = i
	}
	return snap
}

func removePair(members []Member, p pair) []Member {
	out := members[:0:0]
	for _, m := range members {
		if m.ProjectPath != p.path || m.IdentityKey != p.key {
			out = append(out, m)
		}
	}
	return out
}

// diff names the projects and identities whose memberships differ between two
// snapshots. Reason and provenance changes are not access changes and are not
// reported.
func diff(old, next *snapshot) Change {
	projects, identities := map[string]bool{}, map[string]bool{}
	note := func(m Member) {
		projects[m.ProjectPath] = true
		identities[m.IdentityKey] = true
	}
	var oldMembers []Member
	if old != nil {
		oldMembers = old.members
	}
	for _, m := range oldMembers {
		i, ok := next.byPair[pair{m.ProjectPath, m.IdentityKey}]
		if !ok || next.members[i].Role != m.Role {
			note(m)
		}
	}
	for _, m := range next.members {
		if old == nil {
			note(m)
			continue
		}
		if _, ok := old.byPair[pair{m.ProjectPath, m.IdentityKey}]; !ok {
			note(m)
		}
	}
	return Change{Projects: sortedKeys(projects), Identities: sortedKeys(identities)}
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ── normalisation ───────────────────────────────────────────────────────────

// KeyFor derives the membership key for an identity's claims, exactly as
// oidcauth.Identity.OwnerKey does: the lowercased email, or "sub:" and the
// subject when the identity provider released no email. "" when it has
// neither. One definition, because the key is the namespace project owners
// and members share, and a second spelling would match nobody.
func KeyFor(email, sub string) string {
	if email = strings.TrimSpace(email); email != "" {
		return strings.ToLower(email)
	}
	if sub = strings.TrimSpace(sub); sub != "" {
		return "sub:" + sub
	}
	return ""
}

// NormalizeKey canonicalises an identity key without judging it: emails are
// lowercased, because an identity provider may release a casing the operator
// did not type; a "sub:" key keeps its subject's case, because a subject is an
// opaque identifier and two differing only in case are two people.
func NormalizeKey(key string) string {
	key = strings.TrimSpace(key)
	if len(key) >= 4 && strings.EqualFold(key[:4], "sub:") {
		rest := strings.TrimSpace(key[4:])
		if rest == "" {
			return ""
		}
		return "sub:" + rest
	}
	return strings.ToLower(key)
}

// ParseKey normalises a key typed by an operator and refuses one that could
// never match a signed-in identity: OwnerKey is always an email or "sub:"
// and a subject, so anything else would be stored, listed, and grant nobody
// anything.
func ParseKey(raw string) (string, error) {
	key := NormalizeKey(raw)
	switch {
	case key == "":
		return "", errors.New(`projectmember: an identity is required — the member's email, or "sub:<subject>" when the identity provider releases no email`)
	case len(key) > MaxKeyLen:
		return "", fmt.Errorf("projectmember: an identity is at most %d characters", MaxKeyLen)
	}
	for _, r := range key {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return "", fmt.Errorf("projectmember: %q contains whitespace or a control character", raw)
		}
	}
	if strings.HasPrefix(key, "sub:") {
		return key, nil
	}
	at := strings.LastIndex(key, "@")
	if at <= 0 || at == len(key)-1 {
		return "", fmt.Errorf(`projectmember: %q is neither an email address nor "sub:<subject>"`, raw)
	}
	return key, nil
}

// ParseGrantableRole parses a role a membership may carry: any rung of the
// ladder above "none". A membership granting nothing is a revocation in a
// membership's clothes, and would list somebody on a project they cannot open.
func ParseGrantableRole(raw string) (authz.Role, error) {
	role, ok := authz.ParseRole(raw)
	if !ok || role == authz.RoleNone {
		return authz.RoleNone, fmt.Errorf("projectmember: role %q is not one of viewer, operator, maintainer, admin", raw)
	}
	return role, nil
}

// NormalizePath canonicalises a project path so two spellings of one directory
// are one membership: absolute and cleaned, but deliberately not
// symlink-resolved, because the registry and authz.Scope.ProjectPath carry the
// path as registered and a resolved key would match neither.
func NormalizePath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	if abs, err := filepath.Abs(path); err == nil {
		return filepath.Clean(abs)
	}
	return filepath.Clean(path)
}
