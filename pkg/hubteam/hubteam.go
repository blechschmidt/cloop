// Package hubteam is the hub's list of teams: named groups of people a project
// can be shared with (Task 20478).
//
// It follows the split pkg/projectmember uses: pkg/statedb owns the tables and
// their transactions, and this package owns what a team means, normalisation,
// and the cache that makes asking "is this person on that team" affordable on
// every authorization decision.
//
// # Who is on a team
//
// A team's members are the union of three sets:
//
//   - the people added to it by name (team_members), in the namespace project
//     owners and members use: a lowercased email, or "sub:<subject>";
//   - when it follows an identity-provider group (IdPGroup), everyone whose ID
//     token carries that group claim value, compared exactly as a `group` role
//     mapping compares it;
//   - when it follows a provisioned group (SCIMGroup), everyone the identity
//     provider placed in that group over SCIM, compared as a `scim_group` role
//     mapping compares it.
//
// The last two are what let an organisation keep membership where it already
// keeps it: removing an engineer from the group at the identity provider takes
// them off the team, and so off every project shared with it, without anybody
// editing the hub.
//
// The built-in team Everyone (slug "everyone") has every signed-in identity as
// its member and no row: sharing a project with it is how a project is opened
// to the whole hub.
//
// # Who keeps the list
//
// The hub's administrators (user.manage). Whoever decides who is on a team
// decides who reaches every project shared with it, so letting a project's
// maintainer edit a team would let them reach every other project that team
// was given. This package does not know who is asking; pkg/ui and the CLI
// enforce it.
//
// # Freshness and failure
//
// As pkg/projectmember: reads come from a snapshot refreshed every TTL, a write
// through a Store is in force in this process when it returns, a refresh that
// fails keeps serving the last good snapshot, and every reload that finds the
// list changed is reported to the OnChange callback — which is how a hub
// closes the streams of somebody who just left a team.
package hubteam

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"

	"github.com/blechschmidt/cloop/pkg/authz"
	"github.com/blechschmidt/cloop/pkg/projectmember"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// Everyone is the slug of the built-in team of every signed-in identity.
const Everyone = statedb.EveryoneTeam

// EveryoneName is how the built-in team is shown.
const EveryoneName = "Everyone on this hub"

// KeyPrefix starts the project_members identity key of a share with a team.
const KeyPrefix = statedb.TeamKeyPrefix

// DefaultTTL bounds how long a change written by another process takes to
// reach this one's decisions.
const DefaultTTL = 10 * time.Second

// MaxSlugLen, MaxNameLen, MaxDescriptionLen and MaxGroupLen bound what a team
// stores.
const (
	MaxSlugLen        = statedb.MaxTeamSlugLen
	MaxNameLen        = 100
	MaxDescriptionLen = 500
	MaxGroupLen       = 256
)

// Team is one team as the rest of the hub sees it.
type Team struct {
	Slug        string    `json:"slug"`
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	IdPGroup    string    `json:"idp_group,omitempty"`
	SCIMGroup   string    `json:"scim_group,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	CreatedBy   string    `json:"created_by,omitempty"`
	UpdatedAt   time.Time `json:"updated_at"`
	UpdatedBy   string    `json:"updated_by,omitempty"`
	// Members are the people added by name, ordered by identity.
	Members []Member `json:"members"`
}

// Builtin reports whether t is the built-in team.
func (t Team) Builtin() bool { return t.Slug == Everyone }

// Label is how the team is shown: its name, or its slug when it has none.
func (t Team) Label() string {
	if strings.TrimSpace(t.Name) != "" {
		return t.Name
	}
	return t.Slug
}

// Member is one person added to a team by name.
type Member struct {
	IdentityKey string    `json:"identity"`
	AddedAt     time.Time `json:"added_at"`
	AddedBy     string    `json:"added_by,omitempty"`
}

// Facts are what a team decision needs to know about an identity.
type Facts struct {
	// Key is the identity's member key (projectmember.KeyFor). Empty for no
	// identity, which is on no team at all — not even Everyone.
	Key string
	// Groups are the group claim values its ID token carried.
	Groups []string
	// SCIMGroups are the groups the provisioning directory places it in.
	SCIMGroups []string
}

// Change is what a reload found different.
type Change struct {
	// Teams are the slugs whose definition or members changed.
	Teams []string
}

// Empty reports whether nothing changed.
func (c Change) Empty() bool { return len(c.Teams) == 0 }

// Audit builds the audit events committed together with a change.
type Audit = statedb.TeamAudit

// Store reads teams through a TTL cache.
type Store struct {
	db       *statedb.DB
	ttl      time.Duration
	now      func() time.Time
	onError  func(error)
	onChange func(Change)

	refreshMu sync.Mutex
	snap      atomic.Pointer[snapshot]
	stale     atomic.Bool
}

type snapshot struct {
	at     time.Time
	teams  []Team // ordered by slug, the built-in team excluded
	bySlug map[string]int
	// byKey maps a named member to the teams naming them.
	byKey map[string][]string
	// linked lists the teams that follow a group, so a decision about a
	// person on no team by name checks only those.
	linked []int
	// scim reports whether any team follows a provisioned group, which is the
	// only case in which a decision needs the directory at all.
	scim bool
}

// Option configures a Store.
type Option func(*Store)

// WithTTL overrides the refresh interval; non-positive values are ignored.
func WithTTL(d time.Duration) Option {
	return func(s *Store) {
		if d > 0 {
			s.ttl = d
		}
	}
}

// WithErrorHandler installs a sink for failed refreshes and skipped rows.
func WithErrorHandler(fn func(error)) Option { return func(s *Store) { s.onError = fn } }

// WithOnChange installs the callback a reload calls, on its own goroutine,
// when the list changed.
func WithOnChange(fn func(Change)) Option { return func(s *Store) { s.onChange = fn } }

// WithClock injects a clock, for tests.
func WithClock(now func() time.Time) Option {
	return func(s *Store) {
		if now != nil {
			s.now = now
		}
	}
}

// New adapts the hub's control-plane database and performs the first load.
// The database must be the hub's own: a tenant able to write the file holding
// these tables could add itself to any team.
func New(db *statedb.DB, opts ...Option) (*Store, error) {
	if db == nil {
		return nil, errors.New("team: nil database")
	}
	s := &Store{db: db, ttl: DefaultTTL, now: time.Now}
	for _, opt := range opts {
		opt(s)
	}
	teams, err := s.load()
	if err != nil {
		return nil, err
	}
	s.snap.Store(newSnapshot(teams, s.now()))
	return s, nil
}

// Invalidate makes the next read reload.
func (s *Store) Invalidate() {
	if s != nil {
		s.stale.Store(true)
	}
}

// Refresh reloads now and reports a failure.
func (s *Store) Refresh() error {
	if s == nil {
		return nil
	}
	s.refreshMu.Lock()
	defer s.refreshMu.Unlock()
	return s.reloadLocked()
}

func (s *Store) current() *snapshot {
	if snap := s.snap.Load(); s.fresh(snap) {
		return snap
	}
	s.refreshMu.Lock()
	defer s.refreshMu.Unlock()
	if snap := s.snap.Load(); s.fresh(snap) {
		return snap
	}
	_ = s.reloadLocked()
	return s.snap.Load()
}

func (s *Store) fresh(snap *snapshot) bool {
	return !s.stale.Load() && s.now().Sub(snap.at) < s.ttl
}

func (s *Store) reloadLocked() error {
	s.stale.Store(false)
	teams, err := s.load()
	old := s.snap.Load()
	if err != nil {
		stamped := *old
		stamped.at = s.now()
		s.snap.Store(&stamped)
		s.report(err)
		return err
	}
	s.swapLocked(old, newSnapshot(teams, s.now()))
	return nil
}

func (s *Store) swapLocked(old, next *snapshot) {
	s.snap.Store(next)
	if change := diff(old, next); !change.Empty() && s.onChange != nil {
		fn := s.onChange
		go func() {
			defer func() {
				if r := recover(); r != nil {
					s.report(fmt.Errorf("team: change callback panicked: %v", r))
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

// All returns every stored team, ordered by slug. The built-in team is not
// among them; see BuiltinTeam.
func (s *Store) All() []Team {
	if s == nil {
		return nil
	}
	snap := s.current()
	out := make([]Team, len(snap.teams))
	for i, t := range snap.teams {
		out[i] = cloneTeam(t)
	}
	return out
}

// Any reports whether any team is stored.
func (s *Store) Any() bool { return s != nil && len(s.current().teams) > 0 }

// Get returns the team with slug; the built-in team for Everyone.
func (s *Store) Get(slug string) (Team, bool) {
	slug = NormalizeSlug(slug)
	if slug == Everyone {
		return BuiltinTeam(), true
	}
	if s == nil || slug == "" {
		return Team{}, false
	}
	snap := s.current()
	i, ok := snap.bySlug[slug]
	if !ok {
		return Team{}, false
	}
	return cloneTeam(snap.teams[i]), true
}

// BuiltinTeam describes Everyone.
func BuiltinTeam() Team {
	return Team{Slug: Everyone, Name: EveryoneName,
		Description: "Every identity that can sign in to this hub.", Members: []Member{}}
}

// NeedsDirectory reports whether any team follows a provisioned group, i.e.
// whether a decision has to ask the SCIM directory for an identity's groups.
func (s *Store) NeedsDirectory() bool { return s != nil && s.current().scim }

// TeamsOf returns the slugs of the teams f is on, Everyone included for any
// identity, as a set. A nil Store knows only Everyone.
func (s *Store) TeamsOf(f Facts) map[string]bool {
	key := projectmember.NormalizeKey(f.Key)
	if key == "" || IsShareKey(key) {
		// No identity is on no team; and a key spelled like a share is
		// nobody's — see projectmember.KeyFor.
		return nil
	}
	out := map[string]bool{Everyone: true}
	if s == nil {
		return out
	}
	snap := s.current()
	for _, slug := range snap.byKey[key] {
		out[slug] = true
	}
	for _, i := range snap.linked {
		t := snap.teams[i]
		if out[t.Slug] {
			continue
		}
		if t.IdPGroup != "" && authz.ClaimValueIn(f.Groups, t.IdPGroup) {
			out[t.Slug] = true
			continue
		}
		if t.SCIMGroup != "" && authz.ClaimValueIn(f.SCIMGroups, t.SCIMGroup) {
			out[t.Slug] = true
		}
	}
	return out
}

// IsMember reports whether f is on the team slug.
func (s *Store) IsMember(slug string, f Facts) bool {
	return s.TeamsOf(f)[NormalizeSlug(slug)]
}

// Create stores a new team. It is in force in this process when it returns.
func (s *Store) Create(t Team, audit Audit) (Team, error) {
	row, err := validate(t)
	if err != nil {
		return Team{}, err
	}
	if row.Slug == Everyone {
		return Team{}, fmt.Errorf("team: %q is the built-in team of every signed-in identity and cannot be created", Everyone)
	}
	row.CreatedBy = strings.TrimSpace(t.CreatedBy)
	row.CreatedAt = s.now()
	stored, err := s.db.CreateTeam(row, audit)
	if err != nil {
		return Team{}, fmt.Errorf("team: create %s: %w", row.Slug, err)
	}
	s.afterWrite()
	out, _ := s.Get(stored.Slug)
	if out.Slug == "" {
		out = fromRow(stored, nil)
	}
	return out, nil
}

// Update replaces a team's name, description and group links, returning the
// team as stored and as it was.
func (s *Store) Update(t Team, audit Audit) (Team, Team, error) {
	row, err := validate(t)
	if err != nil {
		return Team{}, Team{}, err
	}
	if row.Slug == Everyone {
		return Team{}, Team{}, fmt.Errorf("team: the built-in team %q cannot be changed", Everyone)
	}
	row.UpdatedBy = strings.TrimSpace(t.UpdatedBy)
	row.UpdatedAt = s.now()
	stored, prev, err := s.db.UpdateTeam(row, audit)
	if err != nil {
		return Team{}, Team{}, fmt.Errorf("team: update %s: %w", row.Slug, err)
	}
	s.afterWrite()
	out, ok := s.Get(stored.Slug)
	if !ok {
		out = fromRow(stored, nil)
	}
	return out, fromRow(prev, nil), nil
}

// Delete removes a team, its named members and every project share naming it,
// and reports the shares removed.
func (s *Store) Delete(slug string, audit Audit) (Team, []projectmember.Member, error) {
	slug = NormalizeSlug(slug)
	if slug == Everyone {
		return Team{}, nil, fmt.Errorf("team: the built-in team %q cannot be deleted", Everyone)
	}
	if slug == "" {
		return Team{}, nil, errors.New("team: a team is required")
	}
	row, members, shares, err := s.db.DeleteTeam(slug, audit)
	if err != nil {
		return Team{}, nil, fmt.Errorf("team: delete %s: %w", slug, err)
	}
	s.afterWrite()
	out := make([]projectmember.Member, 0, len(shares))
	for _, sh := range shares {
		role, _ := authz.ParseRole(sh.Role)
		out = append(out, projectmember.Member{
			ProjectPath: sh.ProjectPath, IdentityKey: sh.IdentityKey, Role: role,
			Reason: sh.Reason, GrantedAt: sh.GrantedAt, GrantedBy: sh.GrantedBy,
		})
	}
	return fromRow(row, members), out, nil
}

// AddMember names identityKey on a team, reporting whether they already were.
func (s *Store) AddMember(slug, identityKey, by string, audit Audit) (Member, bool, error) {
	slug = NormalizeSlug(slug)
	if slug == Everyone {
		return Member{}, false, fmt.Errorf("team: every signed-in identity is already on %q", Everyone)
	}
	key, err := ParseMemberKey(identityKey)
	if err != nil {
		return Member{}, false, err
	}
	row, existed, err := s.db.AddTeamMember(statedb.TeamMemberRow{
		TeamSlug: slug, IdentityKey: key, AddedAt: s.now(), AddedBy: strings.TrimSpace(by),
	}, audit)
	if err != nil {
		return Member{}, false, fmt.Errorf("team: add %s to %s: %w", key, slug, err)
	}
	s.afterWrite()
	return Member{IdentityKey: row.IdentityKey, AddedAt: row.AddedAt, AddedBy: row.AddedBy}, existed, nil
}

// RemoveMember takes identityKey off a team, returning the row removed or nil.
func (s *Store) RemoveMember(slug, identityKey string, audit Audit) (*Member, error) {
	slug, key := NormalizeSlug(slug), projectmember.NormalizeKey(identityKey)
	if slug == "" || key == "" {
		return nil, errors.New("team: a team and an identity are required")
	}
	row, err := s.db.RemoveTeamMember(slug, key, audit)
	if err != nil {
		return nil, fmt.Errorf("team: remove %s from %s: %w", key, slug, err)
	}
	s.afterWrite()
	if row == nil {
		return nil, nil
	}
	return &Member{IdentityKey: row.IdentityKey, AddedAt: row.AddedAt, AddedBy: row.AddedBy}, nil
}

// afterWrite reloads after a write this process committed, so the write is in
// force when the call returns. A reload that fails leaves the snapshot to be
// re-read at the next opportunity; the write itself already committed.
func (s *Store) afterWrite() {
	s.refreshMu.Lock()
	defer s.refreshMu.Unlock()
	if err := s.reloadLocked(); err != nil {
		s.stale.Store(true)
	}
}

func (s *Store) load() ([]Team, error) {
	rows, err := s.db.ListTeams()
	if err != nil {
		return nil, fmt.Errorf("team: load teams: %w", err)
	}
	members, err := s.db.ListTeamMembers()
	if err != nil {
		return nil, fmt.Errorf("team: load team members: %w", err)
	}
	bySlug := make(map[string][]statedb.TeamMemberRow, len(rows))
	for _, m := range members {
		bySlug[m.TeamSlug] = append(bySlug[m.TeamSlug], m)
	}
	out := make([]Team, 0, len(rows))
	for _, row := range rows {
		if _, err := ParseSlug(row.Slug); err != nil || row.Slug == Everyone {
			s.report(fmt.Errorf("team: skipping team %q: not a valid slug", row.Slug))
			continue
		}
		out = append(out, fromRow(row, bySlug[row.Slug]))
	}
	return out, nil
}

func fromRow(row statedb.TeamRow, members []statedb.TeamMemberRow) Team {
	t := Team{
		Slug: row.Slug, Name: row.Name, Description: row.Description,
		IdPGroup: row.IdPGroup, SCIMGroup: row.SCIMGroup,
		CreatedAt: row.CreatedAt, CreatedBy: row.CreatedBy, UpdatedAt: row.UpdatedAt, UpdatedBy: row.UpdatedBy,
		Members: make([]Member, 0, len(members)),
	}
	for _, m := range members {
		key := projectmember.NormalizeKey(m.IdentityKey)
		if key == "" {
			continue
		}
		t.Members = append(t.Members, Member{IdentityKey: key, AddedAt: m.AddedAt, AddedBy: m.AddedBy})
	}
	sort.Slice(t.Members, func(i, j int) bool { return t.Members[i].IdentityKey < t.Members[j].IdentityKey })
	return t
}

func cloneTeam(t Team) Team {
	t.Members = append([]Member{}, t.Members...)
	return t
}

func newSnapshot(teams []Team, at time.Time) *snapshot {
	sort.Slice(teams, func(i, j int) bool { return teams[i].Slug < teams[j].Slug })
	snap := &snapshot{at: at, teams: teams, bySlug: make(map[string]int, len(teams)), byKey: map[string][]string{}}
	for i, t := range teams {
		snap.bySlug[t.Slug] = i
		for _, m := range t.Members {
			snap.byKey[m.IdentityKey] = append(snap.byKey[m.IdentityKey], t.Slug)
		}
		if t.IdPGroup != "" || t.SCIMGroup != "" {
			snap.linked = append(snap.linked, i)
		}
		if t.SCIMGroup != "" {
			snap.scim = true
		}
	}
	return snap
}

// diff names the teams whose definition or member list differs. Display-only
// fields (name, description, provenance) are not access changes and are not
// reported.
func diff(old, next *snapshot) Change {
	changed := map[string]bool{}
	sig := func(t Team) string {
		var b strings.Builder
		b.WriteString(t.IdPGroup + "\x00" + t.SCIMGroup + "\x00")
		for _, m := range t.Members {
			b.WriteString(m.IdentityKey + "\x00")
		}
		return b.String()
	}
	if old != nil {
		for _, t := range old.teams {
			i, ok := next.bySlug[t.Slug]
			if !ok || sig(next.teams[i]) != sig(t) {
				changed[t.Slug] = true
			}
		}
	}
	for _, t := range next.teams {
		if old == nil {
			changed[t.Slug] = true
			continue
		}
		if _, ok := old.bySlug[t.Slug]; !ok {
			changed[t.Slug] = true
		}
	}
	out := make([]string, 0, len(changed))
	for slug := range changed {
		out = append(out, slug)
	}
	sort.Strings(out)
	return Change{Teams: out}
}

// ── names ───────────────────────────────────────────────────────────────────

// ShareKey is the project_members identity key of a share with slug.
func ShareKey(slug string) string { return KeyPrefix + NormalizeSlug(slug) }

// IsShareKey reports whether a project_members identity key names a team.
func IsShareKey(key string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(key)), KeyPrefix)
}

// SlugOfShareKey returns the team a share key names, and whether it names one.
func SlugOfShareKey(key string) (string, bool) {
	key = strings.ToLower(strings.TrimSpace(key))
	if !strings.HasPrefix(key, KeyPrefix) {
		return "", false
	}
	slug, err := ParseSlug(key[len(KeyPrefix):])
	if err != nil {
		return "", false
	}
	return slug, true
}

// NormalizeSlug lowercases and trims a slug without judging it.
func NormalizeSlug(slug string) string { return strings.ToLower(strings.TrimSpace(slug)) }

// ParseSlug normalises a slug and refuses one a share key could not carry:
// lowercase letters, digits, "-", "_" and ".", starting with a letter or digit,
// at most MaxSlugLen characters.
func ParseSlug(raw string) (string, error) {
	slug := NormalizeSlug(raw)
	if slug == "" {
		return "", errors.New("team: a team slug is required — lowercase letters, digits, '-', '_' and '.'")
	}
	if len(slug) > MaxSlugLen {
		return "", fmt.Errorf("team: a team slug is at most %d characters", MaxSlugLen)
	}
	if !statedb.ValidTeamSlug(slug) {
		return "", fmt.Errorf("team: %q is not a valid team slug — use lowercase letters, digits, '-', '_' and '.', starting with a letter or digit", raw)
	}
	return slug, nil
}

// ParseMemberKey normalises the identity of a person added to a team: an email
// or "sub:<subject>", exactly what a project membership names.
func ParseMemberKey(raw string) (string, error) {
	if IsShareKey(raw) {
		return "", errors.New("team: a team's member is a person, not another team")
	}
	key, err := projectmember.ParseKey(raw)
	if err != nil {
		return "", errors.New(strings.Replace(err.Error(), "projectmember:", "team:", 1))
	}
	return key, nil
}

// validate checks the editable fields and builds the row they make.
func validate(t Team) (statedb.TeamRow, error) {
	slug, err := ParseSlug(t.Slug)
	if err != nil {
		return statedb.TeamRow{}, err
	}
	name := strings.TrimSpace(t.Name)
	if name == "" {
		name = slug
	}
	desc := strings.TrimSpace(t.Description)
	idp := authz.NormalizeClaimValue(t.IdPGroup)
	scim := strings.TrimSpace(t.SCIMGroup)
	switch {
	case len(name) > MaxNameLen:
		return statedb.TeamRow{}, fmt.Errorf("team: a team name is at most %d characters", MaxNameLen)
	case len(desc) > MaxDescriptionLen:
		return statedb.TeamRow{}, fmt.Errorf("team: a team description is at most %d characters", MaxDescriptionLen)
	case len(idp) > MaxGroupLen || len(scim) > MaxGroupLen:
		return statedb.TeamRow{}, fmt.Errorf("team: a group name is at most %d characters", MaxGroupLen)
	}
	for _, v := range []string{name, idp, scim} {
		for _, r := range v {
			if unicode.IsControl(r) {
				return statedb.TeamRow{}, errors.New("team: names and groups may not contain control characters")
			}
		}
	}
	return statedb.TeamRow{Slug: slug, Name: name, Description: desc, IdPGroup: idp, SCIMGroup: scim}, nil
}
