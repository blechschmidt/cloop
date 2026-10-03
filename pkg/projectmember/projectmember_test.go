package projectmember

import (
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/authz"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// fakeClock is a settable clock for the TTL tests.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

func openDB(t *testing.T) *statedb.DB {
	t.Helper()
	db, err := statedb.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// changeLog collects what OnChange reported.
type changeLog struct {
	mu      sync.Mutex
	changes []Change
	signal  chan struct{}
}

func newChangeLog() *changeLog { return &changeLog{signal: make(chan struct{}, 64)} }

func (l *changeLog) record(c Change) {
	l.mu.Lock()
	l.changes = append(l.changes, c)
	l.mu.Unlock()
	l.signal <- struct{}{}
}

// next waits for the next reported change, bounded.
func (l *changeLog) next(t *testing.T) Change {
	t.Helper()
	select {
	case <-l.signal:
	case <-time.After(10 * time.Second):
		t.Fatal("no change was reported")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.changes[len(l.changes)-1]
}

func (l *changeLog) none(t *testing.T) {
	t.Helper()
	select {
	case <-l.signal:
		l.mu.Lock()
		defer l.mu.Unlock()
		t.Fatalf("a change was reported when nothing changed: %+v", l.changes[len(l.changes)-1])
	case <-time.After(50 * time.Millisecond):
	}
}

func TestNormalisation(t *testing.T) {
	t.Run("keys", func(t *testing.T) {
		for raw, want := range map[string]string{
			"  Bob@Corp.Example ": "bob@corp.example",
			"SUB:Opaque-ID":       "sub:Opaque-ID",
			"sub: abc ":           "sub:abc",
			"sub:":                "",
			"":                    "",
		} {
			if got := NormalizeKey(raw); got != want {
				t.Errorf("NormalizeKey(%q) = %q, want %q", raw, got, want)
			}
		}
		if got := KeyFor("Alice@Example.COM", "s-1"); got != "alice@example.com" {
			t.Errorf("KeyFor with an email = %q", got)
		}
		if got := KeyFor("", "S-1"); got != "sub:S-1" {
			t.Errorf("KeyFor with a subject only = %q", got)
		}
		if got := KeyFor("", ""); got != "" {
			t.Errorf("KeyFor with nothing = %q", got)
		}
	})
	t.Run("operator input", func(t *testing.T) {
		for _, ok := range []string{"bob@corp.example", "sub:auth0|123", "Bob@Corp.Example"} {
			if _, err := ParseKey(ok); err != nil {
				t.Errorf("ParseKey(%q) refused: %v", ok, err)
			}
		}
		for _, bad := range []string{"", "bob", "@corp.example", "bob@", "local", "sub:", "bob @corp.example",
			"bob@corp\x00.example", strings.Repeat("a", MaxKeyLen) + "@x"} {
			if _, err := ParseKey(bad); err == nil {
				t.Errorf("ParseKey(%q) accepted a key no identity can carry", bad)
			}
		}
	})
	t.Run("roles", func(t *testing.T) {
		for _, ok := range []string{"viewer", "Operator", " maintainer ", "admin"} {
			if _, err := ParseGrantableRole(ok); err != nil {
				t.Errorf("ParseGrantableRole(%q): %v", ok, err)
			}
		}
		for _, bad := range []string{"", "none", "owner", "root"} {
			if _, err := ParseGrantableRole(bad); err == nil {
				t.Errorf("ParseGrantableRole(%q) accepted a role that grants nothing or does not exist", bad)
			}
		}
	})
	t.Run("paths", func(t *testing.T) {
		if got := NormalizePath(" /srv/p/../p/ "); got != "/srv/p" {
			t.Errorf("NormalizePath = %q", got)
		}
		if got := NormalizePath(""); got != "" {
			t.Errorf("NormalizePath(\"\") = %q", got)
		}
	})
}

func TestStoreGrantAndRevokeTakeEffectAtOnce(t *testing.T) {
	db := openDB(t)
	clock := &fakeClock{now: time.Unix(1_800_000_000, 0)}
	changes := newChangeLog()
	s, err := New(db, WithClock(clock.Now), WithOnChange(changes.record))
	if err != nil {
		t.Fatal(err)
	}
	if s.Any() {
		t.Fatal("a fresh hub reports memberships")
	}

	stored, prev, err := s.Grant(Member{ProjectPath: "/srv/p", IdentityKey: "Bob@Corp.Example", Role: "viewer",
		Reason: "  pairing  ", GrantedBy: "alice@corp.example"}, nil)
	if err != nil || prev != nil {
		t.Fatalf("Grant: %+v prev=%v err=%v", stored, prev, err)
	}
	if stored.IdentityKey != "bob@corp.example" || stored.Reason != "pairing" || stored.Role != authz.RoleViewer {
		t.Errorf("stored %+v, want the normalised grant", stored)
	}
	// No clock advance: an in-process write must not wait out the TTL.
	if role, ok := s.RoleFor("/srv/p/", "BOB@corp.example"); !ok || role != authz.RoleViewer {
		t.Fatalf("RoleFor after Grant = %s %v", role, ok)
	}
	if c := changes.next(t); strings.Join(c.Projects, ",") != "/srv/p" || strings.Join(c.Identities, ",") != "bob@corp.example" {
		t.Errorf("grant reported %+v", c)
	}

	if _, prev, err := s.Grant(Member{ProjectPath: "/srv/p", IdentityKey: "bob@corp.example", Role: "operator"}, nil); err != nil || prev == nil || prev.Role != authz.RoleViewer {
		t.Fatalf("a role change reported prev=%+v err=%v", prev, err)
	}
	changes.next(t)
	if got := s.MembersOf("/srv/p"); len(got) != 1 || got[0].Role != authz.RoleOperator {
		t.Fatalf("after a role change the roster is %+v", got)
	}
	if got := s.ProjectsOf("bob@corp.example"); len(got) != 1 || got[0].ProjectPath != "/srv/p" {
		t.Fatalf("ProjectsOf = %+v", got)
	}

	removed, err := s.Revoke("/srv/p", "bob@corp.example", nil)
	if err != nil || removed == nil || removed.Role != authz.RoleOperator {
		t.Fatalf("Revoke = %+v %v", removed, err)
	}
	if _, ok := s.RoleFor("/srv/p", "bob@corp.example"); ok {
		t.Fatal("a revoked member still holds a role before the TTL")
	}
	changes.next(t)
	if again, err := s.Revoke("/srv/p", "bob@corp.example", nil); err != nil || again != nil {
		t.Fatalf("a second Revoke = %+v %v, want nothing removed", again, err)
	}
	changes.none(t)
}

func TestStoreRefusesWhatNoIdentityCouldUse(t *testing.T) {
	s, err := New(openDB(t))
	if err != nil {
		t.Fatal(err)
	}
	for name, m := range map[string]Member{
		"no project":   {IdentityKey: "bob@corp.example", Role: "viewer"},
		"no identity":  {ProjectPath: "/srv/p", Role: "viewer"},
		"not an email": {ProjectPath: "/srv/p", IdentityKey: "bob", Role: "viewer"},
		"role none":    {ProjectPath: "/srv/p", IdentityKey: "bob@corp.example", Role: "none"},
		"no such role": {ProjectPath: "/srv/p", IdentityKey: "bob@corp.example", Role: "owner"},
		"long reason":  {ProjectPath: "/srv/p", IdentityKey: "bob@corp.example", Role: "viewer", Reason: strings.Repeat("x", MaxReasonLen+1)},
	} {
		if _, _, err := s.Grant(m, nil); err == nil {
			t.Errorf("%s: Grant accepted %+v", name, m)
		}
	}
	if s.Any() {
		t.Error("a refused grant was stored")
	}
}

// TestStoreTTLBoundsAnotherWritersChange: a write the store did not make (the
// CLI, another hub member) lands within one TTL, and at once on Invalidate.
func TestStoreTTLBoundsAnotherWritersChange(t *testing.T) {
	db := openDB(t)
	clock := &fakeClock{now: time.Unix(1_800_000_000, 0)}
	changes := newChangeLog()
	s, err := New(db, WithClock(clock.Now), WithTTL(10*time.Second), WithOnChange(changes.record))
	if err != nil {
		t.Fatal(err)
	}
	put := func(key, role string) {
		t.Helper()
		if _, _, err := db.PutProjectMember(statedb.ProjectMemberRow{ProjectPath: "/srv/p", IdentityKey: key, Role: role}, nil); err != nil {
			t.Fatal(err)
		}
	}

	put("carol@corp.example", "viewer")
	if _, ok := s.RoleFor("/srv/p", "carol@corp.example"); ok {
		t.Fatal("the cache saw an outside write before its TTL — it is not caching")
	}
	clock.Advance(10 * time.Second)
	if role, ok := s.RoleFor("/srv/p", "carol@corp.example"); !ok || role != authz.RoleViewer {
		t.Fatalf("an outside write was not visible after the TTL: %s %v", role, ok)
	}
	if c := changes.next(t); strings.Join(c.Identities, ",") != "carol@corp.example" {
		t.Errorf("the TTL reload reported %+v", c)
	}

	if _, err := db.DeleteProjectMember("/srv/p", "carol@corp.example", nil); err != nil {
		t.Fatal(err)
	}
	s.Invalidate()
	if _, ok := s.RoleFor("/srv/p", "carol@corp.example"); ok {
		t.Fatal("an invalidated cache still served a membership the table no longer holds")
	}
	changes.next(t)

	// Refresh reloads whatever the TTL says, which is what a hub's watcher
	// calls, and a reload that finds nothing new reports nothing.
	put("dave@corp.example", "admin")
	if err := s.Refresh(); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.RoleFor("/srv/p", "dave@corp.example"); !ok {
		t.Fatal("Refresh did not reload")
	}
	changes.next(t)
	if err := s.Refresh(); err != nil {
		t.Fatal(err)
	}
	changes.none(t)
}

// TestStoreKeepsTheLastGoodSnapshot: a refresh that fails must not un-share
// every project for as long as the fault lasts, and a row this build cannot
// read is skipped without taking the rest of the table with it.
func TestStoreKeepsTheLastGoodSnapshot(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	db, err := statedb.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range []statedb.ProjectMemberRow{
		{ProjectPath: "/srv/p", IdentityKey: "bob@corp.example", Role: "operator"},
		{ProjectPath: "/srv/p", IdentityKey: "eve@corp.example", Role: "superuser"},
	} {
		if _, _, err := db.PutProjectMember(r, nil); err != nil {
			t.Fatal(err)
		}
	}
	var reported atomic.Int32
	clock := &fakeClock{now: time.Unix(1_800_000_000, 0)}
	s, err := New(db, WithClock(clock.Now), WithErrorHandler(func(error) { reported.Add(1) }))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := s.RoleFor("/srv/p", "eve@corp.example"); ok {
		t.Error("a row with a role this build does not know grants something")
	}
	if role, ok := s.RoleFor("/srv/p", "bob@corp.example"); !ok || role != authz.RoleOperator {
		t.Fatalf("one unreadable row took a readable one with it: %s %v", role, ok)
	}
	if reported.Load() == 0 {
		t.Error("the skipped row was not reported")
	}

	before := reported.Load()
	_ = db.Close() // every read now fails
	clock.Advance(time.Minute)
	if role, ok := s.RoleFor("/srv/p", "bob@corp.example"); !ok || role != authz.RoleOperator {
		t.Fatalf("a failed refresh dropped the last good snapshot: %s %v", role, ok)
	}
	if reported.Load() == before {
		t.Error("the failed refresh was not reported")
	}
	// Re-stamped, so the next read inside the TTL does not retry.
	n := reported.Load()
	_, _ = s.RoleFor("/srv/p", "bob@corp.example")
	if reported.Load() != n {
		t.Error("a wedged database was retried by every read instead of once per TTL")
	}
}

// TestStoreWriteHoldsWhenTheReloadFails: a revocation must be in force when
// Revoke returns even if the database then refuses the reload.
func TestStoreWriteHoldsWhenTheReloadFails(t *testing.T) {
	db := openDB(t)
	s, err := New(db)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Grant(Member{ProjectPath: "/srv/p", IdentityKey: "bob@corp.example", Role: "viewer"}, nil); err != nil {
		t.Fatal(err)
	}
	// Make the reload after the next write fail: the error handler runs only
	// for failed refreshes, and the patch path is what keeps the write.
	failing := false
	s.onError = func(error) {}
	s.afterWriteHook = func() error {
		if failing {
			return errors.New("injected: the database refused the read")
		}
		return nil
	}
	failing = true
	if _, err := s.Revoke("/srv/p", "bob@corp.example", nil); err != nil {
		t.Fatal(err)
	}
	// Read the snapshot itself: any read through the store would reload, and
	// the reload would hide whether the patch worked.
	if _, ok := s.snap.Load().byPair[pair{"/srv/p", "bob@corp.example"}]; ok {
		t.Fatal("a committed revocation was not in force because the reload after it failed")
	}
	if !s.stale.Load() {
		// The patched snapshot is a guess, so the table is read again next.
		t.Error("a patched snapshot was not marked for a reload")
	}
	failing = false
	if _, ok := s.RoleFor("/srv/p", "bob@corp.example"); ok {
		t.Fatal("the reload after the patch brought the revoked member back")
	}
}

// TestStoreIsSafeForConcurrentUse is for the race detector: readers on the
// authorization path, writers on the REST path, and the watcher's refreshes.
func TestStoreIsSafeForConcurrentUse(t *testing.T) {
	s, err := New(openDB(t), WithTTL(time.Millisecond), WithOnChange(func(Change) {}))
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	stop := make(chan struct{})
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				_, _ = s.RoleFor("/srv/p", "bob@corp.example")
				_ = s.MembersOf("/srv/p")
				_ = s.Any()
			}
		}()
	}
	for i := 0; i < 20; i++ {
		if _, _, err := s.Grant(Member{ProjectPath: "/srv/p", IdentityKey: "bob@corp.example", Role: "viewer"}, nil); err != nil {
			t.Fatal(err)
		}
		if err := s.Refresh(); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Revoke("/srv/p", "bob@corp.example", nil); err != nil {
			t.Fatal(err)
		}
	}
	close(stop)
	wg.Wait()
	if s.Any() {
		t.Error("the last revocation did not hold")
	}
}
