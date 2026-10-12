package secretstore_test

// Changing CLOOP_SECRET_KEY itself, against a real database (Task 20425): the
// roots a keyring holds, the attribution migration 0073 records, and the
// change made online — under concurrent reads and writes of every population
// sealed under the root: brokered secrets, session refresh tokens, and the
// private key of the hub's own CA.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/hubca"
	"github.com/blechschmidt/cloop/pkg/oidcauth"
	"github.com/blechschmidt/cloop/pkg/rootkey"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/secretstore"
	"github.com/blechschmidt/cloop/pkg/sessionstore"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

const (
	rootBefore = "root-change-old-key-0123456789abcdefghij"
	rootAfter  = "root-change-new-key-KLMNOPQRSTUVWXYZ9876"
)

// member is one hub process over the shared database: its keyring, the broker
// and the session store it serves with, and a rotator over every sealed set.
type member struct {
	store    *secretstore.Store
	keyring  *secretbroker.Keyring
	broker   *secretbroker.Broker
	sessions *sessionstore.Store
	ca       *hubca.Store
	rotator  *secretbroker.Rotator
}

// startMember opens db the way a hub started with these roots would, or
// returns the error it would refuse to start with.
func startMember(db *statedb.DB, current, previous string) (*member, error) {
	store, err := secretstore.New(db)
	if err != nil {
		return nil, err
	}
	kr, err := secretbroker.OpenKeyring(store, secretbroker.WithKeyringRoots(current, previous),
		secretbroker.WithKeyringActor("test"))
	if err != nil {
		return nil, err
	}
	b, err := secretbroker.New(store, secretbroker.WithKeyring(kr), secretbroker.WithAuditor(secretstore.NewAuditor(db)))
	if err != nil {
		return nil, err
	}
	sessions, err := sessionstore.New(db)
	if err != nil {
		return nil, err
	}
	sessions.WithKeyring(kr)
	ca, err := hubca.NewStore(db)
	if err != nil {
		return nil, err
	}
	rot, err := secretbroker.NewRotator(kr, store, sessions, ca)
	if err != nil {
		return nil, err
	}
	rot.WithHistory(store)
	return &member{store: store, keyring: kr, broker: b, sessions: sessions, ca: ca, rotator: rot}, nil
}

func mustStart(t *testing.T, db *statedb.DB, current, previous string) *member {
	t.Helper()
	m, err := startMember(db, current, previous)
	if err != nil {
		t.Fatalf("start a member: %v", err)
	}
	return m
}

func (m *member) openSecret(id string) (string, error) {
	sec, err := m.store.GetSecret(id)
	if err != nil {
		return "", err
	}
	plain, err := m.keyring.OpenEnvelope(secretbroker.AADFor(secretbroker.SetSecrets, sec.ID), sec.Envelope())
	return string(plain), err
}

func sessionRecord(id, token string) oidcauth.SessionRecord {
	now := time.Now()
	return oidcauth.SessionRecord{
		ID:           id,
		Identity:     oidcauth.Identity{Sub: "sub-" + id, Email: id + "@example.com"},
		IssuedAt:     now,
		LastSeen:     now,
		ExpiresAt:    now.Add(time.Hour),
		RefreshToken: token,
	}
}

// truth is what every sealed row must open to, kept current by the writers.
type truth struct {
	mu       sync.Mutex
	secrets  map[string]string
	sessions map[string]string
}

func (w *truth) setSecret(id, v string) {
	w.mu.Lock()
	w.secrets[id] = v
	w.mu.Unlock()
}

func (w *truth) setSession(id, v string) {
	w.mu.Lock()
	w.sessions[id] = v
	w.mu.Unlock()
}

// The whole online procedure under load: two members restarted with the new
// root beside the old serve reads and writes of secrets and session refresh
// tokens while one of them retires the previous root; then a member started
// without the previous root opens every secret, every refresh token and the
// hub CA's key, and a member holding only the old root refuses to start.
func TestRootChangeUnderConcurrentLoad(t *testing.T) {
	db, _ := openTestDB(t)

	// The hub as it ran before: everything sealed under the old root.
	before := mustStart(t, db, rootBefore, "")
	if _, err := before.keyring.AddKey("test"); err != nil {
		t.Fatal(err)
	}
	authority, err := hubca.OpenAuthority(before.ca, before.keyring, hubca.Options{Actor: "test"})
	if err != nil {
		t.Fatalf("mint the hub CA: %v", err)
	}
	caSerial := authority.Serial()
	w := &truth{secrets: map[string]string{}, sessions: map[string]string{}}
	var secretIDs, sessionIDs []string
	for i := 0; i < 16; i++ {
		v := fmt.Sprintf("SECRET_%02d=before", i)
		s, err := before.broker.Mint(context.Background(), secretbroker.MintRequest{
			Name: fmt.Sprintf("load-%02d", i), Kind: secretbroker.KindEnv, Payload: []byte(v), Actor: "test"})
		if err != nil {
			t.Fatal(err)
		}
		secretIDs = append(secretIDs, s.ID)
		w.setSecret(s.ID, v)

		id := fmt.Sprintf("sess_root_%02d", i)
		token := fmt.Sprintf("rt_before_%02d_0123456789", i)
		if err := before.sessions.Put(sessionRecord(id, token)); err != nil {
			t.Fatal(err)
		}
		sessionIDs = append(sessionIDs, id)
		w.setSession(id, token)
	}

	// The rolling restart: both members now hold the new root, the old one
	// beside it.
	a := mustStart(t, db, rootAfter, rootBefore)
	b := mustStart(t, db, rootAfter, rootBefore)

	var (
		wg    sync.WaitGroup
		stop  = make(chan struct{})
		errCh = make(chan error, 64)
	)
	report := func(err error) {
		select {
		case errCh <- err:
		default:
		}
	}
	for _, m := range []*member{a, b} {
		m := m
		// Readers: every row opens, all the time, on either member.
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				for _, id := range secretIDs {
					if _, err := m.openSecret(id); err != nil {
						report(fmt.Errorf("read secret %s during the change: %w", id, err))
						return
					}
				}
				for _, id := range sessionIDs {
					rec, err := m.sessions.Get(id)
					if err != nil || rec.RefreshToken == "" {
						report(fmt.Errorf("read session %s during the change: token %q, %v", id, rec.RefreshToken, err))
						return
					}
				}
			}
		}()
	}
	// Writers: one re-mints secrets, the other refreshes sessions, both under
	// whatever the primary is at that instant.
	wg.Add(2)
	go func() {
		defer wg.Done()
		for round := 0; ; round++ {
			select {
			case <-stop:
				return
			default:
			}
			id := secretIDs[round%len(secretIDs)]
			v := fmt.Sprintf("SECRET=rewritten-%d", round)
			env, err := a.keyring.SealFor(secretbroker.AADFor(secretbroker.SetSecrets, id), []byte(v))
			if err != nil {
				report(fmt.Errorf("seal during the change: %w", err))
				return
			}
			sec, err := a.store.GetSecret(id)
			if err != nil {
				continue
			}
			if err := a.store.PutSecret(sec.WithEnvelope(env)); err != nil {
				continue
			}
			w.setSecret(id, v)
		}
	}()
	go func() {
		defer wg.Done()
		for round := 0; ; round++ {
			select {
			case <-stop:
				return
			default:
			}
			id := sessionIDs[round%len(sessionIDs)]
			token := fmt.Sprintf("rt_rotated_%d_%s", round, id)
			if err := b.sessions.ApplyRefresh(id, oidcauth.RefreshResult{RefreshToken: token, CheckedAt: time.Now()}); err != nil {
				report(fmt.Errorf("refresh %s during the change: %w", id, err))
				return
			}
			w.setSession(id, token)
		}
	}()

	// Retire the previous root while all of that runs. A writer that read the
	// old primary a moment before the new one was promoted can still land a
	// row under an old key, which the retirement refuses and the next run
	// moves: that is what re-running is for.
	a.rotator.WithBatch(3)
	var rep secretbroker.RetirePreviousReport
	for attempt := 1; ; attempt++ {
		rep, err = a.rotator.RetirePrevious(context.Background(), secretbroker.RetirePreviousOptions{Actor: "test"})
		if err == nil {
			break
		}
		if attempt == 4 || !(errors.Is(err, secretbroker.ErrKeyInUse) || errors.Is(err, secretbroker.ErrRotationFailed)) {
			t.Fatalf("retire the previous root under load (attempt %d): %v", attempt, err)
		}
	}
	time.Sleep(50 * time.Millisecond) // let the writers land a few under the new root
	close(stop)
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Error(err)
	}
	if !rep.Complete || len(rep.Keys) != 2 {
		t.Fatalf("report %+v, want complete with the old root's two keys retired", rep)
	}

	// Restart without the previous root: everything opens.
	after := mustStart(t, db, rootAfter, "")
	w.mu.Lock()
	defer w.mu.Unlock()
	for id, want := range w.secrets {
		if got, err := after.openSecret(id); err != nil || got != want {
			t.Errorf("secret %s after the change: %q, %v; want %q", id, got, err, want)
		}
	}
	for id, want := range w.sessions {
		rec, err := after.sessions.Get(id)
		if err != nil || rec.RefreshToken != want {
			t.Errorf("session %s after the change: token %q, %v; want %q", id, rec.RefreshToken, err, want)
		}
	}
	reopened, err := hubca.OpenAuthority(after.ca, after.keyring, hubca.Options{Actor: "test"})
	if err != nil {
		t.Fatalf("the hub CA's key after the change: %v", err)
	}
	if reopened.Serial() != caSerial {
		t.Errorf("the hub CA changed: serial %s, was %s", reopened.Serial(), caSerial)
	}
	counts, _ := after.ca.CountSealedByKey()
	if counts[after.keyring.PrimaryID()] == 0 {
		t.Errorf("the hub CA's key is not under the new root's key: %v", counts)
	}

	// And a member holding only the old root refuses to start rather than
	// mint a registry of its own.
	if _, err := startMember(db, rootBefore, ""); !errors.Is(err, secretbroker.ErrKeyUnavailable) {
		t.Errorf("a member on the old root alone after the change: %v", err)
	}
}

// A member still serving on the old root alone when the change was finished
// loses nothing (Task 20425). The retire step refuses while it advertises the
// old root, but a member can start inside that window. It cannot open a
// session's refresh token sealed under the new root — and the update it makes
// after a renewal must not write its "" over the token as if there were none,
// which is what sessionstore did: the member that can open it, and this one
// once restarted, still find it. Its sign-ins fail loudly instead of sealing
// under a key nobody else holds.
func TestAMemberWithoutTheNewRootDropsNoRefreshToken(t *testing.T) {
	db, _ := openTestDB(t)
	const token = "rt_the_only_copy_0123456789"
	before := mustStart(t, db, rootBefore, "")
	if err := before.sessions.Put(sessionRecord("sess_kept", token)); err != nil {
		t.Fatal(err)
	}
	stale := mustStart(t, db, rootBefore, "") // started before the change, still serving

	changer := mustStart(t, db, rootAfter, rootBefore)
	if _, err := changer.rotator.RetirePrevious(context.Background(), secretbroker.RetirePreviousOptions{}); err != nil {
		t.Fatal(err)
	}

	rec, err := stale.sessions.Get("sess_kept")
	if err != nil {
		t.Fatal(err)
	}
	if rec.RefreshToken != "" {
		t.Fatalf("the stale member opened a token sealed under a root it does not hold: %q", rec.RefreshToken)
	}
	// A browser renewal on the stale member: the result carries the token the
	// record held — none, as far as this member can tell — and new claims.
	if err := stale.sessions.ApplyRefresh("sess_kept", oidcauth.RefreshResult{
		RefreshToken: rec.RefreshToken, CheckedAt: rec.RefreshCheckedAt,
		ClaimsAsserted: true, Groups: []string{"g"}, ClaimsAsOf: time.Now(),
	}); err != nil {
		t.Fatalf("apply the renewal: %v", err)
	}
	after := mustStart(t, db, rootAfter, "")
	got, err := after.sessions.Get("sess_kept")
	if err != nil || got.RefreshToken != token {
		t.Fatalf("after the stale member's update the token is %q (%v), want %q — it was dropped", got.RefreshToken, err, token)
	}
	if len(got.Identity.Groups) != 1 {
		t.Errorf("the renewal's claims were not written: %v", got.Identity.Groups)
	}

	// Its sign-ins fail, loudly, rather than sealing under a key no member
	// that holds the new root could open.
	if err := stale.sessions.Put(sessionRecord("sess_new", "rt_new")); !errors.Is(err, secretbroker.ErrKeyUnavailable) {
		t.Errorf("a sign-in on the stale member: %v, want ErrKeyUnavailable", err)
	}
}

// Keys minted before migration 0073 have no recorded root. The first process
// whose root derives them writes it, once; a recorded root is never rewritten
// by a process holding another.
func TestUnattributedKeysAreAttributedOnceByTrialDerivation(t *testing.T) {
	db, path := openTestDB(t)
	before := mustStart(t, db, rootBefore, "")
	if _, err := before.keyring.AddKey("test"); err != nil {
		t.Fatal(err)
	}
	// As a hub before migration 0073 left them.
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`UPDATE broker_keks SET root = ''`); err != nil {
		t.Fatal(err)
	}
	_ = raw.Close()

	mustStart(t, db, rootAfter, rootBefore) // the previous root derives them
	oldFP, _ := rootkey.Fingerprint(rootBefore)
	keks, err := db.ListKEKs()
	if err != nil {
		t.Fatal(err)
	}
	if len(keks) != 2 {
		t.Fatalf("%d keys", len(keks))
	}
	for _, k := range keks {
		if k.Root != oldFP {
			t.Errorf("key %s attributed to %q, want the old root %s", k.ID, k.Root, oldFP)
		}
	}
	// SetKEKRoot writes only an unattributed key.
	if ok, err := db.SetKEKRoot(keks[0].ID, "0000000000000000"); err != nil || ok {
		t.Errorf("rewriting a recorded root: %v, %v", ok, err)
	}
	// And a put that carries no root leaves the recorded one alone.
	k := keks[0]
	k.Root = ""
	if err := db.PutKEK(k); err != nil {
		t.Fatal(err)
	}
	keks, _ = db.ListKEKs()
	for _, kk := range keks {
		if kk.ID == k.ID && kk.Root != oldFP {
			t.Errorf("a put without a root blanked the recorded one: %q", kk.Root)
		}
	}
}
