package executorstore

// Enrollment tests against real SQLite.
//
// pkg/executor/remote's own tests run the same flow against an in-memory fake.
// This file matters because the single-use guarantee is not implemented in Go:
// it lives in a conditional UPDATE inside pkg/statedb. A fake store can satisfy
// the contract while the real one does not, so the replay and concurrency
// assertions have to be re-run against the storage that ships.

import (
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor/remote"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	db, err := statedb.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open statedb: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	store, err := New(db)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return store
}

func TestSQLiteMintRedeemAuthenticate(t *testing.T) {
	store := newTestStore(t)

	token, rec, err := remote.Mint(store, remote.MintOptions{
		Name:        "edge-1",
		TTL:         10 * time.Minute,
		WorkDirRoot: "/srv/work",
		Labels:      map[string]string{"region": "eu", "arch": "arm64"},
		CreatedBy:   "oidc|alice",
	})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	// The secret must not be recoverable from storage.
	stored, err := store.GetEnrollment(rec.ID)
	if err != nil {
		t.Fatalf("GetEnrollment: %v", err)
	}
	if strings.Contains(token, stored.SecretHash) {
		t.Error("the stored hash appears in the token: the secret is recoverable from the database")
	}
	if stored.CreatedBy != "oidc|alice" {
		t.Errorf("CreatedBy = %q, want oidc|alice", stored.CreatedBy)
	}
	if stored.Labels["region"] != "eu" {
		t.Errorf("labels did not round-trip: %v", stored.Labels)
	}

	cred, agent, err := remote.Redeem(store, token, remote.RedeemOptions{})
	if err != nil {
		t.Fatalf("Redeem: %v", err)
	}
	if agent.WorkDirRoot != "/srv/work" {
		t.Errorf("workdir root = %q, want /srv/work", agent.WorkDirRoot)
	}
	if agent.Labels["arch"] != "arm64" {
		t.Errorf("labels should carry from token to agent, got %v", agent.Labels)
	}

	got, err := remote.Authenticate(store, cred, time.Now())
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if got.AgentID != agent.AgentID {
		t.Errorf("authenticated as %q, want %q", got.AgentID, agent.AgentID)
	}
	// Authentication should have recorded a last-seen timestamp.
	refreshed, err := store.GetAgent(agent.AgentID)
	if err != nil {
		t.Fatalf("GetAgent: %v", err)
	}
	if refreshed.LastSeen.IsZero() {
		t.Error("Authenticate should record last-seen so operators can spot dormant devices")
	}
}

// TestSQLiteReplayRejected re-runs the anti-replay assertion against the real
// conditional UPDATE.
func TestSQLiteReplayRejected(t *testing.T) {
	store := newTestStore(t)
	token, _, err := remote.Mint(store, remote.MintOptions{Name: "edge-1"})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if _, _, err := remote.Redeem(store, token, remote.RedeemOptions{}); err != nil {
		t.Fatalf("first Redeem: %v", err)
	}
	_, _, err = remote.Redeem(store, token, remote.RedeemOptions{})
	if !errors.Is(err, remote.ErrTokenAlreadyUsed) {
		t.Fatalf("replayed token should give ErrTokenAlreadyUsed, got %v", err)
	}
}

// TestSQLiteConcurrentRedeemOnlyOneWins is the important one: it proves the
// atomicity claim in the schema comment. If RedeemEnrollmentToken were ever
// rewritten as read-then-write, two racing devices would both enroll and this
// test would catch it.
func TestSQLiteConcurrentRedeemOnlyOneWins(t *testing.T) {
	store := newTestStore(t)
	token, _, err := remote.Mint(store, remote.MintOptions{Name: "edge-1"})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	const racers = 8
	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		winners  []string
		failures []error
	)
	start := make(chan struct{})
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, agent, err := remote.Redeem(store, token, remote.RedeemOptions{})
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				failures = append(failures, err)
				return
			}
			winners = append(winners, agent.AgentID)
		}()
	}
	close(start)
	wg.Wait()

	if len(winners) != 1 {
		t.Fatalf("exactly one redemption must win, got %d: %v", len(winners), winners)
	}
	for _, err := range failures {
		if !errors.Is(err, remote.ErrTokenAlreadyUsed) && !errors.Is(err, remote.ErrRevoked) {
			t.Errorf("losing racer got an unexpected error: %v", err)
		}
	}

	// Only the winner's agent record may exist. A second credential row would
	// mean two devices share one enrollment.
	agents, err := store.ListAgents()
	if err != nil {
		t.Fatalf("ListAgents: %v", err)
	}
	if len(agents) != 1 {
		t.Fatalf("expected exactly 1 enrolled agent, got %d", len(agents))
	}
	if agents[0].AgentID != winners[0] {
		t.Errorf("stored agent %q is not the redemption winner %q", agents[0].AgentID, winners[0])
	}
}

func TestSQLiteRevokeCascadesToAgent(t *testing.T) {
	store := newTestStore(t)
	token, rec, err := remote.Mint(store, remote.MintOptions{Name: "edge-1"})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	cred, agent, err := remote.Redeem(store, token, remote.RedeemOptions{})
	if err != nil {
		t.Fatalf("Redeem: %v", err)
	}

	kind, err := remote.Revoke(store, rec.ID, time.Now())
	if err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if kind != "enrollment+agent" {
		t.Errorf("kind = %q, want enrollment+agent", kind)
	}
	if _, err := remote.Authenticate(store, cred, time.Now()); !errors.Is(err, remote.ErrRevoked) {
		t.Fatalf("revoked credential must not authenticate, got %v", err)
	}

	stored, err := store.GetAgent(agent.AgentID)
	if err != nil {
		t.Fatalf("GetAgent: %v", err)
	}
	if !stored.Revoked() {
		t.Error("agent row should carry a revocation timestamp")
	}
	if stored.EnrollmentID != rec.ID {
		t.Errorf("agent should record its minting token %q, got %q", rec.ID, stored.EnrollmentID)
	}
}

func TestSQLiteExpiredTokenRejected(t *testing.T) {
	store := newTestStore(t)
	minted := time.Now()
	token, _, err := remote.Mint(store, remote.MintOptions{
		Name: "edge-1",
		TTL:  time.Minute,
		Now:  func() time.Time { return minted },
	})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	later := minted.Add(5 * time.Minute)
	_, _, err = remote.Redeem(store, token, remote.RedeemOptions{Now: func() time.Time { return later }})
	if !errors.Is(err, remote.ErrTokenExpired) {
		t.Fatalf("expected ErrTokenExpired, got %v", err)
	}
}

func TestSQLiteUnknownIDs(t *testing.T) {
	store := newTestStore(t)

	if _, err := store.GetEnrollment("nope"); !errors.Is(err, remote.ErrTokenInvalid) {
		t.Errorf("unknown enrollment should map to ErrTokenInvalid, got %v", err)
	}
	if _, err := store.GetAgent("nope"); !errors.Is(err, remote.ErrAgentNotFound) {
		t.Errorf("unknown agent should map to ErrAgentNotFound, got %v", err)
	}
	if _, err := remote.Revoke(store, "nope", time.Now()); !errors.Is(err, remote.ErrAgentNotFound) {
		t.Errorf("revoking an unknown ID should map to ErrAgentNotFound, got %v", err)
	}
}

// TestSQLiteRefusesEmptySecretHash guards the "never store a plaintext secret"
// invariant from the other direction: a row with no hash could never
// authenticate, so persisting one silently would produce a device that
// mysteriously cannot connect.
func TestSQLiteRefusesEmptySecretHash(t *testing.T) {
	store := newTestStore(t)

	err := store.PutEnrollment(remote.EnrollmentRecord{ID: "x", Name: "n"})
	if err == nil {
		t.Error("an enrollment with no secret hash must be refused")
	}
	err = store.PutAgent(remote.AgentRecord{AgentID: "x", Name: "n"})
	if err == nil {
		t.Error("an agent with no secret hash must be refused")
	}
}

func TestSQLiteListEnrollments(t *testing.T) {
	store := newTestStore(t)
	for _, name := range []string{"edge-1", "edge-2", "edge-3"} {
		if _, _, err := remote.Mint(store, remote.MintOptions{Name: name}); err != nil {
			t.Fatalf("Mint %s: %v", name, err)
		}
	}
	list, err := store.ListEnrollments()
	if err != nil {
		t.Fatalf("ListEnrollments: %v", err)
	}
	if len(list) != 3 {
		t.Fatalf("expected 3 tokens, got %d", len(list))
	}
	for _, rec := range list {
		if rec.Redeemed() || rec.Revoked() {
			t.Errorf("token %s should be outstanding", rec.ID)
		}
		if rec.ExpiresAt.IsZero() {
			t.Errorf("token %s should have a TTL: unbounded enrollment tokens defeat the design", rec.ID)
		}
	}
}

// TestSQLitePersistsAcrossReopen confirms credentials survive a control-plane
// restart — otherwise every device in a fleet would need re-enrolling after a
// deploy.
func TestSQLitePersistsAcrossReopen(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.db")

	db, err := statedb.Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	store, err := New(db)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	token, _, err := remote.Mint(store, remote.MintOptions{Name: "edge-1"})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	cred, agent, err := remote.Redeem(store, token, remote.RedeemOptions{})
	if err != nil {
		t.Fatalf("Redeem: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	reopened, err := statedb.Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer reopened.Close()
	store2, err := New(reopened)
	if err != nil {
		t.Fatalf("New after reopen: %v", err)
	}

	got, err := remote.Authenticate(store2, cred, time.Now())
	if err != nil {
		t.Fatalf("credential should still authenticate after a restart: %v", err)
	}
	if got.AgentID != agent.AgentID {
		t.Errorf("agent ID = %q, want %q", got.AgentID, agent.AgentID)
	}
}
