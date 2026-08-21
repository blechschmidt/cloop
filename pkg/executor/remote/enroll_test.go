package remote_test

// Enrollment tests: minting, redemption, replay rejection, expiry, revocation.
//
// These cover the security boundary of the whole remote-executor feature. An
// enrollment token is the secret that gets pasted into terminals and
// provisioning scripts, so the properties asserted here — single-use, TTL
// bounded, revocable, never stored in plaintext — are what limit the damage
// when one leaks.

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor/remote"
)

func TestMintAndRedeem(t *testing.T) {
	store := newMemStore()

	token, rec, err := remote.Mint(store, remote.MintOptions{
		Name:        "edge-1",
		TTL:         15 * time.Minute,
		WorkDirRoot: "/srv/work",
	})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if rec.Name != "edge-1" {
		t.Errorf("name = %q, want edge-1", rec.Name)
	}
	if !strings.HasPrefix(token, "clet1.") {
		t.Errorf("token %q should carry the enrollment prefix", token)
	}

	// The secret must never be recoverable from storage. Only its hash is
	// kept, and the hash must not be the secret itself.
	stored, err := store.GetEnrollment(rec.ID)
	if err != nil {
		t.Fatalf("GetEnrollment: %v", err)
	}
	if stored.SecretHash == "" {
		t.Fatal("stored record has no secret hash")
	}
	if strings.Contains(token, stored.SecretHash) {
		t.Error("the stored hash appears inside the token: the secret is being stored in recoverable form")
	}

	cred, agent, err := remote.Redeem(store, token, remote.RedeemOptions{})
	if err != nil {
		t.Fatalf("Redeem: %v", err)
	}
	if !strings.HasPrefix(cred, "clac1.") {
		t.Errorf("credential %q should carry the credential prefix", cred)
	}
	if agent.Name != "edge-1" {
		t.Errorf("agent name = %q, want edge-1", agent.Name)
	}
	if agent.WorkDirRoot != "/srv/work" {
		t.Errorf("workdir root = %q, want /srv/work; enrollment policy must carry to the agent", agent.WorkDirRoot)
	}
	if agent.EnrollmentID != rec.ID {
		t.Errorf("agent should record the token that minted it, got %q", agent.EnrollmentID)
	}

	// The issued credential must authenticate.
	got, err := remote.Authenticate(store, cred, time.Now())
	if err != nil {
		t.Fatalf("Authenticate with the issued credential: %v", err)
	}
	if got.AgentID != agent.AgentID {
		t.Errorf("authenticated as %q, want %q", got.AgentID, agent.AgentID)
	}
}

// TestRedeemReplayRejected is the core anti-replay assertion: a captured token
// cannot be used twice. Without this, a token leaked through shell history or
// a chat log would let an attacker enroll a second device sharing the
// legitimate one's identity.
func TestRedeemReplayRejected(t *testing.T) {
	store := newMemStore()
	token, _, err := remote.Mint(store, remote.MintOptions{Name: "edge-1"})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	if _, _, err := remote.Redeem(store, token, remote.RedeemOptions{}); err != nil {
		t.Fatalf("first Redeem should succeed: %v", err)
	}

	_, _, err = remote.Redeem(store, token, remote.RedeemOptions{})
	if err == nil {
		t.Fatal("replaying an enrollment token must fail")
	}
	if !errors.Is(err, remote.ErrTokenAlreadyUsed) {
		t.Fatalf("replay should report ErrTokenAlreadyUsed so an operator can tell a leak from a typo; got %v", err)
	}
}

// TestConcurrentRedeemOnlyOneWins covers the race a leaked token creates: the
// attacker and the real device redeem simultaneously. Exactly one must win,
// and the loser must be told the token is spent rather than both silently
// receiving credentials for the same identity.
func TestConcurrentRedeemOnlyOneWins(t *testing.T) {
	store := newMemStore()
	token, _, err := remote.Mint(store, remote.MintOptions{Name: "edge-1"})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	const racers = 8
	var (
		wg        sync.WaitGroup
		mu        sync.Mutex
		succeeded []string
		failures  []error
	)
	start := make(chan struct{})
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			cred, agent, err := remote.Redeem(store, token, remote.RedeemOptions{})
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				failures = append(failures, err)
				return
			}
			succeeded = append(succeeded, agent.AgentID+":"+cred)
		}()
	}
	close(start)
	wg.Wait()

	if len(succeeded) != 1 {
		t.Fatalf("exactly one redemption must succeed, got %d", len(succeeded))
	}
	if len(failures) != racers-1 {
		t.Fatalf("expected %d failures, got %d", racers-1, len(failures))
	}
	for _, err := range failures {
		if !errors.Is(err, remote.ErrTokenAlreadyUsed) {
			t.Errorf("losing racer should get ErrTokenAlreadyUsed, got %v", err)
		}
	}
}

func TestRedeemExpiredToken(t *testing.T) {
	store := newMemStore()
	minted := time.Now()
	token, _, err := remote.Mint(store, remote.MintOptions{
		Name: "edge-1",
		TTL:  time.Minute,
		Now:  func() time.Time { return minted },
	})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	// Redeem two minutes later, past the one-minute TTL.
	later := minted.Add(2 * time.Minute)
	_, _, err = remote.Redeem(store, token, remote.RedeemOptions{Now: func() time.Time { return later }})
	if !errors.Is(err, remote.ErrTokenExpired) {
		t.Fatalf("expected ErrTokenExpired, got %v", err)
	}
}

func TestRedeemRevokedToken(t *testing.T) {
	store := newMemStore()
	token, rec, err := remote.Mint(store, remote.MintOptions{Name: "edge-1"})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if _, err := remote.Revoke(store, rec.ID, time.Now()); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	_, _, err = remote.Redeem(store, token, remote.RedeemOptions{})
	if !errors.Is(err, remote.ErrRevoked) {
		t.Fatalf("expected ErrRevoked, got %v", err)
	}
}

// TestRevokingTokenAlsoRevokesItsAgent covers the leak-after-redemption case:
// if an attacker redeemed a leaked token before the operator noticed, revoking
// the token must also kill the credential it produced. Revoking only the
// spent token would leave the attacker's access untouched.
func TestRevokingTokenAlsoRevokesItsAgent(t *testing.T) {
	store := newMemStore()
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
		t.Errorf("revoking a redeemed token should report enrollment+agent, got %q", kind)
	}

	if _, err := remote.Authenticate(store, cred, time.Now()); !errors.Is(err, remote.ErrRevoked) {
		t.Fatalf("the credential minted by a revoked token must stop authenticating; got %v", err)
	}
	stored, _ := store.GetAgent(agent.AgentID)
	if !stored.Revoked() {
		t.Error("agent record should be marked revoked")
	}
}

func TestRevokeAgentDirectly(t *testing.T) {
	store := newMemStore()
	token, _, err := remote.Mint(store, remote.MintOptions{Name: "edge-1"})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	cred, agent, err := remote.Redeem(store, token, remote.RedeemOptions{})
	if err != nil {
		t.Fatalf("Redeem: %v", err)
	}

	kind, err := remote.Revoke(store, agent.AgentID, time.Now())
	if err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if kind != "agent" {
		t.Errorf("kind = %q, want agent", kind)
	}
	if _, err := remote.Authenticate(store, cred, time.Now()); !errors.Is(err, remote.ErrRevoked) {
		t.Fatalf("expected ErrRevoked, got %v", err)
	}
}

// TestTamperedTokenRejected checks the MAC path: a token whose secret was
// altered must be rejected without the store ever being consulted.
func TestTamperedTokenRejected(t *testing.T) {
	store := newMemStore()
	token, _, err := remote.Mint(store, remote.MintOptions{Name: "edge-1"})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	parts := strings.Split(token, ".")
	if len(parts) != 4 {
		t.Fatalf("token should have 4 segments, got %d", len(parts))
	}
	// Flip a character in the secret segment.
	secret := []byte(parts[2])
	if secret[0] == 'A' {
		secret[0] = 'B'
	} else {
		secret[0] = 'A'
	}
	parts[2] = string(secret)
	tampered := strings.Join(parts, ".")

	if _, _, err := remote.Redeem(store, tampered, remote.RedeemOptions{}); !errors.Is(err, remote.ErrTokenInvalid) {
		t.Fatalf("a tampered token must be rejected as invalid, got %v", err)
	}

	// The real token must still work: rejecting the tamper must not have
	// consumed the legitimate token.
	if _, _, err := remote.Redeem(store, token, remote.RedeemOptions{}); err != nil {
		t.Fatalf("the genuine token should still redeem after a failed tamper: %v", err)
	}
}

// TestWrongTokenTypeRejected ensures an agent credential cannot be presented
// where an enrollment token belongs, and vice versa. The distinct prefixes
// exist to make that a clear error rather than a confusing hash mismatch.
func TestWrongTokenTypeRejected(t *testing.T) {
	store := newMemStore()
	token, _, err := remote.Mint(store, remote.MintOptions{Name: "edge-1"})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	cred, _, err := remote.Redeem(store, token, remote.RedeemOptions{})
	if err != nil {
		t.Fatalf("Redeem: %v", err)
	}

	if _, _, err := remote.Redeem(store, cred, remote.RedeemOptions{}); !errors.Is(err, remote.ErrTokenInvalid) {
		t.Errorf("redeeming a credential as an enrollment token should fail, got %v", err)
	}
	if _, err := remote.Authenticate(store, token, time.Now()); !errors.Is(err, remote.ErrCredentialInvalid) {
		t.Errorf("authenticating with an enrollment token should fail, got %v", err)
	}
}

func TestMintRejectsExcessiveTTL(t *testing.T) {
	store := newMemStore()
	_, _, err := remote.Mint(store, remote.MintOptions{Name: "edge-1", TTL: 30 * 24 * time.Hour})
	if err == nil {
		t.Fatal("a month-long enrollment TTL must be rejected, not silently clamped")
	}
	if !strings.Contains(err.Error(), "short-lived") {
		t.Errorf("error should explain why long TTLs are refused, got %v", err)
	}
}

func TestMintRequiresName(t *testing.T) {
	store := newMemStore()
	if _, _, err := remote.Mint(store, remote.MintOptions{}); err == nil {
		t.Fatal("minting without a name must fail")
	}
}

func TestAuthenticateUnknownAgent(t *testing.T) {
	store := newMemStore()
	// A well-formed but unissued credential: correct prefix and MAC would not
	// verify, so this exercises the invalid-format path.
	if _, err := remote.Authenticate(store, "clac1.abc.def.0123456789abcdef", time.Now()); err == nil {
		t.Fatal("authenticating an unknown credential must fail")
	}
}
