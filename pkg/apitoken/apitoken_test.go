package apitoken

// Unit tests for minting, verification, expiry, revocation, the constant-time
// comparison, and the anti-escalation rule.
//
// These run against a memory store so they exercise the crypto and the policy
// without a SQLite file; pkg/statedb has its own round-trip coverage, and
// pkg/ui/tokens_api_test.go covers the wiring end to end.

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/authz"
)

// memStore is an in-memory Store.
type memStore struct {
	mu      sync.Mutex
	tokens  map[string]Token
	touched map[string]time.Time
	putErr  error
}

func newMemStore() *memStore {
	return &memStore{tokens: map[string]Token{}, touched: map[string]time.Time{}}
}

func (m *memStore) Put(t Token) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.putErr != nil {
		return m.putErr
	}
	if _, dup := m.tokens[t.ID]; dup {
		return fmt.Errorf("duplicate id %q", t.ID)
	}
	m.tokens[t.ID] = t
	return nil
}

func (m *memStore) Get(id string) (Token, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.tokens[id]
	if !ok {
		return Token{}, fmt.Errorf("%w: %q", ErrNotFound, id)
	}
	return t, nil
}

func (m *memStore) List() ([]Token, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Token, 0, len(m.tokens))
	for _, t := range m.tokens {
		out = append(out, t)
	}
	return out, nil
}

func (m *memStore) Revoke(id string, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.tokens[id]
	if !ok {
		return fmt.Errorf("%w: %q", ErrNotFound, id)
	}
	if t.RevokedAt.IsZero() {
		t.RevokedAt = at
		m.tokens[id] = t
	}
	return nil
}

func (m *memStore) Touch(id string, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.touched[id] = at
	return nil
}

func (m *memStore) touchedAt(id string) (time.Time, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.touched[id]
	return t, ok
}

func newTestManager(t *testing.T) (*Manager, *memStore) {
	t.Helper()
	store := newMemStore()
	mgr, err := NewManager(store)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	return mgr, store
}

// ---------------------------------------------------------------------------
// mint
// ---------------------------------------------------------------------------

func TestMintProducesAVerifiableToken(t *testing.T) {
	mgr, _ := newTestManager(t)

	minted, err := mgr.Mint(MintOptions{Name: "ci", Roles: []string{"operator"}})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if !strings.HasPrefix(minted.Plaintext, Prefix) {
		t.Errorf("plaintext %q does not start with %q", minted.Plaintext, Prefix)
	}
	if minted.Token.Prefix != Prefix+minted.Token.ID {
		t.Errorf("Prefix = %q, want %q", minted.Token.Prefix, Prefix+minted.Token.ID)
	}

	got, err := mgr.Verify(minted.Plaintext)
	if err != nil {
		t.Fatalf("Verify freshly minted token: %v", err)
	}
	if got.ID != minted.Token.ID {
		t.Errorf("verified id = %q, want %q", got.ID, minted.Token.ID)
	}
}

// TestMintNeverStoresThePlaintext is the core non-disclosure property: the
// persisted record must not contain the secret in any field, in any form.
func TestMintNeverStoresThePlaintext(t *testing.T) {
	mgr, store := newTestManager(t)

	minted, err := mgr.Mint(MintOptions{Name: "ci", Roles: []string{"viewer"}})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	_, secret, ok := Parse(minted.Plaintext)
	if !ok {
		t.Fatal("minted plaintext does not parse")
	}

	stored, err := store.Get(minted.Token.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	blob := fmt.Sprintf("%#v", stored)
	if strings.Contains(blob, secret) {
		t.Fatal("the stored record contains the token secret — it must hold only a hash")
	}
	if strings.Contains(blob, minted.Plaintext) {
		t.Fatal("the stored record contains the full token string")
	}
	if !strings.HasPrefix(stored.Hash, "hmac-sha256$") {
		t.Errorf("Hash = %q, want the algorithm-tagged form", stored.Hash)
	}
}

// TestMintDrawsFreshEntropyEveryTime guards against a mistake that would be
// invisible in every other test: two tokens sharing an id or a secret.
func TestMintDrawsFreshEntropyEveryTime(t *testing.T) {
	mgr, _ := newTestManager(t)

	ids := map[string]bool{}
	secrets := map[string]bool{}
	hashes := map[string]bool{}
	for i := 0; i < 50; i++ {
		m, err := mgr.Mint(MintOptions{Name: fmt.Sprintf("t%d", i), Roles: []string{"viewer"}})
		if err != nil {
			t.Fatalf("Mint %d: %v", i, err)
		}
		id, secret, _ := Parse(m.Plaintext)
		if ids[id] {
			t.Fatalf("duplicate token id %q at iteration %d", id, i)
		}
		if secrets[secret] {
			t.Fatalf("duplicate token secret at iteration %d", i)
		}
		if hashes[m.Token.Hash] {
			t.Fatalf("duplicate stored hash at iteration %d — the salt is not per-token", i)
		}
		ids[id], secrets[secret], hashes[m.Token.Hash] = true, true, true
	}
}

func TestMintRejectsBadInput(t *testing.T) {
	cases := []struct {
		name string
		opts MintOptions
		want string
	}{
		{"no name", MintOptions{Roles: []string{"viewer"}}, "name is required"},
		{"long name", MintOptions{Name: strings.Repeat("x", MaxNameLen+1), Roles: []string{"viewer"}}, "longer than"},
		{"no roles", MintOptions{Name: "x"}, "at least one role"},
		{"unknown role", MintOptions{Name: "x", Roles: []string{"superuser"}}, "not a known role"},
		{"role none", MintOptions{Name: "x", Roles: []string{"none"}}, "grants nothing"},
		{
			"past expiry",
			MintOptions{Name: "x", Roles: []string{"viewer"}, ExpiresAt: time.Now().Add(-time.Hour)},
			"in the past",
		},
		{
			"scope too large",
			MintOptions{Name: "x", Roles: []string{"viewer"}, ProjectScope: manyProjects(MaxProjectScope + 1)},
			"the limit is",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Mint(tc.opts); err == nil {
				t.Fatal("expected an error, got nil")
			} else if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want it to mention %q", err, tc.want)
			}
		})
	}
}

func manyProjects(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("project-%d", i)
	}
	return out
}

// ---------------------------------------------------------------------------
// verify
// ---------------------------------------------------------------------------

func TestVerifyRejectsMalformedInput(t *testing.T) {
	mgr, _ := newTestManager(t)
	minted, err := mgr.Mint(MintOptions{Name: "ci", Roles: []string{"viewer"}})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	id, secret, _ := Parse(minted.Plaintext)

	cases := []struct {
		name string
		raw  string
		want error
	}{
		{"empty", "", ErrMalformed},
		{"no prefix", id + "_" + secret, ErrMalformed},
		{"wrong prefix", "github_pat_" + id + "_" + secret, ErrMalformed},
		{"no separator", Prefix + id + secret, ErrMalformed},
		{"truncated secret", Prefix + id + "_" + secret[:10], ErrMalformed},
		{"uppercase hex", Prefix + id + "_" + strings.ToUpper(secret), ErrMalformed},
		{"non-hex secret", Prefix + id + "_" + strings.Repeat("z", len(secret)), ErrMalformed},
		{"unknown id", Prefix + strings.Repeat("0", len(id)) + "_" + secret, ErrNotFound},
		{"wrong secret", Prefix + id + "_" + flipFirstHexDigit(secret), ErrBadSecret},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := mgr.Verify(tc.raw); !errors.Is(err, tc.want) {
				t.Errorf("Verify(%q) error = %v, want %v", tc.raw, err, tc.want)
			}
		})
	}
}

// TestVerifyRejectsExpired covers the whole expiry boundary: before, exactly
// at, and after. "Exactly at" must be a rejection — an expiry that is still
// valid at its own timestamp is an off-by-one nobody notices until an audit.
func TestVerifyRejectsExpired(t *testing.T) {
	mgr, _ := newTestManager(t)
	base := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	mgr.SetClock(func() time.Time { return base })

	minted, err := mgr.Mint(MintOptions{
		Name: "ci", Roles: []string{"viewer"},
		ExpiresAt: base.Add(time.Hour), Now: base,
	})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	mgr.SetClock(func() time.Time { return base.Add(59 * time.Minute) })
	if _, err := mgr.Verify(minted.Plaintext); err != nil {
		t.Fatalf("token should still be valid one minute before expiry: %v", err)
	}

	mgr.SetClock(func() time.Time { return base.Add(time.Hour) })
	if _, err := mgr.Verify(minted.Plaintext); !errors.Is(err, ErrExpired) {
		t.Errorf("at the expiry instant: error = %v, want ErrExpired", err)
	}

	mgr.SetClock(func() time.Time { return base.Add(2 * time.Hour) })
	if _, err := mgr.Verify(minted.Plaintext); !errors.Is(err, ErrExpired) {
		t.Errorf("after expiry: error = %v, want ErrExpired", err)
	}
}

func TestVerifyRejectsRevoked(t *testing.T) {
	mgr, _ := newTestManager(t)
	minted, err := mgr.Mint(MintOptions{Name: "ci", Roles: []string{"operator"}})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if _, err := mgr.Verify(minted.Plaintext); err != nil {
		t.Fatalf("token should verify before revocation: %v", err)
	}

	if err := mgr.Revoke(minted.Token.ID); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if _, err := mgr.Verify(minted.Plaintext); !errors.Is(err, ErrRevoked) {
		t.Errorf("after revocation: error = %v, want ErrRevoked", err)
	}
	// Idempotent.
	if err := mgr.Revoke(minted.Token.ID); err != nil {
		t.Errorf("second Revoke should be a no-op success, got %v", err)
	}
	if err := mgr.Revoke("does-not-exist"); !errors.Is(err, ErrNotFound) {
		t.Errorf("revoking an unknown id = %v, want ErrNotFound", err)
	}
}

// TestVerifyChecksSecretBeforeLifecycle pins the ordering that keeps the error
// from being an oracle: a caller with the *wrong* secret is told ErrBadSecret
// whether or not the token is also revoked or expired, so they cannot use the
// distinction to confirm a guessed token id is real.
func TestVerifyChecksSecretBeforeLifecycle(t *testing.T) {
	mgr, _ := newTestManager(t)
	base := time.Now()
	mgr.SetClock(func() time.Time { return base })

	minted, err := mgr.Mint(MintOptions{Name: "ci", Roles: []string{"viewer"}, Now: base})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if err := mgr.Revoke(minted.Token.ID); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	id, secret, _ := Parse(minted.Plaintext)
	wrong := Prefix + id + "_" + flipFirstHexDigit(secret)
	if _, err := mgr.Verify(wrong); !errors.Is(err, ErrBadSecret) {
		t.Fatalf("wrong secret on a revoked token = %v, want ErrBadSecret "+
			"(revocation must not be observable without the secret)", err)
	}
}

// TestVerifyRejectsATokenWithNoUsableRole covers a row written by a future
// binary whose role names this one does not know. It must fail closed rather
// than authenticate into an empty permission set.
func TestVerifyRejectsATokenWithNoUsableRole(t *testing.T) {
	mgr, store := newTestManager(t)
	minted, err := mgr.Mint(MintOptions{Name: "ci", Roles: []string{"viewer"}})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	store.mu.Lock()
	tok := store.tokens[minted.Token.ID]
	tok.Roles = []string{"archon"} // a role from a future ladder
	store.tokens[minted.Token.ID] = tok
	store.mu.Unlock()

	if _, err := mgr.Verify(minted.Plaintext); !errors.Is(err, ErrNoRoles) {
		t.Errorf("error = %v, want ErrNoRoles", err)
	}
}

// ---------------------------------------------------------------------------
// hashing
// ---------------------------------------------------------------------------

func TestVerifyHashIsConstantTimeAndSaltBound(t *testing.T) {
	salt := []byte("0123456789abcdef")
	encoded := hashSecret("s3cr3t", salt)

	if !VerifyHash(encoded, "s3cr3t") {
		t.Fatal("the correct secret did not verify")
	}
	if VerifyHash(encoded, "s3cr3u") {
		t.Error("a wrong secret verified")
	}
	// A different salt over the same secret must not collide: that is what
	// makes one precomputed table useless against the whole column.
	other := hashSecret("s3cr3t", []byte("fedcba9876543210"))
	if other == encoded {
		t.Error("two salts produced the same digest — the salt is not mixed in")
	}
	if VerifyHash(other, "s3cr3t") != true {
		t.Error("the same secret under a different salt should verify against its own record")
	}

	for _, bad := range []string{"", "nonsense", "hmac-sha256$zz$zz", "hmac-sha256$aabb", "argon2id$aabb$ccdd"} {
		if VerifyHash(bad, "s3cr3t") {
			t.Errorf("VerifyHash(%q) = true, want false", bad)
		}
	}
}

// TestVerifyHashUsesConstantTimeComparison is a source-level assertion.
//
// A timing property cannot be measured reliably in a unit test on a shared CI
// box — the noise floor is orders of magnitude above the signal, so a
// benchmark-style check would either flake or pass vacuously. What *can* be
// pinned is the thing that actually guarantees it: that the comparison goes
// through crypto/subtle rather than bytes.Equal or a string ==.
func TestVerifyHashUsesConstantTimeComparison(t *testing.T) {
	src := readPackageSource(t, "apitoken.go")

	body := functionBody(t, src, "func VerifyHash(")
	if !strings.Contains(body, "subtle.ConstantTimeCompare") {
		t.Error("VerifyHash must compare digests with subtle.ConstantTimeCompare — " +
			"an early-exit compare leaks how many leading bytes of a guess were correct")
	}
	for _, banned := range []string{"bytes.Equal", "== want", "string(want)"} {
		if strings.Contains(body, banned) {
			t.Errorf("VerifyHash contains %q, which is not constant time", banned)
		}
	}
}

// ---------------------------------------------------------------------------
// scope and decisions
// ---------------------------------------------------------------------------

func TestAllowsProject(t *testing.T) {
	scoped := &Token{ProjectScope: []string{"payments", "/srv/infra"}}
	unscoped := &Token{}

	cases := []struct {
		name, project, path string
		tok                 *Token
		want                bool
	}{
		{"unscoped allows anything", "anything", "/any/path", unscoped, true},
		{"by name", "payments", "/srv/payments", scoped, true},
		{"by name, different case", "PAYMENTS", "", scoped, true},
		{"by path", "", "/srv/infra", scoped, true},
		{"out of scope", "billing", "/srv/billing", scoped, false},
		{"global scope passes", "", "", scoped, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.tok.AllowsProject(tc.project, tc.path); got != tc.want {
				t.Errorf("AllowsProject(%q,%q) = %v, want %v", tc.project, tc.path, got, tc.want)
			}
		})
	}
	var nilTok *Token
	if nilTok.AllowsProject("x", "y") {
		t.Error("a nil token must allow nothing")
	}
}

func TestDecisionCarriesRolePermissions(t *testing.T) {
	now := time.Now()
	tok := &Token{Roles: []string{"operator"}, CreatedAt: now}

	d := tok.Decision(authz.GlobalScope, now)
	for _, want := range []authz.Permission{authz.PermProjectRead, authz.PermRunStart, authz.PermTaskMutate} {
		if !d.Allows(want) {
			t.Errorf("operator token should hold %q", want)
		}
	}
	for _, notWant := range []authz.Permission{authz.PermSecretGrant, authz.PermExecutorManage, authz.PermTokenAdmin} {
		if d.Allows(notWant) {
			t.Errorf("operator token must not hold %q", notWant)
		}
	}
	if d.Source != authz.SourceAPIToken {
		t.Errorf("Source = %q, want %q", d.Source, authz.SourceAPIToken)
	}
}

// TestDecisionDeniesOutOfScopeProject is the containment property: a scoped
// token asked about another project gets *nothing*, not a reduced role — so
// the caller's 404/403 split reports the project as nonexistent.
func TestDecisionDeniesOutOfScopeProject(t *testing.T) {
	now := time.Now()
	tok := &Token{Roles: []string{"admin"}, ProjectScope: []string{"payments"}}

	in := tok.Decision(authz.Scope{Project: "payments", ProjectPath: "/srv/payments"}, now)
	if !in.Allows(authz.PermProjectRead) {
		t.Fatal("an in-scope project must be readable")
	}

	out := tok.Decision(authz.Scope{Project: "billing", ProjectPath: "/srv/billing"}, now)
	if out.Allows(authz.PermProjectRead) {
		t.Error("an out-of-scope project must not be readable, even for an admin token")
	}
	if len(out.Permissions()) != 0 {
		t.Errorf("out-of-scope decision granted %v, want nothing", out.Permissions())
	}
}

func TestDecisionDeniesInactiveTokens(t *testing.T) {
	now := time.Now()
	for name, tok := range map[string]*Token{
		"revoked": {Roles: []string{"admin"}, RevokedAt: now.Add(-time.Minute)},
		"expired": {Roles: []string{"admin"}, ExpiresAt: now.Add(-time.Minute)},
		"noroles": {Roles: []string{"archon"}},
		"nil":     nil,
	} {
		t.Run(name, func(t *testing.T) {
			if d := tok.Decision(authz.GlobalScope, now); len(d.Permissions()) != 0 {
				t.Errorf("granted %v, want nothing", d.Permissions())
			}
		})
	}
}

// ---------------------------------------------------------------------------
// last-used tracking
// ---------------------------------------------------------------------------

// TestVerifyRecordsLastUseAsynchronously checks both halves of the contract:
// the write happens, and Verify does not block on it.
func TestVerifyRecordsLastUseAsynchronously(t *testing.T) {
	mgr, store := newTestManager(t)
	base := time.Now()
	mgr.SetClock(func() time.Time { return base })

	minted, err := mgr.Mint(MintOptions{Name: "ci", Roles: []string{"viewer"}, Now: base})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if _, err := mgr.Verify(minted.Plaintext); err != nil {
		t.Fatalf("Verify: %v", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, ok := store.touchedAt(minted.Token.ID); ok {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("last-used was never recorded")
}

// TestLastUseIsCoalesced pins the write-amplification guard: a token used in a
// tight loop must not produce a database write per request.
func TestLastUseIsCoalesced(t *testing.T) {
	store := newMemStore()
	counting := &countingStore{Store: store}
	mgr, err := NewManager(counting)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	base := time.Now()
	mgr.SetClock(func() time.Time { return base })

	minted, err := mgr.Mint(MintOptions{Name: "ci", Roles: []string{"viewer"}, Now: base})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	for i := 0; i < 200; i++ {
		if _, err := mgr.Verify(minted.Plaintext); err != nil {
			t.Fatalf("Verify %d: %v", i, err)
		}
	}
	// Let any dispatched writes land.
	time.Sleep(200 * time.Millisecond)

	if got := counting.touches(); got > 2 {
		t.Errorf("200 verifications produced %d last-used writes, want at most 2 "+
			"— the %v coalescing window is not being applied", got, touchInterval)
	}

	// Past the window, a use writes again.
	mgr.SetClock(func() time.Time { return base.Add(2 * touchInterval) })
	if _, err := mgr.Verify(minted.Plaintext); err != nil {
		t.Fatalf("Verify after window: %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if counting.touches() >= 2 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Errorf("no write after the coalescing window elapsed (touches=%d)", counting.touches())
}

type countingStore struct {
	Store
	mu sync.Mutex
	n  int
}

func (c *countingStore) Touch(id string, at time.Time) error {
	c.mu.Lock()
	c.n++
	c.mu.Unlock()
	return c.Store.Touch(id, at)
}

func (c *countingStore) touches() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.n
}

// TestConcurrentVerifyIsRaceFree exercises the manager under -race.
func TestConcurrentVerifyIsRaceFree(t *testing.T) {
	mgr, _ := newTestManager(t)
	minted, err := mgr.Mint(MintOptions{Name: "ci", Roles: []string{"operator"}})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				if _, err := mgr.Verify(minted.Plaintext); err != nil {
					t.Errorf("Verify: %v", err)
					return
				}
			}
		}()
	}
	wg.Wait()
}

// ---------------------------------------------------------------------------
// delegation
// ---------------------------------------------------------------------------

func TestCheckDelegationBoundsRolesByTheMinter(t *testing.T) {
	operator := Delegator{Decision: authz.FromRoles(
		[]authz.Role{authz.RoleOperator}, authz.SourceBinding, "alice", authz.GlobalScope)}
	admin := Delegator{Decision: authz.FromRoles(
		[]authz.Role{authz.RoleAdmin}, authz.SourceBinding, "root", authz.GlobalScope)}

	cases := []struct {
		name    string
		d       Delegator
		roles   []string
		wantErr bool
	}{
		{"operator mints viewer", operator, []string{"viewer"}, false},
		{"operator mints operator", operator, []string{"operator"}, false},
		{"operator mints maintainer", operator, []string{"maintainer"}, true},
		{"operator mints admin", operator, []string{"admin"}, true},
		{"operator sneaks admin in second", operator, []string{"viewer", "admin"}, true},
		{"admin mints admin", admin, []string{"admin"}, false},
		{"admin mints viewer", admin, []string{"viewer"}, false},
		{"unrestricted mints admin", Delegator{Unrestricted: true}, []string{"admin"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := CheckDelegation(tc.d, tc.roles, nil)
			if tc.wantErr && err == nil {
				t.Fatal("expected a refusal, got nil — this is a privilege escalation")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected refusal: %v", err)
			}
		})
	}
}

// TestCheckDelegationBoundsScope covers the second axis: a scoped token must
// not be able to mint one that reaches further than itself.
func TestCheckDelegationBoundsScope(t *testing.T) {
	scoped := Delegator{
		Decision: authz.FromRoles([]authz.Role{authz.RoleAdmin}, authz.SourceAPIToken, "tok", authz.GlobalScope),
		// An admin PAT limited to two projects.
		ProjectScope: []string{"payments", "infra"},
	}

	if err := CheckDelegation(scoped, []string{"operator"}, []string{"payments"}); err != nil {
		t.Errorf("minting within scope should be allowed: %v", err)
	}
	if err := CheckDelegation(scoped, []string{"operator"}, []string{"payments", "infra"}); err != nil {
		t.Errorf("minting the full scope should be allowed: %v", err)
	}
	if err := CheckDelegation(scoped, []string{"operator"}, []string{"billing"}); err == nil {
		t.Error("minting outside the scope must be refused")
	}
	if err := CheckDelegation(scoped, []string{"operator"}, nil); err == nil {
		t.Error("a scoped minter must not be able to mint an unscoped token — that widens its reach")
	}

	// An unscoped minter may issue whatever it likes.
	unscoped := Delegator{Decision: authz.FromRoles(
		[]authz.Role{authz.RoleAdmin}, authz.SourceBinding, "root", authz.GlobalScope)}
	if err := CheckDelegation(unscoped, []string{"admin"}, nil); err != nil {
		t.Errorf("an unscoped admin should mint freely: %v", err)
	}
}

// TestCheckDelegationRefusesADenyDecision is the deny-by-default case: an
// identity that matched no binding holds nothing, and must be able to mint
// nothing.
func TestCheckDelegationRefusesADenyDecision(t *testing.T) {
	none := Delegator{Decision: authz.Deny(authz.SourceDefaultRole, "nobody", authz.GlobalScope)}
	for _, role := range []string{"viewer", "operator", "maintainer", "admin"} {
		if err := CheckDelegation(none, []string{role}, nil); err == nil {
			t.Errorf("an identity holding nothing minted a %q token", role)
		}
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func flipFirstHexDigit(s string) string {
	if s == "" {
		return s
	}
	if s[0] == '0' {
		return "1" + s[1:]
	}
	return "0" + s[1:]
}
