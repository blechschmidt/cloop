package security

// Guarantee 4: time-bounded credentials really are time-bounded, single-use
// tokens really are single-use, and secret comparisons are constant-time.
//
// These three properties share a failure mode: each one is invisible when
// broken. An expired lease that still works looks exactly like a valid lease.
// A replayable enrollment token looks exactly like a fresh one until two
// agents claim the same identity. A `==` on a token hash behaves identically
// to a constant-time compare in every test except the one an attacker runs
// with a stopwatch. So none of them can be caught by using the system; they
// have to be asserted.
//
// Expiry is tested through an injected clock rather than by sleeping. Sleeping
// makes a test slow and flaky, and worse, it can only test expiry that is
// seconds away — the interesting case is a lease minted with an hour's TTL
// that must still be refused at hour one, and no test suite can wait for that.

import (
	"context"
	"errors"
	"go/ast"
	"go/token"
	"go/types"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor/remote"
	"github.com/blechschmidt/cloop/pkg/executorstore"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/statedb"

	"golang.org/x/tools/go/packages"
)

// fakeClock is a manually-advanced clock.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{now: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// newClockedBroker builds a broker whose sense of time the test controls.
func newClockedBroker(t *testing.T) (*secretbroker.Broker, *fakeClock) {
	t.Helper()
	t.Setenv(secretbroker.EnvPassphraseKey, "conformance-suite-passphrase")
	clock := newFakeClock()
	b, err := secretbroker.New(newMemStore(),
		secretbroker.WithAuditor(&recordingAuditor{}),
		secretbroker.WithClock(clock.Now))
	if err != nil {
		t.Fatalf("secretbroker.New: %v", err)
	}
	return b, clock
}

// seedGrantedSecret mints a secret and grants it to executor edge-01 with the
// given TTL, returning the grant.
func seedGrantedSecret(t *testing.T, b *secretbroker.Broker, ttl time.Duration) secretbroker.Grant {
	t.Helper()
	ctx := context.Background()
	secret, err := b.Mint(ctx, secretbroker.MintRequest{
		Name:    "lease-conformance",
		Kind:    secretbroker.KindGitHubPAT,
		Payload: []byte("ghp_leaseConformance0123456789abcdefghij"),
		Actor:   "suite",
	})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	grant, err := b.Grant(ctx, secretbroker.GrantRequest{
		SecretRef:   secret.ID,
		Subject:     secretbroker.Subject{Type: secretbroker.SubjectExecutor, Value: "edge-01"},
		Constraints: secretbroker.Constraints{Repos: []string{"acme/*"}},
		TTL:         ttl,
		Actor:       "suite",
	})
	if err != nil {
		t.Fatalf("Grant: %v", err)
	}
	return grant
}

// TestLeaseIsRefusedAfterGrantExpiry is the redemption-time check.
func TestLeaseIsRefusedAfterGrantExpiry(t *testing.T) {
	broker, clock := newClockedBroker(t)
	ctx := context.Background()
	seedGrantedSecret(t, broker, time.Hour)

	// Before expiry the lease is issued and carries material.
	lease, err := broker.Lease(ctx, "edge-01", "/srv/project")
	if err != nil {
		t.Fatalf("Lease before expiry: %v", err)
	}
	if len(lease.Materials) == 0 {
		t.Fatal("a valid grant produced a lease with no material")
	}
	broker.Release(lease.ID)

	// One second past the grant's expiry, the same request must deliver
	// nothing.
	//
	// The broker skips expired grants rather than failing the whole lease —
	// one dead grant among five should not deny the other four — so the
	// security assertion is on the material, not on the error. "A lease was
	// issued" is not the problem; "a credential was handed over" is.
	clock.Advance(time.Hour + time.Second)
	after, err := broker.Lease(ctx, "edge-01", "/srv/project")
	if err == nil && len(after.Materials) > 0 {
		t.Fatalf("an expired grant still delivered %d material(s) — TTLs are decoration",
			len(after.Materials))
	}
	if err == nil {
		defer broker.Release(after.ID)
	}
}

// TestLeaseRenewalReevaluatesExpiryMidSession is the mid-session check, and
// the one that matters for long-running work. A cloop task can run for hours;
// if renewal only refreshed the lease's own deadline without re-reading the
// grant, a revoked or expired credential would stay live for as long as the
// workload kept asking.
func TestLeaseRenewalReevaluatesExpiryMidSession(t *testing.T) {
	broker, clock := newClockedBroker(t)
	ctx := context.Background()
	seedGrantedSecret(t, broker, time.Hour)

	lease, err := broker.Lease(ctx, "edge-01", "/srv/project")
	if err != nil {
		t.Fatalf("Lease: %v", err)
	}

	// Renewal inside the window keeps working.
	clock.Advance(30 * time.Minute)
	renewed, err := broker.Renew(ctx, lease.ID)
	if err != nil {
		t.Fatalf("Renew inside the grant window: %v", err)
	}
	if len(renewed.Materials) == 0 {
		t.Fatal("renewal inside the window dropped the material")
	}

	// Past the grant's expiry the renewal must come back empty: the workload
	// keeps its session, but the credential is gone.
	clock.Advance(time.Hour)
	expired, err := broker.Renew(ctx, renewed.ID)
	if err == nil && len(expired.Materials) > 0 {
		t.Fatalf("renewal past the grant's expiry still delivered %d material(s); "+
			"a long-running workload would hold a dead credential indefinitely",
			len(expired.Materials))
	}
}

// TestRevocationTakesEffectMidSession covers the operator's emergency lever.
// Revocation that only applied to future leases would be useless: the whole
// reason to revoke is that something already running should stop.
func TestRevocationTakesEffectMidSession(t *testing.T) {
	broker, clock := newClockedBroker(t)
	ctx := context.Background()
	grant := seedGrantedSecret(t, broker, 24*time.Hour)

	lease, err := broker.Lease(ctx, "edge-01", "/srv/project")
	if err != nil {
		t.Fatalf("Lease: %v", err)
	}

	if err := broker.Revoke(ctx, grant.ID, "suite"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	clock.Advance(time.Minute)

	renewed, err := broker.Renew(ctx, lease.ID)
	if err == nil && len(renewed.Materials) > 0 {
		t.Fatalf("a revoked grant still delivered %d material(s) on renewal; "+
			"revocation does not reach sessions that are already running",
			len(renewed.Materials))
	}
	fresh, err := broker.Lease(ctx, "edge-01", "/srv/project")
	if err == nil && len(fresh.Materials) > 0 {
		t.Fatalf("a revoked grant still delivered %d material(s) to a new lease",
			len(fresh.Materials))
	}
	if err == nil {
		broker.Release(fresh.ID)
	}
}

// newEnrollStore returns a real SQLite-backed enrollment store.
//
// Real rather than in-memory on purpose: single-use enforcement lives in the
// UPDATE ... WHERE redeemed_at IS NULL of the SQL statement, so a fake store
// would test a Go-level check that production does not rely on.
func newEnrollStore(t *testing.T) *executorstore.Store {
	t.Helper()
	db, err := statedb.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("open statedb: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	store, err := executorstore.New(db)
	if err != nil {
		t.Fatalf("executorstore.New: %v", err)
	}
	return store
}

// TestEnrollmentTokenIsSingleUse is the replay assertion. An enrollment token
// grants a machine a durable identity in the control plane; if it can be
// redeemed twice, a token leaked from a provisioning log lets an attacker
// enroll a second executor that receives real workloads and real credentials.
func TestEnrollmentTokenIsSingleUse(t *testing.T) {
	store := newEnrollStore(t)
	clock := newFakeClock()

	token, rec, err := remote.Mint(store, remote.MintOptions{
		Name: "edge-01", TTL: 15 * time.Minute,
		WorkDirRoot: "/srv/work", CreatedBy: "suite", Now: clock.Now,
	})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	cred, agent, err := remote.Redeem(store, token, remote.RedeemOptions{Now: clock.Now})
	if err != nil {
		t.Fatalf("first Redeem: %v", err)
	}
	if cred == "" || agent.AgentID == "" {
		t.Fatal("a successful redemption returned no credential or agent")
	}

	// The replay.
	_, _, err = remote.Redeem(store, token, remote.RedeemOptions{Now: clock.Now})
	if err == nil {
		t.Fatal("the enrollment token was redeemed twice; a leaked token " +
			"enrolls an attacker's machine as a trusted executor")
	}
	if !errors.Is(err, remote.ErrTokenAlreadyUsed) {
		t.Errorf("replay error = %v, want ErrTokenAlreadyUsed so callers can "+
			"distinguish a replay (an attack) from an expiry (a mistake)", err)
	}
	// The refusal must not leak the token itself into whatever logs it.
	assertNoSecretLeak(t, err.Error(), token, "the replay refusal")
	_ = rec
}

// TestEnrollmentTokenSurvivesOnlyOneOfManyConcurrentRedemptions closes the
// race. A check-then-write single-use guard passes the sequential test above
// and fails here, and this is the shape an attacker actually uses: fire N
// redemptions at once and hope two land between the check and the write.
func TestEnrollmentTokenSurvivesOnlyOneOfManyConcurrentRedemptions(t *testing.T) {
	store := newEnrollStore(t)
	clock := newFakeClock()

	token, _, err := remote.Mint(store, remote.MintOptions{
		Name: "edge-race", TTL: 15 * time.Minute,
		WorkDirRoot: "/srv/work", CreatedBy: "suite", Now: clock.Now,
	})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	const racers = 8
	var (
		wg        sync.WaitGroup
		mu        sync.Mutex
		succeeded []string
	)
	wg.Add(racers)
	for i := 0; i < racers; i++ {
		go func() {
			defer wg.Done()
			_, agent, err := remote.Redeem(store, token, remote.RedeemOptions{Now: clock.Now})
			if err == nil {
				mu.Lock()
				succeeded = append(succeeded, agent.AgentID)
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	if len(succeeded) != 1 {
		t.Fatalf("%d of %d concurrent redemptions succeeded (agents %v); "+
			"single-use enforcement is not atomic, so a racing attacker gets "+
			"an executor identity of their own", len(succeeded), racers, succeeded)
	}
}

// TestEnrollmentTokenExpires covers the other half of the token's bounds.
func TestEnrollmentTokenExpires(t *testing.T) {
	store := newEnrollStore(t)
	clock := newFakeClock()

	token, _, err := remote.Mint(store, remote.MintOptions{
		Name: "edge-expiring", TTL: 15 * time.Minute,
		WorkDirRoot: "/srv/work", CreatedBy: "suite", Now: clock.Now,
	})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	clock.Advance(15*time.Minute + time.Second)
	_, _, err = remote.Redeem(store, token, remote.RedeemOptions{Now: clock.Now})
	if err == nil {
		t.Fatal("an expired enrollment token was redeemed")
	}
	if !errors.Is(err, remote.ErrTokenExpired) {
		t.Errorf("expiry error = %v, want ErrTokenExpired", err)
	}
}

// TestTamperedEnrollmentTokenIsRejected checks the token's integrity tag. The
// token carries its own MAC so a forged or mutated token is refused before any
// database lookup happens.
func TestTamperedEnrollmentTokenIsRejected(t *testing.T) {
	store := newEnrollStore(t)
	clock := newFakeClock()

	token, _, err := remote.Mint(store, remote.MintOptions{
		Name: "edge-tamper", TTL: 15 * time.Minute,
		WorkDirRoot: "/srv/work", CreatedBy: "suite", Now: clock.Now,
	})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	for _, tc := range []struct{ name, tok string }{
		{"empty", ""},
		{"garbage", "not-a-token"},
		{"truncated", token[:len(token)/2]},
		{"flipped last byte", flipLastByte(token)},
		{"extra segment", token + ".extra"},
		{"segments dropped", strings.Join(strings.Split(token, ".")[:2], ".")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := remote.Redeem(store, tc.tok, remote.RedeemOptions{Now: clock.Now}); err == nil {
				t.Fatalf("a tampered token (%s) was accepted", tc.name)
			}
		})
	}

	// And the genuine token still works, so the test above is not passing
	// because redemption is broken outright.
	if _, _, err := remote.Redeem(store, token, remote.RedeemOptions{Now: clock.Now}); err != nil {
		t.Fatalf("the genuine token was rejected too: %v", err)
	}
}

func flipLastByte(s string) string {
	if s == "" {
		return s
	}
	b := []byte(s)
	b[len(b)-1] ^= 0x01
	return string(b)
}

// ---------------------------------------------------------------------------
// Constant-time comparison
// ---------------------------------------------------------------------------

// secretishIdent matches identifier names that hold a credential or something
// derived from one.
var secretishIdent = []string{
	"token", "secret", "password", "passphrase", "apikey", "credential",
	"mac", "signature", "hmac", "digest", "tokenhash", "secrethash",
}

// identifierNotMaterial excludes names that denote a credential's *identity*
// rather than its contents. A secret's name, ID, or reference is not secret —
// they are printed in list APIs and audit records by design — so comparing
// them with == leaks nothing, and flagging them would train readers to ignore
// this test.
var identifierNotMaterial = []string{"name", "ref", "id", "path", "file", "kind", "type", "label"}

// TestSecretComparisonsAreConstantTime scans every non-test source file for
// equality comparisons between two non-constant credential-shaped values.
//
// A `==` on a token leaks its contents through timing: the comparison returns
// at the first differing byte, so an attacker who can measure the response can
// recover the secret one byte at a time. The bug is invisible in every
// functional test, which is exactly why it needs a structural one.
//
// Comparisons against a constant (`token == ""`, `kind == "bearer"`) are
// ignored: there is no secret on one side, so there is no secret to leak.
func TestSecretComparisonsAreConstantTime(t *testing.T) {
	root, err := moduleRoot()
	if err != nil {
		t.Fatalf("locate module root: %v", err)
	}
	cfg := &packages.Config{
		Mode: packages.NeedName | packages.NeedFiles | packages.NeedSyntax |
			packages.NeedTypes | packages.NeedTypesInfo | packages.NeedImports,
		Dir:   root,
		Tests: false,
	}
	pkgs, err := packages.Load(cfg, ModulePath+"/...")
	if err != nil {
		t.Fatalf("load packages: %v", err)
	}
	if len(pkgs) == 0 {
		t.Fatal("no packages loaded — the scan would pass vacuously")
	}

	scanned := 0
	for _, p := range pkgs {
		if !strings.HasPrefix(p.PkgPath, ModulePath) || p.TypesInfo == nil {
			continue
		}
		for _, file := range p.Syntax {
			scanned++
			ast.Inspect(file, func(n ast.Node) bool {
				bin, ok := n.(*ast.BinaryExpr)
				if !ok || (bin.Op != token.EQL && bin.Op != token.NEQ) {
					return true
				}
				if !isSecretish(bin.X) && !isSecretish(bin.Y) {
					return true
				}
				// One side constant means nothing secret is being compared.
				if isConstant(p, bin.X) || isConstant(p, bin.Y) {
					return true
				}
				// Only string/byte comparisons are timing-observable in the
				// way that matters; an int or a bool compares in one step.
				if !isStringLike(p, bin.X) {
					return true
				}
				pos := p.Fset.Position(bin.Pos())
				t.Errorf("%s:%d:%d: %s compares two credential-shaped values with %s.\n"+
					"    Use crypto/subtle.ConstantTimeCompare: a byte-wise == returns "+
					"early at the first mismatch, which leaks the secret to anyone who "+
					"can time the response.",
					filepath.Base(pos.Filename), pos.Line, pos.Column,
					p.PkgPath, bin.Op)
				return true
			})
		}
	}
	if scanned == 0 {
		t.Fatal("no files were scanned — the guard would pass vacuously")
	}
	t.Logf("scanned %d files for timing-unsafe secret comparisons", scanned)
}

// isSecretish reports whether an expression's rendered name suggests it holds
// credential material.
func isSecretish(e ast.Expr) bool {
	var name string
	switch v := e.(type) {
	case *ast.Ident:
		name = v.Name
	case *ast.SelectorExpr:
		name = v.Sel.Name
	case *ast.CallExpr:
		// hashSecret(x) == stored is the canonical shape.
		if id, ok := v.Fun.(*ast.Ident); ok {
			name = id.Name
		}
	default:
		return false
	}
	lower := strings.ToLower(name)
	for _, frag := range identifierNotMaterial {
		if strings.Contains(lower, frag) {
			return false
		}
	}
	for _, frag := range secretishIdent {
		if strings.Contains(lower, frag) {
			return true
		}
	}
	return false
}

func isConstant(p *packages.Package, e ast.Expr) bool {
	if tv, ok := p.TypesInfo.Types[e]; ok {
		return tv.Value != nil
	}
	return false
}

func isStringLike(p *packages.Package, e ast.Expr) bool {
	tv, ok := p.TypesInfo.Types[e]
	if !ok || tv.Type == nil {
		return false
	}
	switch u := tv.Type.Underlying().(type) {
	case *types.Basic:
		return u.Kind() == types.String
	case *types.Slice:
		b, ok := u.Elem().Underlying().(*types.Basic)
		return ok && b.Kind() == types.Byte
	}
	return false
}

// TestKnownSecretComparisonsUseSubtle is the positive half: the places that
// legitimately compare credentials must be calling crypto/subtle, and there
// must be a healthy number of them. If this count collapses, somebody replaced
// the constant-time compares with something cheaper and the scan above would
// not necessarily notice (a rename to `want`/`got` defeats the heuristic).
func TestKnownSecretComparisonsUseSubtle(t *testing.T) {
	root, err := moduleRoot()
	if err != nil {
		t.Fatalf("locate module root: %v", err)
	}
	cfg := &packages.Config{
		Mode: packages.NeedName | packages.NeedSyntax | packages.NeedTypes |
			packages.NeedTypesInfo | packages.NeedImports,
		Dir:   root,
		Tests: false,
	}
	pkgs, err := packages.Load(cfg, ModulePath+"/...")
	if err != nil {
		t.Fatalf("load packages: %v", err)
	}

	sites := map[string]int{}
	for _, p := range pkgs {
		if !strings.HasPrefix(p.PkgPath, ModulePath) || p.TypesInfo == nil {
			continue
		}
		for _, file := range p.Syntax {
			ast.Inspect(file, func(n ast.Node) bool {
				id, ok := n.(*ast.Ident)
				if !ok {
					return true
				}
				fn, ok := p.TypesInfo.Uses[id].(*types.Func)
				if !ok || fn.Pkg() == nil || fn.Pkg().Path() != "crypto/subtle" {
					return true
				}
				sites[p.PkgPath]++
				return true
			})
		}
	}

	// Every package that authenticates a caller must be represented. Naming
	// them explicitly means deleting the last constant-time compare from one
	// of them is a test failure and not a silent change.
	for _, want := range []string{
		ModulePath + "/pkg/executor/remote", // enrollment token MAC + secret hash
		ModulePath + "/pkg/egressbroker",    // proxy session token
		ModulePath + "/pkg/ui",              // dashboard bearer token
	} {
		if sites[want] == 0 {
			t.Errorf("%s performs no constant-time comparison. It authenticates "+
				"callers, so it must compare credentials with "+
				"crypto/subtle.ConstantTimeCompare.", want)
		}
	}
	t.Logf("constant-time comparison sites by package: %v", sites)
}
