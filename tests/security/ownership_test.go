package security

// Guarantee: a personal secret reaches its owner and nobody else (Task 20275).
//
// This is a tenancy guarantee rather than a non-disclosure one, and the
// distinction is what makes it worth asserting separately. secrets_test.go
// proves that the *material* never leaves the broker — true for every secret,
// personal or shared, and untouched by this feature. What this file proves is
// narrower and newer: that one user's credential is not reachable, listable,
// spendable or destroyable by another user, and that the ability to see is not
// silently the ability to use.
//
// It lives in tests/security rather than only in pkg/secretbroker because the
// rule spans two packages that do not import each other. The broker decides
// ownership; the hub decides whether the caller also holds organisation-level
// authority. Each half is tested at home, and the property that matters —
// "alice's PAT is alice's" — is the conjunction, which has no home but here.
//
// The leak detector is reused deliberately. Isolation that holds for metadata
// while the plaintext escapes through some other path would be no isolation at
// all, so every assertion below that says "bob cannot see it" is also checked
// against the raw credential in encoded forms.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/secretbroker"
)

const (
	aliceID = "alice@corp.example"
	bobID   = "bob@corp.example"
	rootID  = "root@corp.example"

	alicePATCanary = "ghp_ALICEPERSONALCANARY0123456789abcd"
	sharedCanary   = "ghp_SHAREDFLEETCANARY0123456789abcdef"
)

func aliceView() secretbroker.Viewer { return secretbroker.Viewer{Identity: aliceID} }
func bobView() secretbroker.Viewer   { return secretbroker.Viewer{Identity: bobID} }
func rootView() secretbroker.Viewer  { return secretbroker.PrivilegedViewer(rootID) }

// seedTenancy mints one personal secret for alice and one shared secret, which
// is the smallest world in which every assertion below is non-vacuous.
func seedTenancy(t *testing.T, b *secretbroker.Broker) (personal, shared secretbroker.Secret) {
	t.Helper()
	ctx := context.Background()

	var err error
	personal, err = b.Mint(ctx, secretbroker.MintRequest{
		Name: "alice-personal-pat", Kind: secretbroker.KindGitHubPAT,
		Payload: []byte(alicePATCanary), Actor: aliceID,
		Owner: aliceID, Personal: true,
	})
	if err != nil {
		t.Fatalf("mint alice's personal secret: %v", err)
	}
	if !personal.Personal() {
		t.Fatal("the fixture's personal secret has no owner — every assertion below would be vacuous")
	}
	shared, err = b.Mint(ctx, secretbroker.MintRequest{
		Name: "fleet-deploy-pat", Kind: secretbroker.KindGitHubPAT,
		Payload: []byte(sharedCanary), Actor: "ops",
	})
	if err != nil {
		t.Fatalf("mint the shared secret: %v", err)
	}
	return personal, shared
}

// TestPersonalSecretIsNotReachableByAnotherTenant is the guarantee, swept over
// every read path that takes a name or an ID.
//
// Each of these is a different call with a different caller in production —
// the Secrets panel, the request catalogue, the grant dialog, the project
// provisioning flow — and the failure mode this catches is the one where the
// rule is applied in three of them.
func TestPersonalSecretIsNotReachableByAnotherTenant(t *testing.T) {
	b, _, _ := newBroker(t)
	personal, shared := seedTenancy(t, b)

	t.Run("listing", func(t *testing.T) {
		got, err := b.ListSecretsFor(bobView())
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		for _, s := range got {
			if s.ID == personal.ID {
				t.Fatal("bob's secret listing contains alice's personal credential")
			}
		}
		// Non-vacuity: bob does see the shared one, so the sweep above is
		// proving scoping rather than an empty store or a broken fixture.
		found := false
		for _, s := range got {
			if s.ID == shared.ID {
				found = true
			}
		}
		if !found {
			t.Fatal("bob cannot see the shared secret either — this test proves nothing")
		}
	})

	t.Run("resolve by id", func(t *testing.T) {
		_, err := b.DescribeSecretFor(personal.ID, bobView())
		if !errors.Is(err, secretbroker.ErrSecretNotFound) {
			t.Fatalf("err = %v, want ErrSecretNotFound", err)
		}
	})

	t.Run("resolve by guessable name", func(t *testing.T) {
		// The reconnaissance case. "alice-personal-pat" is the obvious guess,
		// and the answer must be indistinguishable from a name that was never
		// minted at all.
		byName, errName := b.DescribeSecretFor("alice-personal-pat", bobView())
		byNonsense, errNonsense := b.DescribeSecretFor("no-such-secret-at-all", bobView())
		if !errors.Is(errName, secretbroker.ErrSecretNotFound) {
			t.Fatalf("guessing the name: err = %v, want ErrSecretNotFound", errName)
		}
		if !errors.Is(errNonsense, secretbroker.ErrSecretNotFound) {
			t.Fatalf("a name that does not exist: err = %v, want ErrSecretNotFound", errNonsense)
		}
		if byName.ID != "" || byNonsense.ID != "" {
			t.Fatal("a refused resolve returned a secret")
		}
		// And neither error may carry the credential, in any encoding.
		assertNoSecretLeak(t, errName.Error(), alicePATCanary, "resolve error")
	})

	t.Run("grant listing", func(t *testing.T) {
		mustGrantOwn(t, b, personal, aliceView(), "project:/srv/alice-app")
		got, err := b.ListGrantsFor(secretbroker.GrantFilter{}, bobView())
		if err != nil {
			t.Fatalf("list grants: %v", err)
		}
		for _, g := range got {
			if g.SecretID == personal.ID {
				t.Fatal("bob's grant listing contains a grant over alice's personal credential")
			}
		}
	})
}

// TestSeeingAPersonalSecretIsNotUsingIt is the asymmetry the model turns on.
//
// An admin must be able to see and destroy a departed colleague's credentials,
// or offboarding is impossible. An admin must *not* be able to hand one to a
// workload. Every other admin power in the hub is a superset of everyone
// else's, which is exactly why this one needs a test: the natural refactor is
// to let Admin short-circuit the ownership check, and that would be a silent,
// auditable-looking escalation.
func TestSeeingAPersonalSecretIsNotUsingIt(t *testing.T) {
	b, _, _ := newBroker(t)
	personal, _ := seedTenancy(t, b)

	// Sees it.
	if _, err := b.DescribeSecretFor(personal.ID, rootView()); err != nil {
		t.Fatalf("an admin cannot see a personal secret, so offboarding is impossible: %v", err)
	}

	// Cannot spend it. Note this must be ErrNotOwner, not ErrSecretNotFound:
	// concealment is not available as an answer to someone who can see the row,
	// so the refusal has to be explicit.
	subject, err := secretbroker.ParseSubject("project:/srv/somewhere")
	if err != nil {
		t.Fatalf("parse subject: %v", err)
	}
	_, err = b.Grant(context.Background(), secretbroker.GrantRequest{
		SecretRef:   personal.ID,
		Subject:     subject,
		Constraints: secretbroker.Constraints{Repos: []string{"acme/*"}},
		TTL:         time.Hour,
		Actor:       rootID,
		Viewer:      rootView(),
	})
	if !errors.Is(err, secretbroker.ErrNotOwner) {
		t.Fatalf("an admin granted another user's personal secret: err = %v, want ErrNotOwner", err)
	}
	assertNoSecretLeak(t, err.Error(), alicePATCanary, "admin grant refusal")

	// Can destroy it, which offboarding requires.
	if err := b.DeleteSecretFor(context.Background(), personal.ID, rootView()); err != nil {
		t.Fatalf("an admin cannot delete a personal secret: %v", err)
	}
}

// TestPersonalCredentialNeverLeasesToAnotherTenantsWork is the end of the
// chain, and the only assertion here that reaches actual plaintext.
//
// Everything above concerns metadata. This runs the real mint → grant → lease
// lifecycle and checks that a workload running somebody else's project never
// receives the credential — which is what all the scoping is ultimately for.
func TestPersonalCredentialNeverLeasesToAnotherTenantsWork(t *testing.T) {
	b, _, _ := newBroker(t)
	personal, _ := seedTenancy(t, b)
	ctx := context.Background()

	mustGrantOwn(t, b, personal, aliceView(), "project:/srv/alice-app")

	// Alice's own project gets it — without this the assertion below could
	// pass because nothing was ever grantable.
	own, err := b.Lease(ctx, "exec-1", "/srv/alice-app")
	if err != nil {
		t.Fatalf("alice's own project cannot lease her credential: %v", err)
	}
	defer b.Release(own.ID)
	if len(own.Materials) == 0 {
		t.Fatal("alice's lease carried no materials — the rest of this test would be vacuous")
	}

	// Bob's project, same executor, same hub.
	other, err := b.Lease(ctx, "exec-1", "/srv/bob-app")
	if err == nil && other != nil {
		defer b.Release(other.ID)
		for _, m := range other.Materials {
			// Every channel a credential can ride out on: the env values, the
			// file bodies, and the audit-safe summary.
			for k, v := range m.Env {
				assertNoSecretLeak(t, v, alicePATCanary,
					"another tenant's lease env "+k)
			}
			for _, f := range m.Files {
				assertNoSecretLeak(t, string(f.Content), alicePATCanary,
					"another tenant's lease file "+f.Name)
			}
			assertNoSecretLeak(t, m.Summary, alicePATCanary,
				"another tenant's lease summary")
		}
		if len(other.Materials) > 0 {
			t.Fatalf("bob's project received %d materials from alice's personal grant", len(other.Materials))
		}
	}
}

// TestAPersonalSecretCannotBeGrantedToEveryone pins the wildcard refusal.
//
// A personal credential granted to `any` or `project:*` is redeemed by whoever
// runs next, which converts a private credential into a fleet-wide one in a
// single click. It is refused rather than narrowed, because narrowing would
// require guessing which project the owner meant.
func TestAPersonalSecretCannotBeGrantedToEveryone(t *testing.T) {
	b, _, _ := newBroker(t)
	personal, shared := seedTenancy(t, b)

	for _, subject := range []string{"any", "project:*", "executor:*"} {
		sub, err := secretbroker.ParseSubject(subject)
		if err != nil {
			t.Fatalf("parse %q: %v", subject, err)
		}
		req := func(ref string, v secretbroker.Viewer, actor string) error {
			_, gerr := b.Grant(context.Background(), secretbroker.GrantRequest{
				SecretRef:   ref,
				Subject:     sub,
				Constraints: secretbroker.Constraints{Repos: []string{"acme/*"}},
				TTL:         time.Hour,
				Actor:       actor,
				Viewer:      v,
			})
			return gerr
		}
		if err := req(personal.ID, aliceView(), aliceID); !errors.Is(err, secretbroker.ErrPersonalWildcard) {
			t.Errorf("granting a personal secret to %q: err = %v, want ErrPersonalWildcard", subject, err)
		}
		// The same subject over a shared secret must still work: this is a
		// consequence of ownership, not a new blanket policy, and breaking the
		// fleet-wide grant would be a regression in a different direction.
		if err := req(shared.ID, secretbroker.Viewer{}, "ops"); err != nil {
			t.Errorf("granting the shared secret to %q was refused: %v", subject, err)
		}
	}
}

// TestUnownedSecretsBehaveExactlyAsBefore is the compatibility half.
//
// Every secret that existed before this feature has an empty owner. A tenancy
// model that quietly made them unreachable would be an outage, and one that
// quietly made them *more* reachable would be the escalation. Neither.
func TestUnownedSecretsBehaveExactlyAsBefore(t *testing.T) {
	b, _, _ := newBroker(t)
	_, shared := seedTenancy(t, b)

	for _, v := range []secretbroker.Viewer{aliceView(), bobView(), rootView(), {}} {
		if !shared.VisibleTo(v) {
			t.Errorf("a shared secret became invisible to %+v", v)
		}
		if !shared.SpendableBy(v) {
			t.Errorf("a shared secret became unspendable by %+v", v)
		}
		if !shared.DeletableBy(v) {
			t.Errorf("a shared secret became undeletable by %+v", v)
		}
		if _, err := b.DescribeSecretFor(shared.ID, v); err != nil {
			t.Errorf("a shared secret stopped resolving for %+v: %v", v, err)
		}
	}
}

// mustGrantOwn grants a personal secret on behalf of its owner.
func mustGrantOwn(t *testing.T, b *secretbroker.Broker, s secretbroker.Secret,
	v secretbroker.Viewer, subject string) secretbroker.Grant {
	t.Helper()
	sub, err := secretbroker.ParseSubject(subject)
	if err != nil {
		t.Fatalf("parse subject %q: %v", subject, err)
	}
	g, err := b.Grant(context.Background(), secretbroker.GrantRequest{
		SecretRef:   s.ID,
		Subject:     sub,
		Constraints: secretbroker.Constraints{Repos: []string{"acme/*"}},
		TTL:         time.Hour,
		Actor:       v.Identity,
		Viewer:      v,
	})
	if err != nil {
		t.Fatalf("owner granting their own secret to %s: %v", subject, err)
	}
	return g
}
