package secretbroker

import (
	"context"
	"errors"
	"testing"
	"time"
)

// Personal-secret ownership (Task 20275).
//
// The property under test throughout: a secret with an owner is reachable by
// that owner and by nobody else. "Reachable" is four separate verbs — see it,
// resolve it by name, spend it, destroy it — and each is tested separately
// because each has its own call path and they have historically been the kind
// of thing that gets fixed in one place and missed in three.

func mintPersonal(t *testing.T, b *Broker, name, owner, token string) Secret {
	t.Helper()
	s, err := b.Mint(context.Background(), MintRequest{
		Name:     name,
		Kind:     KindGitHubPAT,
		Payload:  []byte(token),
		Actor:    owner,
		Owner:    owner,
		Personal: true,
	})
	if err != nil {
		t.Fatalf("mint personal %s for %s: %v", name, owner, err)
	}
	return s
}

func alice() Viewer { return Viewer{Identity: "alice@corp"} }
func bob() Viewer   { return Viewer{Identity: "bob@corp"} }
func admin() Viewer { return Viewer{Identity: "root@corp", Admin: true} }

// TestPersonalSecretIsInvisibleToOtherUsers is the headline guarantee: the
// listing one user sees must not contain another user's credential.
func TestPersonalSecretIsInvisibleToOtherUsers(t *testing.T) {
	b, _, _, _ := newTestBroker(t)

	mintPersonal(t, b, "alice-pat", "alice@corp", "ghp_aliceahhh")
	mintPersonal(t, b, "bob-pat", "bob@corp", "ghp_bobbbbbbb")
	mintGitHub(t, b, "fleet-deploy", "ghp_sharedshared")

	for _, tc := range []struct {
		name   string
		viewer Viewer
		want   []string
	}{
		// Each user sees their own personal secret and the shared one. The
		// shared one is here deliberately: the broker must not start hiding
		// the organisation's credentials, which is the hub's route table's
		// decision to make, not this package's.
		{"alice sees her own and the shared one", alice(), []string{"alice-pat", "fleet-deploy"}},
		{"bob sees his own and the shared one", bob(), []string{"bob-pat", "fleet-deploy"}},
		{"an admin sees everything", admin(), []string{"alice-pat", "bob-pat", "fleet-deploy"}},
		// The zero viewer is what a caller that forgot to say who it is
		// produces. It must fail closed.
		{"an anonymous caller sees no personal secret", Viewer{}, []string{"fleet-deploy"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := b.ListSecretsFor(tc.viewer)
			if err != nil {
				t.Fatalf("list: %v", err)
			}
			names := make([]string, 0, len(got))
			for _, s := range got {
				names = append(names, s.Name)
			}
			if len(names) != len(tc.want) {
				t.Fatalf("saw %v, want %v", names, tc.want)
			}
			for i := range names {
				if names[i] != tc.want[i] {
					t.Fatalf("saw %v, want %v", names, tc.want)
				}
			}
		})
	}
}

// TestPersonalSecretIsNotAnOracleByName checks that resolving a name you do
// not own reports absence, not refusal.
//
// Secret names are chosen by people and are guessable — "alice-github-pat" is
// the obvious thing to try — so a broker that distinguished "no such secret"
// from "not yours" would answer the reconnaissance question directly.
func TestPersonalSecretIsNotAnOracleByName(t *testing.T) {
	b, _, _, _ := newTestBroker(t)
	mintPersonal(t, b, "alice-pat", "alice@corp", "ghp_aliceahhh")

	_, err := b.DescribeSecretFor("alice-pat", bob())
	if !errors.Is(err, ErrSecretNotFound) {
		t.Fatalf("describing another user's secret: err = %v, want ErrSecretNotFound", err)
	}
	// And the same name resolves for its owner, so the test above is proving
	// concealment rather than a broken fixture.
	if _, err := b.DescribeSecretFor("alice-pat", alice()); err != nil {
		t.Fatalf("owner cannot resolve her own secret: %v", err)
	}
}

// TestPersonalSecretCannotBeSpentByAnotherUser covers the act that matters
// most: turning somebody else's credential into a grant an executor redeems.
func TestPersonalSecretCannotBeSpentByAnotherUser(t *testing.T) {
	b, _, _, _ := newTestBroker(t)
	alicePAT := mintPersonal(t, b, "alice-pat", "alice@corp", "ghp_aliceahhh")

	sub, err := ParseSubject("project:/srv/app")
	if err != nil {
		t.Fatalf("parse subject: %v", err)
	}
	mk := func(v Viewer) error {
		_, gerr := b.Grant(context.Background(), GrantRequest{
			SecretRef:   alicePAT.ID,
			Subject:     sub,
			Constraints: Constraints{Repos: []string{"org/*"}},
			TTL:         time.Hour,
			Actor:       v.Identity,
			Viewer:      v,
		})
		return gerr
	}

	// Bob has never seen it and must not learn it exists.
	if err := mk(bob()); !errors.Is(err, ErrSecretNotFound) {
		t.Fatalf("bob granting alice's secret: err = %v, want ErrSecretNotFound", err)
	}
	// An admin *can* see it, so concealment is not available as an answer —
	// this must be an explicit refusal. Admin is the case most likely to be
	// wrong, because every other admin power in the hub is a superset.
	if err := mk(admin()); !errors.Is(err, ErrNotOwner) {
		t.Fatalf("an admin granting alice's secret: err = %v, want ErrNotOwner", err)
	}
	// A caller with no identity at all.
	if err := mk(Viewer{}); !errors.Is(err, ErrSecretNotFound) {
		t.Fatalf("anonymous granting alice's secret: err = %v, want ErrSecretNotFound", err)
	}
	// And Alice can, so the refusals above are about ownership.
	if err := mk(alice()); err != nil {
		t.Fatalf("alice cannot grant her own secret: %v", err)
	}
}

// TestPersonalGrantRefusesAWildcardSubject: a credential granted to every
// project is not personal any more, whoever pressed the button.
func TestPersonalGrantRefusesAWildcardSubject(t *testing.T) {
	b, _, _, _ := newTestBroker(t)
	alicePAT := mintPersonal(t, b, "alice-pat", "alice@corp", "ghp_aliceahhh")
	shared := mintGitHub(t, b, "fleet-deploy", "ghp_sharedshared")

	for _, subject := range []string{"any", "project:*", "executor:*"} {
		t.Run(subject, func(t *testing.T) {
			sub, err := ParseSubject(subject)
			if err != nil {
				t.Fatalf("parse %q: %v", subject, err)
			}
			_, err = b.Grant(context.Background(), GrantRequest{
				SecretRef:   alicePAT.ID,
				Subject:     sub,
				Constraints: Constraints{Repos: []string{"org/*"}},
				TTL:         time.Hour,
				Actor:       "alice@corp",
				Viewer:      alice(),
			})
			if !errors.Is(err, ErrPersonalWildcard) {
				t.Fatalf("wildcard grant of a personal secret: err = %v, want ErrPersonalWildcard", err)
			}

			// The same wildcard over a shared secret is still allowed: this
			// restriction is a consequence of ownership, not a new blanket
			// policy, and breaking the fleet-wide grant would be a regression.
			if _, err := b.Grant(context.Background(), GrantRequest{
				SecretRef:   shared.ID,
				Subject:     sub,
				Constraints: Constraints{Repos: []string{"org/*"}},
				TTL:         time.Hour,
				Actor:       "ops",
			}); err != nil {
				t.Fatalf("wildcard grant of a shared secret was refused: %v", err)
			}
		})
	}
}

// TestPersonalSecretDeletionFollowsOwnership: the owner may destroy it, an
// admin may destroy it (offboarding), a colleague may not learn it exists.
func TestPersonalSecretDeletionFollowsOwnership(t *testing.T) {
	b, _, _, _ := newTestBroker(t)
	ctx := context.Background()

	mintPersonal(t, b, "alice-pat", "alice@corp", "ghp_aliceahhh")
	if err := b.DeleteSecretFor(ctx, "alice-pat", bob()); !errors.Is(err, ErrSecretNotFound) {
		t.Fatalf("bob deleting alice's secret: err = %v, want ErrSecretNotFound", err)
	}
	if err := b.DeleteSecretFor(ctx, "alice-pat", alice()); err != nil {
		t.Fatalf("alice deleting her own secret: %v", err)
	}

	// Offboarding: the departed user's account is gone, so only an admin is
	// left to clean up. This is the one case where Admin reaches a secret it
	// does not own, and it has to work or credentials outlive their owners.
	mintPersonal(t, b, "carol-pat", "carol@corp", "ghp_carolcarol")
	if err := b.DeleteSecretFor(ctx, "carol-pat", admin()); err != nil {
		t.Fatalf("admin offboarding carol's secret: %v", err)
	}
	if got, _ := b.ListSecretsFor(admin()); len(got) != 0 {
		t.Fatalf("after offboarding, %d secrets remain", len(got))
	}
}

// TestPersonalMintRefusesAnEmptyOwner pins the fail-closed direction of the
// mint path.
//
// The failure this prevents is specific and quiet: a handler whose identity
// lookup returned "" mints what the user asked to be private as a shared
// secret, which every maintainer can then read and spend. Nothing downstream
// would report that as wrong — a shared secret is a valid object — so the
// refusal has to happen here.
func TestPersonalMintRefusesAnEmptyOwner(t *testing.T) {
	b, _, _, _ := newTestBroker(t)

	_, err := b.Mint(context.Background(), MintRequest{
		Name:     "orphan",
		Kind:     KindGitHubPAT,
		Payload:  []byte("ghp_orphanorphan"),
		Actor:    "somebody",
		Personal: true, // asked for personal...
		Owner:    "  ", // ...but no identity resolved
	})
	if !errors.Is(err, ErrOwnerRequired) {
		t.Fatalf("mint with no owner: err = %v, want ErrOwnerRequired", err)
	}
	if got, _ := b.ListSecretsFor(admin()); len(got) != 0 {
		t.Fatalf("a refused mint left %d secrets behind", len(got))
	}
}

// TestOwnerComparisonIsCaseInsensitiveForEmails: IdPs are inconsistent about
// the case they release an email in, and a user locked out of their own
// credential by a capital letter is a bug, not a security win.
//
// The "sub:" form is the opposite case and is checked alongside: an issuer
// subject is opaque and case-sensitive, so folding it could merge two people.
func TestOwnerComparisonIsCaseInsensitiveForEmails(t *testing.T) {
	b, _, _, _ := newTestBroker(t)
	s := mintPersonal(t, b, "alice-pat", "Alice@Corp", "ghp_aliceahhh")

	if s.Owner != "alice@corp" {
		t.Fatalf("stored owner = %q, want it normalised to lowercase", s.Owner)
	}
	if !s.OwnedBy("ALICE@CORP") {
		t.Error("an email owner must match case-insensitively")
	}
	if s.OwnedBy("bob@corp") {
		t.Error("a different email must not match")
	}

	sub := mintPersonal(t, b, "sub-pat", "sub:AbCdEf", "ghp_subsubsubs")
	if sub.Owner != "sub:AbCdEf" {
		t.Fatalf("stored subject owner = %q, want the opaque part preserved", sub.Owner)
	}
	if sub.OwnedBy("sub:abcdef") {
		t.Error("two issuer subjects differing only in case are two different people")
	}
}

// TestSharedSecretsAreUnaffectedByOwnership is the compatibility guarantee:
// every secret that existed before this feature has an empty owner, and must
// behave exactly as it did.
func TestSharedSecretsAreUnaffectedByOwnership(t *testing.T) {
	b, _, _, _ := newTestBroker(t)
	shared := mintGitHub(t, b, "fleet-deploy", "ghp_sharedshared")

	if shared.Personal() {
		t.Fatal("a secret minted with no owner must not be personal")
	}
	for _, v := range []Viewer{alice(), bob(), admin(), {}} {
		if !shared.VisibleTo(v) {
			t.Errorf("shared secret invisible to %+v", v)
		}
		if !shared.SpendableBy(v) {
			t.Errorf("shared secret not spendable by %+v", v)
		}
		if !shared.DeletableBy(v) {
			t.Errorf("shared secret not deletable by %+v", v)
		}
	}

	// And the grant it produces carries no owner, so it stays visible in
	// everyone's listing rather than silently vanishing from the panel.
	g := grantTo(t, b, shared.ID, "project:/srv/app", Constraints{Repos: []string{"org/*"}}, time.Hour)
	if g.Personal() {
		t.Fatal("a grant over a shared secret must not be personal")
	}
	if !g.VisibleTo(Viewer{}) {
		t.Fatal("a grant over a shared secret must stay visible")
	}
}

// TestPersonalGrantsFollowTheirSecretInListings checks the denormalised owner
// on the grant row actually gets written, since every grant-side filter
// depends on it.
func TestPersonalGrantsFollowTheirSecretInListings(t *testing.T) {
	b, _, _, _ := newTestBroker(t)

	alicePAT := mintPersonal(t, b, "alice-pat", "alice@corp", "ghp_aliceahhh")
	sub, err := ParseSubject("project:/srv/alice-app")
	if err != nil {
		t.Fatalf("parse subject: %v", err)
	}
	if _, err := b.Grant(context.Background(), GrantRequest{
		SecretRef:   alicePAT.ID,
		Subject:     sub,
		Constraints: Constraints{Repos: []string{"org/*"}},
		TTL:         time.Hour,
		Actor:       "alice@corp",
		Viewer:      alice(),
	}); err != nil {
		t.Fatalf("alice granting her own secret: %v", err)
	}
	shared := mintGitHub(t, b, "fleet-deploy", "ghp_sharedshared")
	grantTo(t, b, shared.ID, "project:/srv/app", Constraints{Repos: []string{"org/*"}}, time.Hour)

	for _, tc := range []struct {
		name   string
		viewer Viewer
		want   int
	}{
		{"alice sees her grant and the shared one", alice(), 2},
		{"bob sees only the shared one", bob(), 1},
		{"an admin sees both", admin(), 2},
		{"anonymous sees only the shared one", Viewer{}, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := b.ListGrantsFor(GrantFilter{}, tc.viewer)
			if err != nil {
				t.Fatalf("list grants: %v", err)
			}
			if len(got) != tc.want {
				for _, g := range got {
					t.Logf("  grant %s secret=%s owner=%q", g.ID, g.SecretID, g.Owner)
				}
				t.Fatalf("saw %d grants, want %d", len(got), tc.want)
			}
		})
	}
}
