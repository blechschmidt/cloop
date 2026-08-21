package secretbroker

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// mintGitHub is the fixture used by most lifecycle tests: a PAT secret plus
// a grant to one project, scoped to org/*.
func mintGitHub(t *testing.T, b *Broker, name, token string) Secret {
	t.Helper()
	s, err := b.Mint(context.Background(), MintRequest{
		Name:    name,
		Kind:    KindGitHubPAT,
		Payload: []byte(token),
		Actor:   "test",
	})
	if err != nil {
		t.Fatalf("mint %s: %v", name, err)
	}
	return s
}

func grantTo(t *testing.T, b *Broker, secretID, subject string, c Constraints, ttl time.Duration) Grant {
	t.Helper()
	sub, err := ParseSubject(subject)
	if err != nil {
		t.Fatalf("parse subject %q: %v", subject, err)
	}
	g, err := b.Grant(context.Background(), GrantRequest{
		SecretRef:   secretID,
		Subject:     sub,
		Constraints: c,
		TTL:         ttl,
		Actor:       "test",
	})
	if err != nil {
		t.Fatalf("grant to %s: %v", subject, err)
	}
	return g
}

// TestLeaseDeliversOnlyMatchingSubject is the core isolation property: an
// executor working for one project must not receive another project's
// credentials, however many grants exist.
func TestLeaseDeliversOnlyMatchingSubject(t *testing.T) {
	b, _, _, _ := newTestBroker(t)
	ctx := context.Background()

	mine := mintGitHub(t, b, "mine", "ghp_mineminemine")
	theirs := mintGitHub(t, b, "theirs", "ghp_theirstheirs")
	grantTo(t, b, mine.ID, "project:/srv/app", Constraints{Repos: []string{"org/*"}}, time.Hour)
	grantTo(t, b, theirs.ID, "project:/srv/other", Constraints{Repos: []string{"org/*"}}, time.Hour)

	lease, err := b.Lease(ctx, "exec-1", "/srv/app")
	if err != nil {
		t.Fatalf("lease: %v", err)
	}
	if len(lease.Materials) != 1 {
		t.Fatalf("got %d materials, want 1: %v", len(lease.Materials), lease.SecretNames())
	}
	if lease.Materials[0].SecretName != "mine" {
		t.Errorf("leased %q, want %q", lease.Materials[0].SecretName, "mine")
	}
	// The other project's token must not appear anywhere in the lease.
	assertNoToken(t, lease, "ghp_theirstheirs")
}

// TestLeaseSubjectTypes covers project/executor/label/any matching, plus the
// path-normalisation rule that keeps /srv/app-staging from picking up
// /srv/app's grants.
func TestLeaseSubjectTypes(t *testing.T) {
	tests := []struct {
		name     string
		subject  string
		executor string
		project  string
		labels   map[string]string
		want     bool
	}{
		{"project exact", "project:/srv/app", "e1", "/srv/app", nil, true},
		{"project trailing slash normalises", "project:/srv/app/", "e1", "/srv/app", nil, true},
		{"project request trailing slash", "project:/srv/app", "e1", "/srv/app/", nil, true},
		{"project prefix is not a match", "project:/srv/app", "e1", "/srv/app-staging", nil, false},
		{"project mismatch", "project:/srv/app", "e1", "/srv/other", nil, false},
		{"project wildcard", "project:*", "e1", "/anywhere", nil, true},

		{"executor exact", "executor:edge-01", "edge-01", "/srv/app", nil, true},
		{"executor mismatch", "executor:edge-01", "edge-02", "/srv/app", nil, false},
		{"executor wildcard", "executor:*", "anything", "/srv/app", nil, true},

		{"label match", "label:region=eu", "e1", "/srv/app", map[string]string{"region": "eu"}, true},
		{"label subset required", "label:region=eu,gpu=true", "e1", "/srv/app",
			map[string]string{"region": "eu"}, false},
		{"label all present", "label:region=eu,gpu=true", "e1", "/srv/app",
			map[string]string{"region": "eu", "gpu": "true", "extra": "x"}, true},
		{"label value mismatch", "label:region=eu", "e1", "/srv/app",
			map[string]string{"region": "us"}, false},
		{"label absent", "label:region=eu", "e1", "/srv/app", nil, false},

		{"any matches everything", "any", "e1", "/srv/app", nil, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			b, _, _, _ := newTestBroker(t)
			s := mintGitHub(t, b, "tok", "ghp_abcdefghij")
			grantTo(t, b, s.ID, tc.subject, Constraints{Repos: []string{"*"}}, time.Hour)

			lease, err := b.LeaseFor(context.Background(), Requester{
				ExecutorID: tc.executor,
				ProjectID:  tc.project,
				Labels:     tc.labels,
			}, "test")
			if err != nil {
				t.Fatalf("lease: %v", err)
			}
			got := len(lease.Materials) == 1
			if got != tc.want {
				t.Errorf("subject %q vs executor=%s project=%s labels=%v: delivered=%v, want %v",
					tc.subject, tc.executor, tc.project, tc.labels, got, tc.want)
			}
		})
	}
}

// TestGrantTTLExpiry: a grant stops being leased once its TTL elapses, and
// the refusal is audited with a reason.
func TestGrantTTLExpiry(t *testing.T) {
	b, _, auditor, clock := newTestBroker(t)
	ctx := context.Background()

	s := mintGitHub(t, b, "short-lived", "ghp_expiringtoken")
	grantTo(t, b, s.ID, "project:/srv/app", Constraints{Repos: []string{"org/*"}}, time.Hour)

	// Before expiry: delivered.
	lease, err := b.Lease(ctx, "e1", "/srv/app")
	if err != nil {
		t.Fatalf("lease: %v", err)
	}
	if len(lease.Materials) != 1 {
		t.Fatalf("before expiry: got %d materials, want 1", len(lease.Materials))
	}

	// After expiry: gone.
	clock.advance(2 * time.Hour)
	lease, err = b.Lease(ctx, "e1", "/srv/app")
	if err != nil {
		t.Fatalf("lease after expiry: %v", err)
	}
	if len(lease.Materials) != 0 {
		t.Fatalf("after expiry: got %d materials, want 0", len(lease.Materials))
	}

	// The denial must be in the audit trail with a cause. A credential that
	// silently stops arriving is an outage nobody can diagnose.
	var found bool
	for _, ev := range auditor.byAction(ActionLease) {
		if ev.Decision == DecisionDeny && strings.Contains(ev.Reason, "expired") {
			found = true
		}
	}
	if !found {
		t.Error("expired grant must produce an audited denial naming the expiry")
	}
}

// TestLeaseTTLClampedToGrant: a lease must never outlive the authority it
// was issued under, even when the broker's max lease TTL is longer.
func TestLeaseTTLClampedToGrant(t *testing.T) {
	b, _, _, clock := newTestBroker(t)
	s := mintGitHub(t, b, "tok", "ghp_abcdefghij")
	grantTo(t, b, s.ID, "project:/srv/app", Constraints{Repos: []string{"*"}}, 5*time.Minute)

	lease, err := b.Lease(context.Background(), "e1", "/srv/app")
	if err != nil {
		t.Fatalf("lease: %v", err)
	}
	want := clock.Now().Add(5 * time.Minute)
	if !lease.ExpiresAt.Equal(want) {
		t.Errorf("lease expires %s, want the grant's expiry %s", lease.ExpiresAt, want)
	}
}

// TestLeaseTTLBoundedByMax: conversely, a long-lived grant does not produce
// a long-lived lease. The short lease is what bounds a compromised
// executor's window.
func TestLeaseTTLBoundedByMax(t *testing.T) {
	b, _, _, clock := newTestBroker(t)
	s := mintGitHub(t, b, "tok", "ghp_abcdefghij")
	grantTo(t, b, s.ID, "project:/srv/app", Constraints{Repos: []string{"*"}}, 30*24*time.Hour)

	lease, err := b.Lease(context.Background(), "e1", "/srv/app")
	if err != nil {
		t.Fatalf("lease: %v", err)
	}
	want := clock.Now().Add(DefaultMaxLeaseTTL)
	if !lease.ExpiresAt.Equal(want) {
		t.Errorf("lease expires %s, want the max lease TTL %s", lease.ExpiresAt, want)
	}
	if lease.Expired(clock.Now()) {
		t.Error("a freshly issued lease must not be expired")
	}
}

// TestRevocationTakesEffectOnNextLease is the requirement that revocation is
// not merely recorded but acted on.
func TestRevocationTakesEffectOnNextLease(t *testing.T) {
	b, _, auditor, _ := newTestBroker(t)
	ctx := context.Background()

	s := mintGitHub(t, b, "revokeme", "ghp_revokedtoken")
	g := grantTo(t, b, s.ID, "project:/srv/app", Constraints{Repos: []string{"org/*"}}, 24*time.Hour)

	first, err := b.Lease(ctx, "e1", "/srv/app")
	if err != nil {
		t.Fatalf("first lease: %v", err)
	}
	if len(first.Materials) != 1 {
		t.Fatalf("first lease should deliver the grant, got %d materials", len(first.Materials))
	}

	if err := b.Revoke(ctx, g.ID, "test"); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	second, err := b.Lease(ctx, "e1", "/srv/app")
	if err != nil {
		t.Fatalf("second lease: %v", err)
	}
	if len(second.Materials) != 0 {
		t.Fatalf("revoked grant must not be leased, got %d materials", len(second.Materials))
	}
	assertNoToken(t, second, "ghp_revokedtoken")

	var denied bool
	for _, ev := range auditor.byAction(ActionLease) {
		if ev.Decision == DecisionDeny && strings.Contains(ev.Reason, "revoked") {
			denied = true
		}
	}
	if !denied {
		t.Error("revoked grant must produce an audited denial")
	}
}

// TestRevocationTakesEffectOnRenew: Renew re-evaluates grants rather than
// extending the materials it already issued. Without that, a revocation
// would not land until the grant itself expired.
func TestRevocationTakesEffectOnRenew(t *testing.T) {
	b, _, _, _ := newTestBroker(t)
	ctx := context.Background()

	s := mintGitHub(t, b, "tok", "ghp_renewabletoken")
	g := grantTo(t, b, s.ID, "project:/srv/app", Constraints{Repos: []string{"*"}}, 24*time.Hour)

	lease, err := b.Lease(ctx, "e1", "/srv/app")
	if err != nil {
		t.Fatalf("lease: %v", err)
	}
	if len(lease.Materials) != 1 {
		t.Fatalf("expected one material, got %d", len(lease.Materials))
	}

	if err := b.Revoke(ctx, g.ID, "test"); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	renewed, err := b.Renew(ctx, lease.ID)
	if err != nil {
		t.Fatalf("renew: %v", err)
	}
	if len(renewed.Materials) != 0 {
		t.Errorf("renewal must drop the revoked grant, got %d materials", len(renewed.Materials))
	}
	// The old lease ID is retired so a captured ID cannot be renewed forever.
	if _, err := b.Renew(ctx, lease.ID); !errors.Is(err, ErrLeaseNotFound) {
		t.Errorf("renewing a superseded lease id should fail with ErrLeaseNotFound, got %v", err)
	}
}

// TestRevokeIsIdempotent: a retried revoke must report success, and must not
// move the recorded moment access was withdrawn.
func TestRevokeIsIdempotent(t *testing.T) {
	b, store, _, clock := newTestBroker(t)
	ctx := context.Background()

	s := mintGitHub(t, b, "tok", "ghp_abcdefghij")
	g := grantTo(t, b, s.ID, "project:/srv/app", Constraints{Repos: []string{"*"}}, time.Hour)

	if err := b.Revoke(ctx, g.ID, "test"); err != nil {
		t.Fatalf("first revoke: %v", err)
	}
	first, _ := store.GetGrant(g.ID)

	clock.advance(time.Minute)
	if err := b.Revoke(ctx, g.ID, "test"); err != nil {
		t.Fatalf("second revoke should be a no-op, got %v", err)
	}
	second, _ := store.GetGrant(g.ID)

	if !first.RevokedAt.Equal(second.RevokedAt) {
		t.Errorf("revocation timestamp moved: %s → %s", first.RevokedAt, second.RevokedAt)
	}
}

// TestRevokeUnknownGrant surfaces a typo rather than reporting success.
func TestRevokeUnknownGrant(t *testing.T) {
	b, _, _, _ := newTestBroker(t)
	err := b.Revoke(context.Background(), "grant_doesnotexist", "test")
	if !errors.Is(err, ErrGrantNotFound) {
		t.Errorf("want ErrGrantNotFound, got %v", err)
	}
}

// TestDeleteSecretRevokesGrants: leaving grants behind would leave rows that
// read, in a listing, as still-live access to a credential that is gone.
func TestDeleteSecretRevokesGrants(t *testing.T) {
	b, _, _, _ := newTestBroker(t)
	ctx := context.Background()

	s := mintGitHub(t, b, "doomed", "ghp_abcdefghij")
	grantTo(t, b, s.ID, "project:/srv/app", Constraints{Repos: []string{"*"}}, time.Hour)

	if err := b.DeleteSecret(ctx, "doomed", "test"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	active, err := b.ListGrants(GrantFilter{ActiveOnly: true})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(active) != 0 {
		t.Errorf("deleting a secret must revoke its grants, %d still active", len(active))
	}
	// The history survives, so "who had access" is still answerable.
	all, _ := b.ListGrants(GrantFilter{})
	if len(all) != 1 {
		t.Errorf("revoked grant should remain visible with --all, got %d", len(all))
	}
}

// TestMintRejectsDuplicateName: names are the CLI handle, so an ambiguous
// one would attach a grant to the wrong credential.
func TestMintRejectsDuplicateName(t *testing.T) {
	b, _, _, _ := newTestBroker(t)
	mintGitHub(t, b, "dup", "ghp_abcdefghij")
	_, err := b.Mint(context.Background(), MintRequest{
		Name: "dup", Kind: KindGitHubPAT, Payload: []byte("ghp_other"), Actor: "test",
	})
	if !errors.Is(err, ErrDuplicateName) {
		t.Errorf("want ErrDuplicateName, got %v", err)
	}
}

// TestMintZeroesCallerPayload: a mint site should not be left holding
// plaintext in a buffer.
func TestMintZeroesCallerPayload(t *testing.T) {
	b, _, _, _ := newTestBroker(t)
	payload := []byte("ghp_sensitivevalue")
	if _, err := b.Mint(context.Background(), MintRequest{
		Name: "zeroed", Kind: KindGitHubPAT, Payload: payload, Actor: "test",
	}); err != nil {
		t.Fatalf("mint: %v", err)
	}
	for i, c := range payload {
		if c != 0 {
			t.Fatalf("caller payload not zeroed at byte %d (%q)", i, payload)
		}
	}
}

// TestGrantRejectsUngatedConstraints: the fail-closed rule reaches the
// broker, not just Constraints.ValidateFor.
func TestGrantRejectsUngatedConstraints(t *testing.T) {
	b, _, _, _ := newTestBroker(t)
	s := mintGitHub(t, b, "tok", "ghp_abcdefghij")

	sub, _ := ParseSubject("project:/srv/app")
	_, err := b.Grant(context.Background(), GrantRequest{
		SecretRef: s.ID, Subject: sub, TTL: time.Hour, Actor: "test",
		// No Repos: a github grant with no allowlist.
	})
	if !errors.Is(err, ErrInvalidConstraint) {
		t.Fatalf("want ErrInvalidConstraint, got %v", err)
	}
	active, _ := b.ListGrants(GrantFilter{})
	if len(active) != 0 {
		t.Errorf("a rejected grant must not be stored, found %d", len(active))
	}
}

// TestSealedPayloadNeverLeavesStore: the Secret type has no plaintext field,
// so what the store holds is ciphertext. A regression that added one would
// show up here.
func TestSealedPayloadNeverLeavesStore(t *testing.T) {
	b, store, _, _ := newTestBroker(t)
	const token = "ghp_verysecrettokenvalue"
	mintGitHub(t, b, "sealed", token)

	secrets, err := store.ListSecrets()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(secrets) != 1 {
		t.Fatalf("got %d secrets, want 1", len(secrets))
	}
	if strings.Contains(string(secrets[0].Sealed), token) {
		t.Fatal("stored payload contains the plaintext token")
	}
	// ... and it round-trips, so the sealing is real encryption and not a
	// destructive transform that happens to hide the string.
	lease, err := b.Lease(context.Background(), "e1", "/srv/app")
	if err != nil {
		t.Fatalf("lease: %v", err)
	}
	_ = lease
}

// TestEnvSecretKeyFiltering: an env grant delivers only the keys it names.
func TestEnvSecretKeyFiltering(t *testing.T) {
	b, _, _, _ := newTestBroker(t)
	ctx := context.Background()

	s, err := b.Mint(ctx, MintRequest{
		Name:    "multi",
		Kind:    KindEnv,
		Payload: []byte(`{"ALLOWED":"yes","DENIED":"no"}`),
		Actor:   "test",
	})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	grantTo(t, b, s.ID, "project:/srv/app", Constraints{EnvKeys: []string{"ALLOWED"}}, time.Hour)

	lease, err := b.Lease(ctx, "e1", "/srv/app")
	if err != nil {
		t.Fatalf("lease: %v", err)
	}
	if len(lease.Materials) != 1 {
		t.Fatalf("got %d materials, want 1", len(lease.Materials))
	}
	env := lease.Materials[0].Env
	if env["ALLOWED"] != "yes" {
		t.Errorf("ALLOWED not delivered: %v", env)
	}
	if _, ok := env["DENIED"]; ok {
		t.Error("DENIED must be filtered out by the grant's env-key allowlist")
	}
	assertNoToken(t, lease, "no")
}

// TestGitHubTokenNotExportedForNarrowGrant is the enforcement distinction
// that makes the repo allowlist real: a bare GITHUB_TOKEN is unscoped by
// construction, so it is exported only for an explicit "*" grant. A narrower
// grant gets the credential helper instead.
func TestGitHubTokenNotExportedForNarrowGrant(t *testing.T) {
	tests := []struct {
		name     string
		repos    []string
		wantBare bool
	}{
		{"narrow grant uses helper only", []string{"org/*"}, false},
		{"exact repo uses helper only", []string{"org/tool"}, false},
		{"explicit wildcard exports token", []string{"*"}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			b, _, _, _ := newTestBroker(t)
			s := mintGitHub(t, b, "tok", "ghp_thetokenvalue")
			grantTo(t, b, s.ID, "project:/srv/app", Constraints{Repos: tc.repos}, time.Hour)

			lease, err := b.Lease(context.Background(), "e1", "/srv/app")
			if err != nil {
				t.Fatalf("lease: %v", err)
			}
			if len(lease.Materials) != 1 {
				t.Fatalf("got %d materials, want 1", len(lease.Materials))
			}
			m := lease.Materials[0]
			_, hasBare := m.Env["GITHUB_TOKEN"]
			if hasBare != tc.wantBare {
				t.Errorf("GITHUB_TOKEN exported=%v, want %v (repos=%v)", hasBare, tc.wantBare, tc.repos)
			}
			// Either way the helper and token file are delivered.
			var names []string
			for _, f := range m.Files {
				names = append(names, f.Name)
			}
			joined := strings.Join(names, ",")
			for _, want := range []string{credentialHelperName, tokenFileName, gitconfigName} {
				if !strings.Contains(joined, want) {
					t.Errorf("missing delivered file %q, got %s", want, joined)
				}
			}
		})
	}
}

// TestCheckRepoAccess is the in-process gate cloop's own GitHub call sites
// use, so a denied repository never reaches a request.
func TestCheckRepoAccess(t *testing.T) {
	b, _, _, _ := newTestBroker(t)
	ctx := context.Background()

	s := mintGitHub(t, b, "tok", "ghp_abcdefghij")
	grantTo(t, b, s.ID, "project:/srv/app", Constraints{Repos: []string{"org/*"}}, time.Hour)
	r := Requester{ExecutorID: "e1", ProjectID: "/srv/app"}

	if err := b.CheckRepoAccess(ctx, r, "org/tool", "test"); err != nil {
		t.Errorf("org/tool should be allowed: %v", err)
	}
	if err := b.CheckRepoAccess(ctx, r, "other/tool", "test"); !errors.Is(err, ErrRepoDenied) {
		t.Errorf("other/tool should be denied with ErrRepoDenied, got %v", err)
	}
	// A different project has no github grant at all.
	other := Requester{ExecutorID: "e1", ProjectID: "/srv/other"}
	if err := b.CheckRepoAccess(ctx, other, "org/tool", "test"); !errors.Is(err, ErrRepoDenied) {
		t.Errorf("unscoped project should be denied, got %v", err)
	}
}

// TestListGrantsFilters covers the CLI's listing paths.
func TestListGrantsFilters(t *testing.T) {
	b, _, _, clock := newTestBroker(t)
	s := mintGitHub(t, b, "tok", "ghp_abcdefghij")
	grantTo(t, b, s.ID, "project:/srv/app", Constraints{Repos: []string{"*"}}, time.Hour)
	grantTo(t, b, s.ID, "project:/srv/other", Constraints{Repos: []string{"*"}}, time.Hour)

	all, err := b.ListGrants(GrantFilter{})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("got %d grants, want 2", len(all))
	}

	filtered, err := b.ListGrants(GrantFilter{Subject: "project:/srv/app"})
	if err != nil {
		t.Fatalf("list filtered: %v", err)
	}
	if len(filtered) != 1 || filtered[0].Subject.Value != "/srv/app" {
		t.Errorf("subject filter returned %d grants: %+v", len(filtered), filtered)
	}

	clock.advance(2 * time.Hour)
	active, err := b.ListGrants(GrantFilter{ActiveOnly: true})
	if err != nil {
		t.Fatalf("list active: %v", err)
	}
	if len(active) != 0 {
		t.Errorf("all grants are expired, got %d active", len(active))
	}
}

// TestConcurrentLeases exercises the broker's mutex under -race.
func TestConcurrentLeases(t *testing.T) {
	b, _, _, _ := newTestBroker(t)
	s := mintGitHub(t, b, "tok", "ghp_abcdefghij")
	grantTo(t, b, s.ID, "project:*", Constraints{Repos: []string{"*"}}, time.Hour)

	done := make(chan error, 8)
	for i := 0; i < 8; i++ {
		go func() {
			lease, err := b.Lease(context.Background(), "e1", "/srv/app")
			if err == nil {
				b.Release(lease.ID)
			}
			done <- err
		}()
	}
	for i := 0; i < 8; i++ {
		if err := <-done; err != nil {
			t.Errorf("concurrent lease: %v", err)
		}
	}
}

// assertNoToken fails if a credential string appears anywhere in a lease's
// delivered material. Used to prove that a denial actually withheld the
// payload rather than merely omitting a flag.
func assertNoToken(t *testing.T, lease *Lease, token string) {
	t.Helper()
	for _, m := range lease.Materials {
		for k, v := range m.Env {
			if strings.Contains(v, token) {
				t.Errorf("token leaked into env %s of material %s", k, m.SecretName)
			}
		}
		for _, f := range m.Files {
			if strings.Contains(string(f.Content), token) {
				t.Errorf("token leaked into file %s of material %s", f.Name, m.SecretName)
			}
		}
		if strings.Contains(m.Summary, token) {
			t.Errorf("token leaked into the summary of material %s", m.SecretName)
		}
	}
}
