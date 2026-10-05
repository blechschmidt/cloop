package secretbroker

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

// Tests for the names-only environment preview and for withholding a grant
// from one lease (Task 20379).

const offerCanary = "sk-ant-oat01-PREVIEWCANARY-must-never-surface"

func mintEnv(t *testing.T, b *Broker, name, payload string) Secret {
	t.Helper()
	s, err := b.Mint(context.Background(), MintRequest{
		Name: name, Kind: KindEnv, Payload: []byte(payload), Actor: "test",
	})
	if err != nil {
		t.Fatalf("mint %s: %v", name, err)
	}
	return s
}

func TestEnvOffersNamesTheKeysAGrantWouldDeliverAndNothingElse(t *testing.T) {
	b, _, audit, _ := newTestBroker(t)

	harness := mintEnv(t, b, "harness", `{"CLAUDE_CODE_OAUTH_TOKEN":"`+offerCanary+`","OTHER":"x"}`)
	g := grantTo(t, b, harness.ID, "project:/srv/app", Constraints{EnvKeys: []string{"CLAUDE_CODE_OAUTH_TOKEN"}}, time.Hour)
	// Noise the preview must leave out: another project's grant, and a grant
	// of a kind that puts nothing into a variable by name.
	elsewhere := mintEnv(t, b, "elsewhere", `{"ANTHROPIC_API_KEY":"sk-ant-api03-elsewhere-elsewhere"}`)
	grantTo(t, b, elsewhere.ID, "project:/srv/other", Constraints{}, time.Hour)
	pat := mintGitHub(t, b, "pat", "ghp_previewpreviewpreviewpreviewpreview")
	grantTo(t, b, pat.ID, "project:/srv/app", Constraints{Repos: []string{"org/*"}}, time.Hour)

	before := len(audit.all())
	// A trailing slash is the same project, as it is to LeaseFor.
	offers, err := b.EnvOffers(Requester{ExecutorID: "e1", ProjectID: "/srv/app/"})
	if err != nil {
		t.Fatalf("EnvOffers: %v", err)
	}
	if len(offers) != 1 {
		t.Fatalf("got %d offers, want exactly the env grant to /srv/app: %+v", len(offers), offers)
	}
	o := offers[0]
	if o.Grant.ID != g.ID || o.Secret.Name != "harness" {
		t.Errorf("offer = grant %s secret %s, want %s/harness", o.Grant.ID, o.Secret.Name, g.ID)
	}
	if !reflect.DeepEqual(o.Keys, []string{"CLAUDE_CODE_OAUTH_TOKEN"}) {
		t.Errorf("keys = %v, want only the key the grant allows", o.Keys)
	}
	if !o.Active(time.Date(2026, 3, 1, 12, 30, 0, 0, time.UTC)) {
		t.Error("an unexpired grant's offer is not active")
	}
	if strings.Contains(fmt.Sprintf("%+v", offers), offerCanary) {
		t.Fatal("the preview carries a credential value")
	}
	if got := len(audit.all()); got != before {
		t.Errorf("a preview wrote %d audit rows; it leases nothing and must write none", got-before)
	}
}

func TestEnvOffersReportExpiryAndDropRevocation(t *testing.T) {
	b, _, _, clock := newTestBroker(t)
	s := mintEnv(t, b, "harness", `{"ANTHROPIC_API_KEY":"sk-ant-api03-expiry-expiry-expiry"}`)
	short := grantTo(t, b, s.ID, "project:/srv/app", Constraints{}, 5*time.Minute)
	revoked := grantTo(t, b, s.ID, "project:/srv/app", Constraints{}, time.Hour)
	if err := b.Revoke(context.Background(), revoked.ID, "test"); err != nil {
		t.Fatal(err)
	}
	clock.advance(10 * time.Minute)

	offers, err := b.EnvOffers(Requester{ExecutorID: "e1", ProjectID: "/srv/app"})
	if err != nil {
		t.Fatal(err)
	}
	if len(offers) != 1 || offers[0].Grant.ID != short.ID {
		t.Fatalf("offers = %+v, want only the expired grant (a revoked one is a decision, not a lapse)", offers)
	}
	if offers[0].Active(clock.Now()) {
		t.Error("an expired grant's offer reports active")
	}
}

// The preview and the lease must agree about which keys a payload defines, for
// every payload shape the store accepts — otherwise the hub would refuse a run
// whose lease would have worked, or start one that reaches claude logged out.
func TestEnvOffersAgreeWithTheLeaseOnEveryPayloadShape(t *testing.T) {
	cases := []struct {
		name, payload string
		allow         []string
	}{
		{"object", `{"CLAUDE_CODE_OAUTH_TOKEN":"a","ANTHROPIC_BASE_URL":"https://relay"}`, nil},
		{"object-narrowed", `{"ANTHROPIC_AUTH_TOKEN":"a","ANTHROPIC_BASE_URL":"b","X":"c"}`, []string{"ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_BASE_URL"}},
		// A bare value is the single variable named after the secret.
		{"anthropic-api-key", `sk-ant-api03-barevalue-barevalue`, nil},
		// Not every JSON object is the object shape: one with a non-string
		// value is a bare value to the lease, so it must be to the preview.
		{"claude-code-oauth-token", `{"CLAUDE_CODE_OAUTH_TOKEN": 7}`, nil},
		// A key K=V cannot carry is dropped by both.
		{"badkey", `{"GOOD":"1","BAD=KEY":"2"}`, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, _, _, _ := newTestBroker(t)
			s := mintEnv(t, b, tc.name, tc.payload)
			grantTo(t, b, s.ID, "project:/srv/app", Constraints{EnvKeys: tc.allow}, time.Hour)

			offers, err := b.EnvOffers(Requester{ExecutorID: "e1", ProjectID: "/srv/app"})
			if err != nil || len(offers) != 1 {
				t.Fatalf("EnvOffers = %+v, %v", offers, err)
			}
			lease, err := b.Lease(context.Background(), "e1", "/srv/app")
			if err != nil {
				t.Fatal(err)
			}
			defer b.Release(lease.ID)
			var leased []string
			for _, m := range lease.Materials {
				for k := range m.Env {
					leased = append(leased, k)
				}
			}
			sort.Strings(leased)
			if !reflect.DeepEqual(offers[0].Keys, leased) {
				t.Errorf("preview keys %v, lease keys %v", offers[0].Keys, leased)
			}
		})
	}
}

func TestEnvKeyNamesForFollowsVisibility(t *testing.T) {
	b, _, _, _ := newTestBroker(t)
	ctx := context.Background()
	mine, err := b.Mint(ctx, MintRequest{
		Name: "alice-claude", Kind: KindEnv, Personal: true, Owner: "alice@corp.example",
		Payload: []byte(`{"CLAUDE_CODE_OAUTH_TOKEN":"` + offerCanary + `"}`), Actor: "alice@corp.example",
	})
	if err != nil {
		t.Fatal(err)
	}

	keys, err := b.EnvKeyNamesFor(mine.Name, Viewer{Identity: "Alice@corp.example"})
	if err != nil || !reflect.DeepEqual(keys, []string{"CLAUDE_CODE_OAUTH_TOKEN"}) {
		t.Fatalf("owner's view = %v, %v", keys, err)
	}
	// Somebody else is told it does not exist, by name and by id alike.
	for _, ref := range []string{mine.Name, mine.ID} {
		if _, err := b.EnvKeyNamesFor(ref, Viewer{Identity: "bob@corp.example"}); !errors.Is(err, ErrSecretNotFound) {
			t.Errorf("another user reading %s: err = %v, want ErrSecretNotFound", ref, err)
		}
	}
	pat := mintGitHub(t, b, "pat", "ghp_keynameskeynameskeynameskeynames")
	if _, err := b.EnvKeyNamesFor(pat.ID, PrivilegedViewer("ops")); !errors.Is(err, ErrInvalidKind) {
		t.Errorf("a github_pat: err = %v, want ErrInvalidKind", err)
	}
}

func TestWithheldGrantIsDeniedAuditedAndStaysWithheldOnRenew(t *testing.T) {
	b, _, audit, _ := newTestBroker(t)
	ctx := context.Background()
	keep := mintEnv(t, b, "keep", `{"CLAUDE_CODE_OAUTH_TOKEN":"sk-ant-oat01-keepkeepkeepkeep"}`)
	drop := mintEnv(t, b, "drop", `{"CLAUDE_CODE_OAUTH_TOKEN":"`+offerCanary+`"}`)
	grantTo(t, b, keep.ID, "project:/srv/app", Constraints{}, time.Hour)
	dropped := grantTo(t, b, drop.ID, "project:/srv/app", Constraints{}, time.Hour)

	const why = "personal credential of alice@corp.example is not spent on a run bob@corp.example started"
	lease, err := b.LeaseFor(ctx, Requester{
		ExecutorID: "e1", ProjectID: "/srv/app",
		Withhold: map[string]string{dropped.ID: why},
	}, "hub")
	if err != nil {
		t.Fatal(err)
	}
	check := func(l *Lease, when string) {
		t.Helper()
		if len(l.Materials) != 1 || l.Materials[0].SecretName != "keep" {
			t.Fatalf("%s: materials = %+v, want only the grant not withheld", when, l.Materials)
		}
		assertNoToken(t, l, offerCanary)
	}
	check(lease, "lease")

	denied := 0
	for _, ev := range audit.byAction(ActionLease) {
		if ev.GrantID == dropped.ID && ev.Decision == DecisionDeny && strings.Contains(ev.Reason, why) {
			denied++
		}
	}
	if denied != 1 {
		t.Errorf("found %d denial rows naming the withheld grant and why, want 1", denied)
	}

	renewed, err := b.Renew(ctx, lease.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Release(renewed.ID)
	check(renewed, "renewal")
}

// The horizon is the grant a lease would end with: the earliest expiry among
// the grants it would consider, of any kind, leaving out what is revoked,
// expired, withheld, or never expires.
func TestLeaseHorizonIsTheFirstGrantALeaseWouldEndWith(t *testing.T) {
	b, _, audit, clock := newTestBroker(t)
	ctx := context.Background()
	env := mintEnv(t, b, "env", `{"CLAUDE_CODE_OAUTH_TOKEN":"`+offerCanary+`"}`)
	pat := mintGitHub(t, b, "pat", "ghp_horizonhorizonhorizonhorizonhori")

	grantTo(t, b, env.ID, "project:/srv/app", Constraints{}, 30*24*time.Hour)
	gh := grantTo(t, b, pat.ID, "project:/srv/app", Constraints{Repos: []string{"org/*"}}, 2*time.Hour)
	withheld := grantTo(t, b, env.ID, "project:/srv/app", Constraints{}, time.Hour)
	revoked := grantTo(t, b, env.ID, "project:/srv/app", Constraints{}, 30*time.Minute)
	if err := b.Revoke(ctx, revoked.ID, "test"); err != nil {
		t.Fatal(err)
	}
	lapsing := grantTo(t, b, env.ID, "project:/srv/app", Constraints{}, 10*time.Minute)
	grantTo(t, b, env.ID, "project:/srv/other", Constraints{}, time.Minute)
	clock.advance(15 * time.Minute) // the 10-minute grant has lapsed

	before := len(audit.all())
	first, ok, err := b.LeaseHorizon(Requester{
		ExecutorID: "e1", ProjectID: "/srv/app", Withhold: map[string]string{withheld.ID: "test"},
	})
	if err != nil || !ok {
		t.Fatalf("LeaseHorizon = %v, %v", ok, err)
	}
	if first.ID != gh.ID {
		t.Errorf("horizon = %s, want the 2-hour GitHub grant %s (lapsed %s, withheld %s, revoked %s left out)",
			first.ID, gh.ID, lapsing.ID, withheld.ID, revoked.ID)
	}
	if len(audit.all()) != before {
		t.Error("a horizon preview wrote audit rows")
	}

	// A lease issued now ends exactly there.
	lease, err := b.LeaseFor(ctx, Requester{ExecutorID: "e1", ProjectID: "/srv/app",
		Withhold: map[string]string{withheld.ID: "test"}}, "test")
	if err != nil {
		t.Fatal(err)
	}
	defer b.Release(lease.ID)
	if lease.ExpiresAt.After(first.ExpiresAt) {
		t.Errorf("the lease ends at %s, after the horizon %s", lease.ExpiresAt, first.ExpiresAt)
	}

	if _, ok, err := b.LeaseHorizon(Requester{ExecutorID: "e1", ProjectID: "/srv/none"}); ok || err != nil {
		t.Errorf("a requester with no grants has a horizon: %v %v", ok, err)
	}
}
