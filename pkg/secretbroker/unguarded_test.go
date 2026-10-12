package secretbroker

// unguarded_test.go: a kubeconfig grant whose constraints only the Kubernetes
// access monitor enforces is not delivered without one, unless an
// administrator acknowledged it — and the acknowledgement is validated,
// audited and withdrawable (Task 20420).

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// ackUnguarded records an acknowledgement on grantID, for a test whose subject
// is delivery without the monitor rather than the refusal of it.
func ackUnguarded(t *testing.T, b *Broker, grantID string) {
	t.Helper()
	if _, err := b.AcknowledgeUnguarded(context.Background(), UnguardedAckRequest{
		GrantID: grantID, Actor: "admin@example.com", Reason: "a test cluster with no monitor",
	}); err != nil {
		t.Fatalf("acknowledge %s: %v", grantID, err)
	}
}

// allKubeVerbs is a grant that claims every verb, which no monitor is needed
// to honour.
var allKubeVerbs = []string{"get", "list", "watch", "create", "update", "patch", "delete", "deletecollection"}

func TestKubeMonitorOnlyNamesWhatOnlyTheMonitorEnforces(t *testing.T) {
	for _, tc := range []struct {
		name string
		c    Constraints
		want []string
	}{
		{"read-only by default", Constraints{Contexts: []string{"prod"}}, []string{"read-only access (get, list, watch)"}},
		{"a namespace", Constraints{Namespaces: []string{"app"}, Verbs: allKubeVerbs},
			[]string{"namespaces app"}},
		{"both", Constraints{Namespaces: []string{"app", "web"}, Verbs: []string{"get", "create"}},
			[]string{"namespaces app, web", "verbs get, create"}},
		{"every namespace and verb", Constraints{Namespaces: []string{"*"}, Verbs: allKubeVerbs}, nil},
		{"contexts and every verb", Constraints{Contexts: []string{"prod"}, Verbs: allKubeVerbs}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.c.KubeMonitorOnly()
			if strings.Join(got, "|") != strings.Join(tc.want, "|") {
				t.Errorf("KubeMonitorOnly() = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestConstrainedKubeconfigIsNotDeliveredWithoutTheMonitor is the hole: a
// "read-only, namespace app" grant on a hub with no monitor delivered a
// kubeconfig whose identity could do anything, with nothing checking either.
func TestConstrainedKubeconfigIsNotDeliveredWithoutTheMonitor(t *testing.T) {
	for _, tc := range []struct {
		name      string
		c         Constraints
		guard     KubeGuard
		ack       bool
		delivered bool
	}{
		{"read-only, one namespace, no monitor", Constraints{Contexts: []string{"prod"}, Namespaces: []string{"app"}}, nil, false, false},
		{"read-only, no monitor", Constraints{Contexts: []string{"prod"}}, nil, false, false},
		{"writes in one namespace, no monitor", Constraints{Namespaces: []string{"app"}, Verbs: allKubeVerbs}, nil, false, false},
		{"monitor declines", Constraints{Namespaces: []string{"app"}}, declineAll{}, false, false},
		{"acknowledged", Constraints{Namespaces: []string{"app"}}, nil, true, true},
		{"monitor declines, acknowledged", Constraints{Namespaces: []string{"app"}}, declineAll{}, true, true},
		{"claims nothing the monitor enforces", Constraints{Contexts: []string{"prod"}, Verbs: allKubeVerbs}, nil, false, true},
		{"monitored", Constraints{Namespaces: []string{"app"}}, acceptAll{}, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, _, auditor, _ := newTestBroker(t)
			ctx := context.Background()
			sec, err := b.Mint(ctx, MintRequest{Name: "kube", Kind: KindKubeconfig,
				Payload: []byte(testKubeconfig("kube-canary-token")), Actor: "test"})
			if err != nil {
				t.Fatal(err)
			}
			g := grantTo(t, b, sec.ID, "project:/srv/app", tc.c, time.Hour)
			if tc.ack {
				ackUnguarded(t, b, g.ID)
			}
			if tc.guard != nil {
				b.KubeGuard = tc.guard
			}
			lease, err := b.LeaseFor(ctx, Requester{ExecutorID: "e1", ProjectID: "/srv/app"}, "test")
			if err != nil {
				t.Fatal(err)
			}
			if tc.delivered {
				if len(lease.Materials) != 1 {
					t.Fatalf("not delivered: refused %+v", lease.Refused)
				}
				sum := lease.Materials[0].Summary
				unguarded := tc.ack && (tc.guard == nil || tc.guard == KubeGuard(declineAll{}))
				if strings.Contains(sum, "unguarded") != unguarded {
					t.Errorf("summary %q; it must say unguarded exactly when the acknowledgement let it through", sum)
				}
				return
			}
			if len(lease.Materials) != 0 {
				t.Fatalf("delivered without the monitor: %q", lease.Materials[0].Summary)
			}
			if len(lease.Refused) != 1 || !lease.Refused[0].Delivery {
				t.Fatalf("the grant is not named as refused: %+v", lease.Refused)
			}
			reason := lease.Refused[0].Reason
			for _, want := range []string{"only cloop's Kubernetes access monitor enforces",
				"executors.kube_guard", "tls: auto", "cloop hub grant unguarded " + g.ID} {
				if !strings.Contains(reason, want) {
					t.Errorf("the refusal does not say %q: %s", want, reason)
				}
			}
			var denied bool
			for _, ev := range auditor.all() {
				if ev.Action == ActionLease && ev.Decision == DecisionDeny && ev.GrantID == g.ID &&
					strings.Contains(ev.Reason, ErrKubeConstraintsUnenforced.Error()) {
					denied = true
				}
			}
			if !denied {
				t.Error("no secret.lease deny row names the refusal")
			}
		})
	}
}

// TestAKubeconfigTheHubKeepsIsNotRefused: the kubernetes executor's own
// cluster credential is leased by a broker with no monitor, and used by the
// hub itself. That is no delivery to a workload, and the refusal is not for
// it — through a renewal too. The same grant asked for by a run still is.
func TestAKubeconfigTheHubKeepsIsNotRefused(t *testing.T) {
	b, _, _, _ := newTestBroker(t)
	ctx := context.Background()
	sec, err := b.Mint(ctx, MintRequest{Name: "cluster", Kind: KindKubeconfig,
		Payload: []byte(testKubeconfig("kube-canary-token")), Actor: "test"})
	if err != nil {
		t.Fatal(err)
	}
	grantTo(t, b, sec.ID, "executor:k8s", Constraints{Namespaces: []string{"cloop"}}, time.Hour)

	own, err := b.LeaseFor(ctx, Requester{ExecutorID: "k8s", ProjectID: "/srv/app", KubeInProcess: true}, "executor:k8s")
	if err != nil {
		t.Fatal(err)
	}
	if len(own.Materials) != 1 || len(own.Refused) != 0 {
		t.Fatalf("the executor's own credential was refused: %+v", own.Refused)
	}
	if strings.Contains(own.Materials[0].Summary, "unguarded") {
		t.Errorf("the hub's own use is summarised as an unguarded delivery: %q", own.Materials[0].Summary)
	}
	renewed, err := b.Renew(ctx, own.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(renewed.Materials) != 1 {
		t.Fatalf("the renewal lost the executor's own credential: %+v", renewed.Refused)
	}

	run, err := b.LeaseFor(ctx, Requester{ExecutorID: "k8s", ProjectID: "/srv/app", RunID: "r1"}, "ui")
	if err != nil {
		t.Fatal(err)
	}
	if len(run.Materials) != 0 || len(run.Refused) != 1 ||
		!strings.Contains(run.Refused[0].Reason, "only cloop's Kubernetes access monitor enforces") {
		t.Fatalf("a run on the executor was handed its cluster credential with no monitor: %d delivered, refused %+v",
			len(run.Materials), run.Refused)
	}
}

// TestAnAcknowledgementDoesNotOverrideABrokenMonitor: a hub configured for the
// monitor whose monitor is down refuses every kubeconfig, acknowledged or not.
func TestAnAcknowledgementDoesNotOverrideABrokenMonitor(t *testing.T) {
	b, _, _, _ := newTestBroker(t)
	ctx := context.Background()
	sec, err := b.Mint(ctx, MintRequest{Name: "kube", Kind: KindKubeconfig,
		Payload: []byte(testKubeconfig("kube-canary-token")), Actor: "test"})
	if err != nil {
		t.Fatal(err)
	}
	g := grantTo(t, b, sec.ID, "project:/srv/app", Constraints{Namespaces: []string{"app"}}, time.Hour)
	ackUnguarded(t, b, g.ID)
	b.KubeGuard = UnavailableKubeGuard{Reason: "the monitor is not running"}
	lease, err := b.LeaseFor(ctx, Requester{ExecutorID: "e1", ProjectID: "/srv/app"}, "test")
	if err != nil {
		t.Fatal(err)
	}
	if len(lease.Materials) != 0 || len(lease.Refused) != 1 ||
		!strings.Contains(lease.Refused[0].Reason, "guard unavailable") {
		t.Fatalf("lease = %+v", lease)
	}
}

// plainStore hides every optional extension of the store it wraps.
type plainStore struct{ Store }

func TestAcknowledgeUnguardedIsValidatedAndAudited(t *testing.T) {
	b, store, auditor, clock := newTestBroker(t)
	ctx := context.Background()
	kube, err := b.Mint(ctx, MintRequest{Name: "kube", Kind: KindKubeconfig,
		Payload: []byte(testKubeconfig("kube-canary-token")), Actor: "test"})
	if err != nil {
		t.Fatal(err)
	}
	constrained := grantTo(t, b, kube.ID, "project:/srv/app", Constraints{Namespaces: []string{"app"}}, time.Hour)
	unconstrained := grantTo(t, b, kube.ID, "project:/srv/web", Constraints{Contexts: []string{"prod"}, Verbs: allKubeVerbs}, time.Hour)
	revoked := grantTo(t, b, kube.ID, "project:/srv/old", Constraints{Namespaces: []string{"app"}}, time.Hour)
	if err := b.Revoke(ctx, revoked.ID, "test"); err != nil {
		t.Fatal(err)
	}
	pat := mintGitHub(t, b, "pat", "ghp_"+strings.Repeat("Z", 36))
	patGrant := grantTo(t, b, pat.ID, "project:/srv/app", Constraints{Repos: []string{"acme/*"}}, time.Hour)
	share := mintShare(t, b, KubeShareRenewalHub)
	shareGrant, err := b.Grant(ctx, GrantRequest{SecretRef: share.ID, Subject: Subject{Type: SubjectProject, Value: "/srv/app"},
		Constraints: Constraints{Namespaces: []string{"team-a"}}, TTL: time.Hour, Actor: "alice@example.com",
		Viewer: Viewer{Identity: "alice@example.com"}})
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name  string
		req   UnguardedAckRequest
		match string
	}{
		{"no reason", UnguardedAckRequest{GrantID: constrained.ID, Actor: "admin"}, "needs a reason"},
		{"no actor", UnguardedAckRequest{GrantID: constrained.ID, Reason: "ok"}, "needs an actor"},
		{"an overlong reason", UnguardedAckRequest{GrantID: constrained.ID, Actor: "admin", Reason: strings.Repeat("x", 501)}, "longer than"},
		{"not a kubeconfig grant", UnguardedAckRequest{GrantID: patGrant.ID, Actor: "admin", Reason: "ok"}, "only a kubeconfig grant"},
		{"nothing to acknowledge", UnguardedAckRequest{GrantID: unconstrained.ID, Actor: "admin", Reason: "ok"}, "nothing to acknowledge"},
		{"a revoked grant", UnguardedAckRequest{GrantID: revoked.ID, Actor: "admin", Reason: "ok"}, "revoked or expired"},
		{"a share the hub renews", UnguardedAckRequest{GrantID: shareGrant.ID, Actor: "admin", Reason: "ok"}, "no acknowledgement changes that"},
		{"no such grant", UnguardedAckRequest{GrantID: "grant_nope", Actor: "admin", Reason: "ok"}, "grant_nope"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := len(auditor.all())
			_, err := b.AcknowledgeUnguarded(ctx, tc.req)
			if err == nil || !strings.Contains(err.Error(), tc.match) {
				t.Fatalf("err = %v, want one saying %q", err, tc.match)
			}
			evs := auditor.all()[before:]
			if len(evs) != 1 || evs[0].Action != ActionUnguardedAck || evs[0].Decision != DecisionDeny {
				t.Errorf("a refused acknowledgement is not one deny row: %+v", evs)
			}
		})
	}

	clock.advance(time.Minute)
	g, err := b.AcknowledgeUnguarded(ctx, UnguardedAckRequest{GrantID: constrained.ID, Actor: "admin@example.com",
		Reason: "dev cluster; the monitor arrives next sprint"})
	if err != nil {
		t.Fatal(err)
	}
	stored, err := store.GetGrant(constrained.ID)
	if err != nil || !stored.UnguardedAck.Recorded() || stored.UnguardedAck.By != "admin@example.com" ||
		!stored.UnguardedAck.At.Equal(clock.Now()) || g.UnguardedAck != stored.UnguardedAck {
		t.Fatalf("stored acknowledgement = %+v (%v), returned %+v", stored.UnguardedAck, err, g.UnguardedAck)
	}
	evs := auditor.all()
	last := evs[len(evs)-1]
	if last.Action != ActionUnguardedAck || last.Decision != DecisionAllow || last.GrantID != constrained.ID ||
		last.SecretName != "kube" || last.Actor != "admin@example.com" ||
		!strings.Contains(last.Reason, "namespaces app") || !strings.Contains(last.Reason, "next sprint") {
		t.Errorf("acknowledgement row = %+v", last)
	}

	if _, err := b.WithdrawUnguardedAck(ctx, UnguardedAckRequest{GrantID: constrained.ID, Actor: "sec@example.com",
		Reason: "the monitor is on"}); err != nil {
		t.Fatal(err)
	}
	if stored, _ := store.GetGrant(constrained.ID); stored.UnguardedAck.Recorded() {
		t.Error("the withdrawal was not stored")
	}
	evs = auditor.all()
	last = evs[len(evs)-1]
	if last.Action != ActionUnguardedWithdraw || last.Decision != DecisionAllow ||
		!strings.Contains(last.Reason, "admin@example.com") || !strings.Contains(last.Reason, "the monitor is on") {
		t.Errorf("withdrawal row = %+v", last)
	}
	if _, err := b.WithdrawUnguardedAck(ctx, UnguardedAckRequest{GrantID: constrained.ID, Actor: "sec"}); err == nil {
		t.Error("withdrawing an acknowledgement that is not in force succeeded")
	}

	// A store that keeps none says so instead of pretending.
	cipher, err := NewCipherWithKey(testKey)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := New(plainStore{store}, WithCipher(cipher), WithClock(clock.Now))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := plain.AcknowledgeUnguarded(ctx, UnguardedAckRequest{GrantID: constrained.ID, Actor: "admin",
		Reason: "ok"}); !errors.Is(err, ErrUnguardedAckUnsupported) {
		t.Errorf("err = %v, want ErrUnguardedAckUnsupported", err)
	}
}
