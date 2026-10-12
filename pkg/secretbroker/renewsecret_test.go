package secretbroker

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

const shareKubeconfig = `apiVersion: v1
kind: Config
current-context: aks-dev
clusters:
- name: aks-dev
  cluster:
    server: https://k8s.example.test:6443
contexts:
- name: aks-dev
  context:
    cluster: aks-dev
    user: aks-dev
    namespace: team-a
users:
- name: aks-dev
  user:
    token: first-serviceaccount-token
`

// mintShare stores a kubeconfig share the way the hub's POST /api/secrets
// does, with the metadata `cloop remote kube share` sends.
func mintShare(t *testing.T, b *Broker, renewal string) Secret {
	t.Helper()
	s, err := b.Mint(context.Background(), MintRequest{
		Name: "aks-dev", Kind: KindKubeconfig, Payload: []byte(shareKubeconfig), Actor: "alice@example.com",
		Owner: "alice@example.com", Personal: true,
		Metadata: map[string]string{"kube.share": "3f9c2a1b", KubeShareMetaRenewal: renewal},
	})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestRenewSecretReplacesThePayloadInPlace(t *testing.T) {
	b, store, audit, clock := newTestBroker(t)
	ctx := context.Background()
	sec := mintShare(t, b, KubeShareRenewalHub)
	g, err := b.Grant(ctx, GrantRequest{SecretRef: sec.ID, Subject: Subject{Type: SubjectProject, Value: "/srv/app"},
		Constraints: Constraints{Namespaces: []string{"team-a"}}, TTL: time.Hour, Actor: "alice@example.com",
		Viewer: Viewer{Identity: "alice@example.com"}})
	if err != nil {
		t.Fatal(err)
	}

	var handed []byte
	renewed, err := b.RenewSecret(ctx, RenewSecretRequest{
		Ref: sec.Name, Kind: KindKubeconfig, Actor: "hub",
		Renew: func(_ context.Context, s Secret, plaintext []byte) (RenewedPayload, error) {
			handed = plaintext
			if s.ID != sec.ID || !bytes.Contains(plaintext, []byte("first-serviceaccount-token")) {
				t.Errorf("Renew was handed %s / %q", s.ID, plaintext)
			}
			meta := map[string]string{"kube.share": "3f9c2a1b", KubeShareMetaRenewal: KubeShareRenewalHub, "kube.renewals": "1"}
			return RenewedPayload{
				Payload:   bytes.Replace(plaintext, []byte("first-serviceaccount-token"), []byte("second-serviceaccount-token"), 1),
				Metadata:  meta,
				ExpiresAt: clock.Now().Add(24 * time.Hour),
				Reason:    "ServiceAccount token renewed by the hub",
			}, nil
		},
	})
	if err != nil {
		t.Fatalf("RenewSecret: %v", err)
	}
	for _, c := range handed {
		if c != 0 {
			t.Fatal("the plaintext handed to Renew was not wiped afterwards")
		}
	}
	if renewed.ID != sec.ID || renewed.Owner != sec.Owner || renewed.Name != sec.Name || renewed.Metadata["kube.renewals"] != "1" {
		t.Errorf("renewed secret = %+v", renewed)
	}
	// The grant still points at it and the lease delivers the new token.
	if gg, err := store.GetGrant(g.ID); err != nil || gg.SecretID != sec.ID || !gg.RevokedAt.IsZero() {
		t.Fatalf("the grant did not survive the renewal: %+v %v", gg, err)
	}
	b.KubeGuard = acceptAll{}
	lease, err := b.LeaseFor(ctx, Requester{ExecutorID: "e1", ProjectID: "/srv/app"}, "test")
	if err != nil {
		t.Fatal(err)
	}
	if len(lease.Materials) != 1 {
		t.Fatalf("lease = %+v", lease)
	}
	if got := string(acceptedKubeconfig); !strings.Contains(got, "second-serviceaccount-token") {
		t.Errorf("the monitor was handed the old token after the renewal:\n%s", got)
	}

	rows := audit.byAction(ActionRenew)
	if len(rows) != 1 || rows[0].Decision != DecisionAllow || rows[0].SecretID != sec.ID || rows[0].Kind != KindKubeconfig ||
		rows[0].Actor != "hub" || rows[0].ExpiresAt.IsZero() || !strings.Contains(rows[0].Reason, "renewed by the hub") {
		t.Errorf("secret.renew rows = %+v", rows)
	}
}

func TestRenewSecretRefusesWhatItCannotDo(t *testing.T) {
	b, _, audit, _ := newTestBroker(t)
	ctx := context.Background()
	sec := mintShare(t, b, KubeShareRenewalHub)

	cause := errors.New("the cluster no longer accepts the share's token")
	_, err := b.RenewSecret(ctx, RenewSecretRequest{Ref: sec.ID, Actor: "hub",
		Renew: func(context.Context, Secret, []byte) (RenewedPayload, error) { return RenewedPayload{}, cause }})
	if !errors.Is(err, cause) {
		t.Fatalf("err = %v", err)
	}
	if rows := audit.byAction(ActionRenew); len(rows) != 1 || rows[0].Decision != DecisionDeny ||
		!strings.Contains(rows[0].Reason, "no longer accepts") {
		t.Errorf("a failed renewal's row = %+v", rows)
	}
	// A caller retrying the same failure on a timer records it once.
	_, _ = b.RenewSecret(ctx, RenewSecretRequest{Ref: sec.ID, Actor: "hub", AuditFailure: func(error) bool { return false },
		Renew: func(context.Context, Secret, []byte) (RenewedPayload, error) { return RenewedPayload{}, cause }})
	if rows := audit.byAction(ActionRenew); len(rows) != 1 {
		t.Errorf("a quiet failure wrote a row: %d rows", len(rows))
	}

	// Wrong kind.
	if _, err := b.RenewSecret(ctx, RenewSecretRequest{Ref: sec.ID, Kind: KindGitHubPAT, Actor: "hub",
		Renew: func(context.Context, Secret, []byte) (RenewedPayload, error) { return RenewedPayload{}, nil }}); !errors.Is(err, ErrInvalidSecret) {
		t.Errorf("a kind mismatch: err = %v", err)
	}

	// A renewal that loses a race to another gives way: the secret changed
	// under it, and the newer payload stands.
	_, err = b.RenewSecret(ctx, RenewSecretRequest{Ref: sec.ID, Actor: "hub",
		Renew: func(ctx context.Context, s Secret, plaintext []byte) (RenewedPayload, error) {
			if _, err := b.RenewSecret(ctx, RenewSecretRequest{Ref: sec.ID, Actor: "alice@example.com",
				Renew: func(context.Context, Secret, []byte) (RenewedPayload, error) {
					return RenewedPayload{Payload: []byte(strings.Replace(shareKubeconfig, "first-", "pushed-", 1))}, nil
				}}); err != nil {
				t.Fatalf("the inner renewal: %v", err)
			}
			return RenewedPayload{Payload: []byte(strings.Replace(shareKubeconfig, "first-", "loser-", 1))}, nil
		}})
	if !errors.Is(err, ErrSecretChanged) {
		t.Fatalf("the losing renewal: err = %v", err)
	}
	b.KubeGuard = acceptAll{}
	if _, err := b.Grant(ctx, GrantRequest{SecretRef: sec.ID, Subject: Subject{Type: SubjectProject, Value: "/srv/app"},
		Constraints: Constraints{Namespaces: []string{"team-a"}}, TTL: time.Hour, Actor: "alice@example.com",
		Viewer: Viewer{Identity: "alice@example.com"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := b.LeaseFor(ctx, Requester{ExecutorID: "e1", ProjectID: "/srv/app"}, "test"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(acceptedKubeconfig), "pushed-serviceaccount-token") {
		t.Errorf("the winning renewal's payload did not stand:\n%s", acceptedKubeconfig)
	}

	// Metadata alone.
	s, err := b.UpdateSecretMetadata(sec.ID, func(m map[string]string) { m["kube.renew_error"] = "forbidden" })
	if err != nil || s.Metadata["kube.renew_error"] != "forbidden" || s.Metadata["kube.share"] != "3f9c2a1b" {
		t.Errorf("UpdateSecretMetadata = %+v, %v", s.Metadata, err)
	}
}

// acceptAll is a monitor that takes custody of every kubeconfig and records
// the last one it was handed.
type acceptAll struct{}

var acceptedKubeconfig []byte

func (acceptAll) GuardKubeconfig(_ context.Context, req KubeGuardRequest) (KubeGuardResult, error) {
	acceptedKubeconfig = append([]byte(nil), req.Kubeconfig...)
	return KubeGuardResult{
		Kubeconfig: []byte("apiVersion: v1\nkind: Config\ncurrent-context: cloop\ncontexts:\n- name: cloop\n  context: {cluster: cloop, user: cloop}\nclusters:\n- name: cloop\n  cluster: {server: \"https://monitor.example.test:8444\"}\nusers:\n- name: cloop\n  user: {token: session-token}\n"),
		SessionID:  "kgs1", ExpiresAt: time.Now().Add(time.Hour), ReadOnly: true, Summary: "read-only via monitor",
	}, nil
}

// TestSelfRenewingShareIsDeliveredOnlyThroughTheMonitor: a share the hub
// renews holds a ServiceAccount that may create its own tokens, so handing
// its kubeconfig to a workload as a file would hand over a credential that
// extends itself. Without a monitor it is refused — named on the lease — and
// no acknowledgement changes that. A manually renewed share, which has no
// such permission, is delivered without a monitor only on an administrator's
// acknowledgement, like any grant whose namespaces only the monitor enforces
// (Task 20420).
func TestSelfRenewingShareIsDeliveredOnlyThroughTheMonitor(t *testing.T) {
	for _, tc := range []struct {
		name      string
		renewal   string
		guard     KubeGuard
		ack       bool
		delivered bool
		refused   string
	}{
		{"hub-renewed, no monitor", KubeShareRenewalHub, nil, false, false, "delivered only through the Kubernetes access monitor"},
		{"hub-renewed, monitor declines", KubeShareRenewalHub, declineAll{}, false, false, "delivered only through the Kubernetes access monitor"},
		{"hub-renewed, monitored", KubeShareRenewalHub, acceptAll{}, false, true, ""},
		{"manually renewed, no monitor", "manual", nil, false, false, "only cloop's Kubernetes access monitor enforces"},
		{"manually renewed, no monitor, acknowledged", "manual", nil, true, true, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, _, _, _ := newTestBroker(t)
			ctx := context.Background()
			sec := mintShare(t, b, tc.renewal)
			if tc.guard != nil {
				b.KubeGuard = tc.guard
			}
			g, err := b.Grant(ctx, GrantRequest{SecretRef: sec.ID, Subject: Subject{Type: SubjectProject, Value: "/srv/app"},
				Constraints: Constraints{Namespaces: []string{"team-a"}}, TTL: time.Hour, Actor: "alice@example.com",
				Viewer: Viewer{Identity: "alice@example.com"}})
			if err != nil {
				t.Fatal(err)
			}
			if tc.ack {
				ackUnguarded(t, b, g.ID)
			}
			lease, err := b.LeaseFor(ctx, Requester{ExecutorID: "e1", ProjectID: "/srv/app"}, "test")
			if tc.delivered {
				if err != nil || len(lease.Materials) != 1 {
					t.Fatalf("lease = %+v, %v", lease, err)
				}
				return
			}
			if err == nil && len(lease.Materials) > 0 {
				t.Fatalf("the share was delivered without the monitor: %+v", lease.Materials[0].Summary)
			}
			if lease == nil || len(lease.Refused) != 1 || !strings.Contains(lease.Refused[0].Reason, tc.refused) ||
				!lease.Refused[0].Delivery {
				t.Fatalf("lease = %+v, err = %v; want the share named as refused", lease, err)
			}
			for _, m := range lease.Materials {
				for _, f := range m.Files {
					if bytes.Contains(f.Content, []byte("first-serviceaccount-token")) {
						t.Fatal("the token reached a delivered file")
					}
				}
			}
		})
	}
}

// declineAll is a hub with no monitor running: the guard declines.
type declineAll struct{}

func (declineAll) GuardKubeconfig(context.Context, KubeGuardRequest) (KubeGuardResult, error) {
	return KubeGuardResult{}, nil
}
