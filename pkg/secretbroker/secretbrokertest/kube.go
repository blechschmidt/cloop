package secretbrokertest

// kube.go: kubeconfigs, a stand-in for the hub's Kubernetes monitor, and a lease
// carrying several kubeconfig grants — for the claim that such a lease reaches
// every driver as one merged document (Task 20413). That claim spans packages
// as Task 20375's did: the broker renders the document, and the hub, the
// container driver, a device's agent and the Kubernetes driver each have to
// accept and place it.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/secretbroker"
)

// Kubeconfig renders a one-context kubeconfig for the cluster at server, whose
// user presents token, with namespace as the context's default.
//
// Its names are the ones a kubeconfig exported from a cluster usually carries —
// cluster "kubernetes", user "kubernetes-admin", context
// "kubernetes-admin@kubernetes" — so two clusters' collide on every name, as
// two real clusters' do.
func Kubeconfig(server, token, namespace string) []byte {
	ns := ""
	if namespace != "" {
		ns = "\n    namespace: " + namespace
	}
	return []byte(`apiVersion: v1
kind: Config
current-context: kubernetes-admin@kubernetes
clusters:
- name: kubernetes
  cluster:
    server: ` + server + `
contexts:
- name: kubernetes-admin@kubernetes
  context:
    cluster: kubernetes
    user: kubernetes-admin` + ns + `
users:
- name: kubernetes-admin
  user:
    token: ` + token + `
`)
}

// KubeGuard stands in for the hub's Kubernetes monitor. It answers the broker
// with the document the monitor issues — one cluster, user and context, all
// named "cloop", pointing at BaseURL with a session token — and remembers what
// it was given, so a test can check what a restore would re-derive.
type KubeGuard struct {
	// BaseURL is where the documents it issues point.
	BaseURL string
	// Decline names secrets, by name, whose grants it declines: those are
	// delivered as their minimised kubeconfig, as on a hub with no monitor.
	Decline map[string]bool
	// Refuse names secrets, by name, whose grants it refuses, with the reason
	// — a monitor that cannot hold that credential.
	Refuse map[string]string

	mu       sync.Mutex
	sessions []KubeSession
}

// KubeSession is one session the stand-in minted.
type KubeSession struct {
	ID    string
	Token string
	// Request is what the broker asked for, the minimised kubeconfig
	// included: what a restore re-derives from the grant.
	Request secretbroker.KubeGuardRequest
}

// GuardKubeconfig implements secretbroker.KubeGuard.
func (g *KubeGuard) GuardKubeconfig(_ context.Context, req secretbroker.KubeGuardRequest) (secretbroker.KubeGuardResult, error) {
	if g.Decline[req.SecretName] {
		return secretbroker.KubeGuardResult{}, nil
	}
	if why, ok := g.Refuse[req.SecretName]; ok {
		return secretbroker.KubeGuardResult{}, errors.New(why)
	}
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return secretbroker.KubeGuardResult{}, err
	}
	g.mu.Lock()
	id := fmt.Sprintf("kgs%d", len(g.sessions)+1)
	token := id + "." + hex.EncodeToString(buf)
	req.Kubeconfig = append([]byte(nil), req.Kubeconfig...)
	g.sessions = append(g.sessions, KubeSession{ID: id, Token: token, Request: req})
	g.mu.Unlock()

	ns := ""
	for _, n := range req.Namespaces {
		if !strings.ContainsAny(n, "*?[]") {
			ns = "\n    namespace: " + n
			break
		}
	}
	doc := `apiVersion: v1
kind: Config
current-context: cloop
clusters:
- name: cloop
  cluster:
    server: ` + g.BaseURL + `
contexts:
- name: cloop
  context:
    cluster: cloop
    user: cloop` + ns + `
users:
- name: cloop
  user:
    token: ` + token + `
`
	return secretbroker.KubeGuardResult{
		Kubeconfig: []byte(doc),
		SessionID:  id,
		ExpiresAt:  time.Now().Add(time.Hour),
		ReadOnly:   true,
		Summary:    "via the stand-in monitor",
	}, nil
}

// Sessions returns what the stand-in minted, in order.
func (g *KubeGuard) Sessions() []KubeSession {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]KubeSession(nil), g.sessions...)
}

// KubeGrant is one kubeconfig grant KubeLease issues.
type KubeGrant struct {
	// Secret names the secret. Grants naming the same one share it, as one
	// cluster granted twice does.
	Secret      string
	Kubeconfig  []byte
	Constraints secretbroker.Constraints
	// Unacknowledged leaves the grant without the unguarded acknowledgement
	// KubeLease otherwise records on it, so a grant the monitor does not
	// hold is refused (secretbroker.ErrKubeConstraintsUnenforced) the way it
	// is on a hub where nobody acknowledged it.
	Unacknowledged bool
}

// KubeProject and KubeExecutor are the requester KubeLease leases for.
const (
	KubeProject  = "/srv/app"
	KubeExecutor = "e1"
)

// KubeLease issues a lease of grants to KubeProject on KubeExecutor, through a
// broker over a fresh in-memory store whose Kubernetes monitor is guard (nil
// for none). It returns the broker too, for a test that withdraws or renews.
//
// Every grant claiming something only the monitor enforces carries an
// unguarded acknowledgement (Task 20420) unless it is Unacknowledged: the tests
// using this are about how a lease renders and merges where the monitor does
// not hold a grant, and without one such a grant is not delivered at all. The
// refusal itself is pkg/secretbroker's to test.
func KubeLease(t testing.TB, guard secretbroker.KubeGuard, grants ...KubeGrant) (*secretbroker.Broker, *secretbroker.Lease) {
	t.Helper()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i*13 + 7)
	}
	cipher, err := secretbroker.NewCipherWithKey(key)
	if err != nil {
		t.Fatalf("cipher: %v", err)
	}
	b, err := secretbroker.New(NewStore(), secretbroker.WithCipher(cipher))
	if err != nil {
		t.Fatalf("broker: %v", err)
	}
	if guard != nil {
		b.KubeGuard = guard
	}
	ctx := context.Background()
	ids := map[string]string{}
	for _, g := range grants {
		id, ok := ids[g.Secret]
		if !ok {
			// A copy: Mint zeroes the payload it was handed.
			s, err := b.Mint(ctx, secretbroker.MintRequest{Name: g.Secret, Kind: secretbroker.KindKubeconfig,
				Payload: append([]byte(nil), g.Kubeconfig...), Actor: "test"})
			if err != nil {
				t.Fatalf("mint %s: %v", g.Secret, err)
			}
			id = s.ID
			ids[g.Secret] = id
		}
		grant, err := b.Grant(ctx, secretbroker.GrantRequest{SecretRef: id,
			Subject:     secretbroker.Subject{Type: secretbroker.SubjectProject, Value: KubeProject},
			Constraints: g.Constraints, TTL: time.Hour, Actor: "test"})
		if err != nil {
			t.Fatalf("grant %s: %v", g.Secret, err)
		}
		if !g.Unacknowledged && len(g.Constraints.KubeMonitorOnly()) > 0 {
			if _, err := b.AcknowledgeUnguarded(ctx, secretbroker.UnguardedAckRequest{GrantID: grant.ID,
				Actor: "admin@example.com", Reason: "a test cluster"}); err != nil {
				t.Fatalf("acknowledge %s: %v", g.Secret, err)
			}
		}
	}
	requester, err := secretbroker.RequesterFor(nil, KubeExecutor, secretbroker.RequestScope{ProjectID: KubeProject})
	if err != nil {
		t.Fatalf("requester: %v", err)
	}
	lease, err := b.LeaseFor(ctx, requester, "test")
	if err != nil {
		t.Fatalf("lease: %v", err)
	}
	return b, lease
}
