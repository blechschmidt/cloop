package kubecontroller

// rig_test.go puts a controller between the fake API server and the fake hub,
// with the timings shortened so a scale-up, a scale-down or a collection
// happens in well under a second.

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor/kubernetes"
	"github.com/blechschmidt/cloop/pkg/imagepolicy"
)

const testNS = "runners"

// fastTimings shortens the controller's waits for one test.
func fastTimings(t *testing.T) {
	t.Helper()
	saved := []struct {
		p *time.Duration
		v time.Duration
	}{
		{&feedWait, time.Second}, {&feedFresh, 5 * time.Second}, {&feedBackoffBase, 50 * time.Millisecond},
		{&feedBackoffMax, 200 * time.Millisecond}, {&podSecretGrace, 300 * time.Millisecond},
		{&expiredGrace, 100 * time.Millisecond}, {&orphanHubGrace, 300 * time.Millisecond},
		{&requeueWhileStarting, 100 * time.Millisecond}, {&queueBaseDelay, 20 * time.Millisecond},
		{&queueMaxDelay, 200 * time.Millisecond}, {&watchTimeout, 2 * time.Second},
		{&expectationTTL, 5 * time.Second}, {&minIdleBeforeRetire, 0},
	}
	for i := range saved {
		old := *saved[i].p
		*saved[i].p = saved[i].v
		saved[i].v = old
	}
	t.Cleanup(func() {
		for _, s := range saved {
			*s.p = s.v
		}
	})
}

// fakeResolver resolves every tag to one digest.
type fakeResolver struct{ err error }

const fakeDigest = "sha256:1111111111111111111111111111111111111111111111111111111111111111"

func (f fakeResolver) ResolveDigest(context.Context, string) (string, error) {
	if f.err != nil {
		return "", f.err
	}
	return fakeDigest, nil
}

// fakeVerifier answers one verdict.
type fakeVerifier struct{ status imagepolicy.ProvenanceStatus }

func (f fakeVerifier) VerifyProvenance(context.Context, string) imagepolicy.ProvenanceVerdict {
	return imagepolicy.ProvenanceVerdict{Status: f.status, Detail: "fake verifier"}
}
func (f fakeVerifier) TrustRoot() (string, string) { return "issuer", "identity" }

// logBuf collects a controller's log lines.
type logBuf struct {
	mu    sync.Mutex
	lines []string
}

func (l *logBuf) logf(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, fmt.Sprintf(format, args...))
}

func (l *logBuf) all() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Join(l.lines, "\n")
}

type rig struct {
	t    *testing.T
	k8s  *fakeK8s
	hub  *fakeHub
	logs *logBuf

	mu      sync.Mutex
	running []*runningController
}

type runningController struct {
	c      *Controller
	cancel context.CancelFunc
	// done is closed when Run returns.
	done chan struct{}
}

func newRig(t *testing.T) *rig {
	t.Helper()
	fastTimings(t)
	r := &rig{t: t, k8s: newFakeK8s(t), hub: newFakeHub(t), logs: &logBuf{}}
	r.k8s.apply("secrets", testNS, Secret{Metadata: ObjectMeta{Name: "pool-cred"},
		Data: map[string][]byte{"credential": []byte(fakeCredential + "\n")}})
	t.Cleanup(r.stopAll)
	return r
}

// options are a controller's defaults in the rig.
func (r *rig) options() Options {
	return Options{
		REST: r.k8s.restConfig(), Namespace: testNS, Resync: 3 * time.Second, Workers: 2,
		Logf: r.logs.logf, HubTransport: r.hub.srv.Client().Transport,
		ImageResolver: fakeResolver{}, ImageVerifier: fakeVerifier{status: imagepolicy.ProvenanceVerified},
	}
}

// start runs a controller built from the rig's options as mutated.
func (r *rig) start(mutate ...func(*Options)) *runningController {
	r.t.Helper()
	opts := r.options()
	for _, m := range mutate {
		m(&opts)
	}
	c, err := New(opts)
	if err != nil {
		r.t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	rc := &runningController{c: c, cancel: cancel, done: make(chan struct{})}
	go func() {
		defer close(rc.done)
		if err := c.Run(ctx); err != nil {
			r.t.Errorf("Run: %v", err)
		}
	}()
	r.mu.Lock()
	r.running = append(r.running, rc)
	r.mu.Unlock()
	return rc
}

// stop ends a controller and waits for it.
func (rc *runningController) stop(t *testing.T) {
	t.Helper()
	rc.cancel()
	select {
	case <-rc.done:
	case <-time.After(15 * time.Second):
		t.Fatal("the controller did not stop within 15s of its context ending")
	}
}

func (r *rig) stopAll() {
	r.mu.Lock()
	running := r.running
	r.running = nil
	r.mu.Unlock()
	for _, rc := range running {
		rc.cancel()
		select {
		case <-rc.done:
		case <-time.After(15 * time.Second):
			r.t.Error("a controller did not stop within 15s")
		}
	}
}

// spec is a valid spec against the rig's hub.
func (r *rig) spec() ExecutorPoolSpec {
	return ExecutorPoolSpec{HubURL: r.hub.url(), PoolCredentialSecretRef: SecretKeyRef{Name: "pool-cred"},
		MaxRunners: 5, ScaleDownDelay: "0s"}
}

// pool creates or updates the ExecutorPool name.
func (r *rig) pool(name string, spec ExecutorPoolSpec) map[string]any {
	return r.k8s.apply("pools", testNS, ExecutorPool{APIVersion: APIVersion, Kind: Kind,
		Metadata: ObjectMeta{Name: name}, Spec: spec})
}

// status reads a pool's status.
func (r *rig) status(name string) ExecutorPoolStatus {
	var p ExecutorPool
	r.k8s.decode("pools", testNS, name, &p)
	return p.Status
}

// eventually waits for cond.
func (r *rig) eventually(what string, cond func() bool) {
	r.t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	r.t.Fatalf("timed out waiting for %s\ncontroller log:\n%s", what, r.logs.all())
}

// never checks cond stays false for d.
func (r *rig) never(what string, d time.Duration, cond func() bool) {
	r.t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			r.t.Fatalf("%s\ncontroller log:\n%s", what, r.logs.all())
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// pods are the runner Pods in the namespace.
func (r *rig) pods() []string { return r.k8s.names("pods", testNS) }

// runnerSecrets are the runner Secrets in the namespace (not the credential).
func (r *rig) runnerSecrets() []string {
	var out []string
	for _, n := range r.k8s.names("secrets", testNS) {
		if n != "pool-cred" {
			out = append(out, n)
		}
	}
	return out
}

// enrollmentOf returns the enrollment ID the Secret of runner Pod pod names.
func (r *rig) enrollmentOf(pod string) string {
	var s Secret
	if !r.k8s.decode("secrets", testNS, pod, &s) {
		return ""
	}
	return s.Metadata.Annotations[AnnotationEnrollmentID]
}

// condition returns a pool's condition of type t.
func (r *rig) condition(name, t string) Condition {
	st := r.status(name)
	if c := st.condition(t); c != nil {
		return *c
	}
	return Condition{}
}

// mustJSON renders v for messages.
func mustJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// mustAPIClient is a client of the fake API server.
func mustAPIClient(t *testing.T, k *fakeK8s) *kubernetes.APIClient {
	t.Helper()
	c, err := kubernetes.NewAPIClient(k.restConfig(), kubernetes.APIClientOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return c
}
