package kubecontroller

import (
	"context"
	"encoding/pem"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/tlsconf"
)

// The controller's own TLS to the hub: the CA bundle as the only roots, the
// pin checked after the chain, and a wrong pin refused before the credential
// is sent.
func TestTheHubConnectionIsVerifiedAndPinned(t *testing.T) {
	fastTimings(t)
	h := newFakeHub(t)
	k := newFakeK8s(t)
	k.apply("secrets", testNS, Secret{Metadata: ObjectMeta{Name: "pool-cred"},
		Data: map[string][]byte{"credential": []byte(fakeCredential)}})
	api := &kubeAPI{c: mustAPIClient(t, k)}
	caPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: h.srv.Certificate().Raw}))
	pin := tlsconf.Fingerprint(h.srv.Certificate())

	cfg := hubConfig{URL: h.url(), CABundle: caPEM, Pin: pin, Namespace: testNS, Secret: "pool-cred", Key: "credential"}
	client, err := newHubClient(cfg, &credentialSource{api: api, cfg: cfg}, nil)
	if err != nil {
		t.Fatal(err)
	}
	msg, err := client.Feed(context.Background(), "", time.Second)
	if err != nil {
		t.Fatalf("a pinned feed: %v", err)
	}
	if msg.Snapshot.PoolID != h.poolID {
		t.Fatalf("feed %+v", msg)
	}
	before := len(h.retireRequests())

	wrong := cfg
	wrong.Pin = "sha256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="
	client, err = newHubClient(wrong, &credentialSource{api: api, cfg: wrong}, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Retire(context.Background(), []string{"x"})
	if err == nil || !errors.Is(err, tlsconf.ErrPinMismatch) {
		t.Fatalf("a wrong pin: %v", err)
	}
	if len(h.retireRequests()) != before {
		t.Fatal("a request reached the hub over a connection whose pin did not match")
	}

	// Without the CA bundle the system store does not know the test CA.
	noCA := cfg
	noCA.CABundle = ""
	client, _ = newHubClient(noCA, &credentialSource{api: api, cfg: noCA}, nil)
	if _, err := client.Feed(context.Background(), "", time.Second); err == nil {
		t.Fatal("an unknown CA was trusted")
	}
}

// A credential Secret that holds something else is refused before it is sent
// anywhere.
func TestACredentialSecretWithoutACredentialIsRefused(t *testing.T) {
	k := newFakeK8s(t)
	k.apply("secrets", testNS, Secret{Metadata: ObjectMeta{Name: "pool-cred"},
		Data: map[string][]byte{"credential": []byte("hunter2")}})
	src := &credentialSource{api: &kubeAPI{c: mustAPIClient(t, k)},
		cfg: hubConfig{Namespace: testNS, Secret: "pool-cred", Key: "credential"}}
	_, err := src.get(context.Background())
	var ce *credentialError
	if !errors.As(err, &ce) || !strings.Contains(err.Error(), "does not hold a pool controller credential") {
		t.Fatalf("got %v", err)
	}
	if strings.Contains(err.Error(), "hunter2") {
		t.Fatal("the Secret's value is in the error")
	}
}

// The feed backs off while the hub is down and is back as soon as it answers.
func TestTheFeedBacksOffAndRecovers(t *testing.T) {
	fastTimings(t)
	h := newFakeHub(t)
	k := newFakeK8s(t)
	k.apply("secrets", testNS, Secret{Metadata: ObjectMeta{Name: "pool-cred"},
		Data: map[string][]byte{"credential": []byte(fakeCredential)}})
	h.set(func(h *fakeHub) { h.down = true })
	api := &kubeAPI{c: mustAPIClient(t, k)}
	cfg := hubConfig{URL: h.url(), Namespace: testNS, Secret: "pool-cred", Key: "credential"}
	client, err := newHubClient(cfg, &credentialSource{api: api, cfg: cfg}, h.srv.Client().Transport)
	if err != nil {
		t.Fatal(err)
	}
	f := &feed{cfg: cfg, client: client, done: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	changes := make(chan struct{}, 100)
	go f.run(ctx, func() { changes <- struct{}{} }, func(string, ...any) {})
	deadline := time.After(5 * time.Second)
	for f.snapshot().Err == nil {
		select {
		case <-changes:
		case <-deadline:
			t.Fatal("no failure recorded")
		}
	}
	time.Sleep(600 * time.Millisecond)
	h.mu.Lock()
	tries := h.feedReqs
	h.mu.Unlock()
	if tries > 8 {
		t.Fatalf("%d feed requests in 0.6s against a hub that is down: no backoff", tries)
	}
	h.set(func(h *fakeHub) { h.down = false })
	for {
		if s := f.snapshot(); s.Err == nil && s.Have {
			break
		}
		select {
		case <-changes:
		case <-time.After(5 * time.Second):
			t.Fatal("the feed did not recover")
		}
	}
	cancel()
	<-f.done
}
