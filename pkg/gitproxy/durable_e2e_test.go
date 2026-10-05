// End-to-end: a session survives its proxy being replaced (Task 20383).
//
// The harness's proxy is swapped for a new one with an empty registry behind
// the same URL — what a hub restart looks like to a sandbox — and the session
// is restored there from the record its first registry wrote. The client keeps
// the credential it was handed before the "restart": if the restore did not
// bring back the same id and token hash, git would fail with a 401; if it did
// not bring back the same policy, the push to main below would go through.
package gitproxy_test

import (
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/gitproxy"
)

// recordingStore is a gitproxy.SessionStore for tests outside the package.
type recordingStore struct {
	mu      sync.Mutex
	records map[string]gitproxy.SessionRecord
	closed  map[string]string
}

func newRecordingStore() *recordingStore {
	return &recordingStore{records: map[string]gitproxy.SessionRecord{}, closed: map[string]string{}}
}

func (s *recordingStore) SaveSession(rec gitproxy.SessionRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records[rec.ID] = rec
	return nil
}

func (s *recordingStore) CloseSession(id, reason string, _ time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed[id] = reason
	return nil
}

func TestRestoredSessionServesTheSandboxAfterARestart(t *testing.T) {
	h := newHarness(t)
	store := newRecordingStore()
	h.reg.Store = store

	pol := gitproxy.WriteBackPolicy()
	pol.AllowFetch = true
	m, err := h.reg.Mint(gitproxy.MintRequest{
		Upstream:   h.upstream,
		Credential: gitproxy.Credential{Username: forgeUser, Password: forgePAT, LeaseID: "lease_1", GrantID: "grant_1"},
		Policy:     pol,
		TTL:        time.Hour,
		ProjectID:  "proj-e2e",
		ExecutorID: "exec-1",
		Actor:      "e2e",
		RunID:      "run_1",
		Durable:    true,
	})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	dir, out, err := h.clone(t, m)
	if err != nil {
		t.Fatalf("clone before the restart: %v\n%s", err, out)
	}

	// The restart: the first registry is gone with its process, and a new
	// proxy with an empty registry answers at the same URL.
	h.advance(5 * time.Minute)
	restarted, err := gitproxy.NewRegistry(h.proxySrv.URL)
	if err != nil {
		t.Fatal(err)
	}
	restarted.Now = h.now
	restarted.OnEvent = h.record
	restarted.Store = store
	px, err := gitproxy.New(restarted, gitproxy.Options{Transport: h.forge.Client().Transport})
	if err != nil {
		t.Fatal(err)
	}
	h.handler.Store(http.Handler(px))

	// Before the restore the sandbox's credential is worth nothing here.
	h.commit(t, dir, "before.txt", "before the restore\n")
	if out, err := h.git(t, dir, h.credEnv(m), "push", "origin", "HEAD:refs/heads/cloop/before-restore"); err == nil {
		t.Fatalf("a push before the restore succeeded:\n%s", out)
	}

	store.mu.Lock()
	rec := store.records[m.Session.ID]
	store.mu.Unlock()
	if _, err := restarted.Restore(gitproxy.RestoreRequest{
		Record:     rec,
		Credential: gitproxy.Credential{Username: forgeUser, Password: forgePAT},
		From:       "hub_old",
	}); err != nil {
		t.Fatalf("Restore: %v", err)
	}

	// The same credential, through the new process: the write-back lands...
	h.commit(t, dir, "after.txt", "after the restore\n")
	if out, err := h.git(t, dir, h.credEnv(m), "push", "origin", "HEAD:refs/heads/cloop/after-restore"); err != nil {
		t.Fatalf("push after the restore: %v\n%s", err, out)
	}
	if _, ok := h.upstreamSHA(t, "refs/heads/cloop/after-restore"); !ok {
		t.Fatal("the forge did not receive the push made after the restore")
	}
	// ...and the policy came back with it: main stays out of reach.
	before, _ := h.upstreamSHA(t, "refs/heads/main")
	if out, err := h.git(t, dir, h.credEnv(m), "push", "origin", "HEAD:refs/heads/main"); err == nil {
		t.Fatalf("a push to main succeeded through the restored session:\n%s", out)
	}
	if after, _ := h.upstreamSHA(t, "refs/heads/main"); after != before {
		t.Fatal("main moved through the restored session")
	}
	restoredRows := h.eventsOf(gitproxy.EventSessionRestored)
	if len(restoredRows) != 1 || !strings.Contains(restoredRows[0].Detail, "hub_old") {
		t.Fatalf("restored rows = %+v\n%s", restoredRows, h.eventLog())
	}
}
