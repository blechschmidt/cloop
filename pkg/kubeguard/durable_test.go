package kubeguard

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// memSessionStore is a SessionStore that remembers what it was told.
type memSessionStore struct {
	mu      sync.Mutex
	records map[string]SessionRecord
	closed  map[string]string
}

func newMemSessionStore() *memSessionStore {
	return &memSessionStore{records: map[string]SessionRecord{}, closed: map[string]string{}}
}

func (m *memSessionStore) SaveSession(rec SessionRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.records[rec.ID] = rec
	return nil
}

func (m *memSessionStore) CloseSession(id, reason string, _ time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed[id] = reason
	return nil
}

func (m *memSessionStore) get(t *testing.T, id string) SessionRecord {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.records[id]
	if !ok {
		t.Fatalf("no record of %s", id)
	}
	return rec
}

func (m *memSessionStore) closeReason(id string) (string, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.closed[id]
	return r, ok
}

// TestDurableKubeSessionIsRecordedWithoutItsCredentials: the record has the
// bearer token's hash, the cluster and the policy — never the session token
// or the cluster credential.
func TestDurableKubeSessionIsRecordedWithoutItsCredentials(t *testing.T) {
	reg := newTestRegistry(t)
	store := newMemSessionStore()
	reg.Store = store
	m, err := reg.Mint(MintRequest{
		Kubeconfig: testKubeconfig(""),
		Policy:     Policy{Verbs: ReadVerbs, Namespaces: []string{"app"}},
		LeaseID:    "lease_1", GrantID: "grant_1", RunID: "run_1", Actor: "alice", Durable: true,
	})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if !m.Session.Durable() {
		t.Fatal("not recorded")
	}
	rec := store.get(t, m.Session.ID)
	sum := sha256.Sum256([]byte(m.Token))
	if rec.TokenSHA256 != hex.EncodeToString(sum[:]) || rec.ClusterURL != testClusterServer ||
		rec.ContextName != "prod" || rec.LeaseID != "lease_1" || rec.RunID != "run_1" ||
		strings.Join(rec.Policy.Namespaces, ",") != "app" {
		t.Fatalf("record = %+v", rec)
	}
	raw, _ := json.Marshal(rec)
	for _, secret := range []string{m.Token, testClusterToken, m.Token[strings.Index(m.Token, ".")+1:]} {
		if strings.Contains(string(raw), secret) {
			t.Fatalf("the record carries a credential: %s", raw)
		}
	}
	reg.CloseForLease("lease_1", "lease released")
	if reason, ok := store.closeReason(m.Session.ID); !ok || reason != "lease released" {
		t.Fatalf("close recorded as %q, %v", reason, ok)
	}
}

// TestRestoredKubeSessionServesTheOriginalToken: a monitor with an empty
// registry — a restarted hub — restores the session from its record, and the
// sandbox's kubectl, holding the token the first monitor minted, reaches the
// cluster through it with the re-derived credential, under the same policy.
func TestRestoredKubeSessionServesTheOriginalToken(t *testing.T) {
	api := newFakeAPIServer(t)
	store := newMemSessionStore()

	first, err := NewRegistry("https://monitor.example:8444")
	if err != nil {
		t.Fatal(err)
	}
	first.Store = store
	m, err := first.Mint(MintRequest{
		Kubeconfig: testInsecureKubeconfig(api.srv.URL),
		Policy:     Policy{Verbs: ReadVerbs, Namespaces: []string{"app"}},
		LeaseID:    "lease_1", GrantID: "grant_1", ProjectID: "/srv/app", Durable: true,
	})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	second, err := NewRegistry("https://monitor.example:8444")
	if err != nil {
		t.Fatal(err)
	}
	second.Store = store
	var restored []Event
	second.OnEvent = func(e Event) {
		if e.Kind == EventSessionRestored {
			restored = append(restored, e)
		}
	}
	px, err := New(second, Options{})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(px)
	t.Cleanup(func() { srv.Close(); _ = px.Close() })

	get := func(path string) int {
		req, _ := http.NewRequest(http.MethodGet, srv.URL+path, nil)
		req.Header.Set("Authorization", "Bearer "+m.Token)
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if code := get("/api/v1/namespaces/app/pods"); code != http.StatusUnauthorized {
		t.Fatalf("before the restore = %d, want 401", code)
	}

	if _, err := second.Restore(RestoreRequest{
		Record:     store.get(t, m.Session.ID),
		Kubeconfig: testInsecureKubeconfig(api.srv.URL),
		From:       "hub_old",
	}); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if code := get("/api/v1/namespaces/app/pods"); code != http.StatusOK {
		t.Fatalf("after the restore = %d, want 200", code)
	}
	if got := api.last().Header.Get("Authorization"); got != "Bearer "+testClusterToken {
		t.Fatalf("upstream credential = %q, want the re-derived cluster token", got)
	}
	// The policy came back with it.
	if code := get("/api/v1/namespaces/kube-system/secrets"); code != http.StatusForbidden {
		t.Fatalf("a namespace outside the restored policy = %d, want 403", code)
	}
	if len(restored) != 1 || !strings.Contains(restored[0].Detail, "hub_old") {
		t.Fatalf("restored rows = %+v", restored)
	}
}

// TestKubeRestoreRefusesWhatMintWouldRefuse.
func TestKubeRestoreRefusesWhatMintWouldRefuse(t *testing.T) {
	reg := newTestRegistry(t)
	store := newMemSessionStore()
	reg.Store = store
	m, err := reg.Mint(MintRequest{Kubeconfig: testKubeconfig(""), LeaseID: "lease_1", Durable: true})
	if err != nil {
		t.Fatal(err)
	}
	good := store.get(t, m.Session.ID)
	other := newTestRegistry(t)

	cases := []struct {
		name   string
		mutate func(*SessionRecord)
		kc     []byte
		want   error
	}{
		{"lapsed", func(r *SessionRecord) { r.ExpiresAt = time.Now().Add(-time.Second) }, nil, ErrSessionLapsed},
		{"hash not sha256", func(r *SessionRecord) { r.TokenSHA256 = "zz" }, nil, nil},
		{"no policy", func(r *SessionRecord) { r.Policy = Policy{} }, nil, nil},
		{"credential now names another cluster", func(*SessionRecord) {}, testKubeconfig("https://elsewhere.example:6443"), nil},
		{"no kubeconfig", func(*SessionRecord) {}, []byte{}, nil},
		{"id with a dot", func(r *SessionRecord) { r.ID = "a.b" }, nil, nil},
		{"deadline beyond any mint", func(r *SessionRecord) {
			r.ExpiresAt = r.IssuedAt.Add(MaxSessionTTL + time.Minute)
		}, nil, nil},
		{"no issue time", func(r *SessionRecord) { r.IssuedAt = time.Time{} }, nil, nil},
	}
	for _, tc := range cases {
		rec := good
		tc.mutate(&rec)
		kc := tc.kc
		if kc == nil {
			kc = testKubeconfig("")
		}
		_, err := other.Restore(RestoreRequest{Record: rec, Kubeconfig: kc})
		if err == nil {
			t.Errorf("%s: restored", tc.name)
			continue
		}
		if tc.want != nil && !errors.Is(err, tc.want) {
			t.Errorf("%s: %v, want %v", tc.name, err, tc.want)
		}
	}
	if _, err := reg.Restore(RestoreRequest{Record: good, Kubeconfig: testKubeconfig("")}); !errors.Is(err, ErrSessionExists) {
		t.Fatalf("restore over the live session = %v", err)
	}
}

// TestKubeSuspendLeavesTheRecordOpen.
func TestKubeSuspendLeavesTheRecordOpen(t *testing.T) {
	reg := newTestRegistry(t)
	store := newMemSessionStore()
	reg.Store = store
	m, err := reg.Mint(MintRequest{Kubeconfig: testKubeconfig(""), LeaseID: "lease_1", Durable: true})
	if err != nil {
		t.Fatal(err)
	}
	// Not recorded, so nothing could restore it: closed, not suspended.
	unrecorded, err := reg.Mint(MintRequest{Kubeconfig: testKubeconfig(""), LeaseID: "lease_1"})
	if err != nil {
		t.Fatal(err)
	}
	if ids := reg.SuspendForLease("lease_1", "handed over"); len(ids) != 1 || ids[0] != m.Session.ID {
		t.Fatalf("suspended %v, want only the recorded session", ids)
	}
	if reg.Known(m.Session.ID) {
		t.Fatal("a suspended session is still served")
	}
	if reason := unrecorded.Session.CloseReason(); !unrecorded.Session.Closed() || reason != "handed over" {
		t.Fatalf("the unrecorded session ended with %q, want it closed with the reason", reason)
	}
	if _, ok := store.closeReason(m.Session.ID); ok {
		t.Fatal("suspending recorded the session closed")
	}
	if _, err := reg.Authenticate(m.Token); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("a suspended session authenticated: %v", err)
	}
}
