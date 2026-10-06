package claudeproxy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path"
	"strings"
	"sync"
	"testing"
	"time"
)

// memStore is a SessionStore in memory, recording every call.
type memStore struct {
	mu          sync.Mutex
	recs        map[string]SessionRecord
	checkpoints map[string]int
	closed      map[string]string
	failSave    error
	// gone marks records another process closed or took over.
	gone map[string]bool
}

func newMemStore() *memStore {
	return &memStore{recs: map[string]SessionRecord{}, checkpoints: map[string]int{}, closed: map[string]string{},
		gone: map[string]bool{}}
}

func (m *memStore) SaveSession(rec SessionRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failSave != nil {
		return m.failSave
	}
	m.recs[rec.ID] = rec
	return nil
}

func (m *memStore) CheckpointSession(id string, u Usage, lastUsed time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.gone[id] {
		return ErrRecordGone
	}
	rec := m.recs[id]
	rec.Usage, rec.LastUsed = u, lastUsed
	m.recs[id] = rec
	m.checkpoints[id]++
	return nil
}

func (m *memStore) CloseSession(id, reason string, _ time.Time, u Usage) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec := m.recs[id]
	rec.Usage = u
	m.recs[id] = rec
	m.closed[id] = reason
	return nil
}

func (m *memStore) record(id string) SessionRecord {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.recs[id]
}

// TestDurable_MintRecordsTheHashNeverTheToken: the record a minted session
// leaves carries the SHA-256 of its token, its rule, pipeline and policy, and
// the claims the hub handed over — and not one byte of the token.
func TestDurable_MintRecordsTheHashNeverTheToken(t *testing.T) {
	t.Parallel()
	store := newMemStore()
	r := NewRegistry("https://hub.example.com/api/ci/anthropic")
	r.Store = store
	claims := json.RawMessage(`{"repository":"acme/tool","ref":"refs/heads/main"}`)
	m := testMint(t, r, func(req *MintRequest) { req.Claims = claims })
	if !m.Session.Durable() {
		t.Fatal("a session minted with a store is not durable")
	}
	rec := store.record(m.Session.ID)
	sum := sha256.Sum256([]byte(m.Token))
	if rec.TokenSHA256 != hex.EncodeToString(sum[:]) {
		t.Fatalf("recorded hash %q is not the token's", rec.TokenSHA256)
	}
	if rec.RuleID != "rule-1" || rec.Repository != "acme/tool" || len(rec.Policy.Models) != 1 ||
		string(rec.Claims) != string(claims) || !rec.ExpiresAt.Equal(m.Session.ExpiresAt) {
		t.Fatalf("record = %+v", rec)
	}
	raw, _ := json.Marshal(rec)
	_, secret, _ := strings.Cut(strings.TrimPrefix(m.Token, TokenPrefix), ".")
	if strings.Contains(string(raw), secret) || strings.Contains(string(raw), m.Token) {
		t.Fatalf("the record carries the token: %s", raw)
	}
}

// TestDurable_AStoreThatFailsCostsSurvivalNotUse: a record that cannot be
// written leaves the session working here, and says so on its minted row.
func TestDurable_AStoreThatFailsCostsSurvivalNotUse(t *testing.T) {
	t.Parallel()
	store := newMemStore()
	store.failSave = errors.New("disk full")
	r := NewRegistry("https://hub.example.com")
	r.Store = store
	var detail string
	r.OnEvent = func(e Event) {
		if e.Kind == EventSessionMinted {
			detail = e.Detail
		}
	}
	m := testMint(t, r)
	if m.Session.Durable() {
		t.Fatal("a session whose record failed is durable")
	}
	if _, err := r.Authenticate(m.Token); err != nil {
		t.Fatalf("the unrecorded session does not authenticate: %v", err)
	}
	if !strings.Contains(detail, "not recorded durably") || !strings.Contains(detail, "disk full") {
		t.Fatalf("minted row detail = %q", detail)
	}
	if n := r.Checkpoint(); n != 0 {
		t.Fatalf("checkpointed %d unrecorded sessions", n)
	}
}

// TestDurable_CheckpointWritesWhatMoved: the timer's checkpoint writes a
// session's counters only when they changed since the last one.
func TestDurable_CheckpointWritesWhatMoved(t *testing.T) {
	t.Parallel()
	store := newMemStore()
	r := NewRegistry("https://hub.example.com")
	r.Store = store
	m := testMint(t, r)
	if n := r.Checkpoint(); n != 0 {
		t.Fatalf("a fresh session checkpointed %d times", n)
	}
	if !m.Session.claimRequest() {
		t.Fatal("claim")
	}
	m.Session.inTok.Add(120)
	m.Session.outTok.Add(30)
	if n := r.Checkpoint(); n != 1 {
		t.Fatalf("a session that spent checkpointed %d times, want 1", n)
	}
	if got := store.record(m.Session.ID).Usage; got.Requests != 1 || got.InputTokens != 120 || got.OutputTokens != 30 {
		t.Fatalf("checkpointed usage = %+v", got)
	}
	if n := r.Checkpoint(); n != 0 {
		t.Fatalf("an idle session checkpointed again (%d)", n)
	}
	if _, err := r.Authenticate(m.Token); err != nil {
		t.Fatal(err)
	}
	if n := r.Checkpoint(); n != 1 {
		t.Fatalf("a use that moved last_used checkpointed %d times, want 1", n)
	}
}

// TestDurable_SuspendLeavesTheRecordOpen: a hub stopping gracefully suspends
// its recorded sessions — their spend written, no close row, no longer served
// here — and closes the ones it holds no record of.
func TestDurable_SuspendLeavesTheRecordOpen(t *testing.T) {
	t.Parallel()
	store := newMemStore()
	r := NewRegistry("https://hub.example.com")
	r.Store = store
	var kinds []EventKind
	var mu sync.Mutex
	r.OnEvent = func(e Event) {
		mu.Lock()
		kinds = append(kinds, e.Kind)
		mu.Unlock()
	}
	durable := testMint(t, r)
	durable.Session.claimRequest()
	store.failSave = errors.New("down")
	plain := testMint(t, r)
	store.failSave = nil

	ids := r.SuspendAll("the hub is shutting down")
	if len(ids) != 1 || ids[0] != durable.Session.ID {
		t.Fatalf("suspended %v, want only the recorded session", ids)
	}
	if _, closed := store.closed[durable.Session.ID]; closed {
		t.Fatal("a suspended session's record was closed")
	}
	if got := store.record(durable.Session.ID).Usage.Requests; got != 1 {
		t.Fatalf("the suspension did not write the session's spend: requests = %d", got)
	}
	if !plain.Session.Closed() || r.Known(plain.Session.ID) || r.Known(durable.Session.ID) {
		t.Fatal("a session is still served after the suspension")
	}
	for _, tok := range []string{durable.Token, plain.Token} {
		if _, err := r.Authenticate(tok); !errors.Is(err, ErrUnauthenticated) {
			t.Fatalf("a suspended registry authenticated a token: %v", err)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	var suspended, closed int
	for _, k := range kinds {
		switch k {
		case EventSessionSuspended:
			suspended++
		case EventSessionClosed:
			closed++
		}
	}
	if suspended != 1 || closed != 1 {
		t.Fatalf("events = %v, want one suspension and one close", kinds)
	}
}

// TestDurable_CloseAndExpiryEndTheRecord: a revoked or lapsed session's record
// is closed with what it spent.
func TestDurable_CloseAndExpiryEndTheRecord(t *testing.T) {
	t.Parallel()
	store := newMemStore()
	r := NewRegistry("https://hub.example.com")
	r.Store = store
	now := time.Now()
	r.SetClock(func() time.Time { return now })
	a := testMint(t, r)
	b := testMint(t, r, func(req *MintRequest) { req.TTL = MinTTL })
	a.Session.claimRequest()
	if err := r.Close(a.Session.ID, "revoked by operator"); err != nil {
		t.Fatal(err)
	}
	if store.closed[a.Session.ID] != "revoked by operator" || store.record(a.Session.ID).Usage.Requests != 1 {
		t.Fatalf("the revoked session's record = %q %+v", store.closed[a.Session.ID], store.record(a.Session.ID))
	}
	now = now.Add(2 * MinTTL)
	if n := r.ReapExpired(); n != 1 {
		t.Fatalf("reaped %d", n)
	}
	if store.closed[b.Session.ID] != "expired" {
		t.Fatalf("the lapsed session's record = %q", store.closed[b.Session.ID])
	}
}

// TestDurable_RestoreServesTheSameTokenAndBudget: another process restores the
// recorded session; the pipeline's token authenticates there, the counters
// carry on, and the request budget is the one left, not a fresh one.
func TestDurable_RestoreServesTheSameTokenAndBudget(t *testing.T) {
	t.Parallel()
	store := newMemStore()
	a := NewRegistry("https://hub.example.com")
	a.Store = store
	m := testMint(t, a, func(req *MintRequest) { req.Policy.MaxRequests = 3 })
	m.Session.claimRequest()
	m.Session.claimRequest()
	m.Session.outTok.Add(40)
	a.SuspendAll("stopping")

	b := NewRegistry("https://hub.example.com")
	b.Store = store
	var restored Event
	b.OnEvent = func(e Event) {
		if e.Kind == EventSessionRestored {
			restored = e
		}
	}
	s, err := b.Restore(RestoreRequest{Record: store.record(m.Session.ID), From: "hub-a"})
	if err != nil {
		t.Fatalf("Restore: %v", err)
	}
	got, err := b.Authenticate(m.Token)
	if err != nil || got != s {
		t.Fatalf("the pipeline's token on the restoring process = %v, %v", got, err)
	}
	if u := s.Usage(); u.Requests != 2 || u.OutputTokens != 40 {
		t.Fatalf("restored usage = %+v", u)
	}
	if !s.claimRequest() {
		t.Fatal("the last request of the budget was refused")
	}
	if s.claimRequest() {
		t.Fatal("a restored session was given a fresh budget")
	}
	if !strings.Contains(restored.Detail, "held until then by hub-a") || restored.RuleID != "rule-1" {
		t.Fatalf("restored row = %+v", restored)
	}
	if _, err := b.Restore(RestoreRequest{Record: store.record(m.Session.ID)}); !errors.Is(err, ErrSessionExists) {
		t.Fatalf("a second restore = %v, want ErrSessionExists", err)
	}
	// Wrong tokens are still refused.
	if _, err := b.Authenticate(TokenPrefix + m.Session.ID + ".00"); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("a forged secret half = %v", err)
	}
}

// TestDurable_RestoreChecksTheRecordAsStrictlyAsAMint: a record is read back
// from a database, so one Mint could not have written is refused.
func TestDurable_RestoreChecksTheRecordAsStrictlyAsAMint(t *testing.T) {
	t.Parallel()
	now := time.Now()
	sum := sha256.Sum256([]byte("token"))
	good := SessionRecord{
		ID: "0123456789abcdef01234567", TokenSHA256: hex.EncodeToString(sum[:]),
		Policy:   Policy{Models: []string{"claude-sonnet-*"}, MaxRequests: 5},
		IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour),
	}
	for _, tc := range []struct {
		name   string
		mutate func(*SessionRecord)
		is     error
	}{
		{"an id Mint does not make", func(r *SessionRecord) { r.ID = "../etc" }, nil},
		{"a hash that is not a SHA-256", func(r *SessionRecord) { r.TokenSHA256 = "abcd" }, nil},
		{"no model", func(r *SessionRecord) { r.Policy.Models = nil }, nil},
		{"a broken model pattern", func(r *SessionRecord) { r.Policy.Models = []string{"claude-["} }, nil},
		{"a negative bound", func(r *SessionRecord) { r.Policy.MaxRequests = -1 }, nil},
		{"lapsed", func(r *SessionRecord) { r.ExpiresAt = now.Add(-time.Second) }, ErrSessionLapsed},
		{"no issue time", func(r *SessionRecord) { r.IssuedAt = time.Time{} }, nil},
		{"beyond MaxTTL", func(r *SessionRecord) { r.ExpiresAt = r.IssuedAt.Add(MaxTTL + time.Minute) }, nil},
	} {
		rec := good
		rec.Policy = good.Policy.clone()
		tc.mutate(&rec)
		r := NewRegistry("https://hub.example.com")
		r.SetClock(func() time.Time { return now })
		_, err := r.Restore(RestoreRequest{Record: rec})
		if err == nil {
			t.Errorf("%s: restored", tc.name)
			continue
		}
		if tc.is != nil && !errors.Is(err, tc.is) {
			t.Errorf("%s: %v, want %v", tc.name, err, tc.is)
		}
	}
	r := NewRegistry("https://hub.example.com")
	r.SetClock(func() time.Time { return now })
	if _, err := r.Restore(RestoreRequest{Record: good}); err != nil {
		t.Fatalf("the good record: %v", err)
	}
}

// TestNarrow: a restored session is held to the narrower of its recorded policy
// and its rule's policy now, and never to the wider.
func TestNarrow(t *testing.T) {
	t.Parallel()
	recorded := Policy{Models: []string{"claude-sonnet-*", "claude-haiku-4-5"}, MaxRequests: 500, MaxOutputTokens: 32000}
	for _, tc := range []struct {
		name string
		now  Policy
		want Policy
		err  bool
	}{
		{"unchanged", recorded,
			Policy{Models: []string{"claude-haiku-4-5", "claude-sonnet-*"}, MaxRequests: 500, MaxOutputTokens: 32000,
				MaxBodyBytes: DefaultMaxBodyBytes}, false},
		{"widened stays as recorded",
			Policy{Models: []string{"claude-*"}, MaxRequests: 5000, MaxOutputTokens: 64000},
			Policy{Models: []string{"claude-haiku-4-5", "claude-sonnet-*"}, MaxRequests: 500, MaxOutputTokens: 32000,
				MaxBodyBytes: DefaultMaxBodyBytes}, false},
		{"narrowed applies",
			Policy{Models: []string{"claude-sonnet-5"}, MaxRequests: 10, MaxOutputTokens: 1000},
			Policy{Models: []string{"claude-sonnet-5"}, MaxRequests: 10, MaxOutputTokens: 1000,
				MaxBodyBytes: DefaultMaxBodyBytes}, false},
		{"nothing in common", Policy{Models: []string{"claude-opus-*"}, MaxRequests: 10}, Policy{}, true},
	} {
		got, err := Narrow(recorded, tc.now)
		if tc.err {
			if err == nil {
				t.Errorf("%s: narrowed to %+v, want a refusal", tc.name, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", tc.name, err)
			continue
		}
		if strings.Join(got.Models, ",") != strings.Join(tc.want.Models, ",") || got.MaxRequests != tc.want.MaxRequests ||
			got.MaxOutputTokens != tc.want.MaxOutputTokens || got.MaxBodyBytes != tc.want.MaxBodyBytes {
			t.Errorf("%s: %+v, want %+v", tc.name, got, tc.want)
		}
	}
}

// TestIntersectModelsIsNeverWider checks the pattern intersection against a
// population of model ids: every id the result admits is admitted by both
// inputs, and the shapes it can prove are not lost.
func TestIntersectModelsIsNeverWider(t *testing.T) {
	t.Parallel()
	models := []string{
		"claude-sonnet-5", "claude-sonnet-4-6", "claude-haiku-4-5", "claude-opus-5-5", "claude-fable-5-1",
		"claude-sonnet-4-5-20250929", "gpt-4", "claude-", "claude-*", "claude-sonnet-*",
	}
	admits := func(pats []string, m string) bool {
		for _, p := range pats {
			if ok, err := path.Match(p, m); err == nil && ok {
				return true
			}
		}
		return false
	}
	sets := [][]string{
		{"claude-sonnet-*"}, {"claude-*"}, {"claude-sonnet-5", "claude-haiku-*"}, {"claude-?onnet-*"},
		{"claude-[sh]*"}, {"*"}, {"claude-*-5"}, {"claude-haiku-4-5"}, {`claude-\*`}, {"*-5"},
	}
	for _, a := range sets {
		for _, b := range sets {
			got := IntersectModels(a, b)
			for _, m := range models {
				if admits(got, m) && !(admits(a, m) && admits(b, m)) {
					t.Errorf("IntersectModels(%v, %v) = %v admits %q, which both do not", a, b, got, m)
				}
			}
		}
	}
	for _, tc := range []struct {
		a, b []string
		want string
	}{
		{[]string{"claude-sonnet-*"}, []string{"claude-*"}, "claude-sonnet-*"},
		{[]string{"claude-*"}, []string{"claude-sonnet-*"}, "claude-sonnet-*"},
		{[]string{"claude-haiku-4-5"}, []string{"claude-[hs]*"}, "claude-haiku-4-5"},
		{[]string{"claude-sonnet-*", "claude-haiku-*"}, []string{"claude-sonnet-*"}, "claude-sonnet-*"},
		{[]string{"claude-opus-*"}, []string{"claude-sonnet-*"}, ""},
	} {
		if got := strings.Join(IntersectModels(tc.a, tc.b), ","); got != tc.want {
			t.Errorf("IntersectModels(%v, %v) = %q, want %q", tc.a, tc.b, got, tc.want)
		}
	}
}

// TestSessionIDOf accepts only the shape Mint gives a token.
func TestSessionIDOf(t *testing.T) {
	t.Parallel()
	r := NewRegistry("https://hub.example.com")
	m := testMint(t, r)
	if id, ok := SessionIDOf(m.Token); !ok || id != m.Session.ID {
		t.Fatalf("SessionIDOf(minted) = %q, %v", id, ok)
	}
	for _, tok := range []string{"", "sk-ant-x", TokenPrefix + "abc.def", TokenPrefix + "../../x.y", TokenPrefix + m.Session.ID} {
		if _, ok := SessionIDOf(tok); ok {
			t.Errorf("SessionIDOf(%q) accepted", tok)
		}
	}
}

// TestDurable_ARecordGoneElsewhereEndsTheSession: a checkpoint that finds the
// session's record closed or taken over by another hub process — its rule
// withdrawn there, or the session restored there — stops serving it here, and
// writes nothing to a record that is not this process's.
func TestDurable_ARecordGoneElsewhereEndsTheSession(t *testing.T) {
	t.Parallel()
	store := newMemStore()
	r := NewRegistry("https://hub.example.com")
	r.Store = store
	var closed, suspended []Event
	r.OnEvent = func(e Event) {
		switch e.Kind {
		case EventSessionClosed:
			closed = append(closed, e)
		case EventSessionSuspended:
			suspended = append(suspended, e)
		}
	}
	m := testMint(t, r)
	keep := testMint(t, r)
	m.Session.claimRequest()
	keep.Session.claimRequest()
	store.mu.Lock()
	store.gone[m.Session.ID] = true
	store.mu.Unlock()
	r.Checkpoint()
	if r.Known(m.Session.ID) || !m.Session.Closed() {
		t.Fatal("a session whose record went elsewhere is still served")
	}
	if _, err := r.Authenticate(m.Token); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("its token after the checkpoint = %v", err)
	}
	if _, wrote := store.closed[m.Session.ID]; wrote {
		t.Fatal("the registry wrote to a record that is not its own")
	}
	// Whoever closed the record wrote the close; this process only stopped
	// serving it.
	if len(closed) != 0 || len(suspended) != 1 || !strings.Contains(suspended[0].Detail, "another hub process") {
		t.Fatalf("closed rows = %+v, suspended rows = %+v", closed, suspended)
	}
	if !r.Known(keep.Session.ID) {
		t.Fatal("a session whose record is still held was dropped")
	}
}

// TestDurable_ASessionClosedHereIsNotRestoredHere: a registry that closed a
// session — revoked, its rule withdrawn — refuses to restore it, even from a
// record whose close never landed; and DropUnheld stops serving the sessions
// whose records went elsewhere without waiting for their counters to move.
func TestDurable_ASessionClosedHereIsNotRestoredHere(t *testing.T) {
	t.Parallel()
	store := newMemStore()
	r := NewRegistry("https://hub.example.com")
	r.Store = store
	m := testMint(t, r)
	rec := store.record(m.Session.ID)
	if err := r.Close(m.Session.ID, "revoked by operator"); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Restore(RestoreRequest{Record: rec}); !errors.Is(err, ErrClosedHere) {
		t.Fatalf("restoring a session this registry closed = %v, want ErrClosedHere", err)
	}

	idle := testMint(t, r)
	held := testMint(t, r)
	ids := r.DurableIDs()
	if n := r.DropUnheld(ids, map[string]bool{held.Session.ID: true}); n != 1 {
		t.Fatalf("dropped %d, want the idle session whose record went elsewhere", n)
	}
	if r.Known(idle.Session.ID) || !r.Known(held.Session.ID) {
		t.Fatal("DropUnheld dropped the wrong session")
	}
}
