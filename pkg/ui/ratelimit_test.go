package ui

// Regression tests for the per-IP rate-limit and auth-fail map bounds.
//
// The UI is a long-lived daemon. Without an upper bound on these maps, a flood
// of unique source IPs (e.g. SYN-cookie scan from a botnet, or a misconfigured
// client cycling addresses) would grow them unbounded — a slow memory leak
// that survives until the process is restarted. Both maps now apply the same
// bounded eviction policy as pkg/apiserver: TTL sweep first, then evict the
// least-recently-seen entry if the cap is still exceeded.

import (
	"testing"
	"time"
)

// TestUIAllow_RLBucketsBounded fills rlBuckets past uiRLMaxBuckets with stale
// entries and confirms the next insert sweeps them away rather than letting
// the map grow without bound.
func TestUIAllow_RLBucketsBounded_StaleSweep(t *testing.T) {
	s := New(t.TempDir(), 0, "")

	stale := time.Now().Add(-2 * uiRLBucketIdleTTL)
	s.rlMu.Lock()
	for i := 0; i < uiRLMaxBuckets; i++ {
		s.rlBuckets[fakeIP(i)] = &uiIPBucket{tokens: 1, lastSeen: stale}
	}
	s.rlMu.Unlock()

	if !s.uiAllow("9.9.9.9") {
		t.Fatalf("uiAllow on a fresh IP should succeed within burst budget")
	}

	s.rlMu.Lock()
	got := len(s.rlBuckets)
	s.rlMu.Unlock()

	// After a successful insert that triggered the TTL sweep, the map should
	// hold exactly one entry: the brand-new one. All stale entries should
	// have been evicted.
	if got != 1 {
		t.Fatalf("expected stale TTL sweep to leave 1 bucket, got %d", got)
	}
}

// TestUIAllow_RLBucketsBounded_LRUEvict fills rlBuckets past uiRLMaxBuckets
// with FRESH entries (no TTL eviction would help) and confirms the inserter
// evicts the single least-recently-seen entry so the cap is preserved.
func TestUIAllow_RLBucketsBounded_LRUEvict(t *testing.T) {
	s := New(t.TempDir(), 0, "")

	now := time.Now()
	s.rlMu.Lock()
	for i := 0; i < uiRLMaxBuckets; i++ {
		s.rlBuckets[fakeIP(i)] = &uiIPBucket{
			tokens:   1,
			lastSeen: now.Add(time.Duration(i) * time.Second),
		}
	}
	s.rlMu.Unlock()

	// fakeIP(0) has the oldest lastSeen — it should be the one evicted.
	if !s.uiAllow("9.9.9.9") {
		t.Fatalf("uiAllow on a fresh IP should succeed within burst budget")
	}

	s.rlMu.Lock()
	got := len(s.rlBuckets)
	_, oldestStillThere := s.rlBuckets[fakeIP(0)]
	_, newcomerThere := s.rlBuckets["9.9.9.9"]
	s.rlMu.Unlock()

	if got > uiRLMaxBuckets {
		t.Fatalf("rlBuckets exceeded cap %d after insert, got %d", uiRLMaxBuckets, got)
	}
	if oldestStillThere {
		t.Errorf("least-recently-seen bucket should have been evicted")
	}
	if !newcomerThere {
		t.Errorf("newly-inserted bucket missing from map")
	}
}

// TestEvictAuthFailsLocked_StaleSweep verifies the auth-fail map applies the
// same TTL sweep on cap-exceeded inserts. A flood of unique IPs hitting
// /api/* with no valid token would otherwise grow this map without limit.
func TestEvictAuthFailsLocked_StaleSweep(t *testing.T) {
	s := New(t.TempDir(), 0, "")

	stale := time.Now().Add(-2 * uiAuthFailsIdleTTL)
	s.authMu.Lock()
	for i := 0; i < uiAuthFailsMaxEntries; i++ {
		s.authFails[fakeIP(i)] = &authFailEntry{lastSeen: stale}
	}
	now := time.Now()
	s.evictAuthFailsLocked(now)
	got := len(s.authFails)
	s.authMu.Unlock()

	if got != 0 {
		t.Fatalf("expected stale TTL sweep to drain auth-fail map, got %d remaining", got)
	}
}

// TestEvictAuthFailsLocked_LRUEvict confirms LRU eviction kicks in when no
// entries are stale enough to sweep — the oldest one is dropped so the map
// stays at the cap.
func TestEvictAuthFailsLocked_LRUEvict(t *testing.T) {
	s := New(t.TempDir(), 0, "")

	now := time.Now()
	s.authMu.Lock()
	for i := 0; i < uiAuthFailsMaxEntries; i++ {
		s.authFails[fakeIP(i)] = &authFailEntry{lastSeen: now.Add(time.Duration(i) * time.Second)}
	}
	s.evictAuthFailsLocked(now)
	got := len(s.authFails)
	_, oldestStillThere := s.authFails[fakeIP(0)]
	s.authMu.Unlock()

	if got >= uiAuthFailsMaxEntries {
		t.Fatalf("evictAuthFailsLocked failed to free a slot under the cap; size=%d cap=%d", got, uiAuthFailsMaxEntries)
	}
	if oldestStillThere {
		t.Errorf("least-recently-seen auth-fail entry should have been evicted")
	}
}

func fakeIP(i int) string {
	// Stable, unique-per-i string. The actual IP shape doesn't matter — these
	// tests treat the map keys as opaque identifiers.
	return "10.0." + itoa(i/256) + "." + itoa(i%256)
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var buf [4]byte
	n := 0
	for i > 0 {
		buf[n] = byte('0' + i%10)
		n++
		i /= 10
	}
	out := make([]byte, n)
	for j := 0; j < n; j++ {
		out[j] = buf[n-1-j]
	}
	return string(out)
}
