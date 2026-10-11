package statictoken

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/apitoken"
)

func TestFingerprint(t *testing.T) {
	fp := Fingerprint("s3cret-static-token")
	if !Valid(fp) {
		t.Fatalf("Fingerprint produced %q, which Valid refuses", fp)
	}
	if fp != Fingerprint("s3cret-static-token") {
		t.Fatal("Fingerprint is not deterministic: a retirement written by one process would name nothing another holds")
	}
	if fp == Fingerprint("s3cret-static-tokem") {
		t.Fatal("two values share a fingerprint")
	}
	// Domain-separated: not the plain digest a table of common passwords keys on.
	plain := sha256.Sum256([]byte("s3cret-static-token"))
	if fp == hex.EncodeToString(plain[:]) {
		t.Fatal("the fingerprint is the plain SHA-256 of the value")
	}
	if strings.Contains(fp, "s3cret") {
		t.Fatal("the fingerprint carries the value")
	}
	if got := Short(fp); len(got) != ShortLen || !strings.HasPrefix(fp, got) {
		t.Fatalf("Short = %q", got)
	}
	for _, bad := range []string{"", "abc", strings.ToUpper(fp), fp + "0", strings.Repeat("g", 64)} {
		if Valid(bad) {
			t.Errorf("Valid(%q) = true", bad)
		}
	}
}

func TestHeld(t *testing.T) {
	now := time.Now()
	if Held(time.Time{}, now) {
		t.Error("a token never reported counts as held")
	}
	if !Held(now.Add(-ReportInterval), now) {
		t.Error("a token reported one interval ago does not count as held")
	}
	if Held(now.Add(-HeldWithin-time.Second), now) {
		t.Error("a token last reported past the window counts as held")
	}
}

func TestActiveAdminTokens(t *testing.T) {
	now := time.Now()
	tokens := []apitoken.Token{
		{ID: "ok", Roles: []string{"admin"}},
		{ID: "two-roles", Roles: []string{"viewer", "admin"}},
		{ID: "viewer", Roles: []string{"viewer"}},
		{ID: "revoked", Roles: []string{"admin"}, RevokedAt: now.Add(-time.Minute)},
		{ID: "expired", Roles: []string{"admin"}, ExpiresAt: now.Add(-time.Minute)},
		{ID: "glasses", Roles: []string{"admin"}, Kind: apitoken.KindGlasses},
		{ID: "owned", Roles: []string{"admin"}, Owner: &apitoken.Owner{Email: "a@example.com"}},
		{ID: "unreadable-owner", Roles: []string{"admin"}, OwnerUnreadable: true},
	}
	if got := ActiveAdminTokens(tokens, now); got != 2 {
		t.Fatalf("ActiveAdminTokens = %d, want the two active, ordinary, unowned admin tokens", got)
	}
}

func TestCheckRetire(t *testing.T) {
	for _, tc := range []struct {
		name        string
		sso         bool
		adminTokens int
		force       bool
		strands     bool
	}{
		{"token-only, nothing else", false, 0, false, true},
		{"token-only, forced", false, 0, true, false},
		{"token-only with an admin token", false, 1, false, false},
		{"single sign-on", true, 0, false, false},
	} {
		err := CheckRetire(tc.sso, tc.adminTokens, tc.force)
		if got := errors.Is(err, ErrWouldStrand); got != tc.strands {
			t.Errorf("%s: CheckRetire = %v, want stranding %v", tc.name, err, tc.strands)
		}
		if err != nil && !strings.Contains(err.Error(), "--force") {
			t.Errorf("%s: the refusal does not say how to override it: %v", tc.name, err)
		}
	}
}
