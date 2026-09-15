package ciauth

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// fakeForge is a stand-in for token.actions.githubusercontent.com: it serves a
// discovery document and a key set, and can mint tokens signed by the key it
// publishes. Everything the verifier trusts comes from here, so a test can
// break any one link and check that verification refuses.
type fakeForge struct {
	t   *testing.T
	srv *httptest.Server

	rsaKey *rsa.PrivateKey
	ecKey  *ecdsa.PrivateKey

	// kid is what the key set publishes. Changing it without re-minting is
	// how the tests simulate rotation.
	kid string

	discoveryHits atomic.Int64
	jwksHits      atomic.Int64

	// overrides let a test corrupt one response without rewriting the server.
	issuerOverride  string
	jwksURIOverride string
	jwksStatus      int
}

func newFakeForge(t *testing.T) *fakeForge {
	t.Helper()
	rk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	ek, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate EC key: %v", err)
	}
	f := &fakeForge{t: t, rsaKey: rk, ecKey: ek, kid: "key-1"}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		f.discoveryHits.Add(1)
		iss := f.srv.URL
		if f.issuerOverride != "" {
			iss = f.issuerOverride
		}
		jwks := f.srv.URL + "/jwks"
		if f.jwksURIOverride != "" {
			jwks = f.jwksURIOverride
		}
		writeJSON(w, map[string]any{"issuer": iss, "jwks_uri": jwks})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		f.jwksHits.Add(1)
		if f.jwksStatus != 0 {
			w.WriteHeader(f.jwksStatus)
			return
		}
		writeJSON(w, map[string]any{"keys": []any{f.rsaJWK(), f.ecJWK()}})
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func (f *fakeForge) rsaJWK() map[string]any {
	return map[string]any{
		"kty": "RSA", "use": "sig", "alg": "RS256", "kid": f.kid,
		"n": b64(f.rsaKey.N.Bytes()),
		"e": b64(big.NewInt(int64(f.rsaKey.E)).Bytes()),
	}
}

func (f *fakeForge) ecJWK() map[string]any {
	return map[string]any{
		"kty": "EC", "use": "sig", "alg": "ES256", "kid": f.kid + "-ec", "crv": "P-256",
		"x": b64(f.ecKey.X.FillBytes(make([]byte, 32))),
		"y": b64(f.ecKey.Y.FillBytes(make([]byte, 32))),
	}
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// mint signs a token with the RSA key. claims overrides win over the defaults.
func (f *fakeForge) mint(overrides map[string]any) string {
	f.t.Helper()
	now := time.Now()
	claims := map[string]any{
		"iss":                   f.srv.URL,
		"aud":                   "cloop",
		"sub":                   "repo:acme/tool:ref:refs/heads/main",
		"jti":                   fmt.Sprintf("jti-%d", time.Now().UnixNano()),
		"iat":                   now.Unix(),
		"nbf":                   now.Unix(),
		"exp":                   now.Add(10 * time.Minute).Unix(),
		"repository":            "acme/tool",
		"repository_owner":      "acme",
		"repository_visibility": "private",
		"ref":                   "refs/heads/main",
		"ref_type":              "branch",
		"workflow":              "release",
		"workflow_ref":          "acme/tool/.github/workflows/release.yml@refs/heads/main",
		"job_workflow_ref":      "acme/tool/.github/workflows/release.yml@refs/heads/main",
		"actor":                 "dana",
		"event_name":            "push",
		"run_id":                "1234567890",
		"runner_environment":    "github-hosted",
	}
	for k, v := range overrides {
		if v == nil {
			delete(claims, k)
			continue
		}
		claims[k] = v
	}
	return f.sign("RS256", f.kid, claims)
}

func (f *fakeForge) sign(alg, kid string, claims map[string]any) string {
	f.t.Helper()
	hdr := map[string]any{"alg": alg, "typ": "JWT"}
	if kid != "" {
		hdr["kid"] = kid
	}
	hb, _ := json.Marshal(hdr)
	cb, _ := json.Marshal(claims)
	signing := b64(hb) + "." + b64(cb)
	digest := sha256.Sum256([]byte(signing))

	var sig []byte
	switch alg {
	case "RS256":
		s, err := rsa.SignPKCS1v15(rand.Reader, f.rsaKey, crypto.SHA256, digest[:])
		if err != nil {
			f.t.Fatalf("sign: %v", err)
		}
		sig = s
	case "ES256":
		r, s, err := ecdsa.Sign(rand.Reader, f.ecKey, digest[:])
		if err != nil {
			f.t.Fatalf("sign: %v", err)
		}
		sig = append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	case "none":
		sig = nil
	case "HS256":
		// A token whose signature is an HMAC keyed by the issuer's *public*
		// key is the classic alg-confusion payload: it verifies against
		// anything that treats `alg` as an instruction.
		mac := hmac.New(sha256.New, f.rsaKey.N.Bytes())
		mac.Write([]byte(signing))
		sig = mac.Sum(nil)
	default:
		f.t.Fatalf("unsupported test alg %q", alg)
	}
	return signing + "." + b64(sig)
}

func (f *fakeForge) verifier(t *testing.T, mutate ...func(*VerifierConfig)) *Verifier {
	t.Helper()
	cfg := VerifierConfig{
		Issuer:   f.srv.URL,
		Audience: "cloop",
		Client:   f.srv.Client(),
	}
	for _, m := range mutate {
		m(&cfg)
	}
	v, err := NewVerifier(cfg)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	return v
}

func TestVerify_AcceptsAGenuineToken(t *testing.T) {
	f := newFakeForge(t)
	v := f.verifier(t)

	c, err := v.Verify(context.Background(), f.mint(nil))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if c.Repository != "acme/tool" {
		t.Errorf("Repository = %q, want acme/tool", c.Repository)
	}
	if c.Ref != "refs/heads/main" {
		t.Errorf("Ref = %q", c.Ref)
	}
	if c.Workflow != "release" {
		t.Errorf("Workflow = %q", c.Workflow)
	}
	if got := c.All["repository_owner"]; got != "acme" {
		t.Errorf("All[repository_owner] = %v", got)
	}
	if want := "acme/tool@refs/heads/main (release)"; c.Label() != want {
		t.Errorf("Label() = %q, want %q", c.Label(), want)
	}
	if want := "https://github.com/acme/tool/actions/runs/1234567890"; c.RunURL("") != want {
		t.Errorf("RunURL() = %q, want %q", c.RunURL(""), want)
	}
}

func TestVerify_AcceptsES256(t *testing.T) {
	f := newFakeForge(t)
	v := f.verifier(t)
	now := time.Now()
	tok := f.sign("ES256", f.kid+"-ec", map[string]any{
		"iss": f.srv.URL, "aud": "cloop", "sub": "repo:acme/tool", "exp": now.Add(time.Minute).Unix(),
	})
	if _, err := v.Verify(context.Background(), tok); err != nil {
		t.Fatalf("Verify ES256: %v", err)
	}
}

func TestVerify_RefusesTamperedAndForgedTokens(t *testing.T) {
	f := newFakeForge(t)

	// A second forge with its own keys: a correctly-formed token signed by
	// the wrong party.
	other := newFakeForge(t)

	good := f.mint(nil)
	parts := strings.Split(good, ".")

	cases := []struct {
		name  string
		token string
		want  string
	}{
		{"empty", "", "empty assertion"},
		{"not a JWS", "abc", "compact JWS"},
		{"payload tampered", parts[0] + "." + b64([]byte(`{"iss":"x","sub":"y","aud":"cloop","exp":9999999999}`)) + "." + parts[2], "signature invalid"},
		{"signature tampered", parts[0] + "." + parts[1] + "." + b64([]byte("nope")), "signature invalid"},
		{"signed by another issuer", other.mint(nil), "signature invalid"},
		{"alg none", f.sign("none", f.kid, map[string]any{"iss": f.srv.URL, "aud": "cloop", "sub": "s", "exp": time.Now().Add(time.Minute).Unix()}), "unsupported alg"},
		{"alg HS256 confusion", f.sign("HS256", f.kid, map[string]any{"iss": f.srv.URL, "aud": "cloop", "sub": "s", "exp": time.Now().Add(time.Minute).Unix()}), "unsupported alg"},
		{"unknown kid", f.sign("RS256", "nope", map[string]any{"iss": f.srv.URL, "aud": "cloop", "sub": "s", "exp": time.Now().Add(time.Minute).Unix()}), "key set"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := f.verifier(t)
			_, err := v.Verify(context.Background(), tc.token)
			if err == nil {
				t.Fatal("Verify accepted a token it must refuse")
			}
			if !errors.Is(err, ErrUnverified) {
				t.Errorf("error = %v, want it to wrap ErrUnverified", err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want it to mention %q", err, tc.want)
			}
		})
	}
}

func TestVerify_RefusesBadRegisteredClaims(t *testing.T) {
	f := newFakeForge(t)
	now := time.Now()

	cases := []struct {
		name      string
		overrides map[string]any
		want      string
	}{
		{"wrong audience", map[string]any{"aud": "someone-else"}, "does not include"},
		{"audience absent", map[string]any{"aud": nil}, "does not include"},
		{"expired", map[string]any{"exp": now.Add(-10 * time.Minute).Unix()}, "expired"},
		{"no expiry", map[string]any{"exp": nil}, "no exp"},
		{"issued in the future", map[string]any{"iat": now.Add(10 * time.Minute).Unix()}, "future"},
		{"not yet valid", map[string]any{"nbf": now.Add(10 * time.Minute).Unix()}, "not valid before"},
		{"no subject", map[string]any{"sub": nil}, "no sub"},
		{"wrong issuer in payload", map[string]any{"iss": "https://evil.example"}, "issued by"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := f.verifier(t)
			_, err := v.Verify(context.Background(), f.mint(tc.overrides))
			if err == nil {
				t.Fatal("Verify accepted a token it must refuse")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want it to mention %q", err, tc.want)
			}
		})
	}
}

func TestVerify_AudienceAcceptsBothShapes(t *testing.T) {
	f := newFakeForge(t)
	v := f.verifier(t)
	// `aud` is a string in most GitHub tokens and an array in the spec.
	for _, aud := range []any{"cloop", []any{"cloop"}, []any{"other", "cloop"}} {
		if _, err := v.Verify(context.Background(), f.mint(map[string]any{"aud": aud})); err != nil {
			t.Errorf("Verify with aud=%v: %v", aud, err)
		}
	}
}

func TestVerify_ClockSkewIsBoundedAndApplied(t *testing.T) {
	f := newFakeForge(t)
	now := time.Now()
	// A token that expired 30s ago is accepted under the default 60s skew...
	v := f.verifier(t)
	if _, err := v.Verify(context.Background(), f.mint(map[string]any{"exp": now.Add(-30 * time.Second).Unix()})); err != nil {
		t.Errorf("Verify within skew: %v", err)
	}
	// ...and an operator cannot configure skew past the ceiling.
	wide, err := NewVerifier(VerifierConfig{Issuer: f.srv.URL, Audience: "cloop", Client: f.srv.Client(), ClockSkew: 24 * time.Hour})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	if wide.skew != MaxClockSkew {
		t.Errorf("skew = %v, want it clamped to %v", wide.skew, MaxClockSkew)
	}
	if _, err := wide.Verify(context.Background(), f.mint(map[string]any{"exp": now.Add(-time.Hour).Unix()})); err == nil {
		t.Error("Verify accepted a token an hour stale despite the skew ceiling")
	}
}

func TestVerify_RefusesReplay(t *testing.T) {
	f := newFakeForge(t)
	v := f.verifier(t)
	tok := f.mint(nil)

	if _, err := v.Verify(context.Background(), tok); err != nil {
		t.Fatalf("first Verify: %v", err)
	}
	_, err := v.Verify(context.Background(), tok)
	if err == nil {
		t.Fatal("Verify accepted the same token twice")
	}
	if !errors.Is(err, ErrUnverified) || !strings.Contains(err.Error(), "already been exchanged") {
		t.Errorf("error = %v, want a replay refusal", err)
	}
	// A different token from the same pipeline is still fine.
	if _, err := v.Verify(context.Background(), f.mint(nil)); err != nil {
		t.Errorf("second distinct token: %v", err)
	}
}

func TestVerify_DiscoveryIsPinnedToTheIssuer(t *testing.T) {
	f := newFakeForge(t)

	t.Run("document naming another issuer", func(t *testing.T) {
		f.issuerOverride = "https://evil.example"
		defer func() { f.issuerOverride = "" }()
		v := f.verifier(t)
		if _, err := v.Verify(context.Background(), f.mint(nil)); err == nil ||
			!strings.Contains(err.Error(), "names issuer") {
			t.Fatalf("error = %v, want a refusal naming the issuer mismatch", err)
		}
	})

	t.Run("key set on another host", func(t *testing.T) {
		evil := newFakeForge(t)
		f.jwksURIOverride = evil.srv.URL + "/jwks"
		defer func() { f.jwksURIOverride = "" }()
		v := f.verifier(t)
		if _, err := v.Verify(context.Background(), f.mint(nil)); err == nil ||
			!strings.Contains(err.Error(), "does not match issuer host") {
			t.Fatalf("error = %v, want a refusal naming the host mismatch", err)
		}
	})
}

func TestVerify_CachesTheKeySet(t *testing.T) {
	f := newFakeForge(t)
	v := f.verifier(t)
	for i := 0; i < 5; i++ {
		if _, err := v.Verify(context.Background(), f.mint(nil)); err != nil {
			t.Fatalf("Verify %d: %v", i, err)
		}
	}
	if got := f.jwksHits.Load(); got != 1 {
		t.Errorf("fetched the key set %d times for 5 tokens, want 1", got)
	}
	if got := f.discoveryHits.Load(); got != 1 {
		t.Errorf("ran discovery %d times, want 1", got)
	}
}

func TestVerify_UnknownKidDoesNotStampedeTheForge(t *testing.T) {
	f := newFakeForge(t)
	v := f.verifier(t)
	// Prime the cache.
	if _, err := v.Verify(context.Background(), f.mint(nil)); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	before := f.jwksHits.Load()
	for i := 0; i < 20; i++ {
		bogus := f.sign("RS256", fmt.Sprintf("forged-%d", i), map[string]any{
			"iss": f.srv.URL, "aud": "cloop", "sub": "s", "exp": time.Now().Add(time.Minute).Unix(),
		})
		if _, err := v.Verify(context.Background(), bogus); err == nil {
			t.Fatal("Verify accepted a token signed with an unpublished kid")
		}
	}
	if got := f.jwksHits.Load() - before; got > 1 {
		t.Errorf("20 forged-kid tokens caused %d key-set fetches, want at most 1", got)
	}
}

func TestVerify_SurvivesAForgeOutageOnCachedKeys(t *testing.T) {
	f := newFakeForge(t)
	v := f.verifier(t)
	if _, err := v.Verify(context.Background(), f.mint(nil)); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	// Age the cache out so the next call tries to refresh, then break the
	// endpoint. A cached key that still verifies beats refusing every
	// pipeline because the forge had a bad minute.
	v.mu.Lock()
	v.fetchedAt = time.Now().Add(-2 * jwksMaxAge)
	v.mu.Unlock()
	f.jwksStatus = http.StatusServiceUnavailable
	defer func() { f.jwksStatus = 0 }()

	if _, err := v.Verify(context.Background(), f.mint(nil)); err != nil {
		t.Errorf("Verify during a forge outage: %v", err)
	}
}

func TestNewVerifier_RefusesBadConfiguration(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		cfg  VerifierConfig
		want string
	}{
		{"no issuer", VerifierConfig{Audience: "cloop"}, "issuer is required"},
		{"no audience", VerifierConfig{Issuer: GitHubActionsIssuer}, "audience is required"},
		{"plaintext issuer", VerifierConfig{Issuer: "http://token.actions.githubusercontent.com", Audience: "cloop"}, "must use https"},
		{"not a URL", VerifierConfig{Issuer: "::nope", Audience: "cloop"}, "is not a URL"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := NewVerifier(tc.cfg); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("NewVerifier = %v, want it to mention %q", err, tc.want)
			}
		})
	}
	// Loopback over plain HTTP is the one exception, for local IdPs and tests.
	if _, err := NewVerifier(VerifierConfig{Issuer: "http://127.0.0.1:8080", Audience: "cloop"}); err != nil {
		t.Errorf("NewVerifier for a loopback issuer: %v", err)
	}
}

func TestParseJWKSet_SkipsUnusableKeysButKeepsTheRest(t *testing.T) {
	t.Parallel()
	f := newFakeForge(t)
	body, _ := json.Marshal(map[string]any{"keys": []any{
		map[string]any{"kty": "oct", "kid": "sym", "k": "AAAA"},
		map[string]any{"kty": "RSA", "kid": "short", "n": b64(big.NewInt(65537).Bytes()), "e": b64(big.NewInt(65537).Bytes())},
		map[string]any{"kty": "EC", "kid": "wrong-curve", "crv": "P-384", "x": "AA", "y": "AA"},
		f.rsaJWK(),
	}})
	keys, err := parseJWKSet(body)
	if err != nil {
		t.Fatalf("parseJWKSet: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("kept %d keys, want 1: %v", len(keys), keys)
	}
	if _, ok := keys[f.kid]; !ok {
		t.Errorf("did not keep the usable RSA key")
	}
}

func TestParseJWKSet_RefusesAnEmptyResult(t *testing.T) {
	t.Parallel()
	if _, err := parseJWKSet([]byte(`{"keys":[]}`)); err == nil {
		t.Fatal("parseJWKSet accepted a key set with nothing usable in it")
	}
}

func TestReplayCache_ForgetsExpiredEntriesUnderPressure(t *testing.T) {
	t.Parallel()
	c := newReplayCache()
	now := time.Now()
	// Fill past the bound with entries that have already expired.
	for i := 0; i < maxReplayEntries+10; i++ {
		c.admit(fmt.Sprintf("old-%d", i), now.Add(-time.Minute), now)
	}
	if len(c.seen) > maxReplayEntries {
		t.Fatalf("cache holds %d entries, bound is %d", len(c.seen), maxReplayEntries)
	}
	// A live entry is still refused on its second presentation.
	if !c.admit("live", now.Add(time.Hour), now) {
		t.Fatal("first presentation refused")
	}
	if c.admit("live", now.Add(time.Hour), now) {
		t.Fatal("second presentation accepted")
	}
}
