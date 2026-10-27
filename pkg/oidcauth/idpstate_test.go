package oidcauth

// What the sign-in client holds of its issuer, and the fetches it reports
// (Task 20446).

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestIdPStateFollowsTheSignInClient: before anything the client holds
// nothing; a preflight leaves it holding the document and the keys; a key-set
// refresh that fails is recorded beside the keys it still holds, and cleared
// by one that succeeds. Every fetch reaches the observer, named for who made
// it, and a key set never named makes no fetch. Reading the state never waits
// on a fetch in flight.
func TestIdPStateFollowsTheSignInClient(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var failKeys atomic.Bool
	var srv *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"issuer": srv.URL, "authorization_endpoint": srv.URL + "/authorize",
			"token_endpoint": srv.URL + "/token", "jwks_uri": srv.URL + "/jwks"})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		if failKeys.Load() {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kty": "RSA", "kid": "k1", "use": "sig", "alg": "RS256",
			"n": base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.PublicKey.E)).Bytes()),
		}}})
	})
	srv = httptest.NewServer(mux)
	defer srv.Close()

	var mu sync.Mutex
	var seen []IdPFetch
	ObserveFetches(func(f IdPFetch) {
		mu.Lock()
		seen = append(seen, f)
		mu.Unlock()
	})
	t.Cleanup(func() { ObserveFetches(nil) })
	fetches := func() []IdPFetch {
		mu.Lock()
		defer mu.Unlock()
		return append([]IdPFetch(nil), seen...)
	}

	a, err := New(Config{Enabled: true, Issuer: srv.URL, ClientID: "cloop", ClientSecret: "s",
		RedirectURL: "http://localhost:8080/auth/callback"})
	if err != nil {
		t.Fatal(err)
	}
	if st := a.IdPState(); st.Issuer != srv.URL || st.Discovery != nil || st.Ready || st.LastError != nil || st.SigningKeys != 0 {
		t.Fatalf("before anything the client reports %+v", st)
	}

	before := time.Now()
	if _, err := a.Preflight(context.Background()); err != nil {
		t.Fatalf("Preflight: %v", err)
	}
	st := a.IdPState()
	if !st.Ready || st.Discovery == nil || st.Discovery.JWKSURI != srv.URL+"/jwks" || st.SigningKeys != 1 ||
		st.Discovery.SigningKeys != 1 || st.DiscoveredAt.Before(before) || st.KeysFetchedAt.Before(before) || st.LastError != nil {
		t.Fatalf("after a preflight the client reports %+v", st)
	}
	if f := fetches(); len(f) != 2 || f[0] != (IdPFetch{Document: FetchDocumentDiscovery, Client: FetchClientSignIn}) ||
		f[1] != (IdPFetch{Document: FetchDocumentJWKS, Client: FetchClientSignIn}) {
		t.Errorf("the preflight reported %+v, want the sign-in client's discovery and key-set fetches", f)
	}

	// The key set goes away; a token signed by a key the client does not hold
	// makes it try again, past the refresh throttle.
	failKeys.Store(true)
	pastThrottle := func() {
		a.jwksMu.Lock()
		a.jwksFetched = time.Time{}
		a.jwksMu.Unlock()
	}
	pastThrottle()
	if _, err := a.signingKey(context.Background(), "rotated"); err == nil {
		t.Fatal("a key the issuer does not serve verified")
	}
	st = a.IdPState()
	var pe *PreflightError
	if !st.Ready || st.SigningKeys != 1 || !errors.As(st.LastError, &pe) || pe.Stage != StageJWKS || pe.Status != 503 ||
		st.LastErrorAt.IsZero() {
		t.Errorf("after a failed refresh the client reports %+v, want its key and the failure", st)
	}
	if f := fetches(); len(f) != 3 || f[2].Document != FetchDocumentJWKS || f[2].Client != FetchClientSignIn || f[2].Err == nil {
		t.Errorf("the failed refresh reported %+v", f)
	}

	// One that succeeds clears it, whatever the token it was for.
	failKeys.Store(false)
	pastThrottle()
	_, _ = a.signingKey(context.Background(), "rotated")
	if st2 := a.IdPState(); st2.LastError != nil || !st2.LastErrorAt.IsZero() || !st2.KeysFetchedAt.After(st.KeysFetchedAt) {
		t.Errorf("after a refresh that succeeded the client reports %+v", st2)
	}

	// A standalone resolution reports itself as one.
	if _, err := Preflight(context.Background(), srv.URL, PreflightOptions{}); err != nil {
		t.Fatalf("Preflight: %v", err)
	}
	if f := fetches(); len(f) != 6 || f[4].Client != FetchClientPreflight || f[5].Client != FetchClientPreflight ||
		f[4].Err != nil || f[5].Err != nil {
		t.Errorf("a standalone preflight reported %+v", f[4:])
	}

	// A document naming no key set: discovery is a fetch, the key set is not.
	var bare *httptest.Server
	bare = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"issuer": bare.URL,
			"authorization_endpoint": bare.URL + "/authorize", "token_endpoint": bare.URL + "/token"})
	}))
	defer bare.Close()
	n := len(fetches())
	if _, err := Preflight(context.Background(), bare.URL, PreflightOptions{}); !errors.As(err, &pe) || pe.Reason != PreflightNoJWKSURI {
		t.Fatalf("a document naming no key set: %v", err)
	}
	if got := fetches()[n:]; len(got) != 1 || got[0].Document != FetchDocumentDiscovery || got[0].Err != nil {
		t.Errorf("a resolution that never reached a key set reported %+v, want its discovery alone", got)
	}

	// Reading the state never waits on the locks fetches are made under.
	a.discMu.Lock()
	a.jwksMu.Lock()
	done := make(chan IdPState, 1)
	go func() { done <- a.IdPState() }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Error("IdPState waited on a lock held across a fetch")
	}
	a.jwksMu.Unlock()
	a.discMu.Unlock()

	var disabled *Authenticator
	if st := disabled.IdPState(); st.Discovery != nil || st.Ready || st.Issuer != "" {
		t.Errorf("a disabled client reports %+v", st)
	}
}
