package oidcauth

// What the sign-in client holds of its issuer, and what fetching it cost
// (Task 20446).
//
// The hub's Settings → Hub health report used to resolve the issuer afresh on
// every run — the discovery document and the key set, two round trips to the
// identity provider — and a run was made for every open administrator's tab
// about once a minute. Everything that report wanted to know the hub's own
// sign-in client already knows: whether discovery resolved and what it
// resolved to, how many keys it holds and since when, and why the last attempt
// to fetch either failed. IdPState reads that, under a lock no network call is
// ever made under, so a diagnosis of the identity path costs the issuer
// nothing.
//
// ObserveFetches is the other half: every fetch of either document, by the
// sign-in client or by a standalone Preflight, is reported to one observer the
// hub installs, which counts it in hubmetrics. A callback rather than an import
// because this package stays stdlib-only.

import (
	"errors"
	"sync/atomic"
	"time"
)

// The documents an issuer serves that a sign-in depends on, and who fetched
// them: closed sets, so a metric may be labelled by them.
const (
	FetchDocumentDiscovery = "discovery"
	FetchDocumentJWKS      = "jwks"

	// FetchClientSignIn is the hub's own sign-in client: at startup, on a
	// sign-in that finds discovery missing, and for a token signed by a key
	// it does not hold.
	FetchClientSignIn = "signin"
	// FetchClientPreflight is a standalone resolution of an issuer, with no
	// Authenticator behind it: `cloop hub doctor`, Settings → Single sign-on's
	// Test, and Hub health's check of an issuer the running client is not
	// using.
	FetchClientPreflight = "preflight"
)

// IdPFetch is one fetch of an issuer's discovery document or key set.
type IdPFetch struct {
	// Document is FetchDocumentDiscovery or FetchDocumentJWKS.
	Document string
	// Client is FetchClientSignIn or FetchClientPreflight.
	Client string
	// Err is why the document could not be used — unreachable, an HTTP
	// error, malformed, no usable key — or nil.
	Err error
}

// fetchObserver is the process's one observer of IdP fetches.
var fetchObserver atomic.Pointer[func(IdPFetch)]

// ObserveFetches installs fn as the observer of every discovery and key-set
// fetch this process makes from now on, replacing any earlier one; nil stops
// observing. fn runs on the fetching goroutine and must not block.
func ObserveFetches(fn func(IdPFetch)) {
	if fn == nil {
		fetchObserver.Store(nil)
		return
	}
	fetchObserver.Store(&fn)
}

// noteFetch reports one fetch to the observer. A key-set stage that failed
// because discovery named no key set made no request, and is not a fetch.
func noteFetch(document, client string, err error) {
	var pe *PreflightError
	if errors.As(err, &pe) && pe.Reason == PreflightNoJWKSURI {
		return
	}
	if fn := fetchObserver.Load(); fn != nil {
		(*fn)(IdPFetch{Document: document, Client: client, Err: err})
	}
}

// IdPState is what this hub's sign-in client holds of its issuer, read without
// contacting it.
type IdPState struct {
	// Issuer is the issuer the client was configured with.
	Issuer string
	// Discovery is what the discovery document resolved to, with SigningKeys
	// the keys held now; nil until discovery has resolved. The client keeps a
	// resolved document for its lifetime.
	Discovery *PreflightResult
	// DiscoveredAt is when discovery resolved.
	DiscoveredAt time.Time
	// SigningKeys is how many keys the client can verify a token with, and
	// KeysFetchedAt when the set they came from was fetched.
	SigningKeys   int
	KeysFetchedAt time.Time
	// Ready reports that discovery and a usable key set have both resolved at
	// least once, which is what /readyz asserts.
	Ready bool
	// LastError is the last failure to fetch either document, cleared by the
	// next fetch that succeeds, and LastErrorAt when it happened.
	LastError   error
	LastErrorAt time.Time
}

// IdPState reports what the client holds of its issuer. It takes only the
// readiness lock, which no network call is made under, so it never waits on
// an issuer that is slow to answer. The zero value for a disabled client.
func (a *Authenticator) IdPState() IdPState {
	if !a.Enabled() {
		return IdPState{}
	}
	a.idpMu.Lock()
	defer a.idpMu.Unlock()
	st := IdPState{
		Issuer:        a.cfg.Issuer,
		DiscoveredAt:  a.idpDiscAt,
		SigningKeys:   a.idpKeys,
		KeysFetchedAt: a.idpKeysAt,
		Ready:         a.idpReady,
		LastError:     a.idpErr,
		LastErrorAt:   a.idpErrAt,
	}
	if a.idpDisc != nil {
		st.Discovery = resultFor(a.cfg.Issuer, a.idpDisc, a.idpKeys)
	}
	return st
}

// noteDiscovered records a discovery document the client just cached.
func (a *Authenticator) noteDiscovered(doc *discoveryDoc) {
	cp := *doc
	a.idpMu.Lock()
	a.idpDisc, a.idpDiscAt = &cp, time.Now()
	a.idpMu.Unlock()
}
