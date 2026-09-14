package oidcauth

// Fail fast on a misconfigured identity provider (Task 20247).
//
// Discovery used to happen lazily, on the first BeginLogin. That is the right
// *retry* behaviour — an IdP that is down for a minute must not need a hub
// restart to recover — and the wrong startup behaviour: a hub pointed at a
// misspelled issuer came up green, reported healthy, and failed for the first
// human who tried to sign in, with an error page rendered from an exception
// three layers below the setting that was actually wrong.
//
// Preflight is the same two round trips performed deliberately, at startup,
// with a short timeout and an error that names the issuer URL and the HTTP
// status. Nothing else changes: a failed preflight does not disable the lazy
// path, so a transiently-unreachable IdP still recovers on its own. What it
// buys is that the failure is reported once, in the hub's own log, at the
// moment an operator is watching — and that `cloop hub doctor` and the hub
// itself resolve the issuer through exactly the same code, so the doctor
// cannot be green about a login that will fail.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// DefaultPreflightTimeout bounds an entire preflight — discovery and the JWKS
// fetch together, not each.
//
// Short on purpose. This runs before the listener binds, so every second of it
// is a second the hub is not serving; and the thing it is waiting for is a
// metadata document that a healthy IdP returns in milliseconds. A slow answer
// is diagnostically the same as no answer, and the lazy path will retry either
// way.
const DefaultPreflightTimeout = 10 * time.Second

// Preflight stages — which of the two round trips failed.
const (
	StageDiscovery = "discovery"
	StageJWKS      = "jwks"
)

// Preflight failure reasons. A closed set: every PreflightError carries one of
// these, so a caller can branch on the cause without matching on prose.
const (
	// PreflightUnreachable covers everything that is not an answer: DNS,
	// connection refused, TLS, timeout, and any non-200 status.
	PreflightUnreachable = "unreachable"

	// PreflightMalformed means the endpoint answered but not with the
	// document it is supposed to serve.
	PreflightMalformed = "malformed"

	// PreflightIssuerMismatch means the provider calls itself something
	// other than the configured issuer. The spec makes that equality
	// load-bearing, and cloop enforces it at ID-token validation, so this
	// is a hub whose every sign-in will be rejected.
	PreflightIssuerMismatch = "issuer_mismatch"

	// PreflightNoJWKSURI means the discovery document advertises no signing
	// keys — usually a bare OAuth 2 server rather than an OIDC provider.
	PreflightNoJWKSURI = "no_jwks_uri"

	// PreflightNoKeys means the key set held nothing cloop can verify with
	// (RS256/ES256). The provider works; this hub can never validate a
	// token from it.
	PreflightNoKeys = "no_keys"

	// PreflightNotConfigured means there is no issuer to contact.
	PreflightNotConfigured = "not_configured"

	// PreflightUnverified means nothing has tried yet. It is the fail-closed
	// initial state: "not attempted" and "succeeded" must not read the same
	// to a readiness probe, or a hub that skipped its preflight would report
	// the identity path as healthy on no evidence at all.
	PreflightUnverified = "unverified"
)

// PreflightResult is what a successful preflight resolved: the endpoints a
// sign-in will actually use, reported so an operator can see them rather than
// infer them from the issuer.
type PreflightResult struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
	EndSessionEndpoint    string `json:"end_session_endpoint,omitempty"`

	// SigningKeys is how many keys in the set cloop can actually verify
	// with, which is the number that decides whether a token validates —
	// not how many the provider published.
	SigningKeys int `json:"signing_keys"`
}

// PreflightError is a failure to resolve an issuer.
//
// It is a type rather than a formatted string because three callers need to
// branch on it: the doctor turns the reason into a remediation, /readyz turns
// it into a probe response, and the hub turns it into a startup refusal when
// the IdP is declared mandatory. Matching prose for any of those would break
// the first time the wording changed.
type PreflightError struct {
	// Issuer is the configured issuer, always populated — it is the value
	// an operator most likely needs to correct.
	Issuer string

	// Stage is StageDiscovery or StageJWKS.
	Stage string

	// URL is the endpoint that failed.
	URL string

	// Status is the HTTP status when the endpoint answered, 0 when it did
	// not answer at all (DNS, refused connection, TLS, timeout).
	Status int

	// Reason is one of the Preflight* constants.
	Reason string

	// Detail is the human-readable specifics.
	Detail string

	// Resolved carries what the preflight did establish before it failed,
	// which for a StageJWKS failure is the whole discovery document. A
	// diagnostic reports the two stages separately — "the issuer resolved,
	// its keys did not" is a different problem with a different fix — and
	// without this it would have to re-fetch the document to say so.
	// Nil for a StageDiscovery failure, where nothing was established.
	Resolved *PreflightResult

	// Err is the underlying error, if any.
	Err error
}

func (e *PreflightError) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "oidcauth: identity provider %q is not usable: %s", e.Issuer, e.Stage)
	if e.URL != "" {
		b.WriteString(" at " + e.URL)
	}
	if e.Status != 0 {
		fmt.Fprintf(&b, " returned HTTP %d", e.Status)
	}
	if e.Detail != "" {
		b.WriteString(": " + e.Detail)
	}
	return b.String()
}

func (e *PreflightError) Unwrap() error { return e.Err }

// Remediation is the one-line fix, chosen from the reason. It is phrased for
// an operator reading `kubectl describe pod` or a doctor report, so it names
// the setting to change rather than the code path that failed.
func (e *PreflightError) Remediation() string {
	switch e.Reason {
	case PreflightNotConfigured:
		return "Set ui.oidc.issuer to the identity provider's issuer URL"
	case PreflightUnreachable:
		// The status discriminates three genuinely different problems, and
		// the generic "check network and certificates" advice is wrong for
		// two of them: a host that answered 404 is reachable and trusted, and
		// the operator sent to check their firewall will not find anything.
		switch {
		case e.Status == http.StatusNotFound:
			return "The host answered but publishes nothing there — check ui.oidc.issuer " +
				"includes the realm or tenant path segment, and no trailing /.well-known"
		case e.Status == http.StatusUnauthorized || e.Status == http.StatusForbidden:
			return "The issuer metadata is behind authentication; it must be publicly readable " +
				"(check any proxy or WAF in front of the provider)"
		case e.Status >= 500:
			return "The provider returned a server error — it may still be starting, or the " +
				"realm may be disabled. The hub retries at the next sign-in"
		case e.Status != 0:
			return "Confirm ui.oidc.issuer names the OpenID provider's base URL"
		}
		return "Check that this host can reach " + e.Issuer +
			" and trusts its certificate (SSL_CERT_DIR adds a private CA)"
	case PreflightMalformed:
		return "Confirm ui.oidc.issuer names the OpenID provider itself, not a login page in front of it"
	case PreflightIssuerMismatch:
		return "Set ui.oidc.issuer to the name the provider gives itself in its discovery document"
	case PreflightNoJWKSURI:
		return "Confirm ui.oidc.issuer names an OpenID Connect provider, not a bare OAuth 2 server"
	case PreflightNoKeys:
		return "Configure the identity provider to sign ID tokens with RS256 or ES256"
	case PreflightUnverified:
		return "Run `cloop hub doctor` — the hub also retries at the first sign-in"
	}
	return "Run `cloop hub doctor` for the full identity diagnosis"
}

// statusOf extracts the HTTP status from an IdP transport error, or 0 when
// the endpoint never answered.
func statusOf(err error) int {
	var se *idpStatusError
	if errors.As(err, &se) {
		return se.Status
	}
	return 0
}

// unwrapDetail renders the cause for a PreflightError's Detail. For a status
// error the status is already carried in its own field, so only the body
// excerpt is worth repeating.
func unwrapDetail(err error) string {
	var se *idpStatusError
	if errors.As(err, &se) {
		if se.Body == "" {
			return ""
		}
		return se.Body
	}
	return err.Error()
}

// PreflightOptions tunes a standalone preflight. The zero value is usable.
type PreflightOptions struct {
	// Timeout bounds the whole preflight. Zero uses DefaultPreflightTimeout.
	Timeout time.Duration

	// Client performs the requests. Nil builds one bounded by Timeout. A
	// caller supplying one (the doctor, tests) owns its transport and its
	// own timeout.
	Client *http.Client
}

func (o PreflightOptions) timeout() time.Duration {
	if o.Timeout > 0 {
		return o.Timeout
	}
	return DefaultPreflightTimeout
}

func (o PreflightOptions) client() *http.Client {
	if o.Client != nil {
		return o.Client
	}
	return &http.Client{Timeout: o.timeout()}
}

// Preflight resolves an issuer's endpoints and signing keys without needing an
// Authenticator — so a diagnostic can run it against an issuer whose client
// credentials are missing, which is precisely the config a diagnostic exists
// to report on.
//
// It performs exactly what a sign-in performs before it can begin: fetch the
// discovery document, check the issuer agrees on its own name, fetch the key
// set, and count the keys cloop can verify with.
func Preflight(ctx context.Context, issuer string, opts PreflightOptions) (*PreflightResult, error) {
	issuer = strings.TrimSpace(issuer)
	if issuer == "" {
		return nil, &PreflightError{
			Stage:  StageDiscovery,
			Reason: PreflightNotConfigured,
			Detail: "no issuer is configured",
		}
	}

	ctx, cancel := context.WithTimeout(ctx, opts.timeout())
	defer cancel()

	client := opts.client()
	doc, err := fetchDiscovery(ctx, client, issuer)
	if err != nil {
		return nil, err
	}
	keys, err := fetchJWKS(ctx, client, issuer, doc)
	if err != nil {
		return nil, withResolved(err, issuer, doc)
	}
	return resultFor(issuer, doc, len(keys)), nil
}

// withResolved records on a JWKS-stage failure what discovery did establish,
// so a caller can report the two stages independently.
//
// It returns a copy rather than annotating in place. By the time this runs the
// original has already been handed to noteIdPErr and is reachable from every
// concurrent /readyz probe — writing a field into it there would be a data race
// on an error value two goroutines share, which is a strange enough shape that
// it is worth not having at all.
func withResolved(err error, issuer string, doc *discoveryDoc) error {
	var pe *PreflightError
	if !errors.As(err, &pe) {
		return err
	}
	annotated := *pe
	annotated.Resolved = resultFor(issuer, doc, 0)
	return &annotated
}

// resultFor renders a successful preflight.
func resultFor(issuer string, doc *discoveryDoc, keys int) *PreflightResult {
	return &PreflightResult{
		Issuer:                issuer,
		AuthorizationEndpoint: doc.AuthorizationEndpoint,
		TokenEndpoint:         doc.TokenEndpoint,
		JWKSURI:               doc.JWKSURI,
		EndSessionEndpoint:    doc.EndSessionEndpoint,
		SigningKeys:           keys,
	}
}

// wellKnownURL is where an issuer's metadata lives. One function so the hub,
// the preflight and the doctor cannot disagree about it.
func wellKnownURL(issuer string) string {
	return strings.TrimSuffix(issuer, "/") + "/.well-known/openid-configuration"
}

// fetchDiscovery performs one discovery round trip and validates the document
// as far as a login depends on it. Shared by the lazy path, the startup
// preflight and the doctor.
func fetchDiscovery(ctx context.Context, client *http.Client, issuer string) (*discoveryDoc, error) {
	u := wellKnownURL(issuer)
	body, err := getJSON(ctx, client, u)
	if err != nil {
		return nil, &PreflightError{
			Issuer: issuer, Stage: StageDiscovery, URL: u,
			Status: statusOf(err), Reason: PreflightUnreachable,
			Detail: unwrapDetail(err), Err: err,
		}
	}
	var doc discoveryDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, &PreflightError{
			Issuer: issuer, Stage: StageDiscovery, URL: u,
			Reason: PreflightMalformed,
			Detail: "the response is not a JSON discovery document (" + err.Error() + ")",
			Err:    err,
		}
	}
	if doc.AuthorizationEndpoint == "" || doc.TokenEndpoint == "" {
		return nil, &PreflightError{
			Issuer: issuer, Stage: StageDiscovery, URL: u,
			Reason: PreflightMalformed,
			Detail: "the discovery document is missing authorization_endpoint or token_endpoint",
		}
	}
	if !issuerEqual(doc.Issuer, issuer) {
		return nil, &PreflightError{
			Issuer: issuer, Stage: StageDiscovery, URL: u,
			Reason: PreflightIssuerMismatch,
			Detail: fmt.Sprintf("the provider calls itself %q, so every ID token will be rejected", doc.Issuer),
		}
	}
	return &doc, nil
}

// fetchJWKS performs the key-set round trip and parses it into kid → public
// key, keeping only the keys cloop can actually verify with.
func fetchJWKS(ctx context.Context, client *http.Client, issuer string, doc *discoveryDoc) (map[string]any, error) {
	if strings.TrimSpace(doc.JWKSURI) == "" {
		return nil, &PreflightError{
			Issuer: issuer, Stage: StageJWKS,
			Reason: PreflightNoJWKSURI,
			Detail: "the discovery document advertises no jwks_uri, so ID tokens cannot be verified",
		}
	}
	body, err := getJSON(ctx, client, doc.JWKSURI)
	if err != nil {
		return nil, &PreflightError{
			Issuer: issuer, Stage: StageJWKS, URL: doc.JWKSURI,
			Status: statusOf(err), Reason: PreflightUnreachable,
			Detail: unwrapDetail(err), Err: err,
		}
	}
	keys, err := parseJWKSet(body)
	if err != nil {
		reason := PreflightNoKeys
		if errors.Is(err, errJWKSMalformed) {
			reason = PreflightMalformed
		}
		return nil, &PreflightError{
			Issuer: issuer, Stage: StageJWKS, URL: doc.JWKSURI,
			Reason: reason, Detail: err.Error(), Err: err,
		}
	}
	return keys, nil
}

// ── the authenticator's view ────────────────────────────────────────────────

// unverified is what IdPReady reports before anything has succeeded and
// nothing has failed — a hub that has not yet been asked to resolve its
// issuer. It is a PreflightError like every other identity failure so a probe
// body carries a remediation here too: "not contacted yet" with no next step
// is precisely the unactionable report this whole gate exists to replace.
func (a *Authenticator) unverified() error {
	return &PreflightError{
		Issuer: a.cfg.Issuer,
		Stage:  StageDiscovery,
		Reason: PreflightUnverified,
		Detail: "the hub has not resolved this issuer yet, so no sign-in has been proven possible",
	}
}

// Preflight resolves this authenticator's issuer and warms its caches, so the
// first real sign-in does not pay for discovery.
//
// A failure is recorded (see IdPReady) but changes nothing else: the lazy path
// stays exactly as it was and will retry on the next login. That is the whole
// design — preflight makes a misconfiguration loud, it does not make a
// transient outage permanent.
func (a *Authenticator) Preflight(ctx context.Context) (*PreflightResult, error) {
	if !a.Enabled() {
		return nil, &PreflightError{
			Stage: StageDiscovery, Reason: PreflightNotConfigured,
			Detail: "OIDC is not enabled on this hub",
		}
	}
	ctx, cancel := context.WithTimeout(ctx, DefaultPreflightTimeout)
	defer cancel()

	// discover and fetchJWKSLocked both record their own verdict, so the
	// readiness view is identical whether it was a preflight or a login that
	// last touched the IdP.
	doc, err := a.discover(ctx)
	if err != nil {
		return nil, err
	}
	a.jwksMu.Lock()
	err = a.fetchJWKSLocked(ctx)
	keys := len(a.jwksKeys)
	a.jwksMu.Unlock()
	if err != nil {
		return nil, withResolved(err, a.cfg.Issuer, doc)
	}
	return resultFor(a.cfg.Issuer, doc, keys), nil
}

// IdPReady reports whether this hub has ever successfully resolved its issuer
// — discovery *and* a usable key set.
//
// It returns the last failure, not a generic one, because the caller is
// /readyz and the audience for a readiness body is an operator who has just
// watched a rollout stall. Once a resolution has succeeded it keeps returning
// nil even if the IdP later goes away: existing sessions still authenticate,
// so flapping the whole hub out of its Service on the IdP's availability would
// convert a login outage into a total one.
func (a *Authenticator) IdPReady() error {
	if !a.Enabled() {
		return nil
	}
	a.idpMu.Lock()
	defer a.idpMu.Unlock()
	if a.idpReady {
		return nil
	}
	if a.idpErr != nil {
		return a.idpErr
	}
	return a.unverified()
}

// noteIdPOK records that discovery and the key set both resolved.
func (a *Authenticator) noteIdPOK() {
	a.idpMu.Lock()
	a.idpReady, a.idpErr = true, nil
	a.idpMu.Unlock()
}

// noteIdPErr records a failure. It never clears idpReady: a hub that resolved
// its issuer once is configured correctly, and a later failure is an outage,
// which is a different thing and must not be reported as a misconfiguration.
func (a *Authenticator) noteIdPErr(err error) {
	a.idpMu.Lock()
	a.idpErr = err
	a.idpMu.Unlock()
}
