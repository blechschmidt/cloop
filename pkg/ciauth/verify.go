package ciauth

// verify.go validates a CI/CD OIDC token against the forge's published
// signing keys.
//
// It does not reuse pkg/oidcauth. That package verifies an id_token obtained
// through an interactive authorization-code flow it drove itself: it knows the
// nonce it generated, the client_id it registered, and the state it stored,
// and its Authenticator is built around holding those. Here there is no flow
// and no client registration — an unauthenticated caller presents a bearer
// assertion minted by a third party — so the checks that matter are a
// different set, and entangling the two would make each harder to reason
// about. What is shared is the shape: the same algorithm allowlist, the same
// refusal to let a token name its own verification method.

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// maxTokenBytes bounds the assertion. A GitHub Actions token is around
	// 1 KiB; anything an order of magnitude past that is not one.
	maxTokenBytes = 16 << 10

	// maxDiscoveryBytes bounds both the discovery document and the key set.
	maxDiscoveryBytes = 1 << 20

	// jwksMinRefresh is the floor between key-set fetches triggered by an
	// unknown kid. Without it, a stream of tokens carrying forged kids turns
	// this hub into a load generator aimed at the forge.
	jwksMinRefresh = time.Minute

	// jwksMaxAge forces a periodic refetch even when every kid is known, so
	// a key rotated out at the forge stops being accepted here within an hour
	// rather than for the lifetime of the process.
	jwksMaxAge = time.Hour

	// discoveryTimeout bounds a single call to the forge.
	discoveryTimeout = 15 * time.Second

	// DefaultClockSkew tolerates modest clock drift between the forge and
	// this hub. Kept small deliberately: these tokens live minutes, so a
	// generous skew is a meaningful extension of their life.
	DefaultClockSkew = 60 * time.Second

	// MaxClockSkew bounds what an operator may configure.
	MaxClockSkew = 5 * time.Minute
)

// VerifierConfig configures a Verifier.
type VerifierConfig struct {
	// Issuer is the OIDC issuer, e.g. GitHubActionsIssuer. Discovery runs at
	// <issuer>/.well-known/openid-configuration.
	Issuer string

	// Audience is the `aud` a token must carry. Required: accepting any
	// audience would let a token a pipeline minted for an unrelated service
	// be replayed here.
	Audience string

	// ClockSkew tolerated on exp/iat/nbf. Zero uses DefaultClockSkew,
	// values are clamped to MaxClockSkew.
	ClockSkew time.Duration

	// Client overrides the HTTP client used for discovery and JWKS. Tests
	// point this at an httptest server; production leaves it nil.
	Client *http.Client

	// Now overrides the clock, for tests.
	Now func() time.Time
}

// Verifier verifies CI OIDC assertions. It caches the issuer's discovery
// document and key set, and is safe for concurrent use.
type Verifier struct {
	issuer    string
	audience  string
	skew      time.Duration
	client    *http.Client
	now       func() time.Time
	allowHTTP bool

	mu          sync.Mutex
	jwksURI     string
	keys        map[string]any
	fetchedAt   time.Time
	lastAttempt time.Time

	replay *replayCache
}

// NewVerifier validates the configuration and returns a Verifier.
//
// It does not contact the issuer: a hub must start when the forge is
// unreachable, and the first exchange will report the failure with the detail
// an operator needs. What it does refuse is a configuration that could not
// work — an issuer that is not an https URL, or a missing audience — because
// those are mistakes better found at boot than at the first pipeline run.
func NewVerifier(cfg VerifierConfig) (*Verifier, error) {
	iss := strings.TrimSpace(cfg.Issuer)
	if iss == "" {
		return nil, errors.New("ciauth: issuer is required")
	}
	iss = strings.TrimSuffix(iss, "/")
	u, err := url.Parse(iss)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("ciauth: issuer %q is not a URL", cfg.Issuer)
	}
	allowHTTP := isLoopbackHost(u.Hostname())
	switch {
	case u.Scheme == "https":
	case u.Scheme == "http" && allowHTTP:
		// A loopback issuer is a test fixture or a local IdP on the same
		// machine; there is no network to intercept.
	default:
		return nil, fmt.Errorf("ciauth: issuer %q must use https", cfg.Issuer)
	}
	aud := strings.TrimSpace(cfg.Audience)
	if aud == "" {
		return nil, errors.New("ciauth: audience is required")
	}
	skew := cfg.ClockSkew
	if skew <= 0 {
		skew = DefaultClockSkew
	}
	if skew > MaxClockSkew {
		skew = MaxClockSkew
	}
	client := cfg.Client
	if client == nil {
		client = &http.Client{Timeout: discoveryTimeout}
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	return &Verifier{
		issuer:    iss,
		audience:  aud,
		skew:      skew,
		client:    client,
		now:       now,
		allowHTTP: allowHTTP,
		keys:      map[string]any{},
		replay:    newReplayCache(),
	}, nil
}

// Issuer returns the configured issuer.
func (v *Verifier) Issuer() string { return v.issuer }

// Audience returns the configured audience.
func (v *Verifier) Audience() string { return v.audience }

// Verify checks the signature and the registered claims of raw, and returns
// its payload.
//
// Every failure wraps ErrUnverified so a caller can answer "genuine token,
// unknown pipeline" differently from "not a token I will read", while the
// message keeps the detail an operator needs. The message is safe to log and
// is deliberately *not* returned to the pipeline: a caller learning precisely
// which check failed learns how to approach the next one.
func (v *Verifier) Verify(ctx context.Context, raw string) (*Claims, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("%w: empty assertion", ErrUnverified)
	}
	if len(raw) > maxTokenBytes {
		return nil, fmt.Errorf("%w: assertion is %d bytes, limit is %d",
			ErrUnverified, len(raw), maxTokenBytes)
	}
	payload, err := v.verifySignature(ctx, raw)
	if err != nil {
		return nil, err
	}

	var all map[string]any
	if err := json.Unmarshal(payload, &all); err != nil {
		return nil, fmt.Errorf("%w: payload is not a JSON object: %v", ErrUnverified, err)
	}
	// Claims are read field by field out of the decoded map rather than by
	// unmarshalling the payload a second time into the struct. A single
	// json.Unmarshal is all-or-nothing, and these payloads have fields whose
	// JSON type is not fixed: `aud` is a bare string in most GitHub tokens
	// and an array in the spec, and `run_id` has been seen as both a string
	// and a number. One such field aborts the whole decode and leaves every
	// other field at its zero value — which for `exp` would mean a token
	// being refused for having no expiry that plainly has one, and, far
	// worse, is the shape of a bug where a check passes because the value it
	// checks was silently dropped.
	c := claimsFrom(all)

	if !issuerEqual(c.Issuer, v.issuer) {
		return nil, fmt.Errorf("%w: issued by %q, expected %q", ErrUnverified, c.Issuer, v.issuer)
	}
	if c.Subject == "" {
		return nil, fmt.Errorf("%w: no sub claim", ErrUnverified)
	}
	if !containsString(c.Audience, v.audience) {
		return nil, fmt.Errorf("%w: audience %v does not include %q — the workflow must request "+
			"an ID token with this audience", ErrUnverified, c.Audience, v.audience)
	}

	now := v.now()
	if c.ExpiresAt == 0 {
		// An assertion with no expiry is a bearer credential forever. The
		// forge always sets one; a token without one is not from the forge.
		return nil, fmt.Errorf("%w: no exp claim", ErrUnverified)
	}
	exp := time.Unix(c.ExpiresAt, 0)
	if !now.Before(exp.Add(v.skew)) {
		return nil, fmt.Errorf("%w: expired at %s", ErrUnverified, exp.UTC().Format(time.RFC3339))
	}
	if c.IssuedAt != 0 {
		iat := time.Unix(c.IssuedAt, 0)
		if iat.After(now.Add(v.skew)) {
			return nil, fmt.Errorf("%w: issued in the future, at %s",
				ErrUnverified, iat.UTC().Format(time.RFC3339))
		}
	}
	if c.NotBefore != 0 {
		nbf := time.Unix(c.NotBefore, 0)
		if nbf.After(now.Add(v.skew)) {
			return nil, fmt.Errorf("%w: not valid before %s",
				ErrUnverified, nbf.UTC().Format(time.RFC3339))
		}
	}

	// Single use. The forge mints these per job and they remain valid for
	// several minutes after the step that requested one has finished, so a
	// token recovered from a debug log or a leaked runner filesystem is
	// otherwise replayable for the rest of its life. Refusing the second
	// presentation costs a correctly behaving pipeline nothing: it asks the
	// forge for a fresh token whenever it needs one.
	if c.JTI != "" {
		if !v.replay.admit(c.JTI, exp, now) {
			return nil, fmt.Errorf("%w: %v", ErrUnverified, ErrReplayed)
		}
	}
	return c, nil
}

// verifySignature parses the compact JWS and checks it against the issuer's
// key set, returning the raw payload.
func (v *Verifier) verifySignature(ctx context.Context, raw string) ([]byte, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("%w: not a compact JWS", ErrUnverified)
	}
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("%w: header is not base64url: %v", ErrUnverified, err)
	}
	var hdr struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
		Typ string `json:"typ"`
	}
	if err := json.Unmarshal(headerJSON, &hdr); err != nil {
		return nil, fmt.Errorf("%w: header is not JSON: %v", ErrUnverified, err)
	}
	// "none" and the HMAC family are refused by omission rather than by name:
	// an algorithm the verifier does not implement cannot be negotiated by
	// the token itself, which is the alg-confusion attack this exists to stop.
	switch hdr.Alg {
	case "RS256", "ES256":
	default:
		return nil, fmt.Errorf("%w: unsupported alg %q (supported: RS256, ES256)", ErrUnverified, hdr.Alg)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("%w: payload is not base64url: %v", ErrUnverified, err)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("%w: signature is not base64url: %v", ErrUnverified, err)
	}
	key, err := v.signingKey(ctx, hdr.Kid)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	switch pub := key.(type) {
	case *rsa.PublicKey:
		if hdr.Alg != "RS256" {
			return nil, fmt.Errorf("%w: alg %s does not match an RSA key", ErrUnverified, hdr.Alg)
		}
		if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig); err != nil {
			return nil, fmt.Errorf("%w: signature invalid", ErrUnverified)
		}
	case *ecdsa.PublicKey:
		if hdr.Alg != "ES256" {
			return nil, fmt.Errorf("%w: alg %s does not match an EC key", ErrUnverified, hdr.Alg)
		}
		if len(sig) != 64 {
			return nil, fmt.Errorf("%w: ES256 signature must be 64 bytes, got %d", ErrUnverified, len(sig))
		}
		r := new(big.Int).SetBytes(sig[:32])
		s := new(big.Int).SetBytes(sig[32:])
		if !ecdsa.Verify(pub, digest[:], r, s) {
			return nil, fmt.Errorf("%w: signature invalid", ErrUnverified)
		}
	default:
		return nil, fmt.Errorf("%w: unsupported key type %T", ErrUnverified, key)
	}
	return payload, nil
}

// signingKey returns the public key for kid, refreshing the key set when the
// kid is unknown or the cache has aged out.
func (v *Verifier) signingKey(ctx context.Context, kid string) (any, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	stale := v.fetchedAt.IsZero() || v.now().Sub(v.fetchedAt) > jwksMaxAge
	if key, ok := v.keys[kid]; ok && !stale {
		return key, nil
	}
	// Rate-limit refreshes triggered by tokens rather than by the clock.
	if !stale && v.now().Sub(v.lastAttempt) < jwksMinRefresh {
		return nil, fmt.Errorf("%w: unknown signing key %q", ErrUnverified, kid)
	}
	v.lastAttempt = v.now()
	if err := v.refreshLocked(ctx); err != nil {
		// A stale key that still verifies is better than refusing every
		// pipeline because the forge had a bad minute.
		if key, ok := v.keys[kid]; ok {
			return key, nil
		}
		return nil, fmt.Errorf("%w: %v", ErrUnverified, err)
	}
	key, ok := v.keys[kid]
	if !ok {
		return nil, fmt.Errorf("%w: signing key %q is not in the issuer's key set", ErrUnverified, kid)
	}
	return key, nil
}

// refreshLocked re-runs discovery when needed and refetches the key set. The
// caller holds v.mu.
func (v *Verifier) refreshLocked(ctx context.Context) error {
	if v.jwksURI == "" {
		uri, err := v.discoverJWKS(ctx)
		if err != nil {
			return err
		}
		v.jwksURI = uri
	}
	body, err := v.get(ctx, v.jwksURI)
	if err != nil {
		return fmt.Errorf("fetch key set: %w", err)
	}
	keys, err := parseJWKSet(body)
	if err != nil {
		return err
	}
	v.keys = keys
	v.fetchedAt = v.now()
	return nil
}

// discoverJWKS reads the issuer's discovery document and returns its
// jwks_uri.
func (v *Verifier) discoverJWKS(ctx context.Context) (string, error) {
	docURL := v.issuer + "/.well-known/openid-configuration"
	body, err := v.get(ctx, docURL)
	if err != nil {
		return "", fmt.Errorf("discovery at %s: %w", docURL, err)
	}
	var doc struct {
		Issuer  string `json:"issuer"`
		JWKSURI string `json:"jwks_uri"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return "", fmt.Errorf("discovery at %s is not JSON: %w", docURL, err)
	}
	// The document must claim the issuer we asked about. Without this an open
	// redirect or a misconfigured proxy in front of the issuer could hand back
	// someone else's key set, and every token they sign would verify here.
	if !issuerEqual(doc.Issuer, v.issuer) {
		return "", fmt.Errorf("discovery document names issuer %q, expected %q", doc.Issuer, v.issuer)
	}
	if doc.JWKSURI == "" {
		return "", fmt.Errorf("discovery at %s has no jwks_uri", docURL)
	}
	u, err := url.Parse(doc.JWKSURI)
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("jwks_uri %q is not a URL", doc.JWKSURI)
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && v.allowHTTP) {
		return "", fmt.Errorf("jwks_uri %q must use https", doc.JWKSURI)
	}
	// Pin the key set to the issuer's own host. The document is served by the
	// issuer over TLS and is therefore authoritative, but a key set fetched
	// from a third host is a redirection of trust that no legitimate issuer
	// needs and that nothing downstream would reveal.
	issURL, _ := url.Parse(v.issuer)
	if issURL != nil && !strings.EqualFold(u.Host, issURL.Host) {
		return "", fmt.Errorf("jwks_uri host %q does not match issuer host %q", u.Host, issURL.Host)
	}
	return doc.JWKSURI, nil
}

// get performs a bounded GET.
func (v *Verifier) get(ctx context.Context, u string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, discoveryTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := v.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close() //nolint:errcheck // read-only
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, maxDiscoveryBytes))
}

// jwk is one entry of an RFC 7517 key set.
type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

// parseJWKSet decodes a key set, keeping only keys this verifier can use.
func parseJWKSet(body []byte) (map[string]any, error) {
	var set struct {
		Keys []jwk `json:"keys"`
	}
	if err := json.Unmarshal(body, &set); err != nil {
		return nil, fmt.Errorf("key set is not JSON: %w", err)
	}
	out := map[string]any{}
	for _, k := range set.Keys {
		if k.Use != "" && k.Use != "sig" {
			continue
		}
		if k.Alg != "" && k.Alg != "RS256" && k.Alg != "ES256" {
			continue
		}
		key, err := parseJWK(k)
		if err != nil {
			// One unusable key must not discard the rest: issuers publish
			// keys for algorithms this verifier does not implement.
			continue
		}
		if k.Kid == "" {
			// A key set with a single unnamed key is legal; tokens from such
			// an issuer carry no kid either, so "" is the right index.
			out[""] = key
			continue
		}
		out[k.Kid] = key
	}
	if len(out) == 0 {
		return nil, errors.New("key set contains no usable RS256 or ES256 signing key")
	}
	return out, nil
}

func parseJWK(k jwk) (any, error) {
	switch k.Kty {
	case "RSA":
		nb, err := base64.RawURLEncoding.DecodeString(k.N)
		if err != nil {
			return nil, err
		}
		eb, err := base64.RawURLEncoding.DecodeString(k.E)
		if err != nil {
			return nil, err
		}
		if len(nb) == 0 || len(eb) == 0 || len(eb) > 8 {
			return nil, errors.New("malformed RSA key")
		}
		e := new(big.Int).SetBytes(eb).Int64()
		if e < 3 || e > 1<<31 {
			return nil, errors.New("RSA exponent out of range")
		}
		n := new(big.Int).SetBytes(nb)
		// Below 2048 bits is not a key set this hub should be trusting.
		if n.BitLen() < 2048 {
			return nil, fmt.Errorf("RSA modulus is %d bits", n.BitLen())
		}
		return &rsa.PublicKey{N: n, E: int(e)}, nil
	case "EC":
		if k.Crv != "P-256" {
			return nil, fmt.Errorf("unsupported curve %q", k.Crv)
		}
		xb, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil {
			return nil, err
		}
		yb, err := base64.RawURLEncoding.DecodeString(k.Y)
		if err != nil {
			return nil, err
		}
		x := new(big.Int).SetBytes(xb)
		y := new(big.Int).SetBytes(yb)
		if !elliptic.P256().IsOnCurve(x, y) {
			return nil, errors.New("EC point is not on P-256")
		}
		return &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, nil
	}
	return nil, fmt.Errorf("unsupported key type %q", k.Kty)
}

// claimsFrom projects a decoded payload onto the typed fields. Unreadable or
// absent fields are left zero; every check that matters treats zero as a
// refusal rather than as a pass.
func claimsFrom(all map[string]any) *Claims {
	c := &Claims{All: all, Audience: audienceOf(all)}
	c.Issuer = claimString(all, "iss")
	c.Subject = claimString(all, "sub")
	c.JTI = claimString(all, "jti")
	c.IssuedAt = claimInt(all, "iat")
	c.NotBefore = claimInt(all, "nbf")
	c.ExpiresAt = claimInt(all, "exp")

	c.Repository = claimString(all, "repository")
	c.RepositoryOwner = claimString(all, "repository_owner")
	c.RepositoryVisiblity = claimString(all, "repository_visibility")
	c.Ref = claimString(all, "ref")
	c.RefType = claimString(all, "ref_type")
	c.Workflow = claimString(all, "workflow")
	c.WorkflowRef = claimString(all, "workflow_ref")
	c.JobWorkflowRef = claimString(all, "job_workflow_ref")
	c.Environment = claimString(all, "environment")
	c.Actor = claimString(all, "actor")
	c.EventName = claimString(all, "event_name")
	c.RunID = claimString(all, "run_id")
	c.RunAttempt = claimString(all, "run_attempt")
	c.RunnerEnvironment = claimString(all, "runner_environment")
	c.SHA = claimString(all, "sha")
	return c
}

// claimString reads a string claim, rendering a number as its decimal form so
// a run_id that arrived unquoted still populates the field.
func claimString(all map[string]any, key string) string {
	switch v := all[key].(type) {
	case string:
		return v
	case float64:
		if v == float64(int64(v)) {
			return strconv.FormatInt(int64(v), 10)
		}
	}
	return ""
}

// claimInt reads a numeric claim, accepting the quoted form some issuers emit.
func claimInt(all map[string]any, key string) int64 {
	switch v := all[key].(type) {
	case float64:
		return int64(v)
	case string:
		n, err := strconv.ParseInt(v, 10, 64)
		if err == nil {
			return n
		}
	}
	return 0
}

// issuerEqual compares issuers, tolerating a trailing slash on either side.
func issuerEqual(a, b string) bool {
	return strings.TrimSuffix(a, "/") == strings.TrimSuffix(b, "/")
}

// audienceOf reads `aud` in either of its legal shapes.
func audienceOf(all map[string]any) []string {
	switch v := all["aud"].(type) {
	case string:
		return []string{v}
	case []any:
		out := make([]string, 0, len(v))
		for _, el := range v {
			if s, ok := el.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func containsString(hay []string, needle string) bool {
	for _, s := range hay {
		if s == needle {
			return true
		}
	}
	return false
}

func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// ---------------------------------------------------------------------------
// Replay cache
// ---------------------------------------------------------------------------

// maxReplayEntries bounds the cache. Entries are dropped when a token expires,
// so this is only reached by a burst; evicting the earliest-expiring entry
// under pressure degrades to "replay is possible again" rather than to
// unbounded memory, which is the right way round for a hub whose real defence
// is the token's own short life.
const maxReplayEntries = 16384

type replayCache struct {
	mu   sync.Mutex
	seen map[string]time.Time
}

func newReplayCache() *replayCache {
	return &replayCache{seen: make(map[string]time.Time)}
}

// admit records jti and reports whether this is its first presentation.
func (c *replayCache) admit(jti string, exp, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	if until, ok := c.seen[jti]; ok && now.Before(until) {
		return false
	}
	if len(c.seen) >= maxReplayEntries {
		c.sweepLocked(now)
		if len(c.seen) >= maxReplayEntries {
			// Still full of live entries: drop the one expiring soonest.
			var oldestKey string
			var oldest time.Time
			for k, t := range c.seen {
				if oldestKey == "" || t.Before(oldest) {
					oldestKey, oldest = k, t
				}
			}
			delete(c.seen, oldestKey)
		}
	}
	c.seen[jti] = exp
	return true
}

func (c *replayCache) sweepLocked(now time.Time) {
	for k, until := range c.seen {
		if !now.Before(until) {
			delete(c.seen, k)
		}
	}
}
