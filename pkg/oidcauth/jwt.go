package oidcauth

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
	"math/big"
	"strings"
	"time"
)

// audClaim tolerates the two encodings the spec allows for "aud":
// a single string or an array of strings.
type audClaim []string

func (a *audClaim) UnmarshalJSON(data []byte) error {
	var single string
	if err := json.Unmarshal(data, &single); err == nil {
		*a = audClaim{single}
		return nil
	}
	var many []string
	if err := json.Unmarshal(data, &many); err != nil {
		return err
	}
	*a = audClaim(many)
	return nil
}

// stringListClaim tolerates the shapes IdPs actually emit for group and
// role claims: a JSON array of strings, or a single string holding one or
// more comma- or space-separated values. Anything else (a number, an
// object) yields an empty list rather than an error — a malformed optional
// claim must not reject an otherwise valid token, it must simply grant
// nothing.
type stringListClaim []string

func (c *stringListClaim) UnmarshalJSON(data []byte) error {
	var many []string
	if err := json.Unmarshal(data, &many); err == nil {
		*c = stringListClaim(many)
		return nil
	}
	var one string
	if err := json.Unmarshal(data, &one); err == nil {
		*c = stringListClaim(splitClaimList(one))
		return nil
	}
	*c = nil
	return nil
}

// splitClaimList breaks a single-string group/role claim on commas and
// whitespace, dropping empties.
func splitClaimList(s string) []string {
	fields := strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\n'
	})
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}

type idClaims struct {
	Iss               string   `json:"iss"`
	Sub               string   `json:"sub"`
	Aud               audClaim `json:"aud"`
	Azp               string   `json:"azp"`
	Exp               int64    `json:"exp"`
	Iat               int64    `json:"iat"`
	Nonce             string   `json:"nonce"`
	Email             string   `json:"email"`
	Name              string   `json:"name"`
	PreferredUsername string   `json:"preferred_username"`

	// Group and role claims drive pkg/authz role mappings. Several
	// spellings are read because there is no interoperable standard:
	// `groups` is the de-facto convention, Okta and Auth0 also emit
	// `roles`, and Keycloak nests roles under realm_access/resource_access.
	Groups stringListClaim `json:"groups"`
	Roles  stringListClaim `json:"roles"`

	RealmAccess struct {
		Roles stringListClaim `json:"roles"`
	} `json:"realm_access"`

	ResourceAccess map[string]struct {
		Roles stringListClaim `json:"roles"`
	} `json:"resource_access"`
}

// emailAddress is the address cloop identifies this person by: the `email`
// claim, or `preferred_username` when the provider sent no `email` but did
// send something address-shaped.
//
// The fallback exists because Microsoft Entra ID only emits `email` when the
// account has a mail attribute populated, while the address a person actually
// signs in with — their UPN — always arrives as `preferred_username`. Without
// it, an Entra deployment authenticates the administrator named in
// admin_emails and then resolves them to no role at all, because the email
// binding has nothing to match. That failure is silent from the user's side:
// sign-in succeeds and the dashboard is simply empty.
//
// It is guarded on the value looking like an address, because OIDC Core §5.1
// makes no promise that `preferred_username` is one — on some providers it is
// a bare login name, and a bare name can never match an email binding anyway.
// The guard is what keeps this from widening identity matching in general.
//
// Worth knowing when choosing bindings: OIDC Core also warns that
// `preferred_username` need not be stable or unique, so on a provider where
// users can edit their own, prefer `claim: sub` bindings. On Entra, Okta,
// Auth0 and Keycloak the value is the administrator-controlled login.
func (c *idClaims) emailAddress() string {
	if e := strings.TrimSpace(c.Email); e != "" {
		return strings.ToLower(e)
	}
	u := strings.TrimSpace(c.PreferredUsername)
	if looksLikeEmail(u) {
		return strings.ToLower(u)
	}
	return ""
}

// looksLikeEmail is a deliberately conservative shape check: exactly one "@",
// something either side of it, and a dot in the domain. It decides only
// whether a username may stand in for a missing email claim — never whether
// an address is deliverable.
func looksLikeEmail(s string) bool {
	at := strings.IndexByte(s, '@')
	if at <= 0 || at != strings.LastIndexByte(s, '@') || at == len(s)-1 {
		return false
	}
	domain := s[at+1:]
	dot := strings.IndexByte(domain, '.')
	return dot > 0 && dot < len(domain)-1 && !strings.ContainsAny(s, " \t\r\n")
}

// groupValues returns the flattened, de-duplicated group claim values.
func (c *idClaims) groupValues() []string {
	return dedupeFold(c.Groups)
}

// roleValues returns the flattened, de-duplicated role claim values across
// every spelling, including Keycloak's realm roles and the roles this
// client was granted under resource_access.
func (c *idClaims) roleValues(clientID string) []string {
	all := make([]string, 0, len(c.Roles)+len(c.RealmAccess.Roles))
	all = append(all, c.Roles...)
	all = append(all, c.RealmAccess.Roles...)
	if ra, ok := c.ResourceAccess[clientID]; ok {
		all = append(all, ra.Roles...)
	}
	return dedupeFold(all)
}

// dedupeFold removes case-insensitive duplicates and empties, preserving
// first-seen order so the list is stable across token refreshes.
func dedupeFold(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		key := strings.ToLower(strings.TrimPrefix(v, "/"))
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, v)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// verifyIDToken parses the compact JWS, verifies its signature against the
// issuer's JWKS (RS256/ES256), and validates iss/aud/azp/exp/iat/nonce.
// nonce must match the value bound to this login attempt — it ties the
// token to the browser session that initiated the flow.
//
// An empty nonce skips only the nonce binding, and exists for exactly one
// caller: the refresh-token grant (Task 20176), whose response is not the
// answer to any authorization request and therefore carries no nonce to bind
// to. Every other check still applies. The login path can never reach this
// branch by accident — BeginLogin always generates one, so p.nonce is never
// empty there — and a *present* nonce that does not match is still rejected
// below, so an IdP echoing someone else's nonce does not slip through.
func (a *Authenticator) verifyIDToken(ctx context.Context, raw, nonce string) (*Identity, error) {
	payloadJSON, err := a.verifyJWSPayload(ctx, "id_token", raw)
	if err != nil {
		return nil, err
	}

	var claims idClaims
	if err := json.Unmarshal(payloadJSON, &claims); err != nil {
		return nil, fmt.Errorf("oidcauth: id_token claims parse: %w", err)
	}
	disc, err := a.discover(ctx)
	if err != nil {
		return nil, err
	}
	if !issuerEqual(claims.Iss, disc.Issuer) {
		return nil, fmt.Errorf("oidcauth: id_token issuer %q does not match %q", claims.Iss, disc.Issuer)
	}
	if !audContains(claims.Aud, a.cfg.ClientID) {
		return nil, fmt.Errorf("oidcauth: id_token audience %v does not include client_id", []string(claims.Aud))
	}
	if len(claims.Aud) > 1 && claims.Azp != "" && claims.Azp != a.cfg.ClientID {
		return nil, fmt.Errorf("oidcauth: id_token azp %q does not match client_id", claims.Azp)
	}
	now := time.Now()
	skew := a.clockSkew()
	if claims.Exp == 0 || now.After(time.Unix(claims.Exp, 0).Add(skew)) {
		return nil, fmt.Errorf("oidcauth: id_token is expired (leeway %s)", skew)
	}
	if claims.Iat != 0 && time.Unix(claims.Iat, 0).After(now.Add(skew)) {
		return nil, fmt.Errorf("oidcauth: id_token issued in the future (leeway %s; clock skew too large?)", skew)
	}
	if nonce != "" && claims.Nonce != nonce {
		return nil, errors.New("oidcauth: id_token nonce does not match this login attempt")
	}
	if claims.Sub == "" {
		return nil, errors.New("oidcauth: id_token has no sub claim")
	}

	name := claims.Name
	if name == "" {
		name = claims.PreferredUsername
	}
	return &Identity{
		Sub:    claims.Sub,
		Email:  claims.emailAddress(),
		Name:   name,
		Groups: claims.groupValues(),
		Roles:  claims.roleValues(a.cfg.ClientID),
	}, nil
}

// verifyJWSPayload parses a compact JWS, verifies its signature against the
// issuer's JWKS, and returns the raw payload. Claim validation is the caller's
// business, because the two callers validate different things: an id_token
// carries exp/aud/nonce, while a signed userinfo response carries neither an
// expiry nor a nonce and is bound to the session by its sub instead.
//
// kind names the artefact in error messages. It is threaded through rather
// than hardcoded so an operator reading "userinfo signature invalid" is not
// sent looking at their id_token configuration.
func (a *Authenticator) verifyJWSPayload(ctx context.Context, kind, raw string) ([]byte, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("oidcauth: %s is not a compact JWS", kind)
	}
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("oidcauth: %s header decode: %w", kind, err)
	}
	var hdr struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(headerJSON, &hdr); err != nil {
		return nil, fmt.Errorf("oidcauth: %s header parse: %w", kind, err)
	}
	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("oidcauth: %s payload decode: %w", kind, err)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("oidcauth: %s signature decode: %w", kind, err)
	}

	// "none" and the HMAC family are rejected by omission: an algorithm the
	// caller does not name cannot be negotiated by the token itself, which is
	// the alg-confusion attack this switch exists to refuse.
	switch hdr.Alg {
	case "RS256", "ES256":
	default:
		return nil, fmt.Errorf("oidcauth: unsupported %s alg %q (supported: RS256, ES256)", kind, hdr.Alg)
	}
	key, err := a.signingKey(ctx, hdr.Kid)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	switch pub := key.(type) {
	case *rsa.PublicKey:
		if hdr.Alg != "RS256" {
			return nil, fmt.Errorf("oidcauth: alg %s does not match RSA signing key", hdr.Alg)
		}
		if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig); err != nil {
			return nil, fmt.Errorf("oidcauth: %s signature invalid: %w", kind, err)
		}
	case *ecdsa.PublicKey:
		if hdr.Alg != "ES256" {
			return nil, fmt.Errorf("oidcauth: alg %s does not match EC signing key", hdr.Alg)
		}
		if len(sig) != 64 {
			return nil, fmt.Errorf("oidcauth: ES256 signature must be 64 bytes, got %d", len(sig))
		}
		r := new(big.Int).SetBytes(sig[:32])
		s := new(big.Int).SetBytes(sig[32:])
		if !ecdsa.Verify(pub, digest[:], r, s) {
			return nil, fmt.Errorf("oidcauth: %s signature invalid", kind)
		}
	default:
		return nil, fmt.Errorf("oidcauth: unsupported signing key type %T", key)
	}
	return payloadJSON, nil
}

func audContains(aud audClaim, clientID string) bool {
	for _, a := range aud {
		if a == clientID {
			return true
		}
	}
	return false
}

// ── JWKS ────────────────────────────────────────────────────────────────────

type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	// RSA
	N string `json:"n"`
	E string `json:"e"`
	// EC
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

// signingKey returns the public key for kid, refreshing the cached JWKS at
// most once per jwksMinRefreshInterval when the kid is unknown (covers IdP
// key rotation without letting forged kids trigger fetch storms). A token
// with no kid matches only when the JWKS holds exactly one signing key.
func (a *Authenticator) signingKey(ctx context.Context, kid string) (any, error) {
	a.jwksMu.Lock()
	defer a.jwksMu.Unlock()

	if key, ok := a.lookupKeyLocked(kid); ok {
		return key, nil
	}
	if time.Since(a.jwksFetched) < jwksMinRefreshInterval && len(a.jwksKeys) > 0 {
		return nil, fmt.Errorf("oidcauth: no JWKS key matches kid %q", kid)
	}
	if err := a.fetchJWKSLocked(ctx); err != nil {
		return nil, err
	}
	if key, ok := a.lookupKeyLocked(kid); ok {
		return key, nil
	}
	return nil, fmt.Errorf("oidcauth: no JWKS key matches kid %q after refresh", kid)
}

func (a *Authenticator) lookupKeyLocked(kid string) (any, bool) {
	if kid != "" {
		key, ok := a.jwksKeys[kid]
		return key, ok
	}
	if len(a.jwksKeys) == 1 {
		for _, key := range a.jwksKeys {
			return key, true
		}
	}
	return nil, false
}

func (a *Authenticator) fetchJWKSLocked(ctx context.Context) error {
	disc, err := a.discover(ctx)
	if err != nil {
		return err
	}
	keys, err := fetchJWKS(ctx, a.client, a.cfg.Issuer, disc)
	if err != nil {
		a.noteIdPErr(err)
		return err
	}
	a.jwksKeys = keys
	a.jwksFetched = time.Now()
	// Reaching here means discovery *and* a usable key set both resolved,
	// which is the whole of what readiness asserts — so a hub that never ran
	// a preflight still becomes ready the moment somebody signs in.
	a.noteIdPOK()
	return nil
}

// errJWKSMalformed marks a key set that is not RFC 7517 JSON, as distinct from
// one that parses and holds nothing cloop can use. The two have different
// fixes, so the preflight reports them as different reasons.
var errJWKSMalformed = errors.New("jwks is not a JSON key set")

// parseJWKSet turns a JWK set into kid → public key, keeping only the keys
// cloop can verify with (RS256/ES256, use=sig or unset).
//
// An unusable *entry* is skipped rather than fatal — a provider publishing an
// encryption key alongside its signing key is normal, and other keys may still
// verify. An empty *result* is fatal: the provider works and this hub can
// never validate a token from it, which presents as "login worked and then
// nothing happened" and is worth failing loudly for.
func parseJWKSet(body []byte) (map[string]any, error) {
	var set struct {
		Keys []jwk `json:"keys"`
	}
	if err := json.Unmarshal(body, &set); err != nil {
		return nil, fmt.Errorf("%w: %v", errJWKSMalformed, err)
	}
	keys := make(map[string]any, len(set.Keys))
	kinds := map[string]int{}
	for i, k := range set.Keys {
		kinds[k.Kty]++
		if k.Use != "" && k.Use != "sig" {
			continue
		}
		pub, err := parseJWK(k)
		if err != nil {
			continue
		}
		kid := k.Kid
		if kid == "" {
			kid = fmt.Sprintf("_nokid_%d", i)
		}
		keys[kid] = pub
	}
	if len(keys) == 0 {
		if len(set.Keys) == 0 {
			return nil, errors.New("the key set is empty, so no ID token can be verified")
		}
		return nil, fmt.Errorf("%d key(s) published but none are usable RS256/ES256 signing keys (types: %v)",
			len(set.Keys), kinds)
	}
	return keys, nil
}

func parseJWK(k jwk) (any, error) {
	switch k.Kty {
	case "RSA":
		nb, err := base64.RawURLEncoding.DecodeString(k.N)
		if err != nil {
			return nil, fmt.Errorf("jwk n decode: %w", err)
		}
		eb, err := base64.RawURLEncoding.DecodeString(k.E)
		if err != nil {
			return nil, fmt.Errorf("jwk e decode: %w", err)
		}
		e := new(big.Int).SetBytes(eb)
		if !e.IsInt64() || e.Int64() <= 1 || e.Int64() > 1<<31 {
			return nil, fmt.Errorf("jwk RSA exponent out of range")
		}
		return &rsa.PublicKey{N: new(big.Int).SetBytes(nb), E: int(e.Int64())}, nil
	case "EC":
		if k.Crv != "P-256" {
			return nil, fmt.Errorf("unsupported EC curve %q", k.Crv)
		}
		xb, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil {
			return nil, fmt.Errorf("jwk x decode: %w", err)
		}
		yb, err := base64.RawURLEncoding.DecodeString(k.Y)
		if err != nil {
			return nil, fmt.Errorf("jwk y decode: %w", err)
		}
		pub := &ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     new(big.Int).SetBytes(xb),
			Y:     new(big.Int).SetBytes(yb),
		}
		if !pub.Curve.IsOnCurve(pub.X, pub.Y) {
			return nil, errors.New("jwk EC point is not on P-256")
		}
		return pub, nil
	default:
		return nil, fmt.Errorf("unsupported jwk kty %q", k.Kty)
	}
}
