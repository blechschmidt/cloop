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
}

// verifyIDToken parses the compact JWS, verifies its signature against the
// issuer's JWKS (RS256/ES256), and validates iss/aud/azp/exp/iat/nonce.
// nonce must match the value bound to this login attempt — it ties the
// token to the browser session that initiated the flow.
func (a *Authenticator) verifyIDToken(ctx context.Context, raw, nonce string) (*Identity, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil, errors.New("oidcauth: id_token is not a compact JWS")
	}
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("oidcauth: id_token header decode: %w", err)
	}
	var hdr struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(headerJSON, &hdr); err != nil {
		return nil, fmt.Errorf("oidcauth: id_token header parse: %w", err)
	}
	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("oidcauth: id_token payload decode: %w", err)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("oidcauth: id_token signature decode: %w", err)
	}

	switch hdr.Alg {
	case "RS256", "ES256":
	default:
		return nil, fmt.Errorf("oidcauth: unsupported id_token alg %q (supported: RS256, ES256)", hdr.Alg)
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
			return nil, fmt.Errorf("oidcauth: id_token signature invalid: %w", err)
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
			return nil, errors.New("oidcauth: id_token signature invalid")
		}
	default:
		return nil, fmt.Errorf("oidcauth: unsupported signing key type %T", key)
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
	if claims.Exp == 0 || now.After(time.Unix(claims.Exp, 0).Add(clockSkew)) {
		return nil, errors.New("oidcauth: id_token is expired")
	}
	if claims.Iat != 0 && time.Unix(claims.Iat, 0).After(now.Add(clockSkew)) {
		return nil, errors.New("oidcauth: id_token issued in the future (clock skew too large?)")
	}
	if claims.Nonce == "" || claims.Nonce != nonce {
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
		Sub:   claims.Sub,
		Email: strings.ToLower(claims.Email),
		Name:  name,
	}, nil
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
	if disc.JWKSURI == "" {
		return errors.New("oidcauth: discovery document has no jwks_uri; cannot verify id_token signatures")
	}
	body, err := a.getJSON(ctx, disc.JWKSURI)
	if err != nil {
		return fmt.Errorf("oidcauth: JWKS fetch: %w", err)
	}
	var set struct {
		Keys []jwk `json:"keys"`
	}
	if err := json.Unmarshal(body, &set); err != nil {
		return fmt.Errorf("oidcauth: JWKS parse: %w", err)
	}
	keys := make(map[string]any, len(set.Keys))
	for i, k := range set.Keys {
		if k.Use != "" && k.Use != "sig" {
			continue
		}
		pub, err := parseJWK(k)
		if err != nil {
			// Skip unusable entries (unsupported kty/crv) rather than
			// failing the whole set; other keys may still verify.
			continue
		}
		kid := k.Kid
		if kid == "" {
			kid = fmt.Sprintf("_nokid_%d", i)
		}
		keys[kid] = pub
	}
	if len(keys) == 0 {
		return errors.New("oidcauth: JWKS contained no usable RS256/ES256 signing keys")
	}
	a.jwksKeys = keys
	a.jwksFetched = time.Now()
	return nil
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
