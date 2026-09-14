// Claim re-assertion from the userinfo endpoint (Task 20261).
//
// Revalidation re-asserts a session's groups and roles from the id_token the
// refresh grant returns. The hole this file closes is that many providers do
// not return one: RFC 6749 does not require an id_token on a refresh, and
// Okta, Auth0 and Keycloak all omit it under common configurations. For those
// deployments the session kept whatever claims it had at sign-in, so an
// administrator removed from the admin group at the IdP stayed an administrator
// here until the absolute session TTL ran out — which on a hub configured for
// a working week is days.
//
// The userinfo endpoint is the other current statement the provider makes about
// the user, and the access token from the very same refresh response is what
// authorises reading it. So when there is no id_token, ask userinfo.
//
// # Why this is safe to act on
//
// The response is bound to the session three ways. It is fetched from the
// endpoint named by the issuer's own discovery document, over TLS; it is
// authorised by an access token the IdP minted seconds earlier for this
// session's refresh token; and its sub is compared against the session's sub by
// the caller, which ends the session outright on a mismatch rather than
// applying somebody else's groups.
//
// A signed response (application/jwt, OIDC Core 5.3.2) is signature-verified
// against the same JWKS as an id_token. An unsigned one is trusted only because
// TLS to the discovered endpoint already is — the same trust the token endpoint
// itself runs on.
//
// # Why a failure is not fatal
//
// An unreachable userinfo endpoint means claims could not be re-asserted, which
// is exactly the state this file exists to improve, not a reason to sign
// everybody out. The session survives with its previous claims and the
// authenticator records AuditSessionClaimsUnverified naming which of the two
// reasons applied, so an operator can tell "my IdP omits id_tokens" from "my
// IdP's userinfo endpoint is down".

package oidcauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"
)

// maxUserinfoBytes bounds the response. A claim bundle is a few kilobytes; the
// limit is here so a compromised or malfunctioning IdP cannot make the hub read
// an unbounded body once per session per revalidation interval.
const maxUserinfoBytes = 1 << 20 // 1 MiB

// ErrClaimsRepudiated marks a userinfo response in which the provider actively
// declined to vouch for the session — as opposed to one it simply could not
// answer (Task 20273).
//
// The distinction is the whole reason it exists. "The endpoint timed out" and
// "the endpoint said your token is not valid" arrive at the same call site and
// mean opposite things: the first is the hub's problem and must not change what
// a session may do, the second is the provider's verdict on this session's
// authorization and must.
var ErrClaimsRepudiated = errors.New("oidcauth: the identity provider refused to confirm this session's claims")

// userinfoRepudiates reports whether a non-200 userinfo response is the
// provider declining to vouch, rather than failing to answer.
//
// RFC 6750 §3.1 puts the reason in WWW-Authenticate rather than the body, so
// that is where it is read from. A bare 401 counts on its own: the header is
// recommended, not universal, and a provider that rejects a bearer token
// without explaining why has still rejected it.
//
// 403 counts only with an explicit invalid_token. A 403 alone is ambiguous in
// exactly the direction that matters — it is what a provider returns when the
// token is perfectly valid but lacks a scope, which is a deployment
// misconfiguration and must not be read as a verdict about the user. Anything
// else (404, 5xx, a gateway's HTML error page) is an endpoint that did not
// answer and is left to the unreachable path.
func userinfoRepudiates(resp *http.Response) bool {
	switch resp.StatusCode {
	case http.StatusUnauthorized:
		return true
	case http.StatusForbidden:
		return strings.Contains(strings.ToLower(resp.Header.Get("WWW-Authenticate")), "invalid_token")
	}
	return false
}

// userinfoIdentity fetches and validates the userinfo response for the session
// the access token belongs to.
//
// It returns (nil, nil) when the deployment has no userinfo endpoint to ask —
// a provider that advertises none is not an error, it simply cannot be used to
// close the gap, and the caller records the session's claims as unverified.
func (a *Authenticator) userinfoIdentity(ctx context.Context, accessToken string) (*Identity, error) {
	if strings.TrimSpace(accessToken) == "" {
		return nil, fmt.Errorf("oidcauth: userinfo needs an access token")
	}
	disc, err := a.discover(ctx)
	if err != nil {
		return nil, err
	}
	if disc.UserinfoEndpoint == "" {
		return nil, nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, disc.UserinfoEndpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("oidcauth: userinfo request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("oidcauth: userinfo fetch: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxUserinfoBytes))
	if err != nil {
		return nil, fmt.Errorf("oidcauth: userinfo read: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		err := fmt.Errorf("oidcauth: userinfo returned %s", resp.Status)
		if userinfoRepudiates(resp) {
			// The provider rejected an access token it minted seconds ago, on
			// this very session's refresh. It is still not treated as a revoked
			// grant — the refresh itself succeeded, and the competing readings
			// (a provider that does not accept this token at userinfo, one that
			// wants a scope this deployment did not request) are misconfigurations
			// rather than statements about the user, so terminating here would
			// turn a claim-freshness improvement into a fleet-wide logout bug.
			//
			// What it is no longer treated as is nothing at all. Before Task
			// 20273 this returned an undifferentiated error that the caller
			// recorded as "claims unverified" and then kept the sign-in-time
			// claims indefinitely — so the one response in which the IdP
			// explicitly declines to vouch for a session was the response that
			// changed the least. It is now reported as a repudiation:
			// ErrClaimsRepudiated marks the session's claims expired as of this
			// instant, which leaves reads working and refuses everything above
			// operator until a later read succeeds.
			return nil, fmt.Errorf("%w: %w", ErrClaimsRepudiated, err)
		}
		return nil, err
	}

	claims, err := a.decodeUserinfo(ctx, resp.Header.Get("Content-Type"), body)
	if err != nil {
		return nil, err
	}
	if claims.Sub == "" {
		// OIDC Core 5.3.2 requires sub. Without it there is nothing to bind the
		// response to a session, so it cannot be allowed to change authority.
		return nil, fmt.Errorf("oidcauth: userinfo response has no sub claim")
	}

	name := claims.Name
	if name == "" {
		name = claims.PreferredUsername
	}
	return &Identity{
		Sub:    claims.Sub,
		Email:  strings.ToLower(claims.Email),
		Name:   name,
		Groups: claims.groupValues(),
		Roles:  claims.roleValues(a.cfg.ClientID),
	}, nil
}

// decodeUserinfo parses a userinfo body, verifying the signature when the
// provider returned a signed one.
func (a *Authenticator) decodeUserinfo(ctx context.Context, contentType string, body []byte) (*idClaims, error) {
	mediaType := ""
	if contentType != "" {
		if mt, _, err := mime.ParseMediaType(contentType); err == nil {
			mediaType = strings.ToLower(mt)
		}
	}

	payload := body
	if mediaType == "application/jwt" {
		verified, err := a.verifyJWSPayload(ctx, "userinfo", strings.TrimSpace(string(body)))
		if err != nil {
			return nil, err
		}
		payload = verified

		// A signed response also carries iss, and it must be this issuer.
		// Without the check a validly-signed token from another tenant of a
		// shared IdP would be accepted on its signature alone.
		var env struct {
			Iss string `json:"iss"`
		}
		if err := json.Unmarshal(payload, &env); err == nil && env.Iss != "" {
			disc, derr := a.discover(ctx)
			if derr != nil {
				return nil, derr
			}
			if !issuerEqual(env.Iss, disc.Issuer) {
				return nil, fmt.Errorf("oidcauth: userinfo issuer %q does not match %q",
					env.Iss, disc.Issuer)
			}
		}
	}

	var claims idClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("oidcauth: userinfo claims parse: %w", err)
	}
	return &claims, nil
}
