package hubdoctor

// Identity checks: is single sign-on configured, and would a login actually
// complete?
//
// Every one of these fails at the same moment — the first time a user tries to
// sign in, which on a fresh deployment is usually the operator demonstrating it
// to somebody else. They are also the checks with the least informative native
// failure: a redirect_uri the IdP does not recognise produces an error page
// rendered by the IdP, in the IdP's words, about a value the IdP was never
// shown. So this file re-derives, from the hub's side, everything the login
// depends on and says which value is wrong.
//
// The probes mirror pkg/oidcauth exactly rather than approximating it: the same
// well-known path, the same trailing-slash-tolerant issuer comparison, the same
// JWKS URI taken from the document rather than guessed. A doctor that checks a
// *different* thing than the code does is worse than no doctor, because it
// produces confident green lines for a login that will fail.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/blechschmidt/cloop/pkg/config"
)

// maxDiscoveryBody bounds what a probe reads from an issuer. Discovery
// documents and JWKS are a few kilobytes; a megabyte cap means a hostile or
// misrouted endpoint cannot exhaust a CLI that is trying to diagnose it.
const maxDiscoveryBody = 1 << 20

// callbackPath is where pkg/ui mounts the OIDC callback. Repeated rather than
// imported: pkg/ui pulls in the whole dashboard, and this is a constant that
// has never changed and would be a breaking change if it did.
const callbackPath = "/auth/callback"

// discoveryDoc is the subset of the OpenID Provider metadata cloop uses. It
// mirrors pkg/oidcauth's unexported type.
type discoveryDoc struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
	EndSessionEndpoint    string `json:"end_session_endpoint"`
}

func checkOIDC(ctx context.Context, cfg *config.Config, opts Options, add addFn) {
	oc := cfg.UI.OIDC

	if !oc.Enabled {
		// Not a failure on its own — a hub can legitimately be a
		// single-operator deployment behind a token. It becomes one the
		// moment the deployment looks hosted, which is what external_url
		// says: something other than this machine is meant to reach it.
		sev, remediation := SeverityPass, ""
		msg := "single sign-on is off; access is by the static UI token"
		if strings.TrimSpace(cfg.UI.ExternalURL) != "" {
			sev = SeverityWarn
			msg = "single sign-on is off, but ui.external_url is set — this hub is reachable " +
				"by more than one person and authenticates them all as the same token holder"
			remediation = "Configure ui.oidc (see `cloop hub bootstrap --oidc-issuer …`), or unset ui.external_url"
		}
		add(Finding{
			Check: "oidc.enabled", Title: "Single sign-on", Severity: sev,
			Message: msg, Remediation: remediation,
		})
		return
	}

	add(Finding{
		Check: "oidc.enabled", Title: "Single sign-on", Severity: SeverityPass,
		Message: fmt.Sprintf("enabled for issuer %s", strings.TrimSpace(oc.Issuer)),
	})

	checkOIDCClientCredentials(oc, add)
	checkRedirectURI(cfg, add)

	if opts.Offline {
		add(Finding{
			Check: "oidc.discovery", Title: "Issuer discovery", Severity: SeverityWarn,
			Message:     "skipped: --offline was passed, so the issuer was not contacted",
			Remediation: "Re-run without --offline from a host that can reach the issuer",
		})
		return
	}
	doc := checkDiscovery(ctx, oc, opts, add)
	if doc != nil {
		checkJWKS(ctx, *doc, opts, add)
	}
}

// checkOIDCClientCredentials verifies the hub can authenticate itself to the
// IdP, and objects to the secret living in a file.
//
// The env-var preference is not stylistic. .cloop/config.yaml is committed in
// every deployment topology cloop documents — it is a ConfigMap in the Helm
// chart and a read-only bind mount in the compose stack — and a client secret
// in it is a client secret in git.
func checkOIDCClientCredentials(oc config.OIDCConfig, add addFn) {
	if strings.TrimSpace(oc.ClientID) == "" {
		add(Finding{
			Check: "oidc.client_id", Title: "OIDC client id", Severity: SeverityFail,
			Message:     "ui.oidc.client_id is empty, so the hub cannot identify itself to the issuer",
			Remediation: "Set ui.oidc.client_id to the client you registered at the identity provider",
		})
	}

	// The environment is checked first because Load has already copied an
	// env-supplied secret into oc.ClientSecret: by the time this runs, the two
	// sources are indistinguishable from the struct alone, and the env is the
	// one that wins.
	inConfig := strings.TrimSpace(oc.ClientSecret) != ""
	inEnv := strings.TrimSpace(os.Getenv(config.EnvOIDCClientSecret)) != ""
	switch {
	case inEnv:
		add(Finding{
			Check: "oidc.client_secret", Title: "OIDC client secret", Severity: SeverityPass,
			Message: "supplied via " + config.EnvOIDCClientSecret + ", not from the config file",
		})
	case !inConfig:
		add(Finding{
			Check: "oidc.client_secret", Title: "OIDC client secret", Severity: SeverityFail,
			Message: "no client secret: neither ui.oidc.client_secret nor " +
				config.EnvOIDCClientSecret + " is set, so the code exchange will be rejected",
			Remediation: "Export " + config.EnvOIDCClientSecret + " (it is written to .cloop/hub.env by `cloop hub bootstrap`)",
		})
	default:
		add(Finding{
			Check: "oidc.client_secret", Title: "OIDC client secret", Severity: SeverityWarn,
			Message: "the client secret is stored in .cloop/config.yaml, which is committed " +
				"in every deployment topology cloop documents",
			Remediation: "Move it to the " + config.EnvOIDCClientSecret + " environment variable and delete the config field",
		})
	}
}

// checkRedirectURI is the mismatch check.
//
// The redirect URI has to be identical in three places — the hub's config, the
// client registration at the IdP, and the URL the browser is actually on — and
// the hub only knows two of them. What it can prove is the half that is its own
// fault: that the redirect it will send matches the external URL it claims to
// be served at, and that it points at the path the router actually mounts.
func checkRedirectURI(cfg *config.Config, add addFn) {
	raw := strings.TrimSpace(cfg.UI.OIDC.RedirectURL)
	if raw == "" {
		add(Finding{
			Check: "oidc.redirect_uri", Title: "Redirect URI", Severity: SeverityFail,
			Message:     "ui.oidc.redirect_url is empty; the hub refuses to start with OIDC enabled and no redirect",
			Remediation: "Set ui.oidc.redirect_url to " + joinURL(cfg.UI.ExternalURL, callbackPath),
		})
		return
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || !u.IsAbs() {
		add(Finding{
			Check: "oidc.redirect_uri", Title: "Redirect URI", Severity: SeverityFail,
			Message:     fmt.Sprintf("ui.oidc.redirect_url %q is not an absolute URL", raw),
			Remediation: "Set it to the full URL a browser lands on, e.g. " + joinURL(cfg.UI.ExternalURL, callbackPath),
		})
		return
	}

	if u.Path != callbackPath {
		add(Finding{
			Check: "oidc.redirect_uri", Title: "Redirect URI path", Severity: SeverityFail,
			Message: fmt.Sprintf("ui.oidc.redirect_url points at %q, but the hub only serves the callback at %s",
				u.Path, callbackPath),
			Remediation: "Change the path to " + callbackPath + " here and in the client registration at the issuer",
		})
	}

	ext := strings.TrimSpace(cfg.UI.ExternalURL)
	if ext == "" {
		add(Finding{
			Check: "oidc.external_url", Title: "External URL", Severity: SeverityWarn,
			Message: "ui.external_url is unset, so the redirect URI could not be cross-checked " +
				"and enrollment bundles will carry no server address",
			Remediation: "Set ui.external_url to " + originOf(u),
		})
		return
	}
	e, err := url.Parse(ext)
	if err != nil || e.Host == "" {
		add(Finding{
			Check: "oidc.external_url", Title: "External URL", Severity: SeverityFail,
			Message:     fmt.Sprintf("ui.external_url %q is not a URL", ext),
			Remediation: "Set it to the scheme and host a browser types, e.g. https://cloop.example.com",
		})
		return
	}

	if !strings.EqualFold(e.Scheme, u.Scheme) || !strings.EqualFold(e.Host, u.Host) {
		add(Finding{
			Check: "oidc.redirect_uri", Title: "Redirect URI origin", Severity: SeverityFail,
			Message: fmt.Sprintf("redirect origin %s does not match ui.external_url %s; "+
				"the issuer will redirect the browser away from this hub",
				originOf(u), originOf(e)),
			Remediation: "Set ui.oidc.redirect_url to " + joinURL(ext, callbackPath),
		})
		return
	}

	if !strings.EqualFold(u.Scheme, "https") && !isLoopbackHost(u.Hostname()) {
		add(Finding{
			Check: "oidc.redirect_uri", Title: "Redirect URI scheme", Severity: SeverityFail,
			Message: "the redirect URI is http:// to a non-loopback host, so the authorization " +
				"code crosses the network in the clear",
			Remediation: "Terminate TLS (a proxy or ui.tls) and change both URLs to https://",
		})
		return
	}

	add(Finding{
		Check: "oidc.redirect_uri", Title: "Redirect URI", Severity: SeverityPass,
		Message: raw + " matches ui.external_url and the served callback path",
	})
}

// checkDiscovery fetches the well-known document and validates the one property
// the OIDC spec makes load-bearing: that the document's own issuer equals the
// configured one. Returns the document so the JWKS check can use its jwks_uri
// rather than guessing a path.
func checkDiscovery(ctx context.Context, oc config.OIDCConfig, opts Options, add addFn) *discoveryDoc {
	issuer := strings.TrimSpace(oc.Issuer)
	if issuer == "" {
		add(Finding{
			Check: "oidc.discovery", Title: "Issuer discovery", Severity: SeverityFail,
			Message:     "ui.oidc.issuer is empty",
			Remediation: "Set ui.oidc.issuer to the identity provider's issuer URL",
		})
		return nil
	}
	wellKnown := strings.TrimSuffix(issuer, "/") + "/.well-known/openid-configuration"

	body, err := getJSON(ctx, opts, wellKnown)
	if err != nil {
		add(Finding{
			Check: "oidc.discovery", Title: "Issuer discovery", Severity: SeverityFail,
			Message:     fmt.Sprintf("%s could not be fetched: %v", wellKnown, err),
			Remediation: "Check that this host can reach the issuer and trusts its certificate (SSL_CERT_DIR adds a private CA)",
		})
		return nil
	}
	var doc discoveryDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		add(Finding{
			Check: "oidc.discovery", Title: "Issuer discovery", Severity: SeverityFail,
			Message:     fmt.Sprintf("%s did not return a JSON discovery document: %v", wellKnown, err),
			Remediation: "Confirm ui.oidc.issuer names the issuer itself, not a login page in front of it",
		})
		return nil
	}
	if doc.AuthorizationEndpoint == "" || doc.TokenEndpoint == "" {
		add(Finding{
			Check: "oidc.discovery", Title: "Issuer discovery", Severity: SeverityFail,
			Message:     "the discovery document has no authorization_endpoint or token_endpoint",
			Remediation: "Confirm ui.oidc.issuer names an OpenID Connect provider",
		})
		return nil
	}
	// The spec requires this equality, and cloop enforces it at login. A hub
	// whose issuer resolves but disagrees about its own name fails every
	// sign-in with an error that names neither value.
	if !issuerEqual(doc.Issuer, issuer) {
		add(Finding{
			Check: "oidc.discovery", Title: "Issuer discovery", Severity: SeverityFail,
			Message: fmt.Sprintf("the provider calls itself %q but ui.oidc.issuer is %q; "+
				"every sign-in will be rejected at ID-token validation", doc.Issuer, issuer),
			Remediation: "Set ui.oidc.issuer to " + doc.Issuer,
		})
		return &doc
	}

	add(Finding{
		Check: "oidc.discovery", Title: "Issuer discovery", Severity: SeverityPass,
		Message: "the issuer is reachable and its document agrees on the issuer name",
		Details: map[string]any{
			"authorization_endpoint": doc.AuthorizationEndpoint,
			"token_endpoint":         doc.TokenEndpoint,
		},
	})
	return &doc
}

// checkJWKS fetches the signing keys. Without at least one usable key every ID
// token is rejected as unverifiable, which presents as "login worked and then
// nothing happened".
func checkJWKS(ctx context.Context, doc discoveryDoc, opts Options, add addFn) {
	if strings.TrimSpace(doc.JWKSURI) == "" {
		add(Finding{
			Check: "oidc.jwks", Title: "Signing keys (JWKS)", Severity: SeverityFail,
			Message:     "the discovery document advertises no jwks_uri, so ID tokens cannot be verified",
			Remediation: "Confirm ui.oidc.issuer names an OpenID Connect provider, not a bare OAuth 2 server",
		})
		return
	}
	body, err := getJSON(ctx, opts, doc.JWKSURI)
	if err != nil {
		add(Finding{
			Check: "oidc.jwks", Title: "Signing keys (JWKS)", Severity: SeverityFail,
			Message:     fmt.Sprintf("%s could not be fetched: %v", doc.JWKSURI, err),
			Remediation: "Check network reachability and certificate trust from this host to the issuer",
		})
		return
	}
	var set struct {
		Keys []struct {
			Kid string `json:"kid"`
			Kty string `json:"kty"`
			Alg string `json:"alg"`
			Use string `json:"use"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(body, &set); err != nil {
		add(Finding{
			Check: "oidc.jwks", Title: "Signing keys (JWKS)", Severity: SeverityFail,
			Message:     fmt.Sprintf("%s did not return a JWK set: %v", doc.JWKSURI, err),
			Remediation: "Confirm jwks_uri serves RFC 7517 JSON",
		})
		return
	}

	// cloop verifies RS256 and ES256, so RSA and EC are the key types that
	// matter. A set of only unsupported types is a working IdP and a hub that
	// can never validate a token from it.
	usable, kinds := 0, map[string]int{}
	for _, k := range set.Keys {
		kinds[k.Kty]++
		if k.Use != "" && k.Use != "sig" {
			continue
		}
		if k.Kty == "RSA" || k.Kty == "EC" {
			usable++
		}
	}
	switch {
	case len(set.Keys) == 0:
		add(Finding{
			Check: "oidc.jwks", Title: "Signing keys (JWKS)", Severity: SeverityFail,
			Message:     doc.JWKSURI + " returned an empty key set, so no ID token can be verified",
			Remediation: "Check the identity provider's signing key configuration",
		})
	case usable == 0:
		add(Finding{
			Check: "oidc.jwks", Title: "Signing keys (JWKS)", Severity: SeverityFail,
			Message: fmt.Sprintf("%d key(s) published but none are RSA or EC signing keys; "+
				"cloop verifies RS256 and ES256 only", len(set.Keys)),
			Remediation: "Configure the issuer to sign ID tokens with RS256 or ES256",
			Details:     map[string]any{"key_types": kinds},
		})
	default:
		add(Finding{
			Check: "oidc.jwks", Title: "Signing keys (JWKS)", Severity: SeverityPass,
			Message: fmt.Sprintf("%d usable signing key(s) at %s", usable, doc.JWKSURI),
		})
	}
}

// getJSON performs one bounded GET and returns the body.
func getJSON(ctx context.Context, opts Options, rawURL string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, opts.timeout())
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := opts.client().Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxDiscoveryBody))
		_ = resp.Body.Close()
	}()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("HTTP %s", resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, maxDiscoveryBody))
}

// issuerEqual compares issuer URLs tolerating a trailing slash, matching
// pkg/oidcauth so the doctor accepts exactly what a login accepts.
func issuerEqual(a, b string) bool {
	return strings.TrimSuffix(a, "/") == strings.TrimSuffix(b, "/")
}

func originOf(u *url.URL) string { return u.Scheme + "://" + u.Host }

func joinURL(base, path string) string {
	base = strings.TrimSpace(base)
	if base == "" {
		return "https://<your-host>" + path
	}
	return strings.TrimRight(base, "/") + path
}

func isLoopbackHost(host string) bool {
	switch strings.ToLower(host) {
	case "localhost", "127.0.0.1", "::1":
		return true
	}
	return false
}
