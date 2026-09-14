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
// The network probes do not mirror pkg/oidcauth — they *are* pkg/oidcauth.
// oidcauth.Preflight is the same function the hub runs at startup and the same
// two round trips a sign-in performs before it can begin, so this report cannot
// be green about a login that will fail. That mattered enough to be worth a
// shared entry point: a doctor which merely re-implemented the same checks
// would drift the first time one side was fixed and the other was not, and the
// failure mode of that drift is a confident green line.

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/oidcauth"
)

// callbackPath is where pkg/ui mounts the OIDC callback. Repeated rather than
// imported: pkg/ui pulls in the whole dashboard, and this is a constant that
// has never changed and would be a breaking change if it did.
const callbackPath = "/auth/callback"

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
	checkPreflight(ctx, oc, opts, add)
}

// checkPreflight runs the hub's own identity preflight and reports it as two
// findings — discovery and signing keys — keeping the check ids an operator's
// CI already selects on.
//
// The resolved endpoints are printed on success because they are the answer to
// the question this command is usually run to settle: "is it talking to the
// realm I think it is?" An issuer URL that resolves to the wrong realm looks
// identical from the config file and obvious from its authorization endpoint.
func checkPreflight(ctx context.Context, oc config.OIDCConfig, opts Options, add addFn) {
	issuer := strings.TrimSpace(oc.Issuer)
	res, err := oidcauth.Preflight(ctx, issuer, oidcauth.PreflightOptions{
		Timeout: opts.timeout(),
		Client:  opts.client(),
	})

	var pe *oidcauth.PreflightError
	if err != nil && !errors.As(err, &pe) {
		// Preflight always returns a *PreflightError; this branch exists so a
		// future return path cannot produce a finding with no cause.
		add(Finding{
			Check: "oidc.discovery", Title: "Issuer discovery", Severity: SeverityFail,
			Message:     "the issuer could not be resolved: " + err.Error(),
			Remediation: "Check that this host can reach the issuer and trusts its certificate",
		})
		return
	}

	// The stages are reported separately because they fail separately and
	// have different fixes. A key set that cannot be used is not a reason to
	// stay quiet about an issuer that resolved perfectly well.
	resolved := res
	if resolved == nil && pe != nil {
		resolved = pe.Resolved
	}
	if resolved == nil {
		add(Finding{
			Check: "oidc.discovery", Title: "Issuer discovery", Severity: SeverityFail,
			Message:     preflightMessage(pe),
			Remediation: pe.Remediation(),
			Details:     preflightDetails(pe),
		})
		return
	}

	add(Finding{
		Check: "oidc.discovery", Title: "Issuer discovery", Severity: SeverityPass,
		Message: "the issuer is reachable and its document agrees on the issuer name",
		Details: map[string]any{
			"authorization_endpoint": resolved.AuthorizationEndpoint,
			"token_endpoint":         resolved.TokenEndpoint,
			"jwks_uri":               resolved.JWKSURI,
		},
	})
	if pe != nil {
		add(Finding{
			Check: "oidc.jwks", Title: "Signing keys (JWKS)", Severity: SeverityFail,
			Message:     preflightMessage(pe),
			Remediation: pe.Remediation(),
			Details:     preflightDetails(pe),
		})
		return
	}
	add(Finding{
		Check: "oidc.jwks", Title: "Signing keys (JWKS)", Severity: SeverityPass,
		Message: fmt.Sprintf("%d usable signing key(s) at %s", res.SigningKeys, res.JWKSURI),
	})
}

// preflightMessage renders the failure for an operator: what was contacted,
// what came back, and — for the two cases where the provider answered
// correctly and the hub still cannot use it — what that costs.
func preflightMessage(pe *oidcauth.PreflightError) string {
	var b strings.Builder
	if pe.URL != "" {
		b.WriteString(pe.URL + " ")
	}
	switch {
	case pe.Status != 0:
		fmt.Fprintf(&b, "returned HTTP %d", pe.Status)
	case pe.Reason == oidcauth.PreflightUnreachable:
		b.WriteString("could not be fetched")
	default:
		b.WriteString("is not usable")
	}
	if pe.Detail != "" {
		b.WriteString(": " + pe.Detail)
	}
	if pe.Reason == oidcauth.PreflightIssuerMismatch || pe.Reason == oidcauth.PreflightNoKeys {
		b.WriteString(" — every sign-in will be rejected at ID-token validation")
	}
	return b.String()
}

func preflightDetails(pe *oidcauth.PreflightError) map[string]any {
	d := map[string]any{"reason": pe.Reason}
	if pe.Status != 0 {
		d["http_status"] = pe.Status
	}
	return d
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
