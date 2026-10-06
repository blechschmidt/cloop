package hubdoctor

// Identity checks: is single sign-on configured, and would a login actually
// complete?
//
// Every one of these fails at the same moment — the first time a user tries to
// sign in, which on a fresh deployment is usually the operator demonstrating it
// to somebody else. They are also the checks with the least informative native
// failure: a redirect_uri the IdP does not recognise produces an error page
// rendered by the IdP, in the IdP's words, about a value the IdP was never
// shown. So this file checks, from the hub's side, everything the login
// depends on and says which value is wrong.
//
// The checks do not mirror pkg/oidcauth — they *are* pkg/oidcauth. Whether the
// hub would start is oidcauth.New's answer, asked of the builder `cloop ui`
// builds its authenticator from; the redirect path is oidcauth.ValidateRedirectURL,
// the rule New applies and CallbackPath serves; and the network probes are
// oidcauth.Preflight, the same function the hub runs at startup and the same
// two round trips a sign-in performs before it can begin. A doctor which
// merely re-implemented those rules drifts the first time one side is fixed
// and the other is not, and the failure mode of that drift is a confident
// verdict in either direction. This one had it: it required the callback to be
// /auth/callback when the hub serves any path under /auth/, and failed a
// working hub registered at /auth/oidc — telling its operator to change an IdP
// registration that was correct (Task 20387).

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/oidcauth"
	"github.com/blechschmidt/cloop/pkg/tlsconf"
)

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

	checkOIDCStartup(oc, add)
	checkOIDCClientSecret(oc, add)
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

// checkOIDCStartup reports whether `cloop ui` would start with this ui.oidc
// block, by asking the constructor startup runs — oidcauth.New, on the builder
// startup uses — rather than re-deriving its rules. Startup treats a refusal
// as fatal, so this is the verdict most expensive to get wrong either way: a
// pass here over a block New refuses is a hub that does not come back from its
// next restart.
//
// New stops at its first refusal, which once let a bad issuer hide an empty
// client id. Each refusal names its setting (oidcauth.ConfigError), so it is
// set aside with a value New accepts and New is asked again, until it has
// nothing more to refuse. The redirect URL is set aside up front: it is
// checkRedirectURI's to report, with the remediation it has always had. The
// client id is reported under oidc.client_id, the id it always had.
func checkOIDCStartup(oc config.OIDCConfig, add addFn) {
	probe := oc.AuthConfig()
	var setAside []string
	if _, err := oidcauth.ValidateRedirectURL(probe.RedirectURL); err != nil {
		standIn(&probe, "redirect_url")
		setAside = append(setAside, "the redirect URL")
	}
	var refused []string
	for attempt := 0; attempt < 8; attempt++ {
		_, err := oidcauth.New(probe)
		if err == nil {
			break
		}
		var ce *oidcauth.ConfigError
		if !errors.As(err, &ce) || !standIn(&probe, ce.Field) {
			refused = append(refused, err.Error())
			break
		}
		if ce.Field == "client_id" {
			add(Finding{
				Check: "oidc.client_id", Title: "OIDC client id", Severity: SeverityFail,
				Message:     "the hub will not start: " + ce.Error(),
				Remediation: "Set ui.oidc.client_id to the client you registered at the identity provider",
			})
			setAside = append(setAside, "the client id")
			continue
		}
		refused = append(refused, ce.Error())
	}
	if len(refused) > 0 {
		add(Finding{
			Check: "oidc.startup", Title: "Single sign-on settings", Severity: SeverityFail,
			Message: "the hub will not start: " + strings.Join(refused, "; "),
			Remediation: "Correct the ui.oidc settings named, in .cloop/config.yaml or this hub's " +
				"per-port overlay; `cloop ui` exits at startup until they are fixed",
		})
		return
	}
	subject := "ui.oidc"
	if len(setAside) > 0 {
		subject = "the rest of ui.oidc (" + strings.Join(setAside, " and ") + " reported on its own)"
	}
	add(Finding{
		Check: "oidc.startup", Title: "Single sign-on settings", Severity: SeverityPass,
		Message: "oidcauth.New, which `cloop ui` runs at startup, accepts " + subject,
	})
}

// standIn replaces the setting a refusal names with a value oidcauth.New
// accepts, so the refusal behind it can surface. False for a setting it has
// no stand-in for, which ends the search.
func standIn(c *oidcauth.Config, field string) bool {
	switch field {
	case "issuer":
		c.Issuer = "https://issuer.invalid"
	case "client_id":
		c.ClientID = "cloop-hub-doctor"
	case "redirect_url":
		c.RedirectURL = "https://cloop.invalid" + oidcauth.DefaultCallbackPath
	case "cookie_secure":
		c.CookieSecure = ""
	case "max_claim_age":
		c.MaxClaimAge = 0 // the default
	case "clock_skew":
		c.ClockSkew = 0 // the default
	default:
		return false
	}
	return true
}

// checkOIDCClientSecret objects to the client secret living in a file.
//
// The env-var preference is not stylistic. .cloop/config.yaml is committed in
// every deployment topology cloop documents — it is a ConfigMap in the Helm
// chart and a read-only bind mount in the compose stack — and a client secret
// in it is a client secret in git.
//
// The client id has no check of its own here: an empty one is a startup
// refusal, and checkOIDCStartup reports it in oidcauth.New's words.
func checkOIDCClientSecret(oc config.OIDCConfig, add addFn) {
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
		// Pass, not fail. An absent secret is the public-client configuration
		// — the one the Terraform module provisions by default — where the
		// PKCE S256 binding authenticates the code exchange on its own. This
		// used to report a hub that works as one that cannot sign anyone in.
		//
		// It stays a distinct message rather than silence because the failure
		// it can still describe is a real one: a *confidential* registration
		// whose secret was never exported looks exactly like this from here,
		// and the only place the difference is visible is the IdP.
		add(Finding{
			Check: "oidc.client_secret", Title: "OIDC client secret", Severity: SeverityPass,
			Message: "no client secret, so the hub authenticates the code exchange with PKCE (S256) " +
				"as a public client; if this client is registered as confidential at the issuer, " +
				"export " + config.EnvOIDCClientSecret + " instead",
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
// fault: that it will serve the path the issuer sends the browser back to, and
// that the redirect it sends matches the external URL it claims to be served
// at.
//
// The first half is oidcauth.ValidateRedirectURL, not a restatement of it.
// The IdP decides the path — /auth/callback is only the hub's default, and an
// Entra SPA registration is commonly /auth/oidc — and the hub serves whatever
// path that rule admits. So the only path finding is the hub's own refusal,
// which means it will not start. The value is checked untrimmed, as New
// receives it.
func checkRedirectURI(cfg *config.Config, add addFn) {
	raw := cfg.UI.OIDC.RedirectURL
	ext := strings.TrimSpace(cfg.UI.ExternalURL)

	u, err := oidcauth.ValidateRedirectURL(raw)
	if err != nil {
		add(Finding{
			Check: "oidc.redirect_uri", Title: "Redirect URI", Severity: SeverityFail,
			Message: "the hub will not start: " + err.Error(),
			Remediation: "Set ui.oidc.redirect_url to " + redirectFor(ext, raw, oidcauth.DefaultCallbackPath) +
				" (any path under /auth/ the hub can route will do), and register the same URI " +
				"for the client at the issuer",
		})
		return
	}

	// Past here the hub starts and serves u.Path. Everything below is about
	// whether a browser can complete a sign-in through it, and each fix keeps
	// the path the operator registered: the issuer already holds it, so
	// changing it would trade one mismatch for another.
	if !u.IsAbs() || u.Host == "" {
		add(Finding{
			Check: "oidc.redirect_uri", Title: "Redirect URI", Severity: SeverityFail,
			Message: fmt.Sprintf("ui.oidc.redirect_url %q is not an absolute URL; the hub starts, but "+
				"OAuth 2.0 requires an absolute redirect_uri and no client registration matches this one, "+
				"so every sign-in stops at the issuer", raw),
			Remediation: "Set it to the full URL a browser lands on, " + redirectFor(ext, "", u.Path) +
				", and register the same URI at the issuer",
		})
		return
	}

	if !strings.EqualFold(u.Scheme, "https") && !tlsconf.IsLoopbackHost(u.Hostname()) {
		add(Finding{
			Check: "oidc.redirect_uri", Title: "Redirect URI scheme", Severity: SeverityFail,
			Message: "the redirect URI is http:// to a non-loopback host, so the authorization " +
				"code crosses the network in the clear",
			Remediation: "Terminate TLS (a proxy or ui.tls) and change both URLs to https://",
		})
		return
	}

	// The cross-check against ui.external_url. Without a usable external URL
	// the path is still verified — it is the hub's own rule — so the redirect
	// passes on what was checked and says what was not.
	var e *url.URL
	if ext != "" {
		e, err = url.Parse(ext)
		if err != nil || e.Host == "" {
			add(Finding{
				Check: "oidc.external_url", Title: "External URL", Severity: SeverityFail,
				Message:     fmt.Sprintf("ui.external_url %q is not a URL", ext),
				Remediation: "Set it to the scheme and host a browser types, e.g. " + originOf(u),
			})
			e = nil
		}
	} else {
		add(Finding{
			Check: "oidc.external_url", Title: "External URL", Severity: SeverityWarn,
			Message: "ui.external_url is unset, so the redirect URI could not be cross-checked " +
				"and enrollment bundles will carry no server address",
			Remediation: "Set ui.external_url to " + originOf(u),
		})
	}
	if e == nil {
		add(Finding{
			Check: "oidc.redirect_uri", Title: "Redirect URI", Severity: SeverityPass,
			Message: fmt.Sprintf("the hub serves its callback at %s; with no usable ui.external_url, "+
				"the origin %s was not cross-checked", u.Path, originOf(u)),
		})
		return
	}

	if !strings.EqualFold(e.Scheme, u.Scheme) || !strings.EqualFold(e.Host, u.Host) {
		add(Finding{
			Check: "oidc.redirect_uri", Title: "Redirect URI origin", Severity: SeverityFail,
			Message: fmt.Sprintf("redirect origin %s does not match ui.external_url %s; "+
				"the issuer will redirect the browser away from this hub",
				originOf(u), originOf(e)),
			Remediation: "Set ui.oidc.redirect_url to " + redirectFor(ext, "", u.Path) +
				", and register the same URI for the client at the issuer",
		})
		return
	}

	add(Finding{
		Check: "oidc.redirect_uri", Title: "Redirect URI", Severity: SeverityPass,
		Message: fmt.Sprintf("%s matches ui.external_url, and the hub serves its callback at %s", raw, u.Path),
	})
}

func originOf(u *url.URL) string { return u.Scheme + "://" + u.Host }

// redirectFor proposes a redirect URL ending in path: the origin of
// ui.external_url when that parses, else the origin of the configured
// redirect, else a placeholder.
//
// The origin and not the whole external URL, because the hub serves its
// callback at the root of its own path space: a prefix carried over from
// external_url would put the suggestion outside /auth/, which is advice the
// hub would then refuse to start on.
func redirectFor(external, redirect, path string) string {
	for _, raw := range []string{external, redirect} {
		if u, err := url.Parse(strings.TrimSpace(raw)); err == nil && u.Scheme != "" && u.Host != "" {
			return originOf(u) + path
		}
	}
	return "https://<your-host>" + path
}
