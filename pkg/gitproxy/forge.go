package gitproxy

// forge.go gives every forge host its own route through the proxy (Task 20423).
//
// A session presents its credential to one forge host: github.com, or the
// GitHub Enterprise Server host its grant's secret names. Before this file the
// proxy served every session beneath its base — /<owner>/<name> — so the
// sandbox's rewrite of github.com and a rewrite of any other host would have
// pointed at the same URLs, and a lease holding a github.com grant and an
// enterprise grant for the same owner/name could not say which host a request
// was for. The credential helpers would pick a session by path alone, and the
// proxy would present whichever host's credential that session held.
//
// So github.com keeps the base, and every other host is served beneath
// /_forge/<host>/: the sandbox rewrites https://<host>/ to that route, and the
// proxy admits a request on a route only with a session for that route's host.
// A request whose credential is for one host, on another host's route, is
// refused before anything is forwarded: a GitHub Enterprise Server token is
// never presented to github.com, and a github.com token never leaves for an
// enterprise server.

import (
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/blechschmidt/cloop/pkg/forgehost"
)

// ForgeRouteSegment is the path segment the proxy serves a forge host other
// than github.com beneath: /_forge/<host>/<owner>/<name>. No GitHub owner can
// be named it — an owner name may not begin with an underscore — and the
// route's four segments cannot be mistaken for a repository's two.
const ForgeRouteSegment = "_forge"

// ErrWrongForge means an authenticated session addressed another forge host's
// route than the one its credential is for.
var ErrWrongForge = errors.New("gitproxy: session is for another forge host")

// ForgeRoute returns the URL beneath base that the sandbox's https://<host>/ is
// rewritten to: base itself for github.com, base/_forge/<host> for any other
// host. host is canonicalised; one that is not usable in a URL path — an IPv6
// literal — is refused.
func ForgeRoute(base, host string) (string, error) {
	b, err := NormalizeBaseURL(base)
	if err != nil {
		return "", err
	}
	path, err := forgeRoutePath(host)
	if err != nil {
		return "", err
	}
	if path == "" {
		return b, nil
	}
	return b + "/" + path, nil
}

// forgeRoutePath is ForgeRoute's path, without a leading slash: "" for
// github.com.
func forgeRoutePath(host string) (string, error) {
	c, err := canonicalForgeHost(host)
	if err != nil {
		return "", err
	}
	if c == forgehost.GitHub {
		return "", nil
	}
	return ForgeRouteSegment + "/" + c, nil
}

// canonicalForgeHost canonicalises a forge host the proxy can route: one whose
// canonical form is plain path text.
func canonicalForgeHost(host string) (string, error) {
	c, err := forgehost.Canonical(host)
	if err != nil {
		return "", fmt.Errorf("gitproxy: forge host %q: %w", host, err)
	}
	for _, r := range c {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
		case r == '.' || r == '-' || r == '_' || r == ':':
		default:
			return "", fmt.Errorf("gitproxy: forge host %q cannot be routed through the proxy", c)
		}
	}
	return c, nil
}

// splitRoutedPath splits a request path into the forge host its route names —
// "" for the base, which is github.com's — and the repository and endpoint
// splitGitPath finds beneath it.
//
// A route must name its host exactly as ForgeRoute renders it: canonical, and
// never github.com, whose route is the base. Any other spelling is not a route
// this proxy serves, rather than one it folds — a folded spelling would be a
// second URL for one session, and the credential helpers match URLs literally.
func splitRoutedPath(p string) (host, repo, endpoint string, ok bool) {
	trimmed := strings.TrimLeft(p, "/")
	rest, routed := strings.CutPrefix(trimmed, ForgeRouteSegment+"/")
	if !routed {
		repo, endpoint, ok = splitGitPath(p)
		return "", repo, endpoint, ok
	}
	h, after, found := strings.Cut(rest, "/")
	if !found || h == "" {
		return "", "", "", false
	}
	c, err := canonicalForgeHost(h)
	if err != nil || c != h || c == forgehost.GitHub {
		return "", "", "", false
	}
	repo, endpoint, ok = splitGitPath("/" + after)
	if !ok {
		return "", "", "", false
	}
	return c, repo, endpoint, true
}

// routedRepoPath is the repository a request path addresses, beneath whichever
// route it is on.
func routedRepoPath(p string) (string, bool) {
	_, repo, _, ok := splitRoutedPath(p)
	return repo, ok
}

// forgeMismatch reports why sess may not be served on the route for host —
// "" for the base — or "".
//
// A route that names a host admits only a session for that host. The base
// admits a pinned session for any host, because a pinned session's own URL is
// the base and its repository (Minted.RepoURL) and it forwards to nothing but
// the one repository it was minted for; and it admits a scoped session only
// for github.com, the host the base's rewrite is of.
func forgeMismatch(sess *Session, host string) string {
	if sess == nil {
		return "no session"
	}
	if host != "" {
		if sess.ForgeHost != host {
			return fmt.Sprintf("session's credential is for %s, not %s", sess.ForgeHost, host)
		}
		return ""
	}
	if sess.Scoped() && sess.ForgeHost != forgehost.GitHub {
		return fmt.Sprintf("session's credential is for %s, and this is the route for %s",
			sess.ForgeHost, forgehost.GitHub)
	}
	return ""
}

// sessionForgeHost settles the forge host a session is minted or restored for:
// the one the caller named, or — for a request that names none, as every
// request did before hosts were recorded — github.com for a scoped session and
// the upstream's own host for a pinned one. A pinned session's upstream, and a
// scoped one's for any host but github.com, must be on that host: the session
// presents its credential nowhere else. (A scoped github.com session's
// upstream is the hub's to choose; a test puts its own forge there.)
func sessionForgeHost(named, upstream string, scoped bool) (string, error) {
	named = strings.TrimSpace(named)
	if named == "" {
		if scoped {
			named = forgehost.GitHub
		} else {
			named = upstream
		}
	}
	host, err := forgehost.Canonical(named)
	if err != nil {
		return "", fmt.Errorf("gitproxy: forge host %q: %w", named, err)
	}
	if scoped && host == forgehost.GitHub {
		return host, nil
	}
	if scoped {
		// Served beneath a route of its own, so it must be one.
		if _, err := canonicalForgeHost(host); err != nil {
			return "", err
		}
	}
	u, err := url.Parse(strings.TrimSpace(upstream))
	if err != nil {
		return "", fmt.Errorf("gitproxy: upstream %q is not a URL: %w", upstream, err)
	}
	if err := forgehost.Check(u.Host, host); err != nil {
		return "", fmt.Errorf("gitproxy: upstream %s is not on %s, the host the session's credential is for: %w",
			upstream, host, err)
	}
	return host, nil
}
