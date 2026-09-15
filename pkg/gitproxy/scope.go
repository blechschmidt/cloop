package gitproxy

// scope.go widens a session from one repository to a set of them.
//
// # Why a session ever needs more than one repository
//
// The original session model pins exactly one repository, because it was built
// for workspace write-back: the hub knows which repository the task is working
// in before it dispatches, so it can name it at mint time. That is the whole
// story for a project's own clone.
//
// It is not the story for a *user's* GitHub PAT. A developer stores one token
// and grants it to a project with an allowlist like "acme/*", and neither they
// nor the hub can enumerate what that matches — the set lives on GitHub and
// changes without telling anyone. Pinning would mean either minting a session
// per repository the hub cannot know about, or refusing the grant. So a scoped
// session carries the allowlist itself and matches per request.
//
// # What this does and does not relax
//
// The credential still never reaches the sandbox, and it is still only ever
// presented to the host the *session* names — a scoped session's Upstream is a
// forge host base, not something a request supplies. What the request supplies
// is the repository path, and it is honoured only after AllowsRepo admits it
// against the allowlist fixed at mint time.
//
// So the authority a scoped session confers is "the allowlist, through this
// proxy, under this ref policy, until the TTL expires", against a broad PAT's
// "every repository the token can reach, anywhere, forever". That narrowing is
// the point: it is enforced on the network path rather than by a credential
// helper running inside the sandbox it is meant to constrain.

import (
	"errors"
	"fmt"
	"net/url"
	"path"
	"strings"
)

// MaxRepoPatterns bounds the allowlist a single session may carry.
//
// Every pattern is tested on every request, so an unbounded list is a way to
// make each git operation arbitrarily expensive. The limit is far above any
// real grant — an allowlist is a handful of globs, not an inventory.
const MaxRepoPatterns = 64

// NormalizeRepoPath renders an owner/name path in the form the matcher and the
// audit trail both use: no leading or trailing slash, no ".git" suffix, and
// lowercased, because GitHub treats repository paths case-insensitively and a
// matcher that did not would let "Acme/Tool" slip past an "acme/*" allowlist.
//
// Normalisation only. It does not decide whether the result is usable — that is
// validRepoSegment's job, and the two are separate because the audit trail
// wants to record what was asked for even when the answer is no.
func NormalizeRepoPath(p string) string {
	s := strings.Trim(strings.TrimSpace(p), "/")
	s = strings.TrimSuffix(s, ".git")
	return strings.ToLower(s)
}

// validRepoSegment reports whether one path component is a repository name this
// proxy will forward.
//
// The charset is the load-bearing part of the allowlist, not decoration.
// AllowsRepo matches a *string*, and the URL that string ends up in is parsed
// again on the way to the forge — so any character that survives matching and
// then changes meaning during that second parse makes the approved path and the
// forwarded path two different things.
//
// The concrete escape this closes: "%252F" arrives as the literal text "%2F",
// which contains no separator, so it passes the one-slash check and matches
// "acme/*" — and is then decoded back into "/" by the forge, reaching a
// repository the allowlist denies with the PAT attached. "%3F" and "%23" do the
// same trick with "?" and "#", truncating the path at the second parse so the
// forge sees a prefix of what was matched.
//
// Restricting to what a forge actually permits in a repository name makes the
// matched string and the forwarded string necessarily identical. It mirrors
// secretbroker.validRepoSegment, which already applies this on the grant side;
// the two must agree or a grant could name something this refuses.
func validRepoSegment(s string) bool {
	// Bounds and the ".." rule are copied from secretbroker.validRepoSegment
	// rather than approximated: a grant may name only what that accepts, so a
	// segment this refused but that one allowed would be a repository an
	// operator could grant and the proxy would never serve.
	if s == "" || len(s) > 100 || s == "." || strings.Contains(s, "..") {
		return false
	}
	// A name that *still* ends in ".git" after normalisation is refused, and
	// this is a second instance of the same bug class as the charset above:
	// ".git" is stripped in three places — splitGitPath, NormalizeRepoPath, and
	// again where the upstream URL is assembled — but approval happens after
	// the second. So "tool.git.git.git" arrives, is approved as "acme/tool.git",
	// and is forwarded as "acme/tool": an allowlist of "acme/tool.*" admits the
	// first and denies the second, and the sandbox reads a repository it was
	// refused.
	//
	// The general defect is that NormalizeRepoPath is not idempotent, and the
	// check/forward seam depends on it being so. Refusing the fixed point's
	// input restores that: after this, normalising twice cannot differ from
	// normalising once. GitHub does not permit a repository named "x.git"
	// anyway, so nothing real is lost.
	if strings.HasSuffix(strings.ToLower(s), ".git") {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '.' || r == '_' || r == '-':
		default:
			return false
		}
	}
	return true
}

// validRepoPath reports whether a normalised path is exactly two forwardable
// segments. This is the single gate AllowsRepo and upstreamFor share.
func validRepoPath(p string) bool {
	owner, name, found := strings.Cut(p, "/")
	if !found || strings.Contains(name, "/") {
		return false
	}
	return validRepoSegment(owner) && validRepoSegment(name)
}

// ValidateRepoPattern checks one owner/name glob.
//
// The shape requirement — exactly one slash, or the bare "*" wildcards — is
// what keeps path.Match's semantics predictable here: "*" does not cross a
// separator, so "acme/*" matches acme/tool and not acme/group/tool. A pattern
// with a different shape could only ever match paths this proxy rejects
// anyway, so it is a mistake worth reporting at mint time rather than a
// silently dead entry in an allowlist someone is relying on.
func ValidateRepoPattern(pattern string) error {
	p := NormalizeRepoPath(pattern)
	if p == "" {
		return errors.New("gitproxy: repository pattern is empty")
	}
	if p == "*" || p == "*/*" {
		return nil
	}
	if strings.Count(p, "/") != 1 {
		return fmt.Errorf("gitproxy: repository pattern %q is not owner/name", pattern)
	}
	for _, comp := range strings.Split(p, "/") {
		if comp == "" || comp == "." || comp == ".." {
			return fmt.Errorf("gitproxy: repository pattern %q has an unusable component", pattern)
		}
	}
	// path.Match only reports a bad pattern when it actually scans the
	// malformed part, so match it against a probe rather than trusting that a
	// stray "[" would surface later.
	if _, err := path.Match(p, "owner/name"); err != nil {
		return fmt.Errorf("gitproxy: repository pattern %q is malformed: %w", pattern, err)
	}
	return nil
}

// normalizeRepoPatterns validates and canonicalises an allowlist.
func normalizeRepoPatterns(patterns []string) ([]string, error) {
	if len(patterns) > MaxRepoPatterns {
		return nil, fmt.Errorf("gitproxy: %d repository patterns exceeds the %d maximum",
			len(patterns), MaxRepoPatterns)
	}
	out := make([]string, 0, len(patterns))
	seen := make(map[string]bool, len(patterns))
	for _, p := range patterns {
		if strings.TrimSpace(p) == "" {
			continue
		}
		if err := ValidateRepoPattern(p); err != nil {
			return nil, err
		}
		n := NormalizeRepoPath(p)
		if n == "*" {
			n = "*/*"
		}
		if seen[n] {
			continue
		}
		seen[n] = true
		out = append(out, n)
	}
	if len(out) == 0 {
		return nil, errors.New("gitproxy: repository allowlist is empty")
	}
	return out, nil
}

// matchRepoPattern reports whether an already-normalised path matches an
// already-normalised pattern.
func matchRepoPattern(pattern, repoPath string) bool {
	// Enforced here as well as in AllowsRepo because this is the function that
	// decides, and a path with a different shape must not reach path.Match
	// where "*" could behave differently than the validator assumed.
	if !validRepoPath(repoPath) {
		return false
	}
	ok, err := path.Match(pattern, repoPath)
	return err == nil && ok
}

// Scoped reports whether the session serves an allowlist rather than a single
// pinned repository.
func (s *Session) Scoped() bool { return s != nil && len(s.RepoPatterns) > 0 }

// AllowsRepo reports whether this session may address the given owner/name.
//
// Deny-by-default in both modes: a pinned session admits its one repository, a
// scoped session admits only what its allowlist matches, and a session with
// neither admits nothing.
func (s *Session) AllowsRepo(repoPath string) bool {
	if s == nil {
		return false
	}
	p := NormalizeRepoPath(repoPath)
	if !validRepoPath(p) {
		return false
	}
	if !s.Scoped() {
		return s.RepoPath != "" && strings.EqualFold(s.RepoPath, p)
	}
	for _, pattern := range s.RepoPatterns {
		if matchRepoPattern(pattern, p) {
			return true
		}
	}
	return false
}

// scopeDescription renders what this session admits, for a refusal message and
// for audit rows. It names no credential and is safe to return to the sandbox.
func (s *Session) scopeDescription() string {
	if s == nil {
		return ""
	}
	if s.Scoped() {
		return strings.Join(s.RepoPatterns, ",")
	}
	return s.RepoPath
}

// upstreamFor returns the forge URL this session forwards repoPath to.
//
// The host always comes from the session. For a pinned session the whole URL
// does, and repoPath is not consulted at all; for a scoped session the host
// comes from the session's Upstream base and only the path segment is taken
// from the request — after AllowsRepo has admitted it, which this function
// re-checks rather than assuming its caller did. That check is the invariant
// that keeps the credential from being steered: there is no input to this
// function that can change which host the token is presented to.
func (s *Session) upstreamFor(repoPath string) (string, error) {
	if s == nil {
		return "", errors.New("gitproxy: no session")
	}
	if !s.Scoped() {
		return strings.TrimSuffix(s.Upstream, ".git"), nil
	}
	if !s.AllowsRepo(repoPath) {
		return "", fmt.Errorf("gitproxy: session does not admit %s", repoPath)
	}
	p := NormalizeRepoPath(repoPath)
	// Belt and braces. AllowsRepo has already required both segments to be
	// forwardable, so this cannot fire — but it is what makes the
	// concatenation below safe to read in isolation: every character in p is
	// one that survives a URL re-parse unchanged, so the string approved above
	// and the path the forge receives are necessarily the same.
	if !validRepoPath(p) {
		return "", fmt.Errorf("gitproxy: %q is not a forwardable repository path", repoPath)
	}
	return strings.TrimSuffix(s.Upstream, "/") + "/" + p, nil
}

// UpstreamHostBase checks the forge base a scoped session forwards to.
//
// A scoped session's Upstream is a host, not a repository, so it is validated
// against the opposite requirement from UpstreamRepoPath: there must be *no*
// path, because every path segment on a scoped session comes from the request
// and a base with one would silently prefix them all.
func UpstreamHostBase(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", errors.New("gitproxy: upstream host base is empty")
	}
	u, err := url.Parse(s)
	if err != nil {
		return "", fmt.Errorf("gitproxy: upstream host base %q is not a URL: %w", s, err)
	}
	switch {
	case u.Scheme != "https":
		return "", fmt.Errorf("gitproxy: upstream host base must be https, got scheme %q", u.Scheme)
	case u.Host == "":
		return "", errors.New("gitproxy: upstream host base has no host")
	case u.User != nil:
		return "", errors.New("gitproxy: upstream host base must not embed credentials")
	case strings.Trim(u.Path, "/") != "":
		return "", fmt.Errorf("gitproxy: upstream host base must have no path, got %q", u.Path)
	case u.RawQuery != "" || u.Fragment != "":
		return "", errors.New("gitproxy: upstream host base must not carry a query or fragment")
	}
	return u.Scheme + "://" + u.Host, nil
}
