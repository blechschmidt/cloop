package secretbroker

import (
	"fmt"
	"path"
	"sort"
	"strings"
)

// Constraints narrow what a granted secret may be used for. Which fields
// apply depends on the secret's Kind; ValidateFor rejects a grant whose
// constraints do not gate its kind, so an under-specified grant is a
// creation-time error rather than a delivery-time surprise.
//
// The wildcard "*" is always spelled out. An empty list on a gating
// dimension is rejected by ValidateFor rather than treated as "allow all" —
// the single most common way allowlists fail open is an empty slice reading
// as "no restrictions", and that reading is unavailable here.
type Constraints struct {
	// Repos is an owner/repo glob allowlist for github_pat and github_app.
	// Patterns match case-insensitively; "*" alone allows every repository.
	Repos []string `json:"repos,omitempty"`
	// Permissions is the permission set a github credential may exercise
	// ("contents:read", "pull_requests:write"). Enforced at cloop's own
	// GitHub call sites via AllowsPermission; GitHub cannot narrow an
	// already-issued PAT server-side.
	Permissions []string `json:"permissions,omitempty"`
	// Namespaces is the Kubernetes namespace allowlist for kubeconfig.
	Namespaces []string `json:"namespaces,omitempty"`
	// Contexts is the kubeconfig context allowlist. The delivered
	// kubeconfig contains only these contexts.
	Contexts []string `json:"contexts,omitempty"`
	// Hosts is the allowed-host list for egress_proxy. A leading "*."
	// matches subdomains only, not the bare domain.
	Hosts []string `json:"hosts,omitempty"`
	// Registries is the container-registry allowlist for registry secrets.
	Registries []string `json:"registries,omitempty"`
	// EnvKeys restricts which keys of an env secret are delivered. Empty
	// means every key in the secret, which is safe because an env secret's
	// keys *are* its scope — there is nothing wider to fall open to.
	EnvKeys []string `json:"env_keys,omitempty"`
	// Writable makes a local_repo grant read-write. It is the one constraint
	// that widens rather than narrows, so it is a bool that defaults to the
	// safe reading: a grant that says nothing delivers a read-only mount.
	//
	// Read-only is the useful default rather than a cautious one. The common
	// case is a sandbox that needs to *read* a developer's checkout — build
	// against it, grep it, copy from it — and a read-only bind means a
	// runaway harness cannot rewrite the history of a repository that exists
	// nowhere else. A project that genuinely needs to commit asks for it.
	Writable bool `json:"writable,omitempty"`
}

// patternCharset is the set of characters a glob pattern may contain.
//
// This is a security boundary, not tidiness: github_pat delivery embeds the
// repo patterns into a generated POSIX shell credential helper. Restricting
// the charset at grant-creation time means no quote, backtick, dollar sign,
// newline, or backslash can ever reach that generator, so the injection
// class is closed at the door rather than escaped at the sink. The generator
// re-checks anyway (see githubpat.go) in case a pattern arrives from a
// database written by an older or hostile writer.
func validPatternChar(r rune) bool {
	switch {
	case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		return true
	case r == '-', r == '_', r == '.', r == '/', r == '*', r == '?', r == ':':
		return true
	}
	return false
}

// validatePattern rejects patterns that are unsafe to embed or that
// path.Match cannot parse. A pattern that fails here can never be stored, so
// no matcher downstream has to cope with it.
func validatePattern(field, p string) error {
	if strings.TrimSpace(p) == "" {
		return fmt.Errorf("%w: %s contains an empty pattern", ErrInvalidConstraint, field)
	}
	if len(p) > 256 {
		return fmt.Errorf("%w: %s pattern %q exceeds 256 characters", ErrInvalidConstraint, field, p)
	}
	for _, r := range p {
		if !validPatternChar(r) {
			return fmt.Errorf("%w: %s pattern %q contains disallowed character %q",
				ErrInvalidConstraint, field, p, string(r))
		}
	}
	// "..": a path-traversal token has no meaning in any of these
	// namespaces and is a classic way to smuggle a wider match past a
	// normaliser.
	if strings.Contains(p, "..") {
		return fmt.Errorf("%w: %s pattern %q contains %q", ErrInvalidConstraint, field, p, "..")
	}
	// path.Match's own parser is the last word on syntax. We call it with a
	// throwaway subject purely to surface ErrBadPattern.
	if _, err := path.Match(p, "x"); err != nil {
		return fmt.Errorf("%w: %s pattern %q is malformed: %v", ErrInvalidConstraint, field, p, err)
	}
	return nil
}

func validatePatterns(field string, ps []string) error {
	for _, p := range ps {
		if err := validatePattern(field, p); err != nil {
			return err
		}
	}
	return nil
}

// ValidateFor checks that these constraints are well-formed *and* that they
// actually gate the given kind. A github_pat grant with no repo allowlist is
// rejected here: there is no safe default for "which repositories may this
// token touch", so the operator has to say, even if what they say is "*".
func (c Constraints) ValidateFor(kind Kind) error {
	if err := validatePatterns("repos", c.Repos); err != nil {
		return err
	}
	if err := validatePatterns("namespaces", c.Namespaces); err != nil {
		return err
	}
	if err := validatePatterns("contexts", c.Contexts); err != nil {
		return err
	}
	if err := validatePatterns("hosts", c.Hosts); err != nil {
		return err
	}
	if err := validatePatterns("registries", c.Registries); err != nil {
		return err
	}
	if err := validatePatterns("permissions", c.Permissions); err != nil {
		return err
	}
	for _, k := range c.EnvKeys {
		if err := validateEnvKey(k); err != nil {
			return err
		}
	}

	switch kind {
	case KindGitHubPAT, KindGitHubApp:
		if len(c.Repos) == 0 {
			return fmt.Errorf(
				"%w: a %s grant needs a repository allowlist (--repos org/*, or --repos '*' to allow all)",
				ErrInvalidConstraint, kind)
		}
	case KindKubeconfig:
		if len(c.Namespaces) == 0 && len(c.Contexts) == 0 {
			return fmt.Errorf(
				"%w: a kubeconfig grant needs --namespaces and/or --contexts",
				ErrInvalidConstraint)
		}
	case KindEgressProxy:
		if len(c.Hosts) == 0 {
			return fmt.Errorf(
				"%w: an egress_proxy grant needs an allowed-host list (--hosts)",
				ErrInvalidConstraint)
		}
	case KindRegistry:
		if len(c.Registries) == 0 {
			return fmt.Errorf(
				"%w: a registry grant needs a registry allowlist (--registries)",
				ErrInvalidConstraint)
		}
	case KindLocalRepo:
		if len(c.Repos) == 0 {
			return fmt.Errorf(
				"%w: a local_repo grant needs a repository allowlist (--repos my-service, or --repos '*' for every repository under the root)",
				ErrInvalidConstraint)
		}
	case KindEnv:
		// EnvKeys may be empty: an env secret's own keys bound it.
	}
	if c.Writable && kind != KindLocalRepo {
		return fmt.Errorf(
			"%w: writable applies to local_repo grants, not %s",
			ErrInvalidConstraint, kind)
	}
	return nil
}

// validateEnvKey enforces POSIX-ish environment variable naming. A key with
// an '=' or a NUL in it would corrupt the K=V env encoding every executor
// relies on, and a key with a newline could forge additional lines.
func validateEnvKey(k string) error {
	if k == "" {
		return fmt.Errorf("%w: env_keys contains an empty key", ErrInvalidConstraint)
	}
	if len(k) > 256 {
		return fmt.Errorf("%w: env key %q exceeds 256 characters", ErrInvalidConstraint, k)
	}
	for i, r := range k {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r == '_':
		case r >= '0' && r <= '9' && i > 0:
		default:
			return fmt.Errorf("%w: env key %q is not a valid environment variable name", ErrInvalidConstraint, k)
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// github: repository allowlist
// ---------------------------------------------------------------------------

// NormalizeRepo canonicalises the many ways a repository gets named into the
// single "owner/repo" form the allowlist is written in, so that
// "https://github.com/Org/Repo.git" and "org/repo" are the same subject.
//
// Anything that does not reduce to exactly one owner and one repo is an
// error, not a best guess: a caller that hands us something unrecognisable
// must be denied, not matched against a partially-parsed string.
func NormalizeRepo(repo string) (string, error) {
	s := strings.TrimSpace(repo)
	if s == "" {
		return "", fmt.Errorf("%w: empty repository", ErrRepoDenied)
	}
	// Strip a scheme and host: https://github.com/o/r, git://…, ssh URLs.
	if i := strings.Index(s, "://"); i >= 0 {
		rest := s[i+3:]
		if j := strings.Index(rest, "/"); j >= 0 {
			s = rest[j+1:]
		} else {
			return "", fmt.Errorf("%w: %q has no path component", ErrRepoDenied, repo)
		}
	}
	// scp-style "git@github.com:owner/repo".
	if i := strings.Index(s, "@"); i >= 0 {
		rest := s[i+1:]
		if j := strings.Index(rest, ":"); j >= 0 {
			s = rest[j+1:]
		}
	}
	s = strings.Trim(s, "/")
	s = strings.TrimSuffix(s, ".git")
	s = strings.ToLower(s)

	owner, name, found := strings.Cut(s, "/")
	if !found || owner == "" || name == "" || strings.Contains(name, "/") {
		return "", fmt.Errorf("%w: %q is not in owner/repo form", ErrRepoDenied, repo)
	}
	// Both segments must be drawn from GitHub's own name charset. Checking
	// the whole charset rather than blacklisting the dangerous characters
	// closes the class rather than the instances: a wildcard, a traversal
	// token, a space, a control character, and a Unicode look-alike are all
	// rejected by the same rule.
	//
	// A fuzz run found why the blacklist form was not enough — "/ org/repo"
	// normalised to " org/repo", which is a distinct owner *and* is not
	// idempotent under a second normalisation, so the matcher's verdict
	// depended on how many times the caller had normalised.
	for _, part := range []string{owner, name} {
		if part == "." || part == ".." || !validRepoSegment(part) {
			return "", fmt.Errorf("%w: %q contains an illegal path element", ErrRepoDenied, repo)
		}
	}
	return owner + "/" + name, nil
}

// validRepoSegment reports whether s is a legal GitHub owner or repository
// name: ASCII letters, digits, '.', '_', and '-', with no ".." run.
//
// The ".." rule mirrors validatePattern's, deliberately. Keeping the subject
// charset and the pattern charset identical is what guarantees that anything
// a subject can express, a pattern can also express — so there is no string
// that slips through a glob because only one side of the comparison
// sanitised it. GitHub rejects ".." in names anyway.
func validRepoSegment(s string) bool {
	if s == "" || len(s) > 100 || strings.Contains(s, "..") {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '.', r == '_', r == '-':
		default:
			return false
		}
	}
	return true
}

// AllowsRepo reports whether repo is covered by the allowlist.
//
// Matching is per-segment: path.Match's "*" does not cross "/", so "org/*"
// covers org/tool but not a three-segment path, and a bare "*" is special-
// cased to mean every repository. Comparison is case-insensitive because
// GitHub owner and repo names are.
func (c Constraints) AllowsRepo(repo string) bool {
	return c.CheckRepo(repo) == nil
}

// CheckRepo is AllowsRepo with the denial reason attached, so callers can
// put a cause in the audit log instead of a bare false.
func (c Constraints) CheckRepo(repo string) error {
	norm, err := NormalizeRepo(repo)
	if err != nil {
		return err
	}
	if len(c.Repos) == 0 {
		return fmt.Errorf("%w: %s (grant carries no repository allowlist)", ErrRepoDenied, norm)
	}
	for _, pat := range c.Repos {
		if matchRepoPattern(pat, norm) {
			return nil
		}
	}
	return fmt.Errorf("%w: %s is not in the grant's repository allowlist (%s)",
		ErrRepoDenied, norm, strings.Join(c.Repos, ", "))
}

func matchRepoPattern(pat, norm string) bool {
	pat = strings.ToLower(strings.TrimSpace(pat))
	if pat == "" {
		return false
	}
	// A bare "*" cannot match "owner/repo" under path.Match (it will not
	// cross the separator), so allow-everything is handled explicitly.
	if pat == "*" || pat == "*/*" {
		return true
	}
	pat = strings.TrimSuffix(strings.Trim(pat, "/"), ".git")
	ok, err := path.Match(pat, norm)
	return err == nil && ok
}

// AllowsPermission reports whether a github permission is within the grant's
// permission set. An empty set permits nothing beyond read: an operator who
// does not enumerate permissions has not authorised any write.
func (c Constraints) AllowsPermission(perm string) bool {
	p := strings.ToLower(strings.TrimSpace(perm))
	if p == "" {
		return false
	}
	for _, allowed := range c.Permissions {
		a := strings.ToLower(strings.TrimSpace(allowed))
		if a == "*" || a == p {
			return true
		}
		// "contents" as a grant entry covers "contents:read"/"contents:write";
		// the reverse is not true.
		if scope, _, found := strings.Cut(p, ":"); found && a == scope {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// kubernetes: namespace and context allowlists
// ---------------------------------------------------------------------------

// AllowsNamespace reports whether ns is permitted. An empty allowlist denies:
// ValidateFor guarantees a kubeconfig grant has namespaces or contexts, and
// where it has only contexts, namespace checks are not the gate.
func (c Constraints) AllowsNamespace(ns string) bool {
	return matchAny(c.Namespaces, ns)
}

// AllowsContext reports whether a kubeconfig context name is permitted.
// A grant that lists namespaces but no contexts permits every context (the
// namespace pin is then the constraint); a grant that lists contexts
// restricts to exactly those.
func (c Constraints) AllowsContext(name string) bool {
	if len(c.Contexts) == 0 {
		return len(c.Namespaces) > 0
	}
	return matchAny(c.Contexts, name)
}

// ---------------------------------------------------------------------------
// egress: host allowlist
// ---------------------------------------------------------------------------

// NormalizeHost reduces a host, host:port, or URL authority to a bare
// lowercase hostname. Anything carrying a path, credentials, or a wildcard
// is rejected: those are the shapes an attacker uses to make "evil.com" look
// like "api.example.com" to a naive matcher.
func NormalizeHost(host string) (string, error) {
	h := strings.TrimSpace(host)
	if h == "" {
		return "", fmt.Errorf("%w: empty host", ErrHostDenied)
	}
	if i := strings.Index(h, "://"); i >= 0 {
		h = h[i+3:]
	}
	// Credentials in the authority ("user@host") are stripped, but only
	// after we have refused to let them hide a second host.
	if i := strings.LastIndex(h, "@"); i >= 0 {
		h = h[i+1:]
	}
	if i := strings.IndexAny(h, "/?#"); i >= 0 {
		h = h[:i]
	}
	// Strip a port, taking care not to mangle a bracketed IPv6 literal.
	if strings.HasPrefix(h, "[") {
		if end := strings.Index(h, "]"); end >= 0 {
			h = h[1:end]
		}
	} else if i := strings.LastIndex(h, ":"); i >= 0 && !strings.Contains(h[i+1:], ":") {
		h = h[:i]
	}
	h = strings.ToLower(strings.TrimSuffix(h, "."))
	if h == "" {
		return "", fmt.Errorf("%w: %q has no host component", ErrHostDenied, host)
	}
	if strings.ContainsAny(h, "*?[]\\ \t\n") || strings.Contains(h, "..") {
		return "", fmt.Errorf("%w: %q contains an illegal character", ErrHostDenied, host)
	}
	return h, nil
}

// AllowsHost reports whether host is in the egress allowlist.
func (c Constraints) AllowsHost(host string) bool {
	return c.CheckHost(host) == nil
}

// CheckHost is AllowsHost with a reason attached.
//
// "*.example.com" matches subdomains only — api.example.com yes,
// example.com no. Requiring the bare domain to be listed separately keeps
// "allow the API subdomains" from silently also allowing the apex, which is
// often a different service on a different box.
func (c Constraints) CheckHost(host string) error {
	norm, err := NormalizeHost(host)
	if err != nil {
		return err
	}
	if len(c.Hosts) == 0 {
		return fmt.Errorf("%w: %s (grant carries no host allowlist)", ErrHostDenied, norm)
	}
	for _, pat := range c.Hosts {
		p := strings.ToLower(strings.TrimSpace(strings.TrimSuffix(pat, ".")))
		switch {
		case p == "*":
			return nil
		case strings.HasPrefix(p, "*."):
			suffix := p[1:] // ".example.com"
			if strings.HasSuffix(norm, suffix) && len(norm) > len(suffix) {
				return nil
			}
		case p == norm:
			return nil
		}
	}
	return fmt.Errorf("%w: %s is not in the grant's host allowlist (%s)",
		ErrHostDenied, norm, strings.Join(c.Hosts, ", "))
}

// ---------------------------------------------------------------------------
// registry and env
// ---------------------------------------------------------------------------

// AllowsRegistry reports whether a container registry host is permitted.
// Registry names are host-shaped, so they reuse the host matcher's
// subdomain semantics after normalisation.
func (c Constraints) AllowsRegistry(reg string) bool {
	norm, err := NormalizeHost(reg)
	if err != nil {
		return false
	}
	for _, pat := range c.Registries {
		p := strings.ToLower(strings.TrimSpace(pat))
		switch {
		case p == "*":
			return true
		case strings.HasPrefix(p, "*."):
			suffix := p[1:]
			if strings.HasSuffix(norm, suffix) && len(norm) > len(suffix) {
				return true
			}
		case p == norm:
			return true
		}
	}
	return false
}

// AllowsEnvKey reports whether an env secret's key may be delivered. An
// empty EnvKeys list allows every key the secret contains — see the field
// comment for why that is not a fail-open.
func (c Constraints) AllowsEnvKey(key string) bool {
	if len(c.EnvKeys) == 0 {
		return true
	}
	for _, k := range c.EnvKeys {
		if k == key {
			return true
		}
	}
	return false
}

// matchAny reports whether value matches any pattern in pats, using
// path.Match semantics with an explicit "*" wildcard. Empty pats denies.
func matchAny(pats []string, value string) bool {
	v := strings.TrimSpace(value)
	if v == "" || len(pats) == 0 {
		return false
	}
	for _, pat := range pats {
		p := strings.TrimSpace(pat)
		if p == "*" {
			return true
		}
		if ok, err := path.Match(p, v); err == nil && ok {
			return true
		}
	}
	return false
}

// Summary renders the constraints as a short, sorted, human-readable string
// for CLI listings and audit payloads. It contains only allowlist patterns,
// never payload material.
func (c Constraints) Summary() string {
	var parts []string
	add := func(label string, vals []string) {
		if len(vals) == 0 {
			return
		}
		cp := append([]string(nil), vals...)
		sort.Strings(cp)
		parts = append(parts, label+"="+strings.Join(cp, "|"))
	}
	add("repos", c.Repos)
	add("perms", c.Permissions)
	add("ns", c.Namespaces)
	add("ctx", c.Contexts)
	add("hosts", c.Hosts)
	add("registries", c.Registries)
	add("env", c.EnvKeys)
	if c.Writable {
		// Only when true. A "writable=false" on every github grant's summary
		// would be noise, and the read-only default is what the absence means.
		parts = append(parts, "writable")
	}
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, " ")
}
