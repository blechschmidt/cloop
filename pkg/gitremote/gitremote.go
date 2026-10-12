// Package gitremote reads a git remote as the GitHub repository it names.
//
// `cloop remote init` (Task 20417) creates a hub project from the checkout it
// is run in, and the first thing it needs from that checkout is which
// repository it is a clone of — the name the project's GitHub grant is then
// narrowed to. The answer is in the origin remote, written in whichever of
// git's spellings the developer cloned with: https, the scp form GitHub prints
// for ssh (git@github.com:owner/name.git), an ssh:// URL, the ssh-over-443
// host. All of them name the same owner/name, and that is all this package
// returns.
//
// Two things are refused rather than read, and both by name:
//
//   - A remote that is not on GitHub. The hub reaches repositories through a
//     GitHub App installation or a GitHub token, so a GitLab or Bitbucket
//     remote names nothing either could reach, and guessing an owner/name from
//     its path would attach a GitHub repository of the same name — somebody
//     else's.
//   - A remote that carries a credential: https://<token>@github.com/…, a
//     password in an ssh URL, an access_token query. Nothing here would use
//     it, and every place the remote would go next — a grant, an audit row,
//     an error message — is somewhere a credential must not. Errors print the
//     remote with its user information replaced (Redact).
package gitremote

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// Repo is a repository on github.com.
type Repo struct {
	Owner string
	Name  string
}

// FullName is owner/name, the form a grant's repository allowlist takes.
func (r Repo) FullName() string { return r.Owner + "/" + r.Name }

// URL is the repository's https address.
func (r Repo) URL() string { return "https://github.com/" + r.FullName() }

// String is FullName.
func (r Repo) String() string { return r.FullName() }

// The three ways a remote can fail to name a GitHub repository. An *Error
// matches exactly one of them with errors.Is.
var (
	// ErrNotGitHub: the remote names a repository somewhere other than
	// github.com, or a local path.
	ErrNotGitHub = errors.New("not a GitHub repository")
	// ErrCredential: the remote embeds a credential.
	ErrCredential = errors.New("embeds a credential")
	// ErrMalformed: the remote is not a repository URL at all.
	ErrMalformed = errors.New("not a repository URL")
)

// Error says why a remote names no GitHub repository. Remote is already
// redacted, so the error is safe to print.
type Error struct {
	Remote string
	Reason string
	kind   error
}

func (e *Error) Error() string {
	if e.Remote == "" {
		return e.Reason
	}
	return e.Remote + ": " + e.Reason
}

// Is reports which of the three sentinels the error is.
func (e *Error) Is(target error) bool { return target == e.kind }

// githubHosts are the host names a github.com remote is written with:
// ssh.github.com is the ssh-over-port-443 endpoint for networks that block 22.
var githubHosts = map[string]bool{
	"github.com":     true,
	"www.github.com": true,
	"ssh.github.com": true,
}

// tokenQueryKeys are query parameters that carry a credential when a remote
// has them.
var tokenQueryKeys = []string{"access_token", "token", "private_token", "oauth_token", "password"}

// ParseGitHub reads a git remote — https, http, ssh, git+ssh, git://, or the
// scp form [user@]host:owner/name — as the GitHub repository it names.
func ParseGitHub(remote string) (Repo, error) {
	raw := strings.TrimSpace(remote)
	if raw == "" {
		return Repo{}, &Error{Reason: "the remote is empty", kind: ErrMalformed}
	}
	shown := Redact(raw)
	for _, c := range raw {
		if c < 0x20 || c == 0x7f || c == ' ' || c == '\t' {
			return Repo{}, &Error{Remote: shown, Reason: "contains whitespace or control characters", kind: ErrMalformed}
		}
	}
	if !strings.Contains(raw, "://") {
		return parseSCP(raw, shown)
	}

	u, err := url.Parse(raw)
	if err != nil {
		return Repo{}, &Error{Remote: shown, Reason: "is not a URL", kind: ErrMalformed}
	}
	scheme := strings.ToLower(u.Scheme)
	switch scheme {
	case "https", "http", "git":
		// Any user information over these is a credential, or a user name
		// standing in for one: GitHub's https remotes are written
		// https://<token>@github.com/… and https://x-access-token:<token>@….
		if u.User != nil {
			return Repo{}, credentialError(shown)
		}
	case "ssh", "git+ssh", "ssh+git":
		// An ssh user name is not a secret (GitHub's is always "git"); a
		// password is.
		if _, hasPassword := u.User.Password(); hasPassword {
			return Repo{}, credentialError(shown)
		}
	case "file":
		return Repo{}, &Error{Remote: shown, Reason: "is a local path, not a GitHub repository", kind: ErrNotGitHub}
	default:
		return Repo{}, &Error{Remote: shown,
			Reason: fmt.Sprintf("uses the %q scheme, which no GitHub remote does", u.Scheme), kind: ErrMalformed}
	}
	if u.RawQuery != "" || u.Fragment != "" {
		q := u.Query()
		for _, k := range tokenQueryKeys {
			if q.Has(k) {
				return Repo{}, credentialError(shown)
			}
		}
		return Repo{}, &Error{Remote: shown, Reason: "carries a query or a fragment, which no repository URL has", kind: ErrMalformed}
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return Repo{}, &Error{Remote: shown, Reason: "has no host", kind: ErrMalformed}
	}
	if !githubHosts[host] {
		return Repo{}, notGitHubError(shown, host)
	}
	return parsePath(u.Path, shown)
}

// parseSCP reads git's scp-like form, [user@]host:path.
func parseSCP(raw, shown string) (Repo, error) {
	if strings.HasPrefix(raw, "/") || strings.HasPrefix(raw, ".") || strings.HasPrefix(raw, "~") {
		return Repo{}, &Error{Remote: shown, Reason: "is a local path, not a GitHub repository", kind: ErrNotGitHub}
	}
	colon := strings.Index(raw, ":")
	if colon < 0 {
		// No scheme and no colon: git reads it as a path relative to the
		// current directory.
		return Repo{}, &Error{Remote: shown, Reason: "is a local path, not a GitHub repository", kind: ErrNotGitHub}
	}
	authority, path := raw[:colon], raw[colon+1:]
	if at := strings.LastIndex(authority, "@"); at >= 0 {
		authority = authority[at+1:]
	} else if at := strings.Index(path, "@"); at >= 0 && !strings.Contains(path[:at], "/") {
		// user:password@host:path — the first colon was inside the user
		// information, which makes what follows it a password.
		return Repo{}, credentialError(shown)
	}
	host := strings.ToLower(authority)
	if strings.ContainsAny(host, "/\\") || host == "" {
		return Repo{}, &Error{Remote: shown, Reason: "is neither a URL nor git's host:path form", kind: ErrMalformed}
	}
	if len(host) == 1 {
		// C:\repo — a Windows drive letter, not a host.
		return Repo{}, &Error{Remote: shown, Reason: "is a local path, not a GitHub repository", kind: ErrNotGitHub}
	}
	if !githubHosts[host] {
		return Repo{}, notGitHubError(shown, host)
	}
	return parsePath(path, shown)
}

// parsePath reads /owner/name[.git][/] from a remote's path.
func parsePath(path, shown string) (Repo, error) {
	p := strings.Trim(path, "/")
	p = strings.TrimSuffix(p, ".git")
	parts := strings.Split(p, "/")
	if len(parts) != 2 {
		return Repo{}, &Error{Remote: shown,
			Reason: "does not name a repository as owner/name", kind: ErrMalformed}
	}
	repo := Repo{Owner: parts[0], Name: parts[1]}
	if err := validate(repo); err != nil {
		return Repo{}, &Error{Remote: shown, Reason: err.Error(), kind: ErrMalformed}
	}
	return repo, nil
}

// ParseRepo reads a repository named on a command line: owner/name, or any
// remote ParseGitHub accepts.
func ParseRepo(s string) (Repo, error) {
	raw := strings.TrimSpace(s)
	if strings.Contains(raw, "://") || strings.Contains(raw, ":") || strings.Contains(raw, "@") {
		return ParseGitHub(raw)
	}
	// github.com/owner/name, as a browser's address bar shows it.
	for host := range githubHosts {
		if len(raw) > len(host)+1 && strings.EqualFold(raw[:len(host)+1], host+"/") {
			raw = raw[len(host)+1:]
			break
		}
	}
	parts := strings.Split(strings.TrimSuffix(strings.TrimSuffix(raw, "/"), ".git"), "/")
	if len(parts) != 2 {
		return Repo{}, &Error{Remote: raw, Reason: "is not owner/name", kind: ErrMalformed}
	}
	repo := Repo{Owner: parts[0], Name: parts[1]}
	if err := validate(repo); err != nil {
		return Repo{}, &Error{Remote: raw, Reason: err.Error(), kind: ErrMalformed}
	}
	return repo, nil
}

// validate checks owner and name against what GitHub allows: an owner of up
// to 39 letters, digits and hyphens (and the underscore of an enterprise-managed
// user), not starting or ending with a hyphen; a name of up to 100 letters,
// digits, dots, hyphens and underscores that is not "." or "..".
func validate(r Repo) error {
	if n := len(r.Owner); n == 0 || n > 39 {
		return fmt.Errorf("owner %q is not a GitHub account name", r.Owner)
	}
	if strings.HasPrefix(r.Owner, "-") || strings.HasSuffix(r.Owner, "-") {
		return fmt.Errorf("owner %q is not a GitHub account name", r.Owner)
	}
	for _, c := range r.Owner {
		if !isAlnum(c) && c != '-' && c != '_' {
			return fmt.Errorf("owner %q is not a GitHub account name", r.Owner)
		}
	}
	if n := len(r.Name); n == 0 || n > 100 || r.Name == "." || r.Name == ".." {
		return fmt.Errorf("%q is not a GitHub repository name", r.Name)
	}
	for _, c := range r.Name {
		if !isAlnum(c) && c != '-' && c != '_' && c != '.' {
			return fmt.Errorf("%q is not a GitHub repository name", r.Name)
		}
	}
	return nil
}

func isAlnum(c rune) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

func credentialError(shown string) error {
	return &Error{Remote: shown, kind: ErrCredential,
		Reason: "embeds a credential; take it out of the remote (git remote set-url origin <url without it>) " +
			"and revoke it, since anything that read this remote has it"}
}

func notGitHubError(shown, host string) error {
	return &Error{Remote: shown, kind: ErrNotGitHub,
		Reason: fmt.Sprintf("is on %s, not github.com", host)}
}

// Redact returns remote with any user information and query replaced by
// "***", so a remote can be quoted in an error without the credential it may
// carry.
func Redact(remote string) string {
	raw := strings.TrimSpace(remote)
	if strings.Contains(raw, "://") {
		u, err := url.Parse(raw)
		if err != nil {
			// Unparseable: cut anything that could be user information.
			if i := strings.LastIndex(raw, "@"); i >= 0 {
				if j := strings.Index(raw, "://"); j >= 0 && j < i {
					return raw[:j+3] + "***@" + raw[i+1:]
				}
			}
			return raw
		}
		masked := u.Scheme + "://"
		if u.User != nil {
			if _, hasPassword := u.User.Password(); hasPassword || u.Scheme == "https" || u.Scheme == "http" || u.Scheme == "git" {
				masked += "***@"
			} else {
				masked += u.User.Username() + "@"
			}
		}
		masked += u.Host + u.EscapedPath()
		if u.RawQuery != "" {
			masked += "?***"
		}
		return masked
	}
	// scp form: keep a user name, drop anything after a colon inside it.
	if colon := strings.Index(raw, ":"); colon >= 0 {
		if at := strings.Index(raw[colon:], "@"); at >= 0 && !strings.Contains(raw[colon:colon+at], "/") {
			return "***@" + raw[colon+at+1:]
		}
	}
	return raw
}
