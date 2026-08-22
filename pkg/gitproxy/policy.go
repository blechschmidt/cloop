package gitproxy

import (
	"errors"
	"fmt"
	"path"
	"strings"

	"github.com/blechschmidt/cloop/pkg/executor"
)

// MaxRefPatterns bounds an allowlist. A policy with thousands of patterns is a
// configuration mistake, and matching every one of them against every ref in
// every push is work an attacker would otherwise get to choose the size of.
const MaxRefPatterns = 256

// DefaultMaxCommands caps the ref updates one push may carry.
//
// A write-back moves one branch. Anything with more than a handful of commands
// is either a mirror push or an attempt to find a ref the allowlist forgot, and
// neither is what a sandbox is for.
const DefaultMaxCommands = 16

// DefaultAllowedRef is the allowlist a policy gets when it names none.
//
// It is the write-back namespace and nothing else. pkg/executor already
// requires every write-back branch to sit under this prefix so that the hub can
// force-update it without being able to overwrite a branch a human owns — but
// that rule is enforced by code running *inside* the sandbox, which makes it a
// convention rather than a boundary. Restating it here, outside, is what turns
// it into one.
var DefaultAllowedRef = "refs/heads/" + executor.WriteBackBranchPrefix + "**"

// ErrRefDenied is the refusal. Every rejected command wraps it, so a caller can
// distinguish "the policy said no" — an expected, reportable outcome — from a
// malformed request or a broken upstream.
var ErrRefDenied = errors.New("ref update denied by policy")

// Policy is what a sandbox is allowed to do to a repository's refs.
//
// It is deny-by-default in every dimension. An empty AllowedRefs is not "no
// restriction", it is the built-in write-back namespace; an unset AllowDelete
// is a refusal, not an omission. The failure mode of a permissive default here
// is a sandbox force-pushing over main, which is exactly the outcome the
// subsystem exists to make impossible, so there is no default that trades
// safety for convenience.
type Policy struct {
	// AllowedRefs are glob patterns over full ref names. A pattern without a
	// refs/ prefix is read as a branch name and gets refs/heads/ prepended, so
	// "cloop/*" and "refs/heads/cloop/*" mean the same thing.
	//
	// Matching follows path.Match: "*" does not cross a "/". A trailing "/**"
	// matches any depth below the prefix, which is what a per-task namespace
	// like cloop/task-42/fixup needs.
	AllowedRefs []string `json:"allowed_refs,omitempty"`

	// AllowCreate permits a push that brings a ref into existence. Creating a
	// new branch under an allowed namespace is the ordinary write-back case, so
	// this is the one authority a caller almost always wants.
	AllowCreate bool `json:"allow_create,omitempty"`

	// AllowUpdate permits moving an existing allowed ref to a new commit. A
	// retried task legitimately replaces its own predecessor.
	AllowUpdate bool `json:"allow_update,omitempty"`

	// AllowDelete permits removing an allowed ref. Off by default: deleting is
	// not something a write-back ever needs, and a name-only allowlist that
	// forgot about deletes would let a sandbox destroy the very branches it was
	// scoped to.
	AllowDelete bool `json:"allow_delete,omitempty"`

	// AllowFetch permits the read half of the protocol — git-upload-pack — over
	// the same session. A sandbox that clones through the proxy needs it; one
	// that only pushes back a tree it was handed does not.
	AllowFetch bool `json:"allow_fetch,omitempty"`

	// MaxCommands caps ref updates per push. 0 means DefaultMaxCommands.
	MaxCommands int `json:"max_commands,omitempty"`

	// MaxPackBytes caps the request body. 0 means DefaultMaxPackBytes.
	MaxPackBytes int64 `json:"max_pack_bytes,omitempty"`
}

// DefaultMaxPackBytes bounds one pushed pack.
//
// The proxy streams the pack rather than buffering it, so this is not a memory
// bound — it is a bound on what one sandbox session can push through the hub's
// credential in a single request.
const DefaultMaxPackBytes int64 = 2 << 30 // 2 GiB

// WriteBackPolicy returns the policy the executor write-back path needs: create
// and update inside the cloop/ namespace, no deletes, no fetch.
//
// It is a constructor rather than a documented recipe because every caller that
// hand-assembled these four booleans would be a caller that could get one
// wrong, and three of the four failures are silent.
func WriteBackPolicy() Policy {
	return Policy{
		AllowedRefs: []string{DefaultAllowedRef},
		AllowCreate: true,
		AllowUpdate: true,
	}
}

// Normalize fills defaults and canonicalises patterns. It is idempotent.
func (p *Policy) Normalize() {
	if len(p.AllowedRefs) == 0 {
		p.AllowedRefs = []string{DefaultAllowedRef}
	}
	seen := make(map[string]bool, len(p.AllowedRefs))
	out := p.AllowedRefs[:0]
	for _, raw := range p.AllowedRefs {
		pat := normalizeRefPattern(raw)
		if pat == "" || seen[pat] {
			continue
		}
		seen[pat] = true
		out = append(out, pat)
	}
	p.AllowedRefs = out
	if p.MaxCommands <= 0 {
		p.MaxCommands = DefaultMaxCommands
	}
	if p.MaxPackBytes <= 0 {
		p.MaxPackBytes = DefaultMaxPackBytes
	}
}

// normalizeRefPattern trims a pattern and gives a bare branch name its
// refs/heads/ prefix.
func normalizeRefPattern(raw string) string {
	pat := strings.TrimSpace(raw)
	if pat == "" {
		return ""
	}
	if !strings.HasPrefix(pat, "refs/") {
		pat = "refs/heads/" + strings.TrimPrefix(pat, "/")
	}
	return pat
}

// Validate reports whether the policy is usable. Call Normalize first.
func (p Policy) Validate() error {
	switch {
	case len(p.AllowedRefs) == 0:
		return errors.New("policy has no allowed ref patterns")
	case len(p.AllowedRefs) > MaxRefPatterns:
		return fmt.Errorf("policy has %d ref patterns, at most %d are allowed",
			len(p.AllowedRefs), MaxRefPatterns)
	case !p.AllowCreate && !p.AllowUpdate && !p.AllowDelete && !p.AllowFetch:
		// A policy that permits nothing is almost certainly a caller that built
		// a Policy{} and expected defaults. Say so rather than minting a
		// session that refuses every request it will ever see.
		return errors.New("policy permits nothing: set at least one of allow_create, allow_update, allow_delete, allow_fetch")
	}
	for _, pat := range p.AllowedRefs {
		if err := validateRefPattern(pat); err != nil {
			return fmt.Errorf("ref pattern %q: %w", pat, err)
		}
	}
	return nil
}

// validateRefPattern checks a pattern is well formed and cannot match outside
// the refs/ namespace.
func validateRefPattern(pat string) error {
	switch {
	case !strings.HasPrefix(pat, "refs/"):
		return errors.New("must name a ref under refs/")
	case strings.Contains(pat, ".."):
		return errors.New("contains ..")
	case strings.Contains(pat, "//"):
		return errors.New("contains an empty path component")
	case strings.HasSuffix(pat, "/"):
		return errors.New("ends with /")
	}
	for i := 0; i < len(pat); i++ {
		if c := pat[i]; c < 0x20 || c == 0x7f || c == ' ' {
			return errors.New("contains a control character or space")
		}
	}
	// A pattern of just "refs/**" or "refs/*" permits the whole namespace,
	// including refs/heads/main. That is a legitimate thing for an operator to
	// configure deliberately, so it is allowed here — but path.Match must be
	// able to compile it, or the pattern would silently match nothing and read
	// as a working allowlist that denies everything.
	probe := strings.TrimSuffix(pat, "/**")
	if _, err := path.Match(probe, "refs/heads/probe"); err != nil {
		return fmt.Errorf("is not a valid glob: %w", err)
	}
	return nil
}

// AllowsRef reports whether any pattern admits the ref name.
func (p Policy) AllowsRef(ref string) bool {
	for _, pat := range p.AllowedRefs {
		if matchRefPattern(pat, ref) {
			return true
		}
	}
	return false
}

// matchRefPattern applies one pattern.
func matchRefPattern(pat, ref string) bool {
	if prefix, ok := strings.CutSuffix(pat, "/**"); ok {
		// "refs/heads/cloop/**" admits anything strictly below the prefix, at
		// any depth, but not the prefix itself: a namespace is a place to put
		// branches, not a branch.
		return strings.HasPrefix(ref, prefix+"/")
	}
	ok, err := path.Match(pat, ref)
	return err == nil && ok
}

// Decide returns nil if the update is permitted, or an error wrapping
// ErrRefDenied whose text is shown to the person running git push.
//
// The two checks are ordered name-first deliberately. A sandbox probing for a
// ref it is not allowed to touch learns the same thing either way, but an
// operator reading the audit trail wants "main is not in the allowlist" rather
// than "delete is not permitted", because the first names the real problem.
func (p Policy) Decide(u RefUpdate) error {
	if !p.AllowsRef(u.Ref) {
		return fmt.Errorf("%w: %s is not in this session's branch allowlist (%s)",
			ErrRefDenied, u.Ref, strings.Join(p.AllowedRefs, ", "))
	}
	switch {
	case u.IsDelete() && !p.AllowDelete:
		return fmt.Errorf("%w: this session may not delete refs", ErrRefDenied)
	case u.IsCreate() && !p.AllowCreate:
		return fmt.Errorf("%w: this session may not create refs", ErrRefDenied)
	case u.IsUpdate() && !p.AllowUpdate:
		return fmt.Errorf("%w: this session may not update existing refs", ErrRefDenied)
	}
	return nil
}

// Decision pairs one command with its verdict, for reporting and for audit.
type Decision struct {
	Update RefUpdate
	Err    error
}

// Allowed reports whether the command passed.
func (d Decision) Allowed() bool { return d.Err == nil }

// Reason renders the refusal as a single line fit for git's status report,
// which is newline-delimited and would otherwise be split by a multi-line
// message into a status line and garbage.
func (d Decision) Reason() string {
	if d.Err == nil {
		return ""
	}
	msg := strings.TrimPrefix(d.Err.Error(), ErrRefDenied.Error()+": ")
	msg = strings.Join(strings.Fields(msg), " ")
	return elide(msg)
}

// DecideAll evaluates every command.
//
// A push is atomic here whatever the client asked for: if any command is
// refused, none is forwarded. Partially applying a push would mean the sandbox
// discovers the allowlist by watching which half of its commands landed, and
// leaves the repository in a state neither side asked for.
func (p Policy) DecideAll(cmds []RefUpdate) ([]Decision, bool) {
	out := make([]Decision, 0, len(cmds))
	ok := true
	for _, c := range cmds {
		err := p.Decide(c)
		if err != nil {
			ok = false
		}
		out = append(out, Decision{Update: c, Err: err})
	}
	return out, ok
}

// ValidateRefName applies git's ref naming rules to a name arriving from a
// sandbox.
//
// The proxy forwards this string to a real git server, so a name that git
// would refuse must be refused here rather than passed along: the rules below
// are what stop "refs/heads/../../x" and "refs/heads/ --upload-pack=sh" from
// being this proxy's problem to reason about.
func ValidateRefName(ref string) error {
	switch {
	case ref == "":
		return errors.New("ref name is empty")
	case len(ref) > 1024:
		return fmt.Errorf("ref name is %d bytes, at most 1024 are allowed", len(ref))
	case !strings.HasPrefix(ref, "refs/"):
		return fmt.Errorf("ref name %q does not start with refs/", elide(ref))
	case strings.HasSuffix(ref, "/"), strings.HasSuffix(ref, "."):
		return fmt.Errorf("ref name %q ends with / or .", elide(ref))
	case strings.Contains(ref, ".."), strings.Contains(ref, "//"),
		strings.Contains(ref, "@{"), strings.Contains(ref, "\\"):
		return fmt.Errorf("ref name %q contains .., //, @{ or a backslash", elide(ref))
	}
	for i := 0; i < len(ref); i++ {
		switch c := ref[i]; {
		case c < 0x20, c == 0x7f:
			return fmt.Errorf("ref name %q contains a control character", elide(ref))
		case c == ' ', c == '~', c == '^', c == ':', c == '?', c == '*', c == '[':
			return fmt.Errorf("ref name %q contains %q, which git forbids", elide(ref), string(rune(c)))
		}
	}
	for _, comp := range strings.Split(ref, "/") {
		switch {
		case comp == "":
			return fmt.Errorf("ref name %q has an empty component", elide(ref))
		case strings.HasPrefix(comp, "."):
			return fmt.Errorf("ref name %q has a component starting with .", elide(ref))
		case strings.HasSuffix(comp, ".lock"):
			return fmt.Errorf("ref name %q has a component ending in .lock", elide(ref))
		}
	}
	return nil
}
