package secretbroker

import (
	"fmt"
	"path"
	"reflect"
	"slices"
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
	// Branches narrows where a github_pat or github_app grant may push:
	// branch-name globs such as "cloop/*", "feature/**" or "develop". Empty
	// means the grant adds no branch restriction of its own, and the hub's git
	// proxy policy (executors.git_proxy.allowed_refs) is the only limit.
	//
	// Only a grant that authorises a push may carry one — a branch list on a
	// read-only grant restricts nothing and would read as though it did — and
	// it restricts branches only: a push of a tag, or of any other ref, is
	// outside every branch list.
	//
	// Nothing inside a sandbox can enforce this, because git's credential
	// protocol never says which ref a push is for. The git proxy can, since it
	// reads every pushed command before forwarding it; see pkg/gitproxy
	// Policy.RestrictRefs. Where no proxy guards the grant, the broker withholds
	// the grant's write authority rather than deliver a credential that would
	// ignore the list: see RestrictsBranches.
	Branches []string `json:"branches,omitempty"`
	// Namespaces is the Kubernetes namespace allowlist for kubeconfig.
	Namespaces []string `json:"namespaces,omitempty"`
	// Contexts is the kubeconfig context allowlist. The delivered
	// kubeconfig contains only these contexts.
	Contexts []string `json:"contexts,omitempty"`
	// Verbs is the RBAC verb allowlist for a kubeconfig grant: what the
	// holder may *do* to the cluster, as opposed to which parts of it the
	// other two fields let them see.
	//
	// Empty means read-only — get, list and watch — which is the answer to
	// "an operator granted a cluster and said nothing about writes". It is
	// the one place in this struct where an empty list is neither "allow all"
	// nor a validation error, and the asymmetry is deliberate: the safe
	// reading of silence about a cluster credential is that nobody asked for
	// the ability to change anything.
	//
	// Unlike Namespaces and Contexts, this cannot be enforced by rewriting
	// the kubeconfig — a kubeconfig has no field for it. It is enforced by
	// pkg/kubeguard, the monitor the hub runs outside the sandbox, and it
	// therefore only takes effect when executors.kube_guard is enabled.
	// KubeconfigGuarded reports whether that is so for a given grant, and the
	// Secrets panel renders the difference rather than letting a grant claim
	// an enforcement that is not running.
	Verbs []string `json:"verbs,omitempty"`
	// Hosts is the allowed-host list for egress_proxy. A leading "*."
	// matches subdomains only, not the bare domain.
	Hosts []string `json:"hosts,omitempty"`
	// Registries is the container-registry allowlist for registry secrets.
	Registries []string `json:"registries,omitempty"`
	// EnvKeys restricts which keys of an env secret are delivered. Empty
	// means every key in the secret, which is safe because an env secret's
	// keys *are* its scope — there is nothing wider to fall open to.
	EnvKeys []string `json:"env_keys,omitempty"`
	// Devices is the device-name allowlist for host_device. Patterns match
	// case-sensitively against the inventory's handles; "*" alone allows
	// every device in the inventory.
	//
	// Case-sensitive for the reason the local_repo matcher is: these names
	// are chosen by an operator and matched exactly, and folding would make a
	// grant on "gpu0" also open "GPU0" — which, if both existed, would be two
	// different pieces of hardware nobody named.
	Devices []string `json:"devices,omitempty"`
	// Interfaces is the interface-name allowlist for host_interface. Patterns
	// match case-sensitively against the inventory's handles, exactly as
	// Devices does and for the same reason; "*" alone allows every interface
	// in the inventory.
	Interfaces []string `json:"interfaces,omitempty"`
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

// MaxBranchPatterns bounds a grant's branch allowlist. A handful is the real
// shape; the bound exists because the proxy matches every pushed ref against
// every pattern, and a caller should not get to choose how large that is.
const MaxBranchPatterns = 32

// branchRefPrefix is the namespace a branch allowlist lives in.
const branchRefPrefix = "refs/heads/"

// validateBranchPattern checks one entry of a branch allowlist.
//
// The rules are git's own branch-naming rules applied to a glob, plus the
// matching semantics pkg/gitproxy enforces with — so a pattern that is accepted
// here is one the proxy reads the way the operator meant, and one git could
// actually push to:
//
//   - a narrower charset than git allows. Branch names with other characters
//     exist, but this list is rendered into environment variables, prompts and
//     comma-separated form fields, and a comma or a quote in a pattern would
//     turn one entry into two in some of those places.
//   - no empty, dot-leading or ".lock"-suffixed component, no "..", and no
//     leading "-": the forms git refuses, so a pattern built from them could
//     never match a branch that exists.
//   - "**" only as a whole final component. pkg/gitproxy gives "/**" its "any
//     depth" meaning only at the end; anywhere else path.Match would read it as
//     two single-level stars, which is not what anyone typing it means.
//
// A "refs/heads/" prefix is accepted and means the same thing as its absence;
// any other ref namespace is refused, because the field is a *branch* list and
// a tag pattern in it would be a restriction the operator never sees rendered
// as one.
func validateBranchPattern(raw string) error {
	p := strings.TrimSpace(raw)
	switch {
	case p == "":
		return fmt.Errorf("%w: branches contains an empty pattern", ErrInvalidConstraint)
	case len(p) > 200:
		return fmt.Errorf("%w: branch pattern %q exceeds 200 characters", ErrInvalidConstraint, p)
	}
	name := strings.TrimPrefix(p, branchRefPrefix)
	if strings.HasPrefix(name, "refs/") {
		return fmt.Errorf("%w: branch pattern %q names a ref outside refs/heads/ — this list restricts "+
			"branches only", ErrInvalidConstraint, p)
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '-', r == '_', r == '.', r == '/', r == '*', r == '?':
		default:
			return fmt.Errorf("%w: branch pattern %q contains %q; use letters, digits, '-', '_', '.', "+
				"'/', and the wildcards '*' and '?'", ErrInvalidConstraint, p, string(r))
		}
	}
	if strings.Contains(name, "..") || strings.HasSuffix(name, ".") {
		return fmt.Errorf("%w: branch pattern %q contains \"..\" or ends with \".\", which git forbids "+
			"in a branch name", ErrInvalidConstraint, p)
	}
	comps := strings.Split(name, "/")
	for i, c := range comps {
		switch {
		case c == "":
			return fmt.Errorf("%w: branch pattern %q has an empty path component", ErrInvalidConstraint, p)
		case strings.HasPrefix(c, "."), strings.HasSuffix(c, ".lock"):
			return fmt.Errorf("%w: branch pattern %q has a component git forbids (leading \".\" or "+
				"\".lock\" suffix)", ErrInvalidConstraint, p)
		case i == 0 && strings.HasPrefix(c, "-"):
			return fmt.Errorf("%w: branch pattern %q starts with \"-\", which git forbids", ErrInvalidConstraint, p)
		case strings.Contains(c, "**") && (c != "**" || i != len(comps)-1):
			return fmt.Errorf("%w: branch pattern %q uses \"**\" inside a name; it is only meaningful as the "+
				"whole last component (\"release/**\" is every branch below release/)", ErrInvalidConstraint, p)
		}
	}
	// path.Match is the last word on the rest of the syntax, applied the way
	// pkg/gitproxy applies it: with a trailing "/**" set aside.
	probe := strings.TrimSuffix(branchRefPrefix+name, "/**")
	if _, err := path.Match(probe, "refs/heads/probe"); err != nil {
		return fmt.Errorf("%w: branch pattern %q is malformed: %v", ErrInvalidConstraint, p, err)
	}
	return nil
}

// validateBranches applies validateBranchPattern to a whole list and bounds it.
func validateBranches(ps []string) error {
	if len(ps) > MaxBranchPatterns {
		return fmt.Errorf("%w: %d branch patterns, at most %d are allowed",
			ErrInvalidConstraint, len(ps), MaxBranchPatterns)
	}
	for _, p := range ps {
		if err := validateBranchPattern(p); err != nil {
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
	if err := validatePatterns("devices", c.Devices); err != nil {
		return err
	}
	if err := validatePatterns("interfaces", c.Interfaces); err != nil {
		return err
	}
	for _, k := range c.EnvKeys {
		if err := validateEnvKey(k); err != nil {
			return err
		}
	}
	if err := validateBranches(c.Branches); err != nil {
		return err
	}

	switch kind {
	case KindGitHubPAT, KindGitHubApp:
		if len(c.Repos) == 0 {
			return fmt.Errorf(
				"%w: a %s grant needs a repository allowlist (--repos org/*, or --repos '*' to allow all)",
				ErrInvalidConstraint, kind)
		}
		// A branch list says where a push may go, so on a grant that
		// authorises no push it would describe a permission that does not
		// exist. Refused rather than ignored: an operator who wrote one
		// believes they granted something, and the place to find out
		// otherwise is here, not in a sandbox that cannot push.
		//
		// The test is the one the git guard applies to decide whether a
		// session may push at all, so the two cannot disagree about what
		// "authorises a push" means.
		if len(c.Branches) > 0 && !c.AllowsPermission("contents:write") {
			return fmt.Errorf(
				"%w: a branch allowlist limits where a grant may push, and this %s grant authorises "+
					"no push — add contents:write to --permissions, or drop --branches",
				ErrInvalidConstraint, kind)
		}
		if kind == KindGitHubApp {
			// A github_app grant's permissions are sent to GitHub verbatim, so
			// their syntax has a right answer and a typo has a consequence:
			// GitHub answers "pull_requests:maybe" with a 422 at lease time,
			// inside someone else's run. Checked here, in front of the operator
			// who wrote it. github_pat permissions stay free-form because
			// nothing transmits them — AllowsPermission is the only reader.
			if _, err := GitHubAppPermissions(c); err != nil {
				return err
			}
		}
	case KindKubeconfig:
		if len(c.Namespaces) == 0 && len(c.Contexts) == 0 {
			return fmt.Errorf(
				"%w: a kubeconfig grant needs --namespaces and/or --contexts",
				ErrInvalidConstraint)
		}
		for _, v := range c.Verbs {
			if !knownKubeVerb(v) {
				return fmt.Errorf(
					"%w: %q is not a Kubernetes verb; use one or more of %s, or omit --verbs "+
						"for read-only access",
					ErrInvalidConstraint, v, strings.Join(kubeVerbOrder, ", "))
			}
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
	case KindHostDevice:
		if len(c.Devices) == 0 {
			return fmt.Errorf(
				"%w: a host_device grant needs a device allowlist (--devices serial0, or --devices '*' for every device in the inventory)",
				ErrInvalidConstraint)
		}
	case KindHostInterface:
		if len(c.Interfaces) == 0 {
			return fmt.Errorf(
				"%w: a host_interface grant needs an interface allowlist (--interfaces dut, or --interfaces '*' for every interface in the inventory)",
				ErrInvalidConstraint)
		}
	case KindEnv:
		// EnvKeys may be empty: an env secret's own keys bound it.
	}
	if c.Writable && kind != KindLocalRepo && kind != KindHostDevice {
		return fmt.Errorf(
			"%w: writable applies to local_repo and host_device grants, not %s",
			ErrInvalidConstraint, kind)
	}
	if len(c.Devices) > 0 && kind != KindHostDevice {
		return fmt.Errorf(
			"%w: a device allowlist applies to host_device grants, not %s",
			ErrInvalidConstraint, kind)
	}
	if len(c.Interfaces) > 0 && kind != KindHostInterface {
		return fmt.Errorf(
			"%w: an interface allowlist applies to host_interface grants, not %s",
			ErrInvalidConstraint, kind)
	}
	if len(c.Verbs) > 0 && kind != KindKubeconfig {
		return fmt.Errorf(
			"%w: a verb allowlist applies to kubeconfig grants, not %s",
			ErrInvalidConstraint, kind)
	}
	if len(c.Branches) > 0 && kind != KindGitHubPAT && kind != KindGitHubApp {
		return fmt.Errorf(
			"%w: a branch allowlist applies to github_pat and github_app grants, not %s",
			ErrInvalidConstraint, kind)
	}
	return nil
}

// RestrictsBranches reports whether this grant's pushes are limited to a
// branch allowlist.
//
// It is the question every delivery path has to answer before handing over a
// credential that can write, because the answer decides whether the credential
// may leave the hub at all. A restricted grant is only ever honoured through
// the git proxy; where there is none, the broker withholds the write rather
// than deliver a credential that would ignore the list.
func (c Constraints) RestrictsBranches() bool {
	return len(c.Branches) > 0 && c.AllowsPermission("contents:write")
}

// BranchRefPatterns renders the branch allowlist as full ref patterns, the form
// pkg/gitproxy matches pushed refs against: "cloop/*" becomes
// "refs/heads/cloop/*", and an entry already written with the prefix is kept
// as it is.
func (c Constraints) BranchRefPatterns() []string {
	if len(c.Branches) == 0 {
		return nil
	}
	out := make([]string, 0, len(c.Branches))
	for _, b := range c.Branches {
		b = strings.TrimSpace(b)
		if b == "" {
			continue
		}
		if !strings.HasPrefix(b, branchRefPrefix) {
			b = branchRefPrefix + b
		}
		out = append(out, b)
	}
	return out
}

// BranchNames is the allowlist without the refs/heads/ prefix, the form a
// person types and reads.
func (c Constraints) BranchNames() []string {
	if len(c.Branches) == 0 {
		return nil
	}
	out := make([]string, 0, len(c.Branches))
	for _, b := range c.Branches {
		if b = strings.TrimPrefix(strings.TrimSpace(b), branchRefPrefix); b != "" {
			out = append(out, b)
		}
	}
	return out
}

// kubeVerbOrder is the RBAC verb set, in the order an operator reads it.
//
// Spelled out here rather than imported from pkg/kubeguard because that
// package parses a kubeconfig with pkg/executor/kubernetes, which imports
// this one — so the dependency can only run one way. The lists agreeing is a
// correctness requirement rather than a coincidence, and
// pkg/kubeguard/constraints_test.go asserts it from the side that is allowed
// to see both.
var kubeVerbOrder = []string{
	"get", "list", "watch", "create", "update", "patch", "delete", "deletecollection",
}

// kubeReadVerbs are the verbs that only read. The empty Verbs list means
// exactly this set; see the field comment.
var kubeReadVerbs = []string{"get", "list", "watch"}

func knownKubeVerb(v string) bool {
	want := strings.ToLower(strings.TrimSpace(v))
	for _, k := range kubeVerbOrder {
		if k == want {
			return true
		}
	}
	return false
}

// KubeVerbs returns the effective verb allowlist for a kubeconfig grant,
// resolving the empty list to read-only.
//
// Callers must use this rather than reading Verbs directly, because the two
// differ in exactly the case that matters: a grant nobody configured.
func (c Constraints) KubeVerbs() []string {
	if len(c.Verbs) == 0 {
		return append([]string(nil), kubeReadVerbs...)
	}
	out := make([]string, 0, len(c.Verbs))
	for _, v := range c.Verbs {
		out = append(out, strings.ToLower(strings.TrimSpace(v)))
	}
	return out
}

// KubeReadOnly reports whether the grant's effective verbs only read. It is
// what the UI badges and the audit summary render.
func (c Constraints) KubeReadOnly() bool {
	for _, v := range c.KubeVerbs() {
		switch v {
		case "get", "list", "watch":
		default:
			return false
		}
	}
	return true
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
	add("branches", c.Branches)
	add("ns", c.Namespaces)
	add("ctx", c.Contexts)
	add("verbs", c.Verbs)
	add("hosts", c.Hosts)
	add("registries", c.Registries)
	add("env", c.EnvKeys)
	add("devices", c.Devices)
	add("interfaces", c.Interfaces)
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

// ---------------------------------------------------------------------------
// supersession: does a replacement allow everything the original did?
// ---------------------------------------------------------------------------

// Covers reports whether c allows at least everything old allows and, when it
// does not, names the first dimension that narrows.
//
// It decides whether a grant replacing old may stand for the material a
// running workload already holds under old (Task 20403). Keeping that material
// on c's authority is safe only if c would have delivered it too — otherwise
// an edit that narrows a grant would narrow every run but the ones running.
// So the proof is literal: every pattern old lists, c lists as well, or c lifts
// the restriction altogether. It never compares what two different patterns
// match, which makes it conservative in one direction only: an edit that
// widens by rewriting a pattern ("cloop/a" into "cloop/*") reads as one that
// narrows, and the old grant is withdrawn rather than kept. Never the reverse.
func (c Constraints) Covers(old Constraints) (bool, string) {
	for _, l := range []struct {
		name       string
		old, next  []string
		emptyIsAll bool // an empty list restricts nothing
		fold       bool // the dimension matches case-insensitively
	}{
		{"repos", old.Repos, c.Repos, false, true},
		{"branches", old.Branches, c.Branches, true, false},
		{"namespaces", old.Namespaces, c.Namespaces, false, false},
		{"contexts", old.Contexts, c.Contexts, false, false},
		{"verbs", old.KubeVerbs(), c.KubeVerbs(), false, false},
		{"hosts", old.Hosts, c.Hosts, false, false},
		{"registries", old.Registries, c.Registries, false, false},
		{"env_keys", old.EnvKeys, c.EnvKeys, true, false},
		{"devices", old.Devices, c.Devices, false, false},
		{"interfaces", old.Interfaces, c.Interfaces, false, false},
	} {
		if !listCovers(l.next, l.old, l.emptyIsAll, l.fold) {
			return false, l.name
		}
	}
	if !permissionsCover(c.Permissions, old.Permissions) {
		return false, "permissions"
	}
	if old.Writable && !c.Writable {
		return false, "writable"
	}
	// A dimension added to Constraints after this was written is compared
	// whole: the same, or it narrows.
	a, b := old, c
	for _, z := range []*Constraints{&a, &b} {
		z.Repos, z.Permissions, z.Branches, z.Namespaces, z.Contexts, z.Verbs = nil, nil, nil, nil, nil, nil
		z.Hosts, z.Registries, z.EnvKeys, z.Devices, z.Interfaces, z.Writable = nil, nil, nil, nil, nil, false
	}
	if !reflect.DeepEqual(a, b) {
		return false, "constraints"
	}
	return true, ""
}

// listCovers reports whether the allowlist next admits everything old does, by
// literal inclusion. emptyIsAll marks a dimension where an empty list restricts
// nothing; elsewhere an empty list means what the secret's kind makes of it, so
// only another empty list is known to mean the same.
func listCovers(next, old []string, emptyIsAll, fold bool) bool {
	if emptyIsAll && len(next) == 0 {
		return true
	}
	if len(old) == 0 || len(next) == 0 {
		return len(old) == 0 && len(next) == 0
	}
	for _, o := range old {
		o = strings.TrimSpace(o)
		if !slices.ContainsFunc(next, func(n string) bool {
			n = strings.TrimSpace(n)
			if fold {
				return strings.EqualFold(n, o)
			}
			return n == o
		}) {
			return false
		}
	}
	return true
}

// permissionsCover reports whether next grants every permission old does: "*"
// covers everything, a bare scope ("contents") covers its levels, and a level
// covers itself and the levels GitHub ranks below it — "contents:write" can
// read, as the token it mints and the git proxy's read-only switch both treat
// it (permissionRank). An unranked level covers only itself.
func permissionsCover(next, old []string) bool {
	if len(old) == 0 || len(next) == 0 {
		return len(old) == 0 && len(next) == 0
	}
	for _, p := range old {
		p = strings.ToLower(strings.TrimSpace(p))
		scope, level, leveled := strings.Cut(p, ":")
		if !slices.ContainsFunc(next, func(n string) bool {
			n = strings.ToLower(strings.TrimSpace(n))
			if n == "*" || n == p || (leveled && n == scope) {
				return true
			}
			nScope, nLevel, ok := strings.Cut(n, ":")
			return leveled && ok && nScope == scope && permissionRank(nLevel) > permissionRank(level) &&
				permissionRank(level) > 0
		}) {
			return false
		}
	}
	return true
}
