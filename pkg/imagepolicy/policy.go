// Package imagepolicy decides whether a container image may be used to execute
// a project's code, and pins the answer to a digest.
//
// # The hole it closes
//
// cloop's premise is that the hub never runs untrusted code on the host: every
// workload goes into a container or a Pod. A project's .cloop/sandbox.yaml can
// name the image that container is built from, and that file arrives by
// `git pull` — anyone who can open a pull request can propose one. Before this
// package, the only check on that name was that it was syntactically usable as
// an argv token. `image: evil.example/backdoor:latest` passed.
//
// An image is not data the sandbox processes; it is the sandbox. Its entrypoint,
// its libraries and its PATH are the environment the harness runs inside, and
// the credentials the hub injects at start are handed straight to it. An
// unverified image does not weaken the isolation boundary — it is on the trusted
// side of it, which puts the whole thing back where it started.
//
// # Shape
//
// Evaluate is pure. It takes a string and returns a decision, with no clock, no
// filesystem and no network. That is what makes the registry-confusion cases
// below testable as a table, and it is what lets the UI render the same verdict
// a run would get before any task has started. Everything impure — resolving a
// tag to a digest, shelling out to cosign — lives behind the Resolver and
// Verifier interfaces in enforce.go and is composed on top.
//
// # Deny by default
//
// A configured policy denies anything it does not explicitly allow. An
// *unconfigured* policy (Configured() false) allows everything, because turning
// on image trust must be a decision an operator makes, not one an upgrade makes
// for them by breaking every project that pins a tag.
package imagepolicy

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// Rule names identify which rule produced a denial. They appear in the error
// text, in the audit payload and in the API response, so they are stable
// strings rather than an enum whose numbering could shift.
const (
	// RuleSyntax: the reference is not a reference.
	RuleSyntax = "reference-syntax"
	// RuleUnqualified: the reference named no registry and the policy has no
	// default, so which registry it would come from is undecidable.
	RuleUnqualified = "unqualified-reference"
	// RuleRegistry: the registry is not on allowed_registries.
	RuleRegistry = "registry-allowlist"
	// RuleRepository: the repository is not on allowed_repos.
	RuleRepository = "repository-allowlist"
	// RuleDigest: require_digest is set and the reference is tag-only.
	RuleDigest = "digest-required"
	// RuleResolution: the reference had to be pinned and could not be.
	RuleResolution = "digest-resolution"
	// RuleSignature: require_signature is set and verification did not pass.
	RuleSignature = "signature-required"
	// RuleConfig: the policy itself is unusable.
	RuleConfig = "policy-configuration"
)

// ErrDenied is the class of every refusal, for callers that want errors.Is
// rather than a type assertion.
var ErrDenied = errors.New("imagepolicy: image denied by policy")

// Identity is one keyless-signing identity: a Fulcio certificate whose OIDC
// issuer matches Issuer and whose subject matches SubjectRegexp.
type Identity struct {
	// Issuer is the exact OIDC issuer URL, e.g.
	// "https://token.actions.githubusercontent.com".
	Issuer string `json:"issuer" yaml:"issuer"`
	// SubjectRegexp is a regular expression the certificate subject must
	// match, e.g. "^https://github\\.com/acme/.+".
	SubjectRegexp string `json:"subject_regexp" yaml:"subject_regexp"`
}

// Policy is the hub-wide image trust configuration.
//
// The zero Policy is not "deny everything" — it is "no policy", which allows
// everything. See Configured.
type Policy struct {
	// AllowedRegistries are the registry hosts a project may pull from.
	// Matching is on the parsed host, whole-string and case-insensitive. Two
	// forms beyond an exact host are accepted:
	//
	//	*.example.com   any subdomain of example.com, at a label boundary
	//	*               any registry (use with require_digest to constrain
	//	                provenance without constraining the source)
	//
	// Empty means this dimension is not constrained — a policy of nothing but
	// require_digest is a legitimate one ("I do not care where images come
	// from, but they must be immutable"), and reading an empty list as
	// deny-all would make it a hub that refuses every image. Validate refuses
	// the one combination where that reading would be a hole: a registry-less
	// allowed_repos entry with no allowed_registries constrains the path and
	// not the source.
	AllowedRegistries []string `json:"allowed_registries,omitempty" yaml:"allowed_registries,omitempty"`

	// AllowedRepos further narrows which repositories within those registries
	// are permitted. Empty means "any repository on an allowed registry".
	//
	// An entry may name a registry ("ghcr.io/acme/tools") or not
	// ("acme/tools"), in which case it applies within whichever registry
	// already passed AllowedRegistries. A trailing "/*" matches the prefix at
	// a path-component boundary.
	AllowedRepos []string `json:"allowed_repos,omitempty" yaml:"allowed_repos,omitempty"`

	// RequireDigest refuses any reference that is not already pinned to a
	// digest. Without it, a tag reference is still resolved and pinned where
	// the executor can do so — RequireDigest is what makes the *reference*
	// carry the pin, which is the only form that survives an executor with no
	// local image store to resolve against.
	RequireDigest bool `json:"require_digest,omitempty" yaml:"require_digest,omitempty"`

	// RequireSignature refuses any image whose signature cosign cannot verify
	// against CosignPublicKeys or CosignIdentities. Verification is on the
	// digest, never on a tag.
	RequireSignature bool `json:"require_signature,omitempty" yaml:"require_signature,omitempty"`

	// CosignPublicKeys are paths to public keys any one of which may carry the
	// signature (`cosign verify --key`).
	CosignPublicKeys []string `json:"cosign_public_keys,omitempty" yaml:"cosign_public_keys,omitempty"`

	// CosignIdentities are keyless identities any one of which may carry the
	// signature (`cosign verify --certificate-oidc-issuer …`).
	CosignIdentities []Identity `json:"cosign_identities,omitempty" yaml:"cosign_identities,omitempty"`

	// DefaultRegistry qualifies a reference that names no registry.
	//
	// Absent it, "alpine:3.20" is *denied* rather than assumed to be Docker
	// Hub. That is not pedantry: podman resolves an unqualified name against
	// unqualified-search-registries, which is host configuration the policy
	// cannot see, so the same reference can legitimately pull from different
	// registries on two executors in the same fleet. An operator who wants the
	// Docker convention writes it down here.
	DefaultRegistry string `json:"default_registry,omitempty" yaml:"default_registry,omitempty"`
}

// Configured reports whether this policy constrains anything.
//
// Only the allowlists and the two Require flags count. Cosign keys alone do
// not: a policy carrying keys but no RequireSignature has nothing to enforce,
// and treating it as configured would turn a half-finished edit into a hub that
// denies every image.
func (p Policy) Configured() bool {
	return len(p.AllowedRegistries) > 0 || len(p.AllowedRepos) > 0 ||
		p.RequireDigest || p.RequireSignature
}

// Normalize returns a copy with entries trimmed, lower-cased and de-duplicated.
// Evaluate calls it, so callers never have to; it is exported because the
// config layer wants to store the normalized form.
func (p Policy) Normalize() Policy {
	out := p
	out.AllowedRegistries = normalizeList(p.AllowedRegistries, strings.ToLower)
	out.AllowedRepos = normalizeList(p.AllowedRepos, strings.ToLower)
	out.CosignPublicKeys = normalizeList(p.CosignPublicKeys, nil)
	out.DefaultRegistry = strings.ToLower(strings.TrimSpace(p.DefaultRegistry))
	ids := make([]Identity, 0, len(p.CosignIdentities))
	for _, id := range p.CosignIdentities {
		id.Issuer = strings.TrimSpace(id.Issuer)
		id.SubjectRegexp = strings.TrimSpace(id.SubjectRegexp)
		if id.Issuer == "" && id.SubjectRegexp == "" {
			continue
		}
		ids = append(ids, id)
	}
	out.CosignIdentities = ids
	return out
}

func normalizeList(in []string, fold func(string) string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if fold != nil {
			s = fold(s)
		}
		if s == "" {
			continue
		}
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

// Validate reports a policy that cannot do what it says.
//
// It is separate from Evaluate because these are the operator's mistakes, not a
// project's: they must surface where the config was written, at `cloop config
// set` and at hub start, rather than as a denial on some project's first run.
func (p Policy) Validate() error {
	n := p.Normalize()

	for _, r := range n.AllowedRegistries {
		if r == "*" {
			continue
		}
		host := strings.TrimPrefix(r, "*.")
		if host == "" || host == r && strings.Contains(r, "*") {
			return fmt.Errorf("allowed_registries entry %q: a wildcard is only valid as "+
				"\"*\" or a leading \"*.\" label", r)
		}
		if strings.Contains(host, "*") {
			return fmt.Errorf("allowed_registries entry %q: a wildcard is only valid as "+
				"\"*\" or a leading \"*.\" label", r)
		}
		if strings.Contains(host, "/") {
			return fmt.Errorf("allowed_registries entry %q names a path; registries are "+
				"hosts — put %q in allowed_repos instead", r, r)
		}
		if err := validateRegistryHost(host); err != nil {
			return fmt.Errorf("allowed_registries entry %q: %w", r, err)
		}
	}

	for _, repo := range n.AllowedRepos {
		registry, _, err := parseRepoPattern(repo)
		if err != nil {
			return fmt.Errorf("allowed_repos entry %q: %w", repo, err)
		}
		// The one place an empty allowed_registries would be a hole rather
		// than a deliberate non-constraint: "acme/tools" with nothing
		// constraining the host allows evil.example/acme/tools, which reads
		// exactly like the intended rule and is not it.
		if registry == "" && len(n.AllowedRegistries) == 0 {
			return fmt.Errorf("allowed_repos entry %q names no registry and "+
				"allowed_registries is empty, so it would allow that path on *any* "+
				"registry — qualify it (e.g. ghcr.io/%s) or set allowed_registries", repo, repo)
		}
	}

	if n.DefaultRegistry != "" {
		if strings.Contains(n.DefaultRegistry, "/") || strings.Contains(n.DefaultRegistry, "*") {
			return fmt.Errorf("default_registry %q must be a bare registry host", n.DefaultRegistry)
		}
		if err := validateRegistryHost(n.DefaultRegistry); err != nil {
			return fmt.Errorf("default_registry %q: %w", n.DefaultRegistry, err)
		}
	}

	// Requiring a signature with nothing to check it against would deny every
	// image with a message about cosign, sending the operator to debug their
	// installation rather than their config.
	if n.RequireSignature && len(n.CosignPublicKeys) == 0 && len(n.CosignIdentities) == 0 {
		return errors.New("require_signature is set but neither cosign_public_keys nor " +
			"cosign_identities is configured — there is nothing to verify against")
	}
	for i, id := range n.CosignIdentities {
		if id.Issuer == "" {
			return fmt.Errorf("cosign_identities[%d]: issuer is required", i)
		}
		if id.SubjectRegexp == "" {
			return fmt.Errorf("cosign_identities[%d]: subject_regexp is required — an issuer "+
				"alone would trust every workflow at that provider", i)
		}
		if _, err := compileIdentity(id); err != nil {
			return fmt.Errorf("cosign_identities[%d]: %w", i, err)
		}
	}
	return nil
}

// Fingerprint is a stable hash of the fields that affect a verdict. It keys the
// signature-verification cache, so a policy edit invalidates it rather than
// letting a run inherit a verdict reached under the previous rules.
func (p Policy) Fingerprint() string {
	n := p.Normalize()
	var b strings.Builder
	fmt.Fprintf(&b, "registries=%s\n", strings.Join(n.AllowedRegistries, ","))
	repos := append([]string(nil), n.AllowedRepos...)
	sort.Strings(repos)
	fmt.Fprintf(&b, "repos=%s\n", strings.Join(repos, ","))
	fmt.Fprintf(&b, "digest=%t\nsignature=%t\ndefault=%s\n",
		n.RequireDigest, n.RequireSignature, n.DefaultRegistry)
	fmt.Fprintf(&b, "keys=%s\n", strings.Join(n.CosignPublicKeys, ","))
	for _, id := range n.CosignIdentities {
		fmt.Fprintf(&b, "identity=%s|%s\n", id.Issuer, id.SubjectRegexp)
	}
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:8])
}

// Decision is the verdict on one reference.
//
// It is returned whether or not the reference was allowed, so a UI can render
// "this would be refused, because X" without catching an error, and an audit
// row can record the same fields the operator was shown.
type Decision struct {
	// Ref is the parsed, normalized reference. Zero when parsing failed.
	Ref Reference `json:"ref"`
	// Allowed is the verdict.
	Allowed bool `json:"allowed"`
	// Rule names the rule that decided. On an allow it is empty; on a denial
	// it is one of the Rule* constants.
	Rule string `json:"rule,omitempty"`
	// Reason states what was observed, in the operator's terms.
	Reason string `json:"reason,omitempty"`
	// Remediation states what to do about it.
	Remediation string `json:"remediation,omitempty"`
	// NeedsPin is true for an allowed reference that is not digest-pinned.
	// The executor must resolve and pin it before running; see Enforcer.
	NeedsPin bool `json:"needs_pin,omitempty"`
	// NeedsSignature is true when the policy requires cosign verification of
	// this image. Evaluate does not perform it — it is impure.
	NeedsSignature bool `json:"needs_signature,omitempty"`
	// PolicyActive reports whether any rule was applied at all.
	PolicyActive bool `json:"policy_active"`
}

// Err returns a *DenyError for a refused decision, nil for an allowed one.
func (d Decision) Err() error {
	if d.Allowed {
		return nil
	}
	return &DenyError{
		Ref:         d.Ref.Original,
		Rule:        d.Rule,
		Reason:      d.Reason,
		Remediation: d.Remediation,
	}
}

// DenyError is a refusal, carrying the rule that produced it.
//
// It is typed for the reason every other refusal in cloop is: the developer who
// wrote the image reference and the operator who owns the allowlist are
// different people, and the error has to give the first enough to file a useful
// request to the second.
type DenyError struct {
	Ref         string
	Rule        string
	Reason      string
	Remediation string
}

// Error implements error.
func (e *DenyError) Error() string {
	msg := fmt.Sprintf("image %q is refused by the hub's image trust policy (rule: %s): %s",
		e.Ref, e.Rule, e.Reason)
	if e.Remediation != "" {
		msg += " " + e.Remediation
	}
	return msg
}

// Is makes errors.Is(err, ErrDenied) true for every refusal.
func (e *DenyError) Is(target error) bool { return target == ErrDenied }

// Malformed reports a refusal caused by the reference not being a reference,
// as opposed to one caused by a rule the operator configured.
//
// The distinction decides who is being told to do something. A malformed
// reference is a broken file whose author can fix it alone — the drivers map it
// onto executor.ErrInvalidSpec, which the API renders as 400. Every other rule
// is a well-formed request that conflicts with the hub's configuration, which
// is a 409 and may need an operator.
func (e *DenyError) Malformed() bool { return e.Rule == RuleSyntax }

// Evaluate decides whether ref may be used. It is pure.
//
// An unconfigured policy allows any *syntactically valid* reference: even with
// no rules, a string that is not a reference is refused, because it would fail
// later in a runtime's argv with a far worse message.
func (p Policy) Evaluate(ref string) (Decision, error) {
	n := p.Normalize()
	active := n.Configured()

	parsed, err := ParseReference(ref)
	if err != nil {
		d := deny(RuleSyntax, err.Error(),
			"Write the image as registry/repository:tag or registry/repository@sha256:….")
		d.Ref = Reference{Original: ref}
		d.PolicyActive = active
		return d, d.Err()
	}
	parsed.Original = ref

	d := Decision{Ref: parsed, Allowed: true, PolicyActive: active}

	if !parsed.Qualified {
		switch {
		case n.DefaultRegistry != "":
			parsed.Registry = n.DefaultRegistry
			if parsed.Registry == DockerHub && !strings.Contains(parsed.Repository, "/") {
				parsed.Repository = "library/" + parsed.Repository
			}
			d.Ref = parsed
		case active:
			// Deny rather than guess. Which registry this resolves to is the
			// executor host's configuration, so allowing it would mean the
			// allowlist governs a name and not a source.
			return denyRef(parsed, active, RuleUnqualified,
				fmt.Sprintf("%q names no registry, so which registry it would be pulled from "+
					"depends on the executor host's configuration rather than on this policy", ref),
				fmt.Sprintf("Fully qualify it, e.g. %s/%s, or set sandbox.image_policy."+
					"default_registry on the hub.", DockerHub, parsed.Repository))
		}
	}

	if !active {
		// No rules to apply. NeedsPin is still reported: pinning a tag is
		// worth doing whether or not an allowlist exists, and the executor
		// uses this flag to decide whether to resolve.
		d.NeedsPin = !parsed.Pinned()
		return d, nil
	}

	if len(n.AllowedRegistries) > 0 && !matchRegistry(parsed.Registry, n.AllowedRegistries) {
		return denyRef(parsed, active, RuleRegistry,
			fmt.Sprintf("registry %q is not on the allowlist (allowed: %s)",
				parsed.Registry, listOrNone(n.AllowedRegistries)),
			fmt.Sprintf("Publish the image to an allowed registry, or ask an operator to add "+
				"%q to sandbox.image_policy.allowed_registries.", parsed.Registry))
	}

	if len(n.AllowedRepos) > 0 && !matchRepo(parsed, n.AllowedRepos) {
		return denyRef(parsed, active, RuleRepository,
			fmt.Sprintf("repository %q is not on the allowlist (allowed: %s)",
				parsed.Name(), listOrNone(n.AllowedRepos)),
			fmt.Sprintf("Ask an operator to add %q to sandbox.image_policy.allowed_repos.",
				parsed.Name()))
	}

	if n.RequireDigest && !parsed.Pinned() {
		return denyRef(parsed, active, RuleDigest,
			fmt.Sprintf("%q is pinned to a tag, and this hub requires a digest", ref),
			"Pin the image by digest — `docker buildx imagetools inspect "+parsed.Name()+
				":"+orDefault(parsed.Tag, "latest")+"` prints it — and write it as "+
				parsed.Name()+"@sha256:….")
	}

	d.Ref = parsed
	d.NeedsPin = !parsed.Pinned()
	d.NeedsSignature = n.RequireSignature
	return d, nil
}

func deny(rule, reason, remediation string) Decision {
	return Decision{Rule: rule, Reason: reason, Remediation: remediation}
}

func denyRef(ref Reference, active bool, rule, reason, remediation string) (Decision, error) {
	d := deny(rule, reason, remediation)
	d.Ref = ref
	d.PolicyActive = active
	return d, d.Err()
}

// matchRegistry compares a parsed host against the allowlist.
//
// Whole-string, or a "*."-prefixed pattern matched at a label boundary. Both of
// the confusion cases fall out of this: "docker.io.evil.com" is not equal to
// "docker.io" and does not end in ".docker.io", and "evil.com/docker.io/foo"
// never reaches here with "docker.io" as its host because the parser put that
// string in the repository.
func matchRegistry(host string, allowed []string) bool {
	if host == "" {
		return false
	}
	for _, pattern := range allowed {
		if pattern == "*" {
			return true
		}
		if suffix, ok := strings.CutPrefix(pattern, "*."); ok {
			if strings.HasSuffix(host, "."+suffix) {
				return true
			}
			continue
		}
		if host == pattern {
			return true
		}
	}
	return false
}

// matchRepo compares a parsed reference against the repository allowlist.
func matchRepo(ref Reference, allowed []string) bool {
	for _, pattern := range allowed {
		registry, path, err := parseRepoPattern(pattern)
		if err != nil {
			// Validate rejects these at config time; a malformed entry that
			// got in anyway must not match, or a typo would widen the policy.
			continue
		}
		if registry != "" && registry != ref.Registry {
			continue
		}
		if prefix, ok := strings.CutSuffix(path, "/*"); ok {
			if ref.Repository == prefix || strings.HasPrefix(ref.Repository, prefix+"/") {
				return true
			}
			continue
		}
		if ref.Repository == path {
			return true
		}
	}
	return false
}

// parseRepoPattern splits an allowed_repos entry into an optional registry and
// a repository path, using the same domain heuristic references use so an
// entry means the same thing as the reference it is meant to match.
func parseRepoPattern(pattern string) (registry, path string, err error) {
	pattern = strings.TrimSpace(strings.ToLower(pattern))
	if pattern == "" {
		return "", "", errors.New("the entry is empty")
	}
	domain, remainder := splitDomain(pattern)
	if domain != "" {
		normalized, nerr := normalizeRegistry(domain)
		if nerr != nil {
			return "", "", nerr
		}
		registry = normalized
	}
	if remainder == "" {
		return "", "", errors.New("the entry names a registry but no repository")
	}
	// The trailing "/*" is the only wildcard; anything else would let a
	// pattern match across a component boundary, which is the same class of
	// mistake as a substring match.
	check := strings.TrimSuffix(remainder, "/*")
	if strings.Contains(check, "*") {
		return "", "", errors.New("a wildcard is only valid as a trailing \"/*\"")
	}
	if err := validateRepository(check); err != nil {
		return "", "", err
	}
	// Docker Hub's shorthand again, so "library/alpine" and an entry of
	// "docker.io/alpine" agree.
	if registry == DockerHub && !strings.Contains(check, "/") {
		remainder = "library/" + remainder
	}
	return registry, remainder, nil
}

func listOrNone(in []string) string {
	if len(in) == 0 {
		return "none"
	}
	return strings.Join(in, ", ")
}

func orDefault(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}
