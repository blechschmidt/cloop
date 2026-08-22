package imagepolicy

// reference.go is a parser for OCI image references.
//
// # Why this exists rather than a substring check
//
// Every rule in policy.go matches on the *parsed* reference, and that is the
// whole security property. A registry allowlist implemented with
// strings.Contains admits both of these:
//
//	evil.com/docker.io/foo      the allowed name appears as a repository path
//	docker.io.evil.com/foo      the allowed name appears as a domain prefix
//
// Both pull from evil.com. Neither is exotic — they are the first two things
// anyone tries. Only a parser that knows where the registry ends can tell them
// apart, so the reference is split into (registry, repository, tag, digest)
// before any comparison happens, and comparisons are on whole components.
//
// # Why not a dependency
//
// distribution/reference is the canonical implementation and it is a fine
// library. cloop has kept its dependency list to five modules, and a trust
// boundary is the last place to add a transitive tree that is not read. The
// grammar below is the same one, deliberately *stricter* in the three places
// where strictness costs nothing and leniency costs provenance: digests must
// name a known algorithm at its exact length, the whole reference must be
// ASCII, and an unqualified name is not silently assigned a registry.

import (
	"errors"
	"fmt"
	"strings"
)

// MaxRefLen bounds a reference. Real ones are well under 200 bytes; the limit
// exists so a malformed spec cannot hand megabytes to a runtime's argv.
const MaxRefLen = 512

// DockerHub is the canonical spelling of Docker Hub's registry host.
const DockerHub = "docker.io"

// dockerHubAliases are the other names for the same registry. They are folded
// to DockerHub so an allowlist entry of "docker.io" covers every spelling of
// it — an operator who allowed Docker Hub allowed Docker Hub, and being made
// to enumerate its aliases would produce a policy with a hole in it.
var dockerHubAliases = map[string]string{
	"docker.io":            DockerHub,
	"index.docker.io":      DockerHub,
	"registry-1.docker.io": DockerHub,
}

// ErrBadReference is the class of every parse failure, so a caller that only
// wants "this is not a reference" does not match on message text.
var ErrBadReference = errors.New("imagepolicy: malformed image reference")

// Reference is a parsed image reference.
//
// Registry and Repository are the two fields policy matching uses, and they are
// only ever set from the parse — there is no path that assigns them from a
// prefix or a suffix of the original string.
type Reference struct {
	// Original is the reference exactly as supplied.
	Original string `json:"original"`
	// Registry is the normalized host[:port]. Empty when the reference named
	// no registry and no default was applied — see Qualified.
	Registry string `json:"registry,omitempty"`
	// Repository is the path below the registry, e.g. "library/alpine".
	Repository string `json:"repository"`
	// Tag is the tag, empty for a digest-only reference.
	Tag string `json:"tag,omitempty"`
	// Digest is the "sha256:…" content digest, empty when the reference is
	// tag-only.
	Digest string `json:"digest,omitempty"`
	// Qualified reports whether the *reference itself* named a registry.
	// False means the registry, if any, came from Policy.DefaultRegistry.
	Qualified bool `json:"qualified"`
}

// Name is "registry/repository", the identity a signature is made over.
func (r Reference) Name() string {
	if r.Registry == "" {
		return r.Repository
	}
	return r.Registry + "/" + r.Repository
}

// Canonical is the strongest form of this reference: "registry/repo@digest".
// Empty when there is no digest, because there is then no canonical form —
// and returning the tag would let a caller believe it had pinned something.
func (r Reference) Canonical() string {
	if r.Digest == "" {
		return ""
	}
	return r.Name() + "@" + r.Digest
}

// String re-renders the reference from its parts. It round-trips a qualified
// reference exactly and differs from Original only where normalization applied
// (host case folding, a Docker Hub alias, an added default registry).
func (r Reference) String() string {
	var b strings.Builder
	b.WriteString(r.Name())
	if r.Tag != "" {
		b.WriteString(":")
		b.WriteString(r.Tag)
	}
	if r.Digest != "" {
		b.WriteString("@")
		b.WriteString(r.Digest)
	}
	return b.String()
}

// Pinned reports whether this reference names an exact artifact. A tag never
// does: it is a mutable pointer, and the registry is free to repoint it
// between the moment a policy accepted it and the moment a runtime pulls it.
func (r Reference) Pinned() bool { return r.Digest != "" }

// WithDigest returns a copy pinned to digest, dropping the tag.
//
// The tag is dropped rather than kept as "repo:tag@digest". Both forms are
// legal and resolve identically, but only one of them is unambiguous to a
// human reading a Pod spec six months later, and the tag it would carry is by
// then a claim nobody can check.
func (r Reference) WithDigest(digest string) (Reference, error) {
	if err := validateDigest(digest); err != nil {
		return Reference{}, err
	}
	out := r
	out.Tag = ""
	out.Digest = digest
	return out, nil
}

// ParseReference parses ref without applying any default registry.
//
// A reference with no registry component yields Qualified false and an empty
// Registry. That is not an oversight: which registry a bare "alpine:3" resolves
// to is a property of the *host's* runtime configuration (podman consults
// unqualified-search-registries, docker assumes Docker Hub), so the reference
// alone does not determine it and a policy must not pretend otherwise. Policy
// decides what to do about that; see Policy.DefaultRegistry.
func ParseReference(ref string) (Reference, error) {
	out := Reference{Original: ref}

	if strings.TrimSpace(ref) != ref {
		return out, fmt.Errorf("%w: %q has leading or trailing whitespace", ErrBadReference, ref)
	}
	if ref == "" {
		return out, fmt.Errorf("%w: the reference is empty", ErrBadReference)
	}
	if len(ref) > MaxRefLen {
		return out, fmt.Errorf("%w: the reference is %d bytes, at most %d are allowed",
			ErrBadReference, len(ref), MaxRefLen)
	}
	if err := assertASCII(ref); err != nil {
		return out, err
	}

	rest := ref

	// --- digest -----------------------------------------------------------
	// Split at the last '@'. A digest's own value contains no '@', and a
	// repository path may not, so the last one is the only candidate.
	if i := strings.LastIndexByte(rest, '@'); i >= 0 {
		digest := rest[i+1:]
		if err := validateDigest(digest); err != nil {
			return out, err
		}
		out.Digest = digest
		rest = rest[:i]
		if rest == "" {
			return out, fmt.Errorf("%w: %q is a digest with no repository", ErrBadReference, ref)
		}
	}

	// --- tag --------------------------------------------------------------
	// A ':' belongs to the tag only when it comes after the last '/'. Before
	// it, the colon is a registry port: "localhost:5000/app" has no tag.
	if i := strings.LastIndexByte(rest, ':'); i >= 0 && !strings.ContainsAny(rest[i+1:], "/") {
		tag := rest[i+1:]
		if err := validateTag(tag); err != nil {
			return out, err
		}
		out.Tag = tag
		rest = rest[:i]
		if rest == "" {
			return out, fmt.Errorf("%w: %q is a tag with no repository", ErrBadReference, ref)
		}
	}

	// --- registry / repository --------------------------------------------
	domain, remainder := splitDomain(rest)
	if domain != "" {
		normalized, err := normalizeRegistry(domain)
		if err != nil {
			return out, err
		}
		out.Registry = normalized
		out.Qualified = true
	}
	if err := validateRepository(remainder); err != nil {
		return out, err
	}
	out.Repository = remainder

	// Docker Hub's one-component shorthand. "alpine" is "library/alpine"
	// there and nowhere else, so the expansion is applied only once the
	// registry is known to be Docker Hub — never to an unqualified name,
	// whose registry is not known at all.
	if out.Registry == DockerHub && !strings.Contains(out.Repository, "/") {
		out.Repository = "library/" + out.Repository
	}
	return out, nil
}

// splitDomain separates a possible registry host from the repository path.
//
// The rule is the one every runtime uses: the first path component is a host
// only if it looks like one — it contains a dot or a colon, or it is
// "localhost", or it contains an uppercase letter (which a repository
// component may not, so it cannot be one).
//
// This is the function the whole registry-confusion class turns on. For
// "evil.com/docker.io/foo" it returns ("evil.com", "docker.io/foo"): the
// allowed name ends up in the repository, where the registry allowlist never
// looks at it.
func splitDomain(name string) (domain, remainder string) {
	i := strings.IndexByte(name, '/')
	if i < 0 {
		return "", name
	}
	head := name[:i]
	if strings.ContainsAny(head, ".:") || head == "localhost" || strings.ToLower(head) != head {
		return head, name[i+1:]
	}
	return "", name
}

// normalizeRegistry lower-cases the host and folds Docker Hub's aliases.
//
// Case folding is not cosmetic: DNS is case-insensitive, so "GHCR.IO" and
// "ghcr.io" are the same registry, and an allowlist that compared them
// byte-wise would be bypassed by pressing shift.
func normalizeRegistry(domain string) (string, error) {
	if err := validateRegistryHost(domain); err != nil {
		return "", err
	}
	lower := strings.ToLower(domain)
	if canonical, ok := dockerHubAliases[lower]; ok {
		return canonical, nil
	}
	return lower, nil
}

// validateRegistryHost checks a host[:port], including the bracketed IPv6 form.
func validateRegistryHost(domain string) error {
	host, port := domain, ""
	if strings.HasPrefix(domain, "[") {
		end := strings.IndexByte(domain, ']')
		if end < 0 {
			return fmt.Errorf("%w: registry %q has an unterminated IPv6 literal", ErrBadReference, domain)
		}
		host = domain[:end+1]
		switch {
		case end+1 == len(domain):
		case domain[end+1] == ':':
			port = domain[end+2:]
		default:
			return fmt.Errorf("%w: registry %q has trailing characters after the IPv6 literal",
				ErrBadReference, domain)
		}
		if err := validateIPv6Literal(host); err != nil {
			return err
		}
	} else if i := strings.LastIndexByte(domain, ':'); i >= 0 {
		host, port = domain[:i], domain[i+1:]
	}

	if port != "" {
		if len(port) > 5 {
			return fmt.Errorf("%w: registry %q has an out-of-range port", ErrBadReference, domain)
		}
		for _, r := range port {
			if r < '0' || r > '9' {
				return fmt.Errorf("%w: registry %q has a non-numeric port", ErrBadReference, domain)
			}
		}
	}

	if strings.HasPrefix(host, "[") {
		return nil
	}
	if host == "" {
		return fmt.Errorf("%w: registry %q has an empty host", ErrBadReference, domain)
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" {
			return fmt.Errorf("%w: registry %q has an empty domain label", ErrBadReference, domain)
		}
		if !isAlnum(label[0]) || !isAlnum(label[len(label)-1]) {
			return fmt.Errorf("%w: registry %q has a label that does not begin and end alphanumerically",
				ErrBadReference, domain)
		}
		for i := 0; i < len(label); i++ {
			if !isAlnum(label[i]) && label[i] != '-' {
				return fmt.Errorf("%w: registry %q contains %q, which is not valid in a hostname",
					ErrBadReference, domain, string(label[i]))
			}
		}
	}
	return nil
}

// validateIPv6Literal accepts the "[…]" form with hex groups and colons only.
// It is not a full RFC 4291 parser; it exists so a bracketed value cannot
// smuggle a slash or a dot-quad that later parses as something else.
func validateIPv6Literal(host string) error {
	inner := strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	if inner == "" {
		return fmt.Errorf("%w: registry %q has an empty IPv6 literal", ErrBadReference, host)
	}
	for i := 0; i < len(inner); i++ {
		c := inner[i]
		isHex := c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
		if !isHex && c != ':' && c != '.' {
			return fmt.Errorf("%w: registry %q contains %q, which is not valid in an IPv6 literal",
				ErrBadReference, host, string(c))
		}
	}
	return nil
}

// validateRepository checks the path components below the registry.
//
// Uppercase is rejected, as the OCI grammar requires. That rule is what makes
// splitDomain's "contains an uppercase letter therefore it is a host" branch
// sound, so relaxing it here would quietly change how references are split.
func validateRepository(path string) error {
	if path == "" {
		return fmt.Errorf("%w: the reference names no repository", ErrBadReference)
	}
	if len(path) > MaxRefLen {
		return fmt.Errorf("%w: repository path is %d bytes", ErrBadReference, len(path))
	}
	for _, comp := range strings.Split(path, "/") {
		if comp == "" {
			return fmt.Errorf("%w: repository %q has an empty path component", ErrBadReference, path)
		}
		if !isLowerAlnum(comp[0]) || !isLowerAlnum(comp[len(comp)-1]) {
			return fmt.Errorf("%w: repository component %q must begin and end with a lowercase "+
				"letter or digit", ErrBadReference, comp)
		}
		for i := 0; i < len(comp); i++ {
			c := comp[i]
			if isLowerAlnum(c) || c == '.' || c == '_' || c == '-' {
				continue
			}
			if c >= 'A' && c <= 'Z' {
				return fmt.Errorf("%w: repository component %q contains an uppercase letter; "+
					"image repositories are lowercase", ErrBadReference, comp)
			}
			return fmt.Errorf("%w: repository component %q contains %q", ErrBadReference, comp, string(c))
		}
	}
	return nil
}

// validateTag enforces the tag grammar: [A-Za-z0-9_][A-Za-z0-9._-]{0,127}.
func validateTag(tag string) error {
	if tag == "" {
		return fmt.Errorf("%w: the reference ends with an empty tag", ErrBadReference)
	}
	if len(tag) > 128 {
		return fmt.Errorf("%w: tag %q is %d bytes, at most 128 are allowed", ErrBadReference, tag, len(tag))
	}
	if !isAlnum(tag[0]) && tag[0] != '_' {
		return fmt.Errorf("%w: tag %q must begin with a letter, digit or underscore", ErrBadReference, tag)
	}
	for i := 0; i < len(tag); i++ {
		c := tag[i]
		if isAlnum(c) || c == '_' || c == '.' || c == '-' {
			continue
		}
		return fmt.Errorf("%w: tag %q contains %q", ErrBadReference, tag, string(c))
	}
	return nil
}

// digestLengths are the hex lengths of the algorithms this policy will accept.
//
// Restricting to two named algorithms at their exact length is stricter than
// the OCI grammar, which allows any registered algorithm and any hex string of
// 32 characters or more. The looser rule admits "sha256:dead" — syntactically a
// digest, semantically nothing — and admits algorithms whose collision
// resistance is not a property anyone here has checked. A pin is only worth
// having if it names exactly one artifact.
var digestLengths = map[string]int{
	"sha256": 64,
	"sha512": 128,
}

func validateDigest(digest string) error {
	i := strings.IndexByte(digest, ':')
	if i <= 0 {
		return fmt.Errorf("%w: digest %q is not \"algorithm:hex\"", ErrBadReference, digest)
	}
	alg, hex := digest[:i], digest[i+1:]
	want, ok := digestLengths[alg]
	if !ok {
		return fmt.Errorf("%w: digest algorithm %q is not accepted (use one of sha256, sha512)",
			ErrBadReference, alg)
	}
	if len(hex) != want {
		return fmt.Errorf("%w: %s digest must be %d hex characters, got %d",
			ErrBadReference, alg, want, len(hex))
	}
	for i := 0; i < len(hex); i++ {
		c := hex[i]
		// Lowercase only: registries emit lowercase, and accepting both
		// spellings would make the same artifact hash to two cache keys and
		// two audit rows.
		if c >= '0' && c <= '9' || c >= 'a' && c <= 'f' {
			continue
		}
		return fmt.Errorf("%w: digest %q contains %q, which is not lowercase hex",
			ErrBadReference, digest, string(c))
	}
	return nil
}

// assertASCII refuses any byte outside printable ASCII.
//
// This is the homograph defence, and it is placed before every other check on
// purpose. "dоcker.io" with a Cyrillic о renders identically to "docker.io" in
// every code review and every UI, and would be a distinct hostname resolving
// wherever its owner points it. Since a valid reference is ASCII by grammar,
// refusing non-ASCII outright costs nothing and removes the whole class —
// including the punycode a Unicode-aware normalizer might otherwise produce.
func assertASCII(ref string) error {
	for i := 0; i < len(ref); i++ {
		c := ref[i]
		if c >= 0x21 && c <= 0x7e {
			continue
		}
		if c >= 0x80 {
			return fmt.Errorf("%w: %q contains a non-ASCII character at byte %d — image "+
				"references are ASCII, and a Unicode lookalike of an allowed registry is the "+
				"oldest trick there is", ErrBadReference, ref, i)
		}
		return fmt.Errorf("%w: %q contains a control character or space at byte %d",
			ErrBadReference, ref, i)
	}
	return nil
}

func isAlnum(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

func isLowerAlnum(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= '0' && c <= '9'
}
