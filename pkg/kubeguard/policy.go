package kubeguard

// policy.go decides whether one APIRequest may be forwarded.
//
// The policy is deliberately small. It answers four questions — which verbs,
// which namespaces, which resources, which non-resource paths — and it
// answers them about the tuple apirequest.go produced, never about a raw
// path. Anything that needs to reason about a URL has already done so.
//
// Two rules are not configurable, and both are refusals:
//
//   - a subresource in dangerousSubresources is denied outright, because it
//     confers a capability (a shell, a tunnel, a laundered request) rather
//     than returning data, and no verb allowlist expresses that distinction;
//   - a protocol upgrade is denied outright, for the reason in decideUpgrade.
//
// Everything else is allowlist-and-deny-by-default.

import (
	"errors"
	"fmt"
	"path"
	"sort"
	"strings"
)

// Defaults and ceilings.
const (
	// DefaultMaxBodyBytes caps a request body. Kubernetes refuses objects
	// above roughly 1.5 MiB (etcd's own limit), so this is comfortably above
	// anything the API server would accept and far below anything that would
	// cost the hub memory. Under the default read-only policy no request has
	// a body at all.
	DefaultMaxBodyBytes int64 = 3 << 20

	// MaxPatterns bounds each allowlist, so a grant cannot turn every request
	// into a few thousand glob evaluations.
	MaxPatterns = 256
)

// DefaultNonResourcePaths is the discovery surface kubectl needs before it
// can issue a single useful request.
//
// Without these, a read-only session is not read-only — it is broken.
// `kubectl get pods` begins by fetching /api and /apis to learn which groups
// exist, then /api/v1 to learn that pods are namespaced. Denying discovery
// produces "the server could not find the requested resource" on every
// command, which reads as a cluster problem rather than a policy one.
//
// They are all reads of schema and health. None returns cluster data: /api
// and /apis list group names, /openapi returns the type schema, /version
// returns the server's build, and the health endpoints return "ok". A
// trailing "/**" admits any depth below the prefix.
var DefaultNonResourcePaths = []string{
	"/",
	"/api",
	"/api/*",
	"/apis",
	"/apis/*",
	"/apis/*/*",
	"/version",
	"/openapi/**",
	"/healthz",
	"/readyz",
	"/livez",
}

// DenyReason classifies a refusal. It is a metric label and an audit field,
// so the set is small and stable: an operator watching a fleet wants to tell
// "someone's chart tried to write" from "someone probed kube-system".
type DenyReason string

const (
	DenyVerbNotAllowed       DenyReason = "verb_not_allowed"
	DenyNamespaceNotAllowed  DenyReason = "namespace_not_allowed"
	DenyClusterScope         DenyReason = "cluster_scope"
	DenyResourceNotAllowed   DenyReason = "resource_not_allowed"
	DenyDangerousSubresource DenyReason = "dangerous_subresource"
	DenyNonResourcePath      DenyReason = "non_resource_path"
	DenyProtocolUpgrade      DenyReason = "protocol_upgrade"
	DenyBodyTooLarge         DenyReason = "body_too_large"
)

// ErrDenied is what every refusal wraps, so a caller can test with errors.Is
// without caring which rule fired.
var ErrDenied = errors.New("request denied by kubernetes access policy")

// Denial is a refusal carrying its classification and the prose the sandbox
// sees.
//
// The message is written for the person reading `kubectl`'s output, because
// that is who will read it: it names what was attempted and what the session
// is allowed, so the next step is obvious. It never names the cluster
// credential, the grant, or another tenant.
type Denial struct {
	Reason  DenyReason
	Message string
}

func (d *Denial) Error() string {
	if d == nil {
		return ""
	}
	return string(d.Reason) + ": " + d.Message
}

func (d *Denial) Unwrap() error { return ErrDenied }

// DenyReasonOf extracts the classification from an error returned by Decide.
func DenyReasonOf(err error) (DenyReason, bool) {
	var d *Denial
	if errors.As(err, &d) && d != nil {
		return d.Reason, true
	}
	return "", false
}

// Policy is what one session may do against one cluster.
//
// The zero value is not usable directly; Normalize turns it into the
// read-only policy, which is the answer to "the operator granted a cluster
// and said nothing else".
type Policy struct {
	// Verbs is the RBAC verb allowlist. Empty means ReadVerbs.
	Verbs []string `json:"verbs,omitempty"`

	// Namespaces is a glob allowlist of namespace names. Empty means no
	// namespace confinement — every namespace the credential can reach.
	//
	// When it is non-empty it does more than filter: it also refuses
	// collection requests that name no namespace (see decideNamespace), which
	// is the enforcement a kubeconfig's default namespace could never
	// provide.
	Namespaces []string `json:"namespaces,omitempty"`

	// Resources is a glob allowlist matched against "resource" for the core
	// group and "group/resource" otherwise — the spelling RBAC uses, so a
	// pattern can be copied out of a Role. Empty means every resource.
	//
	// Patterns match the resource *without* its subresource, so "pods"
	// admits "pods/log". A subresource is governed by the verb and by the
	// dangerous-subresource rule, not by this list.
	Resources []string `json:"resources,omitempty"`

	// NonResourcePaths is a glob allowlist of non-resource URLs. Empty means
	// DefaultNonResourcePaths. A trailing "/**" admits any depth below the
	// prefix.
	NonResourcePaths []string `json:"non_resource_paths,omitempty"`

	// MaxBodyBytes caps a request body. Zero means DefaultMaxBodyBytes.
	MaxBodyBytes int64 `json:"max_body_bytes,omitempty"`
}

// ReadOnlyPolicy returns the policy this package exists to enforce: get, list
// and watch, every namespace, every resource, discovery allowed.
//
// Narrow it with Namespaces to confine a project to its own namespaces.
func ReadOnlyPolicy() Policy {
	p := Policy{Verbs: append([]string(nil), ReadVerbs...)}
	p.Normalize()
	return p
}

// IsZero distinguishes "never filled in" from "deliberately empty", so a
// caller can tell a default apart from a choice.
func (p Policy) IsZero() bool {
	return len(p.Verbs) == 0 && len(p.Namespaces) == 0 && len(p.Resources) == 0 &&
		len(p.NonResourcePaths) == 0 && p.MaxBodyBytes == 0
}

// ReadOnly reports whether every permitted verb only reads. It is what the UI
// and audit rows render, and it is computed from the verb list rather than
// tracked alongside it so the two cannot disagree.
func (p Policy) ReadOnly() bool {
	for _, v := range p.Verbs {
		if !isReadVerb(v) {
			return false
		}
	}
	return true
}

func isReadVerb(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case VerbGet, VerbList, VerbWatch:
		return true
	}
	return false
}

// Normalize fills defaults, lowercases and dedupes verbs, and drops empty
// patterns. It is idempotent.
func (p *Policy) Normalize() {
	p.Verbs = normalizeVerbs(p.Verbs)
	if len(p.Verbs) == 0 {
		// The default is the whole point of the package. An operator who
		// grants a cluster and says nothing about verbs gets read access,
		// not the credential's own authority.
		p.Verbs = append([]string(nil), ReadVerbs...)
	}
	p.Namespaces = normalizePatterns(p.Namespaces)
	p.Resources = normalizePatterns(p.Resources)
	p.NonResourcePaths = normalizePatterns(p.NonResourcePaths)
	if len(p.NonResourcePaths) == 0 {
		p.NonResourcePaths = append([]string(nil), DefaultNonResourcePaths...)
	}
	if p.MaxBodyBytes <= 0 {
		p.MaxBodyBytes = DefaultMaxBodyBytes
	}
}

// Validate reports the first structural problem. Call after Normalize.
func (p Policy) Validate() error {
	if len(p.Verbs) == 0 {
		return errors.New("policy permits no verbs")
	}
	for _, v := range p.Verbs {
		if !knownVerb(v) {
			return fmt.Errorf("unknown verb %q (want one of %s)", v,
				strings.Join(allVerbs(), ", "))
		}
	}
	for field, pats := range map[string][]string{
		"namespaces":         p.Namespaces,
		"resources":          p.Resources,
		"non_resource_paths": p.NonResourcePaths,
	} {
		if len(pats) > MaxPatterns {
			return fmt.Errorf("%s has %d patterns, at most %d are allowed",
				field, len(pats), MaxPatterns)
		}
		for _, pat := range pats {
			if err := validateGlob(field, pat); err != nil {
				return err
			}
		}
	}
	if p.MaxBodyBytes <= 0 {
		return fmt.Errorf("max_body_bytes must be positive (got %d)", p.MaxBodyBytes)
	}
	return nil
}

// Summary renders the policy for an audit row or a UI badge. It is short by
// design: "read-only, namespaces app|app-staging".
func (p Policy) Summary() string {
	parts := []string{"verbs=" + strings.Join(p.Verbs, "|")}
	if p.ReadOnly() {
		parts[0] = "read-only"
	}
	if len(p.Namespaces) > 0 {
		cp := append([]string(nil), p.Namespaces...)
		sort.Strings(cp)
		parts = append(parts, "ns="+strings.Join(cp, "|"))
	}
	if len(p.Resources) > 0 {
		cp := append([]string(nil), p.Resources...)
		sort.Strings(cp)
		parts = append(parts, "resources="+strings.Join(cp, "|"))
	}
	return strings.Join(parts, " ")
}

// Intersect narrows p by other and returns the result. Neither input is
// modified.
//
// This is how a deployment-wide floor and a per-grant policy combine: the
// session runs under what *both* permit, so an operator who sets
// executors.kube_guard.verbs to read-only has made every grant on the hub
// read-only regardless of what its own verbs say, and a grant that asks for
// less than the floor allows still gets only what it asked for.
//
// Verbs intersect exactly — there are eight of them and set intersection is
// the whole answer.
//
// The glob lists cannot. There is no general way to compute the intersection
// of two glob languages, so this narrows conservatively instead: an entry
// from other survives only if p already admits it. That is sound in the
// direction that matters (the result never admits something p denied) and
// lossy in the other — a grant for "app-*" under a floor of "app-1" yields
// nothing, even though "app-1" is in both languages.
//
// The lossy case is returned as an error rather than as a policy, and the
// distinction is load-bearing. An empty *namespace* list does not mean "no
// namespaces"; it means "no namespace confinement", so returning one would
// turn a floor the grant failed to satisfy into a session that can read every
// namespace in the cluster — a widening, produced by the narrowing function,
// in the one direction a security control must never fail. The same is true
// of Resources. So an empty result on any dimension is a refusal, and
// GuardKubeconfig turns it into a lease that fails with the two policies
// named.
//
// In practice this is rare: the common floor is empty or "*", where no
// narrowing happens at all. An operator who does write a floor should write
// it as a literal superset of what grants will ask for.
func (p Policy) Intersect(other Policy) (Policy, error) {
	p.Normalize()
	other.Normalize()

	out := Policy{
		Verbs:        intersectVerbs(p.Verbs, other.Verbs),
		MaxBodyBytes: min(p.MaxBodyBytes, other.MaxBodyBytes),
	}
	var err error
	if out.Namespaces, err = narrowGlobs("namespaces", p.Namespaces, other.Namespaces, p.AllowsNamespace); err != nil {
		return Policy{}, err
	}
	if out.Resources, err = narrowGlobs("resources", p.Resources, other.Resources,
		func(s string) bool { return matchAnyGlob(p.Resources, s) }); err != nil {
		return Policy{}, err
	}
	if out.NonResourcePaths, err = narrowGlobs("non_resource_paths", p.NonResourcePaths,
		other.NonResourcePaths, p.AllowsNonResourcePath); err != nil {
		return Policy{}, err
	}
	// Deliberately not Normalize()d: an empty verb list here means the two
	// policies permit nothing in common, and normalising would turn that into
	// the read-only default — silently widening a session past a floor that
	// excluded it. Validate reports it instead, which is safe because an
	// empty verb list genuinely does mean "nothing" to every reader.
	return out, nil
}

// intersectVerbs returns the verbs in both lists, in a's order.
func intersectVerbs(a, b []string) []string {
	has := make(map[string]bool, len(b))
	for _, v := range b {
		has[v] = true
	}
	out := make([]string, 0, len(a))
	for _, v := range a {
		if has[v] {
			out = append(out, v)
		}
	}
	return out
}

// narrowGlobs keeps the entries of b that admits already permits, and refuses
// rather than returning nothing.
//
// An empty list on either side means "no restriction from that side", so the
// other carries through unchanged. An empty *result* from two non-empty
// inputs is the failure described on Intersect, and it is an error because
// the empty list would be read as "no restriction" by everything downstream.
func narrowGlobs(field string, a, b []string, admits func(string) bool) ([]string, error) {
	switch {
	case len(a) == 0:
		return append([]string(nil), b...), nil
	case len(b) == 0:
		return append([]string(nil), a...), nil
	}
	out := make([]string, 0, len(b))
	for _, pat := range b {
		if admits(pat) {
			out = append(out, pat)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf(
			"%s: the grant asks for %s but this hub's policy floor allows only %s, and no "+
				"entry of the first is covered by the second; widen the floor or narrow the "+
				"grant to a literal subset of it",
			field, strings.Join(b, ", "), strings.Join(a, ", "))
	}
	return out, nil
}

// AllowsVerb reports whether the verb is in the allowlist.
func (p Policy) AllowsVerb(v string) bool {
	want := strings.ToLower(strings.TrimSpace(v))
	for _, got := range p.Verbs {
		if got == want {
			return true
		}
	}
	return false
}

// AllowsNamespace reports whether ns is inside the allowlist. An empty
// allowlist admits every namespace.
//
// The glob semantics deliberately match pkg/secretbroker's matchAny: "*"
// admits everything, otherwise path.Match decides. The same allowlist string
// is written once on a grant and read in both places, so the two agreeing is
// a correctness requirement, not a nicety — kubeguard_constraints_test.go
// asserts it directly.
func (p Policy) AllowsNamespace(ns string) bool {
	if len(p.Namespaces) == 0 {
		return true
	}
	return matchAnyGlob(p.Namespaces, ns)
}

// AllowsResource reports whether the request's resource is in the allowlist.
func (p Policy) AllowsResource(r APIRequest) bool {
	if len(p.Resources) == 0 {
		return true
	}
	name := r.Resource
	if r.APIGroup != "" {
		name = r.APIGroup + "/" + r.Resource
	}
	return matchAnyGlob(p.Resources, name)
}

// AllowsNonResourcePath reports whether a non-resource URL is readable.
func (p Policy) AllowsNonResourcePath(pth string) bool {
	return matchAnyPath(p.NonResourcePaths, pth)
}

// Decide returns nil when the request may be forwarded, or a *Denial.
//
// The order of the checks is chosen for the message the operator reads, not
// for speed: the most specific and most alarming reason wins, so a sandbox
// that tried to exec into a pod is told that, rather than being told its verb
// was fine and leaving the reader to work out why the request still failed.
func (p Policy) Decide(r APIRequest) error {
	// 1. A capability subresource, whatever the method. Ahead of everything,
	//    because a GET to pods/exec is a shell and must never be reported as
	//    an allowed read.
	if r.Dangerous() {
		return &Denial{
			Reason: DenyDangerousSubresource,
			Message: fmt.Sprintf(
				"%s is not readable through the cloop Kubernetes monitor: the %q subresource "+
					"opens a session into the workload rather than returning data, so it is "+
					"refused for every verb",
				r.ResourceString(), r.Subresource),
		}
	}

	// 2. A protocol upgrade.
	if r.Upgrade {
		return decideUpgrade(r)
	}

	// 3. Non-resource URLs are a separate namespace of rules.
	if !r.IsResource {
		if r.Verb != "get" {
			return &Denial{
				Reason: DenyNonResourcePath,
				Message: fmt.Sprintf(
					"%s %s is refused: non-resource URLs are readable only, and this session "+
						"may not write to them", strings.ToUpper(r.Verb), r.Path),
			}
		}
		if !p.AllowsNonResourcePath(r.Path) {
			return &Denial{
				Reason: DenyNonResourcePath,
				Message: fmt.Sprintf(
					"%s is not in this session's non-resource allowlist (%s)",
					r.Path, strings.Join(p.NonResourcePaths, ", ")),
			}
		}
		return nil
	}

	// 4. The verb.
	if !p.AllowsVerb(r.Verb) {
		msg := fmt.Sprintf("this session may not %s %s; it is allowed %s only",
			r.Verb, r.ResourceString(), strings.Join(p.Verbs, ", "))
		if p.ReadOnly() {
			msg = fmt.Sprintf(
				"this session has read-only access to the cluster, so it may not %s %s "+
					"(allowed: %s)", r.Verb, r.ResourceString(), strings.Join(p.Verbs, ", "))
		}
		return &Denial{Reason: DenyVerbNotAllowed, Message: msg}
	}

	// 5. The resource.
	if !p.AllowsResource(r) {
		return &Denial{
			Reason: DenyResourceNotAllowed,
			Message: fmt.Sprintf("%s is not in this session's resource allowlist (%s)",
				r.ResourceString(), strings.Join(p.Resources, ", ")),
		}
	}

	// 6. The namespace.
	return p.decideNamespace(r)
}

// decideNamespace enforces the confinement a kubeconfig cannot.
//
// Two distinct refusals, and the second is the one that matters:
//
//   - a request naming a namespace outside the allowlist, which is the case
//     everyone pictures (`kubectl -n kube-system get secrets`);
//   - a request naming *no* namespace while an allowlist exists. `kubectl get
//     pods --all-namespaces` and `GET /api/v1/secrets` are collection reads
//     spanning the whole cluster. Letting them through because "no namespace
//     was named, so no namespace was violated" would make the allowlist
//     decorative — the one request it must stop is the one that asks for
//     everything at once.
//
// A genuinely cluster-scoped resource (nodes, persistentvolumes,
// storageclasses) is caught by the same rule, which is correct: a grant
// confined to namespaces has not been given the cluster. An operator who
// wants those adds them to Resources and drops the namespace list, or grants
// a second, cluster-scoped grant.
func (p Policy) decideNamespace(r APIRequest) error {
	if len(p.Namespaces) == 0 {
		return nil
	}
	if r.Namespace == "" {
		return &Denial{
			Reason: DenyClusterScope,
			Message: fmt.Sprintf(
				"%s without a namespace would read across the whole cluster; this session is "+
					"confined to %s, so name one with -n",
				r.ResourceString(), strings.Join(p.Namespaces, ", ")),
		}
	}
	if !p.AllowsNamespace(r.Namespace) {
		return &Denial{
			Reason: DenyNamespaceNotAllowed,
			Message: fmt.Sprintf(
				"namespace %q is not in this session's allowlist (%s)",
				r.Namespace, strings.Join(p.Namespaces, ", ")),
		}
	}
	return nil
}

// decideUpgrade refuses a protocol switch.
//
// Every upgrade the Kubernetes API offers a client is a streaming session:
// SPDY for exec, attach and port-forward, websockets for those plus watch.
// The first three are already denied by subresource. That leaves websocket
// watch, which is the only legitimate upgrade a read-only session could want
// — and kubectl does not use it, because client-go watches over chunked
// HTTP/1.1 and HTTP/2, which this proxy forwards unchanged.
//
// So refusing every upgrade costs a capability nothing in the normal path
// uses, and buys a boundary that does not depend on getting hijacked-
// connection accounting right for a bidirectional stream the proxy cannot
// parse. A tunnel the monitor cannot read is a tunnel the monitor is not
// monitoring, and that is the one thing this package must not ship.
func decideUpgrade(r APIRequest) error {
	return &Denial{
		Reason: DenyProtocolUpgrade,
		Message: fmt.Sprintf(
			"%s asked to upgrade the connection; the cloop Kubernetes monitor forwards only "+
				"ordinary HTTP requests, so streaming sessions are refused. Watches work "+
				"normally over HTTP", r.Path),
	}
}

// normalizeVerbs lowercases, trims, drops empties and dedupes while keeping
// the caller's order.
func normalizeVerbs(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, v := range in {
		s := strings.ToLower(strings.TrimSpace(v))
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

// normalizePatterns trims, drops empties and dedupes.
func normalizePatterns(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, v := range in {
		s := strings.TrimSpace(v)
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

func knownVerb(v string) bool {
	switch v {
	case VerbGet, VerbList, VerbWatch, VerbCreate, VerbUpdate, VerbPatch,
		VerbDelete, VerbDeleteCollection:
		return true
	}
	return false
}

func allVerbs() []string {
	return []string{VerbGet, VerbList, VerbWatch, VerbCreate, VerbUpdate,
		VerbPatch, VerbDelete, VerbDeleteCollection}
}

// validateGlob refuses a pattern that path.Match cannot parse, and one
// carrying "..", which has no meaning in any of these namespaces and is a
// classic way to smuggle a wider match past a normaliser.
func validateGlob(field, pat string) error {
	if strings.TrimSpace(pat) == "" {
		return fmt.Errorf("%s contains an empty pattern", field)
	}
	if len(pat) > 256 {
		return fmt.Errorf("%s pattern %q exceeds 256 characters", field, pat)
	}
	if strings.Contains(pat, "..") {
		return fmt.Errorf("%s pattern %q contains %q", field, pat, "..")
	}
	probe := strings.TrimSuffix(pat, "/**")
	if _, err := path.Match(probe, "x"); err != nil {
		return fmt.Errorf("%s pattern %q is malformed: %v", field, pat, err)
	}
	return nil
}

// matchAnyGlob is pkg/secretbroker's matchAny, kept identical on purpose.
func matchAnyGlob(pats []string, value string) bool {
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

// matchAnyPath is matchAnyGlob plus a trailing "/**", which admits any depth
// below the prefix. path.Match's "*" does not cross a "/", so without this
// there is no way to write "/openapi and everything under it".
func matchAnyPath(pats []string, value string) bool {
	v := strings.TrimSpace(value)
	if v == "" || len(pats) == 0 {
		return false
	}
	// A trailing slash is the same resource to the API server.
	if v != "/" {
		v = strings.TrimSuffix(v, "/")
	}
	for _, pat := range pats {
		p := strings.TrimSpace(pat)
		if p == "*" || p == "/**" {
			return true
		}
		if prefix, ok := strings.CutSuffix(p, "/**"); ok {
			if v == prefix || strings.HasPrefix(v, prefix+"/") {
				return true
			}
			continue
		}
		if ok, err := path.Match(p, v); err == nil && ok {
			return true
		}
	}
	return false
}
