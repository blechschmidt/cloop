package ciauth

// rule.go is the operator's half of trust: which verified pipelines this hub
// is willing to act for, and what a match buys them.
//
// A rule has two kinds of matcher and they compose with AND. The glob fields
// cover what nearly every deployment needs — this repository, these branches,
// that environment — and are legible to someone who has never read a CEL
// grammar. Condition is the escape hatch for the policies globs cannot state,
// and is evaluated by pkg/celmatch, which refuses anything it does not fully
// implement rather than guessing.

import (
	"fmt"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/celmatch"
)

// TTL bounds for a minted CI session. The floor keeps a rule from being
// configured into uselessness; the ceiling is the real control, because the
// session token is the thing a leaked runner log would expose.
const (
	MinTTL     = 1 * time.Minute
	MaxTTL     = 6 * time.Hour
	DefaultTTL = 60 * time.Minute
)

// Request-count bounds. A CI session's blast radius is "how much Claude can
// this job spend", and the request cap is the crude but effective lever.
const (
	MaxRequestsCeiling = 10000
	DefaultMaxRequests = 500
)

// Matcher describes which pipeline identities a rule admits.
//
// An empty field is "don't care". At least one of Repository or Condition
// must be set — see Validate for why the others cannot stand alone.
type Matcher struct {
	// Repository is a glob over the `repository` claim, e.g. "acme/tool" or
	// "acme/*". The owner segment may not contain a wildcard.
	Repository string `json:"repository,omitempty"`

	// Ref is a glob over the `ref` claim, e.g. "refs/heads/main" or
	// "refs/heads/**". A trailing "/**" admits anything strictly below.
	Ref string `json:"ref,omitempty"`

	// Workflow is a glob matched against the workflow's display name (the
	// `workflow` claim), its full reference (`workflow_ref`), or that
	// reference with the trailing "@<ref>" removed. Naming the file is the
	// stronger form: a display name is whatever the workflow file says it is,
	// and anyone who can open a pull request can say it.
	//
	// The third form exists because `workflow_ref` is
	// "owner/name/.github/workflows/x.yml@refs/heads/main" and a glob's `*`
	// does not cross a slash, so the pattern an operator naturally writes —
	// ".../x.yml@*" — would match the ref "main" and not "release/1.2". That
	// is a trap that fails open-looking and closed-behaving, so the path is
	// offered as its own thing to match.
	Workflow string `json:"workflow,omitempty"`

	// Environment is a glob over the `environment` claim. A token only
	// carries one when the job declares an environment, so a rule that sets
	// this never admits a job that did not — which is the point: GitHub
	// environment protection rules are the approval gate this leans on.
	Environment string `json:"environment,omitempty"`

	// Actor is a glob over the `actor` claim: who triggered the run.
	Actor string `json:"actor,omitempty"`

	// EventName is a glob over the `event_name` claim, e.g. "push".
	EventName string `json:"event_name,omitempty"`

	// Condition is a strict-CEL expression over `assertion.<claim>`. See
	// pkg/celmatch for exactly what the dialect accepts.
	Condition string `json:"condition,omitempty"`
}

// IsEmpty reports whether the matcher constrains nothing.
func (m Matcher) IsEmpty() bool {
	return m.Repository == "" && m.Ref == "" && m.Workflow == "" &&
		m.Environment == "" && m.Actor == "" && m.EventName == "" && m.Condition == ""
}

// GrantPolicy is what a matching pipeline is allowed to do with the session
// it receives.
type GrantPolicy struct {
	// Models is an allowlist of model IDs, matched as globs so
	// "claude-sonnet-*" keeps working across point releases. Empty means the
	// hub's own default allowlist applies; it does not mean "any model".
	Models []string `json:"models,omitempty"`

	// MaxRequests caps how many upstream calls one session may make. Zero
	// uses DefaultMaxRequests.
	MaxRequests int `json:"max_requests,omitempty"`

	// MaxOutputTokens clamps `max_tokens` on every request. Zero means the
	// hub default applies.
	MaxOutputTokens int `json:"max_output_tokens,omitempty"`

	// TTLSeconds is the session lifetime. Zero uses DefaultTTL; values are
	// clamped to [MinTTL, MaxTTL].
	TTLSeconds int `json:"ttl_seconds,omitempty"`
}

// TTL returns the clamped session lifetime.
func (p GrantPolicy) TTL() time.Duration {
	if p.TTLSeconds <= 0 {
		return DefaultTTL
	}
	d := time.Duration(p.TTLSeconds) * time.Second
	if d < MinTTL {
		return MinTTL
	}
	if d > MaxTTL {
		return MaxTTL
	}
	return d
}

// Requests returns the clamped request cap.
func (p GrantPolicy) Requests() int {
	if p.MaxRequests <= 0 {
		return DefaultMaxRequests
	}
	if p.MaxRequests > MaxRequestsCeiling {
		return MaxRequestsCeiling
	}
	return p.MaxRequests
}

// Rule is one entry of the pipeline allowlist.
type Rule struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`

	Match  Matcher     `json:"match"`
	Policy GrantPolicy `json:"policy"`

	// Project optionally binds sessions minted under this rule to a cloop
	// project, so the spend shows up against it.
	Project string `json:"project,omitempty"`

	CreatedBy string    `json:"created_by,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at,omitempty"`

	// LastMatchedAt is advisory, updated out of band. It is what tells an
	// operator that a rule they were about to delete is still load-bearing.
	LastMatchedAt time.Time `json:"last_matched_at,omitempty"`

	// prog is Match.Condition compiled. Nil when there is no condition.
	// Populated by Prepare; a rule that has not been prepared refuses to
	// match rather than ignoring its condition.
	prog     *celmatch.Program
	prepared bool
}

// Validate checks a rule an operator submitted and compiles its condition.
//
// It is strict on purpose. Every refusal here is a rule that would otherwise
// have admitted more pipelines than the person writing it intended, and the
// cost of finding that out later is a third party's workload spending this
// hub's Anthropic credential.
func (r *Rule) Validate() error {
	r.Name = strings.TrimSpace(r.Name)
	if r.Name == "" {
		return fmt.Errorf("name is required")
	}
	if len(r.Name) > 200 {
		return fmt.Errorf("name is %d characters, limit is 200", len(r.Name))
	}
	r.Project = strings.TrimSpace(r.Project)
	r.Match.Repository = strings.TrimSpace(r.Match.Repository)
	r.Match.Ref = strings.TrimSpace(r.Match.Ref)
	r.Match.Workflow = strings.TrimSpace(r.Match.Workflow)
	r.Match.Environment = strings.TrimSpace(r.Match.Environment)
	r.Match.Actor = strings.TrimSpace(r.Match.Actor)
	r.Match.EventName = strings.TrimSpace(r.Match.EventName)
	r.Match.Condition = strings.TrimSpace(r.Match.Condition)

	if r.Match.IsEmpty() {
		return fmt.Errorf("a rule must constrain something: set a repository pattern or a condition")
	}
	// Ref, workflow, environment, actor and event all describe *how* a job
	// ran, not *whose* job it is. A rule built only from those would admit
	// any repository on GitHub whose workflow happened to be called "release"
	// and would look, to the person who wrote it, like a rule about their
	// own repository.
	if r.Match.Repository == "" && r.Match.Condition == "" {
		return fmt.Errorf("a rule must identify the repository: set `repository`, " +
			"or a `condition` that pins assertion.repository")
	}
	if r.Match.Repository != "" {
		if err := validateRepositoryPattern(r.Match.Repository); err != nil {
			return fmt.Errorf("repository %q: %w", r.Match.Repository, err)
		}
	}
	for _, f := range []struct{ name, pat string }{
		{"ref", r.Match.Ref},
		{"workflow", r.Match.Workflow},
		{"environment", r.Match.Environment},
		{"actor", r.Match.Actor},
		{"event_name", r.Match.EventName},
	} {
		if f.pat == "" {
			continue
		}
		if err := validateGlob(f.pat); err != nil {
			return fmt.Errorf("%s %q: %w", f.name, f.pat, err)
		}
	}
	if r.Match.Condition != "" {
		prog, err := celmatch.Compile(r.Match.Condition)
		if err != nil {
			return fmt.Errorf("condition: %w", err)
		}
		r.prog = prog
	} else {
		r.prog = nil
	}
	for _, m := range r.Policy.Models {
		if strings.TrimSpace(m) == "" {
			return fmt.Errorf("model allowlist contains an empty entry")
		}
		if err := validateGlob(m); err != nil {
			return fmt.Errorf("model %q: %w", m, err)
		}
	}
	if r.Policy.MaxOutputTokens < 0 {
		return fmt.Errorf("max_output_tokens cannot be negative")
	}
	if r.Policy.MaxRequests < 0 {
		return fmt.Errorf("max_requests cannot be negative")
	}
	if r.Policy.TTLSeconds < 0 {
		return fmt.Errorf("ttl_seconds cannot be negative")
	}
	r.prepared = true
	return nil
}

// Prepare compiles a rule loaded from storage so it can match.
//
// It is separate from Validate only in intent: Validate is what a write path
// calls, Prepare is what a read path calls, and they do the same work because
// a rule that round-tripped through the database must be held to exactly the
// checks it passed on the way in. A rule that fails here is not silently
// dropped — RuleSet records it so an operator can see that a stored rule has
// stopped being loadable.
func (r *Rule) Prepare() error { return r.Validate() }

// validateRepositoryPattern refuses a pattern that does not pin the owner.
//
// "*/tool" reads like "the tool repository" and means "any account on GitHub
// that creates a repository called tool" — which anyone can do, in seconds,
// for free. Pinning the owner segment is the difference between an allowlist
// and an invitation.
func validateRepositoryPattern(pat string) error {
	owner, name, ok := strings.Cut(pat, "/")
	if !ok {
		return fmt.Errorf("must be owner/name (for example acme/tool or acme/*)")
	}
	if owner == "" || name == "" {
		return fmt.Errorf("must be owner/name (for example acme/tool or acme/*)")
	}
	if strings.ContainsAny(owner, "*?[") {
		return fmt.Errorf("the owner segment %q may not contain a wildcard — "+
			"any account can create a repository with a matching name", owner)
	}
	if strings.Contains(name, "/") {
		return fmt.Errorf("a repository name contains no slash")
	}
	return validateGlob(pat)
}

// validateGlob rejects a pattern path.Match cannot compile. Such a pattern
// matches nothing while reading like a working allowlist, which is the worst
// of the available failure modes.
func validateGlob(pat string) error {
	probe := strings.TrimSuffix(pat, "/**")
	if _, err := path.Match(probe, "probe"); err != nil {
		return fmt.Errorf("is not a valid glob: %w", err)
	}
	return nil
}

// matchGlob applies one pattern, with the same "/**" convention pkg/gitproxy
// uses for refs: a trailing /** admits anything strictly below the prefix.
func matchGlob(pat, s string) bool {
	if pat == "" {
		return true
	}
	if prefix, ok := strings.CutSuffix(pat, "/**"); ok {
		return strings.HasPrefix(s, prefix+"/")
	}
	ok, err := path.Match(pat, s)
	return err == nil && ok
}

// matchesWorkflow applies a workflow pattern to the three forms a workflow is
// identified by. See Matcher.Workflow for why the path-without-ref form is
// offered separately.
func matchesWorkflow(pat string, c *Claims) bool {
	if matchGlob(pat, c.Workflow) || matchGlob(pat, c.WorkflowRef) {
		return true
	}
	if path, _, ok := strings.Cut(c.WorkflowRef, "@"); ok {
		return matchGlob(pat, path)
	}
	return false
}

// Matches reports whether the rule admits these claims.
//
// The error return is not "no match": it means the rule could not be decided,
// which happens when a condition reads a claim the token does not carry. A
// caller must treat it as a denial, and callers do — RuleSet.Match records it
// and moves on to the next rule rather than letting an undecidable rule stop
// the search or, worse, admit.
func (r *Rule) Matches(c *Claims) (bool, error) {
	if c == nil {
		return false, fmt.Errorf("no claims")
	}
	if !r.Enabled {
		return false, nil
	}
	if !r.prepared {
		// A rule that was never compiled has a condition nobody checked.
		// Refusing is the only safe reading.
		return false, fmt.Errorf("rule %s was not prepared", r.ID)
	}
	m := r.Match
	if m.Repository != "" && !matchGlob(m.Repository, c.Repository) {
		return false, nil
	}
	if m.Ref != "" && !matchGlob(m.Ref, c.Ref) {
		return false, nil
	}
	if m.Workflow != "" && !matchesWorkflow(m.Workflow, c) {
		return false, nil
	}
	if m.Environment != "" && !matchGlob(m.Environment, c.Environment) {
		return false, nil
	}
	if m.Actor != "" && !matchGlob(m.Actor, c.Actor) {
		return false, nil
	}
	if m.EventName != "" && !matchGlob(m.EventName, c.EventName) {
		return false, nil
	}
	if r.prog != nil {
		ok, err := r.prog.Eval(c.All)
		if err != nil {
			return false, fmt.Errorf("condition: %w", err)
		}
		if !ok {
			return false, nil
		}
	}
	return true, nil
}

// RuleSet is an ordered allowlist. First match wins.
type RuleSet struct {
	rules []*Rule
	// broken records rules that failed to prepare, keyed by ID, so the
	// dashboard can show "this rule is stored but not in force" instead of
	// simply not listing it.
	broken map[string]string
}

// NewRuleSet prepares rules and returns a set ready to match against.
//
// Preparation failures do not fail the call. One unparseable rule must not
// take a hub's whole CI allowlist offline — the rest keep working, and the
// broken one is inert and reported. The alternative, refusing to serve any
// pipeline because one row is bad, turns a typo into an outage.
func NewRuleSet(rules []Rule) *RuleSet {
	rs := &RuleSet{broken: map[string]string{}}
	sorted := make([]Rule, len(rules))
	copy(sorted, rules)
	// Deterministic order: creation time, then ID. "First match wins" is only
	// a meaningful rule if the order is stable across restarts.
	sort.SliceStable(sorted, func(i, j int) bool {
		if !sorted[i].CreatedAt.Equal(sorted[j].CreatedAt) {
			return sorted[i].CreatedAt.Before(sorted[j].CreatedAt)
		}
		return sorted[i].ID < sorted[j].ID
	})
	for i := range sorted {
		r := sorted[i]
		if err := r.Prepare(); err != nil {
			rs.broken[r.ID] = err.Error()
			continue
		}
		rs.rules = append(rs.rules, &r)
	}
	return rs
}

// Len returns the number of rules in force.
func (rs *RuleSet) Len() int {
	if rs == nil {
		return 0
	}
	return len(rs.rules)
}

// Broken returns the IDs of stored rules that could not be prepared, mapped
// to the reason.
func (rs *RuleSet) Broken() map[string]string {
	if rs == nil {
		return nil
	}
	out := make(map[string]string, len(rs.broken))
	for k, v := range rs.broken {
		out[k] = v
	}
	return out
}

// MatchResult explains a search, for audit and for the operator staring at a
// pipeline that is being refused.
type MatchResult struct {
	// Rule is the first rule that admitted the claims, or nil.
	Rule *Rule
	// Considered counts the enabled rules examined.
	Considered int
	// Errors names rules that could not be decided, keyed by rule ID. A rule
	// here neither admitted nor cleanly declined, and the distinction is the
	// whole reason this field exists: "no rule matched" and "your rule reads
	// a claim this token does not have" are different problems.
	Errors map[string]string
}

// Match finds the first rule that admits c.
//
// A nil Rule with a nil error means no rule matched, which is the ordinary
// outcome for a pipeline nobody has allowlisted.
func (rs *RuleSet) Match(c *Claims) MatchResult {
	res := MatchResult{}
	if rs == nil || c == nil {
		return res
	}
	for _, r := range rs.rules {
		if !r.Enabled {
			continue
		}
		res.Considered++
		ok, err := r.Matches(c)
		if err != nil {
			if res.Errors == nil {
				res.Errors = map[string]string{}
			}
			res.Errors[r.ID] = err.Error()
			continue
		}
		if ok {
			res.Rule = r
			return res
		}
	}
	return res
}

// AllowsModel reports whether the policy admits a model ID.
//
// An empty allowlist is "the hub's default applies", resolved by the caller
// before it reaches here; by the time a session holds a policy the list is
// populated. A policy that somehow reached here empty denies, because the one
// reading of an empty allowlist that must never be "everything" is this one.
func (p GrantPolicy) AllowsModel(model string) bool {
	if model == "" {
		return false
	}
	for _, pat := range p.Models {
		if ok, err := path.Match(pat, model); err == nil && ok {
			return true
		}
	}
	return false
}
