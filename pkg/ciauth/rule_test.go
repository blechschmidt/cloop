package ciauth

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// claimsFor builds a verified claim set without going through a forge, for
// tests about matching rather than about verification.
func claimsFor(t *testing.T, overrides map[string]any) *Claims {
	t.Helper()
	all := map[string]any{
		"iss":              GitHubActionsIssuer,
		"aud":              "cloop",
		"sub":              "repo:acme/tool:ref:refs/heads/main",
		"repository":       "acme/tool",
		"repository_owner": "acme",
		"ref":              "refs/heads/main",
		"workflow":         "release",
		"workflow_ref":     "acme/tool/.github/workflows/release.yml@refs/heads/main",
		"actor":            "dana",
		"event_name":       "push",
		"exp":              float64(time.Now().Add(time.Minute).Unix()),
	}
	for k, v := range overrides {
		if v == nil {
			delete(all, k)
			continue
		}
		all[k] = v
	}
	// Round-trip through JSON so numbers arrive as float64, exactly as they
	// would from a real token.
	b, _ := json.Marshal(all)
	var decoded map[string]any
	if err := json.Unmarshal(b, &decoded); err != nil {
		t.Fatalf("fixture: %v", err)
	}
	return claimsFrom(decoded)
}

func mustRule(t *testing.T, r Rule) *Rule {
	t.Helper()
	if r.ID == "" {
		r.ID = "r1"
	}
	if r.Name == "" {
		r.Name = "test"
	}
	r.Enabled = true
	if err := r.Validate(); err != nil {
		t.Fatalf("Validate(%+v): %v", r, err)
	}
	return &r
}

func TestRuleMatches_Globs(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		match  Matcher
		claims map[string]any
		want   bool
	}{
		{"exact repository", Matcher{Repository: "acme/tool"}, nil, true},
		{"other repository", Matcher{Repository: "acme/other"}, nil, false},
		{"org wildcard", Matcher{Repository: "acme/*"}, nil, true},
		{"org wildcard, other org", Matcher{Repository: "acme/*"}, map[string]any{"repository": "evil/tool"}, false},
		{"ref exact", Matcher{Repository: "acme/tool", Ref: "refs/heads/main"}, nil, true},
		{"ref mismatch", Matcher{Repository: "acme/tool", Ref: "refs/heads/dev"}, nil, false},
		{"ref recursive glob", Matcher{Repository: "acme/tool", Ref: "refs/heads/**"}, map[string]any{"ref": "refs/heads/team/feature"}, true},
		{"ref recursive glob excludes the prefix", Matcher{Repository: "acme/tool", Ref: "refs/heads/**"}, map[string]any{"ref": "refs/heads"}, false},
		{"ref single-segment glob does not cross a slash", Matcher{Repository: "acme/tool", Ref: "refs/heads/*"}, map[string]any{"ref": "refs/heads/team/feature"}, false},
		{"workflow by display name", Matcher{Repository: "acme/tool", Workflow: "release"}, nil, true},
		{"workflow by file path", Matcher{Repository: "acme/tool", Workflow: "acme/tool/.github/workflows/release.yml"}, nil, true},
		{"workflow by file path, ref with slashes", Matcher{Repository: "acme/tool", Workflow: "acme/tool/.github/workflows/release.yml"}, map[string]any{"workflow_ref": "acme/tool/.github/workflows/release.yml@refs/heads/release/1.2"}, true},
		{"workflow by full ref", Matcher{Repository: "acme/tool", Workflow: "acme/tool/.github/workflows/release.yml@refs/heads/main"}, nil, true},
		{"workflow file path mismatch", Matcher{Repository: "acme/tool", Workflow: "acme/tool/.github/workflows/deploy.yml"}, nil, false},
		{"workflow mismatch", Matcher{Repository: "acme/tool", Workflow: "deploy"}, nil, false},
		{"actor", Matcher{Repository: "acme/tool", Actor: "dana"}, nil, true},
		{"actor mismatch", Matcher{Repository: "acme/tool", Actor: "mallory"}, nil, false},
		{"event", Matcher{Repository: "acme/tool", EventName: "push"}, nil, true},
		{"event mismatch", Matcher{Repository: "acme/tool", EventName: "pull_request"}, nil, false},
		{"environment absent from the token", Matcher{Repository: "acme/tool", Environment: "production"}, nil, false},
		{"environment present", Matcher{Repository: "acme/tool", Environment: "production"}, map[string]any{"environment": "production"}, true},
		{"all conditions AND", Matcher{Repository: "acme/tool", Ref: "refs/heads/main", Actor: "dana", EventName: "push"}, nil, true},
		{"one condition of many fails", Matcher{Repository: "acme/tool", Ref: "refs/heads/main", Actor: "mallory"}, nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := mustRule(t, Rule{Match: tc.match})
			got, err := r.Matches(claimsFor(t, tc.claims))
			if err != nil {
				t.Fatalf("Matches: %v", err)
			}
			if got != tc.want {
				t.Errorf("Matches = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestRuleMatches_Condition(t *testing.T) {
	t.Parallel()
	r := mustRule(t, Rule{Match: Matcher{
		Condition: `assertion.repository == "acme/tool" && assertion.ref.startsWith("refs/heads/release/")`,
	}})
	if ok, err := r.Matches(claimsFor(t, map[string]any{"ref": "refs/heads/release/1.2"})); err != nil || !ok {
		t.Fatalf("Matches = (%v, %v), want (true, nil)", ok, err)
	}
	if ok, err := r.Matches(claimsFor(t, nil)); err != nil || ok {
		t.Fatalf("Matches = (%v, %v), want (false, nil)", ok, err)
	}
}

func TestRuleMatches_GlobAndConditionCompose(t *testing.T) {
	t.Parallel()
	// Both halves must pass. A condition cannot widen a glob.
	r := mustRule(t, Rule{Match: Matcher{
		Repository: "acme/tool",
		Condition:  `assertion.actor == "dana"`,
	}})
	if ok, _ := r.Matches(claimsFor(t, nil)); !ok {
		t.Error("want a match when both halves pass")
	}
	if ok, _ := r.Matches(claimsFor(t, map[string]any{"actor": "mallory"})); ok {
		t.Error("condition failed but the rule matched anyway")
	}
	if ok, _ := r.Matches(claimsFor(t, map[string]any{"repository": "other/repo"})); ok {
		t.Error("glob failed but the rule matched anyway")
	}
}

func TestRuleMatches_UndecidableConditionIsAnErrorNotAMatch(t *testing.T) {
	t.Parallel()
	r := mustRule(t, Rule{Match: Matcher{
		Repository: "acme/tool",
		Condition:  `assertion.environment == "production"`,
	}})
	ok, err := r.Matches(claimsFor(t, nil)) // no environment claim
	if ok {
		t.Fatal("a rule reading an absent claim matched")
	}
	if err == nil {
		t.Fatal("want an error so the operator learns the rule could not be decided")
	}
}

func TestRuleMatches_DisabledRuleNeverMatches(t *testing.T) {
	t.Parallel()
	r := mustRule(t, Rule{Match: Matcher{Repository: "acme/tool"}})
	r.Enabled = false
	if ok, err := r.Matches(claimsFor(t, nil)); ok || err != nil {
		t.Fatalf("Matches = (%v, %v), want (false, nil)", ok, err)
	}
}

func TestRuleMatches_UnpreparedRuleRefuses(t *testing.T) {
	t.Parallel()
	// A rule that skipped Validate has a condition nobody compiled. Matching
	// it would mean ignoring the condition entirely.
	r := &Rule{ID: "x", Name: "x", Enabled: true, Match: Matcher{
		Repository: "acme/tool",
		Condition:  `assertion.actor == "nobody"`,
	}}
	if ok, err := r.Matches(claimsFor(t, nil)); ok || err == nil {
		t.Fatalf("Matches = (%v, %v), want (false, error)", ok, err)
	}
}

func TestRuleValidate_RefusesRulesThatWouldOverReach(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		rule Rule
		want string
	}{
		{"no name", Rule{Match: Matcher{Repository: "acme/tool"}}, "name is required"},
		{"no matcher at all", Rule{Name: "n"}, "must constrain something"},
		{"only a ref", Rule{Name: "n", Match: Matcher{Ref: "refs/heads/main"}}, "must identify the repository"},
		{"only a workflow", Rule{Name: "n", Match: Matcher{Workflow: "release"}}, "must identify the repository"},
		{"only an environment", Rule{Name: "n", Match: Matcher{Environment: "production"}}, "must identify the repository"},
		{"only an actor", Rule{Name: "n", Match: Matcher{Actor: "dana"}}, "must identify the repository"},
		{"wildcard owner", Rule{Name: "n", Match: Matcher{Repository: "*/tool"}}, "owner segment"},
		{"bare wildcard", Rule{Name: "n", Match: Matcher{Repository: "*"}}, "owner/name"},
		{"wildcard both", Rule{Name: "n", Match: Matcher{Repository: "*/*"}}, "owner segment"},
		{"no slash", Rule{Name: "n", Match: Matcher{Repository: "tool"}}, "owner/name"},
		{"empty owner", Rule{Name: "n", Match: Matcher{Repository: "/tool"}}, "owner/name"},
		{"three segments", Rule{Name: "n", Match: Matcher{Repository: "acme/tool/extra"}}, "no slash"},
		{"bad glob", Rule{Name: "n", Match: Matcher{Repository: "acme/[", Ref: ""}}, "valid glob"},
		{"bad ref glob", Rule{Name: "n", Match: Matcher{Repository: "acme/tool", Ref: "["}}, "valid glob"},
		{"bad condition", Rule{Name: "n", Match: Matcher{Condition: `assertion.repo ==`}}, "condition"},
		{"condition using a macro", Rule{Name: "n", Match: Matcher{Condition: `assertion.x.all(i, i > 1)`}}, "condition"},
		{"empty model entry", Rule{Name: "n", Match: Matcher{Repository: "acme/tool"}, Policy: GrantPolicy{Models: []string{""}}}, "empty entry"},
		{"negative ttl", Rule{Name: "n", Match: Matcher{Repository: "acme/tool"}, Policy: GrantPolicy{TTLSeconds: -1}}, "ttl_seconds"},
		{"negative requests", Rule{Name: "n", Match: Matcher{Repository: "acme/tool"}, Policy: GrantPolicy{MaxRequests: -1}}, "max_requests"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := tc.rule
			err := r.Validate()
			if err == nil {
				t.Fatalf("Validate accepted a rule it must refuse: %+v", tc.rule)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want it to mention %q", err, tc.want)
			}
		})
	}
}

func TestRuleValidate_AcceptsAConditionThatPinsTheRepository(t *testing.T) {
	t.Parallel()
	// A condition alone is enough, because a condition can pin the repository
	// in ways a glob cannot — for example a set of unrelated repositories.
	r := Rule{Name: "n", Match: Matcher{
		Condition: `assertion.repository in ["acme/tool", "acme/other"]`,
	}}
	if err := r.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestGrantPolicy_ClampsItsBounds(t *testing.T) {
	t.Parallel()
	if got := (GrantPolicy{}).TTL(); got != DefaultTTL {
		t.Errorf("TTL() = %v, want %v", got, DefaultTTL)
	}
	if got := (GrantPolicy{TTLSeconds: 1}).TTL(); got != MinTTL {
		t.Errorf("TTL() = %v, want it raised to %v", got, MinTTL)
	}
	if got := (GrantPolicy{TTLSeconds: 999999}).TTL(); got != MaxTTL {
		t.Errorf("TTL() = %v, want it clamped to %v", got, MaxTTL)
	}
	if got := (GrantPolicy{}).Requests(); got != DefaultMaxRequests {
		t.Errorf("Requests() = %d, want %d", got, DefaultMaxRequests)
	}
	if got := (GrantPolicy{MaxRequests: 1 << 30}).Requests(); got != MaxRequestsCeiling {
		t.Errorf("Requests() = %d, want %d", got, MaxRequestsCeiling)
	}
}

func TestGrantPolicy_AllowsModel(t *testing.T) {
	t.Parallel()
	p := GrantPolicy{Models: []string{"claude-sonnet-*", "claude-haiku-4-5-20251001"}}
	for _, tc := range []struct {
		model string
		want  bool
	}{
		{"claude-sonnet-4-6", true},
		{"claude-haiku-4-5-20251001", true},
		{"claude-opus-4-8", false},
		{"", false},
		{"claude-sonnet", false},
	} {
		if got := p.AllowsModel(tc.model); got != tc.want {
			t.Errorf("AllowsModel(%q) = %v, want %v", tc.model, got, tc.want)
		}
	}
	// An empty allowlist denies. The one reading of "no models listed" that
	// must never be "every model" is this one.
	if (GrantPolicy{}).AllowsModel("claude-sonnet-4-6") {
		t.Error("an empty model allowlist admitted a model")
	}
}

func TestRuleSet_FirstMatchWinsInAStableOrder(t *testing.T) {
	t.Parallel()
	base := time.Now()
	rs := NewRuleSet([]Rule{
		{ID: "b", Name: "broad", Enabled: true, CreatedAt: base.Add(time.Minute),
			Match: Matcher{Repository: "acme/*"}, Policy: GrantPolicy{MaxRequests: 10}},
		{ID: "a", Name: "narrow", Enabled: true, CreatedAt: base,
			Match: Matcher{Repository: "acme/tool"}, Policy: GrantPolicy{MaxRequests: 99}},
	})
	if rs.Len() != 2 {
		t.Fatalf("Len() = %d, want 2", rs.Len())
	}
	res := rs.Match(claimsFor(t, nil))
	if res.Rule == nil {
		t.Fatal("no rule matched")
	}
	// Ordered by creation time, so the older narrow rule is consulted first
	// regardless of the slice order handed to NewRuleSet.
	if res.Rule.ID != "a" {
		t.Errorf("matched rule %q, want the earlier-created %q", res.Rule.ID, "a")
	}
}

func TestRuleSet_NoMatchIsNotAnError(t *testing.T) {
	t.Parallel()
	rs := NewRuleSet([]Rule{{ID: "a", Name: "n", Enabled: true, Match: Matcher{Repository: "other/repo"}}})
	res := rs.Match(claimsFor(t, nil))
	if res.Rule != nil {
		t.Fatal("a rule matched that should not have")
	}
	if res.Considered != 1 {
		t.Errorf("Considered = %d, want 1", res.Considered)
	}
	if len(res.Errors) != 0 {
		t.Errorf("Errors = %v, want none", res.Errors)
	}
}

func TestRuleSet_AnUndecidableRuleDoesNotStopTheSearch(t *testing.T) {
	t.Parallel()
	base := time.Now()
	rs := NewRuleSet([]Rule{
		{ID: "broken", Name: "reads a missing claim", Enabled: true, CreatedAt: base,
			Match: Matcher{Repository: "acme/tool", Condition: `assertion.environment == "prod"`}},
		{ID: "good", Name: "plain", Enabled: true, CreatedAt: base.Add(time.Second),
			Match: Matcher{Repository: "acme/tool"}},
	})
	res := rs.Match(claimsFor(t, nil))
	if res.Rule == nil || res.Rule.ID != "good" {
		t.Fatalf("matched %v, want the rule after the undecidable one", res.Rule)
	}
	if res.Errors["broken"] == "" {
		t.Error("the undecidable rule was not reported")
	}
}

func TestRuleSet_OneBadRuleDoesNotDisableTheRest(t *testing.T) {
	t.Parallel()
	rs := NewRuleSet([]Rule{
		{ID: "bad", Name: "", Enabled: true}, // fails Validate
		{ID: "good", Name: "n", Enabled: true, Match: Matcher{Repository: "acme/tool"}},
	})
	if rs.Len() != 1 {
		t.Fatalf("Len() = %d, want 1 rule in force", rs.Len())
	}
	if rs.Broken()["bad"] == "" {
		t.Error("the unloadable rule was not reported as broken")
	}
	if res := rs.Match(claimsFor(t, nil)); res.Rule == nil || res.Rule.ID != "good" {
		t.Errorf("matched %v, want the loadable rule", res.Rule)
	}
}

func TestRuleSet_DisabledRulesAreSkipped(t *testing.T) {
	t.Parallel()
	rs := NewRuleSet([]Rule{{ID: "a", Name: "n", Enabled: false, Match: Matcher{Repository: "acme/tool"}}})
	res := rs.Match(claimsFor(t, nil))
	if res.Rule != nil {
		t.Fatal("a disabled rule matched")
	}
	if res.Considered != 0 {
		t.Errorf("Considered = %d, want 0", res.Considered)
	}
}

func TestRuleSet_NilIsUsable(t *testing.T) {
	t.Parallel()
	var rs *RuleSet
	if rs.Len() != 0 || rs.Match(claimsFor(t, nil)).Rule != nil || rs.Broken() != nil {
		t.Error("a nil RuleSet should behave as an empty one")
	}
}
