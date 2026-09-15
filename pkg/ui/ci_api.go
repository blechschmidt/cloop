package ui

// CI/CD pipeline federation endpoints (Task 20278).
//
// Two of these are reached by a pipeline and carry their own credential:
//
//	POST /api/ci/token          exchange a forge OIDC assertion for a session
//	ANY  /api/ci/anthropic/…    relay to the Anthropic API under that session
//
// The rest are ordinary RBAC-gated configuration, reached by an operator:
//
//	GET/PUT /api/ci/config      the deployment switch and its shape
//	GET     /api/ci/rules       the pipeline allowlist
//	POST    /api/ci/rules       add a rule
//	PUT     /api/ci/rules/{id}  edit one
//	DELETE  /api/ci/rules/{id}  remove one, revoking its live sessions
//	POST    /api/ci/rules/test  dry-run a rule against a claim set
//	GET     /api/ci/sessions    live sessions and their spend
//	DELETE  /api/ci/sessions/{id}  revoke one now
//	GET     /api/ci/exchanges   recent federation attempts, accepted and not
//
// # Why the exchange tells the pipeline so little
//
// A refused exchange answers 403 with one sentence and no detail about which
// rule nearly matched or what the allowlist contains. The caller is
// unauthenticated by construction, so every word of explanation is a word an
// attacker enumerating the hub gets for free. The detail exists — it is in
// /api/ci/exchanges, behind RBAC, where the operator who can act on it is.

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/apierror"
	"github.com/blechschmidt/cloop/pkg/ciauth"
	"github.com/blechschmidt/cloop/pkg/claudeproxy"
	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/logger"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// maxCIAssertionBytes bounds the exchange request body. The assertion inside
// is bounded again by pkg/ciauth; this is the outer guard on an endpoint that
// answers before authentication.
const maxCIAssertionBytes = 64 << 10

// ---------------------------------------------------------------------------
// The exchange
// ---------------------------------------------------------------------------

type ciExchangeRequest struct {
	// Token is the forge's OIDC assertion. `id_token` is accepted as an
	// alias because that is what the OIDC specification calls it and what
	// several CI helper actions name their output.
	Token   string `json:"token"`
	IDToken string `json:"id_token"`
}

type ciExchangeResponse struct {
	Token     string    `json:"token"`
	BaseURL   string    `json:"base_url"`
	SessionID string    `json:"session_id"`
	ExpiresAt time.Time `json:"expires_at"`
	ExpiresIn int       `json:"expires_in"`

	Models      []string `json:"models"`
	MaxRequests int      `json:"max_requests"`
	Rule        string   `json:"rule"`
	Pipeline    string   `json:"pipeline"`

	// Env is the exact environment a pipeline needs, so a workflow step is a
	// loop over a map rather than a list of names the author has to know.
	Env map[string]string `json:"env"`
}

// handleCIExchange serves POST /api/ci/token.
//
// It is reached without a hub session: the assertion is the credential. Every
// refusal is recorded with the claims that were actually presented, because
// the operator debugging "my pipeline gets a 403" cannot decode the token and
// has nowhere else to look.
func (s *Server) handleCIExchange(w http.ResponseWriter, r *http.Request) {
	svc, err := s.ciSvc()
	if err != nil {
		if errors.Is(err, ciauth.ErrDisabled) {
			s.recordCIExchange(r, statedb.CIExchangeRow{
				Reason: "disabled", Detail: "CI federation is not enabled on this hub"}, nil)
			apierror.WriteError(w, apierror.New(apierror.CodeUnavailable,
				"CI federation is not enabled on this hub"))
			return
		}
		s.log().Error(logger.EventAuthz, 0, "ci: build federation service",
			map[string]interface{}{"error": err.Error()})
		s.recordCIExchange(r, statedb.CIExchangeRow{
			Reason: "misconfigured", Detail: err.Error()}, nil)
		// The operator's problem, not the pipeline's, and the pipeline is not
		// told what it is.
		apierror.WriteError(w, apierror.New(apierror.CodeUnavailable,
			"CI federation is not available on this hub"))
		return
	}

	var req ciExchangeRequest
	limitJSONBody(w, r, maxCIAssertionBytes)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondToBodyError(w, err)
		return
	}
	assertion := strings.TrimSpace(req.Token)
	if assertion == "" {
		assertion = strings.TrimSpace(req.IDToken)
	}
	if assertion == "" {
		// Also accept the bearer form, which is what a bare `curl -H
		// "Authorization: Bearer $ID_TOKEN"` sends and what several CI
		// examples reach for first.
		if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
			assertion = strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))
		}
	}
	if assertion == "" {
		apierror.WriteError(w, apierror.New(apierror.CodeInvalidInput,
			"send the pipeline's OIDC token as {\"token\": \"…\"}"))
		return
	}

	claims, err := svc.verifier.Verify(r.Context(), assertion)
	if err != nil {
		s.recordCIExchange(r, statedb.CIExchangeRow{
			Issuer: svc.verifier.Issuer(),
			Reason: "unverified", Detail: err.Error()}, nil)
		apierror.WriteError(w, apierror.New(apierror.CodeUnauthorized,
			"the pipeline's OIDC token was not accepted"))
		return
	}

	rules, err := s.ciRuleSet()
	if err != nil {
		s.log().Error(logger.EventAuthz, 0, "ci: load rules",
			map[string]interface{}{"error": err.Error()})
		s.recordCIExchange(r, statedb.CIExchangeRow{Reason: "rules_unavailable",
			Detail: err.Error()}, claims)
		apierror.WriteError(w, apierror.New(apierror.CodeUnavailable,
			"CI federation is not available on this hub"))
		return
	}
	res := rules.Match(claims)
	if res.Rule == nil {
		detail := fmt.Sprintf("no rule admits this pipeline (%d considered)", res.Considered)
		if len(res.Errors) > 0 {
			// The single most useful line in this whole file. A rule reading
			// a claim the token does not carry looks exactly like "no rule
			// matched" from the pipeline's side, and an operator who cannot
			// tell them apart will rewrite a rule that was nearly right.
			var parts []string
			for id, msg := range res.Errors {
				parts = append(parts, id+": "+msg)
			}
			sort.Strings(parts)
			detail += "; undecidable rules: " + strings.Join(parts, "; ")
		}
		s.recordCIExchange(r, statedb.CIExchangeRow{Reason: "no_rule", Detail: detail}, claims)
		apierror.WriteError(w, apierror.New(apierror.CodeForbidden,
			"this pipeline is not on the hub's CI allowlist"))
		return
	}

	models := res.Rule.Policy.Models
	if len(models) == 0 {
		models = svc.models
	}
	minted, err := svc.reg.Mint(claudeproxy.MintRequest{
		Policy: claudeproxy.Policy{
			Models:          models,
			MaxOutputTokens: res.Rule.Policy.MaxOutputTokens,
			MaxRequests:     res.Rule.Policy.Requests(),
		},
		RuleID:     res.Rule.ID,
		RuleName:   res.Rule.Name,
		Project:    res.Rule.Project,
		Subject:    claims.Subject,
		Repository: claims.Repository,
		Ref:        claims.Ref,
		Workflow:   claims.Workflow,
		Actor:      claims.Actor,
		RunID:      claims.RunID,
		RunURL:     claims.RunURL(""),
		TTL:        res.Rule.Policy.TTL(),
	})
	if err != nil {
		s.log().Error(logger.EventAuthz, 0, "ci: mint session",
			map[string]interface{}{"error": err.Error()})
		s.recordCIExchange(r, statedb.CIExchangeRow{
			RuleID: res.Rule.ID, RuleName: res.Rule.Name,
			Reason: "mint_failed", Detail: err.Error()}, claims)
		apierror.WriteError(w, apierror.New(apierror.CodeUnavailable,
			"the hub could not issue a CI session"))
		return
	}

	baseURL := s.ciBaseURL(r)
	s.recordCIExchange(r, statedb.CIExchangeRow{
		Accepted: true, RuleID: res.Rule.ID, RuleName: res.Rule.Name,
		SessionID: minted.Session.ID,
		Detail: fmt.Sprintf("session for %s, %d requests, expires %s",
			claims.Label(), minted.Session.Policy.MaxRequests,
			minted.Session.ExpiresAt.UTC().Format(time.RFC3339))}, claims)
	s.touchCIRule(res.Rule.ID)

	// The one place the session token is written out. It is returned over the
	// same TLS connection the assertion arrived on and is never stored.
	jsonOK(w, ciExchangeResponse{
		Token:       minted.Token,
		BaseURL:     baseURL,
		SessionID:   minted.Session.ID,
		ExpiresAt:   minted.Session.ExpiresAt,
		ExpiresIn:   int(time.Until(minted.Session.ExpiresAt).Seconds()),
		Models:      models,
		MaxRequests: minted.Session.Policy.MaxRequests,
		Rule:        res.Rule.Name,
		Pipeline:    claims.Label(),
		Env: map[string]string{
			"ANTHROPIC_BASE_URL":   baseURL,
			"ANTHROPIC_AUTH_TOKEN": minted.Token,
		},
	})
}

// handleCIRelay serves the Anthropic relay subtree.
//
// It is reached without a hub session: the session token minted above is the
// credential, and pkg/claudeproxy authenticates it.
func (s *Server) handleCIRelay(w http.ResponseWriter, r *http.Request) {
	svc, err := s.ciSvc()
	if err != nil {
		// Shaped as an Anthropic API error so an SDK surfaces the sentence
		// rather than "unexpected response body".
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"type": "error",
			"error": map[string]any{
				"type":    "api_error",
				"message": "CI federation is not available on this hub",
			},
		})
		return
	}
	svc.proxy.ServeHTTP(w, r)
}

// ---------------------------------------------------------------------------
// Rules
// ---------------------------------------------------------------------------

// ciRuleSet loads and prepares the stored allowlist.
func (s *Server) ciRuleSet() (*ciauth.RuleSet, error) {
	rows, err := s.listCIRuleRows()
	if err != nil {
		return nil, err
	}
	rules := make([]ciauth.Rule, 0, len(rows))
	for _, row := range rows {
		rules = append(rules, ciRuleFromRow(row))
	}
	return ciauth.NewRuleSet(rules), nil
}

func (s *Server) listCIRuleRows() ([]statedb.CIPipelineRuleRow, error) {
	db, err := s.controlPlaneDB()
	if err != nil {
		return nil, err
	}
	defer db.Close() //nolint:errcheck // read-only
	return db.ListCIPipelineRules()
}

func ciRuleFromRow(row statedb.CIPipelineRuleRow) ciauth.Rule {
	return ciauth.Rule{
		ID:      row.ID,
		Name:    row.Name,
		Enabled: row.Enabled,
		Match: ciauth.Matcher{
			Repository:  row.Repository,
			Ref:         row.Ref,
			Workflow:    row.Workflow,
			Environment: row.Environment,
			Actor:       row.Actor,
			EventName:   row.EventName,
			Condition:   row.Condition,
		},
		Policy: ciauth.GrantPolicy{
			Models:          row.Models,
			MaxRequests:     row.MaxRequests,
			MaxOutputTokens: row.MaxOutputTokens,
			TTLSeconds:      row.TTLSeconds,
		},
		Project:       row.Project,
		CreatedBy:     row.CreatedBy,
		CreatedAt:     row.CreatedAt,
		UpdatedAt:     row.UpdatedAt,
		LastMatchedAt: row.LastMatchedAt,
	}
}

func ciRowFromRule(r ciauth.Rule) statedb.CIPipelineRuleRow {
	return statedb.CIPipelineRuleRow{
		ID:              r.ID,
		Name:            r.Name,
		Enabled:         r.Enabled,
		Repository:      r.Match.Repository,
		Ref:             r.Match.Ref,
		Workflow:        r.Match.Workflow,
		Environment:     r.Match.Environment,
		Actor:           r.Match.Actor,
		EventName:       r.Match.EventName,
		Condition:       r.Match.Condition,
		Models:          r.Policy.Models,
		MaxRequests:     r.Policy.MaxRequests,
		MaxOutputTokens: r.Policy.MaxOutputTokens,
		TTLSeconds:      r.Policy.TTLSeconds,
		Project:         r.Project,
		CreatedBy:       r.CreatedBy,
		CreatedAt:       r.CreatedAt,
		UpdatedAt:       r.UpdatedAt,
		LastMatchedAt:   r.LastMatchedAt,
	}
}

// ciRuleView is a rule as the panel sees it.
type ciRuleView struct {
	statedb.CIPipelineRuleRow
	// Broken reports why a stored rule is not in force. Empty means it is.
	Broken string `json:"broken,omitempty"`
	// EffectiveModels is what this rule actually grants once the hub default
	// has been applied, so the panel does not have to reimplement the rule.
	EffectiveModels []string `json:"effective_models"`
	EffectiveTTL    int      `json:"effective_ttl_seconds"`
	EffectiveMax    int      `json:"effective_max_requests"`
	// LiveSessions counts sessions currently minted under this rule.
	LiveSessions int `json:"live_sessions"`
}

type ciRulesResponse struct {
	Rules []ciRuleView `json:"rules"`
	// DefaultModels is what a rule naming no models inherits.
	DefaultModels []string `json:"default_models"`
	Enabled       bool     `json:"enabled"`
}

// handleCIRulesList serves GET /api/ci/rules.
func (s *Server) handleCIRulesList(w http.ResponseWriter, r *http.Request) {
	rows, err := s.listCIRuleRows()
	if err != nil {
		apierror.WriteError(w, apierror.New(apierror.CodeUnavailable, err.Error()))
		return
	}
	// Prepared here as well as at exchange time so the panel can show which
	// stored rules are inert. A rule that stopped compiling — because a claim
	// was renamed, or because the row was hand-edited — is invisible
	// otherwise, and its absence reads as "someone deleted my rule".
	set := ciauth.NewRuleSet(func() []ciauth.Rule {
		out := make([]ciauth.Rule, 0, len(rows))
		for _, row := range rows {
			out = append(out, ciRuleFromRow(row))
		}
		return out
	}())
	broken := set.Broken()

	live := map[string]int{}
	if svc := s.ci.svc.Load(); svc != nil {
		for _, sess := range svc.reg.Sessions() {
			live[sess.RuleID]++
		}
	}

	defaults := config.DefaultCIModels
	enabled := false
	if cfg, err := s.loadHubConfig(); err == nil && cfg != nil {
		defaults = cfg.UI.CI.Models()
		enabled = cfg.UI.CI.Enabled
	}

	views := make([]ciRuleView, 0, len(rows))
	for _, row := range rows {
		rule := ciRuleFromRow(row)
		models := rule.Policy.Models
		if len(models) == 0 {
			models = defaults
		}
		views = append(views, ciRuleView{
			CIPipelineRuleRow: row,
			Broken:            broken[row.ID],
			EffectiveModels:   models,
			EffectiveTTL:      int(rule.Policy.TTL().Seconds()),
			EffectiveMax:      rule.Policy.Requests(),
			LiveSessions:      live[row.ID],
		})
	}
	jsonOK(w, ciRulesResponse{Rules: views, DefaultModels: defaults, Enabled: enabled})
}

// ciRuleRequest is the wire shape of a create or edit.
type ciRuleRequest struct {
	Name    string `json:"name"`
	Enabled *bool  `json:"enabled"`

	Repository  string `json:"repository"`
	Ref         string `json:"ref"`
	Workflow    string `json:"workflow"`
	Environment string `json:"environment"`
	Actor       string `json:"actor"`
	EventName   string `json:"event_name"`
	Condition   string `json:"condition"`

	Models          []string `json:"models"`
	MaxRequests     int      `json:"max_requests"`
	MaxOutputTokens int      `json:"max_output_tokens"`
	TTLSeconds      int      `json:"ttl_seconds"`
	Project         string   `json:"project"`
}

func (req ciRuleRequest) toRule(id string) ciauth.Rule {
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	models := make([]string, 0, len(req.Models))
	for _, m := range req.Models {
		if t := strings.TrimSpace(m); t != "" {
			models = append(models, t)
		}
	}
	return ciauth.Rule{
		ID:      id,
		Name:    req.Name,
		Enabled: enabled,
		Match: ciauth.Matcher{
			Repository:  req.Repository,
			Ref:         req.Ref,
			Workflow:    req.Workflow,
			Environment: req.Environment,
			Actor:       req.Actor,
			EventName:   req.EventName,
			Condition:   req.Condition,
		},
		Policy: ciauth.GrantPolicy{
			Models:          models,
			MaxRequests:     req.MaxRequests,
			MaxOutputTokens: req.MaxOutputTokens,
			TTLSeconds:      req.TTLSeconds,
		},
		Project: req.Project,
	}
}

// handleCIRuleCreate serves POST /api/ci/rules.
func (s *Server) handleCIRuleCreate(w http.ResponseWriter, r *http.Request) {
	var req ciRuleRequest
	if !decodeSecretsBody(w, r, &req) {
		return
	}
	id, err := newCIRuleID()
	if err != nil {
		apierror.WriteError(w, apierror.New(apierror.CodeInternal, err.Error()))
		return
	}
	rule := req.toRule(id)
	// Validation is pkg/ciauth's, not this layer's. Every refusal it produces
	// is a rule that would have admitted more pipelines than the author meant.
	if err := rule.Validate(); err != nil {
		apierror.WriteError(w, apierror.New(apierror.CodeInvalidInput, err.Error()))
		return
	}
	now := time.Now().UTC()
	rule.CreatedAt, rule.UpdatedAt = now, now
	rule.CreatedBy = s.grantFor(r).subjectLabel()

	if err := s.putCIRule(rule); err != nil {
		apierror.WriteError(w, apierror.New(apierror.CodeUnavailable, err.Error()))
		return
	}
	s.auditCIRule(r, "ci.rule.created", rule, "")
	jsonOK(w, map[string]any{"ok": true, "id": id})
}

// handleCIRuleUpdate serves PUT /api/ci/rules/{id}.
func (s *Server) handleCIRuleUpdate(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		apierror.WriteError(w, apierror.New(apierror.CodeInvalidInput, "rule id is required"))
		return
	}
	var req ciRuleRequest
	if !decodeSecretsBody(w, r, &req) {
		return
	}
	existing, err := s.getCIRule(id)
	if err != nil {
		if errors.Is(err, statedb.ErrCIPipelineRuleNotFound) {
			apierror.WriteError(w, apierror.New(apierror.CodeNotFound, "no such rule"))
			return
		}
		apierror.WriteError(w, apierror.New(apierror.CodeUnavailable, err.Error()))
		return
	}
	rule := req.toRule(id)
	if err := rule.Validate(); err != nil {
		apierror.WriteError(w, apierror.New(apierror.CodeInvalidInput, err.Error()))
		return
	}
	rule.CreatedAt = existing.CreatedAt
	rule.CreatedBy = existing.CreatedBy
	rule.UpdatedAt = time.Now().UTC()

	if err := s.putCIRule(rule); err != nil {
		apierror.WriteError(w, apierror.New(apierror.CodeUnavailable, err.Error()))
		return
	}
	// An edit narrows as often as it widens, and a session minted under the
	// old text would keep spending under a policy that no longer exists. The
	// pipeline re-federates on its next run at the cost of one request.
	closed := s.closeCISessionsForRule(id, "rule edited")
	s.auditCIRule(r, "ci.rule.updated", rule, fmt.Sprintf("%d live sessions revoked", closed))
	jsonOK(w, map[string]any{"ok": true, "revoked_sessions": closed})
}

// handleCIRuleDelete serves DELETE /api/ci/rules/{id}.
func (s *Server) handleCIRuleDelete(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		apierror.WriteError(w, apierror.New(apierror.CodeInvalidInput, "rule id is required"))
		return
	}
	db, err := s.controlPlaneDB()
	if err != nil {
		apierror.WriteError(w, apierror.New(apierror.CodeUnavailable, err.Error()))
		return
	}
	defer db.Close() //nolint:errcheck
	removed, err := db.DeleteCIPipelineRule(id)
	if err != nil {
		apierror.WriteError(w, apierror.New(apierror.CodeUnavailable, err.Error()))
		return
	}
	if !removed {
		apierror.WriteError(w, apierror.New(apierror.CodeNotFound, "no such rule"))
		return
	}
	closed := s.closeCISessionsForRule(id, "rule deleted")
	s.auditCIRule(r, "ci.rule.deleted", ciauth.Rule{ID: id},
		fmt.Sprintf("%d live sessions revoked", closed))
	jsonOK(w, map[string]any{"ok": true, "revoked_sessions": closed})
}

// ciRuleTestRequest dry-runs a rule against a claim set.
type ciRuleTestRequest struct {
	ciRuleRequest
	// Claims is the token payload to test against. Empty uses a
	// representative GitHub Actions claim set, so the common case — "does my
	// condition parse, and does it do roughly what I meant" — needs no input.
	Claims map[string]any `json:"claims"`
}

type ciRuleTestResponse struct {
	Valid   bool     `json:"valid"`
	Error   string   `json:"error,omitempty"`
	Matched bool     `json:"matched"`
	Reason  string   `json:"reason,omitempty"`
	Claims  []string `json:"condition_reads,omitempty"`
}

// handleCIRuleTest serves POST /api/ci/rules/test.
//
// A rule is a security policy typed into a form, and the two questions its
// author has — "will this compile" and "would it admit the pipeline I am
// thinking of" — are otherwise answerable only by pushing a commit and
// watching a workflow fail. This is the cheap answer to both.
func (s *Server) handleCIRuleTest(w http.ResponseWriter, r *http.Request) {
	var req ciRuleTestRequest
	if !decodeSecretsBody(w, r, &req) {
		return
	}
	rule := req.ciRuleRequest.toRule("test")
	rule.Enabled = true
	if err := rule.Validate(); err != nil {
		jsonOK(w, ciRuleTestResponse{Valid: false, Error: err.Error()})
		return
	}
	claims := req.Claims
	if len(claims) == 0 {
		claims = sampleCIClaims()
	}
	probe := &ciauth.Claims{All: claims}
	probe.Repository, _ = claims["repository"].(string)
	probe.Ref, _ = claims["ref"].(string)
	probe.Workflow, _ = claims["workflow"].(string)
	probe.WorkflowRef, _ = claims["workflow_ref"].(string)
	probe.Environment, _ = claims["environment"].(string)
	probe.Actor, _ = claims["actor"].(string)
	probe.EventName, _ = claims["event_name"].(string)
	probe.Subject, _ = claims["sub"].(string)

	matched, err := rule.Matches(probe)
	resp := ciRuleTestResponse{Valid: true, Matched: matched}
	if err != nil {
		// Undecidable, which is neither a match nor a clean decline. Naming
		// it here is what stops an operator shipping a rule that will refuse
		// every real token for a reason they cannot see.
		resp.Matched = false
		resp.Reason = err.Error()
	} else if !matched {
		resp.Reason = "the claim set does not satisfy this rule"
	}
	jsonOK(w, resp)
}

// sampleCIClaims is a representative GitHub Actions payload for the rule
// tester. It is a fixture, not a default: nothing outside the tester reads it.
func sampleCIClaims() map[string]any {
	return map[string]any{
		"iss":                   ciauth.GitHubActionsIssuer,
		"aud":                   ciauth.DefaultAudience,
		"sub":                   "repo:acme/tool:ref:refs/heads/main",
		"repository":            "acme/tool",
		"repository_owner":      "acme",
		"repository_visibility": "private",
		"ref":                   "refs/heads/main",
		"ref_type":              "branch",
		"workflow":              "release",
		"workflow_ref":          "acme/tool/.github/workflows/release.yml@refs/heads/main",
		"actor":                 "dana",
		"event_name":            "push",
		"run_id":                "1234567890",
		"runner_environment":    "github-hosted",
	}
}

func (s *Server) getCIRule(id string) (statedb.CIPipelineRuleRow, error) {
	db, err := s.controlPlaneDB()
	if err != nil {
		return statedb.CIPipelineRuleRow{}, err
	}
	defer db.Close() //nolint:errcheck
	return db.GetCIPipelineRule(id)
}

func (s *Server) putCIRule(rule ciauth.Rule) error {
	db, err := s.controlPlaneDB()
	if err != nil {
		return err
	}
	defer db.Close() //nolint:errcheck
	return db.PutCIPipelineRule(ciRowFromRule(rule))
}

func (s *Server) touchCIRule(id string) {
	db, err := s.controlPlaneDB()
	if err != nil {
		return
	}
	defer db.Close() //nolint:errcheck
	// Advisory. A federation that succeeded must not be reported as failed
	// because a bookkeeping write lost a race with a delete.
	_ = db.TouchCIPipelineRule(id, time.Now().UTC())
}

// closeCISessionsForRule revokes the live sessions a rule minted.
func (s *Server) closeCISessionsForRule(id, reason string) int {
	svc := s.ci.svc.Load()
	if svc == nil {
		return 0
	}
	return svc.reg.CloseByRule(id, reason)
}

// ---------------------------------------------------------------------------
// Sessions
// ---------------------------------------------------------------------------

type ciSessionView struct {
	ID         string    `json:"id"`
	RuleID     string    `json:"rule_id,omitempty"`
	RuleName   string    `json:"rule_name,omitempty"`
	Project    string    `json:"project,omitempty"`
	Repository string    `json:"repository,omitempty"`
	Ref        string    `json:"ref,omitempty"`
	Workflow   string    `json:"workflow,omitempty"`
	Actor      string    `json:"actor,omitempty"`
	RunURL     string    `json:"run_url,omitempty"`
	IssuedAt   time.Time `json:"issued_at"`
	ExpiresAt  time.Time `json:"expires_at"`
	LastUsedAt time.Time `json:"last_used_at,omitempty"`
	Models     []string  `json:"models"`

	Remaining int               `json:"remaining_requests"`
	Usage     claudeproxy.Usage `json:"usage"`
}

// handleCISessionsList serves GET /api/ci/sessions.
func (s *Server) handleCISessionsList(w http.ResponseWriter, r *http.Request) {
	out := []ciSessionView{}
	if svc := s.ci.svc.Load(); svc != nil {
		for _, sess := range svc.reg.Sessions() {
			out = append(out, ciSessionView{
				ID: sess.ID, RuleID: sess.RuleID, RuleName: sess.RuleName,
				Project: sess.Project, Repository: sess.Repository, Ref: sess.Ref,
				Workflow: sess.Workflow, Actor: sess.Actor, RunURL: sess.RunURL,
				IssuedAt: sess.IssuedAt, ExpiresAt: sess.ExpiresAt,
				LastUsedAt: sess.LastUsed(), Models: sess.Policy.Models,
				Remaining: int(sess.RemainingRequests()), Usage: sess.Usage(),
			})
		}
	}
	jsonOK(w, map[string]any{"sessions": out})
}

// handleCISessionRevoke serves DELETE /api/ci/sessions/{id}.
func (s *Server) handleCISessionRevoke(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("id"))
	svc := s.ci.svc.Load()
	if svc == nil {
		apierror.WriteError(w, apierror.New(apierror.CodeNotFound, "no such session"))
		return
	}
	if err := svc.reg.Close(id, "revoked by operator"); err != nil {
		apierror.WriteError(w, apierror.New(apierror.CodeNotFound, "no such session"))
		return
	}
	s.auditCIRule(r, "ci.session.revoked", ciauth.Rule{ID: id}, "revoked by operator")
	jsonOK(w, map[string]any{"ok": true})
}

// handleCIExchanges serves GET /api/ci/exchanges.
func (s *Server) handleCIExchanges(w http.ResponseWriter, r *http.Request) {
	db, err := s.controlPlaneDB()
	if err != nil {
		apierror.WriteError(w, apierror.New(apierror.CodeUnavailable, err.Error()))
		return
	}
	defer db.Close() //nolint:errcheck
	rows, err := db.ListCIExchanges(100)
	if err != nil {
		apierror.WriteError(w, apierror.New(apierror.CodeUnavailable, err.Error()))
		return
	}
	if rows == nil {
		rows = []statedb.CIExchangeRow{}
	}
	jsonOK(w, map[string]any{"exchanges": rows})
}

// ---------------------------------------------------------------------------
// Settings
// ---------------------------------------------------------------------------

type ciSettingsView struct {
	Enabled          bool     `json:"enabled"`
	Issuer           string   `json:"issuer"`
	Audience         string   `json:"audience"`
	ClockSkewSeconds int      `json:"clock_skew_seconds"`
	DefaultModels    []string `json:"default_models"`
	UpstreamBaseURL  string   `json:"upstream_base_url,omitempty"`

	// Upstream describes the credential without revealing it, and
	// UpstreamReady is what the panel needs to warn before a pipeline finds
	// out: a hub with federation on and nothing to relay with answers every
	// exchange with a 503.
	Upstream      string `json:"upstream"`
	UpstreamReady bool   `json:"upstream_ready"`

	// BaseURL is what a pipeline should set ANTHROPIC_BASE_URL to.
	BaseURL string `json:"base_url"`

	// Error is the most recent build failure, if the service will not start.
	Error string `json:"error,omitempty"`

	// Snippet is a ready-to-paste workflow step.
	Snippet string `json:"snippet"`
}

// handleCISettings serves GET /api/ci/config.
func (s *Server) handleCISettings(w http.ResponseWriter, r *http.Request) {
	jsonOK(w, s.ciSettings(r))
}

func (s *Server) ciSettings(r *http.Request) ciSettingsView {
	view := ciSettingsView{
		Issuer:           ciauth.GitHubActionsIssuer,
		Audience:         ciauth.DefaultAudience,
		ClockSkewSeconds: config.CIClockSkewDefault,
		DefaultModels:    config.DefaultCIModels,
		BaseURL:          s.ciBaseURL(r),
	}
	cfg, err := s.loadHubConfig()
	if err == nil && cfg != nil {
		c := cfg.UI.CI
		view.Enabled = c.Enabled
		if v := strings.TrimSpace(c.Issuer); v != "" {
			view.Issuer = v
		}
		if v := strings.TrimSpace(c.Audience); v != "" {
			view.Audience = v
		}
		view.ClockSkewSeconds = c.ClockSkew()
		view.DefaultModels = c.Models()
		view.UpstreamBaseURL = c.UpstreamBaseURL

		up := claudeproxy.Upstream{BaseURL: c.UpstreamBaseURL}
		if tok := strings.TrimSpace(c.UpstreamAuthToken); tok != "" {
			up.AuthToken = tok
		} else {
			up.APIKey = strings.TrimSpace(cfg.Anthropic.APIKey)
		}
		view.Upstream = up.Redacted()
		view.UpstreamReady = up.Validate() == nil
	}
	if p := s.ci.lastErr.Load(); p != nil {
		view.Error = *p
	}
	view.Snippet = ciWorkflowSnippet(view.BaseURL, view.Audience)
	return view
}

type ciSettingsRequest struct {
	Enabled          *bool    `json:"enabled"`
	Issuer           *string  `json:"issuer"`
	Audience         *string  `json:"audience"`
	ClockSkewSeconds *int     `json:"clock_skew_seconds"`
	DefaultModels    []string `json:"default_models"`
	UpstreamBaseURL  *string  `json:"upstream_base_url"`
}

// handleCISettingsSave serves PUT /api/ci/config.
func (s *Server) handleCISettingsSave(w http.ResponseWriter, r *http.Request) {
	var req ciSettingsRequest
	if !decodeSecretsBody(w, r, &req) {
		return
	}

	hubConfigMu.Lock()
	cfg, err := config.Load(s.WorkDir)
	if err != nil || cfg == nil {
		hubConfigMu.Unlock()
		apierror.WriteError(w, apierror.New(apierror.CodeUnavailable, "load hub config"))
		return
	}
	was := cfg.UI.CI.Enabled
	if req.Enabled != nil {
		cfg.UI.CI.Enabled = *req.Enabled
	}
	if req.Issuer != nil {
		cfg.UI.CI.Issuer = strings.TrimSpace(*req.Issuer)
	}
	if req.Audience != nil {
		cfg.UI.CI.Audience = strings.TrimSpace(*req.Audience)
	}
	if req.ClockSkewSeconds != nil {
		cfg.UI.CI.ClockSkewSeconds = *req.ClockSkewSeconds
	}
	if req.DefaultModels != nil {
		models := make([]string, 0, len(req.DefaultModels))
		for _, m := range req.DefaultModels {
			if t := strings.TrimSpace(m); t != "" {
				models = append(models, t)
			}
		}
		cfg.UI.CI.DefaultModels = models
	}
	if req.UpstreamBaseURL != nil {
		cfg.UI.CI.UpstreamBaseURL = strings.TrimSpace(*req.UpstreamBaseURL)
	}

	// Refuse a configuration that could not work, rather than saving it and
	// letting the first pipeline discover it. The verifier's own constructor
	// is the check: it is the one that will run at exchange time.
	if cfg.UI.CI.Enabled {
		issuer := strings.TrimSpace(cfg.UI.CI.Issuer)
		if issuer == "" {
			issuer = ciauth.GitHubActionsIssuer
		}
		audience := strings.TrimSpace(cfg.UI.CI.Audience)
		if audience == "" {
			audience = ciauth.DefaultAudience
		}
		if _, err := ciauth.NewVerifier(ciauth.VerifierConfig{
			Issuer: issuer, Audience: audience,
		}); err != nil {
			hubConfigMu.Unlock()
			apierror.WriteError(w, apierror.New(apierror.CodeInvalidInput, err.Error()))
			return
		}
	}

	if err := config.Save(s.WorkDir, cfg); err != nil {
		hubConfigMu.Unlock()
		apierror.WriteError(w, apierror.New(apierror.CodeInternal, err.Error()))
		return
	}
	hubConfigMu.Unlock()

	// Turning the feature off must stop the pipelines already federated, not
	// just the ones that have not asked yet. Any other setting change is
	// picked up by the fingerprint on the next exchange.
	if was && !cfg.UI.CI.Enabled {
		s.ci.mu.Lock()
		if old := s.ci.svc.Swap(nil); old != nil {
			old.shutdown("CI federation disabled")
		}
		s.ci.mu.Unlock()
	}
	s.auditCIRule(r, "ci.config.updated", ciauth.Rule{},
		fmt.Sprintf("enabled=%v issuer=%q audience=%q",
			cfg.UI.CI.Enabled, cfg.UI.CI.Issuer, cfg.UI.CI.Audience))
	jsonOK(w, s.ciSettings(r))
}

// ciWorkflowSnippet renders the GitHub Actions step an operator pastes.
//
// Generated rather than documented because the two values that vary — this
// hub's URL and its audience — are exactly the two an operator gets wrong, and
// a snippet they can copy is the difference between the feature working on the
// first try and a support conversation about 401s.
func ciWorkflowSnippet(baseURL, audience string) string {
	hub := strings.TrimSuffix(baseURL, ciMountPath)
	return `permissions:
  id-token: write   # required: lets the job mint an OIDC token
  contents: read

steps:
  - uses: actions/checkout@v5
  - name: Federate with cloop
    run: |
      ID_TOKEN=$(curl -sS -H "Authorization: Bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
        "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=` + audience + `" | jq -r .value)
      RESP=$(curl -sS -X POST ` + hub + `/api/ci/token \
        -H 'content-type: application/json' \
        -d "{\"token\":\"$ID_TOKEN\"}")
      echo "ANTHROPIC_BASE_URL=$(echo "$RESP" | jq -r .base_url)" >> "$GITHUB_ENV"
      echo "::add-mask::$(echo "$RESP" | jq -r .token)"
      echo "ANTHROPIC_AUTH_TOKEN=$(echo "$RESP" | jq -r .token)" >> "$GITHUB_ENV"
  - name: Run the agent
    run: npx -y @anthropic-ai/claude-code -p "review the diff and fix any bug you find"`
}

// ---------------------------------------------------------------------------
// Audit
// ---------------------------------------------------------------------------

// recordCIExchange stores a federation attempt and mirrors it into the audit
// trail.
//
// Storage failures are logged, never returned: an exchange that succeeded must
// not be reported as failed because the debugging log could not be written.
func (s *Server) recordCIExchange(r *http.Request, row statedb.CIExchangeRow, claims *ciauth.Claims) {
	id, err := newCIRuleID()
	if err != nil {
		return
	}
	row.ID = id
	row.At = time.Now().UTC()
	row.RemoteAddr = clientIP(r)
	if claims != nil {
		row.Issuer = claims.Issuer
		row.Subject = claims.Subject
		row.Repository = claims.Repository
		row.Ref = claims.Ref
		row.Workflow = claims.Workflow
		row.Actor = claims.Actor
		row.EventName = claims.EventName
		row.RunID = claims.RunID
		row.Claims = claims.All
	}

	db, err := s.controlPlaneDB()
	if err != nil {
		s.log().Warn(logger.EventAuthz, 0, "ci: record exchange",
			map[string]interface{}{"error": err.Error()})
		return
	}
	defer db.Close() //nolint:errcheck
	if err := db.PutCIExchange(row); err != nil {
		s.log().Warn(logger.EventAuthz, 0, "ci: record exchange",
			map[string]interface{}{"error": err.Error()})
		return
	}
	keep := config.CIExchangeKeepDefault
	if cfg, cerr := s.loadHubConfig(); cerr == nil && cfg != nil {
		keep = cfg.UI.CI.ExchangeKeep()
	}
	_, _ = db.PruneCIExchanges(keep)

	kind := claudeproxy.EventExchangeRejected
	if row.Accepted {
		kind = claudeproxy.EventExchangeAccepted
	}
	// Written through the same connection this function already holds, rather
	// than opening a second one: two handles on the SQLite file this process
	// has open contend, and the loser is an audit row nobody notices missing.
	_ = appendCIAuditEvent(db, claudeproxy.Event{
		Kind: kind, SessionID: row.SessionID, RuleID: row.RuleID, RuleName: row.RuleName,
		Subject: row.Subject, Repository: row.Repository, Ref: row.Ref,
		Workflow: row.Workflow, Actor: row.Actor, RunID: row.RunID,
		Reason: claudeproxy.DenyReason(row.Reason), Detail: row.Detail, At: row.At,
	})
}

// auditCIRule records an operator's change to the allowlist.
func (s *Server) auditCIRule(r *http.Request, eventType string, rule ciauth.Rule, detail string) {
	payload, err := json.Marshal(map[string]any{
		"rule_id":    rule.ID,
		"rule_name":  rule.Name,
		"repository": rule.Match.Repository,
		"ref":        rule.Match.Ref,
		"condition":  rule.Match.Condition,
		"models":     rule.Policy.Models,
		"detail":     detail,
	})
	if err != nil {
		payload = []byte(`{}`)
	}
	db, err := statedb.Open(state.DBPath(s.WorkDir))
	if err != nil {
		s.log().Warn(logger.EventAuthz, 0, "ci: audit rule change",
			map[string]interface{}{"error": err.Error()})
		return
	}
	defer db.Close() //nolint:errcheck
	if err := db.AppendAuditEvent(&statedb.AuditEvent{
		Timestamp:  time.Now().UTC(),
		Actor:      s.grantFor(r).subjectLabel(),
		EventType:  eventType,
		EntityType: "ci_rule",
		EntityID:   rule.ID,
		Payload:    string(payload),
	}); err != nil {
		s.log().Warn(logger.EventAuthz, 0, "ci: audit rule change",
			map[string]interface{}{"error": err.Error()})
	}
}
