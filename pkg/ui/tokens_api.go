package ui

// Scoped API tokens for non-interactive hub access (Task 20175).
//
// Two things live here: the *authentication* path that turns a
// `cloop_pat_…` string into an identity the route gates can enforce, and the
// three RBAC-gated endpoints that mint, list, and revoke them.
//
//	GET    /api/tokens        list, never including a secret
//	POST   /api/tokens        mint one; plaintext returned exactly once
//	DELETE /api/tokens/{id}   revoke
//
// # Why a token is not a bypass
//
// The static bearer token (`--token`) authenticates *and* short-circuits
// authorization: it resolves to authz.AllowAll and sees every project. A PAT
// does the opposite. It resolves to an ordinary authz.Decision built from the
// roles stamped into it (pkg/apitoken.Token.Decision), so every permission
// check in routes.go applies to it unchanged and deny-by-default is inherited
// rather than reimplemented. There is no code path here that grants a token
// anything; there is only a code path that *reports its roles* to the same
// gate a browser session goes through.
//
// # The three containment properties
//
//   - Roles cannot exceed the minter's. Enforced by apitoken.CheckDelegation
//     against the caller's own decision at the global scope, so token.admin
//     confers the ability to delegate authority, never to invent it.
//   - Project scope cannot be widened. A scoped token filters
//     visibleProjectEntries, which is the same list resolveWorkDir maps
//     ?project_idx through — an out-of-scope project therefore has no index
//     the token can name, and a direct hit resolves to a scope its decision
//     denies, which the 404/403 split reports as nonexistent.
//   - The plaintext exists once. It is returned by the create call and never
//     stored, logged, or re-derivable; every later read returns the prefix.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/apierror"
	"github.com/blechschmidt/cloop/pkg/apitoken"
	"github.com/blechschmidt/cloop/pkg/authz"
	"github.com/blechschmidt/cloop/pkg/eventlog"
	"github.com/blechschmidt/cloop/pkg/logger"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

const (
	// tokenMaxTTLDays bounds the lifetime the API may request.
	//
	// Not a security boundary — an operator can always re-mint — but it is
	// what keeps the panel from being the easy path back to the
	// forever-credential this feature exists to replace. The CLI can still
	// mint a non-expiring token for an edge device that cannot be
	// re-provisioned on a calendar, which is an explicit choice rather than
	// the default one.
	tokenMaxTTLDays = 365

	// tokenMinTTLMinutes rejects a token that would expire before the caller
	// could use it, which is indistinguishable from one that was never
	// created.
	tokenMinTTLMinutes = 1
)

// ---------------------------------------------------------------------------
// request context
// ---------------------------------------------------------------------------

type apiTokenCtxKey struct{}

// tokenFromRequest returns the API token the caller authenticated with, or nil.
//
// The value is placed on the context by authenticateAPIToken, which runs in
// the auth middleware — so by the time any gate or handler asks, the token has
// already been verified against the store. A nil result means "this caller is
// not a token", never "not checked yet".
func tokenFromRequest(r *http.Request) *apitoken.Token {
	if r == nil {
		return nil
	}
	tok, _ := r.Context().Value(apiTokenCtxKey{}).(*apitoken.Token)
	return tok
}

// ---------------------------------------------------------------------------
// manager
// ---------------------------------------------------------------------------

// tokenManager returns the hub's token manager, opening the control-plane
// database on first use and caching it for the process lifetime.
//
// Cached rather than opened per request because this sits on the
// authentication path: re-opening SQLite (which re-checks the migration state)
// for every authenticated call would make token auth measurably slower than
// the static token it replaces, and slowness is how a security feature gets
// turned off.
//
// The database is the *hub's* own, never a managed project's — a tenant able
// to write to the file holding its credentials could mint itself an admin
// token. Same rule as executor bindings and secret grants.
func (s *Server) tokenManager() (*apitoken.Manager, error) {
	s.tokenMu.Lock()
	defer s.tokenMu.Unlock()
	if s.tokens != nil {
		return s.tokens, nil
	}
	dbPath := state.DBPath(s.WorkDir)
	if _, err := os.Stat(dbPath); err != nil {
		return nil, fmt.Errorf("the control plane has no state database at %s yet", dbPath)
	}
	db, err := statedb.Open(dbPath)
	if err != nil {
		return nil, fmt.Errorf("open control-plane database: %w", err)
	}
	store, err := apitoken.NewSQLStore(db)
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	mgr, err := apitoken.NewManager(store)
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	mgr.SetTouchErrorHandler(func(terr error) {
		s.log().Warn(logger.EventAuthz, 0, "api token: record last use",
			map[string]interface{}{"error": terr.Error()})
	})
	s.tokenDB = db
	s.tokens = mgr
	return mgr, nil
}

// closeTokenManager releases the cached database handle. Called from Shutdown
// so a restarted test server does not leave a connection behind.
func (s *Server) closeTokenManager() {
	s.tokenMu.Lock()
	db := s.tokenDB
	s.tokenDB, s.tokens = nil, nil
	s.tokenMu.Unlock()
	if db != nil {
		_ = db.Close()
	}
}

// ---------------------------------------------------------------------------
// authentication
// ---------------------------------------------------------------------------

// bearerCredential extracts the credential a request is presenting, from the
// Authorization header or the ?token= query parameter.
//
// The query parameter is supported because EventSource cannot set headers; it
// is the same fallback the static token already uses. Callers that log or
// audit must never echo the returned value.
func bearerCredential(r *http.Request) string {
	if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))
	}
	return strings.TrimSpace(r.URL.Query().Get("token"))
}

// authenticateAPIToken resolves a presented PAT.
//
// Returns:
//
//	r2, true, false   authenticated — r2 carries the token on its context
//	nil, false, true  a PAT was presented and rejected; the 401 is written
//	nil, false, false the request is not presenting a PAT at all
//
// The three-way result exists so the caller can tell "not a token" from "a bad
// token". Falling through on a bad token would let a revoked credential be
// silently retried as the static one, which is precisely the confusion that
// makes revocation untrustworthy.
//
// Every rejection reason — malformed, unknown, wrong secret, expired, revoked
// — produces the same 401 body. The distinction is written to the audit trail,
// where the operator can see it, and withheld from the caller, who would
// otherwise have an oracle for which token ids exist.
func (s *Server) authenticateAPIToken(w http.ResponseWriter, r *http.Request) (*http.Request, bool, bool) {
	cred := bearerCredential(r)
	if !apitoken.LooksLikeToken(cred) {
		return nil, false, false
	}

	ip := clientIP(r)
	if s.authLockoutActive(ip) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Retry-After", "60")
		w.WriteHeader(http.StatusTooManyRequests)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "too many failed attempts, try again later"})
		return nil, false, true
	}

	mgr, err := s.tokenManager()
	if err != nil {
		// The store is unreachable. Fail closed: a caller presenting a token
		// must not be silently downgraded to whatever the next credential in
		// the chain would have granted.
		s.log().Error(logger.EventAuthz, 0, "api token: open store",
			map[string]interface{}{"error": err.Error()})
		jsonErr(w, "token authentication is unavailable", http.StatusServiceUnavailable)
		return nil, false, true
	}

	tok, verr := mgr.Verify(cred)
	if verr != nil {
		s.recordAuthFailure(ip)
		s.auditTokenEvent(tokenAuditRecord{
			Actor:     "anonymous",
			EventType: "api_token.auth_failed",
			TokenID:   tokenIDForAudit(cred),
			Extra: map[string]any{
				"reason": tokenFailureReason(verr),
				"ip":     ip,
				"method": r.Method,
				"path":   r.URL.Path,
			},
		})
		jsonErr(w, "unauthorized", http.StatusUnauthorized)
		return nil, false, true
	}
	return r.WithContext(context.WithValue(r.Context(), apiTokenCtxKey{}, tok)), true, false
}

// tokenFailureReason maps a verification error to a stable audit string. It is
// never returned to the caller — see authenticateAPIToken.
func tokenFailureReason(err error) string {
	switch {
	case errors.Is(err, apitoken.ErrMalformed):
		return "malformed"
	case errors.Is(err, apitoken.ErrNotFound):
		return "unknown_token"
	case errors.Is(err, apitoken.ErrBadSecret):
		return "bad_secret"
	case errors.Is(err, apitoken.ErrExpired):
		return "expired"
	case errors.Is(err, apitoken.ErrRevoked):
		return "revoked"
	case errors.Is(err, apitoken.ErrNoRoles):
		return "no_usable_role"
	}
	return "error"
}

// tokenIDForAudit extracts the *public* half of a presented credential so a
// failed attempt can be attributed to a specific token.
//
// Only the id, never the secret: an audit trail that recorded the whole string
// would turn read access to the trail into credential theft, and a failed
// attempt is exactly when the string most likely belongs to someone else.
func tokenIDForAudit(cred string) string {
	if id, _, ok := apitoken.Parse(cred); ok {
		return apitoken.Prefix + id
	}
	return "(unparseable)"
}

// ---------------------------------------------------------------------------
// wire types
// ---------------------------------------------------------------------------

// tokenView is one row of GET /api/tokens.
//
// There is deliberately no field that could carry a secret — not the hash, not
// a truncation of it, not a length. Prefix is the public half of the token
// string and is all an operator needs to match a row here against a value in
// a CI variable.
type tokenView struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	Prefix       string   `json:"prefix"`
	Roles        []string `json:"roles"`
	ProjectScope []string `json:"project_scope,omitempty"`
	CreatedBy    string   `json:"created_by,omitempty"`
	CreatedAt    string   `json:"created_at,omitempty"`
	ExpiresAt    string   `json:"expires_at,omitempty"`
	LastUsedAt   string   `json:"last_used_at,omitempty"`
	RevokedAt    string   `json:"revoked_at,omitempty"`

	// Status is the single word the panel renders: active, expired, or
	// revoked. Derived server-side so the UI cannot disagree with the
	// verification path about whether a credential still works.
	Status string `json:"status"`
}

type tokensListResponse struct {
	Tokens []tokenView `json:"tokens"`

	// Roles the *calling* identity may delegate. The panel uses it to offer
	// only the roles that would be accepted, so an operator does not compose
	// a request the anti-escalation rule will refuse.
	GrantableRoles []string `json:"grantable_roles"`

	// Projects the caller may scope a token to, by registry name.
	Projects []string `json:"projects"`

	// StaticTokenActive reports whether the deprecated --token is configured,
	// so the panel can say so where an operator will act on it.
	StaticTokenActive bool `json:"static_token_active"`
}

type tokenCreateRequest struct {
	Name         string   `json:"name"`
	Roles        []string `json:"roles"`
	ProjectScope []string `json:"project_scope"`

	// ExpiresInDays is the TTL. 0 means no expiry, which the API accepts
	// only because some edge devices genuinely cannot be re-provisioned;
	// the panel defaults it to a bounded value.
	ExpiresInDays int `json:"expires_in_days"`
}

type tokenCreateResponse struct {
	Token tokenView `json:"token"`

	// Plaintext is the full credential. This is the only response in cloop
	// that carries one, and it is unrecoverable afterwards: it is not stored,
	// not logged, and not derivable from the hash.
	Plaintext string `json:"plaintext"`

	Warning string `json:"warning"`
}

// ---------------------------------------------------------------------------
// handlers
// ---------------------------------------------------------------------------

// tokenManagerOr resolves the manager or writes the 503 explaining why it
// could not.
func (s *Server) tokenManagerOr(w http.ResponseWriter) (*apitoken.Manager, bool) {
	mgr, err := s.tokenManager()
	if err != nil {
		s.log().Error(logger.EventAuthz, 0, "api tokens: open store",
			map[string]interface{}{"error": err.Error()})
		apierror.WriteError(w, apierror.New(apierror.CodeUnavailable, err.Error()))
		return nil, false
	}
	return mgr, true
}

// handleTokensList serves GET /api/tokens.
func (s *Server) handleTokensList(w http.ResponseWriter, r *http.Request) {
	mgr, ok := s.tokenManagerOr(w)
	if !ok {
		return
	}
	tokens, err := mgr.List()
	if err != nil {
		apierror.WriteError(w, apierror.New(apierror.CodeInternal, err.Error()))
		return
	}
	now := time.Now()
	views := make([]tokenView, 0, len(tokens))
	for i := range tokens {
		views = append(views, toTokenView(&tokens[i], now))
	}
	jsonOK(w, tokensListResponse{
		Tokens:            views,
		GrantableRoles:    s.grantableRoles(r),
		Projects:          s.scopableProjects(r),
		StaticTokenActive: s.Token != "",
	})
}

// handleTokenCreate serves POST /api/tokens.
func (s *Server) handleTokenCreate(w http.ResponseWriter, r *http.Request) {
	var req tokenCreateRequest
	if !decodeSecretsBody(w, r, &req) {
		return
	}

	roles, err := apitoken.NormalizeRoles(req.Roles)
	if err != nil {
		apierror.WriteError(w, apierror.New(apierror.CodeInvalidInput, err.Error()))
		return
	}
	scope, err := apitoken.NormalizeProjectScope(req.ProjectScope)
	if err != nil {
		apierror.WriteError(w, apierror.New(apierror.CodeInvalidInput, err.Error()))
		return
	}

	// The anti-escalation rule. Evaluated against the caller's authority at
	// the *global* scope: a token is a fleet-level object, and resolving
	// against a single project would let someone who is maintainer there mint
	// a hub-wide maintainer credential.
	if err := apitoken.CheckDelegation(s.delegatorFor(r), roles, scope); err != nil {
		s.auditTokenEvent(tokenAuditRecord{
			Actor:     s.grantFor(r).subjectLabel(),
			EventType: "api_token.create_denied",
			Extra: map[string]any{
				"reason":        err.Error(),
				"roles":         roles,
				"project_scope": scope,
			},
		})
		apierror.WriteError(w, apierror.New(apierror.CodeForbidden, err.Error()).
			WithDetails(map[string]any{"requested_roles": roles}))
		return
	}

	expires, err := tokenExpiry(req.ExpiresInDays, time.Now())
	if err != nil {
		apierror.WriteError(w, apierror.New(apierror.CodeInvalidInput, err.Error()))
		return
	}

	mgr, ok := s.tokenManagerOr(w)
	if !ok {
		return
	}
	actor := s.grantFor(r).subjectLabel()
	minted, err := mgr.Mint(apitoken.MintOptions{
		Name:         req.Name,
		Roles:        roles,
		ProjectScope: scope,
		CreatedBy:    actor,
		ExpiresAt:    expires,
	})
	if err != nil {
		apierror.WriteError(w, apierror.New(apierror.CodeInvalidInput, err.Error()))
		return
	}

	s.auditTokenEvent(tokenAuditRecord{
		Actor:     actor,
		EventType: "api_token.created",
		TokenID:   minted.Token.Prefix,
		Extra: map[string]any{
			"name":          minted.Token.Name,
			"roles":         minted.Token.Roles,
			"project_scope": minted.Token.ProjectScope,
			"expires_at":    formatTokenTime(minted.Token.ExpiresAt),
		},
	})

	jsonOK(w, tokenCreateResponse{
		Token:     toTokenView(&minted.Token, time.Now()),
		Plaintext: minted.Plaintext,
		Warning: "This is the only time this token is shown. cloop stores a salted hash, " +
			"not the value — it cannot be recovered. Store it in your secret manager now; " +
			"if you lose it, revoke this token and mint another.",
	})
}

// handleTokenRevoke serves DELETE /api/tokens/{id}.
func (s *Server) handleTokenRevoke(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		apierror.WriteError(w, apierror.New(apierror.CodeInvalidInput, "a token id is required"))
		return
	}
	mgr, ok := s.tokenManagerOr(w)
	if !ok {
		return
	}

	// Read first so the audit record can name what was withdrawn. Revoking a
	// row and only then discovering it existed leaves an entry an auditor
	// cannot interpret.
	tok, err := mgr.Get(id)
	if err != nil {
		if errors.Is(err, apitoken.ErrNotFound) {
			apierror.WriteError(w, apierror.New(apierror.CodeNotFound, "no such token"))
			return
		}
		apierror.WriteError(w, apierror.New(apierror.CodeInternal, err.Error()))
		return
	}
	if err := mgr.Revoke(id); err != nil {
		if errors.Is(err, apitoken.ErrNotFound) {
			apierror.WriteError(w, apierror.New(apierror.CodeNotFound, "no such token"))
			return
		}
		apierror.WriteError(w, apierror.New(apierror.CodeInternal, err.Error()))
		return
	}

	s.auditTokenEvent(tokenAuditRecord{
		Actor:     s.grantFor(r).subjectLabel(),
		EventType: "api_token.revoked",
		TokenID:   tok.Prefix,
		Extra: map[string]any{
			"name":  tok.Name,
			"roles": tok.Roles,
		},
	})
	jsonOK(w, map[string]any{"ok": true, "id": id})
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// delegatorFor describes the calling identity's authority for the
// anti-escalation check.
func (s *Server) delegatorFor(r *http.Request) apitoken.Delegator {
	g := s.grantFor(r)
	d := apitoken.Delegator{Decision: g.decide(authz.GlobalScope)}
	if g.token != nil {
		d.ProjectScope = g.token.ProjectScope
		return d
	}
	// The local operator (OIDC off) and the static bearer token both already
	// act as the deployment itself. Bounding them against their own allow-all
	// decision would be a no-op dressed up as a check, so the bypass is
	// recorded explicitly instead.
	d.Unrestricted = g.bypass != ""
	return d
}

// grantableRoles lists the roles the caller could put in a token, so the panel
// can offer exactly those. Purely advisory: CheckDelegation is what enforces.
func (s *Server) grantableRoles(r *http.Request) []string {
	d := s.delegatorFor(r)
	out := []string{}
	for _, role := range authz.AllRoles {
		if role == authz.RoleNone {
			continue
		}
		if err := apitoken.CheckDelegation(d, []string{string(role)}, nil); err == nil {
			out = append(out, string(role))
		}
	}
	return out
}

// scopableProjects lists the project names the caller may scope a token to.
// Reuses visibleProjectEntries so a scoped caller is offered only what it can
// itself reach.
func (s *Server) scopableProjects(r *http.Request) []string {
	entries := s.visibleProjectEntries(r)
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.Name != "" {
			out = append(out, e.Name)
		}
	}
	return out
}

// tokenExpiry converts the request's TTL in days into an absolute time.
func tokenExpiry(days int, now time.Time) (time.Time, error) {
	if days == 0 {
		return time.Time{}, nil
	}
	if days < 0 {
		return time.Time{}, errors.New("expires_in_days cannot be negative")
	}
	if days > tokenMaxTTLDays {
		return time.Time{}, fmt.Errorf("expires_in_days is at most %d", tokenMaxTTLDays)
	}
	exp := now.Add(time.Duration(days) * 24 * time.Hour)
	if exp.Sub(now) < tokenMinTTLMinutes*time.Minute {
		return time.Time{}, errors.New("the requested lifetime is too short to be usable")
	}
	return exp, nil
}

func toTokenView(t *apitoken.Token, now time.Time) tokenView {
	return tokenView{
		ID:           t.ID,
		Name:         t.Name,
		Prefix:       t.Prefix,
		Roles:        t.Roles,
		ProjectScope: t.ProjectScope,
		CreatedBy:    t.CreatedBy,
		CreatedAt:    formatTokenTime(t.CreatedAt),
		ExpiresAt:    formatTokenTime(t.ExpiresAt),
		LastUsedAt:   formatTokenTime(t.LastUsedAt),
		RevokedAt:    formatTokenTime(t.RevokedAt),
		Status:       TokenStatus(t, now),
	}
}

// TokenStatus renders a token's lifecycle state. Exported so `cloop hub token
// list` prints the same word the panel does, from the same rules.
func TokenStatus(t *apitoken.Token, now time.Time) string {
	switch {
	case t.Revoked():
		return "revoked"
	case t.Expired(now):
		return "expired"
	}
	return "active"
}

func formatTokenTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// ---------------------------------------------------------------------------
// audit
// ---------------------------------------------------------------------------

// tokenAuditRecord is one entry appended to the hash-chained trail.
type tokenAuditRecord struct {
	Actor     string
	EventType string
	TokenID   string
	Extra     map[string]any
}

// auditTokenEvent appends a token lifecycle event to the hub's own audit log.
//
// Best-effort, matching the contract in auditAuthz: a wedged journal must not
// turn minting a credential — or failing to authenticate with one — into an
// error path. Failures are logged.
//
// Nothing written here can contain a secret: TokenID is always a prefix
// (the public half), and Extra is populated only with roles, scopes and names
// by the three call sites above.
func (s *Server) auditTokenEvent(rec tokenAuditRecord) {
	payload := map[string]any{}
	for k, v := range rec.Extra {
		payload[k] = v
	}
	if rec.TokenID != "" {
		payload["token"] = rec.TokenID
	}
	blob, err := json.Marshal(payload)
	if err != nil {
		s.log().Warn(logger.EventAuthz, 0, "api token audit: marshal payload",
			map[string]interface{}{"error": err.Error()})
		return
	}
	actor := rec.Actor
	if actor == "" {
		actor = "anonymous"
	}
	log, err := eventlog.Open(s.WorkDir)
	if err != nil {
		if !errors.Is(err, eventlog.ErrNoProject) {
			s.log().Warn(logger.EventAuthz, 0, "api token audit: open event log",
				map[string]interface{}{"error": err.Error()})
		}
		return
	}
	defer log.Close()
	if err := log.Append(&eventlog.AuditEvent{
		Actor:      actor,
		EventType:  rec.EventType,
		EntityType: "api_token",
		EntityID:   rec.TokenID,
		Payload:    string(blob),
	}); err != nil {
		s.log().Warn(logger.EventAuthz, 0, "api token audit: append",
			map[string]interface{}{"error": err.Error()})
	}
}
