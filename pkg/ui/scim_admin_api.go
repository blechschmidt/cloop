package ui

// The Settings side of SCIM provisioning (Task 20415): the credential an
// identity provider presents, minted, rotated and revoked from the dashboard
// as from `cloop hub scim credential`, and the legal holds an automatic
// offboarding honours. Gated on user.manage: minting a credential that can
// deactivate every account on the hub is administering access itself.

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/apierror"
	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/provision"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// scimCredentialView is a credential as the panel shows it: no secret, no
// hash.
type scimCredentialView struct {
	ID                 string `json:"id"`
	Name               string `json:"name"`
	Prefix             string `json:"prefix"`
	CreatedAt          string `json:"created_at"`
	CreatedBy          string `json:"created_by,omitempty"`
	RotatedAt          string `json:"rotated_at,omitempty"`
	RotatedBy          string `json:"rotated_by,omitempty"`
	PreviousValidUntil string `json:"previous_valid_until,omitempty"`
	RevokedAt          string `json:"revoked_at,omitempty"`
	RevokedBy          string `json:"revoked_by,omitempty"`
	LastUsedAt         string `json:"last_used_at,omitempty"`
}

func scimCredentialViewOf(c statedb.SCIMCredentialRow, now time.Time) scimCredentialView {
	v := scimCredentialView{
		ID: c.ID, Name: c.Name, Prefix: provision.CredentialPrefix + c.ID,
		CreatedAt: formatTokenTime(c.CreatedAt), CreatedBy: c.CreatedBy,
		RotatedAt: formatTokenTime(c.RotatedAt), RotatedBy: c.RotatedBy,
		RevokedAt: formatTokenTime(c.RevokedAt), RevokedBy: c.RevokedBy,
		LastUsedAt: formatTokenTime(c.LastUsedAt),
	}
	if c.PreviousHash != "" && now.Before(c.PreviousExpiresAt) {
		v.PreviousValidUntil = formatTokenTime(c.PreviousExpiresAt)
	}
	return v
}

type legalHoldView struct {
	Identity string `json:"identity"`
	Reason   string `json:"reason"`
	PlacedAt string `json:"placed_at"`
	PlacedBy string `json:"placed_by,omitempty"`
}

// scimStatus is GET /api/scim.
type scimStatus struct {
	// Enabled: the hub serves /scim/v2 — single sign-on is on and the
	// directory opened.
	Enabled            bool                      `json:"enabled"`
	Endpoint           string                    `json:"endpoint"`
	MatchClaim         string                    `json:"match_claim"`
	OffboardAfterDays  int                       `json:"offboard_after_days"`
	RateLimitPerMinute int                       `json:"rate_limit_per_minute"`
	Directory          *provision.DirectoryStats `json:"directory,omitempty"`
	PendingOffboards   int                       `json:"pending_offboards"`
	Credentials        []scimCredentialView      `json:"credentials"`
	Holds              []legalHoldView           `json:"holds"`
}

// handleSCIMStatus serves GET /api/scim.
func (s *Server) handleSCIMStatus(w http.ResponseWriter, r *http.Request) {
	if !s.requireIdentityAdmin(w, r) {
		return
	}
	db, closer, err := s.openControlPlaneDB()
	if err != nil {
		apierror.WriteError(w, apierror.New(apierror.CodeUnavailable, err.Error()))
		return
	}
	defer closer()
	now := time.Now()
	st := scimStatus{Endpoint: s.scimBase(r), Credentials: []scimCredentialView{}, Holds: []legalHoldView{}}
	s.scim.mu.Lock()
	cfg, svc, dir := s.scim.cfg, s.scim.svc, s.scim.dir
	s.scim.mu.Unlock()
	st.Enabled = svc != nil && s.oidcEnabled()
	st.MatchClaim = string(provision.MatchEmail)
	if c, err := provision.ParseMatchClaim(cfg.MatchClaim); err == nil {
		st.MatchClaim = string(c)
	}
	st.OffboardAfterDays = cfg.EffectiveOffboardAfterDays()
	st.RateLimitPerMinute = cfg.EffectiveRateLimitPerMinute()
	if dir != nil {
		stats := dir.Stats()
		st.Directory = &stats
	}
	if svc != nil && svc.Config.OffboardAfter > 0 {
		if pending, err := db.PendingSCIMOffboards(now.Add(-svc.Config.OffboardAfter)); err == nil {
			st.PendingOffboards = len(pending)
		}
	}
	creds, err := db.ListSCIMCredentials()
	if err != nil {
		apierror.WriteFromError(w, err)
		return
	}
	for _, c := range creds {
		st.Credentials = append(st.Credentials, scimCredentialViewOf(c, now))
	}
	holds, err := db.ListLegalHolds()
	if err != nil {
		apierror.WriteFromError(w, err)
		return
	}
	for _, h := range holds {
		st.Holds = append(st.Holds, legalHoldView{Identity: h.Identity, Reason: h.Reason,
			PlacedAt: formatTokenTime(h.PlacedAt), PlacedBy: h.PlacedBy})
	}
	jsonOK(w, st)
}

// requireIdentityAdmin refuses, on a hub with single sign-on and no RBAC
// policy, anyone not in admin_emails — the treatment executor management gets
// (requireExecutorAdmin), and for a sharper reason. Such a hub grants every
// signed-in identity every permission but executor administration (the
// upgrade rule, authz.Enforced), and a SCIM credential can deactivate every
// account on the hub, administrators included: it is not something every
// user of a pre-RBAC hub may mint, and neither is deciding whose stored
// credentials an offboarding keeps. With a policy, or an API token, the route
// gate already required user.manage, which an operator grants deliberately.
func (s *Server) requireIdentityAdmin(w http.ResponseWriter, r *http.Request) bool {
	if !s.oidcEnabled() || s.authzActiveFor(r) {
		return true
	}
	id := s.sessionIdentity(r)
	if id == nil || s.OIDC.IsAdmin(id) {
		// No session: the static token admitted it, the deployment's own
		// operator credential.
		return true
	}
	apierror.WriteError(w, apierror.New(apierror.CodeForbidden,
		"administering SCIM provisioning and legal holds requires an administrator account (ui.oidc.admin_emails) "+
			"on a hub without a role policy: a SCIM credential can deactivate every account here"))
	return false
}

type scimCredentialRequest struct {
	Name         string `json:"name"`
	Reason       string `json:"reason"`
	GraceMinutes int    `json:"grace_minutes"`
}

// scimAdmin is who is administering, for the trail.
func (s *Server) scimAdmin(r *http.Request, reason string) provision.AdminContext {
	return provision.AdminContext{Actor: s.grantFor(r).subjectLabel(), Reason: strings.TrimSpace(reason), Via: "ui"}
}

// writeProvisionError maps a provisioning refusal onto the hub's error body.
func writeProvisionError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, provision.ErrInvalid):
		apierror.WriteError(w, apierror.New(apierror.CodeInvalidInput, err.Error()))
	case errors.Is(err, statedb.ErrSCIMNotFound):
		apierror.WriteError(w, apierror.New(apierror.CodeNotFound, err.Error()))
	default:
		apierror.WriteFromError(w, err)
	}
}

// handleSCIMCredentialCreate serves POST /api/scim/credentials. The plaintext
// is in this response and in no other.
func (s *Server) handleSCIMCredentialCreate(w http.ResponseWriter, r *http.Request) {
	if !s.requireIdentityAdmin(w, r) {
		return
	}
	var req scimCredentialRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	db, closer, err := s.openControlPlaneDB()
	if err != nil {
		apierror.WriteError(w, apierror.New(apierror.CodeUnavailable, err.Error()))
		return
	}
	defer closer()
	now := time.Now()
	minted, err := provision.MintCredential(db, req.Name, s.scimAdmin(r, req.Reason), now)
	if err != nil {
		writeProvisionError(w, err)
		return
	}
	s.broadcastAuditAppend(string(auditaction.ActionSCIMCredentialCreate))
	jsonOK(w, map[string]any{"credential": scimCredentialViewOf(minted.Row, now), "token": minted.Plaintext,
		"endpoint": s.scimBase(r)})
}

// handleSCIMCredentialRotate serves POST /api/scim/credentials/{id}/rotate.
func (s *Server) handleSCIMCredentialRotate(w http.ResponseWriter, r *http.Request) {
	if !s.requireIdentityAdmin(w, r) {
		return
	}
	var req scimCredentialRequest
	if !decodeOptionalJSON(w, r, &req) {
		return
	}
	db, closer, err := s.openControlPlaneDB()
	if err != nil {
		apierror.WriteError(w, apierror.New(apierror.CodeUnavailable, err.Error()))
		return
	}
	defer closer()
	now := time.Now()
	grace := time.Duration(req.GraceMinutes) * time.Minute
	minted, err := provision.RotateCredential(db, r.PathValue("id"), grace, s.scimAdmin(r, req.Reason), now)
	if err != nil {
		writeProvisionError(w, err)
		return
	}
	s.broadcastAuditAppend(string(auditaction.ActionSCIMCredentialRotate))
	jsonOK(w, map[string]any{"credential": scimCredentialViewOf(minted.Row, now), "token": minted.Plaintext,
		"endpoint": s.scimBase(r)})
}

// handleSCIMCredentialRevoke serves POST /api/scim/credentials/{id}/revoke.
func (s *Server) handleSCIMCredentialRevoke(w http.ResponseWriter, r *http.Request) {
	if !s.requireIdentityAdmin(w, r) {
		return
	}
	var req scimCredentialRequest
	if !decodeOptionalJSON(w, r, &req) {
		return
	}
	db, closer, err := s.openControlPlaneDB()
	if err != nil {
		apierror.WriteError(w, apierror.New(apierror.CodeUnavailable, err.Error()))
		return
	}
	defer closer()
	now := time.Now()
	c, revoked, err := provision.RevokeCredential(db, r.PathValue("id"), s.scimAdmin(r, req.Reason), now)
	if err != nil {
		writeProvisionError(w, err)
		return
	}
	if revoked {
		s.broadcastAuditAppend(string(auditaction.ActionSCIMCredentialRevoke))
	}
	jsonOK(w, map[string]any{"credential": scimCredentialViewOf(c, now), "revoked": revoked})
}

type legalHoldRequest struct {
	Identity string `json:"identity"`
	Reason   string `json:"reason"`
}

// handleLegalHolds serves GET /api/users/holds.
func (s *Server) handleLegalHolds(w http.ResponseWriter, r *http.Request) {
	if !s.requireIdentityAdmin(w, r) {
		return
	}
	db, closer, err := s.openControlPlaneDB()
	if err != nil {
		apierror.WriteError(w, apierror.New(apierror.CodeUnavailable, err.Error()))
		return
	}
	defer closer()
	holds, err := db.ListLegalHolds()
	if err != nil {
		apierror.WriteFromError(w, err)
		return
	}
	out := make([]legalHoldView, 0, len(holds))
	for _, h := range holds {
		out = append(out, legalHoldView{Identity: h.Identity, Reason: h.Reason,
			PlacedAt: formatTokenTime(h.PlacedAt), PlacedBy: h.PlacedBy})
	}
	jsonOK(w, map[string]any{"holds": out})
}

// handleLegalHoldPlace serves POST /api/users/holds: place a hold, or restate
// the reason of one already placed.
func (s *Server) handleLegalHoldPlace(w http.ResponseWriter, r *http.Request) {
	if !s.requireIdentityAdmin(w, r) {
		return
	}
	var req legalHoldRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	db, closer, err := s.openControlPlaneDB()
	if err != nil {
		apierror.WriteError(w, apierror.New(apierror.CodeUnavailable, err.Error()))
		return
	}
	defer closer()
	h, err := provision.PlaceHold(db, req.Identity, req.Reason, s.scimAdmin(r, ""), time.Now())
	if err != nil {
		writeProvisionError(w, err)
		return
	}
	s.broadcastAuditAppend(string(auditaction.ActionUserHoldPlace))
	jsonOK(w, legalHoldView{Identity: h.Identity, Reason: h.Reason, PlacedAt: formatTokenTime(h.PlacedAt),
		PlacedBy: h.PlacedBy})
}

// handleLegalHoldRelease serves POST /api/users/holds/release.
func (s *Server) handleLegalHoldRelease(w http.ResponseWriter, r *http.Request) {
	if !s.requireIdentityAdmin(w, r) {
		return
	}
	var req legalHoldRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	reason := strings.TrimSpace(req.Reason)
	if len(reason) < 4 {
		apierror.WriteError(w, apierror.New(apierror.CodeInvalidInput,
			"say why the hold is released: the release is recorded in the audit trail"))
		return
	}
	db, closer, err := s.openControlPlaneDB()
	if err != nil {
		apierror.WriteError(w, apierror.New(apierror.CodeUnavailable, err.Error()))
		return
	}
	defer closer()
	prev, released, err := provision.ReleaseHold(db, req.Identity, s.scimAdmin(r, reason), time.Now())
	if err != nil {
		writeProvisionError(w, err)
		return
	}
	if !released {
		apierror.WriteError(w, apierror.New(apierror.CodeNotFound, "no legal hold is placed on "+
			strings.TrimSpace(req.Identity)))
		return
	}
	s.broadcastAuditAppend(string(auditaction.ActionUserHoldRelease))
	jsonOK(w, map[string]any{"released": true, "identity": prev.Identity})
}
