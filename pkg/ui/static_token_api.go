package ui

// GET /api/static-token and POST /api/static-token/retire (Task 20406): the
// Settings card for the static admin token — whether one is configured, its
// fingerprint, its last use — and its Retire button.
//
// Admin-only (token.admin), like the API tokens it is retired in favour of.
// The static token itself holds that permission, which is deliberate: it may
// retire itself — break the glass, then lock the door behind you.

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/logger"
	"github.com/blechschmidt/cloop/pkg/statedb"
	"github.com/blechschmidt/cloop/pkg/statictoken"
)

// staticTokenView is what the Settings card draws.
type staticTokenView struct {
	// Configured reports that this hub was given a static token, retired or
	// not: a retired token is still configured, and the hub stays closed.
	Configured bool `json:"configured"`
	// Fingerprint is the first characters of the token's fingerprint, never
	// the value.
	Fingerprint string `json:"fingerprint,omitempty"`
	// Status is "none", "accepted", "retired", or "unknown" when the retired
	// tokens could not be read.
	Status  string                  `json:"status"`
	Retired *staticTokenRetiredView `json:"retired,omitempty"`
	// LastUsedAt and LastUsedIP are the latest request admitted with it, by
	// any hub process holding it, RFC 3339.
	LastUsedAt string                  `json:"last_used_at,omitempty"`
	LastUsedIP string                  `json:"last_used_ip,omitempty"`
	Refused    *staticTokenRefusedView `json:"refused,omitempty"`
	// SSO and AdminTokens are the ways in that remain once it is retired;
	// Strands reports that there would be none.
	SSO         bool `json:"sso"`
	AdminTokens int  `json:"admin_tokens"`
	Strands     bool `json:"strands"`
	// Self reports that this request was authenticated with the static token.
	Self bool `json:"self"`
}

type staticTokenRetiredView struct {
	At     string `json:"at"`
	By     string `json:"by"`
	Reason string `json:"reason,omitempty"`
}

type staticTokenRefusedView struct {
	Count  int64  `json:"count"`
	LastAt string `json:"last_at,omitempty"`
	LastIP string `json:"last_ip,omitempty"`
}

// staticTokenReasonMax bounds a retirement's reason: a sentence for a
// reviewer, not a document.
const staticTokenReasonMax = 1000

type staticTokenRetireRequest struct {
	Reason string `json:"reason"`
	// Force retires a token-only hub's static token although nothing else
	// could administer the hub afterwards.
	Force bool `json:"force"`
}

type staticTokenRetireResponse struct {
	// Retired is false when the token already was: nothing was written.
	Retired bool            `json:"retired"`
	Token   staticTokenView `json:"token"`
}

// handleStaticToken serves GET /api/static-token.
func (s *Server) handleStaticToken(w http.ResponseWriter, r *http.Request) {
	jsonOK(w, s.staticTokenViewFor(r))
}

// handleStaticTokenRetire serves POST /api/static-token/retire.
func (s *Server) handleStaticTokenRetire(w http.ResponseWriter, r *http.Request) {
	var req staticTokenRetireRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if !s.staticTokenConfigured() {
		jsonErr(w, "this hub has no static token to retire", http.StatusConflict)
		return
	}
	reason := strings.TrimSpace(req.Reason)
	if len(reason) < 4 {
		jsonErr(w, "a reason is required: the retirement is recorded in the audit trail and read back during review",
			http.StatusBadRequest)
		return
	}
	if len(reason) > staticTokenReasonMax {
		jsonErr(w, "the reason is too long: keep it to a sentence or two", http.StatusBadRequest)
		return
	}
	sso := s.oidcEnabled()
	admins := s.activeAdminTokens()
	strands := statictoken.CheckRetire(sso, admins, false) != nil
	if err := statictoken.CheckRetire(sso, admins, req.Force); err != nil {
		jsonErr(w, err.Error(), http.StatusConflict)
		return
	}

	fp := s.staticTokenFingerprint()
	actor := s.staticTokenActor(r)
	self := admittedByStaticToken(r)
	payload, _ := json.Marshal(map[string]any{
		"fingerprint": fp,
		"reason":      reason,
		"via":         "ui",
		"forced":      strands && req.Force,
		"self":        self,
	})
	db, err := s.controlPlaneDB()
	if err != nil {
		jsonErr(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	_, written, err := db.RetireStaticToken(statedb.RetiredStaticTokenRow{
		Fingerprint: fp, RetiredAt: time.Now(), RetiredBy: actor, Reason: reason,
	}, &statedb.AuditEvent{
		Actor:      actor,
		EventType:  string(auditaction.ActionStaticTokenRetired),
		EntityType: "static_token",
		EntityID:   fp,
		Payload:    string(payload),
	})
	db.Close()
	if err != nil {
		s.log().Error(logger.EventAuthz, 0, "static token: retire", map[string]interface{}{"error": err.Error()})
		jsonErr(w, "the static token could not be retired: "+err.Error(), http.StatusInternalServerError)
		return
	}
	s.applyStaticTokenRetirement(fp)
	if written {
		s.log().Warn(logger.EventAuthz, 0, "static token retired", map[string]interface{}{
			"fingerprint": statictoken.Short(fp), "by": actor, "self": self, "forced": strands && req.Force,
		})
	}
	jsonOK(w, staticTokenRetireResponse{Retired: written, Token: s.staticTokenViewFor(r)})
}

// applyStaticTokenRetirement makes a retirement this process wrote take
// effect: here at once, and on every other member over the bus.
func (s *Server) applyStaticTokenRetirement(fp string) {
	_ = s.reloadRetiredStaticTokens()
	s.recheckStaticTokenStreams()
	s.publishInvalidate(invalidateStaticToken, map[string]string{"fingerprint": fp})
}

// staticTokenActor names who is retiring the token, for the row and the
// audit trail: the static token itself, an API token, or the signed-in
// person — by name even on a hub without RBAC, where every grant reads as the
// local operator.
func (s *Server) staticTokenActor(r *http.Request) string {
	if admittedByStaticToken(r) {
		return "static-token"
	}
	if tok := tokenFromRequest(r); tok != nil {
		return tok.Label()
	}
	if id := s.sessionIdentity(r); id != nil {
		return subjectFromIdentity(id).Label()
	}
	return s.grantFor(r).subjectLabel()
}

// activeAdminTokens counts the API tokens that could administer this hub
// without the static token. A store that cannot be read counts none, which
// is the answer that refuses rather than strands.
func (s *Server) activeAdminTokens() int {
	mgr, err := s.tokenManager()
	if err != nil {
		return 0
	}
	tokens, err := mgr.List()
	if err != nil {
		return 0
	}
	return statictoken.ActiveAdminTokens(tokens, time.Now())
}

// staticTokenViewFor assembles the card's view for r.
func (s *Server) staticTokenViewFor(r *http.Request) staticTokenView {
	v := staticTokenView{
		Configured:  s.staticTokenConfigured(),
		Status:      "none",
		SSO:         s.oidcEnabled(),
		AdminTokens: s.activeAdminTokens(),
		Self:        admittedByStaticToken(r),
	}
	if !v.Configured {
		return v
	}
	v.Strands = statictoken.CheckRetire(v.SSO, v.AdminTokens, false) != nil
	fp := s.staticTokenFingerprint()
	v.Fingerprint = statictoken.Short(fp)
	if set, err := s.retiredStaticTokenSet(); err != nil {
		v.Status = "unknown"
	} else if rec, retired := set[fp]; retired {
		v.Status = "retired"
		v.Retired = &staticTokenRetiredView{
			At: rec.RetiredAt.UTC().Format(time.RFC3339), By: rec.RetiredBy, Reason: rec.Reason,
		}
	} else {
		v.Status = "accepted"
	}

	// The latest use any member flushed, or this process saw since — and the
	// refusals, flushed and not.
	used := s.latestStaticTokenUse()
	var refused statedb.StaticTokenUseRow
	if db, err := s.existingControlPlane(); err == nil && db != nil {
		if rows, err := db.ListStaticTokenUse(); err == nil {
			for _, row := range rows {
				if row.Fingerprint != fp {
					continue
				}
				if row.LastUsedAt.After(used.at) {
					used = staticTokenSeen{at: row.LastUsedAt, ip: row.LastUsedIP}
				}
				refused = row
			}
		}
		db.Close()
	}
	if !used.at.IsZero() {
		v.LastUsedAt, v.LastUsedIP = used.at.UTC().Format(time.RFC3339), used.ip
	}
	s.staticTok.useMu.Lock()
	if p := s.staticTok.refused[fp]; p != nil {
		refused.RefusedCount += p.n
		if p.last.at.After(refused.LastRefusedAt) {
			refused.LastRefusedAt, refused.LastRefusedIP = p.last.at, p.last.ip
		}
	}
	s.staticTok.useMu.Unlock()
	if refused.RefusedCount > 0 {
		v.Refused = &staticTokenRefusedView{
			Count: refused.RefusedCount, LastAt: refused.LastRefusedAt.UTC().Format(time.RFC3339),
			LastIP: refused.LastRefusedIP,
		}
	}
	return v
}
