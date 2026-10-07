package ui

// The Settings panel that edits ui.oidc (Task 20308).
//
// Four routes, all global-scoped and gated on user.manage:
//
//	GET  /api/config/oidc          what is configured, and what is running
//	PUT  /api/config/oidc          change it, or be told why it was refused
//	POST /api/config/oidc/test     contact an issuer without saving anything
//	POST /api/config/oidc/enforce  leave the RBAC-off state in one step
//
// user.manage rather than config.write, which every other Settings route uses.
// This block decides who may sign in and what authority they arrive with, so
// writing it is equivalent to granting a role — and config.write is held by
// maintainers, who are deliberately not able to promote themselves. The
// separation is the whole reason the permission exists.
//
// # Why a save does not take effect immediately
//
// oidcauth.New runs once, at startup, and the Authenticator it returns is
// immutable by design: the session cache, the JWKS cache, the discovery
// document, the janitor goroutine and the authz resolver are all built around
// it. Swapping that mid-flight for a hub with live sessions is a much larger
// change than editing a config block, and the failure modes are the kind that
// sign everybody out.
//
// So this writes the file and says so. The view reports the *running*
// configuration next to the saved one and sets restart_required when they
// differ, which turns the one genuinely confusing thing about the feature —
// "I enabled it and nothing happened" — into a line of text in the panel.
// Everything else about the block is already re-read from disk per request.
//
// # The client secret
//
// Never leaves the hub. The view reports whether one is set and where it came
// from; a save with the field absent or empty keeps the stored value, which is
// what makes it possible to edit the issuer without re-typing a credential the
// panel cannot show you. Clearing it needs the explicit clear_client_secret
// flag, so an empty input can never silently disarm a working deployment.

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/apierror"
	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/authz"
	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/eventlog"
	"github.com/blechschmidt/cloop/pkg/logger"
	"github.com/blechschmidt/cloop/pkg/oidcauth"
)

// oidcSecretSource says where the client secret in force came from, so the
// panel can explain why a value typed into it would be ignored.
const (
	oidcSecretUnset = "unset"
	oidcSecretFile  = "file"
	oidcSecretEnv   = "env"
)

// oidcSettingsView is the whole editable block plus the context needed to edit
// it safely: what is running, what the bounds are, and what the valid
// enumerations are.
//
// The bounds and enumerations are served rather than hardcoded in the frontend
// because they are already constants in pkg/config and pkg/authz. A second copy
// in JavaScript would be the copy that goes stale, and the symptom would be a
// panel that accepts a value the next startup rejects.
type oidcSettingsView struct {
	Enabled     bool     `json:"enabled"`
	Issuer      string   `json:"issuer"`
	ClientID    string   `json:"client_id"`
	RedirectURL string   `json:"redirect_url"`
	Scopes      []string `json:"scopes"`
	AdminEmails []string `json:"admin_emails"`
	DefaultRole string   `json:"default_role"`

	RoleMappings []config.RoleMapping `json:"role_mappings"`

	SessionTTLHours        int    `json:"session_ttl_hours"`
	IdleTimeoutHours       int    `json:"idle_timeout_hours"`
	RefreshIntervalMinutes int    `json:"refresh_interval_minutes"`
	MaxClaimAgeMinutes     int    `json:"max_claim_age_minutes"`
	ClockSkewSeconds       int    `json:"clock_skew_seconds"`
	RequireIdP             bool   `json:"require_idp"`
	RequireRBAC            bool   `json:"require_rbac"`
	CookieSecure           string `json:"cookie_secure"`

	// ClientSecretSet and ClientSecretSource describe the credential without
	// disclosing it. Source is what makes the difference actionable: on a hub
	// where the environment supplies it, a value typed here would be saved and
	// then ignored, and the panel needs to be able to say so.
	ClientSecretSet    bool   `json:"client_secret_set"`
	ClientSecretSource string `json:"client_secret_source"`

	// Active describes the authenticator this process is actually running,
	// which is the answer to "why did enabling it change nothing".
	Active oidcActiveView `json:"active"`

	// RestartRequired is set when the saved block and the running
	// authenticator disagree.
	RestartRequired bool `json:"restart_required"`

	// RBAC is whether a role policy is in force, running and saved.
	RBAC oidcRBACView `json:"rbac"`

	// Bounds and enumerations for the form.
	Limits oidcLimitsView `json:"limits"`
	Roles  []string       `json:"roles"`
	Claims []string       `json:"claims"`
}

// oidcActiveView is the running authenticator, not the file.
type oidcActiveView struct {
	Enabled bool   `json:"enabled"`
	Issuer  string `json:"issuer"`

	// IdPReady is whether the issuer has ever resolved in this process, and
	// Error the reason it has not. Same source /readyz reads.
	IdPReady bool   `json:"idp_ready"`
	Error    string `json:"error,omitempty"`
}

// oidcRBACView says whether role-based access control is in force — for this
// process and for the saved block — as authz.Enforced answers it (Task 20395).
//
// Served rather than worked out in the panel, which would have to restate the
// rule from default_role and role_mappings. That is how the panel came to show
// "none — deny by default" on a hub whose RBAC was off: an unset default_role
// rendered as what it would mean if a policy existed.
type oidcRBACView struct {
	// Enforced is this process: the answer its request gate acts on.
	Enforced bool `json:"enforced"`

	// SavedEnforced is the saved block: what the next start will enforce.
	SavedEnforced bool `json:"saved_enforced"`

	// DefaultRole is what a signed-in identity matching no mapping gets under
	// the saved block, set only when that block enforces a policy — the
	// resolver's answer, so an unset default_role reads "none" here only where
	// a mapping makes it mean that.
	DefaultRole string `json:"default_role,omitempty"`

	// Warning is set while single sign-on runs, or will run after a restart,
	// without a role policy. It leads with config.RBACOff, the sentence the
	// startup warning and `cloop hub doctor` lead with too.
	Warning string `json:"warning,omitempty"`

	// CanEnforce is set when the saved block turns single sign-on on with no
	// policy, so POST /api/config/oidc/enforce has something to write.
	CanEnforce bool `json:"can_enforce"`
}

// oidcBound is one numeric field's accepted range, as the panel should
// present it.
type oidcBound struct {
	Default int `json:"default"`
	Lower   int `json:"lower"`
	Upper   int `json:"upper"`

	// Disable is the sentinel that turns the behaviour off entirely, for the
	// two fields that have one. Zero means the field has no such value.
	Disable int `json:"disable,omitempty"`
}

type oidcLimitsView struct {
	SessionTTLHours        oidcBound `json:"session_ttl_hours"`
	IdleTimeoutHours       oidcBound `json:"idle_timeout_hours"`
	RefreshIntervalMinutes oidcBound `json:"refresh_interval_minutes"`
	MaxClaimAgeMinutes     oidcBound `json:"max_claim_age_minutes"`
	ClockSkewSeconds       oidcBound `json:"clock_skew_seconds"`
}

func oidcLimits() oidcLimitsView {
	return oidcLimitsView{
		SessionTTLHours: oidcBound{
			Default: config.OIDCSessionTTLHoursDefault,
			Lower:   config.OIDCSessionTTLHoursLower,
			Upper:   config.OIDCSessionTTLHoursUpper,
		},
		IdleTimeoutHours: oidcBound{
			Default: config.OIDCIdleTimeoutHoursDefault,
			Lower:   config.OIDCIdleTimeoutHoursLower,
			Upper:   config.OIDCIdleTimeoutHoursUpper,
		},
		RefreshIntervalMinutes: oidcBound{
			Default: config.OIDCRefreshIntervalMinutesDefault,
			Lower:   config.OIDCRefreshIntervalMinutesLower,
			Upper:   config.OIDCRefreshIntervalMinutesUpper,
			Disable: config.OIDCDisabledSentinel,
		},
		MaxClaimAgeMinutes: oidcBound{
			Default: config.OIDCMaxClaimAgeMinutesDefault,
			Lower:   config.OIDCMaxClaimAgeMinutesLower,
			Upper:   config.OIDCMaxClaimAgeMinutesUpper,
			Disable: config.OIDCDisabledSentinel,
		},
		ClockSkewSeconds: oidcBound{
			Default: config.OIDCClockSkewSecondsDefault,
			Lower:   0,
			Upper:   config.OIDCClockSkewSecondsUpper,
			Disable: config.OIDCDisabledSentinel,
		},
	}
}

// handleOIDCSettings serves GET /api/config/oidc.
func (s *Server) handleOIDCSettings(w http.ResponseWriter, r *http.Request) {
	view, err := s.oidcSettings()
	if err != nil {
		apierror.WriteError(w, apierror.New(apierror.CodeUnavailable, err.Error()))
		return
	}
	jsonOK(w, view)
}

func (s *Server) oidcSettings() (oidcSettingsView, error) {
	cfg, err := s.loadHubConfig()
	if err != nil {
		return oidcSettingsView{}, fmt.Errorf("load hub config: %w", err)
	}
	if cfg == nil {
		return oidcSettingsView{}, fmt.Errorf("load hub config: no configuration")
	}
	return s.oidcViewOf(cfg.UI.OIDC), nil
}

func (s *Server) oidcViewOf(o config.OIDCConfig) oidcSettingsView {
	view := oidcSettingsView{
		Enabled:     o.Enabled,
		Issuer:      o.Issuer,
		ClientID:    o.ClientID,
		RedirectURL: o.RedirectURL,
		Scopes:      o.Scopes,
		AdminEmails: o.AdminEmails,
		DefaultRole: o.DefaultRole,
		// Never nil: the frontend renders this as a list, and a null would
		// make the first "add a mapping" click a special case.
		RoleMappings:           append([]config.RoleMapping{}, o.RoleMappings...),
		SessionTTLHours:        o.SessionTTLHours,
		IdleTimeoutHours:       o.IdleTimeoutHours,
		RefreshIntervalMinutes: o.RefreshIntervalMinutes,
		MaxClaimAgeMinutes:     o.MaxClaimAgeMinutes,
		ClockSkewSeconds:       o.ClockSkewSeconds,
		RequireIdP:             o.RequireIdP,
		RequireRBAC:            o.RequireRBAC,
		CookieSecure:           o.CookieSecure,
		Limits:                 oidcLimits(),
		Roles:                  oidcRoleNames(),
		Claims:                 oidcClaimNames(),
	}

	// Provenance, not the value. config.Load has already overlaid the
	// environment, so a set ClientSecret that equals the environment's came
	// from there — which is the case the panel has to warn about, because a
	// value typed into it would be stored and then overridden on every load.
	envSecret := strings.TrimSpace(os.Getenv(config.EnvOIDCClientSecret))
	switch {
	case envSecret != "" && sameCredential(o.ClientSecret, envSecret):
		view.ClientSecretSet = true
		view.ClientSecretSource = oidcSecretEnv
	case o.ClientSecret != "":
		view.ClientSecretSet = true
		view.ClientSecretSource = oidcSecretFile
	default:
		view.ClientSecretSource = oidcSecretUnset
	}

	view.Active = oidcActiveView{
		Enabled: s.oidcEnabled(),
		Issuer:  s.OIDC.Issuer(),
	}
	if s.oidcEnabled() {
		if err := s.idpReady(); err != nil {
			view.Active.Error = err.Error()
		} else {
			view.Active.IdPReady = true
		}
	}
	view.RestartRequired = s.oidcRestartRequired(o)
	view.RBAC = s.oidcRBACOf(o)
	return view
}

// oidcRBACOf reports RBAC enforcement for the panel: this process through
// authzActive, the saved block o through RBACEnforced — both authz.Enforced.
func (s *Server) oidcRBACOf(o config.OIDCConfig) oidcRBACView {
	v := oidcRBACView{Enforced: s.authzActive()}
	saved, err := authz.New(o.AuthzConfig(nil))
	if err == nil {
		v.SavedEnforced = authz.Enforced(o.Enabled, saved)
		if v.SavedEnforced {
			v.DefaultRole = string(saved.DefaultRole())
		}
	}
	// An invalid policy is not "off": it is a hub that will not start, which
	// the save path refuses and the restart banner reports.
	savedOff := o.Enabled && err == nil && !v.SavedEnforced
	v.CanEnforce = savedOff
	switch {
	case s.oidcEnabled() && !v.Enforced:
		// Named after the issuer this process signs people in through, which
		// is who holds full access right now.
		v.Warning = config.RBACOff(s.OIDC.Issuer()) + "."
		if v.SavedEnforced {
			v.Warning += " Deny-by-default is saved: restart the hub to enforce it."
		}
	case savedOff:
		v.Warning = "Saved without a role policy — after a restart, " + config.RBACOff(o.Issuer) + "."
	}
	return v
}

// oidcRestartRequired reports whether the saved block differs from what this
// process is running.
//
// Every field a running Authenticator will disclose is compared, not just
// whether SSO is on: the accessors cover the issuer and the three session
// clocks, and each of them is a change an operator can make and then watch not
// happen. The ones with no accessor — the client credentials, the scopes, the
// role mappings — are a false negative here, which is the right direction for
// the error to run. Claiming a restart is needed when it is not would teach an
// operator to ignore the banner, and the banner's whole job is to be believed
// the one time it says the hub is still running without SSO.
func (s *Server) oidcRestartRequired(o config.OIDCConfig) bool {
	if o.Enabled != s.oidcEnabled() {
		return true
	}
	if !o.Enabled {
		return false
	}
	if strings.TrimSpace(o.Issuer) != strings.TrimSpace(s.OIDC.Issuer()) {
		return true
	}
	// Whether a role policy is in force (Task 20395), asked of authz.Enforced
	// on both sides — so this fires on exactly the difference the request gate
	// will act on after a restart, and on no other.
	if enforced, err := o.RBACEnforced(); err == nil && enforced != s.authzActive() {
		return true
	}
	// Effective values on both sides: the running authenticator holds clamped
	// durations, so comparing them against the raw config would report a
	// restart for every hub that left a field at 0 and got the default.
	if time.Duration(o.EffectiveSessionTTLHours())*time.Hour != s.OIDC.SessionTTL() {
		return true
	}
	if time.Duration(o.EffectiveIdleTimeoutHours())*time.Hour != s.OIDC.IdleTimeout() {
		return true
	}
	return time.Duration(o.EffectiveMaxClaimAgeMinutes())*time.Minute != s.OIDC.MaxClaimAge()
}

func oidcRoleNames() []string {
	names := make([]string, 0, len(authz.AllRoles))
	for _, r := range authz.AllRoles {
		names = append(names, string(r))
	}
	return names
}

func oidcClaimNames() []string {
	names := make([]string, 0, len(authz.AllClaimKinds))
	for _, k := range authz.AllClaimKinds {
		names = append(names, string(k))
	}
	return names
}

// oidcSettingsRequest is a partial update: an absent field is left alone.
//
// Pointers rather than values throughout, because every field here has a
// meaningful zero — false disables SSO, "" clears the issuer, 0 means "use the
// default" — and a form that submits only what it changed must not be able to
// clear the rest by omission.
type oidcSettingsRequest struct {
	Enabled      *bool     `json:"enabled"`
	Issuer       *string   `json:"issuer"`
	ClientID     *string   `json:"client_id"`
	ClientSecret *string   `json:"client_secret"`
	RedirectURL  *string   `json:"redirect_url"`
	Scopes       *[]string `json:"scopes"`
	AdminEmails  *[]string `json:"admin_emails"`
	DefaultRole  *string   `json:"default_role"`

	RoleMappings *[]config.RoleMapping `json:"role_mappings"`

	SessionTTLHours        *int    `json:"session_ttl_hours"`
	IdleTimeoutHours       *int    `json:"idle_timeout_hours"`
	RefreshIntervalMinutes *int    `json:"refresh_interval_minutes"`
	MaxClaimAgeMinutes     *int    `json:"max_claim_age_minutes"`
	ClockSkewSeconds       *int    `json:"clock_skew_seconds"`
	RequireIdP             *bool   `json:"require_idp"`
	RequireRBAC            *bool   `json:"require_rbac"`
	CookieSecure           *string `json:"cookie_secure"`

	// ConfirmRBAC says the caller has seen what this save does to whether RBAC
	// is in force and means it (Task 20395). Without it, a save that turns a
	// policy on for a hub whose RBAC was off — or that leaves single sign-on
	// without one — is refused with 409 and the consequence spelled out, so the
	// switch is never a side effect of editing another field.
	ConfirmRBAC bool `json:"confirm_rbac"`

	// ClearClientSecret removes the stored credential. Explicit, because an
	// empty ClientSecret means "keep what is stored" — the panel cannot
	// display the secret, so it cannot submit it back, so blank has to be the
	// no-op.
	ClearClientSecret bool `json:"clear_client_secret"`
}

// handleOIDCSettingsSave serves PUT /api/config/oidc.
func (s *Server) handleOIDCSettingsSave(w http.ResponseWriter, r *http.Request) {
	var req oidcSettingsRequest
	if !decodeSecretsBody(w, r, &req) {
		return
	}

	hubConfigMu.Lock()
	// Write where this hub reads (Task 20318). On a host where a second
	// dashboard shares the working directory, saving SSO into the shared
	// config.yaml would be wrong in both directions at once: this hub would
	// not pick the change up, because its own overlay still shadows it, and
	// the other hub would pick up a redirect_url naming an origin it does not
	// serve. So an overlay, once it exists, is what the panel maintains. The
	// destination is chosen before loading (Task 20364), so config.yaml is
	// only ever rewritten from itself.
	save, err := s.beginHubSettingsSave()
	if err != nil {
		hubConfigMu.Unlock()
		apierror.WriteError(w, apierror.New(apierror.CodeUnavailable, "load hub config"))
		return
	}
	cfg := save.Config
	was := cfg.UI.OIDC
	applyOIDCRequest(&cfg.UI.OIDC, req)

	// Refuse before writing, not after: an invalid block here is a hub that
	// will not start, and the repair for that is a shell on the box.
	//
	// s.Authz is passed as the runtime source — it satisfies RuntimeSource via
	// RuntimeBindings — so an operator whose admin standing comes from an
	// incident binding is not told they are about to demote themselves. It is
	// nil on a hub that has never had a policy, which validateOIDCConfig
	// handles.
	if err := validateOIDCConfig(cfg.UI.OIDC, s.callerSubject(r), s.runtimeRoleSource()); err != nil {
		hubConfigMu.Unlock()
		writeOIDCProblem(w, err)
		return
	}
	// Whether RBAC is in force changes only when the request says it means it
	// to. The panel used to submit "none" for an unset default role, so saving
	// any other field of an SSO hub without a policy switched RBAC on and
	// locked out every identity without a mapping, at the next restart.
	if change := rbacChangeOf(was, cfg.UI.OIDC); change != nil && !req.ConfirmRBAC {
		hubConfigMu.Unlock()
		apierror.WriteError(w, apierror.New(apierror.CodeConflict, change.message).
			WithDetails(map[string]any{"rbac_change": change.code}))
		return
	}
	err = save.commit(func(overlay string) error {
		return config.SaveUIInstanceOIDC(overlay, cfg.UI.OIDC)
	})
	if err != nil {
		hubConfigMu.Unlock()
		apierror.WriteError(w, apierror.New(apierror.CodeInternal, err.Error()))
		return
	}
	saved := cfg.UI.OIDC
	hubConfigMu.Unlock()

	s.auditOIDCConfig(r, was, saved)
	jsonOK(w, s.oidcViewOf(saved))
}

// handleOIDCEnforce serves POST /api/config/oidc/enforce: the one-step way out
// of single sign-on without a role policy (Task 20395).
//
// It writes the smallest policy that is deny-by-default and strands nobody who
// administers the hub now: `default_role: none`, admin_emails kept as they are
// — each is a hub-wide admin binding — and a hub-wide admin mapping for the
// acting admin unless the result already makes them one. The mapping binds
// their `sub`, not their email: an address can be renamed at some providers,
// and the subject is the claim OIDC promises is stable for this client.
//
// Then it runs the save path's own gate, validateOIDCConfig — so a hub with no
// administrator left (a static-token caller, no admin_emails) is refused here
// exactly as a hand-written block would be — writes where the hub reads, and
// records oidc.rbac.enforced. Like every save, it is not live until a restart,
// and the view it answers with says so.
//
// Gated on user.manage like the rest of the block. On a hub whose RBAC is off
// every signed-in identity holds that, and so can call this; it grants nothing
// they could not already write through PUT /api/config/oidc, and it only ever
// narrows what everyone else holds.
func (s *Server) handleOIDCEnforce(w http.ResponseWriter, r *http.Request) {
	var req struct{}
	if !decodeSecretsBody(w, r, &req) {
		return
	}
	caller := s.callerSubject(r)

	hubConfigMu.Lock()
	save, err := s.beginHubSettingsSave()
	if err != nil {
		hubConfigMu.Unlock()
		apierror.WriteError(w, apierror.New(apierror.CodeUnavailable, "load hub config"))
		return
	}
	cfg := save.Config
	next, bound, err := enforceDenyByDefault(cfg.UI.OIDC, caller)
	if err != nil {
		hubConfigMu.Unlock()
		apierror.WriteError(w, apierror.New(apierror.CodeConflict, err.Error()))
		return
	}
	if err := validateOIDCConfig(next, caller, s.runtimeRoleSource()); err != nil {
		hubConfigMu.Unlock()
		writeOIDCProblem(w, err)
		return
	}
	cfg.UI.OIDC = next
	err = save.commit(func(overlay string) error {
		return config.SaveUIInstanceOIDC(overlay, next)
	})
	hubConfigMu.Unlock()
	if err != nil {
		apierror.WriteError(w, apierror.New(apierror.CodeInternal, err.Error()))
		return
	}

	s.appendOIDCAudit(r, auditaction.ActionOIDCRBACEnforced, map[string]any{
		"issuer":           next.Issuer,
		"default_role":     next.DefaultRole,
		"bound":            bound,
		"admin_emails":     len(next.AdminEmails),
		"role_mappings":    len(next.RoleMappings),
		"restart_required": s.oidcRestartRequired(next),
	})
	jsonOK(w, s.oidcViewOf(next))
}

// enforceDenyByDefault returns the block the enforce action writes over o, and
// the mapping it added for caller as "claim=value" ("" when none was needed).
// It refuses a block with nothing to enforce: single sign-on off, a policy
// already in force, or one authz.New rejects.
func enforceDenyByDefault(o config.OIDCConfig, caller *authz.Subject) (config.OIDCConfig, string, error) {
	if !o.Enabled {
		return o, "", errors.New("single sign-on is off in the saved configuration, so there is no RBAC to enforce: " +
			"turn it on first")
	}
	enforced, err := o.RBACEnforced()
	if err != nil {
		return o, "", fmt.Errorf("the saved role policy is invalid, so the hub will not start: %w", err)
	}
	if enforced {
		return o, "", errors.New("RBAC is already in force in the saved configuration")
	}
	next := o
	next.RoleMappings = append([]config.RoleMapping(nil), o.RoleMappings...)
	next.DefaultRole = string(authz.RoleNone)
	if caller == nil || caller.Sub == "" {
		// No session to bind — the static token or a service account, whose
		// authority this block does not decide. validateOIDCConfig then asks
		// whether anybody is left to administer the hub.
		return next, "", nil
	}
	policy, err := authz.New(next.AuthzConfig(nil))
	if err == nil && policy.Resolve(caller, authz.GlobalScope).Allows(authz.PermUserManage) {
		return next, "", nil // already an admin through admin_emails
	}
	next.RoleMappings = append(next.RoleMappings, config.RoleMapping{
		Claim: string(authz.ClaimSub),
		Value: caller.Sub,
		Role:  string(authz.RoleAdmin),
	})
	return next, string(authz.ClaimSub) + "=" + caller.Sub, nil
}

// applyOIDCRequest overlays the supplied fields onto o.
func applyOIDCRequest(o *config.OIDCConfig, req oidcSettingsRequest) {
	if req.Enabled != nil {
		o.Enabled = *req.Enabled
	}
	if req.Issuer != nil {
		// Trailing slashes are the classic issuer typo: the spec makes the
		// issuer string equality-compared against the `iss` claim, so
		// "https://idp/" and "https://idp" are different providers and one of
		// them rejects every token. Preflight catches it as issuer_mismatch;
		// trimming it means the panel does not need to.
		o.Issuer = strings.TrimRight(strings.TrimSpace(*req.Issuer), "/")
	}
	if req.ClientID != nil {
		o.ClientID = strings.TrimSpace(*req.ClientID)
	}
	if req.ClearClientSecret {
		o.ClientSecret = ""
	} else if req.ClientSecret != nil {
		if v := strings.TrimSpace(*req.ClientSecret); v != "" {
			o.ClientSecret = v
		}
	}
	if req.RedirectURL != nil {
		o.RedirectURL = strings.TrimSpace(*req.RedirectURL)
	}
	if req.Scopes != nil {
		o.Scopes = trimmedList(*req.Scopes)
	}
	if req.AdminEmails != nil {
		o.AdminEmails = trimmedList(*req.AdminEmails)
	}
	if req.DefaultRole != nil {
		o.DefaultRole = strings.TrimSpace(*req.DefaultRole)
	}
	if req.RoleMappings != nil {
		o.RoleMappings = trimmedMappings(*req.RoleMappings)
	}
	if req.SessionTTLHours != nil {
		o.SessionTTLHours = *req.SessionTTLHours
	}
	if req.IdleTimeoutHours != nil {
		o.IdleTimeoutHours = *req.IdleTimeoutHours
	}
	if req.RefreshIntervalMinutes != nil {
		o.RefreshIntervalMinutes = *req.RefreshIntervalMinutes
	}
	if req.MaxClaimAgeMinutes != nil {
		o.MaxClaimAgeMinutes = *req.MaxClaimAgeMinutes
	}
	if req.ClockSkewSeconds != nil {
		o.ClockSkewSeconds = *req.ClockSkewSeconds
	}
	if req.RequireIdP != nil {
		o.RequireIdP = *req.RequireIdP
	}
	if req.RequireRBAC != nil {
		o.RequireRBAC = *req.RequireRBAC
	}
	if req.CookieSecure != nil {
		o.CookieSecure = strings.ToLower(strings.TrimSpace(*req.CookieSecure))
	}
}

// The two transitions of whether RBAC is in force that a save must not make
// unasked (Task 20395). Machine-readable, so the panel can ask before it
// resends with confirm_rbac.
const (
	// rbacChangeTurnsOn: the saved block ran single sign-on without a policy,
	// and this save writes one — after a restart, an identity matching no
	// mapping gets the default role.
	rbacChangeTurnsOn = "rbac_turns_on"
	// rbacChangeStaysOff: this save leaves single sign-on on with no policy,
	// from a block that either had one or had single sign-on off.
	rbacChangeStaysOff = "rbac_off"
)

// rbacChange is a save's effect on whether RBAC is in force, when it is one an
// admin has to have meant.
type rbacChange struct {
	code    string
	message string
}

// rbacChangeOf compares the saved block with the one about to replace it, both
// through RBACEnforced — authz.Enforced — and returns the transition that needs
// confirming, or nil. Staying in the same state never does: that is the save
// of an unrelated field, which must not move RBAC either way.
func rbacChangeOf(was, now config.OIDCConfig) *rbacChange {
	nowEnforced, err := now.RBACEnforced()
	if err != nil {
		// An invalid policy: refused by validateOIDCConfig while enabled, and
		// read by nothing while disabled.
		return nil
	}
	wasEnforced, wasErr := was.RBACEnforced()
	wasOff := was.Enabled && wasErr == nil && !wasEnforced
	nowOff := now.Enabled && !nowEnforced
	switch {
	case wasOff && nowEnforced:
		role := authz.RoleNone
		if r, err := authz.New(now.AuthzConfig(nil)); err == nil {
			role = r.DefaultRole()
		}
		return &rbacChange{code: rbacChangeTurnsOn, message: fmt.Sprintf(
			"this save turns RBAC on: after the next restart, a signed-in user who matches no role "+
				"mapping gets %q, and only the admin emails and role mappings keep their access — "+
				"confirm to save it", role)}
	case nowOff && !wasOff:
		return &rbacChange{code: rbacChangeStaysOff, message: "this save leaves single sign-on without " +
			"a role policy: after the next restart, " + config.RBACOff(now.Issuer) + " — choose a " +
			"default role (none denies by default) or a role mapping, or confirm to save it"}
	}
	return nil
}

// trimmedList drops blank entries, so a textarea the user left a trailing
// newline in does not become an empty admin email — which authz would
// otherwise turn into a binding matching an identity with no email claim.
func trimmedList(in []string) []string {
	out := make([]string, 0, len(in))
	for _, v := range in {
		if t := strings.TrimSpace(v); t != "" {
			out = append(out, t)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// trimmedMappings drops rows the user started and left blank, and normalises
// the rest. A row with no claim or no value is not a mapping; authz.New would
// reject it, and refusing the whole save because of an empty trailing row would
// be the panel's fault rather than the operator's.
func trimmedMappings(in []config.RoleMapping) []config.RoleMapping {
	out := make([]config.RoleMapping, 0, len(in))
	for _, m := range in {
		m.Claim = strings.ToLower(strings.TrimSpace(m.Claim))
		m.Value = strings.TrimSpace(m.Value)
		m.Role = strings.ToLower(strings.TrimSpace(m.Role))
		m.Project = strings.TrimSpace(m.Project)
		m.Executor = strings.TrimSpace(m.Executor)
		if m.Claim == "" && m.Value == "" && m.Role == "" {
			continue
		}
		out = append(out, m)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// callerSubject is the claim subject of the signed-in user, or nil when the
// request authenticated some other way.
//
// Separate from recipientIdentity: that answers "whose view is this", which
// deliberately follows a delegated token to its owner. This answers "whose
// authority is being spent", and a token's authority is its own.
func (s *Server) callerSubject(r *http.Request) *authz.Subject {
	id := s.sessionIdentity(r)
	if id == nil {
		return nil
	}
	return subjectFromIdentity(id)
}

// runtimeRoleSource exposes the live runtime role bindings as a RuntimeSource,
// or nil when this hub has no resolver at all.
//
// Returning the resolver itself rather than a snapshot keeps the "source owns
// its own freshness" contract pkg/authz documents: a binding written a moment
// ago is visible to the check that is about to read it.
func (s *Server) runtimeRoleSource() authz.RuntimeSource {
	if s.Authz == nil {
		return nil
	}
	return s.Authz
}

// writeOIDCProblem renders a refusal, keeping the blamed field machine-readable
// so the panel can highlight the input rather than only describe it.
func writeOIDCProblem(w http.ResponseWriter, err error) {
	e := apierror.New(apierror.CodeInvalidInput, err.Error())
	if p, ok := asOIDCConfigProblem(err); ok && p.Field != "" {
		e = e.WithDetails(map[string]any{"field": p.Field})
	}
	apierror.WriteError(w, e)
}

// oidcTestRequest names an issuer to contact. Empty means "the one that is
// saved", so the button works before anything has been typed.
type oidcTestRequest struct {
	Issuer string `json:"issuer"`
}

// oidcTestResponse is a preflight verdict.
type oidcTestResponse struct {
	OK     bool   `json:"ok"`
	Issuer string `json:"issuer"`

	Result *oidcauth.PreflightResult `json:"result,omitempty"`

	Error       string `json:"error,omitempty"`
	Reason      string `json:"reason,omitempty"`
	Stage       string `json:"stage,omitempty"`
	Remediation string `json:"remediation,omitempty"`
}

// handleOIDCTest serves POST /api/config/oidc/test.
//
// Reachability is the one thing static validation cannot answer, and it is the
// most common thing to get wrong: a tenant id fat-fingered into an Azure
// issuer is a valid https URL that will fail every sign-in. Running the same
// preflight startup runs — against a candidate issuer, before saving — turns
// that from an outage into a red line under a text box.
//
// A POST rather than a GET because it makes the hub originate an outbound
// request to a caller-supplied URL; that is a side effect, and it should not be
// something a prefetch or a crawler can trigger.
//
// # On the outbound request
//
// This does let a caller point the hub's HTTP client at a URL they chose, which
// is worth being explicit about rather than leaving a reviewer to work out. It
// grants nothing the caller does not already have: the same caller can write
// that issuer to config.yaml, and the hub will then contact it at every startup
// and every sign-in. The permission is user.manage, the highest the hub has. And
// the response is a fixed shape — resolved endpoints, a key count, or a
// classified failure reason — never the fetched body, so it cannot be used to
// read a page back out of the hub's network. Making the admin save a broken
// issuer to discover it is broken would remove no capability and cost an outage.
func (s *Server) handleOIDCTest(w http.ResponseWriter, r *http.Request) {
	var req oidcTestRequest
	if !decodeSecretsBody(w, r, &req) {
		return
	}
	issuer := strings.TrimRight(strings.TrimSpace(req.Issuer), "/")
	if issuer == "" {
		cfg, err := s.loadHubConfig()
		if err != nil || cfg == nil {
			apierror.WriteError(w, apierror.New(apierror.CodeUnavailable, "load hub config"))
			return
		}
		issuer = strings.TrimSpace(cfg.UI.OIDC.Issuer)
	}
	if issuer == "" {
		apierror.WriteError(w, apierror.New(apierror.CodeInvalidInput,
			"no issuer to test — enter one first"))
		return
	}

	// Bounded by the same constant startup uses, and by the request context, so
	// a client that gives up does not leave the hub waiting on an IdP.
	ctx, cancel := context.WithTimeout(r.Context(), oidcauth.DefaultPreflightTimeout)
	defer cancel()

	result, err := oidcauth.Preflight(ctx, issuer, oidcauth.PreflightOptions{})
	resp := oidcTestResponse{Issuer: issuer}
	if err != nil {
		resp.Error = err.Error()
		var pe *oidcauth.PreflightError
		if errors.As(err, &pe) {
			resp.Reason = pe.Reason
			resp.Stage = pe.Stage
			resp.Remediation = pe.Remediation()
		}
		// 200 with ok:false, not a 4xx. The request was well-formed and the
		// hub answered it correctly; "your IdP is unreachable" is the result,
		// not a failure of the call. A 502 here would also be indistinguishable
		// in the panel from the hub itself being broken.
		jsonOK(w, resp)
		return
	}
	resp.OK = true
	resp.Result = result
	jsonOK(w, resp)
}

// auditOIDCConfig records the change.
//
// The payload names which fields moved and the before/after of the ones that
// are safe to record — never the client secret, and not even its length. The
// two that matter for a later investigation are whether SSO was on and who
// held admin, because those are the two an attacker with this permission would
// change.
func (s *Server) auditOIDCConfig(r *http.Request, was, now config.OIDCConfig) {
	changed := oidcChangedFields(was, now)
	if len(changed) == 0 {
		// A save that changed nothing is a form being re-submitted, not an
		// event. Recording it would dilute the one query this row exists to
		// answer: when did somebody last touch who can sign in.
		return
	}
	// Errors read as "not enforced": an invalid policy enforces nothing, and
	// the save path refuses one while SSO is on.
	wasEnforced, _ := was.RBACEnforced()
	nowEnforced, _ := now.RBACEnforced()
	s.appendOIDCAudit(r, auditaction.ActionOIDCConfigUpdated, map[string]any{
		"changed":           strings.Join(changed, ","),
		"enabled":           now.Enabled,
		"was_enabled":       was.Enabled,
		"issuer":            now.Issuer,
		"default_role":      now.DefaultRole,
		"admin_emails":      len(now.AdminEmails),
		"role_mappings":     len(now.RoleMappings),
		"require_idp":       now.RequireIdP,
		"require_rbac":      now.RequireRBAC,
		"rbac_enforced":     nowEnforced,
		"was_rbac_enforced": wasEnforced,
		"restart_required":  s.oidcRestartRequired(now),
	})
}

// appendOIDCAudit writes one ui.oidc row to the hub's own journal, not a
// project's: these are properties of the deployment. Best-effort, matching
// every other emitter here — a wedged journal must not stop an operator
// repairing their identity provider.
func (s *Server) appendOIDCAudit(r *http.Request, action auditaction.Action, payload map[string]any) {
	blob, err := json.Marshal(payload)
	if err != nil {
		return
	}
	actor := s.auditActor(r)
	if actor == "" {
		actor = "anonymous"
	}
	log, logErr := eventlog.Open(s.WorkDir)
	if logErr != nil {
		if logErr != eventlog.ErrNoProject {
			s.log().Warn(logger.EventAuthz, 0, "oidc config audit: open event log",
				map[string]interface{}{"error": logErr.Error()})
		}
		return
	}
	defer log.Close()
	if err := log.Append(&eventlog.AuditEvent{
		Actor:      actor,
		EventType:  string(action),
		EntityType: "config",
		EntityID:   "ui.oidc",
		Payload:    string(blob),
	}); err != nil {
		s.log().Warn(logger.EventAuthz, 0, "oidc config audit: append",
			map[string]interface{}{"error": err.Error()})
	}
}

// oidcChangedFields lists the field names that differ, so the trail answers
// "what did they change" without storing two copies of the whole block.
func oidcChangedFields(was, now config.OIDCConfig) []string {
	var changed []string
	add := func(name string, differs bool) {
		if differs {
			changed = append(changed, name)
		}
	}
	add("enabled", was.Enabled != now.Enabled)
	add("issuer", was.Issuer != now.Issuer)
	add("client_id", was.ClientID != now.ClientID)
	// Recorded as a change, never as a value.
	add("client_secret", !sameCredential(was.ClientSecret, now.ClientSecret))
	add("redirect_url", was.RedirectURL != now.RedirectURL)
	add("scopes", !sameStrings(was.Scopes, now.Scopes))
	add("admin_emails", !sameStrings(was.AdminEmails, now.AdminEmails))
	add("default_role", was.DefaultRole != now.DefaultRole)
	add("role_mappings", !sameMappings(was.RoleMappings, now.RoleMappings))
	add("session_ttl_hours", was.SessionTTLHours != now.SessionTTLHours)
	add("idle_timeout_hours", was.IdleTimeoutHours != now.IdleTimeoutHours)
	add("refresh_interval_minutes", was.RefreshIntervalMinutes != now.RefreshIntervalMinutes)
	add("max_claim_age_minutes", was.MaxClaimAgeMinutes != now.MaxClaimAgeMinutes)
	add("clock_skew_seconds", was.ClockSkewSeconds != now.ClockSkewSeconds)
	add("require_idp", was.RequireIdP != now.RequireIdP)
	add("require_rbac", was.RequireRBAC != now.RequireRBAC)
	add("cookie_secure", was.CookieSecure != now.CookieSecure)
	return changed
}

// sameCredential compares two secrets without an early return.
//
// Neither call site has an attacker on either side — both compare two values
// the hub already holds, to answer "where did this come from" and "did it
// change" — so the timing channel is theoretical here. It is still spelled this
// way, because the alternative is an allowlist entry in
// TestSecretComparisonsAreConstantTime, and an allowlist is a standing claim
// that a future reader has to re-derive to trust. A constant-time compare costs
// nothing at once per request and leaves nothing to re-derive.
func sameCredential(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func sameMappings(a, b []config.RoleMapping) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
