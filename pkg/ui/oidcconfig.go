package ui

// Editing a hub's OIDC configuration (Task 20308).
//
// Until now `ui.oidc` could only be reached by hand-editing config.yaml on the
// box — eight of its fifteen fields also had a `cloop config set` key, the
// other seven had nothing — and the dashboard could not see it at all. That
// is the wrong shape for the one block whose contents decide who may sign in
// and with what authority: it is edited by the person least likely to have a
// shell on the hub, and its failure mode is discovered by everybody at once.
//
// # Why this file exists at all
//
// The dangerous property of this configuration is not that a bad value is
// rejected late. It is that a bad value is rejected *at startup*: cmd/ui_cmd.go
// treats an invalid ui.oidc block as fatal, on purpose, because a dashboard
// configured to require SSO must not come up wide open. So a Settings panel
// that saves an invalid block does not produce a broken login page — it
// produces a hub that will not boot, whose only repair is a shell on the box,
// which is the situation the panel existed to avoid.
//
// The defence is that the panel validates through the identical code the next
// startup will run, rather than through a second implementation of the same
// rules that can drift from it. That is what these builders are for: there is
// one place that turns a config.OIDCConfig into the arguments of oidcauth.New
// and authz.New, and both the startup path and the save path go through it.
// A rule added to either constructor is enforced on save for free, and a rule
// that exists only in the panel cannot exist at all.
//
// # The three refusals
//
// Startup parity is necessary but not sufficient. A config can be perfectly
// valid and still lock every human out of the hub, which the constructors have
// no opinion about because it is a question about the *deployment*, not the
// syntax. So on top of parity there are three refusals, each of which
// corresponds to a way an admin can lock themselves out with one click:
//
//	wouldNotStart      the next boot fails — the constructors' own verdict
//	wouldStrandTheHub  SSO comes up with nobody holding admin
//	wouldDemoteCaller  SSO comes up with everybody but the caller holding it
//
// The last two are checked by building the prospective resolver and asking it,
// so they answer the real question ("who would be admin after this save")
// rather than a proxy for it.

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/authz"
	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/oidcauth"
)

// OIDCAuthConfig builds the oidcauth.Config a hub runs from its ui.oidc block.
//
// Static fields only: the runtime hooks a live hub supplies — the session
// store, the audit sink, the session-limit and effective-role resolvers — are
// assigned by the caller that has them. Validation does not need them, which
// is what lets the save path call oidcauth.New on the same struct startup will.
//
// Exported because cmd/ui_cmd.go is the other caller, and the entire point is
// that there is only one of these.
func OIDCAuthConfig(o config.OIDCConfig) oidcauth.Config {
	return oidcauth.Config{
		Enabled:      true,
		Issuer:       o.Issuer,
		ClientID:     o.ClientID,
		ClientSecret: o.ClientSecret,
		RedirectURL:  o.RedirectURL,
		Scopes:       o.Scopes,
		AdminEmails:  o.AdminEmails,
		SessionTTL:   time.Duration(o.EffectiveSessionTTLHours()) * time.Hour,
		IdleTimeout:  time.Duration(o.EffectiveIdleTimeoutHours()) * time.Hour,
		// Bounded authorization staleness for privileged actions
		// (Task 20273). Independent of RefreshInterval on purpose: a hub that
		// disabled the background pass still may not grant a credential on
		// claims of unknown age.
		RefreshInterval: time.Duration(o.EffectiveRefreshIntervalMinutes()) * time.Minute,
		MaxClaimAge:     time.Duration(o.EffectiveMaxClaimAgeMinutes()) * time.Minute,
		ClockSkew:       o.EffectiveClockSkew(),
		CookieSecure:    o.CookieSecure,
	}
}

// OIDCBindings converts the YAML role-mapping shape into the authz model.
//
// Lives here rather than in pkg/config because pkg/config stays free of
// authorization logic and pkg/authz stays free of YAML — the split
// RoleMapping's own doc comment describes. The values are not checked here;
// authz.New rejects an unknown claim kind or role name, and it is the
// authority at startup, so a second check would only be a second opinion.
func OIDCBindings(mappings []config.RoleMapping) []authz.Binding {
	if len(mappings) == 0 {
		return nil
	}
	bindings := make([]authz.Binding, 0, len(mappings))
	for _, m := range mappings {
		bindings = append(bindings, authz.Binding{
			Claim:    authz.ClaimKind(m.Claim),
			Value:    m.Value,
			Role:     authz.Role(m.Role),
			Project:  m.Project,
			Executor: m.Executor,
		})
	}
	return bindings
}

// OIDCAuthzConfig builds the authz.Config a hub runs from its ui.oidc block.
//
// runtime may be nil: a prospective policy is evaluated without the runtime
// layer on purpose. Those rows are an operator's emergency grants and
// withdrawals, and a config change must not be judged safe because somebody
// currently holds authority from an incident binding that is meant to be
// temporary.
func OIDCAuthzConfig(o config.OIDCConfig, runtime authz.RuntimeSource) authz.Config {
	return authz.Config{
		DefaultRole: authz.Role(o.DefaultRole),
		Bindings:    OIDCBindings(o.RoleMappings),
		AdminEmails: o.AdminEmails,
		Runtime:     runtime,
	}
}

// oidcConfigProblem is a refusal to save, carrying the field to blame.
//
// The field matters: the panel puts the message beside the input that caused
// it, and "issuer must be https" pointing at the issuer box is the difference
// between a fixable error and a dialog someone dismisses.
type oidcConfigProblem struct {
	Field   string `json:"field,omitempty"`
	Message string `json:"message"`
}

func (p oidcConfigProblem) Error() string {
	if p.Field == "" {
		return p.Message
	}
	return p.Field + ": " + p.Message
}

// validateOIDCConfig decides whether o may be written to config.yaml.
//
// caller is the identity performing the save, or nil when there is none —
// which is the case on a token-only hub, where the static bearer token is the
// deployment's root credential and there is no session to demote. The
// self-demotion check is skipped then, not failed: nobody to strand.
//
// A nil error means the next `cloop ui` start will accept this block and come
// up with at least one administrator.
func validateOIDCConfig(o config.OIDCConfig, caller *authz.Subject) error {
	if !o.Enabled {
		// A disabled block is not read by anything, so there is nothing to
		// get wrong and nothing to be locked out of. Saving a half-filled
		// draft with the switch off has to stay possible — it is how an
		// operator stages an issuer before turning SSO on.
		return nil
	}
	if err := oidcStartupParity(o); err != nil {
		return err
	}
	resolver, err := authz.New(OIDCAuthzConfig(o, nil))
	if err != nil {
		// Reachable: authz.New rejects an unknown claim kind, an unknown role
		// name, and a default_role that is neither. Startup treats each as
		// fatal, so each must be refused here.
		return oidcConfigProblem{Field: "role_mappings", Message: err.Error()}
	}
	if err := wouldStrandTheHub(o, resolver); err != nil {
		return err
	}
	return wouldDemoteCaller(resolver, caller)
}

// oidcStartupParity asks the constructor that runs at startup whether it would
// accept this block.
//
// Deliberately thin. Every rule it enforces — issuer present, parseable, and
// https or loopback; client id, client secret and redirect URL present;
// cookie_secure one of three words; the claim-age and clock-skew ceilings —
// belongs to oidcauth.New, and re-stating any of them here would create a
// second copy that can disagree with the one that decides whether the hub
// boots.
func oidcStartupParity(o config.OIDCConfig) error {
	if _, err := oidcauth.New(OIDCAuthConfig(o)); err != nil {
		return oidcConfigProblem{Field: oidcBlameField(err), Message: err.Error()}
	}
	return nil
}

// oidcBlameField maps a constructor error onto the input that caused it.
//
// Matching on the message is unattractive and the alternative is worse:
// oidcauth.New returns bare errors, and the only other way to attribute them
// is to re-derive the rules here, which is the duplication this file exists to
// avoid. A miss costs a message that appears at the top of the form instead of
// beside a box — so the failure mode of guessing wrong is cosmetic, which is
// what makes it an acceptable place to guess.
func oidcBlameField(err error) string {
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "issuer"):
		return "issuer"
	case strings.Contains(msg, "client_secret"), strings.Contains(msg, "client secret"):
		return "client_secret"
	case strings.Contains(msg, "client_id"), strings.Contains(msg, "client id"):
		return "client_id"
	case strings.Contains(msg, "redirect"):
		return "redirect_url"
	case strings.Contains(msg, "cookie_secure"):
		return "cookie_secure"
	case strings.Contains(msg, "claim age"), strings.Contains(msg, "max_claim_age"):
		return "max_claim_age_minutes"
	case strings.Contains(msg, "skew"):
		return "clock_skew_seconds"
	}
	return ""
}

// wouldStrandTheHub refuses a config that turns SSO on with no administrator.
//
// default_role is "none" unless set, so the natural first draft — an issuer, a
// client, and nothing else — produces a hub where every signed-in user is
// denied everything and the Settings panel that could fix it is among the
// things they are denied. The static bearer token and `cloop hub role` can
// still repair it, so this is recoverable rather than terminal; it is refused
// anyway because it is never what anybody meant, and because the person it
// strands is the person who clicked Save.
//
// Three things count as having an administrator, and they are asked of the
// resolver rather than of the config, so a mapping that grants admin through a
// group claim counts exactly as much as an entry in admin_emails.
func wouldStrandTheHub(o config.OIDCConfig, resolver *authz.Resolver) error {
	if len(o.AdminEmails) > 0 {
		return nil
	}
	if resolver.DefaultRole() == authz.RoleAdmin {
		return nil
	}
	for _, b := range OIDCBindings(o.RoleMappings) {
		if b.Role == authz.RoleAdmin {
			return nil
		}
	}
	return oidcConfigProblem{
		Field: "admin_emails",
		Message: "enabling SSO with no administrator would lock every user out: " +
			"add an admin email, or a role mapping granting the admin role",
	}
}

// wouldDemoteCaller refuses a config under which the person saving it would no
// longer be able to change it back.
//
// The same anti-escalation reasoning as minting an API token, pointed the other
// way: an admin editing role mappings is one typo away from removing their own
// grant, and the surface that would tell them so is the one they just lost.
// Checked against the prospective resolver, so it answers "would I still be an
// admin under the config I am about to save" and not "am I one now".
func wouldDemoteCaller(resolver *authz.Resolver, caller *authz.Subject) error {
	if caller == nil {
		// No session: the caller authenticated with the static bearer token or
		// a service-account token, whose authority does not come from this
		// block and so cannot be revoked by it.
		return nil
	}
	if resolver.Resolve(caller, authz.GlobalScope).Allows(authz.PermUserManage) {
		return nil
	}
	return oidcConfigProblem{
		Field: "role_mappings",
		Message: fmt.Sprintf("this change would remove your own administrative access (%s): "+
			"keep a mapping or admin email that grants you the admin role",
			callerLabel(caller)),
	}
}

// callerLabel names the caller in a refusal without leaking more than they
// already know about themselves.
func callerLabel(caller *authz.Subject) string {
	if caller == nil {
		return "unknown"
	}
	if caller.Email != "" {
		return caller.Email
	}
	if caller.Sub != "" {
		return "sub:" + caller.Sub
	}
	return "unknown"
}

// asOIDCConfigProblem reports whether err is a refusal with a field to blame.
func asOIDCConfigProblem(err error) (oidcConfigProblem, bool) {
	var p oidcConfigProblem
	if errors.As(err, &p) {
		return p, true
	}
	return oidcConfigProblem{}, false
}
