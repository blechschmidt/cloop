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
// rules that can drift from it. That is what the builders are for: there is
// one place that turns a config.OIDCConfig into the arguments of oidcauth.New
// (config.OIDCConfig.AuthConfig) and one for authz.New (AuthzConfig), and the
// startup path, the save path and `cloop hub doctor` all go through them. A rule added to either
// constructor is enforced on save for free, and a rule that exists only in
// the panel cannot exist at all.
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

	"github.com/blechschmidt/cloop/pkg/authz"
	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/oidcauth"
)

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
// runtime supplies the operator-written role bindings in force, and is used for
// exactly one of the two lockout checks. The split is the point: see the two
// resolvers built below.
//
// A nil error means the next `cloop ui` start will accept this block and come
// up with at least one administrator.
func validateOIDCConfig(o config.OIDCConfig, caller *authz.Subject, runtime authz.RuntimeSource) error {
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
	// Two resolvers over the same prospective config, differing only in whether
	// the runtime layer is visible, because the two questions want different
	// answers about it.
	//
	// "Does this deployment have an administrator" must not be satisfied by a
	// runtime binding: those are an operator's emergency grants, written during
	// an incident and meant to be withdrawn, and a hub whose only admin is one
	// is a hub that loses its last admin when somebody tidies up.
	//
	// "Can the person saving this still change it back" must be: if their
	// authority comes from such a binding then this config change does not take
	// it away, they are not locked out, and refusing them would block the
	// incident-response path at exactly the moment it is being used.
	configured, err := authz.New(o.AuthzConfig(nil))
	if err != nil {
		// Reachable: authz.New rejects an unknown claim kind, an unknown role
		// name, and a default_role that is neither. Startup treats each as
		// fatal, so each must be refused here.
		return oidcConfigProblem{Field: "role_mappings", Message: err.Error()}
	}
	if err := wouldStrandTheHub(configured); err != nil {
		return err
	}
	withRuntime, err := authz.New(o.AuthzConfig(runtime))
	if err != nil {
		return oidcConfigProblem{Field: "role_mappings", Message: err.Error()}
	}
	return wouldDemoteCaller(withRuntime, caller)
}

// oidcStartupParity asks the constructor that runs at startup whether it would
// accept this block.
//
// Deliberately thin. Every rule it enforces — issuer present, parseable, and
// https or loopback; client id present; a redirect URL whose path the hub's
// router can serve under /auth/; cookie_secure one of three words; the
// claim-age and clock-skew ceilings —
// belongs to oidcauth.New, and re-stating any of them here would create a
// second copy that can disagree with the one that decides whether the hub
// boots.
func oidcStartupParity(o config.OIDCConfig) error {
	if _, err := oidcauth.New(o.AuthConfig()); err != nil {
		return oidcConfigProblem{Field: oidcBlameField(err), Message: err.Error()}
	}
	return nil
}

// oidcBlameField maps a constructor error onto the input that caused it, by
// the field oidcauth.New names in its refusal (oidcauth.ConfigError) — the
// same tag `cloop hub doctor` reports a refusal under. It used to be guessed
// from the message, which was the only way before New said. Two fields carry
// a unit in the panel that the constructor's name for them does not; an error
// that names no field leaves the message at the top of the form.
func oidcBlameField(err error) string {
	var ce *oidcauth.ConfigError
	if !errors.As(err, &ce) {
		return ""
	}
	switch ce.Field {
	case "max_claim_age":
		return "max_claim_age_minutes"
	case "clock_skew":
		return "clock_skew_seconds"
	}
	return ce.Field
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
// Two things count as having an administrator, and both are asked of the
// resolver rather than of the YAML: a default role of admin, or a binding the
// resolver holds as hub-wide admin (authz.GlobalAdminBindings) — which covers
// admin_emails, a group mapping and an email mapping alike, and is the same
// answer `cloop hub doctor` gives. Asking the YAML went wrong twice (Task
// 20387): "role: Admin" grants admin but was not counted, and an admin binding
// narrowed to one project was counted though it cannot reach this panel.
func wouldStrandTheHub(resolver *authz.Resolver) error {
	if resolver.DefaultRole() == authz.RoleAdmin || len(resolver.GlobalAdminBindings()) > 0 {
		return nil
	}
	return oidcConfigProblem{
		Field: "admin_emails",
		Message: "enabling SSO with no administrator would lock every user out: " +
			"add an admin email, or a role mapping granting the admin role with no project or executor",
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
