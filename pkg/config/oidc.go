package config

import (
	"time"

	"github.com/blechschmidt/cloop/pkg/authz"
	"github.com/blechschmidt/cloop/pkg/oidcauth"
	"github.com/blechschmidt/cloop/pkg/quota"
)

// AuthConfig builds the oidcauth.Config a hub runs from its ui.oidc block.
//
// Static fields only: the runtime hooks a live hub supplies — the session
// store, the audit sink, the session-limit and effective-role resolvers — are
// assigned by the caller that has them. Validation does not need them, which
// is what lets every caller hand the result to oidcauth.New and get the
// verdict startup will get.
//
// There are three such callers and one builder on purpose: `cloop ui` builds
// its authenticator from this, the Settings panel validates a prospective
// block by passing this to the same constructor (Task 20308), and `cloop hub
// doctor` asks the constructor whether the hub would start (Task 20387). With
// a second construction site, the panel could save a block that startup then
// refuses — fatally — or the doctor could pass one.
func (o OIDCConfig) AuthConfig() oidcauth.Config {
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

// AuthzBindings converts role_mappings into the authz model. Field copies and
// nothing else: authz.New normalizes and validates them — it rejects an
// unknown claim kind or role name, and it is the authority at startup — so a
// second check here would only be a second opinion.
func (o OIDCConfig) AuthzBindings() []authz.Binding {
	if len(o.RoleMappings) == 0 {
		return nil
	}
	bindings := make([]authz.Binding, 0, len(o.RoleMappings))
	for _, m := range o.RoleMappings {
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

// AuthzConfig builds the authz.Config a hub runs from its ui.oidc block, with
// the same three callers as AuthConfig and for the same reason: `cloop ui`
// builds its resolver from it, the Settings panel validates a prospective block
// with it, and `cloop hub doctor` judges the policy the hub will enforce
// (Task 20387) rather than the YAML it was written in.
//
// runtime may be nil, which evaluates the configured policy alone.
func (o OIDCConfig) AuthzConfig(runtime authz.RuntimeSource) authz.Config {
	return authz.Config{
		DefaultRole: authz.Role(o.DefaultRole),
		Bindings:    o.AuthzBindings(),
		AdminEmails: o.AdminEmails,
		Runtime:     runtime,
	}
}

// QuotaConfig converts ui.quotas into the quota model: field copies, with every
// rule — unknown resources refused, a negative ceiling read as unlimited, a
// binding with no limits refused — left to quota.New, which `cloop ui` runs at
// startup and `cloop hub doctor` runs to judge the policy the hub will enforce
// rather than the YAML it was written in (Task 20387).
func (q QuotasConfig) QuotaConfig() quota.Config {
	cfg := quota.Config{Defaults: quotaLimits(q.Defaults)}
	for _, b := range q.Bindings {
		cfg.Bindings = append(cfg.Bindings, quota.Binding{
			Claim:  authz.ClaimKind(b.Claim),
			Value:  b.Value,
			Limits: quotaLimits(b.Limits),
		})
	}
	return cfg
}

func quotaLimits(m map[string]float64) quota.Limits {
	if len(m) == 0 {
		return nil
	}
	out := make(quota.Limits, len(m))
	for k, v := range m {
		out[quota.Resource(k)] = v
	}
	return out
}
