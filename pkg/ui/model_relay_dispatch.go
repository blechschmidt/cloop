package ui

// model_relay_dispatch.go: a dispatch's Claude credential stays on the hub
// (Task 20435). See model_relay.go for the relay itself.
//
// applyModelRelay runs on every dispatch path that leases — a run
// (startWorkloadAs), a helper subcommand (runWorkloadEnvFor), a reproduction —
// after the lease, the sandbox file, the firewall and the git proxy's trust
// have shaped the spec. When the relay is on, the executor isolates from the
// hub and the harness is claudecode or anthropic, it takes the Claude
// credential the lease delivered out of the sandbox's environment and mints a
// relay session that spends it here instead: standing on the run's lease,
// charged to the identity the dispatch resolved.
//
// What it will not do is relay a credential kind nobody has proven end to end
// against the real API through it (relayProvenKinds). Such a run gets its
// credential exactly as before the relay existed, and the run's journal, the
// audit trail and the project's Claude credential card say so. Nor does it
// fall back to delivering the credential when the relay should apply and
// cannot: a relay that is not running, a listener that is not there, a session
// that cannot be minted refuse the dispatch.

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/claudeproxy"
	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/cost"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/remote"
	"github.com/blechschmidt/cloop/pkg/provider/anthropic"
	"github.com/blechschmidt/cloop/pkg/provider/claudecode"
	"github.com/blechschmidt/cloop/pkg/redact"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// Relay credential kinds, as claudeproxy.Upstream.Kind names them.
const (
	relayKindOAuth  = "oauth_token"
	relayKindAPIKey = "api_key"
)

// relayProvenKinds are the credential kinds proven end to end against the real
// API through the relay, with the evidence. A kind absent here is never
// relayed: its runs keep the delivery they had before the relay existed. To
// add one, run TestLiveModelRelay with a credential of that kind (see its
// comment) and record what it showed.
var relayProvenKinds = map[string]string{
	// 2026-10-16 (Task 20435): a claude.ai OAuth token (`claude setup-token`)
	// relayed to api.anthropic.com as a bearer with the oauth beta, by real
	// Claude Code in a sandbox that never held it — through a test hub and a
	// device agent on sgx, and by TestLiveModelRelay.
	relayKindOAuth: "proven 2026-10-16: real Claude Code through the relay to api.anthropic.com",
}

// relayProven reports whether a credential kind may be relayed.
func relayProven(kind string) bool {
	_, ok := relayProvenKinds[kind]
	return ok
}

// relayKey is a variable a credential reaches a harness in, and its kind.
type relayKey struct {
	Key  string
	Kind string
}

// relayKeysFor are the variables the relay can take custody of for a
// provider, in the order a harness would prefer them. claudecode's
// ANTHROPIC_AUTH_TOKEN with ANTHROPIC_BASE_URL is a gateway of the project's
// own choosing and is left alone: relaying it would send its bearer to the
// Anthropic API instead.
func relayKeysFor(provider string) []relayKey {
	switch provider {
	case claudecode.ProviderName:
		return []relayKey{{envClaudeOAuthToken, relayKindOAuth}, {envAnthropicAPIKey, relayKindAPIKey}}
	case anthropic.ProviderName:
		return []relayKey{{envAnthropicAPIKey, relayKindAPIKey}, {envCloopAnthropicKey, relayKindAPIKey}}
	}
	return nil
}

// relayWithheldKeys are every variable that hands a harness a Claude
// credential or points it somewhere else for one. A relayed sandbox gets none
// of them from its lease: the relay's own two replace them.
var relayWithheldKeys = []string{
	envClaudeOAuthToken, envAnthropicAPIKey, envAnthropicAuth, envCloopAnthropicKey, envAnthropicBaseURL,
}

// modelRelayEnvKey names the relay session in a sandbox's environment. Not a
// credential: the id is in every audit row the session produces.
const modelRelayEnvKey = "CLOOP_MODEL_RELAY"

// relayCredential is the credential a dispatch would relay.
type relayCredential struct {
	Key     string
	Kind    string
	GrantID string
	// Hub: the hub's own anthropic.api_key, allowed for this project or
	// executor by an administrator.
	Hub   bool
	value string
}

// relayDispatch is what a dispatch path tells applyModelRelay about itself.
type relayDispatch struct {
	runID    string
	payer    string
	provider string
	// run: a project's run, whose spend the relay settles at its end
	// (model_relay_spend.go). A helper subcommand or a reproduction is not.
	run bool
}

// modelRelayBinding is the hub's account of the run a session serves, kept in
// its record (sessionrecord.ModelScope.Run) for the process adopting the run.
type modelRelayBinding struct {
	WorkDir  string `json:"workdir"`
	Provider string `json:"provider"`
	// Key is the variable the credential was granted in, which a restore
	// re-derives it from; Hub that it is the hub's own key instead.
	Key string `json:"key,omitempty"`
	Hub bool   `json:"hub_credential,omitempty"`
	// Run marks a project's run; LedgerFrom is its project ledger's last row
	// when it was dispatched, from which its own report of its spend is read.
	Run        bool  `json:"run,omitempty"`
	LedgerFrom int64 `json:"ledger_from,omitempty"`
}

// relayProviderFor is the provider the dispatch's harness runs, as the
// preflight judged it.
func (c *harnessClearance) relayProviderFor(ex executor.Executor, workDir string) string {
	if c != nil {
		c.mu.Lock()
		rep, prov := c.report, c.provider
		c.mu.Unlock()
		if rep != nil && rep.ExecutorID == ex.ID() && rep.Provider != "" {
			return rep.Provider
		}
		if prov != "" {
			return prov
		}
	}
	return sandboxProviderName(workDir, ex)
}

// relayPayerFor is who a dispatch with no run identity of its own charges:
// the identity the clearance acts for, else "local".
func (c *harnessClearance) relayPayerFor() string {
	if c != nil && c.who.identity != "" {
		return c.who.identity
	}
	return cost.IdentityLocal
}

// modelRelayUnavailableError refuses a dispatch the relay should serve and
// cannot.
type modelRelayUnavailableError struct{ reason string }

func (e *modelRelayUnavailableError) Error() string {
	return "this hub keeps sandboxed runs' Claude credentials behind its model relay " +
		"(executors.model_relay), and the relay cannot serve this run: " + e.reason +
		". The run was not started, rather than given the credential."
}

// applyModelRelay keeps the dispatch's Claude credential on the hub when the
// relay should; see the file's comment. It returns the relayed spec and the
// session's id, spec unchanged and "" when the relay does not apply, and an
// error when it should and cannot.
func applyModelRelay(spec executor.Spec, ex executor.Executor, workDir string, lease *secretLease,
	d relayDispatch) (executor.Spec, string, error) {
	if !modelRelayWanted.Load() || ex == nil || !executor.IsolatesFromHost(ex) {
		return spec, "", nil
	}
	keys := relayKeysFor(d.provider)
	if len(keys) == 0 {
		return spec, "", nil
	}
	svc := activeModelRelay()
	if svc == nil {
		return spec, "", &modelRelayUnavailableError{reason: "the relay is not running: " + modelRelayUnavailableReason()}
	}
	cred, found := relayCredentialIn(spec, keys)
	if !found {
		cred, found = svc.hubCredentialFor(workDir, ex)
	}
	if !found {
		// Nothing the relay could take custody of: the executor brings its
		// own, or the run has none and its preflight said so.
		return spec, "", nil
	}
	if !relayProven(cred.Kind) {
		noteNotRelayed(workDir, ex, d.runID, cred.Kind, fmt.Sprintf("a %s has not been proven through the "+
			"model relay against the real API, so it reaches the sandbox as before the relay existed",
			relayKindLabel(cred.Kind)))
		return spec, "", nil
	}
	if lease == nil || lease.lease == nil {
		// A session stands on its run's lease — that is what ends it with the
		// run, revokes it with the grant and brings it back after a restart.
		// The hub's own key with nothing granted has no lease to stand on.
		return spec, "", &modelRelayUnavailableError{reason: "the run holds no secret lease for its relay session " +
			"to stand on; grant the project its Claude credential"}
	}
	route, err := svc.routeFor(ex)
	if err != nil {
		return spec, "", &modelRelayUnavailableError{reason: err.Error()}
	}
	if route.ca != nil && isDeviceExecutor(ex) {
		if v := agentProtocolOf(ex); !remote.SupportsNodeCA(v) {
			noteNotRelayed(workDir, ex, d.runID, cred.Kind, executor.ProtocolShortfall(
				deviceSubject(ex), v, remote.MinNodeCAVersion,
				"to have this run's harness trust the hub's model relay")+
				"; the run's Claude credential reaches the sandbox as before the relay existed")
			return spec, "", nil
		}
	}

	pol, err := svc.policyFor(workDir)
	if err != nil {
		return spec, "", &modelRelayUnavailableError{reason: err.Error()}
	}
	binding := modelRelayBinding{WorkDir: workDir, Provider: d.provider, Key: cred.Key, Hub: cred.Hub, Run: d.run}
	if d.run {
		binding.LedgerFrom = projectLedgerEnd(workDir)
	}
	run, _ := json.Marshal(binding)
	ttl := time.Until(lease.ExpiresAt())
	if ttl < claudeproxy.MinTTL {
		ttl = claudeproxy.MinTTL
	}
	up := svc.upstream(cred)
	payer := d.payer
	if payer == "" {
		payer = cost.IdentityLocal
	}
	m, err := svc.reg.Mint(claudeproxy.MintRequest{
		Policy:     pol,
		Project:    policyProjectPath(workDir),
		RunID:      d.runID,
		Actor:      payer,
		Subject:    payer,
		LeaseID:    lease.lease.ID,
		GrantID:    cred.GrantID,
		ExecutorID: ex.ID(),
		Payer:      payer,
		TTL:        ttl,
		Claims:     run,
		Upstream:   &up,
	})
	if err != nil {
		return spec, "", &modelRelayUnavailableError{reason: "a relay session could not be minted: " + err.Error()}
	}

	spec = withRelayEnv(spec, d.provider, route.base, m.Token, m.Session.ID)
	if route.ca != nil {
		ca := route.ca
		if spec.GitCA != nil {
			ca = spec.GitCA.Clone()
		}
		ca.Node = true
		spec.GitCA = ca
	}
	logModelRelay(workDir, fmt.Sprintf("Model calls go through the hub's relay (session %s): the %s stays on the "+
		"hub, and what the API reports spending is charged to the identity %q. Models: %s.", m.Session.ID,
		relayKindLabel(cred.Kind), payer, strings.Join(pol.Models, ", ")))
	return spec, m.Session.ID, nil
}

// relayCredentialIn finds the credential the lease delivered in spec's
// environment, in keys' order, with the grant it came from.
func relayCredentialIn(spec executor.Spec, keys []relayKey) (relayCredential, bool) {
	for _, k := range keys {
		v, ok := envValue(spec.Env, k.Key)
		if !ok || strings.TrimSpace(v) == "" {
			continue
		}
		grant := ""
		for _, b := range spec.Secrets {
			for _, key := range b.EnvKeys {
				if key == k.Key {
					grant = b.GrantID
				}
			}
		}
		if grant == "" {
			// Not from a grant — set by the image or the operator — so not
			// the lease's to withhold or the relay's to spend.
			continue
		}
		return relayCredential{Key: k.Key, Kind: k.Kind, GrantID: grant, value: strings.TrimSpace(v)}, true
	}
	return relayCredential{}, false
}

// hubCredentialFor is the hub's own anthropic.api_key, where an administrator
// allowed it for workDir's project or ex.
func (svc *modelRelayService) hubCredentialFor(workDir string, ex executor.Executor) (relayCredential, bool) {
	return svc.hubCredentialForIDs(workDir, ex.ID())
}

// hubCredentialForIDs is hubCredentialFor by the executor's id.
func (svc *modelRelayService) hubCredentialForIDs(workDir, executorID string) (relayCredential, bool) {
	cfg, err := controlPlaneConfig()
	if err != nil || cfg == nil {
		return relayCredential{}, false
	}
	mr, err := svc.settingsFrom(cfg)
	if err != nil {
		return relayCredential{}, false
	}
	key := strings.TrimSpace(cfg.Anthropic.APIKey)
	if key == "" || !mr.HubCredentialAllowed(policyProjectPath(workDir), executorID) {
		return relayCredential{}, false
	}
	return relayCredential{Key: "anthropic.api_key", Kind: relayKindAPIKey, Hub: true, value: key}, true
}

// settingsFrom is the relay section a dispatch is decided by: as cfg, the
// hub's configuration now, states it while it still turns the relay on, and
// as this process started with it otherwise. Switching the relay off takes
// effect at the next restart, and until then the section it leaves must not
// be read as the defaults it would fall back to — every Claude model among
// them. A section edited into one that does not load is an error: the relay
// refuses the run rather than guess.
func (svc *modelRelayService) settingsFrom(cfg *config.Config) (config.ModelRelayConfig, error) {
	if cfg == nil || !cfg.Executors.ModelRelay.Enabled {
		return svc.cfg, nil
	}
	if err := modelRelayBrokenError(cfg.Executors.ModelRelay); err != nil {
		return config.ModelRelayConfig{}, err
	}
	return cfg.Executors.ModelRelay, nil
}

// upstream is what a session relays with.
func (svc *modelRelayService) upstream(c relayCredential) claudeproxy.Upstream {
	up := claudeproxy.Upstream{BaseURL: strings.TrimSpace(svc.cfg.UpstreamBaseURL)}
	switch c.Kind {
	case relayKindOAuth:
		up.AuthToken, up.OAuth = c.value, true
	default:
		up.APIKey = c.value
	}
	return up
}

// policyFor is the model policy a session for workDir's runs gets: the hub's
// allowlist narrowed by the project's own (projectRelayModels), and the
// output clamp — both as the hub's configuration states them now.
func (svc *modelRelayService) policyFor(workDir string) (claudeproxy.Policy, error) {
	cfg, _ := controlPlaneConfig()
	mr, err := svc.settingsFrom(cfg)
	if err != nil {
		return claudeproxy.Policy{}, err
	}
	hub := mr.EffectiveModels()
	models := hub
	if own := projectRelayModels(workDir); len(own) > 0 {
		models = claudeproxy.IntersectModels(own, hub)
		if len(models) == 0 {
			return claudeproxy.Policy{}, fmt.Errorf("the project's model allowlist (%s) permits nothing the "+
				"hub's (%s) does", strings.Join(own, ", "), strings.Join(hub, ", "))
		}
	}
	return claudeproxy.Policy{Models: models, MaxOutputTokens: mr.MaxOutputTokens}, nil
}

// modelRelayRoute is where a sandbox reaches the relay, and the CA its
// harness must trust to verify it, if any.
type modelRelayRoute struct {
	base string
	ca   *executor.GitCA
}

// routeFor is the relay's URL as a sandbox on ex reaches it.
func (svc *modelRelayService) routeFor(ex executor.Executor) (modelRelayRoute, error) {
	switch svc.cfg.ListenerName() {
	case config.ModelRelayListenerDashboard:
		cfg, _ := controlPlaneConfig()
		ext := ""
		if cfg != nil {
			ext = strings.TrimSuffix(strings.TrimSpace(cfg.UI.ExternalURL), "/")
		}
		if !strings.HasPrefix(ext, "https://") {
			return modelRelayRoute{}, fmt.Errorf("listener dashboard serves the relay at ui.external_url, which "+
				"is %q — it must be an https URL sandboxes can reach and verify", ext)
		}
		return modelRelayRoute{base: ext + modelRelayMount}, nil
	default:
		gp := activeGitProxy()
		if gp == nil || gp.BaseURL() == "" {
			return modelRelayRoute{}, fmt.Errorf("listener git_proxy serves the relay beside the git proxy, " +
				"which is not running on this hub process — enable executors.git_proxy, or set " +
				"executors.model_relay.listener: dashboard")
		}
		r := modelRelayRoute{base: strings.TrimSuffix(gp.BaseURL(), "/") + modelRelayMount}
		// A certificate the hub issued itself (tls: auto) is verified with the
		// hub's CA, which the harness's Node is handed for the purpose; one the
		// operator configured is verified by the sandbox's own trust store.
		if ca := gp.SandboxGitCA(); ca != nil {
			r.ca = ca
		}
		return r, nil
	}
}

// withRelayEnv points spec's harness at the relay: every Claude credential
// the lease delivered is taken out of its environment and out of the lease's
// attribution, and the relay's URL and the session's token go in, declared
// sensitive so the output is scrubbed of the token and the stored spec never
// carries it.
func withRelayEnv(spec executor.Spec, provider, base, token, sessionID string) executor.Spec {
	withheld := map[string]bool{}
	for _, k := range relayWithheldKeys {
		withheld[k] = true
	}
	env := make([]string, 0, len(spec.Env)+4)
	var redactKeys []string
	for _, kv := range spec.Env {
		k, v, _ := strings.Cut(kv, "=")
		switch {
		case withheld[k] || k == modelRelayEnvKey:
			continue
		case k == redact.EnvKey:
			redactKeys = append(redactKeys, strings.Split(v, ",")...)
			continue
		}
		env = append(env, kv)
	}
	tokenKey, url := envAnthropicAuth, base
	if provider == anthropic.ProviderName {
		// cloop's own Anthropic provider appends /messages to its base, where
		// Claude Code and the SDKs append /v1/messages.
		tokenKey, url = envAnthropicAPIKey, base+"/v1"
	}
	env = append(env, envAnthropicBaseURL+"="+url, tokenKey+"="+token, modelRelayEnvKey+"="+sessionID)
	redactKeys = append(redactKeys, tokenKey)
	env = append(env, redact.EnvKey+"="+strings.Join(dedupeNonEmpty(redactKeys), ","))
	spec.Env = env

	// The attribution names what the lease delivered for a driver to take
	// back; what was withheld was never delivered.
	if len(spec.Secrets) > 0 {
		bindings := make([]executor.SecretBinding, len(spec.Secrets))
		for i, b := range spec.Secrets {
			keys := make([]string, 0, len(b.EnvKeys))
			for _, k := range b.EnvKeys {
				if !withheld[k] {
					keys = append(keys, k)
				}
			}
			b.EnvKeys = keys
			bindings[i] = b
		}
		spec.Secrets = bindings
	}
	return spec
}

// envValue returns the value exec would give key: its last assignment.
func envValue(env []string, key string) (string, bool) {
	val, found := "", false
	for _, kv := range env {
		if v, ok := strings.CutPrefix(kv, key+"="); ok {
			val, found = v, true
		}
	}
	return val, found
}

func dedupeNonEmpty(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// relayKindLabel names a credential kind for a person.
func relayKindLabel(kind string) string {
	switch kind {
	case relayKindOAuth:
		return "Claude OAuth token"
	case relayKindAPIKey:
		return "Anthropic API key"
	}
	return kind
}

// isDeviceExecutor reports whether ex runs on an enrolled device: a remote
// agent or a virtual executor through one.
func isDeviceExecutor(ex executor.Executor) bool {
	switch ex.Kind() {
	case executor.KindRemoteAgent, executor.KindVirtual:
		return true
	}
	return false
}

// deviceSubject names a device executor the way the protocol helper does.
func deviceSubject(ex executor.Executor) string {
	return fmt.Sprintf("agent %s", ex.ID())
}

// noteNotRelayed journals, and audits, a run the relay would serve whose
// credential is delivered as before.
func noteNotRelayed(workDir string, ex executor.Executor, runID, kind, why string) {
	logModelRelay(workDir, "Not relayed: "+why+".")
	db, err := statedb.Open(state.DBPath(controlPlaneDir()))
	if err != nil {
		return
	}
	defer func() { _ = db.Close() }()
	payload, _ := json.Marshal(map[string]string{
		"project": policyProjectPath(workDir), "run_id": runID, "executor_id": ex.ID(),
		"credential_kind": kind, "reason": why,
	})
	_ = db.AsControlPlane().AppendAuditEvent(&statedb.AuditEvent{
		Timestamp: time.Now().UTC(), Actor: "model-relay",
		EventType: string(auditaction.ActionModelRelayNotRelayed), EntityType: "project",
		EntityID: policyProjectPath(workDir), Payload: string(payload),
	})
}

// logModelRelay writes a model relay row to the project's history.
func logModelRelay(workDir, msg string) {
	state.LogEvent(workDir, state.EventRow{Type: state.EventModelRelay, Step: state.NoStep, Message: msg})
}

// projectLedgerEnd is the last row of workDir's cost ledger, 0 for none.
func projectLedgerEnd(workDir string) int64 {
	db, err := statedb.Open(state.DBPath(workDir))
	if err != nil {
		return 0
	}
	defer func() { _ = db.Close() }()
	n, _ := db.MaxCostRowID()
	return n
}

// hubRelaySatisfies reports whether the model relay will spend the hub's own
// anthropic.api_key for a run of workDir on ex that has no Claude credential
// granted: the relay is running, an administrator allowed the key for the
// project or the executor, the provider reads an API key, and API keys are a
// kind proven through the relay. The caller also needs the run to hold a
// lease, which a session stands on (applyModelRelay).
func hubRelaySatisfies(workDir string, ex executor.Executor, provider string) bool {
	svc := activeModelRelay()
	if svc == nil || ex == nil || !executor.IsolatesFromHost(ex) || !relayProven(relayKindAPIKey) {
		return false
	}
	reads := false
	for _, k := range relayKeysFor(provider) {
		if k.Kind == relayKindAPIKey {
			reads = true
		}
	}
	if !reads {
		return false
	}
	_, ok := svc.hubCredentialFor(workDir, ex)
	return ok
}
