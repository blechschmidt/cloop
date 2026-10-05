package ui

// The Claude credential a sandboxed harness needs, checked before dispatch
// (Task 20379).
//
// A claudecode project bound to an executor that isolates from the host — a
// container, a Pod, an enrolled device, a virtual executor — gets no Claude
// login from the hub: claudeEnvFor hands such executors no CLAUDE_CONFIG_DIR,
// and per-user logins (Task 20241) live in directories on the hub's own disk.
// The only way a credential reaches the sandbox is a secret grant of an `env`
// secret holding CLAUDE_CODE_OAUTH_TOKEN (or an API key), leased into the run.
//
// Nothing used to check for that grant before dispatch. The sandbox started —
// a device may first install claude, which takes a minute — and the first task
// failed auth_refused, in a transcript that said "Not logged in" and nothing
// about grants. Expired grants failed the same way: by 2026-10-03 every grant
// of :8888's test project had lapsed, and the symptom was indistinguishable
// from a broken device.
//
// So every dispatch settles a harnessClearance first. For a harness on an
// isolating executor it is a check: a run whose lease would carry no
// credential — or one whose lease would end within harnessExpiryMargin — is
// refused with a 409 that names the executor and the remedy, and no workload
// starts. tests/arch pins that every dispatch path builds one.
//
// What counts is decided the way the lease decides, because the point is to
// predict the lease: the same requester (executor, and the policy project — a
// feature's parent), the same grants, the same env-key narrowing, the same
// .cloop/sandbox.yaml env allowlist applied after it, and the same deadline —
// a lease ends with the first of its grants, whatever kind that grant is.
//
// One rule is added, and the lease is told about it so the two cannot
// disagree: on a hub with single sign-on a *personal* Claude credential counts
// only for runs its owner starts, and is withheld from every other dispatch's
// lease (Requester.Withhold) — on any executor, for any subcommand. That is
// Task 20241's per-user Claude account carried into the lease: without it,
// granting your own token to a shared project would quietly bill your
// subscription for every member's runs, and a project holding two people's
// tokens would run on whichever the lease happened to render last.

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/provider/anthropic"
	"github.com/blechschmidt/cloop/pkg/provider/claudecode"
	"github.com/blechschmidt/cloop/pkg/sandbox"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// The variables a sandboxed harness can authenticate with.
const (
	envClaudeOAuthToken = "CLAUDE_CODE_OAUTH_TOKEN"
	envAnthropicAPIKey  = "ANTHROPIC_API_KEY"
	envAnthropicAuth    = "ANTHROPIC_AUTH_TOKEN"
	envAnthropicBaseURL = "ANTHROPIC_BASE_URL"
	// Claude Code on a cloud platform: the flag selects it, and the cloud's
	// own credentials — AWS keys, a role, a service account — come with it.
	envClaudeUseBedrock = "CLAUDE_CODE_USE_BEDROCK"
	envClaudeUseVertex  = "CLAUDE_CODE_USE_VERTEX"
	// cloop's own spelling of the anthropic provider's key (cmd/run.go,
	// applyEnvOverrides).
	envCloopAnthropicKey = "CLOOP_ANTHROPIC_API_KEY"
)

// Refusal codes, carried on the 409 so a client can tell this refusal from the
// others a dispatch can meet and open the dialog that fixes it.
const (
	codeHarnessCredentialMissing  = "harness_credential_missing"
	codeHarnessCredentialExpiring = "harness_credential_expiring"
)

// harnessExpiryMargin is how long the credential must outlive the dispatch. A
// grant that ends inside it ends before a run could finish its first task: the
// lease is clamped to the grant, the device scrubs the token when it lapses, and
// the next turn reaches claude logged out — the failure this file exists to
// move in front of the run.
const harnessExpiryMargin = 10 * time.Minute

// harnessGrantDefaultTTL is how long a credential granted from the dialog lasts
// when the caller does not say. Long enough that a project does not lapse in
// the middle of a week's work; still bounded, by the same 90-day ceiling every
// grant the panel creates is (secretGrantTTLMaxMinutes).
const harnessGrantDefaultTTL = 30 * 24 * time.Hour

// harnessNow is the preflight's clock, replaced in tests that need a grant to
// have lapsed without waiting for it.
var harnessNow = time.Now

// harnessKeySets returns the alternative sets of variables, any one of which
// authenticates provider's harness inside a sandbox, in order of preference.
// Nil means the provider is not checked: it either needs no credential (mock)
// or brings its own the hub knows nothing about (openai, ollama).
func harnessKeySets(provider string) [][]string {
	switch provider {
	case claudecode.ProviderName:
		return [][]string{
			{envClaudeOAuthToken},
			{envAnthropicAPIKey},
			// A relay or gateway: a bearer token for a base URL that is not
			// Anthropic's. Neither half authenticates on its own.
			{envAnthropicAuth, envAnthropicBaseURL},
			// The cloud platforms. The flag is what the hub can see; the
			// credentials beside it may be in the same secret or be the
			// machine's role, and are the platform's to check.
			{envClaudeUseBedrock},
			{envClaudeUseVertex},
		}
	case anthropic.ProviderName:
		return [][]string{{envAnthropicAPIKey}, {envCloopAnthropicKey}}
	}
	return nil
}

// harnessGrantableSets are the alternatives the dialog grants by narrowing a
// secret to the keys named: every one but the cloud platforms, whose secret
// carries its platform credentials beside the flag and has to be granted
// whole — from the Secrets panel or the CLI, where that choice is explicit.
func harnessGrantableSets(provider string) [][]string {
	var out [][]string
	for _, set := range harnessKeySets(provider) {
		if set[0] != envClaudeUseBedrock && set[0] != envClaudeUseVertex {
			out = append(out, set)
		}
	}
	return out
}

// isHarnessKey reports whether k is one of the variables any provider's
// harness authenticates with. These are the keys a personal credential is
// withheld for.
func isHarnessKey(k string) bool {
	switch k {
	case envClaudeOAuthToken, envAnthropicAPIKey, envAnthropicAuth, envAnthropicBaseURL,
		envClaudeUseBedrock, envClaudeUseVertex, envCloopAnthropicKey:
		return true
	}
	return false
}

// describeKeySets renders alternatives for a sentence:
// "CLAUDE_CODE_OAUTH_TOKEN, ANTHROPIC_API_KEY, or ANTHROPIC_AUTH_TOKEN with ANTHROPIC_BASE_URL".
func describeKeySets(sets [][]string) string {
	parts := make([]string, 0, len(sets))
	for _, set := range sets {
		parts = append(parts, strings.Join(set, " with "))
	}
	switch len(parts) {
	case 0:
		return ""
	case 1:
		return parts[0]
	case 2:
		return parts[0] + " or " + parts[1]
	}
	return strings.Join(parts[:len(parts)-1], ", ") + ", or " + parts[len(parts)-1]
}

// leaseRequester is who a lease for workDir on ex is issued to. One function
// for the lease and for the preflight that predicts it, so they cannot come to
// match grants differently: a feature holds its parent project's grants
// (features.go), wherever in the project its work happens.
func leaseRequester(workDir string, ex executor.Executor, runID string, withhold map[string]string) secretbroker.Requester {
	executorID := ""
	if ex != nil {
		executorID = ex.ID()
	}
	return secretbroker.Requester{
		ExecutorID: executorID,
		ProjectID:  policyProjectPath(workDir),
		RunID:      runID,
		Withhold:   withhold,
	}
}

// sandboxProviderName is the provider the `cloop run` inside an isolating
// sandbox will choose (cmd/run.go, preferProjectChoice), judged from what
// reaches the sandbox rather than from the hub's own view of the project.
//
// The hub's CLOOP_PROVIDER never counts: a sandbox gets none of the hub's
// environment. The project's config.yaml counts only where the executor works
// on the hub's own tree — the container driver's bind mount — because a device
// or a Pod is sent the project's state and never its config. Then the provider
// the state records; then the default.
func sandboxProviderName(workDir string, ex executor.Executor) string {
	if ex != nil && ex.Capabilities().SharesHostFilesystem {
		if doc, ok := readProjectConfigFile(workDir); ok {
			if p := strings.TrimSpace(doc.Provider); p != "" {
				return p
			}
			// An explicit config without a provider is Default()'s.
			return claudecode.ProviderName
		}
	}
	if st, err := state.LoadLite(workDir); err == nil && st != nil {
		if p := strings.TrimSpace(st.Provider); p != "" {
			return p
		}
	}
	return claudecode.ProviderName
}

// projectConfigFile is the part of a project's config.yaml the preflight
// reads, as written — without the environment overlay config.Load applies,
// which is the hub's environment and reaches no sandbox.
type projectConfigFile struct {
	Provider  string `yaml:"provider"`
	Anthropic struct {
		APIKey string `yaml:"api_key"`
	} `yaml:"anthropic"`
}

// readProjectConfigFile parses workDir's .cloop/config.yaml, reporting whether
// there is one to read.
func readProjectConfigFile(workDir string) (projectConfigFile, bool) {
	var doc projectConfigFile
	data, err := os.ReadFile(config.ConfigPath(workDir))
	if err != nil {
		return doc, false
	}
	if yaml.Unmarshal(data, &doc) != nil {
		return projectConfigFile{}, true
	}
	return doc, true
}

// harnessExempt reports whether the hub's own configuration names executorID
// as supplying its harness credential itself (executors.harness_credential_exempt).
// Never a project's config.yaml, which whoever can push to the project writes.
func harnessExempt(executorID string) bool {
	cfg, err := controlPlaneConfig()
	if err != nil || cfg == nil {
		return false
	}
	return slices.Contains(cfg.Executors.HarnessCredentialExempt, executorID)
}

// harnessWho is whom a dispatch acts for, as far as personal credentials care.
type harnessWho struct {
	// identity is the OwnerKey a personal secret's owner is compared with,
	// normalised the same way; "" when the dispatch acts for nobody (the
	// static bearer token, a service token minted on nobody's behalf).
	identity string
	// personal says personal credentials follow identity, which is true on a
	// hub with single sign-on. Without it there is one person and every grant
	// is theirs, so the rule has nothing to say.
	personal bool
}

// harnessWhoFor resolves whom r's dispatch acts for while the request is still
// in hand — a run outlives its handler, and r must not.
func (s *Server) harnessWhoFor(r *http.Request) harnessWho {
	return harnessWho{
		identity: secretbroker.NormalizeOwner(s.recipientIdentity(r).OwnerKey()),
		personal: s.oidcEnabled(),
	}
}

// harnessWhoForNobody is a dispatch acting for no one: an automatic one the
// hub makes of its own accord. Every personal credential is withheld from it.
func (s *Server) harnessWhoForNobody() harnessWho {
	return harnessWho{personal: s.oidcEnabled()}
}

// harnessWhoForResume is whom an automatic resume of workDir's run acts for:
// whoever started the run being resumed, as the control plane recorded at its
// dispatch (recordHarnessInitiator), so a run that authenticated with its
// starter's personal credential resumes on it rather than being refused on
// every sweep, and a member's run resumes as that member rather than as the
// project's owner. With no record — a run older than the record — the project's
// owner, who is also who the resume bills.
func (s *Server) harnessWhoForResume(workDir string) harnessWho {
	who := harnessWho{personal: s.oidcEnabled()}
	if !who.personal {
		return who
	}
	if id, ok := recordedHarnessInitiator(workDir); ok {
		who.identity = id
		return who
	}
	for _, e := range s.allProjectEntries() {
		if e.Path == workDir {
			who.identity = secretbroker.NormalizeOwner(e.Owner)
			break
		}
	}
	return who
}

// harnessInitiatorKey is the control-plane metadata key holding whom workDir's
// last run was started for. In the hub's database, never the project's: the
// project's tree is the sandbox's to write, and a run that could rewrite whom
// its resume acts for could pick whose personal credential it gets.
func harnessInitiatorKey(workDir string) string { return "harness.initiator:" + workDir }

// recordHarnessInitiator remembers whom a run of workDir was started for.
// Best effort: a resume that finds no record acts for the project's owner.
func recordHarnessInitiator(workDir, identity string) {
	dir := controlPlaneDir()
	if dir == "" || workDir == "" {
		return
	}
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		return
	}
	defer db.Close()
	if err := db.SetHubMeta(harnessInitiatorKey(workDir), identity); err != nil {
		fmt.Fprintf(os.Stderr, "ui: record whom the run of %s acts for: %v\n", workDir, err)
	}
}

// recordedHarnessInitiator reads what recordHarnessInitiator wrote.
func recordedHarnessInitiator(workDir string) (string, bool) {
	dir := controlPlaneDir()
	if dir == "" || workDir == "" {
		return "", false
	}
	db, err := statedb.Open(state.DBPath(dir))
	if err != nil {
		return "", false
	}
	defer db.Close()
	value, ok, err := db.HubMeta(harnessInitiatorKey(workDir))
	if err != nil {
		return "", false
	}
	return value, ok
}

// counts reports whether a grant over a secret owned by owner may stand in for
// the harness credential of a run acting for w.
func (w harnessWho) counts(owner string) bool {
	if !w.personal || strings.TrimSpace(owner) == "" {
		return true
	}
	return w.identity != "" && secretbroker.NormalizeOwner(owner) == w.identity
}

// harnessGrantRef is one grant the preflight relied on or reports about.
type harnessGrantRef struct {
	GrantID    string
	SecretID   string
	SecretName string
	Owner      string
	ExpiresAt  time.Time // zero: never
	Keys       []string  // the harness keys it supplies
	// Foreign marks another person's personal grant, which is named to no one
	// but its owner.
	Foreign bool
}

// harnessReport is what the preflight found for one project on one executor.
type harnessReport struct {
	WorkDir      string
	Provider     string
	ExecutorID   string
	ExecutorKind string
	Isolates     bool
	// Exempt says the hub's configuration lists the executor as supplying its
	// own credential (executors.harness_credential_exempt).
	Exempt bool
	// Applies is true when anything was checked: the executor isolates, the
	// provider needs a credential, the dispatch runs a harness, and the
	// executor is not exempt. When false the dispatch is not refused — though
	// other people's personal credentials are still withheld from it.
	Applies bool
	Needed  [][]string
	// State is "not_needed", "ok", "expiring" or "missing".
	State string
	// Satisfied is the grant set the run will authenticate with: one grant,
	// or two when a relay's token and base URL come from different grants.
	Satisfied []harnessGrantRef
	// ExpiresAt is when the run would lose the credential: the earliest
	// expiry in Satisfied, or the lease's own end if that comes first. Zero
	// means never.
	ExpiresAt time.Time
	// EndedBy is the grant whose expiry ends the run's lease, when that comes
	// before the credential's own: a lease ends with the first of its grants.
	EndedBy *harnessGrantRef
	// FromConfig says the anthropic provider's key is in the project's own
	// config.yaml, on an executor that works on the hub's tree and so reads it.
	FromConfig bool
	// Lapsed are grants that would have counted had they not expired.
	Lapsed []harnessGrantRef
	// Foreign counts other people's personal credentials that would have
	// counted for their owner. Never reported to the caller: whether a
	// colleague granted one is not theirs to learn.
	Foreign int
	// Withhold is what the lease must not deliver: those same credentials,
	// keyed by grant ID, with the reason the denial row records.
	Withhold map[string]string
	// Filtered are harness keys a grant supplies that the project's
	// .cloop/sandbox.yaml env allowlist does not forward.
	Filtered []string
	// Unreadable names secrets granted for this whose payload would not
	// open, by name — the same name a lease's denial row would carry.
	Unreadable []string
	// BrokerProblem is why no grant could be read at all.
	BrokerProblem string
	// BrokerUnset says the reason is the one an operator fixes by setting
	// CLOOP_SECRET_KEY.
	BrokerUnset bool
	// NoControlPlane says the process is not a hub — the CLI's `cloop task
	// reproduce` — and so leases nothing at all.
	NoControlPlane bool
}

// harnessPreflight decides, before anything is dispatched, what the lease a
// dispatch to ex would get must withhold, and — for a harness (check) on an
// executor that isolates — whether that lease carries a credential the harness
// can authenticate with. It is the one shared helper every dispatch path
// reaches through harnessClearance.settle; the GET endpoint renders the same
// report.
//
// provider overrides the project's own provider when non-empty — a
// reproduction runs under the provider its provenance recorded.
func harnessPreflight(workDir string, ex executor.Executor, who harnessWho, provider string, check bool) harnessReport {
	rep := harnessReport{WorkDir: workDir, Provider: provider, State: "not_needed"}
	if ex == nil {
		if rep.Provider == "" {
			rep.Provider = resolveProviderName(workDir)
		}
		return rep
	}
	rep.ExecutorID, rep.ExecutorKind = ex.ID(), string(ex.Kind())
	rep.Isolates = executor.IsolatesFromHost(ex)
	if rep.Provider == "" {
		if rep.Isolates {
			rep.Provider = sandboxProviderName(workDir, ex)
		} else {
			rep.Provider = resolveProviderName(workDir)
		}
	}
	rep.Needed = harnessKeySets(rep.Provider)
	rep.Exempt = rep.Isolates && len(rep.Needed) > 0 && harnessExempt(ex.ID())
	// A host-sharing executor runs the harness on the hub, under the hub's or
	// the user's own login (claudeEnvFor), and is never refused here.
	rep.Applies = check && rep.Isolates && len(rep.Needed) > 0 && !rep.Exempt
	if !rep.Applies && !who.personal {
		return rep // nothing to check, and nobody's credential to withhold
	}

	// The anthropic provider also reads anthropic.api_key from the project's
	// config.yaml, which a sandbox on the hub's own tree reads too.
	if rep.Applies && rep.Provider == anthropic.ProviderName && ex.Capabilities().SharesHostFilesystem {
		if doc, ok := readProjectConfigFile(workDir); ok && strings.TrimSpace(doc.Anthropic.APIKey) != "" {
			rep.State, rep.FromConfig = "ok", true
		}
	}

	dir := controlPlaneDir()
	if dir == "" {
		// The CLI's `cloop task reproduce`, or a Server never bootstrapped:
		// acquireSecretLease leases nothing without a control plane either, so
		// there is nothing to withhold.
		if rep.Applies && !rep.FromConfig {
			rep.State, rep.BrokerProblem = "missing", "this process holds no control plane, so it has no grants to lease"
			rep.NoControlPlane = true
		}
		return rep
	}
	broker, closeBroker, err := openUIBroker(dir)
	if err != nil {
		// A broker this process cannot open is one acquireSecretLease cannot
		// open either: the lease will carry nothing, anyone's or not.
		if rep.Applies && !rep.FromConfig {
			rep.State = "missing"
			switch {
			case errors.Is(err, secretbroker.ErrNoKey):
				rep.BrokerUnset = true
				rep.BrokerProblem = "this hub's secret broker is not configured (CLOOP_SECRET_KEY is not set), " +
					"so nothing can be granted to a sandbox"
			case isBrokerUnconfigured(err):
				rep.BrokerProblem = "the control plane has no state database yet, so it holds no grants"
			default:
				rep.BrokerProblem = "the hub could not open its secret broker: " + err.Error()
			}
		}
		return rep
	}
	defer closeBroker()
	offers, err := broker.EnvOffers(leaseRequester(workDir, ex, "", nil))
	if err != nil {
		if rep.Applies && !rep.FromConfig {
			rep.State, rep.BrokerProblem = "missing", "the hub could not read the grants: "+err.Error()
		}
		// Withholding cannot be computed, and the lease would read the same
		// store: it fails too, or delivers what a moment ago could not be read.
		// Neither leaks a colleague's credential any further than refusing here
		// would prevent, so a non-checked dispatch proceeds.
		return rep
	}
	now := harnessNow()
	rep.withholdForeign(offers, who, now)
	if !rep.Applies || rep.FromConfig {
		return rep
	}
	rep.judge(offers, who, sandboxEnvAllowlist(workDir), now)
	if rep.State != "ok" {
		return rep
	}
	first, ok, err := broker.LeaseHorizon(leaseRequester(workDir, ex, "", rep.Withhold))
	if err == nil && ok {
		rep.applyHorizon(first, who, now, func(id string) string {
			if sec, derr := broker.DescribeSecret(id); derr == nil {
				return sec.Name
			}
			return id
		})
	}
	return rep
}

// sandboxEnvAllowlist returns the project's .cloop/sandbox.yaml env allowlist,
// or nil when it forwards every leased variable — no file, no env list, or a
// file the dispatch will refuse for its own reasons in applySandbox.
func sandboxEnvAllowlist(workDir string) map[string]bool {
	resolved, err := sandbox.Resolve(workDir)
	if err != nil || resolved == nil || !resolved.Present() || len(resolved.Spec.Env) == 0 {
		return nil
	}
	allow := make(map[string]bool, len(resolved.Spec.Env))
	for _, name := range resolved.Spec.Env {
		allow[name] = true
	}
	return allow
}

// harnessKeysOf keeps the harness keys of an offer.
func harnessKeysOf(o secretbroker.EnvOffer) []string {
	var out []string
	for _, k := range o.Keys {
		if isHarnessKey(k) {
			out = append(out, k)
		}
	}
	return out
}

// withholdForeign decides which grants the lease must not deliver: every
// active personal grant carrying a harness key whose owner the dispatch does
// not act for. Withheld whether or not the dispatch runs a harness — a test
// suite or a pull request has no business holding a colleague's Claude token
// either — and recorded on every lease that meets one.
func (rep *harnessReport) withholdForeign(offers []secretbroker.EnvOffer, who harnessWho, now time.Time) {
	for _, o := range offers {
		if who.counts(o.Grant.Owner) || !o.Grant.Active(now) || len(harnessKeysOf(o)) == 0 {
			continue
		}
		if rep.Withhold == nil {
			rep.Withhold = map[string]string{}
		}
		rep.Withhold[o.Grant.ID] = fmt.Sprintf(
			"personal Claude credential of %s, which is spent only on runs its owner starts", o.Grant.Owner)
		rep.Foreign++
	}
}

// judge is the decision, separated from the I/O so it can be read whole.
func (rep *harnessReport) judge(offers []secretbroker.EnvOffer, who harnessWho, allow map[string]bool, now time.Time) {
	type usable struct {
		ref    harnessGrantRef
		keys   map[string]bool
		expiry time.Time // zero: never
	}
	var pool []usable
	filtered := map[string]bool{}
	for _, o := range offers {
		harness := harnessKeysOf(o)
		if len(harness) == 0 && o.Err == nil {
			continue // a grant about something else entirely
		}
		if !who.counts(o.Grant.Owner) {
			continue // another person's credential; withheld above
		}
		ref := harnessGrantRef{
			GrantID: o.Grant.ID, SecretID: o.Grant.SecretID, SecretName: o.Secret.Name,
			Owner: o.Grant.Owner, ExpiresAt: o.Grant.ExpiresAt, Keys: harness,
		}
		if o.Err != nil {
			rep.Unreadable = append(rep.Unreadable, o.Secret.Name)
			continue
		}
		if !o.Grant.Active(now) {
			rep.Lapsed = append(rep.Lapsed, ref)
			continue
		}
		keys := map[string]bool{}
		for _, k := range harness {
			if allow != nil && !allow[k] {
				filtered[k] = true
				continue
			}
			keys[k] = true
		}
		if len(keys) == 0 {
			continue
		}
		pool = append(pool, usable{ref: ref, keys: keys, expiry: o.Grant.ExpiresAt})
	}
	for k := range filtered {
		rep.Filtered = append(rep.Filtered, k)
	}
	sort.Strings(rep.Filtered)
	sort.Strings(rep.Unreadable)

	// For each alternative, the longest-lived grant for each of its keys; the
	// alternative lasts as long as its shortest-lived part. The best
	// alternative is the one that lasts longest — any one of them is enough.
	found := false
	var best []harnessGrantRef
	var bestExpiry time.Time
	for _, set := range rep.Needed {
		var refs []harnessGrantRef
		var setExpiry time.Time
		complete := true
		for i, k := range set {
			pick := -1
			for j, u := range pool {
				if u.keys[k] && (pick < 0 || outlasts(u.expiry, pool[pick].expiry)) {
					pick = j
				}
			}
			if pick < 0 {
				complete = false
				break
			}
			if i == 0 || outlasts(setExpiry, pool[pick].expiry) {
				setExpiry = pool[pick].expiry
			}
			if !containsGrant(refs, pool[pick].ref.GrantID) {
				refs = append(refs, pool[pick].ref)
			}
		}
		if complete && (!found || outlasts(setExpiry, bestExpiry)) {
			found, best, bestExpiry = true, refs, setExpiry
		}
	}
	if !found {
		rep.State = "missing"
		return
	}
	rep.Satisfied, rep.ExpiresAt = best, bestExpiry
	rep.State = "ok"
	if !bestExpiry.IsZero() && bestExpiry.Before(now.Add(harnessExpiryMargin)) {
		rep.State = "expiring"
	}
}

// applyHorizon brings the credential's end forward to the lease's, when a grant
// beside it expires first: the lease is issued only until its earliest grant
// ends and cannot be extended past it, so a five-minute GitHub grant takes a
// thirty-day Claude credential out of the sandbox with it.
func (rep *harnessReport) applyHorizon(first secretbroker.Grant, who harnessWho, now time.Time, name func(string) string) {
	if first.ExpiresAt.IsZero() || (!rep.ExpiresAt.IsZero() && !first.ExpiresAt.Before(rep.ExpiresAt)) {
		return
	}
	rep.ExpiresAt = first.ExpiresAt
	if !containsGrant(rep.Satisfied, first.ID) {
		ref := harnessGrantRef{GrantID: first.ID, SecretID: first.SecretID, Owner: first.Owner, ExpiresAt: first.ExpiresAt}
		if who.counts(first.Owner) {
			ref.SecretName = name(first.SecretID)
		} else {
			ref.Foreign = true
		}
		rep.EndedBy = &ref
	}
	if first.ExpiresAt.Before(now.Add(harnessExpiryMargin)) {
		rep.State = "expiring"
	}
}

// outlasts reports whether expiry a ends after b, zero being never.
func outlasts(a, b time.Time) bool {
	switch {
	case a.IsZero():
		return !b.IsZero()
	case b.IsZero():
		return false
	}
	return a.After(b)
}

func containsGrant(refs []harnessGrantRef, id string) bool {
	for _, r := range refs {
		if r.GrantID == id {
			return true
		}
	}
	return false
}

// harnessCredentialError is the refusal a dispatch meets when its sandbox would
// get no credential. jsonWorkloadErr renders it as a 409 carrying Code.
type harnessCredentialError struct {
	Code         string
	ExecutorID   string
	ExecutorKind string
	Project      string
	Provider     string
	Needed       [][]string
	ExpiresAt    time.Time
	message      string
	remedy       string
}

func (e *harnessCredentialError) Error() string { return e.message }

// Remediation is the "what to do about it" half, rendered apart from the cause.
func (e *harnessCredentialError) Remediation() string { return e.remedy }

// refusal returns the error the dispatch must stop on, or nil.
func (rep harnessReport) refusal() error {
	if !rep.Applies || rep.State == "ok" {
		return nil
	}
	e := &harnessCredentialError{
		Code:         codeHarnessCredentialMissing,
		ExecutorID:   rep.ExecutorID,
		ExecutorKind: rep.ExecutorKind,
		Project:      filepath.Base(rep.WorkDir),
		Provider:     rep.Provider,
		Needed:       rep.Needed,
	}
	if rep.State == "expiring" {
		e.Code, e.ExpiresAt = codeHarnessCredentialExpiring, rep.ExpiresAt
	}
	e.message, e.remedy = rep.explain()
	return e
}

// explain renders the report as a cause and a remedy, for the 409 and for the
// dialog. Other people's credentials are never named.
func (rep harnessReport) explain() (cause, remedy string) {
	project := filepath.Base(rep.WorkDir)
	where := fmt.Sprintf("executor %s (%s)", rep.ExecutorID, rep.ExecutorKind)
	needs := describeKeySets(rep.Needed)
	grantStep := "Open the project's Overview and use Claude credential to grant an env secret holding " +
		describeKeySets(harnessGrantableSets(rep.Provider)) + ", or paste a token from `claude setup-token` " +
		"there. From a shell on the hub: cloop secret grant <secret> --to project:" +
		policyProjectPath(rep.WorkDir) + " --env-keys " + rep.Needed[0][0] + "."
	switch {
	case rep.State == "expiring" && rep.EndedBy != nil:
		ended := "a grant of another user's personal secret"
		if !rep.EndedBy.Foreign {
			ended = rep.EndedBy.SecretName
		}
		cause = fmt.Sprintf("%s's sandbox on %s would lose its Claude credential at %s, in under %d minutes: "+
			"a lease ends with the first of the project's grants to expire, and that is %s (grant %s).",
			project, where, rep.ExpiresAt.UTC().Format(time.RFC3339), int(harnessExpiryMargin/time.Minute),
			ended, rep.EndedBy.GrantID)
		remedy = "Grant " + rep.EndedBy.GrantID + " again for longer, or revoke it, before starting the run."
		return cause, remedy
	case rep.State == "expiring":
		s := rep.Satisfied[0]
		cause = fmt.Sprintf("The only Claude credential granted to %s for %s (%s, grant %s) expires at %s — "+
			"in under %d minutes, before a run could finish its first task.",
			project, where, s.SecretName, s.GrantID,
			rep.ExpiresAt.UTC().Format(time.RFC3339), int(harnessExpiryMargin/time.Minute))
		remedy = "Grant it again for longer, or grant another credential, before starting the run. " + grantStep
		return cause, remedy
	case rep.BrokerProblem != "":
		cause = fmt.Sprintf("%s runs %s's harness in a sandbox, which gets a Claude login only through a "+
			"secret grant — and %s.", where, project, rep.BrokerProblem)
		remedy = "Fix the secret broker, then grant the project an env secret holding " + needs + "."
		switch {
		case rep.NoControlPlane:
			remedy = "Start it from the hub's dashboard or API instead, which lease the project's grants; " +
				"this command runs outside the hub and has none to give the sandbox."
		case rep.BrokerUnset:
			remedy = "Configure the broker by setting CLOOP_SECRET_KEY in the hub's environment, then grant " +
				"the project an env secret holding " + needs + "."
		}
		return cause, remedy
	}
	var b strings.Builder
	fmt.Fprintf(&b, "No active grant gives %s's sandbox on %s a Claude credential (%s): a sandbox has no "+
		"Claude login but what is granted to its project.", project, where, needs)
	for _, l := range rep.Lapsed {
		fmt.Fprintf(&b, " The grant of %s (%s) expired at %s.", l.SecretName, l.GrantID,
			l.ExpiresAt.UTC().Format(time.RFC3339))
	}
	if len(rep.Unreadable) > 0 {
		fmt.Fprintf(&b, " %s would not open with this hub's key, so a lease would deny it too.",
			strings.Join(rep.Unreadable, ", "))
	}
	cause = b.String()
	remedy = grantStep + " An executor that supplies its own credential can be listed in the hub's " +
		"executors.harness_credential_exempt."
	if len(rep.Filtered) > 0 {
		cause += fmt.Sprintf(" %s is granted but not forwarded: the project's %s lists the variables a "+
			"sandbox receives, and it does not name it.", strings.Join(rep.Filtered, ", "), sandbox.FileName)
		remedy = "Add " + strings.Join(rep.Filtered, ", ") + " to the env list in .cloop/" + sandbox.FileName +
			", or grant a credential it already names."
	}
	return cause, remedy
}

// harnessClearance carries a dispatch's preflight from the handler that knows
// who asked to the primitive that resolves the executor, and from there to the
// lease. Every dispatch carries one — tests/arch refuses a nil — built by the
// handler: harnessClearanceFor / newHarnessClearance for a workload that runs a
// harness, which it also checks; leaseClearanceFor / newLeaseClearance for one
// that runs none, which only withholds.
type harnessClearance struct {
	workDir  string
	who      harnessWho
	provider string
	// check says the workload runs a harness, so a sandbox that would get no
	// credential is refused rather than only kept from other people's.
	check bool

	mu     sync.Mutex
	report *harnessReport
}

// newHarnessClearance prepares the preflight for a harness dispatched to
// workDir acting for who. provider is "" for the project's own.
func newHarnessClearance(workDir string, who harnessWho, provider string) *harnessClearance {
	return &harnessClearance{workDir: workDir, who: who, provider: provider, check: true}
}

// newLeaseClearance prepares the preflight for a workload that runs no
// harness — a git operation, a test suite: nothing is checked, and other
// people's personal Claude credentials are withheld from its lease all the same.
func newLeaseClearance(workDir string, who harnessWho) *harnessClearance {
	return &harnessClearance{workDir: workDir, who: who}
}

// harnessClearanceFor is newHarnessClearance for a request's dispatch.
func (s *Server) harnessClearanceFor(r *http.Request, workDir string) *harnessClearance {
	return newHarnessClearance(workDir, s.harnessWhoFor(r), "")
}

// leaseClearanceFor is newLeaseClearance for a request's dispatch.
func (s *Server) leaseClearanceFor(r *http.Request, workDir string) *harnessClearance {
	return newLeaseClearance(workDir, s.harnessWhoFor(r))
}

// settle runs the preflight for a dispatch of workDir to ex — once per
// executor, so a handler that checked early and the primitive that dispatches
// share one answer unless the binding moved in between — and returns the
// grants the lease must withhold, or the refusal the dispatch must stop on.
//
// workDir is the dispatch's own, and a clearance built for another project is
// refused: its identity and its answer were about a different lease.
func (c *harnessClearance) settle(ex executor.Executor, workDir string) (map[string]string, error) {
	if c == nil || ex == nil {
		return nil, nil
	}
	if workDir != c.workDir {
		return nil, fmt.Errorf("ui: a harness clearance built for %q was settled for %q", c.workDir, workDir)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.report == nil || c.report.ExecutorID != ex.ID() {
		rep := harnessPreflight(c.workDir, ex, c.who, c.provider, c.check)
		c.report = &rep
	}
	return c.report.Withhold, c.report.refusal()
}

// started records, once a run is under way, whom it was started for — what an
// automatic resume of it acts for (harnessWhoForResume). Only a harness run on
// a hub with single sign-on has an answer worth keeping.
func (c *harnessClearance) started() {
	if c == nil || !c.check || !c.who.personal {
		return
	}
	recordHarnessInitiator(c.workDir, c.who.identity)
}

// refuseWithoutHarnessCredential answers a 409 before anything is claimed,
// reserved or started when the executor c's project resolves to would get no
// credential, and reports whether it did.
//
// Early on purpose: the dispatch primitive settles the same clearance and is
// the guarantee, but by then a run has taken a cluster claim and a quota slot,
// and a suggest job has already been announced. A project that cannot resolve
// an executor, or whose feature cannot run on it, is left for the dispatch to
// refuse — those are the more fundamental answers, and they name their own fix.
func (s *Server) refuseWithoutHarnessCredential(w http.ResponseWriter, c *harnessClearance) bool {
	registerBuiltinExecutors()
	ex, err := executor.Resolve(c.workDir)
	if err != nil || ex == nil || checkFeatureExecutor(c.workDir, ex) != nil {
		return false
	}
	if _, err := c.settle(ex, c.workDir); err != nil {
		jsonWorkloadErr(w, err)
		return true
	}
	return false
}

// writeHarnessRefusal renders a harnessCredentialError: a 409 with the code,
// the executor, what the provider needs, and the remedy.
func writeHarnessRefusal(w http.ResponseWriter, e *harnessCredentialError) {
	body := map[string]any{
		"error":         e.Error(),
		"code":          e.Code,
		"remediation":   e.Remediation(),
		"executor_id":   e.ExecutorID,
		"executor_kind": e.ExecutorKind,
		"provider":      e.Provider,
		"needed":        e.Needed,
	}
	if !e.ExpiresAt.IsZero() {
		body["expires_at"] = e.ExpiresAt.UTC().Format(time.RFC3339)
	}
	writeJSONStatus(w, http.StatusConflict, body)
}

// asHarnessRefusal unwraps a harnessCredentialError from err.
func asHarnessRefusal(err error) (*harnessCredentialError, bool) {
	var e *harnessCredentialError
	if errors.As(err, &e) {
		return e, true
	}
	return nil, false
}
