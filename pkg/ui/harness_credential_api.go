package ui

// The Claude credential panel's backend (Task 20379).
//
//	GET  /api/projects/{idx}/harness-credential   what the project's sandbox would
//	                                              authenticate with, and what could fill
//	                                              the gap
//	POST /api/projects/{idx}/harness-credential   grant a candidate, or store a pasted
//	                                              token as a personal secret and grant it
//
// It is a narrow front end to the broker calls POST /api/secrets and POST
// /api/grants make, for the same reason the repositories panel is: the general
// grant dialog asks for a subject, a kind and a constraint set, and getting a
// Claude login into a sandbox should not take three forms and a JSON-encoded
// string. Here the subject is the project in the path (its parent, for a
// feature, since a feature runs on its project's grants), the kind is env, and
// the constraint is the one key the harness reads.
//
// Non-disclosure is the same invariant secrets_api.go keeps: no response here
// carries a value. Candidates are listed by name with the *names* of the keys
// they hold; a pasted token goes into the broker's Mint, which seals it and
// zeroes the buffer, and from nowhere else — it is not logged, not echoed in an
// error, and not written outside the secret store.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/apierror"
	"github.com/blechschmidt/cloop/pkg/authz"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/redact"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
)

// harnessGrantScope labels the grants this panel creates, so the Secrets panel
// and an operator listing grants can tell them apart. It carries no authority.
const harnessGrantScope = "claude-credential"

// maxPastedTokenBytes bounds a pasted token before it is scanned. Claude Code's
// OAuth tokens and Anthropic's API keys are around a hundred bytes; anything
// past this is not one of them.
const maxPastedTokenBytes = 1024

// harnessExecutorView names the executor the answer is about.
type harnessExecutorView struct {
	ID       string `json:"id"`
	Kind     string `json:"kind"`
	Isolates bool   `json:"isolates"`
}

// harnessGrantView is one grant the project's sandbox would authenticate with.
type harnessGrantView struct {
	GrantID    string `json:"grant_id"`
	SecretID   string `json:"secret_id"`
	SecretName string `json:"secret_name"`
	Owner      string `json:"owner,omitempty"`
	// ExpiresAt is null for a grant that never expires.
	ExpiresAt *time.Time `json:"expires_at"`
	Keys      []string   `json:"keys"`
}

// harnessCandidateView is a secret the caller could grant to fill the gap.
type harnessCandidateView struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Owner    string `json:"owner,omitempty"`
	Personal bool   `json:"personal"`
	Mine     bool   `json:"mine"`
	// Keys are the harness keys the secret holds, by name.
	Keys []string `json:"keys"`
	// Complete says the secret alone satisfies the provider: it holds every
	// key of at least one alternative.
	Complete bool `json:"complete"`
	// Granted says an active grant of it already reaches this project.
	Granted bool `json:"granted"`
}

// harnessCredentialView is the GET response, and the POST's after it granted.
type harnessCredentialView struct {
	Project string `json:"project"`
	// GrantTarget is the project a grant made here goes to: this one, or the
	// parent a feature runs on.
	GrantTarget string               `json:"grant_target"`
	Applies     bool                 `json:"applies"`
	State       string               `json:"state"`
	Provider    string               `json:"provider"`
	Executor    *harnessExecutorView `json:"executor"`
	Needed      [][]string           `json:"needed"`
	// Grantable are the alternatives the dialog grants by narrowing a secret
	// to their keys — every one but the cloud platforms, whose secret goes
	// whole.
	Grantable   [][]string        `json:"grantable"`
	SatisfiedBy *harnessGrantView `json:"satisfied_by"`
	// Also lists a second grant a relay's credential is split across.
	Also []harnessGrantView `json:"also,omitempty"`
	// ExpiresAt is when the sandbox would lose its credential; null when it
	// has none, or one that never expires.
	ExpiresAt *time.Time `json:"expires_at"`
	Reason    string     `json:"reason,omitempty"`
	Remedy    string     `json:"remedy,omitempty"`
	// Candidates are never other people's personal secrets, and shared ones
	// only for a caller who may grant shared secrets on this project.
	Candidates []harnessCandidateView `json:"candidates"`
	// CanPaste says the caller may store a token from the dialog.
	CanPaste bool `json:"can_paste"`
	// Personal says personal credentials follow the person who starts a run
	// (single sign-on is on), so a pasted token is stored as the caller's own.
	Personal          bool `json:"personal"`
	DefaultTTLMinutes int  `json:"default_ttl_minutes"`
	MaxTTLMinutes     int  `json:"max_ttl_minutes"`
	// BrokerUnavailable is why nothing can be granted on this hub at all.
	BrokerUnavailable string `json:"broker_unavailable,omitempty"`
	// Granted is set on a POST's response: what was just created.
	Granted *harnessGrantedView `json:"granted,omitempty"`
}

// harnessGrantedView describes a grant the POST created.
type harnessGrantedView struct {
	GrantID    string    `json:"grant_id"`
	SecretID   string    `json:"secret_id"`
	SecretName string    `json:"secret_name"`
	EnvKeys    []string  `json:"env_keys"`
	ExpiresAt  time.Time `json:"expires_at"`
	// Minted says the secret was created from a pasted token.
	Minted bool `json:"minted"`
	// Personal says the secret belongs to the caller alone.
	Personal bool `json:"personal"`
	// Superseded lists the shorter grants this panel made earlier that the new
	// one replaced, and which were revoked.
	Superseded []string `json:"superseded,omitempty"`
}

// handleProjectHarnessCredential serves GET /api/projects/{idx}/harness-credential.
func (s *Server) handleProjectHarnessCredential(w http.ResponseWriter, r *http.Request) {
	entry, ok := s.projectEntryFromPath(w, r)
	if !ok {
		return
	}
	jsonOK(w, s.harnessCredentialView(r, entry))
}

// harnessCredentialView renders the preflight's report for the caller, with the
// candidates they could grant.
func (s *Server) harnessCredentialView(r *http.Request, entry projectEntry) harnessCredentialView {
	registerBuiltinExecutors()
	ex, _ := executor.ResolveBinding(entry.Path)
	// The card exists only where something is checked. Elsewhere the report is
	// computed for nobody in particular, which skips the withholding pass and
	// with it a broker opened on every Overview of a host project.
	who := harnessWho{}
	if ex != nil && executor.IsolatesFromHost(ex) {
		who = s.harnessWhoFor(r)
	}
	rep := harnessPreflight(entry.Path, ex, who, "", true)

	target := policyProjectPath(entry.Path)
	view := harnessCredentialView{
		Project:           entry.Name,
		GrantTarget:       filepath.Base(target),
		Applies:           rep.Applies,
		State:             rep.State,
		Provider:          rep.Provider,
		Needed:            rep.Needed,
		Candidates:        []harnessCandidateView{},
		DefaultTTLMinutes: int(harnessGrantDefaultTTL / time.Minute),
		MaxTTLMinutes:     secretGrantTTLMaxMinutes,
	}
	if view.Needed == nil {
		view.Needed = [][]string{}
	}
	view.Grantable = harnessGrantableSets(rep.Provider)
	if view.Grantable == nil {
		view.Grantable = [][]string{}
	}
	if ex != nil {
		view.Executor = &harnessExecutorView{ID: rep.ExecutorID, Kind: rep.ExecutorKind, Isolates: rep.Isolates}
	}
	for i, ref := range rep.Satisfied {
		gv := grantRefView(ref)
		if i == 0 {
			view.SatisfiedBy = &gv
		} else {
			view.Also = append(view.Also, gv)
		}
	}
	if !rep.ExpiresAt.IsZero() {
		t := rep.ExpiresAt.UTC()
		view.ExpiresAt = &t
	}
	if rep.Applies && rep.State != "ok" {
		view.Reason, view.Remedy = rep.explain()
	}
	// Nothing to offer where nothing is checked — a host executor, a provider
	// that reads no Claude credential. The card is hidden there and the dialog
	// never opens, and listing candidates would open every env secret the
	// caller can see, on every Overview visit, for no one to read.
	if !rep.Applies {
		return view
	}

	bs, err := s.openBrokers()
	if err != nil {
		view.BrokerUnavailable = err.Error()
		return view
	}
	defer bs.close()
	if bs.secret == nil {
		view.BrokerUnavailable = bs.status.Reason
		return view
	}
	viewer := s.secretViewer(r)
	view.Personal = viewer.Identity != ""
	// Offered only to someone the POST would admit: secret.own on this
	// project is its floor, and a viewer shown a form they may not submit
	// meets a refusal at the last step.
	if scope, ok := s.projectScopeFromIdx(r); !ok || !s.permissionsFor(r, scope).Allows(authz.PermSecretOwn) {
		return view
	}
	canShared := s.canGrantSharedHere(r)
	view.CanPaste = viewer.Identity != "" || canShared
	view.Candidates = s.harnessCandidates(bs.secret, viewer, canShared, rep, target)
	return view
}

func grantRefView(ref harnessGrantRef) harnessGrantView {
	gv := harnessGrantView{
		GrantID: ref.GrantID, SecretID: ref.SecretID, SecretName: ref.SecretName,
		Owner: ref.Owner, Keys: append([]string{}, ref.Keys...),
	}
	if !ref.ExpiresAt.IsZero() {
		t := ref.ExpiresAt.UTC()
		gv.ExpiresAt = &t
	}
	return gv
}

// canGrantSharedHere reports whether the caller may hand out the organisation's
// shared secrets on the project in the path — the same question, at the same
// scope, the repositories panel asks (githubapp_api.go).
func (s *Server) canGrantSharedHere(r *http.Request) bool {
	scope, ok := s.projectScopeFromIdx(r)
	return ok && s.permissionsFor(r, scope).Allows(authz.PermSecretGrant)
}

// harnessCandidates lists the env secrets the caller could grant to satisfy
// rep: their own personal ones, and shared ones when they may grant those here.
// Spendability, not visibility, is the test — an admin may see a colleague's
// personal secret and may never grant it, and offering it would guarantee a
// refusal.
func (s *Server) harnessCandidates(b *secretbroker.Broker, viewer secretbroker.Viewer, canShared bool, rep harnessReport, target string) []harnessCandidateView {
	out := []harnessCandidateView{}
	secrets, err := b.ListSecretsFor(viewer)
	if err != nil {
		return out
	}
	granted := map[string]bool{}
	if grants, gerr := b.ListGrants(secretbroker.GrantFilter{ActiveOnly: true}); gerr == nil {
		for _, g := range grants {
			if g.Subject.Matches(secretbroker.Requester{ProjectID: target}) {
				granted[g.SecretID] = true
			}
		}
	}
	for _, sec := range secrets {
		if sec.Kind != secretbroker.KindEnv || !sec.SpendableBy(viewer) || (!sec.Personal() && !canShared) {
			continue
		}
		held, kerr := b.EnvKeyNamesFor(sec.ID, viewer)
		if kerr != nil {
			continue
		}
		heldSet := map[string]bool{}
		for _, k := range held {
			heldSet[k] = true
		}
		c := harnessCandidateView{
			ID: sec.ID, Name: sec.Name, Owner: sec.Owner, Personal: sec.Personal(),
			Mine: sec.OwnedBy(viewer.Identity), Granted: granted[sec.ID], Keys: []string{},
		}
		seen := map[string]bool{}
		for _, set := range harnessGrantableSets(rep.Provider) {
			all := true
			for _, k := range set {
				if heldSet[k] {
					if !seen[k] {
						seen[k] = true
						c.Keys = append(c.Keys, k)
					}
				} else {
					all = false
				}
			}
			c.Complete = c.Complete || all
		}
		if len(c.Keys) > 0 {
			out = append(out, c)
		}
	}
	// Complete ones first, then the caller's own, then by name: the dialog's
	// first option should be the one that works.
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Complete != out[j].Complete {
			return out[i].Complete
		}
		if out[i].Mine != out[j].Mine {
			return out[i].Mine
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// harnessGrantRequest is the POST body: a secret to grant, or a token to store.
type harnessGrantRequest struct {
	// Secret is an env secret's ID or name.
	Secret string `json:"secret,omitempty"`
	// EnvKeys narrows which of the secret's keys the grant delivers. Absent
	// means the first alternative the secret satisfies on its own.
	EnvKeys []string `json:"env_keys,omitempty"`
	// Token is a pasted Claude Code OAuth token or Anthropic API key.
	Token string `json:"token,omitempty"`
	// Name names the secret a pasted token is stored as; generated if absent.
	Name string `json:"name,omitempty"`
	// TTLMinutes is the grant's lifetime; 0 means harnessGrantDefaultTTL.
	TTLMinutes int `json:"ttl_minutes,omitempty"`
}

// handleProjectHarnessCredentialGrant serves POST /api/projects/{idx}/harness-credential.
//
// Authority is the existing model, applied at this project's scope: the route
// admits secret.own; a shared secret additionally needs secret.grant here, as
// it does everywhere; a personal one may be granted by its owner alone, which
// Broker.Grant enforces through the viewer. Both broker calls audit themselves
// (secret.mint, secret.grant), on the same chain every other grant lands on.
func (s *Server) handleProjectHarnessCredentialGrant(w http.ResponseWriter, r *http.Request) {
	entry, ok := s.projectEntryFromPath(w, r)
	if !ok {
		return
	}
	var req harnessGrantRequest
	if !decodeSecretsBody(w, r, &req) {
		return
	}
	hasSecret, hasToken := strings.TrimSpace(req.Secret) != "", req.Token != ""
	if hasSecret == hasToken {
		apierror.WriteError(w, apierror.New(apierror.CodeInvalidInput,
			"choose one secret to grant, or paste one token — exactly one of the two"))
		return
	}
	// The provider the sandbox will run, judged as the preflight judges it:
	// what reaches the sandbox, not the hub's own view of the project.
	registerBuiltinExecutors()
	provider := resolveProviderName(entry.Path)
	if ex, _ := executor.ResolveBinding(entry.Path); ex != nil && executor.IsolatesFromHost(ex) {
		provider = sandboxProviderName(entry.Path, ex)
	}
	needed := harnessGrantableSets(provider)
	if len(needed) == 0 {
		apierror.WriteError(w, apierror.New(apierror.CodeConflict, fmt.Sprintf(
			"this project uses the %s provider, which reads no Claude credential", provider)))
		return
	}
	ttl := harnessGrantDefaultTTL
	if req.TTLMinutes != 0 {
		var err error
		if ttl, err = grantTTL(req.TTLMinutes); err != nil {
			apierror.WriteError(w, apierror.New(apierror.CodeInvalidInput, err.Error()))
			return
		}
	}

	bs, ok := s.openBrokersOr(w)
	if !ok {
		return
	}
	defer bs.close()
	if !bs.requireSecretBroker(w) {
		return
	}
	viewer := s.secretViewer(r)
	canShared := s.canGrantSharedHere(r)
	actor := s.auditActor(r)
	// A feature runs on its project's grants, so that is where this goes: a
	// grant to the feature's own path would match no lease ever issued.
	target := policyProjectPath(entry.Path)
	// Detached from the request from here on: a client that disconnects
	// between storing a pasted token and granting it must not leave the token
	// stored and ungranted, which is what a cancelled context would do to the
	// grant and to the rollback alike.
	ctx := context.WithoutCancel(r.Context())

	var (
		sec     secretbroker.Secret
		envKeys []string
		minted  bool
	)
	if hasToken {
		key, err := classifyPastedToken(req.Token)
		if err != nil {
			apierror.WriteError(w, apierror.New(apierror.CodeInvalidInput, err.Error()))
			return
		}
		if !keySetsMention(needed, key) {
			apierror.WriteError(w, apierror.New(apierror.CodeInvalidInput, fmt.Sprintf(
				"that is a %s, and this project's %s provider needs %s", tokenNoun(key), provider,
				describeKeySets(needed))))
			return
		}
		// Personal whenever there is someone to own it. On a hub without single
		// sign-on there is no one to be personal *from*, every secret is
		// shared, and storing one takes the shared-secret permission.
		personal := viewer.Identity != ""
		if !personal && !canShared {
			denySharedSecret(w, authz.PermSecretGrant, "storing a credential for the whole hub")
			return
		}
		name := strings.TrimSpace(req.Name)
		if name == "" {
			if name, err = pastedSecretName(key, target); err != nil {
				apierror.WriteError(w, apierror.New(apierror.CodeInternal, err.Error()))
				return
			}
		}
		if err := secretbroker.ValidateName(name); err != nil {
			apierror.WriteError(w, apierror.New(apierror.CodeInvalidInput, err.Error()))
			return
		}
		owner := ""
		if personal {
			owner = viewer.Identity
		}
		payload, err := json.Marshal(map[string]string{key: strings.TrimSpace(req.Token)})
		if err != nil {
			apierror.WriteError(w, apierror.New(apierror.CodeInternal, "encode the credential"))
			return
		}
		// Mint seals the payload and zeroes the slice; the request's decoded
		// string is not zeroable in Go, which is why nothing here logs it.
		sec, err = bs.secret.Mint(ctx, secretbroker.MintRequest{
			Name:     name,
			Kind:     secretbroker.KindEnv,
			Payload:  payload,
			Metadata: map[string]string{"purpose": "Claude credential", "project": filepath.Base(target)},
			Actor:    actor,
			Owner:    owner,
			Personal: personal,
		})
		if err != nil {
			writeBrokerError(w, err, "store the token")
			return
		}
		minted, envKeys = true, []string{key}
		s.broadcastAuditAppend(string(secretbroker.ActionMint))
	} else {
		var err error
		if sec, err = bs.secret.DescribeSecretFor(strings.TrimSpace(req.Secret), viewer); err != nil {
			writeBrokerError(w, err, "find the secret")
			return
		}
		if sec.Kind != secretbroker.KindEnv {
			apierror.WriteError(w, apierror.New(apierror.CodeInvalidInput, fmt.Sprintf(
				"%s is a %s secret; a Claude credential is an env secret", sec.Name, sec.Kind)))
			return
		}
		if !sec.Personal() && !canShared {
			denySharedSecret(w, authz.PermSecretGrant, "granting it")
			return
		}
		held, err := bs.secret.EnvKeyNamesFor(sec.ID, viewer)
		if err != nil {
			writeBrokerError(w, err, "read the secret's keys")
			return
		}
		if envKeys, err = chooseHarnessKeys(needed, held, cleanList(req.EnvKeys), sec.Name); err != nil {
			apierror.WriteError(w, apierror.New(apierror.CodeInvalidInput, err.Error()))
			return
		}
	}

	grant, err := bs.secret.Grant(ctx, secretbroker.GrantRequest{
		Viewer:      viewer,
		SecretRef:   sec.ID,
		Subject:     secretbroker.Subject{Type: secretbroker.SubjectProject, Value: target},
		Scope:       harnessGrantScope,
		TTL:         ttl,
		Actor:       actor,
		Constraints: secretbroker.Constraints{EnvKeys: envKeys},
	})
	if err != nil {
		// A token stored for a grant that never happened is a credential no
		// one asked to keep. Taken back out, through the owner's own delete.
		if minted {
			if derr := bs.secret.DeleteSecretFor(ctx, sec.ID, viewer); derr != nil {
				s.log().Warn("secret_rollback", 0, "harness credential: could not remove the secret minted for a refused grant",
					map[string]interface{}{"secret": sec.Name, "error": derr.Error()})
			}
		}
		writeBrokerError(w, err, "grant the credential")
		return
	}
	s.broadcastAuditAppend(string(secretbroker.ActionGrant))
	s.broadcastSecretsUpdate("grant_created", grant.ID)
	superseded := s.supersedeHarnessGrants(ctx, r, bs, target, grant, actor)

	view := s.harnessCredentialView(r, entry)
	view.Granted = &harnessGrantedView{
		GrantID: grant.ID, SecretID: sec.ID, SecretName: sec.Name, EnvKeys: envKeys,
		ExpiresAt: grant.ExpiresAt, Minted: minted, Personal: sec.Personal(), Superseded: superseded,
	}
	jsonOK(w, view)
}

// supersedeHarnessGrants revokes the grants this panel made to target earlier
// that the new one replaces: over a secret of the same owner (or shared, like
// it), ending before it. Without this, granting a credential again "for longer"
// would change nothing a run could feel — a lease ends with the first of its
// grants, so the old grant's end would still be the sandbox's.
//
// Only grants carrying this panel's scope are touched: one made from the
// Secrets panel or the CLI is somebody's deliberate choice, which the card
// names when it shortens a lease rather than overrides. A shared grant takes
// secret.revoke on the project to withdraw, as anywhere else; one the caller
// may not revoke is left, and the card says what it does to the lease. Each
// revocation is audited by the broker.
func (s *Server) supersedeHarnessGrants(ctx context.Context, r *http.Request, bs *brokerSet, target string, grant secretbroker.Grant, actor string) []string {
	grants, err := bs.secret.ListGrants(secretbroker.GrantFilter{ActiveOnly: true})
	if err != nil {
		return nil
	}
	scope, scopeOK := s.projectScopeFromIdx(r)
	canRevokeShared := scopeOK && s.permissionsFor(r, scope).Allows(authz.PermSecretRevoke)
	var out []string
	for _, g := range grants {
		if g.ID == grant.ID || g.Scope != harnessGrantScope || !grantIssuedToProject(g, target) {
			continue
		}
		if secretbroker.NormalizeOwner(g.Owner) != secretbroker.NormalizeOwner(grant.Owner) {
			continue
		}
		if g.ExpiresAt.IsZero() || (!grant.ExpiresAt.IsZero() && !g.ExpiresAt.Before(grant.ExpiresAt)) {
			continue
		}
		if !g.Personal() && !canRevokeShared {
			continue
		}
		if err := bs.secret.Revoke(ctx, g.ID, actor); err != nil {
			s.log().Warn("secret_supersede", 0, "harness credential: could not revoke a grant the new one replaces",
				map[string]interface{}{"grant": g.ID, "error": err.Error()})
			continue
		}
		s.broadcastAuditAppend(string(secretbroker.ActionRevoke))
		s.broadcastSecretsUpdate("grant_revoked", g.ID)
		out = append(out, g.ID)
	}
	return out
}

// keySetsMention reports whether key appears in any alternative.
func keySetsMention(sets [][]string, key string) bool {
	for _, set := range sets {
		for _, k := range set {
			if k == key {
				return true
			}
		}
	}
	return false
}

// chooseHarnessKeys picks which of a secret's keys a grant delivers: the keys
// asked for, when they complete an alternative and the secret holds them all;
// otherwise the first alternative the secret completes on its own. Nothing
// else — the grant is limited to what the harness reads.
func chooseHarnessKeys(needed [][]string, held, requested []string, name string) ([]string, error) {
	have := map[string]bool{}
	for _, k := range held {
		have[k] = true
	}
	if len(requested) > 0 {
		want := map[string]bool{}
		for _, k := range requested {
			if !keySetsMention(needed, k) {
				return nil, fmt.Errorf("%s is not a variable this project's harness reads (it reads %s)",
					k, describeKeySets(needed))
			}
			if !have[k] {
				return nil, fmt.Errorf("%s holds no %s", name, k)
			}
			want[k] = true
		}
		for _, set := range needed {
			complete := true
			for _, k := range set {
				complete = complete && want[k]
			}
			if complete {
				out := make([]string, 0, len(want))
				for k := range want {
					out = append(out, k)
				}
				sort.Strings(out)
				return out, nil
			}
		}
		return nil, fmt.Errorf("%s on its own does not authenticate the harness: it needs %s",
			strings.Join(requested, " and "), describeKeySets(needed))
	}
	for _, set := range needed {
		complete := true
		for _, k := range set {
			complete = complete && have[k]
		}
		if complete {
			return append([]string{}, set...), nil
		}
	}
	return nil, fmt.Errorf("%s holds none of the variables this project's harness can authenticate with (%s)",
		name, describeKeySets(needed))
}

// Errors a paste is refused with. None of them repeats the paste.
var (
	errTokenEmpty     = errors.New("paste a token: a Claude Code OAuth token from `claude setup-token`, or an Anthropic API key")
	errTokenShape     = errors.New("that does not look like a Claude Code OAuth token (sk-ant-oat01-…, from `claude setup-token`) or an Anthropic API key (sk-ant-api03-…); paste the token alone, on one line")
	errTokenIsRefresh = errors.New("that is a refresh token (sk-ant-ort01-…), which the harness cannot sign in with; run `claude setup-token` and paste the sk-ant-oat01-… token it prints")
)

// classifyPastedToken decides which variable a pasted token is, by its shape,
// with the credential registry every scanner in cloop shares (pkg/redact): the
// paste must be exactly one recognised Anthropic credential, from its first
// byte to its last.
func classifyPastedToken(token string) (string, error) {
	t := strings.TrimSpace(token)
	if t == "" {
		return "", errTokenEmpty
	}
	if len(t) > maxPastedTokenBytes || strings.ContainsAny(t, " \t\r\n") {
		return "", errTokenShape
	}
	for _, m := range redact.Find(t) {
		if m.Start != 0 || m.End != len(t) {
			continue
		}
		switch m.Detector {
		case "anthropic-oauth-token":
			if strings.HasPrefix(m.Kind, "sk-ant-oat") {
				return envClaudeOAuthToken, nil
			}
			return "", errTokenIsRefresh
		case "anthropic-api-key":
			return envAnthropicAPIKey, nil
		}
	}
	return "", errTokenShape
}

// tokenNoun names what kind of credential key holds, for a sentence.
func tokenNoun(key string) string {
	if key == envClaudeOAuthToken {
		return "Claude Code OAuth token"
	}
	return "Anthropic API key"
}

// pastedSecretName names the secret a pasted token is stored as: what it is,
// which project it was pasted for, and a random suffix so a second paste — a
// rotation — does not collide with the first.
func pastedSecretName(key, target string) (string, error) {
	stem := "claude-oauth"
	if key == envAnthropicAPIKey {
		stem = "anthropic-api-key"
	}
	var b strings.Builder
	for _, r := range filepath.Base(target) {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
		if b.Len() >= 48 {
			break
		}
	}
	buf := make([]byte, 3)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("name the secret: %w", err)
	}
	project := strings.Trim(b.String(), "-.")
	if project == "" {
		return stem + "-" + hex.EncodeToString(buf), nil
	}
	return stem + "-" + project + "-" + hex.EncodeToString(buf), nil
}
