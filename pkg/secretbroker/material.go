package secretbroker

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

// mints accumulates the GitHub App installation tokens one Lease call minted,
// so the broker can bind them to the lease ID it has not generated yet — and
// destroy them at the source if the lease never comes into existence.
//
// A value threaded through the call rather than a broker field because a Broker
// serves concurrent requesters: two leases minting at once must not be able to
// adopt each other's credentials.
type mints struct {
	tokens []appToken
}

func (m *mints) add(t appToken) {
	if m == nil {
		return
	}
	m.tokens = append(m.tokens, t)
}

// materialFor opens a secret's payload and reduces it to what the grant's
// constraints permit.
//
// Every branch either returns a narrowed credential or an error. There is no
// path that falls through to "deliver the payload as stored" — the closest
// thing, KindEnv with no key filter, is narrow already because an env
// secret's keys are its whole scope.
//
// KindGitHubApp is the one branch that does not narrow a payload at all: it
// mints a new credential from it, so rec collects what was minted and ctx is
// the lease request's own deadline.
func (b *Broker) materialFor(ctx context.Context, s Secret, g Grant, req Requester, actor string, rec *mints) (Material, error) {
	plaintext, err := b.seal.OpenEnvelope(AADFor(SetSecrets, s.ID), s.Envelope())
	if err != nil {
		// Both sentinels are chained. Callers that only know about
		// ErrSealFailed keep matching, while an operator-facing path can ask
		// specifically whether the key was *retired* — which is the
		// difference between "re-mint this credential" and "fix your
		// passphrase". The keyring's message names no credential material,
		// only key IDs, so it is safe to carry through verbatim.
		return Material{}, fmt.Errorf("%w: open payload for %s: %w", ErrSealFailed, s.Name, err)
	}
	// The plaintext is copied into the returned Material's fields; wipe the
	// buffer once we are done building from it.
	defer zero(plaintext)

	mat := Material{
		GrantID:     g.ID,
		SecretID:    s.ID,
		SecretName:  s.Name,
		Kind:        s.Kind,
		Constraints: g.Constraints,
		Env:         map[string]string{},
		// Who this delivery is for. Only a GitGuard reads these today, to
		// label the proxy session it mints; they are carried on the Material
		// rather than passed down every deliver* function because every one of
		// them would have to grow the parameter to reach the one that uses it.
		projectID:  req.ProjectID,
		executorID: req.ExecutorID,
		actor:      actor,
		owner:      s.Owner,
	}

	switch s.Kind {
	case KindEnv:
		return b.envMaterial(mat, plaintext)
	case KindGitHubPAT:
		return b.githubMaterial(ctx, mat, plaintext)
	case KindGitHubApp:
		return b.githubAppMaterial(ctx, mat, plaintext, rec)
	case KindKubeconfig:
		return b.kubeMaterial(ctx, mat, plaintext)
	case KindRegistry:
		return b.registryMaterial(mat, plaintext)
	case KindEgressProxy:
		return b.egressMaterial(mat, plaintext)
	case KindLocalRepo:
		return b.localRepoMaterial(mat, plaintext)
	case KindHostDevice:
		return b.hostDeviceMaterial(mat, plaintext)
	default:
		return Material{}, wrapf(ErrInvalidKind, "no delivery rule for kind %q", s.Kind)
	}
}

// envMaterial delivers the allowed subset of an env secret's keys.
func (b *Broker) envMaterial(mat Material, plaintext []byte) (Material, error) {
	all := jsonUnmarshalEnv(plaintext, mat.SecretName)
	var delivered []string
	for k, v := range all {
		if !mat.Constraints.AllowsEnvKey(k) {
			continue
		}
		if err := validateEnvKey(k); err != nil {
			// A key that cannot be encoded as K=V would corrupt the whole
			// environment block, so drop it rather than the run.
			continue
		}
		mat.Env[k] = v
		delivered = append(delivered, k)
		// Every key of an env secret is the secret; there is no constraint
		// echo in this material to tell apart from one.
		mat.SensitiveEnv = append(mat.SensitiveEnv, k)
	}
	if len(delivered) == 0 {
		return Material{}, wrapf(ErrMinimizedEmpty,
			"env secret %s has no key matching %s", mat.SecretName, joinOrAny(mat.Constraints.EnvKeys))
	}
	sort.Strings(delivered)
	mat.Summary = "env keys: " + strings.Join(delivered, ",")
	return mat, nil
}

// githubMaterial delivers a GitHub credential behind a repo-scoped git
// credential helper.
//
// A bare GITHUB_TOKEN is exported only for a "*" allowlist, because an
// environment variable is unscoped by construction: every tool in the
// workload reads it and can point it at any repository. For a narrower grant
// the helper is the only delivery path, which makes "may only touch org/*"
// something *git* will not exceed.
//
// Note the limit of that, because it used to be stated too strongly here: the
// helper runs inside the sandbox and reads a token file inside the sandbox, so
// a workload that bypasses git is not bound by it. The allowlist is enforced
// against git, not against the workload.
//
// When a GitGuard is configured it takes custody of the token first, and what
// reaches the sandbox is a proxy session instead. That path is strictly
// stronger — the allowlist stops being advisory — so it is tried before the
// helper, and a guard that fails takes the lease with it rather than falling
// back to handing over the broad credential. See gitguard.go.
func (b *Broker) githubMaterial(ctx context.Context, mat Material, plaintext []byte) (Material, error) {
	token := strings.TrimSpace(string(plaintext))
	if token == "" {
		return Material{}, wrapf(ErrMalformedPayload, "github secret %s is empty", mat.SecretName)
	}
	// Recorded before either delivery branch, because the hub needs it whether
	// or not the sandbox gets it.
	mat.githubToken = token

	if b != nil && b.GitGuard != nil {
		if len(mat.Constraints.Repos) == 0 {
			return Material{}, wrapf(ErrRepoDenied,
				"github grant %s carries no repository allowlist", mat.GrantID)
		}
		res, err := b.GitGuard.GuardGitHub(ctx, GitGuardRequest{
			Token:       token,
			Repos:       mat.Constraints.Repos,
			Permissions: mat.Constraints.Permissions,
			SecretName:  mat.SecretName,
			SecretID:    mat.SecretID,
			GrantID:     mat.GrantID,
			ProjectID:   mat.projectID,
			ExecutorID:  mat.executorID,
			Actor:       mat.actor,
			Owner:       mat.owner,
		})
		if err != nil {
			return Material{}, fmt.Errorf("%w: guard github secret %s: %w",
				ErrGuardUnavailable, mat.SecretName, err)
		}
		if res.Guarded() {
			mat, err = deliverGuardedGitHub(mat, res)
			if err != nil {
				return Material{}, err
			}
			// The guard's own summary when it wrote one: it knows the ref
			// policy it applied, which this package cannot see and which is
			// half of what "narrowed" means for a guarded grant.
			mode := "read-write"
			if res.ReadOnly {
				mode = "read-only"
			}
			mat.Summary = fmt.Sprintf("github repos: %s (proxy-guarded, %s)",
				strings.Join(mat.Constraints.Repos, "|"), mode)
			if s := strings.TrimSpace(res.Summary); s != "" {
				mat.Summary = "github " + s
			}
			return mat, nil
		}
		// Declined, not failed: the hub has no proxy running and said so.
	}

	mat, err := deliverGitHubToken(mat, token)
	if err != nil {
		return Material{}, err
	}
	mat.Summary = fmt.Sprintf("github repos: %s (helper-scoped=%t)",
		strings.Join(mat.Constraints.Repos, "|"), !allowsAllRepos(mat.Constraints.Repos))
	return mat, nil
}

// githubAppMaterial mints a short-lived installation token from the stored App
// credential and delivers *that*.
//
// The private key stays in this process. It is read out of the sealed payload,
// used to sign a JWT that lives for minutes, and dropped; what reaches the
// executor is a token GitHub itself scoped to the grant's repositories and
// permissions, and which GitHub will stop honouring in about an hour.
//
// That inversion is the whole reason the kind exists. Handing over the key —
// which is what this branch did before Task 20254, by falling through to the
// PAT path — gave a sandbox a credential that never expires and that can mint
// tokens for every repository in the installation, which is strictly worse than
// the PAT the kind was introduced to improve on. There is deliberately no
// fallback to that behaviour: a mint that fails denies the grant.
//
// When a GitGuard is configured it then takes custody of the minted token and
// what reaches the sandbox is a proxy session, exactly as for a PAT. Before
// Task 20306 this branch went straight to deliverGitHubToken and wrote the
// installation token into a file inside the sandbox — so on a proxy-guarded hub
// the App kind, the *narrower* of the two GitHub credentials, was the one that
// still handed a usable GitHub token to the workload. An installation token is
// short-lived and repository-scoped, which bounds that, but "bounded" is not the
// property the hub claims: a guarded grant is one whose credential the workload
// never holds.
func (b *Broker) githubAppMaterial(ctx context.Context, mat Material, plaintext []byte, rec *mints) (Material, error) {
	cred, err := ParseGitHubApp(plaintext)
	if err != nil {
		return Material{}, err
	}
	if len(mat.Constraints.Repos) == 0 {
		return Material{}, wrapf(ErrRepoDenied,
			"github_app grant %s carries no repository allowlist", mat.GrantID)
	}

	res, err := b.appMinter.mint(ctx, cred, mat.Constraints)
	if err != nil {
		return Material{}, err
	}

	// Recorded before either delivery branch and before either can fail, for
	// two reasons: the hub's own workspace provisioning reads it through
	// Material.GitHubToken() whether or not the sandbox gets a copy, and rec
	// below is what makes the token revocable. A return that skipped rec would
	// leave a live credential at GitHub that this hub no longer knows it owns.
	mat.githubToken = res.token.Token
	rec.add(appToken{
		grantID:    mat.GrantID,
		secretID:   mat.SecretID,
		secretName: mat.SecretName,
		baseURL:    cred.BaseURL,
		token:      res.token.Token,
		expiresAt:  res.token.ExpiresAt,
	})

	if b != nil && b.GitGuard != nil {
		guarded, gerr := b.GitGuard.GuardGitHub(ctx, GitGuardRequest{
			Token:       res.token.Token,
			Repos:       mat.Constraints.Repos,
			Permissions: mat.Constraints.Permissions,
			SecretName:  mat.SecretName,
			SecretID:    mat.SecretID,
			GrantID:     mat.GrantID,
			ProjectID:   mat.projectID,
			ExecutorID:  mat.executorID,
			Actor:       mat.actor,
			Owner:       mat.owner,
		})
		if gerr != nil {
			// A guard that was asked for and is broken denies the grant rather
			// than falling back to handing the token over.
			//
			// The token exists at GitHub and will now never reach a workload,
			// so destroy it here rather than let it live out its hour. It stays
			// in rec as well, which is the backstop: LeaseFor only `continue`s
			// past a failed material, so rec is what guarantees the token is
			// destroyed even if this call does not land. Revoking twice is
			// harmless — GitHub answers the second with 401/404, which
			// RevokeInstallationToken treats as the end state it wanted.
			b.appMinter.revoke(ctx, cred.BaseURL, res.token.Token)
			return Material{}, fmt.Errorf("%w: guard github app secret %s: %w",
				ErrGuardUnavailable, mat.SecretName, gerr)
		}
		if guarded.Guarded() {
			mat, err = deliverGuardedGitHub(mat, guarded)
			if err != nil {
				b.appMinter.revoke(ctx, cred.BaseURL, res.token.Token)
				return Material{}, err
			}
			mode := "read-write"
			if guarded.ReadOnly {
				mode = "read-only"
			}
			// Both halves are worth stating: which installation and repositories
			// GitHub scoped the token to, and the fact that the sandbox holds a
			// proxy session rather than that token.
			mat.Summary = fmt.Sprintf(
				"github app installation %d token for %s (proxy-guarded, %s), expires %s",
				cred.InstallationID, res.summary, mode,
				res.token.ExpiresAt.UTC().Format(time.RFC3339))
			return mat, nil
		}
		// Declined, not failed: this hub runs no proxy. Fall through.
	}

	mat, err = deliverGitHubToken(mat, res.token.Token)
	if err != nil {
		b.appMinter.revoke(ctx, cred.BaseURL, res.token.Token)
		return Material{}, err
	}

	// The workload is told when its credential dies so a long task can decide
	// to re-read the file after a renewal rather than discovering the expiry as
	// an authentication failure. A timestamp is not a credential.
	mat.Env["CLOOP_GITHUB_TOKEN_EXPIRES_AT"] = res.token.ExpiresAt.UTC().Format(time.RFC3339)

	mat.Summary = fmt.Sprintf("github app installation %d token for %s, expires %s",
		cred.InstallationID, res.summary, res.token.ExpiresAt.UTC().Format(time.RFC3339))
	return mat, nil
}

// deliverGitHubToken lays a GitHub token out for an executor: the token file,
// the repo-scoped credential helper, and the gitconfig that installs it.
//
// Both GitHub kinds share it on purpose. The App token is already narrowed by
// GitHub, so the helper is not what bounds it — but the helper is also what
// keeps the token out of the environment of every process in the sandbox, and
// that property is worth having whether or not the credential behind it is
// scoped. A workload that reads the file directly is still constrained by
// whatever GitHub will honour, which for an App token is the grant.
func deliverGitHubToken(mat Material, token string) (Material, error) {
	if strings.TrimSpace(token) == "" {
		return Material{}, wrapf(ErrMalformedPayload, "github secret %s yielded an empty token", mat.SecretName)
	}
	if len(mat.Constraints.Repos) == 0 {
		return Material{}, wrapf(ErrRepoDenied,
			"github grant %s carries no repository allowlist", mat.GrantID)
	}

	helper, err := buildGitCredentialHelper(mat.Constraints.Repos)
	if err != nil {
		return Material{}, err
	}

	mat.Files = []File{
		{Name: tokenFileName, Content: []byte(token + "\n"), Mode: 0o600},
		{Name: credentialHelperName, Content: []byte(helper), Mode: 0o700},
		{
			Name:    gitconfigName,
			Content: []byte(buildGitConfig()),
			Mode:    0o600,
			EnvVar:  "GIT_CONFIG_GLOBAL",
		},
	}

	mat.Env["CLOOP_GITHUB_REPO_ALLOWLIST"] = strings.Join(mat.Constraints.Repos, ",")
	if len(mat.Constraints.Permissions) > 0 {
		mat.Env["CLOOP_GITHUB_PERMISSIONS"] = strings.Join(mat.Constraints.Permissions, ",")
	}
	if allowsAllRepos(mat.Constraints.Repos) {
		mat.Env["GITHUB_TOKEN"] = token
		mat.Env["GH_TOKEN"] = token
		mat.SensitiveEnv = append(mat.SensitiveEnv, "GITHUB_TOKEN", "GH_TOKEN")
	}
	return mat, nil
}

// kubeMaterial delivers a kubeconfig rewritten to the allowed contexts and
// namespaces. See MinimizeKubeconfig for the rules.
//
// When a KubeGuard is configured it takes custody of the minimised document
// and what reaches the sandbox is a monitor session instead. That path is
// strictly stronger — the namespace allowlist stops being a client-side
// default and the verb allowlist starts existing at all — so it is tried
// first, and a guard that fails takes the lease with it rather than falling
// back to handing over the cluster credential. See kubeguard.go.
func (b *Broker) kubeMaterial(ctx context.Context, mat Material, plaintext []byte) (Material, error) {
	minimized, err := MinimizeKubeconfig(plaintext, mat.Constraints)
	if err != nil {
		return Material{}, err
	}

	delivered := minimized
	guarded := KubeGuardResult{}
	if b != nil && b.KubeGuard != nil {
		guarded, err = b.KubeGuard.GuardKubeconfig(ctx, KubeGuardRequest{
			Kubeconfig: minimized,
			Verbs:      mat.Constraints.KubeVerbs(),
			Namespaces: mat.Constraints.Namespaces,
			SecretName: mat.SecretName,
			SecretID:   mat.SecretID,
			GrantID:    mat.GrantID,
			ProjectID:  mat.projectID,
			ExecutorID: mat.executorID,
			Actor:      mat.actor,
			Owner:      mat.owner,
		})
		if err != nil {
			return Material{}, fmt.Errorf("%w: guard kubeconfig secret %s: %w",
				ErrGuardUnavailable, mat.SecretName, err)
		}
		if guarded.Guarded() {
			delivered = guarded.Kubeconfig
		}
	}

	mat.Files = []File{{
		Name:    "kubeconfig",
		Content: delivered,
		Mode:    0o600,
		EnvVar:  "KUBECONFIG",
	}}
	if ns := firstConcreteNamespace(mat.Constraints.Namespaces); ns != "" {
		mat.Env["CLOOP_K8S_NAMESPACE"] = ns
	}
	mat.Env["CLOOP_K8S_ALLOWED_NAMESPACES"] = strings.Join(mat.Constraints.Namespaces, ",")
	// The verbs the grant permits, announced to the workload so a harness can
	// read them and not attempt a write it will be refused. This is a
	// courtesy, not a control: the enforcement is pkg/kubeguard, outside the
	// sandbox, and a harness that ignores this variable gets a 403 rather
	// than a write.
	mat.Env["CLOOP_K8S_VERBS"] = strings.Join(mat.Constraints.KubeVerbs(), ",")
	access := "read-only"
	if !mat.Constraints.KubeReadOnly() {
		access = strings.Join(mat.Constraints.KubeVerbs(), "|")
	}
	// The context summary is always taken from the *minimised* document, not
	// the delivered one: under a guard the delivered kubeconfig names one
	// synthetic context pointing at the monitor, and an audit row saying
	// "contexts: cloop" would describe the plumbing instead of the access.
	mat.Summary = "kubeconfig " + access + " contexts: " + KubeconfigSummary(minimized)

	if guarded.Guarded() {
		mat.Env[KubeGuardSessionEnvKey] = guarded.SessionID
		if s := strings.TrimSpace(guarded.Summary); s != "" {
			mat.Summary = "kubeconfig " + s + ", contexts: " + KubeconfigSummary(minimized)
		} else {
			mat.Summary += " (monitored)"
		}
	}
	return mat, nil
}

// registryMaterial delivers a docker config containing only the allowed
// registries' auth entries.
func (b *Broker) registryMaterial(mat Material, plaintext []byte) (Material, error) {
	cfg, names, err := minimizeRegistryAuth(plaintext, mat.Constraints)
	if err != nil {
		return Material{}, err
	}
	// DOCKER_CONFIG names a *directory* holding config.json, so the file
	// takes that name and the env var points at the lease directory.
	mat.Files = []File{{
		Name:     "config.json",
		Content:  cfg,
		Mode:     0o600,
		EnvVar:   "DOCKER_CONFIG",
		EnvIsDir: true,
	}}
	mat.Summary = "registries: " + names
	return mat, nil
}

// egressMaterial delivers a proxy endpoint plus its allowed-host list.
//
// Unlike the kubeconfig and registry cases, the payload is not narrowed
// here: a proxy URL has no substructure to remove. Enforcement is the
// proxy's and the executor network policy's job, and the allowlist is
// carried to both. In-process callers gate on Constraints.AllowsHost.
func (b *Broker) egressMaterial(mat Material, plaintext []byte) (Material, error) {
	proxy := strings.TrimSpace(string(plaintext))
	if proxy == "" {
		return Material{}, wrapf(ErrMalformedPayload, "egress secret %s is empty", mat.SecretName)
	}
	if len(mat.Constraints.Hosts) == 0 {
		return Material{}, wrapf(ErrHostDenied,
			"egress grant %s carries no host allowlist", mat.GrantID)
	}

	allow := strings.Join(mat.Constraints.Hosts, ",")
	mat.Env["HTTPS_PROXY"] = proxy
	mat.Env["HTTP_PROXY"] = proxy
	mat.Env["https_proxy"] = proxy
	mat.Env["http_proxy"] = proxy
	mat.Env["CLOOP_EGRESS_ALLOW"] = allow
	// The proxy URL may carry userinfo — the same reason Summary names only
	// the allowlist — so all four spellings are credential-bearing. The
	// allowlist beside them is not, and must stay readable.
	mat.SensitiveEnv = append(mat.SensitiveEnv,
		"HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy")

	mat.Files = []File{{
		Name:    "egress-allow.txt",
		Content: []byte(strings.Join(mat.Constraints.Hosts, "\n") + "\n"),
		Mode:    0o600,
		EnvVar:  "CLOOP_EGRESS_ALLOW_FILE",
	}}
	// The proxy URL itself may carry credentials, so the summary names only
	// the allowlist.
	mat.Summary = "egress hosts: " + allow
	return mat, nil
}
