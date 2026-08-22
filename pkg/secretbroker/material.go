package secretbroker

import (
	"fmt"
	"sort"
	"strings"
)

// materialFor opens a secret's payload and reduces it to what the grant's
// constraints permit.
//
// Every branch either returns a narrowed credential or an error. There is no
// path that falls through to "deliver the payload as stored" — the closest
// thing, KindEnv with no key filter, is narrow already because an env
// secret's keys are its whole scope.
func (b *Broker) materialFor(s Secret, g Grant) (Material, error) {
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
	}

	switch s.Kind {
	case KindEnv:
		return b.envMaterial(mat, plaintext)
	case KindGitHubPAT, KindGitHubApp:
		return b.githubMaterial(mat, plaintext)
	case KindKubeconfig:
		return b.kubeMaterial(mat, plaintext)
	case KindRegistry:
		return b.registryMaterial(mat, plaintext)
	case KindEgressProxy:
		return b.egressMaterial(mat, plaintext)
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
// the helper is the only delivery path, so "may only touch org/*" is
// something the workload cannot exceed rather than something it is asked to
// respect.
func (b *Broker) githubMaterial(mat Material, plaintext []byte) (Material, error) {
	token := strings.TrimSpace(string(plaintext))
	if token == "" {
		return Material{}, wrapf(ErrMalformedPayload, "github secret %s is empty", mat.SecretName)
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
	}

	mat.Summary = fmt.Sprintf("github repos: %s (helper-scoped=%t)",
		strings.Join(mat.Constraints.Repos, "|"), !allowsAllRepos(mat.Constraints.Repos))
	return mat, nil
}

// kubeMaterial delivers a kubeconfig rewritten to the allowed contexts and
// namespaces. See MinimizeKubeconfig for the rules.
func (b *Broker) kubeMaterial(mat Material, plaintext []byte) (Material, error) {
	minimized, err := MinimizeKubeconfig(plaintext, mat.Constraints)
	if err != nil {
		return Material{}, err
	}
	mat.Files = []File{{
		Name:    "kubeconfig",
		Content: minimized,
		Mode:    0o600,
		EnvVar:  "KUBECONFIG",
	}}
	if ns := firstConcreteNamespace(mat.Constraints.Namespaces); ns != "" {
		mat.Env["CLOOP_K8S_NAMESPACE"] = ns
	}
	mat.Env["CLOOP_K8S_ALLOWED_NAMESPACES"] = strings.Join(mat.Constraints.Namespaces, ",")
	mat.Summary = "kubeconfig contexts: " + KubeconfigSummary(minimized)
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
