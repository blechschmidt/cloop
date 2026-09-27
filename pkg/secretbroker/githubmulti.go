package secretbroker

// githubmulti.go lets one lease carry more than one GitHub grant (Task 20349).
//
// Every GitHub material renders the same three files under fixed names — the
// credential (a token, or a git proxy session credential), the helper that
// releases it, and the gitconfig that installs the helper through
// GIT_CONFIG_GLOBAL. A lease holding two GitHub grants — read access to a
// library and write access to the project's own repository, or an edited
// assignment whose predecessor had not been revoked yet — therefore rendered two
// files at every one of those paths. A hub-materialised lease wrote one over the
// other; a delivered one was refused outright ("secret_files[N] repeats path
// …/github-token"), so the project could not run on an edge device, a container
// or a Pod at all.
//
// coalesceGitHub gives every GitHub material after the first a credential file
// and a helper of its own, and gives the first a gitconfig that installs every
// helper in turn. Git asks each configured helper and takes the first answer,
// and each helper answers only for its own grant's repositories, so every
// repository is authenticated by a grant that names it. Grants with a narrow
// allowlist are installed ahead of wildcard ones, so the grant that names a
// repository outranks one that merely matches it.
//
// The combined gitconfig belongs to the first grant's binding, so revoking that
// grant mid-run takes git's configuration with it and the others stop
// answering too. That errs toward less access, never more, and it ends at the
// next dispatch.

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// gitMaterialProxyEnv is the variable a guarded GitHub material names its proxy
// base in; its presence is what marks a material as guarded.
const gitMaterialProxyEnv = "CLOOP_GIT_PROXY_URL"

// isGitMaterial reports whether m installs a git credential helper through a
// gitconfig — every GitHub material, guarded or not.
func isGitMaterial(m Material) bool {
	var config, helper bool
	for _, f := range m.Files {
		switch {
		case f.Name == gitconfigName && f.EnvVar == "GIT_CONFIG_GLOBAL":
			config = true
		case f.Name == credentialHelperName:
			helper = true
		}
	}
	return config && helper
}

// hasWildcardRepo reports whether m's allowlist admits repositories it does not
// name, which ranks it after grants that do.
func hasWildcardRepo(m Material) bool {
	for _, r := range m.Constraints.Repos {
		if strings.Contains(r, "*") {
			return true
		}
	}
	return false
}

// gitMaterialOrder returns the indices of materials' git materials, in the
// order their helpers are installed.
func gitMaterialOrder(materials []Material) []int {
	var git []int
	for i, m := range materials {
		if isGitMaterial(m) {
			git = append(git, i)
		}
	}
	sort.SliceStable(git, func(a, b int) bool {
		return !hasWildcardRepo(materials[git[a]]) && hasWildcardRepo(materials[git[b]])
	})
	return git
}

// coalesceGitHub returns materials with every GitHub material's files made
// distinct, and the first one's gitconfig installing every helper. A lease with
// at most one GitHub material is returned unchanged. The input is not modified.
func coalesceGitHub(materials []Material) ([]Material, error) {
	git := gitMaterialOrder(materials)
	if len(git) < 2 {
		return materials, nil
	}
	out := append([]Material(nil), materials...)

	var helpers, bases []string
	for rank, idx := range git {
		m := out[idx]
		suffix := ""
		if rank > 0 {
			suffix = fmt.Sprintf("-%d", rank+1)
		}
		base := strings.TrimSpace(m.Env[gitMaterialProxyEnv])
		files := make([]File, 0, len(m.Files))
		for _, f := range m.Files {
			switch f.Name {
			case gitconfigName:
				// Replaced by the combined one below.
				continue
			case tokenFileName, proxyCredentialName:
				f.Name += suffix
			case credentialHelperName:
				var (
					script string
					err    error
				)
				if base != "" {
					// Several sessions share the proxy's host, so each helper
					// must also check the repository.
					script, err = buildProxyCredentialHelperFor(base, proxyCredentialName+suffix, m.Constraints.Repos)
				} else {
					script, err = buildGitCredentialHelperFor(m.Constraints.Repos, tokenFileName+suffix)
				}
				if err != nil {
					return nil, err
				}
				f.Name += suffix
				f.Content = []byte(script)
			}
			files = append(files, f)
		}
		m.Files = files
		out[idx] = m
		helpers = append(helpers, credentialHelperName+suffix)
		if base != "" && !hasString(bases, base) {
			bases = append(bases, base)
		}
	}

	config, err := buildCombinedGitConfig(helpers, bases)
	if err != nil {
		return nil, err
	}
	owner := out[git[0]]
	owner.Files = append(owner.Files, File{
		Name:    gitconfigName,
		Content: []byte(config),
		Mode:    0o600,
		EnvVar:  "GIT_CONFIG_GLOBAL",
	})
	out[git[0]] = owner
	return out, nil
}

// buildCombinedGitConfig installs every helper, in order, and the proxy rewrite
// when any grant is guarded.
func buildCombinedGitConfig(helpers, proxyBases []string) (string, error) {
	var b strings.Builder
	b.WriteString("# Generated by cloop secretbroker for the lifetime of one lease.\n")
	fmt.Fprintf(&b, "# %d GitHub grants: git asks each helper in turn, and each answers only\n", len(helpers))
	b.WriteString("# for its own grant's repositories.\n")
	b.WriteString("[credential]\n")
	b.WriteString("\tuseHttpPath = true\n")
	for _, h := range helpers {
		if !validLeaseFileToken(h) {
			return "", wrapf(ErrInvalidSecret, "unsafe credential helper name %q", h)
		}
		b.WriteString("\thelper = !\"$CLOOP_LEASE_DIR/" + h + "\"\n")
	}
	for _, raw := range proxyBases {
		base, err := normalizeProxyBase(raw)
		if err != nil {
			return "", err
		}
		b.WriteString("[url \"" + base + "/\"]\n")
		b.WriteString("\tinsteadOf = https://" + githubHost + "/\n")
		b.WriteString("\tinsteadOf = git@" + githubHost + ":\n")
		b.WriteString("\tinsteadOf = ssh://git@" + githubHost + "/\n")
	}
	return b.String(), nil
}

// mergeGitHubEnv settles the variables several GitHub materials would each set,
// where the last one written would otherwise speak for all of them.
//
// They describe the grants to the workload — pkg/pm renders the prompt's
// repository section from them — and none of them is a credential the helpers
// read. So: every grant's repositories, and a mode, a push rule or an expiry
// only where the grants agree on it; a statement that holds for one grant and
// not another is dropped rather than applied to both.
func mergeGitHubEnv(env map[string]string, git []Material) {
	if len(git) < 2 {
		return
	}
	var repos []string
	for _, m := range git {
		for _, r := range m.Constraints.Repos {
			if !hasString(repos, r) {
				repos = append(repos, r)
			}
		}
	}
	if len(repos) > 0 {
		env["CLOOP_GITHUB_REPO_ALLOWLIST"] = strings.Join(repos, ",")
	}

	for _, key := range []string{
		"CLOOP_GITHUB_PERMISSIONS",
		"CLOOP_GIT_PROXY_MODE",
		GitPushRefsEnvKey,
		GitHubPushBranchesEnvKey,
		GitHubWriteWithheldEnvKey,
	} {
		first, agree := git[0].Env[key], true
		for _, m := range git[1:] {
			if m.Env[key] != first {
				agree = false
				break
			}
		}
		if agree && first != "" {
			env[key] = first
		} else {
			delete(env, key)
		}
	}

	// The earliest expiry: the workload is told when GitHub access may end.
	var earliest time.Time
	for _, m := range git {
		if t, err := time.Parse(time.RFC3339, m.Env["CLOOP_GITHUB_TOKEN_EXPIRES_AT"]); err == nil &&
			(earliest.IsZero() || t.Before(earliest)) {
			earliest = t
		}
	}
	if !earliest.IsZero() {
		env["CLOOP_GITHUB_TOKEN_EXPIRES_AT"] = earliest.UTC().Format(time.RFC3339)
	}

	// A bare token is exported only for a wildcard grant; with several, the one
	// installed first speaks, rather than whichever happened to render last.
	for _, key := range []string{"GITHUB_TOKEN", "GH_TOKEN"} {
		for _, m := range git {
			if v, ok := m.Env[key]; ok {
				env[key] = v
				break
			}
		}
	}
}

// orderedGitMaterials returns materials' GitHub materials in helper order.
func orderedGitMaterials(materials []Material) []Material {
	var out []Material
	for _, i := range gitMaterialOrder(materials) {
		out = append(out, materials[i])
	}
	return out
}

func hasString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
