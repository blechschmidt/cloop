package secretbroker

import (
	"encoding/json"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// kubeConfig is a structurally-typed view of a kubeconfig document.
//
// The inner cluster/user/context bodies stay as maps because kubeconfig's
// auth surface is open-ended (client certs, tokens, exec credential
// plugins, auth-provider blocks) and dropping a field we did not model would
// silently break a working credential. The *envelope* is typed, though, and
// that is what does the minimising: round-tripping through this struct
// discards every top-level key we did not name, so extensions, preferences,
// and anything a future kubeconfig grows cannot ride along into a delivered
// credential unnoticed.
type kubeConfig struct {
	APIVersion     string           `yaml:"apiVersion,omitempty"`
	Kind           string           `yaml:"kind,omitempty"`
	CurrentContext string           `yaml:"current-context,omitempty"`
	Clusters       []kubeNamedEntry `yaml:"clusters,omitempty"`
	Contexts       []kubeNamedCtx   `yaml:"contexts,omitempty"`
	Users          []kubeNamedEntry `yaml:"users,omitempty"`
}

// kubeNamedEntry is the {name, cluster|user} shape shared by the clusters
// and users lists. Only one of the two body fields is populated per list.
type kubeNamedEntry struct {
	Name    string         `yaml:"name"`
	Cluster map[string]any `yaml:"cluster,omitempty"`
	User    map[string]any `yaml:"user,omitempty"`
}

type kubeNamedCtx struct {
	Name    string      `yaml:"name"`
	Context kubeContext `yaml:"context"`
}

type kubeContext struct {
	Cluster   string `yaml:"cluster"`
	User      string `yaml:"user"`
	Namespace string `yaml:"namespace,omitempty"`
}

// MinimizeKubeconfig rewrites a kubeconfig to contain only what the grant's
// constraints permit, and returns the reduced document.
//
// This is the strongest enforcement in the package, because it is
// subtractive: the executor receives a kubeconfig that has no credentials
// for the clusters it may not reach and no context naming a namespace it may
// not touch. Nothing it can do with that document widens it back out. That
// is a different and better guarantee than handing over the full kubeconfig
// alongside a policy note.
//
// Rules:
//   - a context survives only if Constraints.AllowsContext says so;
//   - when the grant lists namespaces, each surviving context is pinned to
//     an allowed namespace — its own if that is allowed, otherwise the first
//     concrete (non-glob) namespace in the allowlist;
//   - a context whose namespace is disallowed and which cannot be pinned
//     (the allowlist is globs only) is dropped rather than guessed at;
//   - clusters and users not referenced by a surviving context are removed,
//     so their certificates and tokens never leave the control plane;
//   - current-context is repointed at a surviving context;
//   - if nothing survives, the result is ErrMinimizedEmpty — a denial, not
//     an empty file that would look like a working credential.
func MinimizeKubeconfig(raw []byte, c Constraints) ([]byte, error) {
	var cfg kubeConfig
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		return nil, wrapf(ErrMalformedPayload, "kubeconfig is not valid YAML: %v", err)
	}
	if len(cfg.Contexts) == 0 {
		return nil, wrapf(ErrMalformedPayload, "kubeconfig declares no contexts")
	}

	pin := firstConcreteNamespace(c.Namespaces)
	enforceNS := len(c.Namespaces) > 0

	var kept []kubeNamedCtx
	for _, nc := range cfg.Contexts {
		if !c.AllowsContext(nc.Name) {
			continue
		}
		if enforceNS {
			switch {
			case nc.Context.Namespace != "" && c.AllowsNamespace(nc.Context.Namespace):
				// Already inside the allowlist — leave it alone.
			case pin != "":
				nc.Context.Namespace = pin
			default:
				// The allowlist is glob-only and this context points
				// somewhere outside it. There is no defensible namespace to
				// substitute, so the context does not survive.
				continue
			}
		}
		kept = append(kept, nc)
	}
	if len(kept) == 0 {
		return nil, wrapf(ErrMinimizedEmpty,
			"no kubeconfig context satisfies contexts=%s namespaces=%s",
			joinOrAny(c.Contexts), joinOrAny(c.Namespaces))
	}

	// Retain only the clusters and users the surviving contexts reference.
	neededClusters := make(map[string]bool, len(kept))
	neededUsers := make(map[string]bool, len(kept))
	for _, nc := range kept {
		if nc.Context.Cluster != "" {
			neededClusters[nc.Context.Cluster] = true
		}
		if nc.Context.User != "" {
			neededUsers[nc.Context.User] = true
		}
	}

	out := kubeConfig{
		APIVersion: orDefault(cfg.APIVersion, "v1"),
		Kind:       orDefault(cfg.Kind, "Config"),
		Contexts:   kept,
	}
	for _, cl := range cfg.Clusters {
		if neededClusters[cl.Name] {
			out.Clusters = append(out.Clusters, kubeNamedEntry{Name: cl.Name, Cluster: cl.Cluster})
		}
	}
	for _, u := range cfg.Users {
		if neededUsers[u.Name] {
			out.Users = append(out.Users, kubeNamedEntry{Name: u.Name, User: u.User})
		}
	}

	// A current-context naming a dropped context would make kubectl fail
	// with a confusing error, so repoint it at something that exists.
	out.CurrentContext = cfg.CurrentContext
	if !containsContext(kept, out.CurrentContext) {
		out.CurrentContext = kept[0].Name
	}

	data, err := yaml.Marshal(out)
	if err != nil {
		return nil, wrapf(ErrMalformedPayload, "re-encode minimized kubeconfig: %v", err)
	}
	return data, nil
}

// KubeconfigSummary describes a minimized kubeconfig for audit and CLI
// output: which contexts and namespaces survived. It never includes cluster
// endpoints' credentials, only names.
func KubeconfigSummary(minimized []byte) string {
	var cfg kubeConfig
	if err := yaml.Unmarshal(minimized, &cfg); err != nil {
		return "unparseable"
	}
	parts := make([]string, 0, len(cfg.Contexts))
	for _, nc := range cfg.Contexts {
		if nc.Context.Namespace != "" {
			parts = append(parts, nc.Name+"/"+nc.Context.Namespace)
		} else {
			parts = append(parts, nc.Name)
		}
	}
	return strings.Join(parts, ",")
}

// firstConcreteNamespace returns the first allowlist entry that names an
// actual namespace rather than a pattern. A glob cannot be pinned onto a
// context because there is no way to know which of the matching namespaces
// the operator meant.
func firstConcreteNamespace(namespaces []string) string {
	for _, ns := range namespaces {
		n := strings.TrimSpace(ns)
		if n == "" || strings.ContainsAny(n, "*?[]") {
			continue
		}
		return n
	}
	return ""
}

func containsContext(ctxs []kubeNamedCtx, name string) bool {
	if name == "" {
		return false
	}
	for _, c := range ctxs {
		if c.Name == name {
			return true
		}
	}
	return false
}

func orDefault(v, def string) string {
	if strings.TrimSpace(v) == "" {
		return def
	}
	return v
}

func joinOrAny(vals []string) string {
	if len(vals) == 0 {
		return "(unset)"
	}
	return strings.Join(vals, "|")
}

// minimizeRegistryAuth filters a docker config.json to the allowed
// registries, dropping every other entry's auth material. A "user:password"
// payload (the other shape operators paste in) is wrapped into a config.json
// for the first concrete allowed registry.
func minimizeRegistryAuth(raw []byte, c Constraints) ([]byte, string, error) {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" {
		return nil, "", wrapf(ErrMalformedPayload, "registry payload is empty")
	}

	if !strings.HasPrefix(trimmed, "{") {
		reg := firstConcreteNamespace(c.Registries)
		if reg == "" {
			return nil, "", wrapf(ErrInvalidConstraint,
				"a user:password registry secret needs a concrete registry in the allowlist, got %s",
				joinOrAny(c.Registries))
		}
		user, pass, found := strings.Cut(trimmed, ":")
		if !found || user == "" {
			return nil, "", wrapf(ErrMalformedPayload, "registry payload is neither JSON nor user:password")
		}
		cfg := map[string]any{"auths": map[string]any{
			reg: map[string]any{"username": user, "password": pass},
		}}
		data, err := marshalJSON(cfg)
		if err != nil {
			return nil, "", err
		}
		return data, reg, nil
	}

	var cfg struct {
		Auths map[string]any `json:"auths"`
	}
	if err := unmarshalJSON(raw, &cfg); err != nil {
		return nil, "", wrapf(ErrMalformedPayload, "registry payload is not valid docker config JSON: %v", err)
	}
	kept := make(map[string]any)
	var names []string
	for reg, auth := range cfg.Auths {
		if c.AllowsRegistry(reg) {
			kept[reg] = auth
			names = append(names, reg)
		}
	}
	if len(kept) == 0 {
		return nil, "", wrapf(ErrMinimizedEmpty,
			"no registry in the payload matches the allowlist (%s)", joinOrAny(c.Registries))
	}
	data, err := marshalJSON(map[string]any{"auths": kept})
	if err != nil {
		return nil, "", err
	}
	return data, strings.Join(names, ","), nil
}

// marshalJSON gives docker-config encoding errors a consistent wrapping.
func marshalJSON(v any) ([]byte, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("secretbroker: encode json: %w", err)
	}
	return data, nil
}

func unmarshalJSON(data []byte, v any) error {
	return json.Unmarshal(data, v)
}
