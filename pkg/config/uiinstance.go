// Per-instance dashboard configuration (Task 20318).
//
// A cloop hub reads .cloop/config.yaml out of its working directory, which is
// exactly right until two hubs share that directory — and on a host that runs
// a stable dashboard alongside a bleeding-edge one, they do. Both of
// aiden.blechschmidt.io's dashboards run out of /root/Projects/cloop:
//
//	cloop-ui.service         /usr/local/bin/cloop        --port 8080   (:1234)
//	cloop-ui-latest.service  /usr/local/bin/cloop-latest --port 8081   (:8888)
//
// Everything in config.yaml is therefore said to both of them, including the
// settings that can only be true of one. `ui.oidc.redirect_url` names a single
// origin; the hub it does not name authenticates users into a callback it does
// not serve. That is not a hypothetical: enabling SSO for :8888 in the shared
// file puts the other hub into an endless login loop at best, and — with a
// binary predating the public-client work of Task 20314, which is what is
// installed on that host — refuses to let it start at all, turning
// Restart=always into a crash loop on a dashboard nobody was changing.
//
// # The overlay
//
// `cloop ui --port N` reads .cloop/config.ui-N.yaml after config.yaml and
// merges it over the top. The listen port is the key because it is the one
// thing that already distinguishes two hubs in one directory — no new
// identifier to allocate, keep in sync, or get wrong.
//
// A separate *file* rather than a port-keyed section inside config.yaml,
// deliberately, and for a reason that only shows up in the failure case: an
// older binary sharing the directory does not merely ignore keys it does not
// know, it drops them. Anything it cannot parse is gone from the file the next
// time anything calls Save() — and for a block whose job is to require a login,
// being silently deleted means the hub comes back with no authentication at
// all. An old binary never opens a filename it has never heard of, so the
// overlay cannot be rewritten by one. The failure mode runs closed.
//
// # What belongs in it
//
// Settings that are true of this hub rather than of this project: OIDC, TLS,
// the origin allowlist, the WebSocket caps. Not API keys or budgets, which
// belong to the project and should stay in config.yaml where every command
// reads them — the overlay is read by `cloop ui`, and by nothing else.

package config

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// UIInstanceConfigPath returns the per-instance overlay path for a dashboard
// listening on port. It does not check whether the file exists.
func UIInstanceConfigPath(workdir string, port int) string {
	return filepath.Join(workdir, ".cloop", fmt.Sprintf("config.ui-%d.yaml", port))
}

// LoadUIInstance loads the project configuration and then merges the overlay
// for a dashboard listening on port, if one exists.
//
// It returns the effective configuration and the path of the overlay that was
// applied — empty when there was none, which is the ordinary case and not an
// error. Callers report the path so that an operator reading a startup banner
// can tell which file a setting came from; a merged config that names no
// source is the thing this mechanism is most likely to be blamed for.
//
// Merge semantics are YAML's: a key present in the overlay replaces the value
// under it, a key absent leaves the project's value alone. Sequences replace
// rather than append — an overlay that lists two scopes means those two, not
// those two plus whatever config.yaml listed.
func LoadUIInstance(workdir string, port int) (*Config, string, error) {
	cfg, err := Load(workdir)
	if err != nil {
		return nil, "", err
	}
	// A port cloop could not have bound is not worth a stat call, and would
	// otherwise invent filenames like config.ui-0.yaml that no operator wrote.
	if port <= 0 {
		return cfg, "", nil
	}

	path := UIInstanceConfigPath(workdir, port)
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return cfg, "", nil
	}
	if err != nil {
		return nil, "", fmt.Errorf("could not read %s: %w", path, err)
	}
	warnIfConfigTooOpen(path)
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, "", fmt.Errorf("could not parse %s: %w", path, err)
	}
	// Re-run both passes over the merged result. An overlay value is user
	// input like any other, and skipping the clamp here would let a bound that
	// config.yaml cannot escape be escaped by writing it one file over.
	cfg.validateAndClamp(path)
	cfg.applyEnvVars()
	return cfg, path, nil
}

// SaveUIInstanceOIDC writes the ui.oidc block into an overlay file, leaving
// every other key in it untouched.
//
// Whole-file marshalling would be wrong here twice over: it would copy the
// merged project configuration — API keys included — into a file that then
// shadows the original, and it would discard the comments an operator wrote to
// explain a deployment's authentication to the next person. So the document is
// edited in place through yaml.Node, which preserves both.
//
// Comments *inside* the replaced ui.oidc block do not survive, which is the
// honest outcome: that block now has a writer other than the operator.
func SaveUIInstanceOIDC(path string, o OIDCConfig) error {
	var doc yaml.Node
	data, err := os.ReadFile(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		// An overlay that does not exist yet is an empty document, not an
		// error: this is how the settings panel creates one.
	case err != nil:
		return fmt.Errorf("could not read %s: %w", path, err)
	default:
		if err := yaml.Unmarshal(data, &doc); err != nil {
			return fmt.Errorf("could not parse %s: %w", path, err)
		}
	}

	root := documentRoot(&doc)
	ui := mappingValue(root, "ui")
	oidc, err := yaml.Marshal(o)
	if err != nil {
		return fmt.Errorf("could not encode ui.oidc: %w", err)
	}
	var encoded yaml.Node
	if err := yaml.Unmarshal(oidc, &encoded); err != nil {
		return fmt.Errorf("could not re-read encoded ui.oidc: %w", err)
	}
	setMappingValue(ui, "oidc", documentRoot(&encoded))

	out, err := yaml.Marshal(&doc)
	if err != nil {
		return fmt.Errorf("could not encode %s: %w", path, err)
	}
	return writeConfigFileAtomic(path, out)
}

// documentRoot unwraps a decoded document to its content node, substituting an
// empty mapping for an empty or absent document so callers never branch on it.
func documentRoot(n *yaml.Node) *yaml.Node {
	if n.Kind == yaml.DocumentNode {
		if len(n.Content) == 0 {
			n.Content = []*yaml.Node{{Kind: yaml.MappingNode, Tag: "!!map"}}
		}
		return n.Content[0]
	}
	if n.Kind == 0 {
		*n = yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{{Kind: yaml.MappingNode, Tag: "!!map"}}}
		return n.Content[0]
	}
	return n
}

// mappingValue returns the mapping stored under key, creating an empty one if
// the key is absent or holds something that is not a mapping. Overwriting a
// non-mapping is deliberate: `ui: null` is what a half-written file looks like,
// and refusing to repair it would strand the panel behind a shell edit.
func mappingValue(parent *yaml.Node, key string) *yaml.Node {
	for i := 0; i+1 < len(parent.Content); i += 2 {
		if parent.Content[i].Value != key {
			continue
		}
		if parent.Content[i+1].Kind != yaml.MappingNode {
			parent.Content[i+1] = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		}
		return parent.Content[i+1]
	}
	child := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	parent.Content = append(parent.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key},
		child)
	return child
}

// setMappingValue replaces the value stored under key, appending the pair when
// the key is new.
func setMappingValue(parent *yaml.Node, key string, value *yaml.Node) {
	for i := 0; i+1 < len(parent.Content); i += 2 {
		if parent.Content[i].Value == key {
			parent.Content[i+1] = value
			return
		}
	}
	parent.Content = append(parent.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key},
		value)
}

// writeConfigFileAtomic writes data to path through a temporary file in the
// same directory, so a crash mid-write cannot leave a hub with a half-parsed
// authentication policy. 0600 because the file may hold a client secret.
func writeConfigFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".config.ui.*.tmp")
	if err != nil {
		return fmt.Errorf("config: create tmp: %w", err)
	}
	tmpPath := tmp.Name()
	defer func() {
		if _, statErr := os.Stat(tmpPath); statErr == nil {
			_ = os.Remove(tmpPath)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("config: write tmp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("config: sync tmp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("config: close tmp: %w", err)
	}
	if err := os.Chmod(tmpPath, 0o600); err != nil {
		return fmt.Errorf("config: chmod tmp: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("config: rename tmp: %w", err)
	}
	return nil
}
