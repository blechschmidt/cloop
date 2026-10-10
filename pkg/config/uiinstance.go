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
// Settings that are true of this hub rather than of this project. These are
// the hub-scope keys, and `cloop ui` reads every one of them with the overlay
// merged in (Task 20364; pkg/ui/hubconfig.go is the one reader):
//
//	executors.*            allow_host_process, min_agent_build, limits (the
//	                       resource ceiling), container, kubernetes, git_proxy,
//	                       kube_guard, auto_install_harness, the orphan sweep,
//	                       feature_bundle_mb, failover (the cap on
//	                       re-dispatching a lost node's work, Task 20391),
//	                       remote (the memory returned work may hold,
//	                       Task 20399)
//	sandbox.image_policy   the image trust policy, at the hub's early check
//	                       and in the copy each driver takes at startup
//	ui.*                   listen and allow_unauthenticated_network (where
//	                       the dashboard binds, Task 20393), oidc, tls, the
//	                       origin allowlists, the WebSocket caps, quotas,
//	                       cluster, ci, telemetry, auto_resume_on_cap_reset
//	stt                    the hub's dictation settings and key; a project's
//	                       own stt section still overrides them for requests
//	                       about that project
//	retention, audit       the janitor's policy for the hub's own directory
//	backup                 auto-backup of the hub's own directory
//	github.token           the token the hub hands a host-run pull request
//	orchestrator.min_free_disk_mb
//	                       the free-space floor: the hub's doctor and admin
//	                       banner hold its state volume to it, and the hub
//	                       hands it to the runs it starts of its own
//	                       directory (CLOOP_MIN_FREE_DISK_MB), since `cloop
//	                       run` reads no overlay (Task 20381)
//
// executors.allow_host_process, min_agent_build and limits are ratchets
// across everything a hub reads (they only ever tighten), but the overlay
// takes part as the hub's own file. So an overlay that says
// allow_host_process: true does relax a shared config.yaml that says false,
// for this hub alone, as its key-by-key merge promises.
//
// Not API keys, budgets, the provider or the model, which belong to the
// project and stay in config.yaml where every command reads them. The overlay
// is read by `cloop ui`, and by nothing else, so `cloop run` would never see
// a provider written there.
//
// A settings panel writes the keys it edits into the overlay once one exists
// (ui.oidc, ui.telemetry, ui.ci, stt.groq_api_key,
// orchestrator.min_free_disk_mb), and leaves config.yaml byte for byte as it
// was.

package config

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// UIInstanceConfigPath returns the per-instance overlay path for a dashboard
// listening on port. It does not check whether the file exists.
func UIInstanceConfigPath(workdir string, port int) string {
	return filepath.Join(workdir, ".cloop", fmt.Sprintf("config.ui-%d.yaml", port))
}

// UIInstancePorts returns the port of every per-instance overlay in workdir,
// in ascending order: the hubs in that directory that have settings of their
// own.
//
// It exists for code that runs beside the hubs rather than as one of them,
// such as `cloop hub doctor`, and has to answer for all of them. A file whose
// name does not end in a port `cloop ui` could listen on is not an overlay any
// hub reads, and is skipped.
func UIInstancePorts(workdir string) ([]int, error) {
	matches, err := filepath.Glob(filepath.Join(workdir, ".cloop", "config.ui-*.yaml"))
	if err != nil {
		return nil, err
	}
	var ports []int
	for _, m := range matches {
		num := strings.TrimSuffix(strings.TrimPrefix(filepath.Base(m), "config.ui-"), ".yaml")
		port, err := strconv.Atoi(num)
		// Round-tripped so "08081" and "+8081" are refused: neither is the
		// name UIInstanceConfigPath would give the hub on that port.
		if err != nil || port <= 0 || port > 65535 || strconv.Itoa(port) != num {
			continue
		}
		ports = append(ports, port)
	}
	sort.Ints(ports)
	return ports, nil
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
	baseRepairs := len(cfg.loadRepairs)
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, "", fmt.Errorf("could not parse %s: %w", path, err)
	}
	// Re-run both passes over the merged result. An overlay value is user
	// input like any other, and skipping the clamp here would let a bound that
	// config.yaml cannot escape be escaped by writing it one file over.
	cfg.validateAndClamp(path)
	cfg.applyEnvVars()
	var stated map[string]any
	_ = yaml.Unmarshal(data, &stated) // parsed once already, into cfg
	cfg.loadRepairs = mergedRepairs(cfg.loadRepairs[:baseRepairs], cfg.loadRepairs[baseRepairs:],
		func(key string) bool { return statesKey(stated, key) })
	return cfg, path, nil
}

// mergedRepairs keeps the load repairs that describe the merged configuration
// a hub runs, each attributed to the file that holds the value (Task 20387).
//
// From config.yaml's pass, a repaired value the overlay replaces is gone from
// what the hub runs, and a switch-off is superseded where the overlay sets the
// section's enabled itself — on, to be judged again below, or off, which is a
// choice and not a repair. From the overlay's pass, which re-judges the merged
// result, only the overlay's own values are its to report: anything else it
// finds is config.yaml's, recorded already — and a switch-off there can only
// have been caused by what the overlay states.
func mergedRepairs(base, overlay []LoadRepair, states func(key string) bool) []LoadRepair {
	out := make([]LoadRepair, 0, len(base)+len(overlay))
	for _, r := range base {
		switch {
		case r.SwitchedOff != "" && states(r.SwitchedOff+".enabled"):
			continue
		case r.SwitchedOff == "" && states(r.Field):
			continue
		}
		out = append(out, r)
	}
	for _, r := range overlay {
		if r.SwitchedOff != "" || states(r.Field) {
			out = append(out, r)
		}
	}
	return out
}

// statesKey reports whether a parsed YAML document states the dotted key —
// "executors.git_proxy.advertise_url", or a section such as
// "executors.kube_guard".
func statesKey(doc map[string]any, key string) bool {
	var cur any = doc
	for _, part := range strings.Split(key, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return false
		}
		if cur, ok = m[part]; !ok {
			return false
		}
	}
	return true
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
	oidc, err := yaml.Marshal(o)
	if err != nil {
		return fmt.Errorf("could not encode ui.oidc: %w", err)
	}
	var encoded yaml.Node
	if err := yaml.Unmarshal(oidc, &encoded); err != nil {
		return fmt.Errorf("could not re-read encoded ui.oidc: %w", err)
	}
	return saveUIInstanceBlock(path, "oidc", documentRoot(&encoded))
}

// SaveUIInstanceTelemetry writes the ui.telemetry block into an overlay file,
// leaving every other key in it untouched (Task 20311). Collection is a
// per-hub decision: it is what this hub records about the people using it.
//
// Both keys are written even when they hold their zero value, because the
// overlay is merged over config.yaml field by field: an absent `sources`
// would let a narrowing in config.yaml show through a save that ticked every
// front end, and the panel would show the hub collecting less than was saved.
// `enabled` is left out only while it is unset in both files.
func SaveUIInstanceTelemetry(path string, t TelemetryConfig) error {
	block := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	if t.Enabled != nil {
		block.Content = append(block.Content, yamlScalar("!!str", "enabled"),
			yamlScalar("!!bool", strconv.FormatBool(*t.Enabled)))
	}
	sources := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq", Style: yaml.FlowStyle}
	for _, src := range t.Sources {
		sources.Content = append(sources.Content, yamlScalar("!!str", src))
	}
	block.Content = append(block.Content, yamlScalar("!!str", "sources"), sources)
	return saveUIInstanceBlock(path, "telemetry", block)
}

// SaveUIInstanceCI writes the ui.ci keys the Settings panel edits into an
// overlay file, leaving every other key in it untouched (Task 20364).
//
// All six are written even at their zero value, for the reason
// SaveUIInstanceTelemetry gives: the overlay is merged over config.yaml key by
// key, so a key left out would let config.yaml's value show through a save
// that set it. upstream_auth_token and exchange_keep_records are not written.
// The panel cannot edit them, and copying the token out of config.yaml would
// put a credential in a second file for no reason, so whichever file states
// them still does.
func SaveUIInstanceCI(path string, c CIConfig) error {
	models := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq", Style: yaml.FlowStyle}
	for _, m := range c.DefaultModels {
		models.Content = append(models.Content, yamlScalar("!!str", m))
	}
	return saveUIInstanceKeys(path, []string{"ui", "ci"}, []overlayKey{
		{"enabled", yamlScalar("!!bool", strconv.FormatBool(c.Enabled))},
		{"issuer", yamlScalar("!!str", c.Issuer)},
		{"audience", yamlScalar("!!str", c.Audience)},
		{"clock_skew_seconds", yamlScalar("!!int", strconv.Itoa(c.ClockSkewSeconds))},
		{"default_models", models},
		{"upstream_base_url", yamlScalar("!!str", c.UpstreamBaseURL)},
	})
}

// SaveUIInstanceSTTKey writes stt.groq_api_key into an overlay file, leaving
// every other key in it untouched (Task 20364). An empty key is written as an
// empty string rather than removed: clearing the credential for this hub must
// not let a key in the shared config.yaml show through.
func SaveUIInstanceSTTKey(path, key string) error {
	return saveUIInstanceKeys(path, []string{"stt"}, []overlayKey{
		{"groq_api_key", yamlScalar("!!str", key)},
	})
}

// SaveUIInstanceMinFreeDisk writes orchestrator.min_free_disk_mb into an
// overlay file, leaving every other key in it untouched (Task 20381). The value
// is written even when it is the default or 0, for the reason the other savers
// give: a key left out would let config.yaml's value show through the save.
func SaveUIInstanceMinFreeDisk(path string, mb int) error {
	if !ValidMinFreeDiskMB(mb) {
		return MinFreeDiskMBError(mb)
	}
	return saveUIInstanceKeys(path, []string{"orchestrator"}, []overlayKey{
		{"min_free_disk_mb", yamlScalar("!!int", strconv.Itoa(mb))},
	})
}

func yamlScalar(tag, value string) *yaml.Node {
	return &yaml.Node{Kind: yaml.ScalarNode, Tag: tag, Value: value}
}

// overlayKey is one key an overlay save sets.
type overlayKey struct {
	name  string
	value *yaml.Node
}

// saveUIInstanceBlock replaces ui.<key> in the overlay at path with block.
func saveUIInstanceBlock(path, key string, block *yaml.Node) error {
	return saveUIInstanceKeys(path, []string{"ui"}, []overlayKey{{key, block}})
}

// saveUIInstanceKeys sets keys in the mapping reached by following parents
// from the root of the overlay at path. It creates any mapping on the way
// that is missing, and leaves every other key in the file, and its comments,
// as they were.
func saveUIInstanceKeys(path string, parents []string, keys []overlayKey) error {
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

	m := documentRoot(&doc)
	for _, parent := range parents {
		m = mappingValue(m, parent)
	}
	for _, k := range keys {
		setMappingValue(m, k.name, k.value)
	}

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
