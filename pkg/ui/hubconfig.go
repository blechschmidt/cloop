package ui

// hubconfig.go is where this package reads and writes the hub's own
// configuration (Task 20364).
//
// # Two kinds of setting
//
// A hub reads two kinds of setting out of .cloop/config.yaml, and once a
// per-instance overlay exists (.cloop/config.ui-<port>.yaml, Task 20318) they
// come from different files:
//
//   - Hub-scope settings say what this control plane is: executors.* (the
//     host-execution policy, min_agent_build, the resource ceiling, the
//     container and Kubernetes drivers, git_proxy, kube_guard,
//     auto_install_harness, the failover cap), sandbox.image_policy, ui.*,
//     stt, retention and audit (the janitor), backup, and the hub's own
//     github.token. They are read through loadHubConfig or
//     controlPlaneConfig, which merge this hub's overlay over config.yaml.
//
//   - Project-scope settings say what one project asked for: its provider and
//     model, step timeout, budget, Claude Code caps and hooks. They are read
//     with config.Load from that project's own config.yaml, because that is
//     the file the `cloop run` doing the work reads. The overlay is read by
//     `cloop ui` alone, so a provider taken from it would describe a run that
//     never happens.
//
// The hub's own directory is both at once: it is the control plane, and it is
// the project the dashboard opens with no index. So the kind of setting being
// read decides which file answers, and the path cannot.
//
// Reading a hub-scope setting with config.Load fails open. Before this file
// existed, every hub-scope read but four did that: an operator who put
// `executors.allow_host_process: false` or an image policy in the overlay got
// a hub that still spawned harnesses on its host and ran unpinned images,
// while the startup banner said the overlay had been merged.
//
// hubconfig_gate_test.go keeps it from coming back. It fails on any
// config.Load in this package outside its project-scope allowlist, and on any
// config.Save outside an allowlisted writer.
//
// # Writing
//
// A hub settings save picks its destination before it loads anything
// (beginHubSettingsSave). With an overlay, the save writes only the keys its
// panel edits, into the overlay. Without one, it rewrites config.yaml from
// config.yaml alone. A merged view never reaches config.yaml, because that
// would copy this hub's overlay into a file the other dashboard sharing the
// directory also reads.

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/blechschmidt/cloop/pkg/config"
)

// errNoControlPlane is what controlPlaneConfig returns before any Server has
// bootstrapped in this process.
var errNoControlPlane = errors.New("no control plane is bootstrapped in this process")

// controlPlaneSource returns the control plane's directory and the port whose
// overlay applies to it, read together so they cannot come from two
// different bootstraps.
func controlPlaneSource() (dir string, port int) {
	controlPlaneDirMu.RLock()
	defer controlPlaneDirMu.RUnlock()
	return controlPlaneDirValue, controlPlanePortValue
}

// loadHubConfigAt reads the configuration the hub listening on port in dir
// runs under: dir's config.yaml with that hub's overlay merged over it, or
// config.yaml alone when the hub has none (or port is zero).
//
// This is the package's only call to config.LoadUIInstance. Every hub-scope
// read goes through it, so `cloop ui` and the code it runs agree about which
// files the hub is configured by.
func loadHubConfigAt(dir string, port int) (*config.Config, error) {
	cfg, _, err := config.LoadUIInstance(dir, port)
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		return nil, fmt.Errorf("load %s: no configuration", config.ConfigPath(dir))
	}
	return cfg, nil
}

// controlPlaneConfig reads this process's control-plane configuration, for
// code that is reached without a Server, such as the image trust check every
// dispatch makes.
//
// It is read on every call rather than cached, like loadHubConfig, so an
// operator who tightens a policy sees it apply to the next run and not after
// a restart. Process singletons that start once (the git proxy, the
// Kubernetes monitor, the host policy, the drivers) instead receive the
// configuration bootstrapExecutors loaded.
func controlPlaneConfig() (*config.Config, error) {
	dir, port := controlPlaneSource()
	if strings.TrimSpace(dir) == "" {
		return nil, errNoControlPlane
	}
	return loadHubConfigAt(dir, port)
}

// bootstrapHubConfig reads the configuration bootstrapExecutors starts the
// control plane from: dir's config.yaml with the overlay for port merged over
// it, which is what `cloop ui` itself loaded a moment earlier.
//
// An overlay that will not load does not make the hub read nothing. Each
// singleton read config.yaml before Task 20364, so this falls back to
// config.yaml alone and says so on stderr. That is never weaker than what a
// hub applied before overlays were honoured here. `cloop ui` refuses to start
// on an unreadable overlay anyway, so in practice the fallback covers only a
// file edited between the two reads, and embedders. A config.yaml that will
// not load either yields nil, which every consumer treats as "no policy
// stated", as each did before.
func bootstrapHubConfig(dir string, port int) *config.Config {
	if strings.TrimSpace(dir) == "" {
		return nil
	}
	cfg, err := loadHubConfigAt(dir, port)
	if err == nil {
		return cfg
	}
	fmt.Fprintf(os.Stderr, "ui: hub configuration with its instance overlay could not be read "+
		"(%v); starting the executors from %s alone\n", err, config.ConfigPath(dir))
	cfg, err = config.Load(dir)
	if err != nil {
		return nil
	}
	return cfg
}

// loadHubConfig reads this hub's own configuration.
//
// Deliberately re-read rather than cached: the settings panel writes
// config.yaml and the overlay, and a service built from a snapshot taken at
// boot would keep running under a policy an operator has already changed.
//
// It includes the per-instance overlay (Task 20318), because it has to
// answer with the configuration the hub is running under. Where two
// dashboards share a working directory, the bare project config is partly a
// different hub's policy.
func (s *Server) loadHubConfig() (*config.Config, error) {
	return loadHubConfigAt(s.WorkDir, s.Port)
}

// hubConfigOverlay returns this hub's per-instance overlay path, or "" when its
// configuration comes from .cloop/config.yaml alone.
//
// Existence is tested on each call rather than remembered from startup: an
// overlay created while the hub is running has to be found by the next write,
// which is the only way the settings panel can ever create one.
func (s *Server) hubConfigOverlay() string {
	if s.Port <= 0 {
		return ""
	}
	path := config.UIInstanceConfigPath(s.WorkDir, s.Port)
	if _, err := os.Stat(path); err != nil {
		return ""
	}
	return path
}

// governingConfig returns the configuration that governs dir for a setting
// both the hub and a project can state, such as retention, backup or
// dictation. That is the hub's configuration when dir is the hub's own
// directory, and the project's config.yaml otherwise.
//
// Without this, a sweep over the registered projects reaches the hub's own
// directory like any other and reads its bare config.yaml. An overlay's
// retention or backup policy then governs nothing, although the hub's own
// directory is the one it was written for.
func (s *Server) governingConfig(dir string) (*config.Config, error) {
	if isSameConfigDir(dir, s.WorkDir) {
		return s.loadHubConfig()
	}
	return config.Load(dir)
}

// governingConfigFor is governingConfig for code reached without a Server.
// The control plane recorded at bootstrap stands in for the Server.
func governingConfigFor(dir string) (*config.Config, error) {
	cpDir, port := controlPlaneSource()
	if isSameConfigDir(dir, cpDir) {
		return loadHubConfigAt(cpDir, port)
	}
	return config.Load(dir)
}

// isSameConfigDir reports whether a and b name the same directory. Unlike
// sameDir in stale_recovery.go, an empty path matches nothing: an unset
// control plane must not claim every project's configuration.
func isSameConfigDir(a, b string) bool {
	if strings.TrimSpace(a) == "" || strings.TrimSpace(b) == "" {
		return false
	}
	if filepath.Clean(a) == filepath.Clean(b) {
		return true
	}
	resolve := func(p string) string {
		abs, err := filepath.Abs(p)
		if err != nil {
			return filepath.Clean(p)
		}
		if real, err := filepath.EvalSymlinks(abs); err == nil {
			return real
		}
		return abs
	}
	return resolve(a) == resolve(b)
}

// hubSettingsSave is a hub settings write in progress. Its destination is
// chosen before anything is loaded.
type hubSettingsSave struct {
	// dir is the hub's working directory, whose config.yaml is written when
	// there is no overlay.
	dir string

	// overlay is the hub's .cloop/config.ui-<port>.yaml, or "" when its
	// settings live in config.yaml.
	overlay string

	// Config is the view to edit. With an overlay it is the merged view, so
	// that the panel edits what the hub is running under, and only the keys
	// the panel edits are written back, into the overlay. Without an overlay
	// it is config.yaml alone, so that file is only ever rewritten from
	// itself.
	Config *config.Config
}

// beginHubSettingsSave picks where a hub settings save goes and loads the view
// it edits. The caller holds hubConfigMu from before this call until after
// commit, so two saves cannot each load before the other writes.
//
// The order is the point (Task 20364). Loading first and choosing afterwards
// is how a merged view reaches config.yaml. An overlay removed between the
// two steps would leave the save holding this hub's overlay settings, with
// nowhere to write them but the shared file, which the other dashboard in
// the directory reads.
func (s *Server) beginHubSettingsSave() (*hubSettingsSave, error) {
	save := &hubSettingsSave{dir: s.WorkDir, overlay: s.hubConfigOverlay()}
	var (
		cfg *config.Config
		err error
	)
	if save.overlay != "" {
		cfg, err = s.loadHubConfig()
	} else {
		cfg, err = config.Load(s.WorkDir)
	}
	if err != nil {
		return nil, fmt.Errorf("load hub config: %w", err)
	}
	if cfg == nil {
		return nil, errors.New("load hub config: no configuration")
	}
	save.Config = cfg
	return save, nil
}

// commit writes the save. With an overlay, intoOverlay writes the panel's keys
// there and nothing else is touched. Without one, config.yaml is rewritten
// from the view beginHubSettingsSave loaded out of config.yaml itself.
func (h *hubSettingsSave) commit(intoOverlay func(path string) error) error {
	if h.overlay != "" {
		return intoOverlay(h.overlay)
	}
	return config.Save(h.dir, h.Config)
}
