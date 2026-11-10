package executor

import "path/filepath"

// runnerCacheVars are the package-manager caches a runner's builds are
// pointed at beneath a cache directory (Task 20484), each in a directory of
// its own. Only caches that hold what was downloaded or built — never a
// login: no home, no config file, no CARGO_HOME or GRADLE_USER_HOME, which
// keep credentials beside their caches.
var runnerCacheVars = [][2]string{
	{"GOMODCACHE", "go-mod"},
	{"GOCACHE", "go-build"},
	{"npm_config_cache", "npm"},
	{"YARN_CACHE_FOLDER", "yarn"},
	{"PIP_CACHE_DIR", "pip"},
	{"UV_CACHE_DIR", "uv"},
}

// CacheEnv is the environment that points a workload's package managers at
// dir: what an executor pool runner's controller puts on the runner
// container, for workloads that inherit the agent's environment, and what the
// agent adds to one that carries its own.
func CacheEnv(dir string) []string {
	out := make([]string, 0, len(runnerCacheVars))
	for _, v := range runnerCacheVars {
		out = append(out, v[0]+"="+filepath.Join(dir, v[1]))
	}
	return out
}

// scratchCacheVars are caches that would otherwise grow inside a workload's
// home: where an executor pool runner keeps homes in memory (Task 20484),
// they go to its disk-backed scratch instead, which goes with the Pod. Some
// of them can hold a login a build tool wrote — never the volume's to keep.
var scratchCacheVars = [][2]string{
	{"XDG_CACHE_HOME", "xdg"},
	{"GRADLE_USER_HOME", "gradle"},
	{"CARGO_HOME", "cargo"},
	{"RUSTUP_HOME", "rustup"},
}

// ScratchCacheEnv points those caches at directories beneath dir.
func ScratchCacheEnv(dir string) []string {
	out := make([]string, 0, len(scratchCacheVars))
	for _, v := range scratchCacheVars {
		out = append(out, v[0]+"="+filepath.Join(dir, v[1]))
	}
	return out
}

// ScratchCacheVarNames are the variables ScratchCacheEnv sets.
func ScratchCacheVarNames() []string {
	out := make([]string, 0, len(scratchCacheVars))
	for _, v := range scratchCacheVars {
		out = append(out, v[0])
	}
	return out
}
