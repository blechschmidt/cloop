package localprocess

// gitca.go places the hub's CA (Spec.GitCA, Task 20409) for a host process.

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/blechschmidt/cloop/pkg/executor"
)

// withGitCA returns the environment the workload runs with when spec carries
// the hub's CA: its own (or, for a nil Env, this process's) with
// http.<url>.sslCAInfo joined to its GIT_CONFIG_COUNT block, naming a copy of
// the bundle in a fresh 0700 directory. The directory is the caller's to
// remove. With no CA it returns spec.Env and "".
//
// A directory of the run's own rather than a shared, content-named file: a
// path another local user could create first is a path whose contents they
// choose, and the file decides which certificate the workload's git accepts
// for the proxy.
func withGitCA(spec executor.Spec) ([]string, string, error) {
	if spec.GitCA == nil {
		return spec.Env, "", nil
	}
	if err := spec.GitCA.Validate(); err != nil {
		return nil, "", err
	}
	dir, err := os.MkdirTemp("", "cloop-ca-")
	if err != nil {
		return nil, "", fmt.Errorf("localprocess: create a directory for the hub CA: %w", err)
	}
	path := filepath.Join(dir, executor.SandboxGitCAFileName)
	if err := os.WriteFile(path, spec.GitCA.PEM, 0o600); err != nil {
		removeGitCA(dir)
		return nil, "", fmt.Errorf("localprocess: write the hub CA: %w", err)
	}
	env := spec.Env
	if env == nil {
		env = os.Environ()
	}
	env, err = executor.WithGitConfig(append([]string(nil), env...), spec.GitCA.ConfigPairs(path))
	if err != nil {
		removeGitCA(dir)
		return nil, "", err
	}
	// For a harness whose model calls go to the hub's relay (Task 20435):
	// Node's own trust, which is process-wide; see executor.GitCA.
	return append(env, spec.GitCA.NodeEnv(path)...), dir, nil
}

// removeGitCA removes a directory withGitCA made. A certificate is public, so
// this is tidiness, not a wipe.
func removeGitCA(dir string) {
	if dir != "" {
		_ = os.RemoveAll(dir)
	}
}
