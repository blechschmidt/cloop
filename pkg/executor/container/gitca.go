package container

// gitca.go binds the hub's CA (Spec.GitCA, Task 20409) into a sandbox.

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/blechschmidt/cloop/pkg/executor"
)

// gitCADirPrefix names the staging directories.
const gitCADirPrefix = "cloop-ca-"

// stageGitCA writes spec's CA into a fresh directory of its own, to be bound
// read-only at executor.SandboxGitCADir, and returns spec with
// http.<url>.sslCAInfo for each of its URLs joined to its environment's
// GIT_CONFIG_COUNT block. With no CA it returns spec untouched and no mount.
//
// The bundle is world-readable (0644, in a 0755 directory) because it is a
// certificate and the sandbox's uid is not the hub's — the reverse of a lease
// directory, which is 0700 and handed to the sandbox user because it holds a
// credential. Read-only inside the container all the same: a workload that
// could rewrite the bundle could make its git trust any server for the
// proxy's URL.
func (e *Executor) stageGitCA(spec executor.Spec) (executor.Spec, *mount, string, error) {
	if spec.GitCA == nil {
		return spec, nil, "", nil
	}
	if err := spec.GitCA.Validate(); err != nil {
		return spec, nil, "", fmt.Errorf("container: %w", err)
	}
	// Where the engine can see it at the same path: StageDir for a driver
	// that does not share the engine's mount namespace (the remote agent's),
	// else where credential files are staged.
	base := strings.TrimSpace(e.opts.StageDir)
	if base == "" {
		base = secretStageBase()
	}
	dir, err := os.MkdirTemp(base, gitCADirPrefix)
	if err != nil {
		return spec, nil, "", fmt.Errorf("container: create a directory for the hub CA: %w", err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		removeGitCA(dir)
		return spec, nil, "", fmt.Errorf("container: open the hub CA directory to the sandbox: %w", err)
	}
	path := filepath.Join(dir, executor.SandboxGitCAFileName)
	if err := os.WriteFile(path, spec.GitCA.PEM, 0o644); err != nil {
		removeGitCA(dir)
		return spec, nil, "", fmt.Errorf("container: write the hub CA: %w", err)
	}
	// WriteFile honours the mode only when it creates the file, and the umask
	// may have narrowed it.
	if err := os.Chmod(path, 0o644); err != nil {
		removeGitCA(dir)
		return spec, nil, "", fmt.Errorf("container: set the hub CA's mode: %w", err)
	}
	// A copy of the environment: the Spec belongs to the caller, which
	// persists it.
	env, err := executor.WithGitConfig(append([]string(nil), spec.Env...),
		spec.GitCA.ConfigPairs(executor.SandboxGitCAFile))
	if err != nil {
		removeGitCA(dir)
		return spec, nil, "", err
	}
	spec.Env = env
	return spec, &mount{HostPath: dir, TargetPath: executor.SandboxGitCADir, ReadOnly: true}, dir, nil
}

// removeGitCA removes a directory stageGitCA made. A certificate is public, so
// this is tidiness, not a wipe.
func removeGitCA(dir string) {
	if dir != "" {
		_ = os.RemoveAll(dir)
	}
}
