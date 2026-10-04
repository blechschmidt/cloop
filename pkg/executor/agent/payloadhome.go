package agent

// payloadhome.go gives a host-mode payload a home directory of its own,
// beside its working tree rather than inside it (Task 20371).
//
// A Spec that carries an environment — every project holding a secret grant,
// since the hub composes the lease over a nil base — names no HOME, and the
// inner driver's floor (localprocess.withRunnableEnv) then makes the workload's
// own directory its home. On a device that directory is the checkout. So the
// harness wrote its own state into the repository it was working on: Claude
// Code's .claude.json and .claude/ (its session transcript among them), and
// cloop's .config/cloop/costs.jsonl. The first feature to run on a real device
// returned all of it — a feature's write-back commits whatever the run left
// uncommitted — and it landed on the feature's branch on the hub, one pull
// request away from the project's repository. A harness that runs `git add -A`
// itself would have committed it on any run.
//
// The fix is where the payload lives, not a list of names to ignore: a list
// would have to know every file every harness will ever write. A hidden
// sibling of the tree is inside this agent's root, so it is as confined as the
// tree itself; it is per project, because the device directory is, so a
// harness's history persists between that project's runs the way a
// developer's home does, without one project's transcripts being readable by
// another's harness.
//
// A Spec with no environment (nil) inherits this process's, HOME included,
// and is left alone: a device whose operator logged the agent's user into a
// harness relies on that home to find the login. A Spec that names a HOME
// keeps it.

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// payloadHomeSuffix names a tree's home directory: "<dir>" gets ".<dir>.home".
const payloadHomeSuffix = ".home"

// payloadHomeFor returns the home directory for a payload whose tree is
// workDir, or "" when workDir is the agent's root itself — a payload that runs
// in the root has no directory of its own to put a home beside.
func payloadHomeFor(root, workDir string) string {
	workDir = filepath.Clean(workDir)
	if workDir == filepath.Clean(root) {
		return ""
	}
	return filepath.Join(filepath.Dir(workDir), "."+filepath.Base(workDir)+payloadHomeSuffix)
}

// withPayloadHome returns env with HOME set to the payload's own home
// directory, creating it, when env is an explicit environment that names no
// HOME. env is never modified in place.
func withPayloadHome(env []string, root, workDir string) ([]string, error) {
	if env == nil {
		return env, nil
	}
	for _, kv := range env {
		if strings.HasPrefix(kv, "HOME=") {
			return env, nil
		}
	}
	home := payloadHomeFor(root, workDir)
	if home == "" {
		return env, nil
	}
	if err := containedIn(root, home); err != nil {
		return env, err
	}
	if err := ensurePayloadHome(home); err != nil {
		return env, err
	}
	out := make([]string, 0, len(env)+1)
	out = append(out, env...)
	return append(out, "HOME="+home), nil
}

// ensurePayloadHome makes home a directory of mode 0700, reusing one an
// earlier run left. It never follows a link: a payload's previous run could
// have put one where its home goes, and a chmod or a HOME through it would land
// wherever it points. Anything but a real directory there is removed first —
// the link itself, never what it names.
func ensurePayloadHome(home string) error {
	info, err := os.Lstat(home)
	switch {
	case err == nil && info.IsDir():
		// MkdirAll would leave an existing directory's mode alone, and a home
		// a later run reuses must not have been loosened in between.
		if err := os.Chmod(home, 0o700); err != nil {
			return fmt.Errorf("agent: restrict the workload's home directory %s: %w", home, err)
		}
		return nil
	case err == nil:
		if err := os.Remove(home); err != nil {
			return fmt.Errorf("agent: %s is not a directory and cannot be replaced by the workload's home: %w",
				home, err)
		}
	case !errors.Is(err, fs.ErrNotExist):
		return fmt.Errorf("agent: inspect the workload's home directory %s: %w", home, err)
	}
	if err := os.Mkdir(home, 0o700); err != nil {
		return fmt.Errorf("agent: create the workload's home directory %s: %w", home, err)
	}
	return nil
}
