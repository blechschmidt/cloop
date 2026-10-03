package gitprovision

// sandboxedrepo.go prepares a repository a sandbox could write for a git
// command run by something with more authority than that sandbox (Task 20367).
//
// The case it exists for is a remote device running its payloads in a
// container: the workload writes the tree and its .git through a bind mount,
// and after it exits the agent — a process on the device's host — commits and
// bundles the result. Every setting the workload left in .git/config that names
// a program would then run on the device's host, as the agent; executor.
// HardenedGitConfig switches those off. What configuration cannot switch off is
// where git looks for the repository itself, so that is pinned here:
//
//   - .git must be a real directory. A .git *file* is a "gitdir:" pointer, and
//     a symbolic link is one by another name; either would point the agent's
//     git at a repository of the workload's choosing — another project's on the
//     same device.
//   - objects/info/alternates and commondir are removed. Both make git read
//     objects (and, for commondir, refs and config) from another directory,
//     which a workload could aim at a different project's repository to pull
//     its objects into the bundle it returns. A tree cloop provisioned has
//     neither.
//   - GIT_DIR and GIT_WORK_TREE are set explicitly, so a core.worktree the
//     workload configured cannot point `git add --all` at a directory outside
//     the tree.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/blechschmidt/cloop/pkg/executor"
)

// redirectFiles are the files inside .git that make git read another
// directory's objects, refs or configuration.
var redirectFiles = []string{
	"commondir",
	filepath.Join("objects", "info", "alternates"),
	filepath.Join("objects", "info", "http-alternates"),
}

// SandboxedRepoEnv makes the repository at dir safe to run git in from outside
// the sandbox that wrote it, and returns the environment those git commands
// must run with: executor.GitEnv carrying executor.HardenedGitConfig for the
// repository's filter drivers plus extra, and GIT_DIR/GIT_WORK_TREE pinned.
//
// extra joins the same configuration block — see executor.GitEnv for why it
// cannot be appended as a second one.
func SandboxedRepoEnv(ctx context.Context, dir string, extra ...[2]string) ([]string, error) {
	gitDir := filepath.Join(dir, ".git")
	info, err := os.Lstat(gitDir)
	if err != nil {
		return nil, fmt.Errorf("%s is not a git repository: %v", dir, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("%s/.git is not a directory (a gitdir file or a link would point git at "+
			"a repository outside the tree), so it is not a repository cloop will run git in", dir)
	}
	for _, rel := range redirectFiles {
		p := filepath.Join(gitDir, rel)
		if _, err := os.Lstat(p); err == nil {
			if err := os.Remove(p); err != nil {
				return nil, fmt.Errorf("cannot remove %s, which would point git at another repository: %v", p, err)
			}
		} else if !errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("cannot inspect %s: %v", p, err)
		}
	}
	pinned := []string{"GIT_DIR=" + gitDir, "GIT_WORK_TREE=" + dir}
	drivers, err := FilterDrivers(ctx, dir, pinned)
	if err != nil {
		return nil, err
	}
	env := executor.GitEnv(append(executor.HardenedGitConfig(drivers), extra...)...)
	return append(env, pinned...), nil
}

// FilterDrivers lists the filter driver names the configuration of the
// repository at dir defines, so each can be neutralised with
// executor.HardenedGitConfig. Reading configuration runs nothing. extraEnv is
// appended to the closed base environment — GIT_DIR, for a caller pinning it —
// and extraConfig joins its configuration block (safe.directory, for a caller
// reading a repository its account does not own).
func FilterDrivers(ctx context.Context, dir string, extraEnv []string, extraConfig ...[2]string) ([]string, error) {
	cmd := exec.CommandContext(ctx, "git", "config", "--null", "--get-regexp", `^filter\.`)
	cmd.Env = append(executor.GitEnv(extraConfig...), extraEnv...)
	cmd.Dir = dir
	BoundChild(cmd)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		// Exit 1 with nothing printed is "no key matched".
		if stdout.Len() == 0 && strings.TrimSpace(stderr.String()) == "" {
			return nil, nil
		}
		return nil, fmt.Errorf("cannot read the repository's filter configuration in %s: %v: %s",
			dir, err, Collapse(stderr.String()))
	}
	seen := map[string]bool{}
	for _, rec := range strings.Split(stdout.String(), "\x00") {
		key, _, _ := strings.Cut(rec, "\n")
		key = strings.TrimSpace(key)
		const prefix = "filter."
		if len(key) <= len(prefix) || !strings.EqualFold(key[:len(prefix)], prefix) {
			continue
		}
		// filter.<driver>.<variable>: the driver name may itself contain dots,
		// so the variable is what follows the last one. The name is kept as
		// written, since subsection names are case-sensitive.
		rest := key[len(prefix):]
		dot := strings.LastIndex(rest, ".")
		if dot <= 0 {
			continue
		}
		name := rest[:dot]
		if strings.ContainsAny(name, "\x00\n") {
			continue
		}
		seen[name] = true
	}
	if len(seen) > executor.MaxFilterDrivers {
		return nil, fmt.Errorf("the repository in %s configures %d filter drivers, more than the %d cloop "+
			"will neutralise before running git there", dir, len(seen), executor.MaxFilterDrivers)
	}
	out := make([]string, 0, len(seen))
	for name := range seen {
		out = append(out, name)
	}
	sort.Strings(out)
	return out, nil
}
