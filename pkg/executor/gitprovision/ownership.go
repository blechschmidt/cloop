package gitprovision

// ownership.go: git's ownership check against the one owner it protects
// nothing from (Task 20385).

import (
	"os"
	"path/filepath"
	"syscall"

	"github.com/blechschmidt/cloop/pkg/executor"
)

// RootOwnedTrust returns the configuration that lets git work in dir when dir
// is owned by root and this process is not — the shape of a volume a platform
// created for a workload. A Pod's emptyDir is owned by root whatever runAsUser
// says; fsGroup changes its group, never its owner. Nil for any other dir.
//
// git refuses, since 2.35.2, to run in a work tree another user owns, because
// that user's .git/config could run code as you — "detected dubious ownership".
// It is a defence against a *peer*. Root is not one: it can already run
// anything as anyone, so trusting a directory root owns grants nothing root
// could not take. The first live Kubernetes run found every workspace fetch
// refused there, because the provisioner runs as the harness's uid in a
// root-owned /workspace.
//
// Trust goes to dir alone, by its exact path, and only while root owns it. A
// directory another non-root user owns stays refused.
func RootOwnedTrust(dir string) [][2]string {
	if os.Geteuid() == 0 {
		return nil // root's own git has nothing to be refused
	}
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		return nil
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != 0 {
		return nil
	}
	return [][2]string{{"safe.directory", filepath.Clean(dir)}}
}

// localGitEnv is the closed environment for a local git command in dir: the
// base block, with dir trusted when root owns it (RootOwnedTrust), and the
// repository's own hooks and filesystem monitor off (noRepoPrograms).
func localGitEnv(dir string) []string {
	return executor.GitEnv(append(RootOwnedTrust(dir), noRepoPrograms...)...)
}

// noRepoPrograms keep a repository's own configuration and hooks from running
// a program inside a git command cloop runs there (Task 20484). A checkout
// kept between runs — on a device, or on an executor pool runner's volume —
// was last written by a run, and a hook it planted (reference-transaction
// runs on every fetch that moves a ref) would run with the next fetch's
// credential in its environment. No provisioning step needs a hook or a
// monitor; core.hooksPath=/dev/null and core.fsmonitor=false outrank the
// repository's own file.
var noRepoPrograms = [][2]string{{"core.hooksPath", "/dev/null"}, {"core.fsmonitor", "false"}}
