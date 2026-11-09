package localprocess

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/hostsandbox"
)

// metaSandboxDir records the private directory a sandboxed workload's
// temporary files and fresh home are in, so a hub process adopting the
// workload after a restart removes it when the workload ends.
const metaSandboxDir = "sandbox_dir"

// sandboxDirPrefix names the directories sandboxCommand makes. removeSandboxDir
// removes nothing else, whatever a handle row says.
const sandboxDirPrefix = "cloop-sandbox-"

// withSandboxDir adds a sandboxed workload's private directory to its handle
// row's metadata.
func withSandboxDir(meta map[string]string, dir string) map[string]string {
	if dir == "" {
		return meta
	}
	if meta == nil {
		meta = map[string]string{}
	}
	meta[metaSandboxDir] = dir
	return meta
}

// leaseEnvKeys are the variables spec's leases delivered. They are the
// workload's even when they share a name with one of the hub's own.
func leaseEnvKeys(spec executor.Spec) map[string]bool {
	keys := map[string]bool{}
	for _, b := range spec.Secrets {
		for _, k := range b.EnvKeys {
			keys[k] = true
		}
	}
	return keys
}

// sandboxCommand turns cmd, built to run spec's workload, into one that runs
// it in the host sandbox (Task 20480). It returns the private directory it
// made for the run, which the caller removes when the workload ends.
//
// What the hub put in spec.HostSandbox is what only the hub knows: the person's
// homes, their grants, where the harness is. What is added here is what only
// this driver knows: the lease files it was handed, the directory holding the
// hub CA it wrote, the binaries it starts, and the temporary directory it
// makes. Anything it cannot provide fails the start; nothing is started
// without the sandbox it asked for.
func sandboxCommand(cmd *exec.Cmd, spec executor.Spec, gitCADir string) (string, error) {
	sb := spec.HostSandbox
	if spec.WorkDir == "" {
		return "", fmt.Errorf("%w: a sandboxed workload needs a work directory", executor.ErrInvalidSpec)
	}
	if err := hostsandbox.Available(); err != nil {
		return "", fmt.Errorf("%w: this host cannot give the workload the host sandbox it needs: %w",
			executor.ErrUnsupported, err)
	}
	helper, err := hostsandbox.HelperPath()
	if err != nil {
		return "", fmt.Errorf("%w: %w", executor.ErrUnsupported, err)
	}
	env := cmd.Env
	if env == nil {
		env = os.Environ()
	}
	program, resolved, err := programPath(spec.Argv[0], env)
	if err != nil {
		return "", err
	}

	dir, err := os.MkdirTemp("", sandboxDirPrefix)
	if err != nil {
		return "", fmt.Errorf("localprocess: make the sandbox's private directory: %w", err)
	}
	ok := false
	defer func() {
		if !ok {
			removeSandboxDir(dir)
		}
	}()
	tmp := filepath.Join(dir, "tmp")
	if err := os.Mkdir(tmp, 0o700); err != nil {
		return "", fmt.Errorf("localprocess: make the sandbox's temporary directory: %w", err)
	}
	home := sb.Home
	if home == "" {
		home = filepath.Join(dir, "home")
		if err := os.Mkdir(home, 0o700); err != nil {
			return "", fmt.Errorf("localprocess: make the sandbox's home: %w", err)
		}
	}

	namespaces := hostsandbox.UsesNamespaces()
	p := hostsandbox.Policy{
		Argv:       spec.Argv,
		Path:       program,
		Dir:        spec.WorkDir,
		ReadWrite:  dedupe(append(append([]string{spec.WorkDir}, sb.ReadWrite...), home)),
		Devices:    hostsandbox.DefaultDevices,
		Namespaces: namespaces,
		Tmp:        tmp,
	}
	readOnly := append([]string{}, hostsandbox.SystemReadOnly...)
	readOnly = append(readOnly, hostsandbox.EtcReadOnly...)
	// The file /etc/resolv.conf is a link to, usually under /run: that file
	// alone, not the resolver's directory, whose sockets answer root with
	// every lookup on the host.
	if target, err := filepath.EvalSymlinks("/etc/resolv.conf"); err == nil && target != "/etc/resolv.conf" {
		readOnly = append(readOnly, target)
	}
	readOnly = append(readOnly, sb.ReadOnly...)
	// The program by the path it is exec'd at as well as the file that is: in
	// namespace mode a path under a private directory is bound back by name.
	readOnly = append(readOnly, helper, resolved, program)
	if gitCADir != "" {
		readOnly = append(readOnly, gitCADir)
	}
	for _, b := range spec.Secrets {
		if b.Dir != "" {
			readOnly = append(readOnly, b.Dir)
		}
		readOnly = append(readOnly, b.Files...)
	}
	p.ReadOnly = dedupe(readOnly)

	workloadTmp := tmp
	if namespaces {
		workloadTmp = "/tmp"
	}
	realHome, _ := os.UserHomeDir()
	env = onlyInheritable(env, leaseEnvKeys(spec), sb.PassEnv)
	env = hostsandbox.Environment(env, home, workloadTmp, realHome, append(append([]string{}, p.ReadWrite...), p.ReadOnly...))
	env = prependPath(env, sb.Path)
	// A harness that updates itself would install a copy into every person's
	// home, and its installation is read-only here anyway.
	env = append(env, "DISABLE_AUTOUPDATER=1")
	env = append(env, sb.Env...)
	cmd.Env = env
	if err := hostsandbox.Wrap(cmd, helper, p); err != nil {
		return "", fmt.Errorf("%w: %w", executor.ErrUnsupported, err)
	}
	ok = true
	return dir, nil
}

// onlyInheritable keeps, of what a sandboxed workload's environment inherited
// from the hub's own, only what hostsandbox.Inheritable allows and what pass
// names: not the hub's OpenAI key, a GitHub token the service holds for
// something else, a webhook URL or a database DSN. Inherited means it has the
// value this process has; what the hub set for the run, and what a lease
// delivered, is the workload's and stays.
func onlyInheritable(env []string, leased map[string]bool, pass []string) []string {
	passed := make(map[string]bool, len(pass))
	for _, n := range pass {
		passed[n] = true
	}
	out := make([]string, 0, len(env))
	for _, kv := range env {
		name, value, _ := strings.Cut(kv, "=")
		if !leased[name] && !passed[name] && !hostsandbox.Inheritable(name) {
			if own, ok := os.LookupEnv(name); ok && own == value {
				continue
			}
		}
		out = append(out, kv)
	}
	return out
}

// programPath resolves argv[0] on the workload's PATH, as exec would before
// the sandbox's PATH is in place: the absolute path the helper execs, and the
// file it is a link to, which the sandbox must let it execute.
func programPath(name string, env []string) (string, string, error) {
	path := name
	if !strings.Contains(name, "/") {
		path = ""
		for _, kv := range env {
			if v, ok := strings.CutPrefix(kv, "PATH="); ok {
				for _, d := range filepath.SplitList(v) {
					if d == "" || !filepath.IsAbs(d) {
						continue
					}
					candidate := filepath.Join(d, name)
					if fi, err := os.Stat(candidate); err == nil && !fi.IsDir() && fi.Mode()&0o111 != 0 {
						path = candidate
						break
					}
				}
			}
		}
		if path == "" {
			return "", "", fmt.Errorf("%w: %s is not on the workload's PATH", executor.ErrInvalidSpec, name)
		}
	}
	if !filepath.IsAbs(path) {
		abs, err := filepath.Abs(path)
		if err != nil {
			return "", "", fmt.Errorf("%w: resolve %s: %w", executor.ErrInvalidSpec, name, err)
		}
		path = abs
	}
	resolved := path
	if r, err := filepath.EvalSymlinks(path); err == nil {
		resolved = r
	}
	return path, resolved, nil
}

// prependPath puts dirs in front of env's PATH.
func prependPath(env, dirs []string) []string {
	if len(dirs) == 0 {
		return env
	}
	front := strings.Join(dirs, string(filepath.ListSeparator))
	out := make([]string, 0, len(env)+1)
	found := false
	for _, kv := range env {
		if v, ok := strings.CutPrefix(kv, "PATH="); ok {
			found = true
			if v != "" {
				kv = "PATH=" + front + string(filepath.ListSeparator) + v
			} else {
				kv = "PATH=" + front
			}
		}
		out = append(out, kv)
	}
	if !found {
		out = append(out, "PATH="+front)
	}
	return out
}

// dedupe keeps the first of each path, cleaned.
func dedupe(paths []string) []string {
	seen := make(map[string]bool, len(paths))
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		if p == "" {
			continue
		}
		p = filepath.Clean(p)
		if seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return out
}

// removeSandboxDir removes a directory sandboxCommand made. Only that: a path
// that is not absolute or not named like one is left alone, so a handle row
// can never point this at anything else.
func removeSandboxDir(dir string) {
	if dir == "" || !filepath.IsAbs(dir) || !strings.HasPrefix(filepath.Base(dir), sandboxDirPrefix) {
		return
	}
	_ = os.RemoveAll(dir)
}
