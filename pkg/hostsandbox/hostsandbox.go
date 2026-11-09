// Package hostsandbox confines a workload the hub forks on its own host to
// the files of the person it acts for (Task 20480).
//
// # Why the host needs one
//
// The host-process executor forks `cloop run`, and the agent it starts, as the
// hub's own operating-system user. Before this package, nothing but that user's
// permissions stood between one person's agent and everything else the user
// can open: every other project on the hub, every other person's Claude login
// under the identity root, the lease directories in /dev/shm holding other
// runs' credentials, the environments of other runs in /proc, the hub's key
// file and its database. On a hub that runs as root, the Docker and systemd
// sockets made even that boundary moot. A hub with sign-in serves several
// people, so that was a hole between them, not a configuration choice.
//
// # What a sandboxed workload gets
//
// The sandbox is an allow-list enforced by the kernel:
//
//   - Landlock (Linux 6.2 or later, ABI 3) limits every file the workload
//     opens or truncates to the paths of its policy: the system's read-only
//     directories, a short list of /etc files, its project, its person's
//     Claude home and the home directory kept for them, its lease files, and a
//     private temporary directory. A path inside one it may write is opened
//     without following a link out of it. Landlock also stops it reading the
//     memory and environment of any process outside the sandbox, and on ABI 6
//     from signalling one or reaching its abstract sockets.
//   - no_new_privs, so no setuid or file-capability binary gives anything
//     back.
//   - On a hub running as root, fresh mount, PID and IPC namespaces: /tmp,
//     /var/tmp, /dev/shm and /run are private, which hides the daemon sockets
//     (Docker, containerd, systemd, D-Bus) that authorise a peer by its uid;
//     /dev/pts is an instance of its own; everything outside the writable
//     grants is read-only, which stops the chmod, chown and utimes Landlock
//     does not see; the workload sees only its own processes; and every
//     capability but the file-access ones is dropped from the bounding set.
//
// What it does not do is listed in docs/security/model.md ("The host
// sandbox"): the network is the host's, so a service listening on loopback is
// reachable, and below ABI 6 abstract sockets stay reachable and a non-root
// workload can still signal other processes of the hub's user.
//
// # How it is entered
//
// The driver (pkg/executor/localprocess) starts this binary as a helper with
// the policy in an environment variable. The helper applies the restrictions
// to itself and replaces itself with the workload, so the restrictions are the
// workload's from its first instruction and nothing it does can lift them.
// In namespace mode a first helper sets the namespaces up, stays behind as the
// namespace's init, and starts a second that restricts itself and execs.
package hostsandbox

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
)

// Arg is the argument that puts this binary into helper mode. It is entered
// before the CLI parses anything (main.go), like the isolation probe's.
const Arg = "__cloop-host-sandbox"

// EnvPolicy carries the policy to the helper. The helper removes it before it
// execs the workload, so the workload never sees it; it holds paths, never a
// credential.
const EnvPolicy = "CLOOP_HOST_SANDBOX_POLICY"

// ExitHelperFailed is the exit status of a helper that could not set the
// sandbox up. The workload never started: nothing it did is in the output.
const ExitHelperFailed = 125

// MinABI is the oldest Landlock ABI the sandbox runs on. Below ABI 3 Landlock
// does not handle truncate(2), so a workload could empty any file the hub's
// user can write — its database among them — without opening it; ABI 1 also
// refuses every rename between two directories, which breaks git. So a host
// without ABI 3 (Linux 6.2) has no sandbox to offer, not a weaker one.
const MinABI = 3

// ErrUnsupported says this host cannot give a workload the sandbox. A caller
// that needs one refuses the workload; it never runs it without.
var ErrUnsupported = errors.New("hostsandbox: unsupported")

// IsInvocation reports whether args — os.Args — ask for helper mode: exactly
// the binary and Arg, nothing after it. Anything else goes to the CLI.
func IsInvocation(args []string) bool {
	return len(args) == 2 && args[1] == Arg
}

// Policy is everything a helper needs to start one workload in the sandbox.
type Policy struct {
	// Argv is the workload: the program and its arguments. A program named
	// without a slash is looked up on the workload's PATH, unless Path names
	// it.
	Argv []string `json:"argv"`
	// Path is the file the helper execs, when the driver resolved it already:
	// the one its grants were made for, whatever the workload's PATH would
	// find first. Argv[0] is passed on as it is.
	Path string `json:"path,omitempty"`
	// Dir is the directory the workload starts in.
	Dir string `json:"dir,omitempty"`

	// ReadWrite are paths beneath which the workload may read, write, create,
	// rename and remove. Each must exist.
	ReadWrite []string `json:"read_write,omitempty"`
	// ReadOnly are paths beneath which the workload may read and execute.
	// One that does not exist is skipped: the defaults name directories some
	// distributions do not have.
	ReadOnly []string `json:"read_only,omitempty"`
	// Devices are device nodes (and the /dev/pts directory) the workload may
	// open for reading and writing. Missing ones are skipped.
	Devices []string `json:"devices,omitempty"`

	// Namespaces runs the workload in fresh mount, PID and IPC namespaces with
	// private /tmp, /var/tmp, /dev/shm and /run. Root only: it needs
	// CAP_SYS_ADMIN, which is also what makes it necessary.
	Namespaces bool `json:"namespaces,omitempty"`
	// Tmp is the directory the workload's temporary files go to. In namespace
	// mode it is bound over /tmp and /var/tmp; without, it is TMPDIR. What the
	// other lists grant beneath /tmp, /var/tmp, /dev/shm or /run — the run's
	// lease directory, the resolver configuration, a project kept under /tmp
	// — is bound back into the private directories in namespace mode.
	Tmp string `json:"tmp,omitempty"`

	// Stage is which helper this is in namespace mode: 0 for the one the
	// driver started, 1 for the one the namespace's init started. Set by the
	// helpers themselves; Wrap starts every policy at 0.
	Stage int `json:"stage,omitempty"`
}

// Validate checks a policy before anything is forked with it.
func (p Policy) Validate() error {
	if len(p.Argv) == 0 || strings.TrimSpace(p.Argv[0]) == "" {
		return fmt.Errorf("hostsandbox: policy has no program")
	}
	for _, list := range [][]string{p.ReadWrite, p.ReadOnly, p.Devices} {
		for _, path := range list {
			if !filepath.IsAbs(path) {
				return fmt.Errorf("hostsandbox: %q is not an absolute path", path)
			}
		}
	}
	if p.Dir != "" && !filepath.IsAbs(p.Dir) {
		return fmt.Errorf("hostsandbox: working directory %q is not absolute", p.Dir)
	}
	if p.Path != "" && !filepath.IsAbs(p.Path) {
		return fmt.Errorf("hostsandbox: program %q is not an absolute path", p.Path)
	}
	if p.Tmp != "" && !filepath.IsAbs(p.Tmp) {
		return fmt.Errorf("hostsandbox: temporary directory %q is not absolute", p.Tmp)
	}
	return nil
}

// Encode renders a policy as the value of EnvPolicy.
func (p Policy) Encode() (string, error) {
	b, err := json.Marshal(p)
	if err != nil {
		return "", fmt.Errorf("hostsandbox: encode policy: %w", err)
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

// Decode reads a policy from the value of EnvPolicy.
func Decode(s string) (Policy, error) {
	var p Policy
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return p, fmt.Errorf("hostsandbox: decode policy: %w", err)
	}
	if err := json.Unmarshal(b, &p); err != nil {
		return p, fmt.Errorf("hostsandbox: decode policy: %w", err)
	}
	return p, p.Validate()
}

// privateDirs are the directories namespace mode replaces with private ones.
var privateDirs = []string{"/tmp", "/var/tmp", "/dev/shm", "/run"}

// SystemReadOnly are the directories every sandboxed workload may read and
// execute: the system's programs and libraries, and the kernel's views of the
// process. Nothing here belongs to a person. /opt and /snap are not among
// them: software installs keep keys and whole hubs there, so an operator who
// needs a toolchain from one names it in executors.host_sandbox.read_only.
var SystemReadOnly = []string{
	"/usr", "/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32",
	"/nix/store",
	"/proc", "/sys",
	// Where some distributions keep the CA bundle /etc/ssl/certs links into.
	"/var/lib/ca-certificates",
}

// EtcReadOnly are the files and directories under /etc a sandboxed workload
// may read. An allow-list, because /etc on a hub's host holds what is not a
// workload's to read: shadow, the SSH host keys, TLS private keys, systemd
// drop-ins with credentials in them, and the key file a hub may load its root
// secret from.
var EtcReadOnly = []string{
	"/etc/passwd", "/etc/group", "/etc/hosts", "/etc/hostname", "/etc/resolv.conf",
	"/etc/nsswitch.conf", "/etc/host.conf", "/etc/gai.conf", "/etc/services",
	"/etc/protocols", "/etc/networks", "/etc/mtab", "/etc/machine-id",
	"/etc/ssl/certs", "/etc/ssl/openssl.cnf", "/etc/ca-certificates", "/etc/ca-certificates.conf",
	"/etc/pki/tls/certs", "/etc/pki/ca-trust", "/etc/crypto-policies",
	"/etc/localtime", "/etc/timezone", "/etc/locale.alias", "/etc/locale.conf", "/etc/default/locale",
	"/etc/ld.so.cache", "/etc/ld.so.conf", "/etc/ld.so.conf.d", "/etc/alternatives",
	"/etc/environment", "/etc/profile", "/etc/profile.d", "/etc/bash.bashrc", "/etc/inputrc",
	"/etc/shells", "/etc/terminfo", "/etc/magic", "/etc/mime.types", "/etc/gnutls",
	"/etc/os-release", "/etc/lsb-release", "/etc/debian_version", "/etc/alpine-release",
	"/etc/gitconfig", "/etc/ssh/ssh_config", "/etc/ssh/ssh_config.d", "/etc/ssh/ssh_known_hosts",
	"/etc/npmrc", "/etc/pip.conf", "/etc/fonts", "/etc/java", "/etc/subuid", "/etc/subgid",
}

// DefaultDevices are the device nodes every workload may open. Not /dev/pts:
// the host's terminals are there, an administrator's SSH sessions among them,
// and a workload that can open one reads what is typed into it. In namespace
// mode the workload gets a terminal instance of its own instead.
var DefaultDevices = []string{
	"/dev/null", "/dev/zero", "/dev/full", "/dev/random", "/dev/urandom", "/dev/tty",
	// A new terminal, reached through its master with TIOCGPTPEER as openpty
	// does: opening /dev/ptmx makes one and reaches none of the others.
	"/dev/ptmx",
}

// hubCredentialVars are the environment variables that hold the hub's own
// credentials. A workload never needs one: the root key unseals every stored
// secret, the static token is an administrator outside RBAC, and a notifier
// URL posts to a channel the operator chose. The hub reads them from its own
// environment, which a host workload would otherwise inherit whole.
var hubCredentialVars = map[string]bool{
	"CLOOP_SECRET_KEY":               true,
	"CLOOP_SECRET_KEY_FILE":          true,
	"CLOOP_SECRET_KEY_PREVIOUS":      true,
	"CLOOP_SECRET_KEY_PREVIOUS_FILE": true,
	// systemd's credentials directory, where LoadCredential= puts the key.
	"CREDENTIALS_DIRECTORY": true,
	"CLOOP_UI_TOKEN":        true,
	// The hub's OIDC client secret, which `cloop hub doctor` tells operators
	// to keep out of config.yaml and in the environment.
	"CLOOP_OIDC_CLIENT_SECRET": true,
}

// hubCredentialPrefixes are prefixes of further such variables:
// notifications.webhooks[].url_env must name a CLOOP_NOTIFY_ variable.
var hubCredentialPrefixes = []string{"CLOOP_NOTIFY_"}

// IsHubCredentialVar reports whether name is one of the hub's own credential
// variables, which no workload inherits.
func IsHubCredentialVar(name string) bool {
	if hubCredentialVars[name] {
		return true
	}
	for _, p := range hubCredentialPrefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// HubCredentialVars lists the exact names IsHubCredentialVar matches, for a
// caller that scrubs by name.
func HubCredentialVars() []string {
	out := make([]string, 0, len(hubCredentialVars))
	for k := range hubCredentialVars {
		out = append(out, k)
	}
	return out
}

// WithoutHubCredentials returns env without the hub's own credential
// variables, except those named in keep: a lease may legitimately deliver a
// variable of the same name, and what a lease delivered is the workload's.
func WithoutHubCredentials(env []string, keep map[string]bool) []string {
	out := make([]string, 0, len(env))
	for _, kv := range env {
		name, _, _ := strings.Cut(kv, "=")
		if IsHubCredentialVar(name) && !keep[name] {
			continue
		}
		out = append(out, kv)
	}
	return out
}

// LooksLikeCredential reports whether an environment variable's name says it
// holds a credential: a token, a secret, a password, a key. A sandboxed
// workload does not inherit one of those from the hub's own environment —
// they are the hub operator's, and a person's run gets its credentials from
// grants.
func LooksLikeCredential(name string) bool {
	n := strings.ToUpper(name)
	for _, part := range []string{"SECRET", "TOKEN", "PASSWORD", "PASSWD", "PASSPHRASE", "CREDENTIAL",
		"PRIVATE_KEY", "ACCESS_KEY", "APIKEY", "API_KEY"} {
		if strings.Contains(n, part) {
			return true
		}
	}
	return strings.HasSuffix(n, "_KEY") || strings.HasSuffix(n, "_KEYS")
}

// inheritable are the variables a sandboxed workload may inherit from the
// hub's own environment: the locale, the terminal, who it runs as, the
// network's proxies and CA bundles, and the settings of the toolchains and
// the harness that hold no credential. Everything else the hub was started
// with stays with the hub — a webhook URL, a database DSN, a token a unit
// file set for something else — unless executors.host_sandbox.pass_env names
// it. What the hub sets for the run, and what a lease delivers, is not
// inherited and is not filtered.
var inheritable = map[string]bool{
	"PATH": true, "LANG": true, "LANGUAGE": true, "TZ": true, "TERM": true, "COLORTERM": true,
	"USER": true, "LOGNAME": true, "SHELL": true, "HOSTNAME": true,
	"HTTP_PROXY": true, "HTTPS_PROXY": true, "NO_PROXY": true, "ALL_PROXY": true, "FTP_PROXY": true,
	"http_proxy": true, "https_proxy": true, "no_proxy": true, "all_proxy": true, "ftp_proxy": true,
	"SSL_CERT_FILE": true, "SSL_CERT_DIR": true, "NODE_EXTRA_CA_CERTS": true, "REQUESTS_CA_BUNDLE": true,
	"CURL_CA_BUNDLE": true, "GOPROXY": true, "GOSUMDB": true, "GONOSUMDB": true, "GONOPROXY": true,
	"GOPRIVATE": true, "GOFLAGS": true, "GOTOOLCHAIN": true, "GO111MODULE": true, "GOAMD64": true,
	"CGO_ENABLED": true, "ANTHROPIC_BASE_URL": true, "ANTHROPIC_MODEL": true, "ANTHROPIC_SMALL_FAST_MODEL": true,
}

// inheritablePrefixes are families of such settings.
var inheritablePrefixes = []string{"LC_", "CLAUDE_CODE_", "ANTHROPIC_DEFAULT_", "DISABLE_"}

// Inheritable reports whether a sandboxed workload inherits a variable of
// this name from the hub's environment by default. A name that looks like a
// credential never does.
func Inheritable(name string) bool {
	if LooksLikeCredential(name) {
		return false
	}
	if inheritable[name] {
		return true
	}
	for _, p := range inheritablePrefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// sessionVars point at the hub user's session: an SSH agent holding its keys,
// a desktop it is logged in to, a container daemon. A sandboxed workload gets
// none of them.
var sessionVars = []string{
	"SSH_AUTH_SOCK", "SSH_AGENT_PID", "GPG_AGENT_INFO", "KRB5CCNAME",
	"DBUS_SESSION_BUS_ADDRESS", "DBUS_SYSTEM_BUS_ADDRESS",
	"DISPLAY", "WAYLAND_DISPLAY", "XAUTHORITY",
	"DOCKER_HOST", "CONTAINER_HOST", "DOCKER_CONFIG",
	"XDG_RUNTIME_DIR", "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME",
	"XDG_CONFIG_DIRS", "XDG_DATA_DIRS",
}

// Environment returns the environment a sandboxed workload starts with: env
// with HOME and TMPDIR replaced, the variables naming the hub user's session
// removed, and every other variable whose value points into the hub user's
// home directory (realHome) somewhere the policy does not grant (granted)
// removed — a GOPATH or a cache directory there is not the workload's to
// write, and would only fail. A variable pointing into a granted path, such as
// CLAUDE_CONFIG_DIR naming the person's own Claude home, stays. PATH is kept as
// it is: an entry the sandbox does not grant fails to execute, and the
// harness's own directory is one the caller granted.
func Environment(env []string, home, tmp, realHome string, granted []string) []string {
	drop := make(map[string]bool, len(sessionVars)+2)
	for _, v := range sessionVars {
		drop[v] = true
	}
	drop["HOME"] = true
	drop["TMPDIR"] = true
	realHome = filepath.Clean(realHome)
	out := make([]string, 0, len(env)+3)
	for _, kv := range env {
		name, value, ok := strings.Cut(kv, "=")
		if !ok || drop[name] || name == EnvPolicy {
			continue
		}
		if name != "PATH" && realHome != "" && realHome != "/" && pointsOutside(value, realHome, granted) {
			continue
		}
		out = append(out, kv)
	}
	if home != "" {
		out = append(out, "HOME="+home)
	}
	if tmp != "" {
		out = append(out, "TMPDIR="+tmp)
	}
	return out
}

// pointsOutside reports whether value is a path, or a colon-separated list
// with a path, beneath dir and beneath none of granted.
func pointsOutside(value, dir string, granted []string) bool {
	for _, part := range strings.Split(value, ":") {
		part = strings.TrimSpace(part)
		if part == "" || !filepath.IsAbs(part) {
			continue
		}
		part = filepath.Clean(part)
		if !within(part, dir) {
			continue
		}
		ok := false
		for _, g := range granted {
			if within(part, filepath.Clean(g)) {
				ok = true
				break
			}
		}
		if !ok {
			return true
		}
	}
	return false
}

// within reports whether path is dir or beneath it.
func within(path, dir string) bool {
	return path == dir || strings.HasPrefix(path, dir+string(filepath.Separator))
}

// underAny reports whether path is beneath one of dirs (not equal to it).
func underAny(path string, dirs []string) bool {
	path = filepath.Clean(path)
	for _, d := range dirs {
		if strings.HasPrefix(path, d+"/") {
			return true
		}
	}
	return false
}
