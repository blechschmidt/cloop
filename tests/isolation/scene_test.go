package isolation_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/http/cgi"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/secretbroker/secretbrokertest"
)

// hubToken protects every hub the suite starts: a hub without sign-in would
// serve a run on its own host with no credential at all, which is a limit of
// open hubs (docs/security/model.md), not what this suite is about.
const hubToken = "isolation-suite-hub-token-0123456789"

// executor kinds the suite runs against.
const (
	onHost      = "host"
	onDevice    = "device"
	inContainer = "container"
)

// imageBase is the pinned base of the container image, the flagship's.
const imageBase = "alpine@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc"

// sandboxUID owns the projects when the test runs as root: the container
// executor runs a workload as its project directory's owner, never as root.
const sandboxUID = 1000

// lockedBuffer collects a process's output.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// scene is a hub, its three projects and the executor they share.
type scene struct {
	t       *testing.T
	kind    string
	runtime string // the container's OCI runtime
	bin     string
	hostile string
	root    string
	home    string
	env     []string
	hubDir  string
	port    int
	// base is where the test reaches the hub; runBase where a run does.
	base, runBase string

	vault, mallory, library string
	// canary is the content of vault's src/vault.go, libraryCanary of
	// library's README.md.
	canary, libraryCanary string
	vaultEnv, libraryEnv  string

	hub    *exec.Cmd
	hubLog *lockedBuffer

	agent      *exec.Cmd
	agentLog   *lockedBuffer
	deviceRoot string
	executorID string

	image string
	// forge serves the projects' origins a device fetches them from.
	forge *gitForge
	// baseConfig is the hub's .cloop/config.yaml as `cloop init` wrote it.
	baseConfig string
	// hubEnv is the hub process's own environment on top of env.
	hubEnv []string

	// github is the fake GitHub behind the hub's git proxy, on the scenes
	// whose runs reach the proxy on loopback; gitPort is the proxy's port.
	github  *githubUpstream
	gitPort int
	// egressPort is the egress proxy's port on the hub's host and a device.
	egressPort int
	// deviceAddr is the address the device reaches the hub's egress proxy
	// at: this machine's own, which is not loopback.
	deviceAddr string
}

// githubUpstream is a fake GitHub, its App API and its forge, which the hub
// reaches as github.com through a CONNECT proxy and trusts through a test CA.
// vault and mallory each have a repository there, and a grant of their own.
type githubUpstream struct {
	ca      *secretbrokertest.CA
	gh      *secretbrokertest.GitHub
	forge   *secretbrokertest.Forge
	connect *secretbrokertest.ConnectProxy
	api     *httptest.Server
}

func newGitHubUpstream(t *testing.T) *githubUpstream {
	t.Helper()
	secretbrokertest.GitTools(t)
	u := &githubUpstream{ca: secretbrokertest.NewCA(t)}
	u.gh = secretbrokertest.NewGitHub(secretbroker.InstallationRepo{ID: 7, FullName: "acme/vault"},
		secretbroker.InstallationRepo{ID: 8, FullName: "acme/mallory"})
	u.forge = secretbrokertest.NewForgeWithCert(t, "127.0.0.1:0", u.gh, u.ca.Issue(t, "github.com").TLS,
		"acme/vault", "acme/mallory")
	u.connect = secretbrokertest.NewConnectProxy(t, "127.0.0.1:0", u.forge.Addr)
	local := u.ca.Issue(t, "127.0.0.1", "localhost")
	u.api = httptest.NewUnstartedServer(u.gh.APIHandler())
	u.api.TLS = &tls.Config{Certificates: []tls.Certificate{local.TLS}}
	u.api.StartTLS()
	t.Cleanup(u.api.Close)
	return u
}

func newScene(t *testing.T, kind, ociRuntime string) *scene {
	t.Helper()
	for _, tool := range []string{"git"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s is not installed", tool)
		}
	}
	root, err := os.MkdirTemp("", "iso-")
	if err != nil {
		t.Fatal(err)
	}
	if resolved, err := filepath.EvalSymlinks(root); err == nil {
		root = resolved
	}
	// Every directory a sandbox's account has to walk through: the
	// container's runs as sandboxUID.
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatal(err)
	}
	s := &scene{
		t: t, kind: kind, runtime: ociRuntime, root: root,
		bin:     cloopBinary(t, kind == inContainer),
		hostile: hostileBinary(t),
		home:    filepath.Join(root, "home"),
		hubDir:  filepath.Join(root, "hub"),
		vault:   filepath.Join(root, "vault"),
		mallory: filepath.Join(root, "mallory"),
		library: filepath.Join(root, "library"),
		hubLog:  &lockedBuffer{},
	}
	t.Cleanup(s.teardown)
	for _, d := range []string{s.home, s.hubDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	gitconfig := filepath.Join(s.home, ".gitconfig")
	writeFile(t, gitconfig, "[user]\n\tname = Isolation\n\temail = isolation@example.com\n[init]\n\tdefaultBranch = main\n"+
		"[safe]\n\tdirectory = *\n")

	hubBin := filepath.Join(root, "hub-bin")
	if err := os.MkdirAll(hubBin, 0o755); err != nil {
		t.Fatal(err)
	}
	copyFile(t, s.hostile, filepath.Join(hubBin, "claude"), 0o755)

	env := make([]string, 0, len(os.Environ())+12)
	for _, kv := range os.Environ() {
		name, _, _ := strings.Cut(kv, "=")
		switch {
		case strings.HasPrefix(name, "CLOOP_"), strings.HasPrefix(name, "CLAUDE_"),
			strings.HasPrefix(name, "ANTHROPIC_"), strings.HasPrefix(name, "COPILOT_"),
			name == "GH_TOKEN", name == "GITHUB_TOKEN", name == "PATH", name == "HOME":
			continue
		}
		env = append(env, kv)
	}
	s.env = append(env,
		"PATH="+hubBin+string(os.PathListSeparator)+os.Getenv("PATH"),
		"HOME="+s.home,
		"CLOOP_HOME="+filepath.Join(s.home, ".cloop"),
		"CLOOP_UI_TOKEN="+hubToken,
		// The broker, on purpose and the same everywhere: a sandboxed run's
		// harness credential is a grant, and a key inherited from whoever
		// runs the suite would change what the hub does.
		"CLOOP_SECRET_KEY=isolation-suite-root-key-0123456789abcdef",
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL="+gitconfig,
		"GIT_TERMINAL_PROMPT=0",
		"NO_COLOR=1",
	)
	s.port = freePort(t)
	s.base = fmt.Sprintf("http://127.0.0.1:%d", s.port)
	s.runBase = s.base
	if kind == inContainer {
		ip := hostAddress(t)
		s.runBase = fmt.Sprintf("http://%s:%d", ip, s.port)
	}

	if kind == onDevice {
		s.forge = newGitForge(t, root)
		s.deviceAddr = hostAddress(t)
	}
	s.egressPort = freePort(t)
	if kind != inContainer {
		s.github = newGitHubUpstream(t)
		s.gitPort = freePort(t)
		// The forge answers as github.com through the CONNECT proxy, with a
		// certificate the test's CA signed: the hub trusts that CA. Loopback
		// — the App API — is never proxied.
		s.hubEnv = []string{"HTTPS_PROXY=http://" + s.github.connect.Addr, "https_proxy=http://" + s.github.connect.Addr,
			"SSL_CERT_FILE=" + s.github.ca.CertFile}
	}
	s.canary = "VAULT-CANARY-" + randomHex(t, 12)
	s.libraryCanary = "LIBRARY-CANARY-" + randomHex(t, 12)
	s.vaultEnv = "VAULT_API_KEY=vault-" + randomHex(t, 16)
	s.libraryEnv = "LIBRARY_API_KEY=library-" + randomHex(t, 16)
	s.makeProject(s.vault, "Keep the vault's secrets", map[string]string{
		"README.md":          "# vault\n\nThe project the hostile run attacks.\n",
		"src/vault.go":       "package vault\n\n// " + s.canary + "\nconst Secret = \"" + s.canary + "\"\n",
		"src/remove-me.txt":  "a hostile run must not delete this\n",
		".env":               s.vaultEnv + "\n",
		"services/notes.txt": "nested\n",
	})
	writeFile(t, filepath.Join(s.vault, ".cloop", "victim-canary.txt"), "VAULT-CLOOP-CANARY-"+randomHex(t, 8)+"\n")
	s.makeProject(s.library, "Publish the shared library", map[string]string{
		"README.md": "# library\n\n" + s.libraryCanary + "\n",
		".env":      s.libraryEnv + "\n",
	})
	s.makeProject(s.mallory, "Ship mallory's feature", map[string]string{
		"README.md": "# mallory\n",
	})

	s.cloop(s.hubDir, "init", "--provider", "mock", "--skip-clarify", "hub")
	base, err := os.ReadFile(filepath.Join(s.hubDir, ".cloop", "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	s.baseConfig = string(base)
	if kind == inContainer {
		s.image = s.buildImage()
	}
	s.writeHubConfig()
	if kind != onHost {
		// A sandboxed claudecode run is refused without a Claude credential
		// granted to its project (the stand-in ignores it). Made of parts so
		// no literal has a token's shape.
		token := "sk-" + "ant-oat01-" + strings.Repeat("isolation", 4) + "Qx7_Lm2-Pz9"
		s.cloop(s.hubDir, "secret", "mint", "isolation-claude", "--kind", "env",
			"--value", `{"CLAUDE_CODE_OAUTH_TOKEN":"`+token+`"}`)
		for _, p := range []string{s.vault, s.mallory, s.library} {
			s.cloop(s.hubDir, "secret", "grant", "isolation-claude", "--to", "project:"+p,
				"--env-keys", "CLAUDE_CODE_OAUTH_TOKEN", "--ttl", "4h")
		}
	}
	// mallory's egress: one address nothing listens at. What matters is the
	// session it is given, not where it may go.
	s.cloop(s.hubDir, "egress", "grant", "--to", "project:"+s.mallory, "--cidrs", "192.0.2.10/32",
		"--ports", "443", "--ttl", "4h")
	if s.github != nil {
		var app map[string]any
		if err := json.Unmarshal(secretbrokertest.AppPayload(501, 502), &app); err != nil {
			t.Fatal(err)
		}
		app["base_url"] = s.github.api.URL
		payload, _ := json.Marshal(app)
		appFile := filepath.Join(root, "app.json")
		writeFile(t, appFile, string(payload))
		s.cloop(s.hubDir, "secret", "mint", "isolation-app", "--kind", "github_app", "--file", appFile)
		for p, repo := range map[string]string{s.vault: "acme/vault", s.mallory: "acme/mallory"} {
			s.cloop(s.hubDir, "secret", "grant", "isolation-app", "--to", "project:"+p, "--repos", repo,
				"--permissions", "contents:write", "--ttl", "4h")
		}
	}
	return s
}

// writeHubConfig writes the hub's configuration: what `cloop init` wrote,
// the address runs reach the hub at, the executor under test, and the
// projects optOut names in executors.host_sandbox.opt_out. The hub reads it
// at every dispatch.
func (s *scene) writeHubConfig(optOut ...string) {
	cfg := fmt.Sprintf("\nui:\n    external_url: %s\n", s.runBase)
	cfg += "executors:\n"
	switch s.kind {
	case onHost:
		// The default: the hub runs harnesses on its own host, in the host
		// sandbox once it serves a second project (executors.host_sandbox
		// mode auto).
		cfg += "    allow_host_process: true\n"
	case onDevice:
		cfg += "    allow_host_process: false\n"
	case inContainer:
		cfg += fmt.Sprintf("    allow_host_process: false\n    container:\n        enabled: true\n"+
			"        runtime: docker\n        image: %s\n        network: bridge\n", s.image)
		if s.runtime != "" && s.runtime != "runc" {
			cfg += "        oci_runtime: " + s.runtime + "\n"
		}
	}
	switch s.kind {
	case onHost:
		cfg += fmt.Sprintf("    egress:\n        enabled: true\n        listen_addr: 127.0.0.1:%d\n", s.egressPort)
	case onDevice:
		// A device is never sent to a loopback address: the hub takes it
		// for its own. The device here shares the machine, at its address.
		cfg += fmt.Sprintf("    egress:\n        enabled: true\n        listen_addr: %s:%d\n"+
			"        advertise_addr: %s:%d\n", s.deviceAddr, s.egressPort, s.deviceAddr, s.egressPort)
	case inContainer:
		// A container reaches it at its bridge's gateway.
		cfg += "    egress:\n        enabled: true\n        listen_addr: \"0.0.0.0:0\"\n"
	}
	if s.github != nil {
		cfg += fmt.Sprintf("    git_proxy:\n        enabled: true\n        listen_addr: 127.0.0.1:%d\n        tls: auto\n",
			s.gitPort)
	}
	if len(optOut) > 0 {
		cfg += "    host_sandbox:\n        opt_out:\n"
		for _, p := range optOut {
			cfg += "            - " + p + "\n"
		}
	}
	path := filepath.Join(s.hubDir, ".cloop", "config.yaml")
	if err := os.WriteFile(path+".tmp", []byte(s.baseConfig+cfg), 0o600); err != nil {
		s.t.Fatal(err)
	}
	if err := os.Rename(path+".tmp", path); err != nil {
		s.t.Fatal(err)
	}
}

// makeProject makes a git checkout holding files, committed, and a cloop
// project of it whose provider is claudecode. On a device scene the checkout
// gets an https origin on the scene's forge, which is how a device gets a
// project's tree: it fetches it.
func (s *scene) makeProject(dir, goal string, files map[string]string) {
	t := s.t
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	s.git(dir, "init", "-q", "-b", "main")
	for rel, body := range files {
		writeFile(t, filepath.Join(dir, filepath.FromSlash(rel)), body)
	}
	s.git(dir, "add", "-A")
	s.git(dir, "commit", "-qm", "first")
	if s.forge != nil {
		bare, origin := s.forge.repo(t, s.env, "srv/acme/"+filepath.Base(dir)+".git")
		s.git(dir, "remote", "add", "origin", origin)
		s.git(dir, "push", "-q", bare, "main:refs/heads/main")
		s.git(dir, "update-ref", "refs/remotes/origin/main", "refs/heads/main")
	}
	s.cloop(dir, "init", "--provider", "claudecode", "--skip-clarify", goal)
}

// gitForge serves bare repositories under root over HTTPS on loopback,
// through git's own smart HTTP backend.
type gitForge struct {
	root   string
	srv    *httptest.Server
	caFile string
}

func newGitForge(t *testing.T, dir string) *gitForge {
	t.Helper()
	gitBin, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git is not installed")
	}
	f := &gitForge{root: filepath.Join(dir, "forge")}
	if err := os.MkdirAll(f.root, 0o755); err != nil {
		t.Fatal(err)
	}
	f.srv = httptest.NewUnstartedServer(&cgi.Handler{
		Path: gitBin,
		Args: []string{"http-backend"},
		Env: []string{
			"GIT_PROJECT_ROOT=" + f.root,
			"GIT_HTTP_EXPORT_ALL=1",
			"GIT_CONFIG_NOSYSTEM=1",
			"GIT_CONFIG_GLOBAL=/dev/null",
		},
		InheritEnv: []string{"PATH"},
	})
	f.srv.StartTLS()
	t.Cleanup(f.srv.Close)
	f.caFile = filepath.Join(dir, "forge-ca.pem")
	block := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.srv.Certificate().Raw})
	writeFile(t, f.caFile, string(block))
	return f
}

// repo creates a bare repository at path under the forge and returns its
// directory and https URL. Three segments: a repository that is not
// owner/name needs no grant to be fetched, and this forge is public.
func (f *gitForge) repo(t *testing.T, env []string, path string) (string, string) {
	t.Helper()
	dir := filepath.Join(f.root, filepath.FromSlash(path))
	cmd := exec.Command("git", "init", "-q", "--bare", "-b", "main", dir)
	cmd.Env = env
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git init --bare: %v\n%s", err, out)
	}
	return dir, f.srv.URL + "/" + path
}

// start starts the hub, and the device's agent for the device scene, and
// binds the three projects to the executor under test.
func (s *scene) start() {
	t := s.t
	listen := "127.0.0.1"
	if s.kind == inContainer {
		// A container reaches the hub at the host's address; the token
		// protects it there.
		listen = "0.0.0.0"
	}
	s.ownProjects()
	// The per-address request rate well above the default (20 a second,
	// burst 50): the test polls the hub from the address a hostile run on
	// its host sends its probes from, and a slow machine's polling and the
	// probes together go past the default.
	cmd := exec.Command(s.bin, "ui", "--listen", listen, "--port", strconv.Itoa(s.port), "--no-browser",
		"--rate-limit", "500", "--rate-burst", "2000",
		"--projects", s.vault, "--projects", s.mallory, "--projects", s.library)
	cmd.Dir, cmd.Env = s.hubDir, append(append([]string(nil), s.env...), s.hubEnv...)
	s.hub = s.spawn(cmd, s.hubLog)
	s.waitFor("the hub to answer", 90*time.Second, func() bool {
		code, _, _ := s.call("GET", "/api/executors", nil)
		return code == http.StatusOK
	})
	switch s.kind {
	case onDevice:
		s.startAgent()
	case inContainer:
		_, body, _ := s.call("GET", "/api/executors", nil)
		for _, e := range list(body, "executors") {
			if e["kind"] == "container" {
				s.executorID = fmt.Sprint(e["id"])
			}
		}
		if s.executorID == "" {
			t.Fatalf("the hub registered no container executor: %v", body)
		}
	}
	if s.executorID != "" {
		for _, p := range []string{s.vault, s.mallory, s.library} {
			s.mustCall(http.StatusOK, "POST", fmt.Sprintf("/api/projects/%d/executor", s.idx(p)),
				map[string]any{"executor_id": s.executorID})
		}
	}
}

// startAgent enrols a device and starts its agent: a second process that
// speaks the agent protocol to the hub over a WebSocket and runs the
// projects' payloads on its own host, beneath its own root.
func (s *scene) startAgent() {
	t := s.t
	s.deviceRoot = filepath.Join(s.root, "device")
	deviceBin := filepath.Join(s.root, "device-bin")
	for _, d := range []string{s.deviceRoot, deviceBin} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	copyFile(t, s.hostile, filepath.Join(deviceBin, "claude"), 0o755)
	// The hub dispatches the bare name `cloop`: the device's PATH must find
	// the cloop under test.
	if err := os.Symlink(s.bin, filepath.Join(deviceBin, "cloop")); err != nil {
		t.Fatal(err)
	}
	bundle := filepath.Join(s.root, "enroll.bundle")
	s.cloop(s.hubDir, "executor", "enroll", "--name", "edge-isolation", "--server",
		strings.Replace(s.base, "http://", "ws://", 1)+"/api/executors/connect", "--bundle-file", bundle)
	cmd := exec.Command(s.bin, "executor", "agent", "--token-file", bundle,
		"--credential", filepath.Join(s.root, "agent.json"), "--workdir-root", s.deviceRoot,
		"--max-concurrent", "3")
	env := make([]string, 0, len(s.env))
	for _, kv := range s.env {
		if !strings.HasPrefix(kv, "PATH=") && !strings.HasPrefix(kv, "HOME=") &&
			!strings.HasPrefix(kv, "CLOOP_UI_TOKEN=") && !strings.HasPrefix(kv, "CLOOP_SECRET_KEY=") {
			env = append(env, kv)
		}
	}
	cmd.Env = append(env, "PATH="+deviceBin+string(os.PathListSeparator)+os.Getenv("PATH"),
		"HOME="+filepath.Join(s.root, "device-home"),
		// The device trusts the forge's certificate, as a device trusts an
		// operator's private CA.
		"GIT_SSL_CAINFO="+s.forge.caFile)
	s.agentLog = &lockedBuffer{}
	s.agent = s.spawn(cmd, s.agentLog)
	s.waitFor("the agent to connect", 90*time.Second, func() bool {
		_, body, _ := s.call("GET", "/api/executors", nil)
		for _, e := range list(body, "executors") {
			if e["name"] == "edge-isolation" && e["status"] == "online" {
				s.executorID = fmt.Sprint(e["id"])
				return true
			}
		}
		return false
	})
}

// buildImage builds the container's image: the pinned base with git, the
// cloop under test and the hostile agent as claude.
func (s *scene) buildImage() string {
	t := s.t
	dir := t.TempDir()
	copyFile(t, s.bin, filepath.Join(dir, "cloop"), 0o755)
	copyFile(t, s.hostile, filepath.Join(dir, "claude"), 0o755)
	writeFile(t, filepath.Join(dir, "Dockerfile"), "FROM "+imageBase+"\n"+
		"RUN apk add --no-cache git\n"+
		"COPY cloop /usr/local/bin/cloop\n"+
		"COPY claude /usr/local/bin/claude\n"+
		"RUN chmod 0755 /usr/local/bin/cloop /usr/local/bin/claude\n")
	h := sha256.New()
	for _, f := range []string{"cloop", "claude", "Dockerfile"} {
		data, err := os.ReadFile(filepath.Join(dir, f))
		if err != nil {
			t.Fatal(err)
		}
		h.Write(data)
	}
	tag := "cloop-isolation-e2e:" + hex.EncodeToString(h.Sum(nil)[:6])
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()
	if out, err := exec.CommandContext(ctx, "docker", "build", "-q", "-t", tag, dir).CombinedOutput(); err != nil {
		t.Fatalf("docker build: %v\n%s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("docker", "rmi", "-f", tag).Run() })
	return tag
}

// sqliteImage is the pinned base with sqlite3, for the gVisor lock probe.
func (s *scene) sqliteImage() string {
	t := s.t
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "Dockerfile"), "FROM "+imageBase+"\nRUN apk add --no-cache sqlite\n")
	tag := "cloop-isolation-sqlite:" + digestOf(imageBase + "sqlite")[:12]
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()
	if out, err := exec.CommandContext(ctx, "docker", "build", "-q", "-t", tag, dir).CombinedOutput(); err != nil {
		t.Fatalf("docker build: %v\n%s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("docker", "rmi", "-f", tag).Run() })
	return tag
}

// ownProjects hands the projects to sandboxUID before a container runs in
// them, as an operator does, when the test runs as root — the hub's
// databases' journals included, which the hub writes as root.
func (s *scene) ownProjects() {
	if s.kind != inContainer || os.Geteuid() != 0 {
		return
	}
	for _, p := range []string{s.vault, s.mallory, s.library} {
		err := filepath.WalkDir(p, func(path string, _ fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			return os.Lchown(path, sandboxUID, sandboxUID)
		})
		if err != nil {
			s.t.Fatal(err)
		}
	}
}

func (s *scene) spawn(cmd *exec.Cmd, log *lockedBuffer) *exec.Cmd {
	s.t.Helper()
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Stdout, cmd.Stderr = log, log
	if err := cmd.Start(); err != nil {
		s.t.Fatal(err)
	}
	return cmd
}

func (s *scene) teardown() {
	t := s.t
	for _, c := range []*exec.Cmd{s.agent, s.hub} {
		if c == nil || c.Process == nil {
			continue
		}
		_ = syscall.Kill(-c.Process.Pid, syscall.SIGTERM)
		done := make(chan struct{})
		go func() { _, _ = c.Process.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(20 * time.Second):
			_ = syscall.Kill(-c.Process.Pid, syscall.SIGKILL)
			<-done
		}
	}
	// What a stopped run left behind on this machine, by the scene's own
	// paths: a payload outlives neither its hub nor this test.
	for _, pid := range s.processesUnder(s.root) {
		_ = syscall.Kill(pid, syscall.SIGKILL)
	}
	if s.kind == inContainer {
		// Only what this scene made: containers of its projects, then the
		// networks they were on.
		for _, p := range []string{s.vault, s.mallory, s.library} {
			out, _ := exec.Command("docker", "ps", "-aq", "--filter", "label=cloop.project="+p).Output()
			for _, id := range strings.Fields(string(out)) {
				_ = exec.Command("docker", "rm", "-f", id).Run()
			}
		}
		if s.executorID != "" {
			out, _ := exec.Command("docker", "network", "ls", "--format", "{{.Name}}").Output()
			for _, name := range strings.Fields(string(out)) {
				if strings.HasPrefix(name, "cloop-sbx-") && strings.Contains(name, networkName(s.executorID)) {
					_ = exec.Command("docker", "network", "rm", name).Run()
				}
			}
		}
	}
	if t.Failed() || os.Getenv("CLOOP_ISOLATION_LOGS") == "1" {
		t.Logf("hub log:\n%s", tail(s.hubLog.String(), 20000))
		if s.agentLog != nil {
			t.Logf("agent log:\n%s", tail(s.agentLog.String(), 12000))
		}
	}
	if os.Getenv("CLOOP_ISOLATION_KEEP") == "1" {
		t.Logf("kept the scene at %s", s.root)
		return
	}
	_ = os.RemoveAll(s.root)
}

// processesUnder lists the processes whose working directory is beneath
// root, other than this one.
func (s *scene) processesUnder(root string) []int {
	entries, _ := os.ReadDir("/proc")
	var out []int
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid == os.Getpid() {
			continue
		}
		cwd, err := os.Readlink(filepath.Join("/proc", e.Name(), "cwd"))
		if err == nil && (cwd == root || strings.HasPrefix(cwd, root+"/")) {
			out = append(out, pid)
		}
	}
	return out
}

// networkName is the part of a sandbox network's name the driver derives
// from its executor's id.
func networkName(id string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(id) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		} else {
			b.WriteRune('-')
		}
	}
	return strings.Trim(b.String(), "-")
}

// ─── the hub's API ──────────────────────────────────────────────────────────

// call sends one request to the hub with its token.
func (s *scene) call(method, path string, body any) (int, map[string]any, string) {
	s.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, s.base+path, rd)
	if err != nil {
		s.t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+hubToken)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := (&http.Client{Timeout: 3 * time.Minute}).Do(req)
	if err != nil {
		return 0, nil, err.Error()
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	return resp.StatusCode, out, string(raw)
}

func (s *scene) mustCall(want int, method, path string, body any) map[string]any {
	s.t.Helper()
	code, out, raw := s.call(method, path, body)
	if code != want {
		s.t.Fatalf("%s %s = HTTP %d, want %d: %s", method, path, code, want, raw)
	}
	return out
}

func (s *scene) waitFor(what string, timeout time.Duration, cond func() bool) {
	s.t.Helper()
	deadline := time.Now().Add(timeout)
	for !cond() {
		if time.Now().After(deadline) {
			s.t.Fatalf("timed out after %s waiting for %s", timeout, what)
		}
		time.Sleep(250 * time.Millisecond)
	}
}

// idx is a project's index on the hub.
func (s *scene) idx(path string) int {
	s.t.Helper()
	_, body, raw := s.call("GET", "/api/projects", nil)
	projects := list(body, "projects")
	if body == nil {
		var bare []map[string]any
		_ = json.Unmarshal([]byte(raw), &bare)
		projects = bare
	}
	for i, p := range projects {
		if p["path"] == path {
			return i
		}
	}
	s.t.Fatalf("the hub does not serve %s: %s", path, raw)
	return -1
}

// task is one task as the hub reports it.
type task struct {
	ID     int    `json:"id"`
	Title  string `json:"title"`
	Status string `json:"status"`
	Result string `json:"result"`
}

func (s *scene) tasks(project string) []task {
	s.t.Helper()
	code, _, raw := s.call("GET", fmt.Sprintf("/api/state?project_idx=%d", s.idx(project)), nil)
	if code != http.StatusOK {
		s.t.Fatalf("read %s's state = HTTP %d: %s", filepath.Base(project), code, raw)
	}
	var st struct {
		Plan struct {
			Tasks []task `json:"tasks"`
		} `json:"plan"`
	}
	if err := json.Unmarshal([]byte(raw), &st); err != nil {
		s.t.Fatalf("read %s's state: %v", filepath.Base(project), err)
	}
	return st.Plan.Tasks
}

func (s *scene) taskByID(project string, id int) task {
	for _, tk := range s.tasks(project) {
		if tk.ID == id {
			return tk
		}
	}
	return task{}
}

// addTask adds a task through the hub and returns its id.
func (s *scene) addTask(project, title, description string) int {
	s.t.Helper()
	before := map[int]bool{}
	for _, tk := range s.tasks(project) {
		before[tk.ID] = true
	}
	code, _, raw := s.call("POST", fmt.Sprintf("/api/tasks?project_idx=%d", s.idx(project)),
		map[string]any{"title": title, "description": description})
	if code != http.StatusOK && code != http.StatusCreated {
		s.t.Fatalf("add task %q = HTTP %d: %s", title, code, raw)
	}
	for _, tk := range s.tasks(project) {
		if !before[tk.ID] && tk.Title == title {
			return tk.ID
		}
	}
	s.t.Fatalf("the hub did not add task %q", title)
	return 0
}

// run starts a project's run where it is bound.
func (s *scene) run(project string) {
	s.t.Helper()
	s.ownProjects()
	s.mustCall(http.StatusOK, "POST", fmt.Sprintf("/api/projects/%d/run", s.idx(project)), map[string]any{})
}

// waitDone waits for task id of project to end, and fails the test if it
// ended anything but done.
func (s *scene) waitDone(project string, id int, timeout time.Duration) {
	s.t.Helper()
	s.waitFor(fmt.Sprintf("%s's task %d to end", filepath.Base(project), id), timeout, func() bool {
		switch tk := s.taskByID(project, id); tk.Status {
		case "done":
			return true
		case "failed", "skipped", "timed_out":
			s.t.Fatalf("%s's task %d ended %s: %s", filepath.Base(project), id, tk.Status, tk.Result)
		}
		return false
	})
	s.waitIdle(project)
}

// waitIdle waits for a project's run to end.
func (s *scene) waitIdle(project string) {
	s.t.Helper()
	s.waitFor(filepath.Base(project)+"'s run to end", 2*time.Minute, func() bool { return !s.running(project) })
}

// running reports whether the hub says project's run is going.
func (s *scene) running(project string) bool {
	_, body, _ := s.call("GET", "/api/projects", nil)
	for _, p := range list(body, "projects") {
		if p["path"] == project {
			st := fmt.Sprint(p["status"])
			return st == "running" || st == "evolving" || st == "starting"
		}
	}
	return true
}

// attachment is the content of a task's attachment by its name.
func (s *scene) attachment(project string, id int, name string) []byte {
	s.t.Helper()
	body := s.mustCall(http.StatusOK, "GET", fmt.Sprintf("/api/tasks/%d/attachments?project_idx=%d", id, s.idx(project)), nil)
	for _, a := range list(body, "attachments") {
		if a["name"] != name {
			continue
		}
		req, _ := http.NewRequest("GET", fmt.Sprintf("%s/api/tasks/%d/attachments/%v?project_idx=%d", s.base, id,
			a["id"], s.idx(project)), nil)
		req.Header.Set("Authorization", "Bearer "+hubToken)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			s.t.Fatal(err)
		}
		data, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			s.t.Fatalf("download %s = HTTP %d: %s", name, resp.StatusCode, data)
		}
		return data
	}
	return nil
}

// readers runs `cloop project readers <args>` against the hub, as an
// operator does from a terminal.
func (s *scene) readers(args ...string) string {
	s.t.Helper()
	return s.cloop(s.root, append(append([]string{"project", "readers"}, args...), "--hub", s.base,
		"--token", hubToken)...)
}

// ─── where a project's files are ────────────────────────────────────────────

// trees are the copies of project's tree a run on this scene's executor
// could reach: its directory on the hub, and on a device its working copy
// there too.
func (s *scene) trees(project string) []string {
	out := []string{project}
	if s.kind == onDevice {
		out = append(out, s.deviceCopy(project))
	}
	return out
}

// deviceCopy is a project's working copy on the device.
func (s *scene) deviceCopy(project string) string {
	return filepath.Join(s.deviceRoot, executor.DeviceWorkDir(project))
}

// runTree is where the run of project works: its own directory, but its
// working copy on a device.
func (s *scene) runTree(project string) string {
	if s.kind == onDevice {
		return s.deviceCopy(project)
	}
	return project
}

// ─── the victim's state ─────────────────────────────────────────────────────

// victimState is everything of vault's a hostile run could change: every
// file of each copy of its tree outside .cloop, its canary and configuration
// in .cloop, its plan, and the control plane's readers rows.
type victimState struct {
	trees    map[string]map[string]string
	plan     []string
	readers  []string
	registry []string
}

// snapshotVictim reads vault's state, except what vault's own run writes.
func (s *scene) snapshotVictim() victimState {
	t := s.t
	v := victimState{trees: map[string]map[string]string{}}
	for _, tree := range s.trees(s.vault) {
		v.trees[tree] = fingerprint(t, tree)
	}
	db := s.openDB(filepath.Join(s.vault, ".cloop", "state.db"))
	rows, err := db.Query(`SELECT id, title, description FROM plan_tasks ORDER BY id`)
	if err != nil {
		t.Fatalf("read vault's plan: %v", err)
	}
	for rows.Next() {
		var id int
		var title, desc string
		if err := rows.Scan(&id, &title, &desc); err != nil {
			t.Fatal(err)
		}
		v.plan = append(v.plan, fmt.Sprintf("%d %q %q", id, title, desc))
	}
	_ = rows.Close()
	var check string
	if err := db.QueryRow(`PRAGMA quick_check`).Scan(&check); err != nil || check != "ok" {
		t.Errorf("vault's state database is damaged: %q %v", check, err)
	}
	_ = db.Close()
	hub := s.openDB(filepath.Join(s.hubDir, ".cloop", "state.db"))
	rows, err = hub.Query(`SELECT project_path, reader_path FROM project_readers ORDER BY project_path, reader_path`)
	if err != nil {
		t.Fatalf("read the readers lists: %v", err)
	}
	for rows.Next() {
		var p, r string
		if err := rows.Scan(&p, &r); err != nil {
			t.Fatal(err)
		}
		v.readers = append(v.readers, p+" <- "+r)
	}
	_ = rows.Close()
	_ = hub.Close()
	var reg []struct {
		Path string `json:"path"`
	}
	if data, err := os.ReadFile(filepath.Join(s.home, ".cloop", "projects.json")); err == nil {
		_ = json.Unmarshal(data, &reg)
	}
	for _, r := range reg {
		v.registry = append(v.registry, r.Path)
	}
	sort.Strings(v.registry)
	return v
}

// requireVictimUnchanged fails the test for every way vault differs from
// before, save the readers rows the test itself changed.
func (s *scene) requireVictimUnchanged(phase string, before victimState, readers []string) {
	t := s.t
	t.Helper()
	after := s.snapshotVictim()
	for tree, want := range before.trees {
		for _, d := range diffTrees(want, after.trees[tree]) {
			t.Errorf("%s: vault's tree at %s changed: %s", phase, tree, d)
		}
	}
	if strings.Join(after.plan, "\n") != strings.Join(before.plan, "\n") {
		t.Errorf("%s: vault's plan changed:\nbefore:\n%s\nafter:\n%s", phase, strings.Join(before.plan, "\n"),
			strings.Join(after.plan, "\n"))
	}
	if strings.Join(after.readers, "\n") != strings.Join(readers, "\n") {
		t.Errorf("%s: the readers lists are %v, want %v", phase, after.readers, readers)
	}
	if strings.Join(after.registry, "\n") != strings.Join(before.registry, "\n") {
		t.Errorf("%s: the hub's project registry changed: %v, was %v", phase, after.registry, before.registry)
	}
	if s.github != nil {
		if ref := s.github.forge.Ref(t, "acme/vault", "refs/heads/planted-by-mallory"); ref != "" {
			t.Errorf("%s: mallory's run pushed %s to vault's repository", phase, ref)
		}
	}
}

// openDB opens a SQLite database read-only.
func (s *scene) openDB(path string) *sql.DB {
	s.t.Helper()
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro&_pragma=busy_timeout(10000)")
	if err != nil {
		s.t.Fatal(err)
	}
	return db
}

// fingerprint describes every entry of a tree that a hostile run might
// change, by its path: the files outside .cloop with their mode and digest,
// directories with their mode, links with their target. Inside .cloop only
// the files a run never writes are kept, and the victim's own run's socket,
// git's index (which git rewrites on a status) and the run's own marker
// files are left out.
func fingerprint(t *testing.T, root string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil
			}
			return err
		}
		rel, _ := filepath.Rel(root, p)
		rel = filepath.ToSlash(rel)
		switch {
		case rel == ".":
		case rel == ".hv.sock", rel == ".git/index", strings.HasSuffix(rel, ".lock"):
			return nil
		case rel == ".cloop":
		case strings.HasPrefix(rel, ".cloop/"):
			if rel != ".cloop/victim-canary.txt" && rel != ".cloop/config.yaml" {
				if d.IsDir() {
					return fs.SkipDir
				}
				return nil
			}
		}
		info, err := os.Lstat(p)
		if err != nil {
			return err
		}
		switch {
		case info.Mode()&fs.ModeSymlink != 0:
			target, _ := os.Readlink(p)
			out[rel] = "link " + target
		case info.IsDir():
			out[rel] = "dir " + info.Mode().Perm().String()
		case info.Mode().IsRegular():
			data, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			sum := sha256.Sum256(data)
			out[rel] = "file " + info.Mode().Perm().String() + " " + hex.EncodeToString(sum[:])
		default:
			out[rel] = "special " + info.Mode().String()
		}
		return nil
	})
	if err != nil {
		t.Fatalf("fingerprint %s: %v", root, err)
	}
	return out
}

// diffTrees says how after differs from before.
func diffTrees(before, after map[string]string) []string {
	keys := map[string]bool{}
	for k := range before {
		keys[k] = true
	}
	for k := range after {
		keys[k] = true
	}
	var sorted []string
	for k := range keys {
		sorted = append(sorted, k)
	}
	sort.Strings(sorted)
	var out []string
	for _, k := range sorted {
		if before[k] != after[k] {
			out = append(out, fmt.Sprintf("%s: was %q, is %q", k, orNone(before[k]), orNone(after[k])))
		}
	}
	return out
}

func orNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}

// ─── small helpers ──────────────────────────────────────────────────────────

func (s *scene) cloop(dir string, args ...string) string {
	s.t.Helper()
	cmd := exec.Command(s.bin, args...)
	cmd.Dir, cmd.Env = dir, s.env
	out, err := cmd.CombinedOutput()
	if err != nil {
		s.t.Fatalf("cloop %v in %s: %v\n%s", args, dir, err, out)
	}
	return string(out)
}

func (s *scene) git(dir string, args ...string) string {
	s.t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir, cmd.Env = dir, s.env
	out, err := cmd.CombinedOutput()
	if err != nil {
		s.t.Fatalf("git %v in %s: %v\n%s", args, dir, err, out)
	}
	return strings.TrimSpace(string(out))
}

func list(body map[string]any, key string) []map[string]any {
	raw, _ := body[key].([]any)
	out := make([]map[string]any, 0, len(raw))
	for _, r := range raw {
		if m, ok := r.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func copyFile(t *testing.T, from, to string, mode os.FileMode) {
	t.Helper()
	data, err := os.ReadFile(from)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(to, data, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(to, mode); err != nil {
		t.Fatal(err)
	}
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// hostAddress is the address this machine sends from by default: a
// container on any bridge reaches the hub there.
func hostAddress(t *testing.T) string {
	t.Helper()
	c, err := net.Dial("udp", "192.0.2.1:9")
	if err != nil {
		t.Skipf("no route off this machine for a container to reach the hub at: %v", err)
	}
	defer c.Close()
	ip := c.LocalAddr().(*net.UDPAddr).IP
	if ip.IsLoopback() || ip.To4() == nil {
		t.Skipf("this machine's default address %s is not one a container reaches it at", ip)
	}
	return ip.String()
}

func randomHex(t *testing.T, n int) string {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

func digestOf(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func tail(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return "…" + s[len(s)-n:]
}

// encodePlan renders a plan for a task's description.
func encodePlan(t *testing.T, p hostilePlan) string {
	t.Helper()
	blob, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	return "HOSTILE-PLAN:" + p.Tag + ":" + base64.StdEncoding.EncodeToString(blob)
}
