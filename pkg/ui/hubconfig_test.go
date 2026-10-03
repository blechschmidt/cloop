package ui

// hubconfig_test.go proves that hub-scope settings in a per-instance overlay
// govern the hub (Task 20364).
//
// Each test writes the setting into .cloop/config.ui-<port>.yaml and nothing
// into config.yaml, which is the layout of a host where two dashboards share a
// directory. Most also check the control: the same directory served on
// another port, which has no overlay, must not pick the setting up. Without
// that check, a test would pass just as well against a hub that read the
// overlay of whichever dashboard happened to write last.
//
// None of these tests is parallel. The host policy, the build floor, the git
// proxy and the Kubernetes monitor are process singletons, and each test puts
// back what it changed.

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/localprocess"
	"github.com/blechschmidt/cloop/pkg/imagepolicy"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/tlsconf"
)

// overlayHubPort is the port the hubs under test listen on, and so the one
// whose overlay applies. otherHubPort is a second dashboard in the same
// directory, which has none.
const (
	overlayHubPort = 8081
	otherHubPort   = 8080
)

// writeHubConfigs gives dir a config.yaml and, unless overlay is empty, the
// overlay for overlayHubPort. It returns both paths.
func writeHubConfigs(t *testing.T, dir, shared, overlay string) (sharedPath, overlayPath string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(dir, ".cloop"), 0o755); err != nil {
		t.Fatalf("mkdir .cloop: %v", err)
	}
	sharedPath = config.ConfigPath(dir)
	if err := os.WriteFile(sharedPath, []byte(shared), 0o600); err != nil {
		t.Fatalf("write config.yaml: %v", err)
	}
	overlayPath = config.UIInstanceConfigPath(dir, overlayHubPort)
	if overlay != "" {
		if err := os.WriteFile(overlayPath, []byte(overlay), 0o600); err != nil {
			t.Fatalf("write overlay: %v", err)
		}
	}
	return sharedPath, overlayPath
}

// overlayControlPlane creates a control-plane directory with the given
// configuration files, a migrated state database and a project in it, which
// is what a hub's own directory holds.
func overlayControlPlane(t *testing.T, shared, overlay string) (dir, sharedPath, overlayPath string) {
	t.Helper()
	dir = t.TempDir()
	initStateDB(t, dir)
	if _, err := state.Init(dir, "hub-scope overlay test", 0); err != nil {
		t.Fatalf("state.Init: %v", err)
	}
	// After Init, which may write a config.yaml of its own.
	sharedPath, overlayPath = writeHubConfigs(t, dir, shared, overlay)
	return dir, sharedPath, overlayPath
}

// restoreControlPlane puts back the control plane bootstrap recorded, which
// every New in a test overwrites.
func restoreControlPlane(t *testing.T) {
	t.Helper()
	controlPlaneDirMu.Lock()
	dir, port := controlPlaneDirValue, controlPlanePortValue
	controlPlaneDirMu.Unlock()
	t.Cleanup(func() {
		controlPlaneDirMu.Lock()
		controlPlaneDirValue, controlPlanePortValue = dir, port
		controlPlaneDirMu.Unlock()
	})
}

// restoreHostPolicy starts a test permissive and leaves it permissive, with
// the host driver registered again. Restoring the switch alone is not enough:
// strict mode evicts the localprocess driver, and registerBuiltinExecutors
// will not put it back, because it registers once per process.
func restoreHostPolicy(t *testing.T) {
	t.Helper()
	prev := executor.SetAllowHostExecution(true)
	_ = localprocess.Ensure(executor.DefaultRegistry)
	t.Cleanup(func() {
		executor.SetAllowHostExecution(prev)
		if prev {
			_ = localprocess.Ensure(executor.DefaultRegistry)
		}
	})
}

// TestOverlayStrictModeRefusesHostDispatch is the headline of the task: the
// overlay says no harness may run on this host, and before the fix the hub
// spawned them anyway, because bootstrap read config.yaml alone.
func TestOverlayStrictModeRefusesHostDispatch(t *testing.T) {
	restoreControlPlane(t)
	restoreHostPolicy(t)

	dir, _, _ := overlayControlPlane(t, "provider: claudecode\n",
		"# :8081 is the hardened hub.\nexecutors:\n  allow_host_process: false\n")

	// The other dashboard in the directory has no overlay, so it stays
	// permissive. If it does not, the overlay is leaking past its port.
	New(dir, otherHubPort, "")
	if !executor.HostExecutionAllowed() {
		t.Fatal("a hub with no overlay went strict: another hub's overlay applied to it")
	}

	srv := New(dir, overlayHubPort, "")
	if executor.HostExecutionAllowed() {
		t.Fatal("the overlay's executors.allow_host_process: false was ignored; " +
			"the hub still permits host execution")
	}

	// The host driver cannot even be registered again...
	if err := localprocess.Ensure(executor.DefaultRegistry); !errors.Is(err, executor.ErrHostExecutionDenied) {
		t.Errorf("registering the host driver under the overlay's strict mode: err = %v, want a denial", err)
	}
	// ...and a host-side effect is refused with the remediation.
	rec := httptest.NewRecorder()
	if !denyHostSideEffect(rec, dir, "claude-auth-login") || rec.Code != http.StatusConflict {
		t.Errorf("denyHostSideEffect under the overlay's strict mode: refused=%v code=%d",
			rec.Code == http.StatusConflict, rec.Code)
	}

	// A dispatch for the hub's own project is refused by the policy. Skipped
	// when another test left an isolating executor registered, which would
	// accept it for a reason unrelated to this one.
	if len(executor.IsolatedIDs()) == 0 {
		if _, _, err := startWorkload(dir, fixtureArgv(t), nil); !isHostDenied(err) {
			t.Errorf("startWorkload under the overlay's strict mode: err = %v, want a host-execution denial", err)
		}
		if _, err := runWorkload(t.Context(), dir, fixtureArgv(t), nil); !isHostDenied(err) {
			t.Errorf("runWorkload under the overlay's strict mode: err = %v, want a host-execution denial", err)
		}
		// And as the dashboard sees it: a 409 naming the policy and the fix.
		// Strict mode evicts the host driver, so with nothing isolating the
		// registry is empty, and this answered 500 "no default executor
		// configured" until Resolve learned to call that what it is.
		ts := newTestServerFor(t, srv)
		resp, err := http.Post(ts.URL+"/api/run", "application/json", strings.NewReader(`{}`))
		if err != nil {
			t.Fatalf("POST /api/run: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusConflict {
			t.Fatalf("POST /api/run under the overlay's strict mode = HTTP %d, want 409", resp.StatusCode)
		}
		assertHostDeniedBody(t, resp)
	}

	// The Executors panel tells the operator the truth, including that the
	// policy was stated rather than defaulted.
	view := srv.executorPolicy()
	if view.AllowHostProcess || !view.StrictMode {
		t.Errorf("policy view allow_host_process=%v strict_mode=%v, want false/true",
			view.AllowHostProcess, view.StrictMode)
	}
	if !view.Explicit {
		t.Error("the policy view reports the overlay's allow_host_process: false as a default, not a choice")
	}
	if !strings.Contains(view.Banner, "Strict mode") {
		t.Errorf("banner = %q, want it to say strict mode", view.Banner)
	}
}

// TestOverlayImagePolicyIsEnforced: an image allowlist in the overlay refuses
// an image off the list, both at the hub's early check and in the copy the
// drivers take at bootstrap.
func TestOverlayImagePolicyIsEnforced(t *testing.T) {
	restoreControlPlane(t)

	dir, _, _ := overlayControlPlane(t, "provider: claudecode\n", `sandbox:
  image_policy:
    allowed_registries: [registry.example.com]
    require_digest: true
`)
	project := writeSandboxYAML(t, "image: docker.io/library/ubuntu:24.04\n")

	// Served on the other port, the same directory has no policy at all.
	New(dir, otherHubPort, "")
	if hubImagePolicy().Configured() {
		t.Fatal("a hub with no overlay applied another hub's image policy")
	}

	New(dir, overlayHubPort, "")
	if !hubImagePolicy().Configured() {
		t.Fatal("the hub's early image check ignored the overlay's sandbox.image_policy")
	}
	_, _, err := applySandbox(executor.Spec{}, nil, project)
	var denied *imagepolicy.DenyError
	if !errors.As(err, &denied) {
		t.Fatalf("a docker.io image under an overlay allowlisting registry.example.com: err = %v, "+
			"want an image policy denial", err)
	}

	// The drivers are built from the configuration bootstrap loads, and so
	// enforce the same policy when they pull.
	cfg := bootstrapHubConfig(dir, overlayHubPort)
	if cfg == nil || !cfg.Sandbox.ImagePolicy.Policy().RequireDigest {
		t.Error("the configuration the drivers are reconciled from does not carry the overlay's image policy")
	}
}

// resetProxySingletonsForTest gives a test a process in which neither the git
// proxy nor the Kubernetes monitor has started yet, and afterwards closes what
// it started and puts the originals back.
func resetProxySingletonsForTest(t *testing.T) {
	t.Helper()
	prevGit, prevGitRequired := gitProxySingleton.Load(), gitProxyRequired.Load()
	prevKube, prevKubeRequired := kubeGuardSingleton.Load(), kubeGuardRequired.Load()
	gitProxySingleton.Store(nil)
	kubeGuardSingleton.Store(nil)
	gitProxyOnce = sync.Once{}
	kubeGuardOnce = sync.Once{}
	t.Cleanup(func() {
		if svc := gitProxySingleton.Load(); svc != nil && svc != prevGit {
			svc.Close()
		}
		if svc := kubeGuardSingleton.Load(); svc != nil && svc != prevKube {
			svc.Close()
		}
		gitProxySingleton.Store(prevGit)
		gitProxyRequired.Store(prevGitRequired)
		kubeGuardSingleton.Store(prevKube)
		kubeGuardRequired.Store(prevKubeRequired)
		// Left spent: a process starts each monitor at most once, and a later
		// New must not start a second one from its own directory.
		gitProxyOnce = sync.Once{}
		gitProxyOnce.Do(func() {})
		kubeGuardOnce = sync.Once{}
		kubeGuardOnce.Do(func() {})
	})
}

// selfSignedLoopbackPair writes a certificate and key for 127.0.0.1.
func selfSignedLoopbackPair(t *testing.T) (cert, key string) {
	t.Helper()
	dir := t.TempDir()
	cert, key = filepath.Join(dir, "monitor.crt"), filepath.Join(dir, "monitor.key")
	if _, err := tlsconf.GenerateSelfSigned(cert, key, tlsconf.SelfSignedOptions{
		Hosts: []string{"localhost", "127.0.0.1"},
	}); err != nil {
		t.Fatalf("GenerateSelfSigned: %v", err)
	}
	return cert, key
}

// TestOverlayGitProxyStartsTheProxy: executors.git_proxy in the overlay starts
// the interception proxy, on a loopback listener with a self-signed
// certificate. Before the fix, the proxy could be enabled only in config.yaml.
// On :8888 that file is shared with the older :8080 hub, which made
// interception impossible to switch on for one hub alone.
func TestOverlayGitProxyStartsTheProxy(t *testing.T) {
	restoreControlPlane(t)

	cert, key := selfSignedLoopbackPair(t)
	dir, _, _ := overlayControlPlane(t, "provider: claudecode\n", fmt.Sprintf(`executors:
  git_proxy:
    enabled: true
    listen_addr: 127.0.0.1:0
    cert_file: %s
    key_file: %s
  kube_guard:
    enabled: true
    listen_addr: 127.0.0.1:0
    cert_file: %s
    key_file: %s
`, cert, key, cert, key))
	// After the directory exists, so the services holding its audit database
	// are closed before the directory is removed (cleanups run in reverse).
	resetProxySingletonsForTest(t)

	New(dir, overlayHubPort, "")

	svc := activeGitProxy()
	if svc == nil {
		t.Fatal("the overlay's executors.git_proxy section started no proxy")
	}
	if !gitProxyRequired.Load() {
		t.Error("the hub does not record that its configuration requires the git proxy")
	}
	if !strings.HasPrefix(svc.BaseURL(), "https://127.0.0.1:") {
		t.Errorf("git proxy BaseURL = %q, want an https loopback URL", svc.BaseURL())
	}
	conn, err := tls.Dial("tcp", svc.Addr(), &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // self-signed test certificate
	if err != nil {
		t.Fatalf("the git proxy does not speak TLS on %s: %v", svc.Addr(), err)
	}
	_ = conn.Close()

	// The Kubernetes monitor is started by the same bootstrap from the same
	// configuration, and had the same defect.
	kube := activeKubeGuard()
	if kube == nil {
		t.Fatal("the overlay's executors.kube_guard section started no monitor")
	}
	if !kubeGuardRequired.Load() {
		t.Error("the hub does not record that its configuration requires the Kubernetes monitor")
	}
}

// TestOverlayGitProxyIsNotStartedForAnotherHub is the control for the test
// above: the overlay belongs to the hub on its port, and a hub on another
// port must not start that hub's proxy.
func TestOverlayGitProxyIsNotStartedForAnotherHub(t *testing.T) {
	restoreControlPlane(t)

	cert, key := selfSignedLoopbackPair(t)
	dir, _, _ := overlayControlPlane(t, "provider: claudecode\n", fmt.Sprintf(
		"executors:\n  git_proxy:\n    enabled: true\n    listen_addr: 127.0.0.1:0\n    cert_file: %s\n    key_file: %s\n",
		cert, key))
	resetProxySingletonsForTest(t)

	New(dir, otherHubPort, "")
	if activeGitProxy() != nil || gitProxyRequired.Load() {
		t.Error("a hub with no overlay started the git proxy another hub's overlay configures")
	}
}

// TestOverlayMinAgentBuildRatchets: the overlay's build floor is installed,
// and a lower floor elsewhere cannot lower it. That includes the shared
// config.yaml under the overlay and a managed project's own config.yaml.
func TestOverlayMinAgentBuildRatchets(t *testing.T) {
	restoreControlPlane(t)
	prev := executor.SetMinAgentBuild("")
	t.Cleanup(func() { executor.SetMinAgentBuild(prev) })

	dir, _, _ := overlayControlPlane(t,
		"provider: claudecode\nexecutors:\n  min_agent_build: v1.0.0\n",
		"executors:\n  min_agent_build: v2.3.0\n")

	New(dir, overlayHubPort, "")
	if got := executor.MinAgentBuild(); got != "v2.3.0" {
		t.Fatalf("MinAgentBuild = %q after bootstrapping the hub on :%d, want the overlay's v2.3.0",
			got, overlayHubPort)
	}

	// A second bootstrap that reads only the lower floor leaves the higher
	// one in force.
	New(dir, otherHubPort, "")
	if got := executor.MinAgentBuild(); got != "v2.3.0" {
		t.Errorf("a configuration naming v1.0.0 lowered the floor to %q", got)
	}

	// A device below the overlay's floor is refused, even though it satisfies
	// the floor in config.yaml.
	if blocked, reason := blockedFor(&staleDevice{id: "edge-1", build: "v1.5.0"}); !blocked {
		t.Error("a v1.5.0 agent was placeable under the overlay's v2.3.0 floor")
	} else if !strings.Contains(reason, "v2.3.0") {
		t.Errorf("the refusal does not name the overlay's floor: %s", reason)
	}
}

// TestOverlayRetentionGovernsTheHubsOwnDirectoryOnly: retention is a property
// of each project, and of the hub for its own directory. The overlay must
// decide the hub's own directory, and must not reach any other project.
func TestOverlayRetentionGovernsTheHubsOwnDirectoryOnly(t *testing.T) {
	restoreControlPlane(t)

	dir, _, _ := overlayControlPlane(t,
		"provider: claudecode\nretention:\n  keep_snapshots: 50\n",
		"retention:\n  keep_snapshots: 7\n")
	project := t.TempDir()
	writeHubConfigs(t, project, "provider: claudecode\nretention:\n  keep_snapshots: 3\n", "")

	srv := New(dir, overlayHubPort, "")
	for _, c := range []struct {
		name string
		load func(string) (*config.Config, error)
	}{
		{"governingConfig", srv.governingConfig},
		{"governingConfigFor", governingConfigFor},
	} {
		hub, err := c.load(dir)
		if err != nil {
			t.Fatalf("%s(hub): %v", c.name, err)
		}
		if hub.Retention.KeepSnapshots != 7 {
			t.Errorf("%s: the hub's own directory keeps %d snapshots, want the overlay's 7",
				c.name, hub.Retention.KeepSnapshots)
		}
		proj, err := c.load(project)
		if err != nil {
			t.Fatalf("%s(project): %v", c.name, err)
		}
		if proj.Retention.KeepSnapshots != 3 {
			t.Errorf("%s: another project keeps %d snapshots, want its own 3", c.name, proj.Retention.KeepSnapshots)
		}
	}

	// The disk-usage panel shows the policy the sweep will run.
	rec := httptest.NewRecorder()
	srv.handleDiskUsage(rec, httptest.NewRequest(http.MethodGet, "/api/disk-usage", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/disk-usage = %d: %s", rec.Code, rec.Body.String())
	}
	var usage struct {
		Policy struct {
			KeepSnapshots int `json:"keep_snapshots"`
		} `json:"policy"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &usage); err != nil {
		t.Fatalf("decode disk usage: %v", err)
	}
	if usage.Policy.KeepSnapshots != 7 {
		t.Errorf("the disk-usage panel reports keep_snapshots=%d for the hub, want the overlay's 7",
			usage.Policy.KeepSnapshots)
	}
}

// TestOverlayGitHubTokenIsTheHubsToken: the hub hands its own github.token to
// a host-run PR dispatch, so it is the token this hub is configured with that
// must be handed over.
func TestOverlayGitHubTokenIsTheHubsToken(t *testing.T) {
	restoreControlPlane(t)
	restoreHostPolicy(t)
	t.Setenv("GITHUB_TOKEN", "")

	dir, _, _ := overlayControlPlane(t,
		"provider: claudecode\ngithub:\n  token: ghp_the_other_hubs_token\n",
		"github:\n  token: ghp_this_hubs_token\n")
	srv := New(dir, overlayHubPort, "")

	host, err := executor.Get(localprocess.DefaultID)
	if err != nil {
		t.Fatalf("the host driver is not registered: %v", err)
	}
	env := strings.Join(srv.featureTokenEnv()(host), "\n")
	if !strings.Contains(env, "ghp_this_hubs_token") || strings.Contains(env, "ghp_the_other_hubs_token") {
		t.Errorf("featureTokenEnv handed over %q, want this hub's overlay token", env)
	}
}

// ── settings saves ──────────────────────────────────────────────────────────

// overlaySettingsHub is a hub on overlayHubPort whose directory carries the
// given configuration files.
func overlaySettingsHub(t *testing.T, shared, overlay string) (srv *Server, sharedPath, overlayPath string) {
	t.Helper()
	restoreControlPlane(t)
	dir, sharedPath, overlayPath := overlayControlPlane(t, shared, overlay)
	return New(dir, overlayHubPort, ""), sharedPath, overlayPath
}

// assertUnchanged fails when the file at path no longer holds want.
func assertUnchanged(t *testing.T, path, want string) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if !bytes.Equal(got, []byte(want)) {
		t.Errorf("%s was rewritten; it must stay byte for byte as it was.\nwant:\n%s\ngot:\n%s",
			filepath.Base(path), want, got)
	}
}

// sharedWithSecrets is a config.yaml as two dashboards share it: a key the
// relay uses, an upstream token, a dictation key and a comment, none of which
// a save on one hub may rewrite.
const sharedWithSecrets = `# Shared by the :8080 and :8081 dashboards.
provider: claudecode
anthropic:
  api_key: sk-ant-shared
stt:
  groq_api_key: gsk_shared_key
ui:
  ci:
    enabled: false
    issuer: https://token.actions.githubusercontent.com
    upstream_auth_token: sk-ant-oat-shared-upstream
`

// hubOverlay is this hub's own file, with a comment the saves must keep.
const hubOverlay = `# :8081 only.
ui:
  allowed_origins:
    - https://hub.example:8888
`

func putJSON(t *testing.T, handler http.HandlerFunc, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	blob, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req := httptest.NewRequest(method, path, io.NopCloser(bytes.NewReader(blob)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler(rec, req)
	return rec
}

// TestCISettingsSaveWithAnOverlayLeavesConfigYAMLAlone: before the fix,
// handleCISettingsSave loaded and rewrote config.yaml even on a hub with an
// overlay, while ciEnabled read the merged view. A save was then either
// shadowed by the overlay or leaked into the other hub's file.
func TestCISettingsSaveWithAnOverlayLeavesConfigYAMLAlone(t *testing.T) {
	srv, sharedPath, overlayPath := overlaySettingsHub(t, sharedWithSecrets, hubOverlay)

	rec := putJSON(t, srv.handleCISettingsSave, http.MethodPut, "/api/ci/config", map[string]any{
		"enabled":        true,
		"audience":       "cloop-8081",
		"default_models": []string{"claude-sonnet-*"},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT /api/ci/config = %d: %s", rec.Code, rec.Body.String())
	}

	assertUnchanged(t, sharedPath, sharedWithSecrets)

	if !srv.ciEnabled() {
		t.Error("the saved enabled: true is not what the hub runs under")
	}
	view := srv.ciSettings(httptest.NewRequest(http.MethodGet, "/api/ci/config", nil))
	if view.Audience != "cloop-8081" || !view.Enabled {
		t.Errorf("the panel reads enabled=%v audience=%q after the save", view.Enabled, view.Audience)
	}

	raw, err := os.ReadFile(overlayPath)
	if err != nil {
		t.Fatalf("read overlay: %v", err)
	}
	overlay := string(raw)
	for _, want := range []string{"# :8081 only.", "https://hub.example:8888", "audience: cloop-8081"} {
		if !strings.Contains(overlay, want) {
			t.Errorf("the overlay lacks %q after the save:\n%s", want, overlay)
		}
	}
	// The relay's credential is not the panel's to copy into a second file.
	if strings.Contains(overlay, "sk-ant-oat-shared-upstream") {
		t.Errorf("the save copied the shared upstream token into the overlay:\n%s", overlay)
	}
}

// TestCISettingsSaveWithoutAnOverlayStillWritesConfigYAML pins the other
// branch: a hub with no overlay keeps its settings in config.yaml, as before.
func TestCISettingsSaveWithoutAnOverlayStillWritesConfigYAML(t *testing.T) {
	srv, sharedPath, overlayPath := overlaySettingsHub(t, sharedWithSecrets, "")

	rec := putJSON(t, srv.handleCISettingsSave, http.MethodPut, "/api/ci/config",
		map[string]any{"enabled": true, "audience": "cloop-solo"})
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT /api/ci/config = %d: %s", rec.Code, rec.Body.String())
	}
	if _, err := os.Stat(overlayPath); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a hub without an overlay had one created by a save (stat err = %v)", err)
	}
	cfg, err := config.Load(filepath.Dir(filepath.Dir(sharedPath)))
	if err != nil {
		t.Fatalf("load config.yaml: %v", err)
	}
	if !cfg.UI.CI.Enabled || cfg.UI.CI.Audience != "cloop-solo" {
		t.Errorf("config.yaml holds enabled=%v audience=%q, want the save", cfg.UI.CI.Enabled, cfg.UI.CI.Audience)
	}
	// Rewritten from itself, so nothing it held is lost.
	if cfg.UI.CI.UpstreamAuthToken != "sk-ant-oat-shared-upstream" || cfg.STT.GroqAPIKey != "gsk_shared_key" {
		t.Error("rewriting config.yaml dropped keys it held")
	}
}

// TestSTTSettingsSaveWithAnOverlayLeavesConfigYAMLAlone: the dictation key is
// the hub's. With an overlay it goes there, and a Clear clears it for this
// hub without deleting the key the other dashboard reads.
func TestSTTSettingsSaveWithAnOverlayLeavesConfigYAMLAlone(t *testing.T) {
	t.Setenv("GROQ_API_KEY", "")
	srv, sharedPath, overlayPath := overlaySettingsHub(t, sharedWithSecrets, hubOverlay)

	// Before any save the hub dictates with the shared key, because the
	// overlay states none.
	if got := srv.sttConfig(httptest.NewRequest(http.MethodPost, "/api/dictate", nil)).GroqAPIKey; got != "gsk_shared_key" {
		t.Fatalf("dictation key before the save = %q, want the shared one", got)
	}

	rec := putJSON(t, srv.handleSTTSettingsSave, http.MethodPut, "/api/config/stt",
		map[string]string{"groq_api_key": "gsk_this_hub_only"})
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT /api/config/stt = %d: %s", rec.Code, rec.Body.String())
	}
	assertUnchanged(t, sharedPath, sharedWithSecrets)
	if got := srv.sttConfig(httptest.NewRequest(http.MethodPost, "/api/dictate", nil)).GroqAPIKey; got != "gsk_this_hub_only" {
		t.Errorf("dictation key after the save = %q, want the one just saved", got)
	}
	raw, err := os.ReadFile(overlayPath)
	if err != nil {
		t.Fatalf("read overlay: %v", err)
	}
	if !strings.Contains(string(raw), "gsk_this_hub_only") || !strings.Contains(string(raw), "# :8081 only.") {
		t.Errorf("the overlay after the save:\n%s", raw)
	}

	// Clear: this hub stops dictating with a stored key, and the shared file
	// keeps the key the other dashboard uses.
	rec = httptest.NewRecorder()
	srv.handleSTTSettingsClear(rec, httptest.NewRequest(http.MethodDelete, "/api/config/stt", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("DELETE /api/config/stt = %d: %s", rec.Code, rec.Body.String())
	}
	assertUnchanged(t, sharedPath, sharedWithSecrets)
	if got := srv.hubSTTSettings(); got.Stored || got.HasKey {
		t.Errorf("after Clear the panel reports stored=%v has_key=%v; the shared key showed through",
			got.Stored, got.HasKey)
	}
}
