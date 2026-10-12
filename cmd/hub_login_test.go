package cmd

// Tests for the terminal's hub commands (Task 20412). The device flow itself
// is covered in pkg/hubclient and end to end in tests/e2e; these pin what the
// commands decide on their own: that they touch no local database, which hub
// and which credential they use, and that logout deletes nothing it could not
// revoke unless told to.

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/spf13/cobra"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/hubclient"
	"github.com/blechschmidt/cloop/pkg/oidcauth"
	"github.com/blechschmidt/cloop/pkg/state"
)

// credentialHome points the credential file at a fresh directory and returns
// its path.
func credentialHome(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("CLOOP_HUB_URL", "")
	t.Setenv("CLOOP_API_TOKEN", "")
	return filepath.Join(dir, "cloop", hubclient.FileName)
}

func writeCredentials(t *testing.T, path string, hubs ...*hubclient.Hub) {
	t.Helper()
	f := &hubclient.File{}
	for _, h := range hubs {
		f.Put(h)
	}
	if err := f.Save(path); err != nil {
		t.Fatal(err)
	}
}

func TestTheHubCommandsCreateNoDatabase(t *testing.T) {
	for _, c := range []*cobra.Command{loginCmd, logoutCmd, whoamiCmd, remoteProjectsCmd, remoteLogsCmd,
		remoteKubeShareCmd, remoteKubeListCmd, remoteKubeRenewCmd, remoteKubeRevokeCmd,
		remoteInitCmd, remoteExecutorsCmd, remoteReposListCmd, remoteReposAddCmd, remoteReposRemoveCmd,
		remoteGrantsRequestCmd, remoteGrantsListCmd, remoteGrantsWithdrawCmd,
		remoteFeaturesStartCmd, remoteFeaturesListCmd, remoteFeaturesPRCmd} {
		t.Run(c.CommandPath(), func(t *testing.T) {
			dir := t.TempDir()
			if err := os.MkdirAll(filepath.Join(dir, ".cloop"), 0o700); err != nil {
				t.Fatal(err)
			}
			t.Chdir(dir)
			if err := rootCmd.PersistentPreRunE(c, nil); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(state.DBPath(dir)); !os.IsNotExist(err) {
				t.Fatalf("%s's pre-run created %s in the directory it was run from", c.CommandPath(), state.DBPath(dir))
			}
		})
	}
}

func TestApplyConfigKey_DeviceLoginKeys(t *testing.T) {
	cfg := config.Default()
	for key, value := range map[string]string{
		"ui.oidc.device_login":                    "false",
		"ui.oidc.cli_session_ttl_hours":           "12",
		"ui.oidc.cli_idle_timeout_hours":          "2",
		"ui.oidc.device_approval_max_age_minutes": "-1",
	} {
		if err := applyConfigKey(cfg, key, value); err != nil {
			t.Fatalf("set %s=%s: %v", key, value, err)
		}
	}
	o := cfg.UI.OIDC
	if o.DeviceLoginEnabled() || o.CLISessionTTLHours != 12 || o.CLIIdleTimeoutHours != 2 ||
		o.EffectiveDeviceApprovalMaxAgeMinutes() != -1 {
		t.Fatalf("keys did not reach the config: %+v", o)
	}
	for key, value := range map[string]string{
		"ui.oidc.device_login":                    "maybe",
		"ui.oidc.cli_session_ttl_hours":           "1000",
		"ui.oidc.device_approval_max_age_minutes": "5000",
	} {
		if err := applyConfigKey(cfg, key, value); err == nil {
			t.Errorf("%s=%s was accepted", key, value)
		}
	}
	// The terminal's clocks never exceed the browser's, whatever is written.
	cfg.UI.OIDC.SessionTTLHours, cfg.UI.OIDC.IdleTimeoutHours = 8, 4
	cfg.UI.OIDC.CLISessionTTLHours, cfg.UI.OIDC.CLIIdleTimeoutHours = 48, 24
	if ttl, idle := cfg.UI.OIDC.EffectiveCLISessionTTLHours(), cfg.UI.OIDC.EffectiveCLIIdleTimeoutHours(); ttl != 8 || idle != 4 {
		t.Fatalf("effective CLI clocks %dh/%dh, want the browser's 8h/4h", ttl, idle)
	}
	ac := cfg.UI.OIDC.AuthConfig()
	if ac.DeviceLogin || ac.CLISessionTTL > ac.SessionTTL || ac.CLIIdleTimeout > ac.IdleTimeout {
		t.Fatalf("AuthConfig carried %+v", ac)
	}
}

// fakeLogoutHub answers POST /auth/logout and counts the calls.
func fakeLogoutHub(t *testing.T, status int, ended bool) (*httptest.Server, *int32) {
	t.Helper()
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/auth/logout" || !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer cloop_cli_") {
			http.Error(w, "unexpected", http.StatusTeapot)
			return
		}
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": status == 200, "ended": ended})
	}))
	t.Cleanup(srv.Close)
	return srv, &calls
}

func runLogout(t *testing.T, args []string, all, force bool) error {
	t.Helper()
	logoutAll, logoutForce = all, force
	t.Cleanup(func() { logoutAll, logoutForce = false, false })
	return logoutCmd.RunE(logoutCmd, args)
}

func TestLogoutRevokesAtTheHubBeforeDeleting(t *testing.T) {
	path := credentialHome(t)
	hub, calls := fakeLogoutHub(t, http.StatusOK, true)
	writeCredentials(t, path, &hubclient.Hub{URL: mustNormalize(t, hub.URL), Credential: testCredential, SessionID: "s1"})
	if err := runLogout(t, nil, false, false); err != nil {
		t.Fatalf("logout: %v", err)
	}
	if atomic.LoadInt32(calls) != 1 {
		t.Fatalf("the hub saw %d logout calls, want 1", *calls)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("the credential file outlived its last hub")
	}
}

func TestLogoutKeepsWhatItCouldNotRevokeUnlessForced(t *testing.T) {
	path := credentialHome(t)
	dead := httptest.NewServer(http.NotFoundHandler())
	url := mustNormalize(t, dead.URL)
	dead.Close() // nothing listens there now
	writeCredentials(t, path, &hubclient.Hub{URL: url, Credential: testCredential, SessionID: "s1"})

	if err := runLogout(t, nil, false, false); err == nil || !strings.Contains(err.Error(), "--force") {
		t.Fatalf("logout against an unreachable hub = %v, want a refusal naming --force", err)
	}
	if f, err := hubclient.Load(path); err != nil || len(f.Hubs) != 1 {
		t.Fatalf("the credential was deleted although its session could not be ended: %v", err)
	}
	if err := runLogout(t, nil, false, true); err != nil {
		t.Fatalf("logout --force: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("logout --force kept the credential")
	}
}

func TestLogoutForgetsASessionTheHubAlreadyEnded(t *testing.T) {
	path := credentialHome(t)
	hub, _ := fakeLogoutHub(t, http.StatusUnauthorized, false)
	writeCredentials(t, path, &hubclient.Hub{URL: mustNormalize(t, hub.URL), Credential: testCredential})
	if err := runLogout(t, nil, false, false); err != nil {
		t.Fatalf("logout of an already-ended session: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("an already-ended session was kept")
	}
}

func TestLogoutAllDisposesOfAnUnsafeFile(t *testing.T) {
	path := credentialHome(t)
	hub, calls := fakeLogoutHub(t, http.StatusOK, true)
	writeCredentials(t, path, &hubclient.Hub{URL: mustNormalize(t, hub.URL), Credential: testCredential})
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	// Everything that would present the credential refuses the file …
	if err := whoamiCmd.RunE(whoamiCmd, nil); err == nil || !strings.Contains(err.Error(), "logout --all") {
		t.Fatalf("whoami with a world-readable file = %v, want a refusal pointing at logout --all", err)
	}
	// … and logout revokes what may have been copied, then deletes it.
	if err := runLogout(t, nil, true, false); err != nil {
		t.Fatalf("logout --all: %v", err)
	}
	if atomic.LoadInt32(calls) != 1 {
		t.Fatal("logout --all did not revoke the session at its hub")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("the unsafe file was kept")
	}
}

func TestAttachUsesTheStoredSessionForTheHubItTargets(t *testing.T) {
	path := credentialHome(t)
	writeCredentials(t, path,
		&hubclient.Hub{URL: "https://hub-a.example.com", Credential: testCredential, SessionID: "a"},
		&hubclient.Hub{URL: "https://hub-b.example.com", Credential: testCredential2, SessionID: "b"})
	defer func() { attachHubURL, attachToken = "", "" }()

	// The default hub (the first signed in to) and its session.
	attachHubURL, attachToken = "", ""
	got, err := resolveAttachHub()
	if err != nil || got.base != "https://hub-a.example.com" || got.credential != testCredential || !got.fromLogin || !got.byDefault {
		t.Fatalf("default = %+v, %v", got, err)
	}
	// --hub names the other one, in any spelling.
	attachHubURL = "HTTPS://hub-b.example.com:443/"
	if got, err = resolveAttachHub(); err != nil || got.credential != testCredential2 || got.byDefault {
		t.Fatalf("--hub b = %+v, %v", got, err)
	}
	// An explicit token wins over the stored session.
	attachToken = "cloop_pat_explicit"
	if got, err = resolveAttachHub(); err != nil || got.credential != "cloop_pat_explicit" || got.fromLogin {
		t.Fatalf("--token = %+v, %v", got, err)
	}
	// A hub with no stored session is attempted with no credential, to be
	// told by the hub what it wants.
	attachToken, attachHubURL = "", "https://elsewhere.example.com"
	if got, err = resolveAttachHub(); err != nil || got.credential != "" {
		t.Fatalf("an unknown hub = %+v, %v", got, err)
	}
	// A credential file other users can read is refused, not presented.
	attachHubURL = ""
	if err := os.Chmod(path, 0o604); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveAttachHub(); err == nil || !errors.Is(err, hubclient.ErrInsecurePermissions) {
		t.Fatalf("an unsafe file = %v, want ErrInsecurePermissions", err)
	}
}

func TestRemoteClientRefusesAHubItIsNotSignedInTo(t *testing.T) {
	path := credentialHome(t)
	writeCredentials(t, path, &hubclient.Hub{URL: "https://hub-a.example.com", Credential: testCredential})
	defer func() { remoteHub, remoteToken = "", "" }()
	remoteHub = "https://hub-z.example.com"
	if _, err := remoteClient(); err == nil || !strings.Contains(err.Error(), "cloop login https://hub-z.example.com") {
		t.Fatalf("remoteClient = %v, want a pointer to cloop login", err)
	}
	remoteHub = ""
	c, err := remoteClient()
	if err != nil || c.Base != "https://hub-a.example.com" || c.Credential != testCredential {
		t.Fatalf("the default hub = %+v, %v", c, err)
	}
	remoteToken = "cloop_pat_x"
	if _, err := remoteClient(); err == nil || !strings.Contains(err.Error(), "--hub") {
		t.Fatalf("--token without --hub = %v", err)
	}
}

func TestLogoutOfOneHubRefusesAnUnsafeFile(t *testing.T) {
	path := credentialHome(t)
	hub, calls := fakeLogoutHub(t, http.StatusOK, true)
	writeCredentials(t, path,
		&hubclient.Hub{URL: mustNormalize(t, hub.URL), Credential: testCredential},
		&hubclient.Hub{URL: "https://hub-b.example.com", Credential: testCredential2})
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	// Signing out of one would write the other back into a private file,
	// though it may have been copied: only --all disposes of such a file.
	if err := runLogout(t, []string{hub.URL}, false, false); err == nil || !strings.Contains(err.Error(), "logout --all") {
		t.Fatalf("logout of one hub from an unsafe file = %v, want a pointer to logout --all", err)
	}
	if atomic.LoadInt32(calls) != 0 {
		t.Error("the refused logout still called the hub")
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o644 {
		t.Fatalf("the unsafe file was rewritten: %v", err)
	}
}

// fakeDeviceHub approves a terminal's code on its first poll, running
// meanwhile just before, and counts the sessions it is asked to end.
func fakeDeviceHub(t *testing.T, meanwhile func()) (*httptest.Server, *int32) {
	t.Helper()
	var commitment atomic.Value
	var ended int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/device/code":
			var req struct {
				CredentialHash string `json:"credential_hash"`
			}
			_ = json.NewDecoder(r.Body).Decode(&req)
			commitment.Store(req.CredentialHash)
			_ = json.NewEncoder(w).Encode(map[string]any{"device_code": "dc", "user_code": "BCDFG-HJKLM",
				"verification_uri": "https://hub.example.com/device", "expires_in": 600, "interval": 1})
		case "/api/device/token":
			if meanwhile != nil {
				meanwhile()
			}
			c, _ := commitment.Load().(string)
			_ = json.NewEncoder(w).Encode(map[string]any{"token_type": "Bearer",
				"session_id": oidcauth.CLISessionID(c), "expires_in": 3600,
				"identity": map[string]string{"sub": "u1", "email": "alice@example.com"}})
		case "/auth/logout":
			atomic.AddInt32(&ended, 1)
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "ended": true})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &ended
}

func runLogin(t *testing.T, hubURL string) error {
	t.Helper()
	loginNoBrowser = true
	t.Cleanup(func() { loginNoBrowser = false })
	return loginCmd.RunE(loginCmd, []string{hubURL})
}

func TestLoginKeepsWhatAnotherLoginWroteMeanwhile(t *testing.T) {
	path := credentialHome(t)
	other := &hubclient.Hub{URL: "https://hub-b.example.com", Credential: testCredential2, SessionID: "b"}
	hub, _ := fakeDeviceHub(t, func() {
		f := &hubclient.File{}
		f.Put(other)
		_ = f.Save(path)
	})
	if err := runLogin(t, hub.URL); err != nil {
		t.Fatalf("login: %v", err)
	}
	f, err := hubclient.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := f.Hubs[other.URL]; !ok {
		t.Error("the session another login stored while this one waited was lost")
	}
	if h, ok := f.Lookup(hub.URL); !ok || !oidcauth.IsCLICredential(h.Credential) {
		t.Errorf("this login's session was not kept: %+v", f.Hubs)
	}
}

func TestLoginReplacesItsPriorSessionAndEndsIt(t *testing.T) {
	path := credentialHome(t)
	hub, ended := fakeDeviceHub(t, nil)
	writeCredentials(t, path, &hubclient.Hub{URL: mustNormalize(t, hub.URL), Credential: testCredential, SessionID: "old"})
	if err := runLogin(t, hub.URL); err != nil {
		t.Fatalf("login: %v", err)
	}
	f, err := hubclient.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if h, ok := f.Lookup(hub.URL); !ok || h.Credential == testCredential {
		t.Fatalf("the new session did not replace the old one: %+v", f.Hubs)
	}
	if atomic.LoadInt32(ended) != 1 {
		t.Fatalf("the hub was asked to end %d sessions, want the replaced one", *ended)
	}
}

func TestLoginEndsASessionItCannotKeep(t *testing.T) {
	path := credentialHome(t)
	// While the terminal waits, its credential file becomes one other users
	// can read: the new session must not go into it, nor stay live unheld.
	hub, ended := fakeDeviceHub(t, func() {
		f := &hubclient.File{}
		f.Put(&hubclient.Hub{URL: "https://hub-b.example.com", Credential: testCredential2})
		_ = f.Save(path)
		_ = os.Chmod(path, 0o644)
	})
	if err := runLogin(t, hub.URL); err == nil || !strings.Contains(err.Error(), "could not keep the session") {
		t.Fatalf("login = %v, want a failure to keep the session", err)
	}
	if atomic.LoadInt32(ended) != 1 {
		t.Fatal("the session the terminal could not keep was left live at the hub")
	}
}

func TestPlainHTTPIsFlaggedOffLoopbackOnly(t *testing.T) {
	for raw, want := range map[string]bool{
		"http://hub.example.com":   true,
		"http://10.0.0.5:8080":     true,
		"http://127.0.0.1:8080":    false,
		"http://[::1]:8080":        false,
		"http://localhost:8888":    false,
		"https://hub.example.com":  false,
		"https://127.0.0.1:8443/x": false,
	} {
		if got := plainHTTPToAnotherHost(raw); got != want {
			t.Errorf("plainHTTPToAnotherHost(%q) = %v, want %v", raw, got, want)
		}
	}
}

func TestAnAPITokenGoesOnlyToItsHub(t *testing.T) {
	path := credentialHome(t)
	writeCredentials(t, path,
		&hubclient.Hub{URL: "https://hub-a.example.com", Credential: testCredential, SessionID: "a"},
		&hubclient.Hub{URL: "https://hub-b.example.com", Credential: testCredential2, SessionID: "b"})
	defer func() { attachHubURL, attachToken, remoteHub, remoteToken = "", "", "", "" }()
	attach := func(hub string) attachHub {
		t.Helper()
		attachHubURL, attachToken = hub, ""
		got, err := resolveAttachHub()
		if err != nil {
			t.Fatalf("attach --hub %q: %v", hub, err)
		}
		return got
	}
	remote := func(hub string) (*hubclient.Client, error) {
		remoteHub, remoteToken = hub, ""
		return remoteClient()
	}

	// Beside CLOOP_HUB_URL, the token is that hub's and no other's.
	t.Setenv("CLOOP_HUB_URL", "https://hub-a.example.com")
	t.Setenv("CLOOP_API_TOKEN", "cloop_pat_for_a")
	if got := attach(""); got.base != "https://hub-a.example.com" || got.credential != "cloop_pat_for_a" {
		t.Errorf("attach, CLOOP_HUB_URL's hub: %+v", got)
	}
	if got := attach("https://hub-b.example.com"); got.credential != testCredential2 {
		t.Errorf("attach --hub b: %+v, want b's own session", got)
	}
	if got := attach("https://hub-z.example.com"); got.credential != "" {
		t.Errorf("attach --hub z: sent %q to a hub the token is not for", got.credential)
	}
	if c, err := remote(""); err != nil || c.Credential != "cloop_pat_for_a" {
		t.Errorf("remote, CLOOP_HUB_URL's hub: %+v, %v", c, err)
	}
	if c, err := remote("https://hub-b.example.com"); err != nil || c.Credential != testCredential2 {
		t.Errorf("remote --hub b: %+v, %v, want b's own session", c, err)
	}
	if c, err := remote("https://hub-z.example.com"); err == nil {
		t.Errorf("remote --hub z: sent %q to a hub the token is not for", c.Credential)
	}

	// Alone, it is the local hub's when nothing names a hub, and otherwise
	// only for a hub with no session of its own.
	t.Setenv("CLOOP_HUB_URL", "")
	t.Setenv("CLOOP_API_TOKEN", "cloop_pat_loose")
	if got := attach(""); got.base != localHub || got.credential != "cloop_pat_loose" {
		t.Errorf("attach, no hub named: %+v", got)
	}
	if got := attach("https://hub-b.example.com"); got.credential != testCredential2 {
		t.Errorf("attach --hub b: %+v, want b's own session over the loose token", got)
	}
	if got := attach("https://hub-z.example.com"); got.credential != "cloop_pat_loose" {
		t.Errorf("attach --hub z: %+v, want the token, all there is for it", got)
	}
	if c, err := remote(""); err != nil || c.Credential != testCredential {
		t.Errorf("remote, the default hub: %+v, %v, want its own session", c, err)
	}
	if c, err := remote("https://hub-z.example.com"); err != nil || c.Credential != "cloop_pat_loose" {
		t.Errorf("remote --hub z: %+v, %v", c, err)
	}
}

func TestWhoamiNeverPrintsTheCredential(t *testing.T) {
	path := credentialHome(t)
	hub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"email": "alice@example.com", "sub": "s", "role": "operator", "session_kind": "cli",
			"session_expires_in_seconds": 3600,
		})
	}))
	defer hub.Close()
	writeCredentials(t, path, &hubclient.Hub{URL: mustNormalize(t, hub.URL), Credential: testCredential, SessionID: "abcdef0123456789"})
	out, err := captureStdout(t, func() error { return whoamiCmd.RunE(whoamiCmd, nil) })
	if err != nil {
		t.Fatalf("whoami: %v", err)
	}
	if strings.Contains(out, testCredential) || !strings.Contains(out, "alice@example.com") || !strings.Contains(out, "abcdef012345") {
		t.Fatalf("whoami printed:\n%s", out)
	}
}

const (
	testCredential  = "cloop_cli_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	testCredential2 = "cloop_cli_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
)

func mustNormalize(t *testing.T, raw string) string {
	t.Helper()
	u, err := hubclient.NormalizeURL(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}
