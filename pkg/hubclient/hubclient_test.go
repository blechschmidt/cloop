package hubclient

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/oidcauth"
)

// ── the credential file ─────────────────────────────────────────────────────

func TestDefaultPathFollowsXDG(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	got, err := DefaultPath()
	if err != nil || got != filepath.Join(dir, "cloop", "hubs.json") {
		t.Fatalf("DefaultPath = %q, %v", got, err)
	}
	// A relative XDG_CONFIG_HOME is ignored, as the spec says.
	home := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", "relative/dir")
	t.Setenv("HOME", home)
	got, err = DefaultPath()
	if err != nil || got != filepath.Join(home, ".config", "cloop", "hubs.json") {
		t.Fatalf("DefaultPath with a relative XDG_CONFIG_HOME = %q, %v", got, err)
	}
}

func TestCredentialFileIsWrittenPrivateAndRefusedWhenNot(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("mode bits do not protect a file on Windows")
	}
	dir := filepath.Join(t.TempDir(), "cloop")
	path := filepath.Join(dir, FileName)
	const secret = "cloop_cli_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

	f, err := Load(path)
	if err != nil || len(f.Hubs) != 0 {
		t.Fatalf("a missing file loads as %+v, %v; want empty", f, err)
	}
	f.Put(&Hub{URL: "https://hub.example.com", Credential: secret, SessionID: "abc"})
	if err := f.Save(path); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("credential file mode %#o, want 0600", fi.Mode().Perm())
	}
	di, err := os.Stat(dir)
	if err != nil || di.Mode().Perm() != 0o700 {
		t.Fatalf("credential directory mode %#o, want 0700", di.Mode().Perm())
	}
	back, err := Load(path)
	if err != nil || back.Default != "https://hub.example.com" {
		t.Fatalf("reload = %+v, %v", back, err)
	}
	if h, ok := back.Lookup("HTTPS://Hub.Example.com:443/"); !ok || h.Credential != secret {
		t.Fatal("lookup by another spelling of the URL missed the entry")
	}

	for _, mode := range []os.FileMode{0o640, 0o604, 0o644, 0o660} {
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		_, err := Load(path)
		if !errors.Is(err, ErrInsecurePermissions) {
			t.Fatalf("mode %#o: Load = %v, want ErrInsecurePermissions", mode, err)
		}
		if strings.Contains(err.Error(), secret) {
			t.Fatal("the refusal echoed the credential")
		}
		// logout may still read it, to revoke what may have been copied.
		if lf, err := LoadForRevocation(path); err != nil || len(lf.Hubs) != 1 {
			t.Fatalf("mode %#o: LoadForRevocation = %v", mode, err)
		}
	}

	// Not a plain file: refused by both.
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.json")
	if err := os.Symlink(path, link); err != nil {
		t.Skipf("symlink: %v", err)
	}
	if _, err := Load(link); !errors.Is(err, ErrInsecurePermissions) {
		t.Errorf("a symlinked credential file: %v, want ErrInsecurePermissions", err)
	}
	if _, err := LoadForRevocation(link); !errors.Is(err, ErrInsecurePermissions) {
		t.Errorf("LoadForRevocation of a symlink: %v, want ErrInsecurePermissions", err)
	}
}

func TestACorruptCredentialFileIsNotEchoed(t *testing.T) {
	path := filepath.Join(t.TempDir(), FileName)
	if err := os.WriteFile(path, []byte(`{"hubs": cloop_cli_secret-value`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Load(path)
	if err == nil || strings.Contains(err.Error(), "secret-value") {
		t.Fatalf("Load = %v; want a refusal that does not quote the file", err)
	}
}

func TestRemovingTheDefaultHandsItOnOnlyWhenObvious(t *testing.T) {
	f := &File{}
	f.Put(&Hub{URL: "https://a"})
	f.Put(&Hub{URL: "https://b"})
	f.Put(&Hub{URL: "https://c"})
	f.Remove("https://a")
	if f.Default != "" {
		t.Errorf("default after removing it with two left = %q, want none", f.Default)
	}
	f.Default = "https://b"
	f.Remove("https://b")
	if f.Default != "https://c" {
		t.Errorf("default with one hub left = %q, want it", f.Default)
	}
}

func TestNormalizeURL(t *testing.T) {
	for in, want := range map[string]string{
		"hub.example.com":              "https://hub.example.com",
		"HTTPS://Hub.Example.com/":     "https://hub.example.com",
		"https://hub.example.com:443":  "https://hub.example.com",
		"http://127.0.0.1:8080":        "http://127.0.0.1:8080",
		"http://localhost:80":          "http://localhost",
		"https://[::1]:8443":           "https://[::1]:8443",
		"https://hub.example.com:8888": "https://hub.example.com:8888",
	} {
		if got, err := NormalizeURL(in); err != nil || got != want {
			t.Errorf("NormalizeURL(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "ftp://hub", "https://hub/device", "https://u:p@hub", "https://hub?x=1", "https://"} {
		if _, err := NormalizeURL(bad); err == nil {
			t.Errorf("NormalizeURL(%q) accepted", bad)
		}
	}
}

func TestParseErrorReadsAllThreeDialects(t *testing.T) {
	for body, want := range map[string]APIError{
		`{"error":"slow_down","error_description":"wait","interval":10}`: {Code: "slow_down", Message: "wait", IntervalSeconds: 10},
		`{"error":"unauthorized"}`:                                       {Message: "unauthorized"},
		`{"error":{"code":"FORBIDDEN","message":"no"}}`:                  {Code: "FORBIDDEN", Message: "no"},
		`<html>gateway</html>`:                                           {Message: "<html>gateway</html>"},
	} {
		got := parseError(400, []byte(body))
		if got.Code != want.Code || got.Message != want.Message || got.IntervalSeconds != want.IntervalSeconds {
			t.Errorf("parseError(%s) = %+v, want %+v", body, *got, want)
		}
	}
}

// ── the device flow against a fake hub ──────────────────────────────────────

// fakeHub plays the hub's two device endpoints with a script of poll answers.
type fakeHub struct {
	t        *testing.T
	mu       sync.Mutex
	digest   string
	hostname string
	polls    []time.Time
	answers  []func(w http.ResponseWriter)
	approved string // session_id the final answer reports ("" = the one the commitment names)
	// page, when set, replaces the approval page URLs in the code answer.
	page string
	// reportCommitment has the final answer report the commitment itself as
	// the session's id: a hub that wrote the session under it.
	reportCommitment bool
}

func (h *fakeHub) serve() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/device/code", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			CredentialHash string `json:"credential_hash"`
			Hostname       string `json:"hostname"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || r.Header.Get("Authorization") != "" {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		h.mu.Lock()
		h.digest, h.hostname = req.CredentialHash, req.Hostname
		h.mu.Unlock()
		page, complete := "https://hub/device", "https://hub/device?code=BCDFG-HJKLM"
		if h.page != "" {
			page, complete = h.page, h.page
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"device_code": "dc-1", "user_code": "BCDFG-HJKLM",
			"verification_uri": page, "verification_uri_complete": complete,
			"expires_in": 600, "interval": 1,
		})
	})
	mux.HandleFunc("POST /api/device/token", func(w http.ResponseWriter, r *http.Request) {
		h.mu.Lock()
		h.polls = append(h.polls, time.Now())
		n := len(h.polls)
		var answer func(http.ResponseWriter)
		if n <= len(h.answers) {
			answer = h.answers[n-1]
		}
		sessionID := oidcauth.CLISessionID(h.digest)
		if h.approved != "" {
			sessionID = h.approved
		}
		if h.reportCommitment {
			sessionID = h.digest
		}
		h.mu.Unlock()
		if answer != nil {
			answer(w)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"token_type": "Bearer", "session_id": sessionID, "expires_in": 3600, "idle_timeout": 600,
			"revalidated": true, "identity": map[string]string{"sub": "u1", "email": "alice@example.com"},
		})
	})
	return httptest.NewServer(mux)
}

func oauthErr(code string, interval int) func(http.ResponseWriter) {
	return func(w http.ResponseWriter) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		body := map[string]any{"error": code, "error_description": code + " described"}
		if interval > 0 {
			body["interval"] = interval
		}
		_ = json.NewEncoder(w).Encode(body)
	}
}

func fastPolling(t *testing.T) {
	t.Helper()
	old := pollUnit
	pollUnit = 5 * time.Millisecond
	t.Cleanup(func() { pollUnit = old })
}

func TestLoginCommitsToItsCredentialAndHonoursSlowDown(t *testing.T) {
	fastPolling(t)
	hub := &fakeHub{t: t, answers: []func(http.ResponseWriter){
		oauthErr(oidcauth.DeviceErrPending, 0),
		oauthErr(oidcauth.DeviceErrSlowDown, 0),
		oauthErr(oidcauth.DeviceErrPending, 0),
	}}
	srv := hub.serve()
	defer srv.Close()

	var out strings.Builder
	h, err := Login(context.Background(), LoginOptions{HubURL: srv.URL, Hostname: "dev-laptop", Out: &out})
	if err != nil {
		t.Fatalf("Login: %v\n%s", err, out.String())
	}
	if !oidcauth.IsCLICredential(h.Credential) || oidcauth.HashSessionID(h.Credential) != hub.digest {
		t.Fatal("the stored credential is not the one whose digest the terminal sent")
	}
	if h.SessionID != oidcauth.CLISessionID(hub.digest) || h.Email != "alice@example.com" || hub.hostname != "dev-laptop" {
		t.Errorf("hub entry %+v", h)
	}
	if strings.Contains(out.String(), h.Credential) {
		t.Fatal("the instructions printed the credential")
	}
	if !strings.Contains(out.String(), "BCDFG-HJKLM") || !strings.Contains(out.String(), "https://hub/device") {
		t.Errorf("the instructions do not show the code and the page:\n%s", out.String())
	}
	if rv, idle := h.LoginNotes(); !rv || idle != 600*time.Second {
		t.Errorf("notes = %v %v", rv, idle)
	}

	// After the slow_down every gap is the raised interval (1+5 units).
	hub.mu.Lock()
	polls := append([]time.Time(nil), hub.polls...)
	hub.mu.Unlock()
	if len(polls) != 4 {
		t.Fatalf("%d polls, want 4", len(polls))
	}
	if gap := polls[2].Sub(polls[1]); gap < 6*pollUnit {
		t.Errorf("the poll after slow_down came %s later, want at least %s", gap, 6*pollUnit)
	}
	if gap := polls[3].Sub(polls[2]); gap < 6*pollUnit {
		t.Errorf("slow_down did not hold for later polls: %s", gap)
	}
}

func TestLoginRefusesAnApprovalForAnotherSession(t *testing.T) {
	fastPolling(t)
	for name, hub := range map[string]*fakeHub{
		"somebody else's":                        {t: t, approved: strings.Repeat("e", 64)},
		"one stored under the commitment itself": {t: t, reportCommitment: true},
	} {
		srv := hub.serve()
		if _, err := Login(context.Background(), LoginOptions{HubURL: srv.URL}); err == nil ||
			!strings.Contains(err.Error(), "other than the one this terminal committed to") {
			t.Errorf("%s: Login = %v, want a refusal", name, err)
		}
		srv.Close()
	}
}

func TestLoginOpensAndPrintsOnlyAnHTTPPage(t *testing.T) {
	fastPolling(t)
	for _, page := range []string{
		"file:///etc/passwd",
		`\\attacker\share\run.exe`,
		"ms-settings:privacy",
		"javascript:alert(1)",
		"https://hub/device\x1b]8;;https://evil/\x07",
		"https://hub/device\u202eexe.txt",
	} {
		hub := &fakeHub{t: t, page: page}
		srv := hub.serve()
		opened := false
		var out strings.Builder
		_, err := Login(context.Background(), LoginOptions{HubURL: srv.URL, Out: &out,
			OpenBrowser: func(string) error { opened = true; return nil }})
		srv.Close()
		if err == nil || !strings.Contains(err.Error(), "will not show") {
			t.Errorf("page %q: Login = %v, want a refusal", page, err)
		}
		if opened || strings.Contains(out.String(), page) {
			t.Errorf("page %q was opened or printed", page)
		}
	}
}

func TestLoginReportsDenialAndExpiry(t *testing.T) {
	fastPolling(t)
	for code, want := range map[string]error{oidcauth.DeviceErrDenied: ErrDenied, oidcauth.DeviceErrExpired: ErrExpired} {
		hub := &fakeHub{t: t, answers: []func(http.ResponseWriter){oauthErr(code, 0)}}
		srv := hub.serve()
		_, err := Login(context.Background(), LoginOptions{HubURL: srv.URL})
		srv.Close()
		if !errors.Is(err, want) {
			t.Errorf("%s: Login = %v, want %v", code, err, want)
		}
	}
	// invalid_grant — a code reused or unknown — is an error too.
	hub := &fakeHub{t: t, answers: []func(http.ResponseWriter){oauthErr(oidcauth.DeviceErrInvalidGrant, 0)}}
	srv := hub.serve()
	defer srv.Close()
	if _, err := Login(context.Background(), LoginOptions{HubURL: srv.URL}); err == nil {
		t.Fatal("invalid_grant was taken as success")
	}
}

func TestLoginStopsWhenCancelled(t *testing.T) {
	fastPolling(t)
	pending := make([]func(http.ResponseWriter), 1000)
	for i := range pending {
		pending[i] = oauthErr(oidcauth.DeviceErrPending, 0)
	}
	hub := &fakeHub{t: t, answers: pending}
	srv := hub.serve()
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
	defer cancel()
	if _, err := Login(ctx, LoginOptions{HubURL: srv.URL}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Login = %v, want the context's error", err)
	}
}

func TestTheClientNeverFollowsARedirectWithTheCredential(t *testing.T) {
	var leaked bool
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		leaked = r.Header.Get("Authorization") != ""
	}))
	defer other.Close()
	hub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/api/me", http.StatusFound)
	}))
	defer hub.Close()
	c, err := New(hub.URL, "", "cloop_cli_x")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Me(context.Background()); err == nil || leaked {
		t.Fatalf("Me = %v, leaked = %v; want a refusal and no credential sent on", err, leaked)
	}
}
