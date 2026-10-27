package ui

// The "Confirm it's you" dialog in a real browser (Task 20448).
//
// sudo_cluster_test.go and tests/security prove the hub refuses a stale
// session's privileged request and honours a fresh sign-in. What only a browser
// can show is the dashboard's half: that a refused click opens the dialog under
// the hub's script policy, that its button opens the identity provider in a
// window of its own and the refused request then goes through from the page it
// was made on — nothing typed into it lost — and that where no window opens the
// tab goes itself, comes back to the same view and asks for the button again.
// The second half runs at the 360 px the users' phones report.

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/authz"
	"github.com/blechschmidt/cloop/pkg/multiui"
	"github.com/blechschmidt/cloop/pkg/oidcauth"
)

type reauthBrowserPhase struct {
	DialogShown    bool     `json:"dialog_shown"`
	WindowText     string   `json:"window_text"`
	FocusOnGo      bool     `json:"focus_on_go"`
	CancelRejected bool     `json:"cancel_rejected"`
	Enrolled       bool     `json:"enrolled"`
	DialogHidden   bool     `json:"dialog_hidden"`
	Prompts        int      `json:"prompts"`
	NameKept       string   `json:"name_kept"`
	Fits           bool     `json:"fits"`
	Layout         string   `json:"layout"`
	CameBack       bool     `json:"came_back"`
	Toast          string   `json:"toast"`
	ErrorToasts    []string `json:"error_toasts"`
	CSPViolations  []string `json:"csp_violations"`
}

type reauthBrowserResult struct {
	Error *struct {
		Message string `json:"message"`
	} `json:"error"`
	Window  reauthBrowserPhase `json:"window"`
	SameTab reauthBrowserPhase `json:"same_tab"`
	// EnrollStatuses is every answer the hub gave the page's enrollment
	// requests, in order.
	EnrollStatuses []int `json:"enroll_statuses"`
}

func TestConfirmItsYouDialogInBrowser(t *testing.T) {
	chrome := findChrome()
	if chrome == "" {
		t.Skip("no Chrome/Chromium installed; cannot drive the dialog")
	}
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed; cannot drive the browser")
	}
	t.Setenv("HOME", t.TempDir())
	t.Setenv(multiui.EnvRoot, t.TempDir())

	idp := newUIFakeIdP(t)
	idp.groups = []string{"owners"}
	// The provider's own sign-in is three hours old, so the dashboard's
	// sign-in — silent, from that session — is not recent.
	idp.setSignedInAt(time.Now().Add(-3 * time.Hour))

	// Everything the hub serves is configured before it serves anything:
	// Chrome's requests carry no happens-before edge for the race detector.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	base := "http://" + ln.Addr().String()
	dir := setupProjectDir(t, cloopGoal, nil)
	s := New(dir, 0, "")
	s.RPS, s.Burst = 10000, 10000
	auth, err := oidcauth.New(oidcauth.Config{
		Enabled:     true,
		Issuer:      idp.server.URL,
		ClientID:    "cloop-dashboard",
		RedirectURL: base + "/auth/callback",
	})
	if err != nil {
		t.Fatalf("oidcauth.New: %v", err)
	}
	s.OIDC = auth
	resolver, err := authz.New(authz.Config{
		Bindings: []authz.Binding{{Claim: authz.ClaimGroup, Value: "owners", Role: authz.RoleAdmin}},
	})
	if err != nil {
		t.Fatalf("authz.New: %v", err)
	}
	s.Authz = resolver
	hub := httptest.NewUnstartedServer(s.Handler())
	hub.Listener.Close()
	hub.Listener = ln
	hub.Start()
	defer hub.Close()

	// The driver's levers: how many times the provider was told to ask, and
	// making the next sign-in stale again.
	control := http.NewServeMux()
	control.HandleFunc("GET /stats", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]int{"prompts": idp.loginPromptCount()})
	})
	control.HandleFunc("POST /stale", func(w http.ResponseWriter, r *http.Request) {
		idp.setSignedInAt(time.Now().Add(-3 * time.Hour))
	})
	ctl := httptest.NewServer(control)
	defer ctl.Close()

	cmd := exec.Command(node, mustAbs(t, "testdata/reauth_browser.js"), chrome, base, ctl.URL)
	out, err := cmd.Output()
	if os.Getenv("REAUTH_BROWSER_DEBUG") != "" {
		t.Logf("driver output:\n%s", out)
	}
	if err != nil {
		stderr := ""
		if ee, ok := err.(*exec.ExitError); ok {
			stderr = string(ee.Stderr)
		}
		t.Fatalf("driving the browser failed: %v\nstdout:\n%s\nstderr:\n%s", err, out, stderr)
	}
	var got reauthBrowserResult
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("decoding results: %v\nraw:\n%s", err, out)
	}
	if got.Error != nil {
		t.Fatalf("driver: %s\nraw:\n%s", got.Error.Message, out)
	}

	w := got.Window
	switch {
	case !w.DialogShown:
		t.Errorf("a refused enrollment did not open the dialog: %+v", w)
	case w.WindowText != "2 hours":
		t.Errorf("the dialog says the window is %q, want 2 hours", w.WindowText)
	case !w.FocusOnGo:
		t.Errorf("focus did not move into the dialog")
	case !w.CancelRejected:
		t.Errorf("Cancel did not close the dialog and give the click back: %+v", w)
	case !w.Enrolled || !w.DialogHidden:
		t.Errorf("after signing in in the window the enrollment did not go through from the page: %+v", w)
	case w.Prompts != 1:
		t.Errorf("the provider was told to ask %d times, want once", w.Prompts)
	case w.NameKept != "edge-browser":
		t.Errorf("the replayed request did not carry what was typed: %q", w.NameKept)
	}
	sm := got.SameTab
	switch {
	case !sm.DialogShown:
		t.Errorf("at 360px the refused enrollment did not open the dialog: %+v", sm)
	case !sm.Fits:
		t.Errorf("the dialog does not fit a 360px screen: %s", sm.Layout)
	case !sm.CameBack:
		t.Errorf("the same-tab sign-in did not come back to the Executors tab: %+v", sm)
	case sm.Toast == "":
		t.Errorf("coming back, nothing asked for the button once more")
	case !sm.Enrolled:
		t.Errorf("pressing it once more did not enroll: %+v", sm)
	case sm.Prompts != 2:
		t.Errorf("the provider was told to ask %d times in all, want twice", sm.Prompts)
	}
	for _, p := range []reauthBrowserPhase{w, sm} {
		if len(p.CSPViolations) > 0 {
			t.Errorf("the policy blocked something: %v", p.CSPViolations)
		}
	}
	minted := 0
	for _, st := range got.EnrollStatuses {
		if st == http.StatusOK {
			minted++
		} else if st != http.StatusUnauthorized {
			t.Errorf("an enrollment request was answered %d: %v", st, got.EnrollStatuses)
		}
	}
	if minted != 2 {
		t.Errorf("the hub minted %d enrollment tokens, want 2, one per confirmed press: %v", minted, got.EnrollStatuses)
	}
}
