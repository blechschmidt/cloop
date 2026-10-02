package ui

// Which way back a 401 offers, per deployment (Task 20359, re-landing Task
// 20330).
//
// On an SSO hub a lapsed session used to open the token prompt — a box asking
// for an access token no identity provider issues. The fix is a branch, and a
// branch is only as good as the fact it reads: who authenticates at this hub,
// which has to survive the session it outlives and be knowable from a refusal
// alone, since on such a hub /api/me needs a session too.
//
// Driven through the real bundle under testdata/domshim.js: the property spans
// three files and two async hops, none of them greppable as text.
// renew_api_test.go covers the hub's half, renew_browser_test.go the browser's.

import (
	"encoding/json"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// signinView is what the user is looking at after a 401 has been handled.
type signinView struct {
	Assigns    []string `json:"assigns"`
	LoginModal bool     `json:"login_modal"`
	Banner     bool     `json:"banner"`
	BannerText string   `json:"banner_text"`
	Resume     *string  `json:"resume"`
	SigninAt   *string  `json:"signin_at"`
	Error      string   `json:"error"`
}

type signinResults struct {
	SSOLapsedAtBoot signinView `json:"sso_lapsed_at_boot"`
	TokenHub        signinView `json:"token_hub"`
	SSOSocketDrop   struct {
		First  signinView `json:"first"`
		Second signinView `json:"second"`
		Error  string     `json:"error"`
	} `json:"sso_socket_drop"`
	ModeOutlivesTheSession signinView `json:"mode_outlives_the_session"`
	LoopGuard              struct {
		Before     signinView `json:"before"`
		AfterClick signinView `json:"after_click"`
		Error      string     `json:"error"`
	} `json:"loop_guard"`
	Resume struct {
		Assigns     []string `json:"assigns"`
		Breadcrumb  string   `json:"breadcrumb"`
		TasksActive bool     `json:"tasks_active"`
		SocketScope *int     `json:"socket_scope"`
		ResumeLeft  *string  `json:"resume_left"`
		Error       string   `json:"error"`
	} `json:"resume"`
	SavesTheView signinView `json:"saves_the_view"`
}

func runSigninScenarios(t *testing.T) signinResults {
	t.Helper()
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed; cannot drive the bundle")
	}
	dir := t.TempDir()
	bundle := filepath.Join(dir, "bundle.js")
	if err := os.WriteFile(bundle, []byte(loadAssets().bundle), 0o644); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	shim, err := filepath.Abs("testdata/domshim.js")
	if err != nil {
		t.Fatalf("resolve shim: %v", err)
	}
	scenarios, err := filepath.Abs("testdata/signin_scenarios.js")
	if err != nil {
		t.Fatalf("resolve scenarios: %v", err)
	}
	cmd := exec.Command(node, scenarios, shim, bundle)
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		stderr := ""
		if ee, ok := err.(*exec.ExitError); ok {
			stderr = string(ee.Stderr)
		}
		t.Fatalf("running the scenarios failed: %v\nstdout:\n%s\nstderr:\n%s", err, out, stderr)
	}
	var res signinResults
	if err := json.Unmarshal(out, &res); err != nil {
		t.Fatalf("scenario output is not JSON: %v\n%s", err, out)
	}
	return res
}

func TestDashboard_UnauthorizedPicksTheRightSignIn(t *testing.T) {
	res := runSigninScenarios(t)

	// navigatedToSignIn asserts exactly one navigation, to the hub's own login
	// route, carrying where the user was.
	navigatedToSignIn := func(t *testing.T, assigns []string) {
		t.Helper()
		if len(assigns) != 1 {
			t.Fatalf("navigations = %v, want exactly one sign-in redirect", assigns)
		}
		u, err := url.Parse(assigns[0])
		if err != nil || u.Path != "/auth/login" || u.Query().Get("return") != "/" {
			t.Fatalf("navigated to %q, want /auth/login?return=/ — the return path is what "+
				"puts the user back on the page they were on", assigns[0])
		}
	}

	t.Run("a lapsed SSO session goes to the identity provider", func(t *testing.T) {
		v := res.SSOLapsedAtBoot
		if v.Error != "" {
			t.Fatalf("scenario failed: %s", v.Error)
		}
		if v.LoginModal {
			t.Error("the token prompt opened on an SSO hub — it asks for an access token " +
				"no identity provider issues (Task 20330)")
		}
		navigatedToSignIn(t, v.Assigns)
		if v.SigninAt == nil {
			t.Error("the navigation left no record for the loop guard on the page it returns to")
		}
		// Refused before the page had drawn anything: the tab and project are
		// still the defaults, and restoring them would override the landing
		// page the sign-in should come back to.
		if v.Resume != nil {
			t.Errorf("a 401 at boot saved a view to restore: %s", *v.Resume)
		}
	})

	t.Run("a token-only hub still prompts for a token", func(t *testing.T) {
		v := res.TokenHub
		if v.Error != "" {
			t.Fatalf("scenario failed: %s", v.Error)
		}
		if !v.LoginModal {
			t.Error("no token prompt on a token-only hub — on a deployment with no identity " +
				"provider it is the only way in, and the fix must not remove it")
		}
		if len(v.Assigns) != 0 {
			t.Errorf("navigated to %v on a hub with no identity provider", v.Assigns)
		}
	})

	t.Run("a session that lapses under an open tab", func(t *testing.T) {
		s := res.SSOSocketDrop
		if s.Error != "" {
			t.Fatalf("scenario failed: %s", s.Error)
		}
		if s.First.LoginModal || s.Second.LoginModal {
			t.Error("the token prompt opened when the socket's reconnect probe was refused")
		}
		navigatedToSignIn(t, s.First.Assigns)
		if len(s.Second.Assigns) != 1 {
			t.Errorf("navigations after a second refusal = %v, want still one: a hub that keeps "+
				"refusing must not bounce the tab to the provider in a loop", s.Second.Assigns)
		}
		if !s.Second.Banner || !strings.Contains(s.Second.BannerText, "ended") {
			t.Errorf("after the guard held, the banner = %v %q, want it saying the sign-in ended",
				s.Second.Banner, s.Second.BannerText)
		}
	})

	t.Run("knowing the hub uses SSO survives the session lapsing", func(t *testing.T) {
		v := res.ModeOutlivesTheSession
		if v.Error != "" {
			t.Fatalf("scenario failed: %s", v.Error)
		}
		// The regression: one flag meant both "SSO hub" and "live session",
		// so it was false exactly when a session lapsed.
		if v.LoginModal {
			t.Error("an unhinted 401 after /api/me reported no session opened the token prompt — " +
				"\"no live session\" was read as \"not an SSO hub\" (Task 20330)")
		}
		navigatedToSignIn(t, v.Assigns)
	})

	t.Run("a sign-in that came back without a session is not repeated", func(t *testing.T) {
		s := res.LoopGuard
		if s.Error != "" {
			t.Fatalf("scenario failed: %s", s.Error)
		}
		if len(s.Before.Assigns) != 0 {
			t.Fatalf("navigated %v straight after an automatic sign-in that did not work — "+
				"a hub whose cookie the browser refuses would loop for ever", s.Before.Assigns)
		}
		if !s.Before.Banner || s.Before.LoginModal {
			t.Errorf("banner=%v modal=%v, want the banner and no token prompt", s.Before.Banner, s.Before.LoginModal)
		}
		if len(s.AfterClick.Assigns) != 1 {
			t.Errorf("the banner's Sign in button navigated %v, want once: the guard is for "+
				"automatic redirects, not for a person who chose to retry", s.AfterClick.Assigns)
		}
	})

	t.Run("the sign-in comes back to the project and tab", func(t *testing.T) {
		s := res.Resume
		if s.Error != "" {
			t.Fatalf("scenario failed: %s", s.Error)
		}
		if s.Breadcrumb != "beta" {
			t.Errorf("project after the sign-in = %q, want beta — the one the user was in", s.Breadcrumb)
		}
		if s.SocketScope == nil || *s.SocketScope != 1 {
			t.Errorf("the live stream is scoped to %v, want beta's index 1", s.SocketScope)
		}
		if !s.TasksActive {
			t.Error("the Tasks tab is not active after the sign-in, though the user was on it")
		}
		if s.ResumeLeft != nil {
			t.Errorf("the saved view outlived its use: %q — a later page load would jump there", *s.ResumeLeft)
		}
		if len(s.Assigns) != 0 {
			t.Errorf("a healthy page load navigated: %v", s.Assigns)
		}
	})

	t.Run("leaving for a sign-in records the view", func(t *testing.T) {
		v := res.SavesTheView
		if v.Error != "" {
			t.Fatalf("scenario failed: %s", v.Error)
		}
		navigatedToSignIn(t, v.Assigns)
		if v.Resume == nil {
			t.Fatal("no view saved for the page the sign-in returns to")
		}
		var saved struct {
			Path string `json:"path"`
			Tab  string `json:"tab"`
		}
		if err := json.Unmarshal([]byte(*v.Resume), &saved); err != nil {
			t.Fatalf("saved view %q: %v", *v.Resume, err)
		}
		if saved.Path != "/p/beta" || saved.Tab != "kanban" {
			t.Errorf("saved view = %+v, want beta's path and the kanban tab", saved)
		}
	})
}
