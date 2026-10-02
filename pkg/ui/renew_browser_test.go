package ui

// Silent sign-in renewal, observed in a real browser (Task 20359).
//
// renew_api_test.go proves the hub's half and signin_redirect_test.go the
// bundle's decisions. Neither can prove the half that decides whether any of it
// works, because the user agent enforces it:
//
//	the frame      a hidden iframe navigating to the provider and back
//	the policy     frame-src checked against the framing document on every hop,
//	               frame-ancestors on the documents the frame loads
//	the answer     a postMessage crossing the frame boundary, origin-checked
//	the navigation a top-level trip through the provider that has to come back
//	               to the same tab and view
//
// A hub can serve a perfect renewal endpoint and still have a feature that never
// fires, because the browser refused a hop. That looks, from everywhere else,
// like the provider timing out — which is why this test exists.
//
// One Chrome session walks the four behaviours the task names in order:
// scheduled renewal, the reactive retry, the banner when the provider needs the
// user (and its sign-in coming back to the same view), and the 401 redirect.
// The hub's clock is the only thing moved by hand — the driver asks a control
// endpoint to advance it — so each phase meets claims exactly as stale as it
// needs. Skips without Chrome or node, like the other browser gates here.

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/authz"
	"github.com/blechschmidt/cloop/pkg/oidcauth"
)

// browserClock is the hub's clock: real time plus whatever the driver asked for.
type browserClock struct {
	mu  sync.Mutex
	off time.Duration
}

func (c *browserClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return time.Now().Add(c.off)
}

func (c *browserClock) advance(d time.Duration) {
	c.mu.Lock()
	c.off += d
	c.mu.Unlock()
}

// renewBrowserPhase is what the driver reports about one phase.
type renewBrowserPhase struct {
	Error string `json:"error"`

	RenewRequests     int      `json:"renew_requests"`
	PromptNone        int      `json:"prompt_none"`
	MeAfterRenewal    int      `json:"me_after_renewal"`
	ClaimAge          int      `json:"claim_age"`
	Frames            int      `json:"frames"`
	Banner            bool     `json:"banner"`
	BannerText        string   `json:"banner_text"`
	AuditStatuses     []int    `json:"audit_statuses"`
	AuditMessage      string   `json:"audit_message"`
	ErrorToasts       []string `json:"error_toasts"`
	LoginRequests     int      `json:"login_requests"`
	LoginURL          string   `json:"login_url"`
	LoginModal        bool     `json:"login_modal"`
	AuditTabActive    bool     `json:"audit_tab_active"`
	SignedIn          bool     `json:"signed_in"`
	Location          string   `json:"location"`
	CSPViolations     []string `json:"csp_violations"`
	ElapsedMS         int      `json:"elapsed_ms"`
	RenewOutcome      string   `json:"renew_outcome"`
	TokenPromptEver   bool     `json:"token_prompt_ever"`
	AutomaticRedirect bool     `json:"automatic_redirect"`
}

type renewBrowserResult struct {
	Error *struct {
		Message string `json:"message"`
	} `json:"error"`
	Boot      renewBrowserPhase `json:"boot"`
	Scheduled renewBrowserPhase `json:"scheduled"`
	Reactive  renewBrowserPhase `json:"reactive"`
	Banner    renewBrowserPhase `json:"banner"`
	BackIn    renewBrowserPhase `json:"back_in"`
	Blocked   renewBrowserPhase `json:"blocked"`
	Lapsed    renewBrowserPhase `json:"lapsed"`
}

func TestSilentRenewalInBrowser(t *testing.T) {
	chrome := findChrome()
	if chrome == "" {
		t.Skip("no Chrome/Chromium installed; cannot observe a frame crossing origins")
	}
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed; cannot drive the browser")
	}
	t.Setenv("HOME", t.TempDir())

	idp := newUIFakeIdP(t)
	idp.groups = []string{"owners"}
	clk := &browserClock{}

	// Everything the hub serves is configured before it serves anything:
	// requests from Chrome carry no happens-before edge the race detector can
	// see, so a field written after the listener starts would read as a race.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	base := "http://" + ln.Addr().String()
	dir := setupProjectDir(t, cloopGoal, nil)
	s := New(dir, 0, "")
	auth, err := oidcauth.New(oidcauth.Config{
		Enabled:     true,
		Issuer:      idp.server.URL,
		ClientID:    "cloop-dashboard",
		RedirectURL: base + "/auth/callback",
		// No refresh token is ever retained and the background pass is off:
		// the deployment browser renewal exists for.
		RefreshInterval: -1,
		MaxClaimAge:     5 * time.Minute,
		Clock:           clk.now,
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

	// The driver's levers, and nothing else.
	control := http.NewServeMux()
	control.HandleFunc("POST /advance", func(w http.ResponseWriter, r *http.Request) {
		secs, err := strconv.Atoi(r.URL.Query().Get("seconds"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		clk.advance(time.Duration(secs) * time.Second)
	})
	control.HandleFunc("POST /silent", func(w http.ResponseWriter, r *http.Request) {
		idp.setSilentError(r.URL.Query().Get("error"))
		idp.setSilentFramingDenied(r.URL.Query().Get("frame") == "deny")
	})
	control.HandleFunc("POST /revoke", func(w http.ResponseWriter, r *http.Request) {
		recs, err := s.OIDC.ListSessions()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		for _, rec := range recs {
			_, _ = s.OIDC.RevokeSession(rec.ID, "test", "the browser test ends the session")
		}
	})
	control.HandleFunc("GET /stats", func(w http.ResponseWriter, r *http.Request) {
		all, silent := idp.authorizeCounts()
		_ = json.NewEncoder(w).Encode(map[string]int{"authorize": all, "prompt_none": silent})
	})
	ctl := httptest.NewServer(control)
	defer ctl.Close()

	cmd := exec.Command(node, mustAbs(t, "testdata/renew_browser.js"), chrome, base, ctl.URL)
	out, err := cmd.Output()
	if os.Getenv("RENEW_BROWSER_DEBUG") != "" {
		t.Logf("driver output:\n%s", out)
	}
	if err != nil {
		stderr := ""
		if ee, ok := err.(*exec.ExitError); ok {
			stderr = string(ee.Stderr)
		}
		t.Fatalf("driving the browser failed: %v\nstdout:\n%s\nstderr:\n%s", err, out, stderr)
	}
	var got renewBrowserResult
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("decoding results: %v\nraw:\n%s", err, out)
	}
	if got.Error != nil {
		t.Fatalf("the driver reported an error: %s\n%s", got.Error.Message, out)
	}
	phase := func(t *testing.T, p renewBrowserPhase) {
		t.Helper()
		if p.Error != "" {
			t.Fatalf("phase failed in the browser: %s", p.Error)
		}
		if len(p.CSPViolations) > 0 {
			t.Errorf("the browser reported Content-Security-Policy violations: %v", p.CSPViolations)
		}
	}

	t.Run("boot", func(t *testing.T) {
		phase(t, got.Boot)
		if got.Boot.Banner {
			t.Error("the renewal banner is up before anything has failed")
		}
	})

	t.Run("a scheduled renewal completes without the user seeing anything", func(t *testing.T) {
		p := got.Scheduled
		phase(t, p)
		if p.RenewRequests != 1 || p.PromptNone != 1 {
			t.Fatalf("/auth/renew requested %d times, prompt=none reached the provider %d times; want 1 and 1. "+
				"A frame that never reaches the provider is what a frame-src without it looks like",
				p.RenewRequests, p.PromptNone)
		}
		if p.ClaimAge > 30 {
			t.Errorf("claim age %ds after the renewal: the frame said ok but the claims did not move", p.ClaimAge)
		}
		if p.Banner {
			t.Error("a successful renewal raised the banner")
		}
		if p.Frames != 0 {
			t.Errorf("%d iframe(s) left behind; an open tab would accumulate one per renewal", p.Frames)
		}
		if p.MeAfterRenewal != 0 {
			t.Errorf("the page asked /api/me %d time(s) to re-arm after the renewal; that request counts as "+
				"activity, and an unattended tab would never idle out", p.MeAfterRenewal)
		}
	})

	t.Run("a privileged call refused for claim age is renewed and retried", func(t *testing.T) {
		p := got.Reactive
		phase(t, p)
		if len(p.AuditStatuses) != 2 || p.AuditStatuses[0] != http.StatusForbidden || p.AuditStatuses[1] != http.StatusOK {
			t.Fatalf("GET /api/audit statuses = %v, want [403 200]: one refusal, one renewal, one retry", p.AuditStatuses)
		}
		if p.RenewRequests != 1 {
			t.Errorf("/auth/renew requested %d times for one refusal, want 1", p.RenewRequests)
		}
		if len(p.ErrorToasts) != 0 {
			t.Errorf("the user was shown %v for a refusal that was cleared silently", p.ErrorToasts)
		}
		if p.Banner {
			t.Error("the banner went up although the renewal succeeded")
		}
	})

	t.Run("a provider that needs the user raises the banner", func(t *testing.T) {
		p := got.Banner
		phase(t, p)
		if p.RenewOutcome != "interaction_required" {
			t.Errorf("renewal outcome = %q, want interaction_required", p.RenewOutcome)
		}
		if !p.Banner || !strings.Contains(p.BannerText, "needs renewing") {
			t.Fatalf("no banner after the provider asked to see the user (text %q)", p.BannerText)
		}
		if p.LoginRequests != 0 {
			t.Errorf("navigated to sign in %d time(s) on its own; with a live session the user picks the moment", p.LoginRequests)
		}
	})

	t.Run("the banner's sign-in returns to the same tab and view", func(t *testing.T) {
		p := got.BackIn
		phase(t, p)
		if p.LoginRequests != 1 {
			t.Fatalf("/auth/login requested %d times, want 1", p.LoginRequests)
		}
		if !p.SignedIn || p.Location != base+"/" {
			t.Fatalf("after the sign-in: signed in %v at %q, want %s/", p.SignedIn, p.Location, base)
		}
		if !p.AuditTabActive {
			t.Error("the sign-in came back to a different tab than the user left")
		}
		if p.Banner {
			t.Error("the banner survived the sign-in that resolved it")
		}
	})

	// A provider that will not run inside a frame — or a browser that keeps
	// the provider's cookies out of one, which ends the same way for a
	// provider that then has to show a login page — never answers the
	// dashboard. The frame comes to rest on a document that is not ours, and
	// that has to read as "needs the user" promptly, not after a timeout.
	t.Run("a frame the provider will not answer in raises the banner promptly", func(t *testing.T) {
		p := got.Blocked
		if p.Error != "" {
			t.Fatalf("phase failed in the browser: %s", p.Error)
		}
		if p.RenewOutcome != "blocked" {
			t.Fatalf("renewal outcome = %q, want blocked", p.RenewOutcome)
		}
		if p.ElapsedMS >= 15000 {
			t.Errorf("the blocked renewal took %dms to give up, want well under the 20s timeout", p.ElapsedMS)
		}
		if !p.Banner || !strings.Contains(p.BannerText, "needs renewing") {
			t.Errorf("banner %v %q after a blocked renewal, want it offering a sign-in", p.Banner, p.BannerText)
		}
		if p.Frames != 0 {
			t.Errorf("%d iframe(s) left behind after a blocked renewal", p.Frames)
		}
	})

	t.Run("a 401 goes to the identity provider and back, not to the token prompt", func(t *testing.T) {
		p := got.Lapsed
		phase(t, p)
		if p.TokenPromptEver {
			t.Fatal("the access-token prompt opened on an SSO hub (Task 20330)")
		}
		if !p.AutomaticRedirect || p.LoginRequests != 1 {
			t.Fatalf("automatic redirect %v, /auth/login requests %d; want one, on its own", p.AutomaticRedirect, p.LoginRequests)
		}
		if !p.SignedIn || !p.AuditTabActive {
			t.Errorf("after the round trip: signed in %v, audit tab active %v; want both", p.SignedIn, p.AuditTabActive)
		}
	})
}
