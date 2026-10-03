package ui

// The Members card in a real browser (Task 20366). members_api_test.go proves
// the hub's half; this proves the page's: the card's script is not on first
// paint and arrives with the Overview, its delegated controls add, re-role and
// remove members, and a member whose access is withdrawn while they watch is
// returned to the projects that remain — the hub closes their socket with 1008
// and the page has to act on it. Skips without Chrome or node, like the other
// browser gates here.

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/blechschmidt/cloop/pkg/oidcauth"
)

type memberRow struct {
	Identity string `json:"identity"`
	Role     string `json:"role"`
	Editable bool   `json:"editable"`
	Remove   bool   `json:"remove"`
	Leave    bool   `json:"leave"`
}

type membersBrowserResult struct {
	Error *struct {
		Message string `json:"message"`
	} `json:"error"`
	MetaNamesScript      bool              `json:"meta_names_script"`
	LoadedBeforeOverview bool              `json:"loaded_before_overview"`
	LoadedAfterOverview  int               `json:"loaded_after_overview"`
	AliceInitial         []memberRow       `json:"alice_initial"`
	AliceFormVisible     bool              `json:"alice_form_visible"`
	AliceRolesOffered    []string          `json:"alice_roles_offered"`
	AfterAdd             []memberRow       `json:"after_add"`
	ServerAfterAdd       map[string]string `json:"server_after_add"`
	ServerAfterChange    map[string]string `json:"server_after_change"`
	Refusal              []string          `json:"refusal"`
	ServerAfterRemove    map[string]string `json:"server_after_remove"`
	BobMe                string            `json:"bob_me"`
	BobProjects          []string          `json:"bob_projects"`
	BobView              []memberRow       `json:"bob_view"`
	BobFormVisible       bool              `json:"bob_form_visible"`
	BobAfterRevokeToasts []string          `json:"bob_after_revoke_toasts"`
	Readmitted           bool              `json:"readmitted"`
	ServerAfterLeave     map[string]string `json:"server_after_leave"`
}

func TestMembersCardInBrowser(t *testing.T) {
	chrome := findChrome()
	if chrome == "" {
		t.Skip("no Chrome/Chromium installed")
	}
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed; cannot drive the browser")
	}
	t.Setenv("HOME", t.TempDir())
	// Both people sign in here, through the fake IdP, before Chrome starts:
	// the IdP's claims are never flipped while the browser runs.
	f := newMemberFixture(t, true)
	members := f.membersURL(t, f.alice)

	// The driver's levers: what the hub holds, and the changes another
	// maintainer would make while bob watches. Each answers rather than
	// failing the test from a handler goroutine.
	send := func(c *http.Client, method, path string, body any) (int, string) {
		var rdr io.Reader = http.NoBody
		if body != nil {
			b, _ := json.Marshal(body)
			rdr = bytes.NewReader(b)
		}
		req, err := http.NewRequest(method, f.ts.URL+path, rdr)
		if err != nil {
			return 0, err.Error()
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := c.Do(req)
		if err != nil {
			return 0, err.Error()
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	control := http.NewServeMux()
	control.HandleFunc("GET /members", func(w http.ResponseWriter, r *http.Request) {
		out := map[string]string{}
		for _, m := range f.srv.memberStore().MembersOf(f.project) {
			out[m.IdentityKey] = string(m.Role)
		}
		_ = json.NewEncoder(w).Encode(out)
	})
	control.HandleFunc("GET /room", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]int{"clients": f.srv.roomSize(f.project)})
	})
	control.HandleFunc("POST /grant", func(w http.ResponseWriter, r *http.Request) {
		code, body := send(f.alice, http.MethodPost, members,
			map[string]any{"identity": bobEmail, "role": r.URL.Query().Get("role")})
		if code != http.StatusCreated {
			http.Error(w, body, http.StatusBadGateway)
			return
		}
		_, _ = w.Write([]byte(`{}`))
	})
	control.HandleFunc("POST /revoke", func(w http.ResponseWriter, r *http.Request) {
		code, body := send(f.alice, http.MethodDelete, members+"?identity="+url.QueryEscape(bobEmail), nil)
		if code != http.StatusOK {
			http.Error(w, body, http.StatusBadGateway)
			return
		}
		_, _ = w.Write([]byte(`{}`))
	})
	ctl := httptest.NewServer(control)
	defer ctl.Close()

	cookies, _ := json.Marshal(map[string]string{
		"alice": sessionCookie(t, f.alice, f.ts.URL),
		"bob":   sessionCookie(t, f.bob, f.ts.URL),
	})
	cmd := exec.Command(node, mustAbs(t, "testdata/members_browser.js"), chrome, f.ts.URL, ctl.URL, f.project)
	cmd.Env = append(os.Environ(), "MEMBERS_COOKIES="+string(cookies))
	out, err := cmd.Output()
	if os.Getenv("MEMBERS_BROWSER_DEBUG") != "" {
		t.Logf("driver output:\n%s", out)
	}
	if err != nil {
		stderr := ""
		if ee, ok := err.(*exec.ExitError); ok {
			stderr = string(ee.Stderr)
		}
		t.Fatalf("driving the browser failed: %v\nstdout:\n%s\nstderr:\n%s", err, out, stderr)
	}
	var got membersBrowserResult
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("decoding results: %v\nraw:\n%s", err, out)
	}
	if got.Error != nil {
		t.Fatalf("driver: %s\npartial results:\n%s", got.Error.Message, out)
	}

	if !got.MetaNamesScript || got.LoadedBeforeOverview || got.LoadedAfterOverview != 1 {
		t.Errorf("the card's script: named in the page %v, loaded before the Overview %v, loaded %d time(s) after it",
			got.MetaNamesScript, got.LoadedBeforeOverview, got.LoadedAfterOverview)
	}
	if len(got.AliceInitial) != 1 || got.AliceInitial[0].Identity != aliceEmail || got.AliceInitial[0].Role != "owner" {
		t.Errorf("alice's initial roster: %+v, want the owner row alone", got.AliceInitial)
	}
	if !got.AliceFormVisible || strings.Join(got.AliceRolesOffered, ",") != "viewer,operator,maintainer" {
		t.Errorf("a maintainer's add form: visible %v, roles %v — want viewer, operator, maintainer and never admin",
			got.AliceFormVisible, got.AliceRolesOffered)
	}
	if got.ServerAfterAdd[bobEmail] != "operator" {
		t.Errorf("after adding through the card the hub holds %v", got.ServerAfterAdd)
	}
	if got.ServerAfterChange[bobEmail] != "viewer" {
		t.Errorf("after the role change the hub holds %v", got.ServerAfterChange)
	}
	if len(got.Refusal) == 0 || !strings.Contains(got.Refusal[0], "neither an email") {
		t.Errorf("an unusable identity was not refused with the reason: %v", got.Refusal)
	}
	if len(got.ServerAfterRemove) != 0 {
		t.Errorf("after removal the hub still holds %v", got.ServerAfterRemove)
	}
	if got.BobMe != bobEmail {
		t.Fatalf("the browser is signed in as %q, not bob — the session switch did not take", got.BobMe)
	}
	if strings.Join(got.BobProjects, ",") != f.project {
		t.Errorf("bob's projects: %v, want the shared one alone", got.BobProjects)
	}
	var self *memberRow
	for i := range got.BobView {
		if got.BobView[i].Identity == bobEmail {
			self = &got.BobView[i]
		}
	}
	if self == nil || !self.Leave || self.Remove || self.Editable || got.BobFormVisible {
		t.Errorf("a viewer member's card: %+v, form visible %v — want Leave on his own row and nothing to manage",
			got.BobView, got.BobFormVisible)
	}
	if len(got.BobAfterRevokeToasts) == 0 || !strings.Contains(strings.Join(got.BobAfterRevokeToasts, " "), "withdrawn") {
		t.Errorf("bob was not told his access was withdrawn: %v", got.BobAfterRevokeToasts)
	}
	if !got.Readmitted {
		t.Error("re-admitted, bob does not see the project again")
	}
	if len(got.ServerAfterLeave) != 0 {
		t.Errorf("after bob left the hub still holds %v", got.ServerAfterLeave)
	}
}

// sessionCookie returns c's session cookie for base.
func sessionCookie(t *testing.T, c *http.Client, base string) string {
	t.Helper()
	u, err := url.Parse(base)
	if err != nil {
		t.Fatal(err)
	}
	for _, ck := range c.Jar.Cookies(u) {
		if ck.Name == oidcauth.SessionCookieName {
			return ck.Value
		}
	}
	t.Fatal("the client holds no session cookie")
	return ""
}
