package security

// Sudo mode end to end (Task 20448): a session cookie whose owner last signed
// in longer ago than ui.oidc.sudo_max_age_minutes is refused the privileged
// actions — with a typed 401 the dashboard turns into "Confirm it's you" — and
// the same browser can take them once it has signed in again at the identity
// provider with prompt=login. Driven through a real hub (internal/ssohubtest),
// its real route gate, session store and identity-provider round trip.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/blechschmidt/cloop/internal/ssohubtest"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// TestStaleSessionMustConfirmItsYouForPrivilegedActions is the proof: a stale
// cookie is refused secret create, enrollment-token mint and sandbox attach,
// keeps its ordinary reads, and is let through on all three after a
// confirm-it's-you sign-in in the same browser.
func TestStaleSessionMustConfirmItsYouForPrivilegedActions(t *testing.T) {
	const admin = "root@example.com"
	hub := ssohubtest.Start(t, ssohubtest.Options{AdminEmails: []string{admin}})
	execID := seedAttachableTask(t, hub, 1)

	// The provider last asked for a password three hours ago; the dashboard
	// sign-in it answers now is silent, from its own session.
	hub.IdP.SetSignedInAt(time.Now().Add(-3 * time.Hour))
	browser := hub.SignIn(t, admin, ssohubtest.GroupAdmins)

	secret := map[string]any{"name": "deploy-key", "kind": "env", "payload": `{"DEPLOY_KEY":"x"}`, "personal": false}
	enroll := map[string]any{"name": "edge-1"}

	status, body := hub.Call(t, browser, http.MethodPost, "/api/secrets", secret)
	requireReauth(t, "POST /api/secrets", status, body)
	status, body = hub.Call(t, browser, http.MethodPost, "/api/executors/enroll", enroll)
	requireReauth(t, "POST /api/executors/enroll", status, body)
	resp, conn := dialAttach(t, hub, browser, 1)
	if conn != nil {
		conn.CloseNow()
		t.Fatal("a stale session opened a sandbox terminal")
	}
	if resp == nil || resp.StatusCode != http.StatusUnauthorized || resp.Header.Get("X-Cloop-Reauth") != "7200" {
		t.Fatalf("the attach handshake of a stale session: %v, want 401 with X-Cloop-Reauth: 7200", describe(resp))
	}

	// The session is live: what any live session may do, it still does.
	if status, body := hub.Call(t, browser, http.MethodGet, "/api/secrets", nil); status != http.StatusOK {
		t.Fatalf("a stale session lost its reads: GET /api/secrets = %d %s", status, body)
	}
	if status, _ := hub.Call(t, browser, http.MethodGet, "/api/me", nil); status != http.StatusOK {
		t.Fatalf("GET /api/me = %d", status)
	}

	// Confirm it's you, as the dashboard's window does: prompt=login at the
	// provider, which asks — and so reports a new auth_time.
	res, err := browser.Get(hub.URL + "/auth/login?reauth=window")
	if err != nil {
		t.Fatalf("confirm-it's-you sign-in: %v", err)
	}
	doc, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != http.StatusOK || !strings.Contains(string(doc), "data-reauth") ||
		!strings.Contains(string(doc), "granted") {
		t.Fatalf("the sign-in window ended with %d:\n%s", res.StatusCode, doc)
	}
	if n := hub.IdP.LoginPrompts(); n != 1 {
		t.Fatalf("the provider saw %d prompt=login requests, want 1", n)
	}

	status, body = hub.Call(t, browser, http.MethodPost, "/api/secrets", secret)
	if status != http.StatusCreated && status != http.StatusOK {
		t.Fatalf("after signing in again, POST /api/secrets = %d %s", status, body)
	}
	status, body = hub.Call(t, browser, http.MethodPost, "/api/executors/enroll", enroll)
	var minted struct {
		Token string `json:"token"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &minted) != nil || minted.Token == "" {
		t.Fatalf("after signing in again, POST /api/executors/enroll = %d %s", status, body)
	}
	resp, conn = dialAttach(t, hub, browser, 1)
	if conn == nil {
		t.Fatalf("after signing in again the terminal did not open: %v", describe(resp))
	}
	defer conn.CloseNow()
	if !readsReady(t, conn) {
		t.Fatal("the terminal opened but never said it was ready")
	}
	if execID == "" {
		t.Fatal("no sandbox was seeded")
	}
}

// TestConfirmItsYouWithoutAuthTime: a provider that reports no auth_time
// (Entra ID without the optional claim) — every ordinary sign-in is refused
// the privileged actions, and the confirm-it's-you sign-in the hub itself
// started with prompt=login counts from its callback.
func TestConfirmItsYouWithoutAuthTime(t *testing.T) {
	const admin = "root@example.com"
	hub := ssohubtest.Start(t, ssohubtest.Options{AdminEmails: []string{admin}})
	hub.IdP.SetAuthTimeBehaviour(true, false)
	browser := hub.SignIn(t, admin, ssohubtest.GroupAdmins)

	tok := map[string]any{"name": "ci", "roles": []string{"viewer"}, "expires_in_days": 1}
	status, body := hub.Call(t, browser, http.MethodPost, "/api/tokens", tok)
	requireReauth(t, "POST /api/tokens after a sign-in with no auth_time", status, body)

	res, err := browser.Get(hub.URL + "/auth/login?reauth=window")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, res.Body)
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("confirm-it's-you sign-in: %d", res.StatusCode)
	}
	if status, body := hub.Call(t, browser, http.MethodPost, "/api/tokens", tok); status >= 400 {
		t.Fatalf("after a prompted sign-in with no auth_time, POST /api/tokens = %d %s", status, body)
	}
}

// TestConfirmItsYouRefusesAProviderThatDidNotAsk: a provider that ignores
// prompt=login and answers from its old session is caught by its own
// auth_time, and the browser stays as stale as it was.
func TestConfirmItsYouRefusesAProviderThatDidNotAsk(t *testing.T) {
	const admin = "root@example.com"
	hub := ssohubtest.Start(t, ssohubtest.Options{AdminEmails: []string{admin}})
	hub.IdP.SetSignedInAt(time.Now().Add(-3 * time.Hour))
	hub.IdP.SetAuthTimeBehaviour(false, true)
	browser := hub.SignIn(t, admin, ssohubtest.GroupAdmins)

	res, err := browser.Get(hub.URL + "/auth/login?reauth=window")
	if err != nil {
		t.Fatal(err)
	}
	doc, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != http.StatusForbidden || !strings.Contains(string(doc), "refused") {
		t.Fatalf("a provider that did not ask: %d\n%s", res.StatusCode, doc)
	}
	status, body := hub.Call(t, browser, http.MethodPost, "/api/executors/enroll", map[string]any{"name": "edge-2"})
	requireReauth(t, "POST /api/executors/enroll after a refused confirmation", status, body)
}

// TestSudoModeOffTakesAnyLiveSession: ui.oidc.sudo_max_age_minutes -1 is the
// documented way out, and it is honoured.
func TestSudoModeOffTakesAnyLiveSession(t *testing.T) {
	const admin = "root@example.com"
	hub := ssohubtest.Start(t, ssohubtest.Options{AdminEmails: []string{admin}, SudoMaxAge: -1})
	hub.IdP.SetSignedInAt(time.Now().Add(-3 * time.Hour))
	browser := hub.SignIn(t, admin, ssohubtest.GroupAdmins)
	if status, body := hub.Call(t, browser, http.MethodPost, "/api/executors/enroll", map[string]any{"name": "edge-3"}); status != http.StatusOK {
		t.Fatalf("with sudo mode off, POST /api/executors/enroll = %d %s", status, body)
	}
}

// requireReauth asserts the typed refusal: 401 REAUTH_REQUIRED with the
// window and where to confirm, never a bare 403.
func requireReauth(t *testing.T, what string, status int, body []byte) {
	t.Helper()
	var env struct {
		Error struct {
			Code    string         `json:"code"`
			Message string         `json:"message"`
			Details map[string]any `json:"details"`
		} `json:"error"`
	}
	if status != http.StatusUnauthorized || json.Unmarshal(body, &env) != nil || env.Error.Code != "REAUTH_REQUIRED" {
		t.Fatalf("%s from a stale session = %d %s, want 401 REAUTH_REQUIRED", what, status, body)
	}
	if got, _ := env.Error.Details["max_age_seconds"].(float64); got != 7200 {
		t.Errorf("%s: max_age_seconds = %v, want 7200", what, env.Error.Details["max_age_seconds"])
	}
	if u, _ := env.Error.Details["reauth_url"].(string); !strings.Contains(u, "reauth=") {
		t.Errorf("%s: reauth_url = %q", what, u)
	}
}

// seedAttachableTask makes task taskID of the hub's own project run in a
// sandbox the hub can open a terminal in.
func seedAttachableTask(t *testing.T, hub *ssohubtest.Hub, taskID int) string {
	t.Helper()
	execID := "sudo-sandbox-" + strings.ReplaceAll(t.Name(), "/", "-")
	if err := executor.Register(&sandboxExecutor{id: execID}); err != nil {
		t.Fatalf("register: %v", err)
	}
	t.Cleanup(func() { executor.DefaultRegistry.Unregister(execID) })
	db := hub.ControlPlane(t)
	if err := db.OpenExecutorSession(statedb.ExecutorSessionRow{
		ID: "sess-" + execID, ExecutorID: execID, HandleID: "h-" + execID, ProjectPath: hub.Dir,
		TaskID: taskID, ClaimToken: "tok", State: "running", Attempt: 1, StartedAt: time.Now(),
	}); err != nil {
		t.Fatalf("OpenExecutorSession: %v", err)
	}
	return execID
}

// dialAttach opens task taskID's terminal as browser: the handshake's answer
// when it is refused, the connection when it is not.
func dialAttach(t *testing.T, hub *ssohubtest.Hub, browser *http.Client, taskID int) (*http.Response, *websocket.Conn) {
	t.Helper()
	u, _ := url.Parse(hub.URL)
	u.Scheme = "ws"
	u.Path = fmt.Sprintf("/api/tasks/%d/attach", taskID)
	u.RawQuery = "rows=24&cols=80"
	hdr := http.Header{}
	for _, c := range browser.Jar.Cookies(&url.URL{Scheme: "http", Host: u.Host, Path: "/"}) {
		hdr.Add("Cookie", c.Name+"="+c.Value)
	}
	hdr.Set("Origin", hub.URL)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, resp, err := websocket.Dial(ctx, u.String(), &websocket.DialOptions{HTTPHeader: hdr})
	if err != nil {
		return resp, nil
	}
	return resp, conn
}

func readsReady(t *testing.T, conn *websocket.Conn) bool {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for {
		_, data, err := conn.Read(ctx)
		if err != nil {
			return false
		}
		var f struct {
			Type string `json:"type"`
		}
		if json.Unmarshal(data, &f) == nil && f.Type == "ready" {
			return true
		}
	}
}

func describe(resp *http.Response) string {
	if resp == nil {
		return "no response"
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
	return resp.Status + " " + strings.TrimSpace(string(b))
}

// sandboxExecutor isolates, and each terminal it opens stays open until it is
// closed.
type sandboxExecutor struct{ id string }

func (e *sandboxExecutor) ID() string   { return e.id }
func (e *sandboxExecutor) Kind() string { return "sudo-sandbox-fake" }
func (e *sandboxExecutor) Capabilities() executor.Capabilities {
	return executor.Capabilities{Isolation: executor.IsolationContainer}
}
func (e *sandboxExecutor) Start(context.Context, executor.Spec) (executor.Handle, error) {
	return executor.Handle{}, errors.New("runs nothing")
}
func (e *sandboxExecutor) Signal(context.Context, string, executor.Signal) error { return nil }
func (e *sandboxExecutor) Status(context.Context, string) (executor.Status, error) {
	return executor.Status{}, nil
}
func (e *sandboxExecutor) Stream(context.Context, string) (<-chan executor.LogLine, error) {
	return nil, errors.New("runs nothing")
}
func (e *sandboxExecutor) HealthCheck(context.Context) error { return nil }
func (e *sandboxExecutor) Attach(context.Context, executor.AttachRequest) (executor.AttachConn, error) {
	return &idleConn{closed: make(chan struct{})}, nil
}

type idleConn struct {
	once   sync.Once
	closed chan struct{}
}

func (c *idleConn) Read([]byte) (int, error) {
	<-c.closed
	return 0, io.EOF
}
func (c *idleConn) Write(p []byte) (int, error) { return len(p), nil }
func (c *idleConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}
func (c *idleConn) Resize(uint16, uint16) error { return nil }
