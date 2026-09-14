package ui

// attach_api.go is the hub's interactive-session route (Task 20265): a
// WebSocket that carries an operator's terminal into a running task's sandbox,
// and the gates that decide whether it may.
//
// # The order of the checks is the design
//
// Six things must be true before a byte moves, and they are checked in this
// order because each one is cheaper and less revealing than the next:
//
//  1. sandbox.attach, at project scope        — may this caller enter *any*
//     sandbox of this project? Denied reads answer 404, so a caller without it
//     learns nothing about whether the task exists.
//  2. the task is running, on a known handle  — resolved from executor_sessions,
//     which is the control plane's own record of what it dispatched where.
//  3. the executor isolates                   — executor.AttachTarget. This is
//     where a localprocess task is refused, and the refusal names the policy.
//  4. the concurrency ceiling                 — per executor, so one struggling
//     sandbox cannot be piled onto.
//  5. sandbox.attach.write, if asked          — a second, narrower permission.
//     Absent it, the session downgrades to read-only rather than failing: an
//     operator who may look should get to look.
//  6. the audit event                         — written *before* the session
//     opens, so a terminal that crashes the hub still left a record that it was
//     opened. An audit written on close would be an audit an attacker can skip.
//
// # Why the transcript is not stored here
//
// The redaction happens in the driver, on the output reader, before this file
// ever sees a byte — see executor.RedactAttachOutput. What this file retains is
// the *event*: who, when, which sandbox, what command, read-only or not. A full
// keystroke transcript would be a second copy of everything the sandbox holds,
// living on the control plane, outside the lease that governs it.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"nhooyr.io/websocket"

	"github.com/blechschmidt/cloop/pkg/authz"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/logger"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// attachLimiter bounds concurrent sessions per executor for the whole hub.
//
// Package-level rather than a Server field, for the same reason the executor
// registry is: the ceiling protects the executor fleet, which is process-wide,
// and a second Server in the same process (the test harness makes several)
// must not get a second budget against the same machines.
var attachLimiter = executor.NewAttachLimiter(executor.DefaultMaxAttachSessionsPerExecutor)

// Terminal traffic bounds. Small, because a terminal is not a file transfer.
const (
	// attachClientFrameLimit caps one inbound WebSocket message.
	attachClientFrameLimit = 64 << 10
	// attachIdleTimeout ends a session nobody has touched. An abandoned
	// terminal holds a slot against the ceiling and a shell inside a sandbox;
	// both should expire on their own.
	attachIdleTimeout = 30 * time.Minute
	// attachOutputChunk is the read size from the sandbox.
	attachOutputChunk = 16 << 10
)

// attachClientMsg is what the browser or CLI sends.
type attachClientMsg struct {
	// Type is "stdin", "resize", or "close".
	Type string `json:"type"`
	Data string `json:"data,omitempty"`
	Rows uint16 `json:"rows,omitempty"`
	Cols uint16 `json:"cols,omitempty"`
}

// attachServerMsg is what the hub sends back.
type attachServerMsg struct {
	Type     string `json:"type"` // "ready", "data", "error", "closed"
	Data     string `json:"data,omitempty"`
	Message  string `json:"message,omitempty"`
	Writable bool   `json:"writable,omitempty"`
	TTY      bool   `json:"tty,omitempty"`
	Executor string `json:"executor,omitempty"`
	Handle   string `json:"handle,omitempty"`
}

// attachTarget is a resolved, attachable running task.
type attachTarget struct {
	executorID string
	handleID   string
	taskID     int
	attacher   executor.Attacher
}

// handleAttachInfo answers "can this task be attached to, and how?" without
// opening anything, so the UI can render a disabled button with a reason
// instead of an error after the click.
func (s *Server) handleAttachInfo(w http.ResponseWriter, r *http.Request) {
	workDir := s.resolveWorkDir(r)
	taskID, err := attachTaskID(r)
	if err != nil {
		jsonErr(w, err.Error(), http.StatusBadRequest)
		return
	}

	resp := map[string]any{
		"ok":       true,
		"task_id":  taskID,
		"can_read": true,
		// Write authority is reported separately so the terminal can open
		// read-only rather than refusing, and say which it got.
		"can_write": s.grantFor(r).decide(s.projectScope(r)).Allows(authz.PermSandboxAttachWrite),
	}

	target, aerr := s.resolveAttachTarget(workDir, taskID)
	if aerr != nil {
		resp["attachable"] = false
		resp["reason"] = attachReason(aerr)
		jsonOK(w, resp)
		return
	}
	resp["attachable"] = true
	resp["executor_id"] = target.executorID
	resp["reason"] = "Open a shell in this task's sandbox."
	resp["sessions_open"] = attachLimiter.Count(target.executorID)
	resp["sessions_max"] = attachLimiter.Max()
	jsonOK(w, resp)
}

// resolveAttachTarget finds the live handle for a task and checks that its
// executor may be entered.
//
// The lookup is against executor_sessions — the control plane's own record of
// what it dispatched where — rather than against the task's stamped
// ExecutorID. The stamp says where a task *ran*, which is the right answer for
// provenance and the wrong one here: it survives the run, and attaching to a
// handle that has already exited would either fail confusingly or, worse,
// reach a recycled one.
func (s *Server) resolveAttachTarget(workDir string, taskID int) (attachTarget, error) {
	db, err := s.controlPlaneDB()
	if err != nil {
		return attachTarget{}, err
	}
	defer db.Close()

	rows, err := db.ListExecutorSessions("", true)
	if err != nil {
		return attachTarget{}, fmt.Errorf("list running sessions: %w", err)
	}
	var match *statedb.ExecutorSessionRow
	for i := range rows {
		if rows[i].TaskID == taskID && sameProjectPath(rows[i].ProjectPath, workDir) {
			match = &rows[i]
			break
		}
	}
	if match == nil {
		return attachTarget{}, fmt.Errorf("%w: task %d is not running on any executor",
			executor.ErrAttachHandleUnknown, taskID)
	}
	if strings.TrimSpace(match.HandleID) == "" {
		return attachTarget{}, fmt.Errorf("%w: task %d has been dispatched but has no sandbox yet",
			executor.ErrAttachHandleUnknown, taskID)
	}

	ex, err := executor.Get(match.ExecutorID)
	if err != nil {
		return attachTarget{}, fmt.Errorf("%w: executor %q is not registered on this hub",
			executor.ErrAttachHandleUnknown, match.ExecutorID)
	}
	// The single funnel. Every refusal an operator can hit — host execution,
	// a driver with no session support — is decided here and nowhere else.
	at, err := executor.AttachTarget(ex)
	if err != nil {
		return attachTarget{}, err
	}
	return attachTarget{
		executorID: match.ExecutorID,
		handleID:   match.HandleID,
		taskID:     taskID,
		attacher:   at,
	}, nil
}

// handleAttachWS upgrades to a terminal session.
func (s *Server) handleAttachWS(w http.ResponseWriter, r *http.Request) {
	// The route is registered without a method prefix, because a WebSocket
	// upgrade is a GET and the mux pattern would otherwise have to repeat it —
	// so the mux hands this handler every verb, and routes.go's Methods field
	// documents rather than enforces.
	//
	// The check has to be first, and it is not cosmetic. Everything below has
	// side effects an unupgraded request must not get: it claims a slot against
	// the per-executor ceiling, writes an audit event, and *starts a real
	// process inside the sandbox* — all before websocket.Accept would reject a
	// POST. Without this, a caller could spawn and orphan sandbox execs by
	// POSTing at a socket they never intend to open.
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		jsonErr(w, "GET required: this endpoint is a WebSocket upgrade", http.StatusMethodNotAllowed)
		return
	}
	workDir := s.resolveWorkDir(r)
	taskID, err := attachTaskID(r)
	if err != nil {
		jsonErr(w, err.Error(), http.StatusBadRequest)
		return
	}
	// Same CSWSH mitigation as the dashboard socket. A terminal is the last
	// thing that should be openable by a page on another origin.
	if !s.wsOriginAllowed(r) {
		http.Error(w, "forbidden origin", http.StatusForbidden)
		return
	}

	target, err := s.resolveAttachTarget(workDir, taskID)
	if err != nil {
		jsonErr(w, attachReason(err), attachStatus(err))
		return
	}

	// Write authority is a second permission, and its absence downgrades
	// rather than refuses: an operator who may observe should observe.
	writable := s.grantFor(r).decide(s.projectScope(r)).Allows(authz.PermSandboxAttachWrite)
	wantTTY := r.URL.Query().Get("tty") != "0"
	command := attachCommand(r)
	actor := s.auditActor(r)

	sessionID, release, err := attachLimiter.Acquire(executor.AttachSessionInfo{
		ExecutorID: target.executorID,
		HandleID:   target.handleID,
		Actor:      actor,
		Command:    strings.Join(command, " "),
		Writable:   writable,
	})
	if err != nil {
		jsonErr(w, err.Error(), http.StatusTooManyRequests)
		return
	}
	defer release()

	// Recorded before the session opens. An audit written on close is an audit
	// that a crash — or a caller who forces one — erases.
	s.auditAttach(r, "sandbox.attach.open", target, sessionID, command, writable, "")

	req := executor.AttachRequest{
		HandleID: target.handleID,
		Command:  command,
		TTY:      wantTTY,
		Stdin:    writable,
		Rows:     attachUint(r, "rows", 24),
		Cols:     attachUint(r, "cols", 80),
		Env:      []string{"TERM=xterm-256color"},
	}
	conn, err := target.attacher.Attach(r.Context(), req)
	if err != nil {
		s.auditAttach(r, "sandbox.attach.denied", target, sessionID, command, writable, err.Error())
		jsonErr(w, attachReason(err), attachStatus(err))
		return
	}
	defer conn.Close()

	ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
	if err != nil {
		return
	}
	defer ws.CloseNow()

	reason := s.pumpAttachSession(r, ws, conn, target, writable, wantTTY)
	s.auditAttach(r, "sandbox.attach.close", target, sessionID, command, writable, reason)
}

// pumpAttachSession runs the session until either end hangs up, returning why.
func (s *Server) pumpAttachSession(r *http.Request, ws *websocket.Conn, conn executor.AttachConn,
	target attachTarget, writable, tty bool) string {

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	_ = attachSend(ctx, ws, attachServerMsg{
		Type: "ready", Writable: writable, TTY: tty,
		Executor: target.executorID, Handle: target.handleID,
		Message: attachBanner(writable),
	})

	// Sandbox → browser.
	done := make(chan string, 2)
	go func() {
		defer recoverGoroutine("attach output pump")
		buf := make([]byte, attachOutputChunk)
		for {
			n, rerr := conn.Read(buf)
			if n > 0 {
				if serr := attachSend(ctx, ws, attachServerMsg{
					Type: "data", Data: string(buf[:n]),
				}); serr != nil {
					done <- "client disconnected"
					return
				}
			}
			if rerr != nil {
				done <- "sandbox session ended"
				return
			}
		}
	}()

	// Browser → sandbox.
	go func() {
		defer recoverGoroutine("attach input pump")
		ws.SetReadLimit(attachClientFrameLimit)
		for {
			rctx, rcancel := context.WithTimeout(ctx, attachIdleTimeout)
			_, data, rerr := ws.Read(rctx)
			rcancel()
			if rerr != nil {
				if errors.Is(rerr, context.DeadlineExceeded) {
					done <- "idle timeout"
					return
				}
				done <- "client disconnected"
				return
			}
			var msg attachClientMsg
			if json.Unmarshal(data, &msg) != nil {
				continue
			}
			switch msg.Type {
			case "stdin":
				if !writable {
					// Belt and braces. The driver already opened the session
					// without an input descriptor, so this cannot reach the
					// sandbox — but a client that tries is worth refusing
					// loudly rather than ignoring.
					_ = attachSend(ctx, ws, attachServerMsg{
						Type:    "error",
						Message: "this session is read-only (needs sandbox.attach.write)",
					})
					continue
				}
				if _, werr := conn.Write([]byte(msg.Data)); werr != nil {
					done <- "sandbox stopped accepting input"
					return
				}
			case "resize":
				_ = conn.Resize(msg.Rows, msg.Cols)
			case "close":
				done <- "closed by operator"
				return
			}
		}
	}()

	// Runtime withdrawal: the same re-check the dashboard socket performs, so
	// revoking someone's access ends the terminal they already have open
	// rather than only the next one they try to open.
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case reason := <-done:
			_ = attachSend(ctx, ws, attachServerMsg{Type: "closed", Message: reason})
			_ = ws.Close(websocket.StatusNormalClosure, reason)
			return reason
		case <-ticker.C:
			if !s.attachStillAuthorized(r) {
				_ = attachSend(ctx, ws, attachServerMsg{Type: "closed", Message: "authorization withdrawn"})
				_ = ws.Close(websocket.StatusPolicyViolation, "authorization withdrawn")
				return "authorization withdrawn"
			}
		}
	}
}

// attachSend marshals and writes one server message.
func attachSend(ctx context.Context, ws *websocket.Conn, msg attachServerMsg) error {
	blob, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	wctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return ws.Write(wctx, websocket.MessageText, blob)
}

// attachBanner tells the operator which kind of session they got. Saying so up
// front is what stops a read-only terminal reading as a broken one.
func attachBanner(writable bool) string {
	if writable {
		return "Interactive session. Everything you type runs inside the sandbox and is recorded in the audit trail."
	}
	return "Read-only session. Input is disabled; you are observing the sandbox."
}

// auditAttach records one lifecycle event for a session.
//
// Best-effort, like every other emitter in the hub: a wedged journal must not
// stop an operator from reaching a sandbox during an incident. The event is
// what makes an attach attributable — without it, a shell inside a sandbox is
// indistinguishable from the agent's own work.
func (s *Server) auditAttach(r *http.Request, event string, target attachTarget,
	sessionID string, command []string, writable bool, detail string) {

	db, err := s.controlPlaneDB()
	if err != nil {
		s.log().Warn(logger.EventAuthz, 0, "audit: open control-plane db for attach event",
			map[string]interface{}{"error": err.Error(), "event": event})
		return
	}
	defer db.Close()

	statedb.AuditAttachSession(db, statedb.AttachAuditInput{
		Event:      event,
		Actor:      s.auditActor(r),
		SessionID:  sessionID,
		ExecutorID: target.executorID,
		HandleID:   target.handleID,
		TaskID:     target.taskID,
		Command:    strings.Join(command, " "),
		Writable:   writable,
		Detail:     detail,
	})
	s.broadcastAuditAppend(event)
}

// ── Request parsing ───────────────────────────────────────────────────────

// attachTaskID reads the task from the path segment.
func attachTaskID(r *http.Request) (int, error) {
	raw := strings.TrimSpace(r.PathValue("id"))
	if raw == "" {
		raw = strings.TrimSpace(r.URL.Query().Get("task_id"))
	}
	id, err := strconv.Atoi(raw)
	if err != nil || id <= 0 {
		return 0, fmt.Errorf("task id must be a positive integer, got %q", raw)
	}
	return id, nil
}

// attachCommand reads the requested argv.
//
// Deliberately permissive about *what* is run and strict about who may run it:
// restricting the command to an allowlist would be security theatre, because a
// shell is on the list by necessity and everything else is reachable from it.
// The control is the permission and the audit record, both of which name the
// command exactly as given.
func attachCommand(r *http.Request) []string {
	vals := r.URL.Query()["cmd"]
	var out []string
	for _, v := range vals {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}

// attachUint reads a bounded terminal dimension.
func attachUint(r *http.Request, key string, def uint16) uint16 {
	raw := strings.TrimSpace(r.URL.Query().Get(key))
	if raw == "" {
		return def
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n <= 0 || n > 1000 {
		return def
	}
	return uint16(n)
}

// attachStatus maps a refusal to an HTTP status.
func attachStatus(err error) int {
	switch {
	case errors.Is(err, executor.ErrAttachNoSandbox):
		// 403: the caller is authorized, the *workload* is not eligible.
		return http.StatusForbidden
	case errors.Is(err, executor.ErrAttachUnsupported):
		return http.StatusNotImplemented
	case errors.Is(err, executor.ErrAttachBusy):
		return http.StatusTooManyRequests
	case errors.Is(err, executor.ErrAttachHandleUnknown), errors.Is(err, executor.ErrAttachClosed):
		return http.StatusNotFound
	default:
		return http.StatusInternalServerError
	}
}

// attachReason renders a refusal for a human. Driver errors already carry the
// executor and the remediation, so they are passed through rather than
// flattened into a generic message.
func attachReason(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// sameProjectPath compares two project paths the way the registry does.
//
// Cleaned rather than compared raw: executor_sessions stores whatever path the
// dispatcher held, and the request resolves its own from the project list, so
// a trailing slash or a "." segment on either side is entirely ordinary. An
// exact string compare would silently report "not running" for a task that is.
func sameProjectPath(a, b string) bool {
	return filepath.Clean(strings.TrimSpace(a)) == filepath.Clean(strings.TrimSpace(b))
}

// attachStillAuthorized re-resolves the caller's authority from scratch.
//
// It deliberately does not use grantFor. That returns the grant computed once
// by authzMiddleware and memoized on the request context, and grant.decide
// memoizes per scope on top of it — so asking it again on a long-lived
// connection returns the answer from the moment the socket opened, forever. For
// a request that is the right behaviour and the reason the cache exists; for a
// terminal that can stay open for half an hour it makes the re-check a no-op
// that looks like a control.
//
// newGrant re-reads the token, re-resolves the session identity, and re-decides
// against the policy as it stands now, which is what makes revoking someone's
// access close the shell they already have rather than only the next one they
// try to open. That costs a session lookup every 30 seconds per open terminal —
// affordable precisely because the concurrency ceiling is four.
func (s *Server) attachStillAuthorized(r *http.Request) bool {
	return s.newGrant(r).decide(s.projectScope(r)).Allows(authz.PermSandboxAttach)
}
