// Package ui implements a local web dashboard for monitoring and controlling cloop.
package ui

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"nhooyr.io/websocket"

	"github.com/blechschmidt/cloop/pkg/apitoken"
	"github.com/blechschmidt/cloop/pkg/artifact"
	"github.com/blechschmidt/cloop/pkg/authz"
	"github.com/blechschmidt/cloop/pkg/blocker"
	"github.com/blechschmidt/cloop/pkg/boundedread"
	"github.com/blechschmidt/cloop/pkg/claudecodeauth"
	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/cost"
	"github.com/blechschmidt/cloop/pkg/decompose"
	"github.com/blechschmidt/cloop/pkg/epic"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executor/reconcile"
	"github.com/blechschmidt/cloop/pkg/globalbudget"
	"github.com/blechschmidt/cloop/pkg/kb"
	"github.com/blechschmidt/cloop/pkg/logger"
	"github.com/blechschmidt/cloop/pkg/multiui"
	"github.com/blechschmidt/cloop/pkg/oidcauth"
	"github.com/blechschmidt/cloop/pkg/pm"
	"github.com/blechschmidt/cloop/pkg/provider"
	"github.com/blechschmidt/cloop/pkg/quota"
	"github.com/blechschmidt/cloop/pkg/ratelimit"
	"github.com/blechschmidt/cloop/pkg/reqid"
	"github.com/blechschmidt/cloop/pkg/riskmatrix"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
	"github.com/blechschmidt/cloop/pkg/suggest"
	"github.com/blechschmidt/cloop/pkg/taskqueue"
	"github.com/blechschmidt/cloop/pkg/taskreplay"
	"github.com/blechschmidt/cloop/pkg/timeline"
	"github.com/blechschmidt/cloop/pkg/tlsconf"
)

// sseEvent is a typed SSE message. If Event is empty the browser receives a
// default "message" event; otherwise the named event type is sent.
type sseEvent struct {
	Event string // e.g. "" or "log"
	Data  string
}

// sseClient is a single SSE consumer with the same backpressure model as
// hubClient: ch is a bounded outgoing buffer, and resync is a one-shot signal
// that the writer should drain stale events and emit a single "resync" SSE
// directive instead of silently dropping events under load.
type sseClient struct {
	ch     chan sseEvent
	resync chan struct{}

	// user is the OIDC identity bound to this stream at connect time; nil
	// when OIDC is disabled or the client authenticated via bearer token.
	// Broadcasters use it to send per-user filtered "projects" payloads.
	user *oidcauth.Identity

	// token is the API token this stream authenticated with, nil otherwise.
	// A long-lived stream must keep honouring the scope the request that
	// opened it carried, so it is captured here rather than re-derived
	// (Task 20175).
	token *apitoken.Token

	// workDir is the project this stream subscribed to, resolved once at
	// connect time. Project-scoped events (state, run_state, suggest
	// status, live output) are filtered against it — the SSE analogue of
	// the hubClients room key. Without it the SSE fallback path fanned
	// every project's events to every listener (Task 20189).
	workDir string
}

// sseClientBufferSize mirrors hubClientBufferSize for SSE consumers.
const sseClientBufferSize = 64

// sseWriteTimeout caps how long any single SSE write+flush may take. This is
// the SSE analogue of wsWriteTimeout. Without a per-write deadline,
// fmt.Fprintf to the http.ResponseWriter and the subsequent flusher.Flush()
// block on the underlying TCP write until the OS-level send timeout —
// typically minutes — when a slow or wedged client (TCP buffers full,
// network stalled, half-open NAT entry) stops draining. With many such
// peers, SSE writer goroutines pile up and the hub's broadcast loop slows
// down for everyone. 10s mirrors wsWriteTimeout: generous for a slow link
// burst while bounding per-frame stalls so the writer recovers quickly.
//
// Best-effort — if the underlying ResponseWriter doesn't expose a
// SetWriteDeadline (e.g., an in-memory test recorder, or a wrapped writer
// chain that hides it), the helper still propagates Write errors so the
// loop can exit; only the proactive deadline arming is skipped.
//
// Declared as var (not const) so regression tests can shrink it; production
// callers should treat it as immutable.
var sseWriteTimeout = 10 * time.Second

// sseKeepaliveInterval is how often the long-lived SSE handlers
// (handleEvents, handleProjectsEvents) emit an SSE comment frame
// (": keepalive\n\n") on an otherwise quiet stream. SSE comments are
// silently ignored by EventSource clients but force a TCP write — which,
// combined with sseWriteTimeout, lets the server detect a dead peer
// (laptop suspended, network partition, peer crashed without RST) within
// roughly sseKeepaliveInterval+sseWriteTimeout instead of waiting for the
// kernel TCP keepalive (default ~2 hours on Linux). 30s mirrors
// wsPingInterval to keep the symmetry between the SSE and WebSocket paths.
//
// Declared as var (not const) so regression tests can shrink it; production
// callers should treat it as immutable.
var sseKeepaliveInterval = 30 * time.Second

// writeSSE writes a single SSE frame and flushes, with a per-write deadline
// armed via http.ResponseController. Returns the first error encountered;
// callers should return from the SSE loop on any error — a wedged peer
// would otherwise pin the goroutine until OS-level TCP timeout.
//
// Errors include net.Error timeouts (deadline exceeded — the peer is not
// draining), io.ErrClosedPipe / "use of closed network connection" (peer
// went away mid-frame), and broken-pipe variants.
func writeSSE(w http.ResponseWriter, flusher http.Flusher, format string, args ...interface{}) error {
	if rc := http.NewResponseController(w); rc != nil {
		// SetWriteDeadline returns http.ErrNotSupported when the
		// underlying ResponseWriter doesn't implement the interface
		// (e.g., httptest.ResponseRecorder). That's a best-effort
		// arming — drop the error and rely on Write-side error
		// detection below.
		_ = rc.SetWriteDeadline(time.Now().Add(sseWriteTimeout))
	}
	if _, err := fmt.Fprintf(w, format, args...); err != nil {
		return err
	}
	flusher.Flush()
	return nil
}

// sendSSEOrLag is the SSE analogue of sendOrLag: non-blocking send, queue a
// resync signal if the buffer is full.
func (s *Server) sendSSEOrLag(c *sseClient, ev sseEvent) {
	select {
	case c.ch <- ev:
		return
	default:
	}
	select {
	case c.resync <- struct{}{}:
	default:
	}
}

// wsMessage is a typed WebSocket message envelope.
// Type values: "task_update", "step_output", "projects", "run_state",
// "suggest_status", "presence", "task_added", "task_deleted",
// "task_mutation", "provider_call", "resync".
// "error" is client-emitted only; the backend never sends it.
type wsMessage struct {
	Type string          `json:"type"`
	Data json.RawMessage `json:"data"`
}

// hubClient represents a single WebSocket connection with presence metadata.
//
// Backpressure model: ch is a bounded outgoing buffer. When a broadcaster
// would block because the client is too slow to drain its messages, the
// event is dropped and a single resync directive is queued on resync. The
// writer goroutine (handleWS) drains any stale events still in ch, then
// emits one wsMessage{Type:"resync"} so the client can re-fetch full state
// via /api/state — guaranteeing the client never silently misses updates.
type hubClient struct {
	ch     chan wsMessage
	resync chan struct{} // buffered (cap 1); signals the client must resync
	id     string        // unique per-connection identifier
	name   string        // display name (e.g. "Swift Panda")
	color  string        // hex color code (e.g. "#58a6ff")

	// conn is the underlying WebSocket connection. Set in handleWS so the
	// server's graceful-shutdown path can iterate hubClients and send a
	// code-1001 (going away) close frame to each peer before the
	// http.Server.Shutdown() returns. Without this, peers see an abrupt
	// TCP teardown via the deferred conn.CloseNow() and have no chance to
	// distinguish "server going away" from a network blip.
	conn *websocket.Conn

	// user is the OIDC identity bound to this connection at upgrade time;
	// nil when OIDC is disabled or the client authenticated via bearer
	// token. Broadcasters use it to send per-user filtered "projects"
	// payloads.
	user *oidcauth.Identity

	// token is the API token this connection authenticated with, nil
	// otherwise. Captured at upgrade time for the same reason as on
	// sseClient (Task 20175).
	token *apitoken.Token
}

// hubClientBufferSize is the per-client outgoing buffer for WebSocket clients.
// 64 is large enough to absorb routine bursts (e.g., parallel orchestrator
// task updates) but small enough to surface real lag quickly so the resync
// directive fires before the client is hopelessly behind.
const hubClientBufferSize = 64

// wsWriteTimeout caps how long any single WebSocket frame write may take.
// Without a per-write deadline, the writer goroutine in handleWS uses the
// long-lived request context, so a slow or wedged client (TCP buffers full,
// network stalled, half-open NAT entry) will pin the goroutine until the
// OS-level TCP timeout — typically minutes — letting an attacker exhaust
// goroutines by opening many stalled connections. 10s is generous for a
// burst on a slow link while still bounding each frame; on timeout, nhooyr's
// timeoutLoop closes the underlying conn so the writer loop exits cleanly.
//
// Declared as var (not const) so regression tests can shrink it; production
// callers should treat it as immutable.
var wsWriteTimeout = 10 * time.Second

// wsReadFrameLimit caps the size of any single inbound WebSocket frame
// processed by handleWS's drain goroutine. The drain does not parse
// inbound payloads today (it is a bidirectional hook for future use), so
// any client→server frame should be tiny; 4 KiB is generous headroom for
// future ack/control messages while bounding accidental or malicious
// jumbo frames. nhooyr's default is 32 KiB; setting this explicitly makes
// the limit immune to upstream default changes and tightens it to a value
// proportional to actual need. On overshoot, nhooyr closes the connection
// with StatusMessageTooBig.
//
// Declared as var (not const) so regression tests can shrink it; production
// callers should treat it as immutable.
var wsReadFrameLimit int64 = 4 * 1024

// wsMaxInboundMsgsPerSecond caps how many inbound frames the drain
// goroutine accepts per 1-second sliding window. Without a rate cap, a
// client streaming many tiny (sub-wsReadFrameLimit) frames as fast as the
// link allows can keep the drain goroutine hot indefinitely — each Read
// returns immediately and the loop never yields. 100 msg/s is two orders
// of magnitude above any realistic bidirectional protocol the UI would
// adopt; once exceeded the connection is closed with StatusPolicyViolation
// and the goroutine exits cleanly.
//
// Declared as var (not const) so regression tests can shrink it; production
// callers should treat it as immutable.
var wsMaxInboundMsgsPerSecond = 100

// wsPingInterval is how often the writer loop sends a server-initiated
// WebSocket ping to probe peer liveness. Without this, a silent client
// (TCP-connected but unresponsive — laptop suspended, network partition,
// peer crashed without RST) holds the goroutine pair alive until the OS-
// level TCP keepalive fires (default ~2 hours on Linux). Pinging every 30s
// detects dead peers within wsPingInterval+wsPingTimeout, an order of
// magnitude faster than relying on TCP timeouts. nhooyr handles the pong
// dispatch internally via the active drain Read; the writer's Ping call
// blocks on the matching pong (or ctx) so concurrent operation is safe.
//
// Declared as var (not const) so regression tests can shrink it; production
// callers should treat it as immutable.
var wsPingInterval = 30 * time.Second

// wsPingTimeout caps how long the writer loop waits for a pong to a single
// ping. Exceeding this is treated as a dead connection and the writer exits;
// the deferred conn.CloseNow + hubClient cleanup unwind the goroutine. 10s
// is generous for a slow link round-trip but tight enough that a peer that
// stops responding mid-session is detected quickly.
//
// Declared as var (not const) so regression tests can shrink it; production
// callers should treat it as immutable.
var wsPingTimeout = 10 * time.Second

// wsWrite sends a single WebSocket text frame with a per-call deadline
// derived from ctx. Returns whatever Write returns (deadline-exceeded shows
// up as ctx.Err on the wrapped error).
func wsWrite(ctx context.Context, conn *websocket.Conn, data []byte) error {
	wctx, cancel := context.WithTimeout(ctx, wsWriteTimeout)
	defer cancel()
	return conn.Write(wctx, websocket.MessageText, data)
}

// sendOrLag attempts a non-blocking send of msg to hc.ch. If the buffer is
// full, the message is dropped and a resync directive is queued (idempotent
// — at most one resync pending at a time). The writer goroutine in handleWS
// will drain the channel and emit a single wsMessage{Type:"resync"} so the
// client knows to re-fetch state. This replaces the prior pattern of silent
// drops under load (Task 20040).
func (s *Server) sendOrLag(hc *hubClient, msg wsMessage) {
	select {
	case hc.ch <- msg:
		return
	default:
	}
	// Buffer is full — signal resync (chan cap 1, so duplicates collapse).
	select {
	case hc.resync <- struct{}{}:
	default:
	}
}

// conflictEntry records the last editor of a specific task field.
type conflictEntry struct {
	clientID string
	editedAt time.Time
}

// conflictWindow is the period during which two clients editing the same
// (taskID, field) are considered to be in conflict. Entries older than this
// can no longer trigger a conflict and are eligible for sweeping.
const conflictWindow = 2 * time.Second

// maxConflictEntriesPerWorkDir is a defense-in-depth hard cap on the number of
// per-workDir conflict entries. Reached only if the time-based sweep is
// neutralised (e.g., the wall clock jumps backwards) — under normal operation
// the inner map is bounded by edits within conflictWindow.
const maxConflictEntriesPerWorkDir = 4096

// presenceUser is the JSON representation of a connected user sent to clients.
type presenceUser struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Color string `json:"color"`
}

// ChatMessage is a single turn in the chat conversation history.
type ChatMessage struct {
	Role      string    `json:"role"` // "user" or "assistant"
	Content   string    `json:"content"`
	Timestamp time.Time `json:"timestamp"`
	Action    string    `json:"action,omitempty"` // resolved cloop command, if any
}

// maxChatHistoryPerWorkDir caps each per-project chat conversation kept in
// memory by the long-running UI daemon. Without this, every /api/chat POST
// appends forever and the in-memory transcript grows unbounded for the
// lifetime of the process — a slow leak proportional to user activity, not
// project count. The cap keeps the most recent N (user+assistant) turns,
// which is well past any realistic context window the chat handler itself
// would replay back to the model. Trimming copies into a fresh slice so the
// older messages' backing memory is released to the GC instead of being
// kept alive by a re-slice over the same array.
const maxChatHistoryPerWorkDir = 200

// authFailEntry tracks failed authentication attempts for rate-limiting.
type authFailEntry struct {
	count       int
	lockedUntil time.Time
	// lastSeen is updated on every access (success or failure) so the
	// authFails map can be bounded with LRU/TTL eviction; without this, a
	// flood of unique source IPs against /api/* would grow the map forever.
	lastSeen time.Time
}

const (
	authMaxFailures    = 5  // failures before lockout
	authLockoutSeconds = 60 // lockout duration in seconds

	// uiRLMaxBuckets caps the per-IP rate-limit map so a flood of unique IPs
	// cannot grow it without bound. When the map exceeds this size, stale
	// buckets are swept (and if still over, the least-recently-seen bucket
	// is evicted) on each new IP insert.
	uiRLMaxBuckets = 10000
	// uiRLBucketIdleTTL is how long a bucket is kept after the last request
	// from that IP. Anything older is eligible for sweep.
	uiRLBucketIdleTTL = 1 * time.Hour

	// uiAuthFailsMaxEntries caps the auth-fail tracker map analogously.
	uiAuthFailsMaxEntries = 10000
	// uiAuthFailsIdleTTL applies the same staleness threshold to auth-fail
	// entries; an entry whose lastSeen is older than this is eligible for
	// sweep before the next insert.
	uiAuthFailsIdleTTL = 1 * time.Hour
)

// uiIPBucket is a token-bucket state for one remote IP in the UI server.
type uiIPBucket struct {
	tokens   float64
	lastSeen time.Time
}

// Server is the cloop web dashboard HTTP server.
type Server struct {
	WorkDir  string
	Port     int
	Token    string   // optional auth token; empty = no auth
	Projects []string // extra project directories for multi-project dashboard

	// RPS and Burst control the per-IP token-bucket rate limiter.
	// Zero values use 20 req/s and burst 50.
	RPS   float64
	Burst int

	// MaxWebSocketConns caps the total number of concurrent WebSocket
	// connections accepted across every remote IP. Zero substitutes
	// config.WebSocketConnsDefault (256). Each accepted upgrade spawns
	// at least three goroutines (handler, drain, ping ticker) plus a
	// hubClient registry entry; without a cap a flood of upgrades can
	// exhaust scheduler resources and the per-project broadcast budget.
	MaxWebSocketConns int

	// MaxWebSocketConnsPerIP caps the number of concurrent WebSocket
	// connections any single remote IP may hold. Zero substitutes
	// config.WebSocketConnsPerIPDefault (8). Reaching the cap causes
	// new upgrades from that IP to be rejected with HTTP 429 and a
	// Retry-After header before nhooyr.Accept hijacks the response.
	MaxWebSocketConnsPerIP int

	// MaxRequestBodyBytes caps any incoming POST/PUT/PATCH request body
	// the server will accept. Zero substitutes maxJSONBodyBytes (10 MiB).
	// Oversize requests are rejected with HTTP 413 (Request Entity Too
	// Large). Set via config.UIConfig.MaxRequestBodyBytes; bounded by
	// config.MaxRequestBodyBytesLower / Upper. Task 20102.
	MaxRequestBodyBytes int64

	// AllowedWSOrigins lists extra Origin hosts (host or host:port) that may
	// open a WebSocket, in addition to the always-allowed loopback origins
	// and same-origin requests. Needed only when the dashboard sits behind a
	// reverse proxy that rewrites Host so same-origin detection can't see the
	// public hostname. Populated from config.UIConfig.AllowedWSOrigins.
	AllowedWSOrigins []string

	// AllowedOrigins is the deployment-wide origin allowlist: it applies to
	// the dashboard socket AND to the executor-agent endpoint. Populated from
	// config.UIConfig.AllowedOrigins.
	//
	// It is separate from AllowedWSOrigins because the two have different
	// blast radii. An entry here can open an agent connection; an entry in
	// AllowedWSOrigins cannot. Merging them would silently promote every
	// dashboard-scoped origin to the agent endpoint.
	AllowedOrigins []string

	// ExternalURL is what this deployment calls itself, e.g.
	// https://cloop.example.com. Its host is an accepted WebSocket Origin for
	// both the dashboard and the executor-agent endpoint. Populated from
	// config.UIConfig.ExternalURL.
	ExternalURL string

	// TLSCertFile / TLSKeyFile enable native HTTPS. Both must be set or
	// neither; Run refuses to start on a half-configuration rather than
	// silently falling back to plaintext. TLSMinVersion is "1.2" (default)
	// or "1.3". Populated from config.UIConfig.TLS or --tls-cert/--tls-key.
	TLSCertFile   string
	TLSKeyFile    string
	TLSMinVersion string

	mu      sync.Mutex
	clients map[*sseClient]struct{}
	lastMod time.Time

	// projectsMu guards Projects after startup: removeProjectsFlag compacts
	// the slice while watcher goroutines (watchProjects,
	// autobackup) and request handlers iterate it concurrently. Readers use
	// projectsSnapshot; writers hold the write lock.
	projectsMu sync.RWMutex

	// Hub registry: per-project WebSocket client presence tracking.
	// Key is the resolved workDir path.
	hubMu      sync.Mutex
	hubClients map[string]map[*hubClient]struct{}

	// WebSocket connection accounting for the upgrade-time caps
	// (MaxWebSocketConns, MaxWebSocketConnsPerIP). Lock order: wsConnMu
	// is a leaf lock — never call into hubMu, rlMu, or any other Server
	// mutex while holding it. Per-IP counters live in wsConnPerIP and
	// are decremented (and the entry removed when the count hits zero)
	// in handleWS's deferred cleanup so the map stays bounded by the
	// number of *currently connected* IPs rather than the lifetime
	// distinct-IP set.
	wsConnMu    sync.Mutex
	wsConnTotal int
	wsConnPerIP map[string]int

	// Conflict tracker: per-project, per-task-field last-edit records.
	// Outer key: workDir, inner key: "taskID:field".
	conflictMu      sync.Mutex
	conflictTracker map[string]map[string]*conflictEntry

	// Rate limiting: tracks per-IP auth failure counts.
	authMu    sync.Mutex
	authFails map[string]*authFailEntry

	// Per-IP request rate-limit buckets.
	rlMu      sync.Mutex
	rlBuckets map[string]*uiIPBucket

	// Live harness output, partitioned by project workDir (Task 20189).
	// There is deliberately no un-keyed buffer here: every accessor in
	// livelog.go takes a workDir, so a handler that has not resolved a
	// project cannot reach another tenant's bytes.
	liveLogMu    sync.Mutex
	liveLogRooms map[string]*liveLogRoom

	// runStates tracks the last-broadcast running flag per project workDir so
	// the watcher can emit `run_state` WS events only on transitions instead of
	// requiring clients to poll /api/livelog.
	runStateMu sync.Mutex
	runStates  map[string]bool

	// Suggest background job state. Suggestions are generated and held for the
	// user to review individually; clients add either selected ones or all.
	// suggestWorkDir remembers which project the active job was launched from
	// so completion can be broadcast to that project's WS clients.
	suggestMu          sync.Mutex
	suggestRunning     bool
	suggestDone        bool
	suggestErr         string
	suggestSummary     string
	suggestSuggestions []*suggest.Suggestion
	suggestWorkDir     string

	// Multi-project state cache
	projMu       sync.RWMutex
	projStatuses []multiui.ProjectStatus
	projLastMod  map[string]time.Time // path -> last mod time

	// Per-project chat conversation histories (keyed by resolved workDir path).
	chatMu        sync.Mutex
	chatHistories map[string][]ChatMessage

	// Graceful shutdown plumbing. httpServer is set in Run after the
	// http.Server is constructed so Shutdown can call its Shutdown method;
	// shutdownMu guards access for the (rare) case where Shutdown races
	// against Run-failure cleanup. Both are nil before Run and after the
	// underlying server has been replaced.
	shutdownMu sync.Mutex
	httpServer *http.Server

	// ReadyCheck overrides the readiness check used by /readyz. nil
	// means use defaultReadyCheck (stat state.db, open it, run SELECT 1
	// bounded by ctx). Tests use this field to simulate degraded states
	// like "closed db handle" or "state store not initialized".
	ReadyCheck func(ctx context.Context) error

	// Log is the structured logger used for lifecycle / error messages
	// emitted by the UI server itself (panics in HTTP middleware, client
	// JavaScript errors POSTed to /api/client-error, watcher failures).
	// Nil means the package picks a sensible default at first use (text
	// output to stdout, project bound).
	Log logger.Logger

	// ccAuth tracks the in-flight `claude auth login` session driven from
	// the UI. Nil until first use; lazily constructed on the first
	// /api/claudecode/auth/* call.
	ccAuthMu sync.Mutex
	ccAuth   *claudecodeauth.Manager

	// diffCache holds the last ProjectState broadcast per workDir. The
	// state_diff event ships only the delta against this snapshot — Task
	// 20132. Cache is lazily populated on first broadcast; a missing entry
	// produces a "full state" diff (every task in TasksAdded). Initial WS
	// frame still sends the entire state so newly connected clients have
	// something to diff against.
	diffCache *stateCache

	// OIDC is the optional OpenID Connect authenticator (Task 20152). Nil
	// (the default) means OIDC is disabled and the dashboard behaves
	// exactly as before: token auth if Token is set, otherwise open. Set
	// from ui.oidc.* in .cloop/config.yaml by cmd/ui_cmd.go; when active it
	// gates every route behind an IdP session and scopes the multi-project
	// registry per user (see pkg/ui/oidc.go).
	OIDC *oidcauth.Authenticator

	// Authz resolves OIDC claims to roles and permissions (Task 20164).
	// Nil means "no role mappings configured": every session identity then
	// falls back to the resolver's deny-by-default, which is why
	// authzActive() also requires OIDC to be enabled. With OIDC disabled
	// this field is ignored entirely and every request is granted
	// everything, preserving single-tenant local behavior.
	Authz *authz.Resolver

	// quotaEnforcer caps how much each identity may consume (Task 20182).
	// Nil means no quota policy was installed, in which case every
	// admission helper in quotas_api.go succeeds and single-tenant use is
	// unchanged. Installed by SetQuotaPolicy from ui.quotas in
	// .cloop/config.yaml, and rebuilt from live state by ReconcileQuotas
	// before the listener binds.
	//
	// It is where RBAC stops and admission control starts: Authz answers
	// "may this identity act?", this answers "how much?".
	quotaMu       sync.RWMutex
	quotaEnforcer *quota.Enforcer

	// tokens verifies the scoped API tokens that authenticate CI, scripts,
	// and edge devices (Task 20175). Lazily opened on the first request that
	// presents a `cloop_pat_…` credential — and never on hubs that have none
	// — then cached with its database handle for the process lifetime,
	// because verification sits on the authentication path and must not pay
	// a SQLite open per request. tokenDB is held solely so Shutdown can close
	// it. Guarded by tokenMu.
	tokenMu sync.Mutex
	tokens  *apitoken.Manager
	tokenDB *statedb.DB

	// sessions holds the durable session store and its database handle
	// (Task 20176). Opened by OpenSessionStore before OIDC is constructed, so
	// unlike tokens it is not lazily built on the request path. Zero value
	// means process-local sessions.
	sessions sessionStoreState
}

// log returns s.Log, falling back to a default text logger if the field
// was left zero. The fallback is initialised lazily so test servers that
// construct Server{} directly (rather than via New) still get a usable
// logger without explicit wiring.
func (s *Server) log() logger.Logger {
	if s.Log != nil {
		return s.Log
	}
	s.Log = logger.New(false).With("project", s.WorkDir).With("component", "ui")
	return s.Log
}

// New creates a new UI server for the given working directory and port.
// token is optional; if non-empty every API request must supply it via
// "Authorization: Bearer <token>" header or "?token=<token>" query param.
func New(workdir string, port int, token string) *Server {
	// Register the built-in execution drivers and point the registry at
	// this control plane's persisted project→executor bindings, so every
	// handler can call executor.Resolve (Task 20156).
	bootstrapExecutors(workdir)
	return &Server{
		WorkDir:         workdir,
		Port:            port,
		Token:           token,
		clients:         make(map[*sseClient]struct{}),
		hubClients:      make(map[string]map[*hubClient]struct{}),
		wsConnPerIP:     make(map[string]int),
		conflictTracker: make(map[string]map[string]*conflictEntry),
		authFails:       make(map[string]*authFailEntry),
		rlBuckets:       make(map[string]*uiIPBucket),
		chatHistories:   make(map[string][]ChatMessage),
		runStates:       make(map[string]bool),
		liveLogRooms:    make(map[string]*liveLogRoom),
		Log:             logger.New(false).With("project", workdir).With("component", "ui"),
		diffCache:       newStateCache(),
	}
}

// uiAllow reports whether the request from ip is within the rate limit.
func (s *Server) uiAllow(ip string) bool {
	rps := s.RPS
	if rps <= 0 {
		rps = 20.0
	}
	burst := s.Burst
	if burst <= 0 {
		burst = 50
	}

	now := time.Now()
	s.rlMu.Lock()
	defer s.rlMu.Unlock()

	b, ok := s.rlBuckets[ip]
	if !ok {
		// New IP. If we're at the cap, sweep stale buckets first; if still
		// at the cap, evict the least-recently-seen one. Both branches keep
		// the map size bounded by uiRLMaxBuckets.
		if len(s.rlBuckets) >= uiRLMaxBuckets {
			s.evictRLBucketsLocked(now)
		}
		b = &uiIPBucket{tokens: float64(burst), lastSeen: now}
		s.rlBuckets[ip] = b
	}

	elapsed := now.Sub(b.lastSeen).Seconds()
	b.tokens += elapsed * rps
	if b.tokens > float64(burst) {
		b.tokens = float64(burst)
	}
	b.lastSeen = now

	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// evictRLBucketsLocked removes stale rate-limit buckets to keep the map
// bounded. The caller must hold s.rlMu. It first sweeps anything older than
// uiRLBucketIdleTTL; if the map is still at the cap, it evicts the single
// least-recently-seen bucket so the caller can safely insert a new entry.
func (s *Server) evictRLBucketsLocked(now time.Time) {
	for ip, b := range s.rlBuckets {
		if now.Sub(b.lastSeen) > uiRLBucketIdleTTL {
			delete(s.rlBuckets, ip)
		}
	}
	if len(s.rlBuckets) < uiRLMaxBuckets {
		return
	}
	var oldestIP string
	var oldestSeen time.Time
	for ip, b := range s.rlBuckets {
		if oldestIP == "" || b.lastSeen.Before(oldestSeen) {
			oldestIP = ip
			oldestSeen = b.lastSeen
		}
	}
	if oldestIP != "" {
		delete(s.rlBuckets, oldestIP)
	}
}

// evictAuthFailsLocked removes stale auth-fail entries to keep the map
// bounded. The caller must hold s.authMu. Same eviction policy as
// evictRLBucketsLocked: TTL sweep first, then a single oldest-entry evict
// if the map is still at the cap.
func (s *Server) evictAuthFailsLocked(now time.Time) {
	for ip, e := range s.authFails {
		if now.Sub(e.lastSeen) > uiAuthFailsIdleTTL {
			delete(s.authFails, ip)
		}
	}
	if len(s.authFails) < uiAuthFailsMaxEntries {
		return
	}
	var oldestIP string
	var oldestSeen time.Time
	for ip, e := range s.authFails {
		if oldestIP == "" || e.lastSeen.Before(oldestSeen) {
			oldestIP = ip
			oldestSeen = e.lastSeen
		}
	}
	if oldestIP != "" {
		delete(s.authFails, oldestIP)
	}
}

// uiRateLimitMiddleware wraps next with per-IP token-bucket rate limiting.
func (s *Server) uiRateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.uiAllow(clientIP(r)) {
			rps := s.RPS
			if rps <= 0 {
				rps = 20.0
			}
			retryAfter := int(1.0/rps) + 1
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
			w.WriteHeader(http.StatusTooManyRequests)
			json.NewEncoder(w).Encode(map[string]string{"error": "rate limit exceeded"}) //nolint:errcheck
			return
		}
		next.ServeHTTP(w, r)
	})
}

// resolveWorkDir returns the effective working directory for a request.
// In multi-project mode the caller may supply ?project_idx=N to scope the
// request to a registered project's directory instead of the server's WorkDir.
// With OIDC enabled the index space is the requesting user's visible project
// list (see visibleProjectEntries), so a user can never address another
// user's project by index.
func (s *Server) resolveWorkDir(r *http.Request) string {
	if idx := r.URL.Query().Get("project_idx"); idx != "" {
		i, err := strconv.Atoi(idx)
		if err == nil {
			entries := s.visibleProjectEntries(r)
			if i >= 0 && i < len(entries) {
				return entries[i].Path
			}
		}
	}
	return s.WorkDir
}

// Handler returns the HTTP handler for the server with all routes registered
// and security/auth middleware applied.  It does NOT start background goroutines
// (watchState, watchProjects); call Start() for the full lifecycle.
// This method exists primarily to support httptest-based unit tests.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	s.registerRoutes(mux)
	s.registerProviderCallNotifier()
	// Hash and gzip the front end now rather than on the first page load:
	// loadAssets is lazy so that every other cloop subcommand, which links
	// pkg/ui but never serves it, does not pay for it. See static.go.
	loadAssets()
	return s.buildHandler(mux)
}

// buildHandler assembles the final HTTP handler chain. The probe endpoints
// (/healthz, /readyz) are routed BEFORE auth and rate-limit middleware so
// load balancers and Kubernetes-style probes can reach them without
// credentials and without competing with user traffic for tokens. Panic
// recovery still wraps everything so a buggy probe handler cannot crash the
// daemon, and the security headers layer is preserved for the probe responses
// (it adds no auth, only hardening headers).
//
// requestIDMiddleware is the OUTERMOST middleware so the X-Request-ID header
// is set even on rate-limited 429 responses, auth-rejected 401s, and panic
// recovery's 500. The panic recovery layer itself sits below the request-ID
// layer so a panic in the request-ID code path itself would still surface as
// a clean 500 (panic recovery's stderr stack trace gives operators what they
// need in that pathological case).
// The remote-executor connect endpoint is routed around authMiddleware but
// kept behind the rate limiter and every hardening layer: agents are not
// dashboard users and authenticate with their own credentials, which the hub
// verifies itself (Task 20158). See pkg/ui/executor_agents.go.
// authzMiddleware sits directly below authMiddleware: by then the caller is
// authenticated, so the identity it resolves into a permission set is the one
// the route gates will enforce (Task 20164).
func (s *Server) buildHandler(mux *http.ServeMux) http.Handler {
	app := s.uiRateLimitMiddleware(s.securityHeaders(s.executorConnectBypass(s.authMiddleware(s.authzMiddleware(mux)))))
	return uiRequestIDMiddleware(panicRecoveryMiddleware(s.probeBypass(app)))
}

// uiRequestIDMiddleware threads a correlation ID through every Web UI
// request. It mirrors the apiserver implementation: read X-Request-ID,
// validate, fall back to a fresh ID, echo on the response, and bind to
// r.Context() so downstream handlers can pull it via reqid.FromContext.
//
// The middleware is exposed as a standalone helper (not a Server method)
// because Handler() builds its chain from buildHandler and tests rely on
// being able to inspect/replay the chain without a Server receiver.
func uiRequestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, ok := reqid.FromRequest(r)
		if !ok {
			id = reqid.Generate()
		}
		w.Header().Set(reqid.HeaderName, id)
		ctx := reqid.WithContext(r.Context(), id)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// probeBypass routes /healthz and /readyz directly to their handlers,
// skipping auth and rate-limit middleware. Every other request flows
// through the supplied next handler unchanged.
func (s *Server) probeBypass(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/healthz":
			s.handleHealthz(w, r)
			return
		case "/readyz":
			s.handleReadyz(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// handleHealthz is the liveness probe. It returns 200 unconditionally as
// long as the goroutine handling the request is alive — i.e., the process
// is up and the HTTP server is accepting connections. Liveness MUST NOT
// depend on downstream services (DB, network), or a transient outage will
// cause the orchestrator to kill an otherwise-recoverable process.
func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}

// handleReadyz is the readiness probe. It returns 200 only when the
// SQLite-backed state store is reachable AND has been initialized for
// this work directory; any failure yields 503 with a JSON body that
// names the failing check. The check is bounded by a 1s timeout so a
// hung database cannot block the probe response.
//
// The check function is overridable via Server.ReadyCheck for tests; the
// default verifies (a) state.db exists at the resolved workdir, (b) a
// fresh statedb handle opens against it, and (c) `SELECT 1` returns
// within 1s.
// Readiness gates, in the order they are evaluated. The storage check runs
// first because an executor verdict is meaningless on a hub whose state store
// is gone.
//
// The executor gate (Task 20170) is what stops a strict-mode hub with no
// isolating executor from accepting traffic it can only answer with 409s. It
// is deliberately not routed through Server.ReadyCheck: that hook exists so a
// test can stub out SQLite, and letting it also suppress the execution-path
// gate would mean the guarantee held only for deployments nobody had stubbed.
func (s *Server) handleReadyz(w http.ResponseWriter, r *http.Request) {
	storage := s.ReadyCheck
	if storage == nil {
		storage = s.defaultReadyCheck
	}
	ctx, cancel := context.WithTimeout(r.Context(), readyCheckTimeout)
	defer cancel()

	w.Header().Set("Content-Type", "application/json")
	if err := storage(ctx); err != nil {
		writeNotReady(w, "sqlite", err)
		return
	}
	if err := reconcile.Ready(); err != nil {
		writeNotReady(w, "executors", err)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"ready","check":"sqlite"}`))
}

// writeNotReady emits the 503 body, naming the gate that failed and — for the
// executor gate — the remediation as its own field so an operator reading
// `kubectl describe pod` output gets the fix, not just the symptom.
func writeNotReady(w http.ResponseWriter, check string, err error) {
	w.WriteHeader(http.StatusServiceUnavailable)
	body := map[string]any{
		"status": "not_ready",
		"check":  check,
		"error":  err.Error(),
	}
	var notReady *reconcile.NotReadyError
	if errors.As(err, &notReady) {
		body["reason"] = notReady.Reason
		if notReady.Remediation != "" {
			body["remediation"] = notReady.Remediation
		}
		if len(notReady.Diagnostics) > 0 {
			body["diagnostics"] = notReady.Diagnostics
		}
	}
	_ = json.NewEncoder(w).Encode(body)
}

// readyCheckTimeout caps the readiness probe's view of the SQLite store.
// Per Task 20092: "run a SELECT 1 with a 1s timeout."
const readyCheckTimeout = 1 * time.Second

// defaultReadyCheck verifies the state store is initialized at the server's
// configured workdir and reachable. ctx bounds the entire check (file stat,
// DB open, ping), so a hung disk or a wedged SQLite file cannot pin the
// probe goroutine.
func (s *Server) defaultReadyCheck(ctx context.Context) error {
	dbPath := state.StateDBPath(s.WorkDir)
	if _, err := os.Stat(dbPath); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("state store not initialized at %s", dbPath)
		}
		return fmt.Errorf("state store stat: %w", err)
	}
	db, err := statedb.Open(dbPath)
	if err != nil {
		return fmt.Errorf("statedb open: %w", err)
	}
	defer db.Close()
	return db.PingContext(ctx)
}

// Start begins listening on the configured port and broadcasting state
// updates. It installs SIGINT/SIGTERM handlers so the daemon shuts down
// gracefully when supervised by systemd or interrupted from a TTY: in-flight
// requests drain, watcher goroutines stop polling, and Start returns nil.
// Production callers use this entrypoint; tests that need fine-grained
// lifecycle control should call Run with their own context instead.
func (s *Server) Start() error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return s.Run(ctx)
}

// Run is the lifecycle entrypoint without signal handling: it blocks until ctx
// is cancelled or the underlying http.Server fails. On ctx cancellation it
// triggers a bounded graceful shutdown (10s) and returns nil. On listener
// failure it returns the underlying error. Calling Run more than once on the
// same Server is not supported.
func (s *Server) Run(ctx context.Context) error {
	mux := http.NewServeMux()
	s.registerRoutes(mux)
	s.registerProviderCallNotifier()
	s.restoreEnrolledExecutors()

	watcherCtx, cancelWatchers := context.WithCancel(context.Background())
	defer cancelWatchers()
	go s.watchState(watcherCtx)
	go s.watchProjects(watcherCtx)
	go s.watchAutoBackup(watcherCtx)
	s.startSessionJanitor(watcherCtx)
	// Sweeps lapsed secret leases off live agents. Without it a lease TTL
	// binds only the hub: an executor handed a fifteen-minute credential
	// keeps it for as long as its task runs. See secrets_revoke.go.
	s.StartLeaseJanitor(watcherCtx)
	defer s.StopLeaseJanitor()

	addr := ":" + strconv.Itoa(s.Port)
	srv := newUIHTTPServer(addr, s.buildHandler(mux))

	// Resolve TLS before announcing anything, so a broken certificate is an
	// error at startup rather than a dashboard that printed "https" and is
	// serving plaintext.
	tlsCfg, err := s.serverTLSConfig()
	if err != nil {
		return err
	}
	scheme := "http"
	if tlsCfg != nil {
		srv.TLSConfig = tlsCfg
		scheme = "https"
	}
	auth := ""
	if s.Token != "" {
		auth = " (token auth enabled)"
	}
	fmt.Printf("cloop dashboard running at %s://localhost%s%s\n", scheme, addr, auth)
	if tlsCfg != nil {
		fmt.Printf("TLS enabled (minimum %s, certificate %s)\n",
			tlsconf.VersionName(tlsCfg.MinVersion), s.TLSCertFile)
	}

	s.shutdownMu.Lock()
	s.httpServer = srv
	s.shutdownMu.Unlock()

	errCh := make(chan error, 1)
	go func() {
		if tlsCfg != nil {
			// Empty paths: the certificate is already loaded into TLSConfig,
			// so this does not re-read (and cannot disagree with) the files.
			errCh <- srv.ListenAndServeTLS("", "")
			return
		}
		errCh <- srv.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
		fmt.Fprintln(os.Stderr, "cloop ui: shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		// s.Shutdown sends code-1001 close frames to every active
		// WebSocket peer before invoking http.Server.Shutdown, so
		// browsers learn the server is going away (and can choose to
		// stop reconnecting) instead of seeing an abrupt TCP teardown.
		if err := s.Shutdown(shutdownCtx); err != nil && !errors.Is(err, context.DeadlineExceeded) {
			return fmt.Errorf("ui server shutdown: %w", err)
		}
		// Drain ListenAndServe — after Shutdown it returns http.ErrServerClosed.
		<-errCh
		return nil
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

// Shutdown initiates a graceful shutdown of a server started via Run. It is
// safe to call from any goroutine; if the server has not started or has
// already been shut down it is a no-op. The supplied ctx bounds how long
// Shutdown will wait for in-flight requests to drain.
func (s *Server) Shutdown(ctx context.Context) error {
	s.shutdownMu.Lock()
	srv := s.httpServer
	s.httpServer = nil
	s.shutdownMu.Unlock()
	if srv == nil {
		return nil
	}
	// Send a code 1001 (going away) close frame to every active WebSocket
	// peer before draining HTTP handlers. Hijacked WebSocket connections
	// are not tracked by http.Server.Shutdown's wait, so without this step
	// peers would see an abrupt TCP close once the process exits.
	s.closeAllWebSocketsForShutdown(2 * time.Second)
	// Stop probing before the process goes away, so a probe goroutine is not
	// still writing health rows into a database handle that is about to be
	// closed under it.
	stopExecutorSupervisor()
	// Release the API-token database handle held open for the authentication
	// path, so a hub restarted in-process (tests, `cloop hub bootstrap`) does
	// not leak a connection per lifecycle.
	s.closeTokenManager()
	// Same for the session store: the janitor stopped with the watcher context
	// above, so nothing is still reading through this handle.
	s.closeSessionStore()
	return srv.Shutdown(ctx)
}

// closeAllWebSocketsForShutdown sends a code-1001 (websocket.StatusGoingAway)
// close frame to every registered WebSocket client and waits up to timeout
// for the per-connection close handshakes to complete. Each Close call runs
// in its own goroutine because nhooyr's Close blocks on the peer's close-ack
// (capped at ~10s internally); a single wedged peer must not delay shutdown
// for the rest. Once all goroutines return — or the timeout fires — the
// caller proceeds with http.Server.Shutdown so any non-WebSocket handlers
// still draining can finish on their own clock.
//
// hubMu is held only long enough to snapshot the connections, so concurrent
// hubClient cleanup (which also takes hubMu) doesn't deadlock against the
// slow close handshakes running outside the lock.
func (s *Server) closeAllWebSocketsForShutdown(timeout time.Duration) {
	s.hubMu.Lock()
	conns := make([]*websocket.Conn, 0)
	for _, clients := range s.hubClients {
		for hc := range clients {
			if hc.conn != nil {
				conns = append(conns, hc.conn)
			}
		}
	}
	s.hubMu.Unlock()

	if len(conns) == 0 {
		return
	}

	var wg sync.WaitGroup
	wg.Add(len(conns))
	for _, c := range conns {
		go func(conn *websocket.Conn) {
			defer wg.Done()
			defer recoverGoroutine("closeAllWebSocketsForShutdown")
			// nhooyr's Close sends the close frame and waits up to ~10s
			// for the peer's ack; that's fine here because we cap the
			// outer wait via the timeout select below. The error is
			// ignored: on an already-closed conn it's a no-op, on a
			// wedged peer the per-conn close just won't return before
			// the outer timeout fires and shutdown proceeds anyway.
			_ = conn.Close(websocket.StatusGoingAway, "server shutting down")
		}(c)
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(timeout):
		// Slow peers will be forcibly torn down by the deferred
		// conn.CloseNow in handleWS once http.Server.Shutdown returns
		// — or, in the worst case, by process exit.
	}
}

// newUIHTTPServer constructs the http.Server with timeouts tuned for the UI's
// long-lived SSE and WebSocket endpoints. ReadHeaderTimeout defends against
// slowloris (slow header read) without affecting streaming response bodies.
// IdleTimeout closes idle keep-alive connections so a client that holds the
// pool open without sending requests does not pin a goroutine indefinitely.
// ReadTimeout / WriteTimeout are deliberately left unset because the UI serves
// SSE (text/event-stream) and WebSocket frames that must remain open across
// the lifetime of the user's session.
func newUIHTTPServer(addr string, h http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
}

// panicRecoveryMiddleware is the outermost HTTP layer: it recovers any panic
// from a downstream handler (or middleware) and converts it into a clean 500
// JSON response. net/http already recovers panics by default, but only logs
// to stderr and aborts the connection — without this middleware the client
// sees a half-written / dropped response. http.ErrAbortHandler is the
// documented way for handlers to intentionally abort; we re-panic so net/http
// observes it and applies the standard abort semantics.
//
// If the response is already a hijacked WebSocket or partial SSE/JSON write,
// w.WriteHeader / w.Write become no-ops or log "superfluous WriteHeader" but
// neither path crashes the goroutine — recovery still completes.
func panicRecoveryMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			rec := recover()
			if rec == nil {
				return
			}
			if rec == http.ErrAbortHandler {
				panic(rec)
			}
			fmt.Fprintf(os.Stderr, "[ui] panic in %s %s: %v\n%s\n",
				r.Method, r.URL.Path, rec, debug.Stack())
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"error":"internal server error"}`))
		}()
		next.ServeHTTP(w, r)
	})
}

// securityHeaders adds hardening HTTP response headers to every response.
//
// It is a method rather than a package function because the HSTS decision
// needs ui.external_url: see Server.requestIsTLS for why a proxy on another
// host cannot be recognised without it.
func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Prevent MIME-type sniffing.
		w.Header().Set("X-Content-Type-Options", "nosniff")
		// Deny framing to prevent clickjacking.
		w.Header().Set("X-Frame-Options", "DENY")
		// Strict CSP: only allow same-origin resources plus inline styles/scripts
		// needed by the SPA. No external connections permitted.
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'")
		// Disable the Referrer header for privacy.
		w.Header().Set("Referrer-Policy", "no-referrer")
		// HSTS, but only on responses the client received over TLS. Sending
		// it over plaintext is both ignored by browsers (RFC 6797 §8.1) and
		// actively harmful on a loopback dev server, where it would pin
		// localhost to https in the operator's browser for a year and break
		// every other local project on that hostname.
		if s.requestIsTLS(r) {
			w.Header().Set("Strict-Transport-Security", hstsValue)
		}
		// Restrict CORS to localhost only (not wildcard). Parse the Origin
		// and compare the hostname exactly — a prefix match would also
		// accept e.g. http://localhost.evil.com.
		w.Header().Set("Vary", "Origin")
		if origin := r.Header.Get("Origin"); origin != "" {
			if u, err := url.Parse(origin); err == nil {
				switch u.Hostname() {
				case "localhost", "127.0.0.1", "::1":
					w.Header().Set("Access-Control-Allow-Origin", origin)
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}

// clientIP extracts the real client IP. X-Forwarded-For is only honoured
// when the direct peer is a loopback address (i.e. a reverse proxy running
// on this host); otherwise any remote client could spoof the header to
// bypass per-IP rate limits, auth lockout, and WebSocket connection caps.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
			// Take first address only.
			if idx := strings.Index(fwd, ","); idx != -1 {
				return strings.TrimSpace(fwd[:idx])
			}
			return strings.TrimSpace(fwd)
		}
	}
	return host
}

// authMiddleware enforces authentication. With OIDC enabled (Server.OIDC
// set) every route is gated behind an IdP session, with the static bearer
// token still accepted for automation — see oidcGate in oidc.go. Otherwise
// the original token-only behavior applies: Bearer-token auth on all /api/*
// routes when s.Token is set; the root path "/" is always served without
// auth so the login page can be loaded in the browser. Failed attempts are
// rate-limited per IP in both modes.
func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.oidcEnabled() {
			s.oidcGate(next, w, r)
			return
		}
		// A scoped API token is honoured before anything else, including on a
		// hub with no static token configured at all (Task 20175). That
		// ordering is what makes a PAT restrictive rather than decorative: an
		// open hub which skipped this would hand a viewer-scoped CI
		// credential the same authority as the local operator.
		if r2, ok, handled := s.authenticateAPIToken(w, r); handled {
			return
		} else if ok {
			next.ServeHTTP(w, r2)
			return
		}
		if s.Token == "" || r.URL.Path == "/" {
			next.ServeHTTP(w, r)
			return
		}

		ip := clientIP(r)

		// Check the per-IP failure lockout before evaluating the token.
		if s.authLockoutActive(ip) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Retry-After", strconv.Itoa(authLockoutSeconds))
			w.WriteHeader(http.StatusTooManyRequests)
			json.NewEncoder(w).Encode(map[string]string{"error": "too many failed attempts, try again later"}) //nolint:errcheck
			return
		}

		// Check Authorization: Bearer <token> header. Constant-time compare
		// so response timing leaks nothing about how many token bytes match.
		if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
			if subtle.ConstantTimeCompare([]byte(strings.TrimPrefix(auth, "Bearer ")), []byte(s.Token)) == 1 {
				next.ServeHTTP(w, r)
				return
			}
		}
		// Fallback: ?token=<token> query param (needed for EventSource which
		// cannot send custom headers).
		if subtle.ConstantTimeCompare([]byte(r.URL.Query().Get("token")), []byte(s.Token)) == 1 {
			next.ServeHTTP(w, r)
			return
		}

		s.recordAuthFailure(ip)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "unauthorized"}) //nolint:errcheck
	})
}

// authLockoutActive reports whether ip is currently locked out from
// authenticating. As a side effect it refreshes the entry's lastSeen and
// resets the failure counter once an expired lockout window has passed
// (preserving the pre-extraction inline semantics).
func (s *Server) authLockoutActive(ip string) bool {
	now := time.Now()
	s.authMu.Lock()
	defer s.authMu.Unlock()
	entry, ok := s.authFails[ip]
	if !ok {
		if len(s.authFails) >= uiAuthFailsMaxEntries {
			s.evictAuthFailsLocked(now)
		}
		entry = &authFailEntry{}
		s.authFails[ip] = entry
	}
	entry.lastSeen = now
	if entry.count >= authMaxFailures && now.Before(entry.lockedUntil) {
		return true
	}
	// Reset counter if lockout has expired.
	if entry.count >= authMaxFailures && now.After(entry.lockedUntil) {
		entry.count = 0
	}
	return false
}

// recordAuthFailure increments ip's auth failure counter and arms the
// lockout once the threshold is crossed. The entry created by
// authLockoutActive may have been evicted by a concurrent request between
// the two critical sections, so re-check and recreate rather than deref nil.
func (s *Server) recordAuthFailure(ip string) {
	s.authMu.Lock()
	entry := s.authFails[ip]
	if entry == nil {
		entry = &authFailEntry{lastSeen: time.Now()}
		s.authFails[ip] = entry
	}
	entry.count++
	if entry.count >= authMaxFailures {
		entry.lockedUntil = time.Now().Add(authLockoutSeconds * time.Second)
	}
	s.authMu.Unlock()
}

// recoverGoroutine logs a panic + stack trace from a long-running goroutine
// instead of letting it crash the entire daemon. Use as the body of a deferred
// call: `defer recoverGoroutine("watchState")`. The caller continues normally
// after recovery — for ticker loops this means the goroutine exits and the
// watcher stops; for per-iteration recovery (the recommended pattern), wrap
// the loop body in an immediately-invoked func and defer recoverGoroutine
// inside it so the loop keeps running after a single bad iteration.
func recoverGoroutine(name string) {
	if r := recover(); r != nil {
		fmt.Fprintf(os.Stderr, "[ui] panic in %s: %v\n%s\n", name, r, debug.Stack())
	}
}

// watchState polls the state file every second and notifies SSE clients on
// change. It returns when ctx is cancelled so Run can shut down cleanly
// instead of leaking a polling goroutine for the lifetime of the process.
func (s *Server) watchState(ctx context.Context) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		func() {
			defer recoverGoroutine("watchState iteration")
			// State lives in state.db (SQLite); state.json is the legacy
			// pre-migration format kept only as a stat fallback so the
			// watcher still fires for projects that were never migrated.
			dbPath := state.StateDBPath(s.WorkDir)
			fi, err := os.Stat(dbPath)
			if err != nil {
				fi, err = os.Stat(state.StatePath(s.WorkDir))
			}
			if err != nil {
				return
			}
			mod := fi.ModTime()
			// Under WAL journaling, writes land in state.db-wal first and
			// the main db file's mtime can lag behind; take the newest of
			// the two so changes are noticed on the next tick.
			if wfi, werr := os.Stat(dbPath + "-wal"); werr == nil && wfi.ModTime().After(mod) {
				mod = wfi.ModTime()
			}
			if mod.Equal(s.lastMod) {
				return
			}
			s.lastMod = mod

			ps, err := state.LoadLite(s.WorkDir)
			if err != nil {
				return
			}
			data, err := marshalStateForWire(ps)
			if err != nil {
				return
			}
			// SSE consumers still get the full state — they are a fallback
			// path and not the perf-critical one. WebSocket consumers get a
			// state_diff event with only the changed fields (Task 20132).
			s.broadcast(s.WorkDir, string(data))
			s.broadcastStateDiff(s.WorkDir, ps)
		}()
	}
}

// broadcast sends workDir's full-state JSON payload to that project's SSE
// clients. WebSocket clients are fanned out via broadcastStateDiff which
// ships only the delta against the cached snapshot (Task 20132).
//
// Scoped for the same reason as broadcastLog: the payload is one project's
// state — goal, task titles, statuses — and both call sites already pair
// this with a per-project broadcastStateDiff on the WebSocket side. The SSE
// mirror used to fan out to every listener regardless of project
// (Task 20189).
//
// Slow consumers do NOT silently drop events: the SSE path uses
// sendSSEOrLag, which queues a resync directive when the per-client buffer
// is full.
func (s *Server) broadcast(workDir, data string) {
	if workDir == "" {
		return
	}
	s.mu.Lock()
	for c := range s.clients {
		if c.workDir != workDir {
			continue
		}
		s.sendSSEOrLag(c, sseEvent{Data: data})
	}
	s.mu.Unlock()
}

// broadcastStateDiff computes the delta between the cached snapshot for
// workDir and curr, then ships only the changed bits as a "state_diff"
// WebSocket event (Task 20132). The cache is always updated to curr so the
// next call diffs against this version.
//
// First broadcast for a project (no cached prev) yields a full-state diff:
// every task lands in tasks_added and every persisted top-level field lands
// in state_changed. Subsequent broadcasts are typically a few hundred bytes
// regardless of project size.
//
// No-op if curr is nil or the diff has no changes. SSE clients are unaffected
// — they still receive the full-state frame via broadcast().
func (s *Server) broadcastStateDiff(workDir string, curr *state.ProjectState) {
	if curr == nil {
		return
	}
	cache := s.ensureDiffCache()
	prev := cache.swap(workDir, curr)
	diff := computeStateDiff(prev, curr)
	if !diff.HasChanges {
		return
	}
	raw, err := json.Marshal(diff)
	if err != nil {
		return
	}
	s.broadcastToProject(workDir, wsMessage{Type: "state_diff", Data: raw})
}

// resetStateDiffCache forgets the cached snapshot for workDir so the next
// broadcast emits a full-state diff. Called from the WebSocket connect path
// for the connecting client's project so a reconnecting tab catches up via
// state_diff rather than waiting for the next mutation to ship a partial
// delta against a state it never saw.
//
// Single-shot drop — does not coordinate with concurrent broadcasts. If a
// broadcast races in between, the next one will simply re-establish the
// cache (worst case: one redundant full-state diff to other clients).
func (s *Server) resetStateDiffCache(workDir string) {
	if s.diffCache != nil {
		s.diffCache.drop(workDir)
	}
}

// broadcastToProject sends a WebSocket message only to clients connected to
// the given project (identified by its resolved workDir path). Slow clients
// receive a resync directive instead of silent event loss (see sendOrLag).
//
// hubMu is held through the iteration to prevent a concurrent
// `delete(s.hubClients[workDir], hc)` (the WebSocket disconnect cleanup at
// the bottom of handleWS) from triggering Go's "concurrent map iteration
// and map write" runtime panic. sendOrLag is non-blocking (select/default),
// so holding the lock briefly here is safe.
func (s *Server) broadcastToProject(workDir string, msg wsMessage) {
	s.hubMu.Lock()
	defer s.hubMu.Unlock()
	for hc := range s.hubClients[workDir] {
		s.sendOrLag(hc, msg)
	}
}

// presenceUsers returns a snapshot of all users connected to a project.
func (s *Server) presenceUsers(workDir string) []presenceUser {
	s.hubMu.Lock()
	defer s.hubMu.Unlock()
	clients := s.hubClients[workDir]
	users := make([]presenceUser, 0, len(clients))
	for hc := range clients {
		users = append(users, presenceUser{ID: hc.id, Name: hc.name, Color: hc.color})
	}
	return users
}

// broadcastPresence sends the current presence list to all clients in a project.
func (s *Server) broadcastPresence(workDir string) {
	users := s.presenceUsers(workDir)
	raw, _ := json.Marshal(map[string]interface{}{"users": users})
	s.broadcastToProject(workDir, wsMessage{Type: "presence", Data: raw})
}

// checkAndRecordEdit records that clientID edited the given fields of taskID in
// workDir. Returns true if a conflict is detected (same field edited by a
// different client within the last conflictWindow).
//
// On every call the tracker sweeps stale entries across all workDirs (not just
// the current one) — projects that stop being edited never trigger their own
// sweep, so without a global pass their entries would persist for the daemon's
// lifetime. Combined with the conflictWindow cutoff the tracker stays bounded
// by current editing activity rather than session lifetime.
func (s *Server) checkAndRecordEdit(workDir, clientID string, taskID int, fields []string) bool {
	now := time.Now()
	s.conflictMu.Lock()
	defer s.conflictMu.Unlock()

	for wd, m := range s.conflictTracker {
		for k, e := range m {
			if now.Sub(e.editedAt) >= conflictWindow {
				delete(m, k)
			}
		}
		if len(m) == 0 && wd != workDir {
			delete(s.conflictTracker, wd)
		}
	}

	inner := s.conflictTracker[workDir]
	if inner == nil {
		inner = make(map[string]*conflictEntry)
		s.conflictTracker[workDir] = inner
	}
	conflict := false
	for _, field := range fields {
		key := fmt.Sprintf("%d:%s", taskID, field)
		if prev, ok := inner[key]; ok {
			if prev.clientID != clientID && now.Sub(prev.editedAt) < conflictWindow {
				conflict = true
			}
		}
		inner[key] = &conflictEntry{clientID: clientID, editedAt: now}
	}

	for len(inner) > maxConflictEntriesPerWorkDir {
		for k := range inner {
			delete(inner, k)
			if len(inner) <= maxConflictEntriesPerWorkDir {
				break
			}
		}
	}
	return conflict
}

// presenceNames is a list of fun display names for anonymous users.
var presenceNames = []string{
	"Swift Panda", "Bold Fox", "Keen Owl", "Calm Deer", "Brave Wolf",
	"Quick Lynx", "Sharp Hawk", "Witty Otter", "Sage Raven", "Bright Ibis",
	"Cool Moose", "Deft Crane", "Eager Bison", "Fable Lynx", "Glad Ferret",
}

// presenceColors are the accent colors assigned to users (cycling).
var presenceColors = []string{
	"#58a6ff", "#3fb950", "#bc8cff", "#39c5cf", "#f85149",
	"#d29922", "#e3b341", "#ff7b72", "#79c0ff", "#56d364",
}

// broadcastRunState pushes the current run state for workDir to all WebSocket
// clients connected to that project. The event is only emitted when the
// running flag actually changes — repeat broadcasts of the same state are
// suppressed so reconnect storms don't redundantly toggle button visibility.
// If force is true the current value is sent regardless of cached state (used
// for the initial WS handshake so a freshly connected client gets a baseline).
//
// SSE clients (used as a WebSocket fallback when proxies strip Upgrade) also
// receive a typed "run_state" SSE event so polling is eliminated on that
// path too.
func (s *Server) broadcastRunState(workDir string, running, force bool) {
	s.runStateMu.Lock()
	prev, ok := s.runStates[workDir]
	if !force && ok && prev == running {
		s.runStateMu.Unlock()
		return
	}
	s.runStates[workDir] = running
	s.runStateMu.Unlock()

	raw, err := json.Marshal(map[string]interface{}{"running": running})
	if err != nil {
		return
	}
	s.broadcastToProject(workDir, wsMessage{Type: "run_state", Data: raw})

	// Mirror to this project's SSE clients (fallback path) — matching the
	// scoping the WebSocket line above already applies (Task 20189).
	s.mu.Lock()
	for c := range s.clients {
		if c.workDir != workDir {
			continue
		}
		s.sendSSEOrLag(c, sseEvent{Event: "run_state", Data: string(raw)})
	}
	s.mu.Unlock()
}

// broadcastSuggestStatus pushes the current suggest job status to all
// WebSocket clients connected to workDir. Replaces the /api/suggest/status
// polling client used to do.
func (s *Server) broadcastSuggestStatus(workDir string) {
	s.suggestMu.Lock()
	payload := map[string]interface{}{
		"running":     s.suggestRunning,
		"done":        s.suggestDone,
		"error":       s.suggestErr,
		"summary":     s.suggestSummary,
		"suggestions": append([]*suggest.Suggestion(nil), s.suggestSuggestions...),
	}
	s.suggestMu.Unlock()

	raw, err := json.Marshal(payload)
	if err != nil {
		return
	}
	if workDir == "" {
		return
	}
	s.broadcastToProject(workDir, wsMessage{Type: "suggest_status", Data: raw})

	// Mirror to this project's SSE clients (fallback path). The payload
	// carries generated suggestion text for one plan, so it is scoped the
	// same way as the WebSocket line above (Task 20189).
	s.mu.Lock()
	for c := range s.clients {
		if c.workDir != workDir {
			continue
		}
		s.sendSSEOrLag(c, sseEvent{Event: "suggest_status", Data: string(raw)})
	}
	s.mu.Unlock()
}

// broadcastLog ships one chunk of workDir's live harness output to that
// project's subscribers — WebSocket and SSE — and records it for replay.
//
// Every fan-out here is per-project. Live output is raw stdout from an AI
// harness working inside someone's repository, so a chunk reaching a client
// that did not subscribe to workDir is an active disclosure, not a cosmetic
// bug: on a multi-tenant hub the other subscriber may be another identity
// entirely. broadcastToProject is the primitive that gets this right;
// pre-fix this function walked all of s.hubClients and all of s.clients
// instead, so one project's output landed on every open dashboard
// (Task 20189).
func (s *Server) broadcastLog(workDir, chunk string) {
	// No project, no delivery. An unresolved workDir used to mean "send it
	// everywhere"; it now means the chunk is dropped, which is the safe
	// direction to fail.
	if workDir == "" {
		return
	}
	s.liveLogAppend(workDir, chunk)

	data, err := json.Marshal(map[string]string{"chunk": chunk})
	if err != nil {
		return
	}

	s.mu.Lock()
	for c := range s.clients {
		if c.workDir != workDir {
			continue
		}
		s.sendSSEOrLag(c, sseEvent{Event: "log", Data: string(data)})
	}
	s.mu.Unlock()

	s.broadcastToProject(workDir, wsMessage{Type: "step_output", Data: json.RawMessage(data)})
}

// ── helpers ──────────────────────────────────────────────────────────────────

func jsonOK(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func jsonErr(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func requirePOST(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return false
	}
	return true
}

// Maximum sizes for JSON request bodies. These bound peak memory per request
// so a malicious or buggy client cannot OOM the long-running daemon by
// streaming an enormous payload (or holding a slow-trickle connection open).
//
// The default (10 MiB) is generous enough for chat transcripts and bulk
// task edits while sitting well below typical container memory limits.
// Operators can override per-project via config.UIConfig.MaxRequestBodyBytes.
const (
	// maxJSONBodyBytes is the default cap for every POST/PUT/PATCH handler.
	// Mirrors config.MaxRequestBodyBytesDefault so the constant is usable
	// from contexts that haven't loaded config yet (tests, embedded calls).
	maxJSONBodyBytes int64 = 10 << 20 // 10 MiB
	// maxChatJSONBodyBytes is retained as an alias for callers that
	// historically used a larger cap; with the default bumped to 10 MiB
	// it now matches maxJSONBodyBytes.
	maxChatJSONBodyBytes int64 = 10 << 20 // 10 MiB
)

// effectiveMaxBodyBytes returns the configured request-body cap for this
// server, falling back to maxJSONBodyBytes when MaxRequestBodyBytes is unset
// or non-positive.
func (s *Server) effectiveMaxBodyBytes() int64 {
	if s != nil && s.MaxRequestBodyBytes > 0 {
		return s.MaxRequestBodyBytes
	}
	return maxJSONBodyBytes
}

// limitJSONBody wraps r.Body with http.MaxBytesReader so a subsequent
// json.NewDecoder().Decode() stops reading after maxBytes and returns
// *http.MaxBytesError instead of streaming attacker-controlled data into
// memory. Safe to call once per request before decoding.
func limitJSONBody(w http.ResponseWriter, r *http.Request, maxBytes int64) {
	if r != nil && r.Body != nil {
		r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
	}
}

// respondToBodyError writes the right HTTP error response for a JSON
// decode failure. *http.MaxBytesError (returned when MaxBytesReader's
// limit is reached) yields HTTP 413 (Request Entity Too Large); every
// other failure (malformed JSON, type mismatch, EOF) yields HTTP 400.
// Centralising the translation here keeps every handler's decode error
// path consistent and frees callers from importing net/http's error
// type. Task 20102.
func respondToBodyError(w http.ResponseWriter, err error) {
	var maxErr *http.MaxBytesError
	if errors.As(err, &maxErr) {
		jsonErr(w, "request body too large", http.StatusRequestEntityTooLarge)
		return
	}
	jsonErr(w, "invalid request body", http.StatusBadRequest)
}

// ── handlers ─────────────────────────────────────────────────────────────────

// clientErrorMaxField is the per-field byte cap applied to JSON sent to
// /api/client-error. The server-side cap is enforced in addition to the
// outer effectiveMaxBodyBytes() limit so a single oversize stack trace
// can never blow up a log line. Picked at 8 KiB: comfortably larger than
// any browser stack trace observed in practice while still small enough
// that 100 errors/sec stays well below daily-log budgets.
const clientErrorMaxField = 8 * 1024

// truncate returns s clipped to at most max bytes, appending an ellipsis
// marker when truncation occurred so log readers know the line is partial.
func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	if max <= 3 {
		return s[:max]
	}
	return s[:max-3] + "..."
}

// handleClientError accepts a JSON-encoded JavaScript error report from the
// dashboard's window.onerror / unhandledrejection handlers and forwards it
// to the structured logger. The wire body is:
//
//	{ "message": "...", "stack": "...", "url": "...", "userAgent": "...",
//	  "tab": "tasks", "kind": "error" | "unhandledrejection",
//	  "line": 123, "col": 45 }
//
// Every string field is byte-clipped to clientErrorMaxField so a runaway
// stack trace cannot inflate a single log line. The handler always responds
// with 204 No Content on success: the client never reads the body, and a
// short response keeps overhead low under burst-error conditions.
func (s *Server) handleClientError(w http.ResponseWriter, r *http.Request) {
	if !requirePOST(w, r) {
		return
	}
	limitJSONBody(w, r, s.effectiveMaxBodyBytes())
	var req struct {
		Message   string `json:"message"`
		Stack     string `json:"stack"`
		URL       string `json:"url"`
		UserAgent string `json:"userAgent"`
		Tab       string `json:"tab"`
		Kind      string `json:"kind"`
		Line      int    `json:"line"`
		Col       int    `json:"col"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondToBodyError(w, err)
		return
	}
	kind := req.Kind
	if kind == "" {
		kind = "error"
	}
	data := map[string]interface{}{
		"kind":       kind,
		"client_url": truncate(req.URL, clientErrorMaxField),
		"user_agent": truncate(req.UserAgent, clientErrorMaxField),
		"tab":        truncate(req.Tab, 64),
		"client_ip":  clientIP(r),
		"stack":      truncate(req.Stack, clientErrorMaxField),
	}
	if req.Line > 0 {
		data["line"] = req.Line
	}
	if req.Col > 0 {
		data["col"] = req.Col
	}
	msg := truncate(req.Message, clientErrorMaxField)
	if msg == "" {
		msg = "(no message)"
	}
	s.log().WithContext(r.Context()).Error("client_error", 0, msg, data)
	w.WriteHeader(http.StatusNoContent)
}

// marshalStateForWire serialises a ProjectState for the browser without the
// large Steps[] array (Task 20125). The UI only ever reads steps.length
// from the wire — actual rows come from the paginated /api/steps and
// /api/event-history endpoints. Shipping the slice in /api/state and in
// every task_update / task_mutation / task_added / task_deleted broadcast
// was wasting ~1.7 MiB per request on a 5k-step project (83% of payload)
// and dominating perceived UI latency. We replace the array with a new
// top-level "steps_count" field; the frontend prefers it when present and
// falls back to (s.steps||[]).length for older clients.
//
// The caller's ProjectState is never mutated: we copy the struct (cheap,
// ~200 bytes), nil out Steps on the copy, marshal, then splice
// "steps_count":N before the closing brace.
func marshalStateForWire(ps *state.ProjectState) ([]byte, error) {
	if ps == nil {
		return []byte("null"), nil
	}
	// Prefer the explicit StepCount field — set by state.LoadLite where
	// Steps is nil — and fall back to len(Steps) for full loads. Without
	// this, lite-loaded states would always report steps_count:0 on the
	// wire even when the underlying project has thousands of steps.
	stepsCount := len(ps.Steps)
	if stepsCount == 0 && ps.StepCount > 0 {
		stepsCount = ps.StepCount
	}
	clone := *ps
	clone.Steps = nil
	raw, err := json.Marshal(&clone)
	if err != nil {
		return nil, err
	}
	if len(raw) >= 2 && raw[0] == '{' && raw[len(raw)-1] == '}' {
		sep := ","
		if len(raw) == 2 {
			sep = ""
		}
		// Always surface the per-project step timeout on the wire (Task 20147).
		// step_timeout lives in config.yaml, not ProjectState, so before this
		// it was present only in the /api/state HTTP response. Every WebSocket
		// task_update ships a full state via this function and the frontend's
		// `render(data)` replaces appState wholesale — so the first task_update
		// after a run started dropped step_timeout and the Active Options panel
		// snapped back to its "10m" placeholder, looking like the value had
		// been reset. Injecting it here keeps the value stable across both the
		// full-state and the diff (which merges, never clears) code paths.
		// "" (unset) is normalised to "0" (disabled) so the default reads as
		// "off" rather than the misleading "10m".
		stepTimeout := "0"
		if ps.WorkDir != "" {
			if cfg, err := config.Load(ps.WorkDir); err == nil && cfg.StepTimeout != "" {
				stepTimeout = cfg.StepTimeout
			}
		}
		injected := fmt.Sprintf(`%s"steps_count":%d,"step_timeout":%q}`, sep, stepsCount, stepTimeout)
		return append(raw[:len(raw)-1:len(raw)-1], injected...), nil
	}
	return raw, nil
}

// handleDashboard serves the single-page HTML shell. The markup is assembled
// once from assets/index.html with the content-hashed URLs of the CSS and JS
// substituted in; see static.go. It is served no-cache with an ETag, so a
// returning client revalidates in one conditional request and re-downloads the
// scripts only when a deploy changed their hash.
func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	writeAsset(w, r, loadAssets().page)
}

// handleState returns the current project state as JSON.
func (s *Server) handleState(w http.ResponseWriter, r *http.Request) {
	workDir := s.resolveWorkDir(r)
	// LoadLite skips reading per-step rows since marshalStateForWire
	// throws them away anyway — saves ~1.5 MiB of allocation per request
	// on a 5k-step project (Task 20125).
	ps, err := state.LoadLite(workDir)
	if err != nil {
		jsonErr(w, "no cloop project found", http.StatusNotFound)
		return
	}
	// Enrich from config.
	cfg, cfgErr := config.Load(workDir)
	if cfgErr == nil {
		if ps.Model == "" {
			switch ps.Provider {
			case "anthropic":
				ps.Model = cfg.Anthropic.Model
			case "openai":
				ps.Model = cfg.OpenAI.Model
			case "ollama":
				ps.Model = cfg.Ollama.Model
			case "claudecode":
				ps.Model = cfg.ClaudeCode.Model
				if ps.Model == "" {
					ps.Model = "claude-sonnet-4-6"
				}
			}
		}
	}

	// Marshal without the multi-MiB Steps slice (Task 20125). The browser
	// reads only steps_count here; the paginated /api/steps and
	// /api/event-history endpoints supply the actual rows.
	// step_timeout is injected by marshalStateForWire (Task 20147) so it is
	// present consistently on both the HTTP /api/state response and every
	// WebSocket full-state broadcast.
	raw, err := marshalStateForWire(ps)
	if err != nil {
		jsonErr(w, "encode failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(raw)
}

// handleSteps returns a paginated slice of step history, latest first.
//
// GET /api/steps?offset=0&limit=50 → {steps: [...], total: N, offset: O, limit: L}
//
// Used by the Web UI step-history panel for lazy loading. Without pagination,
// projects with thousands of steps make /api/state payloads multi-megabyte and
// freeze the renderer. Steps are returned in reverse-chronological order
// (latest first) to match the panel's display order.
func (s *Server) handleSteps(w http.ResponseWriter, r *http.Request) {
	const (
		defaultLimit = 50
		maxLimit     = 500
	)
	ps, err := state.Load(s.resolveWorkDir(r))
	if err != nil {
		jsonErr(w, "no cloop project found", http.StatusNotFound)
		return
	}
	q := r.URL.Query()
	offset := 0
	if v := q.Get("offset"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			offset = n
		}
	}
	limit := defaultLimit
	if v := q.Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	if limit > maxLimit {
		limit = maxLimit
	}
	total := len(ps.Steps)
	// Latest first: serve from the tail of ps.Steps backwards.
	end := total - offset
	if end < 0 {
		end = 0
	}
	start := end - limit
	if start < 0 {
		start = 0
	}
	out := make([]state.StepResult, 0, end-start)
	for i := end - 1; i >= start; i-- {
		out = append(out, ps.Steps[i])
	}
	jsonOK(w, map[string]interface{}{
		"steps":  out,
		"total":  total,
		"offset": offset,
		"limit":  limit,
	})
}

// handleEventHistory returns the unified event journal (Task 20118) merged
// with the steps table, latest-first, with pagination. Each entry has:
//
//	id          unique within the merged feed (positive = step, negative = event)
//	kind        "step" | event_type ("task_started", "evolve_discovered", ...)
//	timestamp   ISO-8601
//	task_id     0 when not task-bound
//	task_title  may be empty
//	step        step number when kind="step"; -1 otherwise
//	message     short, human-readable summary
//	output      step output (kind="step" only)
//	exit_code   step exit code (kind="step" only)
//	duration    step duration (kind="step" only)
//	details     JSON blob (event-only; may be empty)
//
// GET /api/event-history?offset=0&limit=50 → {entries:[...], total:N, offset:O, limit:L}
func (s *Server) handleEventHistory(w http.ResponseWriter, r *http.Request) {
	const (
		defaultLimit = 50
		maxLimit     = 500
	)
	workDir := s.resolveWorkDir(r)
	ps, err := state.Load(workDir)
	if err != nil {
		jsonErr(w, "no cloop project found", http.StatusNotFound)
		return
	}
	q := r.URL.Query()
	offset := 0
	if v := q.Get("offset"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			offset = n
		}
	}
	limit := defaultLimit
	if v := q.Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	if limit > maxLimit {
		limit = maxLimit
	}

	type entry struct {
		ID        int64     `json:"id"`
		Kind      string    `json:"kind"`
		Timestamp time.Time `json:"timestamp"`
		TaskID    int       `json:"task_id,omitempty"`
		TaskTitle string    `json:"task_title,omitempty"`
		// Step has no omitempty: step 0 is a real step number and events
		// set Step=-1 explicitly when not step-bound — both must round-trip.
		Step int `json:"step"`
		// ExitCode has no omitempty: 0 is the success case for steps; the
		// renderer keys off Kind=="step" to know whether ExitCode is meaningful.
		ExitCode int         `json:"exit_code"`
		Message  string      `json:"message,omitempty"`
		Output   string      `json:"output,omitempty"`
		Duration string      `json:"duration,omitempty"`
		Details  interface{} `json:"details,omitempty"`
	}

	// Build the full merged sequence in memory, then page it. The two streams
	// are typically dwarfed by step count, so we walk both, sort by time desc,
	// and slice. This keeps the SQLite queries simple and is fast enough for
	// the projects we expect — under ~20k combined rows.
	merged := make([]entry, 0, len(ps.Steps)+8)
	for _, st := range ps.Steps {
		merged = append(merged, entry{
			// Step IDs are step+1 to keep them positive and stable across runs.
			ID:        int64(st.Step) + 1,
			Kind:      "step",
			Timestamp: st.Time,
			Step:      st.Step,
			Message:   st.Task,
			Output:    st.Output,
			ExitCode:  st.ExitCode,
			Duration:  st.Duration,
		})
	}
	// Pull the entire events page; we already cap merged size by paging below.
	// Pull at most a safe upper bound so we don't read a runaway row count.
	const maxEventsRead = 5000
	rows, _, evErr := state.ListEvents(workDir, 0, maxEventsRead)
	if evErr == nil {
		for _, ev := range rows {
			var det interface{}
			if ev.Details != "" {
				_ = json.Unmarshal([]byte(ev.Details), &det)
			}
			merged = append(merged, entry{
				// Event IDs are negated so they cannot collide with step IDs.
				ID:        -ev.ID,
				Kind:      string(ev.Type),
				Timestamp: ev.Timestamp,
				TaskID:    ev.TaskID,
				TaskTitle: ev.TaskTitle,
				Step:      ev.Step,
				Message:   ev.Message,
				Details:   det,
			})
		}
	}

	// Sort latest-first. Stable so that events with identical timestamps keep
	// their relative insertion order (events table is monotonically inserted).
	sort.SliceStable(merged, func(i, j int) bool {
		return merged[i].Timestamp.After(merged[j].Timestamp)
	})

	total := len(merged)
	start := offset
	if start > total {
		start = total
	}
	end := start + limit
	if end > total {
		end = total
	}

	jsonOK(w, map[string]interface{}{
		"entries": merged[start:end],
		"total":   total,
		"offset":  offset,
		"limit":   limit,
	})
}

// handleGetTasks returns tasks filtered by query params: q, status (csv), tags (csv), assignee, priority (1-4).
// GET /api/tasks?q=text&status=pending,in_progress&tags=backend&assignee=alice&priority=1
func (s *Server) handleGetTasks(w http.ResponseWriter, r *http.Request) {
	ps, err := state.Load(s.resolveWorkDir(r))
	if err != nil || ps.Plan == nil {
		jsonOK(w, map[string]interface{}{"tasks": []*pm.Task{}, "total": 0})
		return
	}

	q := strings.ToLower(boundedQueryString(r.URL.Query().Get("q"), maxQueryStringLen))
	assignee := boundedQueryString(r.URL.Query().Get("assignee"), maxQueryStringLen)
	priority := parsePriorityFilter(r.URL.Query().Get("priority"))

	statusSet := map[string]bool{}
	for _, sv := range parseCSVList(r.URL.Query().Get("status"), maxCSVItems, maxCSVItemLen) {
		statusSet[sv] = true
	}
	tagSet := map[string]bool{}
	for _, tv := range parseCSVList(r.URL.Query().Get("tags"), maxCSVItems, maxCSVItemLen) {
		tagSet[tv] = true
	}

	out := make([]*pm.Task, 0, len(ps.Plan.Tasks))
	for _, t := range ps.Plan.Tasks {
		if q != "" {
			if !strings.Contains(strings.ToLower(t.Title), q) && !strings.Contains(strings.ToLower(t.Description), q) {
				continue
			}
		}
		if len(statusSet) > 0 {
			st := string(t.Status)
			if st == "" {
				st = "pending"
			}
			if !statusSet[st] {
				continue
			}
		}
		if len(tagSet) > 0 {
			found := false
			for _, tag := range t.Tags {
				if tagSet[tag] {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}
		if assignee != "" && t.Assignee != assignee {
			continue
		}
		if priority > 0 && t.Priority != priority {
			continue
		}
		out = append(out, t)
	}

	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	jsonOK(w, map[string]interface{}{"tasks": out, "total": len(ps.Plan.Tasks)})
}

// handleEvents is an SSE endpoint that streams state updates to the browser.
func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "SSE not supported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	c := &sseClient{
		ch:      make(chan sseEvent, sseClientBufferSize),
		resync:  make(chan struct{}, 1),
		user:    s.sessionIdentity(r),
		token:   tokenFromRequest(r),
		workDir: s.resolveWorkDir(r),
	}
	s.mu.Lock()
	s.clients[c] = struct{}{}
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.clients, c)
		s.mu.Unlock()
	}()

	// Send current state immediately on connect. Lite-load: the SSE frame
	// passes through marshalStateForWire which drops Steps anyway, so
	// reading the per-step rows here is wasted work (Task 20125).
	if ps, err := state.LoadLite(s.WorkDir); err == nil {
		if data, err := marshalStateForWire(ps); err == nil {
			if werr := writeSSE(w, flusher, "data: %s\n\n", data); werr != nil {
				return
			}
		}
	}

	// Replay this stream's own project, never "the" buffer: c.workDir was
	// resolved at connect time above, and a client that subscribed to a
	// project with no output must get an empty replay rather than whatever
	// ran most recently (Task 20189).
	if lines := s.liveLogReplay(c.workDir); len(lines) > 0 {
		if d, err := json.Marshal(map[string]string{"chunk": strings.Join(lines, "")}); err == nil {
			if werr := writeSSE(w, flusher, "event: log\ndata: %s\n\n", d); werr != nil {
				return
			}
		}
	}

	ctx := r.Context()
	keepalive := time.NewTicker(sseKeepaliveInterval)
	defer keepalive.Stop()
	for {
		// Resync takes priority — drain stale events and emit a single
		// "resync" SSE directive so the client knows to refetch /api/state.
		select {
		case <-c.resync:
			drainSSE(c.ch)
			if werr := writeSSE(w, flusher, "event: resync\ndata: {\"reason\":\"lagged\"}\n\n"); werr != nil {
				return
			}
			continue
		default:
		}
		select {
		case <-ctx.Done():
			return
		case <-c.resync:
			drainSSE(c.ch)
			if werr := writeSSE(w, flusher, "event: resync\ndata: {\"reason\":\"lagged\"}\n\n"); werr != nil {
				return
			}
		case <-keepalive.C:
			// SSE comment frame — ignored by EventSource clients but
			// forces a TCP write so a dead peer is detected within
			// sseKeepaliveInterval+sseWriteTimeout (instead of the
			// multi-hour kernel TCP keepalive).
			if werr := writeSSE(w, flusher, ": keepalive\n\n"); werr != nil {
				return
			}
		case ev := <-c.ch:
			var werr error
			if ev.Event != "" {
				werr = writeSSE(w, flusher, "event: %s\ndata: %s\n\n", ev.Event, ev.Data)
			} else {
				werr = writeSSE(w, flusher, "data: %s\n\n", ev.Data)
			}
			if werr != nil {
				return
			}
		}
	}
}

// drainSSE empties any buffered sseEvents from ch without blocking. Used
// when emitting a resync directive: stale events are superseded.
func drainSSE(ch chan sseEvent) {
	for {
		select {
		case <-ch:
		default:
			return
		}
	}
}

// effectiveMaxWebSocketConns returns the active total cap, substituting
// config.WebSocketConnsDefault when Server.MaxWebSocketConns is unset.
func (s *Server) effectiveMaxWebSocketConns() int {
	if s.MaxWebSocketConns <= 0 {
		return config.WebSocketConnsDefault
	}
	return s.MaxWebSocketConns
}

// effectiveMaxWebSocketConnsPerIP returns the active per-IP cap.
func (s *Server) effectiveMaxWebSocketConnsPerIP() int {
	if s.MaxWebSocketConnsPerIP <= 0 {
		return config.WebSocketConnsPerIPDefault
	}
	return s.MaxWebSocketConnsPerIP
}

// admitWebSocket atomically reserves a WebSocket connection slot for ip.
// On success returns (true, "") — the caller MUST call releaseWebSocket(ip)
// once the connection is closed (use defer). On rejection returns (false,
// reason) and the caller should respond with HTTP 429 + Retry-After before
// calling websocket.Accept (rejecting after Accept would leave the client
// thinking the upgrade succeeded).
//
// The reservation is fully transactional: if either cap would be breached,
// neither counter is incremented.
func (s *Server) admitWebSocket(ip string) (bool, string) {
	totalCap := s.effectiveMaxWebSocketConns()
	perIPCap := s.effectiveMaxWebSocketConnsPerIP()
	s.wsConnMu.Lock()
	defer s.wsConnMu.Unlock()
	if s.wsConnTotal >= totalCap {
		return false, "total websocket connection limit reached"
	}
	if ip != "" && s.wsConnPerIP[ip] >= perIPCap {
		return false, "per-IP websocket connection limit reached"
	}
	s.wsConnTotal++
	if ip != "" {
		s.wsConnPerIP[ip]++
	}
	return true, ""
}

// releaseWebSocket reverses a prior admitWebSocket(ip). Must be called
// exactly once per successful admit. Removes the per-IP map entry when
// its counter reaches zero so the map size is bounded by the number of
// currently-connected IPs rather than the lifetime distinct-IP set.
func (s *Server) releaseWebSocket(ip string) {
	s.wsConnMu.Lock()
	defer s.wsConnMu.Unlock()
	if s.wsConnTotal > 0 {
		s.wsConnTotal--
	}
	if ip == "" {
		return
	}
	if n, ok := s.wsConnPerIP[ip]; ok {
		if n <= 1 {
			delete(s.wsConnPerIP, ip)
		} else {
			s.wsConnPerIP[ip] = n - 1
		}
	}
}

// wsRetryAfterSeconds is the Retry-After hint returned alongside an HTTP 429
// when the WebSocket admission caps are breached. Five seconds is short
// enough that a closing peer's slot becomes available within typical reload
// latency, but long enough to discourage tight reconnect loops from a
// misconfigured client. Declared as var so tests may shrink it.
var wsRetryAfterSeconds = 5

// handleWS upgrades the connection to a WebSocket and streams typed JSON
// messages to the client. It also manages per-project presence tracking.
// Clients that cannot upgrade (e.g., proxies that strip the Upgrade header)
// should fall back to the /api/events SSE endpoint.
//
// Connection caps (Task 20090): the upgrade is rejected with HTTP 429 and a
// Retry-After header when either MaxWebSocketConns (total) or
// MaxWebSocketConnsPerIP would be exceeded. Defaults: 256 total, 8 per IP.
// Configure via Config.UI.MaxWebSocketConns / MaxWebSocketConnsPerIP.
// wsOriginAllowed reports whether the WebSocket upgrade request may be
// accepted based on its Origin header. It allows:
//   - requests with no Origin header (non-browser clients: CLI, tests);
//   - loopback origins (localhost / 127.0.0.1 / ::1, any port);
//   - same-origin requests, where the Origin host matches the request Host
//     (the page and the socket are served by the same server — safe even
//     behind a reverse proxy on a public hostname);
//   - the host of s.ExternalURL, i.e. what this deployment calls itself;
//   - any host listed in s.AllowedWSOrigins (for proxies that rewrite Host).
//
// A malformed or genuinely cross-origin browser Origin is rejected, which
// blocks cross-site WebSocket hijacking. The executor-agent endpoint applies
// the same policy through remote.Hub.checkOrigin, fed from the same two
// config values — see pkg/executor/remote/origin.go.
func (s *Server) wsOriginAllowed(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true // non-browser client; no CSWSH risk
	}
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return false
	}
	originHost := u.Hostname()

	// Loopback is always allowed (local dashboard use). Shared with the
	// executor-agent endpoint via tlsconf so one server cannot give two
	// different answers to "is this origin loopback".
	if tlsconf.IsLoopbackHost(originHost) {
		return true
	}

	// Same-origin: Origin host[:port] matches the Host the server sees.
	// Compare both the full host:port and the bare hostname so a proxy that
	// forwards the original Host (with or without an explicit port) matches.
	if r.Host != "" {
		if strings.EqualFold(u.Host, r.Host) {
			return true
		}
		reqHost := r.Host
		if h, _, err := net.SplitHostPort(reqHost); err == nil {
			reqHost = h
		}
		if strings.EqualFold(originHost, reqHost) {
			return true
		}
	}

	// The deployment's own external URL, which is the common case behind a
	// proxy that rewrites Host: the operator has already told us what this
	// server is called, so requiring them to repeat it in allowed_origins
	// would be a second chance to get it wrong.
	if ext := strings.TrimSpace(s.ExternalURL); ext != "" {
		if u2, err := url.Parse(ext); err == nil && u2.Host != "" {
			if strings.EqualFold(u2.Host, u.Host) || strings.EqualFold(u2.Hostname(), originHost) {
				return true
			}
		}
	}

	// Operator-configured extra origins (host or host:port). The dashboard
	// honours both lists; the agent endpoint honours only AllowedOrigins.
	for _, allowed := range append(append([]string(nil), s.AllowedWSOrigins...), s.AllowedOrigins...) {
		if strings.TrimSpace(allowed) == "" {
			continue
		}
		if strings.EqualFold(allowed, u.Host) || strings.EqualFold(allowed, originHost) {
			return true
		}
	}
	return false
}

func (s *Server) handleWS(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if ok, reason := s.admitWebSocket(ip); !ok {
		w.Header().Set("Retry-After", strconv.Itoa(wsRetryAfterSeconds))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": reason})
		return
	}
	// Reverse the admission once the handler exits, regardless of which
	// path tears the connection down. Wrapped in a closure so the func
	// captures the same ip used for admission even if r mutates.
	defer s.releaseWebSocket(ip)

	// Origin enforcement: we do our own check (InsecureSkipVerify tells the
	// websocket lib to skip its OriginPatterns matching) so we can accept
	// same-origin requests behind a reverse proxy on any hostname, not just
	// loopback. wsOriginAllowed permits: no Origin header (CLI/tests),
	// loopback origins, the request's own Host (same-origin — the page and
	// the socket come from the same server, which is inherently safe), and
	// any operator-configured AllowedWSOrigins. Cross-origin browser
	// requests are still rejected, preventing cross-site WebSocket hijacking.
	if !s.wsOriginAllowed(r) {
		http.Error(w, "forbidden origin", http.StatusForbidden)
		return
	}
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		InsecureSkipVerify: true, // origin already validated by wsOriginAllowed
	})
	if err != nil {
		return
	}
	defer conn.CloseNow() //nolint:errcheck

	// Use a cancellable derivative of the request context so the drain
	// goroutine can wake the writer loop on read error or rate-limit
	// violation. Without this, conn.Close() inside the drain only tears
	// down the underlying TCP conn — the writer loop stays blocked on
	// select{} until something tries to write or the request itself ends,
	// leaving the hubClient registered for an extra watcher tick or two.
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	workDir := s.resolveWorkDir(r)
	user := s.sessionIdentity(r)

	// Assign a unique id, color-coded name and accent color to this connection.
	connID := fmt.Sprintf("%x", time.Now().UnixNano())
	s.hubMu.Lock()
	totalClients := 0
	for _, cl := range s.hubClients {
		totalClients += len(cl)
	}
	name := presenceNames[totalClients%len(presenceNames)]
	color := presenceColors[totalClients%len(presenceColors)]
	// With OIDC enabled, present the real signed-in user instead of a random
	// animal name so collaborators see who is actually connected.
	if user != nil {
		// Truncate, don't drop (Task 20188): boundedQueryString returns ""
		// for oversized input, which is right for a filter but here would
		// discard the fallback assigned just above and broadcast a blank
		// label to every peer.
		if dn := boundedDisplayName(user.DisplayName(), maxPresenceFieldLen); dn != "" {
			name = dn
		}
	}
	// Override with user-supplied name/color from query params if provided.
	// Both fields are echoed to every other connected client via the presence
	// broadcast, so they're capped at maxPresenceFieldLen to prevent a single
	// connector from amplifying a multi-megabyte payload across the hub.
	if qn := boundedQueryString(r.URL.Query().Get("name"), maxPresenceFieldLen); qn != "" {
		name = qn
	}
	if qc := boundedQueryString(r.URL.Query().Get("color"), maxPresenceFieldLen); qc != "" {
		color = qc
	}
	hc := &hubClient{
		ch:     make(chan wsMessage, hubClientBufferSize),
		resync: make(chan struct{}, 1),
		id:     connID,
		name:   name,
		color:  color,
		conn:   conn,
		user:   user,
		token:  tokenFromRequest(r),
	}
	if s.hubClients[workDir] == nil {
		s.hubClients[workDir] = make(map[*hubClient]struct{})
	}
	s.hubClients[workDir][hc] = struct{}{}
	s.hubMu.Unlock()

	defer func() {
		s.hubMu.Lock()
		delete(s.hubClients[workDir], hc)
		if len(s.hubClients[workDir]) == 0 {
			delete(s.hubClients, workDir)
		}
		s.hubMu.Unlock()
		// Broadcast updated presence list after disconnection.
		s.broadcastPresence(workDir)
	}()

	// Send current state immediately. Same lite-load reasoning as the SSE
	// initial-state path: the frame is marshalStateForWire'd, so Steps are
	// dropped before going on the wire (Task 20125).
	if ps, err := state.LoadLite(workDir); err == nil {
		if raw, err := marshalStateForWire(ps); err == nil {
			if msg, err := json.Marshal(wsMessage{Type: "task_update", Data: raw}); err == nil {
				_ = wsWrite(ctx, conn, msg)
			}
		}
	}

	// Replay the connecting client's own project. workDir was resolved at
	// the top of handleWS and is the same key this client's hub room uses,
	// so a tab opening on project B never receives project A's backlog
	// (Task 20189).
	if lines := s.liveLogReplay(workDir); len(lines) > 0 {
		if d, err := json.Marshal(map[string]string{"chunk": strings.Join(lines, "")}); err == nil {
			if msg, err := json.Marshal(wsMessage{Type: "step_output", Data: d}); err == nil {
				_ = wsWrite(ctx, conn, msg)
			}
		}
	}

	// Send initial run state so the client can position the Run/Stop buttons
	// without polling /api/livelog.
	{
		running := s.liveLogRunningFor(workDir) || multiui.IsCloopRunningInDir(workDir)
		if raw, err := json.Marshal(map[string]interface{}{"running": running}); err == nil {
			if msg, err := json.Marshal(wsMessage{Type: "run_state", Data: raw}); err == nil {
				_ = wsWrite(ctx, conn, msg)
			}
		}
		// Seed the cache so subsequent watcher ticks don't re-broadcast the
		// same value to all peers when this client connects.
		s.runStateMu.Lock()
		s.runStates[workDir] = running
		s.runStateMu.Unlock()
	}

	// Send initial suggest status if a job for this project is in flight or
	// has results to display, so the suggestions panel can hydrate without
	// polling /api/suggest/status.
	{
		s.suggestMu.Lock()
		matches := s.suggestWorkDir == workDir && (s.suggestRunning || s.suggestDone)
		payload := map[string]interface{}{
			"running":     s.suggestRunning,
			"done":        s.suggestDone,
			"error":       s.suggestErr,
			"summary":     s.suggestSummary,
			"suggestions": append([]*suggest.Suggestion(nil), s.suggestSuggestions...),
		}
		s.suggestMu.Unlock()
		if matches {
			if raw, err := json.Marshal(payload); err == nil {
				if msg, err := json.Marshal(wsMessage{Type: "suggest_status", Data: raw}); err == nil {
					_ = wsWrite(ctx, conn, msg)
				}
			}
		}
	}

	// Send initial presence list to this client, then announce to everyone.
	if users := s.presenceUsers(workDir); len(users) > 0 {
		if raw, err := json.Marshal(map[string]interface{}{"users": users, "you": connID}); err == nil {
			if msg, err := json.Marshal(wsMessage{Type: "presence", Data: raw}); err == nil {
				_ = wsWrite(ctx, conn, msg)
			}
		}
	}
	// Broadcast to others that a new user joined. Wrapped so a panic in the
	// broadcast path (e.g. a downstream sendOrLag race) cannot tear down the
	// whole UI process — every UI-spawned goroutine must terminate cleanly
	// since they share the parent process with cloop run.
	go func() {
		defer recoverGoroutine("handleWS presence join")
		s.broadcastPresence(workDir)
	}()

	// Drain incoming frames (bidirectional hook for future use). Two
	// defensive bounds protect this goroutine from abuse:
	//   - SetReadLimit(wsReadFrameLimit) caps any single frame, so an
	//     oversized payload can't allocate unbounded memory before being
	//     rejected (nhooyr closes with StatusMessageTooBig on overshoot).
	//   - A 1-second sliding-window message counter caps the *rate* of
	//     inbound frames; a client spamming many tiny frames would otherwise
	//     keep this goroutine hot forever (each Read returns immediately,
	//     the loop never yields). Exceeding the cap closes with
	//     StatusPolicyViolation so the goroutine exits cleanly.
	go func() {
		defer recoverGoroutine("handleWS drain")
		// Cancel the parent ctx on any exit path so the writer loop
		// (blocked on select{}) wakes promptly and the deferred
		// hubClient cleanup runs without waiting for the next watcher
		// tick or write attempt.
		defer cancel()
		conn.SetReadLimit(wsReadFrameLimit)
		var (
			windowStart = time.Now()
			windowCount int
		)
		for {
			_, _, err := conn.Read(ctx)
			if err != nil {
				return
			}
			now := time.Now()
			if now.Sub(windowStart) >= time.Second {
				windowStart = now
				windowCount = 1
				continue
			}
			windowCount++
			if windowCount > wsMaxInboundMsgsPerSecond {
				// Send a polite close frame with a rationale, but
				// don't block this goroutine waiting for the peer's
				// ack — nhooyr.Close holds for up to ~10s for the
				// handshake. The deferred conn.CloseNow in handleWS
				// is the unconditional fallback once the writer loop
				// exits via the cancel() above.
				go func() {
					_ = conn.Close(websocket.StatusPolicyViolation, "inbound rate exceeded")
				}()
				return
			}
		}
	}()

	// Pre-marshal the resync directive once.
	resyncBytes, _ := json.Marshal(wsMessage{
		Type: "resync",
		Data: json.RawMessage(`{"reason":"lagged"}`),
	})

	// Server-initiated keepalive ping. Detects dead/unresponsive peers
	// faster than the OS-level TCP keepalive (~2h on Linux). nhooyr's
	// pong dispatch happens via the active drain Read, so it is safe to
	// call Ping here concurrently.
	pingTicker := time.NewTicker(wsPingInterval)
	defer pingTicker.Stop()

	for {
		// Resync takes priority: if the broadcaster signaled lag, drain any
		// stale events and emit a single resync directive. The client will
		// re-fetch /api/state to recover; subsequent events flow normally.
		select {
		case <-hc.resync:
			drainWS(hc.ch)
			if err := wsWrite(ctx, conn, resyncBytes); err != nil {
				return
			}
			continue
		default:
		}
		select {
		case <-ctx.Done():
			// Don't call conn.Close here — it blocks for up to ~10s
			// waiting for the peer's close-frame ack, which delays
			// the deferred hubClient cleanup. The deferred
			// conn.CloseNow in handleWS handles teardown without
			// the handshake. (Polite normal-closure semantics matter
			// less here because ctx is only cancelled when the
			// handler is shutting down or the drain detected abuse,
			// in which case the drain has already kicked off the
			// status-coded close frame asynchronously.)
			return
		case <-pingTicker.C:
			pctx, pcancel := context.WithTimeout(ctx, wsPingTimeout)
			err := conn.Ping(pctx)
			pcancel()
			if err != nil {
				// Dead/unresponsive peer (no pong inside the
				// timeout, or the peer's TCP path broke). Exit
				// the writer; deferred CloseNow + hubClient
				// cleanup unwind the rest.
				return
			}
		case <-hc.resync:
			drainWS(hc.ch)
			if err := wsWrite(ctx, conn, resyncBytes); err != nil {
				return
			}
		case msg := <-hc.ch:
			data, err := json.Marshal(msg)
			if err != nil {
				continue
			}
			if err := wsWrite(ctx, conn, data); err != nil {
				return
			}
		}
	}
}

// drainWS empties any buffered wsMessages from ch without blocking. Used
// when emitting a resync directive: stale events are superseded.
func drainWS(ch chan wsMessage) {
	for {
		select {
		case <-ch:
		default:
			return
		}
	}
}

// handleRun starts `cloop run`. All run options (PM mode, auto-evolve, innovate,
// plan-only, retry-failed, dry-run, parallel, etc.) are persisted in project
// state and toggled via the Active Options badges in the UI; the request body
// is intentionally empty. Provider/model also come from persisted state via
// the Provider stat-card picker.
func (s *Server) handleRun(w http.ResponseWriter, r *http.Request) {
	if !requirePOST(w, r) {
		return
	}
	// Body is ignored; all knobs come from persisted state. We still tolerate a
	// JSON body so older clients don't error.
	_, _ = io.Copy(io.Discard, r.Body)

	// Admission (Task 20182), before anything is dispatched. Starting a run
	// is the action that actually spends the fleet: it holds an executor
	// slot for as long as it runs and bills tokens the whole time. Two gates
	// apply — a concurrency slot the tenant may not have, and a daily budget
	// it may already have spent — and each returns a typed QUOTA_EXCEEDED
	// with a Retry-After, because both clear on their own.
	quotaID := s.quotaIdentity(r)
	if !s.admitSpend(w, r) {
		return
	}
	if !s.admitQuota(w, r, quota.ResConcurrentTasks, 1) {
		return
	}
	// Every path from here must give the slot back exactly once, or a run
	// that never started narrows the tenant until the next reconciliation.
	slotHeld := true
	releaseSlot := func() {
		if slotHeld {
			slotHeld = false
			s.releaseQuota(quotaID, quota.ResConcurrentTasks, 1)
		}
	}

	args := []string{"run"}

	exe, err := os.Executable()
	if err != nil {
		exe = "cloop"
	}
	workDir := s.resolveWorkDir(r)

	// The harness is never forked here. It is handed to whichever executor
	// this project is bound to — the local host by default, a container or
	// a remote edge agent when configured (Task 20156).
	ex, handle, err := startWorkload(workDir, append([]string{exe}, args...), map[string]string{"handler": "run"})
	if err != nil {
		// 409 when strict no-host-execution mode refused the dispatch, so
		// the browser can show the remediation instead of a generic 500
		// (Task 20160).
		releaseSlot()
		jsonWorkloadErr(w, err)
		return
	}

	// Clear this project's old log and mark it running.
	s.liveLogStartRun(workDir)
	s.broadcastRunState(workDir, true, true)

	lines, streamErr := ex.Stream(context.Background(), handle.ID)
	if streamErr != nil {
		// We can no longer observe the run, so we cannot tell when it ends.
		// Clear the running flag rather than leaving the UI wedged showing a
		// run in progress forever.
		fmt.Fprintf(os.Stderr, "ui: cannot stream run output: %v\n", streamErr)
		s.liveLogSetRunning(workDir, false)
		s.broadcastRunState(workDir, false, true)
		// The run is live but unobservable, so nothing will ever tell us it
		// ended. Release the slot now rather than hold one forever: the cap
		// exists to stop a tenant starving the fleet, and a counter that can
		// only go up would do that on its own.
		releaseSlot()
		jsonOK(w, map[string]interface{}{"ok": true, "command": "cloop " + strings.Join(args, " ")})
		return
	}

	go func() {
		// Unconditional, and before the recover: the concurrency slot must
		// come back whether the watcher exits cleanly or panics. A deferred
		// release inside the recover branch would leak the slot on the
		// normal path, and one after it would be skipped on the panic path.
		defer releaseSlot()
		defer func() {
			if rec := recover(); rec != nil {
				fmt.Fprintf(os.Stderr, "ui: run output goroutine panic recovered: %v\n", rec)
				// Best-effort cleanup so the UI doesn't think a run is still in progress.
				s.liveLogSetRunning(workDir, false)
			}
		}()
		// The driver closes the channel only after the workload has been
		// reaped, so falling out of this loop means the run is over.
		for line := range lines {
			if line.Text == "" {
				continue
			}
			os.Stderr.WriteString(line.Text) // also echo to server's stderr
			s.broadcastLog(workDir, line.Text)
		}
		s.liveLogSetRunning(workDir, false)
		s.broadcastRunState(workDir, false, true)
		// Broadcast updated state after run completes. Lite-load —
		// marshalStateForWire drops Steps before broadcast (Task 20125).
		// SSE consumers get the full state; WS clients get a state_diff
		// against the cached snapshot (Task 20132).
		if ps, loadErr := state.LoadLite(workDir); loadErr == nil {
			if data, marshalErr := marshalStateForWire(ps); marshalErr == nil {
				s.broadcast(workDir, string(data))
			}
			s.broadcastStateDiff(workDir, ps)
		}
	}()

	jsonOK(w, map[string]interface{}{"ok": true, "command": "cloop " + strings.Join(args, " ")})
}

// handleStop sends SIGINT to the "cloop run" processes of the requested
// project (?project_idx=N, falling back to the server's WorkDir). It is
// project-scoped via a /proc cwd walk — the pre-fix handler signalled
// *every* cloop run on the host, so pressing Stop on one project's page
// terminated unrelated projects' runs (Task 20153).
//
// When no live process exists but persisted state still says the project is
// running (the run was SIGKILLed, OOM-killed, or the host rebooted before
// the orchestrator could write a terminal status), the handler reconciles
// the stale status instead of erroring. Pre-fix this was a UX deadlock: the
// Run/Stop button renders from persisted status, so the UI showed Stop
// forever while /api/stop kept answering "no running cloop process found".
func (s *Server) handleStop(w http.ResponseWriter, r *http.Request) {
	if !requirePOST(w, r) {
		return
	}
	workDir := s.resolveWorkDir(r)
	pids := multiui.CloopRunPIDsInDir(workDir)
	if len(pids) == 0 {
		if s.reconcileStaleRunState(workDir) {
			jsonOK(w, map[string]interface{}{"ok": true, "message": "no running process found — cleared stale running status"})
			return
		}
		jsonOK(w, map[string]interface{}{"ok": false, "message": "no running cloop process found"})
		return
	}
	signalled := signalPIDs(pids, syscall.SIGINT)
	if signalled == 0 {
		jsonOK(w, map[string]interface{}{"ok": false, "message": "found cloop processes but signalling failed (permission denied?)"})
		return
	}
	s.observeRunExit(workDir)
	jsonOK(w, map[string]interface{}{"ok": true, "message": "pause signal sent", "signalled": signalled})
}

// reconcileStaleRunState clears a persisted "running"/"evolving" project
// status that no longer has a live cloop run process behind it. Returns true
// when stale state was found and cleared. The status is set to "paused" —
// the same terminal the orchestrator writes on a graceful SIGINT — so
// health, status filters, and the Run/Stop button all recover. Broadcasts
// the corrected run_state and a state diff so open dashboards flip from
// Stop to Run without a reload.
func (s *Server) reconcileStaleRunState(workDir string) bool {
	ps, err := state.Load(workDir)
	if err != nil || ps == nil {
		return false
	}
	if ps.Status != "running" && ps.Status != "evolving" {
		return false
	}
	ps.Status = "paused"
	if err := ps.SaveDirect(); err != nil {
		fmt.Fprintf(os.Stderr, "ui: reconcile stale run state for %s: %v\n", workDir, err)
		return false
	}
	s.broadcastRunState(workDir, false, true)
	s.broadcastStateDiff(workDir, ps)
	s.refreshProjectStatuses()
	s.broadcastProjectsUpdate()
	return true
}

// observeRunExit watches for the signalled run to actually exit and then
// pushes refreshed run_state + project events, so the UI reflects the stop
// without client-side polling. Bounded to ~5s so the goroutine never leaks
// when a run ignores SIGINT (it finishes its in-flight step first — the
// watcher's periodic tick eventually reports the exit instead).
func (s *Server) observeRunExit(workDir string) {
	go func() {
		defer recoverGoroutine("handleStop observer")
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			if !multiui.IsCloopRunningInDir(workDir) {
				break
			}
			time.Sleep(150 * time.Millisecond)
		}
		s.broadcastRunState(workDir, multiui.IsCloopRunningInDir(workDir), true)
		s.refreshProjectStatuses()
		s.broadcastProjectsUpdate()
	}()
}

// signalPIDs sends sig to each pid via os.FindProcess+Signal and returns the
// number of successful deliveries. Errors (already-exited / EPERM) are
// swallowed individually because the caller only needs to know whether
// *any* process received the signal.
func signalPIDs(pids []int, sig syscall.Signal) int {
	n := 0
	for _, pid := range pids {
		proc, err := os.FindProcess(pid)
		if err != nil {
			continue
		}
		if err := proc.Signal(sig); err == nil {
			n++
		}
	}
	return n
}

// handleConfig returns the current configuration with secrets masked.
func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET required", http.StatusMethodNotAllowed)
		return
	}
	cfg, err := config.Load(s.resolveWorkDir(r))
	if err != nil {
		jsonErr(w, "config load failed", http.StatusInternalServerError)
		return
	}
	type provInfo struct {
		HasKey  bool   `json:"has_key"`
		Model   string `json:"model"`
		BaseURL string `json:"base_url"`
	}
	jsonOK(w, map[string]interface{}{
		"provider": cfg.Provider,
		"anthropic": provInfo{
			HasKey:  cfg.Anthropic.APIKey != "",
			Model:   cfg.Anthropic.Model,
			BaseURL: cfg.Anthropic.BaseURL,
		},
		"openai": provInfo{
			HasKey:  cfg.OpenAI.APIKey != "",
			Model:   cfg.OpenAI.Model,
			BaseURL: cfg.OpenAI.BaseURL,
		},
		"ollama": map[string]string{
			"base_url": cfg.Ollama.BaseURL,
			"model":    cfg.Ollama.Model,
		},
		"claudecode": map[string]string{
			"model":  cfg.ClaudeCode.Model,
			"effort": cfg.ClaudeCode.Effort,
		},
	})
}

// handleConfigSet sets a single configuration key.
func (s *Server) handleConfigSet(w http.ResponseWriter, r *http.Request) {
	if !requirePOST(w, r) {
		return
	}
	var req struct {
		Key   string `json:"key"`
		Value string `json:"value"`
	}
	limitJSONBody(w, r, maxJSONBodyBytes)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondToBodyError(w, err)
		return
	}
	workDir := s.resolveWorkDir(r)
	cfg, err := config.Load(workDir)
	if err != nil {
		jsonErr(w, "config load failed", http.StatusInternalServerError)
		return
	}
	if err := applyUIConfigKey(cfg, req.Key, req.Value); err != nil {
		jsonErr(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := config.Save(workDir, cfg); err != nil {
		jsonErr(w, "save failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	jsonOK(w, map[string]bool{"ok": true})
}

// applyUIConfigKey applies a key/value pair to a Config struct.
func applyUIConfigKey(cfg *config.Config, key, value string) error {
	switch strings.ToLower(key) {
	case "provider":
		valid := map[string]bool{"anthropic": true, "openai": true, "ollama": true, "claudecode": true}
		if !valid[value] {
			return fmt.Errorf("unknown provider %q — valid: anthropic, openai, ollama, claudecode", value)
		}
		cfg.Provider = value
	case "anthropic.api_key":
		cfg.Anthropic.APIKey = value
	case "anthropic.model":
		cfg.Anthropic.Model = value
	case "anthropic.base_url":
		cfg.Anthropic.BaseURL = value
	case "openai.api_key":
		cfg.OpenAI.APIKey = value
	case "openai.model":
		cfg.OpenAI.Model = value
	case "openai.base_url":
		cfg.OpenAI.BaseURL = value
	case "ollama.base_url":
		cfg.Ollama.BaseURL = value
	case "ollama.model":
		cfg.Ollama.Model = value
	case "claudecode.model":
		cfg.ClaudeCode.Model = value
	case "claudecode.effort":
		if !provider.ValidEffort(value) {
			return fmt.Errorf("invalid effort %q — valid: %s (or empty to clear)", value, strings.Join(provider.EffortLevels, ", "))
		}
		cfg.ClaudeCode.Effort = value
	default:
		return fmt.Errorf("unknown config key %q", key)
	}
	return nil
}

// handleTaskAdd adds a new task to the plan.
func (s *Server) handleTaskAdd(w http.ResponseWriter, r *http.Request) {
	if !requirePOST(w, r) {
		return
	}
	var req struct {
		Title       string `json:"title"`
		Description string `json:"description"`
		Priority    int    `json:"priority"`
		DependsOn   []int  `json:"depends_on"`
	}
	limitJSONBody(w, r, maxJSONBodyBytes)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondToBodyError(w, err)
		return
	}
	req.Title = strings.TrimSpace(req.Title)
	if req.Title == "" {
		jsonErr(w, "title is required", http.StatusBadRequest)
		return
	}

	// LoadLite skips reading per-step rows — we only need plan/tasks to compute
	// the next ID. SaveState upserts steps (never deletes), so writing back
	// with Steps == nil preserves existing rows. On a project with thousands
	// of steps this drops the handler's read cost from ~1.5 MiB to a few KiB,
	// which is the second-biggest contributor to add-task latency after the
	// frontend's redundant refetch.
	ps, err := state.LoadLite(s.resolveWorkDir(r))
	if err != nil {
		jsonErr(w, "no project found — run cloop init first", http.StatusNotFound)
		return
	}
	if ps.Plan == nil {
		ps.Plan = pm.NewPlan(ps.Goal)
		ps.PMMode = true
	}

	maxID, maxPri := 0, 0
	for _, t := range ps.Plan.Tasks {
		if t.ID > maxID {
			maxID = t.ID
		}
		if t.Priority > maxPri {
			maxPri = t.Priority
		}
	}
	priority := req.Priority
	if priority <= 0 {
		priority = maxPri + 1
	}

	// selfID is 0: the task does not exist yet, so it cannot be self-
	// referential, but its dependencies must still name tasks that exist.
	if err := validateDependsOn(req.DependsOn, 0, ps.Plan.Tasks); err != nil {
		jsonErr(w, err.Error(), http.StatusBadRequest)
		return
	}

	task := &pm.Task{
		ID:          maxID + 1,
		Title:       req.Title,
		Description: req.Description,
		Priority:    priority,
		DependsOn:   req.DependsOn,
		Status:      pm.TaskPending,
	}
	ps.Plan.Tasks = append(ps.Plan.Tasks, task)

	if err := ps.SaveDirect(); err != nil {
		jsonErr(w, "save failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Broadcast the new task to all WebSocket clients watching this project.
	// state_diff carries the new task (and any state changes) — task_added
	// remains as a hint event for toasts but no longer embeds the full state.
	addWorkDir := s.resolveWorkDir(r)
	s.broadcastStateDiff(addWorkDir, ps)
	addRaw, _ := json.Marshal(map[string]interface{}{
		"task": task,
	})
	s.broadcastToProject(addWorkDir, wsMessage{Type: "task_added", Data: addRaw})
	// Unified event journal (Task 20118).
	state.LogEvent(addWorkDir, state.EventRow{
		Type:      state.EventTaskAdded,
		TaskID:    task.ID,
		TaskTitle: task.Title,
		Step:      state.NoStep,
		Message:   fmt.Sprintf("Task #%d added via UI: %s", task.ID, task.Title),
	})

	jsonOK(w, map[string]interface{}{"ok": true, "task": task})
}

// decomposeSubtaskWire is the JSON shape of a proposed sub-task exchanged with
// the decompose modal. IDs and dependency wiring are assigned server-side at
// apply time, so the wire form carries only the AI-proposed fields.
type decomposeSubtaskWire struct {
	Title            string `json:"title"`
	Description      string `json:"description"`
	Role             string `json:"role,omitempty"`
	EstimatedMinutes int    `json:"estimated_minutes,omitempty"`
}

// decomposePreviewTimeout bounds the synchronous decompose preview call.
// Decompose makes up to two provider round-trips (expansion + semantic
// dedup), so this is deliberately generous; the client shows a spinner.
const decomposePreviewTimeout = 8 * time.Minute

// decomposeMaxSubtasks caps how many sub-tasks a single apply may inject.
// The AI proposes at most 7; the cap only guards against hand-crafted
// requests flooding the plan.
const decomposeMaxSubtasks = 20

// checkDecomposable rejects parents whose status makes decomposition
// destructive: running tasks would race the orchestrator, and done tasks
// would silently lose their completion (apply marks the parent skipped).
func checkDecomposable(t *pm.Task) error {
	switch t.Status {
	case pm.TaskInProgress:
		return fmt.Errorf("task %d is currently running — stop it before decomposing", t.ID)
	case pm.TaskDone:
		return fmt.Errorf("task %d is already done — decomposing would discard its completion", t.ID)
	}
	return nil
}

// buildProjectProvider builds the AI provider and model configured for the
// project at workDir, mirroring the CLI resolution order: config.yaml
// provider > state provider > claudecode default; per-provider config model
// > state model.
func buildProjectProvider(workDir string, ps *state.ProjectState) (provider.Provider, string, error) {
	cfg, err := config.Load(workDir)
	if err != nil {
		return nil, "", fmt.Errorf("loading config: %w", err)
	}
	pName := cfg.Provider
	if pName == "" && ps != nil {
		pName = ps.Provider
	}
	if pName == "" {
		pName = "claudecode"
	}
	prov, err := provider.Build(provider.ProviderConfig{
		Name:             pName,
		AnthropicAPIKey:  cfg.Anthropic.APIKey,
		AnthropicBaseURL: cfg.Anthropic.BaseURL,
		OpenAIAPIKey:     cfg.OpenAI.APIKey,
		OpenAIBaseURL:    cfg.OpenAI.BaseURL,
		OllamaBaseURL:    cfg.Ollama.BaseURL,
	})
	if err != nil {
		return nil, "", err
	}
	model := ""
	switch pName {
	case "anthropic":
		model = cfg.Anthropic.Model
	case "openai":
		model = cfg.OpenAI.Model
	case "ollama":
		model = cfg.Ollama.Model
	case "claudecode":
		model = cfg.ClaudeCode.Model
	}
	if model == "" && ps != nil {
		model = ps.Model
	}
	return prov, model, nil
}

// handleTaskDecompose asks the AI to break a task into 3-7 sub-tasks and
// returns the proposal WITHOUT mutating the plan
// (POST /api/tasks/{id}/decompose). The client reviews the proposal and
// applies a possibly filtered subset via /api/tasks/{id}/decompose/apply.
func (s *Server) handleTaskDecompose(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil || id <= 0 {
		jsonErr(w, "invalid task id", http.StatusBadRequest)
		return
	}
	workDir := s.resolveWorkDir(r)
	ps, err := state.Load(workDir)
	if err != nil {
		jsonErr(w, err.Error(), statedb.HTTPStatus(err))
		return
	}
	if ps.Plan == nil || len(ps.Plan.Tasks) == 0 {
		jsonErr(w, "no task plan found — run cloop init first", http.StatusNotFound)
		return
	}
	task, err := ps.RequireTask(id)
	if err != nil {
		jsonErr(w, err.Error(), statedb.HTTPStatus(err))
		return
	}
	if err := checkDecomposable(task); err != nil {
		jsonErr(w, err.Error(), http.StatusConflict)
		return
	}

	prov, model, err := buildProjectProvider(workDir, ps)
	if err != nil {
		jsonErr(w, "provider: "+err.Error(), http.StatusInternalServerError)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), decomposePreviewTimeout)
	defer cancel()
	opts := provider.Options{
		Model:   model,
		WorkDir: workDir,
		Timeout: 4 * time.Minute,
	}
	res, err := decompose.Decompose(ctx, prov, opts, ps.Plan, id)
	if err != nil {
		jsonErr(w, err.Error(), http.StatusBadGateway)
		return
	}

	subs := make([]decomposeSubtaskWire, 0, len(res.SubTasks))
	for _, st := range res.SubTasks {
		subs = append(subs, decomposeSubtaskWire{
			Title:            st.Title,
			Description:      st.Description,
			Role:             string(st.Role),
			EstimatedMinutes: st.EstimatedMinutes,
		})
	}
	jsonOK(w, map[string]interface{}{
		"ok":           true,
		"parent_id":    res.Parent.ID,
		"parent_title": res.Parent.Title,
		"subtasks":     subs,
	})
}

// handleTaskDecomposeApply injects reviewed sub-tasks into the plan
// (POST /api/tasks/{id}/decompose/apply). Semantics match
// `cloop task decompose`: the parent is marked skipped with an annotation,
// the first sub-task depends on the parent, and each subsequent sub-task
// depends on the previous one.
func (s *Server) handleTaskDecomposeApply(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil || id <= 0 {
		jsonErr(w, "invalid task id", http.StatusBadRequest)
		return
	}
	var req struct {
		SubTasks []decomposeSubtaskWire `json:"subtasks"`
	}
	limitJSONBody(w, r, maxJSONBodyBytes)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondToBodyError(w, err)
		return
	}

	validRoles := make(map[string]bool, len(pm.ValidRoles()))
	for _, role := range pm.ValidRoles() {
		validRoles[role] = true
	}
	kept := make([]decomposeSubtaskWire, 0, len(req.SubTasks))
	for _, st := range req.SubTasks {
		st.Title = strings.TrimSpace(st.Title)
		if st.Title == "" {
			continue
		}
		if !validRoles[st.Role] {
			st.Role = ""
		}
		if st.EstimatedMinutes < 0 {
			st.EstimatedMinutes = 0
		}
		kept = append(kept, st)
	}
	if len(kept) == 0 {
		jsonErr(w, "no sub-tasks to add", http.StatusBadRequest)
		return
	}
	if len(kept) > decomposeMaxSubtasks {
		jsonErr(w, fmt.Sprintf("too many sub-tasks (max %d)", decomposeMaxSubtasks), http.StatusBadRequest)
		return
	}

	workDir := s.resolveWorkDir(r)
	ps, err := state.Load(workDir)
	if err != nil {
		jsonErr(w, err.Error(), statedb.HTTPStatus(err))
		return
	}
	if ps.Plan == nil {
		jsonErr(w, "no task plan found — run cloop init first", http.StatusNotFound)
		return
	}
	parent, err := ps.RequireTask(id)
	if err != nil {
		jsonErr(w, err.Error(), statedb.HTTPStatus(err))
		return
	}
	if err := checkDecomposable(parent); err != nil {
		jsonErr(w, err.Error(), http.StatusConflict)
		return
	}

	// Rebuild pm.Tasks from the reviewed wire proposals, inheriting parent
	// tags/assignee exactly like decompose.ParseSubTasks does.
	subTasks := make([]*pm.Task, 0, len(kept))
	for i, st := range kept {
		var tags []string
		if len(parent.Tags) > 0 {
			tags = append([]string{}, parent.Tags...)
		}
		t := &pm.Task{
			Title:            st.Title,
			Description:      st.Description,
			Priority:         parent.Priority,
			Role:             pm.AgentRole(st.Role),
			Status:           pm.TaskPending,
			Tags:             tags,
			Assignee:         parent.Assignee,
			EstimatedMinutes: st.EstimatedMinutes,
		}
		if i == 0 {
			t.DependsOn = []int{parent.ID}
		}
		subTasks = append(subTasks, t)
	}

	added := decompose.InjectSubTasks(ps.Plan, &decompose.DecomposeResult{Parent: parent, SubTasks: subTasks})
	if err := ps.SaveDirect(); err != nil {
		jsonErr(w, "save failed: "+err.Error(), statedb.HTTPStatus(err))
		return
	}

	s.broadcastStateDiff(workDir, ps)

	ids := make([]int, 0, len(added))
	idStrs := make([]string, 0, len(added))
	for _, t := range added {
		ids = append(ids, t.ID)
		idStrs = append(idStrs, "#"+strconv.Itoa(t.ID))
	}
	state.LogEvent(workDir, state.EventRow{
		Type:      state.EventTaskAdded,
		TaskID:    parent.ID,
		TaskTitle: parent.Title,
		Step:      state.NoStep,
		Message: fmt.Sprintf("Task #%d decomposed into %d sub-tasks via UI: %s",
			parent.ID, len(added), strings.Join(idStrs, ", ")),
	})

	jsonOK(w, map[string]interface{}{
		"ok":        true,
		"parent_id": parent.ID,
		"added":     ids,
	})
}

// handleTaskStatus changes a task's status.
func (s *Server) handleTaskStatus(w http.ResponseWriter, r *http.Request) {
	if !requirePOST(w, r) {
		return
	}
	var req struct {
		ID     int    `json:"id"`
		Status string `json:"status"`
	}
	limitJSONBody(w, r, maxJSONBodyBytes)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondToBodyError(w, err)
		return
	}
	validStatuses := map[string]pm.TaskStatus{
		"pending":     pm.TaskPending,
		"in_progress": pm.TaskInProgress,
		"done":        pm.TaskDone,
		"skipped":     pm.TaskSkipped,
		"failed":      pm.TaskFailed,
	}
	newStatus, ok := validStatuses[req.Status]
	if !ok {
		jsonErr(w, fmt.Sprintf("invalid status %q", req.Status), http.StatusBadRequest)
		return
	}

	ps, err := state.Load(s.resolveWorkDir(r))
	if err != nil {
		jsonErr(w, err.Error(), statedb.HTTPStatus(err))
		return
	}
	task, err := ps.RequireTask(req.ID)
	if err != nil {
		jsonErr(w, err.Error(), statedb.HTTPStatus(err))
		return
	}

	oldStatus := string(task.Status)
	task.Status = newStatus
	if err := ps.SaveDirect(); err != nil {
		jsonErr(w, "save failed: "+err.Error(), statedb.HTTPStatus(err))
		return
	}
	workDir := s.resolveWorkDir(r)
	// Manual-abort hook (Task 20140): when an operator moves a task out of
	// in_progress, request the orchestrator to cancel its in-flight provider
	// call. The orchestrator's kill-poller picks this up within a second and
	// fires the watchdog-registered cancel. Best-effort — a failure to record
	// the request just means the task continues to run; the disk status is
	// already correct so the UI reflects the operator's choice.
	if oldStatus == string(pm.TaskInProgress) && newStatus != pm.TaskInProgress {
		if killErr := state.RequestTaskKill(workDir, req.ID, req.Status, "ui"); killErr != nil {
			fmt.Fprintf(os.Stderr, "[ui] task %d kill request: %v\n", req.ID, killErr)
		}
	}
	if oldStatus != req.Status {
		state.LogEventDetails(workDir, state.EventRow{
			Type:      state.EventTaskStatusChange,
			TaskID:    req.ID,
			TaskTitle: task.Title,
			Step:      state.NoStep,
			Message:   fmt.Sprintf("Task #%d status changed: %s → %s (via UI)", req.ID, oldStatus, req.Status),
		}, map[string]any{"old_status": oldStatus, "new_status": req.Status})
	}
	jsonOK(w, map[string]interface{}{"ok": true, "id": req.ID, "status": req.Status})
}

// handleTaskMove reorders a task up or down by swapping priorities.
func (s *Server) handleTaskMove(w http.ResponseWriter, r *http.Request) {
	if !requirePOST(w, r) {
		return
	}
	var req struct {
		ID        int    `json:"id"`
		Direction string `json:"direction"`
	}
	limitJSONBody(w, r, maxJSONBodyBytes)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondToBodyError(w, err)
		return
	}
	if req.Direction != "up" && req.Direction != "down" {
		jsonErr(w, "direction must be 'up' or 'down'", http.StatusBadRequest)
		return
	}

	ps, err := state.Load(s.resolveWorkDir(r))
	if err != nil {
		jsonErr(w, err.Error(), statedb.HTTPStatus(err))
		return
	}
	if _, err := ps.RequireTask(req.ID); err != nil {
		jsonErr(w, err.Error(), statedb.HTTPStatus(err))
		return
	}

	sorted := make([]*pm.Task, len(ps.Plan.Tasks))
	copy(sorted, ps.Plan.Tasks)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].Priority < sorted[j].Priority })

	idx := -1
	for i, t := range sorted {
		if t.ID == req.ID {
			idx = i
			break
		}
	}
	// idx != -1: RequireTask already verified the task exists; sorted holds
	// the same task pointers in a different order, so the index lookup is
	// always successful here.

	var other *pm.Task
	if req.Direction == "up" {
		if idx == 0 {
			jsonErr(w, "already at top", http.StatusBadRequest)
			return
		}
		other = sorted[idx-1]
	} else {
		if idx == len(sorted)-1 {
			jsonErr(w, "already at bottom", http.StatusBadRequest)
			return
		}
		other = sorted[idx+1]
	}
	sorted[idx].Priority, other.Priority = other.Priority, sorted[idx].Priority

	if err := ps.SaveDirect(); err != nil {
		jsonErr(w, "save failed: "+err.Error(), statedb.HTTPStatus(err))
		return
	}
	jsonOK(w, map[string]interface{}{"ok": true, "id": req.ID})
}

// handleTaskEdit edits a task's title, description, priority, and/or depends_on.
func (s *Server) handleTaskEdit(w http.ResponseWriter, r *http.Request) {
	if !requirePOST(w, r) {
		return
	}
	var req struct {
		ID          int    `json:"id"`
		Title       string `json:"title"`
		Description string `json:"description"`
		Priority    int    `json:"priority"`
		DependsOn   *[]int `json:"depends_on"` // nil = don't change; []int{} = clear; [1,2] = set
		// MaxMinutes is the per-task wall-clock budget override. Pointer so
		// the absent field is distinguishable from explicit 0 (which means
		// "inherit project default"). See Task 20143.
		MaxMinutes *int `json:"max_minutes"`
	}
	limitJSONBody(w, r, maxJSONBodyBytes)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondToBodyError(w, err)
		return
	}
	if req.MaxMinutes != nil {
		v := *req.MaxMinutes
		if v != 0 && (v < config.OrchestratorTaskTimeoutMinutesLower || v > config.OrchestratorTaskTimeoutMinutesUpper) {
			jsonErr(w, fmt.Sprintf("max_minutes must be 0 or between %d and %d",
				config.OrchestratorTaskTimeoutMinutesLower, config.OrchestratorTaskTimeoutMinutesUpper),
				http.StatusBadRequest)
			return
		}
	}

	ps, err := state.Load(s.resolveWorkDir(r))
	if err != nil {
		jsonErr(w, err.Error(), statedb.HTTPStatus(err))
		return
	}
	task, err := ps.RequireTask(req.ID)
	if err != nil {
		jsonErr(w, err.Error(), statedb.HTTPStatus(err))
		return
	}

	if t := strings.TrimSpace(req.Title); t != "" {
		task.Title = t
	}
	if req.Description != "" {
		task.Description = req.Description
	}
	if req.Priority > 0 {
		task.Priority = req.Priority
	}
	if req.DependsOn != nil {
		if err := validateDependsOn(*req.DependsOn, task.ID, ps.Plan.Tasks); err != nil {
			jsonErr(w, err.Error(), http.StatusBadRequest)
			return
		}
		task.DependsOn = *req.DependsOn
	}
	if req.MaxMinutes != nil {
		task.MaxMinutes = *req.MaxMinutes
	}

	if err := ps.SaveDirect(); err != nil {
		jsonErr(w, "save failed: "+err.Error(), statedb.HTTPStatus(err))
		return
	}
	jsonOK(w, map[string]interface{}{"ok": true, "task": task})
}

// handleTaskRemove removes a task from the plan.
func (s *Server) handleTaskRemove(w http.ResponseWriter, r *http.Request) {
	if !requirePOST(w, r) {
		return
	}
	var req struct {
		ID int `json:"id"`
	}
	limitJSONBody(w, r, maxJSONBodyBytes)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondToBodyError(w, err)
		return
	}

	ps, err := state.Load(s.resolveWorkDir(r))
	if err != nil {
		jsonErr(w, err.Error(), statedb.HTTPStatus(err))
		return
	}
	if _, err := ps.RequireTask(req.ID); err != nil {
		jsonErr(w, err.Error(), statedb.HTTPStatus(err))
		return
	}

	idx := -1
	for i, t := range ps.Plan.Tasks {
		if t.ID == req.ID {
			idx = i
			break
		}
	}
	// idx is guaranteed non-negative here; RequireTask above proved the task
	// exists, and ps.Plan.Tasks is not mutated between the two calls.

	ps.Plan.Tasks = append(ps.Plan.Tasks[:idx], ps.Plan.Tasks[idx+1:]...)
	if err := ps.SaveDirect(); err != nil {
		jsonErr(w, "save failed: "+err.Error(), statedb.HTTPStatus(err))
		return
	}
	jsonOK(w, map[string]bool{"ok": true})
}

// handlePostTasks is a RESTful alias for handleTaskAdd (POST /api/tasks).
func (s *Server) handlePostTasks(w http.ResponseWriter, r *http.Request) {
	s.handleTaskAdd(w, r)
}

// handlePutTask updates a task by ID (PUT /api/tasks/{id}).
func (s *Server) handlePutTask(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	id, err := strconv.Atoi(idStr)
	if err != nil || id <= 0 {
		jsonErr(w, "invalid task id", http.StatusBadRequest)
		return
	}

	var req struct {
		Title       string `json:"title"`
		Description string `json:"description"`
		Priority    int    `json:"priority"`
		Status      string `json:"status"`
		DependsOn   *[]int `json:"depends_on"`
		// MaxMinutes is the per-task wall-clock budget override (Task 20143).
		// Pointer so the absent field is distinguishable from an explicit 0
		// (which means "fall back to the project / process-wide default").
		MaxMinutes *int `json:"max_minutes"`
	}
	limitJSONBody(w, r, maxJSONBodyBytes)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondToBodyError(w, err)
		return
	}
	// Validate the per-task timeout against the same bounds the orchestrator
	// enforces, so a value that the daemon would silently coerce to the default
	// is rejected up-front with a clear error instead.
	if req.MaxMinutes != nil {
		v := *req.MaxMinutes
		if v != 0 && (v < config.OrchestratorTaskTimeoutMinutesLower || v > config.OrchestratorTaskTimeoutMinutesUpper) {
			jsonErr(w, fmt.Sprintf("max_minutes must be 0 or between %d and %d",
				config.OrchestratorTaskTimeoutMinutesLower, config.OrchestratorTaskTimeoutMinutesUpper),
				http.StatusBadRequest)
			return
		}
	}

	ps, err := state.Load(s.resolveWorkDir(r))
	if err != nil {
		jsonErr(w, err.Error(), statedb.HTTPStatus(err))
		return
	}
	task, err := ps.RequireTask(id)
	if err != nil {
		jsonErr(w, err.Error(), statedb.HTTPStatus(err))
		return
	}

	if t := strings.TrimSpace(req.Title); t != "" {
		task.Title = t
	}
	if req.Description != "" {
		task.Description = req.Description
	}
	if req.Priority > 0 {
		task.Priority = req.Priority
	}
	if req.DependsOn != nil {
		if err := validateDependsOn(*req.DependsOn, task.ID, ps.Plan.Tasks); err != nil {
			jsonErr(w, err.Error(), http.StatusBadRequest)
			return
		}
		task.DependsOn = *req.DependsOn
	}
	if req.MaxMinutes != nil {
		task.MaxMinutes = *req.MaxMinutes
	}
	// Capture the prior status BEFORE the assignment so the manual-abort hook
	// below can detect a transition out of in_progress (Task 20140).
	priorStatus := task.Status
	statusChanged := false
	if req.Status != "" {
		validStatuses := map[string]pm.TaskStatus{
			"pending":     pm.TaskPending,
			"in_progress": pm.TaskInProgress,
			"done":        pm.TaskDone,
			"skipped":     pm.TaskSkipped,
			"failed":      pm.TaskFailed,
		}
		if ns, ok := validStatuses[req.Status]; ok {
			task.Status = ns
			statusChanged = ns != priorStatus
		}
	}

	if err := ps.SaveDirect(); err != nil {
		jsonErr(w, "save failed: "+err.Error(), statedb.HTTPStatus(err))
		return
	}

	// Manual-abort hook (Task 20140): when this PUT moved the task out of
	// in_progress, ask the orchestrator's kill-poller to cancel the in-flight
	// provider call. Best-effort — kill_request failures are logged but do
	// not fail the PUT (disk status already reflects the operator's choice).
	if statusChanged && priorStatus == pm.TaskInProgress && task.Status != pm.TaskInProgress {
		if killErr := state.RequestTaskKill(s.resolveWorkDir(r), id, req.Status, "ui"); killErr != nil {
			fmt.Fprintf(os.Stderr, "[ui] task %d kill request: %v\n", id, killErr)
		}
	}

	// Detect which fields were mutated and check for concurrent-edit conflicts.
	mutatedFields := []string{}
	if req.Title != "" {
		mutatedFields = append(mutatedFields, "title")
	}
	if req.Description != "" {
		mutatedFields = append(mutatedFields, "description")
	}
	if req.Priority > 0 {
		mutatedFields = append(mutatedFields, "priority")
	}
	if req.Status != "" {
		mutatedFields = append(mutatedFields, "status")
	}
	if req.MaxMinutes != nil {
		mutatedFields = append(mutatedFields, "max_minutes")
	}
	workDir := s.resolveWorkDir(r)
	clientID := r.Header.Get("X-Client-ID")
	if clientID == "" {
		clientID = clientIP(r)
	}
	conflict := false
	if len(mutatedFields) > 0 {
		conflict = s.checkAndRecordEdit(workDir, clientID, id, mutatedFields)
	}

	// Broadcast the mutation to all WebSocket clients watching this project.
	// state_diff carries the changed fields; task_mutation now just carries
	// the conflict flag + task summary for the toast UI (Task 20132).
	s.broadcastStateDiff(workDir, ps)
	mutRaw, _ := json.Marshal(map[string]interface{}{
		"task":     task,
		"conflict": conflict,
	})
	s.broadcastToProject(workDir, wsMessage{Type: "task_mutation", Data: mutRaw})

	jsonOK(w, map[string]interface{}{"ok": true, "task": task, "conflict": conflict})
}

// handleDeleteTask removes a task by ID (DELETE /api/tasks/{id}).
func (s *Server) handleDeleteTask(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	id, err := strconv.Atoi(idStr)
	if err != nil || id <= 0 {
		jsonErr(w, "invalid task id", http.StatusBadRequest)
		return
	}

	ps, err := state.Load(s.resolveWorkDir(r))
	if err != nil {
		jsonErr(w, err.Error(), statedb.HTTPStatus(err))
		return
	}
	if _, err := ps.RequireTask(id); err != nil {
		jsonErr(w, err.Error(), statedb.HTTPStatus(err))
		return
	}

	idx := -1
	for i, t := range ps.Plan.Tasks {
		if t.ID == id {
			idx = i
			break
		}
	}
	// idx is guaranteed non-negative: RequireTask verified the task above.
	deletedTitle := ps.Plan.Tasks[idx].Title

	ps.Plan.Tasks = append(ps.Plan.Tasks[:idx], ps.Plan.Tasks[idx+1:]...)
	if err := ps.SaveDirect(); err != nil {
		jsonErr(w, "save failed: "+err.Error(), statedb.HTTPStatus(err))
		return
	}

	// Broadcast deletion to all WebSocket clients watching this project.
	// state_diff carries the removed task ID; task_deleted retains the same
	// hint event without the embedded state payload (Task 20132).
	workDir2 := s.resolveWorkDir(r)
	s.broadcastStateDiff(workDir2, ps)
	delRaw, _ := json.Marshal(map[string]interface{}{
		"deleted_id": id,
	})
	s.broadcastToProject(workDir2, wsMessage{Type: "task_deleted", Data: delRaw})
	state.LogEvent(workDir2, state.EventRow{
		Type:      state.EventTaskDeleted,
		TaskID:    id,
		TaskTitle: deletedTitle,
		Step:      state.NoStep,
		Message:   fmt.Sprintf("Task #%d deleted via UI", id),
	})

	jsonOK(w, map[string]bool{"ok": true})
}

// handleTaskBlocker runs blocker detection (and optionally AI analysis) for a task
// (GET /api/tasks/{id}/blocker).
// Query params:
//
//	analyze=true   — also call the AI for root-cause + actions (requires provider config)
//	apply=true     — annotate the task with the AI recommendation (requires analyze=true)
func (s *Server) handleTaskBlocker(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	id, err := strconv.Atoi(idStr)
	if err != nil || id <= 0 {
		jsonErr(w, "invalid task id", http.StatusBadRequest)
		return
	}

	workDir := s.resolveWorkDir(r)
	ps, err := state.Load(workDir)
	if err != nil {
		jsonErr(w, err.Error(), statedb.HTTPStatus(err))
		return
	}
	task, err := ps.RequireTask(id)
	if err != nil {
		jsonErr(w, err.Error(), statedb.HTTPStatus(err))
		return
	}

	info := blocker.Detect(workDir, task, ps.Plan)

	// Detection-only response
	if r.URL.Query().Get("analyze") != "true" {
		jsonOK(w, info)
		return
	}

	// AI analysis requested — need a provider
	cfg, cfgErr := config.Load(workDir)
	if cfgErr != nil {
		jsonErr(w, "config load error: "+cfgErr.Error(), http.StatusInternalServerError)
		return
	}

	pName := cfg.Provider
	if pName == "" {
		pName = "claudecode"
	}
	provCfg := provider.ProviderConfig{
		Name:             pName,
		AnthropicAPIKey:  cfg.Anthropic.APIKey,
		AnthropicBaseURL: cfg.Anthropic.BaseURL,
		OpenAIAPIKey:     cfg.OpenAI.APIKey,
		OpenAIBaseURL:    cfg.OpenAI.BaseURL,
		OllamaBaseURL:    cfg.Ollama.BaseURL,
	}
	prov, provErr := provider.Build(provCfg)
	if provErr != nil {
		jsonErr(w, "provider error: "+provErr.Error(), http.StatusInternalServerError)
		return
	}

	model := ""
	switch pName {
	case "anthropic":
		model = cfg.Anthropic.Model
	case "openai":
		model = cfg.OpenAI.Model
	case "ollama":
		model = cfg.Ollama.Model
	case "claudecode":
		model = cfg.ClaudeCode.Model
	}

	ctx := r.Context()
	report, analyzeErr := blocker.Analyze(ctx, prov, model, 3*time.Minute, task, ps.Plan, workDir)
	if analyzeErr != nil {
		jsonErr(w, "analysis error: "+analyzeErr.Error(), http.StatusInternalServerError)
		return
	}

	// --apply: annotate the task
	if r.URL.Query().Get("apply") == "true" {
		annotation := "[ai-blocker] Recommendation: " + strings.ToUpper(report.Recommendation) +
			". Root cause: " + report.RootCause
		pm.AddAnnotation(task, "ai-blocker", annotation)
		if saveErr := ps.SaveDirect(); saveErr != nil {
			jsonErr(w, "save failed: "+saveErr.Error(), http.StatusInternalServerError)
			return
		}
	}

	jsonOK(w, report)
}

// handleTaskDetails returns the full execution context of a task — the
// Result summary, FailureDiagnosis, annotations, timing, and (when
// available) the contents of the persisted output artifact and the live
// streaming output. Used by the Web UI when the user clicks a task row to
// inspect what already happened.
//
// GET /api/tasks/{id}/details
func (s *Server) handleTaskDetails(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	id, err := strconv.Atoi(idStr)
	if err != nil || id <= 0 {
		jsonErr(w, "invalid task id", http.StatusBadRequest)
		return
	}

	workDir := s.resolveWorkDir(r)
	ps, err := state.Load(workDir)
	if err != nil {
		jsonErr(w, err.Error(), statedb.HTTPStatus(err))
		return
	}
	task, err := ps.RequireTask(id)
	if err != nil {
		jsonErr(w, err.Error(), statedb.HTTPStatus(err))
		return
	}

	// Cap returned bodies so a runaway artifact can't blow up the browser.
	const maxBodyBytes = 256 * 1024 // 256 KB

	clip := func(s string) (string, bool) {
		if len(s) <= maxBodyBytes {
			return s, false
		}
		// Keep the tail — that's where TASK_DONE/FAILED/SKIPPED signals live
		// and what users are most likely looking for.
		return "…[truncated " + strconv.Itoa(len(s)-maxBodyBytes) + " bytes]…\n" + s[len(s)-maxBodyBytes:], true
	}

	artifactBody := ""
	artifactTruncated := false
	artifactSourcePath := task.ArtifactPath
	if task.ArtifactPath != "" {
		full := artifact.ReadTaskOutput(workDir, task)
		artifactBody, artifactTruncated = clip(full)
	}

	liveBody := ""
	liveTruncated := false
	livePath := ""
	// In-progress tasks (or tasks that crashed mid-flight) may not have a
	// finalized artifact but do have a live streaming file we can show.
	if liveAbs := artifact.LiveArtifactPath(workDir, id); liveAbs != "" {
		if data, err := os.ReadFile(liveAbs); err == nil && len(data) > 0 {
			body, trunc := clip(string(data))
			liveBody = body
			liveTruncated = trunc
			if rel, relErr := filepath.Rel(workDir, liveAbs); relErr == nil {
				livePath = rel
			} else {
				livePath = liveAbs
			}
		}
	}

	jsonOK(w, map[string]interface{}{
		"ok":                 true,
		"task":               task,
		"artifact_body":      artifactBody,
		"artifact_truncated": artifactTruncated,
		"artifact_path":      artifactSourcePath,
		"live_body":          liveBody,
		"live_truncated":     liveTruncated,
		"live_path":          livePath,
	})
}

// handleReorderTasks reassigns priorities from the given task ID order (POST /api/tasks/reorder).
func (s *Server) handleReorderTasks(w http.ResponseWriter, r *http.Request) {
	if !requirePOST(w, r) {
		return
	}
	var req struct {
		IDs []int `json:"ids"`
	}
	limitJSONBody(w, r, maxJSONBodyBytes)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondToBodyError(w, err)
		return
	}
	if len(req.IDs) == 0 {
		jsonErr(w, "ids is required", http.StatusBadRequest)
		return
	}

	ps, err := state.Load(s.resolveWorkDir(r))
	if err != nil {
		jsonErr(w, "no project found", http.StatusNotFound)
		return
	}
	if ps.Plan == nil {
		jsonErr(w, "no task plan", http.StatusNotFound)
		return
	}

	taskMap := make(map[int]*pm.Task, len(ps.Plan.Tasks))
	for _, t := range ps.Plan.Tasks {
		taskMap[t.ID] = t
	}
	for i, id := range req.IDs {
		if t, ok := taskMap[id]; ok {
			t.Priority = i + 1
		}
	}

	if err := ps.SaveDirect(); err != nil {
		jsonErr(w, "save failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	jsonOK(w, map[string]bool{"ok": true})
}

// handleLiveLog returns the current live log ring buffer and running status.
// The running field reflects actual process state: it checks the in-memory
// per-project run flag (set when a run was started via this server) and also
// probes /proc for any cloop process running in the project directory.
func (s *Server) handleLiveLog(w http.ResponseWriter, r *http.Request) {
	workDir := s.resolveWorkDir(r)
	// Answer for the project the request resolved to. Pre-fix workDir was
	// computed here and then used only for the /proc probe below, while the
	// lines came from a single global buffer — so ?project_idx=B returned
	// project A's output (Task 20189).
	lines := s.liveLogReplay(workDir)
	running := s.liveLogRunningFor(workDir)

	// If not tracked in-memory, check whether a cloop process is actually
	// running in the project directory (handles externally-started runs).
	if !running {
		running = multiui.IsCloopRunningInDir(workDir)
	}

	jsonOK(w, map[string]interface{}{
		"running": running,
		"lines":   lines,
	})
}

// handleSuggestGenerate runs `cloop suggest --json` in the background, parses
// the resulting suggestions, and stores them for review. Clients then call
// /api/suggest/status to retrieve them.
func (s *Server) handleSuggestGenerate(w http.ResponseWriter, r *http.Request) {
	if !requirePOST(w, r) {
		return
	}
	var req struct {
		Count int `json:"count"`
	}
	limitJSONBody(w, r, maxJSONBodyBytes)
	_ = json.NewDecoder(r.Body).Decode(&req)
	if req.Count <= 0 {
		req.Count = 5
	}
	if req.Count > 20 {
		req.Count = 20
	}

	suggestWorkDir := s.resolveWorkDir(r)

	s.suggestMu.Lock()
	if s.suggestRunning {
		s.suggestMu.Unlock()
		jsonErr(w, "suggest already running", http.StatusConflict)
		return
	}
	s.suggestRunning = true
	s.suggestDone = false
	s.suggestErr = ""
	s.suggestSummary = ""
	s.suggestSuggestions = nil
	s.suggestWorkDir = suggestWorkDir
	s.suggestMu.Unlock()
	s.broadcastSuggestStatus(suggestWorkDir)

	exe, err := os.Executable()
	if err != nil {
		exe = "cloop"
	}

	go func() {
		defer func() {
			if rec := recover(); rec != nil {
				fmt.Fprintf(os.Stderr, "ui: suggest goroutine panic recovered: %v\n", rec)
				// Recover the running flag so the user can retry.
				s.suggestMu.Lock()
				s.suggestRunning = false
				s.suggestDone = true
				s.suggestErr = fmt.Sprintf("internal panic: %v", rec)
				s.suggestMu.Unlock()
				s.broadcastSuggestStatus(suggestWorkDir)
			}
		}()
		// Hard timeout: nothing else cancels this background goroutine, and a
		// hung sub-binary would otherwise leave suggestRunning=true forever
		// (every subsequent /api/suggest/start returns 409 Conflict until the
		// UI server is restarted).
		out, runErr := runCloopSubcommand(context.Background(), exe, suggestWorkDir, suggestSubprocessTimeout,
			"suggest", "--json", "--count", strconv.Itoa(req.Count))

		s.suggestMu.Lock()
		s.suggestRunning = false
		s.suggestDone = true

		if runErr != nil {
			msg := strings.TrimSpace(string(out))
			if msg == "" {
				msg = runErr.Error()
			}
			s.suggestErr = msg
			s.suggestMu.Unlock()
			s.broadcastSuggestStatus(suggestWorkDir)
			return
		}

		var result suggest.Result
		if err := json.Unmarshal(out, &result); err != nil {
			s.suggestErr = "could not parse suggestions: " + err.Error()
			s.suggestMu.Unlock()
			s.broadcastSuggestStatus(suggestWorkDir)
			return
		}
		s.suggestSummary = result.Summary
		s.suggestSuggestions = result.Suggestions
		s.suggestMu.Unlock()
		s.broadcastSuggestStatus(suggestWorkDir)
	}()

	jsonOK(w, map[string]interface{}{"ok": true, "count": req.Count})
}

// handleSuggestStatus returns the current suggest job status and any generated suggestions.
func (s *Server) handleSuggestStatus(w http.ResponseWriter, r *http.Request) {
	s.suggestMu.Lock()
	running := s.suggestRunning
	done := s.suggestDone
	errMsg := s.suggestErr
	summary := s.suggestSummary
	suggestions := append([]*suggest.Suggestion(nil), s.suggestSuggestions...)
	s.suggestMu.Unlock()

	jsonOK(w, map[string]interface{}{
		"running":     running,
		"done":        done,
		"error":       errMsg,
		"summary":     summary,
		"suggestions": suggestions,
	})
}

// handleSuggestAdd injects one or more reviewed suggestions into the plan as PM tasks.
// Accepts either a list of suggestion IDs (referring to the most recent generation)
// or a list of full suggestion objects.
func (s *Server) handleSuggestAdd(w http.ResponseWriter, r *http.Request) {
	if !requirePOST(w, r) {
		return
	}
	var req struct {
		IDs         []int                 `json:"ids"`
		Suggestions []*suggest.Suggestion `json:"suggestions"`
	}
	limitJSONBody(w, r, maxJSONBodyBytes)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondToBodyError(w, err)
		return
	}

	picked := req.Suggestions
	if len(picked) == 0 && len(req.IDs) > 0 {
		s.suggestMu.Lock()
		idx := make(map[int]*suggest.Suggestion, len(s.suggestSuggestions))
		for _, sg := range s.suggestSuggestions {
			idx[sg.ID] = sg
		}
		for _, id := range req.IDs {
			if sg, ok := idx[id]; ok {
				picked = append(picked, sg)
			}
		}
		s.suggestMu.Unlock()
	}

	if len(picked) == 0 {
		jsonErr(w, "no suggestions to add", http.StatusBadRequest)
		return
	}

	workDir := s.resolveWorkDir(r)
	ps, err := state.Load(workDir)
	if err != nil {
		jsonErr(w, "no project found — run cloop init first", http.StatusNotFound)
		return
	}
	if ps.Plan == nil {
		ps.Plan = pm.NewPlan(ps.Goal)
	}
	if !ps.PMMode {
		ps.PMMode = true
	}

	maxID := 0
	for _, t := range ps.Plan.Tasks {
		if t.ID > maxID {
			maxID = t.ID
		}
	}

	added := make([]int, 0, len(picked))
	for _, sg := range picked {
		if sg == nil || strings.TrimSpace(sg.Title) == "" {
			continue
		}
		maxID++
		task := &pm.Task{
			ID:          maxID,
			Title:       sg.Title,
			Description: sg.Description,
			Priority:    suggestEffortToPriorityUI(sg.Effort),
			Status:      pm.TaskPending,
			Role:        suggestCategoryToRoleUI(sg.Category),
		}
		ps.Plan.Tasks = append(ps.Plan.Tasks, task)
		added = append(added, task.ID)
	}

	if err := ps.SaveDirect(); err != nil {
		jsonErr(w, "save failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Drop accepted suggestions from the in-memory list.
	if len(added) > 0 {
		acceptedTitles := make(map[string]bool, len(picked))
		for _, sg := range picked {
			if sg != nil {
				acceptedTitles[sg.Title] = true
			}
		}
		s.suggestMu.Lock()
		remaining := s.suggestSuggestions[:0]
		for _, sg := range s.suggestSuggestions {
			if !acceptedTitles[sg.Title] {
				remaining = append(remaining, sg)
			}
		}
		s.suggestSuggestions = remaining
		s.suggestMu.Unlock()
	}

	s.broadcastStateDiff(workDir, ps)

	jsonOK(w, map[string]interface{}{
		"ok":    true,
		"added": added,
	})
}

// suggestCategoryToRoleUI mirrors cmd/suggest_cmd.go:suggestCategoryToRole.
func suggestCategoryToRoleUI(c suggest.Category) pm.AgentRole {
	switch c {
	case suggest.CategoryFeature, suggest.CategoryPerformance, suggest.CategoryIntegration:
		return pm.RoleBackend
	case suggest.CategoryUX:
		return pm.RoleFrontend
	case suggest.CategorySecurity:
		return pm.RoleSecurity
	case suggest.CategoryDX:
		return pm.RoleDevOps
	case suggest.CategoryDocs:
		return pm.RoleDocs
	default:
		return ""
	}
}

// suggestEffortToPriorityUI mirrors cmd/suggest_cmd.go:suggestEffortToPriority.
func suggestEffortToPriorityUI(e suggest.Effort) int {
	switch e {
	case suggest.EffortXS, suggest.EffortS:
		return 3
	case suggest.EffortM:
		return 4
	case suggest.EffortL, suggest.EffortXL:
		return 5
	default:
		return 4
	}
}

// handleInit initializes a new cloop project.
func (s *Server) handleInit(w http.ResponseWriter, r *http.Request) {
	if !requirePOST(w, r) {
		return
	}
	var req struct {
		Goal         string `json:"goal"`
		Provider     string `json:"provider"`
		Model        string `json:"model"`
		Effort       string `json:"effort"`
		Instructions string `json:"instructions"`
		MaxSteps     int    `json:"maxSteps"`
		PMMode       bool   `json:"pmMode"`
	}
	limitJSONBody(w, r, maxJSONBodyBytes)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondToBodyError(w, err)
		return
	}
	req.Goal = strings.TrimSpace(req.Goal)
	if req.Goal == "" {
		jsonErr(w, "goal is required", http.StatusBadRequest)
		return
	}
	if !provider.ValidEffort(req.Effort) {
		jsonErr(w, "invalid effort "+strconv.Quote(req.Effort)+" — valid: "+strings.Join(provider.EffortLevels, ", "), http.StatusBadRequest)
		return
	}

	ps, err := state.Init(s.resolveWorkDir(r), req.Goal, req.MaxSteps)
	if err != nil {
		jsonErr(w, "init failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if req.Instructions != "" {
		ps.Instructions = req.Instructions
	}
	if req.Model != "" {
		ps.Model = req.Model
	}
	if req.Effort != "" {
		ps.Effort = req.Effort
	}
	if req.Provider != "" {
		ps.Provider = req.Provider
	}
	if req.PMMode {
		ps.PMMode = true
	}
	if err := ps.SaveDirect(); err != nil {
		jsonErr(w, "save failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	jsonOK(w, map[string]interface{}{"ok": true, "goal": ps.Goal})
}

// handleGoal returns or updates the project goal.
//
//	GET  /api/goal  -> { "goal": "..." }
//	PUT  /api/goal  -> body { "goal": "..." }; updates the saved project goal
func (s *Server) handleGoal(w http.ResponseWriter, r *http.Request) {
	workDir := s.resolveWorkDir(r)
	switch r.Method {
	case http.MethodGet:
		ps, err := state.Load(workDir)
		if err != nil {
			jsonErr(w, "load failed: "+err.Error(), http.StatusInternalServerError)
			return
		}
		jsonOK(w, map[string]interface{}{"goal": ps.Goal})
	case http.MethodPut, http.MethodPost:
		var req struct {
			Goal string `json:"goal"`
		}
		limitJSONBody(w, r, maxJSONBodyBytes)
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			respondToBodyError(w, err)
			return
		}
		req.Goal = strings.TrimSpace(req.Goal)
		if req.Goal == "" {
			jsonErr(w, "goal cannot be empty", http.StatusBadRequest)
			return
		}
		ps, err := state.Load(workDir)
		if err != nil {
			jsonErr(w, "load failed: "+err.Error(), http.StatusInternalServerError)
			return
		}
		old := ps.Goal
		ps.Goal = req.Goal
		if ps.Plan != nil {
			ps.Plan.Goal = req.Goal
		}
		if err := ps.SaveDirect(); err != nil {
			jsonErr(w, "save failed: "+err.Error(), http.StatusInternalServerError)
			return
		}
		s.broadcastStateDiff(workDir, ps)
		jsonOK(w, map[string]interface{}{"ok": true, "goal": ps.Goal, "previous": old})
	default:
		jsonErr(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleInstructions returns or updates the project instructions/constraints.
//
//	GET          /api/instructions -> { "instructions": "..." }
//	PUT or POST  /api/instructions -> body { "instructions": "..." }
//
// Instructions are stored in ProjectState and prepended to every task prompt.
// The empty string is allowed (clears the field).
func (s *Server) handleInstructions(w http.ResponseWriter, r *http.Request) {
	workDir := s.resolveWorkDir(r)
	switch r.Method {
	case http.MethodGet:
		ps, err := state.Load(workDir)
		if err != nil {
			jsonErr(w, "load failed: "+err.Error(), http.StatusInternalServerError)
			return
		}
		jsonOK(w, map[string]interface{}{"instructions": ps.Instructions})
	case http.MethodPut, http.MethodPost:
		var req struct {
			Instructions string `json:"instructions"`
		}
		limitJSONBody(w, r, maxJSONBodyBytes)
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			respondToBodyError(w, err)
			return
		}
		req.Instructions = strings.TrimSpace(req.Instructions)
		ps, err := state.Load(workDir)
		if err != nil {
			jsonErr(w, "load failed: "+err.Error(), http.StatusInternalServerError)
			return
		}
		old := ps.Instructions
		ps.Instructions = req.Instructions
		if err := ps.SaveDirect(); err != nil {
			jsonErr(w, "save failed: "+err.Error(), http.StatusInternalServerError)
			return
		}
		s.broadcastStateDiff(workDir, ps)
		jsonOK(w, map[string]interface{}{"ok": true, "instructions": ps.Instructions, "previous": old})
	default:
		jsonErr(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleVoice accepts a multipart audio upload, transcribes it with the local
// cloop listen command, and returns the transcription + resolved action.
// POST /api/voice   multipart field: "audio" (binary audio file)
// Optional query params: stt_provider, whisper_model, groq_api_key, dry_run=true
func (s *Server) handleVoice(w http.ResponseWriter, r *http.Request) {
	if !requirePOST(w, r) {
		return
	}

	// Cap the total request body so a client can't spool unbounded data to
	// disk: ParseMultipartForm's argument only bounds the in-memory portion,
	// not the overall upload size. 64 MiB leaves headroom over the 32 MiB
	// memory budget for multipart framing and form fields.
	r.Body = http.MaxBytesReader(w, r.Body, 64<<20)

	// 32 MB max upload.
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		respondToBodyError(w, err)
		return
	}

	file, fh, err := r.FormFile("audio")
	if err != nil {
		jsonErr(w, "audio field required: "+err.Error(), http.StatusBadRequest)
		return
	}
	defer file.Close()

	// Write to a temp file.
	tmp, err := os.CreateTemp("", "cloop-voice-*-"+fh.Filename)
	if err != nil {
		jsonErr(w, "tmpfile: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer os.Remove(tmp.Name())
	if _, err := io.Copy(tmp, file); err != nil {
		tmp.Close()
		jsonErr(w, "write tmpfile: "+err.Error(), http.StatusInternalServerError)
		return
	}
	tmp.Close()

	// Build cloop listen args.
	// dry_run=false (or execute=true) means the resolved command is actually
	// executed; otherwise we default to --dry-run to just show the intent.
	dryRun := r.FormValue("execute") != "true" && r.FormValue("dry_run") != "false"
	listenArgs := []string{"listen", "--file", tmp.Name()}
	if dryRun {
		listenArgs = append(listenArgs, "--dry-run")
	}

	if v := r.FormValue("stt_provider"); v != "" {
		listenArgs = append(listenArgs, "--stt-provider", v)
	}
	if v := r.FormValue("whisper_model"); v != "" {
		listenArgs = append(listenArgs, "--whisper-model", v)
	}
	// The Groq key travels in the environment, never on the argv: argv is
	// world-readable through /proc/<pid>/cmdline for the lifetime of the
	// child, which is the same reasoning install_script.go already applies
	// to enrollment tokens (Task 20188). `cloop listen` already falls back
	// to GROQ_API_KEY (cmd/listen.go), so no flag is needed.
	var listenEnv []string
	if v := r.FormValue("groq_api_key"); v != "" {
		listenEnv = append(listenEnv, "GROQ_API_KEY="+v)
	}

	// Run cloop listen via the installed binary. Bound by r.Context() so the
	// upload handler doesn't keep the STT subprocess alive after the client
	// gives up, plus a hard timeout in case the STT provider hangs.
	exe, err := os.Executable()
	if err != nil {
		exe = "cloop"
	}
	out, cmdErr := runCloopSubcommandEnv(r.Context(), exe, "", voiceSubprocessTimeout, listenEnv, listenArgs...)
	output := strings.TrimSpace(string(out))

	if cmdErr != nil {
		// Return a partial result with the output so the browser can display it.
		jsonOK(w, map[string]interface{}{
			"ok":     false,
			"output": output,
			"error":  cmdErr.Error(),
		})
		return
	}

	jsonOK(w, map[string]interface{}{
		"ok":     true,
		"output": output,
	})
}

// appendChatMessage adds msg to the workDir's chat history under chatMu and
// trims to the most recent maxChatHistoryPerWorkDir entries. The trim copies
// into a fresh slice so the dropped messages' backing array is released to
// the GC — a plain re-slice would keep the entire prior history pinned in
// memory for the lifetime of the daemon.
func (s *Server) appendChatMessage(workDir string, msg ChatMessage) {
	s.chatMu.Lock()
	defer s.chatMu.Unlock()
	hist := append(s.chatHistories[workDir], msg)
	if len(hist) > maxChatHistoryPerWorkDir {
		keep := make([]ChatMessage, maxChatHistoryPerWorkDir)
		copy(keep, hist[len(hist)-maxChatHistoryPerWorkDir:])
		hist = keep
	}
	s.chatHistories[workDir] = hist
}

// handleChatHistory returns the full chat conversation history as JSON.
// GET /api/chat/history
func (s *Server) handleChatHistory(w http.ResponseWriter, r *http.Request) {
	workDir := s.resolveWorkDir(r)
	s.chatMu.Lock()
	hist := s.chatHistories[workDir]
	h := make([]ChatMessage, len(hist))
	copy(h, hist)
	s.chatMu.Unlock()
	jsonOK(w, h)
}

// handleChat receives a natural-language message, attempts to execute it as a
// cloop command (via `cloop do`), and returns the result.
// POST /api/chat  {"message":"..."}
func (s *Server) handleChat(w http.ResponseWriter, r *http.Request) {
	if !requirePOST(w, r) {
		return
	}

	var req struct {
		Message string `json:"message"`
	}
	limitJSONBody(w, r, maxChatJSONBodyBytes)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondToBodyError(w, err)
		return
	}
	if strings.TrimSpace(req.Message) == "" {
		jsonErr(w, "message required", http.StatusBadRequest)
		return
	}
	msg := strings.TrimSpace(req.Message)
	chatWorkDir := s.resolveWorkDir(r)

	// Store user message.
	s.appendChatMessage(chatWorkDir, ChatMessage{
		Role:      "user",
		Content:   msg,
		Timestamp: time.Now(),
	})

	// Run cloop do <message> to parse and execute the intent. The subprocess
	// is bound by both r.Context() (browser tab close = SIGKILL the child) and
	// a hard timeout so a wedged provider call can't pin this goroutine.
	exe, err := os.Executable()
	if err != nil {
		exe = "cloop"
	}
	out, cmdErr := runCloopSubcommand(r.Context(), exe, chatWorkDir, chatSubprocessTimeout, "do", msg)
	output := strings.TrimSpace(string(out))

	ok := cmdErr == nil
	response := output
	if response == "" {
		if ok {
			response = "Command executed successfully."
		} else {
			response = "Failed: " + cmdErr.Error()
		}
	}

	// Store assistant message.
	s.appendChatMessage(chatWorkDir, ChatMessage{
		Role:      "assistant",
		Content:   response,
		Timestamp: time.Now(),
	})

	jsonOK(w, map[string]interface{}{
		"ok":       ok,
		"response": response,
	})
}

// handlePlanChat streams an AI response that is contextualised with the full
// plan (tasks, statuses, annotations) via SSE.
// POST /api/chat/plan  {"message":"...","history":[{"role":"user","content":"..."},...]}
func (s *Server) handlePlanChat(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Message string `json:"message"`
		History []struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		} `json:"history"`
	}
	limitJSONBody(w, r, maxChatJSONBodyBytes)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondToBodyError(w, err)
		return
	}
	if strings.TrimSpace(req.Message) == "" {
		jsonErr(w, "message required", http.StatusBadRequest)
		return
	}
	msg := strings.TrimSpace(req.Message)

	flusher, ok := w.(http.Flusher)
	if !ok {
		jsonErr(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	workDir := s.resolveWorkDir(r)
	cfg, err := config.Load(workDir)
	if err != nil {
		jsonErr(w, "config load failed", http.StatusInternalServerError)
		return
	}

	// Build plan context.
	var sysB strings.Builder
	sysB.WriteString("You are a plan-aware AI assistant for the cloop AI product manager.\n")
	sysB.WriteString("You help the user understand, analyse, and improve their project plan.\n")
	sysB.WriteString("Be concise, practical, and reference specific task IDs when relevant.\n\n")

	ps, _ := state.Load(workDir)
	if ps != nil && ps.Plan != nil {
		sysB.WriteString("## Current Plan\n")
		sysB.WriteString("**Goal:** " + ps.Goal + "\n\n")
		total := len(ps.Plan.Tasks)
		done, inProg, failed, pending := 0, 0, 0, 0
		for _, t := range ps.Plan.Tasks {
			switch t.Status {
			case pm.TaskDone:
				done++
			case pm.TaskInProgress:
				inProg++
			case pm.TaskFailed:
				failed++
			default:
				pending++
			}
		}
		fmt.Fprintf(&sysB, "**Progress:** %d/%d done, %d in-progress, %d pending, %d failed\n\n",
			done, total, inProg, pending, failed)
		sysB.WriteString("### Tasks\n")
		for _, t := range ps.Plan.Tasks {
			fmt.Fprintf(&sysB, "- [#%d] **%s** — status: `%s`, priority: %d", t.ID, t.Title, t.Status, t.Priority)
			if t.Assignee != "" {
				fmt.Fprintf(&sysB, ", assignee: %s", t.Assignee)
			}
			if t.EstimatedMinutes > 0 {
				fmt.Fprintf(&sysB, ", est: %dm", t.EstimatedMinutes)
			}
			if t.ActualMinutes > 0 {
				fmt.Fprintf(&sysB, ", actual: %dm", t.ActualMinutes)
			}
			if len(t.DependsOn) > 0 {
				fmt.Fprintf(&sysB, ", depends on: %v", t.DependsOn)
			}
			if t.Pinned {
				sysB.WriteString(", pinned")
			}
			sysB.WriteString("\n")
			if t.Description != "" {
				fmt.Fprintf(&sysB, "  %s\n", t.Description)
			}
			if len(t.Annotations) > 0 {
				sysB.WriteString("  annotations:\n")
				for _, a := range t.Annotations {
					fmt.Fprintf(&sysB, "    • [%s] %s\n", a.Author, a.Text)
				}
			}
		}
	} else {
		sysB.WriteString("No plan is currently initialised for this project.\n")
	}

	// Build conversation prompt.
	var convB strings.Builder
	for _, h := range req.History {
		switch h.Role {
		case "user":
			fmt.Fprintf(&convB, "Human: %s\n\n", h.Content)
		case "assistant":
			fmt.Fprintf(&convB, "Assistant: %s\n\n", h.Content)
		}
	}
	fmt.Fprintf(&convB, "Human: %s\n\nAssistant: ", msg)

	// Build provider.
	pName := cfg.Provider
	if pName == "" {
		pName = "claudecode"
	}
	provCfg := provider.ProviderConfig{
		Name:             pName,
		AnthropicAPIKey:  cfg.Anthropic.APIKey,
		AnthropicBaseURL: cfg.Anthropic.BaseURL,
		OpenAIAPIKey:     cfg.OpenAI.APIKey,
		OpenAIBaseURL:    cfg.OpenAI.BaseURL,
		OllamaBaseURL:    cfg.Ollama.BaseURL,
	}
	prov, buildErr := provider.Build(provCfg)
	if buildErr != nil {
		jsonErr(w, "provider: "+buildErr.Error(), http.StatusInternalServerError)
		return
	}

	model := ""
	switch pName {
	case "anthropic":
		model = cfg.Anthropic.Model
	case "openai":
		model = cfg.OpenAI.Model
	case "ollama":
		model = cfg.Ollama.Model
	case "claudecode":
		model = cfg.ClaudeCode.Model
	}

	// Start SSE response.
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	flusher.Flush()

	// Derive a cancellable ctx so a wedged-client write inside OnToken can
	// short-circuit the in-flight provider call instead of letting the
	// server keep streaming bytes nobody will ever read.
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	opts := provider.Options{
		Model:        model,
		SystemPrompt: sysB.String(),
		WorkDir:      workDir,
		Timeout:      2 * time.Minute,
		OnToken: func(token string) {
			d, _ := json.Marshal(map[string]string{"token": token})
			// Per-token write with deadline (sseWriteTimeout). On
			// failure (peer wedged, conn dropped), cancel the parent
			// ctx so prov.Complete returns promptly and we don't
			// continue serializing tokens to a dead connection.
			if werr := writeSSE(w, flusher, "event: token\ndata: %s\n\n", d); werr != nil {
				cancel()
			}
		},
	}

	_, callErr := prov.Complete(ctx, convB.String(), opts)
	if callErr != nil {
		d, _ := json.Marshal(map[string]string{"error": callErr.Error()})
		_ = writeSSE(w, flusher, "event: error\ndata: %s\n\n", d)
	} else {
		_ = writeSSE(w, flusher, "event: done\ndata: {}\n\n")
	}
}

// handleReset resets the project state by running `cloop reset`.
func (s *Server) handleReset(w http.ResponseWriter, r *http.Request) {
	if !requirePOST(w, r) {
		return
	}
	exe, err := os.Executable()
	if err != nil {
		exe = "cloop"
	}
	out, err := runCloopSubcommand(r.Context(), exe, s.resolveWorkDir(r), resetSubprocessTimeout, "reset")
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			msg = err.Error()
		}
		jsonErr(w, msg, http.StatusInternalServerError)
		return
	}
	jsonOK(w, map[string]bool{"ok": true})
}

// ── multi-project handlers ────────────────────────────────────────────────────

// projectsSnapshot returns a copy of s.Projects that is safe to range over
// without holding projectsMu, so readers never observe removeProjectsFlag's
// in-place compaction mid-iteration.
func (s *Server) projectsSnapshot() []string {
	s.projectsMu.RLock()
	defer s.projectsMu.RUnlock()
	return append([]string(nil), s.Projects...)
}

// allProjectEntries returns the union of Projects flag paths + registry.
func (s *Server) allProjectEntries() []multiui.ProjectEntry {
	seen := make(map[string]bool)
	var entries []multiui.ProjectEntry

	// Always include current WorkDir as the "primary" project.
	if s.WorkDir != "" {
		abs, _ := filepath.Abs(s.WorkDir)
		if !seen[abs] {
			seen[abs] = true
			entries = append(entries, multiui.ProjectEntry{
				Name: filepath.Base(abs),
				Path: abs,
			})
		}
	}

	// Paths from --projects / --scan flags.
	for _, p := range s.projectsSnapshot() {
		abs, err := filepath.Abs(p)
		if err != nil {
			continue
		}
		if seen[abs] {
			continue
		}
		seen[abs] = true
		entries = append(entries, multiui.ProjectEntry{
			Name: filepath.Base(abs),
			Path: abs,
		})
	}

	// Paths from persistent registry (~/.cloop/projects.json).
	registered, _ := multiui.Load()
	for _, e := range registered {
		abs, err := filepath.Abs(e.Path)
		if err != nil {
			continue
		}
		if seen[abs] {
			continue
		}
		seen[abs] = true
		name := e.Name
		if name == "" {
			name = filepath.Base(abs)
		}
		entries = append(entries, multiui.ProjectEntry{Name: name, Path: abs, Owner: e.Owner})
	}

	return entries
}

// refreshProjectStatuses rebuilds the projStatuses cache from disk.
func (s *Server) refreshProjectStatuses() {
	entries := s.allProjectEntries()
	statuses := make([]multiui.ProjectStatus, 0, len(entries))
	for _, e := range entries {
		statuses = append(statuses, multiui.GetStatus(e))
	}
	s.projMu.Lock()
	s.projStatuses = statuses
	s.projMu.Unlock()
}

// watchProjects polls state files for all registered projects and broadcasts
// updates to SSE clients on change. It returns when ctx is cancelled so Run
// can shut down cleanly instead of leaking the polling goroutine.
func (s *Server) watchProjects(ctx context.Context) {
	s.projLastMod = make(map[string]time.Time)
	s.refreshProjectStatuses()

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		func() {
			defer recoverGoroutine("watchProjects iteration")
			var changedPaths []string
			for _, e := range s.allProjectEntries() {
				statePath := filepath.Join(e.Path, ".cloop", "state.json")
				fi, err := os.Stat(statePath)
				if err != nil {
					// Also try state.db.
					statePath = filepath.Join(e.Path, ".cloop", "state.db")
					fi, err = os.Stat(statePath)
				}
				if err != nil {
					continue
				}
				prev := s.projLastMod[e.Path]
				if !fi.ModTime().Equal(prev) {
					s.projLastMod[e.Path] = fi.ModTime()
					changedPaths = append(changedPaths, e.Path)
				}
			}
			if len(changedPaths) > 0 {
				s.refreshProjectStatuses()
				s.broadcastProjectsUpdate()

				// Task 20134: push a state_diff for every project whose state
				// file changed so subscribers receive the delta over WebSocket
				// without having to refetch /api/state. Primary project diffs
				// are already handled by watchState (1s cadence); skipping it
				// here avoids a duplicate cache lookup. Only load state for
				// projects with active WebSocket subscribers to keep the
				// secondary-project case zero-cost when nobody is watching.
				primaryAbs, _ := filepath.Abs(s.WorkDir)
				for _, path := range changedPaths {
					if path == primaryAbs {
						continue
					}
					s.hubMu.Lock()
					hasSubs := len(s.hubClients[path]) > 0
					s.hubMu.Unlock()
					if !hasSubs {
						continue
					}
					if ps, err := state.LoadLite(path); err == nil {
						s.broadcastStateDiff(path, ps)
					}
				}
			}

			// Independently of state-file changes, sample running status for each
			// project so externally-started cloop processes flip the Run/Stop
			// buttons without the client having to poll /api/livelog. handleRun
			// already pushes a forced run_state on internal start; this loop
			// catches in-flight transitions and externally-started runs.
			for _, e := range s.allProjectEntries() {
				s.broadcastRunState(e.Path, multiui.IsCloopRunningInDir(e.Path), false)
			}
		}()
	}
}

// broadcastProjectsUpdate sends the updated project statuses to SSE and
// WebSocket clients. With OIDC enabled each client receives the list
// filtered to what its session user may see; payloads are marshalled once
// per distinct visibility (not once per client). With OIDC disabled every
// client shares the unfiltered payload, exactly as before.
func (s *Server) broadcastProjectsUpdate() {
	s.projMu.RLock()
	statuses := s.projStatuses
	s.projMu.RUnlock()

	var entries []multiui.ProjectEntry
	if s.oidcEnabled() {
		entries = s.allProjectEntries()
	}
	payloads := make(map[string][]byte, 1)
	payloadFor := func(user *oidcauth.Identity, tok *apitoken.Token) []byte {
		key := s.visibilityKey(user, tok)
		if p, ok := payloads[key]; ok {
			return p
		}
		visible, stats := s.filterStatusesForRecipient(user, tok, entries, statuses)
		p, err := json.Marshal(map[string]interface{}{
			"projects": visible,
			"stats":    stats,
		})
		if err != nil {
			p = nil
		}
		payloads[key] = p
		return p
	}
	// Pre-warm the unfiltered payload outside the client locks — it serves
	// every client when OIDC is off (and all token/admin clients otherwise).
	if payloadFor(nil, nil) == nil && !s.oidcEnabled() {
		return
	}

	s.mu.Lock()
	for c := range s.clients {
		if p := payloadFor(c.user, c.token); p != nil {
			s.sendSSEOrLag(c, sseEvent{Event: "projects", Data: string(p)})
		}
	}
	s.mu.Unlock()

	s.hubMu.Lock()
	for _, clients := range s.hubClients {
		for hc := range clients {
			if p := payloadFor(hc.user, hc.token); p != nil {
				s.sendOrLag(hc, wsMessage{Type: "projects", Data: json.RawMessage(p)})
			}
		}
	}
	s.hubMu.Unlock()
}

// handleQueue returns recent entries from the central work queue scoped
// to the resolved project workdir. Every PM task execution, auto-heal retry,
// evolve discovery cycle, and externally-merged task is recorded here so the
// UI can render a single auditable activity log.
//
// Query params:
//   - project_idx: index into the multi-project registry (resolved by resolveWorkDir)
//   - limit: max rows (default defaultQueueLimit, hard cap maxQueueLimit)
//   - offset: pagination offset (default 0)
//   - status: filter by lifecycle state (queued|running|done|failed|skipped)
//   - kind:   filter by entry kind (task|heal|evolve|external|session)
//   - task_id: filter rows tied to a specific plan task id
//
// Row bounds for /api/queue, previously documented but never enforced.
const (
	defaultQueueLimit = 200
	maxQueueLimit     = 1000
)

func (s *Server) handleQueue(w http.ResponseWriter, r *http.Request) {
	workDir := s.resolveWorkDir(r)
	q, err := taskqueue.Open(workDir)
	if err != nil {
		jsonErr(w, "queue unavailable: "+err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer q.Close()

	opts := taskqueue.ListOptions{Limit: defaultQueueLimit}
	qs := r.URL.Query()
	if v := qs.Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			opts.Limit = n
		}
	}
	// The doc comment above has always promised this cap; the handler never
	// implemented it, leaving pkg/taskqueue's 5000 as the real bound and the
	// echoed value a fiction (Task 20188).
	if opts.Limit > maxQueueLimit {
		opts.Limit = maxQueueLimit
	}
	if v := qs.Get("offset"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			opts.Offset = n
		}
	}
	if v := qs.Get("status"); v != "" {
		opts.Status = taskqueue.Status(v)
	}
	if v := qs.Get("kind"); v != "" {
		opts.Kind = taskqueue.Kind(v)
	}
	if v := qs.Get("task_id"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			opts.TaskID = n
		}
	}

	entries, err := q.List(opts)
	if err != nil {
		jsonErr(w, "queue list failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if entries == nil {
		entries = []taskqueue.Entry{}
	}
	jsonOK(w, map[string]interface{}{
		"entries": entries,
		"limit":   opts.Limit,
		"offset":  opts.Offset,
	})
}

// handleQueueStats returns counts of queue rows grouped by lifecycle status
// (queued/running/done/failed/skipped) for the resolved project workdir.
// The Web UI uses this to render the queue header summary without fetching
// the full entry list.
func (s *Server) handleQueueStats(w http.ResponseWriter, r *http.Request) {
	workDir := s.resolveWorkDir(r)
	q, err := taskqueue.Open(workDir)
	if err != nil {
		jsonErr(w, "queue unavailable: "+err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer q.Close()

	stats, err := q.Stats()
	if err != nil {
		jsonErr(w, "queue stats failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	out := map[string]int{
		"queued":  stats[taskqueue.StatusQueued],
		"running": stats[taskqueue.StatusRunning],
		"done":    stats[taskqueue.StatusDone],
		"failed":  stats[taskqueue.StatusFailed],
		"skipped": stats[taskqueue.StatusSkipped],
	}
	jsonOK(w, out)
}

// replayRunSummary is the wire-format of one replay row in a list response.
// Long fields (prompt, outputs) are omitted from the list to keep payloads
// small; the detail endpoint returns the full row.
type replayRunSummary struct {
	ID                   int64   `json:"id"`
	CreatedAt            string  `json:"created_at"`
	TaskID               int     `json:"task_id"`
	TaskTitle            string  `json:"task_title"`
	OriginalProvider     string  `json:"original_provider"`
	OriginalModel        string  `json:"original_model"`
	TargetProvider       string  `json:"target_provider"`
	TargetModel          string  `json:"target_model"`
	SimilarityScore      float64 `json:"similarity_score"`
	EquivalenceScore     int     `json:"equivalence_score"`
	EquivalenceRationale string  `json:"equivalence_rationale,omitempty"`
	DurationMS           int64   `json:"duration_ms"`
	InputTokens          int     `json:"input_tokens"`
	OutputTokens         int     `json:"output_tokens"`
	Error                string  `json:"error,omitempty"`
}

// handleReplayRunsList returns the replay history for the project.
// Optional ?task_id=N filters to one task; ?limit=N caps the result count
// (default 100, max 500).
func (s *Server) handleReplayRunsList(w http.ResponseWriter, r *http.Request) {
	workDir := s.resolveWorkDir(r)

	taskID := 0
	if v := r.URL.Query().Get("task_id"); v != "" {
		if id, err := strconv.Atoi(v); err == nil && id > 0 {
			taskID = id
		}
	}
	limit := 100
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			if n > 500 {
				n = 500
			}
			limit = n
		}
	}

	rows, err := taskreplay.ListRuns(workDir, taskID, limit)
	if err != nil {
		jsonErr(w, "list replay runs: "+err.Error(), http.StatusInternalServerError)
		return
	}

	out := make([]replayRunSummary, 0, len(rows))
	for _, run := range rows {
		out = append(out, replayRunSummary{
			ID:                   run.ID,
			CreatedAt:            run.CreatedAt.Format(time.RFC3339),
			TaskID:               run.TaskID,
			TaskTitle:            run.TaskTitle,
			OriginalProvider:     run.OriginalProvider,
			OriginalModel:        run.OriginalModel,
			TargetProvider:       run.TargetProvider,
			TargetModel:          run.TargetModel,
			SimilarityScore:      run.SimilarityScore,
			EquivalenceScore:     run.EquivalenceScore,
			EquivalenceRationale: run.EquivalenceRationale,
			DurationMS:           run.DurationMS,
			InputTokens:          run.InputTokens,
			OutputTokens:         run.OutputTokens,
			Error:                run.Error,
		})
	}
	jsonOK(w, map[string]interface{}{"runs": out, "count": len(out)})
}

// handleReplayRunGet returns a single replay row including the full prompt,
// original output, and replayed output for the side-by-side diff view.
func (s *Server) handleReplayRunGet(w http.ResponseWriter, r *http.Request) {
	workDir := s.resolveWorkDir(r)
	idStr := r.PathValue("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil || id <= 0 {
		jsonErr(w, "invalid replay id", http.StatusBadRequest)
		return
	}
	run, err := taskreplay.GetRun(workDir, id)
	if err != nil {
		jsonErr(w, err.Error(), http.StatusNotFound)
		return
	}
	jsonOK(w, map[string]interface{}{
		"id":                    run.ID,
		"created_at":            run.CreatedAt.Format(time.RFC3339),
		"task_id":               run.TaskID,
		"task_title":            run.TaskTitle,
		"original_provider":     run.OriginalProvider,
		"original_model":        run.OriginalModel,
		"target_provider":       run.TargetProvider,
		"target_model":          run.TargetModel,
		"prompt":                run.Prompt,
		"original_output":       run.OriginalOutput,
		"replayed_output":       run.ReplayedOutput,
		"similarity_score":      run.SimilarityScore,
		"equivalence_score":     run.EquivalenceScore,
		"equivalence_rationale": run.EquivalenceRationale,
		"duration_ms":           run.DurationMS,
		"input_tokens":          run.InputTokens,
		"output_tokens":         run.OutputTokens,
		"error":                 run.Error,
	})
}

// handleReplayRunCreate triggers a new replay and returns the result.
// Body: {"task_id": 42, "provider": "anthropic", "model": "claude-opus-4-5",
//
//	"judge": "anthropic:claude-opus-4-5"}
//
// The replay is performed synchronously: this can take minutes for slow
// providers, so the request timeout should be generous (the per-call timeout
// is 5 minutes by default).
func (s *Server) handleReplayRunCreate(w http.ResponseWriter, r *http.Request) {
	workDir := s.resolveWorkDir(r)
	// Replay assembles task context in-process, which shells out to git in
	// the project directory. That is host execution driven by an HTTP
	// request, so strict mode refuses it.
	if denyHostSideEffect(w, workDir, "git (inline task replay)") {
		return
	}
	limitJSONBody(w, r, maxJSONBodyBytes)

	var req struct {
		TaskID    int    `json:"task_id"`
		Provider  string `json:"provider"`
		Model     string `json:"model"`
		Judge     string `json:"judge"` // "<provider>:<model>" or empty
		MaxTokens int    `json:"max_tokens"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, "invalid JSON body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.TaskID <= 0 {
		jsonErr(w, "task_id is required", http.StatusBadRequest)
		return
	}
	if req.Provider == "" {
		jsonErr(w, "provider is required", http.StatusBadRequest)
		return
	}

	cfg, err := config.Load(workDir)
	if err != nil {
		jsonErr(w, "load config: "+err.Error(), http.StatusInternalServerError)
		return
	}

	target, err := buildReplayProvider(cfg, req.Provider)
	if err != nil {
		jsonErr(w, "build target provider: "+err.Error(), http.StatusBadRequest)
		return
	}

	var (
		judge      provider.Provider
		judgeModel string
	)
	if req.Judge != "" {
		jName, jModel, ok := splitProviderModelToken(req.Judge)
		if !ok {
			jsonErr(w, "judge must be 'provider:model'", http.StatusBadRequest)
			return
		}
		judge, err = buildReplayProvider(cfg, jName)
		if err != nil {
			jsonErr(w, "build judge provider: "+err.Error(), http.StatusBadRequest)
			return
		}
		judgeModel = jModel
	}

	// Generous timeout for the synchronous call; the underlying provider
	// honours ctx, so request cancellation propagates naturally.
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Minute)
	defer cancel()

	res, err := taskreplay.ReplayTask(ctx, workDir, req.TaskID, taskreplay.Options{
		Target:      target,
		TargetName:  req.Provider,
		TargetModel: req.Model,
		MaxTokens:   req.MaxTokens,
		Timeout:     5 * time.Minute,
		Judge:       judge,
		JudgeModel:  judgeModel,
	})
	if err != nil {
		jsonErr(w, "replay: "+err.Error(), http.StatusInternalServerError)
		return
	}
	jsonOK(w, map[string]interface{}{
		"task_id":               res.TaskID,
		"task_title":            res.TaskTitle,
		"original_provider":     res.OriginalProvider,
		"original_model":        res.OriginalModel,
		"target_provider":       res.TargetProvider,
		"target_model":          res.TargetModel,
		"similarity_score":      res.SimilarityScore,
		"equivalence_score":     res.EquivalenceScore,
		"equivalence_rationale": res.EquivalenceRationale,
		"duration_ms":           res.Duration.Milliseconds(),
		"input_tokens":          res.InputTokens,
		"output_tokens":         res.OutputTokens,
		"error":                 res.Err,
	})
}

// buildReplayProvider mirrors cmd/task_replay.go's helper but lives in the
// ui package to avoid an import cycle with cmd.
func buildReplayProvider(cfg *config.Config, name string) (provider.Provider, error) {
	if name == "" {
		return nil, errors.New("provider name required")
	}
	provCfg := provider.ProviderConfig{
		Name:             name,
		AnthropicAPIKey:  cfg.Anthropic.APIKey,
		AnthropicBaseURL: cfg.Anthropic.BaseURL,
		OpenAIAPIKey:     cfg.OpenAI.APIKey,
		OpenAIBaseURL:    cfg.OpenAI.BaseURL,
		OllamaBaseURL:    cfg.Ollama.BaseURL,
	}
	return provider.Build(provCfg)
}

// splitProviderModelToken parses "<provider>:<model>" into its parts.
func splitProviderModelToken(s string) (string, string, bool) {
	i := strings.Index(s, ":")
	if i <= 0 || i == len(s)-1 {
		return "", "", false
	}
	return s[:i], s[i+1:], true
}

// handleProjects returns all project statuses and aggregate stats.
func (s *Server) handleProjects(w http.ResponseWriter, r *http.Request) {
	s.refreshProjectStatuses()
	s.projMu.RLock()
	statuses := s.projStatuses
	s.projMu.RUnlock()
	// With OIDC enabled, scope the list (and the aggregate stats) to the
	// projects the session user may see. Entries are only needed for their
	// ownership metadata, so skip the registry read entirely when OIDC is off.
	var entries []multiui.ProjectEntry
	if s.oidcEnabled() {
		entries = s.allProjectEntries()
	}
	statuses, stats := s.filterStatusesForRecipient(s.sessionIdentity(r), tokenFromRequest(r), entries, statuses)
	// multi_project is true when there are multiple registered projects so the
	// frontend can enable the scoped-tabs experience.
	multiProject := len(statuses) > 1 || len(s.projectsSnapshot()) > 0
	jsonOK(w, map[string]interface{}{
		"projects":      statuses,
		"stats":         stats,
		"multi_project": multiProject,
	})
}

// handleProjectsEvents is an SSE endpoint for multi-project updates.
func (s *Server) handleProjectsEvents(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "SSE not supported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	c := &sseClient{
		ch:      make(chan sseEvent, sseClientBufferSize),
		resync:  make(chan struct{}, 1),
		user:    s.sessionIdentity(r),
		token:   tokenFromRequest(r),
		workDir: s.resolveWorkDir(r),
	}
	s.mu.Lock()
	s.clients[c] = struct{}{}
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.clients, c)
		s.mu.Unlock()
	}()

	// Send current snapshot immediately, scoped to the session user when
	// OIDC is enabled.
	s.projMu.RLock()
	statuses := s.projStatuses
	s.projMu.RUnlock()
	var entries []multiui.ProjectEntry
	if s.oidcEnabled() {
		entries = s.allProjectEntries()
	}
	statuses, stats := s.filterStatusesForRecipient(c.user, c.token, entries, statuses)
	if payload, err := json.Marshal(map[string]interface{}{"projects": statuses, "stats": stats}); err == nil {
		if werr := writeSSE(w, flusher, "event: projects\ndata: %s\n\n", payload); werr != nil {
			return
		}
	}

	ctx := r.Context()
	keepalive := time.NewTicker(sseKeepaliveInterval)
	defer keepalive.Stop()
	for {
		select {
		case <-c.resync:
			drainSSE(c.ch)
			if werr := writeSSE(w, flusher, "event: resync\ndata: {\"reason\":\"lagged\"}\n\n"); werr != nil {
				return
			}
			continue
		default:
		}
		select {
		case <-ctx.Done():
			return
		case <-c.resync:
			drainSSE(c.ch)
			if werr := writeSSE(w, flusher, "event: resync\ndata: {\"reason\":\"lagged\"}\n\n"); werr != nil {
				return
			}
		case <-keepalive.C:
			if werr := writeSSE(w, flusher, ": keepalive\n\n"); werr != nil {
				return
			}
		case ev := <-c.ch:
			if ev.Event == "projects" {
				if werr := writeSSE(w, flusher, "event: projects\ndata: %s\n\n", ev.Data); werr != nil {
					return
				}
			}
		}
	}
}

// handleProjectRun starts a `cloop run` in the specified project directory.
func (s *Server) handleProjectRun(w http.ResponseWriter, r *http.Request) {
	idx, err := strconv.Atoi(r.PathValue("idx"))
	if err != nil {
		jsonErr(w, "invalid project index", http.StatusBadRequest)
		return
	}
	entries := s.visibleProjectEntries(r)
	if idx < 0 || idx >= len(entries) {
		jsonErr(w, "project index out of range", http.StatusBadRequest)
		return
	}
	entry := entries[idx]

	var req struct {
		PM bool `json:"pm"`
	}
	if ct := r.Header.Get("Content-Type"); strings.Contains(ct, "application/json") {
		limitJSONBody(w, r, maxJSONBodyBytes)
		_ = json.NewDecoder(r.Body).Decode(&req)
	}

	exe, err := os.Executable()
	if err != nil {
		exe = "cloop"
	}
	args := []string{"run"}
	if req.PM {
		args = append(args, "--pm")
	}
	// Dispatched to the project's bound executor rather than forked here
	// (Task 20156).
	ex, handle, err := startWorkload(entry.Path, append([]string{exe}, args...),
		map[string]string{"handler": "project-run", "project_name": entry.Name})
	if err != nil {
		jsonWorkloadErr(w, err)
		return
	}
	// Echo the run's output into the server log, which is what
	// cmd.Stdout = os.Stderr used to do.
	if lines, streamErr := ex.Stream(context.Background(), handle.ID); streamErr == nil {
		go drainToStderr(lines, "project-run "+entry.Name)
	}
	// Push immediate run_state + projects events so the UI updates the
	// Run/Stop button and project card without waiting for the 2s
	// watchProjects ticker. Replaces the client-side setTimeout(loadProjects)
	// pseudo-poll (Task 20126).
	s.broadcastRunState(entry.Path, true, true)
	s.refreshProjectStatuses()
	s.broadcastProjectsUpdate()
	jsonOK(w, map[string]interface{}{"ok": true, "project": entry.Name, "command": strings.Join(args, " ")})
}

// handleProjectStop sends SIGINT to `cloop run` processes in the given project directory.
func (s *Server) handleProjectStop(w http.ResponseWriter, r *http.Request) {
	idx, err := strconv.Atoi(r.PathValue("idx"))
	if err != nil {
		jsonErr(w, "invalid project index", http.StatusBadRequest)
		return
	}
	entries := s.visibleProjectEntries(r)
	if idx < 0 || idx >= len(entries) {
		jsonErr(w, "project index out of range", http.StatusBadRequest)
		return
	}
	entry := entries[idx]
	// Project-scoped: only signal cloop run processes whose cwd matches
	// entry.Path. The pre-fix implementation shelled out to
	// `pkill -SIGINT -f "cloop run"`, which signalled *every* cloop run on
	// the host — pressing stop on project A killed runs for B, C, etc.
	pids := multiui.CloopRunPIDsInDir(entry.Path)
	if len(pids) == 0 {
		// No live process: if state still claims the project is running (the
		// run died without writing a terminal status), clear it so the card
		// stops offering a Stop button that can never succeed (Task 20153).
		if s.reconcileStaleRunState(entry.Path) {
			jsonOK(w, map[string]interface{}{"ok": true, "project": entry.Name, "message": "no running process found — cleared stale running status"})
			return
		}
		jsonOK(w, map[string]interface{}{"ok": false, "project": entry.Name, "message": "no running process found"})
		return
	}
	signalled := signalPIDs(pids, syscall.SIGINT)
	if signalled == 0 {
		jsonOK(w, map[string]interface{}{"ok": false, "project": entry.Name, "message": "found cloop processes but signalling failed (permission denied?)"})
		return
	}
	// SIGINT was delivered but the child may take a moment to exit. Watch for
	// the exit and re-broadcast run_state + projects so the UI reflects the
	// stop without client polling (Task 20126).
	s.observeRunExit(entry.Path)
	jsonOK(w, map[string]interface{}{"ok": true, "project": entry.Name, "signalled": signalled})
}

// handleProjectNew creates a new cloop project directory, initialises it, and
// registers it in the multi-project registry so it appears in the dashboard.
//
// POST /api/projects/new
// Body: { "dir": "/abs/or/relative/path", "goal": "...", "provider": "...",
//
//	"model": "...", "pmMode": false, "autoRun": false }
func (s *Server) handleProjectNew(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Dir      string `json:"dir"`
		Goal     string `json:"goal"`
		Provider string `json:"provider"`
		Model    string `json:"model"`
		Effort   string `json:"effort"`
		PMMode   bool   `json:"pmMode"`
		AutoRun  bool   `json:"autoRun"`
		// Access is the executor and the grants the project should have on
		// creation (Task 20187). Absent means an ordinary project on the
		// default executor with no credentials, which is what every existing
		// client sends.
		projectAccessRequest
	}
	limitJSONBody(w, r, maxJSONBodyBytes)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondToBodyError(w, err)
		return
	}
	req.Goal = strings.TrimSpace(req.Goal)
	req.Dir = strings.TrimSpace(req.Dir)
	if req.Goal == "" {
		jsonErr(w, "goal is required", http.StatusBadRequest)
		return
	}
	if req.Dir == "" {
		jsonErr(w, "dir is required", http.StatusBadRequest)
		return
	}
	if !provider.ValidEffort(req.Effort) {
		jsonErr(w, "invalid effort "+strconv.Quote(req.Effort)+" — valid: "+strings.Join(provider.EffortLevels, ", "), http.StatusBadRequest)
		return
	}

	// Access (Task 20187): the executor to pin to and the grants to open. Both
	// are gated on their own permissions rather than riding in on this route's
	// project.write — see provision.go — and both are validated before
	// anything exists on disk, so a mistyped secret name costs nothing.
	access := req.projectAccessRequest
	var accessBrokers *brokerSet
	if access.requested() {
		if !s.authorizeProjectAccess(w, r, access) {
			return
		}
		if len(access.Grants) > 0 {
			bs, ok := s.openBrokersOr(w)
			if !ok {
				return
			}
			defer bs.close()
			accessBrokers = bs
		}
		if err := validateProjectAccess(accessBrokers, access); err != nil {
			jsonErr(w, err.Error(), http.StatusBadRequest)
			return
		}
	}

	// Admission (Task 20182), after validation and before anything is
	// created on disk. Not transient: a tenant at their project cap has to
	// delete one or be given a bigger cap, so this answers 403 rather than
	// 429 and carries no Retry-After.
	quotaID := s.quotaIdentity(r)
	if !s.admitQuota(w, r, quota.ResProjects, 1) {
		return
	}
	projectAdmitted := true
	releaseProject := func() {
		if projectAdmitted {
			projectAdmitted = false
			s.releaseQuota(quotaID, quota.ResProjects, 1)
		}
	}

	// Resolve to absolute path.
	abs, err := filepath.Abs(req.Dir)
	if err != nil {
		releaseProject()
		jsonErr(w, "invalid dir: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Confine the target before creating anything (Task 20188). A relative
	// dir resolves against the *server's* cwd, so "../../../.." escaped
	// freely; an absolute one landed wherever it pointed. The registered
	// path then becomes the workdir for every later ?project_idx= call and
	// the target of ?delete_root=true, so this is the moment to refuse.
	if !isSafeProjectRoot(abs) {
		releaseProject()
		jsonErr(w, "refusing to create a project at "+strconv.Quote(abs)+
			": system directories and bare top-level directories are not valid project roots",
			http.StatusBadRequest)
		return
	}

	// Create the directory if it does not exist.
	if err := os.MkdirAll(abs, 0o755); err != nil {
		releaseProject()
		jsonErr(w, "cannot create dir: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Run `cloop init <goal>` in that directory.
	exe, err := os.Executable()
	if err != nil {
		exe = "cloop"
	}
	args := []string{"init", req.Goal, "--skip-clarify"}
	if req.Provider != "" {
		args = append(args, "--provider", req.Provider)
	}
	if req.Model != "" {
		args = append(args, "--model", req.Model)
	}
	if req.Effort != "" {
		args = append(args, "--effort", req.Effort)
	}
	// `cloop init` is synchronous: the caller needs its output to report a
	// failure, and the project must exist before it can be registered.
	//
	// Deliberately detached from r.Context(): a client that navigates away
	// mid-init must not leave a half-initialised project behind. The
	// timeout still bounds it, which the pre-executor CombinedOutput() call
	// did not.
	initCtx, cancelInit := context.WithTimeout(context.WithoutCancel(r.Context()), initSubprocessTimeout)
	defer cancelInit()
	if out, initErr := runWorkload(initCtx, abs, append([]string{exe}, args...),
		map[string]string{"handler": "project-new"}); initErr != nil {
		releaseProject()
		if errors.Is(initErr, executor.ErrHostExecutionDenied) {
			jsonWorkloadErr(w, initErr)
			return
		}
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			msg = initErr.Error()
		}
		jsonErr(w, "cloop init failed: "+msg, http.StatusInternalServerError)
		return
	}

	// Bind the executor and open the grants. After init, because init writes
	// .cloop/ and has to run where the hub can read it — not on the remote
	// executor this project may be about to be pinned to.
	//
	// A failure here rolls the access back and fails the request: "create a
	// project with access to my cluster" is one intention, and half of it is
	// not a useful thing to hand back. The directory stays, because this code
	// may not have created it and deleting a developer's tree to tidy up a
	// failed API call is worse than anything it would clean up after.
	if access.requested() {
		rollback, accessErr := s.applyProjectAccess(r, accessBrokers, abs, access)
		if accessErr != nil {
			rollback()
			releaseProject()
			jsonErr(w, "project initialised but access could not be provisioned, "+
				"so it was rolled back: "+accessErr.Error(), http.StatusInternalServerError)
			return
		}
	}

	// Register the new project in the multi-project registry. With OIDC
	// enabled the entry is stamped with the creating user's identity, making
	// the project private to that user (plus admins); without OIDC the owner
	// is empty and the project is shared, as before.
	if regErr := multiui.AddPathsOwned([]string{abs}, s.sessionIdentity(r).OwnerKey()); regErr != nil {
		// Non-fatal: project is created, just not registered.
		_ = regErr
	}

	// Optionally start a run immediately.
	if req.AutoRun {
		runArgs := []string{"run"}
		if req.PMMode {
			runArgs = append(runArgs, "--pm")
		}
		runEx, runHandle, startErr := startWorkload(abs, append([]string{exe}, runArgs...),
			map[string]string{"handler": "project-new-autorun"})
		if startErr != nil {
			// Non-fatal: the project was created successfully, only the
			// optional immediate run failed. Surfacing it in the server log
			// beats silently swallowing it as the pre-executor code did.
			fmt.Fprintf(os.Stderr, "ui: auto-run for new project %s failed to start: %v\n", abs, startErr)
		} else if lines, streamErr := runEx.Stream(context.Background(), runHandle.ID); streamErr == nil {
			go drainToStderr(lines, "auto-run "+abs)
		}
	}

	// Refresh project cache and return updated project list. The index is
	// resolved against the creator's visible list so it matches what their
	// frontend will render.
	s.refreshProjectStatuses()
	entries := s.visibleProjectEntries(r)
	newIdx := -1
	for i, e := range entries {
		if e.Path == abs {
			newIdx = i
			break
		}
	}

	jsonOK(w, map[string]interface{}{"ok": true, "dir": abs, "project_idx": newIdx})
}

// handleProjectDelete removes a project from the multi-project registry. When
// ?delete_root=true is supplied (or {"delete_root": true} in the JSON body),
// the project's root directory is also removed from disk after the registry
// entry is dropped — destructive, so the Web UI confirms before sending it.
//
// DELETE /api/projects/{idx}[?delete_root=true]
//
// Refusals:
//   - the project at idx is the UI server's own WorkDir (would break the
//     running server),
//   - a cloop run process is currently executing in the project directory
//     (the user must stop it first to avoid a half-deleted-mid-run state).
func (s *Server) handleProjectDelete(w http.ResponseWriter, r *http.Request) {
	idx, err := strconv.Atoi(r.PathValue("idx"))
	if err != nil {
		jsonErr(w, "invalid project index", http.StatusBadRequest)
		return
	}
	entries := s.visibleProjectEntries(r)
	if idx < 0 || idx >= len(entries) {
		jsonErr(w, "project index out of range", http.StatusBadRequest)
		return
	}
	entry := entries[idx]

	// Parse delete_root from either query string or JSON body so the same
	// endpoint serves both URL-style callers and the UI's fetch wrapper.
	deleteRoot := r.URL.Query().Get("delete_root") == "true"
	if ct := r.Header.Get("Content-Type"); strings.Contains(ct, "application/json") {
		var req struct {
			DeleteRoot bool `json:"delete_root"`
		}
		limitJSONBody(w, r, maxJSONBodyBytes)
		if err := json.NewDecoder(r.Body).Decode(&req); err == nil {
			deleteRoot = deleteRoot || req.DeleteRoot
		}
	}

	// Safety: refuse to delete the UI server's own working directory.
	if s.WorkDir != "" {
		absWork, _ := filepath.Abs(s.WorkDir)
		if entry.Path == absWork {
			jsonErr(w, "cannot delete the project the UI server was launched from", http.StatusBadRequest)
			return
		}
	}

	// Safety: refuse to delete a project with an active cloop run.
	if multiui.IsCloopRunningInDir(entry.Path) {
		jsonErr(w, "project has an active cloop run — stop it first", http.StatusConflict)
		return
	}

	// Remove from the persistent registry. This is a no-op for entries that
	// only live in the in-process Projects slice or are derived from
	// s.WorkDir, but we already refused the latter above.
	if err := multiui.RemovePath(entry.Path); err != nil {
		jsonErr(w, "failed to update registry: "+err.Error(), http.StatusInternalServerError)
		return
	}
	// Give the owner their project slot back (Task 20182). Keyed on the
	// entry's recorded owner rather than on the caller, so an admin
	// deleting somebody else's project credits the right tenant.
	s.releaseQuota(entry.Owner, quota.ResProjects, 1)

	// Drop the in-memory --projects flag entry (if any) so the next
	// allProjectEntries() call doesn't resurrect this project until the
	// server restarts.
	s.removeProjectsFlag(entry.Path)

	// Drop the project's buffered live output. Without this the bytes sit in
	// memory for the daemon's lifetime and would replay to whoever next
	// registers this path — a deleted project is exactly the case where
	// "nobody is watching, so it can wait for LRU eviction" is wrong
	// (Task 20189).
	s.liveLogEvict(entry.Path)

	rootDeleted := false
	if deleteRoot {
		// Defensive path validation: refuse to recursively delete obviously
		// dangerous targets (filesystem root, $HOME, an empty/relative path)
		// even though the registry should only contain absolute project dirs.
		if !isSafeProjectRoot(entry.Path) {
			jsonErr(w, "refusing to delete unsafe path: "+entry.Path, http.StatusBadRequest)
			return
		}
		if err := os.RemoveAll(entry.Path); err != nil {
			// Registry entry is already gone; surface the disk error to the
			// caller so they see why the dir is still on disk.
			jsonErr(w, "registry entry removed, but failed to delete dir: "+err.Error(), http.StatusInternalServerError)
			return
		}
		rootDeleted = true
	}

	// Notify all connected clients so the projects list refreshes.
	s.refreshProjectStatuses()
	s.broadcastProjectsUpdate()

	jsonOK(w, map[string]interface{}{
		"ok":           true,
		"project":      entry.Name,
		"path":         entry.Path,
		"root_deleted": rootDeleted,
	})
}

// removeProjectsFlag drops the given absolute path from the in-memory
// s.Projects slice (the --projects/--scan CLI flag list). Called after a
// delete so the path doesn't reappear on the next allProjectEntries() rebuild.
// No-op when the path was not present.
func (s *Server) removeProjectsFlag(absPath string) {
	s.projectsMu.Lock()
	defer s.projectsMu.Unlock()
	if len(s.Projects) == 0 {
		return
	}
	filtered := s.Projects[:0]
	for _, p := range s.Projects {
		abs, err := filepath.Abs(p)
		if err == nil && abs == absPath {
			continue
		}
		filtered = append(filtered, p)
	}
	s.Projects = filtered
}

// systemSubtrees are directories that are never a valid project root, at any
// depth. Anything under them belongs to the OS or the container image.
var systemSubtrees = []string{
	"/bin", "/boot", "/dev", "/etc", "/lib", "/lib32", "/lib64", "/libx32",
	"/proc", "/run", "/sbin", "/sys", "/usr",
}

// isSafeProjectRoot reports whether path is an acceptable project root — and
// therefore an acceptable target for `cloop init` and, with explicit
// confirmation, for recursive deletion.
//
// It is used by both POST /api/projects/new and
// DELETE /api/projects/{idx}?delete_root=true. Sharing one predicate across
// creation and deletion is deliberate (Task 20188): previously only the
// delete path was guarded, and only against "", relative paths, "/" and
// $HOME. /etc, /usr and /var all passed as "safe". Because os.MkdirAll
// returns nil for a directory that already exists, an unguarded create
// followed by a guarded delete was an arbitrary-directory-deletion primitive
// available to any caller holding project.write.
//
// The rules, in order:
//   - must be an absolute, non-empty path;
//   - never the filesystem root or $HOME itself;
//   - never inside a system subtree (see systemSubtrees);
//   - never a bare top-level directory. /var is refused while
//     /var/lib/cloop/projects/demo is allowed — the latter is where the
//     packaged hub image puts its state, so this must keep working.
func isSafeProjectRoot(path string) bool {
	if path == "" || !filepath.IsAbs(path) {
		return false
	}
	clean := filepath.Clean(path)
	if clean == "/" || clean == "." {
		return false
	}
	if home, err := os.UserHomeDir(); err == nil {
		if cleanHome := filepath.Clean(home); cleanHome != "" && clean == cleanHome {
			return false
		}
	}
	for _, sub := range systemSubtrees {
		if clean == sub || strings.HasPrefix(clean, sub+"/") {
			return false
		}
	}
	// A bare top-level directory (/var, /home, /tmp, /opt, …) is a shared
	// mount point, never one project's root. Depth is measured on the
	// cleaned absolute path, so "/var" has one segment and "/var/x" two.
	if len(strings.Split(strings.TrimPrefix(clean, "/"), "/")) < 2 {
		return false
	}
	return true
}

// ── Knowledge Base handlers ──────────────────────────────────────────────────

// handleKBList returns all KB entries as JSON (GET /api/kb).
func (s *Server) handleKBList(w http.ResponseWriter, r *http.Request) {
	workDir := s.resolveWorkDir(r)
	store, err := kb.Load(workDir)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	entries := store.Entries
	if entries == nil {
		entries = []*kb.Entry{}
	}
	jsonOK(w, map[string]interface{}{"entries": entries})
}

// handleKBAdd creates a new KB entry (POST /api/kb).
// Body: { "title": "...", "body": "...", "tags": ["a","b"] }
func (s *Server) handleKBAdd(w http.ResponseWriter, r *http.Request) {
	workDir := s.resolveWorkDir(r)
	var req struct {
		Title string   `json:"title"`
		Body  string   `json:"body"`
		Tags  []string `json:"tags"`
	}
	limitJSONBody(w, r, maxJSONBodyBytes)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondToBodyError(w, err)
		return
	}
	req.Title = strings.TrimSpace(req.Title)
	req.Body = strings.TrimSpace(req.Body)
	if req.Title == "" {
		http.Error(w, "title required", http.StatusBadRequest)
		return
	}
	entry, err := kb.Add(workDir, req.Title, req.Body, req.Tags)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "entry": entry})
}

// handleKBDelete removes a KB entry by ID (DELETE /api/kb/{id}).
func (s *Server) handleKBDelete(w http.ResponseWriter, r *http.Request) {
	workDir := s.resolveWorkDir(r)
	id, ok := parsePositiveID(r.PathValue("id"))
	if !ok {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}
	if err := kb.Remove(workDir, id); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	jsonOK(w, map[string]interface{}{"ok": true})
}

// handleKBSearch returns KB entries whose title, content, or tags contain the
// query string (case-insensitive substring match). GET /api/kb/search?q=...
func (s *Server) handleKBSearch(w http.ResponseWriter, r *http.Request) {
	workDir := s.resolveWorkDir(r)
	q := strings.ToLower(boundedQueryString(r.URL.Query().Get("q"), maxQueryStringLen))
	store, err := kb.Load(workDir)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var matched []*kb.Entry
	for _, e := range store.Entries {
		if q == "" ||
			strings.Contains(strings.ToLower(e.Title), q) ||
			strings.Contains(strings.ToLower(e.Content), q) ||
			func() bool {
				for _, t := range e.Tags {
					if strings.Contains(strings.ToLower(t), q) {
						return true
					}
				}
				return false
			}() {
			matched = append(matched, e)
		}
	}
	if matched == nil {
		matched = []*kb.Entry{}
	}
	jsonOK(w, map[string]interface{}{"entries": matched})
}

// handleTimeline returns timeline bar data derived from pkg/timeline for the
// SVG Gantt chart in the web UI. Response JSON:
//
//	{ "bars": [...], "planStart": "<RFC3339>", "now": "<RFC3339>" }
//
// Each bar includes task metadata needed for the tooltip (assignee, estimated
// vs actual minutes, depends_on).
func (s *Server) handleTimeline(w http.ResponseWriter, r *http.Request) {
	ps, err := state.Load(s.resolveWorkDir(r))
	if err != nil || ps.Plan == nil {
		jsonOK(w, map[string]interface{}{"bars": []struct{}{}, "planStart": time.Now().Format(time.RFC3339), "now": time.Now().Format(time.RFC3339)})
		return
	}

	// Determine plan start: earliest StartedAt among tasks, or now.
	planStart := time.Now()
	for _, t := range ps.Plan.Tasks {
		if t.StartedAt != nil && !t.StartedAt.IsZero() {
			if t.StartedAt.Before(planStart) {
				planStart = *t.StartedAt
			}
		}
	}
	// If no task has started yet, use a window starting 5 minutes ago so the
	// 'now' cursor appears near the left of the chart.
	allPending := true
	for _, t := range ps.Plan.Tasks {
		if t.Status != pm.TaskPending {
			allPending = false
			break
		}
	}
	if allPending {
		planStart = time.Now().Add(-5 * time.Minute)
	}

	bars := timeline.Build(ps.Plan, planStart)

	// Build enriched response bars with extra fields for the UI tooltip.
	type TimelineBar struct {
		TaskID           int    `json:"taskId"`
		Title            string `json:"title"`
		Start            string `json:"start"`
		End              string `json:"end"`
		Status           string `json:"status"`
		Assignee         string `json:"assignee"`
		EstimatedMinutes int    `json:"estimatedMinutes"`
		ActualMinutes    int    `json:"actualMinutes"`
		DependsOn        []int  `json:"dependsOn"`
	}

	// Build a task-id → Task map for quick lookup.
	taskMap := make(map[int]*pm.Task, len(ps.Plan.Tasks))
	for _, t := range ps.Plan.Tasks {
		taskMap[t.ID] = t
	}

	result := make([]TimelineBar, 0, len(bars))
	for _, b := range bars {
		tb := TimelineBar{
			TaskID: b.TaskID,
			Title:  b.Title,
			Start:  b.Start.Format(time.RFC3339),
			End:    b.End.Format(time.RFC3339),
			Status: string(b.Status),
		}
		if t, ok := taskMap[b.TaskID]; ok {
			tb.Assignee = t.Assignee
			tb.EstimatedMinutes = t.EstimatedMinutes
			tb.ActualMinutes = t.ActualMinutes
			if len(t.DependsOn) > 0 {
				tb.DependsOn = t.DependsOn
			} else {
				tb.DependsOn = []int{}
			}
		} else {
			tb.DependsOn = []int{}
		}
		result = append(result, tb)
	}

	jsonOK(w, map[string]interface{}{
		"bars":      result,
		"planStart": planStart.Format(time.RFC3339),
		"now":       time.Now().Format(time.RFC3339),
	})
}

// ── Dependency graph handler ─────────────────────────────────────────────────

// handleDeps returns nodes (id, title, status, priority) and edges (from, to)
// for the task dependency graph. GET /api/deps
func (s *Server) handleDeps(w http.ResponseWriter, r *http.Request) {
	ps, err := state.Load(s.resolveWorkDir(r))
	if err != nil || ps.Plan == nil {
		jsonOK(w, map[string]interface{}{"nodes": []struct{}{}, "edges": []struct{}{}})
		return
	}

	type Node struct {
		ID          int    `json:"id"`
		Title       string `json:"title"`
		Status      string `json:"status"`
		Priority    int    `json:"priority"`
		Description string `json:"description"`
		Assignee    string `json:"assignee,omitempty"`
		Deadline    string `json:"deadline,omitempty"`
	}
	type Edge struct {
		From int `json:"from"`
		To   int `json:"to"`
	}

	nodes := make([]Node, 0, len(ps.Plan.Tasks))
	edges := make([]Edge, 0)

	for _, t := range ps.Plan.Tasks {
		deadline := ""
		if t.Deadline != nil && !t.Deadline.IsZero() {
			deadline = t.Deadline.Format("2006-01-02 15:04")
		}
		nodes = append(nodes, Node{
			ID:          t.ID,
			Title:       t.Title,
			Status:      string(t.Status),
			Priority:    t.Priority,
			Description: t.Description,
			Assignee:    t.Assignee,
			Deadline:    deadline,
		})
		for _, dep := range t.DependsOn {
			// Edge means dep must complete before t → dep blocks t
			edges = append(edges, Edge{From: dep, To: t.ID})
		}
	}

	jsonOK(w, map[string]interface{}{"nodes": nodes, "edges": edges})
}

// ── Risk Matrix handler ───────────────────────────────────────────────────────

// handleRiskMatrix returns the cached risk/impact matrix entries for all
// active tasks as JSON. Scores come from the RiskScore and ImpactScore fields
// cached by `cloop task ai-risk-matrix --apply`. Tasks without cached scores
// have risk_score and impact_score equal to 0.
// GET /api/risk-matrix
func (s *Server) handleRiskMatrix(w http.ResponseWriter, r *http.Request) {
	ps, err := state.Load(s.resolveWorkDir(r))
	if err != nil || ps.Plan == nil {
		jsonOK(w, map[string]interface{}{"entries": []struct{}{}, "goal": ""})
		return
	}
	entries := riskmatrix.BuildFromCache(ps.Plan)
	jsonOK(w, map[string]interface{}{
		"entries": entries,
		"goal":    ps.Plan.Goal,
	})
}

// ── Analytics handler ─────────────────────────────────────────────────────────

// maxAnalyticsWindowDays caps the ?from/?to span of /api/analytics at ten
// years. The handler builds one label per day in the window and sizes a
// float64 slice per provider from it, so the window is a direct multiplier on
// both allocation and response size. Ten years is far beyond any real
// project's history while keeping the worst case in the low megabytes.
const maxAnalyticsWindowDays = 3660

// handleAnalytics returns a JSON payload with all data needed by the analytics
// dashboard tab. Accepts optional ?from=YYYY-MM-DD and ?to=YYYY-MM-DD query
// params. The date range is clamped to maxAnalyticsWindowDays.
// GET /api/analytics
func (s *Server) handleAnalytics(w http.ResponseWriter, r *http.Request) {
	workDir := s.resolveWorkDir(r)

	// Parse optional date-range filter (default: last 30 days).
	const dayFmt = "2006-01-02"
	now := time.Now().UTC()
	fromDefault := now.AddDate(0, 0, -30).Truncate(24 * time.Hour)
	toDefault := now.Add(24 * time.Hour).Truncate(24 * time.Hour)

	parseDay := func(s string, def time.Time) time.Time {
		if s == "" {
			return def
		}
		if t, err := time.Parse(dayFmt, s); err == nil {
			return t.UTC()
		}
		return def
	}
	fromTime := parseDay(r.URL.Query().Get("from"), fromDefault)
	toTime := parseDay(r.URL.Query().Get("to"), toDefault).Add(24 * time.Hour) // inclusive

	// Clamp the window before anything sizes an allocation from it
	// (Task 20188). parseDay validates only that the value is a date, and
	// time.Parse accepts years 0000-9999 — so ?from=0001-01-01&to=9999-12-31
	// drove the label loop below ~3.65M times and sized three more slices per
	// provider off the result. A 60-byte request returned a 109 MB body, at
	// the *read* permission. Normalising an inverted range here also keeps
	// every dataset the same width as the label axis, so the chart cannot
	// silently misalign costs against dates.
	if toTime.Before(fromTime) {
		fromTime, toTime = toTime, fromTime
	}
	if maxSpan := time.Duration(maxAnalyticsWindowDays) * 24 * time.Hour; toTime.Sub(fromTime) > maxSpan {
		fromTime = toTime.Add(-maxSpan)
	}

	// ── 1. Status donut (current plan state) ──────────────────────────────────
	type statusDonut struct {
		Labels []string `json:"labels"`
		Values []int    `json:"values"`
	}
	donut := statusDonut{
		Labels: []string{"Pending", "In Progress", "Done", "Failed", "Skipped", "Timed Out"},
		Values: make([]int, 6),
	}
	ps, stateErr := state.Load(workDir)
	if stateErr == nil && ps.Plan != nil {
		for _, t := range ps.Plan.Tasks {
			switch t.Status {
			case pm.TaskPending:
				donut.Values[0]++
			case pm.TaskInProgress:
				donut.Values[1]++
			case pm.TaskDone:
				donut.Values[2]++
			case pm.TaskFailed:
				donut.Values[3]++
			case pm.TaskSkipped:
				donut.Values[4]++
			default:
				donut.Values[5]++
			}
		}
	}

	// ── 2. Read cost ledger (source for cost trend + velocity + latency) ───────
	ledger, _ := cost.ReadLedger(workDir)

	// Build date → per-provider cost map, and date → count for velocity.
	type costKey struct {
		Date     string
		Provider string
	}
	costByDayProvider := map[costKey]float64{}
	velocityByDay := map[string]int{}
	providerSet := map[string]struct{}{}

	for _, e := range ledger {
		if e.Timestamp.IsZero() {
			continue
		}
		if e.Timestamp.Before(fromTime) || !e.Timestamp.Before(toTime) {
			continue
		}
		day := e.Timestamp.UTC().Format(dayFmt)
		k := costKey{Date: day, Provider: e.Provider}
		costByDayProvider[k] += e.EstimatedUSD
		velocityByDay[day]++
		if e.Provider != "" {
			providerSet[e.Provider] = struct{}{}
		}
	}

	// ── 3. Generate date labels spanning the range ────────────────────────────
	var dateLabels []string
	for d := fromTime; !d.After(toTime.Add(-24 * time.Hour)); d = d.AddDate(0, 0, 1) {
		dateLabels = append(dateLabels, d.Format(dayFmt))
	}
	if len(dateLabels) == 0 {
		dateLabels = []string{now.Format(dayFmt)}
	}

	// ── 4. Cost trend datasets ─────────────────────────────────────────────────
	type costDataset struct {
		Provider string    `json:"provider"`
		Values   []float64 `json:"values"`
	}
	var providers []string
	for p := range providerSet {
		providers = append(providers, p)
	}
	sort.Strings(providers)

	costDatasets := make([]costDataset, 0, len(providers))
	for _, p := range providers {
		vals := make([]float64, len(dateLabels))
		for i, d := range dateLabels {
			vals[i] = costByDayProvider[costKey{Date: d, Provider: p}]
		}
		costDatasets = append(costDatasets, costDataset{Provider: p, Values: vals})
	}

	// ── 5. Velocity sparkline (tasks/day) ─────────────────────────────────────
	// Last 14 days regardless of selected range.
	velFrom := now.AddDate(0, 0, -13).Truncate(24 * time.Hour)
	var velLabels []string
	var velValues []int
	for d := velFrom; !d.After(now); d = d.AddDate(0, 0, 1) {
		day := d.Format(dayFmt)
		velLabels = append(velLabels, day)
		// Count from full ledger (not date-filtered).
		cnt := 0
		for _, e := range ledger {
			if !e.Timestamp.IsZero() && e.Timestamp.UTC().Format(dayFmt) == day {
				cnt++
			}
		}
		velValues = append(velValues, cnt)
	}

	// ── 6. Burndown chart ─────────────────────────────────────────────────────
	// Cumulative tasks completed (from ledger) vs. remaining (from plan).
	totalTasks := 0
	if stateErr == nil && ps.Plan != nil {
		totalTasks = len(ps.Plan.Tasks)
	}
	// Map day → cumulative done up to that day.
	cumDone := make([]int, len(dateLabels))
	remaining := make([]int, len(dateLabels))
	// Count completed tasks per day from the ledger.
	doneByDay := map[string]int{}
	for _, e := range ledger {
		if e.Timestamp.IsZero() {
			continue
		}
		if e.Timestamp.Before(fromTime) || !e.Timestamp.Before(toTime) {
			continue
		}
		doneByDay[e.Timestamp.UTC().Format(dayFmt)]++
	}
	running := 0
	for i, d := range dateLabels {
		running += doneByDay[d]
		cumDone[i] = running
		rem := totalTasks - running
		if rem < 0 {
			rem = 0
		}
		remaining[i] = rem
	}

	// ── 7. Latency histogram (from checkpoint history) ────────────────────────
	// Scan .cloop/task-checkpoints/ for "complete" events with ElapsedSec.
	type latHistEntry struct {
		Provider string  `json:"provider"`
		ElapsedS float64 `json:"elapsed_s"`
	}
	latByProvider := map[string][]float64{}

	cpBase := filepath.Join(workDir, ".cloop", "task-checkpoints")
	if entries, err := os.ReadDir(cpBase); err == nil {
		for _, taskDir := range entries {
			if !taskDir.IsDir() {
				continue
			}
			taskPath := filepath.Join(cpBase, taskDir.Name())
			files, err := os.ReadDir(taskPath)
			if err != nil {
				continue
			}
			for _, f := range files {
				if f.IsDir() || !strings.HasSuffix(f.Name(), ".json") {
					continue
				}
				// Per-iteration checkpoint files are tiny JSON metadata
				// (largest observed: a few KB). 1 MiB cap prevents a
				// runaway/corrupt checkpoint from blowing this analytics
				// scan out — silently skip on overrun rather than fail
				// the whole histogram.
				raw, err := boundedread.ReadFile(filepath.Join(taskPath, f.Name()), 1<<20)
				if err != nil {
					continue
				}
				var cp struct {
					Event      string    `json:"event"`
					Provider   string    `json:"provider"`
					ElapsedSec float64   `json:"elapsed_sec"`
					Timestamp  time.Time `json:"timestamp"`
				}
				if err := json.Unmarshal(raw, &cp); err != nil {
					continue
				}
				if cp.Event != "complete" || cp.ElapsedSec <= 0 {
					continue
				}
				if !cp.Timestamp.IsZero() {
					if cp.Timestamp.Before(fromTime) || !cp.Timestamp.Before(toTime) {
						continue
					}
				}
				prov := cp.Provider
				if prov == "" {
					prov = "unknown"
				}
				latByProvider[prov] = append(latByProvider[prov], cp.ElapsedSec)
			}
		}
	}

	// Build histogram buckets: 0-5s, 5-15s, 15-30s, 30-60s, 60-120s, >120s
	bucketLabels := []string{"0–5s", "5–15s", "15–30s", "30–60s", "1–2m", ">2m"}
	bucketEdges := []float64{5, 15, 30, 60, 120}

	bucket := func(sec float64) int {
		for i, edge := range bucketEdges {
			if sec < edge {
				return i
			}
		}
		return len(bucketEdges)
	}

	type latDataset struct {
		Provider string `json:"provider"`
		Counts   []int  `json:"counts"`
	}
	var latProviders []string
	for p := range latByProvider {
		latProviders = append(latProviders, p)
	}
	sort.Strings(latProviders)

	latDatasets := make([]latDataset, 0, len(latProviders))
	for _, p := range latProviders {
		counts := make([]int, len(bucketLabels))
		for _, s := range latByProvider[p] {
			counts[bucket(s)]++
		}
		latDatasets = append(latDatasets, latDataset{Provider: p, Counts: counts})
	}

	jsonOK(w, map[string]interface{}{
		"status_donut": donut,
		"burndown": map[string]interface{}{
			"labels":          dateLabels,
			"done_cumulative": cumDone,
			"remaining":       remaining,
		},
		"cost_trend": map[string]interface{}{
			"labels":   dateLabels,
			"datasets": costDatasets,
		},
		"velocity": map[string]interface{}{
			"labels": velLabels,
			"values": velValues,
		},
		"latency": map[string]interface{}{
			"buckets":  bucketLabels,
			"datasets": latDatasets,
		},
	})
}

// handleEpics returns the epic groupings derived from "epic:" task tags.
// It rebuilds epics from existing tags in the plan — no AI call is made here.
// GET /api/epics
func (s *Server) handleEpics(w http.ResponseWriter, r *http.Request) {
	workDir := s.resolveWorkDir(r)

	ps, err := state.Load(workDir)
	if err != nil || ps.Plan == nil {
		jsonOK(w, map[string]interface{}{"epics": []interface{}{}})
		return
	}

	epics := epic.EpicsFromTags(ps.Plan)
	if len(epics) == 0 {
		jsonOK(w, map[string]interface{}{"epics": []interface{}{}})
		return
	}

	progress := epic.Progress(ps.Plan, epics)
	jsonOK(w, map[string]interface{}{"epics": progress})
}

// ── budget handlers ───────────────────────────────────────────────────────────

// handleBudgetGet returns the global budget config, today's usage, per-project
// config, and effective resolved limits. GET /api/budget
func (s *Server) handleBudgetGet(w http.ResponseWriter, r *http.Request) {
	globalCfg, err := globalbudget.Load()
	if err != nil {
		jsonErr(w, "global budget load failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	usage, err := globalbudget.DailyUsage()
	if err != nil {
		usage = globalbudget.DailyStats{} // non-fatal — return zero values
	}

	// Per-project config.
	workDir := s.resolveWorkDir(r)
	projCfg, _ := config.Load(workDir)
	var projBudget config.BudgetConfig
	var projCC config.ClaudeCodeConfig
	if projCfg != nil {
		projBudget = projCfg.Budget
		projCC = projCfg.ClaudeCode
	}

	// Effective resolved limits.
	effectiveUSD := globalbudget.EffectiveProjectUSDLimit(globalCfg, projBudget.GlobalUSDPct)
	effectiveTokens := globalbudget.EffectiveProjectTokenLimit(globalCfg, projBudget.GlobalTokenPct)

	jsonOK(w, map[string]interface{}{
		"global": map[string]interface{}{
			"daily_usd_limit":     globalCfg.DailyUSDLimit,
			"daily_token_limit":   globalCfg.DailyTokenLimit,
			"alert_threshold_pct": globalCfg.AlertThresholdPct,
		},
		"usage": map[string]interface{}{
			"total_usd":    usage.TotalUSD,
			"total_tokens": usage.TotalTokens,
			"entry_count":  usage.EntryCount,
		},
		"project": map[string]interface{}{
			"daily_usd_limit":     projBudget.DailyUSDLimit,
			"daily_token_limit":   projBudget.DailyTokenLimit,
			"monthly_usd":         projBudget.MonthlyUSD,
			"global_usd_pct":      projBudget.GlobalUSDPct,
			"global_token_pct":    projBudget.GlobalTokenPct,
			"alert_threshold_pct": projBudget.AlertThresholdPct,
			// Claude Code subscription caps — single source of truth in
			// cfg.ClaudeCode (also exposed by /api/claudecode-limits and the
			// "Set Caps" modal on the project overview). Both UIs read/write
			// the same fields. See Task 20074.
			"max_weekly_pct":    projCC.MaxWeeklyPct,
			"max_five_hour_pct": projCC.MaxFiveHourPct,
			"block_extra_usage": projBudget.ShouldBlockExtraUsage(),
		},
		"effective": map[string]interface{}{
			"daily_usd_limit":   effectiveUSD,
			"daily_token_limit": effectiveTokens,
		},
	})
}

// handleBudgetGlobalSave saves global budget limits. PUT /api/budget/global
func (s *Server) handleBudgetGlobalSave(w http.ResponseWriter, r *http.Request) {
	var req struct {
		DailyUSDLimit     float64 `json:"daily_usd_limit"`
		DailyTokenLimit   int     `json:"daily_token_limit"`
		AlertThresholdPct int     `json:"alert_threshold_pct"`
	}
	limitJSONBody(w, r, maxJSONBodyBytes)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondToBodyError(w, err)
		return
	}
	// Reject negative spend limits and out-of-range alert thresholds before
	// they hit disk. Without this guard a hand-typed "-1" silently disables
	// budget enforcement (because every comparison "spend < -1" is false) and
	// an alert_threshold_pct of 200 fires nothing useful.
	if req.DailyUSDLimit < 0 {
		jsonErr(w, "daily_usd_limit must be >= 0", http.StatusBadRequest)
		return
	}
	if req.DailyTokenLimit < 0 {
		jsonErr(w, "daily_token_limit must be >= 0", http.StatusBadRequest)
		return
	}
	if req.AlertThresholdPct < config.AlertThresholdMin || req.AlertThresholdPct > config.AlertThresholdMax {
		jsonErr(w, fmt.Sprintf("alert_threshold_pct must be between %d and %d", config.AlertThresholdMin, config.AlertThresholdMax), http.StatusBadRequest)
		return
	}
	cfg := globalbudget.GlobalBudgetConfig{
		DailyUSDLimit:     req.DailyUSDLimit,
		DailyTokenLimit:   req.DailyTokenLimit,
		AlertThresholdPct: req.AlertThresholdPct,
	}
	if err := globalbudget.Save(cfg); err != nil {
		jsonErr(w, "save failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	jsonOK(w, map[string]bool{"ok": true})
}

// handleBudgetProjectSave saves per-project budget config. PUT /api/budget/project
func (s *Server) handleBudgetProjectSave(w http.ResponseWriter, r *http.Request) {
	// Claude Code subscription caps (max_weekly_pct / max_five_hour_pct) live in
	// cfg.ClaudeCode — same fields that /api/claudecode-limits writes. Both UI
	// forms (Budget tab and the "Set Caps" modal on the project overview) hit
	// these fields, so a value entered in one form is immediately visible in
	// the other. See Task 20074.
	var req struct {
		DailyUSDLimit     float64 `json:"daily_usd_limit"`
		DailyTokenLimit   int     `json:"daily_token_limit"`
		MonthlyUSD        float64 `json:"monthly_usd"`
		GlobalUSDPct      float64 `json:"global_usd_pct"`
		GlobalTokenPct    float64 `json:"global_token_pct"`
		AlertThresholdPct int     `json:"alert_threshold_pct"`
		MaxWeeklyPct      float64 `json:"max_weekly_pct"`
		MaxFiveHourPct    float64 `json:"max_five_hour_pct"`
		BlockExtraUsage   *bool   `json:"block_extra_usage,omitempty"`
	}
	limitJSONBody(w, r, maxJSONBodyBytes)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondToBodyError(w, err)
		return
	}
	// All percentages: [0, 100].
	for _, v := range []float64{req.MaxWeeklyPct, req.MaxFiveHourPct, req.GlobalUSDPct, req.GlobalTokenPct} {
		if v < 0 || v > 100 {
			jsonErr(w, "percentage values must be between 0 and 100", http.StatusBadRequest)
			return
		}
	}
	// All spend caps: must be >= 0. Zero is "no limit"; negative is meaningless
	// and bypasses every comparison-based gate downstream.
	if req.DailyUSDLimit < 0 {
		jsonErr(w, "daily_usd_limit must be >= 0", http.StatusBadRequest)
		return
	}
	if req.DailyTokenLimit < 0 {
		jsonErr(w, "daily_token_limit must be >= 0", http.StatusBadRequest)
		return
	}
	if req.MonthlyUSD < 0 {
		jsonErr(w, "monthly_usd must be >= 0", http.StatusBadRequest)
		return
	}
	if req.AlertThresholdPct < config.AlertThresholdMin || req.AlertThresholdPct > config.AlertThresholdMax {
		jsonErr(w, fmt.Sprintf("alert_threshold_pct must be between %d and %d", config.AlertThresholdMin, config.AlertThresholdMax), http.StatusBadRequest)
		return
	}
	workDir := s.resolveWorkDir(r)
	cfg, err := config.Load(workDir)
	if err != nil {
		jsonErr(w, "config load failed", http.StatusInternalServerError)
		return
	}
	cfg.Budget.DailyUSDLimit = req.DailyUSDLimit
	cfg.Budget.DailyTokenLimit = req.DailyTokenLimit
	cfg.Budget.MonthlyUSD = req.MonthlyUSD
	cfg.Budget.GlobalUSDPct = req.GlobalUSDPct
	cfg.Budget.GlobalTokenPct = req.GlobalTokenPct
	cfg.Budget.AlertThresholdPct = req.AlertThresholdPct
	cfg.ClaudeCode.MaxWeeklyPct = req.MaxWeeklyPct
	cfg.ClaudeCode.MaxFiveHourPct = req.MaxFiveHourPct
	if req.BlockExtraUsage != nil {
		cfg.Budget.BlockExtraUsage = req.BlockExtraUsage
	}
	if err := config.Save(workDir, cfg); err != nil {
		jsonErr(w, "save failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	jsonOK(w, map[string]bool{"ok": true})
}

// handleRateLimits returns the most recent Anthropic rate-limit snapshot per
// model captured from anthropic-ratelimit-* response headers.
// GET /api/ratelimits
func (s *Server) handleRateLimits(w http.ResponseWriter, r *http.Request) {
	snap := ratelimit.Snapshot()
	models := make([]map[string]interface{}, 0, len(snap))
	for _, m := range snap {
		entry := map[string]interface{}{
			"model":      m.Model,
			"updated_at": m.UpdatedAt,
			"tier":       m.Tier,
			"requests": map[string]interface{}{
				"limit":     m.Requests.Limit,
				"remaining": m.Requests.Remaining,
				"used":      m.Requests.Used(),
				"pct":       m.Requests.PercentUsed(),
				"reset":     m.Requests.Reset,
			},
			"input_tokens": map[string]interface{}{
				"limit":     m.InputTokens.Limit,
				"remaining": m.InputTokens.Remaining,
				"used":      m.InputTokens.Used(),
				"pct":       m.InputTokens.PercentUsed(),
				"reset":     m.InputTokens.Reset,
			},
			"output_tokens": map[string]interface{}{
				"limit":     m.OutputTokens.Limit,
				"remaining": m.OutputTokens.Remaining,
				"used":      m.OutputTokens.Used(),
				"pct":       m.OutputTokens.PercentUsed(),
				"reset":     m.OutputTokens.Reset,
			},
			"tokens": map[string]interface{}{
				"limit":     m.Tokens.Limit,
				"remaining": m.Tokens.Remaining,
				"used":      m.Tokens.Used(),
				"pct":       m.Tokens.PercentUsed(),
				"reset":     m.Tokens.Reset,
			},
			"weekly": map[string]interface{}{
				"limit":     m.Weekly.Limit,
				"remaining": m.Weekly.Remaining,
				"used":      m.Weekly.Used(),
				"pct":       m.Weekly.PercentUsed(),
				"reset":     m.Weekly.Reset,
			},
			"five_hour": map[string]interface{}{
				"limit":     m.FiveHour.Limit,
				"remaining": m.FiveHour.Remaining,
				"used":      m.FiveHour.Used(),
				"pct":       m.FiveHour.PercentUsed(),
				"reset":     m.FiveHour.Reset,
			},
			"monthly_spend_usd": m.MonthlySpendUSD,
		}
		models = append(models, entry)
	}
	// Sort by model name for stable ordering.
	sort.Slice(models, func(i, j int) bool {
		return fmt.Sprint(models[i]["model"]) < fmt.Sprint(models[j]["model"])
	})
	jsonOK(w, map[string]interface{}{
		"models": models,
		"count":  len(models),
	})
}

// handleClaudeUsage fetches Claude Code subscription usage limits from
// the Anthropic OAuth usage API (5-hour, weekly, per-model breakdowns).
// GET /api/claude-usage
func (s *Server) handleClaudeUsage(w http.ResponseWriter, r *http.Request) {
	// FetchOrCachedUsage enforces a >=1-minute TTL and coalesces concurrent
	// callers, so a browser polling this endpoint plus the orchestrator's
	// per-task limit check share one HTTP round-trip per refresh window.
	usage, err := ratelimit.FetchOrCachedUsage("", 3*time.Minute)
	if err != nil && usage == nil {
		jsonOK(w, map[string]interface{}{"error": err.Error()})
		return
	}
	jsonOK(w, usage)
}

// handleClaudeCodeLimitsGet returns the per-project claudecode subscription
// caps along with the current global utilization snapshot. Used by the
// project overview panel to render configurable limits.
// GET /api/claudecode-limits
func (s *Server) handleClaudeCodeLimitsGet(w http.ResponseWriter, r *http.Request) {
	workDir := s.resolveWorkDir(r)
	cfg, _ := config.Load(workDir)
	var cc config.ClaudeCodeConfig
	if cfg != nil {
		cc = cfg.ClaudeCode
	}
	// Cached for at least 1 minute; ignores fetch errors and falls back to
	// any stale snapshot so the panel still renders historical numbers when
	// the OAuth usage endpoint is briefly unreachable.
	usage, _ := ratelimit.FetchOrCachedUsage("", ratelimit.MinUsageCacheTTL)
	violations := ratelimit.CheckClaudeCodeLimits(cc, usage)
	violationStrs := make([]string, 0, len(violations))
	for _, v := range violations {
		violationStrs = append(violationStrs, v.Error())
	}
	jsonOK(w, map[string]interface{}{
		"limits": map[string]interface{}{
			"max_weekly_pct":        cc.MaxWeeklyPct,
			"max_five_hour_pct":     cc.MaxFiveHourPct,
			"max_weekly_opus_pct":   cc.MaxWeeklyOpusPct,
			"max_weekly_sonnet_pct": cc.MaxWeeklySonnetPct,
		},
		"usage":      usage,
		"violations": violationStrs,
	})
}

// handleClaudeCodeLimitsSave updates the per-project claudecode subscription
// caps in .cloop/config.yaml. PUT /api/claudecode-limits
func (s *Server) handleClaudeCodeLimitsSave(w http.ResponseWriter, r *http.Request) {
	var req struct {
		MaxWeeklyPct       float64 `json:"max_weekly_pct"`
		MaxFiveHourPct     float64 `json:"max_five_hour_pct"`
		MaxWeeklyOpusPct   float64 `json:"max_weekly_opus_pct"`
		MaxWeeklySonnetPct float64 `json:"max_weekly_sonnet_pct"`
	}
	limitJSONBody(w, r, maxJSONBodyBytes)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondToBodyError(w, err)
		return
	}
	for _, v := range []float64{req.MaxWeeklyPct, req.MaxFiveHourPct, req.MaxWeeklyOpusPct, req.MaxWeeklySonnetPct} {
		if v < 0 || v > 100 {
			jsonErr(w, "percentage values must be between 0 and 100", http.StatusBadRequest)
			return
		}
	}
	workDir := s.resolveWorkDir(r)
	cfg, err := config.Load(workDir)
	if err != nil {
		jsonErr(w, "config load failed", http.StatusInternalServerError)
		return
	}
	cfg.ClaudeCode.MaxWeeklyPct = req.MaxWeeklyPct
	cfg.ClaudeCode.MaxFiveHourPct = req.MaxFiveHourPct
	cfg.ClaudeCode.MaxWeeklyOpusPct = req.MaxWeeklyOpusPct
	cfg.ClaudeCode.MaxWeeklySonnetPct = req.MaxWeeklySonnetPct
	if err := config.Save(workDir, cfg); err != nil {
		jsonErr(w, "save failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	jsonOK(w, map[string]bool{"ok": true})
}

// claudeAuthManager lazily allocates the single Manager that owns the
// in-flight `claude auth login` subprocess. Allocated on first use so test
// servers that construct Server{} directly still work without explicit wiring.
func (s *Server) claudeAuthManager() *claudecodeauth.Manager {
	s.ccAuthMu.Lock()
	defer s.ccAuthMu.Unlock()
	if s.ccAuth == nil {
		s.ccAuth = claudecodeauth.NewManager()
	}
	return s.ccAuth
}

// handleClaudeCodeAuthStatus returns the current Claude Code login status
// alongside any in-flight login session state. Used by the UI to render the
// login panel.
// GET /api/claudecode/auth/status
func (s *Server) handleClaudeCodeAuthStatus(w http.ResponseWriter, r *http.Request) {
	if denyHostSideEffect(w, "", "claude CLI (auth status)") {
		return
	}
	resp := map[string]interface{}{}
	if st, err := claudecodeauth.FetchStatus(r.Context()); err != nil {
		resp["status_error"] = err.Error()
	} else {
		resp["status"] = st
	}
	resp["session"] = s.claudeAuthManager().Snapshot()
	jsonOK(w, resp)
}

// handleClaudeCodeAuthLoginStart kicks off `claude auth login` and returns
// the OAuth URL the user must visit in their browser.
// POST /api/claudecode/auth/login  body: {"console":bool,"email":string,"sso":bool}
func (s *Server) handleClaudeCodeAuthLoginStart(w http.ResponseWriter, r *http.Request) {
	if denyHostSideEffect(w, "", "claude CLI (auth login)") {
		return
	}
	var req struct {
		Console bool   `json:"console"`
		Email   string `json:"email"`
		SSO     bool   `json:"sso"`
	}
	limitJSONBody(w, r, maxJSONBodyBytes)
	if r.ContentLength > 0 {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			respondToBodyError(w, err)
			return
		}
	}
	sess, err := s.claudeAuthManager().Start(r.Context(), claudecodeauth.LoginOptions{
		Console: req.Console,
		Email:   req.Email,
		SSO:     req.SSO,
	})
	if err != nil {
		jsonErr(w, err.Error(), http.StatusBadGateway)
		return
	}
	jsonOK(w, map[string]interface{}{"session": sess.Snapshot()})
}

// handleClaudeCodeAuthLoginCode pipes the OAuth authorization code to the
// in-flight login session and returns the final outcome.
// POST /api/claudecode/auth/login/code  body: {"code":string}
func (s *Server) handleClaudeCodeAuthLoginCode(w http.ResponseWriter, r *http.Request) {
	if denyHostSideEffect(w, "", "claude CLI (auth login)") {
		return
	}
	var req struct {
		Code string `json:"code"`
	}
	limitJSONBody(w, r, maxJSONBodyBytes)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondToBodyError(w, err)
		return
	}
	st, err := s.claudeAuthManager().SubmitCode(req.Code)
	if err != nil {
		jsonErr(w, err.Error(), http.StatusBadRequest)
		return
	}
	// Reauthentication invalidates the cached Claude Code usage snapshot:
	// the previous identity's window/extra-usage numbers no longer apply.
	ratelimit.ClearUsageCache()
	// Refresh status so the UI doesn't have to round-trip a second call.
	resp := map[string]interface{}{"session": st}
	if status, sErr := claudecodeauth.FetchStatus(r.Context()); sErr == nil {
		resp["status"] = status
	}
	jsonOK(w, resp)
}

// handleClaudeCodeAuthLoginCancel kills the current login session (if any).
// POST /api/claudecode/auth/login/cancel
func (s *Server) handleClaudeCodeAuthLoginCancel(w http.ResponseWriter, r *http.Request) {
	s.claudeAuthManager().Cancel()
	jsonOK(w, map[string]bool{"ok": true})
}

// handleClaudeCodeAuthLogout calls `claude auth logout`.
// POST /api/claudecode/auth/logout
func (s *Server) handleClaudeCodeAuthLogout(w http.ResponseWriter, r *http.Request) {
	if denyHostSideEffect(w, "", "claude CLI (auth logout)") {
		return
	}
	if err := claudecodeauth.Logout(r.Context()); err != nil {
		jsonErr(w, err.Error(), http.StatusBadGateway)
		return
	}
	// Discard cached usage — it belonged to the now-logged-out identity.
	ratelimit.ClearUsageCache()
	jsonOK(w, map[string]bool{"ok": true})
}

// handleOptionsToggle flips a persistent CLI-mode flag in project state so that
// the running orchestrator (which re-reads s.AutoEvolve / s.InnovateMode each
// loop iteration) picks up the change, and so the next `cloop run` honors it.
// POST /api/options/toggle  body: {"flag":"auto_evolve"|"innovate_mode"|"skip_clarify"|"parallel"|"plan_only"|"retry_failed"|"dry_run","value":bool}
func (s *Server) handleOptionsToggle(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Flag  string `json:"flag"`
		Value bool   `json:"value"`
	}
	limitJSONBody(w, r, maxJSONBodyBytes)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondToBodyError(w, err)
		return
	}
	workDir := s.resolveWorkDir(r)
	ps, err := state.Load(workDir)
	if err != nil {
		jsonErr(w, "no project found", http.StatusNotFound)
		return
	}
	// PM mode is always on (Task 20067 removed non-PM mode); force-true on every save.
	ps.PMMode = true
	switch req.Flag {
	case "auto_evolve":
		ps.AutoEvolve = req.Value
	case "innovate_mode":
		ps.InnovateMode = req.Value
	case "skip_clarify":
		ps.SkipClarify = req.Value
	case "parallel":
		ps.Parallel = req.Value
	case "plan_only":
		ps.PlanOnly = req.Value
	case "retry_failed":
		ps.RetryFailed = req.Value
	case "dry_run":
		ps.DryRun = req.Value
	default:
		jsonErr(w, "unsupported flag: "+req.Flag, http.StatusBadRequest)
		return
	}
	if err := ps.SaveDirect(); err != nil {
		jsonErr(w, "save failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	s.broadcastStateDiff(workDir, ps)
	jsonOK(w, map[string]interface{}{
		"ok":            true,
		"auto_evolve":   ps.AutoEvolve,
		"innovate_mode": ps.InnovateMode,
		"pm_mode":       ps.PMMode,
		"skip_clarify":  ps.SkipClarify,
		"parallel":      ps.Parallel,
		"max_parallel":  ps.MaxParallel,
		"plan_only":     ps.PlanOnly,
		"retry_failed":  ps.RetryFailed,
		"dry_run":       ps.DryRun,
	})
}

// handleMaxParallelSet updates the per-project worker pool size used in parallel
// PM mode. POST /api/options/max-parallel body: {"value":int}. The value must
// be in [config.MaxParallelLower, config.MaxParallelUpper] (1..64); 0,
// negatives, and absurdly large numbers are rejected with HTTP 400 because
// they would either disable parallel dispatch or spawn pathological numbers
// of goroutines per round (Task 20082).
func (s *Server) handleMaxParallelSet(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Value int `json:"value"`
	}
	limitJSONBody(w, r, maxJSONBodyBytes)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondToBodyError(w, err)
		return
	}
	// Bound to [1, 64]: zero (or negative) would either disable parallel
	// dispatch or, worse, allow unbounded goroutine fan-out; > 64 has never
	// been useful in practice and risks exhausting file descriptors and
	// upstream provider rate limits. See pkg/config bounds for the canonical
	// constants used everywhere these values are validated.
	if req.Value < config.MaxParallelLower || req.Value > config.MaxParallelUpper {
		jsonErr(w, fmt.Sprintf("max_parallel must be between %d and %d", config.MaxParallelLower, config.MaxParallelUpper), http.StatusBadRequest)
		return
	}
	workDir := s.resolveWorkDir(r)
	ps, err := state.Load(workDir)
	if err != nil {
		jsonErr(w, "no project found", http.StatusNotFound)
		return
	}
	ps.MaxParallel = req.Value
	if err := ps.SaveDirect(); err != nil {
		jsonErr(w, "save failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	s.broadcastStateDiff(workDir, ps)
	jsonOK(w, map[string]interface{}{
		"ok":           true,
		"max_parallel": ps.MaxParallel,
	})
}

// maxStepTimeout is the upper bound accepted by /api/options/step-timeout. A
// step budget longer than a day is indistinguishable from "disabled" (which
// has its own explicit sentinel, "0") and would let a wedged step pin an
// executor slot past any useful watchdog.
const maxStepTimeout = 24 * time.Hour

// handleStepTimeoutSet updates the per-project step timeout.
// POST /api/options/step-timeout body: {"value":"10m"} or {"value":"0"} to disable.
func (s *Server) handleStepTimeoutSet(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Value string `json:"value"`
	}
	limitJSONBody(w, r, maxJSONBodyBytes)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondToBodyError(w, err)
		return
	}
	// Validate: must be "0", empty, or a valid Go duration inside a sane
	// band. Parseability alone is not enough (Task 20188): "-1h" parses, and
	// the providers special-case only zero ("use the default"), so a negative
	// value reached context.WithTimeout and produced an already-expired
	// context — every provider call in the project then failed instantly
	// with "context deadline exceeded" and nothing in the UI said why.
	// handleMaxParallelSet and handleTaskTimeoutSet next door both range-
	// check; this is the same contract.
	if req.Value != "" && req.Value != "0" {
		d, err := time.ParseDuration(req.Value)
		if err != nil {
			jsonErr(w, "invalid duration format (examples: 10m, 30m, 1h, 0)", http.StatusBadRequest)
			return
		}
		if d <= 0 {
			jsonErr(w, "step_timeout must be positive (use \"0\" to disable the timeout)", http.StatusBadRequest)
			return
		}
		if d > maxStepTimeout {
			jsonErr(w, fmt.Sprintf("step_timeout must be at most %s (use \"0\" to disable the timeout)", maxStepTimeout),
				http.StatusBadRequest)
			return
		}
	}
	workDir := s.resolveWorkDir(r)
	cfg, err := config.Load(workDir)
	if err != nil {
		jsonErr(w, "config load failed", http.StatusInternalServerError)
		return
	}
	cfg.StepTimeout = req.Value
	if err := config.Save(workDir, cfg); err != nil {
		jsonErr(w, "save failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	jsonOK(w, map[string]interface{}{
		"ok":           true,
		"step_timeout": req.Value,
	})
}

// handleTaskTimeoutSet updates the per-project default per-task wall-clock
// budget (state.DefaultMaxMinutes). The value is applied to currently-running
// tasks within ~3 seconds via the orchestrator's live-deadline poller
// (Task 20143). 0 means "use the process-wide default"; out-of-band values
// are rejected with HTTP 400 to match the bounds the orchestrator enforces.
//
// POST /api/options/task-timeout  body: {"value":<minutes>}
func (s *Server) handleTaskTimeoutSet(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Value int `json:"value"`
	}
	limitJSONBody(w, r, maxJSONBodyBytes)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondToBodyError(w, err)
		return
	}
	// 0 is the sentinel for "use the process-wide default"; everything else
	// must fall inside the same [Lower, Upper] band that pkg/config enforces.
	if req.Value != 0 && (req.Value < config.OrchestratorTaskTimeoutMinutesLower || req.Value > config.OrchestratorTaskTimeoutMinutesUpper) {
		jsonErr(w, fmt.Sprintf("task_timeout_minutes must be 0 or between %d and %d",
			config.OrchestratorTaskTimeoutMinutesLower, config.OrchestratorTaskTimeoutMinutesUpper),
			http.StatusBadRequest)
		return
	}
	workDir := s.resolveWorkDir(r)
	ps, err := state.Load(workDir)
	if err != nil {
		jsonErr(w, err.Error(), statedb.HTTPStatus(err))
		return
	}
	ps.DefaultMaxMinutes = req.Value
	if err := ps.SaveDirect(); err != nil {
		jsonErr(w, "save failed: "+err.Error(), statedb.HTTPStatus(err))
		return
	}
	s.broadcastStateDiff(workDir, ps)
	jsonOK(w, map[string]interface{}{
		"ok":                  true,
		"default_max_minutes": ps.DefaultMaxMinutes,
	})
}

// handleProviderModelSet persists the provider, model and/or effort on the
// project state so that subsequent runs (including the persistent UI Run
// buttons) use them without needing to be passed on every invocation. Empty
// provider/model mean "leave unchanged"; effort is a pointer so an omitted
// field leaves it unchanged while an explicit "" clears it back to the
// provider default.
//
// POST /api/options/provider  body: {"provider":"...","model":"...","effort":"..."}
func (s *Server) handleProviderModelSet(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Provider string  `json:"provider"`
		Model    string  `json:"model"`
		Effort   *string `json:"effort"`
	}
	limitJSONBody(w, r, maxJSONBodyBytes)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondToBodyError(w, err)
		return
	}
	// Whitelist providers to prevent garbage in state.json.
	if req.Provider != "" {
		switch req.Provider {
		case "claudecode", "anthropic", "openai", "ollama":
		default:
			jsonErr(w, "unsupported provider: "+req.Provider, http.StatusBadRequest)
			return
		}
	}
	if req.Effort != nil && !provider.ValidEffort(*req.Effort) {
		jsonErr(w, "invalid effort "+strconv.Quote(*req.Effort)+" — valid: "+strings.Join(provider.EffortLevels, ", "), http.StatusBadRequest)
		return
	}
	workDir := s.resolveWorkDir(r)
	ps, err := state.Load(workDir)
	if err != nil {
		jsonErr(w, "no project found", http.StatusNotFound)
		return
	}
	if req.Provider != "" {
		ps.Provider = req.Provider
	}
	// Model is allowed to be cleared explicitly via "" only when a provider was
	// just changed (since the previous model may not apply to the new provider).
	// Otherwise non-empty replaces, empty leaves untouched.
	if req.Model != "" {
		ps.Model = req.Model
	} else if req.Provider != "" {
		ps.Model = ""
	}
	if req.Effort != nil {
		ps.Effort = *req.Effort
	}
	if err := ps.SaveDirect(); err != nil {
		jsonErr(w, "save failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	s.broadcastStateDiff(workDir, ps)
	jsonOK(w, map[string]interface{}{
		"ok":       true,
		"provider": ps.Provider,
		"model":    ps.Model,
		"effort":   ps.Effort,
	})
}
