package ui

// executor_pool_controller.go: what a pool's controller talks to (Task
// 20482).
//
//	GET  /api/pool-controller/feed            the pool's demand and runners, pushed
//	POST /api/pool-controller/runners         runner configurations: {"count": N}
//	POST /api/pool-controller/runners/retire  retire runners that hold no run:
//	                                          {"runners": ["<enrollment id>", …]}
//
// Both are authenticated by the pool's controller credential, presented as
// "Authorization: Bearer cloop_pool1_…" and nowhere else — never a query
// parameter, which a proxy logs — and neither holds or accepts a hub session:
// a controller is not a person, and a credential the dashboard's could stand in
// for would let a leaked API token start runners. So the routes are public to
// the route gate and carried past the hub's own authentication
// (servedBeforeAuth), like the CI relay's and the SCIM service's, and the
// handlers authenticate. They stay behind the rate limiter, the Host and
// Origin guards and the JSON-only rule.
//
// The feed is a WebSocket when the controller asks for one, and a long-poll
// otherwise: GET …/feed?after=<revision>&wait=<seconds> answers at once when
// the pool's snapshot differs from revision, and otherwise when it changes or
// the wait runs out. Either way the controller is pushed a change; it never
// polls in a loop. Every hub member serves it from the shared database, and a
// change on another member reaches it through the cluster bus.
//
// The credential is checked again at every change and every minute, so a
// feed opened before its credential — or its pool — was revoked ends with a
// "revoked" message instead of streaming on.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/coder/websocket"

	"github.com/blechschmidt/cloop/pkg/executor/remote"
	"github.com/blechschmidt/cloop/pkg/executorpool"
	"github.com/blechschmidt/cloop/pkg/hubmetrics"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// The controller's endpoints.
const (
	poolFeedPath    = "/api/pool-controller/feed"
	poolRunnersPath = "/api/pool-controller/runners"
	poolRetirePath  = "/api/pool-controller/runners/retire"
)

// Feed timing.
var (
	// poolFeedMaxWait bounds a long-poll's wait, below the idle timeouts of
	// the proxies a controller is commonly behind.
	poolFeedMaxWait = 60 * time.Second
	// poolFeedRecheck is how often an open feed re-reads the pool and its
	// credential with nothing having woken it: a lapsed runner token changes
	// the snapshot without any event, and a revocation on an older hub member
	// publishes none.
	poolFeedRecheck = 15 * time.Second
	// poolFeedPing keeps a WebSocket's intermediaries from closing it idle,
	// and finds a controller that went away.
	poolFeedPing = 30 * time.Second
)

// isPoolControllerEndpoint reports whether r is for a controller endpoint,
// for servedBeforeAuth.
func isPoolControllerEndpoint(r *http.Request) bool {
	switch r.URL.Path {
	case poolFeedPath:
		return r.Method == http.MethodGet || r.Method == http.MethodHead
	case poolRunnersPath, poolRetirePath:
		return r.Method == http.MethodPost
	}
	return false
}

// poolControllerURL is an https URL for path on this hub, as the request
// reached it.
func (s *Server) poolControllerURL(r *http.Request, path string) string {
	v := s.clientView(r)
	scheme := "http"
	if v.TLS() {
		scheme = "https"
	}
	host := v.Host
	if host == "" {
		host = "YOUR-CONTROL-PLANE"
	}
	return scheme + "://" + host + path
}

// poolBearer is the controller credential in r, or "".
func poolBearer(r *http.Request) string {
	h := strings.TrimSpace(r.Header.Get("Authorization"))
	tok, ok := strings.CutPrefix(h, "Bearer ")
	if !ok {
		return ""
	}
	return strings.TrimSpace(tok)
}

// authenticatePoolController checks the request's controller credential,
// answering 401 itself when it does not hold. Every failure gets the same
// answer; the log and the refusal metric say which it was.
func (s *Server) authenticatePoolController(w http.ResponseWriter, r *http.Request, minting bool) (*executorpool.Store, executorpool.Pool, executorpool.Credential, string, bool) {
	unauthorized := func(reason string, err error) {
		if minting {
			hubmetrics.ExecutorPoolMintRefusals.Inc(reason)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "ui: pool controller refused from %s: %v\n", s.clientIP(r), err)
		}
		w.Header().Set("WWW-Authenticate", `Bearer realm="cloop pool controller"`)
		writeJSONStatus(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized", "code": "pool_credential_invalid"})
	}
	token := poolBearer(r)
	if !strings.HasPrefix(token, executorpool.CredentialPrefix) {
		unauthorized(hubmetrics.ExecutorPoolRefusalInvalidCredential, nil)
		return nil, executorpool.Pool{}, executorpool.Credential{}, "", false
	}
	store, err := s.poolStore()
	if err != nil {
		writeJSONStatus(w, http.StatusServiceUnavailable, map[string]any{"error": "executor pools are unavailable",
			"code": "executor_pool_unavailable"})
		return nil, executorpool.Pool{}, executorpool.Credential{}, "", false
	}
	pool, cred, err := store.Authenticate(token)
	if err != nil {
		reason := hubmetrics.ExecutorPoolRefusalInvalidCredential
		if errors.Is(err, executorpool.ErrCredentialRevoked) || errors.Is(err, executorpool.ErrRevoked) {
			reason = hubmetrics.ExecutorPoolRefusalRevoked
		}
		unauthorized(reason, err)
		return nil, executorpool.Pool{}, executorpool.Credential{}, "", false
	}
	return store, pool, cred, token, true
}

// poolFeedMessage is one message of a controller's feed.
type poolFeedMessage struct {
	// Type is "snapshot", or "revoked" as the last message of a feed whose
	// credential or pool was revoked.
	Type     string                `json:"type"`
	Snapshot executorpool.Snapshot `json:"snapshot"`
	// Pool is the pool's definition: what to start its runners as.
	Pool executorpool.Spec `json:"pool"`
	// Server and Pin are what runners dial, for a controller that templates
	// them without asking for a configuration first.
	Server string `json:"server"`
	Pin    string `json:"pin,omitempty"`
}

// poolFeedState reads the feed's next message. ok is false once the
// credential or the pool no longer authenticates; the message is then the
// "revoked" one.
func (s *Server) poolFeedState(r *http.Request, store *executorpool.Store, token string) (poolFeedMessage, bool, error) {
	pool, _, err := store.Authenticate(token)
	if err != nil {
		if errors.Is(err, executorpool.ErrCredentialRevoked) || errors.Is(err, executorpool.ErrRevoked) ||
			errors.Is(err, executorpool.ErrCredentialInvalid) {
			return poolFeedMessage{Type: "revoked", Snapshot: executorpool.Snapshot{Revoked: true}}, false, nil
		}
		return poolFeedMessage{}, true, err
	}
	snap, _, err := store.Snapshot(pool, s.poolAccessFor(store))
	if err != nil {
		return poolFeedMessage{}, true, err
	}
	return poolFeedMessage{Type: "snapshot", Snapshot: snap, Pool: pool.Spec(), Server: s.agentConnectURL(r),
		Pin: s.transportPin()}, true, nil
}

// handlePoolControllerFeed serves GET /api/pool-controller/feed.
func (s *Server) handlePoolControllerFeed(w http.ResponseWriter, r *http.Request) {
	store, pool, _, token, ok := s.authenticatePoolController(w, r, false)
	if !ok {
		return
	}
	if strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		s.servePoolFeedWS(w, r, store, pool.ID, token)
		return
	}
	s.servePoolFeedPoll(w, r, store, pool.ID, token)
}

// servePoolFeedPoll answers one long-poll.
func (s *Server) servePoolFeedPoll(w http.ResponseWriter, r *http.Request, store *executorpool.Store, poolID, token string) {
	after := strings.TrimSpace(r.URL.Query().Get("after"))
	wait := 30 * time.Second
	if v := strings.TrimSpace(r.URL.Query().Get("wait")); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			jsonErr(w, "wait must be a whole number of seconds", http.StatusBadRequest)
			return
		}
		wait = time.Duration(n) * time.Second
	}
	if wait > poolFeedMaxWait {
		wait = poolFeedMaxWait
	}
	deadline := time.NewTimer(wait)
	defer deadline.Stop()
	w.Header().Set("Cache-Control", "no-store")
	for {
		// The wake-up channel is taken before the read, so a change between
		// the two still wakes this wait.
		changed := s.poolWaitCh(poolID)
		msg, live, err := s.poolFeedState(r, store, token)
		if err != nil {
			writeJSONStatus(w, http.StatusServiceUnavailable, map[string]any{"error": "read the pool: " + err.Error()})
			return
		}
		if !live {
			writeJSONStatus(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized", "code": "pool_credential_revoked",
				"type": "revoked"})
			return
		}
		if msg.Snapshot.Revision != after {
			jsonOK(w, msg)
			return
		}
		recheck := time.NewTimer(poolFeedRecheck)
		select {
		case <-r.Context().Done():
			recheck.Stop()
			return
		case <-deadline.C:
			recheck.Stop()
			jsonOK(w, msg)
			return
		case <-changed:
		case <-recheck.C:
		}
		recheck.Stop()
	}
}

// servePoolFeedWS streams the feed over a WebSocket.
func (s *Server) servePoolFeedWS(w http.ResponseWriter, r *http.Request, store *executorpool.Store, poolID, token string) {
	// Origin is not checked, deliberately. The connection is authenticated by
	// the Authorization header, which a browser cannot attach to a WebSocket
	// handshake; a page that opened one here would have no credential to open
	// it with. The library's own check would refuse a controller whose client
	// sends an Origin of its own, as some do.
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
	if err != nil {
		return
	}
	defer conn.CloseNow() //nolint:errcheck
	ctx := conn.CloseRead(r.Context())

	send := func(msg poolFeedMessage) error {
		b, err := json.Marshal(msg)
		if err != nil {
			return err
		}
		wctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		return conn.Write(wctx, websocket.MessageText, b)
	}
	ping := time.NewTicker(poolFeedPing)
	defer ping.Stop()
	recheck := time.NewTicker(poolFeedRecheck)
	defer recheck.Stop()
	last := ""
	for {
		changed := s.poolWaitCh(poolID)
		msg, live, err := s.poolFeedState(r, store, token)
		switch {
		case err != nil:
			conn.Close(websocket.StatusInternalError, "the pool could not be read") //nolint:errcheck
			return
		case !live:
			_ = send(msg)
			conn.Close(websocket.StatusPolicyViolation, "the pool or its credential was revoked") //nolint:errcheck
			return
		case msg.Snapshot.Revision != last:
			if err := send(msg); err != nil {
				return
			}
			last = msg.Snapshot.Revision
		}
		select {
		case <-ctx.Done():
			return
		case <-changed:
		case <-recheck.C:
		case <-ping.C:
			pctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			err := conn.Ping(pctx)
			cancel()
			if err != nil {
				return
			}
		}
	}
}

// poolRunnersRequest is what a controller asks for.
type poolRunnersRequest struct {
	// Count is how many runners; 1..executorpool.MaxRunnersPerRequest.
	Count int `json:"count"`
	// TTLSeconds bounds the tokens; 0 is the most allowed, ten minutes.
	TTLSeconds int `json:"ttl_seconds,omitempty"`
}

// handlePoolControllerRunners serves POST /api/pool-controller/runners.
func (s *Server) handlePoolControllerRunners(w http.ResponseWriter, r *http.Request) {
	store, pool, cred, _, ok := s.authenticatePoolController(w, r, true)
	if !ok {
		return
	}
	var req poolRunnersRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Count < 1 || req.Count > executorpool.MaxRunnersPerRequest {
		hubmetrics.ExecutorPoolMintRefusals.Inc(hubmetrics.ExecutorPoolRefusalInvalidRequest)
		jsonErr(w, fmt.Sprintf("count must be between 1 and %d", executorpool.MaxRunnersPerRequest), http.StatusBadRequest)
		return
	}
	ttl := time.Duration(req.TTLSeconds) * time.Second
	if req.TTLSeconds < 0 || ttl > remote.MaxRunnerTTL {
		hubmetrics.ExecutorPoolMintRefusals.Inc(hubmetrics.ExecutorPoolRefusalInvalidRequest)
		jsonErr(w, fmt.Sprintf("ttl_seconds must be between 0 and %d", int(remote.MaxRunnerTTL/time.Second)),
			http.StatusBadRequest)
		return
	}
	configs, err := store.MintRunners(pool, req.Count, executorpool.RunnerOptions{
		Server: s.agentConnectURL(r), Pin: s.transportPin(), TTL: ttl,
		Actor: executorpool.CredentialActor(pool.ID, cred.ID), CredentialID: cred.ID,
	})
	var capErr *statedb.PoolAtCapacityError
	switch {
	case errors.As(err, &capErr):
		hubmetrics.ExecutorPoolMintRefusals.Inc(hubmetrics.ExecutorPoolRefusalMaxRunners)
		writeJSONStatus(w, http.StatusConflict, map[string]any{
			"error": err.Error(), "code": "executor_pool_max_runners",
			"runners": capErr.Live, "requested": capErr.Requested, "max_runners": capErr.Max,
		})
		return
	case errors.Is(err, executorpool.ErrRevoked):
		hubmetrics.ExecutorPoolMintRefusals.Inc(hubmetrics.ExecutorPoolRefusalRevoked)
		writeJSONStatus(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized", "code": "pool_credential_revoked"})
		return
	case err != nil:
		writePoolErr(w, err)
		return
	}
	hubmetrics.ExecutorPoolRunnersMinted.Add(float64(len(configs)))
	s.poolChanged(pool.ID)
	w.Header().Set("Cache-Control", "no-store")
	writeJSONStatus(w, http.StatusCreated, map[string]any{
		"pool_id": pool.ID, "runners": configs,
		"notice": "Each token is single-use and expires as stated; the runner it enrolls takes one run and is retired.",
	})
}

// poolRetireRequest is a controller asking for runners to be retired.
type poolRetireRequest struct {
	// Runners are enrollment IDs, as the runner configurations and the feed's
	// runner states name them; 1..executorpool.MaxRunnersPerRequest.
	Runners []string `json:"runners"`
}

// poolRetireResult is what became of one runner a controller asked to retire.
type poolRetireResult struct {
	EnrollmentID string `json:"enrollment_id"`
	// Outcome is "retired" (this request retired it), "busy" (it holds a run,
	// and was left alone), "gone" (already retired) or "unknown" (no runner of
	// this pool has that ID).
	Outcome string `json:"outcome"`
	// State is the runner's state as the hub read it, "" when unknown.
	State string `json:"state,omitempty"`
}

// Outcomes of a retirement request.
const (
	poolRetireRetired = "retired"
	poolRetireBusy    = "busy"
	poolRetireGone    = "gone"
	poolRetireUnknown = "unknown"
)

// handlePoolControllerRetire serves POST /api/pool-controller/runners/retire
// (Task 20483): a controller scaling its pool down, or giving back a runner it
// minted and did not start.
//
// The hub decides, by its own record, never by what the controller believes:
// a pending runner — minted, not enrolled — is retired and its token revoked
// in one transaction, so it cannot enroll afterwards; an idle runner is
// retired only while it is still idle, in the update that retires it, so one
// another member hands a run to in the same moment is left with its run; a
// busy runner is never retired here. A retired idle runner is told so on its
// connection, wherever it is held, and exits with success — which is how its
// controller learns it may delete the machine. The controller asks for
// runners of its own pool only: an ID of another pool's runner is "unknown",
// the answer an ID that does not exist gets.
func (s *Server) handlePoolControllerRetire(w http.ResponseWriter, r *http.Request) {
	store, pool, cred, _, ok := s.authenticatePoolController(w, r, false)
	if !ok {
		return
	}
	var req poolRetireRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if len(req.Runners) < 1 || len(req.Runners) > executorpool.MaxRunnersPerRequest {
		jsonErr(w, fmt.Sprintf("runners must name between 1 and %d runners", executorpool.MaxRunnersPerRequest),
			http.StatusBadRequest)
		return
	}
	// Every ID is checked before any is acted on, so a malformed request
	// retires nothing.
	ids := make([]string, 0, len(req.Runners))
	seen := map[string]bool{}
	for _, raw := range req.Runners {
		id := strings.TrimSpace(raw)
		if id == "" || len(id) > 64 {
			jsonErr(w, "each runner is an enrollment id", http.StatusBadRequest)
			return
		}
		if !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	actor := executorpool.CredentialActor(pool.ID, cred.ID)
	results := make([]poolRetireResult, 0, len(ids))
	changed := false
	for _, id := range ids {
		res := poolRetireResult{EnrollmentID: id, Outcome: poolRetireUnknown}
		row, err := store.RunnerOf(id)
		if err != nil || row.PoolID != pool.ID {
			results = append(results, res)
			continue
		}
		res.Outcome, res.State = s.retireControllerRunner(store, row, actor)
		if res.Outcome == poolRetireRetired {
			changed = true
		}
		results = append(results, res)
	}
	if changed {
		s.poolChanged(pool.ID)
	}
	w.Header().Set("Cache-Control", "no-store")
	jsonOK(w, map[string]any{"pool_id": pool.ID, "results": results})
}

// retireControllerRunner retires one runner a controller asked about, by the
// hub's record: pending and idle runners are retired by a conditional update,
// busy ones never. A runner that moves on between the read and the update —
// pending to idle as it enrolls, idle to busy as it is handed a run — is read
// again and judged as what it is now, once; anything still in motion after
// that is reported busy, and the controller asks again on its next pass.
func (s *Server) retireControllerRunner(store *executorpool.Store, row statedb.ExecutorPoolRunnerRow, actor string) (outcome, state string) {
	for attempt := 0; attempt < 2; attempt++ {
		if attempt > 0 {
			fresh, err := store.RunnerOf(row.EnrollmentID)
			if err != nil {
				return poolRetireUnknown, ""
			}
			row = fresh
		}
		switch row.State {
		case statedb.PoolRunnerPending:
			retired, err := store.RetirePendingRunner(row.EnrollmentID,
				"its controller scaled the pool down before it enrolled", actor)
			if err != nil {
				fmt.Fprintf(os.Stderr, "ui: retire pending runner %s: %v\n", row.EnrollmentID, err)
				return poolRetireBusy, row.State
			}
			if retired {
				hubmetrics.ExecutorPoolRunnersRetired.Inc("scaled_down")
				return poolRetireRetired, statedb.PoolRunnerRetired
			}
		case statedb.PoolRunnerIdle:
			if s.retirePoolRunnerBy(actor, row.ExecutorID, "its controller scaled the pool down", statedb.PoolRunnerIdle) {
				return poolRetireRetired, statedb.PoolRunnerRetired
			}
		case statedb.PoolRunnerBusy:
			return poolRetireBusy, row.State
		default:
			return poolRetireGone, row.State
		}
	}
	return poolRetireBusy, row.State
}
