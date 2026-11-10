package kubecontroller

// fakehub_test.go is a hub's pool-controller endpoints, faked: the demand
// feed as a long-poll with revisions, runner minting with real bundles, and
// retirement by the hub's own record — pending and idle retire, busy never.
// Tests move runners through their states (enroll, assign, finish) the way
// the real hub would as agents connect and runs settle.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/cloop/pkg/executor/remote"
	"github.com/blechschmidt/cloop/pkg/executorpool"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

const (
	fakeCredentialID = "AAAAAAAAAAAAAAAA"
	fakeCredential   = "cloop_pool1_" + fakeCredentialID + ".c2VjcmV0c2VjcmV0c2VjcmV0c2VjcmV0c2VjcmV0"
)

type fakeHub struct {
	t   *testing.T
	srv *httptest.Server

	mu         sync.Mutex
	credential string
	poolID     string
	poolName   string
	maxRunners int
	demand     int
	runners    map[string]*executorpool.RunnerState
	order      []string
	minted     int
	retired    []string
	retireReqs [][]string
	mintReqs   []int
	feedReqs   int
	// down answers every request 503; refuse answers 401; legacy answers
	// the feed as a hub that predates runner states.
	down    bool
	refuse  bool
	legacy  bool
	waiters []chan struct{}
	// tokens are the runner tokens minted, by enrollment ID.
	tokens map[string]string
	pin    string
	// projects is the demand by project (Task 20484); noStorage answers as a
	// hub older than runner storage: no queued_projects, and holds neither
	// recorded nor echoed.
	projects  []executorpool.ProjectDemand
	noStorage bool
	// noEcho records holds and does not echo them, as no real hub does: the
	// controller must not start a runner whose holds the hub did not confirm.
	noEcho bool
	// mintHolds records what each mint request declared its runners hold.
	mintHolds [][]string
	// reports are the controller's storage reports, in order.
	reports []map[string]any
}

func newFakeHub(t *testing.T) *fakeHub {
	t.Helper()
	h := &fakeHub{t: t, credential: fakeCredential, poolID: "pool-abcdefghijklmnop", poolName: "k8s",
		maxRunners: 10, runners: map[string]*executorpool.RunnerState{}, tokens: map[string]string{}}
	h.srv = httptest.NewTLSServer(http.HandlerFunc(h.route))
	t.Cleanup(func() {
		h.mu.Lock()
		h.wakeLocked()
		h.mu.Unlock()
		h.srv.CloseClientConnections()
		h.srv.Close()
	})
	return h
}

func (h *fakeHub) wakeLocked() {
	for _, w := range h.waiters {
		close(w)
	}
	h.waiters = nil
}

// change applies fn to the hub's state and wakes the feed.
func (h *fakeHub) change(fn func()) {
	h.mu.Lock()
	defer h.mu.Unlock()
	fn()
	h.wakeLocked()
}

func (h *fakeHub) snapshotLocked() executorpool.Snapshot {
	s := executorpool.Snapshot{PoolID: h.poolID, Name: h.poolName, MaxRunners: h.maxRunners, Demand: h.demand,
		RunnerStates: []executorpool.RunnerState{}, At: time.Now().UTC()}
	if !h.noStorage {
		s.QueuedProjects = []executorpool.ProjectDemand{}
		for _, d := range h.projects {
			if d.Queued > 0 {
				s.QueuedProjects = append(s.QueuedProjects, d)
			}
		}
	}
	for _, id := range h.order {
		r := h.runners[id]
		if r == nil {
			continue
		}
		s.RunnerStates = append(s.RunnerStates, *r)
		switch r.State {
		case statedb.PoolRunnerBusy:
			s.Busy++
		case statedb.PoolRunnerIdle:
			s.Idle++
		case statedb.PoolRunnerPending:
			s.Pending++
		}
	}
	s.Runners = s.Busy + s.Idle + s.Pending
	s.Spare = max(0, h.maxRunners-s.Runners)
	s.Wanted = min(s.Spare, max(0, s.Demand-s.Idle-s.Pending))
	b, _ := json.Marshal(struct {
		D, M     int
		States   []executorpool.RunnerState
		Projects []executorpool.ProjectDemand
	}{s.Demand, s.MaxRunners, s.RunnerStates, s.QueuedProjects})
	sum := sha256.Sum256(b)
	s.Revision = hex.EncodeToString(sum[:8])
	return s
}

func (h *fakeHub) route(w http.ResponseWriter, r *http.Request) {
	h.mu.Lock()
	down, refuse := h.down, h.refuse
	authorized := r.Header.Get("Authorization") == "Bearer "+h.credential
	h.mu.Unlock()
	if down {
		writeHubJSON(w, 503, map[string]any{"error": "the hub is restarting"})
		return
	}
	if refuse || !authorized {
		writeHubJSON(w, 401, map[string]any{"error": "unauthorized", "code": "pool_credential_invalid"})
		return
	}
	switch {
	case r.Method == http.MethodGet && r.URL.Path == hubFeedPath:
		h.handleFeed(w, r)
	case r.Method == http.MethodPost && r.URL.Path == hubRunnersPath:
		h.handleMint(w, r)
	case r.Method == http.MethodPost && r.URL.Path == hubRetirePath:
		h.handleRetire(w, r)
	case r.Method == http.MethodPost && r.URL.Path == hubStatusPath && !h.isLegacyStorage():
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		h.mu.Lock()
		h.reports = append(h.reports, body)
		h.mu.Unlock()
		writeHubJSON(w, 200, map[string]any{"ok": true})
	default:
		writeHubJSON(w, 404, map[string]any{"error": "no route"})
	}
}

func writeHubJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func (h *fakeHub) handleFeed(w http.ResponseWriter, r *http.Request) {
	after := r.URL.Query().Get("after")
	wait, _ := strconv.Atoi(r.URL.Query().Get("wait"))
	deadline := time.NewTimer(time.Duration(wait) * time.Second)
	defer deadline.Stop()
	h.mu.Lock()
	h.feedReqs++
	h.mu.Unlock()
	for {
		h.mu.Lock()
		snap := h.snapshotLocked()
		wake := make(chan struct{})
		h.waiters = append(h.waiters, wake)
		pin := h.pin
		if h.legacy {
			snap.RunnerStates = nil
		}
		h.mu.Unlock()
		msg := FeedMessage{Type: "snapshot", Snapshot: snap, Server: "wss://hub.example/api/executors/connect", Pin: pin}
		if snap.Revision != after {
			writeHubJSON(w, 200, msg)
			return
		}
		select {
		case <-r.Context().Done():
			return
		case <-deadline.C:
			writeHubJSON(w, 200, msg)
			return
		case <-wake:
		}
	}
}

func (h *fakeHub) isLegacyStorage() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.noStorage
}

func (h *fakeHub) handleMint(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Count int      `json:"count"`
		Holds []string `json:"holds"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	h.mu.Lock()
	defer h.mu.Unlock()
	h.mintReqs = append(h.mintReqs, req.Count)
	h.mintHolds = append(h.mintHolds, append([]string(nil), req.Holds...))
	if len(req.Holds) != 0 && len(req.Holds) != req.Count {
		writeHubJSON(w, 400, map[string]any{"error": "holds must name every runner"})
		return
	}
	live := 0
	for _, r := range h.runners {
		if r != nil {
			live++
		}
	}
	if live+req.Count > h.maxRunners {
		writeHubJSON(w, 409, map[string]any{"error": "the pool is at max_runners", "code": "executor_pool_max_runners"})
		return
	}
	now := time.Now().UTC()
	var out []executorpool.RunnerConfig
	for i := 0; i < req.Count; i++ {
		h.minted++
		id := fmt.Sprintf("Enr-%02d_x", h.minted)
		name := fmt.Sprintf("%s-r%02d", h.poolName, h.minted)
		token := "clrt1." + id + ".secret" + strconv.Itoa(h.minted) + ".mac"
		h.tokens[id] = token
		exp := now.Add(remote.MaxRunnerTTL)
		bundle, err := remote.Bundle{Server: "wss://hub.example/api/executors/connect", Token: token, Pin: h.pin,
			EnrollmentID: id, Name: name, ExpiresAt: exp}.Encode()
		if err != nil {
			writeHubJSON(w, 500, map[string]any{"error": err.Error()})
			return
		}
		holds := ""
		if len(req.Holds) == req.Count && !h.noStorage {
			holds = req.Holds[i]
		}
		h.runners[id] = &executorpool.RunnerState{EnrollmentID: id, Name: name, State: statedb.PoolRunnerPending,
			MintedAt: now, ExpiresAt: exp, CredentialID: fakeCredentialID, Holds: holds}
		h.order = append(h.order, id)
		echo := holds
		if h.noEcho {
			echo = ""
		}
		out = append(out, executorpool.RunnerConfig{EnrollmentID: id, Name: name, Token: token, Bundle: bundle,
			Server: "wss://hub.example/api/executors/connect", ExpiresAt: exp, Ephemeral: true, Holds: echo})
	}
	h.wakeLocked()
	writeHubJSON(w, 201, map[string]any{"pool_id": h.poolID, "runners": out})
}

func (h *fakeHub) handleRetire(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Runners []string `json:"runners"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	h.mu.Lock()
	defer h.mu.Unlock()
	h.retireReqs = append(h.retireReqs, append([]string(nil), req.Runners...))
	var results []RetireResult
	for _, id := range req.Runners {
		rs := h.runners[id]
		switch {
		case rs == nil:
			results = append(results, RetireResult{EnrollmentID: id, Outcome: "unknown"})
		case rs.State == statedb.PoolRunnerBusy:
			results = append(results, RetireResult{EnrollmentID: id, Outcome: "busy", State: rs.State})
		default:
			delete(h.runners, id)
			h.retired = append(h.retired, id)
			results = append(results, RetireResult{EnrollmentID: id, Outcome: "retired", State: statedb.PoolRunnerRetired})
		}
	}
	h.wakeLocked()
	writeHubJSON(w, 200, map[string]any{"pool_id": h.poolID, "results": results})
}

// ── test helpers ───────────────────────────────────────────────────────────

func (h *fakeHub) setDemand(n int) { h.change(func() { h.demand = n }) }

// enroll moves runner id to idle, enrolled at at.
func (h *fakeHub) enroll(id string, at time.Time) {
	h.change(func() {
		if r := h.runners[id]; r != nil {
			r.State, r.EnrolledAt = statedb.PoolRunnerIdle, at.UTC()
		}
	})
}

// assign hands runner id a queued run.
func (h *fakeHub) assign(id string) {
	h.change(func() {
		if r := h.runners[id]; r != nil {
			r.State, r.BusyAt = statedb.PoolRunnerBusy, time.Now().UTC()
			if h.demand > 0 {
				h.demand--
			}
		}
	})
}

// assignProject hands runner id a queued run of tenant, as the hub does: only
// a runner holding nothing or that tenant, and the runner records it.
func (h *fakeHub) assignProject(id, tenant, name, owner string) bool {
	ok := false
	h.change(func() {
		r := h.runners[id]
		if r == nil || r.State != statedb.PoolRunnerIdle || (r.Holds != "" && r.Holds != tenant) {
			return
		}
		r.State, r.BusyAt = statedb.PoolRunnerBusy, time.Now().UTC()
		r.Project, r.ProjectName, r.ProjectOwner = tenant, name, owner
		if h.demand > 0 {
			h.demand--
		}
		for i := range h.projects {
			if h.projects[i].Tenant == tenant && h.projects[i].Queued > 0 {
				h.projects[i].Queued--
			}
		}
		ok = true
	})
	return ok
}

// queue adds n runs of tenant to the demand.
func (h *fakeHub) queue(tenant string, n int) {
	h.change(func() {
		h.demand += n
		for i := range h.projects {
			if h.projects[i].Tenant == tenant {
				h.projects[i].Queued += n
				return
			}
		}
		h.projects = append(h.projects, executorpool.ProjectDemand{Tenant: tenant, Queued: n})
	})
}

// runner returns a copy of runner id's state.
func (h *fakeHub) runner(id string) (executorpool.RunnerState, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	r := h.runners[id]
	if r == nil {
		return executorpool.RunnerState{}, false
	}
	return *r, true
}

// storageReports returns the controller's storage reports so far.
func (h *fakeHub) storageReports() []map[string]any {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]map[string]any(nil), h.reports...)
}

// lastMintHolds is what the last mint request declared.
func (h *fakeHub) lastMintHolds() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.mintHolds) == 0 {
		return nil
	}
	return h.mintHolds[len(h.mintHolds)-1]
}

// finish settles runner id's run and retires it.
func (h *fakeHub) finish(id string) {
	h.change(func() { delete(h.runners, id) })
}

// ids lists the live runners in mint order, with their states.
func (h *fakeHub) states() map[string]string {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := map[string]string{}
	for id, r := range h.runners {
		if r != nil {
			out[id] = r.State
		}
	}
	return out
}

func (h *fakeHub) retiredIDs() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := append([]string(nil), h.retired...)
	sort.Strings(out)
	return out
}

func (h *fakeHub) retireRequests() [][]string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([][]string(nil), h.retireReqs...)
}

func (h *fakeHub) mintedCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.minted
}

func (h *fakeHub) set(fn func(h *fakeHub)) { h.change(func() { fn(h) }) }

// url is the hub's base URL.
func (h *fakeHub) url() string { return h.srv.URL }

// hasToken reports whether s contains any runner token the hub minted.
func (h *fakeHub) leaksToken(s string) string {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, tok := range h.tokens {
		if strings.Contains(s, tok) {
			return tok
		}
	}
	if strings.Contains(s, h.credential) {
		return h.credential
	}
	return ""
}
