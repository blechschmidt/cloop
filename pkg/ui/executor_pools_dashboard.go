package ui

// executor_pools_dashboard.go: adding a Kubernetes executor pool in one step,
// and watching it scale (Task 20486).
//
//	POST /api/executor-pools                    with "credential": true, the pool, its access list and a
//	                                            controller credential at once, and the commands that install
//	                                            its controller with them filled in (shown once)
//	POST /api/executor-pools/{id}/cordon        hold the pool: no run is handed to its runners, no runner minted
//	POST /api/executor-pools/{id}/uncordon      release it
//	GET  /charts/cloop-executor-controller.tgz  this build's executor controller chart, for `helm install`
//
// The pool list and a pool's detail carry what the hub knows of its
// controllers and what that adds up to: the newest controller's build and
// protocol, when one last made contact, its count of the runners' volumes, and
// the problems executorpool.Assess finds — the same function hub doctor calls,
// so the dashboard and the doctor cannot disagree about a stuck pool.

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/blechschmidt/cloop/deploy/helm"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/executorpool"
	"github.com/blechschmidt/cloop/pkg/kubecontroller"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// poolCreateRequest is POST /api/executor-pools's body: the pool's definition,
// and what makes the create a one-step install.
type poolCreateRequest struct {
	executorpool.Spec
	// Audience admits these principals to the pool's access list in the
	// same request, before anything can use the pool. Empty leaves it open to
	// everyone a project binding sends there.
	Audience []poolAudienceRequest `json:"audience,omitempty"`
	// Credential mints a controller credential with the pool and returns it,
	// once, with the commands that install the controller.
	Credential bool `json:"credential,omitempty"`
	// Kubernetes shapes those commands.
	Kubernetes *poolInstallRequest `json:"kubernetes,omitempty"`
}

// poolInstallRequest is how the controller's release is to be installed.
type poolInstallRequest struct {
	// Namespace and Release default to cloop-<pool> and the pool's name.
	Namespace string `json:"namespace,omitempty"`
	Release   string `json:"release,omitempty"`
	// MinRunners is the idle target: runners kept started beyond the demand.
	MinRunners int `json:"min_runners,omitempty"`
	// Persistence gives runners volumes that outlive them.
	Persistence *poolPersistenceRequest `json:"persistence,omitempty"`
}

// poolPersistenceRequest is the runner volumes' defaults.
type poolPersistenceRequest struct {
	Enabled       bool   `json:"enabled"`
	StorageClass  string `json:"storage_class,omitempty"`
	Size          string `json:"size,omitempty"`
	ReclaimPolicy string `json:"reclaim_policy,omitempty"`
}

// poolInstallView is the install block a create answers with.
type poolInstallView struct {
	// Command is the block to paste; empty when Unavailable says why not.
	Command     string `json:"command,omitempty"`
	Unavailable string `json:"unavailable,omitempty"`
	Chart       string `json:"chart"`
	Release     string `json:"release"`
	Namespace   string `json:"namespace"`
	// CredentialSecret is the Secret the credential is kept in.
	CredentialSecret string `json:"credential_secret"`
	HubURL           string `json:"hub_url"`
	Pin              string `json:"pin,omitempty"`
	ImageTag         string `json:"image_tag"`
	// Notes are what to know before pasting.
	Notes []string `json:"notes,omitempty"`
}

// poolHealthView is what the hub knows of a pool's controllers, and what it
// makes of it.
type poolHealthView struct {
	// Problems are executorpool.Assess's, most serious first.
	Problems []executorpool.Problem `json:"problems"`
	// Waiting counts the runs in the pool's queue.
	Waiting int `json:"waiting"`
	// LastContact is the latest use of any live controller credential.
	LastContact time.Time `json:"last_contact,omitzero"`
	// Controller is the controller that made it.
	Controller *poolControllerView `json:"controller,omitempty"`
	// Storage is the newest count of the runners' volumes a controller sent.
	Storage *executorpool.StorageUsage `json:"storage,omitempty"`
	// LiveCredentials counts the controller credentials not revoked.
	LiveCredentials int `json:"live_credentials"`
}

// poolControllerView is the controller a pool heard from last.
type poolControllerView struct {
	CredentialID string    `json:"credential_id"`
	Version      string    `json:"version,omitempty"`
	Protocol     int       `json:"protocol"`
	Behind       bool      `json:"behind"`
	LastContact  time.Time `json:"last_contact"`
}

// poolHealth reads pool's health; nil when it cannot be read, which the views
// leave out rather than guess.
func (s *Server) poolHealth(store *executorpool.Store, pool executorpool.Pool) *poolHealthView {
	in, err := store.HealthInputFor(pool)
	if err != nil {
		return nil
	}
	h := &poolHealthView{Problems: executorpool.Assess(in), Waiting: in.Waiting, LastContact: in.LastContact(),
		Storage: in.Storage()}
	if h.Problems == nil {
		h.Problems = []executorpool.Problem{}
	}
	for _, c := range in.Credentials {
		if !c.Revoked() {
			h.LiveCredentials++
		}
	}
	if c, ok := in.Controller(); ok {
		h.Controller = &poolControllerView{CredentialID: c.ID, Version: c.ControllerVersion,
			Protocol: c.ControllerProtocol, Behind: c.ControllerProtocol < executorpool.ControllerProtocol,
			LastContact: c.LastUsedAt}
	}
	return h
}

// newPoolView is a pool as the API shows it, with its health when asked.
func (s *Server) newPoolView(store *executorpool.Store, p executorpool.Pool, health bool) poolView {
	v := poolView{Pool: p, Binding: p.Binding(), Cordoned: p.Cordoned()}
	if health && store != nil && !p.Revoked() {
		v.Health = s.poolHealth(store, p)
	}
	return v
}

// validPoolAudience refuses an access list entry the store would refuse,
// before the pool it is for exists.
func validPoolAudience(entries []poolAudienceRequest) error {
	if len(entries) > 64 {
		return errors.New("at most 64 access list entries at once")
	}
	for _, e := range entries {
		kind := strings.ToLower(strings.TrimSpace(e.Kind))
		value := strings.TrimSpace(e.Value)
		switch {
		case kind != "user" && kind != "group" && kind != "role":
			return fmt.Errorf("access list entry %q: the principal kind must be user, group or role", e.Kind+":"+e.Value)
		case value == "" || len(value) > 320 || strings.ContainsAny(value, "\n\r\t"):
			return fmt.Errorf("access list entry %q names no principal", e.Kind+":"+e.Value)
		}
	}
	return nil
}

// poolInstallPlan is the controller install for spec as this request reached
// the hub: its URL, its pin, the chart it serves and the image tag of its
// build.
func (s *Server) poolInstallPlan(r *http.Request, spec executorpool.Spec, req *poolInstallRequest) kubecontroller.InstallPlan {
	base := s.externalBaseURL(r)
	tag, _ := kubecontroller.ControllerImageTag(hubVersion())
	plan := kubecontroller.InstallPlan{Chart: base + kubecontroller.ChartArchivePath, PoolName: spec.Name, HubURL: base,
		HubCAPin: s.transportPin(), ImageTag: tag, MaxRunners: spec.MaxRunners}
	if req != nil {
		plan.Namespace, plan.Release, plan.MinRunners = req.Namespace, req.Release, req.MinRunners
		if p := req.Persistence; p != nil && p.Enabled {
			plan.Persistence = &kubecontroller.InstallPersistence{StorageClass: p.StorageClass, Size: p.Size,
				ReclaimPolicy: p.ReclaimPolicy}
		}
	}
	return plan.Normalize()
}

// poolInstall renders plan's install block for the credential just minted.
// Over plaintext it carries no command: a controller reaches a hub over HTTPS
// only, so a command naming an http URL would install a pool that comes up
// Invalid.
func (s *Server) poolInstall(r *http.Request, plan kubecontroller.InstallPlan, credential string) poolInstallView {
	v := poolInstallView{Chart: plan.Chart, Release: plan.Release, Namespace: plan.Namespace,
		CredentialSecret: plan.CredentialSecret, HubURL: plan.HubURL, Pin: plan.HubCAPin, ImageTag: plan.ImageTag}
	if !s.requestIsTLS(r) {
		v.Unavailable = "The executor controller reaches a hub over HTTPS only, and this page was served over plain " +
			"HTTP, so there is no URL to give it. Serve the hub over TLS (ui.tls, or a proxy that sets " +
			"X-Forwarded-Proto: https), then mint a credential for this pool there: cloop executor pool " +
			"rotate-credential " + plan.PoolName + "."
		return v
	}
	v.Command = plan.Script(credential)
	if _, note := kubecontroller.ControllerImageTag(hubVersion()); note != "" {
		v.Notes = append(v.Notes, note)
	}
	if plan.HubCAPin == "" {
		v.Notes = append(v.Notes, "This hub has no certificate of its own to pin (ui.tls), so the controller trusts "+
			"whatever certificate the system store accepts for "+plan.HubURL+".")
	}
	v.Notes = append(v.Notes,
		"helm fetches the chart from this hub over HTTPS: a hub whose certificate the machine running helm does not "+
			"trust needs --ca-file <the CA's PEM> on helm install, and --set-file pool.hubCABundle=<the same file> for "+
			"the controller.",
		"Give the controller a namespace of its own: the commands hold it to the restricted Pod Security profile, "+
			"and one controller serves one namespace.")
	return v
}

// handleExecutorPoolCreate serves POST /api/executor-pools.
func (s *Server) handleExecutorPoolCreate(w http.ResponseWriter, r *http.Request) {
	if !s.requireExecutorAdmin(w, r) {
		return
	}
	var req poolCreateRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	// Everything that could refuse is checked before anything is created: a
	// pool whose access list could not be written would be open to everyone.
	spec := req.Spec.Normalize()
	if err := spec.Validate(); err != nil {
		writePoolErr(w, err)
		return
	}
	if err := validPoolAudience(req.Audience); err != nil {
		jsonErr(w, err.Error(), http.StatusBadRequest)
		return
	}
	var plan kubecontroller.InstallPlan
	if req.Credential || req.Kubernetes != nil {
		plan = s.poolInstallPlan(r, spec, req.Kubernetes)
		if s.requestIsTLS(r) {
			if err := plan.Validate(); err != nil {
				jsonErr(w, "the controller's install: "+err.Error(), http.StatusBadRequest)
				return
			}
		}
	}
	store, ok := s.poolStoreFor(w)
	if !ok {
		return
	}
	audience := make([]executorpool.AudienceEntry, 0, len(req.Audience))
	for _, a := range req.Audience {
		audience = append(audience, executorpool.AudienceEntry{Kind: a.Kind, Value: a.Value})
	}
	// One transaction: the pool, its access list and its credential exist
	// together or not at all.
	made, err := store.CreateWith(req.Spec, s.auditActor(r), audience, req.Credential)
	if err != nil {
		writePoolErr(w, err)
		return
	}
	p := made.Pool
	resp := map[string]any{"ok": true}
	if made.Credential != nil {
		resp["credential"], resp["token"] = *made.Credential, made.Token
		resp["install"] = s.poolInstall(r, plan, made.Token)
		resp["notice"] = "This credential is shown once and cannot be recovered — only its hash is stored. It lets " +
			"a controller start this pool's runners until it or the pool is revoked; keep it in the controller's " +
			"Secret, as the commands below do."
	}
	if len(req.Audience) > 0 {
		s.broadcastAuditAppend("executor_pool.audience")
	}
	if req.Credential {
		s.broadcastAuditAppend("executor_pool.credential_mint")
	}
	s.broadcastAuditAppend("executor_pool.create")
	s.poolChanged(p.ID)
	if fresh, err := store.Get(p.ID); err == nil {
		p = fresh
	}
	resp["pool"] = s.newPoolView(store, p, false)
	if entries, err := store.Audience(p.ID); err == nil {
		if entries == nil {
			entries = []statedb.ExecutorAudienceEntry{}
		}
		resp["audience"] = entries
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSONStatus(w, http.StatusCreated, resp)
}

// poolCordonRequest is the body of a cordon, optional.
type poolCordonRequest struct {
	Reason string `json:"reason,omitempty"`
}

// handleExecutorPoolCordon serves POST /api/executor-pools/{id}/cordon.
func (s *Server) handleExecutorPoolCordon(w http.ResponseWriter, r *http.Request) {
	s.setPoolCordon(w, r, true)
}

// handleExecutorPoolUncordon serves POST /api/executor-pools/{id}/uncordon.
func (s *Server) handleExecutorPoolUncordon(w http.ResponseWriter, r *http.Request) {
	s.setPoolCordon(w, r, false)
}

func (s *Server) setPoolCordon(w http.ResponseWriter, r *http.Request, cordon bool) {
	store, p, ok := s.poolFromPath(w, r)
	if !ok {
		return
	}
	var req poolCordonRequest
	if !decodeOptionalJSON(w, r, &req) {
		return
	}
	next, changed, err := store.Cordon(p.ID, cordon, s.auditActor(r), req.Reason)
	if err != nil {
		writePoolErr(w, err)
		return
	}
	if changed {
		s.broadcastAuditAppend("executor_pool.cordon")
		// The runs waiting for it say so, and the feeds and dispatchers of
		// every member hear of it: a controller stops starting runners at once.
		s.refreshQueuedReasons(store, next)
		s.poolChanged(p.ID)
	}
	jsonOK(w, map[string]any{"ok": true, "changed": changed, "pool": s.newPoolView(store, next, false)})
}

// isPublicChart reports whether r is for the executor controller chart: the
// first kind of servedBeforeAuth entry, a file compiled into the binary and
// identical on every hub of the same build, holding nothing of any tenant's.
// It has to be: `helm install <URL>` sends no credential the hub accepts.
func isPublicChart(r *http.Request) bool {
	return r.URL.Path == kubecontroller.ChartArchivePath && (r.Method == http.MethodGet || r.Method == http.MethodHead)
}

// handleExecutorControllerChart serves the chart archive.
func (s *Server) handleExecutorControllerChart(w http.ResponseWriter, r *http.Request) {
	body, sum, err := helm.ExecutorControllerChart()
	if err != nil {
		jsonErr(w, "the executor controller chart could not be packed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	etag := `"` + sum[:32] + `"`
	h := w.Header()
	h.Set("Content-Type", "application/gzip")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Content-Disposition", `attachment; filename="`+helm.ExecutorControllerChartName+`.tgz"`)
	h.Set("Cache-Control", "no-cache")
	h.Set("ETag", etag)
	if match := r.Header.Get("If-None-Match"); match != "" && strings.Contains(match, etag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	h.Set("Content-Length", fmt.Sprint(len(body)))
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	_, _ = w.Write(body)
}

// noteControllerIdentity records the build and protocol a controller names
// itself with on this request, when they differ from what its credential's
// row holds.
func (s *Server) noteControllerIdentity(store *executorpool.Store, r *http.Request, cred executorpool.Credential) {
	version := executorpool.ParseControllerUserAgent(r.Header.Get("User-Agent"))
	protocol := executorpool.ParseControllerProtocol(r.Header.Get(executorpool.ControllerProtocolHeader))
	if version == cred.ControllerVersion && protocol == cred.ControllerProtocol {
		return
	}
	if err := store.NoteController(cred.ID, version, protocol); err != nil {
		return
	}
	// A controller that changed build is worth a look in the pool list and
	// the hub's health report.
	s.notePoolDashboard(cred.PoolID)
}

// executorPoolRunnerView is the pool an executor is a runner of.
type executorPoolRunnerView struct {
	PoolID   string `json:"pool_id"`
	PoolName string `json:"pool_name"`
	Runner   string `json:"runner"`
	State    string `json:"state"`
}

// applyPoolRunners marks the executors that are a pool's runners: remote
// agents the pool store knows as one. A store that cannot be read marks none,
// and the cards are drawn as ordinary devices.
func (s *Server) applyPoolRunners(views []executorView) []executorView {
	var store *executorpool.Store
	names := map[string]string{}
	for i := range views {
		v := &views[i]
		if v.Kind != executor.KindRemoteAgent {
			continue
		}
		if store == nil {
			st, err := s.poolStore()
			if err != nil {
				return views
			}
			store = st
		}
		r, err := store.RunnerByExecutor(v.ID)
		if err != nil {
			continue
		}
		if _, ok := names[r.PoolID]; !ok {
			if p, err := store.Get(r.PoolID); err == nil {
				names[r.PoolID] = p.Name
			}
		}
		v.PoolRunner = &executorPoolRunnerView{PoolID: r.PoolID, PoolName: names[r.PoolID], Runner: r.Name, State: r.State}
	}
	return views
}

// ── telling dashboards ──────────────────────────────────────────────────────

// poolDashboardDelay coalesces a burst of pool changes — a controller
// scaling up mints, enrolls and hands out runners within a second — into one
// notice to the dashboards.
var poolDashboardDelay = 2 * time.Second

// poolDashboard holds the pending notices.
type poolDashboard struct {
	mu      sync.Mutex
	pending map[string]bool
	timer   *time.Timer
	// closed is set at shutdown: nothing is scheduled after it.
	closed bool
	// notify, when set, is told instead of the dashboards; tests set it.
	notify func(poolID string)
}

// notePoolDashboard tells every hub member's open dashboards, within
// poolDashboardDelay, that poolID changed: the Executors tab redraws its pool
// list from the API. The notice is the fleet's executor_update, which those
// dashboards already follow, with the pool's binding as its executor.
func (s *Server) notePoolDashboard(poolID string) {
	if strings.TrimSpace(poolID) == "" {
		return
	}
	d := &s.poolDash
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return
	}
	if d.pending == nil {
		d.pending = map[string]bool{}
	}
	d.pending[poolID] = true
	if d.timer != nil {
		return
	}
	d.timer = time.AfterFunc(poolDashboardDelay, func() {
		d.mu.Lock()
		if d.closed {
			d.mu.Unlock()
			return
		}
		ids := make([]string, 0, len(d.pending))
		for id := range d.pending {
			ids = append(ids, id)
		}
		d.pending, d.timer = nil, nil
		notify := d.notify
		d.mu.Unlock()
		for _, id := range ids {
			if notify != nil {
				notify(id)
				continue
			}
			s.broadcastExecutorUpdate("pool", "pool:"+id)
		}
	})
}

// stopPoolDashboard drops pending notices at shutdown.
func (s *Server) stopPoolDashboard() {
	d := &s.poolDash
	d.mu.Lock()
	if d.timer != nil {
		d.timer.Stop()
	}
	d.pending, d.timer, d.closed = nil, nil, true
	d.mu.Unlock()
}
