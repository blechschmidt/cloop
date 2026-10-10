package ui

// cluster_api.go: the endpoints hub members call on each other, and the one
// an operator reads the cluster's state from (Task 20354).
//
// The internal endpoints live under clusterAPIPrefix and are served by
// clusterInternalBypass, ahead of user authentication — a member calling
// another carries no user credential, only its peer signature — and they
// answer nothing without one. They are deliberately not in the route table:
// that table is the surface a *user* can reach, and these are not part of it.

import (
	"context"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/authz"
	"github.com/blechschmidt/cloop/pkg/hubcluster"
	"github.com/blechschmidt/cloop/pkg/jsonbody"
	"github.com/blechschmidt/cloop/pkg/state"
)

const (
	clusterAPIPrefix      = "/api/internal/cluster/"
	clusterAPIAutoResume  = clusterAPIPrefix + "autoresume"
	clusterAPILeases      = clusterAPIPrefix + "leases"
	clusterAPIRevokeLease = clusterAPIPrefix + "leases/revoke"
	clusterAPIAgentOp     = clusterAPIPrefix + "agent"
	// clusterAPIOffboardClaude: a departed identity's Claude logins on the
	// member asked (Task 20400). See offboard_claude.go.
	clusterAPIOffboardClaude = clusterAPIPrefix + "offboard/claude"
	// clusterAPIGrantRevoked: a grant revoked on another member, for this one
	// to take back from what it holds (Task 20403). See grant_revoke.go.
	clusterAPIGrantRevoked = clusterAPIPrefix + "grants/revoked"
)

// clusterInternalBypass serves the member-to-member endpoints. Anything under
// the prefix without a verified peer signature is refused here, before any
// other layer sees it — there is no user for whom these exist.
func (s *Server) clusterInternalBypass(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, clusterAPIPrefix) {
			next.ServeHTTP(w, r)
			return
		}
		if !requirePeer(w, r) {
			return
		}
		if s.serveForwardedProxy(w, r) {
			return
		}
		switch {
		case r.URL.Path == clusterAPIAutoResume && r.Method == http.MethodPost:
			s.handleClusterAutoResume(w, r)
		case r.URL.Path == clusterAPILeases && r.Method == http.MethodGet:
			s.handleClusterLeases(w, r)
		case r.URL.Path == clusterAPIRevokeLease && r.Method == http.MethodPost:
			s.handleClusterRevokeLease(w, r)
		case r.URL.Path == clusterAPIAgentOp && r.Method == http.MethodPost:
			s.handleClusterAgentOp(w, r)
		case r.URL.Path == clusterAPIOffboardClaude && r.Method == http.MethodPost:
			s.handleClusterOffboardClaude(w, r)
		case r.URL.Path == clusterAPIGrantRevoked && r.Method == http.MethodPost:
			s.handleClusterGrantRevoked(w, r)
		default:
			jsonErr(w, "unknown cluster endpoint", http.StatusNotFound)
		}
	})
}

// handleClusterAutoResume restarts a cap-paused project on the leader's
// behalf: the project's agent is connected here, so only this member can
// dispatch to it. Everything the leader checked is checked again — the state
// may have changed in the round trip.
func (s *Server) handleClusterAutoResume(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Project string `json:"project"`
	}
	if !jsonbody.Decode(w, r, &req, jsonbody.Options{Limit: 64 << 10}) {
		return
	}
	if strings.TrimSpace(req.Project) == "" {
		jsonErr(w, "project is required", http.StatusBadRequest)
		return
	}
	if !s.isRegisteredProject(req.Project) {
		jsonErr(w, "not a registered project", http.StatusNotFound)
		return
	}
	st, err := state.LoadLite(req.Project)
	if err != nil || st == nil {
		jsonErr(w, "could not load the project", http.StatusConflict)
		return
	}
	if !st.PauseReason.AutoResumable(s.clock()) || s.projectExecuting(req.Project) {
		jsonOK(w, map[string]any{"ok": true, "started": false})
		return
	}
	if err := s.startAutoResumeRun(req.Project); err != nil {
		s.repauseIfOverDiskLimit(req.Project, err)
		jsonErr(w, err.Error(), http.StatusConflict)
		return
	}
	jsonOK(w, map[string]any{"ok": true, "started": true})
}

// isRegisteredProject reports whether dir is one of this hub's projects. An
// internal call names a directory, and a member must not be steerable into
// dispatching a run in an arbitrary one.
func (s *Server) isRegisteredProject(dir string) bool {
	for _, e := range s.allProjectEntries() {
		if sameDir(e.Path, dir) {
			return true
		}
	}
	return false
}

// ── status ──────────────────────────────────────────────────────────────────

// clusterStatus is GET /api/cluster: who serves this control plane, who
// leads, and what each member holds.
type clusterStatus struct {
	Clustered bool                 `json:"clustered"`
	Self      string               `json:"self,omitempty"`
	Leader    string               `json:"leader,omitempty"`
	Members   []hubcluster.Member  `json:"members"`
	Owners    []clusterOwnerStatus `json:"owners,omitempty"`
	Bus       hubcluster.BusStats  `json:"bus"`
	At        time.Time            `json:"at"`
}

type clusterOwnerStatus struct {
	Kind     string    `json:"kind"`
	Key      string    `json:"key"`
	Member   string    `json:"member"`
	Alive    bool      `json:"alive"`
	Since    time.Time `json:"since"`
	Executor string    `json:"executor,omitempty"`
}

func (s *Server) handleClusterStatus(w http.ResponseWriter, r *http.Request) {
	jsonOK(w, s.clusterStatusSnapshot())
}

func (s *Server) clusterStatusSnapshot() clusterStatus {
	out := clusterStatus{At: time.Now().UTC(), Members: []hubcluster.Member{}}
	n := s.clusterNode()
	if n == nil {
		return out
	}
	out.Clustered = true
	out.Self = n.ID()
	out.Leader = n.LeaderID()
	out.Members = n.Members()
	out.Bus = n.BusStats()
	owners, err := n.Owned("")
	if err == nil {
		for _, o := range owners {
			if o.Kind == ownerCCAuth {
				// The key is a user identity; the panel does not need it.
				o.Key = ""
			}
			st := clusterOwnerStatus{Kind: o.Kind, Key: o.Key, Member: o.InstanceID,
				Alive: o.Alive, Since: o.ClaimedAt()}
			if o.Kind == ownerRun {
				var meta runOwnerMeta
				if o.Meta(&meta) == nil {
					st.Executor = meta.Executor
				}
			}
			out.Owners = append(out.Owners, st)
		}
	}
	sort.SliceStable(out.Owners, func(i, j int) bool {
		if out.Owners[i].Kind != out.Owners[j].Kind {
			return out.Owners[i].Kind < out.Owners[j].Kind
		}
		return out.Owners[i].Key < out.Owners[j].Key
	})
	return out
}

// clusterStatusRoute is the route-table entry for GET /api/cluster. Admin-only
// like the rest of the fleet's plumbing: member addresses are internal
// network topology.
func (s *Server) clusterStatusRoute() routeSpec {
	return routeSpec{
		Pattern: "GET /api/cluster",
		Handler: s.handleClusterStatus,
		Perm:    authz.PermExecutorManage,
		Scope:   scopeGlobal,
	}
}

// fanOut calls every live peer's internal endpoint concurrently and returns
// the answers that arrived, keyed by member. A peer that cannot be reached is
// reported in errs rather than failing the whole call: a revocation that
// reached two members of three is worth reporting as exactly that.
func (s *Server) fanOut(ctx context.Context, method, path string, in any, newOut func() any) (map[string]any, map[string]error) {
	n := s.clusterNode()
	results := map[string]any{}
	errs := map[string]error{}
	if n == nil {
		return results, errs
	}
	type answer struct {
		id  string
		out any
		err error
	}
	peers := n.Peers()
	ch := make(chan answer, len(peers))
	for _, m := range peers {
		go func(m hubcluster.Member) {
			out := newOut()
			err := n.Call(ctx, m, method, path, in, out)
			ch <- answer{id: m.ID, out: out, err: err}
		}(m)
	}
	for range peers {
		a := <-ch
		if a.err != nil {
			errs[a.id] = a.err
			continue
		}
		results[a.id] = a.out
	}
	return results, errs
}
