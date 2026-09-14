// Offboarding from the dashboard (Task 20261).
//
// The REST counterpart to `cloop hub user offboard`. Both are thin: resolution,
// planning and execution live in pkg/offboard, because two implementations of
// "who counts as this person" would eventually disagree and the one that
// under-matched would report success over a live credential.
//
// One route, two behaviours, chosen by a body field rather than by method:
// POST with dry_run:true resolves and reports, POST with dry_run:false severs.
// A GET preview was the obvious alternative and is worse — resolving a person's
// entire credential footprint is exactly the read an attacker with a stolen
// operator cookie would enumerate with, and putting it behind the same
// permission as the write keeps the two from drifting apart.

package ui

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/blechschmidt/cloop/pkg/apierror"
	"github.com/blechschmidt/cloop/pkg/offboard"
	"github.com/blechschmidt/cloop/pkg/oidcauth"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// offboardRequest is the POST body for /api/users/offboard.
type offboardRequest struct {
	// Identity is an email address or IdP subject.
	Identity string `json:"identity"`
	// Reason is recorded on every audit event. Required for a real run.
	Reason string `json:"reason"`
	// DryRun resolves and reports without changing anything.
	DryRun bool `json:"dry_run"`
}

// handleUserOffboard serves POST /api/users/offboard.
func (s *Server) handleUserOffboard(w http.ResponseWriter, r *http.Request) {
	var req offboardRequest
	limitJSONBody(w, r, maxJSONBodyBytes)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.WriteError(w, apierror.New(apierror.CodeInvalidInput,
			"invalid JSON body: "+err.Error()))
		return
	}
	identity := strings.TrimSpace(req.Identity)
	if identity == "" {
		apierror.WriteError(w, apierror.New(apierror.CodeInvalidInput,
			"an email address or IdP subject is required"))
		return
	}
	reason := strings.TrimSpace(req.Reason)
	if !req.DryRun && len(reason) < 4 {
		apierror.WriteError(w, apierror.New(apierror.CodeInvalidInput,
			"a reason is required and must say something: this action is recorded "+
				"in the audit trail and read back during review"))
		return
	}

	grant := s.grantFor(r)
	actor := grant.subjectLabel()

	// Refusing to offboard yourself is not paternalism, it is the difference
	// between an admin action and a footgun: the run revokes every session the
	// target holds, which would include the one issuing the request, and the
	// deny binding it writes would then lock the operator out of undoing it.
	// `cloop hub user offboard` from a shell is the escape hatch, and the
	// message says so.
	if selfOffboard(grant, identity) {
		apierror.WriteError(w, apierror.New(apierror.CodeForbidden,
			"refusing to offboard the identity making this request: it would revoke "+
				"this session and deny the account that must undo it. Use "+
				"`cloop hub user offboard` from a shell if this is really intended"))
		return
	}

	db, closer, err := s.openControlPlaneDB()
	if err != nil {
		apierror.WriteError(w, apierror.New(apierror.CodeUnavailable, err.Error()))
		return
	}
	defer closer()

	rep, err := offboard.Run(offboard.Options{
		DB:       db,
		Identity: identity,
		Reason:   reason,
		Actor:    actor,
		Via:      "ui",
		DryRun:   req.DryRun,
		Projects: offboard.RegistryProjects(s.allProjectEntries()),
		Tasks:    offboard.LocalTasks(),
		Leases:   hubLeases{},
		Sessions: s.offboardSessions(),
	})
	if err != nil {
		apierror.WriteFromError(w, err)
		return
	}

	// A partial run is reported with 200 and failures attached rather than as
	// an error status. The caller needs the report either way — it names what
	// *was* severed, which an error body would not carry — and the frontend
	// renders the failures prominently.
	jsonOK(w, rep)
}

// selfOffboard reports whether the identity names the caller.
//
// Both spellings of the caller are checked: the signed-in subject, and the
// owner binding of an API token when the request carried one. A token minted on
// a user's behalf *is* that user for this purpose — offboarding through one's
// own PAT would revoke the very token authorising the request, mid-transaction.
func selfOffboard(g *grant, identity string) bool {
	identity = strings.TrimSpace(identity)
	if g == nil || identity == "" {
		return false
	}
	matches := func(sub, email string) bool {
		if email != "" && strings.EqualFold(email, identity) {
			return true
		}
		if sub != "" && (sub == identity || "sub:"+sub == identity) {
			return true
		}
		return false
	}
	if s := g.subject; s != nil && matches(s.Sub, s.Email) {
		return true
	}
	if t := g.token; t != nil && t.Owner != nil && matches(t.Owner.Sub, t.Owner.Email) {
		return true
	}
	return false
}

// openControlPlaneDB opens the hub's own database.
//
// Grants, sessions and tokens live in the control plane's database rather than
// in a managed project's, for the same reason executor bindings do: a tenant
// must not be able to change who may act by writing to a database it owns.
func (s *Server) openControlPlaneDB() (*statedb.DB, func(), error) {
	dbPath := state.DBPath(s.WorkDir)
	// Stat first. statedb.Open would *create* the file and run migrations, so
	// a misconfigured WorkDir would silently produce an empty control plane
	// and an offboarding that reports nothing to sever — the most dangerous
	// possible answer to "is this person out?".
	if _, err := os.Stat(dbPath); err != nil {
		return nil, nil, fmt.Errorf("the control plane has no state database at %s yet", dbPath)
	}
	db, err := statedb.Open(dbPath)
	if err != nil {
		return nil, nil, fmt.Errorf("open control-plane database: %w", err)
	}
	return db, func() { _ = db.Close() }, nil
}

// ---------------------------------------------------------------------------
// sessions
// ---------------------------------------------------------------------------

// offboardSessions adapts this hub's authenticator, or returns nil when OIDC is
// off — a hub with no sign-on has no sessions to sever.
func (s *Server) offboardSessions() offboard.Sessions {
	if !s.oidcEnabled() {
		return nil
	}
	return authSessions{a: s.OIDC}
}

// authSessions routes session severing through the running authenticator.
//
// Not through the control-plane table directly, for two reasons that both end
// with the person staying signed in: the authenticator serves reads from a
// 30-second cache that a row deletion underneath it does not invalidate, and a
// hub without a durable session store keeps its sessions in process memory,
// where that table is empty however many people are signed in.
type authSessions struct{ a *oidcauth.Authenticator }

func (s authSessions) List() ([]offboard.SessionRef, error) {
	recs, err := s.a.ListSessions()
	if err != nil {
		return nil, err
	}
	out := make([]offboard.SessionRef, 0, len(recs))
	for _, rec := range recs {
		out = append(out, offboard.SessionRef{
			ID:        rec.ID,
			Subject:   rec.Identity.Sub,
			Email:     rec.Identity.Email,
			IP:        rec.IP,
			IssuedAt:  rec.IssuedAt,
			ExpiresAt: rec.ExpiresAt,
		})
	}
	return out, nil
}

func (s authSessions) Revoke(id, actor, reason string) (bool, error) {
	return s.a.RevokeSession(id, actor, reason)
}

// ---------------------------------------------------------------------------
// leases
// ---------------------------------------------------------------------------

// hubLeases adapts this process's live-lease registry.
//
// The registry, not a freshly-constructed broker: a Broker's lease map is
// per-instance, and openBrokers builds a new one per request, so asking it what
// is leased would always answer "nothing". liveLeases is the set of leases this
// hub actually materialised and still holds.
type hubLeases struct{}

func (hubLeases) LiveLeases() []offboard.LeaseRef {
	snap := liveLeases.snapshot()
	out := make([]offboard.LeaseRef, 0, len(snap))
	for _, sl := range snap {
		if sl == nil || sl.lease == nil {
			continue
		}
		out = append(out, offboard.LeaseRef{
			ID:         sl.lease.ID,
			ExecutorID: sl.lease.ExecutorID,
			ProjectID:  sl.lease.ProjectID,
			Kinds:      leaseKindNames(sl.lease.Kinds()),
			ExpiresAt:  sl.lease.ExpiresAt,
		})
	}
	return out
}

// Release closes the lease, which wipes the credential directory, clears its
// durable row and releases it at the broker that issued it — the same teardown
// a finishing task performs, rather than a second, partial one.
func (hubLeases) Release(id string) {
	for _, sl := range liveLeases.snapshot() {
		if sl != nil && sl.lease != nil && sl.lease.ID == id {
			sl.Close()
			return
		}
	}
}

func leaseKindNames(kinds []secretbroker.Kind) []string {
	out := make([]string, 0, len(kinds))
	for _, k := range kinds {
		out = append(out, string(k))
	}
	return out
}
