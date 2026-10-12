package ui

// SCIM 2.0 provisioning at /scim/v2 (Task 20415).
//
// An identity provider — Microsoft Entra ID, Okta — creates, updates,
// deactivates and deletes the hub's users and groups here, and the hub acts on
// it: a deactivation suspends the person in one transaction, a deletion runs
// the full offboarding. pkg/scim reads the protocol and pkg/provision decides
// what each request means; this file is the door.
//
// # Authentication
//
// The routes are served before the hub's own authentication
// (servedBeforeAuth) and authenticate themselves, with one credential and
// nothing else: a cloop_scim_ bearer minted for the provider. Not a session —
// a provider has none — and, deliberately, not an API token or the static
// admin token either. The credential can deactivate every administrator on the
// hub; one that also opened the dashboard would be a second admin credential
// nobody listed, and one the dashboard's credentials could stand in for would
// be a SCIM endpoint any leaked PAT could drive. So the token chain does not
// recognise it, and this door recognises nothing else.
//
// A wrong credential counts against the client address's failure lockout, as
// a wrong static token does. A right one is held to its own rate limit
// (ui.oidc.scim.rate_limit_per_minute), answered 429 with Retry-After past it.
// Every refusal is in the audit trail, at most thirty rows a minute.
//
// # Bodies
//
// Read through pkg/jsonbody like every other body on the hub, which accepts
// application/scim+json here and nowhere else, as forgeryGuard does
// (bodyTypeAccepted). The rule a cross-site form cannot satisfy still holds:
// neither type is one a form can send, and every request carries a bearer.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/jsonbody"
	"github.com/blechschmidt/cloop/pkg/logger"
	"github.com/blechschmidt/cloop/pkg/offboard"
	"github.com/blechschmidt/cloop/pkg/provision"
	"github.com/blechschmidt/cloop/pkg/scim"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/state"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// scimMountPath is where the SCIM service lives: the base URL an identity
// provider is given is the hub's address followed by this.
const scimMountPath = "/scim/v2"

// scimBodyLimit bounds a SCIM request body. A group PATCH adding members is
// the largest a provider sends; a megabyte holds tens of thousands of ids.
const scimBodyLimit = 1 << 20

// scimMediaTypes are the body types the SCIM routes take besides
// application/json.
var scimMediaTypes = []string{scim.MediaType}

// isSCIMEndpoint reports whether r is for the SCIM service.
func isSCIMEndpoint(r *http.Request) bool {
	p := r.URL.Path
	return p == scimMountPath || strings.HasPrefix(p, scimMountPath+"/")
}

// scimState is the hub's provisioning machinery, opened by OpenSCIM.
type scimState struct {
	mu       sync.Mutex
	db       *statedb.DB
	cfg      config.SCIMConfig
	dir      *provision.Directory
	svc      *provision.Service
	verifier *provision.Verifier
	limiter  *provision.RateLimiter
	refusals refusalLog
}

// OpenSCIM opens the provisioning directory over the hub's control plane and
// returns it, for the resolver to read provisioned groups from at every
// decision. `cloop ui` calls it when single sign-on is on, before building
// the resolver; an error is fatal there, for the reason an unreadable role
// store is: a hub that came up without its directory would grant no
// provisioned group and know of no deactivation.
func (s *Server) OpenSCIM(cfg config.SCIMConfig) (*provision.Directory, error) {
	claim, err := provision.ParseMatchClaim(cfg.MatchClaim)
	if err != nil {
		return nil, err
	}
	s.scim.mu.Lock()
	defer s.scim.mu.Unlock()
	if s.scim.dir != nil {
		return s.scim.dir, nil
	}
	db, err := statedb.Open(state.DBPath(s.WorkDir))
	if err != nil {
		return nil, fmt.Errorf("open control-plane database: %w", err)
	}
	db = db.AsControlPlane()
	dir, err := provision.NewDirectory(db, claim, provision.WithDirectoryErrors(func(err error) {
		s.log().Warn(logger.EventAuthz, 0, "could not refresh the SCIM directory — still serving the last copy",
			map[string]interface{}{"error": err.Error()})
	}))
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("read the SCIM directory: %w", err)
	}
	s.scim.db, s.scim.cfg, s.scim.dir = db, cfg, dir
	s.scim.svc = &provision.Service{
		DB:        db,
		Config:    provision.Config{MatchClaim: claim, OffboardAfter: time.Duration(cfg.EffectiveOffboardAfterDays()) * 24 * time.Hour},
		Directory: dir,
		Hub:       scimHub{s: s},
	}
	s.scim.verifier = &provision.Verifier{DB: db}
	s.scim.limiter = provision.NewRateLimiter(cfg.EffectiveRateLimitPerMinute())
	return dir, nil
}

// scimOpen returns the open service, its verifier and its limiter, or nils on
// a hub that did not open them.
func (s *Server) scimOpen() (*provision.Service, *provision.Verifier, *provision.RateLimiter) {
	s.scim.mu.Lock()
	defer s.scim.mu.Unlock()
	return s.scim.svc, s.scim.verifier, s.scim.limiter
}

// scimDirectory returns the open directory, or nil.
func (s *Server) scimDirectory() *provision.Directory {
	s.scim.mu.Lock()
	defer s.scim.mu.Unlock()
	return s.scim.dir
}

// closeSCIM releases the directory's database handle.
func (s *Server) closeSCIM() {
	s.scim.mu.Lock()
	db := s.scim.db
	s.scim.db, s.scim.dir, s.scim.svc, s.scim.verifier, s.scim.limiter = nil, nil, nil, nil, nil
	s.scim.mu.Unlock()
	if db != nil {
		_ = db.Close()
	}
}

// onSCIMInvalidate is a directory change made through another hub member.
func (s *Server) onSCIMInvalidate() {
	if d := s.scimDirectory(); d != nil {
		d.Invalidate()
	}
}

// watchSCIMOffboards runs the full offboarding for users inactive past
// ui.oidc.scim.offboard_after_days. On the leader only: two members running
// one person's offboarding at once would race to report it.
func (s *Server) watchSCIMOffboards(ctx context.Context) {
	svc, _, _ := s.scimOpen()
	if svc == nil || svc.Config.OffboardAfter <= 0 {
		return
	}
	tick := time.NewTicker(15 * time.Minute)
	defer tick.Stop()
	for {
		func() {
			defer recoverGoroutine("scim offboard sweep")
			n, err := svc.OffboardExpired(ctx)
			if err != nil && ctx.Err() == nil {
				s.log().Warn(logger.EventAuthz, 0, "SCIM offboard sweep failed",
					map[string]interface{}{"error": err.Error()})
			}
			if n > 0 {
				s.log().Info(logger.EventAuthz, 0, "offboarded users inactive at the identity provider",
					map[string]interface{}{"count": n})
			}
		}()
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

// ── the hub's side of a change ──────────────────────────────────────────────

// scimHub is provision.Hub for this server.
type scimHub struct{ s *Server }

// Collaborators are the offboarding collaborators the dashboard's offboarding
// uses (handleUserOffboard), so a suspension or a deletion reaches exactly
// what an operator's offboarding from this hub reaches.
func (h scimHub) Collaborators(db *statedb.DB) offboard.Options {
	s := h.s
	o := offboard.Options{
		Projects: offboard.RegistryProjects(s.allProjectEntries()),
		Tasks:    offboard.LocalTasks(),
		Leases:   hubLeases{s: s, actor: "scim", reason: "its holder was deactivated or deleted at the identity provider"},
		Sessions: s.offboardSessions(),
		Claude:   s.offboardClaude(),
	}
	if secrets, err := offboard.StoreSecrets(db); err == nil {
		o.Secrets = secrets
	}
	return o
}

// Severed ends, in this process and on the other members, what a committed
// change ended in the database behind their caches.
func (h scimHub) Severed(v provision.Severance) {
	s := h.s
	if v.RoleBindings {
		s.invalidateRoleCache()
	}
	// Revoked in the transaction, behind the token manager's back: the
	// streams those tokens opened close now, here and on every member.
	s.announceTokensRevoked(v.Tokens)
	for _, id := range v.Sessions {
		s.onSessionChanged(id)
	}
	if len(v.GrantsSuspended) > 0 {
		// A suspended grant is taken back from the workloads holding it, as
		// a revoked one is (Task 20403): the colleague's run that was
		// spending this person's PAT gives it up now, not when its lease
		// lapses.
		ctx := context.Background()
		for _, id := range v.GrantsSuspended {
			s.cascadeGrantRevocation(ctx, secretbroker.GrantRevocation{
				GrantID: id, Actor: v.Actor, Reason: "its owner was deactivated at the identity provider",
				At: time.Now().UTC(), ControlPlane: state.DBPath(s.WorkDir),
			})
		}
	}
	if len(v.GrantsSuspended) > 0 || len(v.GrantsResumed) > 0 {
		s.broadcastSecretsUpdate("provisioned", "")
	}
	if v.Offboard != nil {
		s.offboardAftermath(*v.Offboard)
	}
}

// DirectoryChanged tells the other members to re-read the directory.
func (h scimHub) DirectoryChanged() {
	h.s.publishInvalidate(invalidateSCIM, map[string]string{"scim": "directory"})
}

// ── the door ────────────────────────────────────────────────────────────────

// scimBase is the SCIM base URL as the provider addresses it: ui.external_url
// when set, else the origin the request came to.
func (s *Server) scimBase(r *http.Request) string {
	if ext := strings.TrimRight(strings.TrimSpace(s.ExternalURL), "/"); ext != "" {
		return ext + scimMountPath
	}
	if o, ok := s.requestOrigin(r); ok {
		return o.String() + scimMountPath
	}
	return scimMountPath
}

// scimEnter authenticates a SCIM request and holds it to its credential's
// rate limit. It reports the actor and the service, or has answered.
func (s *Server) scimEnter(w http.ResponseWriter, r *http.Request) (provision.Actor, *provision.Service, bool) {
	svc, verifier, limiter := s.scimOpen()
	if svc == nil || !s.oidcEnabled() {
		s.scimRefuse(w, r, "sso_disabled", "", scim.Errorf(http.StatusNotFound, "",
			"SCIM provisioning needs single sign-on on this hub (ui.oidc.enabled): it matches provisioned "+
				"users to the identities that sign in"))
		return provision.Actor{}, nil, false
	}
	ip := s.clientIP(r)
	if s.authLockoutActive(ip) {
		w.Header().Set("Retry-After", strconv.Itoa(authLockoutSeconds))
		s.scimRefuse(w, r, "locked_out", "", scim.Errorf(http.StatusTooManyRequests, "",
			"too many failed attempts from this address; try again later"))
		return provision.Actor{}, nil, false
	}
	raw := scimBearer(r)
	if raw == "" {
		s.scimUnauthorized(w, r, "unauthenticated", "", "this endpoint takes a SCIM credential: "+
			"Authorization: Bearer cloop_scim_…")
		return provision.Actor{}, nil, false
	}
	v, err := verifier.Verify(raw)
	switch {
	case errors.Is(err, provision.ErrRevoked):
		// The secret was right: no lockout, and the provider's log says why.
		s.scimUnauthorized(w, r, "revoked", "", "this SCIM credential was revoked")
		return provision.Actor{}, nil, false
	case err != nil:
		if !errors.Is(err, provision.ErrNoCredential) && !errors.Is(err, provision.ErrBadCredential) {
			s.log().Warn(logger.EventAuthz, 0, "SCIM credential could not be checked",
				map[string]interface{}{"error": err.Error()})
		}
		s.recordAuthFailure(ip)
		s.scimUnauthorized(w, r, "unknown", "", "the credential is not a valid SCIM credential for this hub")
		return provision.Actor{}, nil, false
	}
	if ok, wait := limiter.Allow(v.Actor.CredentialID); !ok {
		w.Header().Set("Retry-After", strconv.Itoa(int(wait/time.Second)+1))
		s.scimRefuse(w, r, "rate_limited", v.Actor.Name, scim.Errorf(http.StatusTooManyRequests, "",
			"this SCIM credential's rate limit (%d a minute, ui.oidc.scim.rate_limit_per_minute) is spent",
			limiter.PerMinute()))
		return provision.Actor{}, nil, false
	}
	return v.Actor, svc, true
}

// scimBearer is the Authorization header's bearer value. The header only:
// unlike the dashboard's bearerCredential, never ?token=, which a provider has
// no reason to use and every access log would keep.
func scimBearer(r *http.Request) string {
	h := strings.TrimSpace(r.Header.Get("Authorization"))
	if len(h) > 7 && strings.EqualFold(h[:7], "bearer ") {
		return strings.TrimSpace(h[7:])
	}
	return ""
}

func (s *Server) scimUnauthorized(w http.ResponseWriter, r *http.Request, reason, client, detail string) {
	w.Header().Set("WWW-Authenticate", `Bearer realm="cloop SCIM"`)
	s.scimRefuse(w, r, reason, client, scim.Errorf(http.StatusUnauthorized, "", "%s", detail))
}

// scimRefuse answers a refused SCIM request and records it, bounded like
// every other refusal the hub records.
func (s *Server) scimRefuse(w http.ResponseWriter, r *http.Request, reason, client string, err *scim.Error) {
	scim.WriteError(w, err)
	ok, suppressed := s.scim.refusals.admit(time.Now())
	if !ok {
		return
	}
	payload := map[string]any{
		"reason": reason, "method": r.Method, "path": truncate(r.URL.Path, 200), "ip": s.clientIP(r),
	}
	if ua := r.UserAgent(); ua != "" {
		payload["user_agent"] = truncate(ua, 256)
	}
	if client != "" {
		payload["client"] = client
	}
	if suppressed > 0 {
		payload["suppressed"] = suppressed
	}
	if strings.TrimSpace(s.WorkDir) == "" {
		return
	}
	db, derr := s.controlPlaneDB()
	if derr != nil {
		return
	}
	defer db.Close()
	actor := "anonymous"
	if client != "" {
		actor = "scim:" + client
	}
	if aerr := db.AppendAuditEvent(&statedb.AuditEvent{
		Actor: actor, EventType: string(auditaction.ActionSCIMRequestRefused), EntityType: "scim",
		EntityID: r.Method + " " + truncate(r.URL.Path, 200), Payload: statedb.MarshalAuditPayload(payload),
	}); aerr != nil {
		s.log().Warn(logger.EventAuthz, 0, "SCIM refusal audit", map[string]interface{}{"error": aerr.Error()})
	}
}

// scimBody reads a request body as JSON or application/scim+json.
func (s *Server) scimBody(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	data, refusal := jsonbody.Read(w, r, jsonbody.Options{Limit: scimBodyLimit, MediaTypes: scimMediaTypes})
	if refusal != nil {
		status := refusal.Status()
		scim.WriteError(w, scim.Errorf(status, scimTypeFor(status), "%s", refusal.Message))
		return nil, false
	}
	return data, true
}

func scimTypeFor(status int) string {
	if status == http.StatusBadRequest {
		return scim.ErrInvalidSyntax
	}
	return ""
}

// scimRespond writes an operation's result.
func scimRespond(w http.ResponseWriter, res provision.Result, err error) {
	if err != nil {
		scim.WriteError(w, err)
		return
	}
	if res.Version > 0 {
		w.Header().Set("ETag", scim.ETag(res.Version))
	}
	if res.Location != "" {
		w.Header().Set("Location", res.Location)
	}
	if res.Status == http.StatusNoContent || res.Resource == nil {
		w.WriteHeader(res.Status)
		return
	}
	scim.WriteJSON(w, res.Status, res.Resource)
}

// ── discovery ───────────────────────────────────────────────────────────────

func (s *Server) handleSCIMServiceProviderConfig(w http.ResponseWriter, r *http.Request) {
	if _, _, ok := s.scimEnter(w, r); !ok {
		return
	}
	scim.WriteJSON(w, http.StatusOK, scim.ServiceProviderConfig(s.scimBase(r)))
}

func (s *Server) handleSCIMResourceTypes(w http.ResponseWriter, r *http.Request) {
	if _, _, ok := s.scimEnter(w, r); !ok {
		return
	}
	docs := scim.ResourceTypes(s.scimBase(r))
	scim.WriteJSON(w, http.StatusOK, scim.NewListResponse(len(docs), scim.Page{StartIndex: 1, Count: len(docs)}, docs))
}

func (s *Server) handleSCIMResourceType(w http.ResponseWriter, r *http.Request) {
	if _, _, ok := s.scimEnter(w, r); !ok {
		return
	}
	doc, found := scim.FindByID(scim.ResourceTypes(s.scimBase(r)), r.PathValue("id"))
	if !found {
		scim.WriteError(w, scim.NotFound("ResourceType", r.PathValue("id")))
		return
	}
	scim.WriteJSON(w, http.StatusOK, doc)
}

func (s *Server) handleSCIMSchemas(w http.ResponseWriter, r *http.Request) {
	if _, _, ok := s.scimEnter(w, r); !ok {
		return
	}
	docs := scim.Schemas(s.scimBase(r))
	scim.WriteJSON(w, http.StatusOK, scim.NewListResponse(len(docs), scim.Page{StartIndex: 1, Count: len(docs)}, docs))
}

func (s *Server) handleSCIMSchema(w http.ResponseWriter, r *http.Request) {
	if _, _, ok := s.scimEnter(w, r); !ok {
		return
	}
	doc, found := scim.FindByID(scim.Schemas(s.scimBase(r)), r.PathValue("id"))
	if !found {
		scim.WriteError(w, scim.NotFound("Schema", r.PathValue("id")))
		return
	}
	scim.WriteJSON(w, http.StatusOK, doc)
}

// handleSCIMFallback answers every other path under /scim/v2 with a SCIM
// error rather than the dashboard's page: Bulk, /Me and anything mistyped.
func (s *Server) handleSCIMFallback(w http.ResponseWriter, r *http.Request) {
	if _, _, ok := s.scimEnter(w, r); !ok {
		return
	}
	switch r.Method {
	case http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		scim.WriteError(w, scim.Errorf(http.StatusNotFound, "",
			"%s is not a SCIM endpoint this hub serves (Users, Groups, ServiceProviderConfig, ResourceTypes, "+
				"Schemas); bulk operations and /Me are not supported", r.URL.Path))
	default:
		w.Header().Set("Allow", "GET, POST, PUT, PATCH, DELETE")
		scim.WriteError(w, scim.Errorf(http.StatusMethodNotAllowed, "", "%s is not supported", r.Method))
	}
}

// ── users ───────────────────────────────────────────────────────────────────

func (s *Server) handleSCIMUsersList(w http.ResponseWriter, r *http.Request) {
	_, svc, ok := s.scimEnter(w, r)
	if !ok {
		return
	}
	list, err := svc.ListUsers(r.URL.Query(), s.scimBase(r))
	if err != nil {
		scim.WriteError(w, err)
		return
	}
	scim.WriteJSON(w, http.StatusOK, list)
}

func (s *Server) handleSCIMUserCreate(w http.ResponseWriter, r *http.Request) {
	actor, svc, ok := s.scimEnter(w, r)
	if !ok {
		return
	}
	body, ok := s.scimBody(w, r)
	if !ok {
		return
	}
	res, err := svc.CreateUser(r.Context(), actor, body, s.scimBase(r))
	scimRespond(w, res, err)
}

func (s *Server) handleSCIMUserGet(w http.ResponseWriter, r *http.Request) {
	_, svc, ok := s.scimEnter(w, r)
	if !ok {
		return
	}
	res, err := svc.GetUser(r.PathValue("id"), r.URL.Query(), s.scimBase(r))
	scimRespond(w, res, err)
}

func (s *Server) handleSCIMUserReplace(w http.ResponseWriter, r *http.Request) {
	actor, svc, ok := s.scimEnter(w, r)
	if !ok {
		return
	}
	body, ok := s.scimBody(w, r)
	if !ok {
		return
	}
	res, err := svc.ReplaceUser(r.Context(), actor, r.PathValue("id"), body, r.Header.Get("If-Match"), s.scimBase(r))
	scimRespond(w, res, err)
}

func (s *Server) handleSCIMUserPatch(w http.ResponseWriter, r *http.Request) {
	actor, svc, ok := s.scimEnter(w, r)
	if !ok {
		return
	}
	body, ok := s.scimBody(w, r)
	if !ok {
		return
	}
	res, err := svc.PatchUser(r.Context(), actor, r.PathValue("id"), body, r.Header.Get("If-Match"), s.scimBase(r))
	scimRespond(w, res, err)
}

func (s *Server) handleSCIMUserDelete(w http.ResponseWriter, r *http.Request) {
	actor, svc, ok := s.scimEnter(w, r)
	if !ok {
		return
	}
	res, err := svc.DeleteUser(r.Context(), actor, r.PathValue("id"), r.Header.Get("If-Match"))
	scimRespond(w, res, err)
}

// ── groups ──────────────────────────────────────────────────────────────────

func (s *Server) handleSCIMGroupsList(w http.ResponseWriter, r *http.Request) {
	_, svc, ok := s.scimEnter(w, r)
	if !ok {
		return
	}
	list, err := svc.ListGroups(r.URL.Query(), s.scimBase(r))
	if err != nil {
		scim.WriteError(w, err)
		return
	}
	scim.WriteJSON(w, http.StatusOK, list)
}

func (s *Server) handleSCIMGroupCreate(w http.ResponseWriter, r *http.Request) {
	actor, svc, ok := s.scimEnter(w, r)
	if !ok {
		return
	}
	body, ok := s.scimBody(w, r)
	if !ok {
		return
	}
	res, err := svc.CreateGroup(r.Context(), actor, body, s.scimBase(r))
	scimRespond(w, res, err)
}

func (s *Server) handleSCIMGroupGet(w http.ResponseWriter, r *http.Request) {
	_, svc, ok := s.scimEnter(w, r)
	if !ok {
		return
	}
	res, err := svc.GetGroup(r.PathValue("id"), r.URL.Query(), s.scimBase(r))
	scimRespond(w, res, err)
}

func (s *Server) handleSCIMGroupReplace(w http.ResponseWriter, r *http.Request) {
	actor, svc, ok := s.scimEnter(w, r)
	if !ok {
		return
	}
	body, ok := s.scimBody(w, r)
	if !ok {
		return
	}
	res, err := svc.ReplaceGroup(r.Context(), actor, r.PathValue("id"), body, r.Header.Get("If-Match"), s.scimBase(r))
	scimRespond(w, res, err)
}

func (s *Server) handleSCIMGroupPatch(w http.ResponseWriter, r *http.Request) {
	actor, svc, ok := s.scimEnter(w, r)
	if !ok {
		return
	}
	body, ok := s.scimBody(w, r)
	if !ok {
		return
	}
	res, err := svc.PatchGroup(r.Context(), actor, r.PathValue("id"), body, r.Header.Get("If-Match"), s.scimBase(r))
	scimRespond(w, res, err)
}

func (s *Server) handleSCIMGroupDelete(w http.ResponseWriter, r *http.Request) {
	actor, svc, ok := s.scimEnter(w, r)
	if !ok {
		return
	}
	res, err := svc.DeleteGroup(r.Context(), actor, r.PathValue("id"), r.Header.Get("If-Match"))
	scimRespond(w, res, err)
}
