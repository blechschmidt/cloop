// Device forwarder bindings (Task 20430): the decision that one project's
// runs — optionally only those on one virtual executor — get a forwarder's
// device in their sandbox.
//
// A binding is decided like every other grant. Making one takes
// executor.manage at the hub's global scope, as enrolling a forwarder does —
// a project-scoped role is not enough, because the device belongs to no
// project. It carries a TTL (24 hours unless asked otherwise, 90 days at
// most), it is audited as forwarder.bind and forwarder.unbind, and revoking it
// — or its TTL running out, or the forwarder's own revocation — detaches the
// device from any run holding it, on whichever hub member relays it.
//
// Someone without executor.manage asks through the grant-request flow: POST
// /api/grant-requests with "source": "forwarder" files the request, it lands in
// the approvals inbox of everyone who may decide it, and approving it through
// /api/grant-requests/{id}/approve mints the binding. The requests live in
// their own table (forwarder_binding_requests) because a secret grant request
// names a secret, and this names a forwarder and a project; the routes, the
// inbox, the two-person rule and the CLI are the ones secret requests use.

package ui

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/apierror"
	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/authz"
	"github.com/blechschmidt/cloop/pkg/deviceforward"
	"github.com/blechschmidt/cloop/pkg/executor"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

const (
	// ForwarderBindingTTLDefault is a binding's lifetime when none is asked
	// for.
	ForwarderBindingTTLDefault = 24 * time.Hour
	// ForwarderBindingTTLMax bounds any binding: hardware access is a grant,
	// and grants end.
	ForwarderBindingTTLMax = 90 * 24 * time.Hour
	// forwarderRequestWaitDefault is how long a binding request waits for a
	// decision.
	forwarderRequestWaitDefault = 72 * time.Hour
	// forwarderRequestPrefix marks a binding request's id, so the shared
	// request routes know which flow an id belongs to.
	forwarderRequestPrefix = "fbr_"
	// forwarderBindingPrefix marks a binding's id.
	forwarderBindingPrefix = "fbd_"
)

// forwardedInterface is an L2 binding's sandbox-side shape.
type forwardedInterface struct {
	Target  string `json:"target,omitempty"`
	Address string `json:"address,omitempty"`
	Gateway string `json:"gateway,omitempty"`
	MTU     int    `json:"mtu,omitempty"`
}

func (i forwardedInterface) empty() bool { return i == forwardedInterface{} }

func decodeForwardedInterface(s string) forwardedInterface {
	var i forwardedInterface
	if strings.TrimSpace(s) != "" {
		_ = json.Unmarshal([]byte(s), &i)
	}
	return i
}

func encodeForwardedInterface(i forwardedInterface) string {
	if i.empty() {
		return ""
	}
	b, _ := json.Marshal(i)
	return string(b)
}

// ForwarderBindingInput is one binding to make.
type ForwarderBindingInput struct {
	ForwarderID     string
	Project         string
	VirtualExecutor string
	Interface       forwardedInterface
	TTL             time.Duration
	Note            string
	Actor           string
	RequestID       string
}

// ForwarderBindingInterface builds the L2 shape of a binding, for callers
// outside this package (the CLI).
func ForwarderBindingInterface(target, address, gateway string, mtu int) forwardedInterface {
	return forwardedInterface{Target: strings.TrimSpace(target), Address: strings.TrimSpace(address),
		Gateway: strings.TrimSpace(gateway), MTU: mtu}
}

// errBindingConflict reports an active binding of the same forwarder to the
// same project and virtual executor.
var errBindingConflict = errors.New("the forwarder is already bound to this project")

// CreateForwarderBinding validates and records a binding, and audits it as
// forwarder.bind. It is the one path every surface makes a binding through —
// the dashboard, an approved request and `cloop forward bind` — so the rules
// cannot drift between them. The caller has checked who may.
func CreateForwarderBinding(db *statedb.DB, in ForwarderBindingInput, now time.Time) (statedb.ForwarderBindingRow, error) {
	in.ForwarderID = strings.TrimSpace(in.ForwarderID)
	in.Project = strings.TrimSpace(in.Project)
	in.VirtualExecutor = strings.TrimSpace(in.VirtualExecutor)
	if in.ForwarderID == "" {
		return statedb.ForwarderBindingRow{}, fmt.Errorf("a forwarder is required")
	}
	if in.Project == "" || !filepath.IsAbs(in.Project) {
		return statedb.ForwarderBindingRow{}, fmt.Errorf("a project directory (an absolute path) is required")
	}
	in.Project = policyProjectPath(filepath.Clean(in.Project))
	fwd, err := db.GetForwarder(in.ForwarderID)
	if err != nil {
		return statedb.ForwarderBindingRow{}, fmt.Errorf("%w: %v", deviceforward.ErrForwarderNotFound, err)
	}
	if !fwd.RevokedAt.IsZero() {
		return statedb.ForwarderBindingRow{}, fmt.Errorf("forwarder %s was revoked; enroll it again before binding it", in.ForwarderID)
	}
	dev := unmarshalForwarderDevice(fwd.DeviceJSON)
	if dev.Kind == deviceforward.KindL2 {
		probe := executor.HostInterface{Name: "binding", Source: "fwdprobe0", Target: in.Interface.Target,
			Address: in.Interface.Address, Gateway: in.Interface.Gateway, MTU: in.Interface.MTU}
		if err := executor.ValidateHostInterface(probe); err != nil {
			return statedb.ForwarderBindingRow{}, fmt.Errorf("the segment's sandbox-side settings: %w", err)
		}
	} else if !in.Interface.empty() {
		return statedb.ForwarderBindingRow{}, fmt.Errorf("interface settings apply only to a network segment, and forwarder %s carries a USB device", in.ForwarderID)
	}
	if in.VirtualExecutor != "" {
		if _, found, err := db.VirtualExecutor(in.VirtualExecutor); err != nil || !found {
			return statedb.ForwarderBindingRow{}, fmt.Errorf("no virtual executor %q on this hub", in.VirtualExecutor)
		}
	}
	ttl := in.TTL
	if ttl <= 0 {
		ttl = ForwarderBindingTTLDefault
	}
	if ttl > ForwarderBindingTTLMax {
		return statedb.ForwarderBindingRow{}, fmt.Errorf("a binding lasts at most %s", ForwarderBindingTTLMax)
	}
	existing, err := db.ListForwarderBindings(statedb.ForwarderBindingFilter{ForwarderID: in.ForwarderID, Project: in.Project, ActiveAt: now})
	if err != nil {
		return statedb.ForwarderBindingRow{}, err
	}
	for _, b := range existing {
		if b.VirtualExecutor == in.VirtualExecutor {
			return statedb.ForwarderBindingRow{}, fmt.Errorf("%w (binding %s, until %s); unbind it first",
				errBindingConflict, b.ID, b.ExpiresAt.UTC().Format(time.RFC3339))
		}
	}
	row := statedb.ForwarderBindingRow{
		ID:              forwarderBindingPrefix + shortHash(fmt.Sprintf("%s|%s|%d", in.ForwarderID, in.Project, now.UnixNano()), 16),
		ForwarderID:     in.ForwarderID,
		Project:         in.Project,
		VirtualExecutor: in.VirtualExecutor,
		InterfaceJSON:   encodeForwardedInterface(in.Interface),
		Note:            strings.TrimSpace(in.Note),
		CreatedBy:       in.Actor,
		CreatedAt:       now,
		ExpiresAt:       now.Add(ttl),
		RequestID:       in.RequestID,
	}
	if len(row.Note) > 1024 {
		row.Note = row.Note[:1024]
	}
	if err := db.PutForwarderBinding(row); err != nil {
		return statedb.ForwarderBindingRow{}, err
	}
	statedb.AuditForwarderLifecycle(db.AsControlPlane(), statedb.ForwarderAuditInput{
		Action: auditaction.ActionForwarderBind, ForwarderID: row.ForwarderID, Actor: in.Actor,
		Detail: map[string]any{
			"binding_id": row.ID, "project": row.Project, "virtual_executor": row.VirtualExecutor,
			"expires_at": row.ExpiresAt.UTC().Format(time.RFC3339), "request_id": row.RequestID,
		},
	})
	return row, nil
}

// RevokeForwarderBindingRecord revokes a binding in db and audits it as
// forwarder.unbind. It reports whether this call revoked it. Cutting the live
// relays is the caller's: a hub member announces it, the CLI announces it on
// the bus (AnnounceForwarderRevocation).
func RevokeForwarderBindingRecord(db *statedb.DB, bindingID, actor, reason string, now time.Time) (statedb.ForwarderBindingRow, bool, error) {
	b, err := db.GetForwarderBinding(bindingID)
	if err != nil {
		return statedb.ForwarderBindingRow{}, false, err
	}
	if reason == "" {
		reason = "unbound by " + nonEmpty(actor, "an operator")
	}
	ok, err := db.RevokeForwarderBinding(bindingID, actor, reason, now)
	if err != nil || !ok {
		return b, false, err
	}
	statedb.AuditForwarderLifecycle(db.AsControlPlane(), statedb.ForwarderAuditInput{
		Action: auditaction.ActionForwarderUnbind, ForwarderID: b.ForwarderID, Actor: actor,
		Detail: map[string]any{"binding_id": b.ID, "project": b.Project, "reason": reason},
	})
	return b, true, nil
}

// ── views ────────────────────────────────────────────────────────────────────

// forwarderBindingView is one binding as the panels render it.
type forwarderBindingView struct {
	ID              string              `json:"id"`
	ForwarderID     string              `json:"forwarder_id"`
	ForwarderName   string              `json:"forwarder_name"`
	Kind            string              `json:"kind"`
	Device          string              `json:"device"`
	Project         string              `json:"project"`
	ProjectName     string              `json:"project_name,omitempty"`
	VirtualExecutor string              `json:"virtual_executor,omitempty"`
	Interface       *forwardedInterface `json:"interface,omitempty"`
	Note            string              `json:"note,omitempty"`
	CreatedBy       string              `json:"created_by,omitempty"`
	CreatedAt       string              `json:"created_at"`
	ExpiresAt       string              `json:"expires_at,omitempty"`
	RevokedAt       string              `json:"revoked_at,omitempty"`
	RevokedBy       string              `json:"revoked_by,omitempty"`
	RevokeReason    string              `json:"revoke_reason,omitempty"`
	RequestID       string              `json:"request_id,omitempty"`
	Active          bool                `json:"active"`
	// InUse lists the runs this hub member relays the device to right now.
	InUse []forwardInUse `json:"in_use,omitempty"`
}

func (s *Server) bindingViews(db *statedb.DB, rows []statedb.ForwarderBindingRow, now time.Time) []forwarderBindingView {
	names := map[string]string{}
	for _, e := range s.allProjectEntries() {
		names[e.Path] = e.Name
	}
	fwds := map[string]statedb.ForwarderRow{}
	out := make([]forwarderBindingView, 0, len(rows))
	for _, b := range rows {
		f, ok := fwds[b.ForwarderID]
		if !ok {
			f, _ = db.GetForwarder(b.ForwarderID)
			fwds[b.ForwarderID] = f
		}
		dev := unmarshalForwarderDevice(f.DeviceJSON)
		v := forwarderBindingView{
			ID: b.ID, ForwarderID: b.ForwarderID, ForwarderName: f.Name, Kind: string(dev.Kind),
			Device: dev.Describe(), Project: b.Project, ProjectName: names[b.Project],
			VirtualExecutor: b.VirtualExecutor, Note: b.Note, CreatedBy: b.CreatedBy,
			CreatedAt: b.CreatedAt.UTC().Format(time.RFC3339), RevokedBy: b.RevokedBy,
			RevokeReason: b.RevokeReason, RequestID: b.RequestID, Active: b.Active(now),
		}
		if i := decodeForwardedInterface(b.InterfaceJSON); !i.empty() {
			v.Interface = &i
		}
		if !b.ExpiresAt.IsZero() {
			v.ExpiresAt = b.ExpiresAt.UTC().Format(time.RFC3339)
		}
		if !b.RevokedAt.IsZero() {
			v.RevokedAt = b.RevokedAt.UTC().Format(time.RFC3339)
		}
		if v.Active {
			v.InUse = forwardsInUse(b.ID)
		}
		out = append(out, v)
	}
	return out
}

// ── routes ───────────────────────────────────────────────────────────────────

// handleForwarderBindingsList serves GET /api/forwarders/bindings: the
// bindings in force, or with ?all=1 every binding ever made; ?project= and
// ?forwarder= narrow it.
func (s *Server) handleForwarderBindingsList(w http.ResponseWriter, r *http.Request) {
	db, err := s.controlPlaneDB()
	if err != nil {
		jsonErr(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer db.Close()
	now := time.Now()
	f := statedb.ForwarderBindingFilter{
		Project:     strings.TrimSpace(r.URL.Query().Get("project")),
		ForwarderID: strings.TrimSpace(r.URL.Query().Get("forwarder")),
	}
	if !isTruthyParam(r.URL.Query().Get("all")) {
		f.ActiveAt = now
	}
	rows, err := db.ListForwarderBindings(f)
	if err != nil {
		jsonErr(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSONStatus(w, http.StatusOK, map[string]any{"bindings": s.bindingViews(db, rows, now)})
}

// forwarderBindRequest is POST /api/forwarders/{id}/bindings and the
// forwarder fields of POST /api/grant-requests.
type forwarderBindRequest struct {
	Project         string              `json:"project"`
	VirtualExecutor string              `json:"virtual_executor,omitempty"`
	TTLMinutes      int                 `json:"ttl_minutes,omitempty"`
	Interface       *forwardedInterface `json:"interface,omitempty"`
	Note            string              `json:"note,omitempty"`
}

// handleForwarderBind serves POST /api/forwarders/{id}/bindings.
func (s *Server) handleForwarderBind(w http.ResponseWriter, r *http.Request) {
	if !requirePOST(w, r) {
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	var req forwarderBindRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	project, ok := s.resolveBindingProject(req.Project)
	if !ok {
		jsonErr(w, "project must name a project registered on this hub", http.StatusBadRequest)
		return
	}
	ttl, err := forwarderBindingTTL(req.TTLMinutes)
	if err != nil {
		jsonErr(w, err.Error(), http.StatusBadRequest)
		return
	}
	db, err := s.controlPlaneDB()
	if err != nil {
		jsonErr(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer db.Close()
	in := ForwarderBindingInput{
		ForwarderID: id, Project: project, VirtualExecutor: req.VirtualExecutor,
		TTL: ttl, Note: req.Note, Actor: s.auditActor(r),
	}
	if req.Interface != nil {
		in.Interface = *req.Interface
	}
	row, err := CreateForwarderBinding(db, in, time.Now())
	if err != nil {
		jsonErr(w, err.Error(), bindingErrorStatus(err))
		return
	}
	s.broadcastAuditAppend(string(auditaction.ActionForwarderBind))
	s.broadcastForwarderBindings(row.ForwarderID)
	writeJSONStatus(w, http.StatusOK, map[string]any{"binding": s.bindingViews(db, []statedb.ForwarderBindingRow{row}, time.Now())[0]})
}

// handleForwarderUnbind serves DELETE /api/forwarders/bindings/{bid}.
func (s *Server) handleForwarderUnbind(w http.ResponseWriter, r *http.Request) {
	bid := strings.TrimSpace(r.PathValue("bid"))
	if bid == "" {
		jsonErr(w, "binding id is required", http.StatusBadRequest)
		return
	}
	var body struct {
		Reason string `json:"reason,omitempty"`
	}
	if r.ContentLength > 0 && !decodeJSON(w, r, &body) {
		return
	}
	db, err := s.controlPlaneDB()
	if err != nil {
		jsonErr(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer db.Close()
	actor := s.auditActor(r)
	reason := strings.TrimSpace(body.Reason)
	if reason == "" {
		reason = "unbound by " + nonEmpty(actor, "an operator")
	}
	b, changed, err := RevokeForwarderBindingRecord(db, bid, actor, reason, time.Now())
	if err != nil {
		if errors.Is(err, statedb.ErrForwarderBindingNotFound) {
			jsonErr(w, err.Error(), http.StatusNotFound)
			return
		}
		jsonErr(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// Cut at once here and on every other member; idempotent for a binding
	// that was already revoked, whose relays the re-check has closed.
	s.announceForwarderRevocation(forwarderInvalidation{ForwarderID: b.ForwarderID, BindingID: b.ID, Reason: "its binding was revoked: " + reason})
	if changed {
		s.broadcastAuditAppend(string(auditaction.ActionForwarderUnbind))
	}
	s.broadcastForwarderBindings(b.ForwarderID)
	writeJSONStatus(w, http.StatusOK, map[string]any{"unbound": b.ID, "changed": changed})
}

// handleProjectForwarders serves GET /api/projects/{idx}/forwarders: the
// project's device settings — what is bound to it, what could be, and what the
// caller may do about it.
func (s *Server) handleProjectForwarders(w http.ResponseWriter, r *http.Request) {
	e, ok := s.entryAtIdx(r)
	if !ok {
		jsonErr(w, "project not found", http.StatusNotFound)
		return
	}
	project := policyProjectPath(e.Path)
	db, err := s.controlPlaneDB()
	if err != nil {
		jsonErr(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer db.Close()
	now := time.Now()
	rows, err := db.ListForwarderBindings(statedb.ForwarderBindingFilter{Project: project, ActiveAt: now})
	if err != nil {
		jsonErr(w, err.Error(), http.StatusInternalServerError)
		return
	}
	global := s.grantFor(r).decide(authz.GlobalScope)
	canBind := global.Allows(authz.PermExecutorManage)
	canRequest := global.Allows(authz.PermSecretRequest) && s.grantFor(r).decide(s.entryScope(e)).Allows(authz.PermProjectWrite)
	var choices []map[string]any
	if canBind || canRequest {
		fwds, _ := db.ListForwarders()
		for _, f := range fwds {
			if !f.RevokedAt.IsZero() {
				continue
			}
			dev := unmarshalForwarderDevice(f.DeviceJSON)
			online, _ := forwarderOnline(f.ForwarderID)
			choices = append(choices, map[string]any{
				"id": f.ForwarderID, "name": f.Name, "kind": string(dev.Kind),
				"device": dev.Describe(), "connected": online,
			})
		}
	}
	var mine []requestView
	actor := s.auditActor(r)
	if reqs, err := db.ListForwarderBindingRequests(""); err == nil {
		for _, q := range reqs {
			if q.Project == project && sameRequester(q.RequestedBy, actor) && (q.State == statedb.ForwarderRequestPending || now.Sub(q.DecidedAt) <= approvalsMineWindow) {
				mine = append(mine, requestViewOf(forwarderRequestAsAccess(db, q), actor, false, now))
			}
		}
	}
	writeJSONStatus(w, http.StatusOK, map[string]any{
		"project":     project,
		"bindings":    s.bindingViews(db, rows, now),
		"forwarders":  choices,
		"can_bind":    canBind,
		"can_request": canRequest,
		"requests":    mine,
	})
}

// resolveBindingProject maps what a caller named — a registered project's
// path or name — to the policy path a binding names. A path that is not a
// registered project is refused: binding hardware to a directory nobody runs
// is a mistake, and binding it to one the caller cannot see is worse.
func (s *Server) resolveBindingProject(name string) (string, bool) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", false
	}
	for _, e := range s.allProjectEntries() {
		if e.IsFeature() {
			continue
		}
		if e.Path == name || e.Name == name || (filepath.IsAbs(name) && filepath.Clean(name) == e.Path) {
			return policyProjectPath(e.Path), true
		}
	}
	return "", false
}

func forwarderBindingTTL(minutes int) (time.Duration, error) {
	if minutes == 0 {
		return ForwarderBindingTTLDefault, nil
	}
	ttl := time.Duration(minutes) * time.Minute
	if minutes < 1 || ttl > ForwarderBindingTTLMax {
		return 0, fmt.Errorf("ttl_minutes must be between 1 and %d", int(ForwarderBindingTTLMax/time.Minute))
	}
	return ttl, nil
}

func bindingErrorStatus(err error) int {
	switch {
	case errors.Is(err, deviceforward.ErrForwarderNotFound):
		return http.StatusNotFound
	case errors.Is(err, errBindingConflict):
		return http.StatusConflict
	default:
		return http.StatusBadRequest
	}
}

// broadcastForwarderBindings tells open dashboards the bindings changed.
func (s *Server) broadcastForwarderBindings(forwarderID string) {
	s.broadcastToAll(wsMessage{Type: "forwarder_status", Data: forwarderStatusPayload(forwarderID, "bindings")})
}

// ── requests ─────────────────────────────────────────────────────────────────

// forwarderRequestAsAccess presents a binding request in the shape the
// request routes, the approvals inbox and the webhook notifier already render:
// the "secret" is the forwarder, the subject the project.
func forwarderRequestAsAccess(db *statedb.DB, q statedb.ForwarderBindingRequestRow) secretbroker.AccessRequest {
	name := q.ForwarderID
	if f, err := db.GetForwarder(q.ForwarderID); err == nil {
		dev := unmarshalForwarderDevice(f.DeviceJSON)
		name = f.Name + " (" + dev.Describe() + ")"
	}
	scope := "device forwarder"
	if q.VirtualExecutor != "" {
		scope += " on virtual executor " + q.VirtualExecutor
	}
	return secretbroker.AccessRequest{
		ID:            q.ID,
		RequestedBy:   q.RequestedBy,
		SecretID:      "forwarder:" + q.ForwarderID,
		SecretName:    name,
		Kind:          "device_forwarder",
		Subject:       secretbroker.Subject{Type: secretbroker.SubjectProject, Value: q.Project},
		Scope:         scope,
		TTL:           q.TTL,
		Justification: q.Justification,
		State:         secretbroker.RequestState(q.State),
		CreatedAt:     q.CreatedAt,
		ExpiresAt:     q.ExpiresAt,
		DecidedBy:     q.DecidedBy,
		DecidedAt:     q.DecidedAt,
		DecisionNote:  q.DecisionNote,
		GrantID:       q.BindingID,
	}
}

// forwarderRequestsAsAccess reads every binding request, in that shape.
func (s *Server) forwarderRequestsAsAccess() []secretbroker.AccessRequest {
	if _, err := os.Stat(controlPlaneDBPath()); err != nil {
		return nil
	}
	db, err := s.controlPlaneDB()
	if err != nil {
		return nil
	}
	defer db.Close()
	rows, err := db.ListForwarderBindingRequests("")
	if err != nil {
		return nil
	}
	out := make([]secretbroker.AccessRequest, 0, len(rows))
	for _, q := range rows {
		out = append(out, forwarderRequestAsAccess(db, q))
	}
	return out
}

// mayDecideForwarderRequest is the approve route's rule for a binding request:
// pending, not one's own, and executor.manage at the hub's global scope.
func mayDecideForwarderRequest(global authz.Decision, actor string, req secretbroker.AccessRequest, now time.Time) bool {
	return req.Pending(now) && !sameRequester(req.RequestedBy, actor) && global.Allows(authz.PermExecutorManage)
}

// createForwarderBindingRequest files a binding request from POST
// /api/grant-requests with "source": "forwarder".
func (s *Server) createForwarderBindingRequest(w http.ResponseWriter, r *http.Request, body createRequestBody) {
	project, ok := s.resolveBindingProject(body.Project)
	if !ok {
		apierror.WriteError(w, apierror.New(apierror.CodeInvalidInput, "project must name a project registered on this hub"))
		return
	}
	// Asking takes write access to the project the device is for: a request
	// for hardware is a request on someone's behalf, and the someone is the
	// project. Read access is not enough.
	scope := authz.Scope{Project: s.projectNameForPath(project), ProjectPath: project}
	if d := s.grantFor(r).decide(scope); !d.Allows(authz.PermProjectWrite) {
		s.auditAuthz(r, d, authz.PermProjectWrite, scope, false)
		apierror.WriteError(w, apierror.New(apierror.CodeForbidden,
			"asking for a device on a project takes write access to it"))
		return
	}
	if strings.TrimSpace(body.Justification) == "" {
		apierror.WriteError(w, apierror.New(apierror.CodeInvalidInput, "a justification is required"))
		return
	}
	if len(body.Justification) > 4096 {
		apierror.WriteError(w, apierror.New(apierror.CodeInvalidInput, "the justification is longer than 4096 bytes"))
		return
	}
	ttl, err := forwarderBindingTTL(body.TTLMinutes)
	if err != nil {
		apierror.WriteError(w, apierror.New(apierror.CodeInvalidInput, err.Error()))
		return
	}
	wait := forwarderRequestWaitDefault
	if body.WaitMinutes > 0 {
		if body.WaitMinutes > requestTTLMaxMinutes {
			apierror.WriteError(w, apierror.New(apierror.CodeInvalidInput, "wait_minutes is too long"))
			return
		}
		wait = time.Duration(body.WaitMinutes) * time.Minute
	}
	db, err := s.controlPlaneDB()
	if err != nil {
		apierror.WriteError(w, apierror.New(apierror.CodeUnavailable, err.Error()))
		return
	}
	defer db.Close()
	fwd, err := db.GetForwarder(strings.TrimSpace(body.ForwarderID))
	if err != nil || !fwd.RevokedAt.IsZero() {
		apierror.WriteError(w, apierror.New(apierror.CodeNotFound, "no such forwarder, or it was revoked"))
		return
	}
	iface := forwardedInterface{}
	if body.Interface != nil {
		iface = *body.Interface
	}
	now := time.Now()
	actor := s.auditActor(r)
	row := statedb.ForwarderBindingRequestRow{
		ID:              forwarderRequestPrefix + shortHash(fmt.Sprintf("%s|%s|%s|%d", fwd.ForwarderID, project, actor, now.UnixNano()), 16),
		ForwarderID:     fwd.ForwarderID,
		Project:         project,
		VirtualExecutor: strings.TrimSpace(body.VirtualExecutor),
		InterfaceJSON:   encodeForwardedInterface(iface),
		TTL:             ttl,
		Justification:   strings.TrimSpace(body.Justification),
		RequestedBy:     actor,
		State:           statedb.ForwarderRequestPending,
		CreatedAt:       now,
		ExpiresAt:       now.Add(wait),
	}
	if err := db.PutForwarderBindingRequest(row); err != nil {
		apierror.WriteError(w, apierror.New(apierror.CodeInternal, err.Error()))
		return
	}
	statedb.AuditForwarderLifecycle(db.AsControlPlane(), statedb.ForwarderAuditInput{
		Action: auditaction.ActionForwarderBindRequest, ForwarderID: row.ForwarderID, Actor: actor,
		Detail: map[string]any{"request_id": row.ID, "project": row.Project, "virtual_executor": row.VirtualExecutor,
			"ttl_seconds": int64(ttl / time.Second)},
	})
	s.broadcastAuditAppend(string(auditaction.ActionForwarderBindRequest))
	s.broadcastSecretsUpdate("request_created", row.ID)
	jsonOK(w, requestViewOf(forwarderRequestAsAccess(db, row), actor, false, now))
}

// decideForwarderBindingRequest approves, denies or withdraws a binding
// request through the shared /api/grant-requests/{id}/… routes.
func (s *Server) decideForwarderBindingRequest(w http.ResponseWriter, r *http.Request, id string, action requestAction, body decideRequestBody) {
	db, err := s.controlPlaneDB()
	if err != nil {
		apierror.WriteError(w, apierror.New(apierror.CodeUnavailable, err.Error()))
		return
	}
	defer db.Close()
	q, err := db.GetForwarderBindingRequest(id)
	if err != nil {
		apierror.WriteError(w, apierror.New(apierror.CodeNotFound, "no such request"))
		return
	}
	actor := s.auditActor(r)
	now := time.Now()
	req := forwarderRequestAsAccess(db, q)
	switch action {
	case requestActionWithdraw:
		if !sameRequester(q.RequestedBy, actor) {
			apierror.WriteError(w, apierror.New(apierror.CodeForbidden, "only the requester may withdraw a request"))
			return
		}
		if ok, err := db.DecideForwarderBindingRequest(id, statedb.ForwarderRequestWithdrawn, actor, body.Note, "", now); err != nil || !ok {
			apierror.WriteError(w, apierror.New(apierror.CodeConflict, "the request is no longer pending"))
			return
		}
		statedb.AuditForwarderLifecycle(db.AsControlPlane(), statedb.ForwarderAuditInput{
			Action: auditaction.ActionForwarderBindRequestWithdraw, ForwarderID: q.ForwarderID, Actor: actor,
			Detail: map[string]any{"request_id": id},
		})
		s.broadcastAuditAppend(string(auditaction.ActionForwarderBindRequestWithdraw))
		s.broadcastSecretsUpdate("request_withdrawn", id)
		jsonOK(w, map[string]any{"ok": true, "id": id, "state": statedb.ForwarderRequestWithdrawn})
		return
	}
	global := s.grantFor(r).decide(authz.GlobalScope)
	if !global.Allows(authz.PermExecutorManage) {
		s.auditAuthz(r, global, authz.PermExecutorManage, authz.GlobalScope, false)
		apierror.WriteError(w, apierror.New(apierror.CodeForbidden,
			"deciding a request for a device forwarder takes executor.manage, as binding one does").
			WithDetails(map[string]any{"required_permission": string(authz.PermExecutorManage), "role": string(global.Role)}))
		return
	}
	if sameRequester(q.RequestedBy, actor) {
		apierror.WriteError(w, apierror.New(apierror.CodeForbidden, "a request cannot be decided by the person who filed it"))
		return
	}
	if !req.Pending(now) {
		apierror.WriteError(w, apierror.New(apierror.CodeConflict, "the request is no longer pending"))
		return
	}
	if action == requestActionDeny {
		if strings.TrimSpace(body.Note) == "" {
			apierror.WriteError(w, apierror.New(apierror.CodeInvalidInput, "a note saying why is required to deny"))
			return
		}
		if ok, err := db.DecideForwarderBindingRequest(id, statedb.ForwarderRequestDenied, actor, body.Note, "", now); err != nil || !ok {
			apierror.WriteError(w, apierror.New(apierror.CodeConflict, "the request is no longer pending"))
			return
		}
		statedb.AuditForwarderLifecycle(db.AsControlPlane(), statedb.ForwarderAuditInput{
			Action: auditaction.ActionForwarderBindRequestDeny, ForwarderID: q.ForwarderID, Actor: actor,
			Detail: map[string]any{"request_id": id, "note": body.Note},
		})
		s.broadcastAuditAppend(string(auditaction.ActionForwarderBindRequestDeny))
		s.broadcastSecretsUpdate("request_denied", id)
		jsonOK(w, map[string]any{"ok": true, "id": id, "state": statedb.ForwarderRequestDenied})
		return
	}
	// Approve: the decision is recorded first, so two approvers racing mint
	// one binding; the binding is minted as the approver, for what was asked
	// or less.
	ttl := q.TTL
	if body.TTLMinutes > 0 {
		if t := time.Duration(body.TTLMinutes) * time.Minute; t < ttl || ttl <= 0 {
			ttl = t
		}
	}
	if ok, err := db.DecideForwarderBindingRequest(id, statedb.ForwarderRequestApproved, actor, body.Note, "", now); err != nil || !ok {
		apierror.WriteError(w, apierror.New(apierror.CodeConflict, "the request is no longer pending"))
		return
	}
	row, err := CreateForwarderBinding(db, ForwarderBindingInput{
		ForwarderID: q.ForwarderID, Project: q.Project, VirtualExecutor: q.VirtualExecutor,
		Interface: decodeForwardedInterface(q.InterfaceJSON), TTL: ttl, Actor: actor, RequestID: id,
		Note: "approved request " + id,
	}, now)
	if err != nil {
		apierror.WriteError(w, apierror.New(apierror.CodeConflict, "approved, but the binding could not be made: "+err.Error()))
		return
	}
	_ = db.SetForwarderBindingRequestBinding(id, row.ID)
	statedb.AuditForwarderLifecycle(db.AsControlPlane(), statedb.ForwarderAuditInput{
		Action: auditaction.ActionForwarderBindRequestApprove, ForwarderID: q.ForwarderID, Actor: actor,
		Detail: map[string]any{"request_id": id, "binding_id": row.ID, "expires_at": row.ExpiresAt.UTC().Format(time.RFC3339)},
	})
	s.broadcastAuditAppend(string(auditaction.ActionForwarderBindRequestApprove))
	s.broadcastSecretsUpdate("request_approved", id)
	s.broadcastForwarderBindings(q.ForwarderID)
	jsonOK(w, map[string]any{"ok": true, "id": id, "state": statedb.ForwarderRequestApproved, "binding_id": row.ID,
		"expires_at": row.ExpiresAt.UTC().Format(time.RFC3339)})
}

// handleForwarderRequestsList serves GET /api/forwarders/requests: binding
// requests, the caller's own unless they may decide them. It works on a hub
// without a secret broker, where /api/grant-requests does not.
func (s *Server) handleForwarderRequestsList(w http.ResponseWriter, r *http.Request) {
	actor := s.auditActor(r)
	global := s.grantFor(r).decide(authz.GlobalScope)
	canDecide := global.Allows(authz.PermExecutorManage)
	now := time.Now()
	var out []requestView
	for _, req := range s.forwarderRequestsAsAccess() {
		if !canDecide && !sameRequester(req.RequestedBy, actor) {
			continue
		}
		out = append(out, requestViewOf(req, actor, mayDecideForwarderRequest(global, actor, req, now), now))
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	writeJSONStatus(w, http.StatusOK, map[string]any{"requests": out, "can_decide": canDecide})
}

// isForwarderRequestID reports whether a request id names a binding request.
func isForwarderRequestID(id string) bool { return strings.HasPrefix(id, forwarderRequestPrefix) }
