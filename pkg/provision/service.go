package provision

// The SCIM operations on users, and what each one does to the hub.
//
// Every write follows one shape. The request is parsed and normalised; the
// resource it produces is compared with the stored one, and a request that
// changes nothing changes nothing — no new version, no audit row, the stored
// representation returned — so an identity provider's retry, or a request it
// sends twice, is harmless. A real change is one statedb transaction with
// everything that follows from it and its audit rows. Only what cannot join a
// SQL transaction is done outside it: live sessions are ended through the
// running authenticator first, so a failure leaves the person more contained
// and not less; leases and tasks are ended after the commit.
//
// Reordering is handled by what each operation means rather than by when it
// arrives. Group membership is a set: adding a member twice, or removing one
// who is not there, is the state asked for. A deactivation of a user who is
// already inactive does nothing, and so does a reactivation of an active one.
// A request for a user who has been deleted is a 404 — nothing a deletion
// destroyed comes back. A provider that sends If-Match is held to it (412),
// and one that does not is served last-writer-wins under the per-user lock.

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/apitoken"
	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/authz"
	"github.com/blechschmidt/cloop/pkg/offboard"
	"github.com/blechschmidt/cloop/pkg/rolestore"
	"github.com/blechschmidt/cloop/pkg/scim"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// Hub is the running hub's side of a provisioning change: what lives in its
// process rather than in the database.
type Hub interface {
	// Collaborators returns what an offboarding reaches in this hub process
	// — its live sessions, leases, tasks, project registry, secret store and
	// Claude homes — for the control plane db. DB, Identity, Target, Reason,
	// Actor and Via are the caller's to set.
	Collaborators(db *statedb.DB) offboard.Options
	// Severed is told, after a change committed, what it ended or restored
	// behind the hub's caches, so the hub — and its other members — stop
	// honouring it now rather than at their next refresh.
	Severed(Severance)
	// DirectoryChanged is told after every committed directory change.
	DirectoryChanged()
}

// Severance is what one change ended or restored.
type Severance struct {
	Actor string
	// RoleBindings: deny bindings were written or lifted.
	RoleBindings bool
	// Tokens are API tokens and glasses links revoked in the transaction.
	Tokens []string
	// Sessions are session rows deleted in the transaction — only on a hub
	// with no running authenticator, which otherwise ends them itself.
	Sessions []string
	// GrantsSuspended and GrantsResumed are grants over the person's
	// personal secrets.
	GrantsSuspended []string
	GrantsResumed   []string
	// Offboard is the report of a full offboarding, when one ran.
	Offboard *offboard.Report
}

// Service applies SCIM requests to the directory and the hub.
type Service struct {
	DB        *statedb.DB
	Config    Config
	Directory *Directory
	Hub       Hub
	// Now is the clock; nil is time.Now.
	Now func() time.Time

	locks keyedMutex
}

// Result is one operation's response.
type Result struct {
	// Status is the HTTP status.
	Status int
	// Resource is the representation returned, nil for 204.
	Resource map[string]any
	// Location is the resource's URL, for a 201.
	Location string
	// Version is the resource's version, for the ETag header; 0 for none.
	Version int64
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

func (s *Service) collaborators() offboard.Options {
	if s.Hub == nil {
		return offboard.Options{}
	}
	return s.Hub.Collaborators(s.DB)
}

// changed tells the cache and the hub that the directory changed.
func (s *Service) changed() {
	if s.Directory != nil {
		s.Directory.Invalidate()
	}
	if s.Hub != nil {
		s.Hub.DirectoryChanged()
	}
}

func (s *Service) severed(v Severance) {
	if s.Hub != nil {
		s.Hub.Severed(v)
	}
}

// newResourceID returns a random UUID: what SCIM ids look like to a provider.
func newResourceID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("provision: generate id: %w", err)
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

// maxWriteAttempts bounds the retries of a write that lost a race with
// another hub member and carried no If-Match.
const maxWriteAttempts = 3

// userURL is a user's location under the SCIM base URL.
func userURL(base, id string) string { return strings.TrimSuffix(base, "/") + "/Users/" + id }

func groupURL(base, id string) string { return strings.TrimSuffix(base, "/") + "/Groups/" + id }

func encodeResource(obj map[string]any) (string, error) {
	b, err := json.Marshal(obj)
	if err != nil {
		return "", fmt.Errorf("provision: encode resource: %w", err)
	}
	return string(b), nil
}

func decodeResource(blob string) map[string]any {
	var obj map[string]any
	if err := json.Unmarshal([]byte(blob), &obj); err != nil || obj == nil {
		return map[string]any{}
	}
	return obj
}

// translate maps a storage error to the SCIM error a provider understands.
func translate(err error) error {
	if err == nil {
		return nil
	}
	var se *scim.Error
	if errors.As(err, &se) {
		return se
	}
	var c *statedb.SCIMConflict
	if errors.As(err, &c) {
		switch c.Column {
		case "user_name_key":
			return scim.Conflict("userName %q is already provisioned (user %s)", c.Value, c.OtherID)
		case "display_name_key":
			return scim.Conflict("a group named %q is already provisioned (group %s)", c.Value, c.OtherID)
		}
		return scim.Conflict("%s %q already belongs to provisioned user %s: both would be the same hub "+
			"identity, and the hub refuses an ambiguous match", c.Label, c.Value, c.OtherID)
	}
	if errors.Is(err, statedb.ErrSCIMNotFound) {
		return scim.Errorf(http.StatusNotFound, "", "the resource was deleted")
	}
	if errors.Is(err, statedb.ErrSCIMVersion) {
		return scim.Errorf(http.StatusPreconditionFailed, "", "the resource changed since it was read")
	}
	return err
}

// ── reading ─────────────────────────────────────────────────────────────────

// groupNames maps each user id to the groups it belongs to, as the users'
// read-only groups attribute shows them.
type groupRef struct{ id, name string }

func (s *Service) userGroups() (map[string][]groupRef, error) {
	dir, err := s.DB.LoadSCIMDirectory()
	if err != nil {
		return nil, err
	}
	out := map[string][]groupRef{}
	for _, u := range dir.Users {
		for _, gid := range u.GroupIDs {
			out[u.ID] = append(out[u.ID], groupRef{id: gid, name: dir.Groups[gid].DisplayName})
		}
	}
	return out, nil
}

// renderUser is the representation of a stored user.
func renderUser(row statedb.SCIMUserRow, groups []groupRef, base string) map[string]any {
	obj := decodeResource(row.ResourceJSON)
	obj["userName"] = row.UserName
	obj["active"] = row.Active
	if len(groups) > 0 {
		list := make([]any, 0, len(groups))
		for _, g := range groups {
			list = append(list, map[string]any{"value": g.id, "display": g.name,
				"$ref": groupURL(base, g.id), "type": "direct"})
		}
		obj["groups"] = list
	}
	return scim.Render(obj, scim.KindUser, row.ID, scim.Meta{
		Created: row.CreatedAt, LastModified: row.UpdatedAt, Location: userURL(base, row.ID), Version: row.Version,
	})
}

// GetUser serves GET /Users/{id}.
func (s *Service) GetUser(id string, q url.Values, base string) (Result, error) {
	row, err := s.DB.GetSCIMUser(id)
	if err != nil {
		if errors.Is(err, statedb.ErrSCIMNotFound) {
			return Result{}, scim.NotFound("User", id)
		}
		return Result{}, err
	}
	proj, err := scim.ParseProjection(q, scim.KindUser)
	if err != nil {
		return Result{}, err
	}
	groups, err := s.userGroups()
	if err != nil {
		return Result{}, err
	}
	res := renderUser(row, groups[row.ID], base)
	return Result{Status: http.StatusOK, Resource: proj.Apply(res, scim.KindUser), Version: row.Version}, nil
}

// ListUsers serves GET /Users.
func (s *Service) ListUsers(q url.Values, base string) (scim.ListResponse, error) {
	page, err := scim.ParsePage(q)
	if err != nil {
		return scim.ListResponse{}, err
	}
	proj, err := scim.ParseProjection(q, scim.KindUser)
	if err != nil {
		return scim.ListResponse{}, err
	}
	var filter *scim.Filter
	if raw := strings.TrimSpace(q.Get("filter")); raw != "" {
		if filter, err = scim.ParseFilter(raw, scim.KindUser); err != nil {
			return scim.ListResponse{}, err
		}
	}
	rows, err := s.candidateUsers(filter)
	if err != nil {
		return scim.ListResponse{}, err
	}
	groups, err := s.userGroups()
	if err != nil {
		return scim.ListResponse{}, err
	}
	var matched []map[string]any
	for _, row := range rows {
		res := renderUser(row, groups[row.ID], base)
		if filter.Matches(res) {
			matched = append(matched, res)
		}
	}
	pageRes := scim.Paginate(matched, page)
	out := make([]map[string]any, 0, len(pageRes))
	for _, r := range pageRes {
		out = append(out, proj.Apply(r, scim.KindUser))
	}
	return scim.NewListResponse(len(matched), page, out), nil
}

// candidateUsers narrows a filtered listing by an index where the filter
// allows; the filter is still applied to every candidate.
func (s *Service) candidateUsers(f *scim.Filter) ([]statedb.SCIMUserRow, error) {
	if attr, value, ok := f.Equality(); ok {
		switch attr {
		case "userName":
			return s.DB.FindSCIMUsers("user_name_key", strings.ToLower(value))
		case "externalId":
			return s.DB.FindSCIMUsers("external_id", value)
		case "id":
			row, err := s.DB.GetSCIMUser(value)
			if errors.Is(err, statedb.ErrSCIMNotFound) {
				return nil, nil
			}
			if err != nil {
				return nil, err
			}
			return []statedb.SCIMUserRow{row}, nil
		}
	}
	return s.DB.ListSCIMUsers()
}

// ── writing ─────────────────────────────────────────────────────────────────

// userFromResource builds the row a normalised user resource describes.
func userFromResource(norm map[string]any, f scim.UserFields, active bool) (statedb.SCIMUserRow, error) {
	norm["active"] = active
	blob, err := encodeResource(norm)
	if err != nil {
		return statedb.SCIMUserRow{}, err
	}
	return statedb.SCIMUserRow{
		UserName: f.UserName, ExternalID: f.ExternalID, DisplayName: f.DisplayName, Email: f.Email,
		Active: active, ResourceJSON: blob,
	}, nil
}

// uniqueRules are the values no other user may hold: userName, and the value
// the user is matched by — two users matching one hub identity would make
// every decision about that identity a guess.
func (s *Service) uniqueRules(row statedb.SCIMUserRow) []statedb.SCIMUnique {
	rules := []statedb.SCIMUnique{{Column: "user_name_key", Value: strings.ToLower(row.UserName), Label: "userName"}}
	v := UserValue(s.Config.MatchClaim, row)
	col := matchColumn(s.Config.MatchClaim)
	if v != "" && col != "user_name_key" {
		rules = append(rules, statedb.SCIMUnique{Column: col, Value: v,
			Label: fmt.Sprintf("%s (ui.oidc.scim.match_claim: %s)", attrOfClaim(s.Config.MatchClaim), s.Config.MatchClaim)})
	}
	return rules
}

func attrOfClaim(c MatchClaim) string {
	switch c {
	case MatchOID, MatchSub:
		return "externalId"
	case MatchUsername:
		return "userName"
	}
	return "email"
}

// precheckUnique refuses, before anything is severed, a write the transaction
// would refuse for a uniqueness rule.
func (s *Service) precheckUnique(row statedb.SCIMUserRow) error {
	for _, u := range s.uniqueRules(row) {
		others, err := s.DB.FindSCIMUsers(u.Column, u.Value)
		if err != nil {
			return err
		}
		for _, o := range others {
			if o.ID != row.ID {
				return translate(&statedb.SCIMConflict{Column: u.Column, Label: u.Label, Value: u.Value, OtherID: o.ID})
			}
		}
	}
	return nil
}

// CreateUser serves POST /Users.
func (s *Service) CreateUser(ctx context.Context, a Actor, body []byte, base string) (Result, error) {
	obj, err := scim.Decode(body)
	if err != nil {
		return Result{}, err
	}
	norm, err := scim.Normalize(obj, scim.KindUser)
	if err != nil {
		return Result{}, err
	}
	f, err := scim.ReadUser(norm)
	if err != nil {
		return Result{}, err
	}
	active := f.Active == nil || *f.Active
	row, err := userFromResource(norm, f, active)
	if err != nil {
		return Result{}, err
	}
	if row.ID, err = newResourceID(); err != nil {
		return Result{}, err
	}
	row.CreatedBy, row.UpdatedBy = a.Label(), a.Label()
	unlock := s.locks.lock("user:" + row.ID)
	defer unlock()
	applied, err := s.writeUser(ctx, a, nil, row, http.MethodPost, nil)
	if err != nil {
		return Result{}, err
	}
	res := renderUser(applied.Row, nil, base)
	return Result{Status: http.StatusCreated, Resource: res, Location: userURL(base, applied.Row.ID),
		Version: applied.Row.Version}, nil
}

// ReplaceUser serves PUT /Users/{id}: Okta's profile update, and its
// deactivation on older integrations.
func (s *Service) ReplaceUser(ctx context.Context, a Actor, id string, body []byte, ifMatch, base string) (Result, error) {
	obj, err := scim.Decode(body)
	if err != nil {
		return Result{}, err
	}
	if v, ok := obj["id"]; ok {
		if sv, _ := v.(string); sv != id {
			return Result{}, scim.Errorf(http.StatusBadRequest, scim.ErrMutability,
				"the body's id %s is not the resource's", scim.Describe(v))
		}
	}
	norm, err := scim.Normalize(obj, scim.KindUser)
	if err != nil {
		return Result{}, err
	}
	f, err := scim.ReadUser(norm)
	if err != nil {
		return Result{}, err
	}
	return s.updateUser(ctx, a, id, ifMatch, base, http.MethodPut, func(stored statedb.SCIMUserRow) (statedb.SCIMUserRow, error) {
		// A replace that does not say whether the account is active leaves
		// it as it was: its absence is not a reactivation.
		active := stored.Active
		if f.Active != nil {
			active = *f.Active
		}
		return userFromResource(scim.CloneObject(norm), f, active)
	})
}

// PatchUser serves PATCH /Users/{id}: Entra ID's deactivation and attribute
// updates, and Okta's deactivation.
func (s *Service) PatchUser(ctx context.Context, a Actor, id string, body []byte, ifMatch, base string) (Result, error) {
	ops, err := scim.ParsePatch(body)
	if err != nil {
		return Result{}, err
	}
	return s.updateUser(ctx, a, id, ifMatch, base, http.MethodPatch, func(stored statedb.SCIMUserRow) (statedb.SCIMUserRow, error) {
		obj := decodeResource(stored.ResourceJSON)
		obj["userName"] = stored.UserName
		obj["active"] = stored.Active
		if err := scim.ApplyPatch(obj, scim.KindUser, stored.ID, ops); err != nil {
			return statedb.SCIMUserRow{}, err
		}
		norm, err := scim.Normalize(obj, scim.KindUser)
		if err != nil {
			return statedb.SCIMUserRow{}, err
		}
		f, err := scim.ReadUser(norm)
		if err != nil {
			return statedb.SCIMUserRow{}, err
		}
		active := stored.Active
		if f.Active != nil {
			active = *f.Active
		}
		return userFromResource(norm, f, active)
	})
}

// updateUser is the read-modify-write both PUT and PATCH are.
func (s *Service) updateUser(ctx context.Context, a Actor, id, ifMatch, base, method string,
	apply func(statedb.SCIMUserRow) (statedb.SCIMUserRow, error)) (Result, error) {
	unlock := s.locks.lock("user:" + id)
	defer unlock()
	for attempt := 1; ; attempt++ {
		stored, err := s.DB.GetSCIMUser(id)
		if err != nil {
			if errors.Is(err, statedb.ErrSCIMNotFound) {
				return Result{}, scim.NotFound("User", id)
			}
			return Result{}, err
		}
		if !scim.MatchesETag(ifMatch, stored.Version) {
			return Result{}, scim.Errorf(http.StatusPreconditionFailed, "",
				"user %s is at version %s, not %s", id, scim.ETag(stored.Version), ifMatch)
		}
		next, err := apply(stored)
		if err != nil {
			return Result{}, err
		}
		next.ID, next.UpdatedBy = stored.ID, a.Label()
		changed := changedAttributes(stored, next)
		if len(changed) == 0 {
			// Nothing to do, and nothing done: a retry, or a request that
			// restates what the hub already holds.
			groups, gerr := s.userGroups()
			if gerr != nil {
				return Result{}, gerr
			}
			return Result{Status: http.StatusOK, Resource: renderUser(stored, groups[stored.ID], base),
				Version: stored.Version}, nil
		}
		applied, err := s.writeUser(ctx, a, &stored, next, method, changed)
		if errors.Is(err, statedb.ErrSCIMVersion) && strings.TrimSpace(ifMatch) == "" && attempt < maxWriteAttempts {
			continue
		}
		if err != nil {
			return Result{}, translate(err)
		}
		groups, err := s.userGroups()
		if err != nil {
			return Result{}, err
		}
		return Result{Status: http.StatusOK, Resource: renderUser(applied.Row, groups[applied.Row.ID], base),
			Version: applied.Row.Version}, nil
	}
}

// changedAttributes names what differs between a stored user and its next
// state: "active" for the account's state, else the attributes.
func changedAttributes(stored, next statedb.SCIMUserRow) []string {
	var out []string
	if stored.Active != next.Active {
		out = append(out, "active")
	}
	a, b := decodeResource(stored.ResourceJSON), decodeResource(next.ResourceJSON)
	delete(a, "active")
	delete(b, "active")
	keys := map[string]bool{}
	for k := range a {
		keys[k] = true
	}
	for k := range b {
		keys[k] = true
	}
	for k := range keys {
		ja, _ := json.Marshal(a[k])
		jb, _ := json.Marshal(b[k])
		if string(ja) != string(jb) {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// suspensionReason is what a SCIM deny binding says, by the credential that
// wrote it.
func suspensionReason(a Actor) string {
	return "deactivated at the identity provider (" + a.Label() + ")"
}

// writeUser stores a user's new state, with whatever its change of state
// means for the hub.
func (s *Service) writeUser(ctx context.Context, a Actor, stored *statedb.SCIMUserRow, row statedb.SCIMUserRow,
	method string, changed []string) (statedb.SCIMUserApplied, error) {
	if err := s.precheckUnique(row); err != nil {
		return statedb.SCIMUserApplied{}, err
	}
	now := s.now()
	w := statedb.SCIMUserWrite{Row: row, Create: stored == nil, Unique: s.uniqueRules(row), At: now}
	if stored != nil {
		w.ExpectVersion = stored.Version
		row.Suspension = stored.Suspension
		w.Row.Suspension = stored.Suspension
	}
	wasActive := stored == nil || stored.Active
	var susp *suspension
	switch {
	case wasActive && !row.Active:
		var err error
		if susp, err = s.planSuspension(row, a, now); err != nil {
			return statedb.SCIMUserApplied{}, err
		}
		w.Suspend = susp.write
		// Live sessions end before the transaction, through the running
		// authenticator — which also drops them from its cache and tells
		// the other members. A transaction that then failed leaves the
		// person more contained, never less; the provider retries.
		susp.revokeLive(a)
	case !wasActive && row.Active:
		w.Lift = true
	}
	claim := s.Config.MatchClaim
	w.Audit = func(ap statedb.SCIMUserApplied) ([]*statedb.AuditEvent, error) {
		var evs []*statedb.AuditEvent
		base := map[string]any{
			"id": ap.Row.ID, "user_name": ap.Row.UserName, "external_id": ap.Row.ExternalID,
			"email": ap.Row.Email, "active": ap.Row.Active, "match_claim": string(claim),
			"match_value": UserValue(claim, ap.Row),
		}
		action := auditaction.ActionSCIMUserCreate
		if stored != nil {
			action = auditaction.ActionSCIMUserUpdate
			base["method"] = method
			base["changed"] = changed
		}
		ev, err := auditEvent(a.Label(), action, "scim_user", ap.Row.ID, base, now)
		if err != nil {
			return nil, err
		}
		evs = append(evs, ev)
		if susp != nil {
			sevs, err := susp.auditEvents(a, ap, now)
			if err != nil {
				return nil, err
			}
			evs = append(evs, sevs...)
		}
		if w.Lift {
			p := map[string]any{"id": ap.Row.ID, "user_name": ap.Row.UserName,
				"denies_lifted": ap.DeniesLifted, "denies_kept": ap.DeniesKept,
				"grants_resumed": ap.GrantsResumed}
			if !ap.Row.OffboardedAt.IsZero() {
				p["offboarded_at"] = ap.Row.OffboardedAt.Format(time.RFC3339)
				p["note"] = "this account was offboarded; what the offboarding destroyed is not restored, " +
					"and its deny bindings stay until an administrator removes them"
			} else if len(ap.DeniesKept) > 0 {
				p["note"] = "denies_kept were rewritten by an administrator since the suspension, and are theirs"
			}
			ev, err := auditEvent(a.Label(), auditaction.ActionSCIMUserReactivate, "scim_user", ap.Row.ID, p, now)
			if err != nil {
				return nil, err
			}
			evs = append(evs, ev)
		}
		return evs, nil
	}
	applied, err := s.DB.WriteSCIMUser(w)
	if err != nil {
		return statedb.SCIMUserApplied{}, translate(err)
	}
	if susp != nil {
		susp.afterCommit(s, a, applied)
	}
	if w.Lift && (len(applied.DeniesLifted) > 0 || len(applied.GrantsResumed) > 0) {
		s.severed(Severance{Actor: a.Label(), RoleBindings: len(applied.DeniesLifted) > 0,
			GrantsResumed: applied.GrantsResumed})
	}
	s.changed()
	return applied, nil
}

// DeleteUser serves DELETE /Users/{id}: the full offboarding, honouring a
// legal hold, and then the resource is gone.
func (s *Service) DeleteUser(ctx context.Context, a Actor, id, ifMatch string) (Result, error) {
	unlock := s.locks.lock("user:" + id)
	defer unlock()
	row, err := s.DB.GetSCIMUser(id)
	if err != nil {
		if errors.Is(err, statedb.ErrSCIMNotFound) {
			return Result{}, scim.NotFound("User", id)
		}
		return Result{}, err
	}
	if !scim.MatchesETag(ifMatch, row.Version) {
		return Result{}, scim.Errorf(http.StatusPreconditionFailed, "", "user %s is at version %s", id,
			scim.ETag(row.Version))
	}
	now := s.now()
	rep, hold, err := s.offboardUser(ctx, a, row, "scim", "deleted at the identity provider ("+a.Label()+")",
		"delete")
	if err != nil {
		// Nothing deleted: the provider retries, and the offboarding with it.
		return Result{}, err
	}
	payload := map[string]any{"id": row.ID, "user_name": row.UserName, "identity": rep.Target.Key,
		"legal_hold": hold != nil, "failures": failureLines(rep.Failures)}
	ev, err := auditEvent(a.Label(), auditaction.ActionSCIMUserDelete, "scim_user", row.ID, payload, now)
	if err != nil {
		return Result{}, err
	}
	if _, err := s.DB.DeleteSCIMUser(row.ID, []*statedb.AuditEvent{ev}); err != nil {
		return Result{}, err
	}
	s.changed()
	return Result{Status: http.StatusNoContent}, nil
}

func failureLines(fs []offboard.Failure) []string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, f.Surface+": "+f.Detail)
	}
	return out
}

// ── who a provisioned user is ───────────────────────────────────────────────

// ambiguity is a provisioned user whose match value addresses more than one
// hub identity.
type ambiguity struct {
	Subjects []string
	Emails   []string
}

// targetFor resolves a provisioned user to the hub identity it is.
//
// The match claim says what to start from: the user's email, its userName as
// a preferred_username, or its externalId as an oid or a subject. The start
// is expanded as an operator's input to `cloop hub user offboard` is — an
// email to the subjects that signed in with it, a subject to the emails —
// because the surfaces are keyed inconsistently, and matching literally would
// leave a subject-keyed token live.
//
// Unless the expansion reaches more than one subject. Then the provisioned
// user is ambiguous: two accounts on this hub answer to its match value, and
// nothing the identity provider sent says which one it deactivated. The hub
// refuses to guess. It acts on the match value alone — the identifier the
// operator chose to trust — which by construction refuses every account that
// carries it, and does not follow either account's other identifiers to
// credentials the provider said nothing about.
func (s *Service) targetFor(row statedb.SCIMUserRow, collab offboard.Options) (offboard.Target, *ambiguity, error) {
	claim := s.Config.MatchClaim
	value := UserValue(claim, row)
	exact := offboard.Target{Input: row.UserName}
	if value == "" {
		// Unmatchable: the user carries nothing the hub identifies people by.
		return exact, nil, nil
	}
	var seeds []string
	switch claim {
	case MatchEmail:
		seeds, exact.Emails = []string{value}, []string{value}
	case MatchSub:
		seeds, exact.Subjects = []string{"sub:" + value}, []string{value}
	case MatchUsername, MatchOID:
		cands, err := s.accountsCarrying(claim, value, collab)
		if err != nil {
			return offboard.Target{}, nil, err
		}
		seeds = cands
		if claim == MatchUsername {
			exact.Usernames = []string{value}
		} else {
			exact.OIDs = []string{value}
		}
	}
	if len(seeds) == 0 {
		return exact, nil, nil
	}
	t, err := offboard.ResolveTarget(s.DB, seeds)
	if err != nil {
		return offboard.Target{}, nil, err
	}
	if len(t.Subjects) > 1 {
		return exact, &ambiguity{Subjects: t.Subjects, Emails: t.Emails}, nil
	}
	t.Input = row.UserName
	t.Usernames, t.OIDs = exact.Usernames, exact.OIDs
	return t, nil, nil
}

// accountsCarrying finds the hub identities whose sessions or token owners
// carry value in claim — preferred_username or oid — as resolution seeds: each
// email, and each subject spelt sub:<subject>.
func (s *Service) accountsCarrying(claim MatchClaim, value string, collab offboard.Options) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	add := func(sub, email, username, oid string) {
		have := strings.ToLower(strings.TrimSpace(username))
		if claim == MatchOID {
			have = strings.ToLower(strings.TrimSpace(oid))
		}
		if have == "" || have != value {
			return
		}
		for _, seed := range []string{strings.ToLower(strings.TrimSpace(email)), "sub:" + strings.TrimSpace(sub)} {
			if seed == "" || seed == "sub:" || seen[seed] {
				continue
			}
			seen[seed] = true
			out = append(out, seed)
		}
	}
	if collab.Sessions != nil {
		live, err := collab.Sessions.List()
		if err != nil {
			return nil, fmt.Errorf("list live sessions: %w", err)
		}
		for _, r := range live {
			add(r.Subject, r.Email, r.Username, r.OID)
		}
	}
	rows, err := s.DB.ListSessions()
	if err != nil {
		return nil, fmt.Errorf("list sessions: %w", err)
	}
	for _, r := range rows {
		add(r.Subject, r.Email, r.Username, r.OID)
	}
	store, err := apitoken.NewSQLStore(s.DB)
	if err != nil {
		return nil, err
	}
	tokens, err := store.List()
	if err != nil {
		return nil, fmt.Errorf("list api tokens: %w", err)
	}
	for _, t := range tokens {
		if t.Owner != nil {
			add(t.Owner.Sub, t.Owner.Email, t.Owner.Username, t.Owner.OID)
		}
	}
	sort.Strings(out)
	return out, nil
}

// ── suspension ──────────────────────────────────────────────────────────────

// suspension is a planned deactivation.
type suspension struct {
	claim     MatchClaim
	write     *statedb.SCIMSuspendWrite
	plan      offboard.Plan
	collab    offboard.Options
	ambiguous *ambiguity
	reason    string
	// liveRevoked are the sessions the authenticator ended before the
	// transaction.
	liveRevoked []string
}

// planSuspension resolves what deactivating row severs, without writing.
func (s *Service) planSuspension(row statedb.SCIMUserRow, a Actor, now time.Time) (*suspension, error) {
	collab := s.collaborators()
	target, amb, err := s.targetFor(row, collab)
	if err != nil {
		return nil, err
	}
	reason := suspensionReason(a)
	o := collab
	o.DB, o.Target, o.Identity = s.DB, &target, target.Label()
	o.Reason, o.Actor, o.Via, o.DryRun = reason, a.Label(), "scim", true
	// Stored credentials are kept by a suspension, and memberships too; the
	// plan is read for what it severs, so the Claude homes need not be
	// looked at.
	o.Claude = nil
	o.Now = func() time.Time { return now }
	plan, err := offboard.BuildPlan(o)
	if err != nil {
		return nil, err
	}
	w := &statedb.SCIMSuspendWrite{
		Record: statedb.SCIMSuspensionRecord{
			By: a.Label(), Reason: reason, Identity: plan.Target.Key,
			Subjects: plan.Target.Subjects, Emails: plan.Target.Emails,
		},
	}
	for _, d := range plan.Denies {
		r, err := rolestore.RowFor(authz.Binding{Claim: authz.ClaimKind(d.Claim), Value: d.Value, Deny: true},
			reason, a.Label(), now)
		if err != nil {
			continue
		}
		w.Denies = append(w.Denies, r)
	}
	for _, t := range plan.Tokens {
		w.TokenIDs = append(w.TokenIDs, t.ID)
	}
	for _, g := range plan.Glasses {
		w.GlassesIDs = append(w.GlassesIDs, g.ID)
	}
	for _, g := range plan.Credentials.Grants {
		w.GrantIDs = append(w.GrantIDs, g.ID)
	}
	if collab.Sessions == nil {
		for _, sess := range plan.Sessions {
			w.SessionIDs = append(w.SessionIDs, sess.ID)
		}
	}
	return &suspension{claim: s.Config.MatchClaim, write: w, plan: plan, collab: collab, ambiguous: amb,
		reason: reason}, nil
}

// revokeLive ends the planned sessions through the running authenticator.
func (sp *suspension) revokeLive(a Actor) {
	if sp.collab.Sessions == nil {
		return
	}
	for _, sess := range sp.plan.Sessions {
		if ended, err := sp.collab.Sessions.Revoke(sess.ID, a.Label(), "scim_deactivated"); err == nil && ended {
			sp.liveRevoked = append(sp.liveRevoked, sess.ID)
		}
	}
}

// auditEvents are the rows the suspension's transaction carries.
func (sp *suspension) auditEvents(a Actor, ap statedb.SCIMUserApplied, now time.Time) ([]*statedb.AuditEvent, error) {
	t := sp.plan.Target
	leases := make([]string, 0, len(sp.plan.Leases))
	for _, l := range sp.plan.Leases {
		leases = append(leases, l.ID)
	}
	tasks := make([]string, 0, len(sp.plan.Tasks))
	for _, tk := range sp.plan.Tasks {
		tasks = append(tasks, fmt.Sprintf("%s#%d", tk.ProjectPath, tk.ID))
	}
	sessions := append(append([]string(nil), sp.liveRevoked...), ap.SessionsDeleted...)
	payload := map[string]any{
		"id": ap.Row.ID, "user_name": ap.Row.UserName, "identity": t.Key,
		"subjects": t.Subjects, "emails": t.Emails, "usernames": t.Usernames, "oids": t.OIDs,
		"ambiguous": sp.ambiguous != nil, "denies_written": ap.DeniesWritten, "denies_in_force": ap.DeniesInForce,
		"sessions": sessions, "api_tokens": ap.TokensRevoked, "glasses": ap.GlassesRevoked,
		"grants_suspended": ap.GrantsSuspended, "leases": leases, "tasks": tasks,
		"warnings": suspensionWarnings(sp.plan.Warnings),
	}
	ev, err := auditEvent(a.Label(), auditaction.ActionSCIMUserSuspend, "scim_user", ap.Row.ID, payload, now)
	if err != nil {
		return nil, err
	}
	evs := []*statedb.AuditEvent{ev}
	if sp.ambiguous != nil {
		amb, err := ambiguityEvent(a, sp.claim, ap.Row, sp.ambiguous, "suspend", now)
		if err != nil {
			return nil, err
		}
		evs = append(evs, amb)
	}
	return evs, nil
}

// suspensionWarnings keeps the plan's warnings that concern a suspension: a
// suspension keeps stored credentials and memberships, so the plan's notes
// about Claude homes and the stored footprint are not about it.
func suspensionWarnings(in []string) []string {
	var out []string
	for _, w := range in {
		if strings.Contains(w, "Claude Code logins were not checked") {
			continue
		}
		out = append(out, w)
	}
	return out
}

// ambiguityEvent records a provisioned user the hub would not resolve to one
// identity, and what it did instead.
func ambiguityEvent(a Actor, claim MatchClaim, row statedb.SCIMUserRow, amb *ambiguity, op string,
	now time.Time) (*statedb.AuditEvent, error) {
	return auditEvent(a.Label(), auditaction.ActionSCIMMatchAmbiguous, "scim_user", row.ID, map[string]any{
		"id": row.ID, "user_name": row.UserName, "match_claim": string(claim),
		"match_value": UserValue(claim, row), "subjects": amb.Subjects, "emails": amb.Emails, "operation": op,
	}, now)
}

// afterCommit ends what lives outside the database — the leases and the
// running tasks — and tells the hub what the transaction severed.
func (sp *suspension) afterCommit(s *Service, a Actor, ap statedb.SCIMUserApplied) {
	var failures []string
	if sp.collab.Leases != nil {
		for _, l := range sp.plan.Leases {
			sp.collab.Leases.Release(l.ID)
		}
	}
	if sp.collab.Tasks != nil {
		for _, t := range sp.plan.Tasks {
			if err := sp.collab.Tasks.Stop(t, a.Label(), sp.reason); err != nil {
				failures = append(failures, fmt.Sprintf("task %s#%d: %v", t.ProjectPath, t.ID, err))
			}
		}
	}
	s.severed(Severance{
		Actor:           a.Label(),
		RoleBindings:    len(ap.DeniesWritten) > 0,
		Tokens:          append(append([]string(nil), ap.TokensRevoked...), ap.GlassesRevoked...),
		Sessions:        ap.SessionsDeleted,
		GrantsSuspended: ap.GrantsSuspended,
	})
	if len(failures) > 0 {
		if ev, err := auditEvent(a.Label(), auditaction.ActionSCIMUserSuspendIncomplete, "scim_user", ap.Row.ID,
			map[string]any{"id": ap.Row.ID, "user_name": ap.Row.UserName, "failures": failures}, s.now()); err == nil {
			_ = s.DB.AppendAuditEvent(ev)
		}
	}
}

// ── the full offboarding ────────────────────────────────────────────────────

// offboardUser runs the full offboarding for a provisioned user, under a
// legal hold when one is placed on any spelling of the identity.
func (s *Service) offboardUser(ctx context.Context, a Actor, row statedb.SCIMUserRow, via, reason, op string) (offboard.Report, *offboard.HoldRef, error) {
	collab := s.collaborators()
	target, amb, err := s.targetFor(row, collab)
	if err != nil {
		return offboard.Report{}, nil, err
	}
	o := collab
	o.DB, o.Target, o.Identity = s.DB, &target, target.Label()
	// A legal hold is honoured by the offboarding itself (offboard.Plan.Hold),
	// for this run and for an operator's alike.
	o.Reason, o.Actor, o.Via = reason, a.Label(), via
	o.Now = s.Now
	rep, err := offboard.Run(o)
	if err != nil {
		return rep, nil, fmt.Errorf("offboard %s: %w", row.UserName, err)
	}
	if amb != nil {
		if ev, err := ambiguityEvent(a, s.Config.MatchClaim, row, amb, op, s.now()); err == nil {
			_ = s.DB.AppendAuditEvent(ev)
		}
	}
	rep2 := rep
	s.severed(Severance{
		Actor: a.Label(), RoleBindings: len(rep.DeniesWritten) > 0,
		Tokens:   append(append([]string(nil), rep.TokensRevoked...), rep.GlassesRevoked...),
		Offboard: &rep2,
	})
	return rep, rep.Hold, nil
}

// OffboardExpired runs the full offboarding for every user inactive for
// longer than Config.OffboardAfter, and reports how many it offboarded.
func (s *Service) OffboardExpired(ctx context.Context) (int, error) {
	if s.Config.OffboardAfter <= 0 {
		return 0, nil
	}
	now := s.now()
	rows, err := s.DB.PendingSCIMOffboards(now.Add(-s.Config.OffboardAfter))
	if err != nil {
		return 0, err
	}
	n := 0
	for _, pending := range rows {
		if ctx.Err() != nil {
			return n, ctx.Err()
		}
		if s.offboardExpired(ctx, pending.ID, now) {
			n++
		}
	}
	return n, nil
}

func (s *Service) offboardExpired(ctx context.Context, id string, now time.Time) bool {
	unlock := s.locks.lock("user:" + id)
	defer unlock()
	row, err := s.DB.GetSCIMUser(id)
	if err != nil || row.Active || !row.OffboardedAt.IsZero() || row.DeactivatedAt.IsZero() ||
		now.Sub(row.DeactivatedAt) < s.Config.OffboardAfter {
		return false
	}
	a := Actor{Name: strings.TrimPrefix(row.UpdatedBy, "scim:")}
	if rec, ok := row.SuspensionRecord(); ok && strings.HasPrefix(rec.By, "scim:") {
		a.Name = strings.TrimPrefix(rec.By, "scim:")
	}
	days := int(s.Config.OffboardAfter / (24 * time.Hour))
	reason := fmt.Sprintf("inactive at the identity provider since %s, past ui.oidc.scim.offboard_after_days (%d)",
		row.DeactivatedAt.Format("2006-01-02"), days)
	rep, hold, err := s.offboardUser(ctx, a, row, "scim-expiry", reason, "offboard_expired")
	failures := failureLines(rep.Failures)
	if err != nil {
		failures = append(failures, err.Error())
	}
	ev, aerr := auditEvent(a.Label(), auditaction.ActionSCIMUserOffboardExpired, "scim_user", row.ID, map[string]any{
		"id": row.ID, "user_name": row.UserName, "identity": rep.Target.Key,
		"deactivated_at": row.DeactivatedAt.Format(time.RFC3339), "legal_hold": hold != nil, "failures": failures,
	}, now)
	if aerr != nil {
		return false
	}
	if err != nil {
		// The offboarding's transaction failed: nothing is marked, and the
		// next sweep tries again. The row says why it did not happen now.
		_ = s.DB.AppendAuditEvent(ev)
		return false
	}
	marked, merr := s.DB.MarkSCIMUserOffboarded(row.ID, now, []*statedb.AuditEvent{ev})
	if merr != nil || !marked {
		return false
	}
	s.changed()
	return true
}
