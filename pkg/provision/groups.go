package provision

// The SCIM operations on groups.
//
// A provisioned group is what a role binding names with claim: scim_group, by
// display name or external id. Its members are provisioned users, kept as a
// set: adding one twice or removing one who is not there is the state asked
// for, so a retried or reordered membership change converges. A member id that
// names no provisioned user — a user deleted while the change was in flight,
// or a nested group, which the hub does not provision — is skipped and said so
// in the audit row, never stored.

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/blechschmidt/cloop/pkg/auditaction"
	"github.com/blechschmidt/cloop/pkg/scim"
	"github.com/blechschmidt/cloop/pkg/statedb"
)

// renderGroup is the representation of a stored group. members is nil when
// the caller asked for them to be excluded.
func renderGroup(g statedb.SCIMGroupRow, userNames map[string]string, withMembers bool, base string) map[string]any {
	obj := decodeResource(g.ResourceJSON)
	obj["displayName"] = g.DisplayName
	if g.ExternalID != "" {
		obj["externalId"] = g.ExternalID
	}
	if withMembers {
		list := make([]any, 0, len(g.Members))
		for _, id := range g.Members {
			m := map[string]any{"value": id, "$ref": userURL(base, id), "type": "User"}
			if n := userNames[id]; n != "" {
				m["display"] = n
			}
			list = append(list, m)
		}
		obj["members"] = list
	}
	return scim.Render(obj, scim.KindGroup, g.ID, scim.Meta{
		Created: g.CreatedAt, LastModified: g.UpdatedAt, Location: groupURL(base, g.ID), Version: g.Version,
	})
}

// membersExcluded reports whether a projection leaves members out, so they
// need not be read: Entra ID asks for excludedAttributes=members on every
// group lookup.
func membersExcluded(p scim.Projection) bool {
	for _, a := range p.Excluded {
		if a.URN == "" && strings.EqualFold(a.Name, "members") && a.Sub == "" {
			return true
		}
	}
	if len(p.Attributes) > 0 {
		for _, a := range p.Attributes {
			if a.URN == "" && strings.EqualFold(a.Name, "members") {
				return false
			}
		}
		return true
	}
	return false
}

func (s *Service) userNames() (map[string]string, error) {
	dir, err := s.DB.LoadSCIMDirectory()
	if err != nil {
		return nil, err
	}
	out := make(map[string]string, len(dir.Users))
	for _, u := range dir.Users {
		out[u.ID] = u.UserName
	}
	return out, nil
}

// GetGroup serves GET /Groups/{id}.
func (s *Service) GetGroup(id string, q url.Values, base string) (Result, error) {
	g, err := s.DB.GetSCIMGroup(id)
	if err != nil {
		if errors.Is(err, statedb.ErrSCIMNotFound) {
			return Result{}, scim.NotFound("Group", id)
		}
		return Result{}, err
	}
	proj, err := scim.ParseProjection(q, scim.KindGroup)
	if err != nil {
		return Result{}, err
	}
	with := !membersExcluded(proj)
	var names map[string]string
	if with {
		if names, err = s.userNames(); err != nil {
			return Result{}, err
		}
	}
	res := renderGroup(g, names, with, base)
	return Result{Status: http.StatusOK, Resource: proj.Apply(res, scim.KindGroup), Version: g.Version}, nil
}

// ListGroups serves GET /Groups.
func (s *Service) ListGroups(q url.Values, base string) (scim.ListResponse, error) {
	page, err := scim.ParsePage(q)
	if err != nil {
		return scim.ListResponse{}, err
	}
	proj, err := scim.ParseProjection(q, scim.KindGroup)
	if err != nil {
		return scim.ListResponse{}, err
	}
	var filter *scim.Filter
	if raw := strings.TrimSpace(q.Get("filter")); raw != "" {
		if filter, err = scim.ParseFilter(raw, scim.KindGroup); err != nil {
			return scim.ListResponse{}, err
		}
	}
	// A filter on members needs them read even when the response leaves
	// them out.
	with := !membersExcluded(proj) || (filter != nil && strings.Contains(strings.ToLower(filter.String()), "members"))
	var rows []statedb.SCIMGroupRow
	if attr, value, ok := filter.Equality(); ok && (attr == "displayName" || attr == "externalId" || attr == "id") {
		switch attr {
		case "displayName":
			rows, err = s.DB.FindSCIMGroups(true, value)
		case "externalId":
			rows, err = s.DB.FindSCIMGroups(false, value)
		case "id":
			g, gerr := s.DB.GetSCIMGroup(value)
			if gerr == nil {
				rows = []statedb.SCIMGroupRow{g}
			} else if !errors.Is(gerr, statedb.ErrSCIMNotFound) {
				err = gerr
			}
		}
	} else {
		rows, err = s.DB.ListSCIMGroups(with)
	}
	if err != nil {
		return scim.ListResponse{}, err
	}
	var names map[string]string
	if with {
		if names, err = s.userNames(); err != nil {
			return scim.ListResponse{}, err
		}
	}
	var matched []map[string]any
	for _, g := range rows {
		res := renderGroup(g, names, with, base)
		if filter.Matches(res) {
			matched = append(matched, res)
		}
	}
	pageRes := scim.Paginate(matched, page)
	out := make([]map[string]any, 0, len(pageRes))
	for _, r := range pageRes {
		out = append(out, proj.Apply(r, scim.KindGroup))
	}
	return scim.NewListResponse(len(matched), page, out), nil
}

// groupFromResource splits a normalised group into its row and its members;
// members is nil when the resource does not say.
func groupFromResource(norm map[string]any) (statedb.SCIMGroupRow, []string, bool, error) {
	f, err := scim.ReadGroup(norm)
	if err != nil {
		return statedb.SCIMGroupRow{}, nil, false, err
	}
	_, hasMembers := norm["members"]
	stored := scim.CloneObject(norm)
	delete(stored, "members")
	blob, err := encodeResource(stored)
	if err != nil {
		return statedb.SCIMGroupRow{}, nil, false, err
	}
	return statedb.SCIMGroupRow{DisplayName: f.DisplayName, ExternalID: f.ExternalID, ResourceJSON: blob},
		f.Members, hasMembers, nil
}

// CreateGroup serves POST /Groups.
func (s *Service) CreateGroup(ctx context.Context, a Actor, body []byte, base string) (Result, error) {
	obj, err := scim.Decode(body)
	if err != nil {
		return Result{}, err
	}
	norm, err := scim.Normalize(obj, scim.KindGroup)
	if err != nil {
		return Result{}, err
	}
	row, members, _, err := groupFromResource(norm)
	if err != nil {
		return Result{}, err
	}
	if row.ID, err = newResourceID(); err != nil {
		return Result{}, err
	}
	row.CreatedBy, row.UpdatedBy, row.Members = a.Label(), a.Label(), members
	now := s.now()
	applied, err := s.DB.WriteSCIMGroup(statedb.SCIMGroupWrite{
		Row: row, Create: true, SetMembers: true, At: now,
		Audit: func(ap statedb.SCIMGroupApplied) ([]*statedb.AuditEvent, error) {
			ev, err := auditEvent(a.Label(), auditaction.ActionSCIMGroupCreate, "scim_group", ap.Row.ID,
				map[string]any{"id": ap.Row.ID, "display_name": ap.Row.DisplayName, "external_id": ap.Row.ExternalID,
					"members": ap.Added, "unknown_members": ap.Unknown}, now)
			if err != nil {
				return nil, err
			}
			return []*statedb.AuditEvent{ev}, nil
		},
	})
	if err != nil {
		return Result{}, translate(err)
	}
	s.changed()
	names, err := s.userNames()
	if err != nil {
		return Result{}, err
	}
	return Result{Status: http.StatusCreated, Resource: renderGroup(applied.Row, names, true, base),
		Location: groupURL(base, applied.Row.ID), Version: applied.Row.Version}, nil
}

// ReplaceGroup serves PUT /Groups/{id}. A body without members leaves the
// membership as it is: the absence of the attribute is not "no members".
func (s *Service) ReplaceGroup(ctx context.Context, a Actor, id string, body []byte, ifMatch, base string) (Result, error) {
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
	norm, err := scim.Normalize(obj, scim.KindGroup)
	if err != nil {
		return Result{}, err
	}
	return s.updateGroup(ctx, a, id, ifMatch, http.MethodPut, func(stored statedb.SCIMGroupRow) (statedb.SCIMGroupRow, []string, bool, error) {
		return groupFromResource(scim.CloneObject(norm))
	}, base, true)
}

// PatchGroup serves PATCH /Groups/{id}: renames, and member additions and
// removals in every dialect pkg/scim reads. It answers 204, as RFC 7644
// allows, rather than a group of thousands of members nobody asked to see.
func (s *Service) PatchGroup(ctx context.Context, a Actor, id string, body []byte, ifMatch, base string) (Result, error) {
	ops, err := scim.ParsePatch(body)
	if err != nil {
		return Result{}, err
	}
	return s.updateGroup(ctx, a, id, ifMatch, http.MethodPatch, func(stored statedb.SCIMGroupRow) (statedb.SCIMGroupRow, []string, bool, error) {
		obj := decodeResource(stored.ResourceJSON)
		obj["displayName"] = stored.DisplayName
		if stored.ExternalID != "" {
			obj["externalId"] = stored.ExternalID
		}
		scim.SetMembers(obj, stored.Members)
		if err := scim.ApplyPatch(obj, scim.KindGroup, stored.ID, ops); err != nil {
			return statedb.SCIMGroupRow{}, nil, false, err
		}
		norm, err := scim.Normalize(obj, scim.KindGroup)
		if err != nil {
			return statedb.SCIMGroupRow{}, nil, false, err
		}
		if _, ok := norm["members"]; !ok {
			// Every member removed: the attribute went with them.
			norm["members"] = []any{}
		}
		return groupFromResource(norm)
	}, base, false)
}

func (s *Service) updateGroup(ctx context.Context, a Actor, id, ifMatch, method string,
	apply func(statedb.SCIMGroupRow) (statedb.SCIMGroupRow, []string, bool, error), base string,
	withBody bool) (Result, error) {
	unlock := s.locks.lock("group:" + id)
	defer unlock()
	for attempt := 1; ; attempt++ {
		stored, err := s.DB.GetSCIMGroup(id)
		if err != nil {
			if errors.Is(err, statedb.ErrSCIMNotFound) {
				return Result{}, scim.NotFound("Group", id)
			}
			return Result{}, err
		}
		if !scim.MatchesETag(ifMatch, stored.Version) {
			return Result{}, scim.Errorf(http.StatusPreconditionFailed, "",
				"group %s is at version %s, not %s", id, scim.ETag(stored.Version), ifMatch)
		}
		next, members, hasMembers, err := apply(stored)
		if err != nil {
			return Result{}, err
		}
		next.ID, next.UpdatedBy = stored.ID, a.Label()
		attrsChanged := next.DisplayName != stored.DisplayName || next.ExternalID != stored.ExternalID ||
			next.ResourceJSON != stored.ResourceJSON
		next.Members = stored.Members
		membersChanged := false
		if hasMembers {
			next.Members = members
			membersChanged = !sameSet(members, stored.Members)
		}
		if !attrsChanged && !membersChanged {
			return s.groupResult(stored, base, withBody)
		}
		now := s.now()
		applied, err := s.DB.WriteSCIMGroup(statedb.SCIMGroupWrite{
			Row: next, ExpectVersion: stored.Version, SetMembers: membersChanged, At: now,
			Audit: func(ap statedb.SCIMGroupApplied) ([]*statedb.AuditEvent, error) {
				var evs []*statedb.AuditEvent
				if attrsChanged {
					ev, err := auditEvent(a.Label(), auditaction.ActionSCIMGroupUpdate, "scim_group", ap.Row.ID,
						map[string]any{"id": ap.Row.ID, "display_name": ap.Row.DisplayName,
							"previous_display_name": stored.DisplayName, "external_id": ap.Row.ExternalID,
							"method": method}, now)
					if err != nil {
						return nil, err
					}
					evs = append(evs, ev)
				}
				if len(ap.Added) > 0 || len(ap.Removed) > 0 || len(ap.Unknown) > 0 {
					ev, err := auditEvent(a.Label(), auditaction.ActionSCIMGroupMembers, "scim_group", ap.Row.ID,
						map[string]any{"id": ap.Row.ID, "display_name": ap.Row.DisplayName, "added": ap.Added,
							"removed": ap.Removed, "unknown_members": ap.Unknown, "method": method}, now)
					if err != nil {
						return nil, err
					}
					evs = append(evs, ev)
				}
				return evs, nil
			},
		})
		if errors.Is(err, statedb.ErrSCIMVersion) && strings.TrimSpace(ifMatch) == "" && attempt < maxWriteAttempts {
			continue
		}
		if err != nil {
			return Result{}, translate(err)
		}
		s.changed()
		return s.groupResult(applied.Row, base, withBody)
	}
}

func (s *Service) groupResult(g statedb.SCIMGroupRow, base string, withBody bool) (Result, error) {
	if !withBody {
		return Result{Status: http.StatusNoContent, Version: g.Version}, nil
	}
	names, err := s.userNames()
	if err != nil {
		return Result{}, err
	}
	return Result{Status: http.StatusOK, Resource: renderGroup(g, names, true, base), Version: g.Version}, nil
}

// DeleteGroup serves DELETE /Groups/{id}.
func (s *Service) DeleteGroup(ctx context.Context, a Actor, id, ifMatch string) (Result, error) {
	unlock := s.locks.lock("group:" + id)
	defer unlock()
	g, err := s.DB.GetSCIMGroup(id)
	if err != nil {
		if errors.Is(err, statedb.ErrSCIMNotFound) {
			return Result{}, scim.NotFound("Group", id)
		}
		return Result{}, err
	}
	if !scim.MatchesETag(ifMatch, g.Version) {
		return Result{}, scim.Errorf(http.StatusPreconditionFailed, "", "group %s is at version %s", id,
			scim.ETag(g.Version))
	}
	now := s.now()
	ev, err := auditEvent(a.Label(), auditaction.ActionSCIMGroupDelete, "scim_group", g.ID, map[string]any{
		"id": g.ID, "display_name": g.DisplayName, "external_id": g.ExternalID, "members": g.Members,
	}, now)
	if err != nil {
		return Result{}, err
	}
	deleted, err := s.DB.DeleteSCIMGroup(g.ID, []*statedb.AuditEvent{ev})
	if err != nil {
		return Result{}, err
	}
	if !deleted {
		return Result{}, scim.NotFound("Group", id)
	}
	s.changed()
	return Result{Status: http.StatusNoContent}, nil
}

func sameSet(a, b []string) bool {
	set, other := map[string]bool{}, map[string]bool{}
	for _, v := range a {
		set[v] = true
	}
	for _, v := range b {
		other[v] = true
	}
	if len(set) != len(other) {
		return false
	}
	for v := range set {
		if !other[v] {
			return false
		}
	}
	return true
}
