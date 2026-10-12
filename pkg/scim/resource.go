package scim

// Resources as JSON objects.
//
// The hub keeps a provisioned resource as the identity provider sent it — a
// JSON object — because a provider's validator invents attributes and expects
// them back verbatim, and a typed struct would drop them. What it decides on
// is read out of that object here: userName, externalId, active and the
// primary email for a user; displayName, externalId and members for a group.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Bounds on the values the hub decides on. Generous for any directory, and a
// column, not storage.
const (
	maxUserNameLen    = 512
	maxExternalIDLen  = 512
	maxDisplayNameLen = 1024
	maxEmailLen       = 512
)

// Decode parses a request body into a JSON object.
func Decode(body []byte) (map[string]any, error) {
	var obj map[string]any
	dec := json.NewDecoder(strings.NewReader(string(body)))
	if err := dec.Decode(&obj); err != nil {
		return nil, BadRequest(ErrInvalidSyntax, "the body is not a JSON object: %v", err)
	}
	if obj == nil {
		return nil, BadRequest(ErrInvalidSyntax, "the body is not a JSON object")
	}
	if dec.More() {
		return nil, BadRequest(ErrInvalidSyntax, "the body holds more than one JSON value")
	}
	return obj, nil
}

// Clone returns a deep copy of a JSON value.
func Clone(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, e := range t {
			out[k] = Clone(e)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, e := range t {
			out[i] = Clone(e)
		}
		return out
	}
	return v
}

// CloneObject deep-copies a resource.
func CloneObject(obj map[string]any) map[string]any {
	if obj == nil {
		return map[string]any{}
	}
	return Clone(obj).(map[string]any)
}

// Normalize returns the resource a provider sent as the hub stores it: known
// attribute names in their canonical spelling, booleans that arrived as
// "True" and "False" as booleans, and none of what a client may not write —
// id, meta and schemas, which the hub assigns; a user's password, which it
// never keeps; and a user's groups, which are read-only and follow from the
// groups' members.
//
// A group's members stay in the object, normalised to {"value": id}; the
// caller moves them to the membership table.
func Normalize(obj map[string]any, kind Kind) (map[string]any, error) {
	out := make(map[string]any, len(obj))
	seen := map[string]string{}
	put := func(key string, v any, original string) error {
		lk := strings.ToLower(key)
		if prev, dup := seen[lk]; dup {
			return BadRequest(ErrInvalidSyntax, "the attribute %q is given twice (as %q and %q)", key, prev, original)
		}
		seen[lk] = original
		out[key] = v
		return nil
	}
	for k, v := range obj {
		switch strings.ToLower(k) {
		case "id", "meta", "schemas":
			continue
		case "password":
			if kind == KindUser {
				continue
			}
		case "groups":
			if kind == KindUser {
				continue
			}
		}
		if len(k) > 4 && strings.EqualFold(k[:4], "urn:") {
			if strings.EqualFold(k, kind.coreSchema().ID) {
				// Core attributes nested under the core URN: lift them.
				inner, ok := v.(map[string]any)
				if !ok {
					return nil, BadRequest(ErrInvalidSyntax, "%q must be an object", k)
				}
				lifted, err := Normalize(inner, kind)
				if err != nil {
					return nil, err
				}
				for lk, lv := range lifted {
					if err := put(lk, lv, k+":"+lk); err != nil {
						return nil, err
					}
				}
				continue
			}
			inner, ok := v.(map[string]any)
			if !ok {
				return nil, BadRequest(ErrInvalidSyntax, "the extension %q must be an object", k)
			}
			urn := k
			ext := kind.extension(k)
			if ext != nil {
				urn = ext.ID
			}
			norm, err := normalizeAttrs(inner, ext)
			if err != nil {
				return nil, err
			}
			if err := put(urn, norm, k); err != nil {
				return nil, err
			}
			continue
		}
		def := kind.definition(k)
		key := k
		val := v
		if def != nil {
			key = def.Name
			var err error
			if val, err = normalizeValue(def, v); err != nil {
				return nil, err
			}
		}
		if err := put(key, val, k); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// normalizeAttrs normalises an extension object's attributes.
func normalizeAttrs(obj map[string]any, s *Schema) (map[string]any, error) {
	out := make(map[string]any, len(obj))
	for k, v := range obj {
		def := s.attr(k)
		if def == nil {
			out[k] = v
			continue
		}
		val, err := normalizeValue(def, v)
		if err != nil {
			return nil, err
		}
		out[def.Name] = val
	}
	return out, nil
}

// normalizeValue checks and canonicalises one attribute's value.
func normalizeValue(def *Attribute, v any) (any, error) {
	if v == nil {
		return nil, nil
	}
	if def.MultiValued {
		list := asList(v)
		out := make([]any, 0, len(list))
		for _, e := range list {
			ne, err := normalizeSingle(def, e)
			if err != nil {
				return nil, err
			}
			out = append(out, ne)
		}
		return out, nil
	}
	if _, isList := v.([]any); isList {
		return nil, BadRequest(ErrInvalidValue, "%q takes one value, not a list", def.Name)
	}
	return normalizeSingle(def, v)
}

func normalizeSingle(def *Attribute, v any) (any, error) {
	switch def.Type {
	case "boolean":
		b, ok := boolValue(v)
		if !ok {
			return nil, BadRequest(ErrInvalidValue, "%q must be true or false, not %v", def.Name, v)
		}
		return b, nil
	case "complex":
		m, ok := v.(map[string]any)
		if !ok {
			// A bare value given for a complex attribute is its value
			// sub-attribute: ["a@b"] for emails, ["id"] for members, and
			// Entra ID's manager, which it sends as the manager's id.
			if s, isString := v.(string); isString && def.sub("value") != nil {
				return map[string]any{"value": s}, nil
			}
			return nil, BadRequest(ErrInvalidValue, "%q must be an object", def.Name)
		}
		out := make(map[string]any, len(m))
		for k, sv := range m {
			sdef := def.sub(k)
			if sdef == nil {
				out[k] = sv
				continue
			}
			nv, err := normalizeSingle(sdef, sv)
			if err != nil {
				return nil, err
			}
			out[sdef.Name] = nv
		}
		return out, nil
	}
	return v, nil
}

// ── what the hub decides on ─────────────────────────────────────────────────

// Email is one entry of a user's emails.
type Email struct {
	Value   string
	Type    string
	Primary bool
}

// UserFields are the attributes of a user the hub decides on.
type UserFields struct {
	UserName    string
	ExternalID  string
	DisplayName string
	// Active is nil when the resource does not say. A replace without it
	// leaves the account as it was: an identity provider that omits the
	// attribute has not asked for a reactivation, and treating its absence
	// as true would lift a suspension nobody lifted.
	Active *bool
	// Email is the account's address, lowercased: the primary email, else the
	// work address, else the first, else userName when it is address-shaped.
	Email  string
	Emails []Email
}

// ReadUser reads the fields the hub decides on out of a normalised user.
func ReadUser(obj map[string]any) (UserFields, error) {
	var u UserFields
	name, err := stringAttr(obj, "userName", maxUserNameLen)
	if err != nil {
		return u, err
	}
	if strings.TrimSpace(name) == "" {
		return u, BadRequest(ErrInvalidValue, "userName is required")
	}
	u.UserName = strings.TrimSpace(name)
	if u.ExternalID, err = stringAttr(obj, "externalId", maxExternalIDLen); err != nil {
		return u, err
	}
	u.ExternalID = strings.TrimSpace(u.ExternalID)
	if u.DisplayName, err = stringAttr(obj, "displayName", maxDisplayNameLen); err != nil {
		return u, err
	}
	if v, ok := lookup(obj, "active"); ok && v != nil {
		b, ok := boolValue(v)
		if !ok {
			return u, BadRequest(ErrInvalidValue, "active must be true or false")
		}
		u.Active = &b
	}
	if raw, ok := lookup(obj, "emails"); ok {
		for _, e := range asList(raw) {
			m, isObj := e.(map[string]any)
			if !isObj {
				continue
			}
			var em Email
			if v, ok := lookup(m, "value"); ok {
				s, isString := v.(string)
				if !isString {
					return u, BadRequest(ErrInvalidValue, "emails.value must be a string")
				}
				if len(s) > maxEmailLen {
					return u, BadRequest(ErrInvalidValue, "an email address is longer than %d bytes", maxEmailLen)
				}
				em.Value = strings.TrimSpace(s)
			}
			if v, ok := lookup(m, "type"); ok {
				em.Type, _ = v.(string)
			}
			if v, ok := lookup(m, "primary"); ok {
				em.Primary, _ = boolValue(v)
			}
			if em.Value != "" {
				u.Emails = append(u.Emails, em)
			}
		}
	}
	u.Email = primaryEmail(u.Emails, u.UserName)
	return u, nil
}

// primaryEmail picks the address an account is known by.
func primaryEmail(emails []Email, userName string) string {
	for _, e := range emails {
		if e.Primary {
			return strings.ToLower(e.Value)
		}
	}
	for _, e := range emails {
		if strings.EqualFold(e.Type, "work") {
			return strings.ToLower(e.Value)
		}
	}
	if len(emails) > 0 {
		return strings.ToLower(emails[0].Value)
	}
	if LooksLikeEmail(userName) {
		return strings.ToLower(userName)
	}
	return ""
}

// LooksLikeEmail is the conservative shape check oidcauth applies before it
// lets preferred_username stand in for an email: one "@", something either
// side, a dot in the domain, no whitespace. The two must agree, or a
// directory matching on email would describe a user by an address the hub's
// sign-in never calls them.
func LooksLikeEmail(s string) bool {
	at := strings.IndexByte(s, '@')
	if at <= 0 || at != strings.LastIndexByte(s, '@') || at == len(s)-1 {
		return false
	}
	domain := s[at+1:]
	dot := strings.IndexByte(domain, '.')
	return dot > 0 && dot < len(domain)-1 && !strings.ContainsAny(s, " \t\r\n")
}

// GroupFields are the attributes of a group the hub decides on.
type GroupFields struct {
	DisplayName string
	ExternalID  string
	// Members are the member ids, deduplicated, in the order given.
	Members []string
}

// ReadGroup reads the fields the hub decides on out of a normalised group.
func ReadGroup(obj map[string]any) (GroupFields, error) {
	var g GroupFields
	name, err := stringAttr(obj, "displayName", maxDisplayNameLen)
	if err != nil {
		return g, err
	}
	if strings.TrimSpace(name) == "" {
		return g, BadRequest(ErrInvalidValue, "displayName is required")
	}
	g.DisplayName = strings.TrimSpace(name)
	if g.ExternalID, err = stringAttr(obj, "externalId", maxExternalIDLen); err != nil {
		return g, err
	}
	g.ExternalID = strings.TrimSpace(g.ExternalID)
	g.Members = MemberIDs(obj)
	return g, nil
}

// MemberIDs reads a group's member ids.
func MemberIDs(obj map[string]any) []string {
	raw, ok := lookup(obj, "members")
	if !ok {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, e := range asList(raw) {
		var id string
		switch t := e.(type) {
		case map[string]any:
			if v, ok := lookup(t, "value"); ok {
				id, _ = v.(string)
			}
		case string:
			id = t
		}
		id = strings.TrimSpace(id)
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	return out
}

// SetMembers replaces a group object's members with ids.
func SetMembers(obj map[string]any, ids []string) {
	if k, ok := lookupKey(obj, "members"); ok {
		delete(obj, k)
	}
	list := make([]any, 0, len(ids))
	for _, id := range ids {
		list = append(list, map[string]any{"value": id})
	}
	obj["members"] = list
}

func stringAttr(obj map[string]any, name string, max int) (string, error) {
	v, ok := lookup(obj, name)
	if !ok || v == nil {
		return "", nil
	}
	s, isString := v.(string)
	if !isString {
		return "", BadRequest(ErrInvalidValue, "%s must be a string", name)
	}
	if len(s) > max {
		return "", BadRequest(ErrInvalidValue, "%s is longer than %d bytes", name, max)
	}
	return s, nil
}

// ── rendering ───────────────────────────────────────────────────────────────

// Meta is a resource's meta attribute.
type Meta struct {
	Created      time.Time
	LastModified time.Time
	Location     string
	Version      int64
}

// Render is the representation a client receives: the stored object with the
// id, schemas and meta the hub assigns.
func Render(stored map[string]any, kind Kind, id string, meta Meta) map[string]any {
	out := CloneObject(stored)
	out["id"] = id
	schemas := []any{kind.coreSchema().ID}
	var exts []string
	for k, v := range out {
		if _, isObj := v.(map[string]any); isObj && len(k) > 4 && strings.EqualFold(k[:4], "urn:") {
			exts = append(exts, k)
		}
	}
	sort.Strings(exts)
	for _, e := range exts {
		schemas = append(schemas, e)
	}
	out["schemas"] = schemas
	m := map[string]any{"resourceType": kind.String()}
	if !meta.Created.IsZero() {
		m["created"] = meta.Created.UTC().Format(time.RFC3339)
	}
	if !meta.LastModified.IsZero() {
		m["lastModified"] = meta.LastModified.UTC().Format(time.RFC3339)
	}
	if meta.Location != "" {
		m["location"] = meta.Location
	}
	if meta.Version > 0 {
		m["version"] = ETag(meta.Version)
	}
	out["meta"] = m
	return out
}

// Projection is a request's attributes and excludedAttributes parameters.
type Projection struct {
	Attributes []AttrPath
	Excluded   []AttrPath
}

// ParseProjection reads ?attributes= and ?excludedAttributes=.
func ParseProjection(q url.Values, kind Kind) (Projection, error) {
	var p Projection
	read := func(name string) ([]AttrPath, error) {
		var out []AttrPath
		for _, raw := range q[name] {
			for _, part := range strings.Split(raw, ",") {
				part = strings.TrimSpace(part)
				if part == "" {
					continue
				}
				ap, err := ParseAttrPath(part, kind)
				if err != nil {
					return nil, BadRequest(ErrInvalidPath, "%s: %v", name, err.(*Error).Detail)
				}
				out = append(out, ap)
			}
		}
		return out, nil
	}
	var err error
	if p.Attributes, err = read("attributes"); err != nil {
		return p, err
	}
	if p.Excluded, err = read("excludedAttributes"); err != nil {
		return p, err
	}
	return p, nil
}

// alwaysReturned are kept whatever a projection says (RFC 7643 "returned:
// always").
func alwaysReturned(kind Kind, name string) bool {
	switch strings.ToLower(name) {
	case "id", "schemas", "meta":
		return true
	case "username":
		return kind == KindUser
	case "displayname":
		return kind == KindGroup
	}
	return false
}

// Apply narrows a rendered resource to the projection.
func (p Projection) Apply(res map[string]any, kind Kind) map[string]any {
	if len(p.Attributes) == 0 && len(p.Excluded) == 0 {
		return res
	}
	if len(p.Attributes) > 0 {
		out := map[string]any{}
		for k, v := range res {
			if alwaysReturned(kind, k) {
				out[k] = v
			}
		}
		for _, a := range p.Attributes {
			copyPath(out, res, a)
		}
		return out
	}
	out := CloneObject(res)
	for _, a := range p.Excluded {
		if a.URN == "" && alwaysReturned(kind, a.Name) && a.Sub == "" {
			continue
		}
		dropPath(out, a)
	}
	return out
}

func copyPath(dst, src map[string]any, a AttrPath) {
	from, to := src, dst
	if a.URN != "" {
		ext, ok := lookup(src, a.URN)
		m, isObj := ext.(map[string]any)
		if !ok || !isObj {
			return
		}
		key, _ := lookupKey(src, a.URN)
		inner, _ := dst[key].(map[string]any)
		if inner == nil {
			inner = map[string]any{}
			dst[key] = inner
		}
		from, to = m, inner
	}
	key, ok := lookupKey(from, a.Name)
	if !ok {
		return
	}
	if a.Sub == "" {
		to[key] = Clone(from[key])
		return
	}
	switch t := from[key].(type) {
	case map[string]any:
		sk, ok := lookupKey(t, a.Sub)
		if !ok {
			return
		}
		inner, _ := to[key].(map[string]any)
		if inner == nil {
			inner = map[string]any{}
			to[key] = inner
		}
		inner[sk] = Clone(t[sk])
	case []any:
		var list []any
		for _, e := range t {
			if m, isObj := e.(map[string]any); isObj {
				if sk, ok := lookupKey(m, a.Sub); ok {
					list = append(list, map[string]any{sk: Clone(m[sk])})
				}
			}
		}
		to[key] = list
	}
}

func dropPath(obj map[string]any, a AttrPath) {
	target := obj
	if a.URN != "" {
		ext, ok := lookup(obj, a.URN)
		m, isObj := ext.(map[string]any)
		if !ok || !isObj {
			return
		}
		target = m
	}
	key, ok := lookupKey(target, a.Name)
	if !ok {
		return
	}
	if a.Sub == "" {
		delete(target, key)
		return
	}
	switch t := target[key].(type) {
	case map[string]any:
		if sk, ok := lookupKey(t, a.Sub); ok {
			delete(t, sk)
		}
	case []any:
		for _, e := range t {
			if m, isObj := e.(map[string]any); isObj {
				if sk, ok := lookupKey(m, a.Sub); ok {
					delete(m, sk)
				}
			}
		}
	}
}

// ── lists ───────────────────────────────────────────────────────────────────

// ListResponse is the RFC 7644 §3.4.2 list document.
type ListResponse struct {
	Schemas      []string         `json:"schemas"`
	TotalResults int              `json:"totalResults"`
	StartIndex   int              `json:"startIndex"`
	ItemsPerPage int              `json:"itemsPerPage"`
	Resources    []map[string]any `json:"Resources"`
}

// NewListResponse wraps one page of resources.
func NewListResponse(total int, page Page, resources []map[string]any) ListResponse {
	if resources == nil {
		resources = []map[string]any{}
	}
	return ListResponse{
		Schemas:      []string{SchemaListResponse},
		TotalResults: total,
		StartIndex:   page.StartIndex,
		ItemsPerPage: len(resources),
		Resources:    resources,
	}
}

// Page is a request's pagination.
type Page struct {
	// StartIndex is 1-based.
	StartIndex int
	// Count is the most resources to return; 0 asks for the total alone.
	Count int
}

// Offset is the 0-based index of the first resource.
func (p Page) Offset() int { return p.StartIndex - 1 }

// DefaultPageSize and MaxPageSize bound a list. The maximum is what the hub
// advertises in its ServiceProviderConfig.
const (
	DefaultPageSize = 100
	MaxPageSize     = 200
)

// ParsePage reads ?startIndex= and ?count= (RFC 7644 §3.4.2.4): a startIndex
// below 1 is 1, a negative count is 0, and a count above MaxPageSize is
// MaxPageSize.
func ParsePage(q url.Values) (Page, error) {
	p := Page{StartIndex: 1, Count: DefaultPageSize}
	if raw := strings.TrimSpace(q.Get("startIndex")); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil {
			return p, BadRequest(ErrInvalidValue, "startIndex %q is not a number", raw)
		}
		if n > 1 {
			p.StartIndex = n
		}
	}
	if raw := strings.TrimSpace(q.Get("count")); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil {
			return p, BadRequest(ErrInvalidValue, "count %q is not a number", raw)
		}
		switch {
		case n < 0:
			p.Count = 0
		case n > MaxPageSize:
			p.Count = MaxPageSize
		default:
			p.Count = n
		}
	}
	return p, nil
}

// Paginate returns the slice of items the page covers.
func Paginate[T any](items []T, p Page) []T {
	off := p.Offset()
	if off >= len(items) || p.Count == 0 {
		return nil
	}
	end := off + p.Count
	if end > len(items) {
		end = len(items)
	}
	return items[off:end]
}

// StatusFor names the HTTP status a request method succeeds with.
func StatusFor(method string, created bool) int {
	switch {
	case created:
		return http.StatusCreated
	case method == http.MethodDelete:
		return http.StatusNoContent
	}
	return http.StatusOK
}

// Describe renders a value for a message: short, and never a whole resource.
func Describe(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprint(v)
	}
	if len(b) > 120 {
		return string(b[:117]) + "..."
	}
	return string(b)
}
