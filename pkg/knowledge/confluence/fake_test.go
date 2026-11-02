package confluence

// fake_test.go is an in-memory Confluence site: the parts of REST API v2 and
// v1 the connector reads, for Cloud (under /wiki, v2 cursors, v1 search
// cursors) and Data Center (under a context path, start/limit offsets), with
// the site's own authentication, a CQL subset, expansions that appear only
// when asked for, and faults to inject: 429s and 503s, a search index that
// lags, an API that drops the restriction expansion.

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode"
)

type fakeContent struct {
	ID, Type, Status, Title, Space string
	ParentID                       string
	Created, Modified              time.Time
	Body                           string
	Labels                         []string
	// ReadUsers and ReadGroups are the content's own read restriction.
	ReadUsers, ReadGroups []string
}

type fakeSpace struct{ ID, Key string }

// fakeSite is a Confluence site.
type fakeSite struct {
	t          *testing.T
	cloud      bool
	context    string // "/wiki" on Cloud, "" or "/confluence" on Data Center
	email      string // basic auth's email; empty: bearer
	token      string
	srv        *httptest.Server
	mu         sync.Mutex
	spaces     []fakeSpace
	content    map[string]*fakeContent
	nextID     int
	clock      time.Time
	requests   []string
	statusSeq  []fakeFault // answered in order, one per request, before anything else
	searchLag  map[string]bool
	noRestrict bool   // the API leaves out the restriction expansion
	redirect   bool   // every request is answered with a redirect
	echoAuth   bool   // refusals echo the request's Authorization header
	padding    string // added to every answer's body, to make it large
}

// fakeFault is one injected answer.
type fakeFault struct {
	status     int
	retryAfter string
}

func newFakeSite(t *testing.T, cloud bool, context string) *fakeSite {
	t.Helper()
	f := &fakeSite{
		t: t, cloud: cloud, context: context, token: "site-token-" + strings.Repeat("Q7", 12),
		content: map[string]*fakeContent{}, nextID: 1000, searchLag: map[string]bool{},
		clock: time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC),
	}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

// baseURL is what a source configures.
func (f *fakeSite) baseURL() string { return f.srv.URL + f.context }

// addSpace adds a space.
func (f *fakeSite) addSpace(key string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.nextID++
	f.spaces = append(f.spaces, fakeSpace{ID: strconv.Itoa(f.nextID), Key: key})
}

// add adds content, an hour after the last change, and returns it.
func (f *fakeSite) add(typ, space, title, parent, body string) *fakeContent {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.nextID++
	f.clock = f.clock.Add(time.Hour)
	c := &fakeContent{ID: strconv.Itoa(f.nextID), Type: typ, Status: "current", Title: title, Space: space,
		ParentID: parent, Created: f.clock, Modified: f.clock, Body: body}
	f.content[c.ID] = c
	return c
}

// edit changes content: a new version, an hour after the last change.
func (f *fakeSite) edit(c *fakeContent, mutate func(*fakeContent)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.clock = f.clock.Add(time.Hour)
	if mutate != nil {
		mutate(c)
	}
	c.Modified = f.clock
}

// set changes content without a new version: what moving a page, or
// restricting it, does.
func (f *fakeSite) set(mutate func()) {
	f.mu.Lock()
	defer f.mu.Unlock()
	mutate()
}

func (f *fakeSite) fail(faults ...fakeFault) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.statusSeq = append(f.statusSeq, faults...)
}

func (f *fakeSite) requestLog() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.requests...)
}

// ancestorsOf returns c's ancestors, outermost first.
func (f *fakeSite) ancestorsOf(c *fakeContent) []*fakeContent {
	var out []*fakeContent
	for p := f.content[c.ParentID]; p != nil && len(out) < 64; p = f.content[p.ParentID] {
		out = append([]*fakeContent{p}, out...)
	}
	return out
}

// canSee: the site's account sees everything; restrictions only matter to
// what the connector decides.
func (f *fakeSite) authorized(r *http.Request) bool {
	got := r.Header.Get("Authorization")
	if f.email != "" {
		return got == "Basic "+base64.StdEncoding.EncodeToString([]byte(f.email+":"+f.token))
	}
	return got == "Bearer "+f.token
}

func (f *fakeSite) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests = append(f.requests, r.URL.Path+"?"+r.URL.RawQuery)
	if len(f.statusSeq) > 0 {
		fault := f.statusSeq[0]
		f.statusSeq = f.statusSeq[1:]
		if fault.retryAfter != "" {
			w.Header().Set("Retry-After", fault.retryAfter)
		}
		writeJSON(w, fault.status, map[string]any{"statusCode": fault.status, "message": "slow down"})
		return
	}
	if f.redirect {
		http.Redirect(w, r, "https://elsewhere.example/wiki"+r.URL.Path, http.StatusFound)
		return
	}
	if !f.authorized(r) {
		msg := "Client must be authenticated to access this resource."
		if f.echoAuth {
			msg += " Received: " + r.Header.Get("Authorization")
		}
		writeJSON(w, http.StatusUnauthorized, map[string]any{"statusCode": 401, "message": msg})
		return
	}
	path, ok := strings.CutPrefix(r.URL.Path, f.context)
	if !ok {
		http.NotFound(w, r)
		return
	}
	q := r.URL.Query()
	switch {
	case f.cloud && path == "/api/v2/spaces":
		f.v2Spaces(w, q)
	case f.cloud && (path == "/api/v2/pages" || path == "/api/v2/blogposts"):
		f.v2Content(w, q, strings.TrimSuffix(strings.TrimPrefix(path, "/api/v2/"), "s"))
	case !f.cloud && path == "/rest/api/space":
		f.v1Spaces(w, q)
	case path == "/rest/api/content/search":
		f.search(w, q)
	case strings.HasPrefix(path, "/rest/api/content/"):
		rest := strings.TrimPrefix(path, "/rest/api/content/")
		id, sub, _ := strings.Cut(rest, "/")
		c := f.content[id]
		if c == nil {
			writeJSON(w, http.StatusNotFound, map[string]any{"statusCode": 404, "message": "No content found with id " + id})
			return
		}
		switch sub {
		case "":
			writeJSON(w, http.StatusOK, f.v1JSON(c, expansions(q.Get("expand"))))
		case "restriction/byOperation/read":
			if f.noRestrict {
				writeJSON(w, http.StatusOK, map[string]any{"operation": "read"})
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{"operation": "read", "restrictions": f.restrictionsJSON(c)})
		default:
			http.NotFound(w, r)
		}
	default:
		writeJSON(w, http.StatusNotFound, map[string]any{"statusCode": 404, "message": "no route " + path})
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (f *fakeSite) v2Spaces(w http.ResponseWriter, q url.Values) {
	want := map[string]bool{}
	for _, k := range strings.Split(q.Get("keys"), ",") {
		want[k] = true
	}
	results := []map[string]any{}
	for _, s := range f.spaces {
		if want[s.Key] {
			results = append(results, map[string]any{"id": s.ID, "key": s.Key, "name": s.Key + " space"})
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"results": results, "_links": map[string]any{"base": f.baseURL()}})
}

func (f *fakeSite) v1Spaces(w http.ResponseWriter, q url.Values) {
	want := map[string]bool{}
	for _, k := range q["spaceKey"] {
		want[k] = true
	}
	results := []map[string]any{}
	for _, s := range f.spaces {
		if want[s.Key] {
			id, _ := strconv.Atoi(s.ID)
			results = append(results, map[string]any{"id": id, "key": s.Key, "name": s.Key + " space", "type": "global"})
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"results": results, "start": 0, "limit": 100, "size": len(results),
		"_links": map[string]any{"base": f.baseURL(), "context": f.context}})
}

func (f *fakeSite) spaceKey(id string) string {
	for _, s := range f.spaces {
		if s.ID == id {
			return s.Key
		}
	}
	return ""
}

func (f *fakeSite) spaceID(key string) string {
	for _, s := range f.spaces {
		if s.Key == key {
			return s.ID
		}
	}
	return ""
}

func (f *fakeSite) webui(c *fakeContent) string {
	if f.cloud {
		return "/spaces/" + c.Space + "/pages/" + c.ID
	}
	return "/pages/viewpage.action?pageId=" + c.ID
}

// v2Content lists pages or blog posts of spaces, newest change first, a
// cursor at a time.
func (f *fakeSite) v2Content(w http.ResponseWriter, q url.Values, typ string) {
	if q.Get("sort") != "-modified-date" || q.Get("status") != "current" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"errors": []map[string]any{
			{"status": 400, "title": "Bad request", "detail": "the fake serves sort=-modified-date&status=current only"}}})
		return
	}
	spaces := map[string]bool{}
	for _, id := range strings.Split(q.Get("space-id"), ",") {
		if key := f.spaceKey(id); key != "" {
			spaces[key] = true
		}
	}
	var list []*fakeContent
	for _, c := range f.content {
		if c.Type == typ && c.Status == "current" && spaces[c.Space] {
			list = append(list, c)
		}
	}
	sortNewest(list)
	page, next := paginate(list, q, "cursor")
	results := []map[string]any{}
	for _, c := range page {
		m := map[string]any{
			"id": c.ID, "status": c.Status, "title": c.Title, "spaceId": f.spaceID(c.Space),
			"parentId": c.ParentID, "version": map[string]any{"createdAt": c.Modified.Format(time.RFC3339Nano), "number": 1},
			"_links": map[string]any{"webui": f.webui(c)},
		}
		if q.Get("body-format") == "storage" {
			m["body"] = map[string]any{"storage": map[string]any{"value": c.Body + f.padding, "representation": "storage"}}
		}
		results = append(results, m)
	}
	l := map[string]any{"base": f.baseURL()}
	if next != "" {
		nq := cloneValues(q)
		nq.Set("cursor", next)
		l["next"] = "/wiki/api/v2/" + typ + "s?" + nq.Encode()
	}
	writeJSON(w, http.StatusOK, map[string]any{"results": results, "_links": l})
}

func sortNewest(list []*fakeContent) {
	sort.Slice(list, func(i, j int) bool {
		if !list[i].Modified.Equal(list[j].Modified) {
			return list[i].Modified.After(list[j].Modified)
		}
		return list[i].ID > list[j].ID
	})
}

func cloneValues(q url.Values) url.Values {
	out := url.Values{}
	for k, v := range q {
		out[k] = append([]string(nil), v...)
	}
	return out
}

// paginate returns the page of list q asks for, and the next position: a
// base64 cursor in param "cursor", or a start offset in "start".
func paginate(list []*fakeContent, q url.Values, param string) ([]*fakeContent, string) {
	limit, err := strconv.Atoi(q.Get("limit"))
	if err != nil || limit <= 0 {
		limit = 25
	}
	start := 0
	if param == "cursor" {
		if b, err := base64.RawURLEncoding.DecodeString(q.Get("cursor")); err == nil {
			start, _ = strconv.Atoi(string(b))
		}
	} else {
		start, _ = strconv.Atoi(q.Get("start"))
	}
	start = min(max(start, 0), len(list))
	end := min(start+limit, len(list))
	next := ""
	if end < len(list) {
		if param == "cursor" {
			next = base64.RawURLEncoding.EncodeToString([]byte(strconv.Itoa(end)))
		} else {
			next = strconv.Itoa(end)
		}
	}
	return list[start:end], next
}

// search answers a CQL search: Cloud with cursors, Data Center with start
// offsets.
func (f *fakeSite) search(w http.ResponseWriter, q url.Values) {
	query, err := parseCQL(q.Get("cql"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"statusCode": 400, "message": "Could not parse cql : " + err.Error()})
		return
	}
	var list []*fakeContent
	for _, c := range f.content {
		if c.Status == "current" && !f.searchLag[c.ID] && query.where.match(f, c) {
			list = append(list, c)
		}
	}
	switch query.order {
	case "lastmodified desc":
		sortNewest(list)
	default:
		sort.Slice(list, func(i, j int) bool {
			if !list[i].Created.Equal(list[j].Created) {
				return list[i].Created.Before(list[j].Created)
			}
			return list[i].ID < list[j].ID
		})
	}
	param := "start"
	if f.cloud {
		param = "cursor"
	}
	page, next := paginate(list, q, param)
	exp := expansions(q.Get("expand"))
	results := []map[string]any{}
	for _, c := range page {
		results = append(results, f.v1JSON(c, exp))
	}
	l := map[string]any{"base": f.baseURL(), "context": f.context}
	if next != "" {
		nq := cloneValues(q)
		nq.Set(param, next)
		l["next"] = "/rest/api/content/search?" + nq.Encode()
	}
	writeJSON(w, http.StatusOK, map[string]any{"results": results, "size": len(results), "_links": l})
}

func expansions(s string) map[string]bool {
	out := map[string]bool{}
	for _, e := range strings.Split(s, ",") {
		out[strings.TrimSpace(e)] = true
	}
	return out
}

func (f *fakeSite) restrictionsJSON(c *fakeContent) map[string]any {
	users := []map[string]any{}
	for _, u := range c.ReadUsers {
		if f.cloud {
			users = append(users, map[string]any{"type": "known", "accountId": u})
		} else {
			users = append(users, map[string]any{"type": "known", "username": u, "userKey": "key-" + u})
		}
	}
	groups := []map[string]any{}
	for _, g := range c.ReadGroups {
		groups = append(groups, map[string]any{"type": "group", "name": g})
	}
	return map[string]any{
		"user":  map[string]any{"results": users, "start": 0, "limit": 200, "size": len(users)},
		"group": map[string]any{"results": groups, "start": 0, "limit": 200, "size": len(groups)},
	}
}

// v1JSON is content as v1 writes it, with the expansions asked for.
func (f *fakeSite) v1JSON(c *fakeContent, exp map[string]bool) map[string]any {
	m := map[string]any{
		"id": c.ID, "type": c.Type, "status": c.Status, "title": c.Title,
		"_links":      map[string]any{"webui": f.webui(c), "self": f.baseURL() + "/rest/api/content/" + c.ID},
		"_expandable": map[string]any{"restrictions": "", "ancestors": "", "body": "", "space": ""},
	}
	if exp["space"] {
		m["space"] = map[string]any{"key": c.Space, "name": c.Space + " space"}
	}
	if exp["version"] {
		m["version"] = map[string]any{"when": c.Modified.Format("2006-01-02T15:04:05.000Z07:00"), "number": 1}
	}
	if exp["body.storage"] {
		m["body"] = map[string]any{"storage": map[string]any{"value": c.Body + f.padding, "representation": "storage"}}
	}
	if exp["ancestors"] {
		anc := []map[string]any{}
		for _, a := range f.ancestorsOf(c) {
			anc = append(anc, map[string]any{"id": a.ID, "type": a.Type, "status": a.Status, "title": a.Title})
		}
		m["ancestors"] = anc
	}
	if exp["restrictions.read.restrictions.user"] && exp["restrictions.read.restrictions.group"] && !f.noRestrict {
		m["restrictions"] = map[string]any{"read": map[string]any{"operation": "read", "restrictions": f.restrictionsJSON(c)}}
	}
	return m
}

// ── A CQL subset ────────────────────────────────────────────────────────────

type cqlQuery struct {
	where cqlExpr
	order string
}

type cqlExpr interface {
	match(f *fakeSite, c *fakeContent) bool
}

type cqlAnd struct{ l, r cqlExpr }
type cqlOr struct{ l, r cqlExpr }
type cqlNot struct{ e cqlExpr }
type cqlCmp struct {
	field, op string
	values    []string
}

func (e cqlAnd) match(f *fakeSite, c *fakeContent) bool { return e.l.match(f, c) && e.r.match(f, c) }
func (e cqlOr) match(f *fakeSite, c *fakeContent) bool  { return e.l.match(f, c) || e.r.match(f, c) }
func (e cqlNot) match(f *fakeSite, c *fakeContent) bool { return !e.e.match(f, c) }

func (e cqlCmp) match(f *fakeSite, c *fakeContent) bool {
	var have []string
	switch e.field {
	case "id":
		have = []string{c.ID}
	case "type":
		have = []string{c.Type}
	case "space":
		have = []string{c.Space}
	case "label":
		have = c.Labels
	case "title":
		have = []string{c.Title}
	case "ancestor":
		for _, a := range f.ancestorsOf(c) {
			have = append(have, a.ID)
		}
	default:
		return false
	}
	switch e.op {
	case "=", "in":
		return anyIn(have, e.values)
	case "!=", "not in":
		return !anyIn(have, e.values)
	case "~":
		for _, h := range have {
			if strings.Contains(strings.ToLower(h), strings.ToLower(e.values[0])) {
				return true
			}
		}
	}
	return false
}

func anyIn(have, values []string) bool {
	for _, h := range have {
		for _, v := range values {
			if h == v {
				return true
			}
		}
	}
	return false
}

type cqlParser struct {
	toks []string
	i    int
}

func parseCQL(s string) (cqlQuery, error) {
	toks, err := lexCQL(s)
	if err != nil {
		return cqlQuery{}, err
	}
	p := &cqlParser{toks: toks}
	e, err := p.or()
	if err != nil {
		return cqlQuery{}, err
	}
	q := cqlQuery{where: e}
	if p.peekWord("order") {
		p.i++
		if !p.peekWord("by") {
			return q, fmt.Errorf("expected BY")
		}
		p.i++
		var words []string
		for p.i < len(p.toks) {
			words = append(words, strings.ToLower(p.toks[p.i]))
			p.i++
		}
		q.order = strings.Join(words, " ")
	}
	if p.i != len(p.toks) {
		return q, fmt.Errorf("unexpected %q", p.toks[p.i])
	}
	return q, nil
}

func lexCQL(s string) ([]string, error) {
	var toks []string
	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n':
			i++
		case c == '(' || c == ')' || c == ',' || c == '~':
			toks = append(toks, string(c))
			i++
		case c == '=':
			toks = append(toks, "=")
			i++
		case c == '!' && i+1 < len(s) && s[i+1] == '=':
			toks = append(toks, "!=")
			i += 2
		case c == '"' || c == '\'':
			j := i + 1
			var b strings.Builder
			for j < len(s) && s[j] != c {
				if s[j] == '\\' && j+1 < len(s) {
					j++
				}
				b.WriteByte(s[j])
				j++
			}
			if j >= len(s) {
				return nil, fmt.Errorf("unterminated string")
			}
			toks = append(toks, "\x00"+b.String())
			i = j + 1
		default:
			j := i
			for j < len(s) && (unicode.IsLetter(rune(s[j])) || unicode.IsDigit(rune(s[j])) || strings.ContainsRune("_.-~:@", rune(s[j]))) {
				j++
			}
			if j == i {
				return nil, fmt.Errorf("unexpected character %q", c)
			}
			toks = append(toks, s[i:j])
			i = j
		}
	}
	return toks, nil
}

func (p *cqlParser) peekWord(w string) bool {
	return p.i < len(p.toks) && strings.EqualFold(p.toks[p.i], w)
}

func (p *cqlParser) or() (cqlExpr, error) {
	l, err := p.and()
	if err != nil {
		return nil, err
	}
	for p.peekWord("or") {
		p.i++
		r, err := p.and()
		if err != nil {
			return nil, err
		}
		l = cqlOr{l, r}
	}
	return l, nil
}

func (p *cqlParser) and() (cqlExpr, error) {
	l, err := p.factor()
	if err != nil {
		return nil, err
	}
	for p.peekWord("and") {
		p.i++
		r, err := p.factor()
		if err != nil {
			return nil, err
		}
		l = cqlAnd{l, r}
	}
	return l, nil
}

func (p *cqlParser) factor() (cqlExpr, error) {
	if p.i >= len(p.toks) {
		return nil, fmt.Errorf("unexpected end of query")
	}
	switch {
	case p.peekWord("not"):
		p.i++
		e, err := p.factor()
		return cqlNot{e}, err
	case p.toks[p.i] == "(":
		p.i++
		e, err := p.or()
		if err != nil {
			return nil, err
		}
		if p.i >= len(p.toks) || p.toks[p.i] != ")" {
			return nil, fmt.Errorf("expected )")
		}
		p.i++
		return e, nil
	}
	field := strings.ToLower(p.toks[p.i])
	p.i++
	if p.i >= len(p.toks) {
		return nil, fmt.Errorf("expected an operator after %s", field)
	}
	op := strings.ToLower(p.toks[p.i])
	p.i++
	if op == "not" && p.peekWord("in") {
		p.i++
		op = "not in"
	}
	value := func() (string, error) {
		if p.i >= len(p.toks) {
			return "", fmt.Errorf("expected a value")
		}
		v := strings.TrimPrefix(p.toks[p.i], "\x00")
		p.i++
		return v, nil
	}
	switch op {
	case "=", "!=", "~":
		v, err := value()
		return cqlCmp{field, op, []string{v}}, err
	case "in", "not in":
		if p.i >= len(p.toks) || p.toks[p.i] != "(" {
			return nil, fmt.Errorf("expected ( after IN")
		}
		p.i++
		var vs []string
		for {
			v, err := value()
			if err != nil {
				return nil, err
			}
			vs = append(vs, v)
			if p.i < len(p.toks) && p.toks[p.i] == "," {
				p.i++
				continue
			}
			break
		}
		if p.i >= len(p.toks) || p.toks[p.i] != ")" {
			return nil, fmt.Errorf("expected ) after the IN list")
		}
		p.i++
		return cqlCmp{field, op, vs}, nil
	}
	return nil, fmt.Errorf("unsupported operator %q", op)
}
