package jira

// fake_test.go is an in-memory Jira site: the parts of REST API v3 (Cloud) and
// v2 (Data Center) the connector reads — the enhanced search with its
// nextPageToken pages, the offset search with startAt and total, an issue's
// comment pages, serverInfo — with the site's own authentication, a JQL
// subset that includes "updated >= <epoch ms>", fields that appear only when
// asked for, a search that embeds only some of an issue's comments, and
// faults to inject: 429s and 503s, page tokens that lapse, refusals that
// echo the credential, redirects.

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode"
)

type fakeComment struct {
	ID, Author string
	// Body is ADF (Cloud) or wiki markup (Data Center).
	Body       any
	Created    time.Time
	Visibility string // "role:Developers", "group:jira-admins"; "" for everyone
}

type fakeLink struct {
	Type, Inward, Outward string
	To                    string // the linked issue's key
	Outbound              bool
}

type fakeIssue struct {
	ID, Key, Project                   string
	Summary                            string
	Description                        any // ADF (Cloud), wiki markup (Data Center), nil for none
	Status, Type, Priority, Resolution string
	Labels, Components, FixVersions    []string
	Links                              []fakeLink
	Parent                             string
	Security                           string // the level's name; "" for none
	Created, Updated                   time.Time
	Comments                           []fakeComment
}

// fakeJira is a Jira site.
type fakeJira struct {
	t        *testing.T
	cloud    bool
	context  string // "" on Cloud, "/jira" on Data Center
	email    string // basic auth's email; empty: bearer
	token    string
	srv      *httptest.Server
	mu       sync.Mutex
	projects map[string]string // key → name
	issues   map[string]*fakeIssue
	nextID   int
	clock    time.Time
	requests []string
	bodies   []map[string]any
	faults   []fakeFault
	// embed is how many comments a search embeds in an issue; 0 embeds all.
	embed int
	// generation is what the site's page tokens carry: lapse() makes every
	// token it issued before refused.
	generation int
	// maxResults caps a page, as a site's configuration does; 0 does not.
	maxResults int
	echoAuth   bool
	redirect   bool
	padding    string // added to every issue's summary, to make answers large
	// beforePage runs before each search page is answered, and
	// beforeComments before each comment page, outside the lock.
	beforePage     func(n int)
	beforeComments func()
	pages          int
}

type fakeFault struct {
	status     int
	retryAfter string
}

func newFakeJira(t *testing.T, cloud bool) *fakeJira {
	t.Helper()
	f := &fakeJira{
		t: t, cloud: cloud, token: "site-token-" + strings.Repeat("Q7", 12),
		projects: map[string]string{}, issues: map[string]*fakeIssue{}, nextID: 10000,
		clock: time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC),
	}
	if !cloud {
		f.context = "/jira"
	}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

// baseURL is what a source configures.
func (f *fakeJira) baseURL() string { return f.srv.URL + f.context }

func (f *fakeJira) addProject(key, name string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.projects[key] = name
}

// add adds an issue to project, an hour after the last change, and returns
// it.
func (f *fakeJira) add(project, summary string, description any, mutate ...func(*fakeIssue)) *fakeIssue {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.nextID++
	f.clock = f.clock.Add(time.Hour)
	n := 1
	for _, is := range f.issues {
		if is.Project == project {
			n++
		}
	}
	is := &fakeIssue{ID: strconv.Itoa(f.nextID), Key: project + "-" + strconv.Itoa(n), Project: project,
		Summary: summary, Description: description, Status: "To Do", Type: "Task", Priority: "Medium",
		Created: f.clock, Updated: f.clock}
	for _, m := range mutate {
		m(is)
	}
	f.issues[is.ID] = is
	return is
}

// edit changes an issue: its updated time moves an hour past the last change.
func (f *fakeJira) edit(is *fakeIssue, mutate func(*fakeIssue)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.clock = f.clock.Add(time.Hour)
	if mutate != nil {
		mutate(is)
	}
	is.Updated = f.clock
}

// set changes the site without moving any issue's updated time.
func (f *fakeJira) set(mutate func()) {
	f.mu.Lock()
	defer f.mu.Unlock()
	mutate()
}

// comment adds a comment to is, a minute after its last change, which it
// moves.
func (f *fakeJira) comment(is *fakeIssue, author string, body any, visibility string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.clock = f.clock.Add(time.Minute)
	is.Comments = append(is.Comments, fakeComment{ID: strconv.Itoa(20000 + len(is.Comments)), Author: author,
		Body: body, Created: f.clock, Visibility: visibility})
	is.Updated = f.clock
}

func (f *fakeJira) remove(is *fakeIssue) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.issues, is.ID)
}

// lapse makes every page token the site issued so far refused, as tokens
// that expired between syncs are.
func (f *fakeJira) lapse() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.generation++
}

func (f *fakeJira) fail(faults ...fakeFault) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.faults = append(f.faults, faults...)
}

func (f *fakeJira) requestLog() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.requests...)
}

// searches returns the JQL of every search the site was asked.
func (f *fakeJira) searches() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, b := range f.bodies {
		if q, ok := b["jql"].(string); ok {
			out = append(out, q)
		}
	}
	return out
}

func (f *fakeJira) authorized(r *http.Request) bool {
	got := r.Header.Get("Authorization")
	if f.email != "" {
		return got == "Basic "+base64.StdEncoding.EncodeToString([]byte(f.email+":"+f.token))
	}
	return got == "Bearer "+f.token
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func jqlError(w http.ResponseWriter, msg string) {
	writeJSON(w, http.StatusBadRequest, map[string]any{"errorMessages": []string{msg}, "errors": map[string]any{}})
}

func (f *fakeJira) api() string {
	if f.cloud {
		return "/rest/api/3"
	}
	return "/rest/api/2"
}

func (f *fakeJira) serve(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	f.requests = append(f.requests, r.Method+" "+r.URL.Path+"?"+r.URL.RawQuery)
	if len(f.faults) > 0 {
		fault := f.faults[0]
		f.faults = f.faults[1:]
		f.mu.Unlock()
		if fault.retryAfter != "" {
			w.Header().Set("Retry-After", fault.retryAfter)
		}
		writeJSON(w, fault.status, map[string]any{"errorMessages": []string{"Rate limit exceeded."}})
		return
	}
	if f.redirect {
		f.mu.Unlock()
		http.Redirect(w, r, "https://elsewhere.example"+r.URL.Path, http.StatusFound)
		return
	}
	if !f.authorized(r) {
		msg := "Client must be authenticated to access this resource."
		if f.echoAuth {
			msg += " Received: " + r.Header.Get("Authorization")
		}
		f.mu.Unlock()
		writeJSON(w, http.StatusUnauthorized, map[string]any{"errorMessages": []string{msg}})
		return
	}
	path, ok := strings.CutPrefix(r.URL.Path, f.context)
	if !ok {
		f.mu.Unlock()
		http.NotFound(w, r)
		return
	}
	switch {
	case r.Method == http.MethodPost && f.cloud && path == "/rest/api/3/search/jql",
		r.Method == http.MethodPost && !f.cloud && path == "/rest/api/2/search":
		var req map[string]any
		if err := json.Unmarshal(body, &req); err != nil || r.Header.Get("Content-Type") != "application/json" {
			f.mu.Unlock()
			writeJSON(w, http.StatusUnsupportedMediaType, map[string]any{"errorMessages": []string{"bad body"}})
			return
		}
		f.bodies = append(f.bodies, req)
		f.pages++
		n, hook := f.pages, f.beforePage
		f.mu.Unlock()
		if hook != nil {
			hook(n)
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		f.search(w, req)
	case r.Method == http.MethodGet && path == f.api()+"/serverInfo" && f.cloud:
		defer f.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{"baseUrl": "https://corp.atlassian.net", "deploymentType": "Cloud"})
	case r.Method == http.MethodGet && strings.HasPrefix(path, f.api()+"/issue/"):
		rest := strings.TrimPrefix(path, f.api()+"/issue/")
		id, sub, _ := strings.Cut(rest, "/")
		if hook := f.beforeComments; hook != nil && sub == "comment" {
			f.mu.Unlock()
			hook()
			f.mu.Lock()
		}
		defer f.mu.Unlock()
		is := f.issues[id]
		if is == nil {
			writeJSON(w, http.StatusNotFound, map[string]any{"errorMessages": []string{"Issue does not exist or you do not have permission to see it."}})
			return
		}
		switch sub {
		case "":
			writeJSON(w, http.StatusOK, map[string]any{"id": is.ID, "key": is.Key})
		case "comment":
			q := r.URL.Query()
			start, _ := strconv.Atoi(q.Get("startAt"))
			limit, _ := strconv.Atoi(q.Get("maxResults"))
			if limit <= 0 || limit > 100 {
				limit = 100
			}
			start = min(max(start, 0), len(is.Comments))
			end := min(start+limit, len(is.Comments))
			var out []any
			for _, c := range is.Comments[start:end] {
				out = append(out, f.commentJSON(c))
			}
			writeJSON(w, http.StatusOK, map[string]any{"comments": out, "startAt": start, "maxResults": limit,
				"total": len(is.Comments)})
		default:
			http.NotFound(w, r)
		}
	default:
		f.mu.Unlock()
		http.NotFound(w, r)
	}
}

// search answers a search: Cloud by tokens, Data Center by offsets.
func (f *fakeJira) search(w http.ResponseWriter, req map[string]any) {
	jql, _ := req["jql"].(string)
	q, err := parseJQL(jql)
	if err != nil {
		jqlError(w, "Error in the JQL Query: "+err.Error())
		return
	}
	if q.where == nil {
		if f.cloud {
			jqlError(w, "Unbounded JQL queries are not allowed here. Please add a search restriction to your query.")
			return
		}
	}
	if missing := q.missingIssue(f); missing != "" {
		jqlError(w, "An issue with key '"+missing+"' does not exist for field 'id'.")
		return
	}
	var matched []*fakeIssue
	for _, is := range f.issues {
		if q.where == nil || q.where.match(f, is) {
			matched = append(matched, is)
		}
	}
	q.sort(matched)
	limit := 50
	if v, ok := req["maxResults"].(float64); ok {
		limit = int(v)
	}
	if f.maxResults > 0 {
		limit = min(limit, f.maxResults)
	}
	fields := map[string]bool{}
	if list, ok := req["fields"].([]any); ok {
		for _, v := range list {
			if s, ok := v.(string); ok {
				fields[s] = true
			}
		}
	}
	start := 0
	if f.cloud {
		if tok, _ := req["nextPageToken"].(string); tok != "" {
			b, err := base64.RawURLEncoding.DecodeString(tok)
			parts := strings.SplitN(string(b), "|", 3)
			if err != nil || len(parts) != 3 || parts[1] != strconv.Itoa(f.generation) || parts[2] != jql {
				jqlError(w, "The provided next page token is invalid or expired.")
				return
			}
			start, _ = strconv.Atoi(parts[0])
		}
	} else if v, ok := req["startAt"].(float64); ok {
		start = int(v)
	}
	start = min(max(start, 0), len(matched))
	end := min(start+max(limit, 0), len(matched))
	var out []any
	for _, is := range matched[start:end] {
		out = append(out, f.issueJSON(is, fields))
	}
	if out == nil {
		out = []any{}
	}
	if f.cloud {
		answer := map[string]any{"issues": out, "isLast": end >= len(matched)}
		if end < len(matched) {
			answer["nextPageToken"] = base64.RawURLEncoding.EncodeToString([]byte(strconv.Itoa(end) + "|" +
				strconv.Itoa(f.generation) + "|" + jql))
		}
		writeJSON(w, http.StatusOK, answer)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"startAt": start, "maxResults": limit, "total": len(matched), "issues": out})
}

func jiraTime(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05.000-0700") }

// issueJSON is an issue as the API writes it, with the fields asked for.
func (f *fakeJira) issueJSON(is *fakeIssue, want map[string]bool) map[string]any {
	fields := map[string]any{}
	put := func(name string, v any) {
		if want[name] {
			fields[name] = v
		}
	}
	named := func(s string) any {
		if s == "" {
			return nil
		}
		return map[string]any{"name": s, "id": "1"}
	}
	names := func(vs []string) []any {
		out := []any{}
		for _, v := range vs {
			out = append(out, map[string]any{"name": v})
		}
		return out
	}
	put("summary", is.Summary+f.padding)
	put("description", is.Description)
	put("status", named(is.Status))
	put("issuetype", named(is.Type))
	put("priority", named(is.Priority))
	put("resolution", named(is.Resolution))
	put("labels", append([]string{}, is.Labels...))
	put("components", names(is.Components))
	put("fixVersions", names(is.FixVersions))
	put("updated", jiraTime(is.Updated))
	put("created", jiraTime(is.Created))
	put("project", map[string]any{"key": is.Project, "name": f.projects[is.Project], "id": "100"})
	if is.Parent != "" {
		// Jira writes the parent's summary in too: the connector must not
		// copy it.
		put("parent", map[string]any{"key": is.Parent, "fields": map[string]any{"summary": "PARENT-SUMMARY-SECRET"}})
	}
	if is.Security != "" {
		put("security", map[string]any{"id": "10100", "name": is.Security, "description": "only some"})
	} else {
		put("security", nil)
	}
	var links []any
	for _, l := range is.Links {
		link := map[string]any{"type": map[string]any{"name": l.Type, "inward": l.Inward, "outward": l.Outward}}
		linked := map[string]any{"key": l.To, "fields": map[string]any{"summary": "LINKED-SUMMARY-SECRET"}}
		if l.Outbound {
			link["outwardIssue"] = linked
		} else {
			link["inwardIssue"] = linked
		}
		links = append(links, link)
	}
	if links == nil {
		links = []any{}
	}
	put("issuelinks", links)
	if want["comment"] {
		embedded := is.Comments
		if f.embed > 0 && len(embedded) > f.embed {
			embedded = embedded[:f.embed]
		}
		var cs []any
		for _, c := range embedded {
			cs = append(cs, f.commentJSON(c))
		}
		if cs == nil {
			cs = []any{}
		}
		fields["comment"] = map[string]any{"comments": cs, "maxResults": len(cs), "total": len(is.Comments), "startAt": 0}
	}
	return map[string]any{"id": is.ID, "key": is.Key, "self": f.srv.URL + f.api() + "/issue/" + is.ID, "fields": fields}
}

func (f *fakeJira) commentJSON(c fakeComment) map[string]any {
	out := map[string]any{"id": c.ID, "author": map[string]any{"displayName": c.Author, "accountId": "acc-" + c.Author},
		"body": c.Body, "created": jiraTime(c.Created), "updated": jiraTime(c.Created)}
	if typ, value, ok := strings.Cut(c.Visibility, ":"); ok {
		out["visibility"] = map[string]any{"type": typ, "value": value}
	}
	return out
}

// ── A JQL subset ─────────────────────────────────────────────────────────────

type jqlQuery struct {
	where jqlExpr
	order []jqlOrder
}

type jqlOrder struct {
	field string
	desc  bool
}

type jqlExpr interface {
	match(f *fakeJira, is *fakeIssue) bool
}

type jqlAnd struct{ l, r jqlExpr }
type jqlOr struct{ l, r jqlExpr }
type jqlNot struct{ e jqlExpr }
type jqlCmp struct {
	field, op string
	values    []string
}

func (e jqlAnd) match(f *fakeJira, is *fakeIssue) bool { return e.l.match(f, is) && e.r.match(f, is) }
func (e jqlOr) match(f *fakeJira, is *fakeIssue) bool  { return e.l.match(f, is) || e.r.match(f, is) }
func (e jqlNot) match(f *fakeJira, is *fakeIssue) bool { return !e.e.match(f, is) }

func (e jqlCmp) match(_ *fakeJira, is *fakeIssue) bool {
	var have []string
	switch e.field {
	case "id", "key", "issuekey", "issue":
		have = []string{is.ID, is.Key}
	case "project":
		have = []string{is.Project}
	case "labels":
		have = is.Labels
	case "status":
		have = []string{is.Status}
	case "type", "issuetype":
		have = []string{is.Type}
	case "level":
		if is.Security != "" {
			have = []string{is.Security}
		}
	case "updated", "created":
		t := is.Updated
		if e.field == "created" {
			t = is.Created
		}
		ms, err := strconv.ParseInt(e.values[0], 10, 64)
		if err != nil {
			return false
		}
		v := t.UnixMilli()
		switch e.op {
		case ">=":
			return v >= ms
		case ">":
			return v > ms
		case "<=":
			return v <= ms
		case "<":
			return v < ms
		}
		return false
	default:
		return false
	}
	switch e.op {
	case "=", "in":
		return anyIn(have, e.values)
	case "!=", "not in":
		return !anyIn(have, e.values)
	case "is":
		return len(have) == 0
	case "is not":
		return len(have) > 0
	}
	return false
}

func anyIn(have, values []string) bool {
	for _, h := range have {
		for _, v := range values {
			if strings.EqualFold(h, v) {
				return true
			}
		}
	}
	return false
}

// missingIssue returns an id or key the query names with "id =" that the
// site does not have: JQL refuses one.
func (q jqlQuery) missingIssue(f *fakeJira) string {
	var walk func(e jqlExpr) string
	walk = func(e jqlExpr) string {
		switch e := e.(type) {
		case jqlAnd:
			return firstOf(walk(e.l), walk(e.r))
		case jqlOr:
			return firstOf(walk(e.l), walk(e.r))
		case jqlNot:
			return walk(e.e)
		case jqlCmp:
			if e.field == "id" && e.op == "=" {
				for _, is := range f.issues {
					if is.ID == e.values[0] || is.Key == e.values[0] {
						return ""
					}
				}
				return e.values[0]
			}
		}
		return ""
	}
	if q.where == nil {
		return ""
	}
	return walk(q.where)
}

func (q jqlQuery) sort(list []*fakeIssue) {
	sort.SliceStable(list, func(i, j int) bool {
		for _, o := range q.order {
			var c int
			switch o.field {
			case "updated":
				c = list[i].Updated.Compare(list[j].Updated)
			case "created":
				c = list[i].Created.Compare(list[j].Created)
			case "key":
				a, b := list[i].ID, list[j].ID
				c = len(a) - len(b)
				if c == 0 {
					c = strings.Compare(a, b)
				}
			}
			if o.desc {
				c = -c
			}
			if c != 0 {
				return c < 0
			}
		}
		return list[i].ID < list[j].ID
	})
}

type jqlParser struct {
	toks []string
	i    int
}

func parseJQL(s string) (jqlQuery, error) {
	toks, err := lexJQL(s)
	if err != nil {
		return jqlQuery{}, err
	}
	p := &jqlParser{toks: toks}
	var q jqlQuery
	if !p.peekWord("order") && p.i < len(p.toks) {
		if q.where, err = p.or(); err != nil {
			return q, err
		}
	}
	if p.peekWord("order") {
		p.i++
		if !p.peekWord("by") {
			return q, fmt.Errorf("expected BY")
		}
		p.i++
		for p.i < len(p.toks) {
			o := jqlOrder{field: strings.ToLower(p.toks[p.i])}
			p.i++
			if p.peekWord("desc") || p.peekWord("asc") {
				o.desc = strings.EqualFold(p.toks[p.i], "desc")
				p.i++
			}
			q.order = append(q.order, o)
			if p.i < len(p.toks) && p.toks[p.i] == "," {
				p.i++
			}
		}
	}
	if p.i != len(p.toks) {
		return q, fmt.Errorf("unexpected %q", p.toks[p.i])
	}
	return q, nil
}

func lexJQL(s string) ([]string, error) {
	var toks []string
	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n':
			i++
		case c == '(' || c == ')' || c == ',':
			toks = append(toks, string(c))
			i++
		case c == '>' || c == '<' || c == '!' || c == '=':
			if i+1 < len(s) && s[i+1] == '=' {
				toks = append(toks, s[i:i+2])
				i += 2
				continue
			}
			toks = append(toks, string(c))
			i++
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
			for j < len(s) && (unicode.IsLetter(rune(s[j])) || unicode.IsDigit(rune(s[j])) || strings.ContainsRune("_.-", rune(s[j]))) {
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

func (p *jqlParser) peekWord(w string) bool {
	return p.i < len(p.toks) && strings.EqualFold(p.toks[p.i], w)
}

func (p *jqlParser) or() (jqlExpr, error) {
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
		l = jqlOr{l, r}
	}
	return l, nil
}

func (p *jqlParser) and() (jqlExpr, error) {
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
		l = jqlAnd{l, r}
	}
	return l, nil
}

func (p *jqlParser) factor() (jqlExpr, error) {
	if p.i >= len(p.toks) {
		return nil, fmt.Errorf("unexpected end of query")
	}
	switch {
	case p.peekWord("not"):
		p.i++
		e, err := p.factor()
		return jqlNot{e}, err
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
	switch {
	case op == "not" && p.peekWord("in"):
		p.i++
		op = "not in"
	case op == "is" && p.peekWord("not"):
		p.i++
		op = "is not"
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
	case "=", "!=", ">=", ">", "<=", "<":
		v, err := value()
		return jqlCmp{field, op, []string{v}}, err
	case "is", "is not":
		v, err := value()
		if err == nil && !strings.EqualFold(v, "empty") && !strings.EqualFold(v, "null") {
			err = fmt.Errorf("IS takes EMPTY")
		}
		return jqlCmp{field, op, nil}, err
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
		return jqlCmp{field, op, vs}, nil
	}
	return nil, fmt.Errorf("unsupported operator %q", op)
}
