package jira

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/blechschmidt/cloop/pkg/knowledge"
	"github.com/blechschmidt/cloop/pkg/knowledge/internal/atlassian"
)

// Listing bounds.
const (
	// bodyPageLimit is how many issues a listing asks for at once with their
	// descriptions and comments; an answer over maxResponseBytes is asked
	// again for half.
	bodyPageLimit = 25
	// idPageLimit is how many a listing of ids asks for at once.
	idPageLimit = 1000
	// maxIDs bounds a reconciliation's or a narrowing's answer.
	maxIDs = 250_000
	// pageOverlap and idPageOverlap are how many issues before where the
	// last page ended a Data Center page is asked for from (see cursor.go).
	pageOverlap   = 5
	idPageOverlap = 50
	// commentPageLimit is how many comments one request reads, and
	// maxComments how many of an issue's are read at most.
	commentPageLimit = 100
	maxComments      = 1000
)

// maxCommentBytes bounds the comment bodies read for one issue: past it, no
// further comment page is read. The index keeps knowledge.MaxBodyBytes of an
// issue's text whatever is read, so this only stops a site that answers with
// pages of enormous comments from making the hub hold them all. A variable
// only so that a test can reach it without megabytes of comments.
var maxCommentBytes = 4 * knowledge.MaxBodyBytes

// Paths below the REST API's root (settings.api).
const (
	pathCloudSearch = "/search/jql"
	pathDCSearch    = "/search"
	pathServerInfo  = "/serverInfo"
)

var (
	// issueIDPattern is an issue id: Jira's are decimal numbers.
	issueIDPattern = regexp.MustCompile(`^[0-9]{1,20}$`)
	// issueKeyPattern is an issue key: its project's key, a dash, a number.
	issueKeyPattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]*-[0-9]{1,18}$`)
)

// The fields a listing asks for: what a document is made of.
var (
	metaFields = []string{"summary", "status", "issuetype", "priority", "resolution", "labels", "components",
		"fixVersions", "issuelinks", "security", "updated", "project", "parent"}
	listFields = append([]string{"description", "comment"}, metaFields...)
	// idFields are what an id listing needs to decide an issue: its
	// security level.
	idFields = []string{"security"}
)

// flexID reads an id the API writes as a string or a number.
type flexID string

func (f *flexID) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		*f = flexID(s)
		return nil
	}
	var n json.Number
	if err := json.Unmarshal(b, &n); err != nil {
		return fmt.Errorf("an id is a string or a number, not %s", b)
	}
	*f = flexID(n.String())
	return nil
}

// issue is an issue as a search returns it.
type issue struct {
	ID     flexID      `json:"id"`
	Key    string      `json:"key"`
	Fields issueFields `json:"fields"`
}

type named struct {
	Name string `json:"name"`
}

type issueFields struct {
	Summary     string          `json:"summary"`
	Description json.RawMessage `json:"description"`
	Comment     *commentPage    `json:"comment"`
	Status      *named          `json:"status"`
	IssueType   *named          `json:"issuetype"`
	Priority    *named          `json:"priority"`
	Resolution  *named          `json:"resolution"`
	Labels      []string        `json:"labels"`
	Components  []named         `json:"components"`
	FixVersions []named         `json:"fixVersions"`
	IssueLinks  []issueLink     `json:"issuelinks"`
	// Security is the issue's security level; nil when it has none. An
	// object the connector cannot read a name from is a level all the same.
	Security *struct {
		ID   flexID `json:"id"`
		Name string `json:"name"`
	} `json:"security"`
	Updated string `json:"updated"`
	Project *struct {
		Key  string `json:"key"`
		Name string `json:"name"`
	} `json:"project"`
	Parent *struct {
		Key string `json:"key"`
	} `json:"parent"`
}

type linkedIssue struct {
	Key string `json:"key"`
}

type issueLink struct {
	Type struct {
		Name    string `json:"name"`
		Inward  string `json:"inward"`
		Outward string `json:"outward"`
	} `json:"type"`
	InwardIssue  *linkedIssue `json:"inwardIssue"`
	OutwardIssue *linkedIssue `json:"outwardIssue"`
}

// commentPage is the comments a search embeds in an issue, or one page of
// the comment endpoint.
type commentPage struct {
	Comments []comment `json:"comments"`
	Total    int       `json:"total"`
	StartAt  int       `json:"startAt"`
}

type comment struct {
	ID     flexID `json:"id"`
	Author *struct {
		DisplayName string `json:"displayName"`
		Name        string `json:"name"`
	} `json:"author"`
	Body    json.RawMessage `json:"body"`
	Created string          `json:"created"`
	// Visibility restricts a comment to a group or a project role; nil
	// when everyone who can see the issue can see it.
	Visibility *struct {
		Type  string `json:"type"`
		Value string `json:"value"`
	} `json:"visibility"`
}

// secured reports an issue with a security level.
func (is *issue) secured() bool { return is.Fields.Security != nil }

// restricted reports a comment restricted to a group or a role.
func (c *comment) restricted() bool { return c.Visibility != nil }

// parseTime reads an API timestamp: Jira writes "2026-10-01T09:00:00.000+0000",
// whose offset has no colon. Zero when it does not parse.
func parseTime(s string) time.Time {
	s = strings.TrimSpace(s)
	for _, layout := range []string{"2006-01-02T15:04:05.000-0700", "2006-01-02T15:04:05-0700", time.RFC3339Nano} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}

// searchPage is one page of a search.
type searchPage struct {
	issues []issue
	// last reports the search's last page.
	last bool
	// token is a Cloud page's nextPageToken; startAt and total are a Data
	// Center page's place and the number of issues matched.
	token   string
	startAt int
	total   int
}

// search reads one page of jql with fields, at most limit issues, from the
// page at (a Cloud nextPageToken, empty for the first) or startAt (Data
// Center). Both APIs are asked as a POST, so that a query of any length the
// configuration allows fits.
func (ss *session) search(ctx context.Context, jql string, fields []string, limit int, at string, startAt int) (searchPage, error) {
	if ss.s.cloud() {
		req := map[string]any{"jql": jql, "maxResults": limit, "fields": fields}
		if at != "" {
			req["nextPageToken"] = at
		}
		var answer struct {
			Issues        []issue `json:"issues"`
			NextPageToken string  `json:"nextPageToken"`
			IsLast        *bool   `json:"isLast"`
		}
		if err := ss.cl.Post(ctx, ss.s.api()+pathCloudSearch, req, &answer); err != nil {
			return searchPage{}, err
		}
		next := strings.TrimSpace(answer.NextPageToken)
		if len(next) > maxTokenBytes || strings.IndexFunc(next, unicode.IsControl) >= 0 {
			return searchPage{}, errors.New("the site's next-page token is not one the connector can keep")
		}
		page := searchPage{issues: answer.Issues, token: next}
		page.last = next == "" || len(answer.Issues) == 0 || (answer.IsLast != nil && *answer.IsLast)
		if !page.last && next == at {
			return searchPage{}, errors.New("the site answered a page with the token it was asked for: the search does not move")
		}
		return page, nil
	}
	req := map[string]any{"jql": jql, "startAt": startAt, "maxResults": limit, "fields": fields}
	var answer struct {
		StartAt int     `json:"startAt"`
		Total   int     `json:"total"`
		Issues  []issue `json:"issues"`
	}
	if err := ss.cl.Post(ctx, ss.s.api()+pathDCSearch, req, &answer); err != nil {
		return searchPage{}, err
	}
	if answer.StartAt != startAt {
		return searchPage{}, fmt.Errorf("the site answered a search from %d with issues from %d", startAt, answer.StartAt)
	}
	page := searchPage{issues: answer.Issues, startAt: answer.StartAt, total: answer.Total}
	page.last = len(answer.Issues) == 0 || answer.StartAt+len(answer.Issues) >= answer.Total
	return page, nil
}

// listJQL is the query of a pass listing back to since.
func (ss *session) listJQL(since int64) string {
	q := ss.s.scopeJQL()
	if since > 0 {
		q += " AND updated >= " + strconv.FormatInt(since, 10)
	}
	return q + " ORDER BY updated DESC, key DESC"
}

// webBase is where the site's issues are read: the base URL, or for a site
// reached through the gateway, the site's own address as it reports it.
func (ss *session) webBase(ctx context.Context) (string, error) {
	if !ss.s.gateway() {
		return strings.TrimRight(ss.s.base.String(), "/"), nil
	}
	var info struct {
		BaseURL string `json:"baseUrl"`
	}
	if err := ss.cl.Get(ctx, ss.s.api()+pathServerInfo, &info); err != nil {
		return "", fmt.Errorf("look up the site's address: %w", err)
	}
	u, err := url.Parse(strings.TrimSpace(info.BaseURL))
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" ||
		(u.Scheme != "https" && !(u.Scheme == "http" && ss.cl.Insecure())) {
		// Issues are still indexed, without a link to read them at.
		return "", nil
	}
	return strings.TrimRight(u.Scheme+"://"+u.Host+u.EscapedPath(), "/"), nil
}

// browseURL is the address a person reads issue key at.
func browseURL(web, key string) string {
	if web == "" || !issueKeyPattern.MatchString(key) {
		return ""
	}
	return web + "/browse/" + key
}

// fetchListing reads one page of a pass at cur. An answer too large to read
// is asked for again for half as many issues, and at one, once more without
// its description and comments: an issue too large to read is indexed by its
// title and header rather than holding up every sync after it.
func (ss *session) fetchListing(ctx context.Context, jql string, limit int, cur cursor) (searchPage, bool, error) {
	bodies := true
	for {
		fields := listFields
		if !bodies {
			fields = metaFields
		}
		page, err := ss.search(ctx, jql, fields, limit, cur.Token, cur.Start)
		if errors.Is(err, atlassian.ErrTooLarge) {
			switch {
			case limit > 1:
				limit /= 2
				continue
			case bodies:
				bodies = false
				continue
			}
		}
		return page, bodies, err
	}
}

// list returns the issues of the page after cursor raw.
func (ss *session) list(ctx context.Context, raw string, pageSize int) (knowledge.Page, error) {
	cur := decodeCursor(raw)
	limit := bodyPageLimit
	if pageSize > 0 {
		limit = min(limit, pageSize)
	}
	if !cur.Mid {
		// A pass begins: from how far back the last one left it.
		cur = cursor{Since: cur.Since}
		web, err := ss.webBase(ctx)
		if err != nil {
			return knowledge.Page{}, err
		}
		cur.Web = web
	}
	jql := ss.listJQL(cur.Since)
	page, bodies, err := ss.fetchListing(ctx, jql, limit, cur)
	if err != nil && cur.Token != "" && atlassian.IsStatus(err, http.StatusBadRequest) {
		// A token the site no longer takes — it lapsed between syncs: the
		// pass begins again, from where it began.
		cur = cursor{Mid: true, Since: cur.Since, Web: cur.Web}
		page, bodies, err = ss.fetchListing(ctx, jql, limit, cur)
	}
	if err != nil {
		return knowledge.Page{}, err
	}
	repeated := map[string]bool{}
	for _, id := range cur.Tail {
		repeated[id] = true
	}
	var issues []*issue
	for i := range page.issues {
		is := &page.issues[i]
		if repeated[string(is.ID)] {
			continue
		}
		cur.saw(parseTime(is.Fields.Updated), ss.now())
		if issueIDPattern.MatchString(string(is.ID)) {
			issues = append(issues, is)
		}
	}
	docs, err := ss.documents(ctx, issues, cur.Web, bodies)
	if err != nil {
		return knowledge.Page{}, err
	}
	out := knowledge.Page{Documents: docs, More: !page.last}
	if page.last {
		out.Cursor = cur.end().encode()
		return out, nil
	}
	cur.Mid = true
	if ss.s.cloud() {
		cur.Token = page.token
	} else {
		next := page.startAt + len(page.issues)
		k := min(pageOverlap, len(page.issues)/2)
		cur.Start, cur.Tail = next-k, nil
		for _, is := range page.issues[len(page.issues)-k:] {
			cur.Tail = append(cur.Tail, string(is.ID))
		}
	}
	out.Cursor = cur.encode()
	return out, nil
}

// documents turns issues into the documents the index keeps, reading the
// comments a search did not embed in full; an issue that turns out to be gone
// is a deletion.
func (ss *session) documents(ctx context.Context, issues []*issue, web string, bodies bool) ([]knowledge.Document, error) {
	docs := make([]knowledge.Document, 0, len(issues))
	for _, is := range issues {
		if bodies && (!is.secured() || ss.s.includeSecured) {
			if err := ss.completeComments(ctx, is); errors.Is(err, errGone) {
				docs = append(docs, knowledge.Document{ExternalID: string(is.ID), Deleted: true})
				continue
			} else if err != nil {
				return nil, err
			}
		}
		docs = append(docs, ss.document(is, web, bodies))
	}
	return docs, nil
}

// errGone is an issue that went while it was being read.
var errGone = errors.New("the issue is gone")

// completeComments reads the comments of an issue whose search answer
// embedded only some of them, from the comment endpoint, up to maxComments
// and maxCommentBytes of their bodies. An answer too large is asked for in
// smaller pages, and a single comment too large to read ends the reading: the
// issue keeps the comments it has.
func (ss *session) completeComments(ctx context.Context, is *issue) error {
	page := is.Fields.Comment
	if page == nil || page.Total <= len(page.Comments) {
		return nil
	}
	var all []comment
	limit, size := commentPageLimit, 0
	for start := 0; len(all) < maxComments && size < maxCommentBytes; {
		var answer commentPage
		ref := fmt.Sprintf("%s/issue/%s/comment?startAt=%d&maxResults=%d&orderBy=created", ss.s.api(), is.ID, start,
			min(limit, maxComments-len(all)))
		err := ss.cl.Get(ctx, ref, &answer)
		switch {
		case errors.Is(err, atlassian.ErrTooLarge) && limit > 1:
			limit /= 2
			continue
		case errors.Is(err, atlassian.ErrTooLarge):
			page.Comments, page.Total = all, len(all)
			return nil
		case atlassian.IsStatus(err, http.StatusNotFound):
			return errGone
		case err != nil:
			return fmt.Errorf("read the comments of %s: %w", is.Key, err)
		}
		all = append(all, answer.Comments...)
		for _, c := range answer.Comments {
			size += len(c.Body)
		}
		start += len(answer.Comments)
		if len(answer.Comments) == 0 || start >= answer.Total {
			break
		}
	}
	page.Comments, page.Total = all, len(all)
	return nil
}

// document is the index's document for an issue: a deletion for one with a
// security level, unless the source includes them.
func (ss *session) document(is *issue, web string, bodies bool) knowledge.Document {
	id := string(is.ID)
	if is.secured() && !ss.s.includeSecured {
		return knowledge.Document{ExternalID: id, Deleted: true}
	}
	f := &is.Fields
	key := strings.TrimSpace(is.Key)
	if !issueKeyPattern.MatchString(key) {
		key = ""
	}
	project, projectName := "", ""
	if f.Project != nil {
		project, projectName = strings.TrimSpace(f.Project.Key), strings.TrimSpace(f.Project.Name)
	}
	if !projectKeyPattern.MatchString(project) {
		project = ""
		if k, _, ok := strings.Cut(key, "-"); ok {
			project = k
		}
	}
	title := strings.TrimSpace(key + " " + oneLine(f.Summary))
	var acl []string
	if project != "" {
		acl = append(acl, "project:"+project)
	}
	if is.secured() {
		acl = append(acl, "secured")
		if name := oneLine(f.Security.Name); name != "" {
			acl = append(acl, "security:"+name)
		}
	}
	var ancestors []string
	if name := firstOf(projectName, project); name != "" {
		ancestors = append(ancestors, name)
	}
	if f.Parent != nil && issueKeyPattern.MatchString(strings.TrimSpace(f.Parent.Key)) {
		// The parent by its key alone: its summary may be one this issue's
		// readers may not see.
		ancestors = append(ancestors, strings.TrimSpace(f.Parent.Key))
	}
	var comments []comment
	if bodies && f.Comment != nil {
		comments = f.Comment.Comments
	}
	return knowledge.Document{
		ExternalID: id, Title: title, URL: browseURL(web, key), Space: project, UpdatedAt: parseTime(f.Updated),
		Body: ss.renderIssue(is, project, projectName, comments, bodies), ACL: acl, Ancestors: ancestors,
	}
}

// renderIssue is an issue's body: its header, its description and its
// comments, each under a heading the chunker cuts at.
func (ss *session) renderIssue(is *issue, project, projectName string, comments []comment, bodies bool) string {
	f := &is.Fields
	var header []string
	field := func(name, value string) {
		if value = clipValue(oneLine(value)); value != "" {
			header = append(header, name+": "+value)
		}
	}
	switch {
	case projectName != "" && project != "":
		field("Project", projectName+" ("+project+")")
	default:
		field("Project", firstOf(projectName, project))
	}
	if f.IssueType != nil {
		field("Type", f.IssueType.Name)
	}
	if f.Status != nil {
		field("Status", f.Status.Name)
	}
	if f.Priority != nil {
		field("Priority", f.Priority.Name)
	}
	if f.Resolution != nil {
		field("Resolution", f.Resolution.Name)
	}
	field("Labels", joinValues(f.Labels))
	field("Components", joinNames(f.Components))
	field("Fix versions", joinNames(f.FixVersions))
	if f.Parent != nil && issueKeyPattern.MatchString(strings.TrimSpace(f.Parent.Key)) {
		field("Parent", strings.TrimSpace(f.Parent.Key))
	}
	field("Links", links(f.IssueLinks))
	if is.secured() {
		field("Security level", firstOf(oneLine(f.Security.Name), "set"))
	}
	var parts []string
	if len(header) > 0 {
		parts = append(parts, strings.Join(header, "\n"))
	}
	if bodies {
		if desc := renderRich(f.Description, 1); desc != "" {
			parts = append(parts, "# Description", desc)
		}
		var shown []string
		for _, c := range sortedComments(comments) {
			if c.restricted() && !ss.s.includeSecured {
				continue
			}
			heading := firstOf(c.authorName(), "Someone")
			if t := parseTime(c.Created); !t.IsZero() {
				heading += ", " + t.Format("2006-01-02 15:04 UTC")
			}
			if c.restricted() {
				heading += " (restricted to " + firstOf(oneLine(c.Visibility.Type+" "+c.Visibility.Value), "some readers") + ")"
			}
			shown = append(shown, "## "+clipValue(oneLine(heading)))
			if body := renderRich(c.Body, 2); body != "" {
				shown = append(shown, body)
			}
		}
		if len(shown) > 0 {
			parts = append(parts, "# Comments")
			parts = append(parts, shown...)
		}
	}
	return strings.Join(parts, "\n\n")
}

// authorName is who wrote a comment, as the site shows them.
func (c *comment) authorName() string {
	if c.Author == nil {
		return ""
	}
	return oneLine(firstOf(c.Author.DisplayName, c.Author.Name))
}

// sortedComments orders comments oldest first, by when each was written.
func sortedComments(cs []comment) []comment {
	out := append([]comment(nil), cs...)
	sort.SliceStable(out, func(i, j int) bool {
		ti, tj := parseTime(out[i].Created), parseTime(out[j].Created)
		if !ti.Equal(tj) {
			return ti.Before(tj)
		}
		return len(out[i].ID) < len(out[j].ID) || (len(out[i].ID) == len(out[j].ID) && out[i].ID < out[j].ID)
	})
	return out
}

// links names an issue's links by the linked issues' keys alone: "blocks
// ENG-7; is blocked by ENG-3".
func links(ls []issueLink) string {
	var out []string
	for _, l := range ls {
		switch {
		case l.OutwardIssue != nil && issueKeyPattern.MatchString(strings.TrimSpace(l.OutwardIssue.Key)):
			out = append(out, firstOf(oneLine(l.Type.Outward), oneLine(l.Type.Name), "links to")+" "+strings.TrimSpace(l.OutwardIssue.Key))
		case l.InwardIssue != nil && issueKeyPattern.MatchString(strings.TrimSpace(l.InwardIssue.Key)):
			out = append(out, firstOf(oneLine(l.Type.Inward), oneLine(l.Type.Name), "linked from")+" "+strings.TrimSpace(l.InwardIssue.Key))
		}
		if len(out) == maxHeaderValues {
			break
		}
	}
	return strings.Join(out, "; ")
}

// Header bounds: a header value is one line of at most maxHeaderBytes, and a
// list in one at most maxHeaderValues long.
const (
	maxHeaderBytes  = 2048
	maxHeaderValues = 64
)

func joinValues(vs []string) string {
	var out []string
	for _, v := range vs {
		if v = oneLine(v); v != "" {
			out = append(out, v)
		}
		if len(out) == maxHeaderValues {
			break
		}
	}
	return strings.Join(out, ", ")
}

func joinNames(ns []named) string {
	vs := make([]string, 0, len(ns))
	for _, n := range ns {
		vs = append(vs, n.Name)
	}
	return joinValues(vs)
}

// clipValue cuts a header value to maxHeaderBytes, on a character boundary.
func clipValue(s string) string {
	if len(s) <= maxHeaderBytes {
		return s
	}
	cut := maxHeaderBytes
	for cut > 0 && (s[cut]&0xC0) == 0x80 {
		cut--
	}
	return s[:cut] + "…"
}

// oneLine is s with every run of white space and control characters one
// space.
func oneLine(s string) string {
	return strings.Join(strings.FieldsFunc(strings.ToValidUTF8(s, ""), func(r rune) bool {
		return unicode.IsSpace(r) || unicode.IsControl(r)
	}), " ")
}

func firstOf(vs ...string) string {
	for _, v := range vs {
		if v = strings.TrimSpace(v); v != "" {
			return v
		}
	}
	return ""
}

// ids lists the id of every issue jql matches that keep admits, in pages of
// idPageLimit. More than maxIDs is an error rather than an answer cut short:
// the callers' answers are only useful whole.
//
// On Data Center, whose pages are offsets, a page is asked for from
// idPageOverlap issues before where the last one ended, which covers as many
// issues leaving the results — deleted, or changed out of scope — ahead of
// it between two pages. Results that shrank by more than that between two
// pages, or a listing that read fewer issues than the search says it
// matches, may have skipped one, and is an error: the next sync asks again.
// (The listing is ordered by creation, so an issue created meanwhile joins
// its end and shifts nothing.)
func (ss *session) ids(ctx context.Context, jql string, keep func(*issue) bool) ([]string, error) {
	seen := map[string]bool{}
	out := []string{}
	token, start, overlap, total := "", 0, 0, -1
	for {
		page, err := ss.search(ctx, jql, idFields, idPageLimit, token, start)
		if err != nil {
			return nil, err
		}
		if !ss.s.cloud() {
			if total >= 0 && total-page.total > overlap {
				return nil, fmt.Errorf("the search's results changed while they were read (%d issues left them between "+
					"two pages); the next sync tries again", total-page.total)
			}
			total = page.total
		}
		before := len(seen)
		for i := range page.issues {
			is := &page.issues[i]
			id := string(is.ID)
			if !issueIDPattern.MatchString(id) || seen[id] {
				continue
			}
			seen[id] = true
			if len(seen) > maxIDs {
				return nil, fmt.Errorf("the search matched more than %d issues", maxIDs)
			}
			if keep(is) {
				out = append(out, id)
			}
		}
		if page.last {
			if !ss.s.cloud() && len(seen) < page.total {
				return nil, fmt.Errorf("the search's results changed while they were read (%d read, %d matched); "+
					"the next sync tries again", len(seen), page.total)
			}
			return out, nil
		}
		if len(seen) == before {
			// Every page adds an issue, or the listing could go round for
			// ever: this one added none.
			return nil, errors.New("the search returned a page of issues it had returned already: it does not move")
		}
		if ss.s.cloud() {
			token = page.token
			continue
		}
		overlap = min(idPageOverlap, len(page.issues)/2)
		start = page.startAt + len(page.issues) - overlap
	}
}

// reconcile returns the id of every issue the source holds now that a
// listing would index: in scope, and without a security level unless the
// source includes secured issues.
func (ss *session) reconcile(ctx context.Context) ([]string, error) {
	return ss.ids(ctx, ss.s.scopeJQL()+" ORDER BY created ASC, key ASC", func(is *issue) bool {
		return ss.s.includeSecured || !is.secured()
	})
}

// narrow returns the id of every issue in scope that query also matches.
func (ss *session) narrow(ctx context.Context, query string) ([]string, error) {
	if err := checkJQL(query); err != nil {
		return nil, err
	}
	jql := ss.s.scopeJQL() + " AND (" + atlassian.OneLineQuery(query) + ") ORDER BY created ASC, key ASC"
	return ss.ids(ctx, jql, func(is *issue) bool { return ss.s.includeSecured || !is.secured() })
}

// fetch returns one issue in scope: a deletion when the site no longer has
// it, it is out of scope, or it is secured.
func (ss *session) fetch(ctx context.Context, id string) (knowledge.Document, error) {
	if !issueIDPattern.MatchString(id) {
		return knowledge.Document{}, fmt.Errorf("%q is not a Jira issue id", id)
	}
	gone := knowledge.Document{ExternalID: id, Deleted: true}
	page, bodies, err := ss.fetchListing(ctx, ss.s.scopeJQL()+" AND id = "+id, 1, cursor{})
	if atlassian.IsStatus(err, http.StatusBadRequest) {
		// JQL refuses an id that names no issue. Gone, if the site agrees;
		// else the query is at fault.
		var probe struct {
			ID flexID `json:"id"`
		}
		if perr := ss.cl.Get(ctx, ss.s.api()+"/issue/"+id+"?fields=id", &probe); atlassian.IsStatus(perr, http.StatusNotFound) {
			return gone, nil
		}
		return knowledge.Document{}, err
	}
	if err != nil {
		return knowledge.Document{}, err
	}
	if len(page.issues) == 0 || string(page.issues[0].ID) != id {
		return gone, nil
	}
	web, err := ss.webBase(ctx)
	if err != nil {
		return knowledge.Document{}, err
	}
	docs, err := ss.documents(ctx, []*issue{&page.issues[0]}, web, bodies)
	if err != nil {
		return knowledge.Document{}, err
	}
	return docs[0], nil
}
