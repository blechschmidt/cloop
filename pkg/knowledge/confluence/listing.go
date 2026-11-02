package confluence

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/knowledge"
	"github.com/blechschmidt/cloop/pkg/knowledge/internal/atlassian"
)

// Listing bounds.
const (
	// bodyPageLimit is how many documents a listing asks for at once with
	// their bodies; an answer over maxResponseBytes is asked again for half.
	bodyPageLimit = 25
	// idPageLimit is how many a listing of ids asks for at once.
	idPageLimit = 200
	// lookupBatch is how many ids one "id in (...)" search names.
	lookupBatch = 100
	// maxIDs bounds a reconciliation's or a narrowing's answer.
	maxIDs = 250_000
	// maxFallbacks bounds the documents one call looks up one at a time,
	// when search does not return them.
	maxFallbacks = 50
	// maxSpacePages bounds the pages of a space lookup.
	maxSpacePages = 10
)

// Expansions a v1 search asks for. Restrictions are asked for both kinds of
// principal: a page restricted to a group and one restricted to a person are
// both restricted.
const (
	expandRestrictions = "restrictions.read.restrictions.user,restrictions.read.restrictions.group"
	expandPlacement    = "ancestors," + expandRestrictions
	expandListing      = "body.storage,version,space," + expandPlacement
)

// Paths below the API root.
const (
	pathV2Pages     = "/api/v2/pages"
	pathV2Blogposts = "/api/v2/blogposts"
	pathV2Spaces    = "/api/v2/spaces"
	pathSearch      = "/rest/api/content/search"
	pathSpaces      = "/rest/api/space"
)

// contentIDPattern is a content id: Confluence's are decimal numbers.
var contentIDPattern = regexp.MustCompile(`^[0-9]{1,20}$`)

// stream is one listing a pass goes through.
type stream struct {
	// kind is the content type it lists: "page", "blogpost", or "" for a
	// search of both.
	kind string
	path string
}

// streams are the source's listings: a Cloud space-scoped source's pages
// and blog posts through v2, or one CQL search of both.
func (s settings) streams() []stream {
	if s.v2() {
		return []stream{{kind: "page", path: pathV2Pages}, {kind: "blogpost", path: pathV2Blogposts}}
	}
	return []stream{{path: pathSearch}}
}

// session is one call's settings and client.
type session struct {
	s  settings
	cl *atlassian.Client
}

// item is a document as a listing returned it, before it is decided on.
type item struct {
	id       string
	kind     string
	status   string
	title    string
	space    string
	modified time.Time
	webui    string
	body     string
	hasBody  bool
	// placed reports that ancestors and restriction are what the site said,
	// rather than not yet asked.
	placed    bool
	ancestors []ancestor
	restrict  restriction
	// gone reports a document the site no longer has.
	gone bool
}

type ancestor struct{ id, title string }

// restriction is what a document's read restrictions say. One that is not
// known counts as restricted: the decision to show everyone a page is never
// made on missing information.
type restriction struct {
	known bool
	// count is how many people and groups the restriction names; 0 is none.
	count int
	who   []string
}

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

// links is the _links of an answer.
type links struct {
	Next string `json:"next"`
	Base string `json:"base"`
}

// v2Content is a page or blog post from REST API v2.
type v2Content struct {
	ID      flexID `json:"id"`
	Status  string `json:"status"`
	Title   string `json:"title"`
	SpaceID flexID `json:"spaceId"`
	Version struct {
		CreatedAt string `json:"createdAt"`
	} `json:"version"`
	Body struct {
		Storage *struct {
			Value string `json:"value"`
		} `json:"storage"`
	} `json:"body"`
	Links struct {
		WebUI string `json:"webui"`
	} `json:"_links"`
}

type v2List struct {
	Results []v2Content `json:"results"`
	Links   links       `json:"_links"`
}

// principals is one kind of a restriction's principals. Pointers tell a
// restriction the site reported as empty from one it did not report.
type principals struct {
	Results []struct {
		AccountID string `json:"accountId"`
		Username  string `json:"username"`
		UserKey   string `json:"userKey"`
		Name      string `json:"name"`
		ID        flexID `json:"id"`
	} `json:"results"`
	Size      int `json:"size"`
	TotalSize int `json:"totalSize"`
}

type readRestrictions struct {
	User  *principals `json:"user"`
	Group *principals `json:"group"`
}

// v1Content is a page or blog post from REST API v1 search.
type v1Content struct {
	ID     flexID `json:"id"`
	Type   string `json:"type"`
	Status string `json:"status"`
	Title  string `json:"title"`
	Space  struct {
		Key string `json:"key"`
	} `json:"space"`
	Version struct {
		When string `json:"when"`
	} `json:"version"`
	Body struct {
		Storage *struct {
			Value string `json:"value"`
		} `json:"storage"`
	} `json:"body"`
	Ancestors *[]struct {
		ID    flexID `json:"id"`
		Title string `json:"title"`
	} `json:"ancestors"`
	Restrictions *struct {
		Read *struct {
			Restrictions *readRestrictions `json:"restrictions"`
		} `json:"read"`
	} `json:"restrictions"`
	Links struct {
		WebUI string `json:"webui"`
	} `json:"_links"`
}

type v1List struct {
	Results []v1Content `json:"results"`
	Links   links       `json:"_links"`
}

// restrictionOf reads a read restriction the site reported.
func restrictionOf(r *readRestrictions) restriction {
	if r == nil || r.User == nil || r.Group == nil {
		return restriction{}
	}
	out := restriction{known: true}
	for _, p := range []struct {
		set    *principals
		prefix string
	}{{r.User, "user:"}, {r.Group, "group:"}} {
		out.count += max(len(p.set.Results), p.set.Size, p.set.TotalSize)
		for _, who := range p.set.Results {
			name := firstOf(who.AccountID, who.Username, who.UserKey, who.Name, string(who.ID))
			if name != "" {
				out.who = append(out.who, p.prefix+name)
			}
		}
	}
	return out
}

func firstOf(vs ...string) string {
	for _, v := range vs {
		if v = strings.TrimSpace(v); v != "" {
			return v
		}
	}
	return ""
}

// itemOf reads a v1 search result.
func itemOf(c v1Content, withBody bool) *item {
	it := &item{
		id: string(c.ID), kind: c.Type, status: c.Status, title: c.Title, space: c.Space.Key,
		modified: parseTime(c.Version.When), webui: c.Links.WebUI,
	}
	if withBody && c.Body.Storage != nil {
		it.body, it.hasBody = c.Body.Storage.Value, true
	}
	if c.Ancestors != nil && c.Restrictions != nil && c.Restrictions.Read != nil {
		it.placed = true
		for _, a := range *c.Ancestors {
			it.ancestors = append(it.ancestors, ancestor{id: string(a.ID), title: a.Title})
		}
		it.restrict = restrictionOf(c.Restrictions.Read.Restrictions)
	}
	return it
}

// readable reports content of the two types the connector reads, with an id
// it can name in a query.
func (it *item) readable() bool {
	return (it.kind == "page" || it.kind == "blogpost") && contentIDPattern.MatchString(it.id)
}

// current reports a document a listing keeps: current content the connector
// reads. Archived, draft and trashed content is not what the site shows a
// reader.
func (it *item) current() bool {
	return it.readable() && (it.status == "" || it.status == "current")
}

// parseTime reads an API timestamp; zero when it does not parse.
func parseTime(s string) time.Time {
	t, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(s))
	if err != nil {
		return time.Time{}
	}
	return t.UTC()
}

// setParam returns ref with its query parameter key set to value, or removed
// when value is empty.
func setParam(ref, key, value string) string {
	path, query, _ := strings.Cut(ref, "?")
	q, err := url.ParseQuery(query)
	if err != nil {
		q = url.Values{}
	}
	if value == "" {
		q.Del(key)
	} else {
		q.Set(key, value)
	}
	if len(q) == 0 {
		return path
	}
	return path + "?" + q.Encode()
}

// withBodies returns a listing's ref asking for bodies or not.
func withBodies(strm stream, ref string, bodies bool) string {
	if strm.path != pathSearch {
		if bodies {
			return setParam(ref, "body-format", "storage")
		}
		return setParam(ref, "body-format", "")
	}
	if bodies {
		return setParam(ref, "expand", expandListing)
	}
	return setParam(ref, "expand", "version,space,"+expandPlacement)
}

// nextRef turns an answer's next link into a ref below the API root, refusing
// one that leads anywhere but the stream's own endpoint on the same site.
// v2 writes its links from the site's root ("/wiki/api/v2/…"), v1 from the
// API root; either may be absolute.
func (ss *session) nextRef(next, path string) (string, error) {
	next = strings.TrimSpace(next)
	if next == "" {
		return "", nil
	}
	u, err := url.Parse(next)
	if err != nil {
		return "", fmt.Errorf("the site's next-page link %q is not a URL", next)
	}
	if u.IsAbs() || u.Host != "" {
		if !strings.EqualFold(u.Scheme, ss.s.base.Scheme) || !strings.EqualFold(u.Host, ss.s.base.Host) {
			return "", fmt.Errorf("the site's next-page link leads to %s, not to the site", u.Redacted())
		}
	}
	p := u.Path
	switch {
	case ss.s.base.Path != "" && strings.HasPrefix(p, ss.s.base.Path+"/"):
		p = strings.TrimPrefix(p, ss.s.base.Path)
	case ss.s.cloud() && strings.HasPrefix(p, "/wiki/"):
		p = strings.TrimPrefix(p, "/wiki")
	}
	if p != path {
		return "", fmt.Errorf("the site's next-page link leads to %s, not to %s", p, path)
	}
	if u.RawQuery == "" {
		return "", fmt.Errorf("the site's next-page link for %s names no position", path)
	}
	return p + "?" + u.RawQuery, nil
}

// webBase is where the site's pages are read: the base an answer names, when
// it is a URL the connector would itself connect to, else the base URL.
func (ss *session) webBase(answered string) string {
	if u, err := url.Parse(strings.TrimSpace(answered)); err == nil && u.Host != "" && u.User == nil &&
		(u.Scheme == "https" || (u.Scheme == "http" && ss.cl.Insecure())) {
		return strings.TrimRight(u.Scheme+"://"+u.Host+u.EscapedPath(), "/")
	}
	return strings.TrimRight(ss.s.base.String(), "/")
}

// webURL is the address a person reads a document at.
func webURL(base, webui string) string {
	webui = strings.TrimSpace(webui)
	if !strings.HasPrefix(webui, "/") || strings.HasPrefix(webui, "//") {
		return ""
	}
	return base + webui
}

// resolveSpaces returns the configured spaces the site has and the account
// may see. A key it does not — deleted, misspelt, or not visible — holds
// nothing to list, and is dropped: the pages of a space the account lost
// access to then leave the index, which an error would keep.
func (ss *session) resolveSpaces(ctx context.Context) ([]spaceRef, error) {
	if len(ss.s.spaces) == 0 {
		return nil, nil
	}
	want := map[string]string{}
	for _, k := range ss.s.spaces {
		want[strings.ToLower(k)] = k
	}
	var found []spaceRef
	seen := map[string]bool{}
	add := func(id, key string) {
		k, ok := want[strings.ToLower(key)]
		if ok && !seen[k] {
			seen[k] = true
			found = append(found, spaceRef{ID: id, Key: k})
		}
	}
	var ref string
	if ss.s.cloud() {
		q := url.Values{"keys": {strings.Join(ss.s.spaces, ",")}, "limit": {"250"}}
		ref = pathV2Spaces + "?" + q.Encode()
	} else {
		q := url.Values{"spaceKey": ss.s.spaces, "limit": {strconv.Itoa(maxSpaces)}}
		ref = pathSpaces + "?" + q.Encode()
	}
	path := strings.SplitN(ref, "?", 2)[0]
	for page := 0; ref != "" && page < maxSpacePages; page++ {
		var answer struct {
			Results []struct {
				ID  flexID `json:"id"`
				Key string `json:"key"`
			} `json:"results"`
			Links links `json:"_links"`
		}
		if err := ss.cl.Get(ctx, ref, &answer); err != nil {
			return nil, fmt.Errorf("look up the spaces %s: %w", strings.Join(ss.s.spaces, ", "), err)
		}
		for _, r := range answer.Results {
			add(string(r.ID), r.Key)
		}
		next, err := ss.nextRef(answer.Links.Next, path)
		if err != nil {
			return nil, err
		}
		ref = next
	}
	if ss.s.cloud() {
		// v2 lists a space by its id; one without is of no use.
		kept := found[:0]
		for _, sp := range found {
			if contentIDPattern.MatchString(sp.ID) {
				kept = append(kept, sp)
			}
		}
		found = kept
	}
	return found, nil
}

// scopeCQL is the CQL for what the source holds: its spaces, or its query.
func (ss *session) scopeCQL(spaces []spaceRef) string {
	if ss.s.cql != "" {
		return "(" + oneLineCQL(ss.s.cql) + ")"
	}
	quoted := make([]string, 0, len(spaces))
	for _, sp := range spaces {
		quoted = append(quoted, `"`+sp.Key+`"`)
	}
	return "space in (" + strings.Join(quoted, ",") + ")"
}

// contentCQL is scopeCQL narrowed to the content the connector reads.
func (ss *session) contentCQL(spaces []spaceRef) string {
	return ss.scopeCQL(spaces) + " and type in (page, blogpost)"
}

// firstRef is the ref of a stream's first page.
func (ss *session) firstRef(strm stream, spaces []spaceRef, limit int) string {
	if strm.path == pathSearch {
		q := url.Values{
			"cql":    {ss.contentCQL(spaces) + " order by lastmodified desc"},
			"expand": {expandListing},
			"limit":  {strconv.Itoa(limit)},
		}
		return strm.path + "?" + q.Encode()
	}
	ids := make([]string, 0, len(spaces))
	for _, sp := range spaces {
		ids = append(ids, sp.ID)
	}
	q := url.Values{
		"space-id":    {strings.Join(ids, ",")},
		"sort":        {"-modified-date"},
		"status":      {"current"},
		"body-format": {"storage"},
		"limit":       {strconv.Itoa(limit)},
	}
	return strm.path + "?" + q.Encode()
}

// listingPage is one page of a stream.
type listingPage struct {
	items   []*item
	next    string
	webBase string
}

// fetchListing reads one page of strm at ref. An answer too large to read is
// asked for again for half as many documents, and at one, once more without
// its body: a page too large to read is indexed by its title rather than
// holding up every sync after it.
func (ss *session) fetchListing(ctx context.Context, strm stream, ref string, limit int, spaces []spaceRef) (listingPage, error) {
	bodies := true
	for {
		r := withBodies(strm, setParam(ref, "limit", strconv.Itoa(limit)), bodies)
		page, err := ss.readListing(ctx, strm, r, bodies, spaces)
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
		return page, err
	}
}

// readListing reads one page of strm at ref.
func (ss *session) readListing(ctx context.Context, strm stream, ref string, bodies bool, spaces []spaceRef) (listingPage, error) {
	var page listingPage
	var answered links
	if strm.path == pathSearch {
		var answer v1List
		if err := ss.cl.Get(ctx, ref, &answer); err != nil {
			return page, err
		}
		for _, c := range answer.Results {
			page.items = append(page.items, itemOf(c, bodies))
		}
		answered = answer.Links
	} else {
		var answer v2List
		if err := ss.cl.Get(ctx, ref, &answer); err != nil {
			return page, err
		}
		keys := map[string]string{}
		for _, sp := range spaces {
			keys[sp.ID] = sp.Key
		}
		for _, c := range answer.Results {
			it := &item{
				id: string(c.ID), kind: strm.kind, status: c.Status, title: c.Title, space: keys[string(c.SpaceID)],
				modified: parseTime(c.Version.CreatedAt), webui: c.Links.WebUI,
			}
			if bodies && c.Body.Storage != nil {
				it.body, it.hasBody = c.Body.Storage.Value, true
			}
			page.items = append(page.items, it)
		}
		answered = answer.Links
	}
	next, err := ss.nextRef(answered.Next, strm.path)
	if err != nil {
		return page, err
	}
	page.next, page.webBase = next, ss.webBase(answered.Base)
	return page, nil
}

// list returns the documents of the page after cursor raw.
func (ss *session) list(ctx context.Context, raw string, pageSize int) (knowledge.Page, error) {
	streams := ss.s.streams()
	cur := decodeCursor(raw, len(streams))
	limit := bodyPageLimit
	if pageSize > 0 {
		limit = min(limit, pageSize)
	}
	if cur.Stream == 0 && cur.Next == "" {
		// A pass begins: the spaces are looked up afresh, so one created,
		// deleted or shared since the last pass is seen by this one.
		spaces, err := ss.resolveSpaces(ctx)
		if err != nil {
			return knowledge.Page{}, err
		}
		cur.Spaces = spaces
		for i := range cur.Top {
			cur.Top[i] = 0
		}
	}
	if len(ss.s.spaces) > 0 && len(cur.Spaces) == 0 {
		// None of the configured spaces is there to list.
		return knowledge.Page{Cursor: cursor{Since: cur.Since, Top: cur.Top}.encode()}, nil
	}
	i := cur.Stream
	strm := streams[i]
	ref := cur.Next
	if ref == "" {
		ref = ss.firstRef(strm, cur.Spaces, limit)
	}
	page, err := ss.fetchListing(ctx, strm, ref, limit, cur.Spaces)
	if err != nil {
		return knowledge.Page{}, err
	}
	since := cur.since(i)
	ended := page.next == ""
	var kept []*item
	for _, it := range page.items {
		if !since.IsZero() && !it.modified.IsZero() && it.modified.Before(since) {
			// Newest first: everything after this one is older still.
			ended = true
			break
		}
		cur.saw(i, it.modified)
		switch {
		case it.current():
			kept = append(kept, it)
		case it.readable():
			// Archived, trashed: listed to say it is no longer there.
			it.gone = true
			kept = append(kept, it)
		}
	}
	docs, err := ss.documents(ctx, kept, page.webBase)
	if err != nil {
		return knowledge.Page{}, err
	}
	out := knowledge.Page{Documents: docs, More: true}
	if !ended {
		cur.Next = page.next
		out.Cursor = cur.encode()
		return out, nil
	}
	cur.endStream(i)
	cur.Stream++
	if cur.Stream == len(streams) {
		cur.Stream, cur.Spaces, out.More = 0, nil, false
	}
	out.Cursor = cur.encode()
	return out, nil
}

// documents decides on items: looks up where each sits and whether it is
// restricted, where the listing did not say, and turns each into the
// document the index keeps — or, for one restricted or gone, a deletion, so
// that a copy indexed before it was restricted leaves the index.
func (ss *session) documents(ctx context.Context, items []*item, webBase string) ([]knowledge.Document, error) {
	if len(items) == 0 {
		return nil, nil
	}
	if err := ss.place(ctx, items); err != nil {
		return nil, err
	}
	direct, err := ss.ancestorRestrictions(ctx, items)
	if err != nil {
		return nil, err
	}
	docs := make([]knowledge.Document, 0, len(items))
	for _, it := range items {
		docs = append(docs, ss.document(it, webBase, direct))
	}
	return docs, nil
}

// document is the index's document for an item.
func (ss *session) document(it *item, webBase string, direct map[string]restriction) knowledge.Document {
	if it.gone {
		return knowledge.Document{ExternalID: it.id, Deleted: true}
	}
	restricted, who := decide(it, direct)
	if restricted && !ss.s.includeRestricted {
		return knowledge.Document{ExternalID: it.id, Deleted: true}
	}
	var acl []string
	if it.space != "" {
		acl = append(acl, "space:"+it.space)
	}
	if restricted {
		acl = append(acl, "restricted")
		acl = append(acl, who...)
	}
	ancestors := make([]string, 0, len(it.ancestors))
	for _, a := range it.ancestors {
		ancestors = append(ancestors, a.title)
	}
	body := ""
	if it.hasBody {
		body = renderStorage(it.body)
	}
	return knowledge.Document{
		ExternalID: it.id, Title: it.title, URL: webURL(webBase, it.webui), Space: it.space,
		UpdatedAt: it.modified, Body: body, ACL: acl, Ancestors: ancestors,
	}
}

// decide says whether an item carries a view restriction — its own, or one it
// inherits from a page above it — and who the restrictions name. A
// restriction not known, the item's or an ancestor's, counts as one.
func decide(it *item, direct map[string]restriction) (bool, []string) {
	restricted := !it.placed || !it.restrict.known || it.restrict.count > 0
	who := append([]string(nil), it.restrict.who...)
	for _, a := range it.ancestors {
		r, ok := direct[a.id]
		switch {
		case !ok || !r.known:
			restricted = true
		case r.count > 0:
			restricted = true
			who = append(who, r.who...)
		}
	}
	return restricted, who
}

// place looks up the ancestors and read restriction of every item whose
// listing did not say — v2 says neither — with one search per lookupBatch of
// them, and one request each for those search does not return: a page made a
// moment ago may not be in the site's search index yet. One the site no
// longer has is marked gone.
func (ss *session) place(ctx context.Context, items []*item) error {
	byID := map[string]*item{}
	var need []string
	for _, it := range items {
		if !it.placed && !it.gone {
			byID[it.id] = it
			need = append(need, it.id)
		}
	}
	if len(need) == 0 {
		return nil
	}
	err := ss.lookup(ctx, need, expandPlacement, func(c v1Content) {
		if it := byID[string(c.ID)]; it != nil {
			placed := itemOf(c, false)
			if placed.placed {
				it.placed, it.ancestors, it.restrict = true, placed.ancestors, placed.restrict
			}
		}
	})
	if err != nil {
		return err
	}
	fallbacks := 0
	for _, id := range need {
		it := byID[id]
		if it.placed {
			continue
		}
		if fallbacks++; fallbacks > maxFallbacks {
			return fmt.Errorf("the site's search did not return %d or more of the documents it listed; "+
				"the next sync tries them again", maxFallbacks)
		}
		var c v1Content
		err := ss.cl.Get(ctx, "/rest/api/content/"+id+"?expand="+url.QueryEscape(expandPlacement), &c)
		switch {
		case atlassian.IsStatus(err, http.StatusNotFound):
			it.gone = true
		case err != nil:
			return fmt.Errorf("look up page %s: %w", id, err)
		default:
			placed := itemOf(c, false)
			it.placed, it.ancestors, it.restrict = placed.placed, placed.ancestors, placed.restrict
		}
	}
	return nil
}

// ancestorRestrictions returns the read restriction each item's ancestors
// carry themselves — known for the items, looked up for the rest — so that
// decide can tell a page under a restricted page, which a reader of the
// space cannot see either. An ancestor the site does not return is left
// unknown, which counts as restricted.
func (ss *session) ancestorRestrictions(ctx context.Context, items []*item) (map[string]restriction, error) {
	direct := map[string]restriction{}
	for _, it := range items {
		if it.placed {
			direct[it.id] = it.restrict
		}
	}
	var need []string
	asked := map[string]bool{}
	for _, it := range items {
		for _, a := range it.ancestors {
			if _, ok := direct[a.id]; !ok && !asked[a.id] && contentIDPattern.MatchString(a.id) {
				asked[a.id] = true
				need = append(need, a.id)
			}
		}
	}
	if len(need) == 0 {
		return direct, nil
	}
	err := ss.lookup(ctx, need, expandRestrictions, func(c v1Content) {
		if asked[string(c.ID)] && c.Restrictions != nil && c.Restrictions.Read != nil {
			direct[string(c.ID)] = restrictionOf(c.Restrictions.Read.Restrictions)
		}
	})
	if err != nil {
		return nil, err
	}
	fallbacks := 0
	for _, id := range need {
		if r, ok := direct[id]; ok && r.known {
			continue
		}
		if fallbacks++; fallbacks > maxFallbacks {
			// Left unknown they would count as restricted, and the pages
			// under them would be passed over for good: fail, and let the
			// next sync ask again.
			return nil, fmt.Errorf("the site's search did not return %d or more of the pages above the documents it "+
				"listed; the next sync tries them again", maxFallbacks)
		}
		var answer struct {
			Restrictions *readRestrictions `json:"restrictions"`
		}
		err := ss.cl.Get(ctx, "/rest/api/content/"+id+"/restriction/byOperation/read", &answer)
		switch {
		case atlassian.IsStatus(err, http.StatusNotFound):
			// Left unknown: restricted.
		case err != nil:
			return nil, fmt.Errorf("look up the restrictions of page %s: %w", id, err)
		default:
			direct[id] = restrictionOf(answer.Restrictions)
		}
	}
	return direct, nil
}

// lookup runs a search for ids, lookupBatch at a time, with expand, and
// hands each result to each.
func (ss *session) lookup(ctx context.Context, ids []string, expand string, each func(v1Content)) error {
	for start := 0; start < len(ids); start += lookupBatch {
		batch := ids[start:min(start+lookupBatch, len(ids))]
		cql := "id in (" + strings.Join(batch, ",") + ")"
		if _, err := ss.search(ctx, cql, expand, len(batch), len(batch), func(c v1Content) error {
			each(c)
			return nil
		}); err != nil {
			return err
		}
	}
	return nil
}

// search pages through a CQL search with expand, limit results a page, and
// hands each result to each. More than most results is an error rather than
// an answer cut short: the callers' answers are only useful whole.
func (ss *session) search(ctx context.Context, cql, expand string, limit, most int, each func(v1Content) error) (string, error) {
	q := url.Values{"cql": {cql}, "limit": {strconv.Itoa(limit)}}
	if expand != "" {
		q.Set("expand", expand)
	}
	ref := pathSearch + "?" + q.Encode()
	seen, webBase := 0, ""
	for pages := 0; ref != ""; pages++ {
		if pages > most/max(limit, 1)+10 {
			return "", fmt.Errorf("the search did not end after %d pages", pages)
		}
		var answer v1List
		if err := ss.cl.Get(ctx, ref, &answer); err != nil {
			return "", err
		}
		if webBase == "" {
			webBase = ss.webBase(answer.Links.Base)
		}
		for _, c := range answer.Results {
			if seen++; seen > most {
				return "", fmt.Errorf("the search matched more than %d documents", most)
			}
			if err := each(c); err != nil {
				return "", err
			}
		}
		next, err := ss.nextRef(answer.Links.Next, pathSearch)
		if err != nil {
			return "", err
		}
		if len(answer.Results) == 0 {
			next = ""
		}
		ref = next
	}
	return webBase, nil
}

// reconcile returns the id of every document the source holds now that a
// listing would index: current pages and blog posts in scope, without a view
// restriction unless the source includes restricted ones.
func (ss *session) reconcile(ctx context.Context) ([]string, error) {
	spaces, err := ss.resolveSpaces(ctx)
	if err != nil {
		return nil, err
	}
	if len(ss.s.spaces) > 0 && len(spaces) == 0 {
		return []string{}, nil
	}
	var items []*item
	_, err = ss.search(ctx, ss.contentCQL(spaces)+" order by created", expandPlacement, idPageLimit, maxIDs,
		func(c v1Content) error {
			if it := itemOf(c, false); it.current() {
				items = append(items, it)
			}
			return nil
		})
	if err != nil {
		return nil, err
	}
	direct, err := ss.ancestorRestrictions(ctx, items)
	if err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(items))
	for _, it := range items {
		if restricted, _ := decide(it, direct); restricted && !ss.s.includeRestricted {
			continue
		}
		ids = append(ids, it.id)
	}
	return ids, nil
}

// narrow returns the id of every document in scope that query also matches.
func (ss *session) narrow(ctx context.Context, query string) ([]string, error) {
	if err := checkCQL(query); err != nil {
		return nil, err
	}
	spaces, err := ss.resolveSpaces(ctx)
	if err != nil {
		return nil, err
	}
	if len(ss.s.spaces) > 0 && len(spaces) == 0 {
		return []string{}, nil
	}
	cql := ss.scopeCQL(spaces) + " and (" + oneLineCQL(query) + ") and type in (page, blogpost)"
	ids := []string{}
	_, err = ss.search(ctx, cql, "", idPageLimit, maxIDs, func(c v1Content) error {
		if id := string(c.ID); contentIDPattern.MatchString(id) {
			ids = append(ids, id)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return ids, nil
}

// fetch returns one document in scope: a deletion when the site no longer
// has it, it is out of scope, or it is restricted.
func (ss *session) fetch(ctx context.Context, id string) (knowledge.Document, error) {
	if !contentIDPattern.MatchString(id) {
		return knowledge.Document{}, fmt.Errorf("%q is not a Confluence content id", id)
	}
	spaces, err := ss.resolveSpaces(ctx)
	if err != nil {
		return knowledge.Document{}, err
	}
	if len(ss.s.spaces) > 0 && len(spaces) == 0 {
		return knowledge.Document{ExternalID: id, Deleted: true}, nil
	}
	var found *item
	webBase, err := ss.search(ctx, ss.contentCQL(spaces)+" and id = "+id, expandListing, 1, 1, func(c v1Content) error {
		found = itemOf(c, true)
		return nil
	})
	if err != nil {
		return knowledge.Document{}, err
	}
	if found == nil || found.id != id || !found.current() {
		return knowledge.Document{ExternalID: id, Deleted: true}, nil
	}
	docs, err := ss.documents(ctx, []*item{found}, webBase)
	if err != nil {
		return knowledge.Document{}, err
	}
	return docs[0], nil
}
