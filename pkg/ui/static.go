package ui

// Static asset serving for the dashboard front end (Task 20174).
//
// The dashboard used to live in a single ~11,300-line `dashboardHTML` string
// constant in server.go: HTML, CSS and JavaScript for every panel in one Go
// literal, rewritten verbatim on every page load with no compression and no
// cache validator. It now lives on disk under assets/ — index.html, app.css,
// and one JS fragment per panel — embedded here with //go:embed.
//
// Why the JS fragments are concatenated into one bundle rather than served as
// one <script> per panel: the whole front end is a single
// `(function() { 'use strict'; … })();` IIFE. That wrapper is load-bearing —
// it is why a bare `function foo()` is *not* reachable from an inline
// `onclick=`, which is the invariant the architectural tests in
// frontend_test.go enforce (Tasks 20033, 20065). Separate <script> elements
// each get their own top-level scope, so splitting the IIFE across them would
// promote every panel-local helper to a global, silently change shadowing
// semantics between panels, and turn the reachability test into a no-op.
// Concatenating on the server reproduces today's byte-for-byte semantics while
// still giving the on-disk split that makes a change to one panel stop being a
// merge hazard for the other fifteen.
//
// Every representation — the raw bytes, the gzip encoding, and the ETag — is
// computed once and reused for every request. Assets are addressed by a URL
// containing their content hash and served `immutable`, so a client fetches
// each one exactly once per deploy; index.html itself is `no-cache` (it names
// those hashed URLs and must never be stale) but still revalidates cheaply
// through its own ETag.

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
)

// assetFS holds the dashboard front end. `assets/js` pulls in the whole
// fragment directory so a new panel file is embedded without touching a
// directive — but it still has to be listed in bundleFiles below to be
// served, and TestStaticAssets_BundleCoversEveryFragment fails if it is not.
//
// The icon set (Task 20228) is listed explicitly rather than as a directory
// glob so that an asset which is never served cannot slip into the binary.
//
//go:embed assets/index.html assets/glasses.html assets/app.css assets/chart.umd.min.js assets/js
//go:embed assets/favicon.ico assets/icon-192.png assets/icon-512.png
//go:embed assets/apple-touch-icon.png assets/icon.svg assets/manifest.webmanifest
var assetFS embed.FS

// bundleFiles is the concatenation order of the main IIFE. The order is
// explicit rather than implied by directory listing so that it is reviewable
// in a diff: 00-core.js opens the IIFE and defines the shared state and
// helpers every later fragment closes over, and the last entry closes it.
//
// The numeric prefixes keep the on-disk order identical to this list.
var bundleFiles = []string{
	"assets/js/00-core.js",
	// The shared open/close path every dialog on the page goes through
	// (Task 20288). Early, because it owns the document-level Tab handler that
	// contains focus and the stack the Escape chain in 18-shortcuts.js reads.
	"assets/js/00-overlay.js",
	"assets/js/01-overview.js",
	"assets/js/02-tasks.js",
	"assets/js/03-kanban.js",
	"assets/js/04-realtime.js",
	"assets/js/05-projects.js",
	"assets/js/06-kb.js",
	"assets/js/07-queue.js",
	"assets/js/08-provider-calls.js",
	"assets/js/09-deps.js",
	"assets/js/10-risk-matrix.js",
	"assets/js/11-timeline.js",
	"assets/js/12-task-crud.js",
	"assets/js/13-suggest.js",
	"assets/js/15-voice.js",
	"assets/js/16-chat.js",
	"assets/js/17-assistant.js",
	"assets/js/18-shortcuts.js",
	"assets/js/19-analytics.js",
	// The executor list and cards, the Overview's executor and caps cards; the
	// executor dialogs are deferred/execadmin.js (Task 20386).
	"assets/js/23-executors.js",
	// A project's firewall card on the Overview (Task 20363), after the
	// executors fragment whose helpers it uses. A device's firewall dialog is
	// deferred/execadmin.js.
	"assets/js/23-firewall.js",
	"assets/js/24-mobile-nav.js",
	"assets/js/25-replay.js",
	// The header's sign-out buttons (Task 20176). The sessions table they used
	// to sit beside moved with the Secrets tab to deferred/secrets.js.
	"assets/js/26-sessions.js",
	// The header's own-quota badge and the formatting the deferred Quotas tab
	// shares with it (Task 20182).
	"assets/js/27-quotas.js",
	// The running hub's own build (Task 20249): the Settings panel, the footer
	// chip, and the reconnect check that notices the page is now older than
	// the server. One fragment rather than three edits, because those three
	// surfaces share the fetch and the formatting.
	"assets/js/29-build.js",
	// Parallel features (Task 20341): the Features panel on a project's
	// Overview, the banner on a feature's, and their three dialogs. Uses
	// nothing but 00-core.js/00-overlay.js helpers and openProject from
	// 05-projects.js, all in scope by the time it runs.
	"assets/js/32-features.js",
	// Per-project repository assignment on the Overview (Task 20306). The
	// Settings panel that connects an App is deferred/settings.js.
	"assets/js/32-githubapp.js",
	// Silent sign-in renewal and the way back from a lapsed SSO session
	// (Task 20359). Called from 00-core.js's response handling and
	// 18-shortcuts.js's boot, both of which run after every fragment has been
	// evaluated, so it only has to load before the IIFE closes.
	"assets/js/32-renew.js",
	// Last, and it closes the IIFE 00-core.js opened. A fragment appended
	// after the close lands at global scope, where none of the shared helpers
	// are visible — see TestDashboard_MainIIFEClosesInLastFragment. Numbered
	// 99 so that the list, which must stay in filename order, never needs it
	// renumbered when a panel is added.
	"assets/js/99-end.js",
}

// deferredScripts are served as assets of their own and loaded only when a
// panel needs them (Task 20366). Each is named in a <meta> on the page by its
// token and fetched by the code that draws the panel — chart.js's arrangement
// (Task 20289) — so it costs a first paint nothing. A deferred script runs
// outside the bundle's IIFE: it sees none of the bundle's helpers unless the
// loader hands them over, and it must put nothing on window but its entry
// point. They live in assets/js/deferred/, which
// TestStaticAssets_BundleCoversEveryFragment does not read as bundle fragments.
var deferredScripts = []struct{ token, path string }{
	// The Members card on a project's Overview (Task 20366).
	{"members.js", "assets/js/deferred/members.js"},
	// The Claude credential card and dialog (Task 20379).
	{"harness.js", "assets/js/deferred/harness.js"},
	// The offboarding form in the Secrets tab (Task 20261), deferred by Task
	// 20379 to pay for the line above.
	{"offboard.js", "assets/js/deferred/offboard.js"},
	// The free-space floor editor in Settings → Disk & Retention (Task
	// 20381): admin-only, so only an admin's Settings ever fetches it.
	{"diskfloor.js", "assets/js/deferred/diskfloor.js"},
	// The Settings and admin tabs, markup and code, each fetched on its first
	// open (Task 20386): 01-overview.js's openDeferredTab loads them. Their
	// handlers are data-act attributes that mountPanel routes, since a
	// deferred script cannot put functions on window for an inline onclick.
	{"settings.js", "assets/js/deferred/settings.js"},
	{"budget.js", "assets/js/deferred/budget.js"},
	{"secrets.js", "assets/js/deferred/secrets.js"},
	{"audit.js", "assets/js/deferred/audit.js"},
	{"quotas.js", "assets/js/deferred/quotas.js"},
	{"telemetry.js", "assets/js/deferred/telemetry.js"},
	// The executor dialogs — history, sandbox, virtual executors, firewall,
	// limits, access, enrollment and upgrades — fetched on the first open of
	// any of them through panelAct (Task 20386).
	{"execadmin.js", "assets/js/deferred/execadmin.js"},
}

// Cache-Control values. Hashed asset URLs change whenever their bytes change,
// so the response for a given URL can be cached forever; the HTML that names
// those URLs must be revalidated on every load or a deploy would never be
// picked up.
const (
	cacheImmutable = "public, max-age=31536000, immutable"
	cacheNoCache   = "no-cache"
)

// gzipMinBytes is the size below which compressing is not worth the CPU on
// either end — a gzip member carries ~20 bytes of framing, and sub-kilobyte
// bodies fit in a single packet either way.
const gzipMinBytes = 1024

// staticAsset is one fully-prepared response: the identity bytes, the gzip
// encoding (nil when compression did not pay for itself), and a distinct
// strong ETag per encoding. Nothing here is computed per request.
type staticAsset struct {
	ctype    string
	cache    string
	raw      []byte
	gz       []byte
	etag     string // identity representation
	gzETag   string // gzip representation ("…-gzip"), empty when gz is nil
	contents string // raw as a string, for the architectural tests
}

// assetSet is the served view of assetFS: every addressable asset keyed by URL
// path, plus the rendered index.html (which is served from "/" rather than
// from /assets/ because it is not content-addressed).
type assetSet struct {
	byPath map[string]*staticAsset
	page   *staticAsset

	// icons holds the favicon set and the web app manifest, keyed by their
	// fixed root URLs (Task 20228). Separate from byPath because these are
	// not content-addressed — /favicon.ico is probed blind by clients that
	// never read our HTML — so they revalidate instead of caching forever.
	icons map[string]*staticAsset

	// glasses is the wearable's shell, served from /glasses (Task 20194).
	// Self-contained rather than content-addressed: it is a few kilobytes of
	// markup, CSS and script in one document, so a device on a phone's link
	// paints after a single round trip instead of three.
	glasses *staticAsset

	// The individual sources, kept so tests can assert over the whole front
	// end the way they used to assert over the dashboardHTML constant.
	css    string
	bundle string
	// served is the bundle as it goes over the wire: bundle with its
	// whole-line comments removed (jsstrip.go), or bundle itself if the
	// stripper declined.
	served string
	// servedCSS is css as it goes over the wire, its comments removed
	// (cssstrip.go), or css itself if the stripper declined.
	servedCSS string
	boundary  string
	// servedBoundary is errboundary.js as it goes over the wire, its
	// whole-line comments removed like the bundle's, or boundary itself if
	// the stripper declined.
	servedBoundary string
	// deferred holds each deferred script as written and as served, by token.
	deferred  map[string]deferredScript
	indexTmpl string
	// renderedPage is indexTmpl with its asset URLs filled in, comments and
	// all, for the tests that read the front end as its source; servedPage is
	// it as it goes over the wire, its comments removed (htmlstrip.go), or
	// renderedPage itself if the stripper declined.
	renderedPage string
	servedPage   string
	glassesTmpl  string
}

// deferredScript is one of deferredScripts, as written and as served (its
// whole-line comments removed, or as written if the stripper declined).
type deferredScript struct {
	raw, served string
}

// loadAssets builds the asset set on first use and reuses it forever after.
//
// It is deliberately lazy rather than a package `init()`: pkg/ui is linked
// into every cloop subcommand, and gzipping ~400 KiB of JS at BestCompression
// would tax `cloop status` for something only `cloop ui` ever reads. Server
// startup warms it (see Server.Handler) so no HTTP request pays the cost.
var loadAssets = sync.OnceValue(buildAssets)

// buildAssets reads, hashes and compresses every asset.
//
// A read error here means the embedded filesystem does not contain a path
// listed above, which is a build-time mistake that no request can recover
// from — there is no dashboard to degrade to. It panics with the offending
// path; TestStaticAssets_BundleCoversEveryFragment makes that unreachable in
// a binary that passed CI, and panicRecoveryMiddleware turns it into a logged
// 500 rather than a dead process if one ever ships.
func buildAssets() *assetSet {
	read := mustReadAsset

	var bundle bytes.Buffer
	for _, f := range bundleFiles {
		bundle.Write(read(f))
	}

	css := read("assets/app.css")
	boundary := read("assets/js/errboundary.js")
	chart := read("assets/chart.umd.min.js")
	indexTmpl := read("assets/index.html")

	glassesTmpl := read("assets/glasses.html")

	// Comments are for maintainers, not for every browser that paints the
	// dashboard; they were over a third of its script's wire bytes, and of its
	// stylesheet's. Each stripper refuses anything it cannot prove unchanged,
	// and then that asset ships as written — see jsstrip.go and cssstrip.go.
	served, stripErr := stripJSLineComments(bundle.String())
	if stripErr != nil {
		fmt.Fprintf(os.Stderr, "ui: serving the dashboard script with its comments: %v\n", stripErr)
	}
	servedCSS, cssErr := stripCSSComments(string(css))
	if cssErr != nil {
		fmt.Fprintf(os.Stderr, "ui: serving the dashboard stylesheet with its comments: %v\n", cssErr)
	}
	// The error boundary is first-paint too, and was the one script still
	// shipping its prose: 44% of its bytes were comments (Task 20360).
	servedBoundary, boundaryErr := stripJSLineComments(string(boundary))
	if boundaryErr != nil {
		fmt.Fprintf(os.Stderr, "ui: serving the error boundary with its comments: %v\n", boundaryErr)
	}

	set := &assetSet{
		byPath:         map[string]*staticAsset{},
		icons:          buildIcons(),
		css:            string(css),
		bundle:         bundle.String(),
		served:         served,
		servedCSS:      servedCSS,
		boundary:       string(boundary),
		servedBoundary: servedBoundary,
		indexTmpl:      string(indexTmpl),
		glassesTmpl:    string(glassesTmpl),
	}

	// name → (placeholder token, base file name, content type, bytes).
	hashed := []struct {
		token string
		stem  string
		ext   string
		ctype string
		body  []byte
	}{
		{"app.css", "app", "css", "text/css; charset=utf-8", []byte(servedCSS)},
		{"app.js", "app", "js", jsContentType, []byte(served)},
		{"errboundary.js", "errboundary", "js", jsContentType, []byte(servedBoundary)},
		{"chart.js", "chart", "js", jsContentType, chart},
	}
	set.deferred = make(map[string]deferredScript, len(deferredScripts))
	for _, d := range deferredScripts {
		raw := string(read(d.path))
		served, err := stripJSLineComments(raw)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ui: serving %s with its comments: %v\n", d.path, err)
		}
		set.deferred[d.token] = deferredScript{raw: raw, served: served}
		hashed = append(hashed, struct {
			token string
			stem  string
			ext   string
			ctype string
			body  []byte
		}{d.token, strings.TrimSuffix(d.token, ".js"), "js", jsContentType, []byte(served)})
	}

	page := set.indexTmpl
	for _, h := range hashed {
		url := "/assets/" + h.stem + "." + contentHash(h.body) + "." + h.ext
		a := newStaticAsset(h.ctype, cacheImmutable, h.body)
		set.byPath[url] = a
		page = strings.ReplaceAll(page, "{{asset:"+h.token+"}}", url)
	}

	// And the page's own comments, the last prose on the first paint: 22 KB
	// of index.html, 7 KB gzipped (Task 20363). See htmlstrip.go.
	set.renderedPage = page
	servedPage, pageErr := stripHTMLComments(page)
	if pageErr != nil {
		fmt.Fprintf(os.Stderr, "ui: serving the dashboard page with its comments: %v\n", pageErr)
	}
	set.servedPage = servedPage
	set.page = newStaticAsset("text/html; charset=utf-8", cacheNoCache, []byte(servedPage))
	// no-cache with an ETag, like index.html: the glasses re-open the saved
	// URL on every glance, and a 304 is the cheapest possible answer to "is
	// this still the page I have" without ever serving a stale one.
	set.glasses = newStaticAsset("text/html; charset=utf-8", cacheNoCache, glassesTmpl)
	return set
}

// mustReadAsset returns an embedded asset's bytes, or panics naming the path.
//
// A miss here means the embed directive and the code that reads it disagree,
// which is a build-time mistake no request can recover from — there is no
// dashboard to degrade to. See buildAssets for why a panic is the right answer.
func mustReadAsset(path string) []byte {
	b, err := assetFS.ReadFile(path)
	if err != nil {
		panic(fmt.Sprintf("ui: embedded asset %q is missing: %v", path, err))
	}
	return b
}

// jsContentType is the media type for every script we serve. `text/javascript`
// is the one the HTML spec designates; charset is explicit because the
// dashboard ships non-ASCII glyphs in its labels.
const jsContentType = "text/javascript; charset=utf-8"

// contentHash returns the URL-safe fingerprint used both for the immutable
// asset path and for the ETag. 64 bits of SHA-256 is far past the point where
// an accidental collision between two revisions of the same file is a real
// concern, and keeps the path readable.
func contentHash(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:8])
}

// newStaticAsset precomputes every representation of one asset.
func newStaticAsset(ctype, cache string, raw []byte) *staticAsset {
	a := &staticAsset{
		ctype:    ctype,
		cache:    cache,
		raw:      raw,
		etag:     `"` + contentHash(raw) + `"`,
		contents: string(raw),
	}
	if len(raw) < gzipMinBytes {
		return a
	}
	var buf bytes.Buffer
	zw, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		return a // BestCompression is always a valid level; defensive only
	}
	if _, err := zw.Write(raw); err != nil {
		return a
	}
	if err := zw.Close(); err != nil {
		return a
	}
	// Only keep the compressed copy if it actually saves bytes — already-
	// compressed payloads can grow.
	if buf.Len() >= len(raw) {
		return a
	}
	a.gz = buf.Bytes()
	// A distinct validator per encoding: a cache that stored the gzip
	// representation must not satisfy an identity request from it, and vice
	// versa. This mirrors what nginx's gzip_static does.
	a.gzETag = `"` + strings.Trim(a.etag, `"`) + `-gzip"`
	return a
}

// writeAsset serves one prepared asset, negotiating the encoding and honouring
// a conditional request. Nothing is compressed, hashed or copied here: the
// only per-request work is picking which of two byte slices to write.
func writeAsset(w http.ResponseWriter, r *http.Request, a *staticAsset) {
	body, etag := a.raw, a.etag
	gzipped := a.gz != nil && acceptsGzip(r)
	if gzipped {
		body, etag = a.gz, a.gzETag
	}

	h := w.Header()
	h.Set("Content-Type", a.ctype)
	h.Set("Cache-Control", a.cache)
	h.Set("ETag", etag)
	addVary(h, "Accept-Encoding")
	if gzipped {
		h.Set("Content-Encoding", "gzip")
	}

	if etagMatches(r.Header.Get("If-None-Match"), etag) {
		// RFC 9110 §15.4.5: a 304 carries no body and no Content-Length.
		h.Del("Content-Encoding")
		w.WriteHeader(http.StatusNotModified)
		return
	}

	h.Set("Content-Length", strconv.Itoa(len(body)))
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	_, _ = w.Write(body)
}

// addVary declares an additional request header that the response varies on,
// without clobbering what earlier middleware declared — securityHeaders has
// already set Vary: Origin for the CORS decision, and both criteria have to
// survive. The fields are folded into one header line rather than emitted as
// two, because caches and CDNs in the wild are inconsistent about combining
// repeated field-lines.
func addVary(h http.Header, field string) {
	existing := h.Values("Vary")
	for _, v := range existing {
		for _, f := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(f), field) {
				return
			}
		}
	}
	if len(existing) == 0 {
		h.Set("Vary", field)
		return
	}
	h.Set("Vary", strings.Join(append(existing, field), ", "))
}

// etagMatches implements the weak comparison If-None-Match requires
// (RFC 9110 §13.1.2): the header is a comma-separated list, `*` matches
// anything, and a `W/` prefix is ignored on both sides.
func etagMatches(header, etag string) bool {
	if header == "" {
		return false
	}
	want := strings.TrimPrefix(etag, "W/")
	for _, candidate := range strings.Split(header, ",") {
		candidate = strings.TrimSpace(candidate)
		if candidate == "*" {
			return true
		}
		if strings.TrimPrefix(candidate, "W/") == want {
			return true
		}
	}
	return false
}

// acceptsGzip reports whether the client will take a gzip-encoded response.
//
// RFC 9110 §12.5.3: the most specific match wins, so an explicit `gzip;q=0` is
// a refusal even alongside `*;q=1.0` — which is exactly how a client opts out
// of an encoding the wildcard would otherwise have accepted. Both tokens are
// therefore scored before deciding, rather than returning on the first hit.
func acceptsGzip(r *http.Request) bool {
	const unmentioned = -1.0
	gzipQ, starQ := unmentioned, unmentioned

	for _, part := range strings.Split(r.Header.Get("Accept-Encoding"), ",") {
		token := strings.TrimSpace(part)
		params := ""
		if i := strings.Index(token, ";"); i >= 0 {
			params = strings.TrimSpace(token[i+1:])
			token = strings.TrimSpace(token[:i])
		}
		isGzip := strings.EqualFold(token, "gzip")
		if !isGzip && token != "*" {
			continue
		}
		q := 1.0
		if raw, ok := strings.CutPrefix(params, "q="); ok {
			parsed, err := strconv.ParseFloat(strings.TrimSpace(raw), 64)
			if err != nil {
				continue // unparseable qvalue: ignore this entry entirely
			}
			q = parsed
		}
		if isGzip {
			gzipQ = q
		} else {
			starQ = q
		}
	}

	if gzipQ != unmentioned {
		return gzipQ > 0
	}
	return starQ > 0
}

// handleAsset serves the content-hashed static assets. Only the exact hashed
// paths resolve: an unhashed or stale path is a 404 rather than a redirect, so
// a client can never silently receive a different revision than the HTML it
// loaded named.
func (s *Server) handleAsset(w http.ResponseWriter, r *http.Request) {
	a := loadAssets().byPath[r.URL.Path]
	if a == nil {
		http.NotFound(w, r)
		return
	}
	writeAsset(w, r, a)
}
