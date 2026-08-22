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
	"strconv"
	"strings"
	"sync"
)

// assetFS holds the dashboard front end. `assets/js` pulls in the whole
// fragment directory so a new panel file is embedded without touching a
// directive — but it still has to be listed in bundleFiles below to be
// served, and TestStaticAssets_BundleCoversEveryFragment fails if it is not.
//
//go:embed assets/index.html assets/app.css assets/chart.umd.min.js assets/js
var assetFS embed.FS

// bundleFiles is the concatenation order of the main IIFE. The order is
// explicit rather than implied by directory listing so that it is reviewable
// in a diff: 00-core.js opens the IIFE and defines the shared state and
// helpers every later fragment closes over, and 25-replay.js closes it.
//
// The numeric prefixes keep the on-disk order identical to this list.
var bundleFiles = []string{
	"assets/js/00-core.js",
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
	"assets/js/14-settings.js",
	"assets/js/15-voice.js",
	"assets/js/16-chat.js",
	"assets/js/17-assistant.js",
	"assets/js/18-shortcuts.js",
	"assets/js/19-analytics.js",
	"assets/js/20-budget.js",
	"assets/js/21-audit.js",
	"assets/js/22-secrets.js",
	"assets/js/23-executors.js",
	"assets/js/24-mobile-nav.js",
	"assets/js/25-replay.js",
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

	// The individual sources, kept so tests can assert over the whole front
	// end the way they used to assert over the dashboardHTML constant.
	css       string
	bundle    string
	boundary  string
	indexTmpl string
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
	read := func(path string) []byte {
		b, err := assetFS.ReadFile(path)
		if err != nil {
			panic(fmt.Sprintf("ui: embedded asset %q is missing: %v", path, err))
		}
		return b
	}

	var bundle bytes.Buffer
	for _, f := range bundleFiles {
		bundle.Write(read(f))
	}

	css := read("assets/app.css")
	boundary := read("assets/js/errboundary.js")
	chart := read("assets/chart.umd.min.js")
	indexTmpl := read("assets/index.html")

	set := &assetSet{
		byPath:    map[string]*staticAsset{},
		css:       string(css),
		bundle:    bundle.String(),
		boundary:  string(boundary),
		indexTmpl: string(indexTmpl),
	}

	// name → (placeholder token, base file name, content type, bytes).
	hashed := []struct {
		token string
		stem  string
		ext   string
		ctype string
		body  []byte
	}{
		{"app.css", "app", "css", "text/css; charset=utf-8", css},
		{"app.js", "app", "js", jsContentType, bundle.Bytes()},
		{"errboundary.js", "errboundary", "js", jsContentType, boundary},
		{"chart.js", "chart", "js", jsContentType, chart},
	}

	page := set.indexTmpl
	for _, h := range hashed {
		url := "/assets/" + h.stem + "." + contentHash(h.body) + "." + h.ext
		a := newStaticAsset(h.ctype, cacheImmutable, h.body)
		set.byPath[url] = a
		page = strings.ReplaceAll(page, "{{asset:"+h.token+"}}", url)
	}

	set.page = newStaticAsset("text/html; charset=utf-8", cacheNoCache, []byte(page))
	return set
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
