package ui

// Guardrails for the split front end (Task 20174).
//
// Two classes of risk came with moving the dashboard out of a Go string
// constant and into pkg/ui/assets/:
//
//   - Assembly. The browser sees one document made of five files. A fragment
//     dropped from bundleFiles, a placeholder never substituted, or a hashed
//     URL the handler does not serve all produce a page that looks fine to
//     `go build` and is blank in a browser. The tests here walk the served
//     page the way a browser does — parse it, fetch what it references — so
//     none of those can pass CI.
//
//   - Caching. ETags, 304s and pre-compressed representations are easy to get
//     subtly wrong (a body on a 304, a stale validator shared between the
//     identity and gzip encodings, compression happening per request). Those
//     are asserted directly against the HTTP responses.

import (
	"bytes"
	"compress/gzip"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// assetRefRe finds the asset URLs the served page references.
var assetRefRe = regexp.MustCompile(`(?:src|href)="(/assets/[a-zA-Z0-9._-]+)"`)

// fetchDashboard returns a test server plus the body of GET /.
func fetchDashboard(t *testing.T) (*httptest.Server, string) {
	t.Helper()
	s := New(t.TempDir(), 0, "")
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)

	resp, err := http.Get(ts.URL + "/")
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET / = %d, want 200", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read /: %v", err)
	}
	return ts, string(body)
}

// getAsset fetches one URL from ts and fails the test on anything but 200.
func getAsset(t *testing.T, ts *httptest.Server, path string) (*http.Response, []byte) {
	t.Helper()
	resp, err := http.Get(ts.URL + path)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s = %d, want 200", path, resp.StatusCode)
	}
	return resp, body
}

// TestStaticAssets_BundleCoversEveryFragment pins the one thing the compiler
// cannot: that bundleFiles lists exactly the fragments on disk. A new panel
// file that nobody adds to the list is embedded, compiles, and is never
// served — the panel is simply missing at runtime with no error anywhere.
func TestStaticAssets_BundleCoversEveryFragment(t *testing.T) {
	t.Parallel()

	entries, err := fs.ReadDir(assetFS, "assets/js")
	if err != nil {
		t.Fatalf("read assets/js: %v", err)
	}
	onDisk := map[string]bool{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".js") {
			continue
		}
		// errboundary.js is deliberately its own <script>: it must install
		// before the main bundle so a parse error there is still reported.
		if e.Name() == "errboundary.js" {
			continue
		}
		onDisk["assets/js/"+e.Name()] = true
	}

	listed := map[string]bool{}
	for _, f := range bundleFiles {
		if listed[f] {
			t.Errorf("bundleFiles lists %s twice — it would be concatenated twice", f)
		}
		listed[f] = true
		if !onDisk[f] {
			t.Errorf("bundleFiles lists %s, which is not in assets/js", f)
		}
	}
	var missing []string
	for f := range onDisk {
		if !listed[f] {
			missing = append(missing, f)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("%d JS fragment(s) exist in assets/js but are not in bundleFiles "+
			"— they are embedded but never served, so whatever they define is "+
			"missing at runtime:\n  %s\nAdd them to bundleFiles in static.go, in "+
			"the position their numeric prefix implies.",
			len(missing), strings.Join(missing, "\n  "))
	}

	// The order in bundleFiles must match the on-disk numeric prefixes, or the
	// filenames stop being a truthful description of the load order.
	sorted := append([]string(nil), bundleFiles...)
	sort.Strings(sorted)
	for i := range sorted {
		if sorted[i] != bundleFiles[i] {
			t.Errorf("bundleFiles is not in filename order at index %d (%s, want %s) "+
				"— renumber the fragments or reorder the list so the directory "+
				"listing reads in load order", i, bundleFiles[i], sorted[i])
			break
		}
	}
}

// TestStaticAssets_ServedPageIsFullyAssembled walks the served page the way a
// browser does: every asset it references must resolve, no placeholder may
// survive substitution, and the JS the page pulls in must be the whole bundle.
func TestStaticAssets_ServedPageIsFullyAssembled(t *testing.T) {
	ts, page := fetchDashboard(t)

	if strings.Contains(page, "{{asset:") {
		t.Error("the served page still contains an unsubstituted {{asset:…}} " +
			"placeholder — the browser would request that literal path and 404")
	}

	refs := assetRefRe.FindAllStringSubmatch(page, -1)
	if len(refs) < 4 {
		t.Fatalf("served page references %d assets, want at least 4 "+
			"(app.css, chart.js, errboundary.js, app.js)", len(refs))
	}
	var js []string
	for _, m := range refs {
		resp, body := getAsset(t, ts, m[1])
		if len(body) == 0 {
			t.Errorf("%s served an empty body", m[1])
		}
		if strings.HasSuffix(m[1], ".js") {
			js = append(js, string(body))
		}
		if ct := resp.Header.Get("Content-Type"); ct == "" {
			t.Errorf("%s served without a Content-Type", m[1])
		}
	}

	// The bundle the page loads must contain every fragment. A fragment that
	// silently dropped out would take its whole panel with it.
	allJS := strings.Join(js, "\n")
	for _, f := range bundleFiles {
		src, err := assetFS.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		// First non-blank line is the fragment's section banner comment.
		var marker string
		for _, line := range strings.Split(string(src), "\n") {
			if strings.TrimSpace(line) != "" {
				marker = line
				break
			}
		}
		if marker != "" && !strings.Contains(allJS, marker) {
			t.Errorf("fragment %s is not present in the JS the page loads "+
				"(looked for its opening line %q)", f, marker)
		}
	}
}

// TestStaticAssets_ServedPageHasEveryTab is the guardrail the split most
// needed: the HTML and the JS are now different files fetched over different
// requests, so the tab contract spans an asset boundary. Every `<div
// id="tab-X">` panel in the shell must have a `switchTab('X')` entry point in
// the bundle, and every `switchTab('X')` target must have a panel — a mismatch
// is a tab that either cannot be opened or opens onto nothing.
func TestStaticAssets_ServedPageHasEveryTab(t *testing.T) {
	ts, page := fetchDashboard(t)

	var bundle strings.Builder
	for _, m := range assetRefRe.FindAllStringSubmatch(page, -1) {
		if !strings.HasSuffix(m[1], ".js") {
			continue
		}
		_, body := getAsset(t, ts, m[1])
		bundle.Write(body)
		bundle.WriteString("\n")
	}
	js := bundle.String()

	panels := map[string]bool{}
	for _, m := range regexp.MustCompile(`\bid="tab-([a-zA-Z0-9_-]+)"`).
		FindAllStringSubmatch(page, -1) {
		panels[m[1]] = true
	}
	if len(panels) == 0 {
		t.Fatal("the served page contains no tab panels at all")
	}

	// switchTab targets come from both surfaces: the nav buttons live in the
	// HTML, programmatic switches (deep links, keyboard shortcuts) in the JS.
	targets := map[string]bool{}
	for _, m := range regexp.MustCompile(`switchTab\(['"]([a-zA-Z0-9_-]+)['"]\)`).
		FindAllStringSubmatch(page+"\n"+js, -1) {
		targets[m[1]] = true
	}

	var noEntry, noPanel []string
	for p := range panels {
		if !targets[p] {
			noEntry = append(noEntry, p)
		}
	}
	for tgt := range targets {
		if !panels[tgt] {
			noPanel = append(noPanel, tgt)
		}
	}
	sort.Strings(noEntry)
	sort.Strings(noPanel)
	if len(noEntry) > 0 {
		t.Errorf("%d tab panel(s) in the served HTML have no switchTab() entry "+
			"point anywhere — unreachable UI:\n  %s",
			len(noEntry), strings.Join(noEntry, "\n  "))
	}
	if len(noPanel) > 0 {
		t.Errorf("%d switchTab() target(s) have no matching <div id=\"tab-X\"> in "+
			"the served HTML — clicking them is a silent no-op:\n  %s",
			len(noPanel), strings.Join(noPanel, "\n  "))
	}

	// switchTab itself has to be reachable from the inline onclick attributes
	// in the shell, which means it must escape the bundle's IIFE.
	if !strings.Contains(js, "window.switchTab = function") {
		t.Error("window.switchTab is not assigned in the served JS — every nav " +
			"button would throw a ReferenceError")
	}
}

// TestStaticAssets_NoNewInlineScript keeps the CSP story honest. The policy
// still carries 'unsafe-inline' for the pre-paint theme bootstrap that has to
// run before first paint; the split must not have added a second inline
// script, because the goal is to be able to drop 'unsafe-inline' later without
// hunting for stragglers.
func TestStaticAssets_NoNewInlineScript(t *testing.T) {
	_, page := fetchDashboard(t)

	inline := regexp.MustCompile(`<script(?:\s[^>]*)?>`).FindAllStringIndex(page, -1)
	var bodies []string
	for _, loc := range inline {
		rest := page[loc[1]:]
		end := strings.Index(rest, "</script>")
		if end < 0 {
			t.Fatal("unterminated <script> in the served page")
		}
		if body := strings.TrimSpace(rest[:end]); body != "" {
			bodies = append(bodies, body)
		}
	}
	if len(bodies) != 1 {
		t.Fatalf("served page has %d inline <script> block(s), want exactly 1 "+
			"(the pre-paint theme bootstrap). Every other script must be an "+
			"external asset so the CSP can eventually drop 'unsafe-inline'.\n%v",
			len(bodies), bodies)
	}
	if !strings.Contains(bodies[0], "cloop-theme") {
		t.Errorf("the one inline script is not the theme bootstrap:\n%s", bodies[0])
	}
}

// TestStaticAssets_CacheHeaders asserts the two different caching contracts:
// hashed assets are immutable forever, the HTML that names them never is.
func TestStaticAssets_CacheHeaders(t *testing.T) {
	ts, page := fetchDashboard(t)

	resp, err := http.Get(ts.URL + "/")
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	resp.Body.Close()
	if got := resp.Header.Get("Cache-Control"); got != "no-cache" {
		t.Errorf("GET / Cache-Control = %q, want %q — a cached shell would keep "+
			"pointing at the previous deploy's asset hashes", got, "no-cache")
	}
	if resp.Header.Get("ETag") == "" {
		t.Error("GET / has no ETag — every reload would re-download the shell")
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("GET / Content-Type = %q, want text/html…", ct)
	}

	for _, m := range assetRefRe.FindAllStringSubmatch(page, -1) {
		r, _ := getAsset(t, ts, m[1])
		if got := r.Header.Get("Cache-Control"); !strings.Contains(got, "immutable") {
			t.Errorf("%s Cache-Control = %q, want an immutable directive — the "+
				"URL is content-addressed, so it can be cached forever", m[1], got)
		}
		if r.Header.Get("ETag") == "" {
			t.Errorf("%s has no ETag", m[1])
		}
		if !strings.Contains(r.Header.Get("Vary"), "Accept-Encoding") {
			t.Errorf("%s does not Vary on Accept-Encoding — a shared cache could "+
				"hand a gzip body to a client that cannot decode it", m[1])
		}
	}
}

// TestStaticAssets_ConditionalRequestReturns304 exercises the revalidation
// path for both the shell and a hashed asset, in both encodings. A 304 that
// carries a body (or a validator that does not round-trip) makes the whole
// caching layer worse than not having one.
func TestStaticAssets_ConditionalRequestReturns304(t *testing.T) {
	ts, page := fetchDashboard(t)

	paths := []string{"/"}
	for _, m := range assetRefRe.FindAllStringSubmatch(page, -1) {
		paths = append(paths, m[1])
	}

	for _, p := range paths {
		for _, enc := range []string{"", "gzip"} {
			name := p
			if enc != "" {
				name += " (gzip)"
			}
			t.Run(name, func(t *testing.T) {
				req, _ := http.NewRequest(http.MethodGet, ts.URL+p, nil)
				if enc != "" {
					req.Header.Set("Accept-Encoding", enc)
				} else {
					// Stop the transport from adding gzip itself.
					req.Header.Set("Accept-Encoding", "identity")
				}
				first, err := http.DefaultTransport.RoundTrip(req)
				if err != nil {
					t.Fatalf("GET %s: %v", p, err)
				}
				io.Copy(io.Discard, first.Body) //nolint:errcheck
				first.Body.Close()
				etag := first.Header.Get("ETag")
				if etag == "" {
					t.Fatalf("GET %s returned no ETag", p)
				}

				req2, _ := http.NewRequest(http.MethodGet, ts.URL+p, nil)
				req2.Header.Set("Accept-Encoding", req.Header.Get("Accept-Encoding"))
				req2.Header.Set("If-None-Match", etag)
				second, err := http.DefaultTransport.RoundTrip(req2)
				if err != nil {
					t.Fatalf("conditional GET %s: %v", p, err)
				}
				defer second.Body.Close()
				if second.StatusCode != http.StatusNotModified {
					t.Fatalf("conditional GET %s = %d, want 304", p, second.StatusCode)
				}
				body, _ := io.ReadAll(second.Body)
				if len(body) != 0 {
					t.Errorf("304 for %s carried a %d-byte body", p, len(body))
				}
				if ce := second.Header.Get("Content-Encoding"); ce != "" {
					t.Errorf("304 for %s declared Content-Encoding %q for an "+
						"absent body", p, ce)
				}
			})
		}
	}

	// A validator from a different representation must not satisfy the request.
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/", nil)
	req.Header.Set("If-None-Match", `"deadbeefdeadbeef"`)
	resp, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		t.Fatalf("GET / with a stale validator: %v", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body) //nolint:errcheck
	if resp.StatusCode != http.StatusOK {
		t.Errorf("a stale If-None-Match got %d, want 200 — the client would be "+
			"pinned to a version it no longer has", resp.StatusCode)
	}
}

// TestStaticAssets_GzipNegotiation checks the compressed representation is
// correct, is actually smaller, and is only sent to clients that asked for it.
func TestStaticAssets_GzipNegotiation(t *testing.T) {
	ts, page := fetchDashboard(t)

	m := regexp.MustCompile(`src="(/assets/app\.[0-9a-f]+\.js)"`).FindStringSubmatch(page)
	if m == nil {
		t.Fatal("the served page does not reference /assets/app.<hash>.js")
	}
	path := m[1]

	get := func(acceptEncoding string) *http.Response {
		t.Helper()
		req, _ := http.NewRequest(http.MethodGet, ts.URL+path, nil)
		req.Header.Set("Accept-Encoding", acceptEncoding)
		resp, err := http.DefaultTransport.RoundTrip(req)
		if err != nil {
			t.Fatalf("GET %s (Accept-Encoding: %s): %v", path, acceptEncoding, err)
		}
		return resp
	}

	plain := get("identity")
	defer plain.Body.Close()
	raw, _ := io.ReadAll(plain.Body)
	if plain.Header.Get("Content-Encoding") != "" {
		t.Errorf("Accept-Encoding: identity got Content-Encoding %q",
			plain.Header.Get("Content-Encoding"))
	}

	zipped := get("gzip")
	defer zipped.Body.Close()
	if zipped.Header.Get("Content-Encoding") != "gzip" {
		t.Fatalf("Accept-Encoding: gzip got Content-Encoding %q, want gzip",
			zipped.Header.Get("Content-Encoding"))
	}
	gzBody, _ := io.ReadAll(zipped.Body)
	if len(gzBody) >= len(raw) {
		t.Errorf("gzip body (%d bytes) is not smaller than identity (%d bytes)",
			len(gzBody), len(raw))
	}
	zr, err := gzip.NewReader(bytes.NewReader(gzBody))
	if err != nil {
		t.Fatalf("gzip body does not decode: %v", err)
	}
	decoded, err := io.ReadAll(zr)
	if err != nil {
		t.Fatalf("gzip body truncated: %v", err)
	}
	if !bytes.Equal(decoded, raw) {
		t.Error("the gzip representation does not decode to the identity bytes")
	}
	if zipped.Header.Get("ETag") == plain.Header.Get("ETag") {
		t.Error("the gzip and identity representations share an ETag — an " +
			"intermediary could satisfy an identity request from a cached " +
			"gzip body")
	}

	// An explicit refusal must be honoured even though `*` is present.
	refused := get("*;q=1.0, gzip;q=0")
	defer refused.Body.Close()
	io.Copy(io.Discard, refused.Body) //nolint:errcheck
	if ce := refused.Header.Get("Content-Encoding"); ce == "gzip" {
		t.Error("gzip;q=0 was ignored — the client explicitly refused gzip")
	}
}

// TestStaticAssets_UnknownPathIs404 pins that only the exact hashed paths
// resolve. Falling back to an unhashed name would let a client cache a
// non-content-addressed URL under `immutable` and never see a deploy again.
func TestStaticAssets_UnknownPathIs404(t *testing.T) {
	s := New(t.TempDir(), 0, "")
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()

	for _, p := range []string{
		"/assets/app.js",
		"/assets/app.css",
		"/assets/chart.umd.min.js",
		"/assets/js/00-core.js",
		"/assets/",
		"/assets/../server.go",
	} {
		resp, err := http.Get(ts.URL + p)
		if err != nil {
			t.Fatalf("GET %s: %v", p, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404 — only content-hashed paths may "+
				"resolve", p, resp.StatusCode)
		}
	}
}

// TestStaticAssets_ComputedOnce is the performance claim made explicit:
// hashing and compression happen once, so two calls return the identical
// slices rather than equal copies.
func TestStaticAssets_ComputedOnce(t *testing.T) {
	t.Parallel()

	a, b := loadAssets(), loadAssets()
	if a != b {
		t.Fatal("loadAssets rebuilt the asset set — every request would re-gzip " +
			"the whole front end")
	}
	for path, asset := range a.byPath {
		if asset.gz == nil && len(asset.raw) >= gzipMinBytes {
			t.Errorf("%s (%d bytes) has no precomputed gzip representation",
				path, len(asset.raw))
		}
		if !strings.HasPrefix(asset.etag, `"`) || !strings.HasSuffix(asset.etag, `"`) {
			t.Errorf("%s ETag %q is not a quoted entity-tag", path, asset.etag)
		}
	}
	if a.page.gz == nil {
		t.Error("the HTML shell has no precomputed gzip representation")
	}
}

// TestEtagMatches covers the conditional-request comparison directly, including
// the weak-prefix and wildcard forms a proxy may send.
func TestEtagMatches(t *testing.T) {
	t.Parallel()

	cases := []struct {
		header, etag string
		want         bool
	}{
		{"", `"abc"`, false},
		{`"abc"`, `"abc"`, true},
		{`"abc"`, `"def"`, false},
		{`*`, `"abc"`, true},
		{`W/"abc"`, `"abc"`, true},
		{`"abc"`, `W/"abc"`, true},
		{`"xyz", "abc"`, `"abc"`, true},
		{`"xyz",  W/"abc" `, `"abc"`, true},
		{`"xyz", "def"`, `"abc"`, false},
		{`"abc-gzip"`, `"abc"`, false},
	}
	for _, c := range cases {
		if got := etagMatches(c.header, c.etag); got != c.want {
			t.Errorf("etagMatches(%q, %q) = %v, want %v", c.header, c.etag, got, c.want)
		}
	}
}

// TestAcceptsGzip covers the encoding negotiation, especially the q=0 refusal
// that distinguishes "I did not ask" from "I explicitly cannot".
func TestAcceptsGzip(t *testing.T) {
	t.Parallel()

	cases := []struct {
		header string
		want   bool
	}{
		{"", false},
		{"gzip", true},
		{"GZIP", true},
		{"gzip, deflate, br", true},
		{"deflate", false},
		{"*", true},
		{"gzip;q=0", false},
		{"gzip;q=0.0", false},
		{"gzip;q=0.001", true},
		{"gzip;q=1.0", true},
		{"deflate, gzip;q=0.5", true},
		{"identity", false},
		{"*;q=0", false},
	}
	for _, c := range cases {
		r, _ := http.NewRequest(http.MethodGet, "/", nil)
		if c.header != "" {
			r.Header.Set("Accept-Encoding", c.header)
		}
		if got := acceptsGzip(r); got != c.want {
			t.Errorf("acceptsGzip(%q) = %v, want %v", c.header, got, c.want)
		}
	}
}

// TestStaticAssets_BundleParses runs the assembled bundle through a real
// JavaScript parser.
//
// This is the check the split most needed and Go cannot otherwise provide.
// The original constant was not one raw string: it repeatedly broke out of the
// backtick literal to splice in a backtick of its own, because a Go raw string
// cannot contain one. A text-level extraction copies that Go syntax into the
// JS, and the result compiles, embeds, serves with a valid ETag, and passes
// every structural test in this package — while the browser refuses to parse a
// single line of it and the dashboard is a blank page. That is exactly what
// happened during this migration.
//
// It also guards the ongoing risk: a syntax error introduced while editing one
// fragment takes down the whole bundle, since they are concatenated.
//
// Skipped when node is unavailable — the check is worth having where it can
// run, and not worth a JS-engine dependency where it cannot.
func TestStaticAssets_BundleParses(t *testing.T) {
	t.Parallel()

	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed; cannot syntax-check the JS bundle")
	}

	a := loadAssets()
	for _, src := range []struct{ name, js string }{
		{"bundle", a.bundle},
		{"errboundary.js", a.boundary},
	} {
		path := filepath.Join(t.TempDir(), "check.js")
		if err := os.WriteFile(path, []byte(src.js), 0o644); err != nil {
			t.Fatalf("write %s: %v", src.name, err)
		}
		out, err := exec.Command(node, "--check", path).CombinedOutput()
		if err != nil {
			t.Errorf("the served %s is not valid JavaScript — the browser would "+
				"execute none of it:\n%s", src.name, out)
		}
	}
}

// TestStaticAssets_NoGoStringSyntaxLeaked is the cheap, always-on version of
// the parser check above, aimed at the one failure mode this migration
// actually produced: Go's string-concatenation syntax surviving into an asset.
func TestStaticAssets_NoGoStringSyntaxLeaked(t *testing.T) {
	t.Parallel()

	a := loadAssets()
	for _, src := range []struct{ name, body string }{
		{"index.html", a.page.contents},
		{"app.css", a.css},
		{"app.js", a.bundle},
		{"errboundary.js", a.boundary},
	} {
		for _, needle := range []string{"` + \"", "\" + `"} {
			if i := strings.Index(src.body, needle); i >= 0 {
				line := strings.Count(src.body[:i], "\n") + 1
				t.Errorf("%s line %d contains the Go string-concatenation "+
					"sequence %q — an extraction copied Go source syntax into "+
					"a served asset", src.name, line, needle)
			}
		}
	}
}
