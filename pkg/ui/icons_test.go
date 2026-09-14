package ui

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"image/png"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// iconStamp is the digest scripts/build-icons.sh recorded for icon.svg.
//
// Embedded here rather than alongside the icons in static.go because it is
// build metadata, not an asset: no request can ask for it, and the shipped
// binary has no use for it. Only the drift gate below reads it.
//
//go:embed assets/icon.stamp
var iconStamp string

// Tests for the icon set (Task 20228).
//
// The device requirements are the reason most of these exist. Meta Ray-Ban
// Display accepts "Unicode symbols or high-resolution PNG favicons
// (>= 52x52 px) via <link> tags or Web App Manifest. SVGs are not supported."
// None of that is checkable by reading the Go code — it is a property of the
// committed bytes and of two HTML documents — so it is checked here.

// glassesMinIconPx is the floor Meta's web-app guide sets for a PNG icon.
const glassesMinIconPx = 52

// ---------------------------------------------------------------------------
// the committed bytes
// ---------------------------------------------------------------------------

// TestIconsAreInSyncWithTheirSource is the drift gate between icon.svg and the
// rasters generated from it.
//
// //go:embed cannot notice that the mark was edited without `make icons` being
// run, and a stale PNG is exactly the kind of mismatch that survives review
// because nobody opens an image in a diff. scripts/build-icons.sh records the
// source digest; this recomputes it, which catches the drift without needing a
// rasteriser in CI.
func TestIconsAreInSyncWithTheirSource(t *testing.T) {
	t.Parallel()

	sum := sha256.Sum256(mustReadAsset("assets/icon.svg"))
	want := hex.EncodeToString(sum[:])

	var got string
	for _, line := range strings.Split(iconStamp, "\n") {
		if line = strings.TrimSpace(line); line != "" && !strings.HasPrefix(line, "#") {
			got = line
			break
		}
	}
	if got == "" {
		t.Fatal("assets/icon.stamp holds no digest — regenerate it with `make icons`")
	}
	if got != want {
		t.Errorf("icon.svg has changed but the rasters have not been rebuilt.\n"+
			"  icon.stamp: %s\n  icon.svg:   %s\nRun `make icons` and commit the result.", got, want)
	}
}

// TestIconsMeetDisplayGlassesRequirements checks the committed rasters against
// the constraint that motivated shipping rasters at all: the glasses will not
// take an SVG, and will not take a PNG under 52px. A regenerated icon that
// silently came out too small, non-square or in the wrong format would leave a
// blank tile in the launcher with nothing in the logs to say why.
func TestIconsMeetDisplayGlassesRequirements(t *testing.T) {
	t.Parallel()

	rasters := 0
	for _, ic := range iconFiles {
		if ic.ctype != "image/png" {
			continue
		}
		rasters++
		img, err := png.Decode(bytes.NewReader(mustReadAsset(ic.file)))
		if err != nil {
			t.Errorf("%s: declared image/png but does not decode as PNG: %v", ic.path, err)
			continue
		}
		b := img.Bounds()
		switch {
		case b.Dx() != b.Dy():
			t.Errorf("%s is %dx%d — a launcher tile must be square", ic.path, b.Dx(), b.Dy())
		case b.Dx() < glassesMinIconPx:
			t.Errorf("%s is %dpx, below the %dpx floor Meta Ray-Ban Display sets for a PNG icon",
				ic.path, b.Dx(), glassesMinIconPx)
		}
	}
	if rasters < 2 {
		t.Errorf("only %d PNG icon(s) are served; the glasses read <link rel=icon> and "+
			"rel=apple-touch-icon, and both must resolve to a raster", rasters)
	}
}

// TestFaviconIcoCarriesTheBrowserSizes checks the one icon no HTML points at.
// /favicon.ico is probed blind, so if it held a single size the browser would
// be downscaling a 48px bitmap into a 16px tab strip.
func TestFaviconIcoCarriesTheBrowserSizes(t *testing.T) {
	t.Parallel()

	raw := mustReadAsset("assets/favicon.ico")
	if len(raw) < 6 {
		t.Fatal("favicon.ico is too short to hold an ICONDIR header")
	}
	if got := binary.LittleEndian.Uint16(raw[2:4]); got != 1 {
		t.Fatalf("favicon.ico image type = %d, want 1 (icon)", got)
	}
	count := int(binary.LittleEndian.Uint16(raw[4:6]))
	if len(raw) < 6+count*16 {
		t.Fatalf("favicon.ico claims %d entries but is only %d bytes", count, len(raw))
	}

	sizes := map[int]bool{}
	for i := range count {
		e := raw[6+i*16:]
		w := int(e[0]) // 0 encodes 256 in the ICO directory
		if w == 0 {
			w = 256
		}
		sizes[w] = true
	}
	for _, want := range []int{16, 32, 48} {
		if !sizes[want] {
			t.Errorf("favicon.ico has no %dx%d entry (has %v) — run `make icons`", want, want, sizes)
		}
	}
}

// ---------------------------------------------------------------------------
// table, routes and served set agree
// ---------------------------------------------------------------------------

// TestIconTableMatchesServedIcons proves the three derivations of iconFiles
// cannot drift: the map authMiddleware consults, the routes the mux registers,
// and the prepared responses the handler serves.
//
// This is what lets isPublicIcon read a package-level map instead of the built
// asset set — an icon that is reachable without a credential but not actually
// served, or served but not reachable, is caught here rather than in
// production.
func TestIconTableMatchesServedIcons(t *testing.T) {
	t.Parallel()

	served := loadAssets().icons
	srv := &Server{WorkDir: t.TempDir()}

	routed := map[string]bool{}
	for _, rs := range srv.routeTable() {
		if method, path, _ := splitPattern(rs.Pattern); iconPaths[path] {
			if method != http.MethodGet {
				t.Errorf("icon route %q is registered for %s; isPublicIcon only exempts GET and HEAD",
					rs.Pattern, method)
			}
			routed[path] = true
		}
	}

	for _, ic := range iconFiles {
		if !iconPaths[ic.path] {
			t.Errorf("%s is in iconFiles but not in iconPaths — authMiddleware would 401 it", ic.path)
		}
		if !routed[ic.path] {
			t.Errorf("%s is in iconFiles but has no route — it would 404", ic.path)
		}
		a := served[ic.path]
		if a == nil {
			t.Errorf("%s is in iconFiles but was not prepared by buildIcons", ic.path)
			continue
		}
		if a.ctype != ic.ctype {
			t.Errorf("%s is served as %q, want %q", ic.path, a.ctype, ic.ctype)
		}
		// Fixed path, changing bytes: it has to revalidate. Serving an icon
		// immutable would pin a redeployed mark in every browser for a year.
		if a.cache != cacheNoCache {
			t.Errorf("%s is served %q; a non-hashed path must revalidate (%q)", ic.path, a.cache, cacheNoCache)
		}
		if a.etag == "" {
			t.Errorf("%s has no ETag, so every revalidation would refetch the body", ic.path)
		}
	}
	if len(served) != len(iconFiles) {
		t.Errorf("buildIcons prepared %d assets for %d table entries", len(served), len(iconFiles))
	}
}

// ---------------------------------------------------------------------------
// reachability — the point of the whole task
// ---------------------------------------------------------------------------

// TestIconsAreServedWithoutAuthentication is the regression this task turns on.
//
// Under token auth every path except "/" and /glasses answers 401. Nothing that
// fetches an icon sends a credential — a browser probes /favicon.ico with no
// Authorization header, and a display-glasses launcher fetches the tile in a
// request of its own rather than as a subresource of the tokenised page the
// wearer saved. An icon behind auth is therefore not a protected icon, it is
// no icon, in exactly the two places this task exists to fix.
func TestIconsAreServedWithoutAuthentication(t *testing.T) {
	t.Parallel()

	srv := New(t.TempDir(), 0, "a-token-the-client-will-not-send")
	t.Cleanup(srv.closeTokenManager)
	h := srv.Handler()

	for _, ic := range iconFiles {
		t.Run(strings.TrimPrefix(ic.path, "/"), func(t *testing.T) {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, ic.path, nil))

			if rec.Code != http.StatusOK {
				t.Fatalf("GET %s on a token-protected hub = %d, want 200 — no client that "+
					"fetches an icon carries the token", ic.path, rec.Code)
			}
			if got := rec.Header().Get("Content-Type"); got != ic.ctype {
				t.Errorf("Content-Type = %q, want %q (responses carry nosniff, so a wrong "+
					"type is an unrendered icon)", got, ic.ctype)
			}
			if rec.Body.Len() == 0 {
				t.Error("empty body")
			}

			etag := rec.Header().Get("ETag")
			if etag == "" {
				t.Fatal("no ETag: a no-cache icon without one refetches the body on every page load")
			}
			req := httptest.NewRequest(http.MethodGet, ic.path, nil)
			req.Header.Set("If-None-Match", etag)
			rec2 := httptest.NewRecorder()
			h.ServeHTTP(rec2, req)
			if rec2.Code != http.StatusNotModified {
				t.Errorf("conditional GET = %d, want 304", rec2.Code)
			}
		})
	}
}

// TestIconExemptionIsReadOnly keeps the carve-out narrow. isPublicIcon is
// consulted before any credential is checked, so a verb it accepted would be a
// verb reachable by anyone; only a fetch qualifies.
func TestIconExemptionIsReadOnly(t *testing.T) {
	t.Parallel()

	for _, m := range []string{http.MethodGet, http.MethodHead} {
		if !isPublicIcon(httptest.NewRequest(m, "/favicon.ico", nil)) {
			t.Errorf("isPublicIcon(%s /favicon.ico) = false, want true", m)
		}
	}
	for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
		if isPublicIcon(httptest.NewRequest(m, "/favicon.ico", nil)) {
			t.Errorf("isPublicIcon(%s /favicon.ico) = true — the exemption must be read-only", m)
		}
	}
	for _, p := range []string{"/api/state", "/", "/icon-192.png/../api/state", "/favicon.ico/x"} {
		if isPublicIcon(httptest.NewRequest(http.MethodGet, p, nil)) {
			t.Errorf("isPublicIcon(GET %s) = true — only exact icon paths are exempt", p)
		}
	}
}

// ---------------------------------------------------------------------------
// the documents that point at them
// ---------------------------------------------------------------------------

var (
	htmlCommentRe = regexp.MustCompile(`(?s)<!--.*?-->`)
	linkTagRe     = regexp.MustCompile(`<link\s[^>]*>`)
)

// linkTags returns the rel/href pairs of every <link> a browser would act on,
// in source order, along with the raw tag so attributes can be re-read.
//
// Comments are stripped first. Both documents explain their icon choices in
// comments that quote the very tags they are explaining — including, in
// glasses.html, the <link rel="manifest"> it deliberately does not have — and a
// commented-out tag is not a declaration. Without this, every assertion below
// could be satisfied or broken by prose.
func linkTags(doc string) []struct{ rel, href, tag string } {
	var out []struct{ rel, href, tag string }
	doc = htmlCommentRe.ReplaceAllString(doc, "")
	// Attributes are read individually so their order inside a tag is free.
	for _, tag := range linkTagRe.FindAllString(doc, -1) {
		rel := attrValue(tag, "rel")
		href := attrValue(tag, "href")
		if rel == "" || href == "" {
			continue
		}
		out = append(out, struct{ rel, href, tag string }{rel, href, tag})
	}
	return out
}

func attrValue(tag, name string) string {
	m := regexp.MustCompile(name + `="([^"]*)"`).FindStringSubmatch(tag)
	if m == nil {
		return ""
	}
	return m[1]
}

// TestDocumentsDeclareIconsThatResolve catches the dead link. Both documents
// name icons by absolute path, and a typo produces a 404 the browser reports
// nowhere the operator will look and the glasses report not at all.
func TestDocumentsDeclareIconsThatResolve(t *testing.T) {
	t.Parallel()

	assets := loadAssets()
	for name, doc := range map[string]string{
		"index.html":   assets.indexTmpl,
		"glasses.html": assets.glassesTmpl,
	} {
		for _, l := range linkTags(doc) {
			if !strings.Contains(l.rel, "icon") && l.rel != "manifest" {
				continue
			}
			if assets.icons[l.href] == nil {
				t.Errorf("%s declares %s=%q, which is not a served icon path", name, l.rel, l.href)
			}
		}
	}
}

// TestDocumentsLeadWithARasterIcon pins the ordering decision.
//
// Browsers read every declaration and pick by type and size, so order is free
// for them. A launcher that takes the first rel="icon" it parses is not so
// forgiving, and the glasses reject SVG — so if the SVG ever drifts above the
// PNG, the device silently loses its tile. Nothing else would catch that.
func TestDocumentsLeadWithARasterIcon(t *testing.T) {
	t.Parallel()

	assets := loadAssets()
	for name, doc := range map[string]string{
		"index.html":   assets.indexTmpl,
		"glasses.html": assets.glassesTmpl,
	} {
		var first string
		for _, l := range linkTags(doc) {
			if l.rel == "icon" {
				first = l.href
				break
			}
		}
		if first == "" {
			t.Errorf(`%s declares no <link rel="icon">`, name)
			continue
		}
		if a := assets.icons[first]; a == nil || a.ctype != "image/png" {
			t.Errorf(`%s: the first <link rel="icon"> is %q, which is not a PNG. `+
				`Meta Ray-Ban Display rejects SVG, so the raster must come first.`, name, first)
		}
		touch := false
		for _, l := range linkTags(doc) {
			touch = touch || l.rel == "apple-touch-icon"
		}
		if !touch {
			t.Errorf("%s declares no apple-touch-icon; it is one of the two rels the "+
				"display glasses read, and what iOS uses for a home screen tile", name)
		}
	}
}

// TestGlassesPageDoesNotLinkTheManifest guards a footgun rather than a bug.
//
// A manifest declares start_url, and the only URL that works on the glasses is
// the tokenised one the wearer saved. A launcher that honoured start_url would
// relaunch the app at "/" and drop a credential the device has no keyboard to
// re-enter. The wearable gets its icon from <link> tags, which cannot rewrite
// where the app opens; the dashboard, where "/" is correct, links the manifest.
func TestGlassesPageDoesNotLinkTheManifest(t *testing.T) {
	t.Parallel()

	assets := loadAssets()
	linksManifest := func(doc string) bool {
		for _, l := range linkTags(doc) {
			if l.rel == "manifest" {
				return true
			}
		}
		return false
	}
	if linksManifest(assets.glassesTmpl) {
		t.Error("glasses.html links a web app manifest: its start_url would send a " +
			"relaunch to \"/\" without the wearer's token")
	}
	if !linksManifest(assets.indexTmpl) {
		t.Error("index.html no longer links the manifest, so the dashboard is not installable " +
			"and the glasses lose one of their three routes to a PNG")
	}
}

// ---------------------------------------------------------------------------
// the manifest
// ---------------------------------------------------------------------------

// TestManifestIsValidAndHonest parses the manifest the way a launcher does and
// checks it against the bytes actually served. A manifest that names a missing
// icon, or that declares a size its PNG does not have, is a tile that renders
// wrong or not at all — and it fails silently in every client that reads it.
func TestManifestIsValidAndHonest(t *testing.T) {
	t.Parallel()

	var m struct {
		Name      string `json:"name"`
		ShortName string `json:"short_name"`
		StartURL  string `json:"start_url"`
		Icons     []struct {
			Src   string `json:"src"`
			Type  string `json:"type"`
			Sizes string `json:"sizes"`
		} `json:"icons"`
	}
	if err := json.Unmarshal(mustReadAsset("assets/manifest.webmanifest"), &m); err != nil {
		t.Fatalf("manifest is not valid JSON: %v", err)
	}
	if m.Name == "" || m.ShortName == "" {
		t.Error("manifest needs both name and short_name; a launcher labels the tile with one of them")
	}
	if m.StartURL != "/" {
		t.Errorf("start_url = %q, want %q — the dashboard is the installable surface", m.StartURL, "/")
	}
	if len(m.Icons) == 0 {
		t.Fatal("manifest declares no icons, which is the only reason the glasses read it")
	}

	assets := loadAssets()
	big := 0
	for _, ic := range m.Icons {
		a := assets.icons[ic.Src]
		if a == nil {
			t.Errorf("manifest names %q, which is not a served icon", ic.Src)
			continue
		}
		if ic.Type != "image/png" || a.ctype != "image/png" {
			t.Errorf("manifest icon %q is %q; the glasses take PNG only", ic.Src, ic.Type)
			continue
		}
		img, err := png.Decode(bytes.NewReader([]byte(a.contents)))
		if err != nil {
			t.Errorf("manifest icon %q does not decode: %v", ic.Src, err)
			continue
		}
		b := img.Bounds()
		if want := fmt.Sprintf("%dx%d", b.Dx(), b.Dy()); ic.Sizes != want {
			t.Errorf("manifest declares %q for %s but the file is %s", ic.Sizes, ic.Src, want)
		}
		if b.Dx() >= glassesMinIconPx {
			big++
		}
	}
	if big == 0 {
		t.Errorf("no manifest icon reaches the %dpx floor the display glasses require", glassesMinIconPx)
	}
}

// TestDeclaredSizesMatchTheFiles checks the same honesty property for the HTML,
// where a stale sizes="" is just as invisible: a browser trusts the attribute
// when choosing which icon to download and only finds out afterwards.
func TestDeclaredSizesMatchTheFiles(t *testing.T) {
	t.Parallel()

	assets := loadAssets()
	for name, doc := range map[string]string{
		"index.html":   assets.indexTmpl,
		"glasses.html": assets.glassesTmpl,
	} {
		for _, l := range linkTags(doc) {
			a := assets.icons[l.href]
			if a == nil || a.ctype != "image/png" {
				continue // the ICO carries several sizes; the SVG carries none
			}
			sizes := attrValue(l.tag, "sizes")
			if sizes == "" {
				continue
			}
			img, err := png.Decode(bytes.NewReader([]byte(a.contents)))
			if err != nil {
				t.Errorf("%s: %s does not decode: %v", name, l.href, err)
				continue
			}
			b := img.Bounds()
			if want := strconv.Itoa(b.Dx()) + "x" + strconv.Itoa(b.Dy()); sizes != want {
				t.Errorf("%s declares sizes=%q for %s but the file is %s", name, sizes, l.href, want)
			}
		}
	}
}
