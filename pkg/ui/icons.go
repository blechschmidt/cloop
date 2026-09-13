package ui

// Icons for the browser and for Meta Ray-Ban Display glasses (Task 20228).
//
// The hub had no icon at all: a browser tab showed the generic globe, and a
// wearer who added the dashboard to their glasses got a blank tile in the
// launcher with no way to tell one saved app from another.
//
// Three constraints shape everything below.
//
// 1. The glasses will not take an SVG. Meta's web-app guide is explicit —
// "Use Unicode symbols or high-resolution PNG favicons (>= 52x52 px) via
// <link> tags or Web App Manifest. SVGs are not supported." — and it adds that
// "the system checks the Web App manifest and page source (not just
// favicon.ico) for this content". So a lone /favicon.ico is not enough and a
// lone SVG is worse: the icon has to exist as a PNG of at least 52px, reachable
// from a <link> tag or the manifest. That is why the raster sizes start at 180
// and why the SVG is an addition to the PNGs rather than a replacement for them.
//
// 2. Nothing that fetches an icon carries a credential. A browser requests
// /favicon.ico with no Authorization header and no ?token=; the glasses
// launcher fetches the icon in a request of its own, not as a subresource of
// the tokenised page the wearer saved. Under token auth every path except "/"
// and /glasses answers 401 — so icons served like the rest of /assets/ would be
// invisible in exactly the two places this task exists to fix. They are
// therefore served before authentication (see isPublicIcon and
// servedBeforeAuth), which is sound because these bytes are compiled into the
// binary: identical on every deployment, carrying no project, tenant or user
// data, and disclosing only that a cloop hub is listening — which "/" already
// discloses by serving the login page to anyone who asks.
//
// 3. The paths are fixed, not content-hashed. /favicon.ico and
// /apple-touch-icon.png are probed blind at the origin root by clients that
// never parsed our HTML, so they cannot live behind a hash. Fixed path plus
// changing bytes means the response must be revalidated rather than cached
// forever: each icon is no-cache with an ETag, the same bargain index.html
// makes, so a repeat visit costs a 304 and a redeployed mark is never stale.

import (
	"net/http"

	"github.com/blechschmidt/cloop/pkg/authz"
)

// iconFile is one served icon: the URL a client asks for, the embedded file
// behind it, and the media type. Every entry is generated from icon.svg by
// scripts/build-icons.sh except the SVG itself and the manifest.
type iconFile struct {
	path  string // URL path, fixed (see note 3 above)
	file  string // path within assetFS
	ctype string
}

// iconFiles is the complete icon surface. Each entry earns its place:
//
//	/favicon.ico          the URL a browser probes when it has no HTML to go
//	                      on — tab, bookmark, history, feed reader. Holds
//	                      16/32/48 so the browser picks rather than downscales.
//	/icon-192.png         the first <link rel=icon> in both documents, and the
//	                      one the display glasses are expected to take: PNG,
//	                      square, comfortably over their 52px floor.
//	/apple-touch-icon.png iOS home screen, and the second of the two <link>
//	                      rels Meta's guide names. Also probed blind at the
//	                      root by iOS when no tag is present.
//	/icon-512.png         the manifest's install prompt and splash size.
//	/icon.svg             the master, and the best answer for a browser that
//	                      takes it: one file that is crisp at every DPI.
//	/manifest.webmanifest the third route to a PNG for the glasses, and what
//	                      makes the dashboard installable as a PWA.
//
// Content types are explicit because responses carry X-Content-Type-Options:
// nosniff — a wrong or missing type here is a silently unrendered icon rather
// than a mislabelled one that happens to work.
var iconFiles = []iconFile{
	{"/favicon.ico", "assets/favicon.ico", "image/x-icon"},
	{"/icon-192.png", "assets/icon-192.png", "image/png"},
	{"/apple-touch-icon.png", "assets/apple-touch-icon.png", "image/png"},
	{"/icon-512.png", "assets/icon-512.png", "image/png"},
	{"/icon.svg", "assets/icon.svg", "image/svg+xml"},
	{"/manifest.webmanifest", "assets/manifest.webmanifest", "application/manifest+json"},
}

// iconPaths is the lookup isPublicIcon uses. It is derived from the table at
// init rather than read off the built asset set, so the authentication
// decision does not depend on the (lazily built, gzip-compressing) asset
// cache being warm. TestIconTableMatchesServedIcons keeps the two honest.
var iconPaths = func() map[string]bool {
	m := make(map[string]bool, len(iconFiles))
	for _, ic := range iconFiles {
		m[ic.path] = true
	}
	return m
}()

// buildIcons prepares every icon response — bytes, ETag, and the gzip encoding
// where it pays. PNG and ICO payloads are already compressed and newStaticAsset
// drops an encoding that fails to shrink them, so in practice only the SVG and
// the manifest end up with a gzip copy.
func buildIcons() map[string]*staticAsset {
	out := make(map[string]*staticAsset, len(iconFiles))
	for _, ic := range iconFiles {
		out[ic.path] = newStaticAsset(ic.ctype, cacheNoCache, mustReadAsset(ic.file))
	}
	return out
}

// isPublicIcon reports whether the request is for an icon, which is served
// before authentication for the reason given in note 2 at the top of this file.
//
// Narrow on purpose, exactly like isPublicShell: an exact path match from a
// fixed table, and read-only verbs only. A POST to /favicon.ico is not an icon
// fetch and keeps failing closed.
func isPublicIcon(r *http.Request) bool {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return false
	}
	return iconPaths[r.URL.Path]
}

// handleIcon serves one icon. Like handleAsset it does no per-request work:
// every representation was computed once at startup.
func (s *Server) handleIcon(w http.ResponseWriter, r *http.Request) {
	a := loadAssets().icons[r.URL.Path]
	if a == nil {
		// Unreachable: the route table and this map are built from the same
		// iconFiles table, and TestIconTableMatchesServedIcons proves it.
		http.NotFound(w, r)
		return
	}
	writeAsset(w, r, a)
}

// iconRoutes returns one route per icon, for splicing into the route table.
//
// Generated from iconFiles rather than written out entry by entry so that
// adding an icon cannot half-land — a file that is served but unregistered, or
// registered but unserved, is not expressible. The GET prefix means the
// route-drift tests read the accepted verb off the pattern instead of the
// handler body, and it matches isPublicIcon's own verb check.
func (s *Server) iconRoutes() []routeSpec {
	out := make([]routeSpec, 0, len(iconFiles))
	for _, ic := range iconFiles {
		out = append(out, routeSpec{
			Pattern: "GET " + ic.path,
			Handler: s.handleIcon,
			Perm:    authz.PermPublic,
		})
	}
	return out
}
