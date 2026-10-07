package sameorigin

import (
	"mime"
	"net/http"
	"net/netip"
	"strings"
)

// Reason says why a request was admitted or refused. The refusal reasons are
// a closed set, which is what lets them label a metric.
type Reason string

// Admissions.
const (
	// ReasonSafeMethod: GET, HEAD or OPTIONS, which change nothing.
	ReasonSafeMethod Reason = "safe_method"
	// ReasonBearer: the request carries an Authorization: Bearer credential.
	// A page on another origin can attach one only after a CORS preflight,
	// and a hub that grants no preflight never lets it.
	ReasonBearer Reason = "bearer"
	// ReasonSameOrigin: the browser says Sec-Fetch-Site: same-origin.
	ReasonSameOrigin Reason = "same_origin"
	// ReasonUserInitiated: Sec-Fetch-Site: none — the user typed or
	// bookmarked it; no page asked.
	ReasonUserInitiated Reason = "user_initiated"
	// ReasonNoOrigin: neither Sec-Fetch-Site nor Origin — not a browser, or
	// one old enough to send neither on a same-origin request.
	ReasonNoOrigin Reason = "no_origin"
	// ReasonOwnOrigin: no Sec-Fetch-Site, and an Origin exactly equal to one
	// of the hub's own.
	ReasonOwnOrigin Reason = "own_origin"
)

// Refusals.
const (
	// ReasonCrossSite: Sec-Fetch-Site: cross-site — a page on another site.
	ReasonCrossSite Reason = "cross_site"
	// ReasonSameSite: Sec-Fetch-Site: same-site — another origin of the same
	// site: another port of the hub's host, or a sibling subdomain. SameSite
	// cookies are sent to it; this is the case they do not stop.
	ReasonSameSite Reason = "same_site"
	// ReasonUnknownFetchSite: a Sec-Fetch-Site value this check does not
	// know. Refused rather than guessed at.
	ReasonUnknownFetchSite Reason = "unknown_fetch_site"
	// ReasonForeignOrigin: no Sec-Fetch-Site, and an Origin that is not the
	// hub's own — including the opaque origin "null" that sandboxed frames,
	// data: URLs and cross-origin redirects carry.
	ReasonForeignOrigin Reason = "foreign_origin"
	// ReasonMediaType: a body that is neither JSON nor, on the upload routes,
	// multipart form data — what a cross-origin form can send without a
	// preflight.
	ReasonMediaType Reason = "media_type"
	// ReasonUnknownHost: on a hub with no credential, a Host the hub does not
	// answer to — the shape DNS rebinding takes.
	ReasonUnknownHost Reason = "unknown_host"
)

// RefusalReasons is every refusal reason, for a metric's label set and for
// tests.
func RefusalReasons() []Reason {
	return []Reason{ReasonCrossSite, ReasonSameSite, ReasonUnknownFetchSite, ReasonForeignOrigin,
		ReasonMediaType, ReasonUnknownHost}
}

// Verdict is one decision.
type Verdict struct {
	// Allowed reports the request may proceed.
	Allowed bool
	// Reason says why.
	Reason Reason
	// FetchSite is the Sec-Fetch-Site the browser sent, "" when absent.
	FetchSite string
	// Origin is the Origin header as sent, "" when absent.
	Origin string
}

// Unsafe reports a method that can change state: anything but GET, HEAD and
// OPTIONS (RFC 9110 §9.2.1).
func Unsafe(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return false
	}
	return true
}

// HasBearer reports an Authorization header carrying a Bearer credential.
//
// Only Bearer: Basic, Digest and Negotiate are schemes a browser remembers
// and attaches by itself — a reverse proxy asking for Basic auth, or Kerberos
// on an intranet, makes them as ambient as a cookie. A bearer token is only
// ever attached by script, and script on another origin cannot attach it
// without a preflight.
func HasBearer(r *http.Request) bool {
	scheme, cred, ok := strings.Cut(strings.TrimSpace(r.Header.Get("Authorization")), " ")
	return ok && strings.EqualFold(scheme, "Bearer") && strings.TrimSpace(cred) != ""
}

// CheckUnsafe decides whether a state-changing request may proceed, given the
// origins the hub calls its own.
//
//   - A bearer credential admits it (see HasBearer).
//   - Sec-Fetch-Site, which every current browser sends and no page can set,
//     must be same-origin or none.
//   - Without it, an Origin header — which browsers have sent on every POST
//     for longer — must equal one of own exactly, scheme and port included.
//   - With neither, the request is not from a browser that could have been
//     made to send it, and is admitted.
//
// The caller decides which requests are subject to this at all; CheckUnsafe
// admits a safe method without looking further.
func CheckUnsafe(r *http.Request, own []Origin) Verdict {
	v := Verdict{FetchSite: strings.TrimSpace(r.Header.Get("Sec-Fetch-Site")), Origin: strings.TrimSpace(r.Header.Get("Origin"))}
	switch {
	case !Unsafe(r.Method):
		v.Allowed, v.Reason = true, ReasonSafeMethod
		return v
	case HasBearer(r):
		v.Allowed, v.Reason = true, ReasonBearer
		return v
	}
	if v.FetchSite != "" {
		switch strings.ToLower(v.FetchSite) {
		case "same-origin":
			v.Allowed, v.Reason = true, ReasonSameOrigin
		case "none":
			v.Allowed, v.Reason = true, ReasonUserInitiated
		case "same-site":
			v.Reason = ReasonSameSite
		case "cross-site":
			v.Reason = ReasonCrossSite
		default:
			v.Reason = ReasonUnknownFetchSite
		}
		return v
	}
	if v.Origin == "" {
		v.Allowed, v.Reason = true, ReasonNoOrigin
		return v
	}
	if o, err := Parse(v.Origin); err == nil && Contains(own, o) {
		v.Allowed, v.Reason = true, ReasonOwnOrigin
		return v
	}
	v.Reason = ReasonForeignOrigin
	return v
}

// CheckUpgrade decides whether a WebSocket handshake may proceed. A WebSocket
// is exempt from the same-origin policy — a page anywhere may open one to any
// host, cookies included — so its Origin is the only defence: absent, it is
// not a browser (an executor agent, a CLI) and is admitted; present, it must
// equal one of own exactly. Loopback is not special: http://localhost:3000 is
// another origin than a hub on :8080, and any page a developer serves there
// is as foreign to the hub as one on the Internet.
func CheckUpgrade(r *http.Request, own []Origin) Verdict {
	v := Verdict{Origin: strings.TrimSpace(r.Header.Get("Origin")), FetchSite: strings.TrimSpace(r.Header.Get("Sec-Fetch-Site"))}
	if v.Origin == "" {
		v.Allowed, v.Reason = true, ReasonNoOrigin
		return v
	}
	if o, err := Parse(v.Origin); err == nil && Contains(own, o) {
		v.Allowed, v.Reason = true, ReasonOwnOrigin
		return v
	}
	v.Reason = ReasonForeignOrigin
	return v
}

// HostAllowed reports whether a hub with no credential answers to host (a Host
// header value), given the names it was configured with.
//
// Admitted:
//   - no host at all, which no browser sends;
//   - an IP address, any IP address. DNS rebinding needs a *name* the
//     attacker controls to point at the hub; a browser sends an IP-literal
//     Host only to a page whose own origin is that address, which is the hub
//     itself;
//   - localhost and *.localhost, which browsers resolve to loopback without
//     asking DNS (RFC 6761);
//   - an entry of names: a host name (any port) or host:port, compared
//     case-insensitively.
//
// Everything else is a name somebody else's DNS answers for, and a page there
// is same-origin with whatever that name points at.
func HostAllowed(host string, names []string) bool {
	if strings.TrimSpace(host) == "" {
		return true
	}
	h, port, err := SplitHostPort(host)
	if err != nil {
		return false
	}
	h = strings.TrimSuffix(h, ".")
	if _, err := netip.ParseAddr(h); err == nil {
		return true
	}
	if h == "localhost" || strings.HasSuffix(h, ".localhost") {
		return true
	}
	for _, n := range names {
		nh, nport, err := SplitHostPort(n)
		if err != nil {
			continue
		}
		if strings.TrimSuffix(nh, ".") == h && (nport == 0 || nport == port) {
			return true
		}
	}
	return false
}

// IsJSON reports a Content-Type of application/json, with or without
// parameters.
func IsJSON(contentType string) bool {
	return mediaType(contentType) == "application/json"
}

// IsMultipartForm reports a Content-Type of multipart/form-data.
func IsMultipartForm(contentType string) bool {
	return mediaType(contentType) == "multipart/form-data"
}

func mediaType(contentType string) string {
	mt, _, err := mime.ParseMediaType(strings.TrimSpace(contentType))
	if err != nil {
		return ""
	}
	return mt
}
