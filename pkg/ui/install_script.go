package ui

// install_script.go serves GET /install.sh: the one-command onboarding path
// for an edge device (Task 20172).
//
// The script itself is thin — it locates a cloop binary and hands off to
// `cloop executor agent install`, where the hardening actually lives (see
// pkg/executor/install). What this handler contributes is the deployment's
// identity: the WebSocket URL agents dial, and the SPKI fingerprint that says
// which server is allowed to answer at it. Both are derived from the request,
// because a hosted hub sits behind a reverse proxy and the URL it calls itself
// in a config file is frequently not the one the operator's browser reached.
//
// Two refusals shape the endpoint:
//
//   - Plaintext is refused outright. This response is piped into a root shell
//     on a device that has not yet decided who to trust. Anyone able to modify
//     it in flight owns the device, and over HTTP that is anyone on the path.
//     There is no loopback exemption: a device that can only reach the hub
//     over loopback does not need an installer.
//   - It is RBAC-gated on executor.manage, the same permission as minting an
//     enrollment token. The script discloses the hub's URL and pin, which is
//     reconnaissance, and it is only useful to someone who can also mint a
//     token to go with it.
//
// The enrollment token is deliberately NOT in the response. The operator
// carries it separately, in CLOOP_ENROLL_BUNDLE, so this endpoint stays
// idempotent, cacheable-by-nobody, and free of anything worth stealing.

import (
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/blechschmidt/cloop/pkg/executor/install"
	"github.com/blechschmidt/cloop/pkg/tlsconf"
)

// installScriptPath is where the bootstrap script is served.
//
// Deliberately at the root rather than under /api: it exists to be typed into
// a `curl` by a human, and `curl https://hub/install.sh` is the shape everyone
// already recognises.
const installScriptPath = "/install.sh"

// handleInstallScript serves the executor-agent bootstrap script.
func (s *Server) handleInstallScript(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requestIsTLS(r) {
		// 403 rather than a redirect: a redirect would be followed silently
		// by curl -L, and the operator would never learn that the first
		// request — the one an attacker could have answered — went in the
		// clear.
		http.Error(w, installScriptPlaintextRefusal, http.StatusForbidden)
		return
	}

	body := install.BootstrapScript(install.BootstrapParams{
		Server: agentConnectURL(r),
		Pin:    s.transportPin(),
	})

	// text/plain, not application/x-sh: an operator who opens the URL in a
	// browser should read the script, not download and lose track of it.
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	// A stale installer would pin a rotated key or name a decommissioned
	// host, and either produces a device that never connects.
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Length", fmt.Sprint(len(body)))
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	_, _ = w.Write([]byte(body))
}

// installScriptPlaintextRefusal explains the refusal in the terminal where it
// lands, since the caller is a shell pipeline and not a browser.
const installScriptPlaintextRefusal = `cloop: refusing to serve install.sh over plaintext HTTP.

This script is piped into a root shell on a device that does not yet know
which control plane to trust. Over HTTP, anyone on the network path can
replace it. Serve the hub over HTTPS — configure ui.tls (or run
` + "`cloop hub tls-init`" + ` for a development certificate), or terminate TLS at a
proxy that sets X-Forwarded-Proto: https.
`

// requestIsTLS reports whether the client's connection to the deployment was
// encrypted.
//
// X-Forwarded-Proto is honoured because the common hosted topology terminates
// TLS at a proxy, leaving r.TLS nil on a request the browser nonetheless made
// over HTTPS. That header is only trustworthy from a trusted proxy — but the
// alternative is refusing to serve every reverse-proxied deployment, and a
// client able to forge the header is already inside the network path this
// check is defending. The same trade-off is made by agentConnectURL.
func requestIsTLS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	proto := strings.TrimSpace(r.Header.Get("X-Forwarded-Proto"))
	if i := strings.Index(proto, ","); i >= 0 {
		// Proxies chain this header; the first entry is the client's leg.
		proto = strings.TrimSpace(proto[:i])
	}
	return strings.EqualFold(proto, "https")
}

// transportPin returns this hub's SPKI fingerprint, or "" when it has no
// certificate of its own.
//
// A failure to read the configured certificate returns "" rather than an
// error: the script says plainly when there is no pin, which is a better
// outcome than a 500 that leaves the operator with no installer at all. The
// same derivation backs `cloop executor enroll`, so the CLI and the dashboard
// cannot disagree about which key a device should expect.
//
// The warning fires once per process. A certificate that cannot be read will
// fail on every request, and a line per request would bury the one that
// explains it.
func (s *Server) transportPin() string {
	cert := strings.TrimSpace(s.TLSCertFile)
	if cert == "" {
		return ""
	}
	pin, err := tlsconf.PinFromCertFile(cert)
	if err != nil {
		pinWarnOnce.Do(func() {
			fmt.Fprintf(os.Stderr,
				"ui: cannot derive an SPKI pin from %s (%v); install.sh and enrollment "+
					"will be served without one\n", cert, err)
		})
		return ""
	}
	return pin
}

// pinWarnOnce keeps the unreadable-certificate warning to one line per process.
var pinWarnOnce sync.Once

// installCommandFor renders the copy-paste snippet the Executors panel shows.
//
// The bundle travels in the environment rather than as an argument: argv is
// world-readable through /proc for the lifetime of the process, so an argument
// form would expose the token to every local user on the device at exactly the
// moment it is still redeemable.
func installCommandFor(r *http.Request, bundle string) string {
	base := externalBaseURL(r)
	return fmt.Sprintf("CLOOP_ENROLL_BUNDLE=%s \\\n  sh -c \"$(curl -fsSL %s%s)\"",
		shellSingleQuote(bundle), base, installScriptPath)
}

// externalBaseURL reconstructs the https:// origin the caller reached, from
// the same forwarded headers agentConnectURL trusts.
func externalBaseURL(r *http.Request) string {
	scheme := "http"
	if requestIsTLS(r) {
		scheme = "https"
	}
	host := r.Host
	if fwd := strings.TrimSpace(r.Header.Get("X-Forwarded-Host")); fwd != "" {
		if i := strings.Index(fwd, ","); i >= 0 {
			fwd = strings.TrimSpace(fwd[:i])
		}
		host = fwd
	}
	if host == "" {
		host = "YOUR-CONTROL-PLANE"
	}
	return scheme + "://" + host
}

// shellSingleQuote makes a value safe to paste into a POSIX shell.
//
// Unconditional quoting, not "quote when it looks risky": the value is a
// base64url blob whose alphabet is safe today, and a conditional rule is one
// encoding change away from emitting a command that does something other than
// what it displays.
func shellSingleQuote(v string) string {
	return "'" + strings.ReplaceAll(v, "'", `'\''`) + "'"
}
