package agent

// transport.go decides how this device talks to its control plane, and
// refuses to talk at all when the answer would be "in the clear, to whoever
// answers DNS".
//
// The threat this addresses is specific to how agents work. A browser session
// is short and a human is watching it; an agent session is unattended, retries
// forever, and carries a credential that is valid for the life of the device.
// So an interception that a person would notice once is, here, a permanent
// foothold: the attacker keeps the credential, and the device keeps coming
// back. Both halves of the mitigation follow from that — plaintext to a
// non-loopback host is refused outright, and TLS is verified against a pin
// that names one specific public key rather than "any certificate the world's
// CAs would sign for this hostname".

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"nhooyr.io/websocket"

	"github.com/blechschmidt/cloop/pkg/executor/remote"
	"github.com/blechschmidt/cloop/pkg/tlsconf"
)

// dialTimeout bounds one connection attempt. A control plane whose TCP accepts
// but never completes the upgrade would otherwise hold the loop indefinitely,
// which looks identical to "connected and idle" from outside.
const dialTimeout = 30 * time.Second

// resolveTransport validates the server URL against the plaintext policy,
// parses the pin set, and builds the HTTP client every dial will reuse.
//
// It runs in New, before any network activity, because every failure mode here
// is a configuration error the operator can fix — and discovering them at dial
// time would mean the reconnect loop retries a misconfiguration forever
// instead of exiting with a message.
func (a *Agent) resolveTransport() error {
	ep, warning, err := tlsconf.CheckEndpoint(a.cfg.Server, a.cfg.InsecureTransport)
	if err != nil {
		return fmt.Errorf("agent: %w", err)
	}
	a.insecureWarning = warning

	pins, err := tlsconf.ParsePinSet(a.cfg.Pin)
	if err != nil {
		return fmt.Errorf("agent: --pin: %w", err)
	}

	// A pin on a plaintext link is not a weaker guarantee, it is no guarantee
	// at all: there is no certificate to compare it against. Say so, rather
	// than letting the operator believe the flag did something.
	if !pins.Empty() && !ep.Secure {
		return fmt.Errorf(
			"agent: --pin was given but %s is not a TLS URL, so there is no certificate to pin.\n"+
				"  Use wss:// (or https://) to make the pin meaningful",
			ep.URL.Redacted())
	}

	tlsCfg, err := tlsconf.ClientConfig(tlsconf.ClientOptions{
		Pins:       pins,
		RootCAFile: a.cfg.RootCAFile,
	})
	if err != nil {
		return fmt.Errorf("agent: %w", err)
	}

	// One Transport for the life of the agent so reconnects reuse the
	// connection pool and the TLS session cache instead of paying a full
	// handshake every time a flaky link flaps.
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = tlsCfg
	a.httpClient = &http.Client{Transport: transport}
	a.pinned = !pins.Empty()
	a.pinDescription = pins.String()
	return nil
}

// TransportSummary describes the agent's transport for startup output.
func (a *Agent) TransportSummary() string {
	switch {
	case a.insecureWarning != "":
		return "PLAINTEXT (--insecure-transport)"
	case a.pinned:
		return fmt.Sprintf("TLS, pinned to %s", a.pinDescription)
	case strings.HasPrefix(strings.ToLower(strings.TrimSpace(a.cfg.Server)), "ws://"),
		strings.HasPrefix(strings.ToLower(strings.TrimSpace(a.cfg.Server)), "http://"):
		return "plaintext (loopback)"
	default:
		return "TLS, verified against the system trust store (no pin)"
	}
}

// dial opens the transport.
func (a *Agent) dial(ctx context.Context, token string) (remote.Conn, error) {
	if a.cfg.Dial != nil {
		return a.cfg.Dial(ctx, a.cfg.Server, token)
	}

	// Repeat the insecure-transport warning on every attempt. A single line at
	// startup scrolls out of a journal within minutes; the whole purpose of
	// requiring an explicit flag is that the resulting exposure stays visible.
	if a.insecureWarning != "" {
		a.cfg.logf("%s", a.insecureWarning)
	}

	dialCtx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()

	conn, resp, err := websocket.Dial(dialCtx, a.cfg.Server, &websocket.DialOptions{
		HTTPClient: a.httpClient,
		HTTPHeader: http.Header{"Authorization": []string{"Bearer " + token}},
	})
	if err != nil {
		if resp != nil {
			switch resp.StatusCode {
			case http.StatusUnauthorized:
				// Distinguished because retrying will fail identically: this
				// is a credential problem, not a connectivity one.
				return nil, fmt.Errorf("%w: control plane rejected the credential (HTTP 401)",
					remote.ErrCredentialInvalid)
			case http.StatusForbidden:
				return nil, fmt.Errorf(
					"control plane refused the connection (HTTP 403); "+
						"check the hub's allowed origins for %s", a.cfg.Server)
			}
		}
		// Surface a pin mismatch as itself. Buried in a generic dial error it
		// reads as a network fault, and the operator restarts things for an
		// hour before finding out the server's key changed.
		if isPinMismatch(err) {
			return nil, fmt.Errorf(
				"refusing to connect to %s: %w.\n"+
					"  Either the control plane rotated its certificate onto a new key "+
					"(re-enroll, or pass the new --pin), or this is not your control plane",
				a.cfg.Server, err)
		}
		return nil, err
	}
	return remote.NewWSConn(conn), nil
}

// isPinMismatch reports whether err came from the pin check.
//
// errors.Is is tried first and is the correct answer whenever every layer
// between crypto/tls and here wrapped with %w. The substring fallback covers
// the layers that do not: the error crosses crypto/tls, net/http and the
// websocket library on its way out, and a single non-wrapping fmt.Errorf
// anywhere in that chain would otherwise turn a pin mismatch back into an
// anonymous dial failure — the exact diagnosis this is here to preserve.
func isPinMismatch(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, tlsconf.ErrPinMismatch) {
		return true
	}
	return strings.Contains(err.Error(), tlsconf.ErrPinMismatch.Error())
}
