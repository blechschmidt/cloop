package deviceforward

// forwarder.go is the edge side: the process that runs on the on-prem machine
// and does nothing but bridge one device to the hub.
//
// It is the executor agent's shape with everything but the transport removed.
// It dials OUT and holds one authenticated WebSocket open, so it works behind
// NAT with no inbound rule. It reconnects forever with capped backoff. What it
// does NOT have is any of the agent's machinery for running work: no harness,
// no workspace, no sandbox, no project. When the hub opens a channel it opens
// its one device and copies bytes, and that is the entire behaviour. That
// narrowness is the feature — it is what makes a forwarder safe to put on a
// machine the cloud is not otherwise trusted to reach into.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/coder/websocket"

	"github.com/blechschmidt/cloop/pkg/tlsconf"
)

// DialFunc opens a frame connection to a server, for tests to substitute an
// in-memory transport. token is the credential or enrollment token to present.
type DialFunc func(ctx context.Context, server, token string) (frameConn, error)

// ForwarderConfig configures a forwarder.
type ForwarderConfig struct {
	// Server is the full wss://host/api/forwarders/connect URL.
	Server string
	// Token is a bare enrollment token, used only until a credential is saved.
	Token string
	// Bundle, if set, supplies Server/Token/Pin together (explicit fields win).
	Bundle string
	// CredentialPath is where the long-lived credential is saved and loaded.
	CredentialPath string
	// Pin is the hub's SPKI fingerprint; CAFile an extra root; Insecure allows
	// plaintext to a non-loopback host (refused by default).
	Pin      string
	CAFile   string
	Insecure bool
	// Source is the on-prem device endpoint. Required.
	Source LocalSource
	// AgentVersion is the build string reported in the hello.
	AgentVersion string
	// Logf receives operational messages. Nil discards them.
	Logf func(format string, args ...any)
	// Dial overrides the transport, for tests.
	Dial DialFunc
}

func (c ForwarderConfig) logf(format string, args ...any) {
	if c.Logf != nil {
		c.Logf(format, args...)
	}
}

// Forwarder is a running edge forwarder.
type Forwarder struct {
	cfg    ForwarderConfig
	client *http.Client

	insecureWarning string
	pinned          bool
	pinDescription  string
}

// NewForwarder validates the configuration and builds the transport. Every
// failure here is an operator-fixable misconfiguration, so they are reported
// now rather than discovered inside a reconnect loop that would retry forever.
func NewForwarder(cfg ForwarderConfig) (*Forwarder, error) {
	if cfg.Source == nil {
		return nil, fmt.Errorf("deviceforward: a forwarder needs a device source")
	}
	if _, err := cfg.Source.Device().Normalize(); err != nil {
		return nil, err
	}
	// Apply the bundle, then let explicit fields win.
	if strings.TrimSpace(cfg.Bundle) != "" {
		b, err := DecodeBundle(cfg.Bundle)
		if err != nil {
			return nil, err
		}
		if strings.TrimSpace(cfg.Server) == "" {
			cfg.Server = b.Server
		}
		if strings.TrimSpace(cfg.Token) == "" {
			cfg.Token = b.Token
		}
		if strings.TrimSpace(cfg.Pin) == "" {
			cfg.Pin = b.Pin
		}
	}
	f := &Forwarder{cfg: cfg}
	if cfg.Dial == nil {
		if err := f.resolveTransport(); err != nil {
			return nil, err
		}
	}
	return f, nil
}

// resolveTransport mirrors the agent's: refuse plaintext to a non-loopback
// host, refuse a pin on a non-TLS URL, and build the pinned client once.
func (f *Forwarder) resolveTransport() error {
	ep, warning, err := tlsconf.CheckEndpoint(f.cfg.Server, f.cfg.Insecure)
	if err != nil {
		return fmt.Errorf("deviceforward: %w", err)
	}
	f.insecureWarning = warning
	pins, err := tlsconf.ParsePinSet(f.cfg.Pin)
	if err != nil {
		return fmt.Errorf("deviceforward: --pin: %w", err)
	}
	if !pins.Empty() && !ep.Secure {
		return fmt.Errorf("deviceforward: --pin was given but %s is not a TLS URL, so there is no "+
			"certificate to pin; use wss:// to make the pin meaningful", ep.URL.Redacted())
	}
	tlsCfg, err := tlsconf.ClientConfig(tlsconf.ClientOptions{Pins: pins, RootCAFile: f.cfg.CAFile})
	if err != nil {
		return fmt.Errorf("deviceforward: %w", err)
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = tlsCfg
	f.client = &http.Client{Transport: transport}
	f.pinned = !pins.Empty()
	f.pinDescription = pins.String()
	return nil
}

// TransportSummary describes the link for startup output.
func (f *Forwarder) TransportSummary() string {
	switch {
	case f.insecureWarning != "":
		return "PLAINTEXT (--insecure-transport)"
	case f.pinned:
		return "TLS, pinned to " + f.pinDescription
	case strings.HasPrefix(strings.ToLower(strings.TrimSpace(f.cfg.Server)), "ws://"),
		strings.HasPrefix(strings.ToLower(strings.TrimSpace(f.cfg.Server)), "http://"):
		return "plaintext (loopback)"
	default:
		return "TLS, verified against the system trust store (no pin)"
	}
}

// Backoff bounds between reconnect attempts.
const (
	minBackoff = 1 * time.Second
	maxBackoff = 30 * time.Second
)

// errDoNotReconnect wraps a reason the forwarder must stop retrying: a revoked
// or structurally invalid credential, which no amount of retrying will fix.
var errDoNotReconnect = errors.New("deviceforward: do not reconnect")

// Run dials the control plane and serves until ctx is cancelled or the
// credential is refused permanently.
func (f *Forwarder) Run(ctx context.Context) error {
	defer func() { _ = f.cfg.Source.Close() }()
	backoff := minBackoff
	for {
		if err := ctx.Err(); err != nil {
			return nil
		}
		err := f.runOnce(ctx)
		if err == nil || ctx.Err() != nil {
			return nil
		}
		if errors.Is(err, errDoNotReconnect) {
			return err
		}
		f.cfg.logf("link lost: %v; retrying in %s", err, backoff)
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(backoff):
		}
		backoff *= 2
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
}

// authToken returns the credential to present: the saved one if present, else
// the enrollment token.
func (f *Forwarder) authToken() (token string, haveCred bool, cred Credential) {
	if c, ok, err := LoadCredential(f.cfg.CredentialPath); err == nil && ok {
		return c.Credential, true, c
	}
	return strings.TrimSpace(f.cfg.Token), false, Credential{}
}

// runOnce completes one connection: dial, handshake, serve.
func (f *Forwarder) runOnce(ctx context.Context) error {
	token, _, _ := f.authToken()
	if token == "" {
		return fmt.Errorf("%w: no credential and no enrollment token", errDoNotReconnect)
	}
	conn, err := f.dial(ctx, token)
	if err != nil {
		return err
	}
	mx := newMux(conn)
	defer mx.shutdown()
	defer conn.Close()

	if err := f.handshake(ctx, conn); err != nil {
		return err
	}
	return f.serve(ctx, conn, mx)
}

// dial opens the frame transport.
func (f *Forwarder) dial(ctx context.Context, token string) (frameConn, error) {
	if f.cfg.Dial != nil {
		return f.cfg.Dial(ctx, f.cfg.Server, token)
	}
	if f.insecureWarning != "" {
		f.cfg.logf("%s", f.insecureWarning)
	}
	dialCtx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()
	ws, resp, err := websocket.Dial(dialCtx, f.cfg.Server, &websocket.DialOptions{
		HTTPClient: f.client,
		HTTPHeader: http.Header{"Authorization": []string{"Bearer " + token}},
	})
	if err != nil {
		if resp != nil && resp.StatusCode == http.StatusUnauthorized {
			return nil, fmt.Errorf("%w: control plane rejected the credential (401); re-enroll",
				errDoNotReconnect)
		}
		return nil, fmt.Errorf("deviceforward: dial %s: %w", f.cfg.Server, err)
	}
	return newWSConn(ws), nil
}

const dialTimeout = 30 * time.Second

// handshake sends the hello and reads the welcome, saving an issued credential.
func (f *Forwarder) handshake(ctx context.Context, conn frameConn) error {
	dev := f.cfg.Source.Device()
	ok, detail, resolved := f.cfg.Source.Probe(ctx)
	hello := HelloPayload{
		Version:      ProtocolVersion,
		Device:       dev,
		AgentVersion: f.cfg.AgentVersion,
		Available:    ok,
		Detail:       detail,
		Resolved:     resolved,
	}
	wctx, cancel := context.WithTimeout(ctx, writeTimeout)
	err := conn.WriteFrame(wctx, Frame{Type: TypeHello, Payload: marshalJSON(hello)})
	cancel()
	if err != nil {
		return fmt.Errorf("deviceforward: send hello: %w", err)
	}

	rctx, rcancel := context.WithTimeout(ctx, sessionTimeout)
	frame, err := conn.ReadFrame(rctx)
	rcancel()
	if err != nil {
		return fmt.Errorf("deviceforward: read welcome: %w", err)
	}
	if frame.Type == TypeBye {
		var bye ByePayload
		_ = unmarshalJSON(frame.Payload, &bye)
		if !bye.Reconnect {
			return fmt.Errorf("%w: control plane: %s", errDoNotReconnect, bye.Reason)
		}
		return fmt.Errorf("deviceforward: control plane ended the session: %s", bye.Reason)
	}
	if frame.Type != TypeWelcome {
		return fmt.Errorf("%w: expected welcome, got frame type %d", ErrProtocol, frame.Type)
	}
	var w WelcomePayload
	if err := unmarshalJSON(frame.Payload, &w); err != nil {
		return err
	}
	if strings.TrimSpace(w.Credential) != "" {
		cred := Credential{
			Server:      f.cfg.Server,
			ForwarderID: w.ForwarderID,
			Credential:  w.Credential,
			Name:        dev.DefaultLabel(),
			Device:      dev,
			Pin:         f.cfg.Pin,
		}
		if err := SaveCredential(f.cfg.CredentialPath, cred); err != nil {
			// The credential is in hand but could not be saved: next reconnect
			// has no token, so refuse to continue rather than loop forever.
			return fmt.Errorf("%w: enrolled as %s but could not save the credential to %s: %v",
				errDoNotReconnect, w.ForwarderID, f.cfg.CredentialPath, err)
		}
		f.cfg.logf("enrolled as %s; credential saved to %s", w.ForwarderID, f.cfg.CredentialPath)
	}
	f.cfg.logf("connected as %s (protocol v%d)", w.ForwarderID, w.Version)
	return nil
}

// serve runs the frame loop until the connection ends.
func (f *Forwarder) serve(ctx context.Context, conn frameConn, mx *mux) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Heartbeat: a ping on a cadence so the hub can tell a live but idle
	// forwarder from a dead one.
	go func() {
		t := time.NewTicker(heartbeatInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				wctx, wc := context.WithTimeout(ctx, writeTimeout)
				_ = conn.WriteFrame(wctx, Frame{Type: TypePing})
				wc()
			}
		}
	}()

	for {
		rctx, rcancel := context.WithTimeout(ctx, sessionTimeout)
		frame, err := conn.ReadFrame(rctx)
		rcancel()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("deviceforward: read: %w", err)
		}
		switch frame.Type {
		case TypePing:
			wctx, wc := context.WithTimeout(ctx, writeTimeout)
			_ = conn.WriteFrame(wctx, Frame{Type: TypePong})
			wc()
		case TypePong:
			// liveness only
		case TypeOpen:
			go f.handleOpen(ctx, conn, mx, frame.Channel)
		case TypeData:
			mx.deliverData(frame.Channel, frame.Payload)
		case TypeClose:
			mx.deliverClose(frame.Channel)
		case TypeBye:
			var bye ByePayload
			_ = unmarshalJSON(frame.Payload, &bye)
			if !bye.Reconnect {
				return fmt.Errorf("%w: control plane: %s", errDoNotReconnect, bye.Reason)
			}
			return fmt.Errorf("deviceforward: session ended: %s", bye.Reason)
		case TypeError:
			var e ErrorPayload
			_ = unmarshalJSON(frame.Payload, &e)
			f.cfg.logf("control plane error: %s", e.Message)
		default:
			f.cfg.logf("ignoring unexpected frame type %d", frame.Type)
		}
	}
}

// handleOpen opens the local device and splices it to the channel.
func (f *Forwarder) handleOpen(ctx context.Context, conn frameConn, mx *mux, channel uint32) {
	ch, ok := mx.accept(channel)
	if !ok {
		f.sendOpenAck(ctx, conn, channel, false, "channel already in use")
		return
	}
	local, err := f.cfg.Source.Open(ctx)
	if err != nil {
		f.sendOpenAck(ctx, conn, channel, false, err.Error())
		_ = ch.Close()
		f.cfg.logf("open device for channel %d: %v", channel, err)
		return
	}
	f.sendOpenAck(ctx, conn, channel, true, "")
	splice(ch, local)
}

func (f *Forwarder) sendOpenAck(ctx context.Context, conn frameConn, channel uint32, ok bool, msg string) {
	wctx, cancel := context.WithTimeout(ctx, writeTimeout)
	defer cancel()
	_ = conn.WriteFrame(wctx, Frame{
		Type:    TypeOpenAck,
		Channel: channel,
		Payload: marshalJSON(OpenAckPayload{OK: ok, Error: msg}),
	})
}
