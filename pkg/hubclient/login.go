package hubclient

// The device authorization client (RFC 8628) `cloop login` runs.
//
// The terminal generates its session credential before it asks for anything
// and sends only the digest; once a browser approves the code, the hub writes
// the session under the id that digest names (oidcauth.CLISessionID). So the
// token endpoint's success answer carries no secret at all — just the
// session's id, which must be the one this terminal's commitment names, or the
// answer is about somebody else's session and is refused.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/blechschmidt/cloop/pkg/oidcauth"
)

// DeviceCode is the hub's answer to a request for a code (RFC 8628 §3.2).
type DeviceCode struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

// DeviceToken is the hub's answer to the poll that found the code approved.
type DeviceToken struct {
	TokenType   string `json:"token_type"`
	SessionID   string `json:"session_id"`
	ExpiresIn   int    `json:"expires_in"`
	IdleTimeout int    `json:"idle_timeout"`
	Revalidated bool   `json:"revalidated"`
	Identity    struct {
		Sub   string `json:"sub"`
		Email string `json:"email"`
		Name  string `json:"name"`
	} `json:"identity"`
}

// RequestDeviceCode asks the hub for a code, committing to the session
// credential whose digest is credentialHash.
func (c *Client) RequestDeviceCode(ctx context.Context, credentialHash, hostname string) (*DeviceCode, error) {
	var out DeviceCode
	err := c.Do(ctx, http.MethodPost, "/api/device/code", nil,
		map[string]string{"credential_hash": credentialHash, "hostname": hostname}, &out)
	if err != nil {
		var ae *APIError
		if errors.As(err, &ae) && ae.Status == http.StatusNotFound && ae.Code == "unsupported_grant_type" {
			return nil, fmt.Errorf("%s does not offer terminal sign-in: %s", c.Base, ae.Message)
		}
		if errors.As(err, &ae) && ae.Status == http.StatusNotFound {
			return nil, fmt.Errorf("%s answered 404 for the sign-in endpoint: is it a cloop hub, and is it this "+
				"version or newer? (%v)", c.Base, err)
		}
		return nil, err
	}
	if out.DeviceCode == "" || out.UserCode == "" || out.VerificationURI == "" {
		return nil, fmt.Errorf("%s answered the code request without a code", c.Base)
	}
	return &out, nil
}

// Poll errors a terminal can act on.
var (
	// ErrDenied: the code was denied in the browser, or the hub refused it.
	ErrDenied = errors.New("the sign-in was denied")
	// ErrExpired: nobody approved the code in time.
	ErrExpired = errors.New("the code expired before it was approved")
)

// pollUnit is what one second of the device flow's intervals lasts. A
// variable so the package's tests can run the polling contract — five-second
// steps and all — in milliseconds.
var pollUnit = time.Second

// PollDeviceToken polls until the code is approved, denied or expired,
// honouring the interval and slow_down (RFC 8628 §3.5). waiting, if set, is
// called before each sleep with the interval it is about to wait.
func (c *Client) PollDeviceToken(ctx context.Context, code *DeviceCode, waiting func(time.Duration)) (*DeviceToken, error) {
	interval := time.Duration(code.Interval) * pollUnit
	if code.Interval <= 0 {
		interval = time.Duration(oidcauth.DefaultDevicePollInterval/time.Second) * pollUnit
	}
	lifetime := time.Duration(code.ExpiresIn) * pollUnit
	if code.ExpiresIn <= 0 {
		lifetime = time.Duration(oidcauth.DeviceCodeLifetime/time.Second) * pollUnit
	}
	// A little past the code's own lifetime, so the hub — not this clock —
	// is what says it expired.
	deadline := time.Now().Add(lifetime + 30*pollUnit)
	for {
		if waiting != nil {
			waiting(interval)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(interval):
		}
		if time.Now().After(deadline) {
			return nil, ErrExpired
		}
		var out DeviceToken
		err := c.Do(ctx, http.MethodPost, "/api/device/token", nil, map[string]string{
			"grant_type":  oidcauth.DeviceGrantType,
			"device_code": code.DeviceCode,
		}, &out)
		if err == nil {
			return &out, nil
		}
		var ae *APIError
		if !errors.As(err, &ae) {
			// A network failure mid-poll: the code is still good, so keep
			// polling until it is not, rather than abandoning a sign-in the
			// person may be approving right now.
			continue
		}
		switch ae.Code {
		case oidcauth.DeviceErrPending:
			continue
		case oidcauth.DeviceErrSlowDown:
			// RFC 8628: +5 s for this and every later poll, or whatever the
			// hub says, whichever is longer.
			interval += 5 * pollUnit
			if hub := time.Duration(ae.IntervalSeconds) * pollUnit; hub > interval {
				interval = hub
			}
			continue
		case oidcauth.DeviceErrDenied:
			return nil, fmt.Errorf("%w: %s", ErrDenied, ae.Message)
		case oidcauth.DeviceErrExpired:
			return nil, fmt.Errorf("%w: %s", ErrExpired, ae.Message)
		}
		if ae.Status == http.StatusTooManyRequests || ae.Status >= 500 {
			interval += 5 * pollUnit
			continue
		}
		return nil, err
	}
}

// check refuses an answer this terminal could not print or open safely. The
// approval page goes to the desktop's URL opener, which hands a scheme other
// than http(s) to whatever program registered it; and everything printed
// must be text a terminal shows rather than acts on.
func (d *DeviceCode) check() error {
	if strings.TrimSpace(d.DeviceCode) == "" {
		return errors.New("it holds no device code")
	}
	if d.UserCode == "" || len(d.UserCode) > 32 || !plainText(d.UserCode) {
		return errors.New("its user code is not a short line of plain text")
	}
	if err := checkPageURL(d.VerificationURI); err != nil {
		return fmt.Errorf("verification_uri: %w", err)
	}
	if d.VerificationURIComplete != "" {
		if err := checkPageURL(d.VerificationURIComplete); err != nil {
			return fmt.Errorf("verification_uri_complete: %w", err)
		}
	}
	return nil
}

// checkPageURL accepts an approval page URL: absolute http(s), plain text.
func checkPageURL(raw string) error {
	if raw == "" || len(raw) > 2048 || !plainText(raw) {
		return errors.New("not a line of plain text")
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return errors.New("not an http(s) URL")
	}
	return nil
}

// plainText reports whether s is valid UTF-8 of visible characters and
// spaces only: no control or formatting character a terminal would act on.
func plainText(s string) bool {
	if !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if !unicode.IsGraphic(r) {
			return false
		}
	}
	return true
}

// LoginOptions configure one `cloop login`.
type LoginOptions struct {
	// HubURL is the hub to sign in to.
	HubURL string
	// CAFile is a PEM bundle to trust for the hub, kept with the credential.
	CAFile string
	// Hostname is what the terminal calls its machine on the approval page;
	// os.Hostname when empty.
	Hostname string
	// Out receives the instructions: the code and where to enter it.
	Out io.Writer
	// OpenBrowser, when set, is asked to open the approval page.
	OpenBrowser func(url string) error
}

// Login runs the device flow end to end and returns the hub's new entry. It
// does not save it; the caller does, once it has decided where.
func Login(ctx context.Context, opts LoginOptions) (*Hub, error) {
	out := opts.Out
	if out == nil {
		out = io.Discard
	}
	// The commitment is the credential's SHA-256, and sessionID the public id
	// it names: what the hub writes the session under and reports back once
	// it is approved.
	credential, commitment, err := oidcauth.NewCLICredential()
	if err != nil {
		return nil, fmt.Errorf("generate a session credential: %w", err)
	}
	sessionID := oidcauth.CLISessionID(commitment)
	client, err := New(opts.HubURL, opts.CAFile, "")
	if err != nil {
		return nil, err
	}
	host := strings.TrimSpace(opts.Hostname)
	if host == "" {
		host, _ = os.Hostname()
	}
	code, err := client.RequestDeviceCode(ctx, commitment, host)
	if err != nil {
		return nil, err
	}
	if err := code.check(); err != nil {
		return nil, fmt.Errorf("%s answered with a sign-in code this terminal will not show: %w", client.Base, err)
	}

	fmt.Fprintf(out, "To sign this terminal in to %s, open\n\n    %s\n\nand enter the code\n\n    %s\n\n",
		client.Base, code.VerificationURI, code.UserCode)
	if code.VerificationURIComplete != "" {
		fmt.Fprintf(out, "(or open %s)\n\n", code.VerificationURIComplete)
	}
	fmt.Fprintf(out, "Approve it only if the page shows this code. It expires in %s.\n",
		(time.Duration(code.ExpiresIn) * time.Second).Round(time.Second))
	if opts.OpenBrowser != nil && code.VerificationURIComplete != "" {
		if err := opts.OpenBrowser(code.VerificationURIComplete); err != nil {
			fmt.Fprintf(out, "(could not open a browser: %v)\n", err)
		}
	}
	fmt.Fprintln(out, "Waiting for approval…")

	tok, err := client.PollDeviceToken(ctx, code, nil)
	if err != nil {
		return nil, err
	}
	// The hub approved *a* session; it must be the one this terminal holds
	// the credential for. Anything else is an answer about somebody else's.
	if tok.SessionID != sessionID {
		return nil, errors.New("the hub approved a session other than the one this terminal committed to; " +
			"refusing it — run `cloop login` again, and report this to the hub's operator")
	}
	now := time.Now().UTC()
	h := &Hub{
		URL:        client.Base,
		Credential: credential,
		SessionID:  tok.SessionID,
		CAFile:     opts.CAFile,
		Subject:    tok.Identity.Sub,
		Email:      tok.Identity.Email,
		Name:       tok.Identity.Name,
		SignedInAt: now,
		Client:     host,
	}
	if tok.ExpiresIn > 0 {
		h.ExpiresAt = now.Add(time.Duration(tok.ExpiresIn) * time.Second)
	}
	// The hub's view of what the session can do, for the caller to report.
	h.revalidated = tok.Revalidated
	h.idle = time.Duration(tok.IdleTimeout) * time.Second
	return h, nil
}

// LoginNotes are what a fresh session's hub said about it, for `cloop login`
// to tell the person: whether the hub re-checks the session with the identity
// provider, and how long it may go unused.
func (h *Hub) LoginNotes() (revalidated bool, idle time.Duration) {
	return h.revalidated, h.idle
}
