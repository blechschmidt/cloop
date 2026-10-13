package approvalnotify

// The guarded sender.
//
// A webhook URL is operator configuration, and the hub posts to it from inside
// its own network — which makes a careless or hostile URL a way to make the hub
// send requests where its operator never meant it to: the cloud metadata
// service, an admin interface on loopback, a service on the internal network.
// So the client below refuses, rather than trusts:
//
//   - anything but https: the URL is a credential for its channel;
//   - a redirect: a 3xx is a failed send, never an instruction to carry the
//     message, and the URL that authorised it, somewhere else;
//   - a proxy from the environment: the address checked must be the address
//     connected to;
//   - a connection to a cloud metadata service, always, and to a loopback,
//     private, link-local or otherwise non-public address unless the webhook's
//     allow_addresses names it. The check runs on the address the socket is
//     about to connect to, after DNS — so a public name that resolves to
//     169.254.169.254, or rebinds to it between two lookups, is refused at
//     the connect;
//   - an unbounded exchange: the whole request has a deadline, the body sent
//     is bounded, and at most a few kilobytes of the answer are read.
//
// Errors never repeat the URL: Go's *url.Error does, and an error is stored and
// logged.

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"syscall"
	"time"

	"github.com/blechschmidt/cloop/pkg/cloudmeta"
	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/egressbroker"
	"github.com/blechschmidt/cloop/pkg/redact"
	"github.com/blechschmidt/cloop/pkg/version"
)

// maxResponseBytes is how much of a webhook's answer is read: enough for any
// acknowledgement, and the rest is never buffered.
const maxResponseBytes = 8 << 10

// ErrMetadataAddress refuses a connection to a cloud metadata service.
var ErrMetadataAddress = errors.New("approvalnotify: refusing to connect to a cloud metadata service")

// ErrBlockedAddress refuses a connection to a non-public address the webhook
// does not allow.
var ErrBlockedAddress = errors.New("approvalnotify: refusing to connect to a non-public address")

// ErrRedirect is a webhook that answered with a redirect.
var ErrRedirect = errors.New("approvalnotify: the webhook answered with a redirect, which is never followed")

// SendError is a failed send. Permanent says retrying the same message cannot
// succeed: the URL, the address or the receiver's answer refuses it.
type SendError struct {
	Status    int
	Permanent bool
	Err       error
}

func (e *SendError) Error() string {
	if e.Status != 0 {
		return fmt.Sprintf("the webhook answered %d: %v", e.Status, e.Err)
	}
	return e.Err.Error()
}

func (e *SendError) Unwrap() error { return e.Err }

// IsPermanent reports whether err is a failed send that retrying cannot fix.
func IsPermanent(err error) bool {
	var se *SendError
	return errors.As(err, &se) && se.Permanent
}

// Client posts to one webhook.
type Client struct {
	allow []netip.Prefix
	http  *http.Client
}

// NewClient builds the client for a webhook: allow are the non-public
// prefixes it may reach, caFile an extra PEM bundle to trust, timeout the
// bound on one POST.
func NewClient(allow []netip.Prefix, caFile string, timeout time.Duration) (*Client, error) {
	if timeout <= 0 {
		timeout = config.NotificationTimeoutDefault
	}
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if caFile != "" {
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		pem, err := readCAFile(caFile)
		if err != nil {
			return nil, err
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("approvalnotify: ca_file %s holds no PEM certificate", caFile)
		}
		tlsCfg.RootCAs = pool
	}
	c := &Client{allow: append([]netip.Prefix(nil), allow...)}
	dialer := &net.Dialer{
		Timeout: timeout,
		Control: func(_, address string, _ syscall.RawConn) error { return c.checkDial(address) },
	}
	c.http = &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			Proxy:                  nil,
			DialContext:            dialer.DialContext,
			TLSClientConfig:        tlsCfg,
			TLSHandshakeTimeout:    timeout,
			ResponseHeaderTimeout:  timeout,
			MaxResponseHeaderBytes: 16 << 10,
			DisableKeepAlives:      true,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	return c, nil
}

// maxCAFileBytes bounds ca_file: a CA bundle is kilobytes, and the system's
// own is well under a megabyte.
const maxCAFileBytes = 1 << 20

// readCAFile reads ca_file, which must be a regular file of at most
// maxCAFileBytes: a device or a FIFO named there would otherwise hold the
// leader's pass, or its memory, on every send.
func readCAFile(path string) ([]byte, error) {
	notRegular := fmt.Errorf("approvalnotify: ca_file %s is not a regular file", path)
	if info, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf("approvalnotify: read ca_file: %w", err)
	} else if !info.Mode().IsRegular() {
		return nil, notRegular
	}
	// Non-blocking, so a FIFO swapped in after the Stat cannot hold the open;
	// the descriptor's own Stat then refuses it.
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("approvalnotify: read ca_file: %w", err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("approvalnotify: read ca_file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, notRegular
	}
	if info.Size() > maxCAFileBytes {
		return nil, fmt.Errorf("approvalnotify: ca_file %s is %d bytes, over %d", path, info.Size(), maxCAFileBytes)
	}
	pem, err := io.ReadAll(io.LimitReader(f, maxCAFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("approvalnotify: read ca_file: %w", err)
	}
	if len(pem) > maxCAFileBytes {
		return nil, fmt.Errorf("approvalnotify: ca_file %s is over %d bytes", path, maxCAFileBytes)
	}
	return pem, nil
}

// CheckAddress is the address rule, on an address about to be connected to:
// never a metadata service, and a non-public address only when allowed.
func CheckAddress(ip netip.Addr, allow []netip.Prefix) error {
	if svc, ok := cloudmeta.LookupDialed(ip); ok {
		return fmt.Errorf("%w: %s is %s", ErrMetadataAddress, ip, svc.Describe())
	}
	reason := egressbroker.BlockReason(ip)
	if reason == "" {
		return nil
	}
	plain, unwrapped := ip.Unmap(), cloudmeta.Unwrap(ip)
	for _, p := range allow {
		if p.Contains(plain) || p.Contains(unwrapped) {
			return nil
		}
	}
	return fmt.Errorf("%w: %s is %s; name it in the webhook's allow_addresses to send there", ErrBlockedAddress, ip, reason)
}

func (c *Client) checkDial(address string) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("approvalnotify: dial address %q: %w", address, err)
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		// Control sees the resolved address; anything else is a dial this
		// package did not expect, and is refused rather than trusted.
		return fmt.Errorf("approvalnotify: dial address %q is not an IP address", address)
	}
	return CheckAddress(ip, c.allow)
}

// Post sends body to rawURL as JSON.
func (c *Client) Post(ctx context.Context, rawURL string, body []byte) error {
	if err := config.ValidateWebhookURL(rawURL); err != nil {
		return &SendError{Permanent: true, Err: err}
	}
	if len(body) > MaxBodyBytes {
		return &SendError{Permanent: true, Err: fmt.Errorf("the message is %d bytes, over %d", len(body), MaxBodyBytes)}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rawURL, bytes.NewReader(body))
	if err != nil {
		return &SendError{Permanent: true, Err: errors.New("the webhook URL does not form a request")}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "cloop/"+version.String())
	resp, err := c.http.Do(req)
	if err != nil {
		return &SendError{Permanent: errors.Is(err, ErrMetadataAddress) || errors.Is(err, ErrBlockedAddress),
			Err: withoutURL(err)}
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseBytes))
	switch code := resp.StatusCode; {
	case code >= 200 && code < 300:
		return nil
	case code >= 300 && code < 400:
		return &SendError{Status: code, Permanent: true, Err: ErrRedirect}
	case code == http.StatusRequestTimeout, code == http.StatusTooEarly, code == http.StatusTooManyRequests, code >= 500:
		return &SendError{Status: code, Err: errors.New(http.StatusText(code))}
	default:
		return &SendError{Status: code, Permanent: true, Err: errors.New(strconv.Itoa(code) + " " + http.StatusText(code))}
	}
}

// withoutURL strips the URL Go's HTTP client puts in its errors — the URL is
// a credential — and scrubs what is left.
func withoutURL(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		err = ue.Err
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return err
	}
	msg := redact.Scrub(err.Error())
	// Keep the sentinel reachable through errors.Is while the text is the
	// scrubbed one.
	for _, s := range []error{ErrMetadataAddress, ErrBlockedAddress} {
		if errors.Is(err, s) {
			return &scrubbed{msg: msg, sentinel: s}
		}
	}
	return errors.New(msg)
}

type scrubbed struct {
	msg      string
	sentinel error
}

func (e *scrubbed) Error() string { return e.msg }
func (e *scrubbed) Unwrap() error { return e.sentinel }
