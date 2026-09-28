package hubcluster

// peer.go: how one member hands a request to another.
//
// A request that reaches the wrong member — Stop for a run another member
// streams, a login callback for a login another member started — is forwarded
// whole to the member that can answer it, WebSocket upgrades included. The
// owner re-authenticates the caller exactly as if it had been reached
// directly: forwarding moves a request, it does not vouch for it.
//
// What the channel does vouch for is that the forwarder is a member. Each
// forwarded request carries an HMAC over (member, recipient, time, nonce,
// method, URI, client IP) keyed by a secret stored in the control plane. Anyone able to
// read that secret can already rewrite every table the hub trusts, so it adds
// no new place to steal from; what it buys is that a client cannot pretend to
// be a peer — to skip the per-IP rate limit, to claim another client's address
// in the audit trail, or to reach the internal endpoints. The nonce makes a
// captured request single-use within the clock-skew window, and naming the
// recipient makes it useless at any other member: nonces are remembered per
// member, so without it a capture could be replayed once to each of the rest.
//
// The channel does not encrypt. Forwarded requests carry the caller's session
// cookie, so members that talk over a network anyone else can observe should
// advertise https URLs; loopback and pod-to-pod traffic inside one node is the
// case plain HTTP is meant for.

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Header names on a forwarded request.
const (
	HeaderPeer      = "X-Cloop-Peer"
	HeaderPeerTo    = "X-Cloop-Peer-To"
	HeaderPeerTime  = "X-Cloop-Peer-Time"
	HeaderPeerNonce = "X-Cloop-Peer-Nonce"
	HeaderPeerIP    = "X-Cloop-Peer-Client-Ip"
	HeaderPeerSig   = "X-Cloop-Peer-Signature"
	// HeaderPeerHop names the member that answered, on responses, so a
	// client and a test can see where a request was served.
	HeaderServedBy = "X-Cloop-Served-By"
)

// peerKeyMeta is where the shared secret lives in the control plane.
const peerKeyMeta = "cluster.peer_key"

// peerSkew is how far a peer's clock may be from ours.
const peerSkew = 2 * time.Minute

// ErrNotPeer is returned by VerifyPeer for a request with no peer headers.
var ErrNotPeer = errors.New("hubcluster: not a peer request")

// PeerOptions configures the forwarding channel.
type PeerOptions struct {
	// RootCAs verifies https advertise URLs. Nil uses the system pool.
	RootCAs *x509.CertPool
	// ServerName overrides the name certificates are verified against, for
	// members advertised by IP whose certificate names the public host.
	ServerName string
	// Timeout bounds a Call. Forwarded requests are not bounded: they may be
	// WebSockets or event streams that live as long as the client wants.
	Timeout time.Duration
}

type peerChannel struct {
	n         *Node
	key       []byte
	transport *http.Transport
	timeout   time.Duration

	mu     sync.Mutex
	nonces map[string]time.Time
}

func newPeerChannel(n *Node, key []byte, opts PeerOptions) (*peerChannel, error) {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: opts.RootCAs, ServerName: opts.ServerName}
	tr := &http.Transport{
		Proxy:                 nil, // peers are reached directly, never via HTTP_PROXY
		DialContext:           (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSClientConfig:       tlsCfg,
		MaxIdleConnsPerHost:   16,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ExpectContinueTimeout: time.Second,
		ForceAttemptHTTP2:     false,
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	return &peerChannel{n: n, key: key, transport: tr, timeout: timeout, nonces: map[string]time.Time{}}, nil
}

// loadPeerKey returns the control plane's peer secret, creating it on first
// use. Insert-if-absent, so two members starting at once agree on whichever
// key was written first instead of each keeping the one it generated.
func loadPeerKey(store Store) ([]byte, error) {
	if v, ok, err := store.HubMeta(peerKeyMeta); err != nil {
		return nil, fmt.Errorf("hubcluster: read peer key: %w", err)
	} else if ok {
		if key, err := hex.DecodeString(strings.TrimSpace(v)); err == nil && len(key) >= 32 {
			return key, nil
		}
		// An unreadable key is replaced: without one no member can prove
		// itself to another, and nothing else reads this value.
		if err := deleteHubMeta(store, peerKeyMeta); err != nil {
			return nil, err
		}
	}
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return nil, fmt.Errorf("hubcluster: generate peer key: %w", err)
	}
	stored, err := store.SetHubMetaIfAbsent(peerKeyMeta, hex.EncodeToString(buf))
	if err != nil {
		return nil, fmt.Errorf("hubcluster: store peer key: %w", err)
	}
	key, err := hex.DecodeString(strings.TrimSpace(stored))
	if err != nil || len(key) < 32 {
		return nil, fmt.Errorf("hubcluster: the stored peer key is unreadable")
	}
	return key, nil
}

func deleteHubMeta(store Store, key string) error {
	d, ok := store.(interface{ DeleteHubMeta(string) error })
	if !ok {
		return nil
	}
	if err := d.DeleteHubMeta(key); err != nil {
		return fmt.Errorf("hubcluster: reset peer key: %w", err)
	}
	return nil
}

// reloadKey re-reads the peer key after a signature failure: a member that
// raced another at first start may hold the losing key until it looks again.
func (p *peerChannel) reloadKey() bool {
	v, ok, err := p.n.store.HubMeta(peerKeyMeta)
	if err != nil || !ok {
		return false
	}
	key, err := hex.DecodeString(strings.TrimSpace(v))
	if err != nil || len(key) < 32 {
		return false
	}
	p.mu.Lock()
	changed := !bytes.Equal(key, p.key)
	p.key = key
	p.mu.Unlock()
	return changed
}

func (p *peerChannel) currentKey() []byte {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.key
}

func signature(key []byte, member, to, at, nonce, method, uri, clientIP string) string {
	mac := hmac.New(sha256.New, key)
	for _, part := range []string{"cloop-peer-v2", member, to, at, nonce, method, uri, clientIP} {
		mac.Write([]byte(part))
		mac.Write([]byte{0})
	}
	return hex.EncodeToString(mac.Sum(nil))
}

// sign stamps r as coming from this member, for member to, on behalf of
// clientIP.
func (p *peerChannel) sign(r *http.Request, to, clientIP string) {
	nonceBytes := make([]byte, 16)
	_, _ = rand.Read(nonceBytes)
	nonce := hex.EncodeToString(nonceBytes)
	at := strconv.FormatInt(p.n.now().UnixMilli(), 10)
	uri := r.URL.RequestURI()
	r.Header.Set(HeaderPeer, p.n.self.ID)
	r.Header.Set(HeaderPeerTo, to)
	r.Header.Set(HeaderPeerTime, at)
	r.Header.Set(HeaderPeerNonce, nonce)
	r.Header.Set(HeaderPeerIP, clientIP)
	r.Header.Set(HeaderPeerSig, signature(p.currentKey(), p.n.self.ID, to, at, nonce, r.Method, uri, clientIP))
}

// StripPeerHeaders removes anything a client sent that claims to be from a
// peer. Called before signing, so a forwarded request cannot smuggle a claim
// of its own through, and by a server on requests that failed verification.
func StripPeerHeaders(h http.Header) {
	for _, k := range []string{HeaderPeer, HeaderPeerTo, HeaderPeerTime, HeaderPeerNonce, HeaderPeerIP, HeaderPeerSig} {
		h.Del(k)
	}
}

// IsPeerRequest reports whether r claims to come from a peer. It does not
// verify the claim; VerifyPeer does.
func IsPeerRequest(r *http.Request) bool {
	return r != nil && r.Header.Get(HeaderPeer) != ""
}

// PeerCall describes a verified peer request.
type PeerCall struct {
	From     Member
	ClientIP string
}

// VerifyPeer checks a request's peer signature. It returns ErrNotPeer for a
// request that makes no peer claim, and another error for one whose claim is
// false — which the caller must refuse, not treat as an ordinary client.
func (n *Node) VerifyPeer(r *http.Request) (PeerCall, error) {
	if n == nil || n.peer == nil {
		return PeerCall{}, ErrNotPeer
	}
	return n.peer.verify(r)
}

func (p *peerChannel) verify(r *http.Request) (PeerCall, error) {
	member := r.Header.Get(HeaderPeer)
	if member == "" {
		return PeerCall{}, ErrNotPeer
	}
	to := r.Header.Get(HeaderPeerTo)
	at := r.Header.Get(HeaderPeerTime)
	nonce := r.Header.Get(HeaderPeerNonce)
	clientIP := r.Header.Get(HeaderPeerIP)
	sig := r.Header.Get(HeaderPeerSig)
	if to == "" || at == "" || nonce == "" || sig == "" {
		return PeerCall{}, errors.New("hubcluster: incomplete peer signature")
	}
	if to != p.n.self.ID {
		return PeerCall{}, fmt.Errorf("hubcluster: peer request addressed to %s, not this member", to)
	}
	ms, err := strconv.ParseInt(at, 10, 64)
	if err != nil {
		return PeerCall{}, errors.New("hubcluster: malformed peer timestamp")
	}
	now := p.n.now()
	sent := time.UnixMilli(ms)
	if d := now.Sub(sent); d > peerSkew || d < -peerSkew {
		return PeerCall{}, fmt.Errorf("hubcluster: peer request timestamp %s is outside the %s window",
			sent.UTC().Format(time.RFC3339), peerSkew)
	}
	uri := r.URL.RequestURI()
	want := signature(p.currentKey(), member, to, at, nonce, r.Method, uri, clientIP)
	if subtle.ConstantTimeCompare([]byte(want), []byte(sig)) != 1 {
		if !p.reloadKey() {
			return PeerCall{}, errors.New("hubcluster: bad peer signature")
		}
		want = signature(p.currentKey(), member, to, at, nonce, r.Method, uri, clientIP)
		if subtle.ConstantTimeCompare([]byte(want), []byte(sig)) != 1 {
			return PeerCall{}, errors.New("hubcluster: bad peer signature")
		}
	}
	if !p.useNonce(nonce, now) {
		return PeerCall{}, errors.New("hubcluster: replayed peer request")
	}
	if !p.n.IsAlive(member) {
		return PeerCall{}, fmt.Errorf("hubcluster: peer %s is not a live member", member)
	}
	from, _ := p.n.Member(member)
	return PeerCall{From: from, ClientIP: clientIP}, nil
}

// useNonce records a nonce and reports whether it was fresh.
func (p *peerChannel) useNonce(nonce string, now time.Time) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.nonces) > 4096 {
		for k, exp := range p.nonces {
			if now.After(exp) {
				delete(p.nonces, k)
			}
		}
	}
	if exp, seen := p.nonces[nonce]; seen && now.Before(exp) {
		return false
	}
	p.nonces[nonce] = now.Add(2 * peerSkew)
	return true
}

// peerCtxKey marks a request context as served on a peer's behalf.
type peerCtxKey struct{}

// WithPeerCall records a verified peer call in ctx.
func WithPeerCall(ctx context.Context, pc PeerCall) context.Context {
	return context.WithValue(ctx, peerCtxKey{}, pc)
}

// PeerCallFrom returns the verified peer call ctx carries, if any. A handler
// that sees one must answer locally: forwarding it again could loop.
func PeerCallFrom(ctx context.Context) (PeerCall, bool) {
	pc, ok := ctx.Value(peerCtxKey{}).(PeerCall)
	return pc, ok
}

// ErrNoRoute means the target member advertises no URL to reach it by.
var ErrNoRoute = errors.New("hubcluster: member advertises no URL")

func (n *Node) memberURL(to Member) (*url.URL, error) {
	if strings.TrimSpace(to.AdvertiseURL) == "" {
		return nil, fmt.Errorf("%w: %s (set ui.cluster.advertise_url or CLOOP_CLUSTER_ADVERTISE_URL on it)",
			ErrNoRoute, to.ID)
	}
	u, err := url.Parse(to.AdvertiseURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("hubcluster: member %s advertises an unusable URL %q", to.ID, to.AdvertiseURL)
	}
	return u, nil
}

// Forward hands r to member to and copies its response to w, WebSocket
// upgrades included. clientIP is the caller as this member resolved it; the
// owner uses it instead of this member's address. It writes a 502 itself when
// the member cannot be reached, and returns the error so the caller can log.
func (n *Node) Forward(w http.ResponseWriter, r *http.Request, to Member, clientIP string) error {
	if n == nil || n.peer == nil {
		return errors.New("hubcluster: not a cluster member")
	}
	target, err := n.memberURL(to)
	if err != nil {
		writePeerError(w, http.StatusBadGateway, err.Error())
		return err
	}
	var proxyErr error
	rp := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			// Keep the path exactly as the client sent it: SetURL joins the
			// target's own path, which is empty for an advertise URL.
			pr.Out.URL.Path = pr.In.URL.Path
			pr.Out.URL.RawPath = pr.In.URL.RawPath
			pr.Out.URL.RawQuery = pr.In.URL.RawQuery
			// The owner decides same-origin and builds redirect URLs from
			// Host, so it must see the host the client addressed.
			pr.Out.Host = pr.In.Host
			pr.SetXForwarded()
			StripPeerHeaders(pr.Out.Header)
			n.peer.sign(pr.Out, to.ID, clientIP)
		},
		Transport:     n.peer.transport,
		FlushInterval: -1,
		ErrorHandler: func(rw http.ResponseWriter, _ *http.Request, err error) {
			proxyErr = err
			writePeerError(rw, http.StatusBadGateway,
				fmt.Sprintf("the hub member that owns this request (%s) could not be reached: %v", to.ID, err))
		},
	}
	rp.ServeHTTP(w, r)
	return proxyErr
}

// Call makes a JSON request to a peer's internal API: in is sent as the body
// (nil for none) and a 2xx response is decoded into out (nil to discard).
func (n *Node) Call(ctx context.Context, to Member, method, path string, in, out any) error {
	if n == nil || n.peer == nil {
		return errors.New("hubcluster: not a cluster member")
	}
	target, err := n.memberURL(to)
	if err != nil {
		return err
	}
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return fmt.Errorf("hubcluster: encode call: %w", err)
		}
		body = bytes.NewReader(b)
	}
	ctx, cancel := context.WithTimeout(ctx, n.peer.timeout)
	defer cancel()
	u := *target
	u.Path = path
	if i := strings.IndexByte(path, '?'); i >= 0 {
		u.Path, u.RawQuery = path[:i], path[i+1:]
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return fmt.Errorf("hubcluster: build call: %w", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	n.peer.sign(req, to.ID, "")
	resp, err := (&http.Client{Transport: n.peer.transport}).Do(req)
	if err != nil {
		return fmt.Errorf("hubcluster: call %s %s on %s: %w", method, path, to.ID, err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode/100 != 2 {
		msg := strings.TrimSpace(string(data))
		var e struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(data, &e) == nil && e.Error != "" {
			msg = e.Error
		}
		return &CallError{Member: to.ID, Status: resp.StatusCode, Message: msg}
	}
	if out != nil && len(data) > 0 {
		if err := json.Unmarshal(data, out); err != nil {
			return fmt.Errorf("hubcluster: decode reply from %s: %w", to.ID, err)
		}
	}
	return nil
}

// CallError is a non-2xx answer from a peer.
type CallError struct {
	Member  string
	Status  int
	Message string
}

func (e *CallError) Error() string {
	return fmt.Sprintf("hub member %s answered %d: %s", e.Member, e.Status, e.Message)
}

func writePeerError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
