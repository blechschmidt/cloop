package kms

// The Kubernetes KMS v2 plugin protocol (Task 20433).
//
// A KMS v2 plugin is a gRPC server on a unix socket implementing three calls —
// Status, Encrypt and Decrypt — and nothing else; the vendor's plugin holds the
// credentials to the vendor's KMS. kube-apiserver dials it to wrap the data
// keys etcd's contents are sealed under, and the hub dials it to wrap its
// key-encryption keys, so a hub on a cluster that already runs a plugin for
// its API server reuses the operator's knowledge of it, and a hub elsewhere
// runs the same plugin as a sidecar.
//
// The client is the one k8s.io/kms generates from the protocol's own .proto,
// dialled the way kube-apiserver dials it (grpc_service.go there): plaintext
// gRPC over the socket, authority "localhost". A unix socket and nothing else,
// as the API server insists, because a KMS reached over a network would put
// the keys it unwraps on that network.
//
// # Checks on what comes back
//
// The protocol bounds its own fields (StatusResponse.version is v2 or
// v2beta1, a key id is under 1 kB, a ciphertext under 1 kB, annotations under
// 32 kB), and the client holds the plugin to them: a plugin that answers
// outside them is not one the hub should hand its keys to.

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/backoff"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	kmsapi "k8s.io/kms/apis/v2"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
)

// Bounds the protocol sets on what a plugin returns.
const (
	kmsv2MaxKeyID       = 1 << 10
	kmsv2MaxCiphertext  = 1 << 10
	kmsv2MaxAnnotations = 32 << 10
	// kmsv2MaxMessage bounds what the client accepts at all: every field
	// above, with room for framing.
	kmsv2MaxMessage = 64 << 10
)

type kmsv2Client struct {
	name    string
	socket  string
	timeout time.Duration
	conn    *grpc.ClientConn
	client  kmsapi.KeyManagementServiceClient
}

func newKMSv2(cfg config.KMSConfig) (*kmsv2Client, error) {
	socket, err := config.KMSv2SocketPath(cfg.KMSv2.Endpoint)
	if err != nil {
		return nil, fmt.Errorf("kms: %w", err)
	}
	c := &kmsv2Client{name: cfg.EffectiveName(), socket: socket, timeout: cfg.EffectiveTimeout()}
	conn, err := grpc.NewClient("passthrough:///kms-plugin",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithAuthority("localhost"),
		// Wait for the connection within each call's timeout, as
		// kube-apiserver does: a plugin restarting under a serving hub is
		// waited out, not reported as an outage.
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(kmsv2MaxMessage), grpc.WaitForReady(true)),
		// And reconnect within a second of it coming back. gRPC's default
		// backoff grows to two minutes, during which every call would wait
		// out its timeout against a plugin that has been back for most of it.
		grpc.WithConnectParams(grpc.ConnectParams{
			Backoff: backoff.Config{BaseDelay: 100 * time.Millisecond, Multiplier: 1.6, Jitter: 0.2,
				MaxDelay: time.Second},
			MinConnectTimeout: time.Second,
		}),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			if _, err := checkSocket(socket); err != nil {
				return nil, err
			}
			var d net.Dialer
			return d.DialContext(ctx, "unix", socket)
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("kms: set up the KMS v2 plugin connection to %s: %w", socket, err)
	}
	c.conn = conn
	c.client = kmsapi.NewKeyManagementServiceClient(conn)
	return c, nil
}

// checkSocket refuses a socket anyone on the host could have put there, and
// says whether the plugin is there at all. The hub hands Encrypt a plaintext
// key-encryption key: whoever answers on the socket is sent it, so a socket in
// the host's shared temporary directories — /tmp, /var/tmp, /dev/shm, every one
// world-writable with the sticky bit so that any user may create in it — is one
// an attacker could have bound before the plugin. A world-writable directory
// without the sticky bit is what Kubernetes makes of an emptyDir, which only
// the Pod's own containers can reach; that is where the chart shares the
// socket between the plugin sidecar and the hub. It returns the result the
// failure counts as: unavailable for a plugin that is not there, error for one
// the hub will not talk to.
func checkSocket(socket string) (string, error) {
	dir := filepath.Dir(socket)
	fi, err := os.Stat(dir)
	if err != nil {
		return ResultUnavailable, fmt.Errorf("the KMS plugin socket's directory %s: %w", dir, err)
	}
	if fi.Mode().Perm()&0o002 != 0 && fi.Mode()&os.ModeSticky != 0 {
		return ResultError, fmt.Errorf("the KMS plugin socket %s is in %s, a directory every user on the host shares: "+
			"anyone could have bound it first and been sent every key the hub wraps — give the plugin a "+
			"directory only it and the hub can write", socket, dir)
	}
	st, err := os.Lstat(socket)
	if err != nil {
		return ResultUnavailable, fmt.Errorf("no KMS plugin is listening: the socket %s: %w", socket, err)
	}
	if st.Mode().Type() != os.ModeSocket {
		return ResultError, fmt.Errorf("%s is not a socket (%s)", socket, st.Mode().Type())
	}
	return "", nil
}

// precheck fails a call at once when the plugin is not there, rather than
// leaving gRPC to wait out the timeout for a socket that does not exist.
func (c *kmsv2Client) precheck(op string) error {
	if result, err := checkSocket(c.socket); err != nil {
		return &Error{KMS: c.name, Op: op, Result: result, Err: err}
	}
	return nil
}

func (c *kmsv2Client) Name() string     { return c.name }
func (c *kmsv2Client) Kind() string     { return config.KMSProviderKMSv2 }
func (c *kmsv2Client) Describe() string { return "the KMS v2 plugin at unix://" + c.socket }
func (c *kmsv2Client) Close() error     { return c.conn.Close() }

// fail classifies a gRPC error into an *Error.
func (c *kmsv2Client) fail(op string, err error) error {
	result := ResultError
	switch status.Code(err) {
	case codes.Unavailable:
		result = ResultUnavailable
	case codes.DeadlineExceeded:
		result = ResultTimeout
	case codes.PermissionDenied, codes.Unauthenticated:
		result = ResultDenied
	case codes.InvalidArgument, codes.FailedPrecondition, codes.NotFound, codes.OutOfRange:
		result = ResultInvalid
	case codes.Canceled:
		result = unreachable(err)
	}
	msg := err.Error()
	if st, ok := status.FromError(err); ok {
		msg = st.Message()
		if msg == "" {
			msg = st.Code().String()
		}
	}
	return &Error{KMS: c.name, Op: op, Result: result, Err: fmt.Errorf("%s", truncate(msg, 300))}
}

func (c *kmsv2Client) invalid(op, format string, args ...any) error {
	return &Error{KMS: c.name, Op: op, Result: ResultError, Err: fmt.Errorf(format, args...)}
}

// Status asks the plugin whether it is serving, and which key it encrypts
// under.
func (c *kmsv2Client) Status(ctx context.Context) (st Status, err error) {
	start := time.Now()
	defer func() { observe(config.KMSProviderKMSv2, OpStatus, start, err) }()
	if err = c.precheck(OpStatus); err != nil {
		return Status{}, err
	}
	ctx, cancel := withTimeout(ctx, c.timeout)
	defer cancel()
	resp, err := c.client.Status(ctx, &kmsapi.StatusRequest{})
	if err != nil {
		return Status{}, c.fail(OpStatus, err)
	}
	st = Status{Version: resp.GetVersion(), Healthz: resp.GetHealthz(), KeyID: resp.GetKeyId()}
	switch {
	case st.Version != "v2" && st.Version != "v2beta1":
		return st, c.invalid(OpStatus, "the plugin speaks version %q, not v2", truncate(st.Version, 40))
	case len(st.KeyID) > kmsv2MaxKeyID:
		return st, c.invalid(OpStatus, "the plugin's key id is %d bytes, past the protocol's 1 kB", len(st.KeyID))
	case st.Healthz != "ok":
		// The plugin answered and says it is not serving: as unreachable as
		// a plugin that did not answer, for everything the hub needs of it.
		return st, &Error{KMS: c.name, Op: OpStatus, Result: ResultUnavailable,
			Err: fmt.Errorf("the plugin reports healthz %q", truncate(st.Healthz, 200))}
	case st.KeyID == "":
		return st, c.invalid(OpStatus, "the plugin reports no key id")
	}
	st.Healthy = true
	return st, nil
}

// CurrentKeyID is the key the plugin encrypts under now.
func (c *kmsv2Client) CurrentKeyID(ctx context.Context) (string, error) {
	st, err := c.Status(ctx)
	if err != nil {
		return "", err
	}
	return st.KeyID, nil
}

// Encrypt wraps plaintext.
func (c *kmsv2Client) Encrypt(ctx context.Context, plaintext []byte) (out secretbroker.KMSCiphertext, err error) {
	start := time.Now()
	defer func() { observe(config.KMSProviderKMSv2, OpEncrypt, start, err) }()
	if err = c.precheck(OpEncrypt); err != nil {
		return out, err
	}
	ctx, cancel := withTimeout(ctx, c.timeout)
	defer cancel()
	resp, err := c.client.Encrypt(ctx, &kmsapi.EncryptRequest{Plaintext: plaintext, Uid: uuid.NewString()})
	if err != nil {
		return out, c.fail(OpEncrypt, err)
	}
	out = secretbroker.KMSCiphertext{
		KeyID:       resp.GetKeyId(),
		Ciphertext:  append([]byte(nil), resp.GetCiphertext()...),
		Annotations: resp.GetAnnotations(),
	}
	switch {
	case len(out.Ciphertext) == 0:
		return secretbroker.KMSCiphertext{}, c.invalid(OpEncrypt, "the plugin returned an empty ciphertext")
	case len(out.Ciphertext) > kmsv2MaxCiphertext:
		return secretbroker.KMSCiphertext{}, c.invalid(OpEncrypt,
			"the plugin returned a %d-byte ciphertext, past the protocol's 1 kB", len(out.Ciphertext))
	case out.KeyID == "" || len(out.KeyID) > kmsv2MaxKeyID:
		return secretbroker.KMSCiphertext{}, c.invalid(OpEncrypt, "the plugin returned a key id of %d bytes", len(out.KeyID))
	}
	if err := checkAnnotations(out.Annotations); err != nil {
		return secretbroker.KMSCiphertext{}, c.invalid(OpEncrypt, "%v", err)
	}
	return out, nil
}

// Decrypt unwraps what Encrypt returned.
func (c *kmsv2Client) Decrypt(ctx context.Context, in secretbroker.KMSCiphertext) (out []byte, err error) {
	start := time.Now()
	defer func() { observe(config.KMSProviderKMSv2, OpDecrypt, start, err) }()
	if err = c.precheck(OpDecrypt); err != nil {
		return nil, err
	}
	ctx, cancel := withTimeout(ctx, c.timeout)
	defer cancel()
	resp, err := c.client.Decrypt(ctx, &kmsapi.DecryptRequest{
		Ciphertext:  in.Ciphertext,
		Uid:         uuid.NewString(),
		KeyId:       in.KeyID,
		Annotations: in.Annotations,
	})
	if err != nil {
		return nil, c.fail(OpDecrypt, err)
	}
	pt := resp.GetPlaintext()
	out = append([]byte(nil), pt...)
	for i := range pt {
		pt[i] = 0
	}
	if len(out) == 0 {
		return nil, c.invalid(OpDecrypt, "the plugin returned an empty plaintext")
	}
	return out, nil
}

// checkAnnotations holds annotations to the protocol's rules: keys are domain
// names, and keys and values together stay under 32 kB.
func checkAnnotations(m map[string][]byte) error {
	total := 0
	for k, v := range m {
		total += len(k) + len(v)
		if !fqdn(k) {
			return fmt.Errorf("the plugin returned an annotation key %q that is not a domain name", truncate(k, 80))
		}
	}
	if total > kmsv2MaxAnnotations {
		return fmt.Errorf("the plugin returned %d bytes of annotations, past the protocol's 32 kB", total)
	}
	return nil
}

// fqdn reports whether s is a fully qualified domain name in the sense the
// protocol asks of an annotation key (RFC 1123 labels, at least two).
func fqdn(s string) bool {
	s = strings.TrimSuffix(s, ".")
	if len(s) == 0 || len(s) > 253 {
		return false
	}
	labels := strings.Split(s, ".")
	if len(labels) < 2 {
		return false
	}
	for _, l := range labels {
		if len(l) == 0 || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for _, r := range l {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
				return false
			}
		}
	}
	return true
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
