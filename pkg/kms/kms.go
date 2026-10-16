// Package kms connects the secret store's keyring to an external
// key-management service (Task 20433).
//
// The keyring (pkg/secretbroker) can hold a key-encryption key wrapped by a KMS
// instead of deriving it from CLOOP_SECRET_KEY: the record keeps only the KMS's
// ciphertext and key id, and opening the store is a call to the KMS — a call
// the KMS logs and its owner can refuse. This package is the other end of that
// call. It implements secretbroker.KMS twice:
//
//   - kmsv2: the Kubernetes KMS v2 plugin protocol, gRPC over a unix socket.
//     The API server's own envelope encryption speaks it, so one integration
//     reaches Azure Key Vault, AWS KMS, Google Cloud KMS and Vault through the
//     plugins those vendors already ship — deployed as a sidecar beside the hub
//     in the Helm chart. The client is the generated k8s.io/kms/apis/v2 one,
//     so the hub speaks the protocol exactly as kube-apiserver does.
//   - transit: HashiCorp Vault's, or OpenBao's, Transit engine over HTTPS, for
//     a hub with a Vault and no plugin to run.
//
// # What the KMS sees
//
// Thirty-two bytes of key-encryption key on the way in to Encrypt, and the
// ciphertext on the way in to Decrypt. Never a secret, a data key, or a
// payload: those stay sealed under the KEK in the hub's database. The KMS
// can therefore not read the store, and the store cannot be read without it.
//
// # Every call is measured
//
// Each call records cloop_kms_requests_total{backend,operation,result} and
// cloop_kms_request_duration_seconds{backend,operation}, whatever it returns,
// so a slow or failing KMS shows on the hub's metrics before it shows as a
// store that will not open.
package kms

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"github.com/blechschmidt/cloop/pkg/config"
	"github.com/blechschmidt/cloop/pkg/hubmetrics"
	"github.com/blechschmidt/cloop/pkg/secretbroker"
)

// Operations, as the metrics label them.
const (
	OpStatus  = "status"
	OpEncrypt = "encrypt"
	OpDecrypt = "decrypt"
	// OpLogin is a Vault login (the Kubernetes auth method).
	OpLogin = "login"
)

// Results, as the metrics label them. A closed set: every error a provider
// returns is classified into one of these.
const (
	ResultOK          = "ok"
	ResultUnavailable = "unavailable" // could not reach the KMS, or it said it is not serving
	ResultTimeout     = "timeout"     // no answer within the configured timeout
	ResultDenied      = "denied"      // the KMS refused this identity
	ResultInvalid     = "invalid"     // the KMS refused the request: a wrong key, a ciphertext it does not hold
	ResultError       = "error"       // anything else, a malformed answer included
)

// Provider is one configured KMS key.
type Provider interface {
	secretbroker.KMS
	secretbroker.KMSKeyReporter
	// Kind is config.KMSProviderKMSv2 or config.KMSProviderTransit.
	Kind() string
	// Status asks the KMS whether it is serving and which key it encrypts
	// under. Cheap enough to poll: it is what kube-apiserver polls.
	Status(ctx context.Context) (Status, error)
	// Describe says where the KMS is, for a message: the socket, or the
	// server and key. Never a token.
	Describe() string
	// Close releases the provider's connection.
	Close() error
}

// Status is what a KMS says about itself.
type Status struct {
	// Healthy: the KMS answered and says it is serving.
	Healthy bool `json:"healthy"`
	// Healthz is a KMS v2 plugin's health string ("ok" when healthy).
	Healthz string `json:"healthz,omitempty"`
	// KeyID is the key it encrypts under now; a change is a rotation of the
	// KMS key, after which the hub rewraps (secretbroker.Keyring.RewrapKMS).
	KeyID string `json:"key_id,omitempty"`
	// Version is a KMS v2 plugin's protocol version.
	Version string `json:"version,omitempty"`
}

// Error is a failed KMS call: which KMS, which operation, how it was
// classified, and what it said. It wraps secretbroker.ErrKMSUnavailable when
// the KMS could not be reached or did not answer in time, so the keyring tells
// an outage from a refusal without knowing this package.
type Error struct {
	KMS    string
	Op     string
	Result string
	Err    error
}

func (e *Error) Error() string {
	what := map[string]string{
		ResultUnavailable: "cannot be reached",
		ResultTimeout:     "did not answer in time",
		ResultDenied:      "refused this hub's identity",
		ResultInvalid:     "refused the request",
		ResultError:       "failed",
	}[e.Result]
	if what == "" {
		what = "failed"
	}
	return fmt.Sprintf("the KMS %s %s (%s): %v", e.KMS, what, e.Op, e.Err)
}

func (e *Error) Unwrap() []error {
	if e.Result == ResultUnavailable || e.Result == ResultTimeout {
		return []error{secretbroker.ErrKMSUnavailable, e.Err}
	}
	return []error{e.Err}
}

// Open builds the provider a KMS block describes. It does not connect: the
// first call does, so a command that never opens the store never talks to the
// KMS. Call config.ValidateSecrets first; Open re-checks only what it needs.
func Open(cfg config.KMSConfig) (Provider, error) {
	switch strings.TrimSpace(cfg.Provider) {
	case config.KMSProviderKMSv2:
		return newKMSv2(cfg)
	case config.KMSProviderTransit:
		return newTransit(cfg)
	}
	return nil, fmt.Errorf("kms: unknown provider %q (want %q or %q)", cfg.Provider,
		config.KMSProviderKMSv2, config.KMSProviderTransit)
}

// observe records one call in the metrics and classifies its error.
func observe(provider, op string, start time.Time, err error) {
	hubmetrics.KMSRequestDuration.Observe(time.Since(start).Seconds(), provider, op)
	hubmetrics.KMSRequests.Inc(provider, op, resultOf(err))
}

// resultOf is the result label of a call's error.
func resultOf(err error) string {
	if err == nil {
		return ResultOK
	}
	var ke *Error
	if errors.As(err, &ke) {
		return ke.Result
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return ResultTimeout
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return ResultTimeout
	}
	return ResultError
}

// unreachable classifies a transport error: a timeout, or a KMS that is not
// there.
func unreachable(err error) string {
	if errors.Is(err, context.DeadlineExceeded) {
		return ResultTimeout
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return ResultTimeout
	}
	return ResultUnavailable
}

// withTimeout bounds ctx by d unless it is bounded more tightly already.
func withTimeout(ctx context.Context, d time.Duration) (context.Context, context.CancelFunc) {
	if ctx == nil {
		ctx = context.Background()
	}
	if dl, ok := ctx.Deadline(); ok && time.Until(dl) <= d {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, d)
}

// readSmallFile reads a token file, refusing one any user can rewrite: a token
// another user can replace is a Vault identity another user chooses for the
// hub.
func readSmallFile(path, what string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("read the %s %s: %w", what, path, err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return "", fmt.Errorf("read the %s %s: %w", what, path, err)
	}
	if !fi.Mode().IsRegular() {
		return "", fmt.Errorf("the %s %s is not a regular file", what, path)
	}
	if fi.Mode().Perm()&0o002 != 0 {
		return "", fmt.Errorf("the %s %s can be written by every user on the host (mode %04o); "+
			"chmod o-w it", what, path, fi.Mode().Perm())
	}
	const max = 64 << 10
	buf, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return "", fmt.Errorf("read the %s %s: %w", what, path, err)
	}
	if len(buf) > max {
		return "", fmt.Errorf("the %s %s holds more than %d bytes, which is not a token", what, path, max)
	}
	n := len(buf)
	tok := strings.TrimSpace(string(buf[:n]))
	if tok == "" {
		return "", fmt.Errorf("the %s %s is empty", what, path)
	}
	return tok, nil
}
